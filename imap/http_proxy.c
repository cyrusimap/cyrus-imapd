/* http_proxy.c - HTTP proxy support functions
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <syslog.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "httpd.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "iptostring.h"
#include "mupdate-client.h"
#include "prot.h"
#include "proxy.h"
#include "spool.h"
#include "tls.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#include <libxml/uri.h>

static int login(struct backend *s, const char *server __attribute__((unused)),
		 struct protocol_t *prot, const char *userid,
		 sasl_callback_t *cb, const char **status);
static int ping(struct backend *s);
static int logout(struct backend *s __attribute__((unused)));


struct protocol_t http_protocol =
{ "http", "HTTP", TYPE_SPEC,
  { .spec = { &login, &ping, &logout } }
};


const char *digest_recv_success(hdrcache_t hdrs)
{
    const char **hdr = spool_getheader(hdrs, "Authentication-Info");

    return (hdr ? hdr[0]: NULL);
}


static const char *callback_getdata(sasl_conn_t *conn,
				    sasl_callback_t *callbacks,
				    unsigned long callbackid)
{
    sasl_callback_t *cb;
    const char *result = NULL;

    for (cb = callbacks; cb->id != SASL_CB_LIST_END; cb++) {
	if (cb->id == callbackid) {
	    switch (cb->id) {
	    case SASL_CB_USER:
	    case SASL_CB_AUTHNAME: {
		sasl_getsimple_t *simple_cb = (sasl_getsimple_t *) cb->proc;
		simple_cb(cb->context, cb->id, &result, NULL);
		break;
	    }

	    case SASL_CB_PASS: {
		sasl_secret_t *pass;
		sasl_getsecret_t *pass_cb = (sasl_getsecret_t *) cb->proc;
		pass_cb(conn, cb->context, cb->id, &pass);
		result = (const char *) pass->data;
		break;
	    }
	    }
	}
    }

    return result;
}


#define BASE64_BUF_SIZE	21848	/* per RFC 2222bis: ((16K / 3) + 1) * 4  */

static int login(struct backend *s, const char *server __attribute__((unused)),
		 struct protocol_t *prot, const char *userid,
		 sasl_callback_t *cb, const char **status)
{
    int r = 0, local_cb = 0;
    socklen_t addrsize;
    struct sockaddr_storage saddr_l, saddr_r;
    char remoteip[60], localip[60], *p;
    struct buf buf = BUF_INITIALIZER;
    sasl_security_properties_t secprops =
	{ 0, 0xFF, PROT_BUFSIZE, 0, NULL, NULL }; /* default secprops */
    const char *mech_conf, *pass, *clientout = NULL;
    struct auth_scheme_t *scheme = NULL;
    unsigned need_tls = 0, tls_done = 0;

    if (status) *status = NULL;

    /* set the IP addresses */
    addrsize = sizeof(struct sockaddr_storage);
    if (getpeername(s->sock, (struct sockaddr *) &saddr_r, &addrsize) ||
	iptostring((struct sockaddr *) &saddr_r, addrsize, remoteip, 60)) {
	if (status) *status = "Failed to get remote IP address";
	return SASL_FAIL;
    }
  
    addrsize = sizeof(struct sockaddr_storage);
    if (getsockname(s->sock, (struct sockaddr *) &saddr_l, &addrsize) ||
	iptostring((struct sockaddr *) &saddr_l, addrsize, localip, 60)) {
	if (status) *status = "Failed to get local IP address";
	return SASL_FAIL;
    }

    /* Create callbacks, if necessary */
    if (!cb) {
	local_cb = 1;
	buf_setmap(&buf, s->hostname, strcspn(s->hostname, "."));
	buf_appendcstr(&buf, "_password");
	pass = config_getoverflowstring(buf_cstring(&buf), NULL);
	if (!pass) pass = config_getstring(IMAPOPT_PROXY_PASSWORD);
	cb = mysasl_callbacks(NULL, /* userid */
			      config_getstring(IMAPOPT_PROXY_AUTHNAME),
			      config_getstring(IMAPOPT_PROXY_REALM),
			      pass);
    }

    /* Require proxying if we have an "interesting" userid (authzid) */
    r = sasl_client_new(prot->sasl_service, s->hostname, localip, remoteip, cb,
			/* (userid  && *userid ? SASL_NEED_PROXY : 0) | */
			SASL_USAGE_FLAGS, &s->saslconn);
    if (r != SASL_OK) goto done;

    r = sasl_setprop(s->saslconn, SASL_SEC_PROPS, &secprops);
    if (r != SASL_OK) goto done;

    /* Get SASL mechanism list.  We can force a particular
       mechanism using a <shorthost>_mechs option */
    buf_setmap(&buf, s->hostname, strcspn(s->hostname, "."));
    buf_appendcstr(&buf, "_mechs");
    if (!(mech_conf = config_getoverflowstring(buf_cstring(&buf), NULL))) {
	mech_conf = config_getstring(IMAPOPT_FORCE_SASL_CLIENT_MECH);
    }

    do {
	unsigned code;
	hdrcache_t hdrs = NULL;
	const char **hdr, *errstr, *serverin;
	char base64[BASE64_BUF_SIZE+1];
	unsigned int serverinlen, clientoutlen, non_persist;
#ifdef SASL_HTTP_REQUEST
	sasl_http_request_t httpreq = { "OPTIONS",	/* Method */
					"*",		/* URI */
					(u_char *) "",	/* Empty body */
					0,		/* Zero-length body */
					0 };		/* Persistent cxn? */
#endif

	/* Base64 encode any client response, if necessary */
	if (clientout && scheme && (scheme->flags & AUTH_BASE64)) {
	    r = sasl_encode64(clientout, clientoutlen,
			      base64, BASE64_BUF_SIZE, &clientoutlen);
	    if (r != SASL_OK) goto cleanup;

	    clientout = base64;
	}

	/* Send Authorization and/or Upgrade request to server */
	prot_puts(s->out, "OPTIONS * HTTP/1.1\r\n");
	prot_printf(s->out, "Host: %s\r\n", s->hostname);
	if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	    prot_printf(s->out, "User-Agent: %s\r\n", buf_cstring(&serverinfo));
	}
	if (scheme) {
	    prot_printf(s->out, "Authorization: %s %s\r\n", 
			scheme->name, clientout ? clientout : "");
	    if (userid) prot_printf(s->out, "Authorize-As: %s\r\n", userid);
	}
	else {
	    prot_printf(s->out, "Upgrade: %s, %s\r\n",
			TLS_VERSION, HTTP_VERSION);
	    if (need_tls) {
		prot_puts(s->out, "Connection: upgrade\r\n");
		need_tls = 0;
	    }
	    prot_puts(s->out, "Authorization: \r\n");
	}
	prot_puts(s->out, "\r\n");
	prot_flush(s->out);

	serverin = clientout = NULL;
	serverinlen = clientoutlen = 0;

      response:
	r = http_read_response(s, METH_OPTIONS, &code, NULL,
			       &hdrs, NULL, 0, &errstr);
	if (r) {
	    if (status) *status = errstr;
	    goto cleanup;
	}

	/* Check if this is a non-persistent connection */
	non_persist = 0;
	if ((hdr = spool_getheader(hdrs, "Connection")) &&
	    !strcmp(hdr[0], "close")) {
	    non_persist = 1;
	}

	switch (code) {
	case 101: /* Switching Protocols */
	    if (backend_starttls(s, NULL)) {
		r = HTTP_BAD_GATEWAY;
		if (status) *status = "Unable to start TLS";
		break;
	    }
	    else tls_done = 1;
	    /* Fall through as 100-Continue */

	case 100: /* Continue */
	case 102: /* Processing */
	    goto response;

	case 200: /* OK */
	    if (scheme->recv_success &&
		(serverin = scheme->recv_success(hdrs))) {
		serverinlen = strlen(serverin);
	    }
	    /* Fall through and check for any other success data */

	case 401: /* Unauthorized */
	    if (!serverin) {
		int i = 0;
		
		hdr = spool_getheader(hdrs, "WWW-Authenticate");

		if (!scheme) {
		    unsigned avail_auth_schemes = 0;
		    const char *mech = NULL;
		    size_t len;

		    /* Compare authentication schemes offered in
		     * WWW-Authenticate header(s) to what we support */
		    buf_reset(&buf);
		    for (i = 0; hdr && hdr[i]; i++) {
			len = strcspn(hdr[i], " ");

			for (scheme = auth_schemes; scheme->name; scheme++) {
			    if (!strncmp(scheme->name, hdr[i], len) &&
				!((scheme->flags & AUTH_NEED_PERSIST) &&
				  non_persist)) {
				/* Tag the scheme as available */
				avail_auth_schemes |= (1 << scheme->idx);

				/* Add SASL-based schemes to SASL mech list */
				if (scheme->saslmech) {
				    if (buf_len(&buf)) buf_putc(&buf, ' ');
				    buf_appendcstr(&buf, scheme->saslmech);
				}
				break;
			    }
			}
		    }

		    /* If we have a mech_conf, use it */
		    if (mech_conf && buf_len(&buf)) {
			char *conf = xstrdup(mech_conf);
			char *newmechlist =
			    intersect_mechlists(conf,
						(char *) buf_cstring(&buf));

			if (newmechlist) {
			    buf_setcstr(&buf, newmechlist);
			    free(newmechlist);
			}
			else {
			    syslog(LOG_DEBUG, "%s did not offer %s",
				   s->hostname, mech_conf);
			    buf_reset(&buf);
			}
			free(conf);
		    }

#ifdef SASL_HTTP_REQUEST
		    /* Set HTTP request as specified above (REQUIRED) */
		    httpreq.non_persist = non_persist;
		    sasl_setprop(s->saslconn, SASL_HTTP_REQUEST, &httpreq);
#endif

		    /* Try to start SASL exchange using available mechs */
		    r = sasl_client_start(s->saslconn, buf_cstring(&buf),
					  NULL,		/* no prompts */
					  NULL, NULL, 	/* no initial resp */
					  &mech);

		    if (((r == SASL_OK) || (r == SASL_CONTINUE)) && mech) {
			/* Find auth scheme associated with chosen SASL mech */
			for (scheme = auth_schemes; scheme->name; scheme++) {
			    if (scheme->saslmech &&
				!strcmp(scheme->saslmech, mech)) break;
			}
		    }
		    else {
			/* No matching SASL mechs - try Basic */
			scheme = &auth_schemes[AUTH_BASIC];
			if (!(avail_auth_schemes & (1 << scheme->idx))) {
			    need_tls = !tls_done;
			    break;  /* case 401 */
			}
		    }

		    /* Find the associated WWW-Authenticate header */
		    for (i = 0; hdr && hdr[i]; i++) {
			len = strcspn(hdr[i], " ");
			if (!strncmp(scheme->name, hdr[i], len)) break;
		    }
		}

		/* Get server challenge */
		if (hdr && (p = strchr(hdr[i], ' '))) {
		    serverin = ++p;
		    serverinlen = strlen(serverin);
		}
	    }

	    if ((r == SASL_CONTINUE) || serverin) {
		/* Perform the next step in the auth exchange */

		if (scheme->idx == AUTH_BASIC) {
		    /* Don't care about "realm" in server challenge */
		    const char *authid =
			callback_getdata(s->saslconn, cb, SASL_CB_AUTHNAME);
		    pass = callback_getdata(s->saslconn, cb, SASL_CB_PASS);

		    buf_reset(&buf);
		    buf_printf(&buf, "%s:%s", authid, pass);
		    clientout = buf_cstring(&buf);
		    clientoutlen = buf_len(&buf);
		    r = SASL_OK;
		}
		else {
		    /* Base64 decode any server challenge, if necessary */
		    if (serverin && (scheme->flags & AUTH_BASE64)) {
			r = sasl_decode64(serverin, serverinlen,
					  base64, BASE64_BUF_SIZE, &serverinlen);
			if (r != SASL_OK) break;

			serverin = base64;
		    }

		    /* SASL mech (Digest, Negotiate, NTLM) */
		    r = sasl_client_step(s->saslconn, serverin, serverinlen,
					 NULL,		/* no prompts */
					 &clientout, &clientoutlen);
		}
	    }
	    break;  /* case 401 */

	case 426: /* Upgrade Required */
	    if (tls_done) {
		r = HTTP_BAD_GATEWAY;
		if (status) *status = "TLS already active";
	    }
	    else need_tls = 1;
	    break;

	default:
	    r = HTTP_BAD_GATEWAY;
	    if (status) *status = "Unknown backend server error";
	    break;
	}

      cleanup:
	if (hdrs) spool_free_hdrcache(hdrs);

    } while (need_tls || (r == SASL_CONTINUE) || ((r == SASL_OK) && clientout));

  done:
    buf_free(&buf);
    if (local_cb) free_callbacks(cb);

    if (r && status && !*status) *status = sasl_errstring(r, NULL, NULL);

    return r;
}


static int ping(struct backend *s)
{
    int r = 0;
    unsigned code;
    hdrcache_t hdrs = NULL;
    const char **hdr, *errstr;

    /* Send request to server */
    prot_puts(s->out, "OPTIONS * HTTP/1.1\r\n");
    prot_printf(s->out, "Host: %s\r\n", s->hostname);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(s->out, "User-Agent: %s\r\n", buf_cstring(&serverinfo));
    }
    prot_puts(s->out, "\r\n");
    prot_flush(s->out);

    do {
	r = http_read_response(s, METH_OPTIONS, &code, NULL,
			       &hdrs, NULL, 0, &errstr);
	if (r) break;

	/* Check if this is a non-persistent connection */
	if ((hdr = spool_getheader(hdrs, "Connection")) &&
	    !strcmp(hdr[0], "close")) {
	    r = HTTP_BAD_GATEWAY;
	    break;
	}

	/* Continue until error or final response */
    } while (code < 200);

    if (hdrs) spool_free_hdrcache(hdrs);

    return r;
}


static int logout(struct backend *s __attribute__((unused)))
{
    /* Nothing to send, client just closes connection */
    return 0;
}


/* proxy mboxlist_lookup; on misses, it asks the listener for this
 * machine to make a roundtrip to the master mailbox server to make
 * sure it's up to date
 */
int http_mlookup(const char *name, char **server, char **aclp, void *tid)
{
    struct mboxlist_entry mbentry;
    int r;

    r = mboxlist_lookup(name, &mbentry, tid);
    if (r == IMAP_MAILBOX_NONEXISTENT && config_mupdate_server) {
	kick_mupdate();
	r = mboxlist_lookup(name, &mbentry, tid);
    }
    if (r) return r;
    if (mbentry.mbtype & MBTYPE_RESERVE) return IMAP_MAILBOX_RESERVED;
    if (mbentry.mbtype & MBTYPE_MOVING) return IMAP_MAILBOX_MOVED;
    if (mbentry.mbtype & MBTYPE_DELETED) return IMAP_MAILBOX_NONEXISTENT;

    if (aclp) *aclp = mbentry.acl;
    if (server) {
	*server = NULL;
	if (mbentry.mbtype & MBTYPE_REMOTE) {
	    /* xxx hide the fact that we are storing partitions */
	    char *c;
	    *server = mbentry.partition;
	    c = strchr(*server, '!');
	    if (c) *c = '\0';
	}
    }

    return r;
}


/* Construct and write Via header to protstream. */
static void write_via_hdr(struct protstream *pout, hdrcache_t hdrs)
{
    const char **via = spool_getheader(hdrs, "Via");
    const char **host = spool_getheader(hdrs, "Host");

    prot_puts(pout, "Via: ");
    if (via && via[0]) prot_printf(pout, "%s, ", via[0]);
    prot_printf(pout, "%s %s", https ? HTTPS_VERSION : HTTP_VERSION,
		host && *host[0] ? host[0] : config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(pout, " (Cyrus/%s)", cyrus_version());
    }
    prot_puts(pout, "\r\n");
}


/* Write end-to-end header (ignoring hop-by-hop) from cache to protstream. */
static void write_cachehdr(const char *name, const char *contents, void *rock)
{
    struct protstream *pout = (struct protstream *) rock;
    const char **hdr, *hop_by_hop[] =
	{ "authorization", "connection", "content-length", "expect",
	  "host", "keep-alive", "strict-transport-security",
	  "transfer-encoding", "upgrade", "via", NULL };

    for (hdr = hop_by_hop; *hdr && strcmp(name, *hdr); hdr++);

    if (!*hdr) {
	if (!strcmp(name, "max-forwards")) {
	    /* Decrement Max-Forwards before forwarding */
	    unsigned long max = strtoul(contents, NULL, 10);

	    prot_printf(pout, "Max-Forwards: %lu\r\n", max-1);
	}
	else {
	    prot_printf(pout, "%c%s: %s\r\n", toupper(*name), name+1, contents);
	}
    }
}


/* Read a response from backend */
int http_read_response(struct backend *be, unsigned meth,
		       unsigned *code, const char **statline,
		       hdrcache_t *resp_hdrs, struct buf *resp_body,
		       unsigned decode, const char **errstr)
{
    static char statbuf[2048];
    int c = EOF;

    if (statline) *statline = statbuf;
    *errstr = NULL;

    if (*resp_hdrs) spool_free_hdrcache(*resp_hdrs);
    if (!(*resp_hdrs = spool_new_hdrcache())) {
	*errstr = "Unable to create header cache for backend response";
	return HTTP_SERVER_ERROR;
    }
    if (!prot_fgets(statbuf, sizeof(statbuf), be->in) ||
	(sscanf(statbuf, HTTP_VERSION " %u ", code) != 1) ||
	spool_fill_hdrcache(be->in, NULL, *resp_hdrs, NULL)) {
	*errstr = "Unable to read status-line/headers from backend";
	return HTTP_BAD_GATEWAY;
    }
    eatline(be->in, c); /* CRLF separating headers & body */

    /* 1xx (provisional) response - nothing else  to do */
    if (*code < 200) return 0;

    /* Final response */
    if (resp_body) buf_reset(resp_body);

    /* Not expecting a body for 204/304 response or any HEAD response */
    switch (*code){
    case 204: /* No Content */
    case 304: /* Not Modified */
	break;

    default:
	if (meth == METH_HEAD) break;

	if (read_body(be->in, *resp_hdrs, resp_body, decode, errstr)) {
	    return HTTP_BAD_GATEWAY;
	}
    }

    return 0;
}


/* Send a cached response to the client */
static void send_response(struct protstream *pout,
			  const char *statline, hdrcache_t hdrs,
			  struct buf *body, struct txn_flags_t *flags)
{
    unsigned long len;

    /* Stop method processing alarm */
    alarm(0);

    /*
     * - Use cached Status Line
     * - Add/append-to Via: header
     * - Add our own hop-by-hop headers
     * - Use all cached end-to-end headers
     */
    prot_puts(pout, statline);
    write_via_hdr(pout, hdrs);
    if (flags->close)
	prot_puts(pout, "Connection: close\r\n");
    else {
	prot_printf(pout, "Keep-Alive: timeout=%d\r\n", httpd_timeout);
	prot_puts(pout, "Connection: keep-alive\r\n");
    }
    if (httpd_tls_done) {
	prot_puts(httpd_out, "Strict-Transport-Security: max-age=600\r\n");
    }

    spool_enum_hdrcache(hdrs, &write_cachehdr, pout);

    if (!body || !(len = buf_len(body))) {
	/* Empty body -- use  payload headers from response, if any */
	const char **hdr;

	if ((hdr = spool_getheader(hdrs, "Transfer-Encoding"))) {
	    prot_printf(httpd_out, "Transfer-Encoding: %s\r\n", hdr[0]);
	}
	else if ((hdr = spool_getheader(hdrs, "Content-Length"))) {
	    prot_printf(httpd_out, "Content-Length: %s\r\n", hdr[0]);
	}

	prot_puts(httpd_out, "\r\n");
    }
    else {
	/* Body is buffered, so send using "identity" TE */
	prot_printf(httpd_out, "Content-Length: %lu\r\n\r\n", len);
	prot_putbuf(httpd_out, body);
    }
}


/*
 * Proxy (pipe) a client-request/server-response to/from a backend.
 *
 * XXX  This function currently buffers the response headers and body.
 *      Should work on sending them to the client on-the-fly.
 */
int http_pipe_req_resp(struct backend *be, struct transaction_t *txn)
{
    int r = 0, sent_body = 0;
    xmlChar *uri;
    unsigned code;
    const char *statline;
    hdrcache_t resp_hdrs = NULL;
    struct buf *resp_body = &txn->resp_body.payload;

    /*
     * Send client request to backend:
     *
     * - Piece the Request Line back together
     * - Add/append-to Via: header
     * - Add Expect:100-continue header (for synchonicity)
     * - Use all cached end-to-end headers from client
     * - Body will be sent using "chunked" TE
     */
    uri = xmlURIEscapeStr(BAD_CAST txn->req_tgt.path, BAD_CAST "/");
    prot_printf(be->out, "%s %s", http_methods[txn->meth].name, uri);
    free(uri);
    if (*txn->req_tgt.query) {
	prot_printf(be->out, "?%s", txn->req_tgt.query);
    }
    prot_printf(be->out, " %s\r\n", HTTP_VERSION);
    prot_printf(be->out, "Host: %s\r\n", be->hostname);
    write_via_hdr(be->out, txn->req_hdrs);
    spool_enum_hdrcache(txn->req_hdrs, &write_cachehdr, be->out);
    if (spool_getheader(txn->req_hdrs, "Transfer-Encoding") ||
	spool_getheader(txn->req_hdrs, "Content-Length")) {
	prot_puts(be->out, "Expect: 100-continue\r\n");
	prot_puts(be->out, "Transfer-Encoding: chunked\r\n");
    }
    prot_puts(be->out, "\r\n");
    prot_flush(be->out);

    /* Read response(s) from backend until final response or error */
    do {
	r = http_read_response(be, txn->meth, &code, &statline, &resp_hdrs,
			       resp_body, 0, &txn->error.desc);
	if (r) break;

	if ((code == 100) && !sent_body++) {
	    unsigned len;

	    if (!txn->flags.havebody) {
		/* Read body from client */
		txn->flags.havebody = 1;
		r = read_body(httpd_in, txn->req_hdrs, &txn->req_body,
			      txn->flags.cont, &txn->error.desc);
		if (r) {
		    /* Couldn't get the body and can't finish request */
		    txn->flags.close = 1;
		    break;
		}
	    }

	    /* Send single-chunk body to backend to complete the request */
	    if ((len = buf_len(&txn->req_body))) {
		prot_printf(be->out, "%x\r\n", len);
		prot_putbuf(be->out, &txn->req_body);
		prot_puts(be->out, "\r\n");
	    }
	    prot_puts(be->out, "0\r\n\r\n");
	    prot_flush(be->out);
	}
    } while (code < 200);

    if (r) proxy_downserver(be);
    else {
	/* Send response to client */
	send_response(httpd_out, statline, resp_hdrs, resp_body, &txn->flags);
    }

    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);

    return r;
}


/*
 * Proxy a COPY/MOVE client-request when the source and destination are
 * on different backends.  This is handled as a GET from the source and
 * PUT on the destination, while obeying any Overwrite header.
 *
 * XXX  This function currently buffers the response headers and body.
 *      Should work on sending them to the client on-the-fly.
 */
int http_proxy_copy(struct backend *src_be, struct backend *dest_be,
		    struct transaction_t *txn)
{
    int r = 0;
    unsigned code;
    char *etag = NULL;
    const char **hdr, *statline;
    hdrcache_t resp_hdrs = NULL;
    struct buf *resp_body = &txn->resp_body.payload;

    /*
     * Send a HEAD request to source backend to test conditionals:
     *
     * - Use any conditional headers specified by client
     */
    prot_printf(src_be->out, "HEAD %s %s\r\n", txn->req_tgt.path, HTTP_VERSION);
    prot_printf(src_be->out, "Host: %s\r\n", src_be->hostname);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(src_be->out, "User-Agent: %s\r\n",
		    buf_cstring(&serverinfo));
    }
    if ((hdr = spool_getheader(txn->req_hdrs, "If")))
	prot_printf(src_be->out, "If: %s\r\n", hdr[0]);
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Match")))
	prot_printf(src_be->out, "If-Match: %s\r\n", hdr[0]);
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Modified-Since")))
	prot_printf(src_be->out, "If-Modified-Since: %s\r\n", hdr[0]);
    if ((hdr = spool_getheader(txn->req_hdrs, "If-None-Match")))
	prot_printf(src_be->out, "If-None-Match: %s\r\n", hdr[0]);
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Unmodified-Since")))
	prot_printf(src_be->out, "If-Unmodified-Since: %s\r\n", hdr[0]);
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Range")))
	prot_printf(src_be->out, "If-Range: %s\r\n", hdr[0]);
    prot_flush(src_be->out);

    /* Read response from source backend */
    r = http_read_response(src_be, METH_HEAD, &code, &statline,
			   &resp_hdrs, NULL, 0, &txn->error.desc);
    if (r) goto cleanup;

    if (code == 200) {  /* OK */
	/* Make a copy of the Etag for later use */
	if ((hdr = spool_getheader(resp_hdrs, "Etag"))) etag = xstrdup(hdr[0]);

	/*
	 * Send a synchonizing PUT request to dest backend to test conditionals:
	 *
	 * - Add Expect:100-continue header (for synchonicity)
	 * - Obey Overwrite:F by adding If-None-Match:* header
	 * - Use Content-Type, -Language and -Type from HEAD response
	 * - Body will be sent using "chunked" TE
	 */
	hdr = spool_getheader(txn->req_hdrs, "Destination");
	prot_printf(dest_be->out, "PUT %s %s\r\n", hdr[0], HTTP_VERSION);
	prot_printf(dest_be->out, "Host: %s\r\n", dest_be->hostname);
	if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	    prot_printf(dest_be->out, "User-Agent: %s\r\n",
			buf_cstring(&serverinfo));
	}
	prot_puts(dest_be->out, "Expect: 100-continue\r\n");
	if ((hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
	    !strcmp(hdr[0], "F")) {
	    prot_printf(dest_be->out, "If-None-Match: *\r\n");
	}
	hdr = spool_getheader(resp_hdrs, "Content-Type");
	prot_printf(dest_be->out, "Content-Type: %s\r\n", hdr[0]);
	if ((hdr = spool_getheader(resp_hdrs, "Content-Language")))
	    prot_printf(dest_be->out, "Content-Language: %s\r\n", hdr[0]);
	prot_puts(dest_be->out, "Transfer-Encoding: chunked\r\n\r\n");
	prot_flush(dest_be->out);

	/* Read response from dest backend */
	r = http_read_response(dest_be, METH_PUT, &code, &statline,
			       &resp_hdrs, resp_body, 0, &txn->error.desc);
	if (r) goto cleanup;

	if (code == 100) {  /* Continue */
	    /*
	     * Send a GET request to source backend to fetch body:
	     *
	     * - Add If-Match header with ETag from HEAD
	     */
	    prot_printf(src_be->out, "GET %s %s\r\n",
			txn->req_tgt.path, HTTP_VERSION);
	    prot_printf(src_be->out, "Host: %s\r\n", src_be->hostname);
	    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
		prot_printf(src_be->out, "User-Agent: %s\r\n",
			    buf_cstring(&serverinfo));
	    }
	    if (etag) prot_printf(src_be->out, "If-Match: %s\r\n", etag);
	    prot_flush(src_be->out);

	    /* Read response from source backend */
	    r = http_read_response(src_be, METH_GET, &code, &statline,
				   &resp_hdrs, resp_body, 0, &txn->error.desc);
	    if (r) goto cleanup;

	    if (code == 200) {  /* OK */
		/* Send single-chunk body to dest backend to complete the PUT */
		prot_printf(dest_be->out, "%x\r\n", buf_len(resp_body));
		prot_putbuf(dest_be->out, resp_body);
		prot_puts(dest_be->out, "\r\n0\r\n\r\n");
		prot_flush(dest_be->out);

		/* Read final response from dest backend */
		r = http_read_response(dest_be, METH_PUT, &code, &statline,
				       &resp_hdrs, resp_body, 0, &txn->error.desc);
		if (r) goto cleanup;
	    }
	    else {
		/* Couldn't get the body and can't finish PUT */
		proxy_downserver(dest_be);
	    }
	}
    }

    /* Send response to client */
    send_response(httpd_out, statline, resp_hdrs, resp_body, &txn->flags);

    if ((txn->meth == METH_MOVE) && (code < 300)) {
	/*
	 * Send a DELETE request to source backend:
	 *
	 * - Add If-Match header with ETag from HEAD
	 *
	 * XXX  This clearly isn't an atomic MOVE.
	 *      Either try to fix this, or don't allow MOVE
	 */
	prot_printf(src_be->out, "DELETE %s %s\r\n",
		    txn->req_tgt.path, HTTP_VERSION);
	prot_printf(src_be->out, "Host: %s\r\n", src_be->hostname);
	if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	    prot_printf(src_be->out, "User-Agent: %s\r\n",
			buf_cstring(&serverinfo));
	}
	if (etag) prot_printf(src_be->out, "If-Match: %s\r\n", etag);
	prot_flush(src_be->out);

	/* Read response from source backend */
	http_read_response(src_be, METH_DELETE, &code, &statline,
			   &resp_hdrs, NULL, 0, &txn->error.desc);
    }

  cleanup:
    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);
    if (etag) free(etag);

    return r;
}
