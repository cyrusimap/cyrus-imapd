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
#include <assert.h>
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
#include "tok.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#include <libxml/uri.h>

static int login(struct backend *s, const char *userid,
		 sasl_callback_t *cb, const char **status);
static int ping(struct backend *s, const char *userid);
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

static int login(struct backend *s, const char *userid,
		 sasl_callback_t *cb, const char **status)
{
    int r = 0;
    socklen_t addrsize;
    struct sockaddr_storage saddr_l, saddr_r;
    char remoteip[60], localip[60];
    static struct buf buf = BUF_INITIALIZER;
    sasl_security_properties_t secprops =
	{ 0, 0xFF, PROT_BUFSIZE, 0, NULL, NULL }; /* default secprops */
    const char *mech_conf, *pass, *clientout = NULL;
    struct auth_scheme_t *scheme = NULL;
    unsigned need_tls = 0, tls_done = 0, clientoutlen;
    hdrcache_t hdrs = NULL;

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
	buf_setmap(&buf, s->hostname, strcspn(s->hostname, "."));
	buf_appendcstr(&buf, "_password");
	pass = config_getoverflowstring(buf_cstring(&buf), NULL);
	if (!pass) pass = config_getstring(IMAPOPT_PROXY_PASSWORD);
	cb = mysasl_callbacks(NULL, /* userid */
			      config_getstring(IMAPOPT_PROXY_AUTHNAME),
			      config_getstring(IMAPOPT_PROXY_REALM),
			      pass);
	s->sasl_cb = cb;
    }

    /* Create SASL context */
    r = sasl_client_new(s->prot->sasl_service, s->hostname,
			localip, remoteip, cb, SASL_USAGE_FLAGS, &s->saslconn);
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
	const char **hdr, *errstr, *serverin;
	char base64[BASE64_BUF_SIZE+1];
	unsigned int serverinlen;
	struct body_t resp_body;
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
	    if (r != SASL_OK) break;

	    clientout = base64;
	}

	/* Send Authorization and/or Upgrade request to server */
	prot_puts(s->out, "OPTIONS * HTTP/1.1\r\n");
	prot_printf(s->out, "Host: %s\r\n", s->hostname);
	prot_printf(s->out, "User-Agent: %s\r\n", buf_cstring(&serverinfo));
	if (scheme) {
	    prot_printf(s->out, "Authorization: %s %s\r\n", 
			scheme->name, clientout ? clientout : "");
	    prot_printf(s->out, "Authorize-As: %s\r\n",
			userid ? userid : "anonymous");
	}
	else {
	    prot_printf(s->out, "Upgrade: %s\r\n", TLS_VERSION);
	    if (need_tls) {
		prot_puts(s->out, "Connection: Upgrade\r\n");
		need_tls = 0;
	    }
	    prot_puts(s->out, "Authorization: \r\n");
	}
	prot_puts(s->out, "\r\n");
	prot_flush(s->out);

	serverin = clientout = NULL;
	serverinlen = clientoutlen = 0;

	/* Read response(s) from backend until final response or error */
	do {
	    resp_body.flags = BODY_DISCARD;
	    r = http_read_response(s, METH_OPTIONS, &code, NULL,
				   &hdrs, &resp_body, &errstr);
	    if (r) {
		if (status) *status = errstr;
		break;
	    }

	    if (code == 101) {  /* Switching Protocols */
		if (tls_done) {
		    r = HTTP_BAD_GATEWAY;
		    if (status) *status = "TLS already active";
		    break;
		}
		else if (backend_starttls(s, NULL)) {
		    r = HTTP_SERVER_ERROR;
		    if (status) *status = "Unable to start TLS";
		    break;
		}
		else tls_done = 1;
	    }
	} while (code < 200);

	switch (code) {
	default: /* Failure */
	    if (!r) {
		r = HTTP_BAD_GATEWAY;
		if (status) {
		    buf_reset(&buf);
		    buf_printf(&buf,
			       "Unexpected status code from backend: %u", code);
		    *status = buf_cstring(&buf);
		}
	    }
	    break;

	case 426: /* Upgrade Required */
	    if (tls_done) {
		r = HTTP_BAD_GATEWAY;
		if (status) *status = "TLS already active";
	    }
	    else need_tls = 1;
	    break;

	case 200: /* OK */
	    if (scheme->recv_success &&
		(serverin = scheme->recv_success(hdrs))) {
		serverinlen = strlen(serverin);
	    }
	    /* Fall through and process any success data */

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
				  (resp_body.flags & BODY_CLOSE))) {
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
		    httpreq.non_persist = (resp_body.flags & BODY_CLOSE);
		    sasl_setprop(s->saslconn, SASL_HTTP_REQUEST, &httpreq);
#endif

		    /* Try to start SASL exchange using available mechs */
		    r = sasl_client_start(s->saslconn, buf_cstring(&buf),
					  NULL,		/* no prompts */
					  NULL, NULL, 	/* no initial resp */
					  &mech);

		    if (mech) {
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

		/* Get server challenge, if any */
		if (hdr) {
		    const char *p = strchr(hdr[i], ' ');
		    serverin = p ? ++p : "";
		    serverinlen = strlen(serverin);
		}
	    }

	    if (serverin) {
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
		}
		else {
		    /* Base64 decode any server challenge, if necessary */
		    if (serverin && (scheme->flags & AUTH_BASE64)) {
			r = sasl_decode64(serverin, serverinlen,
					  base64, BASE64_BUF_SIZE, &serverinlen);
			if (r != SASL_OK) break;  /* case 401 */

			serverin = base64;
		    }

		    /* SASL mech (Digest, Negotiate, NTLM) */
		    r = sasl_client_step(s->saslconn, serverin, serverinlen,
					 NULL,		/* no prompts */
					 &clientout, &clientoutlen);
		}
	    }
	    break;  /* case 401 */
	}

    } while (need_tls || clientout);

  done:
    if (hdrs) spool_free_hdrcache(hdrs);

    if (r && status && !*status) *status = sasl_errstring(r, NULL, NULL);

    return r;
}


static int ping(struct backend *s, const char *userid)
{
    unsigned code = 0;
    const char *errstr;
    hdrcache_t resp_hdrs = NULL;
    struct body_t resp_body;

    /* Send Authorization request to server */
    prot_puts(s->out, "OPTIONS * HTTP/1.1\r\n");
    prot_printf(s->out, "Host: %s\r\n", s->hostname);
    prot_printf(s->out, "User-Agent: %s\r\n", buf_cstring(&serverinfo));
    prot_printf(s->out, "Authorize-As: %s\r\n", userid ? userid : "anonymous");
    prot_puts(s->out, "\r\n");
    prot_flush(s->out);

    /* Read response(s) from backend until final response or error */
    do {
	resp_body.flags = BODY_DISCARD;
	if (http_read_response(s, METH_OPTIONS, &code, NULL,
			       &resp_hdrs, &resp_body, &errstr)) {
	    break;
	}
    } while (code < 200);

    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);

    return (code != 200);
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


/* Fetch protocol and host used for request from headers */
void http_proto_host(hdrcache_t req_hdrs, const char **proto, const char **host)
{
    const char **fwd;

    if (config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS) &&
	(fwd = spool_getheader(req_hdrs, "Forwarded"))) {
	/* Proxied request - parse last Forwarded header for proto and host */
	/* XXX  This is destructive of the header but we don't care
	 * and more importantly, we need the tokens available after tok_fini()
	 */
	tok_t tok;
	char *token;

	while (fwd[1]) ++fwd;  /* Skip to last Forwarded header */

	tok_initm(&tok, (char *) fwd[0], ";", 0);
	while ((token = tok_next(&tok))) {
	    if (proto && !strncmp(token, "proto=", 6)) *proto = token+6;
	    else if (host && !strncmp(token, "host=", 5)) *host = token+5;
	}
	tok_fini(&tok);
    }
    else {
	/* Use our protocol and host */
	if (proto) *proto = https ? "https" : "http";
	if (host) *host = *spool_getheader(req_hdrs, "Host");
    }
}

/* Construct and write Via header to protstream. */
static void write_forwarding_hdrs(struct protstream *pout, hdrcache_t hdrs,
				  const char *version, const char *proto)
{
    const char **via = spool_getheader(hdrs, "Via");
    const char **fwd = spool_getheader(hdrs, "Forwarded");

    /* Add any existing Via headers */
    for (; via && *via; via++) prot_printf(pout, "Via: %s\r\n", *via);

    /* Create our own Via header */
    prot_printf(pout, "Via: %s %s", version+5, config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(pout, " (Cyrus/%s)", cyrus_version());
    }
    prot_puts(pout, "\r\n");

    /* Add any existing Forwarded headers */
    for (; fwd && *fwd; fwd++) prot_printf(pout, "Forwarded: %s\r\n", *fwd);

    /* Create our own Forwarded header */
    if (proto) {
	char localip[60], remoteip[60], *p;
	socklen_t salen = sizeof(httpd_remoteaddr);
	const char **host = spool_getheader(hdrs, "Host");

	prot_printf(pout, "Forwarded: proto=%s", proto);
	if (host) prot_printf(pout, ";host=%s", *host);
	if (!iptostring((struct sockaddr *)&httpd_remoteaddr, salen,
			remoteip, 60)) {
	    if ((p = strrchr(remoteip, ';'))) *p = '\0';
	    prot_printf(pout, ";for=%s", remoteip);
	}
	if (!iptostring((struct sockaddr *)&httpd_localaddr, salen,
			localip, 60)) {
	    if ((p = strrchr(localip, ';'))) *p = '\0';
	    prot_printf(pout, ";by=%s", localip);
	}
	prot_puts(pout, "\r\n");    
    }
}


/* Write end-to-end header (ignoring hop-by-hop) from cache to protstream. */
static void write_cachehdr(const char *name, const char *contents, void *rock)
{
    struct protstream *pout = (struct protstream *) rock;
    const char **hdr, *hop_by_hop[] =
	{ "authorization", "connection", "content-length", "expect",
	  "forwarded", "host", "keep-alive", "strict-transport-security",
	  "te", "trailer", "transfer-encoding", "upgrade", "via", NULL };

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

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


/* Send a cached response to the client */
static void send_response(const char *statline, hdrcache_t hdrs,
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
    prot_puts(httpd_out, statline);
    write_forwarding_hdrs(httpd_out, hdrs, HTTP_VERSION, NULL);
    if (flags->conn) {
	/* Construct Connection header */
	const char *conn_tokens[] =
	    { "close", "Upgrade", "Keep-Alive", NULL };

	if (flags->conn & CONN_KEEPALIVE) {
	    prot_printf(httpd_out, "Keep-Alive: timeout=%d\r\n", httpd_timeout);
	}

	comma_list_hdr("Connection", conn_tokens, flags->conn);
    }
    if (httpd_tls_done) {
	prot_puts(httpd_out, "Strict-Transport-Security: max-age=600\r\n");
    }

    spool_enum_hdrcache(hdrs, &write_cachehdr, httpd_out);

    if (!body || !(len = buf_len(body))) {
	/* Empty body -- use  payload headers from response, if any */
	const char **hdr;

	if (!flags->ver1_0 &&
	    (hdr = spool_getheader(hdrs, "Transfer-Encoding"))) {
	    prot_printf(httpd_out, "Transfer-Encoding: %s\r\n", hdr[0]);
	    if ((hdr = spool_getheader(hdrs, "Trailer"))) {
		prot_printf(httpd_out, "Trailer: %s\r\n", hdr[0]);
	    }
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


/* Proxy (pipe) a chunk of body data to a client/server. */
static unsigned pipe_chunk(struct protstream *pin, struct protstream *pout,
			   unsigned len)
{
    char buf[PROT_BUFSIZE];
    unsigned n = 0;

    /* Read 'len' octets */
    for (; len; len -= n) {
	n = prot_read(pin, buf, MIN(len, PROT_BUFSIZE));
	if (!n) break;

	prot_write(pout, buf, n);
    }

    return n;
}


/* Proxy (pipe) a response body to a client/server. */
static int pipe_resp_body(struct protstream *pin, struct protstream *pout,
			  hdrcache_t resp_hdrs, struct body_t *resp_body,
			  int ver1_0, const char **errstr)
{
    char buf[PROT_BUFSIZE];

    if (resp_body->framing == FRAMING_UNKNOWN) {
	/* Get message framing */
	int r = http_parse_framing(resp_hdrs, resp_body, errstr);
	if (r) return r;
    }
    
    /* Read and pipe the body */
    switch (resp_body->framing) {
    case FRAMING_LENGTH:
	/* Read 'len' octets */
	if (resp_body->len && !pipe_chunk(pin, pout, resp_body->len)) {
	    syslog(LOG_ERR, "prot_read() error");
	    *errstr = "Unable to read body data";
	    return HTTP_BAD_GATEWAY;
	}
	break;

    case FRAMING_CHUNKED: {
	unsigned chunk;
	char *c;

	/* Read chunks until last-chunk (zero chunk-size) */
	do {
	    /* Read chunk-size */
	    prot_NONBLOCK(pin);
	    c = prot_fgets(buf, PROT_BUFSIZE, pin);
	    prot_BLOCK(pin);
	    if (!c) {
		prot_flush(pout);
		c = prot_fgets(buf, PROT_BUFSIZE, pin);
	    }
	    if (!c || sscanf(buf, "%x", &chunk) != 1) {
		*errstr = "Unable to read chunk size";
		return HTTP_BAD_GATEWAY;

		/* XXX  Do we need to parse chunk-ext? */
	    }
	    else if (chunk > resp_body->max - resp_body->len)
		return HTTP_TOO_LARGE;
	    else if (!ver1_0) prot_puts(pout, buf);

	    if (chunk) {
		/* Read 'chunk' octets */
		if (!pipe_chunk(pin, pout, chunk)) {
		    syslog(LOG_ERR, "prot_read() error");
		    *errstr = "Unable to read chunk data";
		    return HTTP_BAD_GATEWAY;
		}
	    }
	    else {
		/* Read any trailing headers */
		for (*c = prot_ungetc(prot_getc(pin), pin);
		     *c != '\r' && *c != '\n';
		     *c = prot_ungetc(prot_getc(pin), pin)) {
		    if (!prot_fgets(buf, sizeof(buf), pin)) {
			*errstr = "Error reading trailer";
			return HTTP_BAD_GATEWAY;
		    }
		    else if (!ver1_0) prot_puts(pout, buf);
		}
	    }
	    

	    /* Read CRLF terminating the chunk/trailer */
	    if (!prot_fgets(buf, sizeof(buf), pin)) {
		*errstr = "Missing CRLF following chunk/trailer";
		return HTTP_BAD_GATEWAY;
	    }
	    else if (!ver1_0) prot_puts(pout, buf);

	} while (chunk);

	break;
    }

    case FRAMING_CLOSE:
	/* Read until EOF */
	if (pipe_chunk(pin, pout, UINT_MAX) || !pin->eof)
	    return HTTP_BAD_GATEWAY;

	break;

    default:
	/* XXX  Should never get here */
	*errstr = "Unknown length of body data";
	return HTTP_BAD_GATEWAY;
    }

    return 0;
}



/* Proxy (pipe) a client-request/server-response to/from a backend. */
int http_pipe_req_resp(struct backend *be, struct transaction_t *txn)
{
    int r = 0, sent_body = 0;
    xmlChar *uri;
    unsigned code;
    const char **hdr, *statline;
    hdrcache_t resp_hdrs = NULL;
    struct body_t resp_body;

    /*
     * Send client request to backend:
     *
     * - Piece the Request Line back together
     * - Add/append-to Via: header
     * - Add Expect:100-continue header (for synchonicity)
     * - Use all cached end-to-end headers from client
     * - Body will be sent using "chunked" TE, since we might not have it yet
     */
    uri = xmlURIEscapeStr(BAD_CAST txn->req_uri->path, BAD_CAST "/");
    prot_printf(be->out, "%s %s", txn->req_line.meth, uri);
    free(uri);
    if (URI_QUERY(txn->req_uri)) {
	prot_printf(be->out, "?%s", URI_QUERY(txn->req_uri));
    }
    prot_printf(be->out, " %s\r\n", HTTP_VERSION);
    prot_printf(be->out, "Host: %s\r\n", be->hostname);
    write_forwarding_hdrs(be->out, txn->req_hdrs, txn->req_line.ver,
			  https ? "https" : "http");
    spool_enum_hdrcache(txn->req_hdrs, &write_cachehdr, be->out);
    if ((hdr = spool_getheader(txn->req_hdrs, "TE"))) {
	for (; *hdr; hdr++) prot_printf(be->out, "TE: %s\r\n", *hdr);
    }
    if (http_methods[txn->meth].flags & METH_NOBODY)
	prot_puts(be->out, "Content-Length: 0\r\n");
    else if (spool_getheader(txn->req_hdrs, "Transfer-Encoding") ||
	spool_getheader(txn->req_hdrs, "Content-Length")) {
	prot_puts(be->out, "Expect: 100-continue\r\n");
	prot_puts(be->out, "Transfer-Encoding: chunked\r\n");
    }
    prot_puts(be->out, "\r\n");
    prot_flush(be->out);

    /* Read response(s) from backend until final response or error */
    memset(&resp_body, 0, sizeof(struct body_t));

    do {
	r = http_read_response(be, txn->meth, &code, &statline,
			       &resp_hdrs, NULL, &txn->error.desc);
	if (r) break;

	if (code == 100) { /* Continue */
	    if (!sent_body++) {
		unsigned len;

		/* Read body from client */
		r = http_read_body(httpd_in, httpd_out, txn->req_hdrs,
				   &txn->req_body, &txn->error.desc);
		if (r) {
		    /* Couldn't get the body and can't finish request */
		    txn->flags.conn = CONN_CLOSE;
		    break;
		}

		/* Send single-chunk body to backend to complete the request */
		if ((len = buf_len(&txn->req_body.payload))) {
		    prot_printf(be->out, "%x\r\n", len);
		    prot_putbuf(be->out, &txn->req_body.payload);
		    prot_puts(be->out, "\r\n");
		}
		prot_puts(be->out, "0\r\n\r\n");
		prot_flush(be->out);
	    }
	    else {
		prot_puts(httpd_out, statline);
		spool_enum_hdrcache(resp_hdrs, &write_cachehdr, httpd_out);
		prot_puts(httpd_out, "\r\n");
		prot_flush(httpd_out);
	    }
	}
    } while (code < 200);

    if (r) proxy_downserver(be);
    else if (code == 401) {
	/* Don't pipe a 401 response (discard body).
	   Frontend should send its own 401 since it will process auth */
	resp_body.flags |= BODY_DISCARD;
	http_read_body(be->in, httpd_out,
		       resp_hdrs, &resp_body, &txn->error.desc);

	r = HTTP_UNAUTHORIZED;
    }
    else {
	/* Send response to client */
	send_response(statline, resp_hdrs, NULL, &txn->flags);
  
	/* Not expecting a body for 204/304 response or any HEAD response */
	switch (code) {
	case 204: /* No Content */
	case 304: /* Not Modified */
	    break;

	default:
	    if (txn->meth == METH_HEAD) break;

	    if (pipe_resp_body(be->in, httpd_out, resp_hdrs, &resp_body,
			       txn->flags.ver1_0, &txn->error.desc)) {
		/* Couldn't pipe the body and can't finish response */
		txn->flags.conn = CONN_CLOSE;
	    }
	}
    }

    if (resp_body.flags & BODY_CLOSE) proxy_downserver(be);

    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);

    return r;
}


/*
 * Proxy a COPY/MOVE client-request when the source and destination are
 * on different backends.  This is handled as a GET from the source and
 * PUT on the destination, while obeying any Overwrite header.
 *
 * For a MOVE request, we also LOCK, DELETE, and possibly UNLOCK the source.
 *
 * XXX  This function buffers the response bodies of the LOCK & GET requests.
 *      The response body of the PUT request is piped to the client.
 */
int http_proxy_copy(struct backend *src_be, struct backend *dest_be,
		    struct transaction_t *txn)
{
    int r = 0, sent_body;
    unsigned code;
    char *lock = NULL;
    const char **hdr, *statline;
    hdrcache_t resp_hdrs = NULL;
    struct body_t resp_body;

#define write_hdr(pout, name, hdrs)					\
    if ((hdr = spool_getheader(hdrs, name)))				\
	for (; *hdr; hdr++) prot_printf(pout, "%s: %s\r\n", name, *hdr)


    resp_body.payload = txn->resp_body.payload;

    if (txn->meth == METH_MOVE) {
	/*
	 * Send a LOCK request to source backend:
	 *
	 * - Use any relevant conditional headers specified by client
	 */
	prot_printf(src_be->out, "LOCK %s %s\r\n"
				 "Host: %s\r\n"
				 "User-Agent: %s\r\n",
		    txn->req_tgt.path, HTTP_VERSION,
		    src_be->hostname, buf_cstring(&serverinfo));
	write_hdr(src_be->out, "If", txn->req_hdrs);
	write_hdr(src_be->out, "If-Match", txn->req_hdrs);
	write_hdr(src_be->out, "If-Unmodified-Since", txn->req_hdrs);
	write_hdr(src_be->out, "If-Schedule-Tag-Match", txn->req_hdrs);

	assert(!buf_len(&txn->buf));
	buf_printf_markup(&txn->buf, 0,
			  "<?xml version=\"1.0\" encoding=\"utf-8\" ?>");
	buf_printf_markup(&txn->buf, 0, "<D:lockinfo xmlns:D='DAV:'>");
	buf_printf_markup(&txn->buf, 1,
			  "<D:lockscope><D:exclusive/></D:lockscope>");
	buf_printf_markup(&txn->buf, 1,
			  "<D:locktype><D:write/></D:locktype>");
	buf_printf_markup(&txn->buf, 1, "<D:owner>%s</D:owner>", httpd_userid);
	buf_printf_markup(&txn->buf, 0, "</D:lockinfo>");

	prot_printf(src_be->out,
		    "Content-Type: application/xml; charset=utf-8\r\n"
		    "Content-Length: %u\r\n\r\n%s",
		    buf_len(&txn->buf), buf_cstring(&txn->buf));
	buf_reset(&txn->buf);

	prot_flush(src_be->out);

	/* Read response(s) from source backend until final response or error */
	resp_body.flags = 0;

	do {
	    r = http_read_response(src_be, METH_LOCK, &code, &statline,
				   &resp_hdrs, &resp_body, &txn->error.desc);
	    if (r) {
		proxy_downserver(src_be);
		goto done;
	    }
	} while (code < 200);

	/* Get lock token */
	if ((hdr = spool_getheader(resp_hdrs, "Lock-Token")))
	    lock = xstrdup(*hdr);

	switch (code) {
	case 200:
	    /* Success, continue */
	    break;

	case 201:
	    /* Created empty resource, treat as 404 (Not Found) */
	    r = HTTP_NOT_FOUND;
	    goto delete;

	case 409:
	    /* Failed to create resource, treat as 404 (Not Found) */
	    r = HTTP_NOT_FOUND;
	    goto done;

	default:
	    /* Send failure response to client */
	    send_response(statline, resp_hdrs, &resp_body.payload, &txn->flags);
	    goto done;
	}
    }


    /*
     * Send a GET request to source backend to fetch body:
     *
     * - Use any relevant conditional headers specified by client
     *   (if not already sent in LOCK request)
     */
    prot_printf(src_be->out, "GET %s %s\r\n"
    			     "Host: %s\r\n"
			     "User-Agent: %s\r\n",
		txn->req_tgt.path, HTTP_VERSION,
		src_be->hostname, buf_cstring(&serverinfo));
    if (txn->meth != METH_MOVE) {
	write_hdr(src_be->out, "If", txn->req_hdrs);
	write_hdr(src_be->out, "If-Match", txn->req_hdrs);
	write_hdr(src_be->out, "If-Unmodified-Since", txn->req_hdrs);
	write_hdr(src_be->out, "If-Schedule-Tag-Match", txn->req_hdrs);
    }
    prot_puts(src_be->out, "\r\n");
    prot_flush(src_be->out);

    /* Read response(s) from source backend until final response or error */
    resp_body.flags = 0;

    do {
	r = http_read_response(src_be, METH_GET, &code, &statline,
			       &resp_hdrs, &resp_body, &txn->error.desc);
	if (r || (resp_body.flags & BODY_CLOSE)) {
	    proxy_downserver(src_be);
	    goto done;
	}
    } while (code < 200);

    if (code != 200) {
	/* Send failure response to client */
	send_response(statline, resp_hdrs, &resp_body.payload, &txn->flags);
	goto done;
    }


    /*
     * Send a synchonizing PUT request to dest backend:
     *
     * - Add Expect:100-continue header (for synchonicity)
     * - Obey Overwrite by adding If-None-Match header
     * - Use any TE, Prefer, Accept* headers specified by client
     * - Use Content-Type, -Encoding, -Language headers from GET response
     * - Body is buffered, so send using "identity" TE
     */
    prot_printf(dest_be->out, "PUT %s %s\r\n"
    			      "Host: %s\r\n"
			      "User-Agent: %s\r\n"
			      "Expect: 100-continue\r\n",
		*spool_getheader(txn->req_hdrs, "Destination"), HTTP_VERSION,
		dest_be->hostname, buf_cstring(&serverinfo));
    hdr = spool_getheader(txn->req_hdrs, "Overwrite");
    if (hdr && !strcmp(*hdr, "F"))
	prot_puts(dest_be->out, "If-None-Match: *\r\n");
    write_hdr(dest_be->out, "TE", txn->req_hdrs);
    write_hdr(dest_be->out, "Prefer", txn->req_hdrs);
    write_hdr(dest_be->out, "Accept", txn->req_hdrs);
    write_hdr(dest_be->out, "Accept-Charset", txn->req_hdrs);
    write_hdr(dest_be->out, "Accept-Encoding", txn->req_hdrs);
    write_hdr(dest_be->out, "Accept-Language", txn->req_hdrs);
    write_hdr(dest_be->out, "Content-Type", resp_hdrs);
    write_hdr(dest_be->out, "Content-Encoding", resp_hdrs);
    write_hdr(dest_be->out, "Content-Language", resp_hdrs);
    prot_printf(dest_be->out, "Content-Length: %u\r\n\r\n",
		buf_len(&resp_body.payload));
    prot_flush(dest_be->out);

    /* Read response(s) from dest backend until final response or error */
    sent_body = 0;

    do {
	r = http_read_response(dest_be, METH_PUT, &code, &statline,
			       &resp_hdrs, NULL, &txn->error.desc);
	if (r) {
	    proxy_downserver(dest_be);
	    goto done;
	}

	if ((code == 100) /* Continue */  && !sent_body++) {
	    /* Send body to dest backend to complete the PUT */
	    prot_putbuf(dest_be->out, &resp_body.payload);
	    prot_flush(dest_be->out);
	}
    } while (code < 200);

    /* Send response to client */
    send_response(statline, resp_hdrs, NULL, &txn->flags);
    if (code != 204) {
	resp_body.framing = FRAMING_UNKNOWN;
	if (pipe_resp_body(dest_be->in, httpd_out, resp_hdrs, &resp_body,
			   0, &txn->error.desc)) {
	    /* Couldn't pipe the body and can't finish response */
	    txn->flags.conn = CONN_CLOSE;
	    proxy_downserver(dest_be);
	    goto done;
	}
    }


  delete:
    if ((txn->meth == METH_MOVE) && (code < 300)) {
	/*
	 * Send a DELETE request to source backend:
	 *
	 * - Add If header with lock token
	 */
	prot_printf(src_be->out, "DELETE %s %s\r\n"
				 "Host: %s\r\n"
				 "User-Agent: %s\r\n",
		    txn->req_tgt.path, HTTP_VERSION,
		    src_be->hostname, buf_cstring(&serverinfo));
	if (lock) prot_printf(src_be->out, "If: (%s)\r\n", lock);
	prot_puts(src_be->out, "\r\n");
	prot_flush(src_be->out);

	/* Read response(s) from source backend until final resp or error */
	resp_body.flags = BODY_DISCARD;

	do {
	    if (http_read_response(src_be, METH_DELETE, &code, NULL,
				   &resp_hdrs, &resp_body, &txn->error.desc)
		|| (resp_body.flags & BODY_CLOSE)) {
		proxy_downserver(src_be);
		break;
	    }
	} while (code < 200);

	if (code < 300 && lock) {
	    free(lock);
	    lock = NULL;
	}
    }


  done:
    if (lock) {
	/*
	 * Something failed - Send an UNLOCK request to source backend:
	 */
	prot_printf(src_be->out, "UNLOCK %s %s\r\n"
				 "Host: %s\r\n"
				 "User-Agent: %s\r\n"
				 "Lock-Token: %s\r\n\r\n",
		    txn->req_tgt.path, HTTP_VERSION,
		    src_be->hostname, buf_cstring(&serverinfo), lock);
	prot_flush(src_be->out);

	/* Read response(s) from source backend until final resp or error */
	resp_body.flags = BODY_DISCARD;

	do {
	    if (http_read_response(src_be, METH_UNLOCK, &code, NULL,
				   &resp_hdrs, &resp_body, &txn->error.desc)) {
		proxy_downserver(src_be);
		break;
	    }
	} while (code < 200);

	free(lock);
    }

    txn->resp_body.payload = resp_body.payload;
    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);

    return r;
}
