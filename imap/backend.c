/* backend.c -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * $Id: backend.c,v 1.63 2010/08/04 18:57:36 wescraig Exp $
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "prot.h"
#include "backend.h"
#include "global.h"
#include "nonblock.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "iptostring.h"
#include "util.h"
#include "tok.h"

enum {
    AUTO_CAPA_BANNER = -1,
    AUTO_CAPA_NO = 0,
};

static char *parse_capability(const char str[],
			      struct protocol_t *prot, unsigned long *capa)
{
    char *ret = NULL, *tmp;
    struct capa_cmd_t *capa_cmd = &prot->u.std.capa_cmd;
    struct capa_t *c;

    /* look for capabilities in the string */
    for (c = capa_cmd->capa; c->str; c++) {
	if ((tmp = strstr(str, c->str)) != NULL) {
	    *capa = *capa | c->flag;

	    if (c->flag == CAPA_AUTH) {
		if (capa_cmd->parse_mechlist)
		    ret = capa_cmd->parse_mechlist(str, &prot->u.std);
		else
		    ret = xstrdup(tmp+strlen(c->str));
	    }
	}
    }

    return ret;
}

static char *ask_capability(struct protstream *pout, struct protstream *pin,
			    struct protocol_t *prot, unsigned long *capa,
			    char *banner, int automatic)
{
    char str[4096];
    char *mechlist = NULL, *ret;
    const char *resp;
    struct capa_cmd_t *capa_cmd = &prot->u.std.capa_cmd;

    resp = (automatic == AUTO_CAPA_BANNER) ?
	prot->u.std.banner.resp : capa_cmd->resp;

    if (!automatic) {
	/* no capability command */
	if (!capa_cmd->cmd) return NULL;
	
	/* request capabilities of server */
	prot_printf(pout, "%s", capa_cmd->cmd);
	if (capa_cmd->arg) prot_printf(pout, " %s", capa_cmd->arg);
	prot_printf(pout, "\r\n");
	prot_flush(pout);
    }

    *capa = 0;
    
    do {
	if (prot_fgets(str, sizeof(str), pin) == NULL) break;

	if ((ret = parse_capability(str, prot, capa))) {
	    if (mechlist) free(mechlist);
	    mechlist = ret;
	}

	if (!resp) {
	    /* multiline response with no distinct end (IMAP banner) */
	    prot_NONBLOCK(pin);
	}

	if (banner) strncpy(banner, str, 2048);

	/* look for the end of the capabilities */
    } while (!resp || strncasecmp(str, resp, strlen(resp)));
    
    prot_BLOCK(pin);
    return mechlist;
}

static int do_compress(struct backend *s, struct simple_cmd_t *compress_cmd)
{
#ifndef HAVE_ZLIB
    return -1;
#else
    char buf[1024];

    /* send compress command */
    prot_printf(s->out, "%s\r\n", compress_cmd->cmd);
    prot_flush(s->out);

    /* check response */
    if (!prot_fgets(buf, sizeof(buf), s->in) ||
	strncmp(buf, compress_cmd->ok, strlen(compress_cmd->ok)))
	return -1;

    prot_setcompress(s->in);
    prot_setcompress(s->out);

    return 0;
#endif /* HAVE_ZLIB */
}

int backend_starttls(struct backend *s, struct tls_cmd_t *tls_cmd)
{
#ifndef HAVE_SSL
    return -1;
#else
    int r;
    int *layerp;
    char *auth_id;

    if (tls_cmd) {
	char buf[2048];

	/* send starttls command */
	prot_printf(s->out, "%s\r\n", tls_cmd->cmd);
	prot_flush(s->out);

	/* check response */
	if (!prot_fgets(buf, sizeof(buf), s->in) ||
	    strncmp(buf, tls_cmd->ok, strlen(tls_cmd->ok)))
	    return -1;
    }

    r = tls_init_clientengine(5, "", "");
    if (r == -1) return -1;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &s->ext_ssf;
    r = tls_start_clienttls(s->in->fd, s->out->fd, layerp, &auth_id,
			    &s->tlsconn, &s->tlssess);
    if (r == -1) return -1;

    if (s->saslconn) {
	r = sasl_setprop(s->saslconn, SASL_SSF_EXTERNAL, &s->ext_ssf);
	if (r == SASL_OK)
	    r = sasl_setprop(s->saslconn, SASL_AUTH_EXTERNAL, auth_id);
	if (auth_id) free(auth_id);
	if (r != SASL_OK) return -1;
    }

    prot_settls(s->in,  s->tlsconn);
    prot_settls(s->out, s->tlsconn);

    return 0;
#endif /* HAVE_SSL */
}

char *intersect_mechlists( char *config, char *server )
{
    char *newmechlist = xzmalloc( strlen( config ) + 1 );
    char *cmech = NULL, *smech = NULL, *s;
    int count = 0;
    char csave, ssave;

    do {
	if ( isalnum( *config ) || *config == '_' || *config == '-' ) {
	    if ( cmech == NULL ) {
		cmech = config;
	    }
	} else {
	    if ( cmech != NULL ) {
		csave = *config;
		*config = '\0';

		s = server;
		do {
		    if ( isalnum( *s ) || *s == '_' || *s == '-' ) {
			if ( smech == NULL ) {
			    smech = s;
			}
		    } else {
			if ( smech != NULL ) {
			    ssave = *s;
			    *s = '\0';

			    if ( strcasecmp( cmech, smech ) == 0 ) {
				if ( count > 0 ) {
				    strcat( newmechlist, " " );
				}
				strcat( newmechlist, cmech );
				count++;

				*s = ssave;
				smech = NULL;
				break;
			    }

			    *s = ssave;
			    smech = NULL;
			}
		    }
		} while ( *s++ );

		*config = csave;
		cmech = NULL;
	    }
	}
    } while ( *config++ );

    if ( count == 0 ) {
	free( newmechlist );
	return( NULL );
    }
    return( newmechlist );
}

static int backend_authenticate(struct backend *s, struct protocol_t *prot,
				char **mechlist, const char *userid,
				sasl_callback_t *cb, const char **status)
{
    int r;
    sasl_security_properties_t secprops =
	{ 0, 0xFF, PROT_BUFSIZE, 0, NULL, NULL }; /* default secprops */
    struct sockaddr_storage saddr_l, saddr_r;
    char remoteip[60], localip[60];
    socklen_t addrsize;
    char buf[2048], optstr[128], *p;
    const char *mech_conf, *pass;

    /* set the IP addresses */
    addrsize=sizeof(struct sockaddr_storage);
    if (getpeername(s->sock, (struct sockaddr *)&saddr_r, &addrsize) != 0)
	return SASL_FAIL;
    if(iptostring((struct sockaddr *)&saddr_r, addrsize, remoteip, 60) != 0)
	return SASL_FAIL;
  
    addrsize=sizeof(struct sockaddr_storage);
    if (getsockname(s->sock, (struct sockaddr *)&saddr_l, &addrsize)!=0)
	return SASL_FAIL;
    if(iptostring((struct sockaddr *)&saddr_l, addrsize, localip, 60) != 0)
	return SASL_FAIL;

    if (!cb) {
	strlcpy(optstr, s->hostname, sizeof(optstr));
	p = strchr(optstr, '.');
	if (p) *p = '\0';
	strlcat(optstr, "_password", sizeof(optstr));
	pass = config_getoverflowstring(optstr, NULL);
	if(!pass) pass = config_getstring(IMAPOPT_PROXY_PASSWORD);
	cb = mysasl_callbacks(userid, 
			      config_getstring(IMAPOPT_PROXY_AUTHNAME),
			      config_getstring(IMAPOPT_PROXY_REALM),
			      pass);
	s->sasl_cb = cb;
    }

    /* Require proxying if we have an "interesting" userid (authzid) */
    r = sasl_client_new(prot->sasl_service, s->hostname, localip, remoteip, cb,
			(userid  && *userid ? SASL_NEED_PROXY : 0) |
			(prot->u.std.sasl_cmd.parse_success ? SASL_SUCCESS_DATA : 0),
			&s->saslconn);
    if (r != SASL_OK) {
	return r;
    }

    r = sasl_setprop(s->saslconn, SASL_SEC_PROPS, &secprops);
    if (!r) r = sasl_setprop(s->saslconn, SASL_SSF_EXTERNAL, &s->ext_ssf);
    if (r != SASL_OK) {
	return r;
    }

    /* Get SASL mechanism list.  We can force a particular
       mechanism using a <shorthost>_mechs option */
    strcpy(buf, s->hostname);
    p = strchr(buf, '.');
    if (p) *p = '\0';
    strcat(buf, "_mechs");
    mech_conf = config_getoverflowstring(buf, NULL);

    if(!mech_conf) {
	mech_conf = config_getstring(IMAPOPT_FORCE_SASL_CLIENT_MECH);
    }

    do {
	/* If we have a mech_conf, use it */
	if (mech_conf && *mechlist) {
	    char *conf = xstrdup(mech_conf);
	    char *newmechlist = intersect_mechlists( conf, *mechlist );

	    if ( newmechlist == NULL ) {
		syslog( LOG_INFO, "%s did not offer %s", s->hostname,
			mech_conf );
	    }

	    free(conf);
	    free(*mechlist);
	    *mechlist = newmechlist;
	}

	if (*mechlist) {
	    /* we now do the actual SASL exchange */
	    saslclient(s->saslconn, &prot->u.std.sasl_cmd, *mechlist,
		       s->in, s->out, &r, status);

	    /* garbage collect */
	    free(*mechlist);
	    *mechlist = NULL;
	}
	else r = SASL_NOMECH;

	/* If we don't have a usable mech, do TLS and try again */
    } while (r == SASL_NOMECH && CAPA(s, CAPA_STARTTLS) &&
	     backend_starttls(s, &prot->u.std.tls_cmd) != -1 &&
	     (*mechlist = ask_capability(s->out, s->in, prot,
					 &s->capability, NULL,
					 prot->u.std.tls_cmd.auto_capa)));

    if (r == SASL_OK) {
	prot_setsasl(s->in, s->saslconn);
	prot_setsasl(s->out, s->saslconn);
    }

    /* r == SASL_OK on success */
    return r;
}

static int backend_login(struct backend *ret, const char *userid,
			 sasl_callback_t *cb, const char **auth_status)
{
    int r = 0;
    int ask = 1; /* should we explicitly ask for capabilities? */
    char buf[2048], *mechlist = NULL;
    struct protocol_t *prot = ret->prot;

    if (prot->u.std.banner.auto_capa) {
	/* try to get the capabilities from the banner */
	mechlist = ask_capability(ret->out, ret->in, prot,
				  &ret->capability, ret->banner,
				  AUTO_CAPA_BANNER);
	if (mechlist || ret->capability) {
	    /* found capabilities in banner -> don't ask */
	    ask = 0;
	}
    }
    else {
	do { /* read the initial greeting */
	    if (!prot_fgets(buf, sizeof(buf), ret->in)) {
		syslog(LOG_ERR,
		       "backend_connect(): couldn't read initial greeting: %s",
		       ret->in->error ? ret->in->error : "(null)");
		return -1;
	    }
	} while (strncasecmp(buf, prot->u.std.banner.resp,
			     strlen(prot->u.std.banner.resp)));
	strncpy(ret->banner, buf, 2048);
    }

    if (ask) {
	/* get the capabilities */
	mechlist = ask_capability(ret->out, ret->in, prot,
				  &ret->capability, NULL, AUTO_CAPA_NO);
    }

    /* now need to authenticate to backend server,
       unless we're doing LMTP/CSYNC on a UNIX socket (deliver/sync_client) */
    if ((ret->addr.ss_family != PF_UNIX) ||
	(strcmp(prot->sasl_service, "lmtp") &&
	 strcmp(prot->sasl_service, "csync"))) {
	char *mlist = NULL;
	const char *my_status;

	if (mechlist) {
	    mlist = xstrdup(mechlist); /* backend_auth is destructive */
	}

	if ((r = backend_authenticate(ret, prot, &mlist, userid,
				      cb, &my_status))) {
	    syslog(LOG_ERR, "couldn't authenticate to backend server '%s': %s",
		   ret->hostname, sasl_errstring(r, NULL, NULL));
	}
	else {
	    const void *ssf;

	    sasl_getprop(ret->saslconn, SASL_SSF, &ssf);
	    if (*((sasl_ssf_t *) ssf)) {
		/* if we have a SASL security layer, compare SASL mech lists
		   before/after AUTH to check for a MITM attack */
		char *new_mechlist;
		int auto_capa = (prot->u.std.sasl_cmd.auto_capa == AUTO_CAPA_AUTH_SSF);

		if (!strcmp(prot->service, "sieve")) {
		    /* XXX  Hack to handle ManageSieve servers.
		     * No way to tell from protocol if server will
		     * automatically send capabilities, so we treat it
		     * as optional.
		     */
		    char ch;

		    /* wait and probe for possible auto-capability response */
		    usleep(250000);
		    prot_NONBLOCK(ret->in);
		    if ((ch = prot_getc(ret->in)) != EOF) {
			prot_ungetc(ch, ret->in);
		    } else {
			auto_capa = AUTO_CAPA_AUTH_NO;
		    }
		    prot_BLOCK(ret->in);
		}

		/*
		 * A flawed check: backend_authenticate() may be given a
		 * NULL mechlist, negotiate SSL, and get a new mechlist.
		 * This new, correct mechlist won't be visible here.
		 */
		new_mechlist = ask_capability(ret->out, ret->in, prot,
					      &ret->capability, NULL, auto_capa);
		if (new_mechlist && strcmp(new_mechlist, mechlist)) {
		    syslog(LOG_ERR, "possible MITM attack:"
			   "list of available SASL mechanisms changed");
		    r = SASL_BADAUTH;
		}

		if (new_mechlist) free(new_mechlist);
	    }
	    else if (prot->u.std.sasl_cmd.auto_capa == AUTO_CAPA_AUTH_OK) {
		/* try to get the capabilities from the AUTH success response */
		ret->capability = 0;
		if (mechlist) free(mechlist);
		mechlist = parse_capability(my_status, prot,
					    &ret->capability);
	    }

	    if (!(strcmp(prot->service, "imap") &&
		  strcmp(prot->service, "pop3"))) {
		char rsessionid[MAX_SESSIONID_SIZE];

		parse_sessionid(my_status, rsessionid);
		syslog(LOG_NOTICE, "proxy %s sessionid=<%s> remote=<%s>",
		       userid, session_id(), rsessionid);
	    }
	}

	if (mlist) free(mlist);
	if (auth_status) *auth_status = my_status;
    }

    if (mechlist) free(mechlist);

    /* start compression if requested and both client/server support it */
    if (!r && config_getswitch(IMAPOPT_PROXY_COMPRESS) &&
	CAPA(ret, CAPA_COMPRESS) &&
	prot->u.std.compress_cmd.cmd &&
	do_compress(ret, &prot->u.std.compress_cmd)) {

	syslog(LOG_ERR, "couldn't enable compression on backend server");
	r = -1;
    }

    return r;
}


struct backend *backend_connect(struct backend *ret_backend, const char *server,
				struct protocol_t *prot, const char *userid,
				sasl_callback_t *cb, const char **auth_status)
{
    /* need to (re)establish connection to server or create one */
    int sock = -1;
    int r = 0;
    int err = 0, do_tls = 0, no_auth = 0;
    struct addrinfo hints, *res0 = NULL, *res;
    struct sockaddr_un sunsock;
    struct backend *ret;

    if (!ret_backend) {
	ret = xzmalloc(sizeof(struct backend));
	strlcpy(ret->hostname, server, sizeof(ret->hostname));
	ret->timeout = NULL;
    }
    else
	ret = ret_backend;

    if (server[0] == '/') { /* unix socket */
	res0 = &hints;
	memset(res0, 0, sizeof(struct addrinfo));
	res0->ai_family = PF_UNIX;
	res0->ai_socktype = SOCK_STREAM;

 	res0->ai_addr = (struct sockaddr *) &sunsock;
 	res0->ai_addrlen = sizeof(sunsock.sun_family) + strlen(server) + 1;
#ifdef SIN6_LEN
 	res0->ai_addrlen += sizeof(sunsock.sun_len);
 	sunsock.sun_len = res0->ai_addrlen;
#endif
	sunsock.sun_family = AF_UNIX;
	strlcpy(sunsock.sun_path, server, sizeof(sunsock.sun_path));

	/* XXX set that we are preauthed */

	/* change hostname to 'config_servername' */
	strlcpy(ret->hostname, config_servername, sizeof(ret->hostname));
    }
    else { /* inet socket */
	char host[1024], *p;
	const char *service = prot->service;

	/* Parse server string for possible port and options */
	strlcpy(host, server, sizeof(host));
	if ((p = strchr(host, ':'))) {
	    *p++ = '\0';
	    service = p;

	    if ((p = strchr(service, '/'))) {
		tok_t tok;
		char *opt;

		*p++ = '\0';
		tok_initm(&tok, p, "/", 0);
		while ((opt = tok_next(&tok))) {
		    if (!strcmp(opt, "tls")) do_tls = 1;
		    else if (!strcmp(opt, "noauth")) no_auth = 1;
		}
		tok_fini(&tok);
	    }
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, service, &hints, &res0);
	if (err) {
	    syslog(LOG_ERR, "getaddrinfo(%s) failed: %s",
		   server, gai_strerror(err));
	    if (!ret_backend) free(ret);
	    return NULL;
	}
    }

    for (res = res0; res; res = res->ai_next) {
	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0)
	    continue;

	/* Do a non-blocking connect() */
	nonblock(sock, 1);
	if (!connect(sock, res->ai_addr, res->ai_addrlen)) {
	    /* connect() succeeded immediately */
	    break;
	}
	else if (errno == EINPROGRESS) {
	    /* connect() in progress */
	    int n;
	    fd_set wfds, rfds;
	    time_t now = time(NULL);
	    time_t timeout = now + config_getint(IMAPOPT_CLIENT_TIMEOUT);
	    struct timeval waitfor;

	    /* select() socket for writing until we succeed, fail, or timeout */
	    do {
		FD_ZERO(&wfds);
		FD_SET(sock, &wfds);
		rfds = wfds;
    		waitfor.tv_sec = timeout - now;
		waitfor.tv_usec = 0;

		n = select(sock + 1, &rfds, &wfds, NULL, &waitfor);
		now = time(NULL);

		/* Retry select() if interrupted */
	    } while (n < 0 && errno == EINTR && now < timeout);

	    if (!n) {
		/* select() timed out */
		errno = ETIMEDOUT;
	    }
	    else if (FD_ISSET(sock, &rfds) || FD_ISSET(sock, &wfds)) {
		/* Socket is ready for I/O - get SO_ERROR to determine status */
		socklen_t errlen = sizeof(err);

		if (!getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen) &&
		    !(errno = err)) {
		    /* connect() succeeded */
		    break;
		}
	    }
	}

	close(sock);
	sock = -1;
    }

    if (sock < 0) {
	if (res0 != &hints) freeaddrinfo(res0);
	syslog(LOG_ERR, "connect(%s) failed: %m", server);
	if (!ret_backend) free(ret);
	return NULL;
    }

    /* Reset socket to blocking */
    nonblock(sock, 0);

    memcpy(&ret->addr, res->ai_addr, res->ai_addrlen);
    if (res0 != &hints)
	freeaddrinfo(res0);

    ret->in = prot_new(sock, 0);
    ret->out = prot_new(sock, 1);
    ret->sock = sock;
    prot_settimeout(ret->in, config_getint(IMAPOPT_CLIENT_TIMEOUT));
    prot_setflushonread(ret->in, ret->out);
    ret->prot = prot;

    /* use literal+ to send literals */
    prot_setisclient(ret->in, 1);
    prot_setisclient(ret->out, 1);

    /* Start TLS if required */
    if (do_tls) r = backend_starttls(ret, NULL);

    /* Login to the server */
    if (!r && !no_auth) {
	if (prot->type == TYPE_SPEC)
	    r = prot->u.spec.login(ret, userid, cb, auth_status);
	else
	    r = backend_login(ret, userid, cb, auth_status);
    }

    if (r) {
	backend_disconnect(ret);
	if (!ret_backend) free(ret);
	ret = NULL;
    }
    else prot_settimeout(ret->in, 0);
    
    if (!ret_backend) ret_backend = ret;
	    
    return ret;
}

int backend_ping(struct backend *s, const char *userid)
{
    struct simple_cmd_t *ping_cmd;

    if (!s) return 0;
    if (s->sock == -1) return -1; /* Disconnected Socket */

    if (s->prot->type == TYPE_SPEC) return s->prot->u.spec.ping(s, userid);

    ping_cmd = &s->prot->u.std.ping_cmd;
    if (!ping_cmd->cmd) return 0;

    prot_printf(s->out, "%s\r\n", ping_cmd->cmd);
    prot_flush(s->out);

    for (;;) {
	char buf[1024];

	if (!prot_fgets(buf, sizeof(buf), s->in)) {
	    /* connection closed? */
	    return -1;
	} else if (ping_cmd->unsol &&
		   !strncmp(ping_cmd->unsol, buf, strlen(ping_cmd->unsol))) {
	    /* unsolicited response */
	    continue;
	} else {
	    /* success/fail response */
	    return strncmp(ping_cmd->ok, buf, strlen(ping_cmd->ok));
	}
    }
}

void backend_disconnect(struct backend *s)
{
    if (!s || s->sock == -1) return;
    
    if (!prot_error(s->in)) {
	if (s->prot->type == TYPE_SPEC) s->prot->u.spec.logout(s);
	else {
	    struct simple_cmd_t *logout_cmd = &s->prot->u.std.logout_cmd;

	    if (logout_cmd->cmd) {
		prot_printf(s->out, "%s\r\n", logout_cmd->cmd);
		prot_flush(s->out);

		for (;;) {
		    char buf[1024];

		    if (!prot_fgets(buf, sizeof(buf), s->in)) {
			/* connection closed? */
			break;
		    } else if (logout_cmd->unsol &&
			       !strncmp(logout_cmd->unsol, buf,
					strlen(logout_cmd->unsol))) {
			/* unsolicited response */
			continue;
		    } else {
			/* success/fail response -- don't care either way */
			break;
		    }
		}
	    }
	}
    }

    /* Flush the incoming buffer */
    prot_NONBLOCK(s->in);
    prot_fill(s->in);

#ifdef HAVE_SSL
    /* Free tlsconn */
    if (s->tlsconn) {
	tls_reset_servertls(&s->tlsconn);
	s->tlsconn = NULL;
    }
#endif /* HAVE_SSL */

    /* close/free socket & prot layer */
    cyrus_close_sock(s->sock);
    s->sock = -1;
    
    prot_free(s->in);
    prot_free(s->out);
    s->in = s->out = NULL;

    /* Free saslconn */
    if (s->saslconn) {
	sasl_dispose(&(s->saslconn));
	s->saslconn = NULL;
    }

    /* Free any SASL callbacks */
    if (s->sasl_cb) {
	free_callbacks(s->sasl_cb);
	s->sasl_cb = NULL;
    }

    /* free last_result buffer */
    buf_free(&s->last_result);
}
