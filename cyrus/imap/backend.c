/* backend.c -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 */

/* $Id: backend.c,v 1.29 2004/06/04 14:22:27 rjs3 Exp $ */

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
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "prot.h"
#include "backend.h"
#include "global.h"
#include "xmalloc.h"
#include "iptostring.h"
#include "util.h"

static char *ask_capability(struct protstream *pout, struct protstream *pin,
			    struct protocol_t *prot, unsigned long *capa)
{
    char str[4096];
    char *ret = NULL, *tmp;
    struct capa_t *c;

    *capa = 0;
    
    if (prot->capa_cmd.cmd) {
	/* request capabilities of server */
	prot_printf(pout, "%s\r\n", prot->capa_cmd.cmd);
	prot_flush(pout);
    }

    do {
	if (prot_fgets(str, sizeof(str), pin) == NULL) {
	    return NULL;
	}

	/* look for capabilities in the string */
	for (c = prot->capa_cmd.capa; c->str; c++) {
	    if ((tmp = strstr(str, c->str)) != NULL) {
		*capa = *capa | c->flag;

		if (c->flag == CAPA_AUTH) {
		    if (prot->capa_cmd.parse_mechlist)
			ret = prot->capa_cmd.parse_mechlist(str, prot);
		    else
			ret = strdup(tmp+strlen(c->str));
		}
	    }
	}
	/* look for the end of the capabilities */
    } while (strncasecmp(str, prot->capa_cmd.resp, strlen(prot->capa_cmd.resp)));
    
    return ret;
}

static int do_starttls(struct backend *s, struct tls_cmd_t *tls_cmd)
{
#ifndef HAVE_SSL
    return -1;
#else
    char buf[2048];
    int r;
    int *layerp;
    char *auth_id;
    sasl_ssf_t ssf;

    /* send starttls command */
    prot_printf(s->out, "%s\r\n", tls_cmd->cmd);
    prot_flush(s->out);

    /* check response */
    if (!prot_fgets(buf, sizeof(buf), s->in) ||
	strncmp(buf, tls_cmd->ok, strlen(tls_cmd->ok)))
	return -1;

    r = tls_init_clientengine(5, "", "");
    if (r == -1) return -1;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;
    r = tls_start_clienttls(s->in->fd, s->out->fd, layerp, &auth_id,
			    &s->tlsconn, &s->tlssess);
    if (r == -1) return -1;

    r = sasl_setprop(s->saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (r != SASL_OK) return -1;

    r = sasl_setprop(s->saslconn, SASL_AUTH_EXTERNAL, auth_id);
    if (r != SASL_OK) return -1;

    prot_settls(s->in,  s->tlsconn);
    prot_settls(s->out, s->tlsconn);

    return 0;
#endif /* HAVE_SSL */
}

static int backend_authenticate(struct backend *s, struct protocol_t *prot,
				char **mechlist, const char *userid,
				const char **status)
{
    int r;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_storage saddr_l, saddr_r;
    char remoteip[60], localip[60];
    socklen_t addrsize;
    sasl_callback_t *cb;
    char buf[2048], optstr[128], *p;
    const char *mech_conf, *pass;

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

    /* Require proxying if we have an "interesting" userid (authzid) */
    r = sasl_client_new(prot->sasl_service, s->hostname, localip, remoteip, cb,
			(userid  && *userid ? SASL_NEED_PROXY : 0) |
			(prot->sasl_cmd.parse_success ? SASL_SUCCESS_DATA : 0),
			&s->saslconn);
    if (r != SASL_OK) {
	return r;
    }

    secprops = mysasl_secprops(0);
    r = sasl_setprop(s->saslconn, SASL_SEC_PROPS, secprops);
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
	if (mech_conf) {
	    free(*mechlist);
	    *mechlist = xstrdup(mech_conf);
	}

	if (*mechlist) {
	    /* we now do the actual SASL exchange */
	    saslclient(s->saslconn, &prot->sasl_cmd, *mechlist,
		       s->in, s->out, &r, status);

	    /* garbage collect */
	    free(*mechlist);
	    *mechlist = NULL;
	}
	else r = SASL_NOMECH;

	/* If we don't have a usable mech, do TLS and try again */
    } while (r == SASL_NOMECH && CAPA(s, CAPA_STARTTLS) &&
	     do_starttls(s, &prot->tls_cmd) != -1 &&
	     (*mechlist = ask_capability(s->out, s->in, prot, &s->capability)));

    /* xxx unclear that this is correct */
    free_callbacks(cb);

    if (r == SASL_OK) {
	prot_setsasl(s->in, s->saslconn);
	prot_setsasl(s->out, s->saslconn);
    }

    /* r == SASL_OK on success */
    return r;
}

struct backend *backend_connect(struct backend *ret, const char *server,
				struct protocol_t *prot, const char *userid,
				const char **auth_status)
{
    /* need to (re)establish connection to server or create one */
    int sock = -1;
    int r;
    int err;
    struct addrinfo hints, *res0 = NULL, *res;
    struct sockaddr_un sunsock;
    char buf[2048], *mechlist = NULL;

    if (!ret) {
	ret = xmalloc(sizeof(struct backend));
	memset(ret, 0, sizeof(struct backend));
	strlcpy(ret->hostname, server, sizeof(ret->hostname));
	ret->timeout = NULL;
    }

    if (server[0] == '/') { /* unix socket */
	res0 = (struct addrinfo *) xmalloc(sizeof(struct addrinfo));
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
	strcpy(sunsock.sun_path, server);

	/* XXX set that we are preauthed */

	/* change hostname to 'config_servername' */
	strlcpy(ret->hostname, config_servername, sizeof(ret->hostname));
    }
    else { /* inet socket */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(server, prot->service, &hints, &res0);
	if (err) {
	    syslog(LOG_ERR, "getaddrinfo(%s) failed: %s",
		   server, gai_strerror(err));
	    free(ret);
	    return NULL;
	}
    }

    for (res = res0; res; res = res->ai_next) {
	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0)
	    continue;
	if (connect(sock, res->ai_addr, res->ai_addrlen) >= 0)
	    break;
	close(sock);
	sock = -1;
    }
    if (sock < 0) {
	freeaddrinfo(res0);
	syslog(LOG_ERR, "connect(%s) failed: %m", server);
        close(sock);
	free(ret);
	return NULL;
    }
    memcpy(&ret->addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res0);    

    ret->in = prot_new(sock, 0);
    ret->out = prot_new(sock, 1);
    ret->sock = sock;
    prot_setflushonread(ret->in, ret->out);
    
    if (prot->capa_cmd.cmd) {
	/* read the initial greeting */
	if (!prot_fgets(buf, sizeof(buf), ret->in)) {
	    syslog(LOG_ERR,
		   "backend_connect(): couldn't read initial greeting: %s",
		   ret->in->error ? ret->in->error : "(null)");
	    free(ret);
	    close(sock);
	    return NULL;
	}
    }

    /* get the capabilities */
    mechlist = ask_capability(ret->out, ret->in, prot, &ret->capability);

    /* now need to authenticate to backend server,
       unless we're doing LMTP on a UNIX socket (deliver) */
    if ((server[0] != '/') || strcmp(prot->sasl_service, "lmtp")) {
	if ((r = backend_authenticate(ret, prot, &mechlist, userid, auth_status))) {
	    syslog(LOG_ERR, "couldn't authenticate to backend server: %s",
		   sasl_errstring(r, NULL, NULL));
	    free(ret);
	    close(sock);
	    ret = NULL;
	}
    }

    if (mechlist) free(mechlist);
    
    return ret;
}

int backend_ping(struct backend *s, struct protocol_t *prot)
{
    char buf[1024];

    if (!s || !prot || !prot->ping_cmd.cmd) return 0;
    if (!s->sock == -1) return -1; /* Disconnected Socket */
    
    prot_printf(s->out, "%s\r\n", prot->ping_cmd.cmd);
    prot_flush(s->out);

    if (!prot_fgets(buf, sizeof(buf), s->in) ||
	strncmp(prot->ping_cmd.resp, buf, strlen(prot->ping_cmd.resp))) {
	return -1; /* ping failed */
    }

    return 0;
}

void backend_disconnect(struct backend *s, struct protocol_t *prot)
{
    char buf[1024];

    if (!s || s->sock == -1) return;
    
    if (!prot_error(s->in)) {
	if (prot && prot->logout_cmd.cmd) {
	    prot_printf(s->out, "%s\r\n", prot->logout_cmd.cmd);
	    prot_flush(s->out);

	    while (prot_fgets(buf, sizeof(buf), s->in)) {
		if (!strncmp(prot->logout_cmd.resp, buf,
			     strlen(prot->logout_cmd.resp))) {
		    break;
		}
	    }
	}

	/* Flush the incoming buffer */
	prot_NONBLOCK(s->in);
	prot_fill(s->in);
    }

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
    if(s->saslconn) {
	sasl_dispose(&(s->saslconn));
	s->saslconn = NULL;
    }
}
