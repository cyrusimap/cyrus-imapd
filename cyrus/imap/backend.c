/* backend.c -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: backend.c,v 1.7.6.14 2003/02/12 19:12:36 rjs3 Exp $ */

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
#include <com_err.h>
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
			    struct capa_cmd_t *capa_cmd,
			    int *supports_starttls)
{
    char str[4096];
    char *ret = NULL, *tmp;
    
    if (supports_starttls) *supports_starttls = 0;

    if (capa_cmd->cmd) {
	/* request capabilities of server */
	prot_printf(pout, "%s\r\n", capa_cmd->cmd);
	prot_flush(pout);
    }

    do { /* look for the end of the capabilities */
	if (prot_fgets(str, sizeof(str), pin) == NULL) {
	    return NULL;
	}

	/* check for starttls */
	if (capa_cmd->tls &&
	    strstr(str, capa_cmd->tls) != NULL) {
	    if (supports_starttls) *supports_starttls = 1;
	}
	
	/* check for auth */
	if (capa_cmd->auth &&
	    (tmp = strstr(str, capa_cmd->auth)) != NULL) {
	    if (capa_cmd->parse_mechlist)
		ret = capa_cmd->parse_mechlist(str);
	    else
		ret = strdup(tmp+strlen(capa_cmd->auth));
	}
    } while (strncasecmp(str, capa_cmd->resp, strlen(capa_cmd->resp)));
    
    return ret;
}

static int do_starttls(struct backend *s, struct tls_cmd_t *tls_cmd)
{
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
}

static int backend_authenticate(struct backend *s, struct protocol_t *prot,
				const char *userid, const char **status)
{
    int r;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_storage saddr_l, saddr_r;
    char remoteip[60], localip[60];
    socklen_t addrsize;
    sasl_callback_t *cb;
    char buf[2048], optstr[128], *p, *mechlist;
    const char *mech_conf, *pass;
    int have_starttls = 1;

    strcpy(optstr, s->hostname);
    p = strchr(optstr, '.');
    if (p) *p = '\0';
    strcat(optstr, "_password");
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

    if (prot->capa_cmd.cmd) {
	/* read the initial greeting */
	if (!prot_fgets(buf, sizeof(buf), s->in)) {
	    syslog(LOG_ERR,
		   "backend_authenticate(): couldn't read initial greeting: %s",
		   s->in->error ? s->in->error : "(null)");
	    return SASL_FAIL;
	}
    }

    /* Get SASL mechanism list.  We can force a particular
       mechanism using a <shorthost>_mechs option */

    strcpy(buf, s->hostname);
    p = strchr(buf, '.');
    if (p) *p = '\0';
    strcat(buf, "_mechs");
    mech_conf = config_getoverflowstring(buf, NULL);
    
    do {
	/* If we don't have a mech_conf, ask the server what it can do */
	if(!mech_conf) {
	    mechlist = ask_capability(s->out, s->in, &prot->capa_cmd,
				      have_starttls ? &have_starttls : NULL);
	} else {
	    mechlist = xstrdup(mech_conf);
	}

	if (mechlist) {
	    /* we now do the actual SASL exchange */
	    saslclient(s->saslconn, &prot->sasl_cmd, mechlist,
			   s->in, s->out, &r, status);

	    /* garbage collect */
	    free(mechlist);
	    mechlist = NULL;
	}
	else
	    r = SASL_NOMECH;

    } while (r == SASL_NOMECH && have_starttls-- &&
	     do_starttls(s, &prot->tls_cmd) != -1);

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

    if (!ret) {
	struct servent *serv;

	ret = xmalloc(sizeof(struct backend));
	memset(ret, 0, sizeof(struct backend));
	strlcpy(ret->hostname, server, sizeof(ret->hostname));
	if ((serv = getservbyname(prot->service, "tcp")) == NULL) {
	    syslog(LOG_ERR, "getservbyname(%s) failed: %m", prot->service);
	    free(ret);
	    return NULL;
	}
	ret->timeout = NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(server, "143", &hints, &res0);
    if (err) {
	syslog(LOG_ERR, "getaddrinfo(%s) failed: %s",
	       server, gai_strerror(err));
	free(ret);
	return NULL;
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
    
    /* now need to authenticate to backend server */
    if ((r = backend_authenticate(ret, prot, userid, auth_status))) {
	syslog(LOG_ERR, "couldn't authenticate to backend server: %s",
	       sasl_errstring(r, NULL, NULL));
	free(ret);
        close(sock);
	return NULL;
    }
    
    return ret;
}

void backend_disconnect(struct backend *s, struct protocol_t *prot)
{
    char buf[1024];
    if(!s) return;
    
    if (prot) {
	prot_printf(s->out, "%s\r\n", prot->logout_cmd.cmd);
	prot_flush(s->out);
    }

    while (prot_fgets(buf, sizeof(buf), s->in)) {
	if (!strncmp(prot->logout_cmd.resp, buf,
		     strlen(prot->logout_cmd.resp))) {
	    break;
	}
    }

    /* Flush the incoming buffer */
    prot_NONBLOCK(s->in);
    prot_fill(s->in);

    /* Free tlsconn */
    if (s->tlsconn) {
	tls_reset_servertls(&s->tlsconn);
	s->tlsconn = NULL;
    }

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
