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

/* $Id: backend.c,v 1.2 2002/03/14 21:19:25 rjs3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/time.h>
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
#include "imapconf.h"
#include "xmalloc.h"
#include "iptostring.h"

static void get_capability(struct backend *s)
{
    char tag[128];
    char resp[1024];
    int st = 0;

    prot_printf(s->out, "C01 Capability\r\n");
    do {
	if (!prot_fgets(resp, sizeof(resp), s->in)) return;
	if (!strncasecmp(resp, "* Capability ", 13)) {
	    st++; /* increment state */
	    if (strstr(resp, "IDLE")) s->capability |= IDLE;
	    if (strstr(resp, "MUPDATE")) s->capability |= MUPDATE;
	} else {
	    /* line we weren't expecting. hmmm. */
	}
    } while (st == 0);
    do {
	if (!prot_fgets(resp, sizeof(resp), s->in)) return;
	if (!strncmp(resp, tag, strlen(tag))) {
	    st++; /* increment state */
	} else {
	    /* line we weren't expecting. hmmm. */
	}
    } while (st == 1);
}

static int mysasl_getauthline(struct protstream *p, char *tag,
			      char **line, unsigned int *linelen)
{
    char buf[2096];
    char *str = (char *) buf;
    
    if (!prot_fgets(str, sizeof(buf), p)) {
	return SASL_FAIL;
    }
    if (!strncmp(str, tag, strlen(tag))) {
	str += strlen(tag) + 1;
	if (!strncasecmp(str, "OK ", 3)) { return SASL_OK; }
	if (!strncasecmp(str, "NO ", 3)) { return SASL_BADAUTH; }
	return SASL_FAIL; /* huh? */
    } else if (str[0] == '+' && str[1] == ' ') {
	unsigned buflen;
	str += 2; /* jump past the "+ " */

	buflen = strlen(str) + 1;

	*line = xmalloc(buflen);
	if (*str != '\r') {	/* decode it */
	    int r;
	    
	    r = sasl_decode64(str, strlen(str), *line, buflen, linelen);
	    if (r != SASL_OK) {
		return r;
	    }
	    
	    return SASL_CONTINUE;
	} else {		/* blank challenge */
	    *line = NULL;
	    *linelen = 0;

	    return SASL_CONTINUE;
	}
    } else {
	/* huh??? */
	return SASL_FAIL;
    }
}

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);
extern void free_callbacks(sasl_callback_t *in);

static int backend_authenticate(struct backend *s, const char *userid)
{
    int r;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_in saddr_l, saddr_r;
    char remoteip[60], localip[60];
    socklen_t addrsize;
    sasl_callback_t *cb;
    char buf[2048];
    char optstr[128];
    char *in, *p;
    const char *out;
    unsigned int inlen, outlen;
    const char *mechusing;
    unsigned b64len;
    const char *pass;

    strcpy(optstr, s->hostname);
    p = strchr(optstr, '.');
    if (p) *p = '\0';
    strcat(optstr, "_password");
    pass = config_getstring(optstr, NULL);
    cb = mysasl_callbacks(userid, 
			  config_getstring("proxy_authname", "proxy"),
			  config_getstring("proxy_realm", NULL),
			  pass);

    /* set the IP addresses */
    addrsize=sizeof(struct sockaddr_in);
    if (getpeername(s->sock, (struct sockaddr *)&saddr_r, &addrsize) != 0)
	return SASL_FAIL;
    if(iptostring((struct sockaddr *)&saddr_r, sizeof(struct sockaddr_in),
		  remoteip, 60) != 0)
	return SASL_FAIL;
  
    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(s->sock, (struct sockaddr *)&saddr_l, &addrsize)!=0)
	return SASL_FAIL;
    if(iptostring((struct sockaddr *)&saddr_l, sizeof(struct sockaddr_in),
		  localip, 60) != 0)
	return SASL_FAIL;

    r = sasl_client_new("imap", s->hostname, localip, remoteip,
			cb, 0, &s->saslconn);
    if (r != SASL_OK) {
	return r;
    }

    secprops = mysasl_secprops(0);
    r = sasl_setprop(s->saslconn, SASL_SEC_PROPS, secprops);
    if (r != SASL_OK) {
	return r;
    }

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), s->in)) {
	syslog(LOG_ERR,
	       "backend_authenticate(): couldn't read initial greeting: %s",
	       s->in->error ? s->in->error : "(null)");
	return SASL_FAIL;
    }

    strcpy(buf, s->hostname);
    p = strchr(buf, '.');
    *p = '\0';
    strcat(buf, "_mechs");

    /* we now do the actual SASL exchange */
    r = sasl_client_start(s->saslconn, config_getstring(buf, "KERBEROS_V4"),
			  NULL, NULL, NULL, &mechusing);
    if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
	return r;
    }
    prot_printf(s->out, "A01 AUTHENTICATE %s\r\n", mechusing);

    in = NULL;
    inlen = 0;
    r = mysasl_getauthline(s->in, "A01", &in, &inlen);
    while (r == SASL_CONTINUE) {
	r = sasl_client_step(s->saslconn, in, inlen, NULL, &out, &outlen);
	if (in) { 
	    free(in);
	}
	if (r != SASL_OK && r != SASL_CONTINUE) {
	    return r;
	}

	r = sasl_encode64(out, outlen, buf, sizeof(buf), &b64len);
	if (r != SASL_OK) {
	    return r;
	}

	prot_write(s->out, buf, b64len);
	prot_printf(s->out, "\r\n");

	r = mysasl_getauthline(s->in, "A01", &in, &inlen);
    }

    free_callbacks(cb);

    if (r == SASL_OK) {
	prot_setsasl(s->in, s->saslconn);
	prot_setsasl(s->out, s->saslconn);
    }

    /* r == SASL_OK on success */
    return r;
}

struct backend *findserver(struct backend *ret, const char *server,
			   const char *userid) 
{
    /* need to (re)establish connection to server or create one */
    int sock;
    int r;

    if (!ret) {
	struct hostent *hp;

	ret = xmalloc(sizeof(struct backend));
	memset(ret, 0, sizeof(struct backend));
	ret->hostname = xstrdup(server);
	if ((hp = gethostbyname(server)) == NULL) {
	    syslog(LOG_ERR, "gethostbyname(%s) failed: %m", server);
	    free(ret);
	    return NULL;
	}
	ret->addr.sin_family = AF_INET;
	memcpy(&ret->addr.sin_addr, hp->h_addr, hp->h_length);
	ret->addr.sin_port = htons(143);

	ret->timeout = NULL;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "socket() failed: %m");
	free(ret);
	return NULL;
    }
    if (connect(sock, (struct sockaddr *) &ret->addr, 
		sizeof(ret->addr)) < 0) {
	syslog(LOG_ERR, "connect(%s) failed: %m", server);
	free(ret);
	return NULL;
    }
    
    ret->in = prot_new(sock, 0);
    ret->out = prot_new(sock, 1);
    ret->sock = sock;
    prot_setflushonread(ret->in, ret->out);
    
    /* now need to authenticate to backend server */
    if ((r = backend_authenticate(ret,userid))) {
	syslog(LOG_ERR, "couldn't authenticate to backend server: %s",
	       sasl_errstring(r, NULL, NULL));
	free(ret);
	return NULL;
    }
    
    /* find the capabilities of the server */
    get_capability(ret);
    
    return ret;
}

void downserver(struct backend *s) 
{
    char buf[1024];
    if(!s) return;
    
    prot_printf(s->out, "L01 LOGOUT\r\n");
    while (prot_fgets(buf, sizeof(buf), s->in)) {
	if (!strncmp("L01", buf, 3)) {
	    break;
	}
    }

    close(s->sock);
    prot_free(s->in);
    prot_free(s->out);
}
