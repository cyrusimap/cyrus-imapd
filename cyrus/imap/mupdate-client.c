/* mupdate-client.c -- cyrus murder database clients
 *
 * $Id: mupdate-client.c,v 1.19 2002/02/02 21:23:21 leg Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <syslog.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "prot.h"
#include "xmalloc.h"
#include "imapconf.h"
#include "assert.h"
#include "imparse.h"
#include "iptostring.h"
#include "mupdate.h"
#include "mupdate_err.h"
#include "exitcodes.h"

const char service_name[] = "mupdate";

extern sasl_callback_t *mysasl_callbacks(const char *username,
                                         const char *authname,
                                         const char *realm,
                                         const char *password);

static sasl_security_properties_t *make_secprops(int min, int max)
{
  sasl_security_properties_t *ret =
      (sasl_security_properties_t *) xzmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize = 4000; /* xxx */
  ret->min_ssf = config_getint("sasl_minimum_layer", min);	
  ret->max_ssf = config_getint("sasl_maximum_layer", max);

  return ret;
}

static int mupdate_authenticate(mupdate_handle *h,
				const char *mechlist)
{
    int saslresult;
    sasl_security_properties_t *secprops=NULL;
    socklen_t addrsize;
    struct sockaddr_in saddr_l;
    struct sockaddr_in saddr_r;
    char localip[60], remoteip[60];
    const char *out;
    unsigned int outlen;
    const char *mechusing;
    int ch;
    char buf[4096];

    /* Why do this again? */
    if (h->saslcompleted) {
	return 1;
    }

    secprops = make_secprops(0, 256);
    if(!secprops) return 1;
    
    saslresult=sasl_setprop(h->saslconn, SASL_SEC_PROPS, secprops);
    if(saslresult != SASL_OK) return 1;
    free(secprops);
    
    addrsize=sizeof(struct sockaddr_in);
    if (getpeername(h->sock,(struct sockaddr *)&saddr_r,&addrsize)!=0)
	return 1;

    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(h->sock,(struct sockaddr *)&saddr_l,&addrsize)!=0)
	return 1;

    if(iptostring((const struct sockaddr *)&saddr_l, sizeof(struct sockaddr_in),
		  localip, 60) != 0)
	return 1;
    
    if(iptostring((const struct sockaddr *)&saddr_r, sizeof(struct sockaddr_in),
		  remoteip, 60) != 0)
	return 1;

    saslresult=sasl_setprop(h->saslconn, SASL_IPREMOTEPORT, remoteip);
    if (saslresult!=SASL_OK) return 1;

    saslresult=sasl_setprop(h->saslconn, SASL_IPLOCALPORT, localip);
    if (saslresult!=SASL_OK) return 1;

    /* We shouldn't get sasl_interact's,
     * because we provide explicit callbacks */
    saslresult = sasl_client_start(h->saslconn, mechlist,
				   NULL, &out, &outlen, &mechusing);

    if(saslresult != SASL_OK && saslresult != SASL_CONTINUE) return 1;

    if(out) {
	int r = sasl_encode64(out, outlen,
			      buf, sizeof(buf), NULL);
	if(r != SASL_OK) return 1;
	
	/* it's always ok to send the mechname quoted */
	prot_printf(h->pout, "A01 AUTHENTICATE \"%s\" {%d+}\r\n%s\r\n",
		    mechusing, strlen(buf), buf);
    } else {
        prot_printf(h->pout, "A01 AUTHENTICATE \"%s\"\r\n", mechusing);
    }

    while(saslresult == SASL_CONTINUE) {
	char *p, *in;
	unsigned int len, inlen;
	
	if(!prot_fgets(buf, sizeof(buf)-1, h->pin)) {
	    /* Connection Dropped */
	    return 1;
	}

	p = buf + strlen(buf) - 1;
	if(p >= buf && *p == '\n') *p-- = '\0';
	if(p >= buf && *p == '\r') *p-- = '\0';

	len = strlen(buf);
	in = xmalloc(len);
	saslresult = sasl_decode64(buf, len, in, len, &inlen);
	if(saslresult != SASL_OK) {
	    free(in);

	    /* CANCEL */
	    syslog(LOG_ERR, "couldn't base64 decode: aborted authentication");

	    /* If we haven't already canceled due to bad authentication,
	     * then we should */
	    if(strncmp(buf, "A01 NO ", 7)) prot_printf(h->pout, "*");
	    else {
		syslog(LOG_ERR,
		       "Authentication to master failed (%s)", buf+7);
	    }
	    return 1;
	}

	saslresult = sasl_client_step(h->saslconn, in, inlen, NULL,
				      &out, &outlen);
	free(in);

	if((saslresult == SASL_OK || saslresult == SASL_CONTINUE) && out) {
	    int r = sasl_encode64(out, outlen,
				  buf, sizeof(buf), NULL);
	    if(r != SASL_OK) return 1;
	    
	    prot_printf(h->pout, "%s\r\n", buf);
	}
    }

    if(saslresult != SASL_OK) {
	syslog(LOG_ERR, "bad authentication: %s",
	       sasl_errdetail(h->saslconn));
	
	prot_printf(h->pout, "*");
	return 1;
    }

    /* Check Result */
    ch = getword(h->pin, &(h->tag));
    if(ch != ' ') return 1; /* need an OK or NO */

    ch = getword(h->pin, &(h->cmd));
    if(!strncmp(h->cmd.s, "NO", 2)) {
	if(ch != ' ') return 1; /* no reason really necessary, but we failed */
	ch = getstring(h->pin, h->pout, &(h->arg1));
	syslog(LOG_ERR, "authentication failed: %s", h->arg1.s);
	return 1;
    }

    prot_setsasl(h->pin, h->saslconn);
    prot_setsasl(h->pout, h->saslconn);

    h->saslcompleted = 1;

    return 0; /* SUCCESS */
}

int mupdate_connect(const char *server, const char *port,
		    mupdate_handle **handle,
		    sasl_callback_t *cbs)
{
    mupdate_handle *h;
    struct hostent *hp;
    struct servent *sp;
    struct sockaddr_in addr;
    int s, saslresult;
    char buf[4096];
    char *mechlist;
    
    if(!handle)
	return MUPDATE_BADPARAM;

    /* open connection to 'server' */
    if(!server) {
	server = config_getstring("mupdate_server", NULL);
	if (server == NULL) {
	    fatal("couldn't get mupdate server name", EC_UNAVAILABLE);
	}
    }
    if(!port) {
	port = config_getstring("mupdate_port",NULL);
    }
    
    hp = gethostbyname(server);
    if (!hp) {
	syslog(LOG_ERR, "mupdate-client: gethostbyname %s failed: %m", server);
	return MUPDATE_NOCONN;
    }
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "mupdate-client: socket(): %m");
	return MUPDATE_NOCONN;
    }
    
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, hp->h_addr, sizeof(addr.sin_addr));

    if (port && imparse_isnumber(port)) {
	addr.sin_port = htons(atoi(port));
    } else if (port) {
	sp = getservbyname(port, "tcp");
	if (!sp) {
	    syslog(LOG_ERR, "mupdate-client: getservbyname(tcp, %s): %m",
		   port);
	}
	addr.sin_port = sp->s_port;
    } else if((sp = getservbyname("mupdate", "tcp")) != NULL) {
	addr.sin_port = sp->s_port;
    } else {
	addr.sin_port = htons(2004);
    }

    h = xzmalloc(sizeof(mupdate_handle));
    *handle = h;
    h->sock = s;

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	syslog(LOG_ERR, "mupdate-client: connect(%s): %m", server);
	return MUPDATE_NOCONN;
    }

    if(!cbs) {
	cbs = mysasl_callbacks(config_getstring("mupdate_username",""),
			       config_getstring("mupdate_authname",NULL),
			       config_getstring("mupdate_realm",NULL),
			       config_getstring("mupdate_password",NULL));
    }

    saslresult = sasl_client_new(service_name,
				 server,
				 NULL, NULL,
				 cbs,
				 0,
				 &(h->saslconn));

    /* create protstream */
    h->pin = prot_new(h->sock, 0);
    h->pout = prot_new(h->sock, 1);

    prot_setflushonread(h->pin, h->pout);
    prot_settimeout(h->pin, 30*60);

    /* Read the banner */
    if(!prot_fgets(buf, sizeof(buf)-1, h->pin)) {
	goto noconn;
    }

    if(strncmp(buf, "* OK MUPDATE", 12)) {
	syslog(LOG_ERR, 
	       "mupdate-client: invalid banner from remote server: %s", buf);
	mupdate_disconnect(handle);
	return MUPDATE_PROTOCOL_ERROR;
    }

    /* Read the mechlist */
    if (!prot_fgets(buf, sizeof(buf)-1, h->pin)) {
	goto noconn;
    }

    if(strncmp(buf, "* AUTH", 6)) {
	syslog(LOG_ERR, 
	       "mupdate-client: remote server did not send AUTH banner: %s",
	       buf);
	mupdate_disconnect(handle);
	return MUPDATE_PROTOCOL_ERROR;
    }

    mechlist = buf + 6;
    
    if (mupdate_authenticate(h, mechlist)) {
	syslog(LOG_ERR, "authentication to remote mupdate server failed");
	mupdate_disconnect(handle);
	return MUPDATE_NOAUTH;
    }

    /* SUCCESS */
    return 0;

 noconn:
    syslog(LOG_ERR, "mupdate-client: connection to server closed: %s",
	   prot_error(h->pin));
    mupdate_disconnect(handle);

    return MUPDATE_NOCONN;
}

void mupdate_disconnect(mupdate_handle **hp)
{
    mupdate_handle *h;

    if(!hp || !(*hp)) return;
    h = *hp;

    prot_printf(h->pout, "L01 LOGOUT\r\n");
    prot_flush(h->pout);

    freebuf(&(h->tag));
    freebuf(&(h->cmd));
    freebuf(&(h->arg1));
    freebuf(&(h->arg2));
    freebuf(&(h->arg3));
    
    prot_free(h->pin);
    prot_free(h->pout);
    sasl_dispose(&(h->saslconn));
    close(h->sock);

    if(h->acl_buf) free(h->acl_buf);

    free(h); 
    *hp = NULL;
}

/* We're really only looking for an OK or NO or BAD here */
static int mupdate_scarf_one(struct mupdate_mailboxdata *mdata __attribute__((unused)),
			     const char *cmd,
			     void *context) 
{
    int *called = context;
    
    if(*called) {
	/* Only want to be called once per command */
	return -1;
    }
    *called = 1;

    /*only accept OK, NO and BAD */
    if(strncmp(cmd, "OK", 2)) {
	return 0;
    } else if (strncmp(cmd, "NO", 2) || strncmp(cmd, "BAD", 3)) {
	return -1;
    } else {
	return 1;
    }
}


int mupdate_activate(mupdate_handle *handle, 
		     const char *mailbox, const char *server,
		     const char *acl)
{
    int ret;
    int called = 0;
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server || !acl) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    prot_printf(handle->pout,
		"X%u ACTIVATE {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n", 
		handle->tagn++, strlen(mailbox), mailbox, 
		strlen(server), server, strlen(acl), acl);

    ret = mupdate_scarf(handle, mupdate_scarf_one, &called, 1, &response);
    if (ret) {
	return ret;
    } else if (response != MUPDATE_OK) {
	return MUPDATE_FAIL;
    } else {
	return 0;
    }
}

int mupdate_reserve(mupdate_handle *handle,
		    const char *mailbox, const char *server)
{
    int ret;
    int called = 0;
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    prot_printf(handle->pout,
		"X%u RESERVE {%d+}\r\n%s {%d+}\r\n%s\r\n",
		handle->tagn++, strlen(mailbox), mailbox, 
		strlen(server), server);

    ret = mupdate_scarf(handle, mupdate_scarf_one, &called, 1, &response);
    if (ret) {
	return ret;
    } else if (response != MUPDATE_OK) {
	return MUPDATE_FAIL;
    } else {
	return 0;
    }
}

int mupdate_delete(mupdate_handle *handle,
		   const char *mailbox)
{
    int ret;
    int called = 0;
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    prot_printf(handle->pout,
		"X%u DELETE {%d+}\r\n%s\r\n", handle->tagn++, 
		strlen(mailbox), mailbox);

    ret = mupdate_scarf(handle, mupdate_scarf_one, &called, 1, &response);
    if (ret) {
	return ret;
    } else if (response != MUPDATE_OK) {
	return MUPDATE_FAIL;
    } else {
	return 0;
    }
}


static int mupdate_find_cb(struct mupdate_mailboxdata *mdata,
			   const char *cmd, void *context) 
{
    struct mupdate_handle_s *h = (struct mupdate_handle_s *)context;

    if(!h || !cmd || !mdata) return 1;

    if(!strncmp(cmd, "MAILBOX", 7)) {
	int len = strlen(mdata->acl) + 1;
	
	h->mailboxdata_buf.t = ACTIVE;
	
	if(len > h->acl_buf_len) {
	    if(len < 2*h->acl_buf_len)
		len = 2 * h->acl_buf_len;

	    h->acl_buf = xrealloc(h->acl_buf, len);
	    strcpy(h->acl_buf, mdata->acl);
	}
    } else if(!strncmp(cmd, "RESERVE", 7)) {
	h->mailboxdata_buf.t = RESERVE;
	if(!h->acl_buf) {
	    h->acl_buf = xstrdup("");
	    h->acl_buf_len = 1;
	} else {
	    h->acl_buf[0] = '\0';
	}
    } else {
	/* Bad command */
	return 1;
    }
   
    h->mailboxdata_buf.mailbox = h->mailbox_buf;
    h->mailboxdata_buf.server = h->server_buf;
    h->mailboxdata_buf.acl = h->acl_buf;
    
    return 0;
}

int mupdate_find(mupdate_handle *handle, const char *mailbox,
		 struct mupdate_mailboxdata **target) 
{
    int ret;
    enum mupdate_cmd_response response;
    
    if(!handle || !mailbox || !target) return MUPDATE_BADPARAM;

    prot_printf(handle->pout,
		"X%u FIND {%d+}\r\n%s\r\n", handle->tagn++, 
		strlen(mailbox), mailbox);

    memset(&(handle->mailboxdata_buf), 0, sizeof(handle->mailboxdata_buf));

    ret = mupdate_scarf(handle, mupdate_find_cb, handle, 1, &response);

    if (!ret && response == MUPDATE_OK) {
	*target = &(handle->mailboxdata_buf);
	return 0;
    } else {
	*target = NULL;
	return ret ? ret : MUPDATE_FAIL;
    }
}

int mupdate_list(mupdate_handle *handle, mupdate_callback callback,
		 const char *prefix, void *context) 
{
    int ret;
    enum mupdate_cmd_response response;
    
    if(!handle || !callback) return MUPDATE_BADPARAM;

    if(prefix) {
	prot_printf(handle->pout,
		    "X%u LIST {%d+}\r\n%s\r\n", handle->tagn++,
		    strlen(prefix), prefix);
    } else {
	prot_printf(handle->pout,
		    "X%u LIST\r\n", handle->tagn++);
    }
     
    ret = mupdate_scarf(handle, callback, context, 1, &response);

    if (ret) {
	return ret;
    } else if (response != MUPDATE_OK) {
	return MUPDATE_FAIL;
    } else {
	return 0;
    }
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->pin); \
                                 if ((ch) != '\n') { syslog(LOG_ERR, \
                             "extra arguments recieved, aborting connection");\
                                 r = MUPDATE_PROTOCOL_ERROR;\
                                 goto done; }} while(0)

/* Scarf up the incoming data and perform the requested operations */
int mupdate_scarf(mupdate_handle *handle, 
		  mupdate_callback callback,
		  void *context, 
		  int wait_for_ok, 
		  enum mupdate_cmd_response *response)
{
    struct mupdate_mailboxdata box;
    int r = 0;

    if (!handle || !callback) return 1;

    /* keep going while we have input or if we're waiting for an OK */
    while (!r) {
	int ch;
	unsigned char *p;
    
	if (wait_for_ok) {
	    prot_BLOCK(handle->pin);
	} else {
	    prot_NONBLOCK(handle->pin);
	}
	ch = getword(handle->pin, &(handle->tag));
	if (ch == EOF && errno == EAGAIN) {
	    /* this was just "no input" we return 0 */
	    goto done;
	} else {
	    /* this was a fatal error, return 1 */
	    r = MUPDATE_NOCONN;
	    goto done;
	}

	/* set it blocking so we don't get half a line */
	prot_BLOCK(handle->pin);

	if(ch != ' ') {
	    /* We always have a command */
	    syslog(LOG_ERR, "Protocol error from master: no tag",
		   handle->tag.s, ch);
	    r = MUPDATE_PROTOCOL_ERROR;
	    goto done;
	}
	ch = getword(handle->pin, &(handle->cmd));
	if(ch != ' ') {
	    /* We always have an argument */
	    syslog(LOG_ERR, "Protocol error from master: no keyword");
	    r = MUPDATE_PROTOCOL_ERROR;
	    break;
	}
	
	if (islower((unsigned char) handle->cmd.s[0])) {
	    handle->cmd.s[0] = toupper((unsigned char) handle->cmd.s[0]);
	}
	for (p = &(handle->cmd.s[1]); *p; p++) {
	    if (islower((unsigned char) *p))
		*p = toupper((unsigned char) *p);
	}
	
	switch(handle->cmd.s[0]) {
	case 'B':
	    if(!strncmp(handle->cmd.s, "BAD", 6)) {
		ch = getstring(handle->pin, handle->pout, &(handle->arg1));
		CHECKNEWLINE(handle, ch);

		syslog(LOG_DEBUG, "mupdate BAD response: %s", handle->arg1.s);
		if (wait_for_ok && response) {
		    *response = MUPDATE_BAD;
		}
		goto done;
	    }
	    goto badcmd;

	case 'D':
	    if(!strncmp(handle->cmd.s, "DELETE", 6)) {
		ch = getstring(handle->pin, handle->pout, &(handle->arg1));
		CHECKNEWLINE(handle, ch);

		memset(&box, 0, sizeof(box));
		box.mailbox = handle->arg1.s;

		/* Handle delete command */
		r = callback(&box, handle->cmd.s, context);
		if (r) {
		    syslog(LOG_ERR, 
			   "error deleting mailbox: callback returned %d", r);
		    goto done;
		}
		break;
	    }
	    goto badcmd;

	case 'M':
	    if(!strncmp(handle->cmd.s, "MAILBOX", 7)) {
		/* Mailbox Name */
		ch = getstring(handle->pin, handle->pout, &(handle->arg1));
		if(ch != ' ') { 
		    r = MUPDATE_PROTOCOL_ERROR;
		    goto done;
		}
		
		/* Server */
		ch = getstring(handle->pin, handle->pout, &(handle->arg2));
		if(ch != ' ') {
		    r = MUPDATE_PROTOCOL_ERROR;
		    goto done;
		}
		
		/* ACL */
		ch = getstring(handle->pin, handle->pout, &(handle->arg3));
		CHECKNEWLINE(handle, ch);
		
		/* Handle mailbox command */
		memset(&box, 0, sizeof(box));
		box.mailbox = handle->arg1.s;
		box.server = handle->arg2.s;
		box.acl = handle->arg3.s;
		r = callback(&box, handle->cmd.s, context);
		if (r) { /* callback error ? */
		    syslog(LOG_ERR, 
			   "error activating mailbox: callback returned %d", r);
		    goto done;
		}
		break;
	    }
	    goto badcmd;
	case 'N':
	    if(!strncmp(handle->cmd.s, "NO", 6)) {
		ch = getstring(handle->pin, handle->pout, &(handle->arg1));
		CHECKNEWLINE(handle, ch);

		syslog(LOG_DEBUG, "mupdate NO response: %s", handle->arg1.s);
		if (wait_for_ok) {
		    if (response) *response = MUPDATE_NO;
		    goto done;
		}
		break;
	    }
	    goto badcmd;
	case 'O':
	    if(!strncmp(handle->cmd.s, "OK", 2)) {
		/* It's all good, grab the attached string and move on */
		ch = getstring(handle->pin, handle->pout, &(handle->arg1));
		
		CHECKNEWLINE(handle, ch);
		if (wait_for_ok) {
		    if (response) *response = MUPDATE_OK;
		    goto done;
		}
		break;
	    }
	    goto badcmd;
	case 'R':
	    if(!strncmp(handle->cmd.s, "RESERVE", 7)) {
		/* Mailbox Name */
		ch = getstring(handle->pin, handle->pout, &(handle->arg1));
		if(ch != ' ') {
		    r = MUPDATE_PROTOCOL_ERROR;
		    goto done;
		}
		
		/* Server */
		ch = getstring(handle->pin, handle->pout, &(handle->arg2));
		CHECKNEWLINE(handle, ch);
		
		/* Handle reserve command */
		memset(&box, 0, sizeof(box));
		box.mailbox = handle->arg1.s;
		box.server = handle->arg2.s;
		r = callback(&box, handle->cmd.s, context);
		if (r) { /* callback error ? */
		    syslog(LOG_ERR, 
			   "error reserving mailbox: callback returned %d", r);
		    goto done;
		}
		
		break;
	    }
	    goto badcmd;

	default:
	badcmd:
	    /* Bad Command */
	    syslog(LOG_ERR, "bad/unexpected command from master: %s",
		   handle->cmd.s);
	    r = MUPDATE_PROTOCOL_ERROR;
	    goto done;
	}
    }

 done:
    /* reset blocking */
    prot_NONBLOCK(handle->pin);

    return r;
}
