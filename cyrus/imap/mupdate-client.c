/* mupdate-client.c -- cyrus murder database clients
 *
 * $Id: mupdate-client.c,v 1.32.4.6 2002/12/20 18:32:05 rjs3 Exp $
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
#include "protocol.h"

const char service_name[] = "mupdate";

static sasl_security_properties_t *make_secprops(void)
{
  sasl_security_properties_t *ret =
      (sasl_security_properties_t *) xzmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize = PROT_BUFSIZE;
  ret->min_ssf = config_getint(IMAPOPT_SASL_MINIMUM_LAYER);	
  ret->max_ssf = config_getint(IMAPOPT_SASL_MAXIMUM_LAYER);

  return ret;
}

int mupdate_connect(const char *server, const char *port,
		    mupdate_handle **handle,
		    sasl_callback_t *cbs)
{
    mupdate_handle *h = NULL;
    int local_cbs = 0;
    struct hostent *hp;
    struct servent *sp;
    struct sockaddr_in addr;
    int s, saslresult;
    char buf[4096];
    char *mechlist = NULL;
    sasl_security_properties_t *secprops = NULL;
    socklen_t addrsize;
    struct sockaddr_in saddr_l;
    struct sockaddr_in saddr_r;
    char localip[60], remoteip[60];
    const char *sasl_status = NULL;
    
    if(!handle)
	return MUPDATE_BADPARAM;

    /* open connection to 'server' */
    if(!server) {
	server = config_mupdate_server;
	if (server == NULL) {
	    fatal("couldn't get mupdate server name", EC_UNAVAILABLE);
	}
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
	addr.sin_port = htons(config_getint(IMAPOPT_MUPDATE_PORT));
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	syslog(LOG_ERR, "mupdate-client: connect(%s): %m", server);
	return MUPDATE_NOCONN;
    }

    h = xzmalloc(sizeof(mupdate_handle));
    *handle = h;
    h->sock = s;

    if(!cbs) {
	local_cbs = 1;
	cbs = mysasl_callbacks(config_getstring(IMAPOPT_MUPDATE_USERNAME),
			       config_getstring(IMAPOPT_MUPDATE_AUTHNAME),
			       config_getstring(IMAPOPT_MUPDATE_REALM),
			       config_getstring(IMAPOPT_MUPDATE_PASSWORD));
    }

    /* set the IP addresses */
    addrsize=sizeof(struct sockaddr_in);
    if (getpeername(h->sock,(struct sockaddr *)&saddr_r,&addrsize)!=0)
	goto noconn;

    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(h->sock,(struct sockaddr *)&saddr_l,&addrsize)!=0)
	goto noconn;

    if(iptostring((const struct sockaddr *)&saddr_l, sizeof(struct sockaddr_in),
		  localip, 60) != 0)
	goto noconn;
    
    if(iptostring((const struct sockaddr *)&saddr_r, sizeof(struct sockaddr_in),
		  remoteip, 60) != 0)
	goto noconn;

    saslresult = sasl_client_new(service_name,
				 server,
				 localip, remoteip,
				 cbs,
				 0,
				 &(h->saslconn));
    if(saslresult != SASL_OK) goto noconn;

    secprops = make_secprops();
    if(!secprops) goto noconn;
    
    saslresult=sasl_setprop(h->saslconn, SASL_SEC_PROPS, secprops);
    if(saslresult != SASL_OK) goto noconn;
    free(secprops);

    /* create protstream */
    h->pin = prot_new(h->sock, 0);
    h->pout = prot_new(h->sock, 1);

    prot_setflushonread(h->pin, h->pout);
    prot_settimeout(h->pin, 30*60);

    /* Read the mechlist & other capabilities */
    while(1) {
	if (!prot_fgets(buf, sizeof(buf)-1, h->pin)) {
	    goto noconn;
	}

	if(!strncmp(buf, "* AUTH", 6)) {
	    mechlist = xstrdup(buf + 6);
	} else if(!strncmp(buf, "* OK MUPDATE", 12)) {
	    break;
	}
    }

    if(!mechlist) {
	syslog(LOG_ERR, "no AUTH banner from remote");
	mupdate_disconnect(handle);
	free_callbacks(cbs);
	return MUPDATE_NOAUTH;
    }
    
    if (h->saslcompleted || 
	saslclient(h->saslconn, &protocol[PROTOCOL_MUPDATE].sasl_cmd,
		   mechlist, h->pin, h->pout, NULL, &sasl_status) != SASL_OK) {
	syslog(LOG_ERR, "authentication to remote mupdate server failed: %s",
	       sasl_status ? sasl_status : "already authenticated");
	free(mechlist);
	mupdate_disconnect(handle);
	free_callbacks(cbs);
	return MUPDATE_NOAUTH;
    }

    free(mechlist);

    /* xxx unclear that this is correct, but it prevents a memory leak */
    if(local_cbs) free_callbacks(cbs);
    
    prot_setsasl(h->pin, h->saslconn);
    prot_setsasl(h->pout, h->saslconn);

    h->saslcompleted = 1;

    /* SUCCESS */
    return 0;

 noconn:
    if(mechlist) free(mechlist);
    if(secprops) free(secprops);
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

    if(h->pout) {
	prot_printf(h->pout, "L01 LOGOUT\r\n");
	prot_flush(h->pout);
    }
    
    freebuf(&(h->tag));
    freebuf(&(h->cmd));
    freebuf(&(h->arg1));
    freebuf(&(h->arg2));
    freebuf(&(h->arg3));
    
    if(h->pin) prot_free(h->pin);
    if(h->pout) prot_free(h->pout);
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
	return MUPDATE_FAIL_RESERVE;
    } else {
	return 0;
    }
}

int mupdate_deactivate(mupdate_handle *handle,
		       const char *mailbox, const char *server)
{
    int ret;
    int called = 0;
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    prot_printf(handle->pout,
		"X%u DEACTIVATE {%d+}\r\n%s {%d+}\r\n%s\r\n",
		handle->tagn++, strlen(mailbox), mailbox, 
		strlen(server), server);

    ret = mupdate_scarf(handle, mupdate_scarf_one, &called, 1, &response);
    if (ret) {
	return ret;
    } else if (response != MUPDATE_OK) {
	return MUPDATE_FAIL_RESERVE;
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

    /* coyp the data to the handle storage */
    /* xxx why can't we just point to the 'mdata' buffers? */
    strlcpy(h->mailbox_buf, mdata->mailbox, sizeof(h->mailbox_buf));
    strlcpy(h->server_buf, mdata->server, sizeof(h->server_buf));

    if(!strncmp(cmd, "MAILBOX", 7)) {
	int len = strlen(mdata->acl) + 1;
	
	h->mailboxdata_buf.t = ACTIVE;
	
	if(len > h->acl_buf_len) {
	    /* we want to at least double the buffer */
	    if (len < 2 * h->acl_buf_len) {
		len = 2 * h->acl_buf_len;
	    }

	    h->acl_buf = xrealloc(h->acl_buf, len);
	    strcpy(h->acl_buf, mdata->acl);
	}
    } else if (!strncmp(cmd, "RESERVE", 7)) {
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

    /* note that the response is still OK even if there was no data returned,
     * so we have to make sure we actually filled in the data too */
    if (!ret && response == MUPDATE_OK && handle->mailboxdata_buf.mailbox) {
	*target = &(handle->mailboxdata_buf);
	return 0;
    } else if(!ret && response == MUPDATE_OK) {
	/* it looked okay, but we didn't get a mailbox */
	*target = NULL;
	return MUPDATE_MAILBOX_UNKNOWN;
    } else {
	/* Something Bad happened */
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


int mupdate_noop(mupdate_handle *handle, mupdate_callback callback,
		 void *context)
{
    int ret;
    enum mupdate_cmd_response response;
    
    if(!handle || !callback) return MUPDATE_BADPARAM;

    prot_printf(handle->pout,
		"X%u NOOP\r\n", handle->tagn++);

    ret = mupdate_scarf(handle, callback, context, 1, &response);

    if (!ret && response == MUPDATE_OK) {
	return 0;
    } else {
	return ret ? ret : MUPDATE_FAIL;
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

    if (!handle || !callback) return MUPDATE_BADPARAM;

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
	} else if (ch == EOF) {
	    /* this was a fatal error */
	    r = MUPDATE_NOCONN;
	    goto done;
	}

	/* set it blocking so we don't get half a line */
	prot_BLOCK(handle->pin);

	if(ch != ' ') {
	    /* We always have a command */
	    syslog(LOG_ERR, "Protocol error from master: no tag");
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
