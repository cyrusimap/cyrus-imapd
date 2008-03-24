/* mupdate-client.c -- cyrus murder database clients
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
 * $Id: mupdate-client.c,v 1.54 2008/03/24 17:09:18 murch Exp $
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
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "global.h"
#include "imparse.h"
#include "iptostring.h"
#include "mupdate.h"
#include "prot.h"
#include "protocol.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

const char service_name[] = "mupdate";

int mupdate_connect(const char *server,
		    const char *port __attribute__((unused)),
		    mupdate_handle **handle,
		    sasl_callback_t *cbs)
{
    mupdate_handle *h = NULL;
    int local_cbs = 0;
    const char *status = NULL;
    
    if(!handle)
	return MUPDATE_BADPARAM;

    /* open connection to 'server' */
    if(!server) {
	server = config_mupdate_server;
	if (server == NULL) {
	    fatal("couldn't get mupdate server name", EC_UNAVAILABLE);
	}
    }
    
    h = xzmalloc(sizeof(mupdate_handle));
    *handle = h;

    if(!cbs) {
	local_cbs = 1;
	cbs = mysasl_callbacks(config_getstring(IMAPOPT_MUPDATE_USERNAME),
			       config_getstring(IMAPOPT_MUPDATE_AUTHNAME),
			       config_getstring(IMAPOPT_MUPDATE_REALM),
			       config_getstring(IMAPOPT_MUPDATE_PASSWORD));
    }

    h->conn = backend_connect(NULL, server, &protocol[PROTOCOL_MUPDATE],
			      "", cbs, &status);

    /* xxx unclear that this is correct, but it prevents a memory leak */
    if (local_cbs) free_callbacks(cbs);

    if (!h->conn) {
        syslog(LOG_ERR, "mupdate_connect failed: %s", status ? status : "unknown error");
	return MUPDATE_NOCONN;
    }
    
    h->saslcompleted = 1;

    /* SUCCESS */
    return 0;
}

void mupdate_disconnect(mupdate_handle **hp)
{
    mupdate_handle *h;

    if(!hp || !(*hp)) return;
    h = *hp;

    backend_disconnect(h->conn);
    free(h->conn);

    freebuf(&(h->tag));
    freebuf(&(h->cmd));
    freebuf(&(h->arg1));
    freebuf(&(h->arg2));
    freebuf(&(h->arg3));

    if(h->acl_buf) free(h->acl_buf);

    free(h); 
    *hp = NULL;
}

/* We're really only looking for an OK or NO or BAD here -- and the callback
 * is never called in those cases.  So if the callback is called, we have
 * an error! */
static int mupdate_scarf_one(struct mupdate_mailboxdata *mdata __attribute__((unused)),
			     const char *cmd,
			     void *context __attribute__((unused))) 
{
    syslog(LOG_ERR, "mupdate_scarf_one was called, but shouldn't be.  Command recieved was %s", cmd);
    return -1;
}

int mupdate_activate(mupdate_handle *handle, 
		     const char *mailbox, const char *server,
		     const char *acl)
{
    int ret;
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server || !acl) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
	/* we don't care about the server part, everything is local */
	const char *part = strchr(server, '!');

	if (part) server = part + 1;
    }

    prot_printf(handle->conn->out,
		"X%u ACTIVATE {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n", 
		handle->tagn++, strlen(mailbox), mailbox, 
		strlen(server), server, strlen(acl), acl);

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
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
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
	/* we don't care about the server part, everything is local */
	const char *part = strchr(server, '!');

	if (part) server = part + 1;
    }

    prot_printf(handle->conn->out,
		"X%u RESERVE {%d+}\r\n%s {%d+}\r\n%s\r\n",
		handle->tagn++, strlen(mailbox), mailbox, 
		strlen(server), server);

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
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
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
	/* we don't care about the server part, everything is local */
	const char *part = strchr(server, '!');

	if (part) server = part + 1;
    }

    prot_printf(handle->conn->out,
		"X%u DEACTIVATE {%d+}\r\n%s {%d+}\r\n%s\r\n",
		handle->tagn++, strlen(mailbox), mailbox, 
		strlen(server), server);

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
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
    enum mupdate_cmd_response response;
    
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    prot_printf(handle->conn->out,
		"X%u DELETE {%d+}\r\n%s\r\n", handle->tagn++, 
		strlen(mailbox), mailbox);

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
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
	size_t len = strlen(mdata->acl) + 1;
	
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

    prot_printf(handle->conn->out,
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
	prot_printf(handle->conn->out,
		    "X%u LIST {%d+}\r\n%s\r\n", handle->tagn++,
		    strlen(prefix), prefix);
    } else {
	prot_printf(handle->conn->out,
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

    prot_printf(handle->conn->out,
		"X%u NOOP\r\n", handle->tagn++);

    ret = mupdate_scarf(handle, callback, context, 1, &response);

    if (!ret && response == MUPDATE_OK) {
	return 0;
    } else {
	return ret ? ret : MUPDATE_FAIL;
    }
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->conn->in); \
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
	char *p;
    
	if (wait_for_ok) {
	    prot_BLOCK(handle->conn->in);
	} else {
	    /* check for input */
	    prot_NONBLOCK(handle->conn->in);
	    ch = prot_getc(handle->conn->in);

	    if(ch == EOF && errno == EAGAIN) {
		/* this was just "no input" we return 0 */
		goto done;
	    } else if(ch == EOF) {
		/* this was a fatal error */
		r = MUPDATE_NOCONN;
		goto done;
	    } else {
		/* there's input waiting, put back our character */
		prot_ungetc(ch, handle->conn->in);
	    }

	    /* Set it back to blocking so we don't get half a word */
	    prot_BLOCK(handle->conn->in);
	}

	ch = getword(handle->conn->in, &(handle->tag));
	if (ch == EOF) {
	    /* this was a fatal error */
	    r = MUPDATE_NOCONN;
	    goto done;
	}

	if(ch != ' ') {
	    /* We always have a command */
	    syslog(LOG_ERR, "Protocol error from master: no tag");
	    r = MUPDATE_PROTOCOL_ERROR;
	    goto done;
	}
	ch = getword(handle->conn->in, &(handle->cmd));
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
	    if(!strncmp(handle->cmd.s, "BAD", 3)) {
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
		CHECKNEWLINE(handle, ch);

		syslog(LOG_ERR, "mupdate BAD response: %s", handle->arg1.s);
		if (wait_for_ok && response) {
		    *response = MUPDATE_BAD;
		}
		goto done;
	    } else if (!strncmp(handle->cmd.s, "BYE", 3)) {
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
		CHECKNEWLINE(handle, ch);
		
		syslog(LOG_ERR, "mupdate BYE response: %s", handle->arg1.s);
		if(wait_for_ok && response) {
		    *response = MUPDATE_BYE;
		}
		goto done;
	    }
	    goto badcmd;

	case 'D':
	    if(!strncmp(handle->cmd.s, "DELETE", 6)) {
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
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
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
		if(ch != ' ') { 
		    r = MUPDATE_PROTOCOL_ERROR;
		    goto done;
		}
		
		/* Server */
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg2));
		if(ch != ' ') {
		    r = MUPDATE_PROTOCOL_ERROR;
		    goto done;
		}
		
		/* ACL */
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg3));
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
	    if(!strncmp(handle->cmd.s, "NO", 2)) {
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
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
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
		
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
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
		if(ch != ' ') {
		    r = MUPDATE_PROTOCOL_ERROR;
		    goto done;
		}
		
		/* Server */
		ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg2));
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
    prot_NONBLOCK(handle->conn->in);

    return r;
}

void kick_mupdate(void)
{
    char buf[2048];
    struct sockaddr_un srvaddr;
    int s, r;
    int len;
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	return;
    }

    strlcpy(buf, config_dir, sizeof(buf));
    strlcat(buf, FNAME_MUPDATE_TARGET_SOCK, sizeof(buf));
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, buf);
    len = sizeof(srvaddr.sun_family) + strlen(srvaddr.sun_path) + 1;

    r = connect(s, (struct sockaddr *)&srvaddr, len);
    if (r == -1) {
	syslog(LOG_ERR, "kick_mupdate: can't connect to target: %m");
	goto done;
    }

    r = read(s, buf, sizeof(buf));
    if (r <= 0) {
	syslog(LOG_ERR, "kick_mupdate: can't read from target: %m");
    }

 done:
    close(s);
    return;
}
