/* saslclient.c -- shared SASL code for server-server authentication
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: saslclient.c,v 1.9.6.2 2002/12/16 01:28:56 ken3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <syslog.h>

#include "xmalloc.h"
#include "prot.h"
#include "imap_err.h"
#include "saslclient.h"


static int mysasl_simple_cb(void *context, int id, const char **result,
			    unsigned int *len)
{
    if (!result) {
	return SASL_BADPARAM;
    }

    switch (id) {
    case SASL_CB_USER:
	*result = (char *) context;
	break;
    case SASL_CB_AUTHNAME:
	*result = (char *) context;
	break;
    case SASL_CB_LANGUAGE:
	*result = NULL;
	break;
    default:
	return SASL_BADPARAM;
    }
    if (len) {
	*len = *result ? strlen(*result) : 0;
    }

    return SASL_OK;
}

static int mysasl_getrealm_cb(void *context, int id,
			      const char **availrealms __attribute__((unused)),
			      const char **result)
{
    if (id != SASL_CB_GETREALM || !result) {
	return SASL_BADPARAM;
    }

    *result = (char *) context;
    return SASL_OK;
}

static int mysasl_getsecret_cb(sasl_conn_t *conn,
			       void *context,
			       int id,
			       sasl_secret_t **result)
{
    if (!conn || !result || id != SASL_CB_PASS) {
	return SASL_BADPARAM;
    }

    *result = (sasl_secret_t *)context;

    return SASL_OK;
}

sasl_callback_t *mysasl_callbacks(const char *username,
				  const char *authname,
				  const char *realm,
				  const char *password)
{
    sasl_callback_t *ret = xmalloc(5 * sizeof(sasl_callback_t));
    int n = 0;

    if (username) {
	/* user callback */
	ret[n].id = SASL_CB_USER;
	ret[n].proc = &mysasl_simple_cb;
	ret[n].context = (char *) username;
	n++;
    }	

    if (authname) {
	/* authname */
	ret[n].id = SASL_CB_AUTHNAME;
	ret[n].proc = &mysasl_simple_cb;
	ret[n].context = (char *) authname;
	n++;
    }

    if (realm) {
	/* realm */
	ret[n].id = SASL_CB_GETREALM;
	ret[n].proc = &mysasl_getrealm_cb;
	ret[n].context = (char *) realm;
	n++;
    }

    if (password) {
	sasl_secret_t *secret;
	size_t len = strlen(password);
	
	secret = (sasl_secret_t *)xmalloc(sizeof(sasl_secret_t) + len);
	if(!secret) {
	    free(ret);
	    return NULL;
	}

	strcpy(secret->data,password);
	secret->len = len;
		
	/* password */
	ret[n].id = SASL_CB_PASS;
	ret[n].proc = &mysasl_getsecret_cb;
	ret[n].context = secret;
	n++;
    }
    
    ret[n].id = SASL_CB_LIST_END;
    ret[n].proc = NULL;
    ret[n].context = NULL;

    return ret;
}

void free_callbacks(sasl_callback_t *in) 
{
    int i;
    if(!in) return;

    for(i=0; in[i].id != SASL_CB_LIST_END; i++)
	if(in[i].id == SASL_CB_PASS)
	    free(in[i].context);
    
    free(in);
}

#define BASE64_BUF_SIZE	21848	/* per RFC 2222bis: ((16K / 3) + 1) * 4  */
#define AUTH_BUF_SIZE	BASE64_BUF_SIZE+50	/* data + response overhead */

int saslclient(sasl_conn_t *conn, struct sasl_cmd_t *sasl_cmd,
	       const char *mechlist,
               struct protstream *pin, struct protstream *pout,
	       int *sasl_result, const char **status)
{
    static char buf[AUTH_BUF_SIZE+1];
    char *base64, *serverin;
    unsigned int serverinlen = 0;
    const char *mech, *clientout = NULL;
    unsigned int clientoutlen = 0;
    int r;

    if (status) *status = NULL;

    r = sasl_client_start(conn, mechlist, NULL,
			  /* do we support initial response? */
			  sasl_cmd->init ? &clientout : NULL,
			  &clientoutlen, &mech);

    if (r == SASL_CONTINUE || r == SASL_OK) {
    /* send the auth command to the server */
	if (sasl_cmd->quote)
	    prot_printf(pout, "%s \"%s\"", sasl_cmd->cmd, mech);
	else
	    prot_printf(pout, "%s %s", sasl_cmd->cmd, mech);

	if (!clientout) {
	    /* no initial response */
	    prot_printf(pout, "\r\n");
	}
	else if (!clientoutlen) {
	    /* zero-length initial response */
	    prot_printf(pout, " %s\r\n", sasl_cmd->init);
	}
	else {
	    /* encode the initial response */
	    base64 = buf;
	    r = sasl_encode64(clientout, clientoutlen,
			      base64, BASE64_BUF_SIZE, NULL);
	    if (r == SASL_OK) {
		prot_printf(pout, " ");
		if (sasl_cmd->quote) {
		    /* send a literal */
		    prot_printf(pout, "{%d+}\r\n", strlen(base64));
		    prot_flush(pout);
		}
		prot_printf(pout, "%s\r\n", base64);
	    }
	}
    }

    while (r == SASL_CONTINUE || r == SASL_OK) {
	char *p;

	/* get challenge/reply from the server */
	if (!prot_fgets(buf, AUTH_BUF_SIZE, pin)) {
	    if (sasl_result) *sasl_result = SASL_FAIL;
	    return IMAP_SASL_PROTERR;
	}

	/* check response code */
	if (!strncasecmp(buf, sasl_cmd->ok, strlen(sasl_cmd->ok))) {
	    /* success */
	    if (!sasl_cmd->parse_success ||
		(base64 = sasl_cmd->parse_success(buf, status)) == NULL) {

		/* no success data */
		if (status) *status = buf + strlen(sasl_cmd->ok);
		r = SASL_OK;
		break;
	    }

	    /* fall through and process success data */
	}
	else if (!strncasecmp(buf, sasl_cmd->fail, strlen(sasl_cmd->fail))) {
	    /* failure */
	    if (status) *status = buf + strlen(sasl_cmd->fail);
	    r = SASL_BADAUTH;
	    break;
	}
	else if (!strncasecmp(buf, sasl_cmd->cont, strlen(sasl_cmd->cont))) {
	    /* continue */
	    base64 = buf + strlen(sasl_cmd->cont);
	}
	else {
	    /* unknown response */
	    prot_printf(pout, "%s\r\n", sasl_cmd->cancel);
	    if (status) *status = buf;
	    r = SASL_BADPROT;
	    break;
	}

	/* trim CRLF */
	p = base64 + strlen(base64) - 1;
	if (p >= base64 && *p == '\n') *p-- = '\0';
	if (p >= base64 && *p == '\r') *p-- = '\0';

	/* decode the challenge */
	serverin = buf;
	r = sasl_decode64(base64, strlen(base64),
			  serverin, BASE64_BUF_SIZE, &serverinlen);
	if (r != SASL_OK) break;

	/* do the next step */
	r = sasl_client_step(conn, serverin, serverinlen, NULL,
			     &clientout, &clientoutlen);

	/* send the response to the server */
	if (clientout) {
	    base64 = buf;
	    r = sasl_encode64(clientout, clientoutlen,
			      base64, BASE64_BUF_SIZE, NULL);
	    if (r != SASL_OK) break;

	    if (!sasl_cmd->cont) {
		/* send a literal */
		prot_printf(pout, "{%d+}\r\n", strlen(base64));
		prot_flush(pout);
	    }
	    prot_printf(pout, "%s\r\n", base64);
	}
    }

    if (sasl_result) *sasl_result = r;

    return (r == SASL_OK ? 0 : IMAP_SASL_FAIL);
}
