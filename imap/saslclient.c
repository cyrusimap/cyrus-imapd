/* saslclient.c -- shared SASL code for server-server authentication
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

/* $Id: saslclient.c,v 1.10 2003/02/13 20:15:30 rjs3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>

#include "xmalloc.h"

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
