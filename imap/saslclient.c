/* saslclient.c -- shared SASL code for server-server authentication
 *
 * Copyright 2000 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 */

/* $Id: saslclient.c,v 1.5 2000/02/10 21:25:34 leg Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <sasl.h>

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
    const char *pass;
    size_t len;
    /*    struct backend *s = (struct backend *) context; */
    
    

    if (!conn || !result || id != SASL_CB_PASS) {
	return SASL_BADPARAM;
    }

    pass = (char *) context;
    len = strlen(pass);

    *result = (sasl_secret_t *) xmalloc(sizeof(sasl_secret_t) + len);
    (*result)->len = len;
    strcpy((*result)->data, pass);

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
	/* password */
	ret[n].id = SASL_CB_PASS;
	ret[n].proc = &mysasl_getsecret_cb;
	ret[n].context = (char *) password;
	n++;
    }
    
    ret[n].id = SASL_CB_LIST_END;
    ret[n].proc = NULL;
    ret[n].context = NULL;

    return ret;
}
