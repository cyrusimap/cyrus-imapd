#include <stdio.h>
#include <stdlib.h>

#include <sasl.h>

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
    char optstr[1024];
    const char *pass;
    char *p;
    size_t len;
    struct backend *s = (struct backend *) context;

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

sasl_callback_t *mysasl_callbacks(char *username,
				  char *authname,
				  char *realm,
				  char *password)
{
    sasl_callback_t *ret = xmalloc(5 * sizeof(sasl_callback_t));
    int n = 0;

    if (username) {
	/* user callback */
	ret[n].id = SASL_CB_USER;
	ret[n].proc = &mysasl_simple_cb;
	ret[n].context = username;
	n++;
    }	

    if (authname) {
	/* authname */
	ret[n].id = SASL_CB_AUTHNAME;
	ret[n].proc = &mysasl_simple_cb;
	ret[n].context = authname;
	n++;
    }

    if (realm) {
	/* realm */
	ret[n].id = SASL_CB_GETREALM;
	ret[n].proc = &mysasl_getrealm_cb;
	ret[n].context = realm;
	n++;
    }

    if (password) {
	/* password */
	ret[n].id = SASL_CB_PASS;
	ret[n].proc = &mysasl_getsecret_cb;
	ret[n].context = password;
	n++;
    }
    
    ret[n].id = SASL_CB_LIST_END;
    ret[n].proc = NULL;
    ret[n].context = NULL;

    return ret;
}
