/* canonuser_internal.c - INTERNAL canonuser plugin */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/canonuser_internal.h"

#include "libsasl_min/core_saslint.h"

#include <ctype.h>
#include <string.h>

#ifdef MIN
# undef MIN
#endif
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/* not part of public API, but visible for testing */
EXPORTED int _canonuser_internal(const sasl_utils_t *utils,
                                 const char *user,
                                 unsigned ulen,
                                 unsigned flags __attribute__((unused)),
                                 char *out_user,
                                 unsigned out_umax,
                                 unsigned *out_ulen)
{
    unsigned i;
    char *in_buf, *userin;
    const char *begin_u;
    unsigned u_apprealm = 0;
    sasl_server_conn_t *sconn = NULL;

    if (!utils || !user) {
        return SASL_BADPARAM;
    }

    in_buf = sasl_ALLOC((ulen + 2) * sizeof(char));
    if (!in_buf) {
        return SASL_NOMEM;
    }

    userin = in_buf;

    memcpy(userin, user, ulen);
    userin[ulen] = '\0';

    /* Strip User ID */
    for (i = 0; isspace((int) userin[i]) && i < ulen; i++)
        ;
    begin_u = &(userin[i]);
    if (i > 0) {
        ulen -= i;
    }

    for (; ulen > 0 && isspace((int) begin_u[ulen - 1]); ulen--)
        ;
    if (begin_u == &(userin[ulen])) {
        sasl_FREE(in_buf);
        utils->seterror(utils->conn, 0, "All-whitespace username.");
        return SASL_FAIL;
    }

    if (utils->conn && utils->conn->type == SASL_CONN_SERVER) {
        sconn = (sasl_server_conn_t *) utils->conn;
    }

    /* Need to append realm if necessary (see sasl.h) */
    if (sconn && sconn->user_realm && !strchr(user, '@')) {
        u_apprealm = (unsigned) strlen(sconn->user_realm) + 1;
    }

    /* Now Copy */
    memcpy(out_user, begin_u, MIN(ulen, out_umax));
    if (sconn && u_apprealm) {
        if (ulen >= out_umax) {
            return SASL_BUFOVER;
        }
        out_user[ulen] = '@';
        memcpy(&(out_user[ulen + 1]),
               sconn->user_realm,
               MIN(u_apprealm - 1, out_umax - ulen - 1));
    }
    out_user[MIN(ulen + u_apprealm, out_umax)] = '\0';

    if (ulen + u_apprealm > out_umax) {
        return SASL_BUFOVER;
    }

    if (out_ulen) {
        *out_ulen = MIN(ulen + u_apprealm, out_umax);
    }

    sasl_FREE(in_buf);
    return SASL_OK;
}

static int _cu_internal_server(void *glob_context __attribute__((unused)),
                               sasl_server_params_t *sparams,
                               const char *user,
                               unsigned ulen,
                               unsigned flags,
                               char *out_user,
                               unsigned out_umax,
                               unsigned *out_ulen)
{
    return _canonuser_internal(sparams->utils,
                               user,
                               ulen,
                               flags,
                               out_user,
                               out_umax,
                               out_ulen);
}

static int _cu_internal_client(void *glob_context __attribute__((unused)),
                               sasl_client_params_t *cparams,
                               const char *user,
                               unsigned ulen,
                               unsigned flags,
                               char *out_user,
                               unsigned out_umax,
                               unsigned *out_ulen)
{
    return _canonuser_internal(cparams->utils,
                               user,
                               ulen,
                               flags,
                               out_user,
                               out_umax,
                               out_ulen);
}

static sasl_canonuser_plug_t canonuser_internal_plugin = {
    0,          /* features */
    0,          /* spare */
    NULL,       /* glob_context */
    "INTERNAL", /* name */
    NULL,       /* canon_user_free */
    _cu_internal_server,
    _cu_internal_client,
    NULL,
    NULL,
    NULL
};

EXPORTED int internal_canonuser_init(const sasl_utils_t *utils __attribute__((unused)),
                                     int max_version,
                                     int *out_version,
                                     sasl_canonuser_plug_t **plug,
                                     const char *plugname __attribute__((unused)))
{
    if (!out_version || !plug) {
        return SASL_BADPARAM;
    }

    if (max_version < SASL_CANONUSER_PLUG_VERSION) {
        return SASL_BADVERS;
    }

    *out_version = SASL_CANONUSER_PLUG_VERSION;

    *plug = &canonuser_internal_plugin;

    return SASL_OK;
}
