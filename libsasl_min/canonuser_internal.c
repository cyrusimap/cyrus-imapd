/* canonuser_internal.c - INTERNAL canonuser plugin */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/canonuser_internal.h"

#include "libsasl_min/core_saslint.h"

#include <ctype.h>
#include <string.h>

/* not part of public API, but visible for testing */
EXPORTED int _canonuser_internal(const sasl_utils_t *utils,
                                 const char *user,
                                 unsigned ulen,
                                 unsigned flags __attribute__((unused)),
                                 char *out_user,
                                 unsigned out_umax,
                                 unsigned *out_ulen)
{
    const char *append_realm = NULL;
    char *canon = NULL;
    int canon_len, r;

    if (!utils || !user) {
        return SASL_BADPARAM;
    }

    /* by SASL API, user can be unterminated and its length determined by ulen.
     * When ulen is zero, user must be null-terminated.
     */
    if (ulen == 0) ulen = strlen(user);

    /* find first non-space */
    while (ulen > 0 && isspace(user[0])) {
        user ++;
        ulen --;
    }
    if (ulen == 0) {
        utils->seterror(utils->conn, 0, "All-whitespace username.");
        return SASL_FAIL;
    }

    /* find last non-space */
    while (ulen > 0 && isspace(user[ulen - 1]))
        ulen --;

    /* do we need to append a realm? */
    if (utils->conn && utils->conn->type == SASL_CONN_SERVER) {
        const sasl_server_conn_t *sconn =
            (const sasl_server_conn_t *) utils->conn;

        if (sconn->user_realm && !memchr(user, '@', ulen))
            append_realm = sconn->user_realm;
    }

    /* by SASL API, user and out_user memory may overlap, so we need to build
     * the output in a temporary buffer, and copy it into place afterwards
     */
    canon_len = _sasl_mprintf(&canon, "%.*s%s%s",
                                      (int) ulen, user,
                                      append_realm ? "@" : "",
                                      append_realm ? append_realm : "");

    if (canon_len <= 0) {
        /* empty output, out of memory, or a conversion error */
        r = canon_len ? canon_len : SASL_FAIL;
        memset(out_user, 0, out_umax);
        canon_len = 0;
        goto done;
    }

    if ((unsigned) canon_len >= out_umax) {
        /* canonicalised string is too long for output buffer */
        r = SASL_BUFOVER;
        memset(out_user, 0, out_umax);
        canon_len = 0;
        goto done;
    }

    /* Using strncpy here specifically for its behaviour of filling the rest of
     * the buffer with null bytes, hence the dsize parameter is the size of the
     * buffer, not the size of the source.
     * We know canon is null-terminated and will fit without truncation.
     */
    strncpy(out_user, canon, out_umax);
    r = SASL_OK;

 done:
    if (out_ulen)
        *out_ulen = (unsigned) canon_len;
    sasl_FREE(canon);
    return r;
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
