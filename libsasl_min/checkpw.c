/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 */
/*
 * Copyright (c) 1998-2016 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#include "libsasl_min/sasl.h"
#include "libsasl_min/saslutil.h"
#include "libsasl_min/saslplug.h"
#include "libsasl_min/saslint.h"

#include "lib/md5.h"
#include "lib/retry.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

/* we store the following secret to check plaintext passwords:
 *
 * <salt> \0 <secret>
 *
 * where <secret> = MD5(<salt>, "sasldb", <pass>)
 */
static int _sasl_make_plain_secret(const char *salt,
                                   const char *passwd,
                                   size_t passlen,
                                   sasl_secret_t **secret)
{
    MD5_CTX ctx;
    unsigned sec_len = 16 + 1 + 16; /* salt + "\0" + hash */

    *secret = (sasl_secret_t *) sasl_ALLOC(sizeof(sasl_secret_t)
                                           + sec_len * sizeof(char));
    if (*secret == NULL) {
        return SASL_NOMEM;
    }

    MD5Init(&ctx);
    MD5Update(&ctx, salt, 16);
    MD5Update(&ctx, "sasldb", 6);
    MD5Update(&ctx, passwd, passlen);

    memcpy((*secret)->data, salt, 16);
    (*secret)->data[16] = '\0';
    MD5Final((*secret)->data + 17, &ctx);
    (*secret)->len = sec_len;

    return SASL_OK;
}

/* verify user password using auxprop plugins
 */
static int auxprop_verify_password(sasl_conn_t *conn,
                                   const char *userstr,
                                   const char *passwd,
                                   const char *service __attribute__((unused)),
                                   const char *user_realm
                                   __attribute__((unused)))
{
    int ret = SASL_FAIL;
    int result = SASL_OK;
    sasl_server_conn_t *sconn = (sasl_server_conn_t *) conn;
    const char *password_request[] = { SASL_AUX_PASSWORD,
                                       "*cmusaslsecretPLAIN",
                                       NULL };
    struct propval auxprop_values[3];

    if (!conn || !userstr) {
        return SASL_BADPARAM;
    }

    /* We need to clear any previous results and re-canonify to
     * ensure correctness */

    prop_clear(sconn->sparams->propctx, 0);

    /* ensure its requested */
    result = prop_request(sconn->sparams->propctx, password_request);

    if (result != SASL_OK) {
        return result;
    }

    result = _sasl_canon_user_lookup(conn,
                                     userstr,
                                     0,
                                     SASL_CU_AUTHID | SASL_CU_AUTHZID,
                                     &(conn->oparams));
    if (result != SASL_OK) {
        return result;
    }

    result = prop_getnames(sconn->sparams->propctx,
                           password_request,
                           auxprop_values);
    if (result < 0) {
        return result;
    }

    /* Verify that the returned <name>s are correct.
       But we defer checking for NULL values till after we verify
       that a passwd is specified. */
    if (!auxprop_values[0].name && !auxprop_values[1].name) {
        return SASL_NOUSER;
    }

    /* It is possible for us to get useful information out of just
     * the lookup, so we won't check that we have a password until now */
    if (!passwd) {
        ret = SASL_BADPARAM;
        goto done;
    }

    if ((!auxprop_values[0].values || !auxprop_values[0].values[0])
        && (!auxprop_values[1].values || !auxprop_values[1].values[0]))
    {
        return SASL_NOUSER;
    }

    /* At the point this has been called, the username has been canonified
     * and we've done the auxprop lookup.  This should be easy. */
    if (auxprop_values[0].name && auxprop_values[0].values
        && auxprop_values[0].values[0]
        && !strcmp(auxprop_values[0].values[0], passwd))
    {
        /* We have a plaintext version and it matched! */
        return SASL_OK;
    }
    else if (auxprop_values[1].name && auxprop_values[1].values
             && auxprop_values[1].values[0])
    {
        const char *db_secret = auxprop_values[1].values[0];
        sasl_secret_t *construct;

        ret = _sasl_make_plain_secret(db_secret,
                                      passwd,
                                      strlen(passwd),
                                      &construct);
        if (ret != SASL_OK) {
            goto done;
        }

        if (!memcmp(db_secret, construct->data, construct->len)) {
            /* password verified! */
            ret = SASL_OK;
        }
        else {
            /* passwords do not match */
            ret = SASL_BADAUTH;
        }

        sasl_FREE(construct);
    }
    else {
        /* passwords do not match */
        ret = SASL_BADAUTH;
    }

    /* erase the plaintext password */
    sconn->sparams->utils->prop_erase(sconn->sparams->propctx,
                                      password_request[0]);

done:
    /* We're not going to erase the property here because other people
     * may want it */
    return ret;
}

int _sasl_auxprop_verify_apop(sasl_conn_t *conn,
                              const char *userstr,
                              const char *challenge,
                              const char *response,
                              const char *user_realm __attribute__((unused)))
{
    int ret = SASL_BADAUTH;
    char *userid = NULL;
    char *realm = NULL;
    unsigned char digest[16];
    char digeststr[33];
    const char *password_request[] = { SASL_AUX_PASSWORD, NULL };
    struct propval auxprop_values[2];
    sasl_server_conn_t *sconn = (sasl_server_conn_t *) conn;
    MD5_CTX ctx;
    int i;

    if (!conn || !userstr || !challenge || !response) {
        PARAMERROR(conn)
    }

    /* We've done the auxprop lookup already (in our caller) */
    /* sadly, APOP has no provision for storing secrets */
    ret = prop_getnames(sconn->sparams->propctx,
                        password_request,
                        auxprop_values);
    if (ret < 0) {
        sasl_seterror(conn, 0, "could not perform password lookup");
        goto done;
    }

    if (!auxprop_values[0].name || !auxprop_values[0].values
        || !auxprop_values[0].values[0])
    {
        sasl_seterror(conn, 0, "could not find password");
        ret = SASL_NOUSER;
        goto done;
    }

    MD5Init(&ctx);
    MD5Update(&ctx, challenge, strlen(challenge));
    MD5Update(&ctx, auxprop_values[0].values[0],
                    strlen(auxprop_values[0].values[0]));
    MD5Final(digest, &ctx);

    /* erase the plaintext password */
    sconn->sparams->utils->prop_erase(sconn->sparams->propctx,
                                      password_request[0]);

    /* convert digest from binary to ASCII hex */
    for (i = 0; i < 16; i++) {
        sprintf(digeststr + (i * 2), "%02x", digest[i]);
    }

    if (!strncasecmp(digeststr, response, 32)) {
        /* password verified! */
        ret = SASL_OK;
    }
    else {
        /* passwords do not match */
        ret = SASL_BADAUTH;
    }

done:
    if (ret == SASL_BADAUTH) {
        sasl_seterror(conn, SASL_NOLOG, "login incorrect");
    }
    if (userid) {
        sasl_FREE(userid);
    }
    if (realm) {
        sasl_FREE(realm);
    }

    return ret;
}

/* saslauthd-authenticated login */
static int saslauthd_verify_password(sasl_conn_t *conn,
                                     const char *userid,
                                     const char *passwd,
                                     const char *service,
                                     const char *user_realm)
{
    char response[1024];
    char query[8192];
    char *query_end = query;
    int s;
    struct sockaddr_un srvaddr;
    sasl_getopt_t *getopt;
    void *context;
    char pwpath[sizeof(srvaddr.sun_path)];
    const char *p = NULL;
    char *freeme = NULL;

    /* check to see if the user configured a rundir */
    if (_sasl_getcallback(conn,
                          SASL_CB_GETOPT,
                          (sasl_callback_ft *) &getopt,
                          &context)
        == SASL_OK)
    {
        getopt(context, NULL, "saslauthd_path", &p, NULL);
    }
    if (p) {
        if (strlen(p) >= sizeof(pwpath)) {
            return SASL_FAIL;
        }

        strncpy(pwpath, p, sizeof(pwpath) - 1);
        pwpath[strlen(p)] = '\0';
    }
    else {
        return SASL_FAIL;
    }

    /* Split out username/realm if necessary */
    if (strrchr(userid, '@') != NULL) {
        char *rtmp;

        if (_sasl_strdup(userid, &freeme, NULL) != SASL_OK) {
            goto fail;
        }

        userid = freeme;
        rtmp = strrchr(userid, '@');
        *rtmp = '\0';
        user_realm = rtmp + 1;
    }

    /*
     * build request of the form:
     *
     * count authid count password count service count realm
     */
    {
        unsigned short max_len, req_len, u_len, p_len, s_len, r_len;

        max_len = (unsigned short) sizeof(query);

        /* prevent buffer overflow */
        if ((strlen(userid) > USHRT_MAX) || (strlen(passwd) > USHRT_MAX)
            || (strlen(service) > USHRT_MAX)
            || (user_realm && (strlen(user_realm) > USHRT_MAX)))
        {
            goto toobig;
        }

        u_len = (strlen(userid));
        p_len = (strlen(passwd));
        s_len = (strlen(service));
        r_len = ((user_realm ? strlen(user_realm) : 0));

        /* prevent buffer overflow */
        req_len = 30;
        if (max_len - req_len < u_len) {
            goto toobig;
        }
        req_len += u_len;
        if (max_len - req_len < p_len) {
            goto toobig;
        }
        req_len += p_len;
        if (max_len - req_len < s_len) {
            goto toobig;
        }
        req_len += s_len;
        if (max_len - req_len < r_len) {
            goto toobig;
        }

        u_len = htons(u_len);
        p_len = htons(p_len);
        s_len = htons(s_len);
        r_len = htons(r_len);

        memcpy(query_end, &u_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        while (*userid) {
            *query_end++ = *userid++;
        }

        memcpy(query_end, &p_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        while (*passwd) {
            *query_end++ = *passwd++;
        }

        memcpy(query_end, &s_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        while (*service) {
            *query_end++ = *service++;
        }

        memcpy(query_end, &r_len, sizeof(unsigned short));
        query_end += sizeof(unsigned short);
        if (user_realm) {
            while (*user_realm) {
                *query_end++ = *user_realm++;
            }
        }
    }

    /* unix sockets */

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        sasl_seterror(conn, 0, "cannot create socket for saslauthd: %m", errno);
        goto fail;
    }

    memset((char *) &srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    snprintf(srvaddr.sun_path, sizeof(srvaddr.sun_path), "%s", pwpath);

    {
        int r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
        if (r == -1) {
            close(s);
            sasl_seterror(conn,
                          0,
                          "cannot connect to saslauthd server: %m",
                          errno);
            goto fail;
        }
    }

    {
        struct iovec iov[8];

        iov[0].iov_len = query_end - query;
        iov[0].iov_base = query;

        if (retry_writev(s, iov, 1) == -1) {
            close(s);
            sasl_seterror(conn, 0, "write failed");
            goto fail;
        }
    }

    {
        unsigned short count = 0;

        /*
         * read response of the form:
         *
         * count result
         */
        if (retry_read(s, &count, sizeof(count)) < (int) sizeof(count)) {
            sasl_seterror(conn, 0, "size read failed");
            goto fail;
        }

        count = ntohs(count);
        if (count < 2) { /* MUST have at least "OK" or "NO" */
            close(s);
            sasl_seterror(conn, 0, "bad response from saslauthd");
            goto fail;
        }

        count = (int) sizeof(response) <= count ? sizeof(response) - 1 : count;
        if (retry_read(s, response, count) < count) {
            close(s);
            sasl_seterror(conn, 0, "read failed");
            goto fail;
        }
        response[count] = '\0';
    }

    close(s);

    if (freeme) {
        free(freeme);
    }

    if (!strncmp(response, "OK", 2)) {
        return SASL_OK;
    }

    sasl_seterror(conn, SASL_NOLOG, "authentication failed");
    return SASL_BADAUTH;

toobig:
    /* request just too damn big */
    sasl_seterror(conn, 0, "saslauthd request too large");

fail:
    if (freeme) {
        free(freeme);
    }
    return SASL_FAIL;
}

static int always_true(sasl_conn_t *conn,
                       const char *userstr,
                       const char *passwd __attribute__((unused)),
                       const char *service __attribute__((unused)),
                       const char *user_realm __attribute__((unused)))
{
    _sasl_log(conn,
              SASL_LOG_WARN,
              "AlwaysTrue Password Verifier Verified: %s",
              userstr);
    return SASL_OK;
}

struct sasl_verify_password_s _sasl_verify_password[] = {
    { "auxprop",     &auxprop_verify_password    },
    { "saslauthd",   &saslauthd_verify_password  },
    { "alwaystrue",  &always_true                },
    { NULL,          NULL                        }
};
