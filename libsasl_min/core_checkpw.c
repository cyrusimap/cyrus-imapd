/* core_checkpw.c - password verification support */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/core_saslint.h"

#include "libsasl_min/sasl.h"
#include "libsasl_min/saslutil.h"
#include "libsasl_min/saslplug.h"

#include "lib/md5.h"
#include "lib/retry.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

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
        sasl_seterror(conn, 0, "cannot create socket for saslauthd: %m");
        goto fail;
    }

    memset((char *) &srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    snprintf(srvaddr.sun_path, sizeof(srvaddr.sun_path), "%s", pwpath);

    {
        int r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
        if (r == -1) {
            close(s);
            sasl_seterror(conn, 0, "cannot connect to saslauthd server: %m");
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

/* alwaystrue login */
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
    { "saslauthd",   &saslauthd_verify_password  },
    { "alwaystrue",  &always_true                },
    { NULL,          NULL                        }
};
