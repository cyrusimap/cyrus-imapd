/* saslclient.c -- shared SASL code for server-server authentication
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "xmalloc.h"
#include "saslclient.h"
#include "global.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int mysasl_simple_cb(void *context,
                            int id,
                            const char **result,
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

static int mysasl_getrealm_cb(void *context,
                              int id,
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

    *result = (sasl_secret_t *) context;

    return SASL_OK;
}

EXPORTED sasl_callback_t *mysasl_callbacks(const char *username,
                                           const char *authname,
                                           const char *realm,
                                           const char *password)
{
    sasl_callback_t *ret = xmalloc(5 * sizeof(sasl_callback_t));
    int n = 0;

    if (username) {
        /* user callback */
        ret[n].id = SASL_CB_USER;
        ret[n].proc = SASL_CB_PROC_PTR & mysasl_simple_cb;
        ret[n].context = (char *) username;
        n++;
    }

    if (authname) {
        /* authname */
        ret[n].id = SASL_CB_AUTHNAME;
        ret[n].proc = SASL_CB_PROC_PTR & mysasl_simple_cb;
        ret[n].context = (char *) authname;
        n++;
    }

    if (realm) {
        /* realm */
        ret[n].id = SASL_CB_GETREALM;
        ret[n].proc = SASL_CB_PROC_PTR & mysasl_getrealm_cb;
        ret[n].context = (char *) realm;
        n++;
    }

    if (password) {
        sasl_secret_t *secret;
        size_t len = strlen(password);

        secret = (sasl_secret_t *) xmalloc(sizeof(sasl_secret_t) + len);
        strcpy((char *) secret->data, password);
        secret->len = len;

        /* password */
        ret[n].id = SASL_CB_PASS;
        ret[n].proc = SASL_CB_PROC_PTR & mysasl_getsecret_cb;
        ret[n].context = secret;
        n++;
    }

    ret[n].id = SASL_CB_LIST_END;
    ret[n].proc = NULL;
    ret[n].context = NULL;

    return ret;
}

EXPORTED void free_callbacks(sasl_callback_t *in)
{
    int i;
    if (!in) {
        return;
    }

    for (i = 0; in[i].id != SASL_CB_LIST_END; i++) {
        if (in[i].id == SASL_CB_PASS) {
            free(in[i].context);
        }
    }

    free(in);
}

#define BASE64_BUF_SIZE 21848 /* per RFC 2222bis: ((16K / 3) + 1) * 4  */
#define AUTH_BUF_SIZE BASE64_BUF_SIZE + 50 /* data + response overhead */

HIDDEN int saslclient(sasl_conn_t *conn,
                      struct sasl_cmd_t *sasl_cmd,
                      const char *mechlist,
                      struct protstream *pin,
                      struct protstream *pout,
                      int *sasl_result,
                      const char **status)
{
    static char buf[AUTH_BUF_SIZE + 1];
    char *base64, *serverin;
    unsigned int serverinlen = 0;
    const char *mech, *clientout = NULL;
    unsigned int clientoutlen = 0;
    char cmdbuf[40];
    int sendliteral = sasl_cmd->quote;
    int r;

    if (status) {
        *status = NULL;
    }

    r = sasl_client_start(conn,
                          mechlist,
                          NULL,
                          /* do we support initial response? */
                          sasl_cmd->maxlen ? &clientout : NULL,
                          &clientoutlen,
                          &mech);

    if (r != SASL_OK && r != SASL_CONTINUE) {
        if (sasl_result) {
            *sasl_result = r;
        }
        if (status) {
            *status = sasl_errdetail(conn);
        }
        return IMAP_SASL_FAIL;
    }

    /* build the auth command */
    if (sasl_cmd->quote) {
        sprintf(cmdbuf, "%s \"%s\"", sasl_cmd->cmd, mech);
    }
    else {
        sprintf(cmdbuf, "%s %s", sasl_cmd->cmd, mech);
    }
    prot_printf(pout, "%s", cmdbuf);

    if (!clientout) {
        goto noinitresp; /* no initial response */
    }

    /* initial response */
    if (!clientoutlen) { /* zero-length initial response */
        prot_printf(pout, " =");

        clientout = NULL;
    }
    else if (!sendliteral
             && ((strlen(cmdbuf) + clientoutlen + 3) > sasl_cmd->maxlen))
    {
        /* initial response is too long for auth command,
           so wait for a server challenge before sending it */
        goto noinitresp;
    }
    else { /* full response -- encoded below */
        prot_printf(pout, " ");
    }

    do {
        char *p;

        base64 = buf;
        *base64 = '\0';

        if (clientout) { /* response */
            /* convert to base64 */
            r = sasl_encode64(clientout,
                              clientoutlen,
                              base64,
                              BASE64_BUF_SIZE,
                              NULL);

            clientout = NULL;
        }

        /* send to server */
        if (sendliteral) {
            prot_printf(pout, "{" SIZE_T_FMT "+}\r\n", strlen(base64));
            prot_flush(pout);
        }
        prot_printf(pout, "%s", base64);

    noinitresp:
        prot_printf(pout, "\r\n");
        prot_flush(pout);

        /* get challenge/reply from the server */
        if (!prot_fgets(buf, AUTH_BUF_SIZE, pin)) {
            if (sasl_result) {
                *sasl_result = SASL_FAIL;
            }
            if (status) {
                *status = "EOF from server";
            }
            return IMAP_SASL_PROTERR;
        }

        /* check response code */
        base64 = NULL;
        if (!strncasecmp(buf, sasl_cmd->ok, strlen(sasl_cmd->ok))) {
            /* success */
            if (sasl_cmd->parse_success) /* parse success data */
            {
                base64 = sasl_cmd->parse_success(buf, status);
            }

            if (!base64 /* no success data */
                && status)
            {
                *status = buf + strlen(sasl_cmd->ok);
            }

            r = SASL_OK;
        }
        else if (!strncasecmp(buf, sasl_cmd->fail, strlen(sasl_cmd->fail))) {
            /* failure */
            if (status) {
                *status = buf + strlen(sasl_cmd->fail);
            }
            r = SASL_BADAUTH;
            break;
        }
        else if (sasl_cmd->cont
                 && !strncasecmp(buf, sasl_cmd->cont, strlen(sasl_cmd->cont)))
        {
            /* continue */
            base64 = buf + strlen(sasl_cmd->cont);
        }
        else if (!sasl_cmd->cont && buf[0] == '{') {
            unsigned int n, litsize = atoi(buf + 1);

            /* get actual literal data */
            litsize += 2; /* +2 for \r\n */
            p = buf;
            while (litsize) {
                if (!(n = prot_read(pin, p, litsize))) {
                    if (sasl_result) {
                        *sasl_result = SASL_FAIL;
                    }
                    if (status) {
                        *status = "EOF from server";
                    }
                    return IMAP_SASL_PROTERR;
                }
                litsize -= n;
                p += n;
            }

            *p = '\0';
            base64 = buf;
        }
        else {
            /* unknown response */
            if (status) {
                *status = buf;
            }
            r = SASL_BADPROT;
        }

        if (base64) { /* challenge/success data */
            /* trim CRLF */
            p = base64 + strlen(base64) - 1;
            if (p >= base64 && *p == '\n') {
                *p-- = '\0';
            }
            if (p >= base64 && *p == '\r') {
                *p-- = '\0';
            }

            /* decode the challenge */
            serverin = buf;
            r = sasl_decode64(base64,
                              strlen(base64),
                              serverin,
                              BASE64_BUF_SIZE,
                              &serverinlen);

            if (r == SASL_OK
                && (serverinlen
                    || !clientout)) { /* no delayed initial response */
                /* do the next step */
                r = sasl_client_step(conn,
                                     serverin,
                                     serverinlen,
                                     NULL,
                                     &clientout,
                                     &clientoutlen);
            }
        }

        if (r != SASL_OK && r != SASL_CONTINUE) {
            /* cancel the exchange */
            prot_printf(pout, "%s\r\n", sasl_cmd->cancel);
            prot_flush(pout);
        }

        sendliteral = !sasl_cmd->cont;

    } while (r == SASL_CONTINUE || (r == SASL_OK && clientout));

    if (sasl_result) {
        *sasl_result = r;
    }

    return (r == SASL_OK ? 0 : IMAP_SASL_FAIL);
}
