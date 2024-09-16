/* saslserver.c -- shared SASL code for server-side authentication
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

#include <string.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "prot.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define BASE64_BUF_SIZE 21848   /* per RFC 2222bis: ((16K / 3) + 1) * 4  */

/* NOTE: success_data will need to be free()d by the caller */
EXPORTED int saslserver(sasl_conn_t *conn, const char *mech,
               const char *init_resp, const char *resp_prefix,
               const char *continuation, const char *empty_chal,
               struct protstream *pin, struct protstream *pout,
               int *sasl_result, char **success_data)
{
    char base64[BASE64_BUF_SIZE+1];
    char *clientin = NULL;
    unsigned int clientinlen = 0;
    const char *serverout = NULL;
    unsigned int serveroutlen = 0;
    int r = SASL_OK;

    if (success_data) *success_data = NULL;

    /* initial response */
    if (init_resp) {
        clientin = base64;
        if (!strcmp(init_resp, "=")) {
            /* zero-length initial response */
            base64[0] = '\0';
        }
        else {
            r = sasl_decode64(init_resp, strlen(init_resp),
                              clientin, BASE64_BUF_SIZE, &clientinlen);
        }
    }

    /* start the exchange */
    if (r == SASL_OK || r == SASL_CONTINUE)
        r = sasl_server_start(conn, mech, clientin, clientinlen,
                              &serverout, &serveroutlen);

    while (r == SASL_CONTINUE) {
        char *p;

        /* send the challenge to the client */
        if (serveroutlen) {
            r = sasl_encode64(serverout, serveroutlen,
                              base64, BASE64_BUF_SIZE, NULL);
            if (r != SASL_OK) break;
            serverout = base64;
        }
        else {
            serverout = empty_chal;
        }

        prot_printf(pout, "%s%s\r\n", continuation, serverout);
        prot_flush(pout);

        /* get response from the client */
        if (!prot_fgets(base64, BASE64_BUF_SIZE, pin) ||
            strncasecmp(base64, resp_prefix, strlen(resp_prefix))) {
            if (sasl_result) *sasl_result = SASL_FAIL;
            return IMAP_SASL_PROTERR;
        }

        /* trim CRLF */
        p = base64 + strlen(base64) - 1;
        if (p >= base64 && *p == '\n') *p-- = '\0';
        if (p >= base64 && *p == '\r') *p-- = '\0';

        /* trim prefix */
        p = base64 + strlen(resp_prefix);

        /* check if client cancelled */
        if (p[0] == '*') {
            if(sasl_result) *sasl_result = SASL_BADPROT;
            return IMAP_SASL_CANCEL;
        }

        /* decode the response */
        clientin = base64;
        r = sasl_decode64(p, strlen(p),
                          clientin, BASE64_BUF_SIZE, &clientinlen);
        if (r != SASL_OK) break;

        /* do the next step */
        r = sasl_server_step(conn, clientin, clientinlen,
                             &serverout, &serveroutlen);
    }

    /* success data */
    if (r == SASL_OK && serverout && success_data) {
        r = sasl_encode64(serverout, serveroutlen,
                          base64, BASE64_BUF_SIZE, NULL);
        if (r == SASL_OK)
            *success_data = (char *) xstrdup(base64);
    }

    if (sasl_result) *sasl_result = r;
    return (r == SASL_OK ? 0 : IMAP_SASL_FAIL);
}
