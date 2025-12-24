/* saslclient.c -- shared SASL code for server-server authentication */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SASLCLIENT_H
#define SASLCLIENT_H

#include <sasl/sasl.h>

#include "prot.h"

struct sasl_cmd_t {
    const char *cmd;    /* auth command string */
    u_short maxlen;     /* maximum command line length
                           (0 = initial response unsupported by protocol) */
    u_char quote;       /* quote arguments? (literal for base64 data) */
    const char *ok;     /* success response string */
    const char *fail;   /* failure response string */
    const char *cont;   /* continue response string
                           (NULL = send/receive literals) */
    const char *cancel; /* cancel auth string */
    char *(*parse_success)(char *str, const char **status);
                        /* [OPTIONAL] parse response for success data */
    u_char auto_capa;   /* capability response sent automatically after AUTH? */
};

/* values for auto capability after AUTH */
enum {
    AUTO_CAPA_AUTH_NO  = 0,
    AUTO_CAPA_AUTH_OK  = 1,     /* capabilities sent in AUTH success response */
    AUTO_CAPA_AUTH_SSF = 2      /* capabilities sent after AUTH success resp,
                                   iff a SASL security layer was negotiated */
};

sasl_callback_t *mysasl_callbacks(const char *username,
                                  const char *authname,
                                  const char *realm,
                                  const char *password);

void free_callbacks(sasl_callback_t *in);

int saslclient(sasl_conn_t *conn, struct sasl_cmd_t *sasl_cmd,
               const char *mechlist,
               struct protstream *pin, struct protstream *pout,
               int *sasl_result, const char **status);

#endif /* SASLCLIENT_H */
