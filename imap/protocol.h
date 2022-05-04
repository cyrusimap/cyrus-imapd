/* protocol.h -- client-side protocol abstraction
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

#ifndef _INCLUDED_PROTOCOL_H
#define _INCLUDED_PROTOCOL_H

#include "saslclient.h"

enum {
    /* protocol types */
    TYPE_STD           = 0,    /* protocol fits standard template */
    TYPE_SPEC          = 1     /* non-standard needs special functions */
};

struct stdprot_t;
struct backend;

#define MAX_CAPA 13

enum {
    /* generic capabilities */
    CAPA_AUTH           = (1 << 0),
    CAPA_STARTTLS       = (1 << 1),
    CAPA_COMPRESS       = (1 << 2)

    /*
      protocol specific capabilities MUST be in the range
      (1 << 3) .. (1 << MAX_CAPA)
    */
};

struct banner_t {
    u_char auto_capa;           /* capability response sent automatically
                                   in banner? */
    char *resp;                 /* end of banner response */
};

struct capa_t {
    const char *str;
    unsigned long flag;
};

#define CAPAF_MANY_PER_LINE     (0)
#define CAPAF_ONE_PER_LINE      (1<<0)
#define CAPAF_SKIP_FIRST_WORD   (1<<1)
#define CAPAF_QUOTE_WORDS       (1<<2)
#define CAPAF_DASH_STUFFING     (1<<3)

struct capa_cmd_t {
    const char *cmd;            /* [OPTIONAL] capability command string */
    const char *arg;            /* [OPTIONAL] capability command argument */
    const char *resp;           /* end of capability response */
    void (*postcapability)(struct backend *);
                                /* [OPTIONAL] called after capabilities,
                                 * received from server, are parsed */
    int formatflags;            /* CAPAF* constants above */
    struct capa_t capa[MAX_CAPA+1];/* list of capabilities to parse for
                                      (MUST end with NULL entry) */
};

struct tls_cmd_t {
    const char *cmd;            /* TLS command string */
    const char *ok;             /* start TLS prompt */
    const char *fail;           /* failure response */
    u_char auto_capa;           /* capability response sent automatically
                                   after TLS? */
};

struct simple_cmd_t {
    const char *cmd;            /* command string */
    const char *unsol;          /* unsolicited response */
    const char *ok;             /* success response */
};

struct stdprot_t {
    struct banner_t banner;
    struct capa_cmd_t capa_cmd;
    struct tls_cmd_t tls_cmd;
    struct sasl_cmd_t sasl_cmd;
    struct simple_cmd_t compress_cmd;
    struct simple_cmd_t ping_cmd;
    struct simple_cmd_t logout_cmd;
};

struct protocol_t {
    const char *service;       /* INET service name */
    const char *sasl_service;  /* SASL service name */
    unsigned type;
    union {
       struct stdprot_t std;
       struct {
           /* special protocol */
           int (*login)(struct backend *s, const char *userid,
                        sasl_callback_t *cb, const char **status,
                        int noauth);
           int (*ping)(struct backend *s, const char *userid);
           int (*logout)(struct backend *s);
       } spec;
    } u;
};



#endif /* _INCLUDED_PROTOCOL_H */
