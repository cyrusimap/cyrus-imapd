/* protocol.h -- client-side protocol abstraction
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

/* $Id: protocol.h,v 1.1.2.2 2003/02/13 20:33:00 rjs3 Exp $ */

#ifndef _INCLUDED_PROTOCOL_H
#define _INCLUDED_PROTOCOL_H

#include "saslclient.h"

struct capa_cmd_t {
    const char *cmd;		/* [OPTIONAL] capability command string
				   (NULL = capabilities in banner) */
    const char *resp;		/* end of capability response */
    const char *tls;		/* [OPTIONAL] TLS capability string */
    const char *auth;		/* AUTH capability string */
    char *(*parse_mechlist)(char *str);
				/* [OPTIONAL] parse capability string,
				   returns space-separated list of mechs */
};

struct tls_cmd_t {
    const char *cmd;		/* tls command string */
    const char *ok;		/* start tls prompt */
    const char *fail;		/* failure response */
};

struct logout_cmd_t {
    const char *cmd;		/* logout command string */
    const char *resp;		/* logout response */
};

struct protocol_t {
    const char *service;	/* INET service name */
    const char *sasl_service;	/* SASL service name */
    struct capa_cmd_t capa_cmd;
    struct tls_cmd_t tls_cmd;
    struct sasl_cmd_t sasl_cmd;
    struct logout_cmd_t logout_cmd;
};

extern struct protocol_t protocol[];

enum {
    PROTOCOL_IMAP = 0,
    PROTOCOL_POP3,
    PROTOCOL_NNTP,
    PROTOCOL_LMTP,
    PROTOCOL_MUPDATE
};

#endif /* _INCLUDED_PROTOCOL_H */
