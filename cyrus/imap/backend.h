/* backend.h -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: backend.h,v 1.3.6.5 2002/12/16 01:28:53 ken3 Exp $ */

#ifndef _INCLUDED_BACKEND_H
#define _INCLUDED_BACKEND_H

#include "mboxlist.h"
#include "prot.h"
#include "saslclient.h"
#include "tls.h"

/* Functionality to bring up/down connections to backend servers */

#define LAST_RESULT_LEN 1024

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

char *imap_parsemechlist(char *str);

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

struct backend {
    char hostname[MAX_PARTITION_LEN];
    struct sockaddr_in addr;
    int sock;

    /* only used by proxyd */
    struct prot_waitevent *timeout;

    sasl_conn_t *saslconn;
    SSL *tlsconn;
    SSL_SESSION *tlssess;

    enum {
	ACAP = 0x1, /* obsolete */
	IDLE = 0x2,
	MUPDATE = 0x4
    } capability;

    char last_result[LAST_RESULT_LEN];
    struct protstream *in; /* from the be server to me, the proxy */
    struct protstream *out; /* to the be server */
};

/* if cache is NULL, returns a new struct backend, otherwise returns
 * cache on success (and returns NULL on failure, but leaves cache alone) */
struct backend *findserver(struct backend *cache, const char *server,
			   struct protocol_t *prot, const char *userid,
			   const char **auth_status);
void downserver(struct backend *s, struct protocol_t *prot);

#define CAPA(s, c) ((s)->capability & (c))

extern struct protocol_t protocol[];

enum {
    PROTOCOL_IMAP = 0,
    PROTOCOL_POP,
    PROTOCOL_NNTP,
    PROTOCOL_LMTP,
    PROTOCOL_MUPDATE
};

#endif /* _INCLUDED_BACKEND_H */
