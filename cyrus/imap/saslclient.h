/* saslclient.c -- shared SASL code for server-server authentication
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: saslclient.h,v 1.1.2.2 2002/12/16 01:28:56 ken3 Exp $ */

#ifndef SASLCLIENT_H
#define SASLCLIENT_H

#include <sasl/sasl.h>

#include "prot.h"

struct sasl_cmd_t {
    const char *cmd;	/* auth command string */
    int quote;		/* quote arguments (literal for base64 data) */
    const char *init;	/* string to send as empty initial-response,
			   (NULL = initial response unsupported by protocol) */
    const char *ok;	/* success response string */
    const char *fail;	/* failure response string */
    const char *cont;	/* continue response string
			   (NULL = send/receive literals) */
    const char *cancel;	/* cancel auth string */
    char *(*parse_success)(char *str, const char **status);
			/* [OPTIONAL] parse response for success data */
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
