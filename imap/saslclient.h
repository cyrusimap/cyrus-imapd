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
 *
 * $Id: saslclient.h,v 1.4 2008/04/22 13:11:18 murch Exp $
 */

#ifndef SASLCLIENT_H
#define SASLCLIENT_H

#include <sasl/sasl.h>

#include "prot.h"

struct sasl_cmd_t {
    const char *cmd;	/* auth command string */
    int maxlen;		/* maximum command line length
			   (0 = initial response unsupported by protocol) */
    int quote;		/* quote arguments (literal for base64 data) */
    const char *ok;	/* success response string */
    const char *fail;	/* failure response string */
    const char *cont;	/* continue response string
			   (NULL = send/receive literals) */
    const char *cancel;	/* cancel auth string */
    char *(*parse_success)(char *str, const char **status);
			/* [OPTIONAL] parse response for success data */
    int auto_capa;      /* capability response sent automatically
			   after AUTH with SASL security layer */
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
