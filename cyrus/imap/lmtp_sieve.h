/* lmtp_sieve.h -- Sieve implementation for lmtpd
 *
 * $Id: lmtp_sieve.h,v 1.1.2.1 2004/02/08 20:47:31 ken3 Exp $
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
 *
 *
 */

#ifndef LMTP_SIEVE_H
#define LMTP_SIEVE_H

#include "append.h"
#include "auth.h"
#include "lmtpengine.h"
#include "mboxname.h"
#include "sieve_interface.h"

/* data per message */
typedef struct sieve_msgdata {
    message_data_t *m;
    int cur_rcpt;

    struct stagemsg *stage;	/* staging location for single instance
				   store */
    char *notifyheader;
    const char *temp[2];	/* used to avoid extra indirection in
				   getenvelope() */

    struct namespace *namespace;

    char *authuser;		/* user who submitted message */
    struct auth_state *authstate;
} sieve_msgdata_t;

sieve_interp_t *setup_sieve(void);
int run_sieve(char *user, char *mailbox, sieve_interp_t *interp,
	     sieve_msgdata_t *mydata);

#endif /* LMTP_SIEVE_H */
