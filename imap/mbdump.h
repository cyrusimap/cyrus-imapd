/* mbdump.h -- Mailbox dump routine definitions
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

#ifndef INCLUDED_MBDUMP_H
#define INCLUDED_MBDUMP_H

#include "prot.h"
#include "mailbox.h"

/* if tag is non-null, we assume that we are a server sending to the
 * client, and:
 *  a) do not use the + syntax for nonsynchronized literals
 *  b) preface the response with <tag> DUMP
 *
 * if tag is NULL, then we use the + nonsynchronized syntax for everything
 * after the first send.
 *
 * (note that this assumes server LITERAL+ support, but we don't care since
 * this is a Cyrus-only extension)
 */
extern int dump_mailbox(const char *tag, struct mailbox *mailbox, uint32_t uid_start,
                        int oldversion,
                        struct protstream *pin, struct protstream *pout,
                        struct auth_state *auth_state);
extern int undump_mailbox(const char *mbname,
                          struct protstream *pin, struct protstream *pout,
                          struct auth_state *auth_state);

#endif
