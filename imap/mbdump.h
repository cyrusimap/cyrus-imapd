/* mbdump.h - Mailbox dump routine definitions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
