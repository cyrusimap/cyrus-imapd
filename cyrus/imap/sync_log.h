/* sync_log.c -- Cyrus synchonization logging functions
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
 * $Id: sync_log.h,v 1.4 2009/01/30 10:54:13 brong Exp $
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#ifndef INCLUDED_SYNC_LOG_H
#define INCLUDED_SYNC_LOG_H

#define SYNC_LOG_RETRIES (64)

void sync_log_init(void);

void sync_log(char *fmt, ...);

#define sync_log_user(user) \
    sync_log("USER %s\n", user)

#define sync_log_sieve(user) \
    sync_log("META %s\n", user)

#define sync_log_mailbox(name) \
    sync_log("MAILBOX %s\n", name)

#define sync_log_mailbox_double(name1, name2) \
    sync_log("MAILBOX %s\nMAILBOX %s\n", name1, name2)

#define sync_log_append(name) \
    sync_log("APPEND %s\n", name)

#define sync_log_acl(name) \
    sync_log("ACL %s\n", name)

#define sync_log_quota(name) \
    sync_log("QUOTA %s\n", name)

#define sync_log_annotation(name) \
    sync_log("ANNOTATION %s\n", name)

#define sync_log_seen(user, name) \
    sync_log("SEEN %s %s\n", user, name)

#define sync_log_subscribe(user, name) \
    sync_log("SUB %s %s\n", user, name)

#endif /* INCLUDED_SYNC_LOG_H */
