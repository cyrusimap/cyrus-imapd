/* sessionid.h - Session ID management
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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
#ifndef INCLUDED_SESSIONID_H
#define INCLUDED_SESSIONID_H

#include <stdbool.h>

#define MAX_SESSIONID_SIZE 256
#define MAX_TRACEID_SIZE   256

extern void session_new_id(void);
extern const char *session_id(void);
extern bool session_have_id(void);
extern void session_clear_id(void);
extern void parse_sessionid(const char *str, char *sessionid);

/* This is the base64jmap set, which for this purpose is the same as the
 * base64url set without the optional padding character.
 */
#define TRACE_ID_GOODCHARS "-0123456789"                    \
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"     \
                           "_abcdefghijklmnopqrstuvwxyz"

extern int trace_set_id(const char *traceid, size_t len);
extern const char *trace_id(void);

#endif
