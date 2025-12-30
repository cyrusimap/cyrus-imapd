/* sessionid.h - Session ID management */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
