/*
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

#ifndef IDLE_H
#define IDLE_H

#include "mailbox.h"

extern const char *idle_method_desc;

typedef enum {
    /* something noteworthy may have happened to the mailbox,
     * e.g. a delivery, so it needs to be checked */
    IDLE_MAILBOX =      0x1,
    /* the shutdownfile may have been written, needing an ALERT response
     * to be sent to any IMAP clients */
    IDLE_ALERT =        0x2,
    /* input was detected on the @otherfd, probably because the IMAP
     * client cancelled the IDLE */
    IDLE_INPUT =        0x4
} idle_flags_t;

typedef void idle_updateproc_t(idle_flags_t flags);

/* set up the link to the idled for notifications */
void idle_init(void);

/* Is IDLE enabled? */
int idle_enabled(void);

/* Start IDLEing on 'mailbox'. */
void idle_start(const char *mboxname);

/* Wait for something to happen while IDLEing.  @otherfd is a file
 * descriptor on which to wait for input; presumably this will be the
 * fd of the main protstream from the IMAP client.  Returns a mask of
 * flags indicating what if anything happened, see idle_flags_t, or 0
 * on error.  If idled is disabled or was not contacted, we fall back
 * to polling mode and return the flags IDLE_MAILBOX and IDLE_INPUT
 * periodically.
 */
int idle_wait(int otherfd);

/* Stop IDLEing on 'mailbox'. */
void idle_stop(const char *mboxname);

/* Clean up when IDLE is completed. */
void idle_done(void);

#endif
