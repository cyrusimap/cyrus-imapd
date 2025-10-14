/* notifyd.h -- notification method definitions
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

#include <config.h>

#include "notify_null.h"
#include "notify_log.h"
#include "notify_mailto.h"
#include "notify_zephyr.h"
#include "notify_external.h"

/* Notify method dispatch table definition */
typedef struct
{
    const char *name; /* name of the method */
    char *(*notify)(const char *class,
                    const char *priority,
                    const char *user,
                    const char *mailbox,
                    int nopt,
                    char **options,
                    const char *message,
                    const char *fname); /* notification function */
} notifymethod_t;

/* array of supported notification methods */
static notifymethod_t methods[] = {
    { "null",     notify_null     }, /* do nothing */
    { "log",      notify_log      }, /* use syslog (for testing) */
    { "mailto",   notify_mailto   }, /* send an email */
#ifdef HAVE_ZEPHYR
    { "zephyr",   notify_zephyr   }, /* send a zephyrgram */
#endif
    { "external", notify_external }, /* send via external program */
    { NULL,       NULL            }
};
