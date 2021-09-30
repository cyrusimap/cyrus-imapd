/* notify_log.c -- syslog notification method
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

#include "notify_log.h"

#include <syslog.h>
#include <string.h>
#include <stdio.h>

char* notify_log(const char *class, const char *priority,
                 const char *user, const char *mailbox,
                 int nopt, char **options,
                 const char *message,
                 const char *fname __attribute__((unused)))
{
    char opt_str[1024] = "";
    const char *sep = "";
    int i;

    if (nopt) {
        strcpy(opt_str, "(");
        for (i = 0; i < nopt; i++, sep = ", ") {
            snprintf(opt_str+strlen(opt_str), sizeof(opt_str) - 2, "%s%s",
                     sep, options[i]);
        }
        strcat(opt_str, ")");
    }

/*  Not needed, we opened the log file in cyrus_init */
/*    openlog("notifyd", LOG_PID, SYSLOG_FACILITY); */

    syslog(LOG_INFO, "%s, %s, %s, %s, %s \"%s\"",
           class, priority, user, mailbox, opt_str, message);
    closelog();

    return strdup("OK log notification successful");
}
