/* notify_log.c - syslog notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "notify_log.h"

#include <syslog.h>
#include <string.h>
#include <stdio.h>

#include "lib/util.h"

char* notify_log(const char *class, const char *priority,
                 const char *user, const char *mailbox,
                 int nopt, char **options,
                 const char *message,
                 const char *fname __attribute__((unused)))
{
    struct buf opt_str = BUF_INITIALIZER;
    const char *sep = "";
    int i;

    if (nopt) {
        buf_putc(&opt_str, '(');
        for (i = 0; i < nopt; i++, sep = ", ") {
            buf_printf(&opt_str, "%s%s", sep, options[i]);
        }
        buf_putc(&opt_str, ')');
    }

    xsyslog_ev(LOG_INFO, "notify.logged",
               lf_s("notify.class", class),
               lf_s("notify.priority", priority),
               lf_s_opt("u.username", user),
               lf_s_opt("mbox.name", mailbox),
               lf_buf("notify.options", &opt_str),
               lf_s("notify.message", message));

    buf_free(&opt_str);
    return strdup("OK log notification successful");
}
