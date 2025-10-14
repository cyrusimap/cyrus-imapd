/* notify_zephyr.c -- zephyr notification method
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <zephyr/zephyr.h>
#include <syslog.h>

#include "xmalloc.h"
#include "util.h"

#ifndef MAIL_CLASS
# define MAIL_CLASS "MAIL"
#endif

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 256
#endif

#include "notify_zephyr.h"

char *notify_zephyr(const char *class,
                    const char *priority,
                    const char *user,
                    const char *mailbox,
                    int nopt,
                    char **options,
                    const char *message,
                    const char *fname __attribute__((unused)))
{
    ZNotice_t notice;
    int retval;
    char myhost[HOST_NAME_MAX], *mysender = NULL;
    struct buf msgbody = BUF_INITIALIZER;
    char *lines[2];

    if (!*user) {
        return xstrdup("NO zephyr recipient not specified");
    }

    if ((retval = ZInitialize()) != ZERR_NONE) {
        syslog(LOG_ERR, "IOERROR: cannot initialize zephyr: %m");
        return xstrdup("NO cannot initialize zephyr");
    }

    if (gethostname(myhost, sizeof(myhost)) == -1) {
        syslog(LOG_ERR, "IOERROR: cannot get hostname: %m");
        return xstrdup("NO zephyr cannot get hostname");
    }
    myhost[sizeof(myhost) - 1] = '\0';

    if (*mailbox) {
        buf_printf(&msgbody, "You have new mail in %s.\n\n", mailbox);
    }

    if (*message) {
        buf_appendcstr(&msgbody, message);
        buf_putc(&msgbody, '\n');
    }

    lines[0] = myhost;
    lines[1] = (char *) buf_cstring(&msgbody);

    mysender = strconcat("imap@", ZGetRealm(), (char *) NULL);

    memset((char *) &notice, 0, sizeof(notice));
    notice.z_kind = UNSAFE;
    notice.z_class = *class ? (char *) class : (char *) MAIL_CLASS;
    notice.z_class_inst = *priority  ? (char *) priority
                          : *mailbox ? (char *) mailbox
                                     : (char *) "INBOX";

    notice.z_opcode = (char *) "";
    notice.z_sender = mysender;
    notice.z_default_format = (char *) "From Post Office $1:\n$2";

    notice.z_recipient = (char *) user;

    retval = ZSendList(&notice, lines, 2, ZNOAUTH);

    /* do any additional users */
    while (retval == ZERR_NONE && nopt) {
        notice.z_recipient = (char *) options[--nopt];

        retval = ZSendList(&notice, lines, 2, ZNOAUTH);
    }

    buf_free(&msgbody);
    free(mysender);

    if (retval != ZERR_NONE) {
        syslog(LOG_ERR, "IOERROR: cannot send zephyr notice: %m");
        return xstrdup("NO cannot send zephyr notice");
    }

    return xstrdup("OK zephyr notification successful");
}
