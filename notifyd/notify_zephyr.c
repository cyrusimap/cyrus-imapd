/* notify_zephyr.c - zephyr notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
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
#define MAIL_CLASS "MAIL"
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#include "notify_zephyr.h"

char* notify_zephyr(const char *class, const char *priority,
                    const char *user, const char *mailbox,
                    int nopt, char **options,
                    const char *message,
                    const char *fname __attribute__((unused)))
{
    ZNotice_t notice;
    int retval;
    char myhost[HOST_NAME_MAX], *mysender = NULL;
    struct buf msgbody = BUF_INITIALIZER;
    char *lines[2];

    if (!*user) return xstrdup("NO zephyr recipient not specified");

    if ((retval = ZInitialize()) != ZERR_NONE) {
        syslog(LOG_ERR, "IOERROR: cannot initialize zephyr: %m");
        return xstrdup("NO cannot initialize zephyr");
    }

    if (gethostname(myhost,sizeof(myhost)) == -1) {
        syslog(LOG_ERR, "IOERROR: cannot get hostname: %m");
        return xstrdup("NO zephyr cannot get hostname");
    }
    myhost[sizeof(myhost)-1] = '\0';

    if (*mailbox) {
        buf_printf(&msgbody, "You have new mail in %s.\n\n", mailbox);
    }

    if (*message) {
        buf_appendcstr(&msgbody, message);
        buf_putc(&msgbody, '\n');
    }

    lines[0] = myhost;
    lines[1] = (char *)buf_cstring(&msgbody);

    mysender = strconcat("imap@",
                         ZGetRealm(),
                         (char *)NULL);

    memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = UNSAFE;
    notice.z_class = *class ? (char *) class : (char *) MAIL_CLASS;
    notice.z_class_inst = *priority ? (char *) priority :
        *mailbox ? (char *) mailbox : (char *) "INBOX";

    notice.z_opcode = (char *) "";
    notice.z_sender = mysender;
    notice.z_default_format = (char *) "From Post Office $1:\n$2";

    notice.z_recipient = (char *) user;

    retval = ZSendList(&notice,lines,2,ZNOAUTH);

    /* do any additional users */
    while (retval == ZERR_NONE && nopt) {
        notice.z_recipient = (char *) options[--nopt];

        retval = ZSendList(&notice,lines,2,ZNOAUTH);
    }

    buf_free(&msgbody);
    free(mysender);

    if (retval != ZERR_NONE) {
        syslog(LOG_ERR, "IOERROR: cannot send zephyr notice: %m");
        return xstrdup("NO cannot send zephyr notice");
    }

    return xstrdup("OK zephyr notification successful");
}
