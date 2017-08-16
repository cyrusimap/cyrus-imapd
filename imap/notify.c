/* notify.c -- Module to notify of new mail
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "append.h"
#include "global.h"
#include "notify.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mailbox.h"
#include "util.h"
#include "times.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define FNAME_NOTIFY_SOCK "/socket/notify"

static int add_arg(char *buf, int max_size, const char *arg, int *buflen)
{
    const char *myarg = (arg ? arg : "");
    int len = strlen(myarg) + 1;

    if (*buflen + len > max_size) return -1;

    strcat(buf+*buflen, myarg);
    *buflen += len;

    return 0;
}

static void notify_dlist(const char *sockpath, const char *method,
                         const char *class, const char *priority,
                         const char *user, const char *mailbox,
                         int nopt, const char **options,
                         const char *message, const char *fname)
{
    struct sockaddr_un sun_data;
    struct protstream *in = NULL, *out = NULL;
    struct dlist *dl = dlist_newkvlist(NULL, "NOTIFY");
    struct dlist *res = NULL;
    struct dlist *il;
    int c;
    int soc = -1;
    int i;

    dlist_setatom(dl, "METHOD", method);
    dlist_setatom(dl, "CLASS", class);
    dlist_setatom(dl, "PRIORITY", priority);
    dlist_setatom(dl, "USER", user);
    dlist_setatom(dl, "MAILBOX", mailbox);
    il = dlist_newlist(dl, "OPTIONS");
    for (i = 0; i < nopt; i++)
        dlist_setatom(il, NULL, options[i]);
    dlist_setatom(dl, "MESSAGE", message);
    dlist_setatom(dl, "FILEPATH", fname);

    memset((char *)&sun_data, 0, sizeof(sun_data));
    sun_data.sun_family = AF_UNIX;
    strlcpy(sun_data.sun_path, sockpath, sizeof(sun_data.sun_path));

    soc = socket(PF_UNIX, SOCK_STREAM, 0);
    if (soc < 0) {
        syslog(LOG_ERR, "NOTIFY: unable to create notify socket(): %m");
        goto out;
    }

    if (connect(soc, (struct sockaddr *)&sun_data, sizeof(sun_data)) < 0) {
        syslog(LOG_ERR, "NOTIFY: failed to connect to %s: %m", sockpath);
        goto out;
    }

    in = prot_new(soc, 0);
    out = prot_new(soc, 1);
    /* Force use of LITERAL+ */
    prot_setisclient(in, 1);
    prot_setisclient(out, 1);

    dlist_print(dl, 1, out);
    prot_printf(out, "\r\n");
    prot_flush(out);

    c = dlist_parse(&res, 1, 0, in);
    if (c == '\r') c = prot_getc(in);
    /* XXX - do something with the response?  Like have NOTIFY answer */
    if (c == '\n' && res && res->name) {
        syslog(LOG_NOTICE, "NOTIFY: response %s to method %s", res->name, method);
    }
    else {
        syslog(LOG_ERR, "NOTIFY: error sending %s to %s", method, sockpath);
    }

out:
    if (in) prot_free(in);
    if (out) prot_free(out);
    if (soc >= 0) close(soc);
    dlist_free(&dl);
    dlist_free(&res);
}

EXPORTED int notify_at(time_t when, const char *method,
            const char *class, const char *priority,
            const char *user, const char *mboxname,
            int nopt, const char **options,
            const char *message)
{
    struct mailbox *mailbox = NULL;
    char datestr[RFC5322_DATETIME_MAX+1];
    int i;
    int r = mailbox_open_iwl("#events", &mailbox);
    struct buf buf = BUF_INITIALIZER;

    FILE *f = NULL;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    struct appendstate as;
    struct stagemsg *stage = NULL;

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = mboxlist_createmailbox("#events", 0, config_defpartition, 1,
                                   "cyrus", NULL, 0, 0, 0, 0, NULL);
        if (!r) r = mailbox_open_iwl("#events", &mailbox);
    }
    if (r) goto done;

    /* Prepare to stage the message */
    f = append_newstage(mailbox->name, when, 0, &stage);
    if (!f) {
        r = IMAP_IOERROR;
        goto done;
    }

    syslog(LOG_NOTICE, "APPENDING TO STAGE: %s (%u)", mailbox->name, (unsigned)when);
    time_to_rfc5322(when, datestr, sizeof(datestr));
    fprintf(f, "Date: %s\r\n", datestr);
    fprintf(f, "Method: %s\r\n", charset_encode_mimeheader(method, 0));
    fprintf(f, "Class: %s\r\n", charset_encode_mimeheader(class, 0));
    fprintf(f, "Priority: %s\r\n", charset_encode_mimeheader(priority, 0));
    fprintf(f, "User: %s\r\n", charset_encode_mimeheader(user, 0));
    fprintf(f, "Mailbox: %s\r\n", charset_encode_mimeheader(mboxname, 0));
    for (i = 0; i < nopt; i++)
        fprintf(f, "Option: %s\r\n", charset_encode_mimeheader(options[i], 0));
    fprintf(f, "Message: %s\r\n", charset_encode_mimeheader(message, 0));
    fprintf(f, "\r\n");

    fclose(f);
    f = NULL;

    r = append_setup_mbox(&as, mailbox, "cyrus", NULL,
                          0, qdiffs, 0, 0, 0);
    if (r) goto done;

    struct body *body = NULL;
    r = append_fromstage(&as, &body, stage, when, 0, 0, 0);
    if (body) {
        message_free_body(body);
        free(body);
    }
    if (r) goto done;

    r = append_commit(&as);
    if (r) goto done;

done:
    append_removestage(stage);
    append_abort(&as);
    mailbox_close(&mailbox);
    buf_free(&buf);
    if (f) fclose(f);

    return r;
}

EXPORTED void notify(const char *method,
            const char *class, const char *priority,
            const char *user, const char *mailbox,
            int nopt, const char **options,
            const char *message, const char *fname)
{
    const char *notify_sock = config_getstring(IMAPOPT_NOTIFYSOCKET);
    int soc = -1;
    struct sockaddr_un sun_data;
    char buf[NOTIFY_MAXSIZE] = "", noptstr[20];
    int buflen = 0;
    int i, r = 0;
    unsigned bufsiz;
    socklen_t optlen;

    if (!strncmp(notify_sock, "dlist:", 6)) {
        notify_dlist(notify_sock+6, method, class, priority,
                            user, mailbox, nopt, options,
                            message, fname);
        return;
    }

    soc = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (soc == -1) {
        syslog(LOG_ERR, "unable to create notify socket(): %m");
        goto out;
    }

    memset((char *)&sun_data, 0, sizeof(sun_data));
    sun_data.sun_family = AF_UNIX;
    if (notify_sock) {
        strlcpy(sun_data.sun_path, notify_sock, sizeof(sun_data.sun_path));
    }
    else {
        strlcpy(sun_data.sun_path, config_dir, sizeof(sun_data.sun_path));
        strlcat(sun_data.sun_path,
                FNAME_NOTIFY_SOCK, sizeof(sun_data.sun_path));
    }

    /* Get send buffer size */
    optlen = sizeof(bufsiz);
    r = getsockopt(soc, SOL_SOCKET, SO_SNDBUF, &bufsiz, &optlen);
    if (r == -1) {
        syslog(LOG_ERR, "unable to getsockopt(SO_SNDBUF) on notify socket: %m");
        goto out;
    }

    /* Use minimum of 1/10 of send buffer size (-overhead) NOTIFY_MAXSIZE */
    bufsiz = MIN(bufsiz / 10 - 32, NOTIFY_MAXSIZE);

    /*
     * build request of the form:
     *
     * method NUL class NUL priority NUL user NUL mailbox NUL
     *   nopt NUL N(option NUL) message NUL
     */

    r = add_arg(buf, bufsiz, method, &buflen);
    if (!r) r = add_arg(buf, bufsiz, class, &buflen);
    if (!r) r = add_arg(buf, bufsiz, priority, &buflen);
    if (!r) r = add_arg(buf, bufsiz, user, &buflen);
    if (!r) r = add_arg(buf, bufsiz, mailbox, &buflen);

    snprintf(noptstr, sizeof(noptstr), "%d", nopt);
    if (!r) r = add_arg(buf, bufsiz, noptstr, &buflen);

    for (i = 0; !r && i < nopt; i++) {
        r = add_arg(buf, bufsiz, options[i], &buflen);
    }

    if (!r) r = add_arg(buf, bufsiz, message, &buflen);
    if (!r && fname) r = add_arg(buf, bufsiz, fname, &buflen);

    if (r) {
        syslog(LOG_ERR, "notify datagram too large, %s, %s",
               user, mailbox);
        goto out;
    }

    r = sendto(soc, buf, buflen, 0,
               (struct sockaddr *)&sun_data, sizeof(sun_data));

    if (r < 0) {
        syslog(LOG_ERR, "unable to sendto() notify socket: %m");
        goto out;
    }
    if (r < buflen) {
        syslog(LOG_ERR, "short write to notify socket");
        goto out;
    }

out:
    xclose(soc);
}
