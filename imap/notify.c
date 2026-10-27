/* notify.c - Module to notify of new mail */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
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
#include "charset.h"

#include <jansson.h>

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

static void set_optstring(json_t *obj, const char *key, const char *val)
{
    if (val) json_object_set_new(obj, key, json_string(val));
}

/* Send one notification as a line of JSON on a stream socket, and read the
 * one-line JSON reply. */
static void notify_stream(const char *sockpath, const char *method,
                          const char *class, const char *priority,
                          const char *user, const char *mailbox,
                          int nopt, const char **options,
                          json_t *message, const char *fname)
{
    struct sockaddr_un sun_data;
    struct protstream *in = NULL, *out = NULL;
    struct buf line = BUF_INITIALIZER;
    json_t *req = json_object();
    json_t *res = NULL;
    char *payload = NULL;
    const char *status;
    int soc = -1;
    int c;

    set_optstring(req, "method", method);
    set_optstring(req, "class", class);
    set_optstring(req, "priority", priority);
    set_optstring(req, "user", user);
    set_optstring(req, "mailbox", mailbox);
    if (nopt) {
        json_t *jopts = json_array();
        for (int i = 0; i < nopt; i++)
            json_array_append_new(jopts, json_string(options[i]));
        json_object_set_new(req, "options", jopts);
    }
    if (message) json_object_set(req, "message", message);
    set_optstring(req, "filepath", fname);

    payload = json_dumps(req, JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (!payload) {
        xsyslog_ev(LOG_ERR, "notify.encode.failed",
                   lf_s("notify.method", method),
                   lf_s("notify.class", class));
        goto out;
    }

    memset((char *)&sun_data, 0, sizeof(sun_data));
    sun_data.sun_family = AF_UNIX;
    strlcpy(sun_data.sun_path, sockpath, sizeof(sun_data.sun_path));

    soc = socket(PF_UNIX, SOCK_STREAM, 0);
    if (soc < 0) {
        xsyslog_ev(LOG_ERR, "notify.socket.failed",
                   lf_s("notify.class", class));
        goto out;
    }

    if (connect(soc, (struct sockaddr *)&sun_data, sizeof(sun_data)) < 0) {
        xsyslog_ev(LOG_ERR, "notify.connect.failed",
                   lf_s("sys.path", sockpath),
                   lf_s("notify.class", class));
        goto out;
    }

    in = prot_new(soc, 0);
    out = prot_new(soc, 1);

    prot_printf(out, "%s\r\n", payload);
    prot_flush(out);

    while ((c = prot_getc(in)) != EOF && c != '\n') {
        if (c != '\r') buf_putc(&line, c);
    }

    res = json_loads(buf_cstring(&line), 0, NULL);
    status = json_string_value(json_object_get(res, "status"));
    if (!status) {
        xsyslog_ev(LOG_ERR, "notify.reply.unparseable",
                   lf_s("sys.path", sockpath),
                   lf_s("notify.method", method),
                   lf_s("notify.class", class));
    }
    else if (strcmp(status, "OK")) {
        xsyslog_ev(LOG_NOTICE, "notify.reply.not_ok",
                   lf_s("notify.method", method),
                   lf_s("notify.class", class),
                   lf_s("notify.status", status));
    }

out:
    if (in) prot_free(in);
    if (out) prot_free(out);
    if (soc >= 0) close(soc);
    buf_free(&line);
    free(payload);
    json_decref(req);
    json_decref(res);
}

EXPORTED void notify(const char *method,
                     const char *class, const char *priority,
                     const char *user, const char *mailbox,
                     int nopt, const char **options,
                     json_t *message, const char *fname)
{
    const char *notify_sock = config_getstring(IMAPOPT_NOTIFYSOCKET);
    int soc = -1;
    struct sockaddr_un sun_data;
    char buf[NOTIFY_MAXSIZE] = "", noptstr[20];
    const char *text = NULL;
    char *freeme = NULL;
    int buflen = 0;
    int i, r = 0;
    unsigned bufsiz;
    socklen_t optlen;
    struct buf logbuf = BUF_INITIALIZER;
    char *loginfo = NULL;

    if (notify_sock && !strncmp(notify_sock, "json:", 5)) {
        notify_stream(notify_sock+5, method, class, priority,
                      user, mailbox, nopt, options, message, fname);
        return;
    }

    /* A string message goes into the datagram as is */
    if (json_is_string(message))
        text = json_string_value(message);
    else if (message)
        text = freeme = json_dumps(message, JSON_COMPACT | JSON_PRESERVE_ORDER);

    buf_setcstr(&logbuf, class);
    if (user) {
        buf_printf(&logbuf, ", %s", user);
        if (mailbox) {
            buf_printf(&logbuf, ", %s", mailbox);
        }
    }
    loginfo = buf_release(&logbuf);

    soc = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (soc == -1) {
        syslog(LOG_ERR,
               "NOTIFY(%s): unable to create notify socket(): %m", loginfo);
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
        syslog(LOG_ERR,
               "NOTIFY(%s): unable to getsockopt(SO_SNDBUF) on socket: %m",
               loginfo);
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

    if (!r) r = add_arg(buf, bufsiz, text, &buflen);
    if (!r && fname) r = add_arg(buf, bufsiz, fname, &buflen);

    if (r) {
        syslog(LOG_ERR, "NOTIFY(%s): datagram too large", loginfo);
        goto out;
    }

    r = sendto(soc, buf, buflen, 0,
               (struct sockaddr *)&sun_data, sizeof(sun_data));

    if (r < 0) {
        syslog(LOG_ERR, "NOTIFY(%s): unable to sendto() socket: %m", loginfo);
        goto out;
    }
    if (r < buflen) {
        syslog(LOG_ERR, "NOTIFY(%s): short write to socket", loginfo);
        goto out;
    }

out:
    xclose(soc);
    free(loginfo);
    free(freeme);
}

EXPORTED json_t *notify_text(const char *text)
{
    json_t *jtext;
    char *utf8;

    if (!text) text = "";
    if ((jtext = json_string(text))) return jtext;

    /* Not valid UTF-8: replace the bad sequences */
    utf8 = charset_to_utf8cstr(text, strlen(text),
                               charset_lookupname("utf-8"), ENCODING_NONE);
    jtext = json_string(utf8 ? utf8 : "");
    free(utf8);

    return jtext;
}
