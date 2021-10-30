/* mupdate-client.c -- cyrus murder database clients
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <sysexits.h>
#include <syslog.h>
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "global.h"
#include "mupdate.h"
#include "prot.h"
#include "protocol.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

static struct protocol_t mupdate_protocol =
{ "mupdate", "mupdate", TYPE_STD,
  { { { 1, "* OK" },
      { NULL, NULL, "* OK", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_SKIP_FIRST_WORD,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "COMPRESS=DEFLATE", CAPA_COMPRESS },
          { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 1 },
      { "A01 AUTHENTICATE", USHRT_MAX, 1, "A01 OK", "A01 NO", "", "*", NULL, 0 },
      { "Z01 COMPRESS \"DEFLATE\"", NULL, "Z01 OK" },
      { "N01 NOOP", NULL, "N01 OK" },
      { "Q01 LOGOUT", NULL, "Q01 " } } }
};

EXPORTED int mupdate_connect(const char *server,
                    const char *port __attribute__((unused)),
                    mupdate_handle **handle,
                    sasl_callback_t *cbs)
{
    mupdate_handle *h = NULL;
    const char *status = NULL;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    /* open connection to 'server' */
    if (!server) {
        server = config_mupdate_server;
        if (server == NULL) {
            fatal("couldn't get mupdate server name", EX_UNAVAILABLE);
        }
    }

    h = xzmalloc(sizeof(mupdate_handle));
    *handle = h;

    h->sasl_cb = NULL;
    if (!cbs) {
        cbs = mysasl_callbacks(config_getstring(IMAPOPT_MUPDATE_USERNAME),
                               config_getstring(IMAPOPT_MUPDATE_AUTHNAME),
                               config_getstring(IMAPOPT_MUPDATE_REALM),
                               config_getstring(IMAPOPT_MUPDATE_PASSWORD));
        h->sasl_cb = cbs;
    }

    h->conn = backend_connect(NULL, server, &mupdate_protocol,
                              "", cbs, &status, -1);

    if (!h->conn) {
        free_callbacks(h->sasl_cb);
        h->sasl_cb = NULL;
        syslog(LOG_ERR, "mupdate_connect failed: %s", status ? status : "no auth status");
        return MUPDATE_NOCONN;
    }

    h->saslcompleted = 1;

    /* SUCCESS */
    return 0;
}

EXPORTED void mupdate_disconnect(mupdate_handle **hp)
{
    mupdate_handle *h;

    if (!hp || !(*hp)) return;
    h = *hp;

    backend_disconnect(h->conn);
    free(h->conn);

    free_callbacks(h->sasl_cb);
    h->sasl_cb = NULL;

    buf_free(&(h->tag));
    buf_free(&(h->cmd));
    buf_free(&(h->arg1));
    buf_free(&(h->arg2));
    buf_free(&(h->arg3));

    free(h->acl);

    free(h);
    *hp = NULL;
}

/* We're really only looking for an OK or NO or BAD here -- and the callback
 * is never called in those cases.  So if the callback is called, we have
 * an error! */
static int mupdate_scarf_one(struct mupdate_mailboxdata *mdata __attribute__((unused)),
                             const char *cmd,
                             void *context __attribute__((unused)))
{
    syslog(LOG_ERR, "mupdate_scarf_one was called, but shouldn't be.  Command received was %s", cmd);
    return -1;
}

EXPORTED int mupdate_activate(mupdate_handle *handle,
                     const char *mailbox, const char *location,
                     const char *acl)
{
    int ret;
    enum mupdate_cmd_response response;
    const char *p;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!mailbox) {
        syslog(LOG_ERR, "%s: no mailbox", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!location) {
        syslog(LOG_ERR, "%s: no location", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    /* make sure we don't have a double server!partition */
    if ((p = strchr(location, '!')) && strchr(p+1, '!')) {
        syslog(
                LOG_ERR,
                "%s: double ! detected in location '%s'",
                __func__,
                location
            );

        return MUPDATE_BADPARAM;
    }

    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
        /* we don't care about the server part, everything is local */
        if (p) location = p + 1;
    }

    prot_printf(handle->conn->out,
                "X%u ACTIVATE "
                "{" SIZE_T_FMT "+}\r\n%s "
                "{" SIZE_T_FMT "+}\r\n%s "
                "{" SIZE_T_FMT "+}\r\n%s\r\n",
                handle->tagn++,
                strlen(mailbox), mailbox,
                strlen(location), location,
                (acl ? strlen(acl): 0), (acl ? acl : "")
        );

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
    if (ret) {
        return ret;
    } else if (response != MUPDATE_OK) {
        return MUPDATE_FAIL;
    } else {
        return 0;
    }
}

HIDDEN int mupdate_reserve(mupdate_handle *handle,
                    const char *mailbox, const char *location)
{
    int ret;
    enum mupdate_cmd_response response;
    const char *p;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!mailbox) {
        syslog(LOG_ERR, "%s: no mailbox", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!location) {
        syslog(LOG_ERR, "%s: no location", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    /* make sure we don't have a double server!partition */
    if ((p = strchr(location, '!')) && strchr(p+1, '!')) {
        syslog(
                LOG_ERR,
                "%s: double ! detected in location '%s'",
                __func__,
                location
            );

        return MUPDATE_BADPARAM;
    }

    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
        /* we don't care about the location part, everything is local */
        if (p) location = p + 1;
    }

    prot_printf(handle->conn->out,
                "X%u RESERVE "
                "{" SIZE_T_FMT "+}\r\n%s "
                "{" SIZE_T_FMT "+}\r\n%s\r\n",
                handle->tagn++,
                strlen(mailbox), mailbox,
                strlen(location), location
        );

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
    if (ret) {
        return ret;
    } else if (response != MUPDATE_OK) {
        return MUPDATE_FAIL_RESERVE;
    } else {
        return 0;
    }
}

EXPORTED int mupdate_deactivate(mupdate_handle *handle,
                       const char *mailbox, const char *location)
{
    int ret;
    enum mupdate_cmd_response response;
    const char *p;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!mailbox) {
        syslog(LOG_ERR, "%s: no mailbox", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!location) {
        syslog(LOG_ERR, "%s: no location", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    /* make sure we don't have a double server!partition */
    if ((p = strchr(location, '!')) && strchr(p+1, '!')) {
        syslog(
                LOG_ERR,
                "%s: double ! detected in location '%s'",
                __func__,
                location
            );

        return MUPDATE_BADPARAM;
    }

    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
        /* we don't care about the server part, everything is local */
        if (p) location = p + 1;
    }

    prot_printf(handle->conn->out,
            "X%u DEACTIVATE "
            "{" SIZE_T_FMT "+}\r\n%s "
            "{" SIZE_T_FMT "+}\r\n%s\r\n",
            handle->tagn++,
            strlen(mailbox), mailbox,
            strlen(location), location
        );

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
    if (ret) {
        return ret;
    } else if (response != MUPDATE_OK) {
        return MUPDATE_FAIL_RESERVE;
    } else {
        return 0;
    }
}

EXPORTED int mupdate_delete(mupdate_handle *handle,
                   const char *mailbox)
{
    int ret;
    enum mupdate_cmd_response response;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!mailbox) {
        syslog(LOG_ERR, "%s: no mailbox", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    prot_printf(handle->conn->out,
                "X%u DELETE {" SIZE_T_FMT "+}\r\n%s\r\n", handle->tagn++,
                strlen(mailbox), mailbox);

    ret = mupdate_scarf(handle, mupdate_scarf_one, NULL, 1, &response);
    if (ret) {
        return ret;
    } else if (response != MUPDATE_OK) {
        return MUPDATE_FAIL;
    } else {
        return 0;
    }
}


static int mupdate_find_cb(struct mupdate_mailboxdata *mdata,
                           const char *cmd, void *context)
{
    struct mupdate_handle_s *h = (struct mupdate_handle_s *)context;

    if (!h || !cmd || !mdata) return 1;

    /* coyp the data to the handle storage */
    /* xxx why can't we just point to the 'mdata' buffers? */
    strlcpy(h->mailbox_buf, mdata->mailbox, sizeof(h->mailbox_buf));
    strlcpy(h->location_buf, mdata->location, sizeof(h->location_buf));

    if (!strncmp(cmd, "MAILBOX", 7)) {
        h->mailboxdata_buf.t = ACTIVE;

        free(h->acl);
        h->acl = xstrdup(mdata->acl);
    } else if (!strncmp(cmd, "RESERVE", 7)) {
        h->mailboxdata_buf.t = RESERVE;
        free(h->acl);
        h->acl = xstrdup("");
    } else {
        /* Bad command */
        return 1;
    }

    h->mailboxdata_buf.mailbox = h->mailbox_buf;
    h->mailboxdata_buf.location = h->location_buf;
    h->mailboxdata_buf.acl = h->acl;

    return 0;
}

EXPORTED int mupdate_find(mupdate_handle *handle, const char *mailbox,
                 struct mupdate_mailboxdata **target)
{
    int ret;
    enum mupdate_cmd_response response;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!mailbox) {
        syslog(LOG_ERR, "%s: no mailbox", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!target) {
        syslog(LOG_ERR, "%s: no target", __func__);
        return MUPDATE_BADPARAM;
    }

    prot_printf(handle->conn->out,
                "X%u FIND {" SIZE_T_FMT "+}\r\n%s\r\n", handle->tagn++,
                strlen(mailbox), mailbox);

    memset(&(handle->mailboxdata_buf), 0, sizeof(handle->mailboxdata_buf));

    ret = mupdate_scarf(handle, mupdate_find_cb, handle, 1, &response);

    /* note that the response is still OK even if there was no data returned,
     * so we have to make sure we actually filled in the data too */
    if (!ret && response == MUPDATE_OK && handle->mailboxdata_buf.mailbox) {
        *target = &(handle->mailboxdata_buf);
        return 0;
    } else if (!ret && response == MUPDATE_OK) {
        /* it looked okay, but we didn't get a mailbox */
        *target = NULL;
        return MUPDATE_MAILBOX_UNKNOWN;
    } else {
        /* Something Bad happened */
        *target = NULL;
        return ret ? ret : MUPDATE_FAIL;
    }
}

EXPORTED int mupdate_list(mupdate_handle *handle, mupdate_callback callback,
                 const char *prefix, void *context)
{
    int ret;
    enum mupdate_cmd_response response;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!callback) {
        syslog(LOG_ERR, "%s: no callback", __func__);
        return MUPDATE_BADPARAM;
    }

    if (prefix) {
        prot_printf(handle->conn->out,
                    "X%u LIST {" SIZE_T_FMT "+}\r\n%s\r\n", handle->tagn++,
                    strlen(prefix), prefix);
    } else {
        prot_printf(handle->conn->out,
                    "X%u LIST\r\n", handle->tagn++);
    }

    ret = mupdate_scarf(handle, callback, context, 1, &response);

    if (ret) {
        return ret;
    } else if (response != MUPDATE_OK) {
        return MUPDATE_FAIL;
    } else {
        return 0;
    }
}


EXPORTED int mupdate_noop(mupdate_handle *handle, mupdate_callback callback,
                 void *context)
{
    int ret;
    enum mupdate_cmd_response response;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!callback) {
        syslog(LOG_ERR, "%s: no callback", __func__);
        return MUPDATE_BADPARAM;
    }

    prot_printf(handle->conn->out,
                "X%u NOOP\r\n", handle->tagn++);

    ret = mupdate_scarf(handle, callback, context, 1, &response);

    if (!ret && response == MUPDATE_OK) {
        return 0;
    } else {
        return ret ? ret : MUPDATE_FAIL;
    }
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->conn->in); \
                                 if ((ch) != '\n') { syslog(LOG_ERR, \
                             "extra arguments received, aborting connection");\
                                 r = MUPDATE_PROTOCOL_ERROR;\
                                 goto done; }} while(0)

/* Scarf up the incoming data and perform the requested operations */
EXPORTED int mupdate_scarf(mupdate_handle *handle,
                  mupdate_callback callback,
                  void *context,
                  int wait_for_ok,
                  enum mupdate_cmd_response *response)
{
    struct mupdate_mailboxdata box;
    int r = 0;

    if (!handle) {
        syslog(LOG_ERR, "%s: no mupdate_handle", __func__);
        return MUPDATE_BADPARAM;
    }

    if (!callback) {
        syslog(LOG_ERR, "%s: no callback", __func__);
        return MUPDATE_BADPARAM;
    }

    /* keep going while we have input or if we're waiting for an OK */
    while (!r) {
        int ch;
        char *p;

        if (wait_for_ok) {
            prot_BLOCK(handle->conn->in);
        } else {
            /* check for input */
            prot_NONBLOCK(handle->conn->in);
            ch = prot_getc(handle->conn->in);

            if (ch == EOF && errno == EAGAIN) {
                /* this was just "no input" we return 0 */
                goto done;
            } else if (ch == EOF) {
                /* this was a fatal error */
                r = MUPDATE_NOCONN;
                goto done;
            } else {
                /* there's input waiting, put back our character */
                prot_ungetc(ch, handle->conn->in);
            }

            /* Set it back to blocking so we don't get half a word */
            prot_BLOCK(handle->conn->in);
        }

        ch = getword(handle->conn->in, &(handle->tag));
        if (ch == EOF) {
            /* this was a fatal error */
            r = MUPDATE_NOCONN;
            goto done;
        }

        if (ch != ' ') {
            /* We always have a command */
            syslog(LOG_ERR, "Protocol error from master: no tag");
            r = MUPDATE_PROTOCOL_ERROR;
            goto done;
        }
        ch = getword(handle->conn->in, &(handle->cmd));
        if (ch != ' ') {
            /* We always have an argument */
            syslog(LOG_ERR, "Protocol error from master: no keyword");
            r = MUPDATE_PROTOCOL_ERROR;
            break;
        }

        if (Uislower(handle->cmd.s[0])) {
            handle->cmd.s[0] = toupper((unsigned char) handle->cmd.s[0]);
        }
        for (p = &(handle->cmd.s[1]); *p; p++) {
            if (Uislower(*p))
                *p = toupper((unsigned char) *p);
        }

        switch(handle->cmd.s[0]) {
        case 'B':
            if (!strncmp(handle->cmd.s, "BAD", 3)) {
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
                CHECKNEWLINE(handle, ch);

                syslog(LOG_ERR, "mupdate BAD response: %s", handle->arg1.s);
                if (wait_for_ok && response) {
                    *response = MUPDATE_BAD;
                }
                goto done;
            } else if (!strncmp(handle->cmd.s, "BYE", 3)) {
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
                CHECKNEWLINE(handle, ch);

                syslog(LOG_ERR, "mupdate BYE response: %s", handle->arg1.s);
                if (wait_for_ok && response) {
                    *response = MUPDATE_BYE;
                }
                goto done;
            }
            goto badcmd;

        case 'D':
            if (!strncmp(handle->cmd.s, "DELETE", 6)) {
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
                CHECKNEWLINE(handle, ch);

                memset(&box, 0, sizeof(box));
                box.mailbox = handle->arg1.s;

                /* Handle delete command */
                r = callback(&box, handle->cmd.s, context);
                if (r) {
                    syslog(LOG_ERR,
                           "error deleting mailbox: callback returned %d", r);
                    goto done;
                }
                break;
            }
            goto badcmd;

        case 'M':
            if (!strncmp(handle->cmd.s, "MAILBOX", 7)) {
                /* Mailbox Name */
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
                if (ch != ' ') {
                    r = MUPDATE_PROTOCOL_ERROR;
                    goto done;
                }

                /* Server */
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg2));
                if (ch != ' ') {
                    r = MUPDATE_PROTOCOL_ERROR;
                    goto done;
                }

                /* ACL */
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg3));
                CHECKNEWLINE(handle, ch);

                /* Handle mailbox command */
                memset(&box, 0, sizeof(box));
                box.mailbox = handle->arg1.s;
                box.location = handle->arg2.s;
                box.acl = handle->arg3.s;
                r = callback(&box, handle->cmd.s, context);
                if (r) { /* callback error ? */
                    syslog(LOG_ERR,
                           "error activating mailbox: callback returned %d", r);
                    goto done;
                }
                break;
            }
            goto badcmd;
        case 'N':
            if (!strncmp(handle->cmd.s, "NO", 2)) {
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
                CHECKNEWLINE(handle, ch);

                syslog(LOG_DEBUG, "mupdate NO response: %s", handle->arg1.s);
                if (wait_for_ok) {
                    if (response) *response = MUPDATE_NO;
                    goto done;
                }
                break;
            }
            goto badcmd;
        case 'O':
            if (!strncmp(handle->cmd.s, "OK", 2)) {
                /* It's all good, grab the attached string and move on */
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));

                CHECKNEWLINE(handle, ch);
                if (wait_for_ok) {
                    if (response) *response = MUPDATE_OK;
                    goto done;
                }
                break;
            }
            goto badcmd;
        case 'R':
            if (!strncmp(handle->cmd.s, "RESERVE", 7)) {
                /* Mailbox Name */
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg1));
                if (ch != ' ') {
                    r = MUPDATE_PROTOCOL_ERROR;
                    goto done;
                }

                /* Server */
                ch = getstring(handle->conn->in, handle->conn->out, &(handle->arg2));
                CHECKNEWLINE(handle, ch);

                /* Handle reserve command */
                memset(&box, 0, sizeof(box));
                box.mailbox = handle->arg1.s;
                box.location = handle->arg2.s;
                r = callback(&box, handle->cmd.s, context);
                if (r) { /* callback error ? */
                    syslog(LOG_ERR,
                           "error reserving mailbox: callback returned %d", r);
                    goto done;
                }

                break;
            }
            goto badcmd;

        default:
        badcmd:
            /* Bad Command */
            syslog(LOG_ERR, "bad/unexpected command from master: %s",
                   handle->cmd.s);
            r = MUPDATE_PROTOCOL_ERROR;
            goto done;
        }
    }

 done:
    /* reset blocking */
    prot_NONBLOCK(handle->conn->in);

    return r;
}

EXPORTED void kick_mupdate(void)
{
    char buf[2048];
    struct buf addrbuf = BUF_INITIALIZER;
    struct sockaddr_un srvaddr;
    int s, r;
    int len;

    /* no server? drop out */
    if (!config_mupdate_server)
        return;

    /* don't kick on standard backends */
    if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD
        && config_getstring(IMAPOPT_PROXYSERVERS))
        return;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        syslog(LOG_ERR, "socket: %m");
        return;
    }

    buf_appendcstr(&addrbuf, config_dir);
    buf_appendcstr(&addrbuf, FNAME_MUPDATE_TARGET_SOCK);
    if (buf_len(&addrbuf) >= sizeof(srvaddr.sun_path)) {
        syslog(LOG_ERR, "kick_mupdate: configured socket path '%s' is too long"
                        " (maximum length is " SIZE_T_FMT ")",
                        buf_cstring(&addrbuf), sizeof(srvaddr.sun_path) - 1);
        fatal("socket path too long", EX_CONFIG);
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strlcpy(srvaddr.sun_path, buf_cstring(&addrbuf), sizeof(srvaddr.sun_path));
    len = sizeof(srvaddr.sun_family) + strlen(srvaddr.sun_path) + 1;

    r = connect(s, (struct sockaddr *)&srvaddr, len);
    if (r == -1) {
        syslog(LOG_ERR, "kick_mupdate: can't connect to target: %m");
        goto done;
    }

    r = read(s, buf, sizeof(buf));
    if (r <= 0) {
        syslog(LOG_ERR, "kick_mupdate: can't read from target: %m");
    }

 done:
    buf_free(&addrbuf);
    close(s);
    return;
}
