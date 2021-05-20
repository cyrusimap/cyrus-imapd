/* smtpclient.c -- Routines for sending a message via SMTP
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

#include <assert.h>
#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <syslog.h>

#include "backend.h"
#include "xmalloc.h"
#include "global.h"
#include "smtpclient.h"
#include "telemetry.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

typedef struct {
    char code[3];
    struct buf text; /* Zero-terminated reply text, excluding CRLF. OK to overwrite. */
    int is_last;
} smtp_resp_t;

struct smtpclient {
    /* SMTP backend. Client implementations can store
     * their context data in backend->context. */
    struct backend *backend;

    /* Client implementations can free their context
     * stored in backend->context. */
    int (*free_context)(void *ctx);

    /* Telemetry log */
    int logfd;

    /* Internal state */
    hash_table *have_exts;
    struct buf buf;
    char *authid;
    char *notify;
    char *ret;
    char *by;
    unsigned long msgsize;
    smtp_resp_t resp;
};

enum {
    SMTPCLIENT_CAPA_DSN       = (1 << 3),
    SMTPCLIENT_CAPA_DELIVERBY = (1 << 4),
    SMTPCLIENT_CAPA_SIZE      = (1 << 5),
    SMTPCLIENT_CAPA_STATUS    = (1 << 6),
    SMTPCLIENT_CAPA_FUTURE    = (1 << 7),
    SMTPCLIENT_CAPA_PRIORITY  = (1 << 8),
    SMTPCLIENT_CAPA_SENDCHECK = (1 << 9)
};

static struct protocol_t smtp_protocol =
{ "smtp", "smtp", TYPE_STD,
  { { { 0, "220 " },
      { "EHLO", "localhost", "250 ", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_SKIP_FIRST_WORD|CAPAF_DASH_STUFFING,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "DSN", SMTPCLIENT_CAPA_DSN },
          { "DELIVERYBY", SMTPCLIENT_CAPA_DELIVERBY },
          { "SIZE", SMTPCLIENT_CAPA_SIZE },
          { "ENHANCEDSTATUSCODES", SMTPCLIENT_CAPA_STATUS },
          { "FUTURERELEASE", SMTPCLIENT_CAPA_FUTURE },
          { "MT-PRIORITY", SMTPCLIENT_CAPA_PRIORITY },
          { "SENDCHECK", SMTPCLIENT_CAPA_SENDCHECK },
          { NULL, 0 } } },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL },
      { "NOOP", NULL, "250" },
      { "QUIT", NULL, "221" } } }
};


/* SMTP protocol implementation */

typedef int smtp_readcb_t(smtpclient_t *sm, void *rock);

static int smtpclient_read(smtpclient_t *sm, smtp_readcb_t *cb, void *rock);

static int smtpclient_writebuf(smtpclient_t *sm, struct buf *buf, int flush);
static int smtpclient_ehlo(smtpclient_t *sm);
static int smtpclient_rset(smtpclient_t *sm);
static int smtpclient_quit(smtpclient_t *sm);
static int smtpclient_from(smtpclient_t *sm, smtp_addr_t *addr);
static int smtpclient_rcpt_to(smtpclient_t *sm, ptrarray_t *rcpt);
static int smtpclient_data(smtpclient_t *sm, struct protstream *data);
static void smtpclient_logerror(smtpclient_t *sm, const char *cmd, int r);

EXPORTED int smtpclient_open(smtpclient_t **smp)
{
    int r = 0;
    const char *backend = config_getstring(IMAPOPT_SMTP_BACKEND);

    if (!strcmp(backend, "sendmail")) {
        r = smtpclient_open_sendmail(smp);
    }
    else if (!strcmp(backend, "host")) {
        r = smtpclient_open_host(config_getstring(IMAPOPT_SMTP_HOST), smp);
    }
    else {
        syslog(LOG_ERR, "smtpclient_open: unknown backend: %s", backend);
        r = IMAP_INTERNAL;
    }
    return r;
}

EXPORTED int smtpclient_close(smtpclient_t **smp)
{
    if (!smp || !*smp) {
        return 0;
    }

    int r = 0;
    smtpclient_t *sm = *smp;

    /* Close backend */
    backend_disconnect(sm->backend);
    if (sm->free_context) {
        r = sm->free_context(sm->backend->context);
    }
    free(sm->backend);
    sm->backend = NULL;

    /* Close log */
    if (sm->logfd != -1) {
        close(sm->logfd);
    }
    sm->logfd = -1;

    /* Free internal state */
    if (sm->have_exts) {
        free_hash_table(sm->have_exts, free);
        free(sm->have_exts);
        sm->have_exts = NULL;
    }
    buf_free(&sm->buf);
    free(sm->by);
    free(sm->ret);
    free(sm->notify);
    free(sm->authid);
    buf_free(&sm->resp.text);

    free(sm);
    *smp = NULL;
    return r;
}

/* Match the response code to an expected return code defined in rock.
 *
 * rock->code must be a zero-terminated string up to length 3 (excluding the
 * NUL byte). Matching is performed by string matching the SMTP return
 * code to the expected code, stopping at the zero byte.
 *
 * E.g. return code "250", "251" both would match a "2" or "25" rock->code.
 *
 * Also see Daniel Bernstein's site https://cr.yp.to/smtp/request.html:
 * "I recommend that clients avoid looking past the first digit of the
 * code, either 2, 3, 4, or 5. The other two digits and the text are
 * primarily for human consumption. (Exception: See EHLO.)"
 *
 * Return IMAP_PROTOCOL_ERROR on mismatch, 0 on success.
 *
 * rock->cmd should describe the command whose response you're checking.
 * If set, it'll be included in the error log on mismatch.
 *
 */
struct expect_code_rock {
    const char *cmd;
    const char *code;
};

static int expect_code_cb(smtpclient_t *sm, void *rock)
{
    size_t i;
    const struct expect_code_rock *ecrock = (const struct expect_code_rock *) rock;
    smtp_resp_t *resp = &sm->resp;

    for (i = 0; i < 3 && ecrock->code[i]; i++) {
        if (ecrock->code[i] != resp->code[i]) {
            const char *text = buf_cstring(&resp->text);

            syslog(LOG_ERR, "smtpclient: unexpected response%s%s: code=%c%c%c text=%s",
                   ecrock->cmd ? " to " : "",
                   ecrock->cmd ? ecrock->cmd : "",
                   resp->code[0], resp->code[1], resp->code[2], text);

            /* Try to glean specific error from response */
            if (CAPA(sm->backend, SMTPCLIENT_CAPA_STATUS)) {
                if (text[2] == '1' && text[4] >= '1' && text[4] <= '3')
                    return IMAP_MAILBOX_NONEXISTENT;
                else if (text[2] == '3' && text[4] == '4')
                    return IMAP_MESSAGE_TOO_LARGE;
                else if (text[2] == '5' && text[4] == '3')
                    return IMAP_MAILBOX_DISABLED;
                else if (text[2] == '3' && text[4] == '0')
                    return IMAP_REMOTE_DENIED;
            }
            else {
                switch (atoi(resp->code)) {
                case 421:
                case 451:
                case 554:
                    return IMAP_REMOTE_DENIED;
                case 450:
                case 550:
                    return IMAP_MAILBOX_DISABLED;
                case 452:
                case 552:
                    return IMAP_MESSAGE_TOO_LARGE;
                case 553:
                    return IMAP_MAILBOX_NONEXISTENT;
                }
            }

            return IMAP_PROTOCOL_ERROR;
        }
    }
    return 0;
}

static int smtpclient_read(smtpclient_t *sm, smtp_readcb_t *cb, void *rock)
{
    char buf[513]; /* Maximum length of reply line, see RFC 5321, 4.5.3.1.5. */
    int r = IMAP_IOERROR;

    do {
        /* Read next reply line. */
        if (!prot_fgets(buf, 513, sm->backend->in)) {
            r = IMAP_IOERROR;
            return r;
        }
        buf[512] = '\0';

        /* Parse reply line. */
        if (!isdigit(buf[0]) || !isdigit(buf[1]) || !isdigit(buf[2])) {
            return IMAP_PROTOCOL_ERROR;
        }
        if (buf[3] != '-' && !isspace(buf[3])) {
            return IMAP_PROTOCOL_ERROR;
        }
        char *p = memchr(buf + 4, '\n', 508);
        if (p == NULL) {
            return IMAP_PROTOCOL_ERROR;
        }
        if (*(p-1) == '\r') {
            --p;
        }
        *p = '\0';

        /* Call callback. */
        memcpy(sm->resp.code, buf, 3);
        buf_setcstr(&sm->resp.text, buf + 4);
        sm->resp.is_last = isspace(buf[3]);
        r = cb(sm, rock);
    } while (!r && !sm->resp.is_last);

    return r;
}

static int ehlo_cb(smtpclient_t *sm, void *rock __attribute__((unused)))
{
    smtp_resp_t *resp = &sm->resp;

    /* Is this the first response line? */
    if (sm->have_exts == NULL) {
        sm->have_exts = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(sm->have_exts, 16, 0);
        return 0;
    }

    /* Add the extension */
    const char *p = buf_cstring(&resp->text);
    while (*p && !isspace(*p)) {
        p++;
    }
    const char *args = isspace(*p) ? p + 1 : "";
    buf_truncate(&resp->text, p - buf_base(&resp->text));
    hash_insert(buf_cstring(&resp->text), xstrdup(args), sm->have_exts);

    return 0;
}

static int smtpclient_writebuf(smtpclient_t *sm, struct buf *buf, int flush)
{
    if (prot_putbuf(sm->backend->out, buf)) {
        return IMAP_IOERROR;
    }
    if (flush && prot_flush(sm->backend->out)) {
        return IMAP_IOERROR;
    }
    return 0;
}

static void smtpclient_logerror(smtpclient_t *sm, const char *cmd, int r)
{
    if (r == IMAP_IOERROR) {
        /* try to dig a more specific error out of the prot streams */
        const char *errstr = prot_error(sm->backend->out);
        if (!errstr) errstr = prot_error(sm->backend->in);
        if (!errstr) errstr = error_message(r);
        syslog(LOG_ERR, "smtpclient: %s during %s", errstr, cmd);
    }
    else {
        syslog(LOG_ERR, "smtpclient: %s during %s", error_message(r), cmd);
    }
}

static int smtpclient_ehlo(smtpclient_t *sm)
{
    int r = 0;

    /* Say EHLO */
    buf_setcstr(&sm->buf, "EHLO localhost\r\n");
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);

    /* Process response */
    r = smtpclient_read(sm, ehlo_cb, NULL);

done:
    if (r) smtpclient_logerror(sm, "EHLO", r);
    return r;
}

static int smtpclient_rset(smtpclient_t *sm)
{
    int r = 0;

    /* Say RSET */
    buf_setcstr(&sm->buf, "RSET\r\n");
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);

    /* Process response */
    struct expect_code_rock rock = { "RSET", "2" };
    r = smtpclient_read(sm, expect_code_cb, &rock);

done:
    if (r) smtpclient_logerror(sm, "RSET", r);
    return r;
}

static int smtpclient_schk(smtpclient_t *sm)
{
    int r = 0;

    /* Say SCHK */
    buf_setcstr(&sm->buf, "SCHK\r\n");
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);

    /* Process response */
    struct expect_code_rock rock = { "SCHK", "2" };
    r = smtpclient_read(sm, expect_code_cb, &rock);

done:
    if (r) smtpclient_logerror(sm, "SCHK", r);
    return r;
}

__attribute__((unused)) static int smtpclient_quit(smtpclient_t *sm)
{
    int r = 0;

    /* Say QUIT */
    buf_setcstr(&sm->buf, "QUIT\r\n");
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;

    /* Don't insist on an answer */
    struct expect_code_rock rock = { "QUIT", "2" };
    r = smtpclient_read(sm, expect_code_cb, &rock);
    if (r) {
        syslog(LOG_INFO, "smtpclient: QUIT without reply: %s", error_message(r));
        return r;
    }

done:
    if (r) smtpclient_logerror(sm, "QUIT", r);
    return r;
}

static int write_addr(smtpclient_t *sm,
                      const char *cmd,
                      const smtp_addr_t *addr,
                      const ptrarray_t *extra_params)
{
    int i, r = 0;

    buf_reset(&sm->buf);
    buf_printf(&sm->buf, "%s:<%s>", cmd, addr->addr);
    for (i = 0; i < addr->params.count; i++) {
        smtp_param_t *param = ptrarray_nth(&addr->params, i);
        buf_appendcstr(&sm->buf, " ");
        buf_appendcstr(&sm->buf, param->key);
        if (!param->val) {
            continue;
        }
        buf_appendcstr(&sm->buf, "=");
        buf_appendcstr(&sm->buf, param->val);
    }
    for (i = 0; i < extra_params->count; i++) {
        smtp_param_t *param = ptrarray_nth(extra_params, i);
        buf_appendcstr(&sm->buf, " ");
        buf_appendcstr(&sm->buf, param->key);
        if (!param->val) {
            continue;
        }
        buf_appendcstr(&sm->buf, "=");
        buf_appendcstr(&sm->buf, param->val);
    }
    buf_appendcstr(&sm->buf, "\r\n");

    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;

    struct expect_code_rock rock = { cmd, "2" };
    r = smtpclient_read(sm, expect_code_cb, &rock);
    if (r) goto done;

done:
    if (r) smtpclient_logerror(sm, cmd, r);
    buf_reset(&sm->buf);
    return r;
}

/* Add key/value to extra, if it isn't defined in params */
static void smtp_params_set_extra(ptrarray_t *params, ptrarray_t *extra,
                                  const char *key, const char *val)
{
    int i;
    for (i = 0; i < params->count; i++) {
        smtp_param_t *param = ptrarray_nth(params, i);
        if (!strcasecmp(param->key, key)) {
            break;
        }
    }
    if (i == params->count) {
        smtp_param_t *param = xzmalloc(sizeof(smtp_param_t));
        param->key = xstrdup(key);
        param->val = xstrdup(val);
        ptrarray_add(extra, param);
    }
}

static void smtp_params_fini(ptrarray_t *params)
{
    int i;
    for (i = 0; i < params->count; i++) {
        smtp_param_t *param = ptrarray_nth(params, i);
        free(param->key);
        free(param->val);
        free(param);
    }
    ptrarray_fini(params);
}

/* Write a MAIL FROM command for address addr. */
static int smtpclient_from(smtpclient_t *sm, smtp_addr_t *addr)
{
    ptrarray_t extra_params = PTRARRAY_INITIALIZER;
    if (sm->authid && CAPA(sm->backend, CAPA_AUTH)) {
        smtp_params_set_extra(&addr->params, &extra_params, "AUTH", sm->authid);
    }
    if (sm->ret && CAPA(sm->backend, SMTPCLIENT_CAPA_DSN)) {
        smtp_params_set_extra(&addr->params, &extra_params, "RET", sm->ret);
    }
    if (sm->by && CAPA(sm->backend, SMTPCLIENT_CAPA_DELIVERBY)) {
        smtp_params_set_extra(&addr->params, &extra_params, "BY", sm->by);
    }
    if (sm->msgsize && CAPA(sm->backend, SMTPCLIENT_CAPA_SIZE)) {
        char szbuf[21];
        snprintf(szbuf, sizeof(szbuf), "%lu", sm->msgsize);
        smtp_params_set_extra(&addr->params, &extra_params, "SIZE", szbuf);
    }
    int r = write_addr(sm, "MAIL FROM", addr, &extra_params);
    if (r) smtpclient_logerror(sm, "MAIL FROM", r);
    smtp_params_fini(&extra_params);
    return r;
}

/* Write a RCPT TO command for all addresses in rcpt. */
static int smtpclient_rcpt_to(smtpclient_t *sm, ptrarray_t *rcpts)
{
    int i, r = 0;

    for (i = 0; i < rcpts->count; i++) {
        smtp_addr_t *addr = ptrarray_nth(rcpts, i);
        ptrarray_t extra_params = PTRARRAY_INITIALIZER;
        if (sm->notify && CAPA(sm->backend, SMTPCLIENT_CAPA_DSN)) {
            smtp_params_set_extra(&addr->params, &extra_params, "NOTIFY", sm->notify);
        }
        int r1 = write_addr(sm, "RCPT TO", addr, &extra_params);
        smtp_params_fini(&extra_params);
        if (!r1) addr->completed = 1;
        else if (!r) r = r1;
    }

    if (r) smtpclient_logerror(sm, "RCPT TO", r);
    return r;
}

/* Write a DATA command using data as input. Data is dot-escaped
 * before it is written to the SMTP backend. */
static int smtpclient_data(smtpclient_t *sm, struct protstream *data)
{
    int r = 0;

    /* Write DATA */
    buf_setcstr(&sm->buf, "DATA\r\n");
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);

    /* Expect Start Input */
    struct expect_code_rock rock = { "DATA", "3" };
    r = smtpclient_read(sm, expect_code_cb, &rock);
    if (r) goto done;

    /* Write message, escaping dot characters. */
    buf_ensure(&sm->buf, 4096);
    int c;
    int prev1 = 256, prev2 = 256;
    int at_start = 1;
    const char *eot = "\r\n.\r\n";
    while ((c = prot_getc(data)) != EOF) {
        if (c == '.' && at_start) {
            prot_ungetc(c, data);
            c = '.';
        }
        at_start = 0;
        sm->buf.s[sm->buf.len++] = (unsigned char) c;
        if (sm->buf.len == 4096) {
            r = smtpclient_writebuf(sm, &sm->buf, 0);
            if (r) goto done;
            buf_reset(&sm->buf);
        }
        if (c == '\n') {
            at_start = 1;
        }
        prev2 = prev1;
        prev1 = c;
    }
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);
    /* If message ends with CRLF, omit pre-dot CRLF. */
    if (prev2 == '\r' && prev1 == '\n')
        eot = ".\r\n";

    /* Write end-of-text. */
    buf_setcstr(&sm->buf, eot);
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);

    /* Expect OK */
    rock.cmd = "EOT";
    rock.code = "2";
    r = smtpclient_read(sm, expect_code_cb, &rock);
    if (r) goto done;

done:
    if (r) smtpclient_logerror(sm, "DATA", r);
    return r;
}

static int validate_envelope_params(ptrarray_t *params)
{
    if (!params) return 0;

    int i;
    for (i = 0; i < ptrarray_size(params); i++) {
        smtp_param_t *param = ptrarray_nth(params, i);
        if (!smtp_is_valid_esmtp_keyword(param->key)) {
            syslog(LOG_ERR, "smtpclient: invalid estmp keyword: \"%s\"", param->key);
            return IMAP_PROTOCOL_ERROR;
        }
        if (!strcasecmp(param->key, "AUTH")) {
            syslog(LOG_ERR, "smptclient: rejecting AUTH parameter in envelope");
            return IMAP_PERMISSION_DENIED;
        }
        if (param->val && !smtp_is_valid_esmtp_value(param->val)) {
            syslog(LOG_ERR, "smtpclient: invalid estmp value: \"%s\"", param->val);
            return IMAP_PROTOCOL_ERROR;
        }
    }

    return 0;
}

static int validate_envelope(smtp_envelope_t *env)
{
    int i, r;

    if (!env->from.addr) {
        syslog(LOG_ERR, "smtpclient: envelope missing sender");
        return IMAP_PROTOCOL_ERROR;
    }
    r = validate_envelope_params(&env->from.params);
    if (r) return r;

    if (!env->rcpts.count) {
        syslog(LOG_ERR, "smtpclient: envelope missing recipients");
        return IMAP_PROTOCOL_ERROR;
    }
    for (i = 0; i < env->rcpts.count; i++) {
        smtp_addr_t *addr = ptrarray_nth(&env->rcpts, i);
        if (!addr->addr) {
            syslog(LOG_ERR, "smtpclient: invalid recipient at position %d", i);
            return IMAP_PROTOCOL_ERROR;
        }
        r = validate_envelope_params(&addr->params);
        if (r) return r;
    }

    return 0;
}

EXPORTED int smtpclient_sendprot(smtpclient_t *sm, smtp_envelope_t *env, struct protstream *data)
{
    int r = 0;

    if (sm->msgsize) {
        unsigned long maxsize = smtpclient_get_maxsize(sm);

        if (maxsize && maxsize < sm->msgsize) {
            r = IMAP_MESSAGE_TOO_LARGE;
            goto done;
        }
    }

    r = validate_envelope(env);
    if (r) goto done;

    r = smtpclient_from(sm, &env->from);
    if (r) goto done;

    r = smtpclient_rcpt_to(sm, &env->rcpts);
    if (r) goto done;

    if (data) {
        r = smtpclient_data(sm, data);
        if (r) goto done;
    }
    else {
        /* simply pre-flighting the envelope */
        if (CAPA(sm->backend, SMTPCLIENT_CAPA_SENDCHECK)) {
            r = smtpclient_schk(sm);
        }
        else {
            r = smtpclient_rset(sm);
        }
        if (r) goto done;
    }

done:
    return r;
}

EXPORTED int smtpclient_send(smtpclient_t *sm, smtp_envelope_t *env, struct buf *data)
{
    struct protstream *p = prot_readmap(buf_base(data), buf_len(data));
    smtpclient_set_size(sm, buf_len(data));
    int r = smtpclient_sendprot(sm, env, p);
    prot_free(p);
    return r;
}

EXPORTED void smtpclient_set_auth(smtpclient_t *sm, const char *authid)
{
    free(sm->authid);
    sm->authid = xstrdupnull(authid);
}

EXPORTED void smtpclient_set_notify(smtpclient_t *sm, const char *value)
{
    free(sm->notify);
    sm->notify = xstrdupnull(value);
}

EXPORTED void smtpclient_set_ret(smtpclient_t *sm, const char *value)
{
    free(sm->ret);
    sm->ret = xstrdupnull(value);
}

EXPORTED void smtpclient_set_by(smtpclient_t *sm, const char *value)
{
    free(sm->by);
    sm->by = xstrdupnull(value);
}

EXPORTED void smtpclient_set_size(smtpclient_t *sm, unsigned long value)
{
    sm->msgsize = value;
}

EXPORTED unsigned long smtpclient_get_maxsize(smtpclient_t *sm)
{
    unsigned long maxsize = 0;

    if (CAPA(sm->backend, SMTPCLIENT_CAPA_SIZE)) {
        const char *sizestr = smtpclient_has_ext(sm, "SIZE");
        if (sizestr) maxsize = strtoul(sizestr, NULL, 10);
    }

    return maxsize;
}

EXPORTED const char *smtpclient_get_resp_text(smtpclient_t *sm)
{
    return buf_cstring(&sm->resp.text);
}

/* SMTP backend implementations */

static int smtpclient_new(smtpclient_t **smp,
                          struct backend *backend,
                          int (*freectx)(void *), int logfd)
{
    smtpclient_t *sm = xzmalloc(sizeof(smtpclient_t));
    sm->backend = backend;
    sm->free_context = freectx;
    sm->logfd = logfd;
    *smp = sm;
    return 0;
}

EXPORTED const char *smtpclient_has_ext(smtpclient_t *sm, const char *name)
{
    if (!sm->have_exts) {
        int r = smtpclient_ehlo(sm);
        if (r) {
            syslog(LOG_ERR, "smtpclient: can't EHLO for extensions: %s",
                    error_message(r));
            return NULL;
        }
    }
    return hash_lookup(name, sm->have_exts);
}

/* TCP host backend */

typedef struct {
    int sockfd;
} smtpclient_host_t;

EXPORTED int smtpclient_open_host(const char *addr, smtpclient_t **smp)
{
    struct backend *bk = NULL;
    int r = 0;
    char *myaddr = NULL;
    int logfd = -1;

    /* Setup SASL for authentication, if any */
    sasl_callback_t *sasl_cb = NULL;
    if (config_getstring(IMAPOPT_SMTP_AUTH_AUTHNAME)) {
        sasl_cb = mysasl_callbacks(NULL /*userid*/,
                config_getstring(IMAPOPT_SMTP_AUTH_AUTHNAME),
                config_getstring(IMAPOPT_SMTP_AUTH_REALM),
                config_getstring(IMAPOPT_SMTP_AUTH_PASSWORD));
    } else {
        myaddr = strconcat(addr, "/noauth", NULL);
    }

    logfd = telemetry_log("smtpclient.host", NULL, NULL, 0);

    /* Connect to backend */
    const char *host = myaddr ? myaddr : addr;
    syslog(LOG_DEBUG, "smtpclient_open: connecting to host: %s", host);
    bk = backend_connect(NULL, host, &smtp_protocol, NULL, sasl_cb, NULL, logfd);
    if (sasl_cb) free_callbacks(sasl_cb);
    if (!bk) {
        syslog(LOG_ERR, "smptclient_open: can't connect to host: %s", host);
        if (logfd != -1) close(logfd);
        r = IMAP_INTERNAL;
        goto done;
    }
    r = smtpclient_new(smp, bk, /*freectx*/NULL, logfd);

done:
    free(myaddr);
    return r;
}

EXPORTED int smtp_is_valid_esmtp_keyword(const char *val)
{
    if (!isascii(*val) || !isalnum(*val)) {
        return 0;
    }
    for (val = val + 1; *val; val++) {
        if (!isascii(*val) || (*val != '-' && !isalnum(*val))) {
            return 0;
        }
    }
    return 1;
}

EXPORTED int smtp_is_valid_esmtp_value(const char *val)
{
    if (*val == '\0') return 0;
    for ( ; *val; val++) {
        if (*val == '=' || *val < '!' || *val > '~') {
            return 0;
        }
    }
    return 1;
}

/* Encodes into the current location of the struct buf.
   The caller must buf_reset() before calling is necessary. */
EXPORTED void smtp_encode_esmtp_value(const char *val, struct buf *xtext)
{
    const char *p;
    for (p = val; *p; p++) {
        if (('!' <= *p && *p <= '~') && *p != '=' && *p != '+') {
            buf_putc(xtext, *p);
        }
        else buf_printf(xtext, "+%02X", *p);
    }
}


EXPORTED smtp_addr_t *smtp_envelope_set_from(smtp_envelope_t *env, const char *addr)
{
    smtp_params_fini(&env->from.params);
    free(env->from.addr);
    env->from.addr = xstrdup(addr);
    return &env->from;
}

EXPORTED smtp_addr_t *smtp_envelope_add_rcpt(smtp_envelope_t *env, const char *addr)
{
    smtp_addr_t *rcpt = xzmalloc(sizeof(smtp_addr_t));
    rcpt->addr = xstrdup(addr);
    ptrarray_append(&env->rcpts, rcpt);
    return rcpt;
}

EXPORTED void smtp_envelope_fini(smtp_envelope_t *env)
{
    smtp_params_fini(&env->from.params);
    free(env->from.addr);

    smtp_addr_t *a;
    while ((a = ptrarray_pop(&env->rcpts))) {
        smtp_params_fini(&a->params);
        free(a->addr);
        free(a);
    }
    ptrarray_fini(&env->rcpts);
}

/* Sendmail process backend */

typedef struct {
    int infd;
    int outfd;
    pid_t pid;
} smtpclient_sendmail_ctx_t;

static int smtpclient_sendmail_freectx(smtpclient_sendmail_ctx_t *ctx)
{
    if (!ctx) return 0;

    if (ctx->pid && waitpid(ctx->pid, NULL, 0) < 0) {
        syslog(LOG_ERR, "waitpid(): %m");
    }

    if (ctx->infd >= 0)
        close(ctx->infd);

    if (ctx->outfd >= 0)
        close(ctx->outfd);

    free(ctx);
    return 0;
}

EXPORTED int smtpclient_open_sendmail(smtpclient_t **smp)
{
    struct backend *bk = NULL;
    int r = 0;
    int p_child[2];
    int p_parent[2];
    int logfd = -1;

    /* Create the pipes and fork */
    r = pipe(p_child);
    if (!r) {
        r = pipe(p_parent);
    }
    if (r < 0) {
        syslog(LOG_ERR, "smtpclient_open: can't create pipe: %m");
        r = IMAP_SYS_ERROR;
        goto done;
    }
    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "smtpclient_open: can't fork: %m");
        r = IMAP_SYS_ERROR;
        goto done;
    }

    if (pid == 0) {
        /* child process */
        close(p_child[1]);
        dup2(p_child[0], STDIN_FILENO);
        close(p_child[0]);

        close(p_parent[0]);
        dup2(p_parent[1], STDOUT_FILENO);
        close(p_parent[1]);

        execl(config_getstring(IMAPOPT_SENDMAIL), "sendmail", "-bs", (char *)NULL);
        syslog(LOG_ERR, "smtpclient_open: can't exec sendmail: %m");
        exit(1);
    }

    /* parent process */
    close(p_child[0]);
    p_child[0] = -1;
    close(p_parent[1]);
    p_parent[1] = -1;

    smtpclient_sendmail_ctx_t *ctx = xmalloc(sizeof(smtpclient_sendmail_ctx_t));
    ctx->infd  = p_parent[0]; /* reader */
    ctx->outfd = p_child[1];  /* writer */
    ctx->pid   = pid;

    logfd = telemetry_log("smtpclient.sendmail", NULL, NULL, 0);

    /* Create backend and setup context */
    bk = backend_connect_pipe(ctx->infd, ctx->outfd, &smtp_protocol, 0, logfd);
    if (!bk) {
        syslog(LOG_ERR, "smptclient_open: can't open sendmail backend");
        r = IMAP_INTERNAL;
        smtpclient_sendmail_freectx(ctx);
        if (logfd != -1) close(logfd);
        goto done;
    }
    bk->context = ctx;
    r = smtpclient_new(smp, bk, (int (*)(void *)) smtpclient_sendmail_freectx, logfd);

done:
    return r;
}
