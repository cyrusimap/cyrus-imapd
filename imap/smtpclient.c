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
#include <syslog.h>

#include "backend.h"
#include "xmalloc.h"
#include "global.h"
#include "exitcodes.h"
#include "smtpclient.h"
#include "telemetry.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

struct smtpclient {
    /* SMTP backend. Client implementations can store
     * their context data in backend->context. */
    struct backend *backend;

    /* Client implementations can free their context
     * stored in backend->context. */
    int (*free_context)(struct backend *backend);

    /* Telemetry log */
    int logfd;

    /* Internal state */
    hash_table *have_exts;
    struct buf buf;
    char *authid;
    char *notify;
    char *ret;
    char *by;
    unsigned long size;
};

enum {
    SMTPCLIENT_CAPA_DSN       = (1 << 3),
    SMTPCLIENT_CAPA_DELIVERBY = (1 << 4),
    SMTPCLIENT_CAPA_SIZE      = (1 << 5),
    SMTPCLIENT_CAPA_STATUS    = (1 << 6)
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
          { NULL, 0 } } },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL },
      { "NOOP", NULL, "250" },
      { "QUIT", NULL, "221" } } }
};


static int smtpclient_new(smtpclient_t **smp,
                          struct backend *backend,
                          int (*closebk)(struct backend *), int logfd);

/* SMTP protocol implementation */

typedef struct {
    char code[3];
    char *text; /* Zero-terminated reply text, excluding CRLF. OK to overwrite. */
    int is_last;
} smtp_resp_t;

typedef int smtp_readcb_t(const smtp_resp_t *resp, void *rock);

static int smtpclient_read(smtpclient_t *sm, smtp_readcb_t *cb, void *rock);

static int smtpclient_writebuf(smtpclient_t *sm, struct buf *buf, int flush);
static int smtpclient_ehlo(smtpclient_t *sm);
static int smtpclient_quit(smtpclient_t *sm);
static int smtpclient_from(smtpclient_t *sm, smtp_addr_t *addr);
static int smtpclient_rcpt_to(smtpclient_t *sm, ptrarray_t *rcpt);
static int smtpclient_data(smtpclient_t *sm, struct protstream *data);

static int smtpclient_sendmail_freectx(struct backend* backend);

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
        r = sm->free_context(sm->backend);
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

    free(sm);
    *smp = NULL;
    return r;
}

/* Match the response code to an expected return code defined in rock.
 *
 * Rock must be a zero-terminated string up to length 3 (excluding the
 * NUL byte). Matching is performed by string matching the SMTP return
 * code to the expected code, stopping at the zero byte.
 *
 * E.g. return code "250", "251" both would match a "2" or "25" rock.
 *
 * Also see Daniel Bernstein's site https://cr.yp.to/smtp/request.html:
 * "I recommend that clients avoid looking past the first digit of the
 * code, either 2, 3, 4, or 5. The other two digits and the text are
 * primarily for human consumption. (Exception: See EHLO.)"
 *
 * Return IMAP_PROTOCOL_ERROR on mismatch, 0 on success.
 */
static int expect_code_cb(const smtp_resp_t *resp, void *rock)
{
    size_t i;
    const char *code = rock;
    for (i = 0; i < 3 && code[i]; i++) {
        if (code[i] != resp->code[i]) {
            syslog(LOG_ERR, "smtpclient: unexpected response: code=%c%c%c text=%s",
                    resp->code[0], resp->code[1], resp->code[2], resp->text);
            return IMAP_PROTOCOL_ERROR;
        }
    }
    return 0;
}

static int smtpclient_read(smtpclient_t *sm, smtp_readcb_t *cb, void *rock)
{
    char buf[513]; /* Maximum length of reply line, see RFC 5321, 4.5.3.1.5. */
    int r = IMAP_IOERROR;
    smtp_resp_t resp;

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
        memcpy(resp.code, buf, 3);
        resp.text = buf + 4;
        resp.is_last = isspace(buf[3]);
        r = cb(&resp, rock);
    } while (!r && !resp.is_last);

    return r;
}

static int ehlo_cb(const smtp_resp_t *resp, void *rock)
{
    hash_table **extsptr = rock;

    /* Is this the first response line? */
    if (*extsptr == NULL) {
        *extsptr = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(*extsptr, 16, 0);
        return 0;
    }

    /* Add the extension */
    char *p = resp->text;
    while (*p && !isspace(*p)) {
        p++;
    }
    const char *args = isspace(*p) ? p + 1 : "";
    *p = '\0';
    hash_insert(resp->text, xstrdup(args), *extsptr);

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

static int smtpclient_ehlo(smtpclient_t *sm)
{
    int r = 0;

    /* Say EHLO */
    buf_setcstr(&sm->buf, "EHLO localhost\r\n");
    r = smtpclient_writebuf(sm, &sm->buf, 1);
    if (r) goto done;
    buf_reset(&sm->buf);

    /* Process response */
    hash_table *exts = NULL;
    r = smtpclient_read(sm, ehlo_cb, &exts);
    if (r) goto done;
    sm->have_exts = exts;

done:
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
    r = smtpclient_read(sm, expect_code_cb, "2");
    if (r) {
        syslog(LOG_INFO, "smtpclient: QUIT without reply: %s", error_message(r));
    }

done:
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

    r = smtpclient_read(sm, expect_code_cb, "2");
    if (r) goto done;

done:
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
    if (sm->size && CAPA(sm->backend, SMTPCLIENT_CAPA_SIZE)) {
        char szbuf[21];
        snprintf(szbuf, sizeof(szbuf), "%lu", sm->size);
        smtp_params_set_extra(&addr->params, &extra_params, "SIZE", szbuf);
    }
    int r = write_addr(sm, "MAIL FROM", addr, &extra_params);
    smtp_params_fini(&extra_params);
    return r;
}

/* Write a RCPT TO command for all addresses in rcpt. */
static int smtpclient_rcpt_to(smtpclient_t *sm, ptrarray_t *rcpts)
{
    int i, r = IMAP_INTERNAL;

    for (i = 0; i < rcpts->count; i++) {
        smtp_addr_t *addr = ptrarray_nth(rcpts, i);
        ptrarray_t extra_params = PTRARRAY_INITIALIZER;
        if (sm->notify && CAPA(sm->backend, SMTPCLIENT_CAPA_DSN)) {
            smtp_params_set_extra(&addr->params, &extra_params, "NOTIFY", sm->notify);
        }
        r = write_addr(sm, "RCPT TO", addr, &extra_params);
        smtp_params_fini(&extra_params);
        if (r) break;
    }

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
    r = smtpclient_read(sm, expect_code_cb, "3");
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
    r = smtpclient_read(sm, expect_code_cb, "2");
    if (r) goto done;

done:
    return r;
}

static int validate_envelope(smtp_envelope_t *env)
{
    int i;

    if (!env->from.addr) {
        syslog(LOG_ERR, "smtpclient: envelope missing sender");
        return IMAP_PROTOCOL_ERROR;
    }
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
    }

    return 0;
}

EXPORTED int smtpclient_sendprot(smtpclient_t *sm, smtp_envelope_t *env, struct protstream *data)
{
    int r = 0;

    r = validate_envelope(env);
    if (r) goto done;

    r = smtpclient_from(sm, &env->from);
    if (r) goto done;

    r = smtpclient_rcpt_to(sm, &env->rcpts);
    if (r) goto done;

    r = smtpclient_data(sm, data);
    if (r) goto done;

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
    sm->size = value;
}

/* SMTP backend implementations */

static int smtpclient_new(smtpclient_t **smp,
                          struct backend *backend,
                          int (*freectx)(struct backend *), int logfd)
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
} smtpclient_sendmail_fds_t;

static int smtpclient_sendmail_freectx(struct backend *backend)
{
    free(backend->context);
    return 0;
}

EXPORTED int smtpclient_open_sendmail(smtpclient_t **smp)
{
    struct backend *bk = NULL;
    int r = 0;
    int p_child[2];
    int p_parent[2];
    int logfd = -1;
    int *fds = xzmalloc(sizeof(int) * 2);
    fds[0] = -1;
    fds[1] = -1;

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
        dup2(p_child[0], /*FILENO_STDIN*/0);
        close(p_child[0]);

        close(p_parent[0]);
        dup2(p_parent[1], /*FILENO_STDOUT*/1);
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

    fds[0] = p_parent[0]; /* reader */
    fds[1] = p_child[1];  /* writer */

    logfd = telemetry_log("smtpclient.sendmail", NULL, NULL, 0);


    /* Create backend and setup context */
    bk = backend_connect_pipe(fds[0], fds[1], &smtp_protocol, 0, logfd);
    if (!bk) {
        syslog(LOG_ERR, "smptclient_open: can't open sendmail backend");
        r = IMAP_INTERNAL;
        if (logfd != -1) close(logfd);
        goto done;
    }
    bk->context = fds;
    r = smtpclient_new(smp, bk, smtpclient_sendmail_freectx, logfd);

done:
    return r;
}
