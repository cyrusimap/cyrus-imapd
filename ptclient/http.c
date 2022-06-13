/* http.c - HTTP Backend to ptloader
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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
#include <sysexits.h>
#include <syslog.h>
#include <jansson.h>

#include "auth_pts.h"
#include "libconfig.h"
#include "ptloader.h"
#include "strhash.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

#include "imap/backend.h"
#include "imap/http_client.h"
#include "imap/spool.h"


static struct {
    struct backend *conn;
    struct buf buf;
    char *service;
    char *hosthdr;

    struct {
        unsigned https : 1;
        unsigned long port;
        const char *host;
        const char *prefix;
        const char *suffix;
        char *raw;
    } uri;

} state = { NULL, BUF_INITIALIZER, NULL, NULL,
            { 0, 0, NULL, NULL, NULL, NULL } };


static int login(struct backend *be __attribute__((unused)),
                 const char *userid __attribute__((unused)),
                 sasl_callback_t *cb __attribute__((unused)),
                 const char **status,
                 int noauth __attribute__((unused)))
{
    /* No authentication (yet?) */
    if (status) *status = NULL;

    return 0;
}

static int ping(struct backend *be, const char *userid __attribute__((unused)))
{
    unsigned code = 0;
    const char *errstr = NULL;
    hdrcache_t resp_hdrs = NULL;
    struct body_t resp_body;

    prot_puts(be->out, "OPTIONS * HTTP/1.1\r\n");
    prot_printf(be->out, "Host: %s\r\n", state.hosthdr);
    prot_printf(be->out, "User-Agent: Cyrus-ptloader/%s\r\n", CYRUS_VERSION);
    prot_puts(be->out, "\r\n");
    prot_flush(be->out);

    /* Read response(s) from backend until final response or error */
    memset(&resp_body, 0, sizeof(struct body_t));
    do {
        resp_body.flags = BODY_DISCARD;
        if (http_read_response(be, METH_OPTIONS, &code,
                               &resp_hdrs, &resp_body, &errstr)) {
            break;
        }
    } while (code < 200);

    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);

    return (code != 200);
}

static int logout(struct backend *be __attribute__((unused)))
{
    /* Nothing to send, client just closes connection */
    return 0;
}

static struct protocol_t protocol =
{ "http", "HTTP", TYPE_SPEC, { .spec = { &login, &ping, &logout } } };


/* API */

static void myinit(void)
{
    char *p;
    size_t n;

    if (state.uri.raw) return; // Already configured

    /* Fetch and parse URI uri */
    p = state.uri.raw = xstrdupnull(config_getstring(IMAPOPT_HTTPPTS_URI));
    if (!p) fatal("Missing 'httppts_uri' option", EX_CONFIG);

    if (!strncasecmp(p, "https://", 8)) {
        state.uri.host = p += 8;
        state.uri.port = 443;
        state.uri.https = 1;
    }
    else if (!strncasecmp(p, "http://", 7)) {
        state.uri.host = p += 7;
        state.uri.port = 80;
    }
    else fatal("Invalid 'httppts_uri' scheme", EX_CONFIG);

    n = strcspn(p, ":/");
    if (!n) fatal("Missing 'httppts_uri' authority", EX_CONFIG);

    p += n;
    if (*p == ':') {
        *p++ = '\0';
        state.uri.port = strtoul(p, &p, 10);
        if (!state.uri.port || state.uri.port > USHRT_MAX)
            fatal("Invalid 'httppts_uri' port", EX_CONFIG);
    }

    if (*p != '/') fatal("Missing 'httppts_uri' path", EX_CONFIG);

    *p++ = '\0';
    state.uri.prefix = p;

    p = strstr(p, "{groupId}");
    if (!p) fatal("Missing 'httppts_uri' expression", EX_CONFIG);

    *p++ = '\0';
    state.uri.suffix = p += 8;

    buf_printf(&state.buf, "%s:%lu/noauth%s",
               state.uri.host, state.uri.port, state.uri.https ? "/tls" : "");
    state.service = buf_release(&state.buf);

    buf_setcstr(&state.buf, state.uri.host);
    if ((state.uri.https && state.uri.port != 443) || state.uri.port != 80)
        buf_printf(&state.buf, ":%lu", state.uri.port);
    state.hosthdr = buf_release(&state.buf);

    state.conn = backend_connect(state.conn, state.service,
                                 &protocol, NULL, NULL, NULL, -1);
    if (!state.conn) {
        syslog(LOG_NOTICE, "ptloader failed to connect to HTTP service %s",
               state.service);
    }

    return;
}

static struct auth_state *myauthstate(const char *identifier,
                                            size_t size,
                                            const char **reply, int *dsize)
{
    const char *canon_id = ptsmodule_unix_canonifyid(identifier, size);
    struct backend *be = state.conn;
    size_t ngroups = 0;
    json_t *resp = NULL, *groups = NULL;
    struct auth_state *newstate = NULL;
    unsigned code = 0;
    const char *errstr = NULL;
    hdrcache_t resp_hdrs = NULL;
    struct body_t resp_body;
    int i;

    if (canon_id == NULL) {
       syslog(LOG_ERR, "http_canonifyid failed for %s", identifier);
       return NULL;
    }

    *reply = NULL;
    size = strlen(canon_id);

    /* ping/noop the server */
    if (be && (be->sock != -1) && backend_ping(be, NULL)) {
        backend_disconnect(be);
    }

    if (!be || (be->sock == -1)) {
        /* need to reestablish connection to server */
        be = backend_connect(be, state.service,
                                    &protocol, NULL, NULL, NULL, -1);
        if (!be) return NULL;
    }

    /* TODO: URL-encode the canon_id */
    buf_reset(&state.buf);
    buf_printf(&state.buf, "/%s%s%s", state.uri.prefix, canon_id, state.uri.suffix);

    prot_printf(be->out, "GET %s HTTP/1.1\r\n", buf_cstring(&state.buf));
    prot_printf(be->out, "Host: %s\r\n", state.hosthdr);
    prot_printf(be->out, "User-Agent: Cyrus-ptloader/%s\r\n", CYRUS_VERSION);
    prot_puts(be->out, "Accept: application/json\r\n");
    prot_puts(be->out, "\r\n");
    prot_flush(be->out);

    /* Read response(s) from backend until final response or error */
    memset(&resp_body, 0, sizeof(struct body_t));
    do {
        resp_body.flags = BODY_DECODE;
        if (http_read_response(be, METH_GET, &code,
                               &resp_hdrs, &resp_body, &errstr)) {
            break;
        }
    } while (code < 200);

    if (code == 200) {
        json_error_t err;
        resp = json_loads(buf_cstring(&resp_body.payload), 0, &err);
        if (resp && (groups = json_object_get(resp, canon_id))) {
            ngroups = json_array_size(groups);
        }
    }

    /* fill in our new state structure */
    *dsize = sizeof(struct auth_state) + (ngroups * sizeof(struct auth_ident));
    newstate = (struct auth_state *) xzmalloc(*dsize);

    strlcpy(newstate->userid.id, canon_id, sizeof(newstate->userid.id));
    newstate->userid.hash = strhash(canon_id);
    newstate->ngroups = ngroups;
    newstate->mark = time(0);

    /* store group list in contiguous array for easy storage in the database */
    for (i = 0; i < newstate->ngroups; i++) {
        const char *name = json_string_value(json_array_get(groups, i));
        strlcpy(newstate->groups[i].id, name, sizeof(newstate->groups[i].id));
        newstate->groups[i].hash = strhash(name);
    }

    buf_free(&resp_body.payload);
    if (resp_hdrs) spool_free_hdrcache(resp_hdrs);
    if (resp) json_decref(resp);

    return newstate;
}

struct pts_module pts_http =
{
    "http",           /* name */

    &myinit,
    &myauthstate,
};
