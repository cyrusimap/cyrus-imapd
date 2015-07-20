/* http_admin.c -- Routines for handling Cyrus admin/info requests in httpd
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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
 *
 */

/*
 * TODO:
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "global.h"
#include "httpd.h"
#include "http_proxy.h"
#include "proc.h"
#include "proxy.h"
#include "time.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

static time_t compile_time;
static void admin_init(struct buf *serverinfo);
static int meth_get(struct transaction_t *txn, void *params);
static int action_murder(struct transaction_t *txn);
static int action_menu(struct transaction_t *txn);
static int action_proc(struct transaction_t *txn);


/* Namespace for admin service */
struct namespace_t namespace_admin = {
    URL_NS_ADMIN, 1, "/admin", NULL, 1 /* auth */,
    /*mbtype*/0,
    ALLOW_READ,
    admin_init, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get,            NULL },                 /* GET          */
        { &meth_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* POST */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


static void admin_init(struct buf *serverinfo __attribute__((unused)))
{
//    namespace_admin.enabled =
//        config_httpmodules & IMAP_ENUM_HTTPMODULES_ADMIN;

    if (!namespace_admin.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);
}

const struct action_t {
    const char *name;
    const char *desc;
    int (*func)(struct transaction_t *txn);
} actions[] = {
    { "", "    Available Cyrus Admin Functions",  &action_menu },
    { "proc", "Currently Running Cyrus Services", &action_proc },
    { NULL, NULL, NULL }
};


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    struct request_target_t *tgt = &txn->req_tgt;
    int (*action)(struct transaction_t *txn) = NULL;
    size_t len;
    char *p;
    int i;

    if (!httpd_userid) return HTTP_UNAUTHORIZED;

    /* Admins only */
    if (!(httpd_userisadmin || httpd_userisproxyadmin)) return HTTP_FORBIDDEN;

    /* Make a working copy of target path */
    strlcpy(tgt->path, txn->req_uri->path, sizeof(tgt->path));
    p = tgt->path;

    /* Skip namespace */
    p += strlen(namespace_admin.prefix);
    if (*p == '/') *p++ = '\0';

    /* Check if we're in murder space */
    len = strcspn(p, "/");
    if (config_mupdate_server && len == 6 && !strncmp(p, "murder", len)) {
        p += len;
        if (!*p || !*++p) return action_murder(txn);

        /* Get backend server */
        len = strcspn(p, "/");
        tgt->userid = xstrndup(p, len);
        p += len;
        if (*p == '/') *p++ = '\0';
    }

    /* Get collection (action) */
    tgt->collection = p;
    p += strcspn(p, "/");
    if (*p == '/') *p++ = '\0';

    /* Find the matching action */
    for (i = 0; actions[i].name; i++) {
        if (!strcmp(tgt->collection, actions[i].name) && !*p) {
            action = actions[i].func;
            break;
        }
    }

    if (!action) return HTTP_NOT_FOUND;

    else if (tgt->userid && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* Proxy to backend */
        struct backend *be;

        be = proxy_findserver(tgt->userid,
                              &http_protocol, proxy_userid,
                              &backend_cached, NULL, NULL, httpd_in);
        if (!be) return HTTP_UNAVAILABLE;

        return http_pipe_req_resp(be, txn);
    }

    else return action(txn);
}


/* Perform a murder action */
static int action_murder(struct transaction_t *txn)
{
    int precond;
    struct message_guid guid;
    const char *etag, *serverlist = config_getstring(IMAPOPT_SERVERLIST);
    static time_t lastmod = 0;
    unsigned level = 0;
    static struct buf resp = BUF_INITIALIZER;
    struct stat sbuf;
    time_t mtime;

    if (!serverlist) {
        /* Add HTML header */
        buf_reset(&resp);
        buf_printf_markup(&resp, level, HTML_DOCTYPE);
        buf_printf_markup(&resp, level++, "<html>");
        buf_printf_markup(&resp, level++, "<head>");
        buf_printf_markup(&resp, level, "<title>%s</title>",
                          "Available Cyrus Backend Servers");
        buf_printf_markup(&resp, --level, "</head>");
        buf_printf_markup(&resp, level++, "<body>");
        buf_printf_markup(&resp, level, "<h2>%s</h2>",
                          "Error: Can not generate a list of backend servers "
                          "without <tt>serverlist</tt> option being set "
                          "in <tt>imapd.conf</tt>");

        /* Finish HTML */
        buf_printf_markup(&resp, --level, "</body>");
        buf_printf_markup(&resp, --level, "</html>");

        /* Output the HTML response */
        txn->resp_body.type = "text/html; charset=utf-8";
        write_body(HTTP_UNAVAILABLE, txn, buf_cstring(&resp), buf_len(&resp));

        return 0;
    }

    /* Generate ETag based on compile date/time of this source file,
       and the config file size/mtime */
    assert(!buf_len(&txn->buf));
    stat(config_filename, &sbuf);
    buf_printf(&txn->buf, "%ld-%ld-%ld", (long) compile_time,
               sbuf.st_mtime, sbuf.st_size);

    message_guid_generate(&guid, buf_cstring(&txn->buf), buf_len(&txn->buf));
    etag = message_guid_encode(&guid);
    mtime = MAX(compile_time, sbuf.st_mtime);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, etag, mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Etag,  Last-Modified, Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = mtime;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    if (txn->resp_body.lastmod > lastmod) {
        /* Add HTML header */
        const char *sep =
            txn->req_uri->path[strlen(txn->req_uri->path)-1] == '/' ? "" : "/";
        char *server;
        tok_t tok;

        buf_reset(&resp);
        buf_printf_markup(&resp, level, HTML_DOCTYPE);
        buf_printf_markup(&resp, level++, "<html>");
        buf_printf_markup(&resp, level++, "<head>");
        buf_printf_markup(&resp, level, "<title>%s</title>",
                          "Available Cyrus Backend Servers");
        buf_printf_markup(&resp, --level, "</head>");
        buf_printf_markup(&resp, level++, "<body>");
        buf_printf_markup(&resp, level, "<h2>%s @ %s</h2>",
                          "Available Cyrus Backend Servers", config_servername);

        /* Add servers */
        tok_init(&tok, serverlist, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        while ((server = tok_next(&tok))) {
            buf_printf_markup(&resp, level, "<a href=\"%s%s%s\">%s</a>",
                              txn->req_uri->path, sep, server, server);
        }
        tok_fini(&tok);

        /* Finish HTML */
        buf_printf_markup(&resp, --level, "</body>");
        buf_printf_markup(&resp, --level, "</html>");

        /* Update lastmod */
        lastmod = txn->resp_body.lastmod;
    }

    /* Output the HTML response */
    txn->resp_body.type = "text/html; charset=utf-8";
    write_body(precond, txn, buf_cstring(&resp), buf_len(&resp));

    return 0;
}


/* Perform a menu action */
static int action_menu(struct transaction_t *txn)
{
    int precond;
    struct message_guid guid;
    const char *etag;
    static time_t lastmod = 0;
    unsigned level = 0, i;
    static struct buf resp = BUF_INITIALIZER;

    /* Generate ETag based on compile date/time of this source file.
     * Extend this to include config file size/mtime if we add run-time options.
     */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld", (long) compile_time);
    message_guid_generate(&guid, buf_cstring(&txn->buf), buf_len(&txn->buf));
    etag = message_guid_encode(&guid);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, etag, compile_time);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Etag,  Last-Modified, Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = compile_time;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    if (txn->resp_body.lastmod > lastmod) {
        /* Add HTML header */
        const char *sep =
            txn->req_uri->path[strlen(txn->req_uri->path)-1] == '/' ? "" : "/";

        buf_reset(&resp);
        buf_printf_markup(&resp, level, HTML_DOCTYPE);
        buf_printf_markup(&resp, level++, "<html>");
        buf_printf_markup(&resp, level++, "<head>");
        buf_printf_markup(&resp, level, "<title>%s</title>",
                          "Available Cyrus Admin Functions");
        buf_printf_markup(&resp, --level, "</head>");
        buf_printf_markup(&resp, level++, "<body>");
        buf_printf_markup(&resp, level, "<h2>%s @ %s</h2>",
                          actions[0].desc, config_servername);

        /* Add actions */
        for (i = 1; actions[i].name; i++) {
            buf_printf_markup(&resp, level, "<a href=\"%s%s%s\">%s</a>",
                              txn->req_uri->path, sep, actions[i].name,
                              actions[i].desc);
        }

        /* Finish HTML */
        buf_printf_markup(&resp, --level, "</body>");
        buf_printf_markup(&resp, --level, "</html>");

        /* Update lastmod */
        lastmod = txn->resp_body.lastmod;
    }

    /* Output the HTML response */
    txn->resp_body.type = "text/html; charset=utf-8";
    write_body(precond, txn, buf_cstring(&resp), buf_len(&resp));

    return 0;
}


struct proc_info {
    pid_t pid;
    char *servicename;
    char *user;
    char *host;
    char *mailbox;
    char *cmdname;
    char state;
    time_t start;
    unsigned long vmsize;
};

typedef struct {
    unsigned count;
    unsigned alloc;
    struct proc_info **data;
} piarray_t;

static int add_procinfo(pid_t pid,
                        const char *servicename, const char *host,
                        const char *user, const char *mailbox,
                        const char *cmdname,
                        void *rock)
{
    piarray_t *piarray = (piarray_t *) rock;
    struct proc_info *pinfo;
    char procpath[100];
    struct stat sbuf;
    FILE *f;

    snprintf(procpath, sizeof(procpath), "/proc/%d", pid);
    if (stat(procpath, &sbuf)) return 0;

    if (piarray->count >= piarray->alloc) {
        piarray->alloc += 100;
        piarray->data = xrealloc(piarray->data,
                                 piarray->alloc * sizeof(struct proc_info *));
    }

    pinfo = piarray->data[piarray->count++] =
        (struct proc_info *) xzmalloc(sizeof(struct proc_info));
    pinfo->pid = pid;
    pinfo->servicename = xstrdupsafe(servicename);
    pinfo->host = xstrdupsafe(host);
    pinfo->user = xstrdupsafe(user);
    pinfo->mailbox = xstrdupsafe(mailbox);
    pinfo->cmdname = xstrdupsafe(cmdname);

    strlcat(procpath, "/stat", sizeof(procpath));
    f = fopen(procpath, "r");
    if (f) {
        int d;
        long ld;
        unsigned u;
        unsigned long vmsize = 0, lu;
        unsigned long long starttime = 0;
        char state = 0, *s = NULL;

        fscanf(f, "%d %ms %c " /* 1-3 */
               "%d %d %d %d %d %u " /* 4-9 */
               "%lu %lu %lu %lu %lu %lu " /* 10-15 */
               "%ld %ld %ld %ld %ld %ld " /* 16-21 */
               "%llu %lu %ld", /* 22-24 */
               &d, &s, &state,
               &d, &d, &d, &d, &d, &u,
               &lu, &lu, &lu, &lu, &lu, &lu,
               &ld, &ld, &ld, &ld, &ld, &ld,
               &starttime, &vmsize, &ld);

        free(s);
        fclose(f);

        pinfo->state = state;
        pinfo->vmsize = vmsize;
        pinfo->start = starttime/sysconf(_SC_CLK_TCK);
    }

    return 0;
}

static int sort_procinfo(const struct proc_info **a, const struct proc_info **b,
                         const char *key)
{
    int r;
    int rev = islower((int) *key);

    switch (toupper((int) *key)) {
    default:
    case 'P':
        r = (*a)->pid - (*b)->pid;
        break;

    case 'S':
        r = strcmp((*a)->servicename, (*b)->servicename);
        break;

    case 'Q':
        r = (*a)->state - (*b)->state;
        break;

    case 'T':
        r = (*a)->start - (*b)->start;
        break;

    case 'V':
        r = (*a)->vmsize - (*b)->vmsize;
        break;

    case 'H':
        r = strcmp((*a)->host, (*b)->host);
        break;

    case 'U':
        r = strcmp((*a)->user, (*b)->user);
        break;

    case 'R':
        r = strcmp((*a)->mailbox, (*b)->mailbox);
        break;

    case 'C':
        r = strcmp((*a)->cmdname, (*b)->cmdname);
        break;
    }

    return (rev ? -r : r);
}

/* Perform a proc action */
static int action_proc(struct transaction_t *txn)
{
    unsigned level = 0, i;
    struct buf *body = &txn->resp_body.payload;
    piarray_t piarray = { 0, 0, NULL };
    time_t now = time(0), boot_time = 0;
    struct strlist *param;
    struct tm tnow;
    char key = 0;
    FILE *f;
    struct proc_columns {
        char key;
        const char *name;
    } columns[] = {
        { 'P', "PID" },
        { 'S', "Service" },
        { 'Q', "State" },
        { 'T', "Start" },
        { 'V', "VmSize" },
        { 'H', "Client" },
        { 'U', "User" },
        { 'R', "Resource" },
        { 'C', "Command" },
        { 0, NULL}
    };

    localtime_r(&now, &tnow);

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        goto done;
    }

    /* Check for a sort key */
    param = hash_lookup("sort", &txn->req_qparams);
    if (param) {
        char Ukey = toupper((int) *param->s);
        for (i = 0; columns[i].key; i++) {
            if (Ukey == columns[i].key) {
                key = *param->s;
                if (isupper((int) key)) columns[i].key = tolower((int) key);
                break;
            }
        }
    }
    if (!key) {
        key = 'P';
        columns[0].key = 'p';
    }

    /* Find boot time in /proc/stat (needed for calculating process start) */
    f = fopen("/proc/stat", "r");
    if (f) {
        char buf[1024];

        while (fgets(buf, sizeof(buf), f)) {
            if (sscanf(buf, "btime %ld\n", &boot_time) == 1) break;
            while (buf[strlen(buf)-1] != '\n' && fgets(buf, sizeof(buf), f)) {
            }
        }
        fclose(f);
    }

    /* Get and sort info for running processes */
    proc_foreach(add_procinfo, &piarray);

    qsort_r(piarray.data, piarray.count, sizeof(struct proc_info *),
            (int (*)(const void *, const void *, void *)) &sort_procinfo, &key);

    /* Send HTML header */
    buf_reset(body);
    buf_printf_markup(body, level, HTML_DOCTYPE);
    buf_printf_markup(body, level++, "<html>");
    buf_printf_markup(body, level++, "<head>");
    buf_printf_markup(body, level, "<meta http-equiv=\"%s\" content=\"%s\">",
                      "Refresh", "1");
    buf_printf_markup(body, level, "<title>%s</title>",
                      "Currently Running Cyrus Services");
    buf_printf_markup(body, --level, "</head>");
    buf_printf_markup(body, level++, "<body>");
    buf_printf_markup(body, level, "<h2>%s @ %s</h2>",
                      "Currently Running Cyrus Services", config_servername);
    buf_printf_markup(body, level++, "<table border cellpadding=5>");
    buf_printf_markup(body, level, "<caption><b>%.*s</b></caption>",
                      24 /* clip LF */, asctime(&tnow));
    buf_printf_markup(body, level++, "<tr>");
    for (i = 0; columns[i].key; i++) {
        buf_printf_markup(body, level, "<th><a href=\"%s?sort=%c\">%s</a></th>",
                          txn->req_uri->path, columns[i].key, columns[i].name);
    }
    buf_printf_markup(body, --level, "</tr>");

    /* Add processes to table */
    for (i = 0; i < piarray.count; i++) {
        struct proc_info *pinfo = piarray.data[i];

        /* Send a chunk every 100 processes */
        if (!(i % 100)) {
            write_body(HTTP_OK, txn, buf_cstring(body), buf_len(body));
            buf_reset(body);
        }

        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td>%d</td>", (int) pinfo->pid);
        buf_printf_markup(body, level, "<td>%s</td>", pinfo->servicename);

        if (pinfo->vmsize) {
            const char *proc_states[] = {
                /* A */ "", /* B */ "", /* C */ "",
                /* D */ " (waiting)",
                /* E */ "", /* F */ "", /* G */ "", /* H */ "", /* I */ "",
                /* J */ "", /* K */ "", /* L */ "", /* M */ "", /* N */ "",
                /* O */ "", /* P */ "", /* Q */ "",
                /* R */ " (running)",
                /* S */ " (sleeping)",
                /* T */ " (stopped)",
                /* U */ "", /* V */ "",
                /* W */ " (paging)",
                /* X */ "", /* Y */ "",
                /* Z */ " (zombie)"
            };
            const char *monthname[] = {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
            };

            buf_printf_markup(body, level, "<td>%c%s</td>", pinfo->state,
                              isupper((int) pinfo->state) ?
                              proc_states[pinfo->state - 'A'] : "");

            if (boot_time) {
                struct tm start;

                pinfo->start += boot_time;
                localtime_r(&pinfo->start, &start);
                if (start.tm_yday != tnow.tm_yday) {
                    buf_printf_markup(body, level, "<td>%s %02d</td>",
                                      monthname[start.tm_mon], start.tm_mday);
                }
                else {
                    buf_printf_markup(body, level, "<td>%02d:%02d</td>",
                                      start.tm_hour, start.tm_min);
                }
            }
            else buf_printf_markup(body, level, "<td></td>");
                              
            buf_printf_markup(body, level, "<td>%lu</td>", pinfo->vmsize/1024);
        }
        else buf_printf_markup(body, level, "<td></td><td></td><td></td>");

        buf_printf_markup(body, level, "<td>%s</td>", pinfo->host);
        buf_printf_markup(body, level, "<td>%s</td>", pinfo->user);
        buf_printf_markup(body, level, "<td>%s</td>", pinfo->mailbox);
        buf_printf_markup(body, level, "<td>%s</td>", pinfo->cmdname);
        buf_printf_markup(body, --level, "</tr>");

        free(pinfo->servicename);
        free(pinfo->host);
        free(pinfo->user);
        free(pinfo->mailbox);
        free(pinfo->cmdname);
        free(pinfo);
    }
    free(piarray.data);

    /* Finish table */
    buf_printf_markup(body, --level, "</table>");

    /* Finish HTML */
    buf_printf_markup(body, --level, "</body>");
    buf_printf_markup(body, --level, "</html>");
    write_body(0, txn, buf_cstring(body), buf_len(body));

    /* End of output */
    write_body(0, txn, NULL, 0);

 done:
    return 0;
}
