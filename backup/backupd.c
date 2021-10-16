/* backupd.c -- replication-based backup daemon
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

#include <config.h>

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/types.h>

#include "lib/bsearch.h"
#include "lib/imparse.h"
#include "lib/map.h"
#include "lib/signals.h"
#include "lib/strarray.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#include "imap/global.h"
#include "imap/imap_err.h"
#include "imap/proc.h"
#include "imap/sync_support.h"
#include "imap/telemetry.h"
#include "imap/tls.h"
#include "imap/version.h"

#include "backup/backup.h"

const int config_need_data = 0;
static sasl_ssf_t extprops_ssf = 0;

static struct auth_state *backupd_authstate = 0;
static int backupd_userisadmin = 0;
static char *backupd_userid = NULL;
static struct protstream *backupd_out = NULL;
static struct protstream *backupd_in = NULL;
static const char *backupd_clienthost = "[local]";
static sasl_conn_t *backupd_saslconn = NULL;
static int backupd_starttls_done = 0;
static int backupd_compress_done = 0;
static int backupd_logfd = -1;

struct open_backup {
    char *name;
    struct backup *backup;
    time_t timestamp;
    struct open_backup *next;
    struct sync_msgid_list *reserved_guids;
};

static struct open_backups_list {
    struct open_backup *head;
    size_t count;
} backupd_open_backups = {0};

static struct {
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = { NULL, NULL, 0, NULL};

static struct proxy_context backupd_proxyctx = {
    0, 1, &backupd_authstate, &backupd_userisadmin, NULL
};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &backupd_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

extern int saslserver(sasl_conn_t *conn, const char *mech,
                      const char *init_resp, const char *resp_prefix,
                      const char *continuation, const char *empty_resp,
                      struct protstream *pin, struct protstream *pout,
                      int *sasl_result, char **success_data);

static void backupd_reset(void);
static void dobanner(void);
static int reset_saslconn(sasl_conn_t **conn);
static void shut_down(int code) __attribute__((noreturn));
static void usage(void);

static struct open_backup *open_backups_list_add(struct open_backups_list *list,
                                                 const char *name,
                                                 struct backup *backup);
static struct open_backup *open_backups_list_find(struct open_backups_list *list,
                                                  const char *name);
static void open_backups_list_close(struct open_backups_list *list, time_t age);

static int backupd_print_mailbox(const struct backup_mailbox *mailbox,
                                 void *rock __attribute__((__unused__)));
static int backupd_print_seen(const struct backup_seen *seen,
                              void *rock __attribute__((__unused__)));
static int backupd_print_subscriptions(struct backup *backup);
static int backupd_print_sieve(const struct backup_sieve *sieve,
                               void *rock __attribute__((__unused__)));
static const char *backupd_response(int r);

static void cmdloop(void);
static void cmd_authenticate(char *mech, char *resp);
static void cmd_apply(struct dlist *dl);
static void cmd_compress(const char *alg);
static void cmd_get(struct dlist *dl);
static void cmd_restart(void);

/****************************************************************************/

EXPORTED void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        /* We were called recursively. Just give up */
        proc_cleanup();
        exit(recurse_code);
    }
    recurse_code = code;

    open_backups_list_close(&backupd_open_backups, 0);

    if (backupd_out) {
        prot_printf(backupd_out, "* Fatal error: %s\r\n", s);
        prot_flush(backupd_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
EXPORTED int service_init(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    int opt;

    // FIXME should this be calling fatal? fatal exits directly
    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    while ((opt = getopt(argc, argv, "p:f")) != EOF) {
        switch(opt) {
        case 'p': /* external protection */
            extprops_ssf = atoi(optarg);
            break;
        default:
            usage();
        }
    }

    return 0;
}

/* Called by service API to shut down the service */
EXPORTED void service_abort(int error)
{
    shut_down(error);
}

/*
 * run for each accepted connection
 */
EXPORTED int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    const char *localip, *remoteip;
    sasl_security_properties_t *secprops = NULL;
    int timeout;

    signals_poll();

    backupd_in = prot_new(0, 0);
    backupd_out = prot_new(1, 1);

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(backupd_in, 1);
    prot_setisclient(backupd_out, 1);

    /* Find out name of client host */
    backupd_clienthost = get_clienthost(0, &localip, &remoteip);
    if (!strcmp(backupd_clienthost, UNIX_SOCKET)) {
        /* we're not connected to an internet socket! */
        backupd_userid = xstrdup(cyrus_user());
        backupd_userisadmin = 1;
    }
    else {
        /* other params should be filled in */
        if (sasl_server_new("csync", config_servername, NULL, NULL, NULL,
                            NULL, 0, &backupd_saslconn) != SASL_OK)
            fatal("SASL failed initializing: sasl_server_new()",EX_TEMPFAIL);

        /* will always return something valid */
        secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
        if (sasl_setprop(backupd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
            fatal("Failed to set SASL property", EX_TEMPFAIL);

        if (sasl_setprop(backupd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
            fatal("Failed to set SASL property", EX_TEMPFAIL);

        if (localip) {
            sasl_setprop(backupd_saslconn, SASL_IPLOCALPORT, localip);
            saslprops.iplocalport = xstrdup(localip);
        }

        if (remoteip) {
            if (sasl_setprop(backupd_saslconn, SASL_IPREMOTEPORT, remoteip) != SASL_OK)
                fatal("failed to set sasl property", EX_TEMPFAIL);
            saslprops.ipremoteport = xstrdup(remoteip);
        }

        tcp_disable_nagle(1); /* XXX magic fd */
    }

    proc_register(config_ident, backupd_clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getduration(IMAPOPT_SYNC_TIMEOUT, 's');
    if (timeout < 3) timeout = 3;
    prot_settimeout(backupd_in, timeout);

    prot_setflushonread(backupd_in, backupd_out);

    dobanner();

    cmdloop();

    /* EXIT executed */

    /* cleanup */
    backupd_reset();

    return 0;
}

/****************************************************************************/

static void backupd_reset(void)
{
    open_backups_list_close(&backupd_open_backups, 0);

    proc_cleanup();

    if (backupd_in) {
        prot_NONBLOCK(backupd_in);
        prot_fill(backupd_in);
        prot_free(backupd_in);
        backupd_in = NULL;
    }

    if (backupd_out) {
        prot_flush(backupd_out);
        prot_free(backupd_out);
        backupd_out = NULL;
    }

//#ifdef HAVE_SSL
//    if (tls_conn) {
//        tls_reset_servertls(&tls_conn);
//        tls_conn = NULL;
//    }
//#endif

    cyrus_reset_stdio();

    backupd_clienthost = "[local]";
    if (backupd_logfd != -1) {
        close(backupd_logfd);
        backupd_logfd = -1;
    }
    if (backupd_userid != NULL) {
        free(backupd_userid);
        backupd_userid = NULL;
    }
    if (backupd_authstate) {
        auth_freestate(backupd_authstate);
        backupd_authstate = NULL;
    }
    if (backupd_saslconn) {
        sasl_dispose(&backupd_saslconn);
        backupd_saslconn = NULL;
    }

    backupd_starttls_done = 0;
    backupd_compress_done = 0;

    if(saslprops.iplocalport) {
       free(saslprops.iplocalport);
       saslprops.iplocalport = NULL;
    }
    if(saslprops.ipremoteport) {
       free(saslprops.ipremoteport);
       saslprops.ipremoteport = NULL;
    }
    if(saslprops.authid) {
       free(saslprops.authid);
       saslprops.authid = NULL;
    }
    saslprops.ssf = 0;

    backup_cleanup_staging_path();
}

static void dobanner(void)
{
    const char *mechlist;
    int mechcount;

    if (!backupd_userid) {
        if (sasl_listmech(backupd_saslconn, NULL,
                          "* SASL ", " ", "\r\n",
                          &mechlist, NULL, &mechcount) == SASL_OK
            && mechcount > 0) {
            prot_printf(backupd_out, "%s", mechlist);
        }

        if (tls_enabled() && !backupd_starttls_done) {
            prot_printf(backupd_out, "* STARTTLS\r\n");
        }

#ifdef HAVE_ZLIB
        if (!backupd_compress_done && !backupd_starttls_done) {
            prot_printf(backupd_out, "* COMPRESS DEFLATE\r\n");
        }
#endif
    }

    prot_printf(backupd_out,
                "* OK %s Cyrus backup server %s\r\n",
                config_servername, CYRUS_VERSION);

    prot_flush(backupd_out);
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("csync", config_servername,
                         NULL, NULL, NULL,
                         NULL, 0, conn);
    if (ret != SASL_OK) return ret;

    if (saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
                          saslprops.ipremoteport);
    if (ret != SASL_OK) return ret;

    if (saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
                          saslprops.iplocalport);
    if (ret != SASL_OK) return ret;
    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if (ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if (saslprops.ssf) {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    } else {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }

    if (ret != SASL_OK) return ret;

    if (saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

static void shut_down(int code)
{
    in_shutdown = 1;

    backupd_reset();

    cyrus_done();

    exit(code);
}

static void usage(void)
{
    // FIXME
}

/****************************************************************************/

static struct open_backup *open_backups_list_add(struct open_backups_list *list,
                                          const char *name, struct backup *backup)
{
    struct open_backup *open = xzmalloc(sizeof(struct open_backup));

    open->next = list->head;
    list->head = open;
    list->count++;

    open->name = xstrdupnull(name);
    open->backup = backup;
    open->timestamp = time(0);

    /* XXX pick a suitable msgid list hash size:
     *   0 (default) => 256
     *   SYNC_MSGID_LIST_HASH_SIZE (used by sync_server) => 65536
     */
    open->reserved_guids = sync_msgid_list_create(0);

    return open;
}

static struct open_backup *open_backups_list_find(struct open_backups_list *list,
                                           const char *name)
{
    struct open_backup *open;

    for (open = list->head; open; open = open->next) {
        if (strcmpnull(name, open->name) == 0)
            return open;
    }

    return NULL;
}

static int backupd_open_backup(struct open_backup **openp, const mbname_t *mbname)
{
    const char *key = mbname_userid(mbname);

    struct open_backup *open = open_backups_list_find(&backupd_open_backups, key);

    time_t now = time(0);

    if (!open) {
        struct backup *backup = NULL;
        int r = backup_open(&backup, mbname,
                            BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_CREATE);
        if (r) return r;

        r = backup_verify(backup, BACKUP_VERIFY_QUICK, 0, NULL);

        if (!r)
            r = backup_append_start(backup, NULL, BACKUP_APPEND_FLUSH);

        if (r) {
            backup_close(&backup);
            return r;
        }

        open = open_backups_list_add(&backupd_open_backups, key, backup);
    }

    open->timestamp = now;
    *openp = open;

    return 0;
}


// FIXME do i even need this - yes if a user gets renamed, need to close the old handle
#if 0
static struct open_backup *open_backups_list_remove(struct open_backups_list *list,
                                             const char *name)
{
    struct open_backup *open, *prev = NULL;

    for (open = list->head; open; open = open->next) {
        if (strcmp(name, open->name) == 0)
            break;

        prev = open;
    }

    if (!open) return NULL;

    if (prev)
        prev->next = open->next;
    else
        list->head = open->next;

    list->count --;
    open->next = NULL;
    return open;
}
#endif

static void open_backups_list_close(struct open_backups_list *list, time_t age)
{
    time_t now = time(0);

    struct open_backup *current = list->head, *prev = NULL;

    while (current) {
        struct open_backup *next = current->next;

        if (!age || current->timestamp < now - age) {
            current->next = NULL;
            backup_close(&current->backup);
            sync_msgid_list_free(&current->reserved_guids);
            free(current->name);
            free(current);

            if (prev) {
                prev->next = next;
            }
            else {
                list->head = next;
            }

            list->count --;
        }
        else {
            prev = current;
        }

        current = next;
    }
}

/****************************************************************************/

static void cmdloop(void)
{
    int c;
    char *p;
    static struct buf cmd;
    static struct buf arg1, arg2;

    /* we don't expect there to be backups open already */
    assert(backupd_open_backups.head == NULL);
    assert(backupd_open_backups.count == 0);

    for (;;) {
        prot_flush(backupd_out);
        open_backups_list_close(&backupd_open_backups, 5 * 60); /* 5 mins FIXME */

        /* Parse command name */
        if ((c = getword(backupd_in, &cmd)) == EOF)
            break;

        if (!cmd.s[0]) {
            prot_printf(backupd_out, "BAD Null command\r\n");
            eatline(backupd_in, c);
            continue;
        }

        if (Uislower(cmd.s[0]))
            cmd.s[0] = toupper((unsigned char) cmd.s[0]);
        for (p = &cmd.s[1]; *p; p++) {
            if (Uisupper(*p)) *p = tolower((unsigned char) *p);
        }

        /* Must be an admin */
        if (backupd_userid && !backupd_userisadmin) goto noperm;

        switch (cmd.s[0]) {
        case 'A':
            if (!strcmp(cmd.s, "Authenticate")) {
                int haveinitresp = 0;
                if (c != ' ') goto missingargs;
                c = getword(backupd_in, &arg1);
                if (!imparse_isatom(arg1.s)) {
                    prot_printf(backupd_out, "BAD Invalid mechanism\r\n");
                    eatline(backupd_in, c);
                    continue;
                }
                if (c == ' ') {
                    haveinitresp = 1;
                    c = getword(backupd_in, &arg2);
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;

                if (backupd_userid) {
                    prot_printf(backupd_out, "BAD Already authenticated\r\n");
                    continue;
                }
                cmd_authenticate(arg1.s, haveinitresp ? arg2.s : NULL);
                continue;
            }
            if (!backupd_userid) goto nologin;
            if (!strcmp(cmd.s, "Apply")) {
                struct dlist *dl = NULL;
                c = dlist_parse(&dl, /*parsekeys*/ 1, /*isbackup*/ 1, backupd_in);
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                cmd_apply(dl);
                dlist_unlink_files(dl);
                dlist_free(&dl);
                continue;
            }
            break;

        case 'C':
            if (!strcmp(cmd.s, "Compress")) {
                if (c != ' ') goto missingargs;
                c = getword(backupd_in, &arg1);
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                cmd_compress(arg1.s);
                continue;
            }
            break;

        case 'E':
            if (!strcmp(cmd.s, "Exit")) {
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                prot_printf(backupd_out, "OK Finished\r\n");
                prot_flush(backupd_out);
                goto exit;
            }
            break;

        case 'G':
            if (!backupd_userid) goto nologin;
            if (!strcmp(cmd.s, "Get")) {
                struct dlist *dl = NULL;
                c = dlist_parse(&dl, /*parsekeys*/ 1, /*isbackup*/ 1, backupd_in);
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                cmd_get(dl);
                dlist_unlink_files(dl);
                dlist_free(&dl);
                continue;
            }
            break;

        case 'N':
            if (!strcmp(cmd.s, "Noop")) {
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                prot_printf(backupd_out, "OK Noop completed\r\n");
                continue;
            }
            break;

        case 'R':
            if (!strcmp(cmd.s, "Restart")) {
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                cmd_restart();
                prot_printf(backupd_out, "OK Restarting\r\n");
                continue;
            }
            break;

        case 'S':
            if (!strcmp(cmd.s, "Starttls") && tls_enabled()) {
                prot_printf(backupd_out, "NO command not implemented\r\n");
                eatline(backupd_in, c);
                continue;
            }
            break;

        }

        syslog(LOG_ERR, "IOERROR: received bad command: %s", cmd.s);
        prot_printf(backupd_out, "BAD IMAP_PROTOCOL_ERROR Unrecognized command\r\n");
        eatline(backupd_in, c);
        continue;

    nologin:
        prot_printf(backupd_out, "NO Please authenticate first\r\n");
        eatline(backupd_in, c);
        continue;

    noperm:
        prot_printf(backupd_out, "NO %s\r\n",
                    error_message(IMAP_PERMISSION_DENIED));
        eatline(backupd_in, c);
        continue;

    missingargs:
        prot_printf(backupd_out, "BAD Missing required argument to %s\r\n", cmd.s);
        eatline(backupd_in, c);
        continue;

    extraargs:
        prot_printf(backupd_out, "BAD Unexpected extra arguments to %s\r\n", cmd.s);
        eatline(backupd_in, c);
        continue;
    }

exit:
    cmd_restart();
}

static void cmd_authenticate(char *mech, char *resp)
{
    int r, sasl_result;
    sasl_ssf_t ssf;
    const char *ssfmsg = NULL;
    const void *val;
    int failedloginpause;

    if (backupd_userid) {
        prot_printf(backupd_out, "BAD Already authenticated\r\n");
        return;
    }

    r = saslserver(backupd_saslconn, mech, resp, "", "+ ", "",
                   backupd_in, backupd_out, &sasl_result, NULL);

    if (r) {
        const char *errorstring = NULL;

        switch (r) {
        case IMAP_SASL_CANCEL:
            prot_printf(backupd_out,
                        "BAD Client canceled authentication\r\n");
            break;
        case IMAP_SASL_PROTERR:
            errorstring = prot_error(backupd_in);

            prot_printf(backupd_out,
                        "NO Error reading client response: %s\r\n",
                        errorstring ? errorstring : "");
            break;
        default:
            /* failed authentication */
            errorstring = sasl_errstring(sasl_result, NULL, NULL);

            syslog(LOG_NOTICE, "badlogin: %s %s [%s]",
                   backupd_clienthost, mech, sasl_errdetail(backupd_saslconn));

            failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
            if (failedloginpause != 0) {
                sleep(failedloginpause);
            }

            if (errorstring) {
                prot_printf(backupd_out, "NO %s\r\n", errorstring);
            } else {
                prot_printf(backupd_out, "NO Error authenticating\r\n");
            }
        }

        reset_saslconn(&backupd_saslconn);
        return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(backupd_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
        prot_printf(backupd_out, "NO weird SASL error %d SASL_USERNAME\r\n",
                    sasl_result);
        syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME",
               sasl_result);
        reset_saslconn(&backupd_saslconn);
        return;
    }

    backupd_userid = xstrdup((const char *) val);
    proc_register(config_ident, backupd_clienthost, backupd_userid, NULL, NULL);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", backupd_clienthost, backupd_userid,
           mech, backupd_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(backupd_saslconn, SASL_SSF, &val);
    ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (backupd_starttls_done) {
        switch(ssf) {
        case 0: ssfmsg = "tls protection"; break;
        case 1: ssfmsg = "tls plus integrity protection"; break;
        default: ssfmsg = "tls plus privacy protection"; break;
        }
    } else {
        switch(ssf) {
        case 0: ssfmsg = "no protection"; break;
        case 1: ssfmsg = "integrity protection"; break;
        default: ssfmsg = "privacy protection"; break;
        }
    }

    prot_printf(backupd_out, "OK Success (%s)\r\n", ssfmsg);

    prot_setsasl(backupd_in,  backupd_saslconn);
    prot_setsasl(backupd_out, backupd_saslconn);

    /* Create telemetry log */
    backupd_logfd = telemetry_log(backupd_userid, backupd_in, backupd_out, 0);
}

static int cmd_apply_mailbox(struct dlist *dl)
{
    const char *mboxname = NULL;
    mbname_t *mbname;
    struct open_backup *open = NULL;
    int r;

    if (!dlist_getatom(dl, "MBOXNAME", &mboxname)) return IMAP_PROTOCOL_ERROR;

    mbname = mbname_from_intname(mboxname);
    r = backupd_open_backup(&open, mbname);
    mbname_free(&mbname);

    if (!r)
        r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);

    return r;
}

static int cmd_apply_unmailbox(struct dlist *dl)
{
    const char *mboxname = dl->sval;
    struct open_backup *open = NULL;
    int r;

    mbname_t *mbname = mbname_from_intname(mboxname);
    r = backupd_open_backup(&open, mbname);
    mbname_free(&mbname);

    if (!r)
        r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);

    return r;
}

static int cmd_apply_message(struct dlist *dl)
{
    struct sync_msgid_list *guids = sync_msgid_list_create(0);
    struct dlist *di;
    int r = 0;
    struct open_backup *openbkp;
    int appended = 0;

    /* dig out each guid */
    for (di = dl->head; di; di = di->next) {
        struct message_guid computed_guid, *guid = NULL;
        const char *fname = NULL;
        const char *msg_base = NULL;
        size_t msg_len = 0;
        int fd;

        if (!dlist_tofile(di, NULL, &guid, NULL, &fname))
            continue;

        /* bail out if it doesn't match the data */
        fd = open(fname, O_RDWR);
        if (fd != -1) {
            map_refresh(fd, 1, &msg_base, &msg_len, MAP_UNKNOWN_LEN, fname, NULL);

            message_guid_generate(&computed_guid, msg_base, msg_len);
            if (!message_guid_equal(guid, &computed_guid)) {
                syslog(LOG_ERR, "%s: guid mismatch: header %s, derived %s\n",
                    __func__, message_guid_encode(guid),
                    message_guid_encode(&computed_guid));
                r = IMAP_PROTOCOL_ERROR;
            }

            map_free(&msg_base, &msg_len);
            close(fd);
        }
        else {
            syslog(LOG_ERR, "IOERROR: %s open %s: %m", __func__, fname);
            r = IMAP_IOERROR;
        }

        if (r) goto done;
        sync_msgid_insert(guids, guid);
    }

    /* bail out if there's no messages */
    if (!guids->head) {
        r = IMAP_PROTOCOL_ERROR;
        goto done;
    }

    /* find each open backup that wants a copy of any of these guids,
     * and append the entire MESSAGE line to it
     */
    for (openbkp = backupd_open_backups.head; openbkp; openbkp = openbkp->next) {
        struct sync_msgid *msgid;
        int want_append = 0;

        for (msgid = guids->head; msgid; msgid = msgid->next) {
            if (sync_msgid_lookup(openbkp->reserved_guids, &msgid->guid)) {
                want_append++;
                sync_msgid_remove(openbkp->reserved_guids, &msgid->guid);
            }
        }

        if (want_append) {
            r = backup_append(openbkp->backup, dl, NULL, BACKUP_APPEND_FLUSH);
            if (r) break;
            appended++;
        }
    }

    /* for mailboxes that have never been seen before, the sync client
     * will send APPLY MESSAGE commands without a corresponding reserve,
     * which means none of the open backups will accept the message. if
     * we get here and haven't appended the line to any backup, then
     * we've found this case.  so append it to all of the open backups,
     * and let compact sort it out.
     */
    if (!r && appended == 0) {
        if (backupd_open_backups.count) {
            syslog(LOG_DEBUG,
                   "received unreserved messages, applying to all ("
                   SIZE_T_FMT ") open backups...",
                   backupd_open_backups.count);
            for (openbkp = backupd_open_backups.head; openbkp; openbkp = openbkp->next) {
                syslog(LOG_DEBUG, "applying unreserved messages to %s", openbkp->name);
                r = backup_append(openbkp->backup, dl, NULL, BACKUP_APPEND_FLUSH);
                if (r) break;
            }
        }
        else {
            syslog(LOG_DEBUG,
                   "received unreserved messages, but no open backups to apply to");
            r = IMAP_PROTOCOL_ERROR;
        }
    }

done:
    sync_msgid_list_free(&guids);
    return r;
}

static int reserve_one(const mbname_t *mbname,
                       struct dlist *dl, struct dlist *gl,
                       struct sync_msgid_list *missing)
{
    struct open_backup *open = NULL;
    struct dlist *di;
    int r;

    r = backupd_open_backup(&open, mbname);
    if (r) return r;

    r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);
    if (r) return r;

    for (di = gl->head; di; di = di->next) {
        struct message_guid *guid = NULL;
        const char *guid_str;
	int message_id;

        if (!dlist_toguid(di, &guid)) continue;
        guid_str = message_guid_encode(guid);

        message_id = backup_get_message_id(open->backup, guid_str);

        if (message_id <= 0) {
            syslog(LOG_DEBUG, "%s: %s wants message %s",
                              __func__, mbname_intname(mbname), guid_str);

            /* add it to the reserved guids list */
            sync_msgid_insert(open->reserved_guids, guid);

            /* add it to the missing list */
            sync_msgid_insert(missing, guid);
        }
    }

    return 0;
}

static int cmd_apply_reserve(struct dlist *dl)
{
    const char *partition = NULL;
    struct dlist *ml = NULL;
    struct dlist *gl = NULL;
    struct dlist *di;
    strarray_t userids = STRARRAY_INITIALIZER;
    mbname_t *shared_mbname = NULL;
    int i, r;
    struct sync_msgid_list *missing;

    if (!dlist_getatom(dl, "PARTITION", &partition)) return IMAP_PROTOCOL_ERROR;
    if (!dlist_getlist(dl, "MBOXNAME", &ml)) return IMAP_PROTOCOL_ERROR;
    if (!dlist_getlist(dl, "GUID", &gl)) return IMAP_PROTOCOL_ERROR;

    /* find the list of users this reserve applies to */
    for (di = ml->head; di; di = di->next) {
        mbname_t *mbname = mbname_from_intname(di->sval);
        if (mbname_userid(mbname)) {
            strarray_append(&userids, mbname_userid(mbname));
            mbname_free(&mbname);
        }
        else if (!shared_mbname) {
            shared_mbname = mbname;
        }
        else {
            mbname_free(&mbname);
        }
    }
    strarray_sort(&userids, cmpstringp_raw);
    strarray_uniq(&userids);

    /* track the missing guids */
    missing = sync_msgid_list_create(0);

    /* log the entire reserve to all relevant backups, and accumulate missing list */
    for (i = 0; i < strarray_size(&userids); i++) {
        mbname_t *mbname = mbname_from_userid(strarray_nth(&userids, i));
        r = reserve_one(mbname, dl, gl, missing);
        mbname_free(&mbname);

        if (r) goto done;
    }

    /* and the shared mailboxes backup, if there were any */
    if (shared_mbname) {
        r = reserve_one(shared_mbname, dl, gl, missing);
        if (r) goto done;
    }

    if (missing->head) {
        struct dlist *kout = dlist_newlist(NULL, "MISSING");
        struct sync_msgid *msgid;

        for (msgid = missing->head; msgid; msgid = msgid->next) {
            dlist_setguid(kout, "GUID", &msgid->guid);
        }

        prot_printf(backupd_out, "* ");
        dlist_print(kout, 1, backupd_out);
        prot_printf(backupd_out, "\r\n");
        dlist_free(&kout);
    }

done:
    mbname_free(&shared_mbname);
    strarray_fini(&userids);
    sync_msgid_list_free(&missing);
    return r;
}

static int cmd_apply_rename(struct dlist *dl)
{
    int r;
    const char *old_mboxname = NULL;
    const char *new_mboxname = NULL;
    mbname_t *old;
    mbname_t *new;

    if (!dlist_getatom(dl, "OLDMBOXNAME", &old_mboxname)) return IMAP_PROTOCOL_ERROR;
    if (!dlist_getatom(dl, "NEWMBOXNAME", &new_mboxname)) return IMAP_PROTOCOL_ERROR;

    old = mbname_from_intname(old_mboxname);
    new = mbname_from_intname(old_mboxname);

    if (strcmpnull(mbname_userid(old), mbname_userid(new)) == 0) {
        // same user, unremarkable folder rename *whew*
        struct open_backup *open = NULL;
        r = backupd_open_backup(&open, old);
        if (!r)
            r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);
    }
    else {
        // user name has changed!
        // FIXME implement this
        syslog(LOG_ERR, "rename of user not yet supported: %s -> %s",
            old_mboxname, new_mboxname);
        r = IMAP_INTERNAL;
    }

    mbname_free(&old);
    mbname_free(&new);

    return r;
}

static int cmd_apply_seen(struct dlist *dl)
{
    const char *userid = NULL;
    mbname_t *mbname = NULL;
    struct open_backup *open = NULL;
    int r;

    if (!dlist_getatom(dl, "USERID", &userid)) return IMAP_PROTOCOL_ERROR;

    mbname = mbname_from_userid(userid);
    r = backupd_open_backup(&open, mbname);
    mbname_free(&mbname);

    if (r) return r;

    r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);

    return r;
}

static int cmd_apply_sub(struct dlist *dl)
{
    const char *userid = NULL;
    const char *mboxname = NULL;
    mbname_t *mbname = NULL;
    struct open_backup *open = NULL;
    int r;

    if (!dlist_getatom(dl, "USERID", &userid)) return IMAP_PROTOCOL_ERROR;
    if (!dlist_getatom(dl, "MBOXNAME", &mboxname)) return IMAP_PROTOCOL_ERROR;

    mbname = mbname_from_userid(userid);
    r = backupd_open_backup(&open, mbname);
    mbname_free(&mbname);

    if (r) return r;

    r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);

    return r;
}

static int cmd_apply_sieve(struct dlist *dl)
{
    const char *userid = NULL;
    mbname_t *mbname = NULL;
    struct open_backup *open = NULL;
    int r;

    if (!dlist_getatom(dl, "USERID", &userid)) return IMAP_PROTOCOL_ERROR;

    mbname = mbname_from_userid(userid);
    r = backupd_open_backup(&open, mbname);
    mbname_free(&mbname);

    if (r) return r;

    r = backup_append(open->backup, dl, NULL, BACKUP_APPEND_FLUSH);

    return r;
}

static void cmd_apply(struct dlist *dl)
{
    int r;

    if (strcmp(dl->name, "MAILBOX") == 0) {
        r = cmd_apply_mailbox(dl);
    }
    else if (strcmp(dl->name, "UNMAILBOX") == 0) {
        r = cmd_apply_unmailbox(dl);
    }
    else if (strcmp(dl->name, "MESSAGE") == 0) {
        r = cmd_apply_message(dl);
    }
    else if (strcmp(dl->name, "QUOTA") == 0) {
        /* ignore and succeed */
        r = 0;
    }
    else if (strcmp(dl->name, "RENAME") == 0) {
        r = cmd_apply_rename(dl);
    }
    else if (strcmp(dl->name, "RESERVE") == 0) {
        r = cmd_apply_reserve(dl);
    }
    else if (strcmp(dl->name, "SEEN") == 0) {
        r = cmd_apply_seen(dl);
    }
    else if (strcmp(dl->name, "SIEVE") == 0) {
        r = cmd_apply_sieve(dl);
    }
    else if (strcmp(dl->name, "UNSIEVE") == 0) {
        r = cmd_apply_sieve(dl);
    }
    else if (strcmp(dl->name, "ACTIVATE_SIEVE") == 0) {
        /* ignore and succeed */
        r = 0;
    }
    else if (strcmp(dl->name, "UNACTIVATE_SIEVE") == 0) {
        /* ignore and succeed */
        r = 0;
    }
    else if (strcmp(dl->name, "SUB") == 0) {
        r = cmd_apply_sub(dl);
    }
    else if (strcmp(dl->name, "UNSUB") == 0) {
        r = cmd_apply_sub(dl);
    }
    else if (strcmp(dl->name, "UNUSER") == 0) {
        /* ignore and succeed */
        r = 0;
    }
    else {
        r = IMAP_PROTOCOL_ERROR;
    }

    syslog(LOG_DEBUG, "sending response to %s: %i (%s)",
           dl->name, r, error_message(r));
    prot_printf(backupd_out, "%s\r\n", backupd_response(r));
}

static void cmd_compress(const char *alg)
{
    if (backupd_compress_done) {
        prot_printf(backupd_out, "NO Compression already active: %s\r\n", alg);
        return;
    }
    if (strcasecmp(alg, "DEFLATE")) {
        prot_printf(backupd_out, "NO Unknown compression algorithm: %s\r\n", alg);
        return;
    }
    if (ZLIB_VERSION[0] != zlibVersion()[0]) {
        prot_printf(backupd_out, "NO Error initializing %s "
                    "(incompatible zlib version)\r\n", alg);
        return;
    }
    prot_printf(backupd_out, "OK %s active\r\n", alg);
    prot_flush(backupd_out);
    prot_setcompress(backupd_in);
    prot_setcompress(backupd_out);
    backupd_compress_done = 1;
}

static int backupd_print_mailbox(const struct backup_mailbox *mailbox,
                                 void *rock __attribute__((__unused__)))
{
    struct dlist *dlist;

    if (mailbox->deleted) return 0;

    dlist = backup_mailbox_to_dlist(mailbox);
    if (!dlist) return IMAP_INTERNAL;

    prot_puts(backupd_out, "* ");
    dlist_print(dlist, /* printkeys */ 1, backupd_out);
    prot_puts(backupd_out, "\r\n");
    dlist_free(&dlist);

    return 0;
}

static int backupd_print_seen(const struct backup_seen *seen,
                              void *rock __attribute__((__unused__)))
{
    struct dlist *kl = NULL;

    kl = dlist_newkvlist(NULL, "SEEN");
    dlist_setatom(kl, "UNIQUEID", seen->uniqueid);
    dlist_setdate(kl, "LASTREAD", seen->lastread);
    dlist_setnum32(kl, "LASTUID", seen->lastuid);
    dlist_setdate(kl, "LASTCHANGE", seen->lastchange);
    dlist_setatom(kl, "SEENUIDS", seen->seenuids);

    prot_puts(backupd_out, "* ");
    dlist_print(kl, 1, backupd_out);
    prot_puts(backupd_out, "\r\n");

    if (kl) dlist_free(&kl);

    return 0;
}

static int _sublist_add(const struct backup_subscription *sub, void *rock)
{
    strarray_t *list = (strarray_t *) rock;

    if (sub->unsubscribed) return 0;

    strarray_append(list, sub->mboxname);

    return 0;
}

static int backupd_print_subscriptions(struct backup *backup)
{
    int i, r;
    strarray_t list = STRARRAY_INITIALIZER;
    struct dlist *kl = NULL;

    r = backup_subscription_foreach(backup, 0, _sublist_add, &list);
    if (r) goto done;

    kl = dlist_newlist(NULL, "LSUB");

    for (i = 0; i < list.count; i++) {
        const char *mboxname = strarray_nth(&list, i);
        dlist_setatom(kl, "MBOXNAME", mboxname);
    }

    if (kl->head) {
        prot_puts(backupd_out, "* ");
        dlist_print(kl, 1, backupd_out);
        prot_puts(backupd_out, "\r\n");
    }

done:
    if (kl) dlist_free(&kl);
    strarray_fini(&list);
    return r;
}

static int backupd_print_sieve(const struct backup_sieve *sieve,
                               void *rock __attribute__((__unused__)))
{
    struct dlist *kl = NULL;

    if (sieve->deleted) return 0;

    kl = dlist_newkvlist(NULL, "SIEVE");
    dlist_setatom(kl, "FILENAME", sieve->filename);
    dlist_setdate(kl, "LAST_UPDATE", sieve->last_update);
    dlist_setatom(kl, "GUID", message_guid_encode(&sieve->guid));
    dlist_setnum32(kl, "ISACTIVE", 0);

    prot_puts(backupd_out, "* ");
    dlist_print(kl, 1, backupd_out);
    prot_puts(backupd_out, "\r\n");

    if (kl) dlist_free(&kl);

    return 0;
}

static const char *backupd_response(int r)
{
    switch (r) {
    case 0:
        return "OK Success";
    case IMAP_MAILBOX_LOCKED:
        return "NO IMAP_MAILBOX_LOCKED Mailbox locked";
    case IMAP_MAILBOX_NONEXISTENT:
        return "NO IMAP_MAILBOX_NONEXISTENT No Such Mailbox";
    case IMAP_PROTOCOL_ERROR:
        return "NO IMAP_PROTOCOL_ERROR Protocol error";
    case IMAP_PROTOCOL_BAD_PARAMETERS:
        return "NO IMAP_PROTOCOL_BAD_PARAMETERS Bad parameters";
    default:
        return "NO Unknown error";
    }
}

static int cmd_get_mailbox(struct dlist *dl, int want_records)
{
    struct open_backup *open = NULL;
    struct backup_mailbox *mb = NULL;
    mbname_t *mbname = NULL;
    int r;

    if (!dl->sval) return IMAP_PROTOCOL_BAD_PARAMETERS;

    mbname = mbname_from_intname(dl->sval);
    if (!mbname) return IMAP_INTERNAL;

    r = backupd_open_backup(&open, mbname);
    if (r) goto done;

    mb = backup_get_mailbox_by_name(open->backup, mbname, want_records);
    if (!mb) {
        r = IMAP_MAILBOX_NONEXISTENT;
        goto done;
    }

    backupd_print_mailbox(mb, NULL);
    r = 0;

done:
    if (mb) backup_mailbox_free(&mb);
    if (mbname) mbname_free(&mbname);

    return r;
}

static int cmd_get_meta(struct dlist *dl)
{
    struct open_backup *open = NULL;
    mbname_t *mbname = NULL;
    int r;

    if (!dl->sval) return IMAP_PROTOCOL_BAD_PARAMETERS;

    mbname = mbname_from_userid(dl->sval);
    if (!mbname) return IMAP_INTERNAL;

    r = backupd_open_backup(&open, mbname);
    if (r) goto done;

    r = backup_seen_foreach(open->backup, 0,
                            backupd_print_seen, NULL);
    if (r) goto done;

    r = backupd_print_subscriptions(open->backup);
    if (r) goto done;

    r = backup_sieve_foreach(open->backup, 0,
                             backupd_print_sieve, NULL);
    if (r) goto done;

done:
    if (mbname) mbname_free(&mbname);
    return r;
}

static int is_mailboxes_single_user(struct dlist *dl)
{
    char *userid = NULL;
    struct dlist *di;

    for (di = dl->head; di; di = di->next) {
        mbname_t *mbname;

        if (!di->sval) continue;

        mbname = mbname_from_intname(di->sval);

        if (!userid) {
            userid = xstrdupnull(mbname_userid(mbname));
        }
        else if (strcmpnull(userid, mbname_userid(mbname)) != 0) {
            mbname_free(&mbname);
            free(userid);
            return 0;
        }

        mbname_free(&mbname);
    }

    free(userid);
    /* also returns 1 if all mailboxes belong to no user (shared)*/
    return 1;
}

static void cmd_get(struct dlist *dl)
{
    int r = IMAP_PROTOCOL_ERROR;
    mbname_t *mbname = NULL;

    ucase(dl->name);

    if (strcmp(dl->name, "USER") == 0) {
        struct open_backup *open = NULL;

        if (dl->sval) {
            mbname = mbname_from_userid(dl->sval);
            r = backupd_open_backup(&open, mbname);
            if (r) goto done;

            r = backup_mailbox_foreach(open->backup, 0,
                                       BACKUP_MAILBOX_NO_RECORDS,
                                       backupd_print_mailbox, NULL);
            if (r) goto done;

            r = backup_seen_foreach(open->backup, 0,
                                    backupd_print_seen, NULL);
            if (r) goto done;

            r = backupd_print_subscriptions(open->backup);
            if (r) goto done;

            r = backup_sieve_foreach(open->backup, 0,
                                     backupd_print_sieve, NULL);
        }
        else {
            r = IMAP_PROTOCOL_BAD_PARAMETERS;
        }
    }
    else if (strcmp(dl->name, "MAILBOXES") == 0) {
        struct dlist *di;
        if (is_mailboxes_single_user(dl)) {
            for (di = dl->head; di; di = di->next) {
                r = cmd_get_mailbox(di, 0);
                /* it's not an error for a mailbox to not exist here */
                if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
                if (r) break;
            }
        }
        else {
            /* reject MAILBOXES requests that span multiple users.
             * sync_client will promote these to USER requests, which
             * it always sends one at a time with a restart in between
             */
            r = IMAP_PROTOCOL_BAD_PARAMETERS;
        }
    }
    else if (strcmp(dl->name, "FULLMAILBOX") == 0) {
        r = cmd_get_mailbox(dl, 1);
    }
    else if (strcmp(dl->name, "META") == 0) {
        r = cmd_get_meta(dl);
    }
    else if (strcmp(dl->name, "UNIQUEIDS") == 0) {
        r = 0; // we don't send anything back other than OK
    }
    else {
        r = IMAP_PROTOCOL_ERROR;
    }

done:

    if (mbname) mbname_free(&mbname);

    syslog(LOG_DEBUG, "sending response to %s: %i (%s)",
           dl->name, r, error_message(r));
    prot_printf(backupd_out, "%s\r\n", backupd_response(r));
}

static void cmd_restart(void)
{
    open_backups_list_close(&backupd_open_backups, 0);
}
