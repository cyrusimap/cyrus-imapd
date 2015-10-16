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
#include <syslog.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/types.h>

#include "exitcodes.h"
#include "imparse.h"
#include "signals.h"
#include "xmalloc.h"

#include "imap/global.h"
#include "imap/imap_err.h"
#include "imap/proc.h"
#include "imap/telemetry.h"
#include "imap/tls.h"
#include "imap/version.h"

#include "backup/api.h"

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
static const char *backupd_response(int r);

static void cmdloop(void);
static void cmd_authenticate(char *mech, char *resp);
static void cmd_apply(struct dlist *dl);
static void cmd_get(struct dlist *dl);

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
    // FIXME should this be calling fatal? fatal exits directly
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    int opt;
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
    struct protoent *proto;
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
        backupd_userid = xstrdup("cyrus");
        backupd_userisadmin = 1;
    }
    else {
        /* other params should be filled in */
        if (sasl_server_new("csync", config_servername, NULL, NULL, NULL,
                            NULL, 0, &backupd_saslconn) != SASL_OK)
            fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL);

        /* will always return something valid */
        secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
        if (sasl_setprop(backupd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
            fatal("Failed to set SASL property", EC_TEMPFAIL);

        if (sasl_setprop(backupd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
            fatal("Failed to set SASL property", EC_TEMPFAIL);

        if (localip) {
            sasl_setprop(backupd_saslconn, SASL_IPLOCALPORT, localip);
            saslprops.iplocalport = xstrdup(localip);
        }

        if (remoteip) {
            if (sasl_setprop(backupd_saslconn, SASL_IPREMOTEPORT, remoteip) != SASL_OK)
                fatal("failed to set sasl property", EC_TEMPFAIL);
            saslprops.ipremoteport = xstrdup(remoteip);
        }

        /* Disable Nagle's Algorithm => increase throughput
         *
         * http://en.wikipedia.org/wiki/Nagle's_algorithm
         */
        if ((proto = getprotobyname("tcp")) != NULL) {
            int on = 1;

            if (setsockopt(1, proto->p_proto, TCP_NODELAY,
                           (void *) &on, sizeof(on)) != 0) {
                syslog(LOG_ERR, "unable to setsocketopt(TCP_NODELAY): %m");
            }
        }
        else {
            syslog(LOG_ERR, "unable to getprotobyname(\"tcp\"): %m");
        }
    }

    proc_register(config_ident, backupd_clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getint(IMAPOPT_SYNC_TIMEOUT);
    if (timeout < 3) timeout = 3;
    prot_settimeout(backupd_in, timeout);

    prot_setflushonread(backupd_in, backupd_out);

//  FIXME sync logging?
//    sync_log_init();
//    if (!config_getswitch(IMAPOPT_SYNC_LOG_CHAIN))
//        sync_log_suppress();

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
                config_servername, cyrus_version());

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

// FIXME is this needed? i don't see init being called
//    cyrus_done();

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

    open->name = xstrdup(name);
    open->backup = backup;
    open->timestamp = time(0);

    return open;
}

static struct open_backup *open_backups_list_find(struct open_backups_list *list,
                                           const char *name)
{
    struct open_backup *open;

    for (open = list->head; open; open = open->next) {
        if (strcmp(name, open->name) == 0)
            return open;
    }

    return NULL;
}

static struct open_backup *backupd_open_backup(const mbname_t *mbname)
{
    const char *key = mbname_userid(mbname);

    struct open_backup *open = open_backups_list_find(&backupd_open_backups, key);

    time_t now = time(0);

    if (!open) {
        struct backup *backup = backup_open(mbname);
        if (!backup) return NULL;
        backup_append_start(backup); // FIXME error checking
        open = open_backups_list_add(&backupd_open_backups, key, backup);
    }

    open->timestamp = now;

    return open;
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
                c = dlist_parse(&dl, DLIST_SFILE | DLIST_PARSEKEY, backupd_in);
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                cmd_apply(dl);
                dlist_free(&dl);
                continue;
            }
            break;

        case 'C':
            if (!strcmp(cmd.s, "Compress")) {
                prot_printf(backupd_out, "NO command not implemented\r\n");
                eatline(backupd_in, c);
                continue;
            }
            break;

        case 'G':
            if (!backupd_userid) goto nologin;
            if (!strcmp(cmd.s, "Get")) {
                struct dlist *dl = NULL;
                c = dlist_parse(&dl, DLIST_SFILE | DLIST_PARSEKEY, backupd_in);
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(backupd_in);
                if (c != '\n') goto extraargs;
                cmd_get(dl);
                dlist_free(&dl);
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
                prot_printf(backupd_out, "NO command not implemented\r\n");
                eatline(backupd_in, c);
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
    open_backups_list_close(&backupd_open_backups, 0);
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

            failedloginpause = config_getint(IMAPOPT_FAILEDLOGINPAUSE);
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

static int cmd_apply_reserve(struct dlist *dl)
{
    const char *partition = NULL;
    struct dlist *ml = NULL;
    struct dlist *gl = NULL;
    struct dlist *di;

    if (!dlist_getatom(dl, "PARTITION", &partition)) return IMAP_PROTOCOL_ERROR;
    if (!dlist_getlist(dl, "MBOXNAME", &ml)) return IMAP_PROTOCOL_ERROR;
    if (!dlist_getlist(dl, "GUID", &ml)) return IMAP_PROTOCOL_ERROR;

    /*
     * FIXME naively assuming MBOXNAMEs all belong to same user and
     * therefore only caring about the first one
     */
    mbname_t *mbname = mbname_from_intname(ml->head->sval);
    struct open_backup *open = backupd_open_backup(mbname);
    mbname_free(&mbname);

    if (!open) return IMAP_INTERNAL;

    int r = backup_append(open->backup, dl, time(0));
    if (r) {
        syslog(LOG_ERR, "%s: backup_append failed: %i", __func__, r);
        return IMAP_INTERNAL;
    }

    struct dlist *missing = dlist_newlist(NULL, "MISSING");
    for (di = gl->head; di; di = di->next) {
        struct message_guid *guid = NULL;
        const char *guid_str;

        if (!dlist_toguid(di, &guid)) continue;
        guid_str = message_guid_encode(guid);

        int message_id = backup_get_message_id(open->backup, guid_str);

        if (message_id <= 0) {
            /* FIXME this looks like how sync_apply_reserve does it
             * but something about this is irking me...
             * but that might just be me getting confused by the dlist api
             */
            dlist_setguid(missing, "GUID", guid);
        }
    }

    if (missing->head) {
        prot_printf(backupd_out, "* ");
        dlist_print(missing, 1, backupd_out);
        prot_printf(backupd_out, "\r\n");
    }

    dlist_free(&missing);

    return 0;
}

static void cmd_apply(struct dlist *dl)
{
    int r;

    if (strcmp(dl->name, "RESERVE") == 0) {
        r = cmd_apply_reserve(dl);
    }
    // FIXME support other commands
    else {
        r = IMAP_PROTOCOL_ERROR;
    }

    prot_printf(backupd_out, "%s\r\n", backupd_response(r));
}

static int backupd_print_mailbox(const struct backup_mailbox *mailbox,
                                 void *rock __attribute__((__unused__)))
{
    if (mailbox->dlist) {
        prot_puts(backupd_out, "* ");
        dlist_print(mailbox->dlist, /* printkeys */ 1, backupd_out);
    }

    return 0;
}

static const char *backupd_response(int r)
{
    switch (r) {
    case 0:
        return "OK Success";
    case IMAP_PROTOCOL_ERROR:
        return "NO IMAP_PROTOCOL_ERROR protocol error FIXME";
    default:
        return "NO Unknown error";
    }
}

static int cmd_get_mailbox(struct dlist *dl, int want_records)
{
    mbname_t *mbname = mbname_from_intname(dl->sval);
    if (!mbname) return IMAP_INTERNAL;

    struct open_backup *open = backupd_open_backup(mbname);
    mbname_free(&mbname);

    if (!open) return IMAP_INTERNAL;

    struct backup_mailbox *mb = backup_get_mailbox_by_name(open->backup, mbname,
                                                           want_records);
    if (!mb) return IMAP_MAILBOX_NONEXISTENT;

    backupd_print_mailbox(mb, NULL);
    backup_mailbox_free(&mb);

    return 0;
}

static void cmd_get(struct dlist *dl)
{
    int r = IMAP_PROTOCOL_ERROR;
    mbname_t *mbname = NULL;

    ucase(dl->name);

    if (strcmp(dl->name, "USER") == 0) {
        mbname = mbname_from_userid(dl->sval);
        struct open_backup *open = backupd_open_backup(mbname);
        if (!open) {
            r = IMAP_INTERNAL;
            goto done;
        }
        r = backup_mailbox_foreach(open->backup, 0, backupd_print_mailbox, NULL);
    }
    else if (strcmp(dl->name, "MAILBOXES") == 0) {
        struct dlist *di;
        for (di = dl->head; di; di = di->next) {
            r = cmd_get_mailbox(di, 0);
            if (r) goto done;
        }
    }
    else if (strcmp(dl->name, "FULLMAILBOX") == 0) {
        r = cmd_get_mailbox(dl, 1);
    }
    // FIXME implement other commands
    else {
        r = IMAP_PROTOCOL_ERROR;
    }

done:
    if (mbname) mbname_free(&mbname);

    prot_printf(backupd_out, "%s\r\n", backupd_response(r));
}
