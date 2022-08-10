/* sync_server.c -- Cyrus synchronization server
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
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#include <config.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sysexits.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#ifdef WITH_DAV
#include "dav_db.h"
#endif /* WITH_DAV */
#include "dlist.h"
#include "global.h"
#include "hash.h"
#include "imparse.h"
#include "imap_proxy.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "partlist.h"
#include "proc.h"
#include "prot.h"
#include "quota.h"
#include "seen.h"
#include "sync_log.h"
#include "telemetry.h"
#include "tls.h"
#include "user.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "message_guid.h"
#include "sync_support.h"
/*#include "cdb.h"*/

extern int optind;
extern char *optarg;
extern int opterr;

/* for config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

static sasl_ssf_t extprops_ssf = 0;

#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

static sasl_conn_t *sync_saslconn = NULL; /* the sasl connection context */

static char *sync_userid = 0;
static struct namespace sync_namespace;
static struct namespace *sync_namespacep = &sync_namespace;
static struct auth_state *sync_authstate = 0;
static int sync_userisadmin = 0;
static const char *sync_clienthost = "[local]";
static struct protstream *sync_out = NULL;
static struct protstream *sync_in = NULL;
static int sync_logfd = -1;
static int sync_starttls_done = 0;
static int sync_compress_done = 0;
static int sync_sieve_mailbox_enabled = 0;
static int sync_archive_enabled = 0;

static int opt_force = 0;

/* commands that have specific names */
static void cmdloop(void);
static void cmd_authenticate(char *mech, char *resp);
static void cmd_starttls(void);
static void cmd_restart(struct sync_reserve_list **reserve_listp,
                       int realloc);
static void cmd_compress(char *alg);

/* generic commands - in dlist format */
static void cmd_get(struct dlist *kl);
static void cmd_apply(struct dlist *kl,
                      struct sync_reserve_list *reserve_list);
static void cmd_restore(struct dlist *kin,
                        struct sync_reserve_list *reserve_list);

static void usage(void);
void shut_down(int code) __attribute__ ((noreturn));
void shut_down_via_signal(int code) __attribute__ ((noreturn));

extern int saslserver(sasl_conn_t *conn, const char *mech,
                      const char *init_resp, const char *resp_prefix,
                      const char *continuation, const char *empty_resp,
                      struct protstream *pin, struct protstream *pout,
                      int *sasl_result, char **success_data);

static struct saslprops_t saslprops = SASLPROPS_INITIALIZER;

/* the sasl proxy policy context */
static struct proxy_context sync_proxyctx = {
    0, 1, &sync_authstate, &sync_userisadmin, NULL
};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &sync_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static void sync_reset(void)
{
    proc_cleanup();

    if (sync_in) {
        prot_NONBLOCK(sync_in);
        prot_fill(sync_in);

        prot_free(sync_in);
    }

    if (sync_out) {
        prot_flush(sync_out);
        prot_free(sync_out);
    }

    sync_in = sync_out = NULL;

#ifdef HAVE_SSL
    if (tls_conn) {
        tls_reset_servertls(&tls_conn);
        tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    sync_clienthost = "[local]";
    if (sync_logfd != -1) {
        close(sync_logfd);
        sync_logfd = -1;
    }
    if (sync_userid != NULL) {
        free(sync_userid);
        sync_userid = NULL;
    }
    if (sync_authstate) {
        auth_freestate(sync_authstate);
        sync_authstate = NULL;
    }
    if (sync_saslconn) {
        sasl_dispose(&sync_saslconn);
        sync_saslconn = NULL;
    }
    sync_starttls_done = 0;
    sync_compress_done = 0;

    sync_sieve_mailbox_enabled = 0;
    sync_archive_enabled = 0;

    saslprops_reset(&saslprops);
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    int opt, r;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down_via_signal);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    while ((opt = getopt(argc, argv, "p:f")) != EOF) {
        switch(opt) {
        case 'p': /* external protection */
            extprops_ssf = atoi(optarg);
            break;
        case 'f':
            opt_force = 1;
            break;
        default:
            usage();
        }
    }

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(sync_namespacep, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
    }

    mboxevent_setnamespace(sync_namespacep);

    return 0;
}

/*
 * Issue the capability banner
 */
static void dobanner(void)
{
    const char *mechlist;
    int mechcount;

    if (!sync_userid) {
        if (sasl_listmech(sync_saslconn, NULL,
                          "* SASL ", " ", "\r\n",
                          &mechlist, NULL, &mechcount) == SASL_OK
            && mechcount > 0) {
            prot_printf(sync_out, "%s", mechlist);
        }

        if (tls_enabled() && !sync_starttls_done) {
            prot_printf(sync_out, "* STARTTLS\r\n");
        }

#ifdef HAVE_ZLIB
        if (!sync_compress_done && !sync_starttls_done) {
            prot_printf(sync_out, "* COMPRESS DEFLATE\r\n");
        }
#endif

        prot_printf(sync_out, "* SIEVE-MAILBOX\r\n");

        if (config_getswitch(IMAPOPT_ARCHIVE_ENABLED)) {
            prot_printf(sync_out, "* REPLICATION-ARCHIVE\r\n");
        }
    }

    prot_printf(sync_out,
                "* OK %s Cyrus sync server %s\r\n",
                config_servername, CYRUS_VERSION);

    prot_flush(sync_out);
}

/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    const char *localip, *remoteip;
    sasl_security_properties_t *secprops = NULL;
    int timeout;

    signals_poll();

    sync_in = prot_new(0, 0);
    sync_out = prot_new(1, 1);

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(sync_in, 1);
    prot_setisclient(sync_out, 1);

    /* Find out name of client host */
    sync_clienthost = get_clienthost(0, &localip, &remoteip);
    if (!strcmp(sync_clienthost, UNIX_SOCKET)) {
        /* we're not connected to an internet socket! */
        sync_userid = xstrdup(cyrus_user());
        sync_userisadmin = 1;
    }
    else {
        if (localip && remoteip) {
            buf_setcstr(&saslprops.ipremoteport, remoteip);
            buf_setcstr(&saslprops.iplocalport, localip);
        }

        /* other params should be filled in */
        if (sasl_server_new("csync", config_servername, NULL,
                            buf_cstringnull_ifempty(&saslprops.iplocalport),
                            buf_cstringnull_ifempty(&saslprops.ipremoteport),
                            NULL, 0, &sync_saslconn) != SASL_OK)
            fatal("SASL failed initializing: sasl_server_new()",EX_TEMPFAIL);

        /* will always return something valid */
        secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
        if (sasl_setprop(sync_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
            fatal("Failed to set SASL property", EX_TEMPFAIL);

        if (sasl_setprop(sync_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
            fatal("Failed to set SASL property", EX_TEMPFAIL);

        tcp_disable_nagle(1); /* XXX magic fd */
    }

    proc_register(config_ident, sync_clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getduration(IMAPOPT_SYNC_TIMEOUT, 's');
    if (timeout < 3) timeout = 3;
    prot_settimeout(sync_in, timeout);

    prot_setflushonread(sync_in, sync_out);

    sync_log_init();
    if (!config_getswitch(IMAPOPT_SYNC_LOG_CHAIN))
        sync_log_suppress();

    dobanner();

    cmdloop();

    /* EXIT executed */

    /* cleanup */
    sync_reset();

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

static void usage(void)
{
    prot_printf(sync_out, "* usage: sync_server [-C <alt_config>]\r\n");
    prot_flush(sync_out);
    exit(EX_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    in_shutdown = 1;

    libcyrus_run_delayed();

    proc_cleanup();

    seen_done();

    partlist_local_done();

    if (sync_in) {
        prot_NONBLOCK(sync_in);
        prot_fill(sync_in);
        prot_free(sync_in);
    }

    if (sync_out) {
        prot_flush(sync_out);
        prot_free(sync_out);
    }

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    saslprops_free(&saslprops);

    cyrus_done();

    exit(code);
}

void shut_down_via_signal(int code __attribute__((unused)))
{
    if (sync_out) {
        prot_puts(sync_out, "BYE shutting down\r\n");
    }

    shut_down(0);
}

EXPORTED void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        /* We were called recursively. Just give up */
        proc_cleanup();
        exit(recurse_code);
    }
    recurse_code = code;
    if (sync_out) {
        prot_printf(sync_out, "* Fatal error: %s\r\n", s);
        prot_flush(sync_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("csync", config_servername, NULL,
                          buf_cstringnull_ifempty(&saslprops.iplocalport),
                          buf_cstringnull_ifempty(&saslprops.ipremoteport),
                          NULL, 0, conn);
    if (ret != SASL_OK) return ret;

    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if (ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if (saslprops.ssf) {
        ret = saslprops_set_tls(&saslprops, *conn);
    } else {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }

    if (ret != SASL_OK) return ret;
    /* End TLS/SSL Info */

    return SASL_OK;
}

static void cmdloop(void)
{
    struct sync_reserve_list *reserve_list;
    static struct buf cmd;
    static struct buf arg1, arg2;
    int c;
    char *p;
    struct dlist *kl;

    syslog(LOG_DEBUG, "cmdloop(): startup");

    reserve_list = sync_reserve_list_create(SYNC_MESSAGE_LIST_HASH_SIZE);

    for (;;) {
        prot_flush(sync_out);

        libcyrus_run_delayed();

        /* Parse command name */
        if ((c = getword(sync_in, &cmd)) == EOF)
            break;

        if (!cmd.s[0]) {
            prot_printf(sync_out, "BAD Null command\r\n");
            eatline(sync_in, c);
            continue;
        }

        if (Uislower(cmd.s[0]))
            cmd.s[0] = toupper((unsigned char) cmd.s[0]);
        for (p = &cmd.s[1]; *p; p++) {
            if (Uisupper(*p)) *p = tolower((unsigned char) *p);
        }

        /* Must be an admin */
        if (sync_userid && !sync_userisadmin) goto noperm;

        switch (cmd.s[0]) {
        case 'A':
            if (!strcmp(cmd.s, "Authenticate")) {
                int haveinitresp = 0;
                if (c != ' ') goto missingargs;
                c = getword(sync_in, &arg1);
                if (!imparse_isatom(arg1.s)) {
                    prot_printf(sync_out, "BAD Invalid mechanism\r\n");
                    eatline(sync_in, c);
                    continue;
                }
                if (c == ' ') {
                    haveinitresp = 1;
                    c = getword(sync_in, &arg2);
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(sync_in);
                if (c != '\n') goto extraargs;

                if (sync_userid) {
                    prot_printf(sync_out, "BAD Already authenticated\r\n");
                    continue;
                }
                cmd_authenticate(arg1.s, haveinitresp ? arg2.s : NULL);
                continue;
            }
            if (!sync_userid) goto nologin;
            if (!strcmp(cmd.s, "Apply")) {
                kl = sync_parseline(sync_in, sync_archive_enabled);
                if (kl) {
                    cmd_apply(kl, reserve_list);
                    dlist_free(&kl);
                }
                else {
                    xsyslog(LOG_ERR, "IOERROR: received bad command",
                                     "command=<%s>", cmd.s);
                    prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Failed to parse APPLY line\r\n");
                }
                continue;
            }
            break;

        case 'C':
            if (!strcmp(cmd.s, "Compress")) {
                if (c != ' ') goto missingargs;
                c = getword(sync_in, &arg1);
                if (c == '\r') c = prot_getc(sync_in);
                if (c != '\n') goto extraargs;
                cmd_compress(arg1.s);
                continue;
            }
            break;

        case 'G':
            if (!sync_userid) goto nologin;
            if (!strcmp(cmd.s, "Get")) {
                kl = sync_parseline(sync_in, sync_archive_enabled);
                if (kl) {
                    cmd_get(kl);
                    dlist_free(&kl);
                }
                else {
                    xsyslog(LOG_ERR, "IOERROR: received bad command",
                                     "command=<%s>", cmd.s);
                    prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Failed to parse GET line\r\n");
                }
                continue;
            }
            break;

        case 'E':
            if (!strcmp(cmd.s, "Exit")) {
                if (c == '\r') c = prot_getc(sync_in);
                if (c != '\n') goto extraargs;
                prot_printf(sync_out, "OK Finished\r\n");
                prot_flush(sync_out);
                goto exit;
            }
            break;

        case 'N':
            if (!strcmp(cmd.s, "Noop")) {
                if (c == '\r') c = prot_getc(sync_in);
                if (c != '\n') goto extraargs;
                prot_printf(sync_out, "OK Noop completed\r\n");
                continue;
            }
            break;

        case 'R':
            if (!strcmp(cmd.s, "Restart")) {
                if (c == '\r') c = prot_getc(sync_in);
                if (c != '\n') goto extraargs;
                /* just clear the GUID cache */
                cmd_restart(&reserve_list, 1);
                prot_printf(sync_out, "OK Restarting\r\n");
                continue;
            }
            if (!sync_userid) goto nologin;
            if (!strcmp(cmd.s, "Restore")) {
                kl = sync_parseline(sync_in, sync_archive_enabled);
                if (kl) {
                    cmd_restore(kl, reserve_list);
                    dlist_free(&kl);
                }
                else {
                    xsyslog(LOG_ERR, "IOERROR: received bad command",
                                     "command=<%s>", cmd.s);
                    prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Failed to parse RESTORE line\r\n");
                }
                continue;
            }
            break;

        case 'S':
            if (!strcmp(cmd.s, "Starttls") && tls_enabled()) {
                if (c == '\r') c = prot_getc(sync_in);
                if (c != '\n') goto extraargs;

                /* XXX  discard any input pipelined after STARTTLS */
                prot_flush(sync_in);

                /* if we've already done SASL fail */
                if (sync_userid != NULL) {
                    prot_printf(sync_out,
                                "BAD Can't Starttls after authentication\r\n");
                    continue;
                }
                /* check if already did a successful tls */
                if (sync_starttls_done == 1) {
                    prot_printf(sync_out,
                                "BAD Already did a successful Starttls\r\n");
                    continue;
                }
                cmd_starttls();
                continue;
            }
            break;

        }

        xsyslog(LOG_ERR, "IOERROR: received bad command",
                         "command=<%s>", cmd.s);
        prot_printf(sync_out, "BAD IMAP_PROTOCOL_ERROR Unrecognized command\r\n");
        eatline(sync_in, c);
        continue;

    nologin:
        prot_printf(sync_out, "NO Please authenticate first\r\n");
        eatline(sync_in, c);
        continue;

    noperm:
        prot_printf(sync_out, "NO %s\r\n",
                    error_message(IMAP_PERMISSION_DENIED));
        eatline(sync_in, c);
        continue;

    missingargs:
        prot_printf(sync_out, "BAD Missing required argument to %s\r\n", cmd.s);
        eatline(sync_in, c);
        continue;

    extraargs:
        prot_printf(sync_out, "BAD Unexpected extra arguments to %s\r\n", cmd.s);
        eatline(sync_in, c);
        continue;
    }

 exit:
    cmd_restart(&reserve_list, 0);
}

static void cmd_authenticate(char *mech, char *resp)
{
    int r, sasl_result;
    sasl_ssf_t ssf;
    const char *ssfmsg = NULL;
    const void *val;
    int failedloginpause;

    if (sync_userid) {
        prot_printf(sync_out, "BAD Already authenticated\r\n");
        return;
    }

    r = saslserver(sync_saslconn, mech, resp, "", "+ ", "",
                   sync_in, sync_out, &sasl_result, NULL);

    if (r) {
        const char *errorstring = NULL;
        const char *userid = "-notset-";

        switch (r) {
        case IMAP_SASL_CANCEL:
            prot_printf(sync_out,
                        "BAD Client canceled authentication\r\n");
            break;
        case IMAP_SASL_PROTERR:
            errorstring = prot_error(sync_in);

            prot_printf(sync_out,
                        "NO Error reading client response: %s\r\n",
                        errorstring ? errorstring : "");
            break;
        default:
            /* failed authentication */
            errorstring = sasl_errstring(sasl_result, NULL, NULL);

            if (r != SASL_NOUSER)
                sasl_getprop(sync_saslconn, SASL_USERNAME, (const void **) &userid);

            syslog(LOG_NOTICE, "badlogin: %s %s (%s) [%s]",
                   sync_clienthost, mech, userid, sasl_errdetail(sync_saslconn));

            failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
            if (failedloginpause != 0) {
                sleep(failedloginpause);
            }

            if (errorstring) {
                prot_printf(sync_out, "NO %s\r\n", errorstring);
            } else {
                prot_printf(sync_out, "NO Error authenticating\r\n");
            }
        }

        reset_saslconn(&sync_saslconn);
        return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(sync_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
        prot_printf(sync_out, "NO weird SASL error %d SASL_USERNAME\r\n",
                    sasl_result);
        syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME",
               sasl_result);
        reset_saslconn(&sync_saslconn);
        return;
    }

    sync_userid = xstrdup((const char *) val);
    proc_register(config_ident, sync_clienthost, sync_userid, NULL, NULL);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", sync_clienthost, sync_userid,
           mech, sync_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(sync_saslconn, SASL_SSF, &val);
    ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (sync_starttls_done) {
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

    prot_printf(sync_out, "OK Success (%s)\r\n", ssfmsg);

    prot_setsasl(sync_in,  sync_saslconn);
    prot_setsasl(sync_out, sync_saslconn);

    /* Create telemetry log */
    sync_logfd = telemetry_log(sync_userid, sync_in, sync_out, 0);
}

#ifdef HAVE_SSL
static void cmd_starttls(void)
{
    int result;

    if (sync_starttls_done == 1) {
        prot_printf(sync_out, "NO %s\r\n",
                    "Already successfully executed STARTTLS");
        return;
    }

    result=tls_init_serverengine("csync",
                                 5,        /* depth to verify */
                                 1,        /* can client auth? */
                                 NULL);

    if (result == -1) {
        syslog(LOG_ERR, "error initializing TLS");
        prot_printf(sync_out, "NO %s\r\n", "Error initializing TLS");
        return;
    }

    prot_printf(sync_out, "OK %s\r\n", "Begin TLS negotiation now");
    /* must flush our buffers before starting tls */
    prot_flush(sync_out);

    result=tls_start_servertls(0, /* read */
                               1, /* write */
                               180, /* 3 minutes */
                               &saslprops,
                               &tls_conn);

    /* if error */
    if (result==-1) {
        prot_printf(sync_out, "NO Starttls failed\r\n");
        syslog(LOG_NOTICE, "STARTTLS failed: %s", sync_clienthost);
        return;
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(&saslprops, sync_saslconn);
    if (result != SASL_OK) {
        fatal("saslprops_set_tls() failed: cmd_starttls()", EX_TEMPFAIL);
    }

    /* tell the prot layer about our new layers */
    prot_settls(sync_in, tls_conn);
    prot_settls(sync_out, tls_conn);

    sync_starttls_done = 1;

    dobanner();
}
#else
static void cmd_starttls(void)
{
    fatal("cmd_starttls() called, but no OpenSSL", EX_SOFTWARE);
}
#endif /* HAVE_SSL */

#ifdef HAVE_ZLIB
static void cmd_compress(char *alg)
{
    if (sync_compress_done) {
        prot_printf(sync_out, "NO Compression already active: %s\r\n", alg);
        return;
    }
    if (strcasecmp(alg, "DEFLATE")) {
        prot_printf(sync_out, "NO Unknown compression algorithm: %s\r\n", alg);
        return;
    }
    if (ZLIB_VERSION[0] != zlibVersion()[0]) {
        prot_printf(sync_out, "NO Error initializing %s "
                    "(incompatible zlib version)\r\n", alg);
        return;
    }
    prot_printf(sync_out, "OK %s active\r\n", alg);
    prot_flush(sync_out);
    prot_setcompress(sync_in);
    prot_setcompress(sync_out);
    sync_compress_done = 1;
}
#else
static void cmd_compress(char *alg __attribute__((unused)))
{
    prot_printf(sync_out, "NO ZLIB not available\r\n");
}
#endif

/* ====================================================================== */

/* partition_list is simple linked list of names used by cmd_restart */

struct partition_list {
    struct partition_list *next;
    char *name;
};

static struct partition_list *
partition_list_add(char *name, struct partition_list *pl)
{
    struct partition_list *p;

    /* Is name already on list? */
    for (p=pl; p; p = p->next) {
        if (!strcmp(p->name, name))
            return(pl);
    }

    /* Add entry to start of list and return new list */
    p = xzmalloc(sizeof(struct partition_list));
    p->next = pl;
    p->name = xstrdup(name);

    return(p);
}

static void
partition_list_free(struct partition_list *current)
{
    while (current) {
        struct partition_list *next = current->next;

        free(current->name);
        free(current);

        current = next;
    }
}

static void cmd_restart(struct sync_reserve_list **reserve_listp, int re_alloc)
{
    struct sync_reserve *res;
    struct sync_reserve_list *l = *reserve_listp;
    struct sync_msgid *msg;
    int hash_size = l->hash_size;
    struct partition_list *p, *pl = NULL;

    for (res = l->head; res; res = res->next) {
        for (msg = res->list->head; msg; msg = msg->next) {
            if (!msg->fname) continue;
            pl = partition_list_add(res->part, pl);
            unlink(msg->fname);
        }
    }
    sync_reserve_list_free(reserve_listp);

    /* Remove all <partition>/sync./<pid> directories referred to above */
    for (p=pl; p ; p = p->next) {
        static char buf[MAX_MAILBOX_PATH];

        snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu",
                 config_partitiondir(p->name), (unsigned long)getpid());
        rmdir(buf);

        if (config_getswitch(IMAPOPT_ARCHIVE_ENABLED)) {
            /* and the archive partition too */
            snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu",
                    config_archivepartitiondir(p->name), (unsigned long)getpid());
            rmdir(buf);
        }
    }
    partition_list_free(pl);

    if (re_alloc)
        *reserve_listp = sync_reserve_list_create(hash_size);
    else
        *reserve_listp = NULL;
}

/******************************************************************************/

static void cmd_apply(struct dlist *kin, struct sync_reserve_list *reserve_list)
{
    struct sync_state sync_state = {
        sync_userid,
        sync_userisadmin,
        sync_authstate,
        &sync_namespace,
        sync_out,
        0 /* flags */
    };

    if (sync_sieve_mailbox_enabled) {
        sync_state.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }
    if (sync_archive_enabled) {
        sync_state.flags |= SYNC_FLAG_ARCHIVE;
    }

    const char *resp = sync_apply(kin, reserve_list, &sync_state);

    if (sync_state.flags & SYNC_FLAG_SIEVE_MAILBOX) {
        sync_sieve_mailbox_enabled = 1;
    }
    if (sync_state.flags & SYNC_FLAG_ARCHIVE) {
        sync_archive_enabled = 1;
    }

    sync_checkpoint(sync_in);
    prot_printf(sync_out, "%s\r\n", resp);
}

static void cmd_get(struct dlist *kin)
{
    struct sync_state sync_state = {
        sync_userid,
        sync_userisadmin,
        sync_authstate,
        &sync_namespace,
        sync_out,
        0 /* flags */
    };

    if (sync_sieve_mailbox_enabled) {
        sync_state.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }
    if (sync_archive_enabled) {
        sync_state.flags |= SYNC_FLAG_ARCHIVE;
    }

    const char *resp = sync_get(kin, &sync_state);
    prot_printf(sync_out, "%s\r\n", resp);
}

static void cmd_restore(struct dlist *kin, struct sync_reserve_list *reserve_list)
{
    struct sync_state sync_state = {
        sync_userid,
        sync_userisadmin,
        sync_authstate,
        &sync_namespace,
        sync_out,
        0 /* flags */
    };

    if (sync_sieve_mailbox_enabled) {
        sync_state.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }
    if (sync_archive_enabled) {
        sync_state.flags |= SYNC_FLAG_ARCHIVE;
    }

    const char *resp = sync_restore(kin, reserve_list, &sync_state);
    sync_checkpoint(sync_in);
    prot_printf(sync_out, "%s\r\n", resp);
}
