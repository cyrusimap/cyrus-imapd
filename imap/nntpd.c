/* nntpd.c -- NNTP server
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

/*
 * TODO:
 *
 * - add sender and PGP verification code for control messages
 * - figure out what to do with control messages when proxying
 */


#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
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
#include <arpa/inet.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#include "backend.h"
#include "duplicate.h"
#include "global.h"
#include "hash.h"
#include "idle.h"
#include "index.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "mkgmtime.h"
#include "mupdate-client.h"
#include "partlist.h"
#include "proc.h"
#include "prot.h"
#include "proxy.h"
#include "retry.h"
#include "times.h"
#include "smtpclient.h"
#include "spool.h"
#include "sync_support.h"
#include "telemetry.h"
#include "tls.h"
#include "userdeny.h"
#include "util.h"
#include "version.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/nntp_err.h"

extern int optind;
extern char *optarg;
extern int opterr;

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
ptrarray_t backend_cached = PTRARRAY_INITIALIZER;

#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

static sasl_conn_t *nntp_saslconn; /* the sasl connection context */

static int nntp_timeout;
static char newsprefix[100] = "";
static struct wildmat *newsgroups = NULL;
static char *nntp_userid = 0, *newsmaster;
static struct auth_state *nntp_authstate = 0, *newsmaster_authstate;
static struct index_state *group_state;
static const char *nntp_clienthost = "[local]";
static struct protstream *nntp_out = NULL;
static struct protstream *nntp_in = NULL;
static struct protgroup *protin = NULL;
static int nntp_logfd = -1;
static unsigned nntp_exists = 0;
static unsigned nntp_current = 0;
static unsigned did_capabilities = 0;
static int allowanonymous = 0;
static int singleinstance = 1;  /* attempt single instance store */

static struct stagemsg *stage = NULL;

/* Bitmasks for NNTP modes */
enum {
    MODE_READ = (1<<0),
    MODE_FEED = (1<<1)
};

static unsigned nntp_capa = MODE_READ | MODE_FEED; /* general-purpose */

static sasl_ssf_t extprops_ssf = 0;
static int nntps = 0;
static int nntp_starttls_done = 0;
static int nntp_tls_required = 0;
static void *nntp_tls_comp = NULL; /* TLS compression method, if any */
static int nntp_compress_done = 0; /* have we done a successful compress? */

/* the sasl proxy policy context */
static struct proxy_context nntp_proxyctx = {
    0, 1, &nntp_authstate, NULL, NULL
};

/* for config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/*
 * values for article parts
 * these correspond to the last digit of the response code
 */
enum {
    ARTICLE_ALL  = 0,
    ARTICLE_HEAD = 1,
    ARTICLE_BODY = 2,
    ARTICLE_STAT = 3
};

/* values for post modes */
enum {
    POST_POST     = 0,
    POST_IHAVE    = 1,
    POST_CHECK    = 2,
    POST_TAKETHIS = 3
};

/* response codes for each stage of posting */
static struct {
    int ok, cont, no, fail;
} post_codes[] = { { 240, 340, 440, 441 },
                   { 235, 335, 435, 436 },
                   {  -1, 238, 438,  -1 },
                   { 239,  -1,  -1, 439 } };

static void cmdloop(void);
static int open_group(const char *name, int has_prefix,
                      struct backend **ret, int *postable);
static int getuserpass(struct protstream *in, struct buf *buf);
static int parserange(char *str, uint32_t *uid, uint32_t *last,
                      char **msgid, struct backend **be);
static time_t parse_datetime(char *datestr, char *timestr, char *gmt);
static void cmd_article(int part, char *msgid, unsigned long uid);
static void cmd_authinfo_user(char *user);
static void cmd_authinfo_pass(char *pass);
static void cmd_authinfo_sasl(char *cmd, char *mech, char *resp);
static void cmd_capabilities(char *keyword);
static void cmd_hdr(char *cmd, char *hdr, char *pat, char *msgid,
                    unsigned long uid, unsigned long last);
static void cmd_help(void);
static void cmd_list(char *arg1, char *arg2);
static void cmd_mode(char *arg);
static void cmd_newgroups(time_t tstamp);
static void cmd_newnews(char *wild, time_t tstamp);
static void cmd_over(char *msgid, unsigned long uid, unsigned long last);
static void cmd_post(char *msgid, int mode);
static void cmd_starttls(int nntps);
#ifdef HAVE_ZLIB
static void cmd_compress(char *alg);
#endif
static void usage(void);
void shut_down(int code) __attribute__ ((noreturn));

extern int saslserver(sasl_conn_t *conn, const char *mech,
                      const char *init_resp, const char *resp_prefix,
                      const char *continuation, const char *empty_resp,
                      struct protstream *pin, struct protstream *pout,
                      int *sasl_result, char **success_data);

static struct saslprops_t saslprops = SASLPROPS_INITIALIZER;

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &nntp_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static char *nntp_parsesuccess(char *str, const char **status)
{
    char *success = NULL;

    if (!strncmp(str, "283 ", 4)) {
        success = str+4;
    }

    if (status) *status = NULL;
    return success;
}

static struct protocol_t nntp_protocol =
{ "nntp", "nntp", TYPE_STD,
  { { { 0, "20" },
      { "CAPABILITIES", NULL, ".", NULL,
        CAPAF_ONE_PER_LINE,
        { { "SASL", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { NULL, 0 } } },
      { "STARTTLS", "382", "580", 0 },
      { "AUTHINFO SASL", 512, 0, "28", "48", "383 ", "*", &nntp_parsesuccess, 0 },
      { NULL, NULL, NULL },
      { "DATE", NULL, "111" },
      { "QUIT", NULL, "205" } } }
};

static int read_response(struct backend *s, int force_notfatal, char **result)
{
    static char buf[2048];

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    if (!prot_fgets(buf, sizeof(buf), s->in)) {
        /* uh oh */
        if (s == backend_current && !force_notfatal)
            fatal("Lost connection to selected backend", EX_UNAVAILABLE);
        proxy_downserver(s);
        return IMAP_SERVER_UNAVAILABLE;
    }

    *result = buf;
    return 0;
}

static int pipe_to_end_of_response(struct backend *s, int force_notfatal)
{
    char buf[2048];

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    do {
        if (!prot_fgets(buf, sizeof(buf), s->in)) {
            /* uh oh */
            if (s == backend_current && !force_notfatal)
                fatal("Lost connection to selected backend", EX_UNAVAILABLE);
            proxy_downserver(s);
            return IMAP_SERVER_UNAVAILABLE;
        }

        prot_printf(nntp_out, "%s", buf);
    } while (strcmp(buf, ".\r\n"));

    return 0;
}
/* end proxy support functions */

static void nntp_reset(void)
{
    int i;

    proc_cleanup();

    /* close local mailbox */
    if (group_state)
        index_close(&group_state);

    /* close backend connections */
    for (i = 0; i < ptrarray_size(&backend_cached); i++) {
        struct backend *be = ptrarray_nth(&backend_cached, i);
        proxy_downserver(be);
        free(be->context);
        free(be);
    }
    ptrarray_fini(&backend_cached);
    backend_current = NULL;

    if (nntp_in) {
        prot_NONBLOCK(nntp_in);
        prot_fill(nntp_in);

        prot_free(nntp_in);
    }

    if (nntp_out) {
        prot_flush(nntp_out);
        prot_free(nntp_out);
    }

    nntp_in = nntp_out = NULL;

    if (protin) protgroup_reset(protin);

#ifdef HAVE_SSL
    if (tls_conn) {
        tls_reset_servertls(&tls_conn);
        tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    nntp_clienthost = "[local]";
    if (nntp_logfd != -1) {
        close(nntp_logfd);
        nntp_logfd = -1;
    }
    if (nntp_userid != NULL) {
        free(nntp_userid);
        nntp_userid = NULL;
    }
    if (nntp_authstate) {
        auth_freestate(nntp_authstate);
        nntp_authstate = NULL;
    }
    if (nntp_saslconn) {
        sasl_dispose(&nntp_saslconn);
        nntp_saslconn = NULL;
    }
    nntp_compress_done = 0;
    nntp_tls_comp = NULL;
    nntp_starttls_done = 0;

    saslprops_reset(&saslprops);

    nntp_exists = 0;
    nntp_current = 0;
    did_capabilities = 0;
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    int opt;
    const char *prefix;

    initialize_nntp_error_table();

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    if ((prefix = config_getstring(IMAPOPT_NEWSPREFIX)))
        snprintf(newsprefix, sizeof(newsprefix), "%s.", prefix);

    newsgroups = split_wildmats((char *) config_getstring(IMAPOPT_NEWSGROUPS),
                                config_getstring(IMAPOPT_NEWSPREFIX));

    /* initialize duplicate delivery database */
    if (duplicate_init(NULL) != 0) {
        syslog(LOG_ERR,
               "unable to init duplicate delivery database");
        fatal("unable to init duplicate delivery database", EX_SOFTWARE);
    }

    /* setup for sending IMAP IDLE notifications */
    idle_init();

    while ((opt = getopt(argc, argv, "srfp:")) != EOF) {
        switch(opt) {
        case 's': /* nntps (do starttls right away) */
            nntps = 1;
            if (!tls_enabled()) {
                syslog(LOG_ERR, "nntps: required OpenSSL options not present");
                fatal("nntps: required OpenSSL options not present",
                      EX_CONFIG);
            }
            break;

        case 'r': /* enter reader-only mode */
            nntp_capa = MODE_READ;
            break;

        case 'f': /* enter feeder-only mode */
            nntp_capa = MODE_FEED;
            break;

        case 'p': /* external protection */
            extprops_ssf = atoi(optarg);
            break;

        default:
            usage();
        }
    }

    newsmaster = (char *) config_getstring(IMAPOPT_NEWSMASTER);
    newsmaster_authstate = auth_newstate(newsmaster);

    singleinstance = config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

    /* Create a protgroup for input from the client and selected backend */
    protin = protgroup_new(2);

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    const char *localip, *remoteip;
    sasl_security_properties_t *secprops=NULL;
    int shutdown;
    char unavail[1024];

    signals_poll();

    nntp_in = prot_new(0, 0);
    nntp_out = prot_new(1, 1);
    protgroup_insert(protin, nntp_in);

    /* Find out name of client host */
    nntp_clienthost = get_clienthost(0, &localip, &remoteip);

    if (localip && remoteip) {
        buf_setcstr(&saslprops.ipremoteport, remoteip);
        buf_setcstr(&saslprops.iplocalport, localip);
    }

    /* other params should be filled in */
    if (sasl_server_new("nntp", config_servername, NULL,
                        buf_cstringnull_ifempty(&saslprops.iplocalport),
                        buf_cstringnull_ifempty(&saslprops.ipremoteport),
                        NULL, SASL_SUCCESS_DATA, &nntp_saslconn) != SASL_OK)
        fatal("SASL failed initializing: sasl_server_new()",EX_TEMPFAIL);

    /* will always return something valid */
    secprops = mysasl_secprops(0);
    sasl_setprop(nntp_saslconn, SASL_SEC_PROPS, secprops);
    sasl_setprop(nntp_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf);

    if (remoteip) {
        char hbuf[NI_MAXHOST], *p;

        /* Create pre-authentication telemetry log based on client IP */
        strlcpy(hbuf, remoteip, NI_MAXHOST);
        if ((p = strchr(hbuf, ';'))) *p = '\0';
        nntp_logfd = telemetry_log(hbuf, nntp_in, nntp_out, 0);
    }

    nntp_tls_required = config_getswitch(IMAPOPT_TLS_REQUIRED);

    /* Set inactivity timer */
    nntp_timeout = config_getduration(IMAPOPT_NNTPTIMEOUT, 'm');
    if (nntp_timeout < 3 * 60) nntp_timeout = 3 * 60;
    prot_settimeout(nntp_in, nntp_timeout);
    prot_setflushonread(nntp_in, nntp_out);

    /* we were connected on nntps port so we should do
       TLS negotiation immediatly */
    if (nntps == 1) cmd_starttls(1);

    if ((shutdown = shutdown_file(unavail, sizeof(unavail)))) {
        prot_printf(nntp_out, "%u", 400);
    } else {
        prot_printf(nntp_out, "%u", (nntp_capa & MODE_READ) ? 200 : 201);
    }
    if (config_serverinfo) prot_printf(nntp_out, " %s", config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        prot_printf(nntp_out, " Cyrus NNTP %s", CYRUS_VERSION);
    }
    if (shutdown) {
        prot_printf(nntp_out, "server unavailable, %s\r\n", unavail);
        shut_down(0);
    }
    else {
        prot_printf(nntp_out, " server ready, posting %s\r\n",
                    (nntp_capa & MODE_READ) ? "allowed" : "prohibited");
    }

    cmdloop();

    /* QUIT executed */

    /* cleanup */
    nntp_reset();

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

static void usage(void)
{
    prot_printf(nntp_out, "503 usage: nntpd [-C <alt_config>] [-s]\r\n");
    prot_flush(nntp_out);
    exit(EX_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    int i;

    in_shutdown = 1;

    libcyrus_run_delayed();

    proc_cleanup();

    /* close local mailbox */
    if (group_state)
        index_close(&group_state);

    /* close backend connections */
    for (i = 0; i < ptrarray_size(&backend_cached); i++) {
        struct backend *be = ptrarray_nth(&backend_cached, i);
        proxy_downserver(be);
        free(be->context);
        free(be);
    }
    ptrarray_fini(&backend_cached);

    duplicate_done();

    idle_done();

    partlist_local_done();

    if (nntp_in) {
        prot_NONBLOCK(nntp_in);
        prot_fill(nntp_in);
        prot_free(nntp_in);
    }

    if (nntp_out) {
        prot_flush(nntp_out);
        prot_free(nntp_out);
    }

    if (protin) protgroup_free(protin);

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    if (newsgroups) free_wildmats(newsgroups);
    auth_freestate(newsmaster_authstate);

    saslprops_free(&saslprops);

    cyrus_done();

    exit(code);
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
    if (nntp_out) {
        prot_printf(nntp_out, "400 Fatal error: %s\r\n", s);
        prot_flush(nntp_out);
    }
    if (stage) append_removestage(stage);
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
    ret = sasl_server_new("nntp", config_servername, NULL,
                          buf_cstringnull_ifempty(&saslprops.iplocalport),
                          buf_cstringnull_ifempty(&saslprops.ipremoteport),
                          NULL, SASL_SUCCESS_DATA, conn);
    if(ret != SASL_OK) return ret;

    secprops = mysasl_secprops(0);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
        ret = saslprops_set_tls(&saslprops, *conn);
    } else {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }

    if(ret != SASL_OK) return ret;
    /* End TLS/SSL Info */

    return SASL_OK;
}

/*
 * Checks to make sure that the given mailbox is actually something
 * that we're serving up as a newsgroup.  Returns 1 if yes, 0 if no.
 */
static int is_newsgroup(const char *mbox)
{
    struct wildmat *wild;

    /* don't use personal mailboxes */
    if (!mbox || !*mbox ||
        (!strncasecmp(mbox, "INBOX", 5) && (!mbox[5] || mbox[5] == '.')) ||
        !strncmp(mbox, "user.", 5) ||
        strncmp(mbox, newsprefix, strlen(newsprefix))) return 0;

    /* check shared mailboxes against the 'newsgroups' wildmat */
    wild = newsgroups;
    while (wild->pat && wildmat(mbox, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, don't use it */
    if (!wild->pat || wild->not) return 0;

    /* otherwise, its usable */
    return 1;
}


/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    int c, r = 0, mode;
    static struct buf cmd, arg1, arg2, arg3, arg4;
    char *p, *result, buf[1024];
    const char *err;
    uint32_t uid, last;
    struct backend *be;
    char curgroup[MAX_MAILBOX_BUFFER] = "";

    allowanonymous = config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN);

    for (;;) {
        /* Flush any buffered output */
        prot_flush(nntp_out);
        if (backend_current) prot_flush(backend_current->out);

        /* Check for shutdown file */
        if (shutdown_file(buf, sizeof(buf)) ||
            (nntp_userid &&
             userdeny(nntp_userid, config_ident, buf, sizeof(buf)))) {
            prot_printf(nntp_out, "400 %s\r\n", buf);
            shut_down(0);
        }

        signals_poll();

        proc_register(config_ident, nntp_clienthost, nntp_userid, index_mboxname(group_state), NULL);

        libcyrus_run_delayed();

        if (!proxy_check_input(protin, nntp_in, nntp_out,
                               backend_current ? backend_current->in : NULL,
                               NULL, 0)) {
            /* No input from client */
            continue;
        }

        if (group_state &&
            config_getswitch(IMAPOPT_DISCONNECT_ON_VANISHED_MAILBOX)) {
            if (group_state->mailbox->i.options & OPT_MAILBOX_DELETED) {
                /* Mailbox has been (re)moved */
                syslog(LOG_WARNING,
                       "Newsgroup %s has been (re)moved out from under client",
                       group_state->mboxname);
                prot_printf(nntp_out,
                            "400 Newsgroup has been (re)moved\r\n");
                shut_down(0);
            }
        }

        /* Parse command name */
        c = getword(nntp_in, &cmd);
        if (c == EOF) {
            if ((err = prot_error(nntp_in)) != NULL
                 && strcmp(err, PROT_EOF_STRING)) {
                syslog(LOG_WARNING, "%s, closing connection", err);
                prot_printf(nntp_out, "400 %s\r\n", err);
            }
            return;
        }
        if (!cmd.s[0]) {
            prot_printf(nntp_out, "501 Empty command\r\n");
            eatline(nntp_in, c);
            continue;
        }
        if (Uislower(cmd.s[0]))
            cmd.s[0] = toupper((unsigned char) cmd.s[0]);
        for (p = &cmd.s[1]; *p; p++) {
            if (Uisupper(*p)) *p = tolower((unsigned char) *p);
        }

        proc_register(config_ident, nntp_clienthost, nntp_userid, index_mboxname(group_state), cmd.s);

        /* Ihave/Takethis only allowed for feeders */
        if (!(nntp_capa & MODE_FEED) &&
            strchr("IT", cmd.s[0])) goto noperm;

        /* Body/Date/Group/Newgroups/Newnews/Next/Over/Post/Xhdr/Xover/Xpat
           only allowed for readers */
        if (!(nntp_capa & MODE_READ) &&
            strchr("BDGNOPX", cmd.s[0])) goto noperm;

        /* Only Authinfo/Capabilities/Check/Head/Help/Ihave/List Active/
           Mode/Quit/Starttls/Stat/Takethis allowed when not logged in */
        if (!nntp_authstate && !allowanonymous &&
            !strchr("ACHILMQST", cmd.s[0])) goto nologin;

        /* In case a [LIST]GROUP fails or
           a retrieval by msgid makes us switch groups */
        strcpy(curgroup, group_state ? group_state->mboxname : "");

        switch (cmd.s[0]) {
        case 'A':
            if (!strcmp(cmd.s, "Authinfo")) {
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* subcommand */
                if (c == EOF) goto missingargs;

                lcase(arg1.s);

                if (!strcmp(arg1.s, "user") || !strcmp(arg1.s, "pass")) {
                    if (c != ' ') goto missingargs;
                    c = getuserpass(nntp_in, &arg2); /* user/pass */
                    if (c == EOF) goto missingargs;

                    if (c == '\r') c = prot_getc(nntp_in);
                    if (c != '\n') goto extraargs;

                    if (arg1.s[0] == 'u')
                        cmd_authinfo_user(arg2.s);
                    else
                        cmd_authinfo_pass(arg2.s);
                }
                else if (!strcmp(arg1.s, "sasl") || !strcmp(arg1.s, "generic")) {
                    arg2.len = arg3.len = 0;

                    /* mech name required for SASL but not GENERIC */
                    if ((arg1.s[0] == 's') && (c != ' ')) goto missingargs;

                    if (c == ' ') {
                        c = getword(nntp_in, &arg2); /* mech name */
                        if (c == EOF) goto missingargs;

                        if (c == ' ') {
                            c = getword(nntp_in, &arg3); /* init response */
                            if (c == EOF) goto missingargs;
                        }
                    }

                    if (c == '\r') c = prot_getc(nntp_in);
                    if (c != '\n') goto extraargs;

                    cmd_authinfo_sasl(arg1.s, arg2.len ? arg2.s : NULL,
                                      arg3.len ? arg3.s : NULL);
                }
                else
                    prot_printf(nntp_out,
                                "501 Unrecognized AUTHINFO command\r\n");
            }
            else if (!(nntp_capa & MODE_READ)) goto noperm;
            else if (!nntp_authstate && !allowanonymous) goto nologin;
            else if (!strcmp(cmd.s, "Article")) {
                char *msgid;

                mode = ARTICLE_ALL;

              article:
                if (arg1.s) *arg1.s = 0;

                if (c == ' ') {
                    c = getword(nntp_in, &arg1); /* number/msgid (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if (parserange(arg1.s, &uid, NULL, &msgid, &be) != -1) {
                    if (be) {
                        if (arg1.s && *arg1.s)
                            prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);
                        else
                            prot_printf(be->out, "%s\r\n", cmd.s);

                        if (be != backend_current) {
                            r = read_response(be, 0, &result);
                            if (r) goto noopengroup;

                            prot_printf(nntp_out, "%s", result);
                            if (!strncmp(result, "22", 2) &&
                                mode != ARTICLE_STAT) {
                                pipe_to_end_of_response(be, 0);
                            }
                        }
                    }
                    else
                        cmd_article(mode, msgid, uid);
                }

                if (msgid) goto prevgroup;
            }
            else goto badcmd;
            break;

        case 'B':
            if (!strcmp(cmd.s, "Body")) {
                mode = ARTICLE_BODY;
                goto article;
            }
            else goto badcmd;
            break;

        case 'C':
            if (!strcmp(cmd.s, "Capabilities")) {
                arg1.len = 0;

                if (c == ' ') {
                    c = getword(nntp_in, &arg1); /* keyword (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_capabilities(arg1.s);
            }
#ifdef HAVE_ZLIB
            else if (!strcmp(cmd.s, "Compress")) {
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1);
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_compress(arg1.s);
            }
#endif /* HAVE_ZLIB */
            else if (!(nntp_capa & MODE_FEED)) goto noperm;
            else if (!strcmp(cmd.s, "Check")) {
                mode = POST_CHECK;
                goto ihave;
            }
            else goto badcmd;
            break;

        case 'D':
            if (!strcmp(cmd.s, "Date")) {
                time_t now = time(NULL);
                struct tm *my_tm = gmtime(&now);
                char buf[15];

                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", my_tm);
                prot_printf(nntp_out, "111 %s\r\n", buf);
            }
            else goto badcmd;
            break;

        case 'G':
            if (!strcmp(cmd.s, "Group")) {
                arg2.len = 0; /* GROUP command (no range) */

              group:
#define LISTGROUP (arg2.len)

                if (!LISTGROUP && c != ' ') goto missingargs;
                if (c == ' ') {
                    c = getword(nntp_in, &arg1); /* group */
                    if (c == EOF) goto missingargs;
                }
                if (LISTGROUP && c == ' ') {
                    c = getword(nntp_in, &arg2); /* range (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                be = backend_current;
                if (arg1.len &&
                    (r = open_group(arg1.s, 0, &be, NULL))) goto nogroup;
                else if (be) {
                    prot_printf(be->out, "%s", cmd.s);
                    if (arg1.len) {
                        prot_printf(be->out, " %s", arg1.s);
                        if (LISTGROUP) prot_printf(be->out, " %s", arg2.s);
                    }
                    prot_printf(be->out, "\r\n");

                    r = read_response(be, 0, &result);
                    if (r) goto nogroup;

                    prot_printf(nntp_out, "%s", result);

                    if (!strncmp(result, "211", 3)) {
                        if (LISTGROUP) pipe_to_end_of_response(be, 0);

                        if (backend_current && backend_current != be) {
                            /* remove backend_current from the protgroup */
                            protgroup_delete(protin, backend_current->in);
                        }
                        backend_current = be;

                        /* add backend_current to the protgroup */
                        protgroup_insert(protin, backend_current->in);
                    }
                }
                else if (!group_state) goto noopengroup;
                else if (LISTGROUP &&
                         parserange(arg2.s, &uid, &last, NULL, NULL) != 0) {
                    /* parserange() will handle error code -- do nothing */
                }
                else {
                    if (backend_current) {
                        /* remove backend_current from the protgroup */
                        protgroup_delete(protin, backend_current->in);
                    }
                    backend_current = NULL;

                    nntp_exists = group_state->exists;
                    nntp_current = nntp_exists > 0;

                    prot_printf(nntp_out, "211 %u %lu %lu %s\r\n",
                                nntp_exists,
                                nntp_exists ? index_getuid(group_state, 1) :
                                group_state->last_uid+1,
                                nntp_exists ? index_getuid(group_state, nntp_exists) :
                                group_state->last_uid,
                                group_state->mboxname + strlen(newsprefix));

                    if (LISTGROUP) {
                        int msgno, last_msgno;

                        msgno = index_finduid(group_state, uid);
                        if (!msgno || index_getuid(group_state, msgno) != uid) {
                            msgno++;
                        }
                        last_msgno = index_finduid(group_state, last);

                        for (; msgno <= last_msgno; msgno++) {
                            prot_printf(nntp_out, "%u\r\n",
                                        index_getuid(group_state, msgno));
                        }
                        prot_printf(nntp_out, ".\r\n");
                    }
                }
#undef LISTGROUP
            }
            else goto badcmd;
            break;

        case 'H':
            if (!strcmp(cmd.s, "Head")) {
                mode = ARTICLE_HEAD;
                goto article;
            }
            else if (!strcmp(cmd.s, "Help")) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_help();
            }
            else if (!(nntp_capa & MODE_READ)) goto noperm;
            else if (!nntp_authstate && !allowanonymous) goto nologin;
            else if (!strcmp(cmd.s, "Hdr")) {
                char *msgid;

              hdr:
                if (arg2.s) *arg2.s = 0;

                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* header */
                if (c == EOF) goto missingargs;
                if (c == ' ') {
                    c = getword(nntp_in, &arg2); /* range (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if (parserange(arg2.s, &uid, &last, &msgid, &be) != -1) {
                    if (be) {
                        if (arg2.s && *arg2.s)
                            prot_printf(be->out, "%s %s %s\r\n",
                                        cmd.s, arg1.s, arg2.s);
                        else
                            prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);

                        if (be != backend_current) {
                            r = read_response(be, 0, &result);
                            if (r) goto noopengroup;

                            prot_printf(nntp_out, "%s", result);
                            if (!strncmp(result, "22", 2)) { /* 221 or 225 */
                                pipe_to_end_of_response(be, 0);
                            }
                        }
                    }
                    else
                        cmd_hdr(cmd.s, arg1.s, NULL, msgid, uid, last);
                }

                if (msgid) goto prevgroup;
            }
            else goto badcmd;
            break;

        case 'I':
            if (!strcmp(cmd.s, "Ihave")) {
                mode = POST_IHAVE;

              ihave:
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* msgid */
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_post(arg1.s, mode);
            }
            else goto badcmd;
            break;

        case 'L':
            if (!strcmp(cmd.s, "List")) {
                arg1.len = arg2.len = 0;
                if (c == ' ') {
                    c = getword(nntp_in, &arg1); /* subcommand (optional) */
                    if (c == EOF) goto missingargs;
                    if (c == ' ') {
                        c = getword(nntp_in, &arg2); /* argument (optional) */
                        if (c == EOF) goto missingargs;
                    }
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_list(arg1.len ? arg1.s : NULL, arg2.len ? arg2.s : NULL);

                goto prevgroup;  /* In case we did LIST [ACTIVE] */
            }
            else if (!(nntp_capa & MODE_READ)) goto noperm;
            else if (!nntp_authstate && !allowanonymous) goto nologin;
            else if (!strcmp(cmd.s, "Last")) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if (backend_current) {
                    prot_printf(backend_current->out, "LAST\r\n");
                }
                else if (!group_state) goto noopengroup;
                else if (!nntp_current) goto nocurrent;
                else if (nntp_current == 1) {
                    prot_printf(nntp_out,
                                "422 No previous article in this group\r\n");
                }
                else {
                    char *msgid = index_get_msgid(group_state, --nntp_current);

                    prot_printf(nntp_out, "223 %u %s\r\n",
                                index_getuid(group_state, nntp_current),
                                msgid ? msgid : "<0>");

                    if (msgid) free(msgid);
                }
            }
            else if (!strcmp(cmd.s, "Listgroup")) {
                arg1.len = 0;              /* group is optional */
                buf_setcstr(&arg2, "1-");  /* default range is all */
                buf_cstring(&arg2);        /* appends a '\0' */
                goto group;
            }
            else goto badcmd;
            break;

        case 'M':
            if (!strcmp(cmd.s, "Mode")) {
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* mode */
                if (c == EOF) goto missingargs;
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_mode(arg1.s);
            }
            else goto badcmd;
            break;

        case 'N':
            if (!strcmp(cmd.s, "Newgroups")) {
                time_t tstamp;

                arg3.len = 0;
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* date */
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg2); /* time */
                if (c == EOF) goto missingargs;
                if (c == ' ') {
                    c = getword(nntp_in, &arg3); /* "GMT" (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if ((tstamp = parse_datetime(arg1.s, arg2.s,
                                             arg3.len ? arg3.s : NULL)) < 0)
                    goto baddatetime;

                cmd_newgroups(tstamp);
            }
            else if (!strcmp(cmd.s, "Newnews")) {
                time_t tstamp;

                if (!config_getswitch(IMAPOPT_ALLOWNEWNEWS))
                    goto cmddisabled;

                arg4.len = 0;
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* wildmat */
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg2); /* date */
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg3); /* time */
                if (c == EOF) goto missingargs;
                if (c == ' ') {
                    c = getword(nntp_in, &arg4); /* "GMT" (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if ((tstamp = parse_datetime(arg2.s, arg3.s,
                                             arg4.len ? arg4.s : NULL)) < 0)
                    goto baddatetime;

                cmd_newnews(arg1.s, tstamp);
            }
            else if (!strcmp(cmd.s, "Next")) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if (backend_current) {
                    prot_printf(backend_current->out, "NEXT\r\n");
                }
                else if (!group_state) goto noopengroup;
                else if (!nntp_current) goto nocurrent;
                else if (nntp_current == nntp_exists) {
                    prot_printf(nntp_out,
                                "421 No next article in this group\r\n");
                }
                else {
                    char *msgid = index_get_msgid(group_state, ++nntp_current);

                    prot_printf(nntp_out, "223 %u %s\r\n",
                                index_getuid(group_state, nntp_current),
                                msgid ? msgid : "<0>");

                    if (msgid) free(msgid);
                }
            }
            else goto badcmd;
            break;

        case 'O':
            if (!strcmp(cmd.s, "Over")) {
                char *msgid;

              over:
                if (arg1.s) *arg1.s = 0;

                if (c == ' ') {
                    c = getword(nntp_in, &arg1); /* range/msgid (optional) */
                    if (c == EOF) goto missingargs;
                }
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                msgid = NULL;
                if (parserange(arg1.s, &uid, &last,
                               /* XOVER doesn't accept message-id */
                               (cmd.s[0] == 'X' ? NULL : &msgid), &be) != -1) {
                    if (be) {
                        if (arg1.s && *arg1.s)
                            prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);
                        else
                            prot_printf(be->out, "%s\r\n", cmd.s);

                        if (be != backend_current) {
                            r = read_response(be, 0, &result);
                            if (r) goto noopengroup;

                            prot_printf(nntp_out, "%s", result);
                            if (!strncmp(result, "224", 3)) {
                                pipe_to_end_of_response(be, 0);
                            }
                        }
                    }
                    else
                        cmd_over(msgid, uid, last);
                }

                if (msgid) goto prevgroup;
            }
            else goto badcmd;
            break;

        case 'P':
            if (!strcmp(cmd.s, "Post")) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                cmd_post(NULL, POST_POST);
            }
            else goto badcmd;
            break;

        case 'Q':
            if (!strcmp(cmd.s, "Quit")) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                prot_printf(nntp_out, "205 Connection closing\r\n");
                return;
            }
            else goto badcmd;
            break;

        case 'S':
            if (!strcmp(cmd.s, "Starttls") && tls_enabled()) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                /* XXX  discard any input pipelined after STARTTLS */
                prot_flush(nntp_in);

                cmd_starttls(0);
            }
            else if (!strcmp(cmd.s, "Stat")) {
                mode = ARTICLE_STAT;
                goto article;
            }
            else if (!nntp_authstate && !allowanonymous) goto nologin;
            else if (!strcmp(cmd.s, "Slave")) {
                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                prot_printf(nntp_out, "202 Slave status noted\r\n");
            }
            else goto badcmd;
            break;

        case 'T':
            if (!strcmp(cmd.s, "Takethis")) {
                mode = POST_TAKETHIS;
                goto ihave;
            }
            else goto badcmd;
            break;

        case 'X':
            if (!strcmp(cmd.s, "Xhdr")) {
                goto hdr;
            }
            else if (!strcmp(cmd.s, "Xover")) {
                goto over;
            }
            else if (!strcmp(cmd.s, "Xpat")) {
                char *msgid;

                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg1); /* header */
                if (c != ' ') goto missingargs;

                /* gobble extra whitespace (hack for Mozilla) */
                while ((c = prot_getc(nntp_in)) == ' ');
                prot_ungetc(c, nntp_in);

                c = getword(nntp_in, &arg2); /* range */
                if (c != ' ') goto missingargs;
                c = getword(nntp_in, &arg3); /* wildmat */
                if (c == EOF) goto missingargs;

                /* XXX per RFC 2980, we can have multiple patterns */

                if (c == '\r') c = prot_getc(nntp_in);
                if (c != '\n') goto extraargs;

                if (parserange(arg2.s, &uid, &last, &msgid, &be) != -1) {
                    if (be) {
                        prot_printf(be->out, "%s %s %s %s\r\n",
                                    cmd.s, arg1.s, arg2.s, arg3.s);

                        if (be != backend_current) {
                            r = read_response(be, 0, &result);
                            if (r) goto noopengroup;

                            prot_printf(nntp_out, "%s", result);
                            if (!strncmp(result, "221", 3)) {
                                pipe_to_end_of_response(be, 0);
                            }
                        }
                    }
                    else
                        cmd_hdr(cmd.s, arg1.s, arg3.s, msgid, uid, last);
                }

                if (msgid) goto prevgroup;
            }
            else goto badcmd;
            break;

        default:
          badcmd:
            prot_printf(nntp_out, "500 Unrecognized command\r\n");
            eatline(nntp_in, c);
        }

        continue;

      noperm:
        prot_printf(nntp_out, "502 Permission denied\r\n");
        eatline(nntp_in, c);
        continue;

      nologin:
        prot_printf(nntp_out, "480 Authentication required\r\n");
        eatline(nntp_in, c);
        continue;

      cmddisabled:
        prot_printf(nntp_out, "503 \"%s\" disabled\r\n", cmd.s);
        eatline(nntp_in, c);
        continue;

      extraargs:
        prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
        eatline(nntp_in, c);
        continue;

      missingargs:
        prot_printf(nntp_out, "501 Missing argument\r\n");
        eatline(nntp_in, c);
        continue;

      baddatetime:
        prot_printf(nntp_out, "501 Bad date/time\r\n");
        continue;

      nogroup:
        prot_printf(nntp_out, "411 No such newsgroup (%s)\r\n",
                    error_message(r));

      prevgroup:
        /* Return to previously selected group */
        if (*curgroup &&
            (!group_state || strcmp(curgroup, group_state->mboxname))) {
            open_group(curgroup, 1, NULL, NULL);
        }

        continue;

      noopengroup:
        prot_printf(nntp_out, "412 No newsgroup selected\r\n");
        continue;

      nocurrent:
        prot_printf(nntp_out, "420 Current article number is invalid\r\n");
        continue;
    }
}

/*
 * duplicate_find() callback function to fetch a message by msgid
 */
struct findrock {
    const char *mailbox;
    unsigned long uid;
};

static int find_cb(const duplicate_key_t *dkey,
                   time_t mark __attribute__((unused)),
                   unsigned long uid, void *rock)
{
    struct findrock *frock = (struct findrock *) rock;

    /* skip mailboxes that we don't serve as newsgroups */
    if (!is_newsgroup(dkey->to)) return 0;

    frock->mailbox = dkey->to;
    frock->uid = uid;

    return CYRUSDB_DONE;
}

static int my_find_msgid(char *msgid, char **mailbox, uint32_t *uid)
{
    struct findrock frock = { NULL, 0 };

    duplicate_find(msgid, find_cb, &frock);

    if (!frock.mailbox) return 0;

    if (mailbox) {
        if (!frock.mailbox[0]) return 0;
        *mailbox = (char *) frock.mailbox;
    }
    if (uid) {
        if (!frock.uid) return 0;
        *uid = frock.uid;
    }

    return 1;
}

/*
 * Parse a username or password (token which may contain SP or TAB)
 */
#define MAX_NNTP_ARG 497
static int getuserpass(struct protstream *in, struct buf *buf)
{
    int c;

    buf_reset(buf);
    for (;;) {
        c = prot_getc(in);
        if (c == EOF || c == '\r' || c == '\n') {
            buf_cstring(buf); /* appends a '\0' */
            return c;
        }
        buf_putc(buf, c);
        if (buf_len(buf) > MAX_NNTP_ARG) {
            fatal("argument too long", EX_IOERR);
        }
    }
}

static int parserange(char *str, uint32_t *uid, uint32_t *last,
                      char **msgid, struct backend **ret)
{
    const char *p = NULL;
    char *mboxname;
    int r = 0;

    *uid = 0;
    if (last) *last = 0;
    if (msgid) *msgid = NULL;
    if (ret) *ret = NULL;

    if (!str || !*str) {
        /* no argument, use current article */
        if (backend_current) {
            if (ret) *ret = backend_current;
        }
        else if (!group_state) goto noopengroup;
        else if (!nntp_current) goto nocurrent;
        else {
            *uid = index_getuid(group_state, nntp_current);
            if (last) *last = *uid;
        }
    }
    else if (*str == '<') {
        /* message-id, find server and/or mailbox */
        if (!msgid) goto badrange;
        if (!my_find_msgid(str, &mboxname, uid)) goto nomsgid;

        *msgid = str;

        /* open group if its different from our current one */
        if (!group_state || strcmp(mboxname, group_state->mboxname)) {
            if ((r = open_group(mboxname, 1, ret, NULL))) goto nomsgid;
        }
    }
    else if (backend_current) {
        if (ret) *ret = backend_current;
    }
    else if (!group_state) goto noopengroup;
    else if (parseuint32(str, &p, uid) || uid == 0) goto badrange;
    else if (p && *p) {
        /* extra stuff, check for range */
        if (!last || (*p != '-')) goto badrange;
        if (*++p) {
            if (parseuint32(p, NULL, last))
                *last = 0;
        }
        else
            *last = UINT32_MAX;  /* open range -> use highest possible UID */
    }

    if (last && !*last) *last = *uid;

    return 0;

  noopengroup:
    prot_printf(nntp_out, "412 No newsgroup selected\r\n");
    return -1;

  nocurrent:
    prot_printf(nntp_out, "420 Current article number is invalid\r\n");
    return -1;

  nomsgid:
    prot_printf(nntp_out, "430 No article found with that message-id");
    if (r) prot_printf(nntp_out, " (%s)", error_message(r));
    prot_printf(nntp_out, "\r\n");
    return -1;

  badrange:
    prot_printf(nntp_out, "501 Bad message-id, message number, or range\r\n");
    return -1;
}

static const int numdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

#define isleap(year) (!((year) % 4) && (((year) % 100) || !((year) % 400)))

/*
 * Parse a date/time specification per RFC 3977 section 7.3.
 */
static time_t parse_datetime(char *datestr, char *timestr, char *gmt)
{
    int datelen = strlen(datestr), leapday;
    unsigned long d, t;
    char *p;
    struct tm tm;

    memset(&tm, 0, sizeof(tm));

    /* check format of strings */
    if ((datelen != 6 && datelen != 8) ||
        strlen(timestr) != 6 || (gmt && strcasecmp(gmt, "GMT")))
        return -1;

    /* convert datestr to ulong */
    d = strtoul(datestr, &p, 10);
    if (d == ULONG_MAX || *p) return -1;

    /* convert timestr to ulong */
    t = strtoul(timestr, &p, 10);
    if (t == ULONG_MAX || *p) return -1;

    /* populate the time struct */
    tm.tm_year = d / 10000;
    d %= 10000;
    tm.tm_mon = d / 100 - 1;
    tm.tm_mday = d % 100;

    tm.tm_hour = t / 10000;
    t %= 10000;
    tm.tm_min = t / 100;
    tm.tm_sec = t % 100;

    /* massage the year to years since 1900 */
    if (tm.tm_year > 99) tm.tm_year -= 1900;
    else {
        /*
         * guess century
         * if year > current year, use previous century
         * otherwise, use current century
         */
        time_t now = time(NULL);
        struct tm *current;
        int century;

        current = gmt ? gmtime(&now) : localtime(&now);
        century = current->tm_year / 100;
        if (tm.tm_year > current->tm_year % 100) century--;
        tm.tm_year += century * 100;
    }

    /* sanity check the date/time (including leap day and leap second) */
    leapday = tm.tm_mon == 1 && isleap(tm.tm_year + 1900);
    if (tm.tm_year < 70 || tm.tm_mon < 0 || tm.tm_mon > 11 ||
        tm.tm_mday < 1 || tm.tm_mday > (numdays[tm.tm_mon] + leapday) ||
        tm.tm_hour > 23 || tm.tm_min > 59 || tm.tm_sec > 60)
        return -1;

    return (gmt ? mkgmtime(&tm) : mktime(&tm));
}

static int open_group(const char *name, int has_prefix, struct backend **ret,
                      int *postable /* used for LIST ACTIVE only */)
{
    char mailboxname[MAX_MAILBOX_BUFFER];
    int r = 0;
    mbentry_t *mbentry = NULL;
    struct backend *backend_next = NULL;

    /* close local group */
    if (group_state)
        index_close(&group_state);

    if (!has_prefix) {
        snprintf(mailboxname, sizeof(mailboxname), "%s%s", newsprefix, name);
        name = mailboxname;

        if (!is_newsgroup(name)) return IMAP_MAILBOX_NONEXISTENT;
    }

    if (!r) r = proxy_mlookup(name, &mbentry, NULL, NULL);

    if (!r && mbentry->acl) {
        int myrights = cyrus_acl_myrights(nntp_authstate, mbentry->acl);

        if (postable) *postable = myrights & ACL_POST;
        if (!postable && /* allow limited 'r' for LIST ACTIVE */
            !(myrights & ACL_READ)) {
            r = (myrights & ACL_LOOKUP) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        }
    }

    if (r) {
        mboxlist_entry_free(&mbentry);
        return r;
    }

    if (mbentry->server) {
        /* remote group */
        backend_next = proxy_findserver(mbentry->server, &nntp_protocol,
                                        nntp_authstate ? nntp_userid : "anonymous",
                                        &backend_cached, &backend_current,
                                        NULL, nntp_in);
        mboxlist_entry_free(&mbentry);
        if (!backend_next) return IMAP_SERVER_UNAVAILABLE;

        *ret = backend_next;
    }
    else {
        /* local group */
        struct index_init init;

        mboxlist_entry_free(&mbentry);
        memset(&init, 0, sizeof(struct index_init));
        init.userid = nntp_authstate ? nntp_userid : NULL;
        init.authstate = nntp_authstate;
        r = index_open(name, &init, &group_state);
        if (r) return r;

        if (ret) *ret = NULL;
    }

    syslog(LOG_DEBUG, "open: user %s opened %s",
           nntp_userid ? nntp_userid : "anonymous", name);

    return 0;
}

static void cmd_capabilities(char *keyword __attribute__((unused)))
{
    const char *mechlist;
    int mechcount = 0;

    prot_printf(nntp_out, "101 Capability list follows:\r\n");
    prot_printf(nntp_out, "VERSION 2\r\n");
    if (nntp_authstate || (config_serverinfo == IMAP_ENUM_SERVERINFO_ON)) {
        prot_printf(nntp_out,
                    "IMPLEMENTATION Cyrus NNTP %s\r\n", CYRUS_VERSION);
    }

    /* add STARTTLS */
    if (tls_enabled() && !nntp_starttls_done && !nntp_authstate)
        prot_printf(nntp_out, "STARTTLS\r\n");

    if (!nntp_tls_required) {
        /* check for SASL mechs */
        sasl_listmech(nntp_saslconn, NULL, "SASL ", " ", "\r\n",
                      &mechlist, NULL, &mechcount);

        /* add the AUTHINFO variants */
        if (!nntp_authstate) {
            prot_printf(nntp_out, "AUTHINFO%s%s\r\n",
                        (nntp_starttls_done || (extprops_ssf > 1) ||
                         config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) ?
                        " USER" : "", mechcount ? " SASL" : "");
        }

        /* add the SASL mechs */
        if (mechcount) prot_printf(nntp_out, "%s", mechlist);
    }

#ifdef HAVE_ZLIB
    /* add COMPRESS */
    if (!nntp_compress_done && !nntp_tls_comp) {
        prot_printf(nntp_out, "COMPRESS DEFLATE\r\n");
    }
#endif

    /* add the reader capabilities/extensions */
    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "READER\r\n");
        prot_printf(nntp_out, "POST\r\n");
        if (config_getswitch(IMAPOPT_ALLOWNEWNEWS))
            prot_printf(nntp_out, "NEWNEWS\r\n");
        prot_printf(nntp_out, "HDR\r\n");
        prot_printf(nntp_out, "OVER\r\n");
        prot_printf(nntp_out, "XPAT\r\n");
    }

    /* add the feeder capabilities/extensions */
    if (nntp_capa & MODE_FEED) {
        prot_printf(nntp_out, "IHAVE\r\n");
        prot_printf(nntp_out, "STREAMING\r\n");
    }

    /* add the LIST variants */
    prot_printf(nntp_out, "LIST ACTIVE%s\r\n",
                ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) ?
                " HEADERS NEWSGROUPS OVERVIEW.FMT" : "");

    prot_printf(nntp_out, ".\r\n");

    did_capabilities = 1;
}

/*
 * duplicate_find() callback function to build Xref content
 */
static int xref_cb(const duplicate_key_t *dkey,
                   time_t mark __attribute__((unused)),
                   unsigned long uid, void *rock)
{
    struct buf *buf = (struct buf *)rock;

    /* skip mailboxes that we don't serve as newsgroups */
    if (is_newsgroup(dkey->to)) {
        buf_printf(buf,
                 " %s:%lu", dkey->to + strlen(newsprefix), uid);
    }

    return 0;
}

/*
 * Build an Xref header.  We have to do this on the fly because there is
 * no way to store it in the article at delivery time.
 */
static void build_xref(const char *msgid, struct buf *buf, int body_only)
{
    if (!body_only)
        buf_appendcstr(buf, "Xref: ");
    buf_appendcstr(buf, config_servername);
    duplicate_find(msgid, xref_cb, buf);
}

static void cmd_article(int part, char *msgid, unsigned long uid)
{
    int msgno, by_msgid = (msgid != NULL);
    const char *fname;
    FILE *msgfile;
    struct index_record record;

    msgno = index_finduid(group_state, uid);
    if (!msgno || index_getuid(group_state, msgno) != uid) {
        prot_printf(nntp_out, "423 No such article in this newsgroup\r\n");
        return;
    }

    if (index_reload_record(group_state, msgno, &record)) {
        prot_printf(nntp_out, "403 Could not read index record\r\n");
        return;
    }

    fname = mailbox_record_fname(group_state->mailbox, &record);

    msgfile = fopen(fname, "r");
    if (!msgfile) {
        prot_printf(nntp_out, "403 Could not read message file\r\n");
        return;
    }

    if (!by_msgid) {
        nntp_current = msgno;
        msgid = index_get_msgid(group_state, msgno);
    }

    prot_printf(nntp_out, "%u %lu %s\r\n",
                220 + part, by_msgid ? 0 : uid, msgid ? msgid : "<0>");

    if (part != ARTICLE_STAT) {
        char buf[4096];
        int body = 0;
        int output = (part != ARTICLE_BODY);

        while (fgets(buf, sizeof(buf), msgfile)) {
            if (!body && buf[0] == '\r' && buf[1] == '\n') {
                /* blank line between header and body */
                body = 1;
                if (output) {
                    /* add the Xref header */
                    struct buf xref = BUF_INITIALIZER;

                    build_xref(msgid, &xref, 0);
                    prot_printf(nntp_out, "%s\r\n", buf_cstring(&xref));
                    buf_free(&xref);
                }
                if (part == ARTICLE_HEAD) {
                    /* we're done */
                    break;
                }
                else if (part == ARTICLE_BODY) {
                    /* start outputting text */
                    output = 1;
                    continue;
                }
            }

            if (output) {
                if (buf[0] == '.') prot_putc('.', nntp_out);
                do {
                    prot_printf(nntp_out, "%s", buf);
                } while (buf[strlen(buf)-1] != '\n' &&
                         fgets(buf, sizeof(buf), msgfile));
            }
        }

        /* Protect against messages not ending in CRLF */
        if (buf[strlen(buf)-1] != '\n') prot_printf(nntp_out, "\r\n");

        prot_printf(nntp_out, ".\r\n");

        /* Reset inactivity timer in case we spend a long time
           pushing data to the client over a slow link. */
        prot_resettimeout(nntp_in);
    }

    if (!by_msgid) free(msgid);

    fclose(msgfile);
}

static void cmd_authinfo_user(char *user)
{
    const char *p;

    if (nntp_authstate) {
        prot_printf(nntp_out, "502 Already authenticated\r\n");
        return;
    }

    /* possibly disallow AUTHINFO USER */
    if (nntp_tls_required ||
        !(nntp_starttls_done || (extprops_ssf > 1) ||
          config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
        prot_printf(nntp_out,
                    "483 AUTHINFO USER command only available under a layer\r\n");
        return;
    }

    if (nntp_userid) {
        free(nntp_userid);
        nntp_userid = NULL;
    }

    if (!(p = canonify_userid(user, NULL, NULL))) {
        prot_printf(nntp_out, "481 Invalid user\r\n");
        syslog(LOG_NOTICE,
               "badlogin: %s plaintext %s invalid user",
               nntp_clienthost, beautify_string(user));
    }
    else {
        nntp_userid = xstrdup(p);
        prot_printf(nntp_out, "381 Give AUTHINFO PASS command\r\n");
    }
}

static void cmd_authinfo_pass(char *pass)
{
    int failedloginpause;
    int r;

    /* Conceal password in telemetry log */
    if (nntp_logfd != -1 && pass) {
        r = ftruncate(nntp_logfd,
                  lseek(nntp_logfd, -2, SEEK_CUR) - strlen(pass));
        if (!r)
            r = write(nntp_logfd, "...\r\n", 5);
        if (r < 0)
            syslog(LOG_ERR, "IOERROR: cannot conceal password in telemetry log: %m");
    }

    if (nntp_authstate) {
        prot_printf(nntp_out, "502 Already authenticated\r\n");
        return;
    }

    if (!nntp_userid) {
        prot_printf(nntp_out, "482 Must give AUTHINFO USER command first\r\n");
        return;
    }

    if (!strcmp(nntp_userid, "anonymous")) {
        if (allowanonymous) {
            pass = beautify_string(pass);
            if (strlen(pass) > 500) pass[500] = '\0';
            syslog(LOG_NOTICE, "login: %s anonymous %s",
                   nntp_clienthost, pass);
        }
        else {
            syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
                   nntp_clienthost);
            prot_printf(nntp_out, "481 Invalid login\r\n");
            return;
        }
    }
    else if (sasl_checkpass(nntp_saslconn,
                            nntp_userid,
                            strlen(nntp_userid),
                            pass,
                            strlen(pass))!=SASL_OK) {
        syslog(LOG_NOTICE, "badlogin: %s plaintext (%s) [%s]",
               nntp_clienthost, nntp_userid, sasl_errdetail(nntp_saslconn));
        failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
        if (failedloginpause != 0) {
            sleep(failedloginpause);
        }
        prot_printf(nntp_out, "481 Invalid login\r\n");
        free(nntp_userid);
        nntp_userid = 0;

        return;
    }
    else {
        syslog(LOG_NOTICE, "login: %s %s plaintext%s %s", nntp_clienthost,
               nntp_userid, nntp_starttls_done ? "+TLS" : "",
               "User logged in");

        prot_printf(nntp_out, "281 User logged in\r\n");

        /* nntp_authstate may have been set as a side effect
         * of sasl_checkpass() calling mysasl_proxy_policy */
        if (nntp_authstate)
            auth_freestate(nntp_authstate);

        nntp_authstate = auth_newstate(nntp_userid);

        /* Close IP-based telemetry log and create new log based on userid */
        if (nntp_logfd != -1) close(nntp_logfd);
        nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out, 0);
    }
}

static void cmd_authinfo_sasl(char *cmd, char *mech, char *resp)
{
    int r, sasl_result;
    char *success_data;
    sasl_ssf_t ssf;
    char *ssfmsg = NULL;
    const void *val;
    int failedloginpause;
    struct proc_limits limits;

    /* possibly disallow AUTHINFO SASL */
    if (nntp_tls_required) {
        prot_printf(nntp_out,
                    "483 AUTHINFO SASL command only available under a layer\r\n");
        return;
    }

    /* Conceal initial response in telemetry log */
    if (nntp_logfd != -1 && resp) {
        r = ftruncate(nntp_logfd,
                  lseek(nntp_logfd, -2, SEEK_CUR) - strlen(resp));
        r = write(nntp_logfd, "...\r\n", 5);
        r = 0;
    }

    if (nntp_userid) {
        prot_printf(nntp_out, "502 Already authenticated\r\n");
        return;
    }

    /* Stop telemetry logging during SASL exchange */
    if (nntp_logfd != -1 && mech) {
        prot_setlog(nntp_in, PROT_NO_FD);
        prot_setlog(nntp_out, PROT_NO_FD);
    }

    if (cmd[0] == 'g') {
        /* AUTHINFO GENERIC */
        if (!mech) {
            /* If client didn't specify any mech we give them the list */
            const char *sasllist;
            int mechnum;

            prot_printf(nntp_out, "281 List of mechanisms follows\r\n");

            /* CRLF separated, dot terminated */
            if (sasl_listmech(nntp_saslconn, NULL,
                              "", "\r\n", "\r\n",
                              &sasllist,
                              NULL, &mechnum) == SASL_OK) {
                if (mechnum > 0) {
                    prot_printf(nntp_out, "%s", sasllist);
                }
            }

            prot_printf(nntp_out, ".\r\n");
            return;
        }

        r = saslserver(nntp_saslconn, mech, resp, "AUTHINFO GENERIC ", "381 ",
                       "", nntp_in, nntp_out, &sasl_result, &success_data);
    }
    else {
        /* AUTHINFO SASL */
        r = saslserver(nntp_saslconn, mech, resp, "", "383 ", "=",
                       nntp_in, nntp_out, &sasl_result, &success_data);
    }

    /* Restart any telemetry logging */
    prot_setlog(nntp_in, nntp_logfd);
    prot_setlog(nntp_out, nntp_logfd);

    if (r) {
        int code;
        const char *errorstring = NULL;
        const char *userid = "-notset-";

        switch (r) {
        case IMAP_SASL_CANCEL:
            prot_printf(nntp_out,
                        "481 Client canceled authentication\r\n");
            break;
        case IMAP_SASL_PROTERR:
            errorstring = prot_error(nntp_in);

            prot_printf(nntp_out,
                        "482 Error reading client response: %s\r\n",
                        errorstring ? errorstring : "");
            break;
        default:
            /* failed authentication */
            switch (sasl_result) {
            case SASL_NOMECH:
            case SASL_TOOWEAK:
                code = 503;
                break;
            case SASL_ENCRYPT:
                code = 483;
                break;
            case SASL_BADPROT:
                code = 482;
                break;
            default:
                code = 481;
            }

            if (sasl_result != SASL_NOUSER)
                sasl_getprop(nntp_saslconn, SASL_USERNAME, (const void **) &userid);

            syslog(LOG_NOTICE, "badlogin: %s %s (%s) [%s]",
                   nntp_clienthost, mech, userid, sasl_errdetail(nntp_saslconn));

            failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
            if (failedloginpause != 0) {
                sleep(failedloginpause);
            }

            /* Don't allow user probing */
            if (sasl_result == SASL_NOUSER) sasl_result = SASL_BADAUTH;

            errorstring = sasl_errstring(sasl_result, NULL, NULL);
            if (errorstring) {
                prot_printf(nntp_out, "%d %s\r\n", code, errorstring);
            } else {
                prot_printf(nntp_out, "%d Error authenticating\r\n", code);
            }
        }

        reset_saslconn(&nntp_saslconn);
        return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(nntp_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
        prot_printf(nntp_out, "481 weird SASL error %d SASL_USERNAME\r\n",
                    sasl_result);
        syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME",
               sasl_result);
        reset_saslconn(&nntp_saslconn);
        return;
    }
    nntp_userid = xstrdup((const char *) val);

    sasl_getprop(nntp_saslconn, SASL_SSF, &val);
    ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (nntp_starttls_done) {
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

    limits.procname = "nntpd";
    limits.clienthost = nntp_clienthost;
    limits.userid = nntp_userid;
    if (proc_checklimits(&limits)) {
        const char *sep = "";
        char part1[1024] = "";
        char part2[1024] = "";
        prot_printf(nntp_out,
                    "400 Too many open connections (");
        if (limits.maxhost) {
            prot_printf(nntp_out, "%s%d of %d from %s", sep,
                        limits.host, limits.maxhost, nntp_clienthost);
            snprintf(part1, sizeof(part1), "%s%d of %d from %s", sep,
                        limits.host, limits.maxhost, nntp_clienthost);
            sep = ", ";
        }
        if (limits.maxuser) {
            prot_printf(nntp_out, "%s%d of %d for %s", sep,
                        limits.user, limits.maxuser, nntp_userid);
            snprintf(part2, sizeof(part2), "%s%d of %d for %s", sep,
                        limits.user, limits.maxuser, nntp_userid);
        }
        prot_printf(nntp_out, ")\r\n");
        syslog(LOG_ERR, "Too many open connections (%s%s)", part1, part2);
        reset_saslconn(&nntp_saslconn);
        free(nntp_userid);
        nntp_userid = NULL;
        return;
    }

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", nntp_clienthost, nntp_userid,
           mech, nntp_starttls_done ? "+TLS" : "", "User logged in");

    if (success_data) {
        prot_printf(nntp_out, "283 %s\r\n", success_data);
        free(success_data);
    } else {
        prot_printf(nntp_out, "281 Success (%s)\r\n", ssfmsg);
    }

    prot_setsasl(nntp_in,  nntp_saslconn);
    prot_setsasl(nntp_out, nntp_saslconn);

    /* Close IP-based telemetry log and create new log based on userid */
    if (nntp_logfd != -1) close(nntp_logfd);
    nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out, 0);

    if (ssf) {
        /* close any selected group */
        if (group_state)
            index_close(&group_state);
        if (backend_current) {
            proxy_downserver(backend_current);
            backend_current = NULL;
        }
    }
}

static void cmd_hdr(char *cmd, char *hdr, char *pat, char *msgid,
                    unsigned long uid, unsigned long last)
{
    int msgno, last_msgno;
    int by_msgid = (msgid != NULL);
    int found = 0;

    lcase(hdr);

    msgno = index_finduid(group_state, uid);
    if (!msgno || index_getuid(group_state, msgno) != uid) msgno++;
    last_msgno = index_finduid(group_state, last);

    for (; msgno <= last_msgno; msgno++) {
        char *body;

        if (!found++)
            prot_printf(nntp_out, "%u Headers follow:\r\n",
                        cmd[0] == 'X' ? 221 : 225);

        /* see if we're looking for metadata */
        if (hdr[0] == ':') {
            if (!strcasecmp(":bytes", hdr)) {
                struct buf xref = BUF_INITIALIZER;
                unsigned long size = index_getsize(group_state, msgno);

                if (!by_msgid) msgid = index_get_msgid(group_state, msgno);
                build_xref(msgid, &xref, 0);
                if (!by_msgid) free(msgid);

                prot_printf(nntp_out, "%lu %lu\r\n", by_msgid ? 0 : uid,
                            size + xref.len + 2); /* +2 for \r\n */
                buf_free(&xref);
            }
            else if (!strcasecmp(":lines", hdr))
                prot_printf(nntp_out, "%u %lu\r\n",
                            by_msgid ? 0 : index_getuid(group_state, msgno),
                            index_getlines(group_state, msgno));
            else
                prot_printf(nntp_out, "%u \r\n",
                            by_msgid ? 0 : index_getuid(group_state, msgno));
        }
        else if (!strcmp(hdr, "xref") && !pat /* [X]HDR only */) {
            struct buf xref = BUF_INITIALIZER;

            if (!by_msgid) msgid = index_get_msgid(group_state, msgno);
            build_xref(msgid, &xref, 1);
            if (!by_msgid) free(msgid);

            prot_printf(nntp_out, "%u %s\r\n",
                        by_msgid ? 0 : index_getuid(group_state, msgno),
                        buf_cstring(&xref));
            buf_free(&xref);
        }
        else if ((body = index_getheader(group_state, msgno, hdr)) &&
                 (!pat ||                       /* [X]HDR */
                  wildmat(body, pat))) {        /* XPAT with match */
                prot_printf(nntp_out, "%u %s\r\n",
                            by_msgid ? 0 : index_getuid(group_state, msgno), body);
        }
    }

    if (found)
        prot_printf(nntp_out, ".\r\n");
    else
        prot_printf(nntp_out, "423 No such article(s) in this newsgroup\r\n");
}

static void cmd_help(void)
{
    prot_printf(nntp_out, "100 Supported commands:\r\n");

    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "\tARTICLE [ message-id | number ]\r\n"
                    "\t\tRetrieve entirety of the specified article.\r\n");
    }
    if (!nntp_authstate) {
        if (!nntp_userid) {
            prot_printf(nntp_out, "\tAUTHINFO SASL mechanism [initial-response]\r\n"
                        "\t\tPerform an authentication exchange using the specified\r\n"
                        "\t\tSASL mechanism.\r\n");
            prot_printf(nntp_out, "\tAUTHINFO USER username\r\n"
                        "\t\tPresent username for authentication.\r\n");
        }
        prot_printf(nntp_out, "\tAUTHINFO PASS password\r\n"
                    "\t\tPresent clear-text password for authentication.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "\tBODY [ message-id | number ]\r\n"
                    "\t\tRetrieve body of the specified article.\r\n");
    }
    prot_printf(nntp_out, "\tCAPABILITIES\r\n"
                "\t\tList the current server capabilities.\r\n");
    if (nntp_capa & MODE_FEED) {
        prot_printf(nntp_out, "\tCHECK message-id\r\n"
                    "\t\tCheck if the server wants the specified article.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "\tDATE\r\n"
                    "\t\tRequest the current server UTC date and time.\r\n");
        prot_printf(nntp_out, "\tGROUP group\r\n"
                    "\t\tSelect a newsgroup for article retrieval.\r\n");
        prot_printf(nntp_out, "\tHDR header [ message-id | range ]\r\n"
                    "\t\tRetrieve the specified header/metadata from the\r\n"
                    "\t\tspecified article(s).\r\n");
    }
    prot_printf(nntp_out, "\tHEAD [ message-id | number ]\r\n"
                "\t\tRetrieve the headers of the specified article.\r\n");
    prot_printf(nntp_out, "\tHELP\r\n"
                "\t\tRequest command summary (this text).\r\n");
    if (nntp_capa & MODE_FEED) {
        prot_printf(nntp_out, "\tIHAVE message-id\r\n"
                    "\t\tPresent/transfer the specified article to the server.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "\tLAST\r\n"
                    "\t\tSelect the previous article.\r\n");
    }
    prot_printf(nntp_out, "\tLIST [ ACTIVE wildmat ]\r\n"
                "\t\tList the (subset of) valid newsgroups.\r\n");
    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "\tLIST HEADERS [ MSGID | RANGE ]\r\n"
                    "\t\tList the headers and metadata items available via HDR.\r\n");
        prot_printf(nntp_out, "\tLIST NEWSGROUPS [wildmat]\r\n"
                    "\t\tList the descriptions of the specified newsgroups.\r\n");
        prot_printf(nntp_out, "\tLIST OVERVIEW.FMT\r\n"
                    "\t\tList the headers and metadata items available via OVER.\r\n");
        prot_printf(nntp_out, "\tLISTGROUP [group [range]]\r\n"
                    "\t\tList the article numbers in the specified newsgroup.\r\n");
        if (config_getswitch(IMAPOPT_ALLOWNEWNEWS))
            prot_printf(nntp_out, "\tNEWNEWS wildmat date time [GMT]\r\n"
                        "\t\tList the newly arrived articles in the specified newsgroup(s)\r\n"
                        "\t\tsince the specified date and time.\r\n");
        prot_printf(nntp_out, "\tNEXT\r\n"
                    "\t\tSelect the next article.\r\n");
        prot_printf(nntp_out, "\tOVER [ message-id | range ]\r\n"
                    "\t\tRetrieve the overview information for the specified article(s).\r\n");
        prot_printf(nntp_out, "\tPOST\r\n"
                    "\t\tPost an article to the server.\r\n");
    }

    prot_printf(nntp_out, "\tQUIT\r\n"
                "\t\tTerminate the session.\r\n");
    if (tls_enabled() && !nntp_starttls_done && !nntp_authstate) {
        prot_printf(nntp_out, "\tSTARTTLS\r\n"
                    "\t\tStart a TLS negotiation.\r\n");
    }
    prot_printf(nntp_out, "\tSTAT [ message-id | number ]\r\n"
                "\t\tCheck if the specified article exists.\r\n");
    if (nntp_capa & MODE_FEED) {
        prot_printf(nntp_out, "\tTAKETHIS message-id\r\n"
                    "\t\tTransfer the specified article to the server.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_authstate || allowanonymous)) {
        prot_printf(nntp_out, "\tXPAT header message-id|range wildmat\r\n"
                    "\t\tList the specified article(s) in which the contents\r\n"
                    "\t\tof the specified header/metadata matches the wildmat.\r\n");
    }
    prot_printf(nntp_out, ".\r\n");
}

struct list_rock {
    int (*proc)(const char *, void *);
    unsigned rights;
    struct wildmat *wild;
    struct hash_table server_table;
};

/*
 * mboxlist_allmbox() callback function to LIST
 */
static int list_cb(const mbentry_t *mbentry, void *rock)
{
    const char *name = mbentry->name;
    struct list_rock *lrock = (struct list_rock *) rock;
    struct wildmat *wild;

    /* skip mailboxes that we aren't allowed to list */
    if (!mbentry->acl ||
        !(cyrus_acl_myrights(nntp_authstate, mbentry->acl) & lrock->rights)) {
        return 0;
    }

    /* skip mailboxes that we don't want to serve as newsgroups */
    if (!is_newsgroup(name)) return 0;

    /* see if the mailbox matches one of our specified wildmats */
    wild = lrock->wild;
    while (wild->pat && wildmat(name, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    if (mbentry->server) {
        /* remote group */
        struct list_rock *lrock = (struct list_rock *) rock;

        if (!hash_lookup(mbentry->server, &lrock->server_table)) {
            /* add this server to our table */
            hash_insert(mbentry->server,
                        (void *)0xDEADBEEF, &lrock->server_table);
        }

        return 0;
    }
    else if (lrock->proc) return lrock->proc(name, lrock);
    else return CYRUSDB_DONE;
}

struct enum_rock {
    const char *cmd;
    char *wild;
};

/*
 * hash_enumerate() callback function to LIST (proxy)
 */
static void list_proxy(const char *server,
                       void *data __attribute__((unused)), void *rock)
{
    struct enum_rock *erock = (struct enum_rock *) rock;
    struct backend *be;
    char *result;

    be = proxy_findserver(server, &nntp_protocol,
                          nntp_authstate ? nntp_userid : "anonymous",
                          &backend_cached, &backend_current, NULL, nntp_in);
    if (!be) return;

    prot_printf(be->out, "LIST %s %s\r\n", erock->cmd, erock->wild);

    if (!read_response(be, 0, &result) && !strncmp(result, "215 ", 4)) {
        while (!read_response(be, 0, &result) && result[0] != '.') {
            prot_printf(nntp_out, "%s", result);
        }
    }
}

/*
 * perform LIST ACTIVE (backend)
 */
static int do_active(const char *name, void *rock __attribute__((unused)))
{
    int r, postable;
    struct backend *be;

    /* open the group */
    r = open_group(name, 1, &be, &postable);
    if (r) {
        /* can't open group, skip it */
    }
    else {
        prot_printf(nntp_out, "%s %u %u %c\r\n", name+strlen(newsprefix),
                    group_state->exists ?
                    index_getuid(group_state, group_state->exists) :
                    group_state->mailbox->i.last_uid,
                    group_state->exists ? index_getuid(group_state, 1) :
                    group_state->mailbox->i.last_uid+1,
                    postable ? 'y' : 'n');
        index_close(&group_state);
    }

    return 0;
}

/*
 * annotatemore_findall() callback function to LIST NEWSGROUPS
 */
static int newsgroups_cb(const char *mailbox,
                  uint32_t uid __attribute__((unused)),
                  const char *entry __attribute__((unused)),
                  const char *userid,
                  const struct buf *value,
                  const struct annotate_metadata *mdata __attribute__((unused)),
                  void *rock)
{
    struct wildmat *wild = (struct wildmat *) rock;

    /* skip personal mailboxes */
    if ((!strncasecmp(mailbox, "INBOX", 5) &&
         (!mailbox[5] || mailbox[5] == '.')) ||
        !strncmp(mailbox, "user.", 5))
        return 0;

    /* see if the mailbox matches one of our wildmats */
    while (wild->pat && wildmat(mailbox, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    /* we only care about shared /comment */
    if (userid[0]) return 0;

    prot_printf(nntp_out, "%s\t%s\r\n", mailbox+strlen(newsprefix),
                value->s);

    return 0;
}

static void cmd_list(char *arg1, char *arg2)
{
    if (!arg1)
        arg1 = "active";
    else
        lcase(arg1);

    if (!strcmp(arg1, "active")) {
        struct list_rock lrock;
        struct enum_rock erock;

        if (!arg2) arg2 = "*";

        erock.cmd = "ACTIVE";
        erock.wild = xstrdup(arg2); /* make a copy before we munge it */

        lrock.proc = do_active;
        lrock.rights = ACL_READ;
        /* split the list of wildmats */
        lrock.wild = split_wildmats(arg2, config_getstring(IMAPOPT_NEWSPREFIX));

        /* xxx better way to determine a size for this table? */
        construct_hash_table(&lrock.server_table, 10, 1);

        prot_printf(nntp_out, "215 List of newsgroups follows:\r\n");

        mboxlist_allmbox(newsprefix, list_cb, &lrock, 0);

        /* proxy to the backends */
        hash_enumerate(&lrock.server_table, list_proxy, &erock);

        prot_printf(nntp_out, ".\r\n");

        /* free the hash table */
        free_hash_table(&lrock.server_table, NULL);

        /* free the wildmats */
        free_wildmats(lrock.wild);
        free(erock.wild);

        if (group_state)
            index_close(&group_state);
    }
    else if (!(nntp_capa & MODE_READ)) {
        prot_printf(nntp_out, "502 Permission denied\r\n");
        return;
    }
    else if (!nntp_authstate && !allowanonymous) {
        prot_printf(nntp_out, "480 Authentication required\r\n");
        return;
    }
    else if (!strcmp(arg1, "headers")) {
        if (arg2 && strcmp(arg2, "msgid") && strcmp(arg2, "range")) {
            prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
            return;
        }

        prot_printf(nntp_out, "215 Header and metadata list follows:\r\n");
        prot_printf(nntp_out, ":\r\n"); /* all headers */
        prot_printf(nntp_out, ":bytes\r\n");
        prot_printf(nntp_out, ":lines\r\n");
        prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "newsgroups")) {
        char pattern[MAX_MAILBOX_BUFFER];
        struct list_rock lrock;
        struct enum_rock erock;

        if (!arg2) arg2 = "*";

        erock.cmd = "NEWSGROUPS";
        erock.wild = xstrdup(arg2); /* make a copy before we munge it */

        lrock.proc = NULL;
        lrock.rights = ACL_LOOKUP;
        /* split the list of wildmats */
        lrock.wild = split_wildmats(arg2, config_getstring(IMAPOPT_NEWSPREFIX));

        /* xxx better way to determine a size for this table? */
        construct_hash_table(&lrock.server_table, 10, 1);

        prot_printf(nntp_out, "215 List of newsgroups follows:\r\n");

        mboxlist_allmbox(newsprefix, list_cb, &lrock, 0);

        /* proxy to the backends */
        hash_enumerate(&lrock.server_table, list_proxy, &erock);

        strcpy(pattern, newsprefix);
        strcat(pattern, "*");
        annotatemore_findall_pattern(pattern, 0, "/comment", /*modseq*/0,
                             newsgroups_cb, lrock.wild, /*flags*/0);

        prot_printf(nntp_out, ".\r\n");

        /* free the hash table */
        free_hash_table(&lrock.server_table, NULL);

        /* free the wildmats */
        free_wildmats(lrock.wild);
        free(erock.wild);
    }
    else if (!strcmp(arg1, "overview.fmt")) {
        if (arg2) {
            prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
            return;
        }

        prot_printf(nntp_out, "215 Order of overview fields follows:\r\n");
        prot_printf(nntp_out, "Subject:\r\n");
        prot_printf(nntp_out, "From:\r\n");
        prot_printf(nntp_out, "Date:\r\n");
        prot_printf(nntp_out, "Message-ID:\r\n");
        prot_printf(nntp_out, "References:\r\n");
        if (did_capabilities) {
            /* new OVER format */
            prot_printf(nntp_out, ":bytes\r\n");
            prot_printf(nntp_out, ":lines\r\n");
        } else {
            /* old XOVER format */
            prot_printf(nntp_out, "Bytes:\r\n");
            prot_printf(nntp_out, "Lines:\r\n");
        }
        prot_printf(nntp_out, "Xref:full\r\n");
        prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "active.times") || !strcmp(arg1, "distributions") ||
             !strcmp(arg1, "distrib.pats")) {
        prot_printf(nntp_out, "503 Unsupported LIST command\r\n");
    }
    else {
        prot_printf(nntp_out, "501 Unrecognized LIST command\r\n");
    }
    prot_flush(nntp_out);
}

static void cmd_mode(char *arg)
{
    lcase(arg);

    if (!strcmp(arg, "reader")) {
        prot_printf(nntp_out, "%u", (nntp_capa & MODE_READ) ? 200 : 201);
        if (config_serverinfo || nntp_authstate) {
            prot_printf(nntp_out, " %s", config_servername);
        }
        if (nntp_authstate || (config_serverinfo == IMAP_ENUM_SERVERINFO_ON)) {
            prot_printf(nntp_out, " Cyrus NNTP %s", CYRUS_VERSION);
        }
        prot_printf(nntp_out, " server ready, posting %s\r\n",
                    (nntp_capa & MODE_READ) ? "allowed" : "prohibited");
    }
    else if (!strcmp(arg, "stream")) {
        if (nntp_capa & MODE_FEED) {
            prot_printf(nntp_out, "203 Streaming allowed\r\n");
        }
        else {
            prot_printf(nntp_out, "502 Streaming prohibited\r\n");
        }
    }
    else {
        prot_printf(nntp_out, "501 Unrecognized MODE\r\n");
    }
    prot_flush(nntp_out);
}

static void cmd_newgroups(time_t tstamp __attribute__((unused)))
{
    prot_printf(nntp_out, "503 Can't determine NEWGROUPS at this time\r\n");
#if 0
    prot_printf(nntp_out, "231 List of new newsgroups follows:\r\n");

    /* Do search of annotations here. */

    prot_printf(nntp_out, ".\r\n");
#endif
}


/*
 * duplicate_find() callback function to list NEWNEWS
 */
struct newrock {
    time_t tstamp;
    struct wildmat *wild;
    char lastid[1024];
};

static int newnews_cb(const duplicate_key_t *dkey, time_t mark,
                      unsigned long uid, void *rock)
{
    struct newrock *nrock = (struct newrock *) rock;

    /* Make sure we don't return duplicate msgids,
     * the message is newer than the tstamp, and
     * the message is in mailbox we serve as a newsgroup..
     */
    if (strcmp(dkey->id, nrock->lastid) && mark >= nrock->tstamp &&
        uid && is_newsgroup(dkey->to)) {
        struct wildmat *wild = nrock->wild;

        /* see if the mailbox matches one of our specified wildmats */
        while (wild->pat && wildmat(dkey->to, wild->pat) != 1) wild++;

        /* we have a match, and its not a negative match */
        if (wild->pat && !wild->not) {
            prot_printf(nntp_out, "%s\r\n", dkey->id);
            strlcpy(nrock->lastid, dkey->id, sizeof(nrock->lastid));
        }
    }

    return 0;
}

static void cmd_newnews(char *wild, time_t tstamp)
{
    struct newrock nrock;

    memset(&nrock, 0, sizeof(nrock));
    nrock.tstamp = tstamp;
    nrock.wild = split_wildmats(wild, config_getstring(IMAPOPT_NEWSPREFIX));

    prot_printf(nntp_out, "230 List of new articles follows:\r\n");

    duplicate_find("", newnews_cb, &nrock);

    prot_printf(nntp_out, ".\r\n");

    free_wildmats(nrock.wild);
}

static void cmd_over(char *msgid, unsigned long uid, unsigned long last)
{
    uint32_t msgno, last_msgno;
    struct nntp_overview *over;
    int found = 0;

    msgno = index_finduid(group_state, uid);
    if (!msgno || index_getuid(group_state, msgno) != uid) msgno++;
    last_msgno = index_finduid(group_state, last);

    for (; msgno <= last_msgno; msgno++) {
        if (!found++)
            prot_printf(nntp_out, "224 Overview information follows:\r\n");

        if ((over = index_overview(group_state, msgno))) {
            struct buf xref = BUF_INITIALIZER;

            build_xref(over->msgid, &xref, 0);

            prot_printf(nntp_out, "%lu\t%s\t%s\t%s\t%s\t%s\t%lu\t%lu\t%s\r\n",
                        msgid ? 0 : over->uid,
                        over->subj ? over->subj : "",
                        over->from ? over->from : "",
                        over->date ? over->date : "",
                        over->msgid ? over->msgid : "",
                        over->ref ? over->ref : "",
                        over->bytes + xref.len + 2, /* +2 for \r\n */
                        over->lines, buf_cstring(&xref));
            buf_free(&xref);
        }
    }

    if (found)
        prot_printf(nntp_out, ".\r\n");
    else
        prot_printf(nntp_out, "423 No such article(s) in this newsgroup\r\n");
}


#define RCPT_GROW 30

typedef struct message_data message_data_t;

struct message_data {
    struct protstream *data;    /* message in temp file */
    FILE *f;                    /* FILE * corresponding */

    char *id;                   /* message id */
    char *path;                 /* path */
    char *control;              /* control message */
    unsigned long size;         /* size of message in bytes */
    strarray_t rcpt;            /* mailboxes to post message */
    char *date;                 /* date field of header */

    hdrcache_t hdrcache;
};

/* returns non-zero on failure */
static int msg_new(message_data_t **m)
{
    message_data_t *ret = (message_data_t *) xmalloc(sizeof(message_data_t));

    ret->data = NULL;
    ret->f = NULL;
    ret->id = NULL;
    ret->path = NULL;
    ret->control = NULL;
    ret->size = 0;
    strarray_init(&ret->rcpt);
    ret->date = NULL;

    ret->hdrcache = spool_new_hdrcache();

    *m = ret;
    return 0;
}

static void msg_free(message_data_t *m)
{
    if (m->data)
        prot_free(m->data);
    if (m->f)
        fclose(m->f);
    free(m->id);
    free(m->path);
    free(m->control);
    free(m->date);

    strarray_fini(&m->rcpt);

    spool_free_hdrcache(m->hdrcache);

    free(m);
}

static void parse_groups(const char *groups, message_data_t *msg)
{
    const char *p;
    char *rcpt = NULL;
    char *buf = xstrdup(groups);
    const char sep[] = ", \t";

    for (p = strtok(buf, sep) ; p ; p = strtok(NULL, sep)) {
        /* construct the mailbox name */
        free(rcpt);
        rcpt = strconcat(newsprefix, p, (char *)NULL);

        /* skip mailboxes that we don't serve as newsgroups */
        if (!is_newsgroup(rcpt)) continue;

        /* Only add mailboxes that exist */
        if (!proxy_mlookup(rcpt, NULL, NULL, NULL)) {
            strarray_appendm(&msg->rcpt, rcpt);
            rcpt = NULL;
        }
    }
    free(rcpt);
    free(buf);
}

/* Create a new header to be cached and/or spooled to disk.
 *  'destname' contains the name of the new header.
 *  'dest' contains an optional existing header body to be appended to.
 *  'src' contains an optional existing header body to add to 'dest'.
 *  'newspostuser' contains an optional userid used to create "post"
 *    email addresses from newsgroup names
 */
static void add_header(const char *destname, const char **dest,
                       const char **src, const char *newspostuser,
                       hdrcache_t hdrcache, FILE *f)
{
    struct buf buf = BUF_INITIALIZER;
    char *newdest = NULL;
    int fold = 0;

    if (src) {
        if (!newspostuser) {
            /* no translation of source needed - copy as-is to dest */
            buf_appendcstr(&buf, src[0]);
        }
        else {
            /* translate source newsgroups into "post" email addresses */
            const char *s, *sep = "";
            size_t n;

            if (dest) {
                /* append to the existing dest header body */
                buf_appendcstr(&buf, dest[0]);
                fold = buf.len + 1;
                sep = ", ";
            }

            for (s = src[0];; s += n) {
                /* skip whitespace */
                while (s && *s &&
                       (Uisspace(*s) || *s == ',')) s++;
                if (!s || !*s) break;

                /* find end of source address/group */
                n = strcspn(s, ", \t");

                /* append the new (translated) address */
                buf_printf(&buf, "%s%s+%.*s",
                           sep, newspostuser, (int) n, s);
                if (config_defdomain) buf_printf(&buf, "@%s", config_defdomain);

                sep = ", ";
            }
        }
        newdest = buf_release(&buf);

        if (dest) {
            /* replace the existing cached header */
            spool_replace_header(xstrdup(destname), newdest, hdrcache);
        }
        else {
            /* add the new header to the cache */
            spool_cache_header(xstrdup(destname), newdest, hdrcache);
        }
    } else if (dest) {
        /* no source header, use original dest header */
        newdest = (char *) dest[0];
    }

    if (newdest) {
        /* add the new dest header to the spool file */
        fprintf(f, "%s: ", destname);
        if (fold) fprintf(f, "%.*s\r\n\t", fold, newdest);
        fprintf(f, "%s\r\n", newdest+fold);
    }
}

/*
 * file in the message structure 'm' from 'pin', assuming a dot-stuffed
 * stream a la nntp.
 *
 * returns 0 on success, imap error code on failure
 */
static int savemsg(message_data_t *m, FILE *f)
{
    struct stat sbuf;
    const char **body, **groups;
    int r, i;
    time_t now = time(NULL);
    static int post_count = 0;
    FILE *stagef = NULL;
    const char *skipheaders[] = {
        "Path",         /* need to prepend our servername */
        "Xref",         /* need to remove (generated on the fly) */
        "To",           /* need to add "post" email addresses */
        "Reply-To",     /* need to add "post" email addresses */
        NULL
    };

    m->f = f;

    /* fill the cache */
    r = spool_fill_hdrcache(nntp_in, f, m->hdrcache, skipheaders);
    if (r) {
        /* got a bad header */

        /* flush the remaining output */
        spool_copy_msg(nntp_in, NULL);
        return r;
    }

    /* now, using our header cache, fill in the data that we want */

    /* get path */
    if ((body = spool_getheader(m->hdrcache, "path")) != NULL) {
        /* prepend to the cached path */
        m->path = strconcat(config_servername, "!", body[0], (char *)NULL);
        spool_replace_header(xstrdup("Path"), xstrdup(m->path), m->hdrcache);
    } else {
        /* no path, create one */
        m->path = strconcat(config_servername, "!",
                            nntp_userid ? nntp_userid : "anonymous",
                            (char *)NULL);
        spool_cache_header(xstrdup("Path"), xstrdup(m->path), m->hdrcache);
    }
    fprintf(f, "Path: %s\r\n", m->path);

    /* get message-id */
    if ((body = spool_getheader(m->hdrcache, "message-id")) != NULL) {
        m->id = xstrdup(body[0]);
    } else {
        /* no message-id, create one */
        pid_t p = getpid();

        m->id = xmalloc(40 + strlen(config_servername));
        sprintf(m->id, "<cmu-nntpd-%d-%d-%d@%s>", p, (int) now,
                post_count++, config_servername);
        fprintf(f, "Message-ID: %s\r\n", m->id);
        spool_cache_header(xstrdup("Message-ID"), xstrdup(m->id), m->hdrcache);
    }

    /* get date */
    if ((body = spool_getheader(m->hdrcache, "date")) == NULL) {
        /* no date, create one */
        char datestr[RFC5322_DATETIME_MAX+1];

        time_to_rfc5322(now, datestr, sizeof(datestr));
        m->date = xstrdup(datestr);
        fprintf(f, "Date: %s\r\n", datestr);
        spool_cache_header(xstrdup("Date"), xstrdup(datestr), m->hdrcache);
    }
    else {
        m->date = xstrdup(body[0]);
    }

    /* get control */
    if ((body = spool_getheader(m->hdrcache, "control")) != NULL) {
        size_t len;
        char *s;

        m->control = xstrdup(body[0]);

        /* create a recipient for the appropriate pseudo newsgroup */
        len = strcspn(m->control, " \t\r\n");
        s = xmalloc(strlen(newsprefix) + 8 + len + 1);
        sprintf(s, "%scontrol.%.*s", newsprefix, (int) len, m->control);

        strarray_appendm(&m->rcpt, s);
    } else {
        m->control = NULL;      /* no control */

        /* get newsgroups */
        if ((groups = spool_getheader(m->hdrcache, "newsgroups")) != NULL) {
            /* parse newsgroups and create recipients */
            parse_groups(groups[0], m);
            if (!m->rcpt.count) {
                r = IMAP_MAILBOX_NONEXISTENT; /* no newsgroups that we serve */
            }
            if (!r) {
                const char *newspostuser = config_getstring(IMAPOPT_NEWSPOSTUSER);
                unsigned long newsaddheaders =
                    config_getbitfield(IMAPOPT_NEWSADDHEADERS);
                const char **to = NULL, **replyto = NULL;

                /* add To: header to spooled message file,
                   optionally adding "post" email addr based on newsgroup */
                body = spool_getheader(m->hdrcache, "to");
                if (newspostuser &&
                    (newsaddheaders & IMAP_ENUM_NEWSADDHEADERS_TO)) {
                    to = groups;
                }
                add_header("To", body, to, newspostuser, m->hdrcache, f);

                /* add Reply-To: header to spooled message file,
                   optionally adding "post" email addr based on newsgroup */
                body = spool_getheader(m->hdrcache, "reply-to");
                if (newspostuser &&
                    (newsaddheaders & IMAP_ENUM_NEWSADDHEADERS_REPLYTO)) {
                    /* determine which groups header to use for reply-to */
                    replyto = spool_getheader(m->hdrcache, "followup-to");
                    if (!replyto) replyto = groups;
                    else if (!strncasecmp(replyto[0], "poster",
                                          strcspn(replyto[0], " \t"))) {
                        /* reply doesn't go to group */
                        newspostuser = NULL;

                        if (body) replyto = NULL;
                        else replyto = spool_getheader(m->hdrcache, "from");
                    }
                }
                add_header("Reply-To", body, replyto, newspostuser,
                           m->hdrcache, f);
            }
        } else {
            r = NNTP_NO_NEWSGROUPS;             /* no newsgroups header */
        }

        if (r) {
            /* error getting newsgroups */

            /* flush the remaining output */
            spool_copy_msg(nntp_in, NULL);
            return r;
        }
    }

    fflush(f);
    if (ferror(f)) {
        return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
        return IMAP_IOERROR;
    }

    /* spool to the stage of one of the recipients */
    for (i = 0; !stagef && (i < m->rcpt.count); i++) {
        stagef = append_newstage(m->rcpt.data[i], now, 0, &stage);
    }

    if (stagef) {
        const char *base = 0;
        size_t size = 0;
        int n;

        /* copy the header from our tmpfile to the stage */
        map_refresh(fileno(f), 1, &base, &size, sbuf.st_size, "tmp", 0);
        n = retry_write(fileno(stagef), base, size);
        map_free(&base, &size);

        if (n == -1) {
            /* close and remove the stage */
            fclose(stagef);
            append_removestage(stage);
            stage = NULL;
            return IMAP_IOERROR;
        }
        else {
            /* close the tmpfile and use the stage */
            fclose(f);
            m->f = f = stagef;
        }
    }
    /* else this is probably a remote group, so use the tmpfile */

    r = spool_copy_msg(nntp_in, f);

    if (r) return r;

    fflush(f);
    if (ferror(f)) {
        return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
        return IMAP_IOERROR;
    }
    m->size = sbuf.st_size;
    m->data = prot_new(fileno(f), 0);

    return 0;
}

static int deliver_remote(message_data_t *msg, struct dest *dlist)
{
    struct dest *d;

    /* run the txns */
    for (d = dlist; d; d = d->next) {
        struct backend *be;
        char buf[4096];

        be = proxy_findserver(d->server, &nntp_protocol,
                              nntp_authstate ? nntp_userid : "anonymous",
                              &backend_cached, &backend_current,
                              NULL, nntp_in);
        if (!be) return IMAP_SERVER_UNAVAILABLE;

        /* tell the backend about our new article */
        prot_printf(be->out, "IHAVE %s\r\n", msg->id);
        prot_flush(be->out);

        if (!prot_fgets(buf, sizeof(buf), be->in) ||
            strncmp("335", buf, 3)) {
            syslog(LOG_NOTICE, "backend doesn't want article %s", msg->id);
            continue;
        }

        /* send the article */
        rewind(msg->f);
        while (fgets(buf, sizeof(buf), msg->f)) {
            if (buf[0] == '.') prot_putc('.', be->out);
            do {
                prot_printf(be->out, "%s", buf);
            } while (buf[strlen(buf)-1] != '\n' &&
                     fgets(buf, sizeof(buf), msg->f));
        }

        /* Protect against messages not ending in CRLF */
        if (buf[strlen(buf)-1] != '\n') prot_printf(be->out, "\r\n");

        prot_printf(be->out, ".\r\n");

        if (!prot_fgets(buf, sizeof(buf), be->in) ||
            strncmp("235", buf, 3)) {
            syslog(LOG_WARNING, "article %s transfer to backend failed",
                   msg->id);
            return NNTP_FAIL_TRANSFER;
        }
    }

    return 0;
}

static int deliver(message_data_t *msg)
{
    int n, r = 0, myrights;
    char *rcpt = NULL;
    struct body *body = NULL;
    struct dest *dlist = NULL;
    mbentry_t *mbentry = NULL;
    duplicate_key_t dkey = {msg->id, NULL, msg->date};

    /* check ACLs of all mailboxes */
    for (n = 0; n < msg->rcpt.count; n++) {
        rcpt = msg->rcpt.data[n];
        dkey.to = rcpt;

        /* free the mbentry from the last iteration */
        mboxlist_entry_free(&mbentry);

        /* look it up */
        r = proxy_mlookup(rcpt, &mbentry, NULL, NULL);
        if (r) return IMAP_MAILBOX_NONEXISTENT;

        if (!(mbentry->acl && (myrights = cyrus_acl_myrights(nntp_authstate, mbentry->acl)) &&
              (myrights & ACL_POST))) {
            mboxlist_entry_free(&mbentry);
            return IMAP_PERMISSION_DENIED;
        }

        if (mbentry->server) {
            /* remote group */
            proxy_adddest(&dlist, NULL, 0, mbentry->server, "");
        }
        else {
            /* local group */
            struct appendstate as;
            static const quota_t qdiffs[QUOTA_NUMRESOURCES] =
                                    QUOTA_DIFFS_INITIALIZER;

            if (msg->id &&
                duplicate_check(&dkey)) {
                /* duplicate message */
                duplicate_log(&dkey, "nntp delivery");
                continue;
            }

            r = append_setup(&as, rcpt,
                             nntp_authstate ? nntp_userid : NULL,
                             nntp_authstate, ACL_POST, qdiffs, NULL, 0, 0);

            if (!r) {
                prot_rewind(msg->data);
                if (stage) {
                    r = append_fromstage(&as, &body, stage, 0, 0,
                                         NULL, !singleinstance,
                                         /*annotations*/NULL);
                } else {
                    /* XXX should never get here */
                    r = append_fromstream(&as, &body, msg->data, msg->size, 0, NULL);
                }
                if (r || ( msg->id && duplicate_check(&dkey) ) ) {
                    append_abort(&as);

                    if (!r) {
                        /* duplicate message */
                        duplicate_log(&dkey, "nntp delivery");
                        continue;
                    }
                }
                else {
                    r = append_commit(&as);
                }
            }

            if (!r && msg->id)
                duplicate_mark(&dkey, time(NULL), as.baseuid);

            if (r) {
                mboxlist_entry_free(&mbentry);
                return r;
            }
        }
    }
    mboxlist_entry_free(&mbentry);

    if (body) {
        message_free_body(body);
        free(body);
    }

    if (dlist) {
        struct dest *d;

        /* run the txns */
        r = deliver_remote(msg, dlist);

        /* free the destination list */
        d = dlist;
        while (d) {
            struct dest *nextd = d->next;
            free(d);
            d = nextd;
        }
    }

    sync_checkpoint(nntp_in);

    return r;
}

#if 0  /* XXX  Need to review control message auth/authz and implementation */
static int newgroup(message_data_t *msg)
{
    int r;
    char *group;
    char mailboxname[MAX_MAILBOX_BUFFER];

    /* isolate newsgroup */
    group = msg->control + 8; /* skip "newgroup" */
    while (Uisspace(*group)) group++;

    snprintf(mailboxname, sizeof(mailboxname), "%s%.*s",
             newsprefix, (int) strcspn(group, " \t\r\n"), group);

    /* XXX do we need to notify news mailbox creation ? */
    r = mboxlist_createmailbox(mailboxname, 0, NULL, 0,
                               newsmaster, newsmaster_authstate, 0, 0, 0);

    /* XXX check body of message for useful MIME parts */

    sync_checkpoint(nntp_in);

    return r;
}

static int rmgroup(message_data_t *msg)
{
    int r;
    char *group;
    char mailboxname[MAX_MAILBOX_BUFFER];

    /* isolate newsgroup */
    group = msg->control + 7; /* skip "rmgroup" */
    while (Uisspace(*group)) group++;

    snprintf(mailboxname, sizeof(mailboxname), "%s%.*s",
             newsprefix, (int) strcspn(group, " \t\r\n"), group);

    /* skip mailboxes that we don't serve as newsgroups */
    if (!is_newsgroup(mailboxname)) r = IMAP_MAILBOX_NONEXISTENT;

    /* XXX should we delete right away, or wait until empty? */

    if (!r) r = mboxlist_deletemailbox(mailboxname, 0,
                                       newsmaster, newsmaster_authstate,
                                       MBOXLIST_DELETE_CHECKACL);

    sync_checkpoint(nntp_in);

    return r;
}

static int mvgroup(message_data_t *msg)
{
    int r;
    size_t len;
    char *group;
    char oldmailboxname[MAX_MAILBOX_BUFFER];
    char newmailboxname[MAX_MAILBOX_BUFFER];
    struct mbentry_t *mbentry = NULL;

    /* isolate old newsgroup */
    group = msg->control + 7; /* skip "mvgroup" */
    while (Uisspace(*group)) group++;

    len = strcspn(group, " \t\r\n");
    snprintf(oldmailboxname, sizeof(oldmailboxname), "%s%.*s",
             newsprefix, (int)len, group);

    /* isolate new newsgroup */
    group += len; /* skip old newsgroup */
    while (Uisspace(*group)) group++;

    len = strcspn(group, " \t\r\n");
    snprintf(newmailboxname, sizeof(newmailboxname), "%s%.*s",
             newsprefix, (int)len, group);

    r = proxy_mlookup(oldmailboxname, &mbentry, NULL, NULL);
    if (r) return r;

    r = mboxlist_renamemailbox(mbentry, newmailboxname, NULL, 0,
                               newsmaster, newsmaster_authstate, 0, 0, 0, 0, 0);
    mboxlist_entry_free(&mbentry);

    /* XXX check body of message for useful MIME parts */

    sync_checkpoint(nntp_in);

    return r;
}

/*
 * mailbox_exchange() callback function to delete cancelled articles
 */
static unsigned expunge_cancelled(struct mailbox *mailbox __attribute__((unused)),
                                  struct index_record *record,
                                  void *rock)
{
    /* only expunge the UID that we obtained from the msgid */
    return (record->uid == *((unsigned long *) rock));
}

/*
 * duplicate_find() callback function to cancel articles
 */
static int cancel_cb(const duplicate_t *dkey,
                     time_t mark __attribute__((unused)),
                     unsigned long uid,
                     void *rock)
{
    struct mailbox *mailbox = NULL;

    /* make sure its a message in a mailbox that we're serving via NNTP */
    if (is_newsgroup(dkey->to)) {
        int r;

        r = mailbox_open_iwl(dkey->to, &mailbox);

        if (!r &&
            !(cyrus_acl_myrights(newsmaster_authstate, mailbox->acl) & ACL_DELETEMSG))
            r = IMAP_PERMISSION_DENIED;

        if (!r) r = mailbox_expunge(mailbox, expunge_cancelled, &uid, NULL, 0);
        mailbox_close(&mailbox);

        /* if we failed, pass the return code back in the rock */
        if (r) *((int *) rock) = r;
    }

    return 0;
}

static int cancel(message_data_t *msg)
{
    int r = 0;
    char *msgid, *p;

    /* isolate msgid */
    msgid = strchr(msg->control, '<');
    p = strrchr(msgid, '>') + 1;
    *p = '\0';

    /* find and expunge the message from all mailboxes */
    duplicate_find(msgid, cancel_cb, &r);

    /* store msgid of cancelled message for IHAVE/CHECK/TAKETHIS
     * (in case we haven't received the message yet)
     */
    duplicate_key_t dkey = {msgid, "", ""};
    duplicate_mark(&dkey, 0, time(NULL));

    sync_checkpoint(nntp_in);

    return r;
}
#endif

/* strip any post addresses from a header body.
 * returns 1 if a nonpost address was found, 0 otherwise.
 */
static int strip_post_addresses(char *body)
{
    const char *newspostuser = config_getstring(IMAPOPT_NEWSPOSTUSER);
    char *p, *end;
    size_t postlen, n;
    int nonpost = 0;

    if (!newspostuser) return 1;  /* we didn't add this header, so leave it */
    postlen = strlen(newspostuser);

    for (p = body;; p += n) {
        end = p;

        /* skip whitespace */
        while (p && *p && (Uisspace(*p) || *p == ',')) p++;

        if (!p || !*p) break;

        /* find end of address */
        n = strcspn(p, ", \t\r\n");

        if ((n > postlen + 1) &&  /* +1 for '+' */
            !strncmp(p, newspostuser, postlen) && p[postlen] == '+') {
            /* found a post address.  since we always add the post
             * addresses to the end of the header, truncate it right here.
             */
            strcpy(end, "\r\n");
            break;
        }

        nonpost = 1;
    }

    return nonpost;
}


static void feedpeer(char *peer, message_data_t *msg)
{
    char *user, *pass, *host, *port, *wild, *path, *s;
    int oldform = 0;
    struct wildmat *wmat = NULL, *w;
    int len, err, n, feed = 1;
    struct addrinfo hints, *res, *res0;
    int sock = -1;
    struct protstream *pin, *pout;
    char buf[4096];
    int body = 0, skip;

    /* parse the peer */
    user = pass = host = port = wild = NULL;
    if ((wild = strrchr(peer, '/')))
        *wild++ = '\0';
    else if ((wild = strrchr(peer, ':')) &&
             strcspn(wild, "!*?,.") != strlen(wild)) {
        *wild++ = '\0';
        host = peer;
        oldform = 1;
    }
    if (!oldform) {
        if ((host = strchr(peer, '@'))) {
            *host++ = '\0';
            user = peer;
            if ((pass = strchr(user, ':'))) *pass++ = '\0';
        }
        else
            host = peer;

        if ((port = strchr(host, ':'))) *port++ = '\0';
    }

    /* check path to see if this message came through our peer */
    len = strlen(host);
    path = msg->path;
    while (path && (s = strchr(path, '!'))) {
        if ((s - path) == len && !strncmp(path, host, len)) {
            return;
        }
        path = s + 1;
    }

    /* check newsgroups against wildmat to see if we should feed it */
    if (wild && *wild) {
        wmat = split_wildmats(wild, config_getstring(IMAPOPT_NEWSPREFIX));

        feed = 0;
        for (n = 0; n < msg->rcpt.count; n++) {
            /* see if the newsgroup matches one of our wildmats */
            w = wmat;
            while (w->pat &&
                   wildmat(msg->rcpt.data[n], w->pat) != 1) {
                w++;
            }

            if (w->pat) {
                /* we have a match, check to see what kind of match */
                if (!w->not) {
                    /* positive match, ok to feed, keep checking */
                    feed = 1;
                }
                else if (w->not < 0) {
                    /* absolute negative match, do not feed */
                    feed = 0;
                    break;
                }
                else {
                    /* negative match, keep checking */
                }
            }
            else {
                /* no match, keep checking */
            }
        }

        free_wildmats(wmat);
    }

    if (!feed) return;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    if (!port || !*port) port = "119";
    if ((err = getaddrinfo(host, port, &hints, &res0)) != 0) {
        syslog(LOG_ERR, "getaddrinfo(%s, %s) failed: %m", host, port);
        return;
    }

    for (res = res0; res; res = res->ai_next) {
        if ((sock = socket(res->ai_family, res->ai_socktype,
                           res->ai_protocol)) < 0)
            continue;
        if (connect(sock, res->ai_addr, res->ai_addrlen) >= 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res0);
    if(sock < 0) {
        syslog(LOG_ERR, "connect(%s:%s) failed: %m", host, port);
        return;
    }

    pin = prot_new(sock, 0);
    pout = prot_new(sock, 1);
    prot_setflushonread(pin, pout);

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("200", buf, 3)) {
        syslog(LOG_ERR, "peer doesn't allow posting");
        goto quit;
    }

    if (user) {
        /* change to reader mode - not always necessary, so ignore result */
        prot_printf(pout, "MODE READER\r\n");
        prot_fgets(buf, sizeof(buf), pin);

        if (*user) {
            /* authenticate to peer */
            /* XXX this should be modified to support SASL and STARTTLS */

            prot_printf(pout, "AUTHINFO USER %s\r\n", user);
            if (!prot_fgets(buf, sizeof(buf), pin)) {
                syslog(LOG_ERR, "AUTHINFO USER terminated abnormally");
                goto quit;
            }
            else if (!strncmp("381", buf, 3)) {
                /* password required */
                if (!pass) {
                    syslog(LOG_ERR, "need password for AUTHINFO PASS");
                    goto quit;
                }

                prot_printf(pout, "AUTHINFO PASS %s\r\n", pass);
                if (!prot_fgets(buf, sizeof(buf), pin)) {
                    syslog(LOG_ERR, "AUTHINFO PASS terminated abnormally");
                    goto quit;
                }
            }

            if (strncmp("281", buf, 3)) {
                /* auth failed */
                syslog(LOG_ERR, "authentication failed");
                goto quit;
            }
        }

        /* tell the peer we want to post */
        prot_printf(pout, "POST\r\n");
        prot_flush(pout);

        if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("340", buf, 3)) {
            syslog(LOG_ERR, "peer doesn't allow posting");
            goto quit;
        }
    }
    else {
        /* tell the peer about our new article */
        prot_printf(pout, "IHAVE %s\r\n", msg->id);
        prot_flush(pout);

        if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("335", buf, 3)) {
            syslog(LOG_ERR, "peer doesn't want article %s", msg->id);
            goto quit;
        }
    }

    /* send the article */
    rewind(msg->f);
    while (fgets(buf, sizeof(buf), msg->f)) {
        if (!body && buf[0] == '\r' && buf[1] == '\n') {
            /* blank line between header and body */
            body = 1;
        }

        skip = 0;
        if (!body) {
            if (!strncasecmp(buf, "Reply-To:", 9)) {
                /* strip any post addresses, skip if becomes empty */
                if (!strip_post_addresses(buf+9)) skip = 1;
            }
        }

        if (!skip && buf[0] == '.') prot_putc('.', pout);
        do {
            if (!skip) prot_printf(pout, "%s", buf);
        } while (buf[strlen(buf)-1] != '\n' &&
                 fgets(buf, sizeof(buf), msg->f));
    }

    /* Protect against messages not ending in CRLF */
    if (buf[strlen(buf)-1] != '\n') prot_printf(pout, "\r\n");

    prot_printf(pout, ".\r\n");

    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("2", buf, 1)) {
        syslog(LOG_ERR, "article %s transfer to peer failed", msg->id);
    }

  quit:
    prot_printf(pout, "QUIT\r\n");
    prot_flush(pout);

    prot_fgets(buf, sizeof(buf), pin);

    /* Flush the incoming buffer */
    prot_NONBLOCK(pin);
    prot_fill(pin);

    /* close/free socket & prot layer */
    close(sock);

    prot_free(pin);
    prot_free(pout);

    return;
}

static void news2mail(message_data_t *msg)
{
    struct buf attrib = BUF_INITIALIZER, msgbuf = BUF_INITIALIZER;
    int n, r;
    char buf[4096], to[1024] = "";

    smtp_envelope_t sm_env = SMTP_ENVELOPE_INITIALIZER;
    smtp_envelope_set_from(&sm_env, "");

    for (n = 0; n < msg->rcpt.count ; n++) {
        /* see if we want to send this to a mailing list */
        buf_free(&attrib);
        r = annotatemore_lookup(msg->rcpt.data[n],
                                IMAP_ANNOT_NS "news2mail", "",
                                &attrib);
        if (r) continue;

        /* add the email address to the RCPT envelope and to our To: header */
        if (attrib.s) {
            smtp_envelope_add_rcpt(&sm_env, buf_cstring(&attrib));
            if (to[0]) strlcat(to, ", ", sizeof(to));
            strlcat(to, buf_cstring(&attrib), sizeof(to));
        }
    }
    buf_free(&attrib);

    /* send the message */
    if (sm_env.rcpts.count) {
        smtpclient_t *sm = NULL;

        r = smtpclient_open(&sm);

        if (r)
            syslog(LOG_ERR, "news2mail: could not open SMTP client: %s", error_message(r));
        else {
            int body = 0, skip, found_to = 0;

            rewind(msg->f);

            while (fgets(buf, sizeof(buf), msg->f)) {
                if (!body && buf[0] == '\r' && buf[1] == '\n') {
                    /* blank line between header and body */
                    body = 1;

                    /* insert a To: header if the message doesn't have one */
                    if (!found_to) buf_printf(&msgbuf, "To: %s\r\n", to);
                }

                skip = 0;
                if (!body) {
                    /* munge various news-specific headers */
                    if (!strncasecmp(buf, "Newsgroups:", 11)) {
                        /* rename Newsgroups: to X-Newsgroups: */
                        buf_appendcstr(&msgbuf, "X-");
                    } else if (!strncasecmp(buf, "Xref:", 5) ||
                               !strncasecmp(buf, "Path:", 5) ||
                               !strncasecmp(buf, "NNTP-Posting-", 13)) {
                        /* skip these (for now) */
                        skip = 1;
                    } else if (!strncasecmp(buf, "To:", 3)) {
                        /* insert our mailing list RCPTs first, and then
                           fold the header to accomodate the original RCPTs */
                        buf_printf(&msgbuf, "To: %s,\r\n", to);
                        /* overwrite the original "To:" with spaces */
                        memset(buf, ' ', 3);
                        found_to = 1;
                    } else if (!strncasecmp(buf, "Reply-To:", 9)) {
                        /* strip any post addresses, skip if becomes empty */
                        if (!strip_post_addresses(buf+9)) skip = 1;
                    }
                }

                do {
                    if (!skip) buf_appendcstr(&msgbuf, buf);
                } while (buf[strlen(buf)-1] != '\n' &&
                         fgets(buf, sizeof(buf), msg->f));
            }

            /* Protect against messages not ending in CRLF */
            if (buf[strlen(buf)-1] != '\n') buf_appendcstr(&msgbuf, "\r\n");

        }

        r = smtpclient_open(&sm);
        if (!r) {
            r = smtpclient_send(sm, &sm_env, &msgbuf);
        }
        if (r) {
            syslog(LOG_ERR, "news2mail failed: %s", error_message(r));
        }
        smtpclient_close(&sm);
    }

    smtp_envelope_fini(&sm_env);
    buf_free(&msgbuf);

    return;
}

static void cmd_post(char *msgid, int mode)
{
    char *mboxname;
    FILE *f = NULL;
    message_data_t *msg;
    int r = 0;

    /* check if we want this article */
    if (msgid && my_find_msgid(msgid, &mboxname, NULL)) {
        /* already have it */
        syslog(LOG_INFO,
               "dupelim: news article id %s already present in mailbox %s",
               msgid, mboxname);
        r = NNTP_DONT_SEND;
    }

    if (mode != POST_TAKETHIS) {
        if (r) {
            prot_printf(nntp_out, "%u %s Do not send article\r\n",
                        post_codes[mode].no, msgid ? msgid : "");
            return;
        }
        else {
            prot_printf(nntp_out, "%u %s Send article\r\n",
                        post_codes[mode].cont, msgid ? msgid : "");
            if (mode == POST_CHECK) return;
        }
    }

    /* get a spool file (if needed) */
    if (!r) {
        f = tmpfile();
        if (!f) r = IMAP_IOERROR;
    }

    if (f) {
        msg_new(&msg);

        /* spool the article */
        r = savemsg(msg, f);

        /* deliver the article */
        if (!r) r = deliver(msg);

        if (!r) {
            prot_printf(nntp_out, "%u %s Article received ok\r\n",
                        post_codes[mode].ok, msg->id ? msg->id : "");
#if 0  /* XXX  Need to review control message auth/authz and implementation */
            /* process control messages */
            if (msg->control && !config_mupdate_server) {
                int r1 = 0;

                /* XXX check PGP signature */
                if (!strncmp(msg->control, "newgroup", 8))
                    r1 = newgroup(msg);
                else if (!strncmp(msg->control, "rmgroup", 7))
                    r1 = rmgroup(msg);
                else if (!strncmp(msg->control, "mvgroup", 7))
                    r1 = mvgroup(msg);
                else if (!strncmp(msg->control, "cancel", 6))
                    r1 = cancel(msg);
                else
                    r1 = NNTP_UNKNOWN_CONTROLMSG;

                if (r1)
                    syslog(LOG_WARNING, "control message '%s' failed: %s",
                           msg->control, error_message(r1));
                else {
                    syslog(LOG_INFO, "control message '%s' succeeded",
                           msg->control);
                }
            }
#endif
            if (msg->id) {
                const char *peers = config_getstring(IMAPOPT_NEWSPEER);

                /* send the article upstream */
                if (peers) {
                    char *tmpbuf, *cur_peer, *next_peer;

                    /* make a working copy of the peers */
                    cur_peer = tmpbuf = xstrdup(peers);

                    while (cur_peer) {
                        /* eat any leading whitespace */
                        while (Uisspace(*cur_peer)) cur_peer++;

                        /* find end of peer */
                        if ((next_peer = strchr(cur_peer, ' ')) ||
                            (next_peer = strchr(cur_peer, '\t')))
                            *next_peer++ = '\0';

                        /* feed the article to this peer */
                        feedpeer(cur_peer, msg);

                        /* move to next peer */
                        cur_peer = next_peer;
                    }

                    free(tmpbuf);
                }

                /* gateway news to mail */
                news2mail(msg);
            }
        }

        msg_free(msg); /* does fclose() */
        if (stage) append_removestage(stage);
        stage = NULL;
    }
    else {
        /* flush the article from the stream */
        spool_copy_msg(nntp_in, NULL);
    }

    if (r) {
        prot_printf(nntp_out, "%u %s Failed receiving article (%s)\r\n",
                    post_codes[mode].fail, msgid ? msgid : "",
                    error_message(r));
    }

    prot_flush(nntp_out);
}

#ifdef HAVE_SSL
static void cmd_starttls(int nntps)
{
    int result;

    if (nntp_starttls_done == 1) {
        prot_printf(nntp_out, "502 %s\r\n",
                    "TLS is already active");
        return;
    }
    if (nntp_authstate) {
        prot_printf(nntp_out, "502 %s\r\n",
                    "Already authenticated");
        return;
    }

    result=tls_init_serverengine("nntp",
                                 5,        /* depth to verify */
                                 !nntps,   /* can client auth? */
                                 NULL);

    if (result == -1) {

        syslog(LOG_ERR, "[nntpd] error initializing TLS");

        if (nntps == 0)
            prot_printf(nntp_out, "580 %s\r\n", "Error initializing TLS");
        else
            fatal("tls_init() failed",EX_TEMPFAIL);

        return;
    }

    if (nntps == 0)
    {
        prot_printf(nntp_out, "382 %s\r\n", "Begin TLS negotiation now");
        /* must flush our buffers before starting tls */
        prot_flush(nntp_out);
    }

    result=tls_start_servertls(0, /* read */
                               1, /* write */
                               nntps ? 180 : nntp_timeout,
                               &saslprops,
                               &tls_conn);

    /* if error */
    if (result == -1) {
        if (nntps == 0) {
            prot_printf(nntp_out, "580 Starttls failed\r\n");
            syslog(LOG_NOTICE, "[nntpd] STARTTLS failed: %s", nntp_clienthost);
            return;
        } else {
            syslog(LOG_NOTICE, "nntps failed: %s", nntp_clienthost);
            shut_down(0);
        }
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(&saslprops, nntp_saslconn);
    if (result != SASL_OK) {
        syslog(LOG_NOTICE, "saslprops_set_tls() failed: cmd_starttls()");
        if (nntps == 0) {
            fatal("saslprops_set_tls() failed: cmd_starttls()", EX_TEMPFAIL);
        } else {
            shut_down(0);
        }
    }

    /* tell the prot layer about our new layers */
    prot_settls(nntp_in, tls_conn);
    prot_settls(nntp_out, tls_conn);

    nntp_starttls_done = 1;
    nntp_tls_required = 0;

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    nntp_tls_comp = (void *) SSL_get_current_compression(tls_conn);
#endif

    /* close any selected group */
    if (group_state)
        index_close(&group_state);
    if (backend_current) {
        proxy_downserver(backend_current);
        backend_current = NULL;
    }
}
#else
static void cmd_starttls(int nntps __attribute__((unused)))
{
    /* XXX should never get here */
    fatal("cmd_starttls() called, but no OpenSSL", EX_SOFTWARE);
}
#endif /* HAVE_SSL */

#ifdef HAVE_ZLIB
static void cmd_compress(char *alg)
{
    if (nntp_compress_done) {
        prot_printf(nntp_out,
                    "502 DEFLATE compression already active via COMPRESS\r\n");
    }
#if defined(HAVE_SSL) && (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    else if (nntp_tls_comp) {
        prot_printf(nntp_out,
                    "502 %s compression already active via TLS\r\n",
                    SSL_COMP_get_name(nntp_tls_comp));
    }
#endif // defined(HAVE_SSL) && (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    else if (strcasecmp(alg, "DEFLATE")) {
        prot_printf(nntp_out,
                    "502 Unknown COMPRESS algorithm: %s\r\n", alg);
    }
    else if (ZLIB_VERSION[0] != zlibVersion()[0]) {
        prot_printf(nntp_out,
                    "403 Error initializing %s (incompatible zlib version)\r\n",
                    alg);
    }
    else {
        prot_printf(nntp_out,
                    "206 %s compression active\r\n", alg);

        /* enable (de)compression for the prot layer */
        prot_setcompress(nntp_in);
        prot_setcompress(nntp_out);

        nntp_compress_done = 1;
    }
}
#endif /* HAVE_ZLIB */
