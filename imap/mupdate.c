/* mupdate.c -- cyrus murder database master
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <errno.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#if !defined(SIOCGIFCONF) && defined(HAVE_SYS_SOCKIO_H)
# include <sys/sockio.h>
#endif
#include <net/if.h>

#include <pthread.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "mupdate.h"
#include "mupdate-client.h"
#include "telemetry.h"

#include "strarray.h"
#include "assert.h"
#include "global.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mpool.h"
#include "nonblock.h"
#include "prot.h"
#include "tls.h"
#include "tls_th-lock.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* Sent to clients that we can't accept a connection for. */
static const char SERVER_UNABLE_STRING[] = "* BYE \"Server Unable\"\r\n";

static const int NO_NEW_CONNECTION = -1;

static int masterp = 0;

typedef enum {
    DOCMD_OK = 0,
    DOCMD_CONN_FINISHED = 1
} mupdate_docmd_result_t;

enum {
    poll_interval = 1,
    update_wait = 5
};

struct pending {
    struct pending *next;

    char mailbox[MAX_MAILBOX_BUFFER];
};

struct conn {
    int fd;
    int logfd;

    struct protstream *pin;
    struct protstream *pout;
    sasl_conn_t *saslconn;
    char *userid;

#ifdef HAVE_SSL
    SSL *tlsconn;
#else
    void *tlsconn;
#endif
    void *tls_comp;     /* TLS compression method, if any */
    int compress_done;  /* have we done a successful compress? */

    int idle;

    char clienthost[NI_MAXHOST*2+1];

    struct saslprops_t saslprops;

    /* UPDATE command handling */
    const char *streaming; /* tag */
    strarray_t *streaming_hosts; /* partial updates */

    /* pending changes to send, in reverse order */
    pthread_mutex_t m;
    struct pending *plist;
    struct pending *ptail;
    struct conn *updatelist_next;
    struct prot_waitevent *ev; /* invoked every 'update_wait' seconds
                                  to send out updates */

    /* Prefix for list commands */
    const char *list_prefix;
    size_t list_prefix_len;

    /* For parsing */
    struct buf tag, cmd, arg1, arg2, arg3;

    /* For connection list management */
    struct conn *next;
    struct conn *next_idle;
};

static int ready_for_connections = 0;
static pthread_cond_t ready_for_connections_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t ready_for_connections_mutex = PTHREAD_MUTEX_INITIALIZER;

static int synced = 0;
static pthread_cond_t synced_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t synced_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t listener_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t listener_cond = PTHREAD_COND_INITIALIZER;
static int listener_lock = 0;

/* if you want to lock both listener and either of these two, you
 * must lock listener first.  You must have both listener_mutex and
 * idle_connlist_mutex locked to remove anything from the idle_connlist */
static pthread_mutex_t idle_connlist_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct conn *idle_connlist = NULL; /* protected by listener_mutex */
static pthread_mutex_t connection_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int connection_count = 0;
static pthread_mutex_t idle_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static int idle_worker_count = 0;
static pthread_mutex_t worker_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int worker_count = 0;

static pthread_mutex_t connlist_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct conn *connlist = NULL;

static pthread_mutex_t clienthost_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---- connection signaling pipe */
static int conn_pipe[2];

/* ---- database access ---- */
static pthread_mutex_t mailboxes_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct conn *updatelist = NULL;

/* --- prototypes --- */
static void conn_free(struct conn *C);
static mupdate_docmd_result_t docmd(struct conn *c);
static void cmd_authenticate(struct conn *C,
                      const char *tag, const char *mech,
                      const char *clientstart);
static void cmd_set(struct conn *C,
             const char *tag, const char *mailbox,
             const char *location, const char *acl, enum settype t);
static void cmd_find(struct conn *C, const char *tag, const char *mailbox,
              int send_ok, int send_delete);
static void cmd_list(struct conn *C, const char *tag, const char *host_prefix);
static void cmd_startupdate(struct conn *C, const char *tag,
                     strarray_t *partial);
static void cmd_starttls(struct conn *C, const char *tag);
#ifdef HAVE_ZLIB
static void cmd_compress(struct conn *C, const char *tag, const char *alg);
#endif
void shut_down(int code);
static int reset_saslconn(struct conn *c);
static void database_init(void);
static void sendupdates(struct conn *C, int flushnow);

extern int saslserver(sasl_conn_t *conn, const char *mech,
                      const char *init_resp, const char *resp_prefix,
                      const char *continuation, const char *empty_chal,
                      struct protstream *pin, struct protstream *pout,
                      int *sasl_result, char **success_data);

/* --- prototypes in mupdate-slave.c */
void *mupdate_client_start(void *rock);
void *mupdate_placebo_kick_start(void *rock);

/* --- main() for each thread */
static void *thread_main(void *rock);

/* --- for config.c */
const int config_need_data = 0;

static struct conn *conn_new(int fd)
{
    struct conn *C = xzmalloc(sizeof(struct conn));
    const char *clienthost, *localip, *remoteip;
    int r;

    C->fd = fd;
    C->logfd = -1;

    C->pin = prot_new(C->fd, 0);
    C->pout = prot_new(C->fd, 1);

    prot_setflushonread(C->pin, C->pout);
    prot_settimeout(C->pin, 180*60);

    C->pin->userdata = C->pout->userdata = C;

    pthread_mutex_lock(&connlist_mutex); /* LOCK */
    C->next = connlist;
    connlist = C;
    pthread_mutex_unlock(&connlist_mutex); /* UNLOCK */

    pthread_mutex_lock(&connection_count_mutex); /* LOCK */
    connection_count++;
    pthread_mutex_unlock(&connection_count_mutex); /* UNLOCK */

    /* Find out name of client host
     *
     * MUST do this inside a mutex because the values returned
     * from get_clienthost are all static to that function.
     */
    pthread_mutex_lock(&clienthost_mutex); /* LOCK */
    clienthost = get_clienthost(C->fd, &localip, &remoteip);
    strlcpy(C->clienthost, clienthost, sizeof(C->clienthost));

    if (localip && remoteip) {
        buf_setcstr(&C->saslprops.ipremoteport, remoteip);
        buf_setcstr(&C->saslprops.iplocalport, localip);
    }
    pthread_mutex_unlock(&clienthost_mutex); /* UNLOCK */

    /* create sasl connection */
    r = sasl_server_new("mupdate",
                        config_servername, NULL,
                        buf_cstringnull_ifempty(&C->saslprops.iplocalport),
                        buf_cstringnull_ifempty(&C->saslprops.ipremoteport),
                        NULL, 0,
                        &C->saslconn);
    if (r != SASL_OK) {
        syslog(LOG_ERR, "failed to start sasl for connection: %s",
               sasl_errstring(r, NULL, NULL));
        prot_printf(C->pout, SERVER_UNABLE_STRING);

        C->idle = 0;
        conn_free(C);
        return NULL;
    }

    /* set my allowable security properties */
    sasl_setprop(C->saslconn, SASL_SEC_PROPS, mysasl_secprops(SASL_SEC_NOANONYMOUS));

    return C;
}

static void conn_free(struct conn *C)
{
    assert(!C->idle); /* Not allowed to free idle connections */

    if (C->streaming) {         /* remove from updatelist */
        struct conn *upc;

        pthread_mutex_lock(&mailboxes_mutex);

        if (C == updatelist) {
            /* first thing in updatelist */
            updatelist = C->updatelist_next;
        } else {
            /* find in update list */
            for (upc = updatelist; upc->updatelist_next != NULL;
                 upc = upc->updatelist_next) {
                if (upc->updatelist_next == C) break;
            }
            /* must find it ! */
            assert(upc->updatelist_next == C);

            upc->updatelist_next = C->updatelist_next;
        }

        pthread_mutex_unlock(&mailboxes_mutex);
    }

    /* decrease connection counter */
    pthread_mutex_lock(&connection_count_mutex);
    connection_count--;
    pthread_mutex_unlock(&connection_count_mutex);

    /* remove from connlist */
    pthread_mutex_lock(&connlist_mutex); /* LOCK */
    if (C == connlist) {
        connlist = connlist->next;
    } else {
        struct conn *t;

        for (t = connlist; t->next != NULL; t = t->next) {
            if (t->next == C) break;
        }
        assert(t != NULL);
        t->next = C->next;
    }
    pthread_mutex_unlock(&connlist_mutex); /* UNLOCK */

    if (C->ev) prot_removewaitevent(C->pin, C->ev);

    prot_flush(C->pout);

    if (C->pin) prot_free(C->pin);
    if (C->pout) prot_free(C->pout);

#ifdef HAVE_SSL
    if (C->tlsconn) tls_reset_servertls(&C->tlsconn);
    tls_shutdown_serverengine();
#endif

    cyrus_close_sock(C->fd);
    if (C->logfd != -1) close(C->logfd);

    if (C->saslconn) sasl_dispose(&C->saslconn);

    saslprops_free(&C->saslprops);

    /* free struct bufs */
    buf_free(&(C->tag));
    buf_free(&(C->cmd));
    buf_free(&(C->arg1));
    buf_free(&(C->arg2));
    buf_free(&(C->arg3));

    if (C->streaming_hosts) strarray_free(C->streaming_hosts);

    free(C);
}

/*
 * The auth_*.c backends called by mysasl_proxy_policy()
 * use static variables which we need to protect with a mutex.
 */
static pthread_mutex_t proxy_policy_mutex = PTHREAD_MUTEX_INITIALIZER;

static int mupdate_proxy_policy(sasl_conn_t *conn,
                                void *context,
                                const char *requested_user, unsigned rlen,
                                const char *auth_identity, unsigned alen,
                                const char *def_realm,
                                unsigned urlen,
                                struct propctx *propctx)
{
    int r;

    pthread_mutex_lock(&proxy_policy_mutex); /* LOCK */

    r = mysasl_proxy_policy(conn, context, requested_user, rlen,
                            auth_identity, alen, def_realm, urlen, propctx);

    pthread_mutex_unlock(&proxy_policy_mutex); /* UNLOCK */

    return r;
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mupdate_proxy_policy, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/*
 * Is the IP address of the given hostname local?
 * Returns 1 if local, 0 otherwise.
 */
static int islocalip(const char *hostname)
{
    struct hostent *hp;
    struct in_addr *haddr, *iaddr;
    struct ifconf ifc;
    struct ifreq *ifr;
    char buf[8192]; /* XXX this limits us to 256 interfaces */
    int sock, islocal = 0;

    if ((hp = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "unknown host: %s\n", hostname);
        return 0;
    }

    haddr = (struct in_addr *) hp->h_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "socket() failed\n");
        return 0;
    }

    ifc.ifc_buf = buf;
    ifc.ifc_len = sizeof(buf);

    if (ioctl(sock, SIOCGIFCONF, &ifc) != 0) {
        fprintf(stderr, "ioctl(SIOCGIFCONF) failed: %d\n", errno);
        close(sock);
        return 0;
    }

    for (ifr = ifc.ifc_req; ifr - ifc.ifc_req < ifc.ifc_len; ifr++) {
        if (ioctl(sock, SIOCGIFADDR, ifr) != 0) continue;
        if (ioctl(sock, SIOCGIFFLAGS, ifr) != 0) continue;

        /* skip any inactive or loopback interfaces */
        if (!(ifr->ifr_flags & IFF_UP) || (ifr->ifr_flags & IFF_LOOPBACK))
            continue;

        iaddr = &(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr);

        /* compare the host address to the interface address */
        if (!memcmp(haddr, iaddr, sizeof(struct in_addr))) {
            islocal = 1;
            break;
        }
    }

    close(sock);

    return islocal;
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv,
                 char **envp __attribute__((unused)))
{
    int i, r, workers_to_start;
    int opt, autoselect = 0;
    pthread_t t;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    /* Do minor configuration checking */
    workers_to_start = config_getint(IMAPOPT_MUPDATE_WORKERS_START);

    if (config_getint(IMAPOPT_MUPDATE_WORKERS_MAX) < config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)) {
        syslog(LOG_CRIT, "Maximum total worker threads is less than minimum spare worker threads");
        return EX_SOFTWARE;
    }

    if (workers_to_start < config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)) {
        syslog(LOG_CRIT, "Starting worker threads is less than minimum spare worker threads");
        return EX_SOFTWARE;
    }

    if (config_getint(IMAPOPT_MUPDATE_WORKERS_MAXSPARE) < workers_to_start) {
        syslog(LOG_CRIT, "Maximum spare worker threads is less than starting worker threads");
        return EX_SOFTWARE;
    }

    if (config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE) > workers_to_start) {
        syslog(LOG_CRIT, "Minimum spare worker threads is greater than starting worker threads");
        return EX_SOFTWARE;
    }

    if (config_getint(IMAPOPT_MUPDATE_WORKERS_MAX) < workers_to_start) {
        syslog(LOG_CRIT, "Maximum total worker threads is less than starting worker threads");
        return EX_SOFTWARE;
    }

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    global_sasl_init(1, 1, mysasl_cb);

    /* see if we're the master or a slave */
    while ((opt = getopt(argc, argv, "ma")) != EOF) {
        switch (opt) {
        case 'm':
            masterp = 1;
            break;
        case 'a':
            autoselect = 1;
            break;
        default:
            break;
        }
    }

    if (!masterp && autoselect) masterp = islocalip(config_mupdate_server);

    if (masterp &&
        config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) {
        /* XXX  We currently prohibit this because mailboxes created
         * on the master will cause local mailbox entries to be propagated
         * to the slave.  We can probably fix this by prepending
         * config_servername onto the entries before updating the slaves.
         */
        fatal("cannot run mupdate master on a unified server", EX_USAGE);
    }

    if (pipe(conn_pipe) == -1) {
        syslog(LOG_ERR, "could not setup connection signaling pipe %m");
        return EX_OSERR;
    }

    database_init();

#ifdef HAVE_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_thread_setup();
#endif
#endif

    if (!masterp) {
        r = pthread_create(&t, NULL, &mupdate_client_start, NULL);
        if (r == 0) {
            pthread_detach(t);
        } else {
            syslog(LOG_ERR, "could not start client thread");
            return EX_SOFTWARE;
        }

        /* Wait until they sync the database */
        pthread_mutex_lock(&synced_mutex);
        if (!synced)
            pthread_cond_wait(&synced_cond, &synced_mutex);
        pthread_mutex_unlock(&synced_mutex);
    } else {
        pthread_t t;

        r = pthread_create(&t, NULL, &mupdate_placebo_kick_start, NULL);
        if (r == 0) {
            pthread_detach(t);
        } else {
            syslog(LOG_ERR, "could not start placebo kick thread");
            return EX_SOFTWARE;
        }

        mupdate_ready();
    }

    /* Now create the worker thread pool */
    for(i=0; i < workers_to_start; i++) {
        r = pthread_create(&t, NULL, &thread_main, NULL);
        if (r == 0) {
            pthread_detach(t);
        } else {
            syslog(LOG_ERR, "could not start client thread");
            return EX_SOFTWARE;
        }
    }

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
#ifdef HAVE_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_thread_cleanup();
#endif
#endif
    shut_down(error);
}

EXPORTED void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) exit(code);
    else recurse_code = code;

    syslog(LOG_ERR, "%s", s);
    shut_down(code);

    /* NOTREACHED */
    exit(code); /* shut up GCC */
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->pin); \
                                 if ((ch) != '\n') goto extraargs; } while (0)

static mupdate_docmd_result_t docmd(struct conn *c)
{
    mupdate_docmd_result_t ret = DOCMD_OK;
    int ch;
    int was_blocking = prot_IS_BLOCKING(c->pin);
    char *p;

    /* We know we have input, so skip the check below.
     * Note that we MUST skip this nonblocking check in order to properly
     * catch connections that have timed out.
     */
    goto cmd;

 nextcmd:
    /* First we do a check for input */
    prot_NONBLOCK(c->pin);
    ch = prot_getc(c->pin);

    if (ch == EOF && errno == EAGAIN) {
        /* no input from client */
        goto done;
    } else if (ch == EOF) {
        goto lost_conn;
    } else {
        /* there's input waiting, put back our character */
        prot_ungetc(ch, c->pin);
    }

    /* Set it back to blocking so we don't get half a word */
    prot_BLOCK(c->pin);

  cmd:
    ch = getword(c->pin, &(c->tag));
    if (ch == EOF) goto lost_conn;

    if (ch != ' ') {
        prot_printf(c->pout, "* BAD \"Need command\"\r\n");
        eatline(c->pin, ch);
        goto nextcmd;
    }

    /* parse command name */
    ch = getword(c->pin, &(c->cmd));
    if (ch == EOF) {
        goto lost_conn;
    } else if (!c->cmd.s[0]) {
        prot_printf(c->pout, "%s BAD \"Null command\"\r\n", c->tag.s);
        eatline(c->pin, ch);
        goto nextcmd;
    }

    if (Uislower(c->cmd.s[0])) {
        c->cmd.s[0] = toupper((unsigned char) c->cmd.s[0]);
    }
    for (p = &(c->cmd.s[1]); *p; p++) {
        if (Uisupper(*p)) *p = tolower((unsigned char) *p);
    }

    switch (c->cmd.s[0]) {
    case 'A':
        if (!strcmp(c->cmd.s, "Authenticate")) {
            int opt = 0;

            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            if (ch == ' ') {
                ch = getstring(c->pin, c->pout, &(c->arg2));
                opt = 1;
            }
            CHECKNEWLINE(c, ch);

            if (c->userid) {
                prot_printf(c->pout,
                            "%s BAD \"already authenticated\"\r\n",
                            c->tag.s);
                goto nextcmd;
            }

            cmd_authenticate(c, c->tag.s, c->arg1.s,
                             opt ? c->arg2.s : NULL);
        }
        else if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "Activate")) {
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg2));
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg3));
            CHECKNEWLINE(c, ch);

            if (c->streaming) goto notwhenstreaming;
            if (!masterp) goto masteronly;

            cmd_set(c, c->tag.s, c->arg1.s, c->arg2.s,
                    c->arg3.s, SET_ACTIVE);
        }
        else goto badcmd;
        break;

#ifdef HAVE_ZLIB
    case 'C':
        if (!strcmp(c->cmd.s, "Compress")) {
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            CHECKNEWLINE(c, ch);

            cmd_compress(c, c->tag.s, c->arg1.s);
        }
        else goto badcmd;
        break;
#endif

    case 'D':
        if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "Deactivate")) {
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg2));
            CHECKNEWLINE(c, ch);

            if (c->streaming) goto notwhenstreaming;
            if (!masterp) goto masteronly;

            cmd_set(c, c->tag.s, c->arg1.s, c->arg2.s,
                    NULL, SET_DEACTIVATE);
        }
        else if (!strcmp(c->cmd.s, "Delete")) {
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            CHECKNEWLINE(c, ch);

            if (c->streaming) goto notwhenstreaming;
            if (!masterp) goto masteronly;

            cmd_set(c, c->tag.s, c->arg1.s, NULL, NULL, SET_DELETE);
        }
        else goto badcmd;
        break;

    case 'F':
        if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "Find")) {
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            CHECKNEWLINE(c, ch);

            if (c->streaming) goto notwhenstreaming;

            cmd_find(c, c->tag.s, c->arg1.s, 1, 0);
        }
        else goto badcmd;
        break;

    case 'L':
        if (!strcmp(c->cmd.s, "Logout")) {
            CHECKNEWLINE(c, ch);

            prot_printf(c->pout, "%s OK \"bye-bye\"\r\n", c->tag.s);
            ret = DOCMD_CONN_FINISHED;
            goto done;
        }
        else if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "List")) {
            int opt = 0;

            if (ch == ' ') {
                /* Optional partition/host prefix parameter */
                ch = getstring(c->pin, c->pout, &(c->arg1));
                opt = 1;
            }
            CHECKNEWLINE(c, ch);

            if (c->streaming) goto notwhenstreaming;

            cmd_list(c, c->tag.s, opt ? c->arg1.s : NULL);

            prot_printf(c->pout, "%s OK \"list complete\"\r\n", c->tag.s);
        }
        else goto badcmd;
        break;

    case 'N':
        if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "Noop")) {
            CHECKNEWLINE(c, ch);

            if (c->streaming) {
                /* Make *very* sure we are up-to-date */
                kick_mupdate();
                sendupdates(c, 0); /* don't flush pout though */
            }

            prot_printf(c->pout, "%s OK \"Noop done\"\r\n", c->tag.s);
        }
        else goto badcmd;
        break;

    case 'R':
        if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "Reserve")) {
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg1));
            if (ch != ' ') goto missingargs;
            ch = getstring(c->pin, c->pout, &(c->arg2));
            CHECKNEWLINE(c, ch);

            if (c->streaming) goto notwhenstreaming;
            if (!masterp) goto masteronly;

            cmd_set(c, c->tag.s, c->arg1.s, c->arg2.s, NULL, SET_RESERVE);
        }
        else goto badcmd;
        break;

    case 'S':
        if (!strcmp(c->cmd.s, "Starttls")) {
            CHECKNEWLINE(c, ch);

            /* XXX  discard any input pipelined after STARTTLS */
            prot_flush(c->pin);

            if (!tls_enabled()) {
                /* we don't support starttls */
                goto badcmd;
            }

            /* if we've already done SASL fail */
            if (c->userid) {
                prot_printf(c->pout,
                            "%s BAD Can't Starttls after authentication\r\n",
                            c->tag.s);
                goto nextcmd;
            }

            /* if we've already done COMPRESS fail */
            if (c->compress_done) {
                prot_printf(c->pout,
                            "%s BAD Can't Starttls after Compress\r\n",
                            c->tag.s);
                goto nextcmd;
            }

            /* check if already did a successful tls */
            if (c->tlsconn) {
                prot_printf(c->pout,
                            "%s BAD Already did a successful Starttls\r\n",
                            c->tag.s);
                goto nextcmd;
            }
            cmd_starttls(c, c->tag.s);
        }
        else goto badcmd;
        break;

    case 'U':
        if (!c->userid) goto nologin;
        else if (!strcmp(c->cmd.s, "Update")) {
            strarray_t *arg = NULL;
            int counter = 30; /* limit on number of processed hosts */

            while(ch == ' ') {
                /* Hey, look, more bits of a PARTIAL-UPDATE command */
                ch = getstring(c->pin, c->pout, &(c->arg1));
                if (c->arg1.s[0] == '\0') {
                    strarray_free(arg);
                    goto badargs;
                }
                if (counter-- == 0) {
                    strarray_free(arg);
                    goto extraargs;
                }
                if (!arg) arg = strarray_new();
                strarray_append(arg, c->arg1.s);
            }

            CHECKNEWLINE(c, ch);
            if (c->streaming) goto notwhenstreaming;

            cmd_startupdate(c, c->tag.s, arg);
        }
        else goto badcmd;
        break;

    default:
    badcmd:
        prot_printf(c->pout, "%s BAD \"Unrecognized command\"\r\n",
                    c->tag.s);
        eatline(c->pin, ch);
        break;

    extraargs:
        prot_printf(c->pout, "%s BAD \"Extra arguments\"\r\n",
                    c->tag.s);
        eatline(c->pin, ch);
        break;

    badargs:
        prot_printf(c->pout, "%s BAD \"Badly formed arguments\"\r\n",
                    c->tag.s);
        eatline(c->pin, ch);
        break;

    missingargs:
        prot_printf(c->pout, "%s BAD \"Missing arguments\"\r\n",
                    c->tag.s);
        eatline(c->pin, ch);
        break;

    notwhenstreaming:
        prot_printf(c->pout, "%s BAD \"not legal when streaming\"\r\n",
                    c->tag.s);
        break;

    masteronly:
        prot_printf(c->pout,
                    "%s BAD \"read-only session\"\r\n",
                    c->tag.s);
        break;

    nologin:
        prot_printf(c->pout, "%s BAD Please login first\r\n", c->tag.s);
        eatline(c->pin, ch);
        break;
    }

    /* Check for more input */
    goto nextcmd;

 lost_conn:
    {
        const char *err;

        if ((err = prot_error(c->pin)) != NULL
            && strcmp(err, PROT_EOF_STRING)) {
            syslog(LOG_WARNING, "%s, closing connection", err);
            prot_printf(c->pout, "* BYE \"%s\"\r\n", err);
        }

        ret = DOCMD_CONN_FINISHED;
    }

 done:
    /* Restore the state of the input stream */
    if (was_blocking)
        prot_BLOCK(c->pin);
    else
        prot_NONBLOCK(c->pin);

    /* Necessary since we don't ever do a prot_read on an idle connection
     * in mupdate */
    prot_flush(c->pout);

    return ret;
}

/*
 * run for each accepted connection
 */
int service_main_fd(int fd,
                    int argc __attribute__((unused)),
                    char **argv __attribute__((unused)),
                    char **envp __attribute__((unused)))
{
    int flag;
    int r;

    /* First check that we can handle the new connection. */
    pthread_mutex_lock(&connection_count_mutex); /* LOCK */
    flag =
        (connection_count >= config_getint(IMAPOPT_MUPDATE_CONNECTIONS_MAX));
    pthread_mutex_unlock(&connection_count_mutex); /* UNLOCK */

    if (flag) {
        /* Do the nonblocking write, if it fails, too bad for them. */
        nonblock(fd, 1);
        r = write(fd,SERVER_UNABLE_STRING,sizeof(SERVER_UNABLE_STRING));
        close(fd);

        syslog(LOG_ERR,
               "Server too busy, dropping connection.");
        if (r) return 0; /* filthy hack to avoid warning on 'r' */
    } else if (write(conn_pipe[1], &fd, sizeof(fd)) == -1) {
        /* signal that a new file descriptor is available.
         * If it fails... */

        syslog(LOG_CRIT,
               "write to conn_pipe to signal new connection failed: %m");
        return EX_TEMPFAIL;
    }
    return 0;
}

/*
 * Issue the capability banner
 */
static void dobanner(struct conn *c)
{
    char slavebuf[4096];
    const char *mechs;
    int mechcount;
    int ret;

    /* send initial the banner + flush pout */
    ret = sasl_listmech(c->saslconn, NULL,
                        "* AUTH \"", "\" \"", "\"",
                        &mechs, NULL, &mechcount);

    /* Add mupdate:// tag if necessary */
    if (!masterp) {
        if (!config_mupdate_server)
            fatal("mupdate server was not specified for slave",
                  EX_TEMPFAIL);

        snprintf(slavebuf, sizeof(slavebuf), "mupdate://%s",
                 config_mupdate_server);
    }

    prot_printf(c->pout, "%s\r\n",
                (ret == SASL_OK && mechcount > 0) ? mechs : "* AUTH");

    if (tls_enabled() && !c->tlsconn) {
        prot_printf(c->pout, "* STARTTLS\r\n");
    }

#ifdef HAVE_ZLIB
    if (!c->compress_done && !c->tls_comp) {
        prot_printf(c->pout, "* COMPRESS \"DEFLATE\"\r\n");
    }
#endif

    prot_printf(c->pout, "* PARTIAL-UPDATE\r\n");

    prot_printf(c->pout,
                "* OK MUPDATE \"%s\" \"Cyrus IMAP\" \"%s\" \"%s\"\r\n",
                config_servername,
                CYRUS_VERSION, masterp ? "(master)" : slavebuf);

    prot_flush(c->pout);
}

/*
 * The main thread loop
 */
/* Note that You Must Lock Listen mutex before idle worker mutex,
 * though you can lock them individually too */
static void *thread_main(void *rock __attribute__((unused)))
{
    struct conn *C; /* used for loops */
    struct conn *currConn = NULL; /* the connection we care about currently */
    struct protgroup *protin = protgroup_new(PROTGROUP_SIZE_DEFAULT);
    struct protgroup *protout = NULL;
    struct timeval now;
    struct timespec timeout;
    int need_workers, too_many;
    int max_worker_flag;
    int do_a_command;
    int send_a_banner;
    int connflag;
    int new_fd;
    int ret = 0;
    struct conn *ni;

    /* Lock Worker Count Mutex */
    pthread_mutex_lock(&worker_count_mutex); /* LOCK */
    /* Change total number of workers */
    worker_count++;
    syslog(LOG_DEBUG,
           "New worker thread started, for a total of %d", worker_count);
    /* Unlock Worker Count Mutex */
    pthread_mutex_unlock(&worker_count_mutex); /* UNLOCK */

    /* This is a big infinite loop */
    while (1) {
        send_a_banner = do_a_command = 0;

        pthread_mutex_lock(&idle_worker_mutex);
        /* If we are over the limit on idle threads, die. */
        max_worker_flag = (idle_worker_count >=
                           config_getint(IMAPOPT_MUPDATE_WORKERS_MAXSPARE));
        /* Increment Idle Workers */
        if (!max_worker_flag) idle_worker_count++;
        pthread_mutex_unlock(&idle_worker_mutex);

        if (max_worker_flag) goto worker_thread_done;

    retry_lock:

        /* Lock Listen Mutex - If locking takes more than 60 seconds,
         * kill off this thread.  Ideally this is a FILO queue */
        pthread_mutex_lock(&listener_mutex); /* LOCK */
        ret = 0;
        while (listener_lock && ret != ETIMEDOUT) {
            gettimeofday(&now, NULL);
            timeout.tv_sec = now.tv_sec + 60;
            timeout.tv_nsec = now.tv_usec * 1000;
            ret = pthread_cond_timedwait(&listener_cond,
                                         &listener_mutex,
                                         &timeout);
        }
        if (!ret) {
            /* Set listener lock until we decide what to do */
            listener_lock = 1;
        }
        pthread_mutex_unlock(&listener_mutex); /* UNLOCK */

        if (ret == ETIMEDOUT) {
            pthread_mutex_lock(&idle_worker_mutex); /* LOCK */
            if (idle_worker_count <= config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)) {
                pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */
                /* below number of spare workers, try to get the lock again */
                goto retry_lock;
            } else {
                /* Decrement Idle Worker Count */
                idle_worker_count--;
                pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */

                syslog(LOG_DEBUG,
                       "Thread timed out waiting for listener_lock");
                goto worker_thread_done;
            }
        }

        signals_poll();

        /* Check if we are ready for connections, if not, wait */
        pthread_mutex_lock(&ready_for_connections_mutex); /* LOCK */
        /* are we ready to take connections? */
        while (!ready_for_connections) {
            pthread_cond_wait(&ready_for_connections_cond,
                              &ready_for_connections_mutex);
        }
        pthread_mutex_unlock(&ready_for_connections_mutex); /* UNLOCK */

        connflag = 0;

        /* Reset protin to all zeros (to preserve memory allocation) */
        protgroup_reset(protin);

        /* Clear protout if needed */
        protgroup_free(protout);
        protout = NULL;

        /* Build list of idle protstreams */
        pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
        for (C=idle_connlist; C; C=C->next_idle) {
            assert(C->idle);

            protgroup_insert(protin, C->pin);
        }
        pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

        /* Select on Idle Conns + conn_pipe */
        if (prot_select(protin, conn_pipe[0],
                       &protout, &connflag, NULL) == -1) {
            syslog(LOG_ERR, "prot_select() failed in thread_main: %m");
            fatal("prot_select() failed in thread_main", EX_TEMPFAIL);
        }

        /* we've got work to do */
        pthread_mutex_lock(&idle_worker_mutex); /* LOCK */
        idle_worker_count--;
        pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */

        /* If we've been signaled to be unready, drop all current connections
         * in the idle list */
        pthread_mutex_lock(&ready_for_connections_mutex); /* LOCK */
        if (!ready_for_connections) {
            pthread_mutex_unlock(&ready_for_connections_mutex); /* UNLOCK */
            /* Free all connections on idle_connlist.  Note that
             * any connection not currently on the idle_connlist will
             * instead be freed when they drop out of their docmd() below */

            pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
            for (C=idle_connlist; C; C = ni) {
                ni = C->next_idle;

                prot_printf(C->pout,
                            "* BYE \"no longer ready for connections\"\r\n");

                C->idle = 0;
                conn_free(C);
            }
            idle_connlist = NULL;
            pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

            goto nextlistener;
        }
        pthread_mutex_unlock(&ready_for_connections_mutex); /* UNLOCK */

        if (connflag) {
            /* read the fd from the pipe, if needed */
            if (read(conn_pipe[0], &new_fd, sizeof(new_fd)) == -1) {
                syslog(LOG_CRIT,
                       "read from conn_pipe for new connection failed: %m");
                fatal("conn_pipe read failed", EX_TEMPFAIL);
            }
        } else {
            new_fd = NO_NEW_CONNECTION;
        }

        if (new_fd != NO_NEW_CONNECTION) {
            /* new_fd indicates a new connection */
            currConn = conn_new(new_fd);
            if (currConn)
                send_a_banner = 1;
        } else if (protout) {
            /* Handle existing connection, we'll need to pull it off
             * the idle_connlist */
            struct protstream *ptmp;
            struct conn **prev;

            pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */

            /* Grab the first connection out of the ready set, and use it */
            ptmp = protgroup_getelement(protout, 0);
            assert(ptmp);
            currConn = ptmp->userdata;
            assert(currConn);
            assert(currConn->idle);

            currConn->idle = 0;
            for (C=idle_connlist, prev = &(idle_connlist); C;
                    prev = &(C->next_idle), C=C->next_idle) {
                if (C == currConn) {
                    *prev = C->next_idle;
                    C->next_idle = NULL;
                    break;
                }
            }
            pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

            do_a_command = 1;
        }

        /*
         * If this worker will do any real work, we'll want to make sure
         * there are sufficient additional workers while we're busy.
         */
        if (send_a_banner || do_a_command) {
            pthread_mutex_lock(&idle_worker_mutex); /* LOCK */
            need_workers = config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)
                            - idle_worker_count;
            pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */

            pthread_mutex_lock(&worker_count_mutex); /* LOCK */
            if (need_workers > 0) {
                too_many = (need_workers + worker_count) -
                    config_getint(IMAPOPT_MUPDATE_WORKERS_MAX);
                if (too_many > 0) need_workers -= too_many;
            }
            pthread_mutex_unlock(&worker_count_mutex); /* UNLOCK */

            /* Do we need a new worker (or two, or three...)?
             * (are we allowed to create one?) */
            while (need_workers > 0) {
                pthread_t t;
                int r = pthread_create(&t, NULL, &thread_main, NULL);
                if (r == 0) {
                    pthread_detach(t);
                } else {
                    syslog(LOG_ERR,
                           "could not start a new worker thread (not fatal)");
                }
                /* Even if we fail to create the new thread, keep going */
                need_workers--;
            }
        }

    nextlistener:
        /* Let another listener in */
        pthread_mutex_lock(&listener_mutex);
        assert(listener_lock);
        listener_lock = 0;
        pthread_cond_signal(&listener_cond);
        pthread_mutex_unlock(&listener_mutex);

        /* Do work in this thread, if needed */
        if (send_a_banner) {
            dobanner(currConn);
        } else if (do_a_command) {
            assert(currConn);

            if (docmd(currConn) == DOCMD_CONN_FINISHED) {
                conn_free(currConn);
                /* continue to top of loop here since we won't be adding
                 * this back to the idle list */
                continue;
            }

            /* Are we allowed to continue serving data? */
            pthread_mutex_lock(&ready_for_connections_mutex); /* LOCK */
            if (!ready_for_connections) {
                pthread_mutex_unlock(&ready_for_connections_mutex); /* UNLOCK */
                prot_printf(C->pout,
                            "* BYE \"no longer ready for connections\"\r\n");
                conn_free(currConn);
                /* continue to top of loop here since we won't be adding
                 * this back to the idle list */
                continue;
            }
            pthread_mutex_unlock(&ready_for_connections_mutex); /* UNLOCK */
        } /* done handling command */

        if (send_a_banner || do_a_command) {
            /* We did work in this thread, so we need to [re-]add the
             * connection to the idle list and signal the current listener */

            pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
            currConn->idle = 1;
            currConn->next_idle = idle_connlist;
            idle_connlist = currConn;
            pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

            /* Signal to our caller that we should add something
             * to select() on, since this connection is ready again */
            if (write(conn_pipe[1], &NO_NEW_CONNECTION,
                     sizeof(NO_NEW_CONNECTION)) == -1) {
                fatal("write to conn_pipe to signal docmd done failed",
                      EX_TEMPFAIL);
            }
        }

    } /* while(1) */

 worker_thread_done:
    /* Remove this worker from the pool */
    /* Note that workers exiting the loop above should NOT be counted
     * in the idle_worker_count */
    pthread_mutex_lock(&worker_count_mutex); /* LOCK */
    worker_count--;
    pthread_mutex_lock(&idle_worker_mutex); /* LOCK */
    syslog(LOG_DEBUG,
           "Worker thread finished, for a total of %d (%d spare)",
           worker_count, idle_worker_count);
    pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */
    pthread_mutex_unlock(&worker_count_mutex); /* UNLOCK */

    protgroup_free(protin);
    protgroup_free(protout);

    return NULL;
}

/* read from disk database must be unlocked. */
static void database_init(void)
{
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
}

/* log change to database. database must be locked. */
static void database_log(const struct mbent *mb, struct txn **mytid)
{
    char *c;
    mbentry_t *mbentry = NULL;

    mbentry = mboxlist_entry_create();
    mbentry->name = xstrdupnull(mb->mailbox);

    mbentry->server = xstrdupnull(mb->location);

    c = strchr(mbentry->server, '!');
    if (c) {
        *c++ = '\0';
        mbentry->partition = xstrdupnull(c);
    }

    mbentry->acl = xstrdupnull(mb->acl);

    switch (mb->t) {
    case SET_ACTIVE:
        mbentry->mbtype = 0;
        mboxlist_insertremote(mbentry, mytid);
        break;

    case SET_RESERVE:
        mbentry->mbtype |= MBTYPE_RESERVE;
        mboxlist_insertremote(mbentry, mytid);
        break;

    case SET_DELETE:
        mboxlist_deleteremote(mb->mailbox, mytid);
        break;

    case SET_DEACTIVATE:
        /* SET_DEACTIVATE is not a real value that an actual
           mailbox can have! */
        abort();
    }

    mboxlist_entry_free(&mbentry);
}

/* lookup in database. database must be locked */
/* This could probably be more efficient and avoid some copies */
/* passing in a NULL pool implies that we should use regular xmalloc,
 * a non-null pool implies we should use the mpool functionality */
static struct mbent *database_lookup(const char *name, const mbentry_t *mbentry,
                                     struct mpool *pool)
{
    mbentry_t *my_mbentry = NULL;
    struct mbent *out;
    char *location = NULL;
    int r;

    if (!name) return NULL;

    if (!mbentry) {
        r = mboxlist_lookup_allow_all(name, &my_mbentry, NULL);
        if (r) return NULL;
        mbentry = my_mbentry;
    }

    /* XXX - if mbtype & MBTYPE_DELETED, maybe set a delete */

    if (mbentry->mbtype & MBTYPE_RESERVE) {
        if (!pool) out = xmalloc(sizeof(struct mbent) + 1);
        else out = mpool_malloc(pool, sizeof(struct mbent) + 1);
        out->t = SET_RESERVE;
        out->acl[0] = '\0';
    }
    else {
        if (!pool) out = xmalloc(sizeof(struct mbent) + strlen(mbentry->acl));
        else out = mpool_malloc(pool, sizeof(struct mbent) + strlen(mbentry->acl));
        out->t = SET_ACTIVE;
        strcpy(out->acl, mbentry->acl);
    }

    if (mbentry->server && mbentry->partition)
        location = strconcat(mbentry->server, "!", mbentry->partition, NULL);
    else if (mbentry->server)
        location = xstrdup(mbentry->server);
    else if (mbentry->partition)
        location = xstrdup(mbentry->partition);
    else
        location = xstrdup("");

    if (pool) {
        out->mailbox = mpool_strdup(pool, name);
        out->location = mpool_strdup(pool, location);
        free(location);
    }
    else {
        out->mailbox = xstrdup(name);
        out->location = location;
    }

    if (my_mbentry) mboxlist_entry_free(&my_mbentry);

    return out;
}

static void cmd_authenticate(struct conn *C,
                      const char *tag, const char *mech,
                      const char *clientstart)
{
    int r, sasl_result;
    const void *val;
    int failedloginpause;

    r = saslserver(C->saslconn, mech, clientstart, "", "", "",
                   C->pin, C->pout, &sasl_result, NULL);

    if (r) {
        const char *errorstring = NULL;
        const char *userid = "-notset-";

        switch (r) {
        case IMAP_SASL_CANCEL:
            prot_printf(C->pout,
                        "%s NO Client canceled authentication\r\n", tag);
            break;
        case IMAP_SASL_PROTERR:
            errorstring = prot_error(C->pin);

            prot_printf(C->pout,
                        "%s NO Error reading client response: %s\r\n",
                        tag, errorstring ? errorstring : "");
            break;
        default:
            failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
            if (failedloginpause != 0) {
                sleep(failedloginpause);
            }

            if (r != SASL_NOUSER)
                sasl_getprop(C->saslconn, SASL_USERNAME, (const void **) &userid);

            syslog(LOG_ERR, "badlogin: %s %s (%s) [%s]",
                   C->clienthost,
                   mech, userid, sasl_errdetail(C->saslconn));

            prot_printf(C->pout, "%s NO \"%s\"\r\n", tag,
                        sasl_errstring((r == SASL_NOUSER ? SASL_BADAUTH : r),
                                       NULL, NULL));
        }

        reset_saslconn(C);
        return;
    }

    /* Successful Authentication */
    r = sasl_getprop(C->saslconn, SASL_USERNAME, &val);
    if (r != SASL_OK) {
        prot_printf(C->pout, "%s NO \"SASL Error\"\r\n", tag);
        reset_saslconn(C);
        return;
    }

    C->userid = (char *) val;
    syslog(LOG_NOTICE, "login: %s %s %s%s %s", C->clienthost, C->userid,
           mech, C->tlsconn ? "+TLS" : "", "User logged in");

    prot_printf(C->pout, "%s OK \"Authenticated\"\r\n", tag);

    prot_setsasl(C->pin, C->saslconn);
    prot_setsasl(C->pout, C->saslconn);

    C->logfd = telemetry_log(C->userid, C->pin, C->pout, 1);

    return;
}

/* Log the update out to anyone who is in our updatelist */
/* INVARIANT: caller MUST hold mailboxes_mutex */
/* oldlocation is the previous value of the location in this update,
   thislocation is the current value of the mailbox's location */
static void log_update(const char *mailbox,
                const char *oldlocation,
                const char *thislocation)
{
    struct conn *upc;

    for (upc = updatelist; upc != NULL; upc = upc->updatelist_next) {
        /* for each connection, add to pending list */
        struct pending *p = (struct pending *) xmalloc(sizeof(struct pending));
        p->next = NULL;
        strlcpy(p->mailbox, mailbox, sizeof(p->mailbox));

        /* this might need to be inside the mutex, but I doubt it */
        if (upc->streaming_hosts
           && (!oldlocation || strarray_find(upc->streaming_hosts,
                                                  oldlocation, 0) < 0)
           && (!thislocation || strarray_find(upc->streaming_hosts,
                                                   thislocation, 0) < 0)) {
            /* No Match! Continue! */
            continue;
        }

        pthread_mutex_lock(&upc->m);

        if ( upc->plist == NULL ) {
            upc->plist = upc->ptail = p;
        } else {
            upc->ptail->next = p;
            upc->ptail = p;
        }

        pthread_mutex_unlock(&upc->m);
    }
}

static void cmd_set(struct conn *C,
             const char *tag, const char *mailbox,
             const char *location, const char *acl, enum settype t)
{
    struct mbent *m;
    char *oldlocation = NULL;
    char *thislocation = NULL;
    char *tmp;

    /* Hold any output that we need to do */
    enum {
        EXISTS, NOTACTIVE, DOESNTEXIST, ISOK, NOOUTPUT
    } msg = NOOUTPUT;

    syslog(LOG_DEBUG, "cmd_set(fd:%d, %s)", C->fd, mailbox);

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    m = database_lookup(mailbox, NULL, NULL);
    if (m && t == SET_RESERVE) {
        /* Check if we run in a discrete murder topology */
        if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD) {
            /* Replicated backends with the same server name issue
             * reservations twice. Suppress bailing out on the second one
             * (the replica).
             */
            if (strcmp(m->location, location)) {
                /* failed; mailbox already exists */
                msg = EXISTS;
                goto done;
            }
        }
        /* otherwise do nothing (local create on master) */
    }

    if ((!m || m->t != SET_ACTIVE) && t == SET_DEACTIVATE) {
        /* Check if we run in a discrete murder topology */
        if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD) {
            /* Replicated backends with the same server name issue
             * deactivation twice. Suppress bailing out on the second one
             * (the replica).
             */
            if (strcmp(m->location, location)) {
                /* failed; mailbox not currently active */
                msg = NOTACTIVE;
                goto done;
            }
        }
    } else if (t == SET_DEACTIVATE) {
        t = SET_RESERVE;
    }

    if (t == SET_DELETE) {
        if (!m) {
            /* Check if we run in a discrete murder topology */
            if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD) {
                /* Replicated backends with the same server name issue
                 * deletion twice. Suppress bailing out on the second one
                 * (the replica).
                 */
                if (strcmp(m->location, location)) {
                    /* failed; mailbox doesn't exist */
                    msg = DOESNTEXIST;
                    goto done;
                }
            }
            /* otherwise do nothing (local delete on master) */
        } else {
            oldlocation = xstrdup(m->location);

            /* do the deletion */
            m->t = SET_DELETE;
        }
    } else {
        if (m)
            oldlocation = m->location;

        if (m && (!acl || strlen(acl) < strlen(m->acl))) {
            /* change what's already there -- the acl is smaller */
            m->location = xstrdup(location);
            if (acl) strcpy(m->acl, acl);
            else m->acl[0] = '\0';

            m->t = t;
        } else {
            char *thismailbox = m ? m->mailbox : xstrdup(mailbox);
            struct mbent *newm;

            /* allocate new mailbox */
            if (acl) {
                newm = xrealloc(m, sizeof(struct mbent) + strlen(acl));
            } else {
                newm = xrealloc(m, sizeof(struct mbent) + 1);
            }
            newm->mailbox = thismailbox;
            newm->location = xstrdup(location);

            if (acl) {
                strcpy(newm->acl, acl);
            } else {
                newm->acl[0] = '\0';
            }

            newm->t = t;

            /* re-scope */
            m = newm;
        }
    }

    /* write to disk */
    if (m) database_log(m, NULL);

    if (oldlocation) {
        tmp = strchr(oldlocation, '!');
        if (tmp) *tmp = '\0';
    }

    if (location) {
        thislocation = xstrdup(location);
        tmp = strchr(thislocation, '!');
        if (tmp) *tmp = '\0';
    }

    /* post pending changes */
    log_update(mailbox, oldlocation, thislocation);

    msg = ISOK;
 done:
    if (thislocation) free(thislocation);
    if (oldlocation) free(oldlocation);
    free_mbent(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    /* Delay output until here to avoid blocking while holding
     * mailboxes_mutex */
    switch(msg) {
    case EXISTS:
        prot_printf(C->pout, "%s NO \"mailbox already exists\"\r\n", tag);
        break;
    case NOTACTIVE:
        prot_printf(C->pout, "%s NO \"mailbox not currently active\"\r\n",
                    tag);
        break;
    case DOESNTEXIST:
        prot_printf(C->pout, "%s NO \"mailbox doesn't exist\"\r\n", tag);
        break;
    case ISOK:
        prot_printf(C->pout, "%s OK \"done\"\r\n", tag);
        break;
    default:
        break;
    }
}

static void cmd_find(struct conn *C, const char *tag, const char *mailbox,
              int send_ok, int send_delete)
{
    struct mbent *m;

    syslog(LOG_DEBUG, "cmd_find(fd:%d, %s)", C->fd, mailbox);

    /* Only hold the mutex around database_lookup,
     * since the mbent stays valid even if the database changes,
     * and we don't want to block on network I/O */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */
    m = database_lookup(mailbox, NULL, NULL);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    if (m && m->t == SET_ACTIVE) {
        prot_printf(C->pout,
                "%s MAILBOX "
                "{" SIZE_T_FMT "+}\r\n%s "
                "{" SIZE_T_FMT "+}\r\n%s "
                "{" SIZE_T_FMT "+}\r\n%s\r\n",
                tag,
                strlen(m->mailbox), m->mailbox,
                strlen(m->location), m->location,
                strlen(m->acl), m->acl
            );

    } else if (m && m->t == SET_RESERVE) {
        prot_printf(C->pout,
                "%s RESERVE "
                "{" SIZE_T_FMT "+}\r\n%s "
                "{" SIZE_T_FMT "+}\r\n%s\r\n",
                tag,
                strlen(m->mailbox), m->mailbox,
                strlen(m->location), m->location
            );
    } else if (send_delete) {
        /* not found, if needed, send a delete */
        prot_printf(C->pout,
                "%s DELETE "
                "{" SIZE_T_FMT "+}\r\n%s\r\n",
                tag,
                strlen(mailbox), mailbox
            );
    }

    free_mbent(m);

    if (send_ok) {
        prot_printf(C->pout, "%s OK \"Search completed\"\r\n", tag);
    }
}

/* Callback for cmd_startupdate to be passed to mboxlist_allmbox. */
/* Requires that C->streaming be set to the tag to respond with */
static int sendupdate(const mbentry_t *mbentry, void *rock)
{
    struct conn *C = (struct conn *)rock;
    struct mbent *m;

    if (!C) return -1;

    m = database_lookup(mbentry->name, mbentry, NULL);
    if (!m) return -1;

    if (!C->list_prefix ||
       !strncmp(m->location, C->list_prefix, C->list_prefix_len)) {
        /* Either there is not a prefix to test, or we matched it */

        if (!C->streaming_hosts ||
            strarray_find(C->streaming_hosts, mbentry->server, 0) >= 0) {
            switch (m->t) {
            case SET_ACTIVE:
                prot_printf(C->pout,
                        "%s MAILBOX "
                        "{" SIZE_T_FMT "+}\r\n%s "
                        "{" SIZE_T_FMT "+}\r\n%s "
                        "{" SIZE_T_FMT "+}\r\n%s\r\n",
                        C->streaming,
                        strlen(m->mailbox), m->mailbox,
                        strlen(m->location), m->location,
                        strlen(m->acl), m->acl
                    );

                break;
            case SET_RESERVE:
                prot_printf(C->pout,
                        "%s RESERVE "
                        "{" SIZE_T_FMT "+}\r\n%s "
                        "{" SIZE_T_FMT "+}\r\n%s\r\n",
                        C->streaming,
                        strlen(m->mailbox), m->mailbox,
                        strlen(m->location), m->location
                    );

                break;

            case SET_DELETE:
                /* deleted item in the list !?! */
            case SET_DEACTIVATE:
                /* SET_DEACTIVATE is not a real value! */
                abort();
            }
        }
    }

    free_mbent(m);
    return 0;
}

static void cmd_list(struct conn *C, const char *tag, const char *host_prefix)
{
    /* List operations can result in a lot of output, let's do this
     * with the prot layer nonblocking so we don't hold the mutex forever*/
    prot_NONBLOCK(C->pout);

    /* indicate interest in updates */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    /* since this isn't valid when streaming, just use the same callback */
    C->streaming = tag;
    C->list_prefix = host_prefix;
    if (C->list_prefix) C->list_prefix_len = strlen(C->list_prefix);
    else C->list_prefix_len = 0;

    mboxlist_allmbox("", sendupdate, (void*)C, /*flags*/0);

    C->streaming = NULL;
    C->list_prefix = NULL;
    C->list_prefix_len = 0;

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    prot_BLOCK(C->pout);
    prot_flush(C->pout);
}


/*
 * we've registered this connection for streaming, and every X seconds
 * this will be invoked.  note that we always send out updates as soon
 * as we get a noop: that resets this counter back */
static struct prot_waitevent *sendupdates_evt(struct protstream *s __attribute__((unused)),
                                       struct prot_waitevent *ev,
                                       void *rock)
{
    struct conn *C = (struct conn *) rock;

    sendupdates(C, 1);

    /* 'sendupdates()' will update when we next trigger */
    return ev;
}

static void cmd_startupdate(struct conn *C, const char *tag,
                     strarray_t *partial)
{
    /* initialize my condition variable */

    /* The inital dump of the database can result in a lot of data,
     * let's do this nonblocking */
    prot_NONBLOCK(C->pout);

    /* indicate interest in updates */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    C->updatelist_next = updatelist;
    updatelist = C;
    C->streaming = xstrdup(tag);
    C->streaming_hosts = partial;

    /* dump initial list */
    mboxlist_allmbox("", sendupdate, (void*)C, /*flags*/0);

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    prot_printf(C->pout, "%s OK \"streaming starts\"\r\n", tag);

    prot_BLOCK(C->pout);
    prot_flush(C->pout);

    /* schedule our first update */
    C->ev = prot_addwaitevent(C->pin, time(NULL) + update_wait,
                              sendupdates_evt, C);
}

/* send out any pending updates.
   if 'flushnow' is set, flush the output buffer */
static void sendupdates(struct conn *C, int flushnow)
{
    struct pending *p, *q;

    pthread_mutex_lock(&C->m);

    /* just grab the update list and release the lock */
    p = C->plist;
    C->plist = NULL;
    C->ptail = NULL;
    pthread_mutex_unlock(&C->m);

    while (p != NULL) {
        /* send update */
        q = p;
        p = p->next;

        /* notify just like a FIND - except enable sending of DELETE
         * notifications */
        cmd_find(C, C->streaming, q->mailbox, 0, 1);

        free(q);
    }

    /* reschedule event for 'update_wait' seconds */
    C->ev->mark = time(NULL) + update_wait;

    if (flushnow) {
        prot_flush(C->pout);
    }
}

#ifdef HAVE_SSL
static void cmd_starttls(struct conn *C, const char *tag)
{
    int result;

    result=tls_init_serverengine("mupdate",
                                 5,        /* depth to verify */
                                 1,        /* can client auth? */
                                 NULL);

    if (result == -1) {

        syslog(LOG_ERR, "error initializing TLS");

        prot_printf(C->pout, "%s NO Error initializing TLS\r\n", tag);

        return;
    }

    prot_printf(C->pout, "%s OK Begin TLS negotiation now\r\n", tag);
    /* must flush our buffers before starting tls */
    prot_flush(C->pout);

    result=tls_start_servertls(C->pin->fd, /* read */
                               C->pout->fd, /* write */
                               180, /* 3 minutes */
                               &C->saslprops,
                               &C->tlsconn);

    /* if error */
    if (result==-1) {
        prot_printf(C->pout, "%s NO Starttls negotiation failed\r\n",
                    tag);
        syslog(LOG_NOTICE, "STARTTLS negotiation failed: %s",
               C->clienthost);
        return;
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(&C->saslprops, C->saslconn);
    if (result != SASL_OK) {
        fatal("saslprops_set_tls() failed: cmd_starttls()", EX_TEMPFAIL);
    }

    /* tell the prot layer about our new layers */
    prot_settls(C->pin, C->tlsconn);
    prot_settls(C->pout, C->tlsconn);

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    C->tls_comp = (void *) SSL_get_current_compression(C->tlsconn);
#endif

    /* Reissue capability banner */
    dobanner(C);
}
#else
void cmd_starttls(struct conn *C __attribute__((unused)),
                  const char *tag __attribute__((unused)))
{
    fatal("cmd_starttls() executed, but starttls isn't implemented!",
          EX_SOFTWARE);
}
#endif /* HAVE_SSL */

#ifdef HAVE_ZLIB
static void cmd_compress(struct conn *C, const char *tag, const char *alg)
{
    if (C->compress_done) {
        prot_printf(C->pout,
                    "%s BAD DEFLATE active via COMPRESS\r\n", tag);
    }
#if defined(HAVE_SSL) && (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    else if (C->tls_comp) {
        prot_printf(C->pout,
                    "%s NO %s active via TLS\r\n",
                    tag, SSL_COMP_get_name(C->tls_comp));
    }
#endif
    else if (strcasecmp(alg, "DEFLATE")) {
        prot_printf(C->pout,
                    "%s NO Unknown COMPRESS algorithm: %s\r\n", tag, alg);
    }
    else if (ZLIB_VERSION[0] != zlibVersion()[0]) {
        prot_printf(C->pout,
                    "%s NO Error initializing %s (incompatible zlib version)\r\n",
                    tag, alg);
    }
    else {
        prot_printf(C->pout,
                    "%s OK %s active\r\n", tag, alg);

        /* enable (de)compression for the prot layer */
        prot_setcompress(C->pin);
        prot_setcompress(C->pout);

        C->compress_done = 1;
    }
}
#else
void cmd_compress(struct conn *C __attribute__((unused)),
                  const char *tag __attribute__((unused)),
                  const char *alg __attribute__((unused)))
{
    fatal("cmd_compress() executed, but COMPRESS isn't implemented!",
          EX_SOFTWARE);
}
#endif /* HAVE_ZLIB */

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    cyrus_done();

    exit(code);
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(struct conn *c)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(&c->saslconn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("mupdate", config_servername, NULL,
                          buf_cstringnull_ifempty(&c->saslprops.iplocalport),
                          buf_cstringnull_ifempty(&c->saslprops.ipremoteport),
                          NULL, 0, &c->saslconn);
    if (ret != SASL_OK) return ret;

    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    ret = sasl_setprop(c->saslconn, SASL_SEC_PROPS, secprops);
    if (ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if (c->saslprops.ssf) {
        ret = saslprops_set_tls(&c->saslprops, c->saslconn);
    }
    if (ret != SASL_OK) return ret;
    /* End TLS/SSL Info */

    return SASL_OK;
}

int cmd_change(struct mupdate_mailboxdata *mdata,
               const char *rock, void *context __attribute__((unused)))
{
    struct mbent *m = NULL;
    char *oldlocation = NULL;
    char *thislocation = NULL;
    char *tmp;
    enum settype t = -1;
    int ret = 0;

    if (!mdata || !rock || !mdata->mailbox) return 1;

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    if (!strncmp(rock, "DELETE", 6)) {
        m = database_lookup(mdata->mailbox, NULL, NULL);

        if (!m) {
            syslog(LOG_DEBUG, "attempt to delete unknown mailbox %s",
                   mdata->mailbox);
            /* Mailbox doesn't exist - this isn't as fatal as you might
             * think. */
            /* ret = -1; */
            goto done;
        }
        m->t = t = SET_DELETE;

        oldlocation = xstrdup(m->location);
    } else {
        m = database_lookup(mdata->mailbox, NULL, NULL);

        if (m)
            oldlocation = m->location;

        if (m && (!mdata->acl || strlen(mdata->acl) < strlen(m->acl))) {
            /* change what's already there */
            /* old m->location freed when oldlocation is freed */
            m->location = xstrdup(mdata->location);

            if (mdata->acl) strcpy(m->acl, mdata->acl);
            else m->acl[0] = '\0';

            if (!strncmp(rock, "MAILBOX", 6)) {
                m->t = t = SET_ACTIVE;
            } else if (!strncmp(rock, "RESERVE", 7)) {
                m->t = t = SET_RESERVE;
            } else {
                syslog(LOG_DEBUG,
                       "bad mupdate command in cmd_change: %s", rock);
                ret = 1;
                goto done;
            }
        } else {
            struct mbent *newm;

            if (m) {
                free(m->mailbox);
                /* m->location freed when oldlocation freed */
            }

            /* allocate new mailbox */
            if (mdata->acl) {
                newm = xrealloc(m, sizeof(struct mbent) + strlen(mdata->acl));
            } else {
                newm = xrealloc(m, sizeof(struct mbent) + 1);
            }

            newm->mailbox = xstrdup(mdata->mailbox);
            newm->location = xstrdup(mdata->location);

            if (mdata->acl) {
                strcpy(newm->acl, mdata->acl);
            } else {
                newm->acl[0] = '\0';
            }

            if (!strncmp(rock, "MAILBOX", 6)) {
                newm->t = t = SET_ACTIVE;
            } else if (!strncmp(rock, "RESERVE", 7)) {
                newm->t = t = SET_RESERVE;
            } else {
                syslog(LOG_DEBUG,
                       "bad mupdate command in cmd_change: %s", rock);
                ret = 1;
                goto done;
            }

            /* Bring it back into scope */
            m = newm;
        }
    }

    /* write to disk */
    database_log(m, NULL);

    if (oldlocation) {
        tmp = strchr(oldlocation, '!');
        if (tmp) *tmp = '\0';
    }

    if (mdata->location) {
        thislocation = xstrdup(mdata->location);
        tmp = strchr(thislocation, '!');
        if (tmp) *tmp = '\0';
    }

    /* post pending changes to anyone we are talking to */
    log_update(mdata->mailbox, oldlocation, thislocation);

 done:
    if (oldlocation) free(oldlocation);
    if (thislocation) free(thislocation);

    free_mbent(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    return ret;
}

struct sync_rock
{
    struct mpool *pool;
    struct mbent_queue *boxes;
};

/* Read a series of MAILBOX and RESERVE commands and tack them onto a
 * queue */
static int cmd_resync(struct mupdate_mailboxdata *mdata,
               const char *rock, void *context)
{
    struct sync_rock *r = (struct sync_rock *)context;
    struct mbent_queue *remote_boxes = r->boxes;
    struct mbent *newm = NULL;

    if (!mdata || !rock || !mdata->mailbox || !remote_boxes) return 1;

    /* allocate new mailbox */
    if (mdata->acl) {
        newm = mpool_malloc(r->pool,sizeof(struct mbent) + strlen(mdata->acl));
    } else {
        newm = mpool_malloc(r->pool,sizeof(struct mbent) + 1);
    }

    newm->mailbox = mpool_strdup(r->pool, mdata->mailbox);
    newm->location = mpool_strdup(r->pool, mdata->location);

    if (mdata->acl) {
        strcpy(newm->acl, mdata->acl);
    } else {
        newm->acl[0] = '\0';
    }

    if (!strncmp(rock, "MAILBOX", 6)) {
        newm->t = SET_ACTIVE;
    } else if (!strncmp(rock, "RESERVE", 7)) {
        newm->t = SET_RESERVE;
    } else {
        syslog(LOG_NOTICE,
               "bad mupdate command in cmd_resync: %s", rock);
        return 1;
    }

    /* Insert onto queue */
    newm->next = NULL;
    *(remote_boxes->tail) = newm;
    remote_boxes->tail = &(newm->next);

    return 0;
}

/* Callback for mupdate_synchronize to be passed to mboxlist_allmbox. */
static int sync_findall_cb(const mbentry_t *mbentry, void *rock)
{
    struct sync_rock *r = (struct sync_rock *)rock;
    struct mbent_queue *local_boxes = (struct mbent_queue *)r->boxes;
    struct mbent *m;

    if (!local_boxes) return 1;

    m = database_lookup(mbentry->name, mbentry, r->pool);
    /* If it doesn't exist, fine... */
    if (!m) return 0;

    m->next = NULL;
    *(local_boxes->tail) = m;
    local_boxes->tail = &(m->next);

    return 0;
}

int mupdate_synchronize_remote(mupdate_handle *handle,
                               struct mbent_queue *remote_boxes,
                               struct mpool *pool)
{
    struct sync_rock rock;

    if (!handle || !handle->saslcompleted) return 1;

    rock.pool = pool;

    /* ask mupdate master for updates and set nonblocking */
    prot_printf(handle->conn->out, "U01 UPDATE\r\n");

    syslog(LOG_NOTICE,
           "scarfing mailbox list from master mupdate server");

    remote_boxes->head = NULL;
    remote_boxes->tail = &(remote_boxes->head);

    rock.boxes = remote_boxes;

    /* If there is a fatal error, return, other errors ignore */
    if (mupdate_scarf(handle, cmd_resync, &rock, 1, NULL) != 0) {
        struct mbent *p=remote_boxes->head, *p_next=NULL;
        while(p) {
            p_next = p->next;
            p = p_next;
        }
        return 1;
    }

    /* Make socket nonblocking now */
    prot_NONBLOCK(handle->conn->in);

    return 0;
}

int mupdate_synchronize(struct mbent_queue *remote_boxes, struct mpool *pool)
{
    struct mbent_queue local_boxes;
    struct mbent *l,*r;
    struct sync_rock rock;
    struct txn *tid = NULL;
    int ret = 0;
    int err = 0;
    char *c;

    rock.pool = pool;

    /* Note that this prevents other people from running an UPDATE against
     * us for the duration.  this is a GOOD THING */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    syslog(LOG_NOTICE,
           "synchronizing mailbox list with master mupdate server");

    local_boxes.head = NULL;
    local_boxes.tail = &(local_boxes.head);

    rock.boxes = &local_boxes;

    mboxlist_allmbox("", sync_findall_cb, (void*)&rock, /*flags*/0);

    /* Traverse both lists, compare the names */
    /* If they match, ensure that location and acl are correct, if so,
       move on, if not, fix them */
    /* If the local is before the next remote, delete it */
    /* If the next remote is before the local, insert it and try again */
    for(l = local_boxes.head, r = remote_boxes->head; l && r;
        l = local_boxes.head, r = remote_boxes->head)
    {
        int ret = strcmp(l->mailbox, r->mailbox);
        if (!ret) {
            /* Match */
            if (l->t != r->t ||
               strcmp(l->location, r->location) ||
               strcmp(l->acl,r->acl)) {
                /* Something didn't match, replace it */
                /*
                 * If this is a locally hosted mailbox, don't make a
                 * change, just warn.
                 */
                if ((config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) &&
                        (strchr( l->location, '!' ) == NULL )) {
                    syslog(LOG_ERR, "local mailbox %s wrong in mailbox list",
                            l->mailbox );
                    err++;
                } else {
                    mbentry_t *mbentry = mboxlist_entry_create();
                    mbentry->name = xstrdupnull(r->mailbox);
                    mbentry->mbtype |= (r->t == SET_RESERVE ? MBTYPE_RESERVE : 0);
                    mbentry->server = xstrdupnull(r->location);

                    c = strchr(mbentry->server, '!');
                    if (c) {
                        *c++ = '\0';
                        mbentry->partition = xstrdupnull(c);
                    }

                    mbentry->acl = xstrdupnull(r->acl);
                    mboxlist_insertremote(mbentry, &tid);
                    mboxlist_entry_free(&mbentry);
                }
            }
            /* Okay, dump these two */
            local_boxes.head = l->next;
            remote_boxes->head = r->next;
        } else if (ret < 0) {
            /* Local without corresponding remote, delete it */
                /*
                 * In a unified murder, we don't want to delete locally
                 * hosted mailboxes during mupdate's resync process.
                 * If that sort of operation appears necessary, it
                 * probably requires an operator to review it --
                 * ctl_mboxlist is the right place to fix the kind
                 * of configuration error implied.
                 *
                 * A similar problem exists when the location thinks
                 * it is locally hosting a mailbox, but mupdate master
                 * thinks it's somewhere else.
                 */
            if ((config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) &&
                    (strchr( l->location, '!' ) == NULL )) {
                syslog(LOG_ERR, "local mailbox %s not in mailbox list",
                        l->mailbox );
                err++;
            } else {
                mboxlist_deleteremote(l->mailbox, &tid);
            }
            local_boxes.head = l->next;
        } else /* (ret > 0) */ {
            /* Remote without corresponding local, insert it */
            mbentry_t *mbentry = mboxlist_entry_create();
            mbentry->name = xstrdupnull(r->mailbox);
            mbentry->mbtype |= (r->t == SET_RESERVE ? MBTYPE_RESERVE : 0);
            mbentry->server = xstrdupnull(r->location);

            c = strchr(mbentry->server, '!');
            if (c) {
                *c++ = '\0';
                mbentry->partition = xstrdupnull(c);
            }

            mbentry->acl = xstrdupnull(r->acl);
            mboxlist_insertremote(mbentry, &tid);
            mboxlist_entry_free(&mbentry);
            remote_boxes->head = r->next;
        }
    }

    if (l && !r) {
        /* we have more deletes to do */
        while(l) {
            if ((config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) &&
                    (strchr( l->location, '!' ) == NULL )) {
                syslog(LOG_ERR, "local mailbox %s not in mailbox list",
                        l->mailbox );
                err++;
            } else {
                mboxlist_deleteremote(l->mailbox, &tid);
            }
            local_boxes.head = l->next;
            l = local_boxes.head;
        }
    } else if (r && !l) {
        /* we have more inserts to do */
        while (r) {
            mbentry_t *mbentry = mboxlist_entry_create();
            mbentry->name = xstrdupnull(r->mailbox);
            mbentry->mbtype |= (r->t == SET_RESERVE ? MBTYPE_RESERVE : 0);
            mbentry->server = xstrdupnull(r->location);

            c = strchr(mbentry->server, '!');
            if (c) {
                *c++ = '\0';
                mbentry->partition = xstrdupnull(c);
            }

            mbentry->acl = xstrdupnull(r->acl);
            mboxlist_insertremote(mbentry, &tid);
            mboxlist_entry_free(&mbentry);
            remote_boxes->head = r->next;
            r = remote_boxes->head;
        }
    }

    if (tid) mboxlist_commit(tid);

    /* All up to date! */
    if ( err ) {
        syslog(LOG_ERR, "mailbox list synchronization NOT complete (%d) errors",
                err);
    } else {
        syslog(LOG_NOTICE, "mailbox list synchronization complete");
    }

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
    return ret;
}

void mupdate_signal_db_synced(void)
{
    pthread_mutex_lock(&synced_mutex);
    synced = 1;
    pthread_cond_broadcast(&synced_cond);
    pthread_mutex_unlock(&synced_mutex);
}

void mupdate_ready(void)
{
    pthread_mutex_lock(&ready_for_connections_mutex);

    if (ready_for_connections) {
        syslog(LOG_CRIT, "mupdate_ready called when already ready");
        fatal("mupdate_ready called when already ready", EX_TEMPFAIL);
    }

    ready_for_connections = 1;
    pthread_cond_broadcast(&ready_for_connections_cond);
    pthread_mutex_unlock(&ready_for_connections_mutex);
}

/* Signal unreadyness.  Next active worker will kill off all idle connections.
 * any non-idle connection will die off when it leaves docmd() */
void mupdate_unready(void)
{
    pthread_mutex_lock(&ready_for_connections_mutex);

    syslog(LOG_NOTICE, "unready for connections");

    ready_for_connections = 0;

    pthread_mutex_unlock(&ready_for_connections_mutex);
}

/* Used to free malloc'd mbent's (not for mpool'd mbents) */
void free_mbent(struct mbent *p)
{
    if (!p) return;
    free(p->location);
    free(p->mailbox);
    free(p);
}
