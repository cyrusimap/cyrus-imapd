/* lmtpd.c -- Program to deliver mail to a mailbox
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "auth.h"
#ifdef USE_AUTOCREATE
#include "autocreate.h"
#endif
#include "backend.h"
#ifdef WITH_DAV
#include "caldav_db.h"
#include "carddav_db.h"
#endif
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "idle.h"
#include "mailbox.h"
#include "map.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "message.h"
#include "mupdate.h"
#include "notify.h"
#include "prot.h"
#include "proxy.h"
#include "statuscache.h"
#include "telemetry.h"
#include "tls.h"
#include "userdeny.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/lmtp_err.h"
#include "imap/lmtpstats.h"

#include "lmtpd.h"
#include "lmtpengine.h"
#ifdef USE_SIEVE
#include "lmtp_sieve.h"
#endif

#include "sync_log.h"

#include "iostat.h"

/* forward declarations */
static int deliver(message_data_t *msgdata, char *authuser,
                   const struct auth_state *authstate, const struct namespace *ns);
static int verify_user(const mbname_t *mbname,
                       quota_t quotastorage_check, quota_t quotamessage_check,
                       struct auth_state *authstate);
static char *generate_notify(message_data_t *m);

void shut_down(int code);

static FILE *spoolfile(message_data_t *msgdata);
static void removespool(message_data_t *msgdata);

#ifdef USE_AUTOCREATE
static int autocreate_inbox(const mbname_t *mbname);
#endif

/* current namespace */
static struct namespace lmtpd_namespace;

static struct lmtp_func mylmtp = { &deliver, &verify_user, &shut_down,
                            &spoolfile, &removespool, &lmtpd_namespace,
                            0, 1, 0 };

static void usage(void);

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

extern int optind;
extern char *optarg;
static int dupelim = 1;         /* eliminate duplicate messages with
                                   same message-id */
static int singleinstance = 1;  /* attempt single instance store */
static int isproxy = 0;

static struct stagemsg *stage = NULL;

/* per-user/session state */
static struct protstream *deliver_out, *deliver_in;
int deliver_logfd = -1; /* used in lmtpengine.c */

/* our cached connections */
struct backend **backend_cached = NULL;

static struct protocol_t lmtp_protocol =
{ "lmtp", "lmtp", TYPE_STD,
  { { { 0, "220 " },
      { "LHLO", "lmtpproxyd", "250 ", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_SKIP_FIRST_WORD|CAPAF_DASH_STUFFING,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "PIPELINING", CAPA_PIPELINING },
          { "IGNOREQUOTA", CAPA_IGNOREQUOTA },
          { NULL, 0 } } },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL },
      { "NOOP", NULL, "250" },
      { "QUIT", NULL, "221" } } }
};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, NULL },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};


int service_init(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    int r;

    if (geteuid() == 0) return 1;

    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    singleinstance = config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

    global_sasl_init(1, 1, mysasl_cb);

    initialize_lmtp_error_table();

    /* so we can do mboxlist operations */
    mboxlist_init(0);
    mboxlist_open(NULL);

    if (config_mupdate_server &&
        (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD) &&
        !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* proxy only */
        isproxy = 1;
    }
    else {
        dupelim = config_getswitch(IMAPOPT_DUPLICATESUPPRESSION);

#ifdef USE_SIEVE
        mylmtp.addheaders = xzmalloc(2 * sizeof(struct addheader));
        mylmtp.addheaders[0].name = "X-Sieve";
        mylmtp.addheaders[0].body = SIEVE_VERSION;
#else
        if (dupelim)
#endif
        {
            /* initialize duplicate delivery database */
            if (duplicate_init(NULL) != 0) {
                fatal("lmtpd: unable to init duplicate delivery database",
                      EC_SOFTWARE);
            }
        }

        /* so we can do quota operations */
        quotadb_init(0);
        quotadb_open(NULL);

        /* open the user deny db */
        denydb_init(0);
        denydb_open(0);

#ifdef WITH_DAV
        /* so we can do DAV operations */
        caldav_init();
        carddav_init();
#endif

        /* Initialize the annotatemore db (for sieve on shared mailboxes) */
        annotate_init(NULL, NULL);
        annotatemore_open();

        /* setup for statuscache invalidation */
        statuscache_open();

        /* setup for sending IMAP IDLE notifications */
        idle_init();

        /* setup for mailbox event notifications */
        mboxevent_init();
    }

    /* Set namespace */
    if ((r = mboxname_init_namespace(&lmtpd_namespace, 0)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EC_CONFIG);
    }

    mboxevent_setnamespace(&lmtpd_namespace);

    /* create connection to the SNMP listener, if available. */
    snmp_connect(); /* ignore return code */
    snmp_set_str(SERVER_NAME_VERSION, cyrus_version());

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc, char **argv,
                 char **envp __attribute__((unused)))
{
    int opt;

    struct io_count *io_count_start = NULL;
    struct io_count *io_count_stop = NULL;

    if (config_iolog) {
        io_count_start = xmalloc (sizeof (struct io_count));
        io_count_stop = xmalloc (sizeof (struct io_count));
        read_io_count(io_count_start);
    }

    sync_log_init();

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 360);

    while ((opt = getopt(argc, argv, "a")) != EOF) {
        switch(opt) {
        case 'a':
            mylmtp.preauth = 1;
            break;

        default:
            usage();
        }
    }

    snmp_increment(TOTAL_CONNECTIONS, 1);
    snmp_increment(ACTIVE_CONNECTIONS, 1);

    lmtpmode(&mylmtp, deliver_in, deliver_out, 0);

    /* free session state */
    if (deliver_in) prot_free(deliver_in);
    if (deliver_out) prot_free(deliver_out);
    deliver_in = deliver_out = NULL;

    if (deliver_logfd != -1) {
        close(deliver_logfd);
        deliver_logfd = -1;
    }

    cyrus_reset_stdio();

    if (config_iolog) {
        read_io_count(io_count_stop);
        syslog(LOG_INFO,
               "LMTP session stats : I/O read : %d bytes : I/O write : %d bytes",
                io_count_stop->io_read_count - io_count_start->io_read_count,
                io_count_stop->io_write_count - io_count_start->io_write_count);
        free (io_count_start);
        free (io_count_stop);
    }

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

static void usage(void)
{
    fprintf(stderr, "421-4.3.0 usage: lmtpd [-C <alt_config>] [-a]\r\n");
    fprintf(stderr, "421 4.3.0 %s\n", cyrus_version());
    exit(EC_USAGE);
}

struct fuzz_rock {
    const mbname_t *mbname;
    mbname_t *result;
    int depth;
};

#define WSP_CHARS "- _"

static int fuzzyeq(const char *a, const char *b)
{
    while (*a) {
        if (!*b) return 0;
        if (tolower(*a) != tolower(*b) && !(strchr(WSP_CHARS, *a) && strchr(WSP_CHARS, *b)))
            return 0;
        a++;
        b++;
    }
    if (*b) return 0;

    return 1;
}

static int fuzzy_match_cb(const mbentry_t *mbentry, void *rock)
{
    struct fuzz_rock *frock = (struct fuzz_rock *) rock;
    int i;
    mbname_t *thisname = mbname_from_intname(mbentry->name);

    const strarray_t *wantboxes = mbname_boxes(frock->mbname);
    const strarray_t *haveboxes = mbname_boxes(thisname);

    int depth = 0;
    /* XXX - WSP_CHARS */
    for (i = 0; i < strarray_size(wantboxes); i++) {
        if (strarray_size(haveboxes) <= i)
            break;
        const char *want = strarray_nth(wantboxes, i);
        const char *have = strarray_nth(haveboxes, i);
        if (!fuzzyeq(want, have))
            break;
        depth = i+1;
    }

    /* in THEORY we should go for most closely accurate if
       there are multiple matches due to case insensitivity,
       but that way lies madness */
    if (depth > frock->depth) {
        mbname_free(&frock->result);
        frock->result = thisname;
        frock->depth = depth;
    }
    else {
        mbname_free(&thisname);
    }

    /* found it */
    if (frock->depth == strarray_size(wantboxes))
        return CYRUSDB_DONE;

    return 0;
}

static int fuzzy_match(mbname_t *mbname)
{
    struct fuzz_rock frock;
    char *prefix = NULL;

    if (mbname_userid(mbname)) {
        char *name = mboxname_user_mbox(mbname_userid(mbname), NULL);
        prefix = strconcat(name, ".", (char *)NULL);
        free(name);
    }
    else if (mbname_domain(mbname)) {
        prefix = strconcat(mbname_domain(mbname), "!", (char *)NULL);
    }

    frock.mbname = mbname;
    frock.result = NULL;
    frock.depth = 0;

    mboxlist_allmbox(prefix, fuzzy_match_cb, &frock, 0);

    free(prefix);

    if (frock.result) {
        int i;
        const strarray_t *newboxes = mbname_boxes(frock.result);
        mbname_truncate_boxes(mbname, 0);
        for (i = 0; i < strarray_size(newboxes); i++)
            mbname_push_boxes(mbname, strarray_nth(newboxes, i));
        mbname_free(&frock.result);
        return 1;
    }

    return 0;
}

/* proxy mboxlist_lookup; on misses, it asks the listener for this
   machine to make a roundtrip to the master mailbox server to make
   sure it's up to date */
static int mlookup(const char *name, mbentry_t **mbentryptr)
{
    int r;
    mbentry_t *mbentry = NULL;

    /* do a local lookup and kick the slave if necessary */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT && config_mupdate_server) {
        kick_mupdate();
        mboxlist_entry_free(&mbentry);
        r = mboxlist_lookup(name, &mbentry, NULL);
    }
    if (r) return r;
    if (mbentry->mbtype & MBTYPE_MOVING) {
        r = IMAP_MAILBOX_MOVED;
    }
    else if (mbentry->mbtype & MBTYPE_DELETED) {
        r = IMAP_MAILBOX_NONEXISTENT;
    }

    if (mbentryptr && !r) *mbentryptr = mbentry;
    else mboxlist_entry_free(&mbentry);

    return r;
}

/* places msg in mailbox mailboxname.
 * if you wish to use single instance store, pass stage as non-NULL
 * if you want to deliver message regardless of duplicates, pass id as NULL
 * if you want to notify, pass user
 * if you want to force delivery (to force delivery to INBOX, for instance)
 * pass acloverride
 */
int deliver_mailbox(FILE *f,
                    struct message_content *content,
                    struct stagemsg *stage,
                    unsigned size,
                    const strarray_t *flags,
                    const char *authuser,
                    const struct auth_state *authstate,
                    char *id,
                    const char *user,
                    char *notifyheader,
                    const char *mailboxname,
                    char *date,
                    int quotaoverride,
                    int acloverride)
{
    int r = 0;
    struct appendstate as;
    const char *notifier;
    struct mailbox *mailbox = NULL;
    char *uuid = NULL;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_INITIALIZER;

    /* open the mailbox separately so we can hold it open until
     * after the duplicate elimination is done */
    r = mailbox_open_iwl(mailboxname, &mailbox);
    if (r) return r;

    if (quotaoverride)
        qdiffs[QUOTA_STORAGE] = -1;
    else if (config_getswitch(IMAPOPT_LMTP_STRICT_QUOTA))
        qdiffs[QUOTA_STORAGE] = size;
    if (quotaoverride)
        qdiffs[QUOTA_MESSAGE] = -1;
    else if (config_getswitch(IMAPOPT_LMTP_STRICT_QUOTA))
        qdiffs[QUOTA_MESSAGE] = 1;
    if (quotaoverride)
        qdiffs[QUOTA_ANNOTSTORAGE] = -1;
    else if (config_getswitch(IMAPOPT_LMTP_STRICT_QUOTA))
        qdiffs[QUOTA_ANNOTSTORAGE] = 0;

    r = append_setup_mbox(&as, mailbox,
                          authuser, authstate, acloverride ? 0 : ACL_POST,
                          qdiffs, NULL, 0, EVENT_MESSAGE_NEW);
    if (r) {
        mailbox_close(&mailbox);
        return r;
    }

    /* check for duplicate message */
    uuid = xstrdup(as.mailbox->uniqueid);
    dkey.id = id;
    dkey.to = uuid;
    dkey.date = date;
    if (id && dupelim && !(as.mailbox->i.options & OPT_IMAP_DUPDELIVER) &&
        duplicate_check(&dkey)) {
        duplicate_log(&dkey, "delivery");
        append_abort(&as);
        mailbox_close(&mailbox);
        free(uuid);
        return 0;
    }

    if (!r && !content->body) {
        /* parse the message body if we haven't already,
           and keep the file mmap'ed */
        r = message_parse_file(f, &content->base, &content->len, &content->body);
    }

    if (!r) {
        r = append_fromstage(&as, &content->body, stage, 0,
                             flags, !singleinstance,
                             /*annotations*/NULL);

        if (r) {
            append_abort(&as);
        } else {
            r = append_commit(&as);
            if (!r) {
                /* dupelim after commit, but while mailbox is still
                 * locked to avoid race condition */
                syslog(LOG_INFO, "Delivered: %s to mailbox: %s",
                       id, mailboxname);
                if (dupelim && id)
                    duplicate_mark(&dkey, time(NULL), as.baseuid);
            }
        }
    }

    /* safe to close the mailbox before sending responses */
    mailbox_close(&mailbox);

    if (!r && user && (notifier = config_getstring(IMAPOPT_MAILNOTIFIER))) {
        char *extname = NULL;
        if (mboxname_userownsmailbox(user, mailboxname)) {
            char *inbox = mboxname_user_mbox(user, NULL);
            extname = mboxname_to_external(inbox, &lmtpd_namespace, user);
            free(inbox);
        }
        else {
            extname = mboxname_to_external(mailboxname, &lmtpd_namespace, user);
        }

        /* translate mailboxname */
        notify(notifier, "MAIL", NULL, user, extname, 0, NULL,
               notifyheader ? notifyheader : "", /*fname*/NULL);
        free(extname);
    }

    free(uuid);
    return r;
}

enum rcpt_status {
    done = 0,
    nosieve,                    /* no sieve script */
    s_wait,                     /* processing sieve requests */
    s_err,                      /* error in sieve processing/sending */
    s_done,                     /* sieve script successfully run */
};

static void deliver_remote(message_data_t *msgdata,
                    struct dest *dlist, enum rcpt_status *status)
{
    struct dest *d;

    /* run the txns */
    d = dlist;
    while (d) {
        struct lmtp_txn *lt = LMTP_TXN_ALLOC(d->rnum);
        struct rcpt *rc;
        struct backend *remote;
        int i = 0;

        lt->from = msgdata->return_path;
        lt->auth = d->authas[0] ? d->authas : NULL;
        lt->isdotstuffed = 0;
        lt->tempfail_unknown_mailbox = 1;

        prot_rewind(msgdata->data);
        lt->data = msgdata->data;
        lt->rcpt_num = d->rnum;
        rc = d->to;
        for (rc = d->to; rc != NULL; rc = rc->next, i++) {
            assert(i < d->rnum);
            lt->rcpt[i].addr = rc->rcpt;
            lt->rcpt[i].ignorequota =
                msg_getrcpt_ignorequota(msgdata, rc->rcpt_num);
        }
        assert(i == d->rnum);

        remote = proxy_findserver(d->server, &lmtp_protocol, "",
                                  &backend_cached, NULL, NULL, NULL);
        if (remote) {
            int txn_timeout = config_getint(IMAPOPT_LMTPTXN_TIMEOUT);
            if (txn_timeout)
                prot_settimeout(remote->in, txn_timeout);
            lmtp_runtxn(remote, lt);
        } else {
            /* remote server not available; tempfail all deliveries */
            for (rc = d->to, i = 0; i < d->rnum; i++) {
                lt->rcpt[i].result = RCPT_TEMPFAIL;
                lt->rcpt[i].r = IMAP_SERVER_UNAVAILABLE;
            }
        }

        /* process results of the txn, propogating error state to the
           recipients */
        for (rc = d->to, i = 0; rc != NULL; rc = rc->next, i++) {
            int j = rc->rcpt_num;
            switch (status[j]) {
            case s_wait:
                /* hmmm, if something fails we'll want to try an
                   error delivery */
                if (lt->rcpt[i].result != RCPT_GOOD) {
                    status[j] = s_err;
                }
                break;
            case s_err:
                /* we've already detected an error for this recipient,
                   and nothing will convince me otherwise */
                break;
            case nosieve:
                /* this is the only delivery we're attempting for this rcpt */
                msg_setrcpt_status(msgdata, j, lt->rcpt[i].r);
                status[j] = done;
                break;
            case done:
            case s_done:
                /* yikes! we shouldn't be getting a notification for this
                   person! */
                abort();
                break;
            }
        }

        free(lt);
        d = d->next;
    }
}

EXPORTED int deliver_local(deliver_data_t *mydata, const strarray_t *flags,
                           const mbname_t *origmbname)
{
    message_data_t *md = mydata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mydata->cur_rcpt);
    int ret = 1;

    /* case 1: shared mailbox request */
    if (!mbname_userid(origmbname)) {
        return deliver_mailbox(md->f, mydata->content, mydata->stage,
                               md->size, flags,
                               mydata->authuser, mydata->authstate, md->id,
                               NULL, mydata->notifyheader,
                               mbname_intname(origmbname), md->date, quotaoverride, 0);
    }

    mbname_t *mbname = mbname_dup(origmbname);

    if (strarray_size(mbname_boxes(mbname))) {
        ret = deliver_mailbox(md->f, mydata->content, mydata->stage,
                              md->size, flags,
                              mydata->authuser, mydata->authstate, md->id,
                              mbname_userid(mbname), mydata->notifyheader,
                              mbname_intname(mbname), md->date, quotaoverride, 0);

        if (ret == IMAP_MAILBOX_NONEXISTENT &&
            config_getswitch(IMAPOPT_LMTP_FUZZY_MAILBOX_MATCH)) {
            if (fuzzy_match(mbname)) {
                /* try delivery to a fuzzy matched mailbox */
                ret = deliver_mailbox(md->f, mydata->content, mydata->stage,
                                      md->size, flags,
                                      mydata->authuser, mydata->authstate, md->id,
                                      mbname_userid(mbname), mydata->notifyheader,
                                      mbname_intname(mbname), md->date, quotaoverride, 0);
            }
        }
    }

    if (ret) {
        /* normal delivery to INBOX */
        mbname_truncate_boxes(mbname, 0);
        struct auth_state *authstate = auth_newstate(mbname_userid(mbname));

        ret = deliver_mailbox(md->f, mydata->content, mydata->stage,
                              md->size, flags,
                              mbname_userid(mbname), authstate, md->id,
                              mbname_userid(mbname), mydata->notifyheader,
                              mbname_intname(mbname), md->date, quotaoverride, 1);

        if (authstate) auth_freestate(authstate);
    }

    mbname_free(&mbname);

    return ret;
}

int deliver(message_data_t *msgdata, char *authuser,
            const struct auth_state *authstate, const struct namespace *ns)
{
    int n, nrcpts;
    struct dest *dlist = NULL;
    enum rcpt_status *status;
    struct message_content content = { NULL, 0, NULL };
    char *notifyheader;
    deliver_data_t mydata;

    assert(msgdata);
    nrcpts = msg_getnumrcpt(msgdata);
    assert(nrcpts);

    notifyheader = generate_notify(msgdata);

    /* create our per-recipient status */
    status = xzmalloc(sizeof(enum rcpt_status) * nrcpts);

    /* create 'mydata', our per-delivery data */
    mydata.m = msgdata;
    mydata.content = &content;
    mydata.stage = stage;
    mydata.notifyheader = notifyheader;
    mydata.ns = ns;
    mydata.authuser = authuser;
    mydata.authstate = authstate;

    /* loop through each recipient, attempting delivery for each */
    for (n = 0; n < nrcpts; n++) {
        const mbname_t *mbname = msg_getrcpt(msgdata, n);
        char *mboxname = mbname_userid(mbname) ?
                mboxname_user_mbox(mbname_userid(mbname), NULL) :
                xstrdup(mbname_intname(mbname));

        mbentry_t *mbentry = NULL;
        int r = mlookup(mboxname, &mbentry);
        free(mboxname);
        if (r) goto setstatus;

        if (mbentry->server) {
            /* remote mailbox */
            const char *recip = mbname_recipient(mbname, &lmtpd_namespace);
            proxy_adddest(&dlist, recip, n, mbentry->server, authuser);
            status[n] = nosieve;
        }
        else {
            /* local mailbox */
            mydata.cur_rcpt = n;
#ifdef USE_SIEVE
            sieve_interp_t *interp = setup_sieve();
            r = run_sieve(mbname, interp, &mydata);
            sieve_interp_free(&interp);
            /* if there was no sieve script, or an error during execution,
               r is non-zero and we'll do normal delivery */
#else
            r = 1;      /* normal delivery */
#endif

            if (r) {
                r = deliver_local(&mydata, NULL, mbname);
            }
        }

        telemetry_rusage(mbname_userid(mbname));

        setstatus:

        msg_setrcpt_status(msgdata, n, r);

        mboxlist_entry_free(&mbentry);
    }

    if (dlist) {
        struct dest *d;

        /* run the txns */
        deliver_remote(msgdata, dlist, status);

        /* free the recipient/destination lists */
        d = dlist;
        while (d) {
            struct dest *nextd = d->next;
            struct rcpt *rc = d->to;

            while (rc) {
                struct rcpt *nextrc = rc->next;
                free(rc);
                rc = nextrc;
            }
            free(d);
            d = nextd;
        }
        dlist = NULL;

        /* do any sieve error recovery, if needed */
        for (n = 0; n < nrcpts; n++) {
            switch (status[n]) {
            case s_wait:
            case s_err:
            case s_done:
                /* yikes, we haven't implemented sieve ! */
                syslog(LOG_CRIT,
                       "sieve states reached, but we don't implement sieve");
                abort();
            break;
            case nosieve:
                /* yikes, we never got an answer on this one */
                syslog(LOG_CRIT, "still waiting for response to rcpt %d",
                       n);
                abort();
                break;
            case done:
                /* good */
                break;
            }
        }

        /* run the error recovery txns */
        deliver_remote(msgdata, dlist, status);

        /* everything should be in the 'done' state now, verify this */
        for (n = 0; n < nrcpts; n++) {
            assert(status[n] == done || status[n] == s_done);
        }
    }

    /* cleanup */
    free(status);
    if (content.base) map_free(&content.base, &content.len);
    if (content.body) {
        message_free_body(content.body);
        free(content.body);
    }
    append_removestage(stage);
    stage = NULL;
    if (notifyheader) free(notifyheader);

    return 0;
}

EXPORTED void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if(recurse_code) {
        /* We were called recursively. Just give up */
        snmp_increment(ACTIVE_CONNECTIONS, -1);
        exit(recurse_code);
    }
    recurse_code = code;
    if(deliver_out) {
        prot_printf(deliver_out,"421 4.3.0 lmtpd: %s\r\n", s);
        prot_flush(deliver_out);
    }
    if (stage) append_removestage(stage);

    syslog(LOG_ERR, "FATAL: %s", s);

    /* shouldn't return */
    shut_down(code);

    exit(code);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    int i;

    /* set flag */
    in_shutdown = 1;

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
        proxy_downserver(backend_cached[i]);
        free(backend_cached[i]);
        i++;
    }
    if (backend_cached) free(backend_cached);

    mboxlist_close();
    mboxlist_done();

    if (!isproxy) {
        if (dupelim)
            duplicate_done();

        quotadb_close();
        quotadb_done();

        denydb_close();
        denydb_done();

#ifdef WITH_DAV
        carddav_done();
        caldav_done();
#endif

        annotatemore_close();
        annotate_done();

        statuscache_close();
        statuscache_done();

        idle_done();
    }

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif
    if (deliver_out) {
        prot_flush(deliver_out);

        /* one less active connection */
        snmp_increment(ACTIVE_CONNECTIONS, -1);
    }

    sync_log_done();

    cyrus_done();

    exit(code);
}

#ifdef USE_AUTOCREATE
/*
 * Autocreate Inbox and subfolders upon login
 */
int autocreate_inbox(const mbname_t *mbname)
{
    const char *userid = mbname_userid(mbname);

    if (!userid)
        return IMAP_MAILBOX_NONEXISTENT;

    /*
     * Exclude anonymous
     */
    if (!strcmp(userid, "anonymous"))
        return IMAP_MAILBOX_NONEXISTENT;

    /*
     * Check for autocreatequota and createonpost
     */
    if (config_getint(IMAPOPT_AUTOCREATE_QUOTA) < 0)
        return IMAP_MAILBOX_NONEXISTENT;

    if (!config_getswitch(IMAPOPT_AUTOCREATE_POST))
        return IMAP_MAILBOX_NONEXISTENT;

    return autocreate_user(&lmtpd_namespace, userid);
}
#endif // USE_AUTOCREATE

static int verify_user(const mbname_t *origmbname,
                       quota_t quotastorage_check, quota_t quotamessage_check,
                       struct auth_state *authstate)
{
    int r = 0;
    mbentry_t *mbentry = NULL;
    mbname_t *mbname = mbname_dup(origmbname);
    long aclcheck = !mbname_userid(mbname) ? ACL_POST : 0;

    /* if it's the userid, we just check INBOX */
    if (mbname_userid(mbname)) {
        mbname_truncate_boxes(mbname, 0);
    }

    /*
     * check to see if mailbox exists and we can append to it:
     *
     * - must have posting privileges on shared folders
     * - don't care about ACL on INBOX (always allow post)
     * - don't care about message size (1 msg over quota allowed)
     */
    r = mlookup(mbname_intname(mbname), &mbentry);

#ifdef USE_AUTOCREATE
    /* If user mailbox does not exist, then invoke autocreate inbox function */
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = autocreate_inbox(mbname);
        if (!r) r = mlookup(mbname_intname(mbname), &mbentry);
    }
#endif // USE_AUTOCREATE

    if (r == IMAP_MAILBOX_NONEXISTENT && !mbname_userid(mbname) &&
        config_getswitch(IMAPOPT_LMTP_FUZZY_MAILBOX_MATCH)) {
        /* see if we have a mailbox whose name is close */
        if (fuzzy_match(mbname)) {
            r = mlookup(mbname_intname(mbname), &mbentry);
        }
    }

    if (!r && mbentry->server) {
        int access = cyrus_acl_myrights(authstate, mbentry->acl);

        if ((access & aclcheck) != aclcheck) {
            r = (access & ACL_LOOKUP) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        }
    } else if (!r) {
        int strict = config_getswitch(IMAPOPT_LMTP_STRICT_QUOTA);
        quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_INITIALIZER;
        if (quotastorage_check < 0 || strict)
            qdiffs[QUOTA_STORAGE] = quotastorage_check;
        if (quotamessage_check < 0 || strict)
            qdiffs[QUOTA_MESSAGE] = quotamessage_check;

        r = append_check(mbentry->name, authstate, aclcheck, qdiffs);
    }

    mboxlist_entry_free(&mbentry);

    if (!r && mbname_userid(mbname)) {
        char msg[MAX_MAILBOX_PATH+1];

        if (userdeny(mbname_userid(mbname), config_ident, msg, sizeof(msg))) {
            r = IMAP_MAILBOX_DISABLED;
            goto done;
        }
    }

    if (r) syslog(LOG_DEBUG, "verify_user(%s) failed: %s", mbname_userid(mbname),
                  error_message(r));

done:
    mbname_free(&mbname);

    return r;
}

static const char *notifyheaders[] = { "From", "Subject", "To", 0 };
/* returns a malloc'd string that should be sent to users for successful
   delivery of 'm'. */
char *generate_notify(message_data_t *m)
{
    const char **body;
    char *ret = NULL;
    unsigned int len = 0;
    unsigned int pos = 0;
    int i;

    for (i = 0; notifyheaders[i]; i++) {
        const char *h = notifyheaders[i];
        body = msg_getheader(m, h);
        if (body) {
            int j;

            for (j = 0; body[j] != NULL; j++) {
                /* put the header */
                /* need: length + ": " + '\0'*/
                while (pos + strlen(h) + 3 > len) {
                    ret = xrealloc(ret, len += 1024);
                }
                pos += sprintf(ret + pos, "%s: ", h);

                /* put the header body.
                   xxx it would be nice to linewrap.*/
                /* need: length + '\n' + '\0' */
                while (pos + strlen(body[j]) + 2 > len) {
                    ret = xrealloc(ret, len += 1024);
                }
                pos += sprintf(ret + pos, "%s\n", body[j]);
            }
        }
    }

    return ret;
}

FILE *spoolfile(message_data_t *msgdata)
{
    int i, n;
    time_t now = time(NULL);
    FILE *f = NULL;

    /* spool to the stage of one of the recipients
       (don't bother if we're only a proxy) */
    n = isproxy ? 0 : msg_getnumrcpt(msgdata);
    for (i = 0; !f && (i < n); i++) {
        mbentry_t *mbentry = NULL;
        int r;

        /* build the mailboxname from the recipient address */
        const mbname_t *origmbname = msg_getrcpt(msgdata, i);

        /* do the userid */
        mbname_t *mbname = mbname_dup(origmbname);
        if (mbname_userid(mbname)) {
            mbname_truncate_boxes(mbname, 0);
        }

        r = mlookup(mbname_intname(mbname), &mbentry);
        if (r || !mbentry->server) {
            /* local mailbox -- setup stage for later use by deliver() */
            f = append_newstage(mbname_intname(mbname), now, 0, &stage);
        }

        mboxlist_entry_free(&mbentry);
        mbname_free(&mbname);
    }

    if (!f) {
        /* we only have remote mailboxes, so use a tempfile */
        int fd = create_tempfile(config_getstring(IMAPOPT_TEMP_PATH));

        if (fd != -1) f = fdopen(fd, "w+");
    }

    return f;
}

void removespool(message_data_t *msgdata __attribute__((unused)))
{
    append_removestage(stage);
    stage = NULL;
}
