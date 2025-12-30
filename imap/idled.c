/* idled.c - daemon for handling IMAP IDLE notifications */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <fcntl.h>

#include "acl.h"
#include "arrayu64.h"
#include "idle.h"
#include "idlemsg.h"
#include "global.h"
#include "json_support.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "sqldb.h"
#include "xmalloc.h"

#define CMD_CREATE                                  \
    "CREATE TABLE event_groups ("                   \
    " rowid   INTEGER PRIMARY KEY,"                 \
    " pid     INTEGER,"                             \
    " events  INTEGER,"                             \
    " timeout INTEGER,"                             \
    " filter  INTEGER,"                             \
    " keys    TEXT,"                                \
    " client  BLOB,"                                \
    " UNIQUE ( pid, filter ) );"

#define CMD_INSERT                                                      \
    "INSERT INTO event_groups"                                          \
    " ( pid, events, timeout, filter, keys, client )"                   \
    " VALUES ( :pid, :events, :timeout, :filter, :keys, :client );"

#define CMD_SELECT                                                      \
    "SELECT pid, events, timeout, filter, keys, client"                 \
    " FROM event_groups WHERE events & :events"                         \
    " ORDER BY pid;"

#define CMD_SELECT_ALL                          \
    "SELECT DISTINCT client FROM event_groups;"

#define CMD_DELETE_EVENT "DELETE FROM event_groups"     \
    " WHERE pid = :pid AND filter = :filter;"

#define CMD_DELETE_PIDS "DELETE FROM event_groups"      \
    " WHERE pid IN ( :pid );"

extern int optind;
extern char *optarg;

static int verbose = 0;
static int debugmode = 0;

static sqldb_t *db = NULL;

EXPORTED void fatal(const char *msg, int err)
{
    if (debugmode) fprintf(stderr, "dying with %s %d\n",msg,err);
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");

    cyrus_done();

    if (err != EX_PROTOCOL && config_fatals_abort) abort();

    exit(err);
}

static int alert_cb(sqlite3_stmt *stmt, void *rock)
{
    json_t *msg = rock;
    struct sockaddr_un *client =
        (struct sockaddr_un *) sqlite3_column_blob(stmt, 0);

    idle_send(client, msg);
    return 0;
}

struct notify_rock {
    json_t *msg;
    pid_t last_pid;
    arrayu64_t *failed_pids;
};

static int notify_cb(sqlite3_stmt *stmt, void *rock)
{
    struct notify_rock *nrock = rock;
    const char *mboxid = idle_msg_get_mboxid(nrock->msg);

    if (!mboxid) return 0;

    pid_t pid = sqlite3_column_int(stmt, 0);
    unsigned long events = sqlite3_column_int(stmt, 1);
    time_t timeout = sqlite3_column_int(stmt, 2);
    mailbox_filter_t filter = sqlite3_column_int(stmt, 3);
    struct sockaddr_un *client =
        (struct sockaddr_un *) sqlite3_column_blob(stmt, 5);

    if (timeout && (timeout < time(NULL))) {
        /* This process has been idling for longer than the timeout
         * period, so it probably died.  Remove it from the list. */
        if (verbose || debugmode)
            syslog(LOG_DEBUG, "    TIMEOUT %s", idle_id_from_addr(client));

        arrayu64_add(nrock->failed_pids, pid);
        return 0;
    }

    /* XXX  Should we check /proc/pid to make sure the client is still active? */

    /* Don't notify the same client more than once */
    if (pid == nrock->last_pid) return 0;

    json_error_t jerr;
    json_t *keys =
        json_loads((const char *) sqlite3_column_text(stmt, 4), 0, &jerr);
    json_t *key = json_array_get(keys, 0);
    const char *keyval = json_string_value(key);
    mbentry_t *mbentry = NULL;
    int notify = 0;
    size_t i;

    /* Is it a mailbox in which the client has interest? */
    if (filter == FILTER_SELECTED) {
        /* keyval is currently selected mailbox id */
        if (!strcmp(mboxid, keyval))
            notify = 1;
    }
    else if (!mboxlist_lookup_by_uniqueid(mboxid, &mbentry, NULL)) {
        switch (filter) {
        case FILTER_INBOXES:
            /* Is it an INBOX or postable by anonymous? */
            if (!mboxname_isusermailbox(mbentry->name, /*isinbox*/1) &&
                !(cyrus_acl_myrights(NULL, mbentry->acl) & ACL_POST))
                break;

            GCC_FALLTHROUGH

        case FILTER_PERSONAL:
            /* keyval is userid */
            if (mboxname_userownsmailbox(keyval, mbentry->name))
                notify = 1;
            break;

        case FILTER_SUBSCRIBED: {
            /* keyval is userid */
            strarray_t *sublist = mboxlist_sublist(keyval);
            if (strarray_contains(sublist, mbentry->name))
                notify = 1;
            strarray_free(sublist);
            break;
        }

        case FILTER_SUBTREE:
            json_array_foreach(keys, i, key) {
                const char *mboxname = json_string_value(key);
                if (mboxname_is_prefix(mbentry->name, mboxname)) {
                    notify = 1;
                    break;
                }
            }
            break;

        case FILTER_MAILBOXES:
            if (json_array_find(keys, mbentry->name) >= 0)
                notify = 1;
            break;

        default:
            break;
        }
    }

    if (!notify) goto done;

    nrock->last_pid = pid;

    if (verbose || debugmode)
        syslog(LOG_DEBUG, "    fwd NOTIFY %s", idle_id_from_addr(client));

    /* forward the received msg onto our clients */
    int r = idle_send(client, nrock->msg);
    if (r) {
        /* ENOENT can happen as result of a race between delivering
         * messages and shutting down imapd.  It indicates that the
         * imapd's socket was unlinked, which means that imapd went
         * through it's graceful shutdown path, so don't syslog.
         * Either way, remove it from the list. */
        if (r != ENOENT)
            syslog(LOG_ERR, "IDLE: error sending message "
                   "NOTIFY to imapd %s events=<%lu> filter=<%u>: %s, forgetting.",
                   idle_id_from_addr(client), events, filter, error_message(r));

        if (verbose || debugmode)
            syslog(LOG_DEBUG, "    forgetting %s", idle_id_from_addr(client));

        arrayu64_add(nrock->failed_pids, pid);
    }

  done:
    mboxlist_entry_free(&mbentry);
    json_decref(keys);

    return 0;
}

static void process_message(struct sockaddr_un *remote, json_t *msg)
{
    const char *type = json_string_value(json_object_get(msg, "@type"));
    pid_t pid = json_integer_value(json_object_get(msg, "pid"));
    struct sqldb_bindval bval[] = {
        { ":pid", SQLITE_INTEGER, { .i = pid } },
        { NULL,   SQLITE_INTEGER, { 0        } },
        { NULL,   SQLITE_INTEGER, { 0        } },
        { NULL,   SQLITE_INTEGER, { 0        } },
        { NULL,   SQLITE_TEXT,    { 0        } },
        { NULL,   SQLITE_BLOB,    { 0        } },
        { NULL,   SQLITE_NULL,    { 0        } } };

    if (!strcmp(type, "start")) {
        unsigned long events = json_integer_value(json_object_get(msg, "events"));
        time_t timeout = json_integer_value(json_object_get(msg, "timeout"));
        mailbox_filter_t filter =
            json_integer_value(json_object_get(msg, "filter"));
        char *keys = json_dumps(json_object_get(msg, "keys"), JSON_COMPACT);

        if (verbose || debugmode) {
            syslog(LOG_DEBUG, "imapd[%s]: idle start"
                   " pid=<%d> events=<%lu> filter=<%u> keys=%s",
                   idle_id_from_addr(remote), pid, events, filter, keys);
        }

        /* add client and events to db */
        bval[1].name = ":events";
        bval[1].val.i = events;
        bval[2].name = ":timeout";
        bval[2].val.i = timeout;
        bval[3].name = ":filter";
        bval[3].val.i = filter;
        bval[4].name = ":keys";
        bval[4].val.s = keys;
        bval[5].name = ":client";
        buf_init_ro(&bval[5].val.b, (void *) remote, sizeof(*remote));

        sqldb_exec(db, CMD_INSERT, bval, NULL, NULL);

        free(keys);
    }
    else if (!strcmp(type, "stop")) {
        mailbox_filter_t filter =
            json_integer_value(json_object_get(msg, "filter"));

        if (verbose || debugmode) {
            syslog(LOG_DEBUG, "imapd[%s]: idle stop"
                   " pid=<%d> filter=<%u>",
                   idle_id_from_addr(remote), pid, filter);
        }

        /* remove client from db */
        if (filter == FILTER_NONE) {
            sqldb_exec(db, CMD_DELETE_PIDS, bval, NULL, NULL);
        }
        else {
            bval[1].name = ":filter";
            bval[1].val.i = filter;

            sqldb_exec(db, CMD_DELETE_EVENT, bval, NULL, NULL);
        }
    }
    else if (!strcmp(type, "notify")) {
        const char *jevent = json_string_value(json_object_get(msg, "event"));
        enum event_type event = name_to_mboxevent(jevent);
        arrayu64_t failed_pids = ARRAYU64_INITIALIZER;
        struct notify_rock nrock = { msg, 0, &failed_pids };

        if (verbose || debugmode) {
            syslog(LOG_DEBUG, "idle notify '%s'", jevent);
        }

        /* notify clients that are interested in this event */
        bval[0].name = ":events";
        bval[0].val.i = event;
        bval[1].name = NULL;

        sqldb_exec(db, CMD_SELECT, bval, &notify_cb, &nrock);

        if (arrayu64_size(&failed_pids)) {
            /* remove clients that have stopped listening to us */
            struct buf buf = BUF_INITIALIZER;
            const char *sep = "";
            size_t i;
            
            for (i = 0; i < arrayu64_size(&failed_pids); i++) {
                buf_printf(&buf, "%s%" PRIu64, sep, arrayu64_nth(&failed_pids, i));
                sep = ", ";
            }

            bval[0].type = SQLITE_TEXT;
            bval[0].val.s = buf_cstring(&buf);

            sqldb_exec(db, CMD_DELETE_PIDS, bval, NULL, NULL);

            buf_free(&buf);
        }

        arrayu64_fini(&failed_pids);
    }
    else {
        syslog(LOG_ERR, "unrecognized message: %s", type);
    }
}

static void shut_down(int ec) __attribute__((noreturn));
static void shut_down(int ec)
{
    /* signal all clients to check ALERTs */
    json_t *msg = json_pack("{s:s s:i s:s}",
                            "@type", "alert", "pid", getpid(),
                            "message", "idled shutting down");

    sqldb_exec(db, CMD_SELECT_ALL, NULL, &alert_cb, msg);
    json_decref(msg);

    sqldb_close(&db);
    sqldb_done();

    idle_done_sock();
    cyrus_done();
    exit(ec);
}

int main(int argc, char **argv)
{
    char *p = NULL;
    int opt;
    int s;
    struct sockaddr_un local;
    fd_set read_set, rset;
    int nfds;
    struct timeval timeout;
    pid_t pid;
    char *alt_config = NULL;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;

    while ((opt = getopt(argc, argv, "C:d")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'd': /* don't fork. debugging mode */
            debugmode = 1;
            break;
        default:
            fprintf(stderr, "invalid argument\n");
            exit(EX_USAGE);
            break;
        }
    }

    cyrus_init(alt_config, "idled", 0, 0);

    signals_set_shutdown(shut_down);
    signals_add_handlers(0);

    if (!idle_make_server_address(&local) ||
        !idle_init_sock(&local)) {
        cyrus_done();
        exit(1);
    }
    s = idle_get_sock();

    /* fork unless we were given the -d option or we're running as a daemon */
    if (debugmode == 0 && !getenv("CYRUS_ISDAEMON")) {

        pid = fork();

        if (pid == -1) {
            perror("fork");
            exit(1);
        }

        if (pid != 0) { /* parent */
            exit(0);
        }
    }
    /* child */

    sqldb_init();
    db = sqldb_open(":memory:", CMD_CREATE, 1, NULL, SQLDB_DEFAULT_TIMEOUT);

    /* get ready for select() */
    FD_ZERO(&read_set);
    FD_SET(s, &read_set);
    nfds = s + 1;

    for (;;) {
        int n;
        int sig;

        sig = signals_poll();
        if (sig == SIGHUP && getenv("CYRUS_ISDAEMON")) {
            /* XXX maybe don't restart if we have clients? */
            syslog(LOG_DEBUG, "received SIGHUP, shutting down gracefully");
            shut_down(0);
        }

        /* check for shutdown file */
        if (shutdown_file(NULL, 0)) {
            /* signal all processes to shutdown */
            if (verbose || debugmode)
                syslog(LOG_DEBUG, "Detected shutdown file");
            shut_down(1);
        }

        /* timeout for select is 1 second */
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        /* check for the next input */
        rset = read_set;
        n = signals_select(nfds, &rset, NULL, NULL, &timeout);
        if (n < 0 && errno == EAGAIN) continue;
        if (n < 0 && errno == EINTR) continue;
        if (n == -1) {
            /* uh oh */
            syslog(LOG_ERR, "select(): %m");
            close(s);
            fatal("select error",-1);
        }

        /* read and process a message */
        if (FD_ISSET(s, &rset)) {
            struct sockaddr_un from;
            json_t *msg = idle_recv(&from);

            if (msg) {
                process_message(&from, msg);
                json_decref(msg);
            }
        }

    }

    /* NOTREACHED */
    shut_down(1);
}

