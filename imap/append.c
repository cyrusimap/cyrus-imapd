/* append.c -- Routines for appending messages to a mailbox
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

#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/poll.h>

#include "acl.h"
#include "assert.h"
#include "mailbox.h"
#include "notify.h"
#include "message.h"
#include "msgrecord.h"
#include "append.h"
#include "global.h"
#include "prot.h"
#include "sync_log.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "seen.h"
#include "retry.h"
#include "quota.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "annotate.h"
#include "message_guid.h"
#include "strarray.h"
#include "conversations.h"

#if defined ENABLE_OBJECTSTORE
#include "objectstore.h"
#endif

struct stagemsg {
    char fname[1024];

    strarray_t parts; /* buffer of current stage parts */
    struct message_guid guid;
};

static int append_addseen(struct mailbox *mailbox, const char *userid,
                          struct seqset *newseen);
static int append_setseen(struct appendstate *as, msgrecord_t *mr);

/*
 * Check to see if mailbox can be appended to
 *
 * Arguments:
 *      name       - name of mailbox directory
 *      aclcheck   - user must have these rights on mailbox ACL
 *      quotastorage_check - mailbox must have this much storage quota left
 *                   (-1 means don't care about quota)
 *      quotamessage_check - mailbox must have this much message quota left
 *                   (-1 means don't care about quota)
 *
 */
EXPORTED int append_check(const char *name,
                 struct auth_state *auth_state,
                 long aclcheck,
                 const quota_t quotacheck[QUOTA_NUMRESOURCES])
{
    struct mailbox *mailbox = NULL;
    int myrights;
    int r;

    r = mailbox_open_irl(name, &mailbox);
    if (r) return r;

    myrights = cyrus_acl_myrights(auth_state, mailbox->acl);

    if ((myrights & aclcheck) != aclcheck) {
        r = (myrights & ACL_LOOKUP) ?
          IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        goto done;
    }

    if (quotacheck)
        r = mailbox_quota_check(mailbox, quotacheck);

done:
    mailbox_close(&mailbox);

    return r;
}

/*
 * Open a mailbox for appending
 *
 * Arguments:
 *      name       - name of mailbox directory
 *      aclcheck   - user must have these rights on mailbox ACL
 *      quotastorage_check - mailbox must have this much storage quota left
 *                   (-1 means don't care about quota)
 *      quotamessage_check - mailbox must have this much message quota left
 *                   (-1 means don't care about quota)
 *      event_type - the event among MessageNew, MessageAppend and
 *                   vnd.cmu.MessageCopy (zero means don't send notification)
 * On success, the struct pointed to by 'as' is set up.
 *
 * when you commit or abort, the mailbox is closed
 */
EXPORTED int append_setup(struct appendstate *as, const char *name,
                 const char *userid, const struct auth_state *auth_state,
                 long aclcheck, const quota_t quotacheck[QUOTA_NUMRESOURCES],
                 const struct namespace *namespace, int isadmin, enum event_type  event_type)
{
    int r;
    struct mailbox *mailbox = NULL;

    r = mailbox_open_iwl(name, &mailbox);
    if (r) {
        memset(as, 0, sizeof(*as));
        return r;
    }

    r = append_setup_mbox(as, mailbox, userid, auth_state,
                          aclcheck, quotacheck, namespace, isadmin, event_type);
    if (r) mailbox_close(&mailbox);
    else as->close_mailbox_when_done = 1;

    return r;
}

/* setup for append with an existing mailbox
 *
 * same as append_setup, but when you commit, the mailbox remains open and locked.
 *
 * Requires as write locked mailbox (of course)
 */
EXPORTED int append_setup_mbox(struct appendstate *as, struct mailbox *mailbox,
                               const char *userid, const struct auth_state *auth_state,
                               long aclcheck, const quota_t quotacheck[QUOTA_NUMRESOURCES],
                               const struct namespace *namespace, int isadmin,
                               enum event_type event_type)
{
    int r;

    memset(as, 0, sizeof(*as));

    as->myrights = cyrus_acl_myrights(auth_state, mailbox->acl);

    if ((as->myrights & aclcheck) != aclcheck) {
        r = (as->myrights & ACL_LOOKUP) ?
          IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        return r;
    }

    if (quotacheck) {
        r = mailbox_quota_check(mailbox, quotacheck);
        if (r) return r;
    }

    if (userid) {
        strlcpy(as->userid, userid, sizeof(as->userid));
    } else {
        as->userid[0] = '\0';
    }
    as->namespace = namespace;
    as->auth_state = auth_state;
    as->isadmin = isadmin;

    /* initialize seen list creator */
    as->internalseen = mailbox_internal_seen(mailbox, as->userid);
    as->seen_seq = seqset_init(0, SEQ_SPARSE);

    /* zero out metadata */
    as->nummsg = 0;
    as->baseuid = mailbox->i.last_uid + 1;
    as->s = APPEND_READY;

    as->event_type = event_type;
    as->mboxevents = NULL;

    as->mailbox = mailbox;

    return 0;
}

EXPORTED uint32_t append_uidvalidity(struct appendstate *as)
{
    return as->mailbox->i.uidvalidity;
}

static void append_free(struct appendstate *as)
{
    if (!as) return;
    if (as->s == APPEND_DONE) return;

    seqset_free(as->seen_seq);
    as->seen_seq = NULL;

    mboxevent_freequeue(&as->mboxevents);
    as->event_type = 0;

    if (as->close_mailbox_when_done)
        mailbox_close(&as->mailbox);

    as->s = APPEND_DONE;
}

/* may return non-zero, indicating that the entire append has failed
 and the mailbox is probably in an inconsistent state. */
EXPORTED int append_commit(struct appendstate *as)
{
    int r = 0;

    if (as->s == APPEND_DONE) return 0;

    if (as->nummsg) {
        /* Calculate new index header information */
        as->mailbox->i.last_appenddate = time(0);

        /* log the append so rolling squatter can index this mailbox */
        sync_log_append(as->mailbox->name);

        /* set seen state */
        if (as->userid[0])
            append_addseen(as->mailbox, as->userid, as->seen_seq);
    }

    /* We want to commit here to guarantee mailbox on disk vs
     * duplicate DB consistency */
    r = mailbox_commit(as->mailbox);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: committing mailbox append",
                         "mailbox=<%s> error=<%s>",
                         as->mailbox->name, error_message(r));
        append_abort(as);
        return r;
    }

    /* send the list of MessageCopy or MessageAppend event notifications at once */
    mboxevent_notify(&as->mboxevents);

    append_free(as);
    return 0;
}

/* may return non-zero, indicating an internal error of some sort. */
EXPORTED int append_abort(struct appendstate *as)
{
    int i, r = 0;
    if (as->s == APPEND_DONE) return 0;

    // nuke any files that we've created
    for (i = 0; i < as->nummsg; i++) {
        mailbox_cleanup_uid(as->mailbox, as->baseuid + i, "ZZ");
    }

    if (as->mailbox) r = mailbox_abort(as->mailbox);
    append_free(as);

    return r;
}

/*
 * staging, to allow for single-instance store.  initializes the stage
 * with the file for the given mailboxname and returns the open file
 * so it can double as the spool file
 */
EXPORTED FILE *append_newstage_full(const char *mailboxname, time_t internaldate,
                      int msgnum, struct stagemsg **stagep, const char *sourcefile)
{
    struct stagemsg *stage;
    char stagedir[MAX_MAILBOX_PATH+1], stagefile[MAX_MAILBOX_PATH+1];
    FILE *f;
    int r;

    assert(mailboxname != NULL);
    assert(stagep != NULL);

    *stagep = NULL;

    stage = xmalloc(sizeof(struct stagemsg));
    strarray_init(&stage->parts);

    snprintf(stage->fname, sizeof(stage->fname), "%d-%d-%d",
             (int) getpid(), (int) internaldate, msgnum);

    r = mboxlist_findstage(mailboxname, stagedir, sizeof(stagedir));
    if (r) {
        syslog(LOG_ERR, "couldn't find stage directory for mbox: '%s': %s",
               mailboxname, error_message(r));
        free(stage);
        return NULL;
    }
    strlcpy(stagefile, stagedir, sizeof(stagefile));
    strlcat(stagefile, stage->fname, sizeof(stagefile));

    /* create this file and put it into stage->parts[0] */
    unlink(stagefile);
    if (sourcefile) {
        r = mailbox_copyfile(sourcefile, stagefile, 0);
        if (r) {
            syslog(LOG_ERR, "couldn't copy stagefile '%s' for mbox: '%s': %s",
                   sourcefile, mailboxname, error_message(r));
            free(stage);
            return NULL;
        }
        f = fopen(stagefile, "r+");
    }
    else {
        f = fopen(stagefile, "w+");
    }
    if (!f) {
        if (mkdir(stagedir, 0755) != 0) {
            syslog(LOG_ERR, "couldn't create stage directory: %s: %m",
                   stagedir);
        } else {
            syslog(LOG_NOTICE, "created stage directory %s",
                   stagedir);
            f = fopen(stagefile, "w+");
        }
    }
    if (!f) {
        xsyslog(LOG_ERR, "IOERROR: creating message file",
                         "filename=<%s>", stagefile);
        strarray_fini(&stage->parts);
        free(stage);
        return NULL;
    }

    strarray_append(&stage->parts, stagefile);

    *stagep = stage;
    return f;
}

/*
 * Send the args down a socket.  We use a counted encoding
 * similar in concept to HTTP chunked encoding, with a decimal
 * ASCII encoded length followed by that many bytes of data.
 * A zero length indicates end of message.
 */
static int callout_send_args(int fd, const struct buf *args)
{
    char lenbuf[32];
    int r = 0;

    snprintf(lenbuf, sizeof(lenbuf), "%u\n", (unsigned)args->len);
    r = retry_write(fd, lenbuf, strlen(lenbuf));
    if (r < 0)
        goto out;

    if (args->len) {
        r = retry_write(fd, args->s, args->len);
        if (r < 0)
            goto out;
        r = retry_write(fd, "0\n", 2);
    }

out:
    return (r < 0 ? IMAP_SYS_ERROR : 0);
}

#define CALLOUT_TIMEOUT_MS      (10*1000)

static int callout_receive_reply(const char *callout,
                                 int fd, struct dlist **results)
{
    struct protstream *p = NULL;
    int r;
    int c;
    struct pollfd pfd;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;

    r = poll(&pfd, 1, CALLOUT_TIMEOUT_MS);
    if (r < 0) {
        syslog(LOG_ERR, "cannot poll() waiting for callout %s: %m",
               callout);
        r = IMAP_SYS_ERROR;
        goto out;
    }
    if (r == 0) {
        syslog(LOG_ERR, "timed out waiting for callout %s",
               callout);
        r = IMAP_SYS_ERROR;
        goto out;
    }

    p = prot_new(fd, /*write*/0);
    prot_setisclient(p, 1);

    /* read and parse the reply as a dlist */
    c = dlist_parse(results, /*parsekeys*/0, /*isbackup*/0, p);
    r = (c == EOF ? IMAP_SYS_ERROR : 0);

out:
    if (p)
        prot_free(p);
    return r;
}

/*
 * Handle the callout as a service listening on a UNIX domain socket.
 * Send the encoded arguments down the socket; capture the reply and
 * decode it as a dlist.
 */
static int callout_run_socket(const char *callout,
                              const struct buf *args,
                              struct dlist **results)
{
    int sock = -1;
    struct sockaddr_un mysun;
    int r;

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "cannot create socket for callout: %m");
        r = IMAP_SYS_ERROR;
        goto out;
    }

    memset(&mysun, 0, sizeof(mysun));
    mysun.sun_family = AF_UNIX;
    xstrncpy(mysun.sun_path, callout, sizeof(mysun.sun_path));
    r = connect(sock, (struct sockaddr *)&mysun, sizeof(mysun));
    if (r < 0) {
        syslog(LOG_ERR, "cannot connect socket for callout: %m");
        r = IMAP_SYS_ERROR;
        goto out;
    }

    r = callout_send_args(sock, args);
    if (r)
        goto out;

    r = callout_receive_reply(callout, sock, results);

out:
    if (sock >= 0)
        close(sock);
    return r;
}

/*
 * Handle the callout as an executable.  Fork and exec the callout as an
 * executable, with the encoded arguments appearing on stdin and the
 * stdout captured as a dlist.
 */
static int callout_run_executable(const char *callout,
                                  const struct buf *args,
                                  struct dlist **results)
{
    pid_t pid, reaped;
#define PIPE_READ    0
#define PIPE_WRITE   1
    int inpipe[2] = { -1, -1 };
    int outpipe[2] = { -1, -1 };
    int status;
    int r;

    r = pipe(inpipe);
    if (!r)
        r = pipe(outpipe);
    if (r < 0) {
        syslog(LOG_ERR, "cannot create pipe for callout: %m");
        r = IMAP_SYS_ERROR;
        goto out;
    }

    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "cannot fork for callout: %m");
        r = IMAP_SYS_ERROR;
        goto out;
    }

    if (pid == 0) {
        /* child process */

        close(inpipe[PIPE_WRITE]);
        dup2(inpipe[PIPE_READ], STDIN_FILENO);
        close(inpipe[PIPE_READ]);

        close(outpipe[PIPE_READ]);
        dup2(outpipe[PIPE_WRITE], STDOUT_FILENO);
        close(outpipe[PIPE_WRITE]);

        execl(callout, callout, (char *)NULL);
        syslog(LOG_ERR, "cannot exec callout %s: %m", callout);
        exit(1);
    }
    /* parent process */
    close(inpipe[PIPE_READ]);
    inpipe[PIPE_READ] = -1;
    close(outpipe[PIPE_WRITE]);
    outpipe[PIPE_WRITE] = -1;

    r = callout_send_args(inpipe[PIPE_WRITE], args);
    if (r)
        goto out;

    r = callout_receive_reply(callout, outpipe[PIPE_READ], results);
    if (r)
        goto out;

    /* reap the child process */
    do {
        reaped = waitpid(pid, &status, 0);
        if (reaped < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ESRCH)
                break;
            if (errno == ECHILD)
                break;
            syslog(LOG_ERR, "error reaping callout pid %d: %m",
                    (int)pid);
            r = IMAP_SYS_ERROR;
            goto out;
        }
    }
    while (reaped != pid);
    r = 0;

out:
    if (inpipe[PIPE_READ] >= 0)
        close(inpipe[PIPE_READ]);
    if (inpipe[PIPE_WRITE] >= 0)
        close(inpipe[PIPE_WRITE]);
    if (outpipe[PIPE_READ] >= 0)
        close(outpipe[PIPE_READ]);
    if (outpipe[PIPE_WRITE] >= 0)
        close(outpipe[PIPE_WRITE]);
    return r;
#undef PIPE_READ
#undef PIPE_WRITE
}

/*
 * Encode the arguments for a callout into @buf.
 */
static void callout_encode_args(struct buf *args,
                                const char *fname,
                                const struct body *body,
                                struct entryattlist *annotations,
                                strarray_t *flags)
{
    struct entryattlist *ee;
    int i;

    buf_putc(args, '(');

    buf_printf(args, "FILENAME ");
    message_write_nstring(args, fname);

    buf_printf(args, " ANNOTATIONS (");
    for (ee = annotations ; ee ; ee = ee->next) {
        struct attvaluelist *av;
        message_write_nstring(args, ee->entry);
        buf_putc(args, ' ');
        buf_putc(args, '(');
        for (av = ee->attvalues ; av ; av = av->next) {
            message_write_nstring(args, av->attrib);
            buf_putc(args, ' ');
            message_write_nstring_map(args, av->value.s, av->value.len);
            if (av->next)
                buf_putc(args, ' ');
        }
        buf_putc(args, ')');
        if (ee->next)
            buf_putc(args, ' ');
    }
    buf_putc(args, ')');

    buf_printf(args, " FLAGS (");
    for (i = 0 ; i < flags->count ; i++) {
        if (i)
            buf_putc(args, ' ');
        buf_appendcstr(args, flags->data[i]);
    }
    buf_putc(args, ')');

    buf_appendcstr(args, " BODY ");
    message_write_body(args, body, 2);

    buf_printf(args, " GUID %s", message_guid_encode(&body->guid));
    buf_putc(args, ')');
    buf_cstring(args);
}

/*
 * Parse the reply from the callout.  This designed to be similar to the
 * arguments of the STORE command, except that we can have multiple
 * items one after the other and the whole thing is in a list.
 *
 * Examples:
 * (+FLAGS \Flagged)
 * (+FLAGS (\Flagged \Seen))
 * (-FLAGS \Flagged)
 * (ANNOTATION (/comment (value.shared "Hello World")))
 * (+FLAGS \Flagged ANNOTATION (/comment (value.shared "Hello")))
 *
 * The result is merged into @user_annots, @system_annots, and @flags.
 * User-set annotations are kept separate from system-set annotations
 * for two reasons: a) system-set annotations need to bypass the ACL
 * check to allow them to work during local delivery, and b) failure
 * to set system-set annotations needs to be logged but must not cause
 * the append to fail.
 */
static void callout_decode_results(const char *callout,
                                   const struct dlist *results,
                                   struct entryattlist **user_annots,
                                   struct entryattlist **system_annots,
                                   strarray_t *flags)
{
    struct dlist *dd;

    for (dd = results->head ; dd ; dd = dd->next) {
        const char *key = dlist_cstring(dd);
        const char *val;
        dd = dd->next;
        if (!dd)
            goto error;

        if (!strcasecmp(key, "+FLAGS")) {
            if (dd->head) {
                struct dlist *dflag;
                for (dflag = dd->head ; dflag ; dflag = dflag->next)
                    if ((val = dlist_cstring(dflag)))
                        strarray_add_case(flags, val);
            }
            else if ((val = dlist_cstring(dd))) {
                strarray_add_case(flags, val);
            }
        }
        else if (!strcasecmp(key, "-FLAGS")) {
            if (dd->head) {
                struct dlist *dflag;
                for (dflag = dd->head ; dflag ; dflag = dflag->next) {
                    if ((val = dlist_cstring(dflag)))
                        strarray_remove_all_case(flags, val);
                }
            }
            else if ((val = dlist_cstring(dd))) {
                strarray_remove_all_case(flags, val);
            }
        }
        else if (!strcasecmp(key, "ANNOTATION")) {
            const char *entry;
            struct dlist *dx = dd->head;

            if (!dx)
                goto error;
            entry = dlist_cstring(dx);
            if (!entry)
                goto error;

            for (dx = dx->next ; dx ; dx = dx->next) {
                const char *attrib;
                const char *valmap;
                size_t vallen;
                struct buf value = BUF_INITIALIZER;

                /* must be a list with exactly two elements,
                 * an attrib and a value */
                if (!dx->head || !dx->head->next || dx->head->next->next)
                    goto error;
                attrib = dlist_cstring(dx->head);
                if (!attrib)
                    goto error;
                if (!dlist_tomap(dx->head->next, &valmap, &vallen))
                    goto error;
                buf_init_ro(&value, valmap, vallen);
                clearentryatt(user_annots, entry, attrib);
                setentryatt(system_annots, entry, attrib, &value);
                buf_free(&value);
            }
        }
        else {
            goto error;
        }
    }

    return;
error:
    syslog(LOG_WARNING, "Unexpected data in response from callout %s",
           callout);
}

static int callout_run(const char *fname,
                       const struct body *body,
                       struct entryattlist **user_annots,
                       struct entryattlist **system_annots,
                       strarray_t *flags)
{
    const char *callout;
    struct stat sb;
    struct buf args = BUF_INITIALIZER;
    struct dlist *results = NULL;
    int r;

    callout = config_getstring(IMAPOPT_ANNOTATION_CALLOUT);
    assert(callout);
    assert(flags);

    callout_encode_args(&args, fname, body, *user_annots, flags);

    if (stat(callout, &sb) < 0) {
        syslog(LOG_ERR, "cannot stat annotation_callout %s: %m", callout);
        r = IMAP_IOERROR;
        goto out;
    }
    if (S_ISSOCK(sb.st_mode)) {
        /* UNIX domain socket on which a service is listening */
        r = callout_run_socket(callout, &args, &results);
        if (r)
            goto out;
    }
    else if (S_ISREG(sb.st_mode) &&
             (sb.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) {
        /* regular file, executable */
        r = callout_run_executable(callout, &args, &results);
        if (r)
            goto out;
    }
    else {
        syslog(LOG_ERR, "cannot classify annotation_callout %s", callout);
        r = IMAP_IOERROR;
        goto out;
    }

    if (results) {
        /* We have some results, parse them and merge them back into
         * the annotations and flags we were given */
        callout_decode_results(callout, results,
                               user_annots, system_annots, flags);
    }

out:
    buf_free(&args);
    dlist_free(&results);

    return r;
}

static int append_apply_flags(struct appendstate *as,
                              struct mboxevent *mboxevent,
                              msgrecord_t *msgrec,
                              const strarray_t *flags)
{
    int userflag;
    uint32_t system_flags = 0, internal_flags = 0;
    int i, r = 0;

    assert(flags);

    for (i = 0; i < flags->count; i++) {
        const char *flag = strarray_nth(flags, i);
        if (!strcasecmp(flag, "\\seen")) {
            r = append_setseen(as, msgrec);
            if (r) goto out;
            mboxevent_add_flag(mboxevent, flag);
        }
        else if (!strcasecmp(flag, "\\expunged")) {
            /* NOTE - this is a fake internal name */
            if (as->myrights & ACL_DELETEMSG) {
                internal_flags |= FLAG_INTERNAL_EXPUNGED;
            }
        }
        else if (!strcasecmp(flag, "\\snoozed")) {
            /* NOTE - this is a fake internal name */
            if (as->myrights & ACL_WRITE) {
                internal_flags |= FLAG_INTERNAL_SNOOZED;
            }
        }
        else if (!strcasecmp(flag, "\\deleted")) {
            if (as->myrights & ACL_DELETEMSG) {
                system_flags |= FLAG_DELETED;
                mboxevent_add_flag(mboxevent, flag);
            }
        }
        else if (!strcasecmp(flag, "\\draft")) {
            if (as->myrights & ACL_WRITE) {
                system_flags |= FLAG_DRAFT;
                mboxevent_add_flag(mboxevent, flag);
            }
        }
        else if (!strcasecmp(flag, "\\flagged")) {
            if (as->myrights & ACL_WRITE) {
                system_flags |= FLAG_FLAGGED;
                mboxevent_add_flag(mboxevent, flag);
            }
        }
        else if (!strcasecmp(flag, "\\answered")) {
            if (as->myrights & ACL_WRITE) {
                system_flags |= FLAG_ANSWERED;
                mboxevent_add_flag(mboxevent, flag);
            }
        }
        else if (as->myrights & ACL_WRITE) {
            r = mailbox_user_flag(as->mailbox, flag, &userflag, 1);
            if (r) goto out;
            r = msgrecord_set_userflag(msgrec, userflag, 1);
            if (r) goto out;
            mboxevent_add_flag(mboxevent, flag);
        }
    }

    r = msgrecord_add_systemflags(msgrec, system_flags);
    if (r) goto out;

    r = msgrecord_add_internalflags(msgrec, internal_flags);
    if (r) goto out;

out:
    return r;
}

struct findstage_cb_rock {
    const char *partition;
    const char *stagefile;
};

static int findstage_cb(const conv_guidrec_t *rec, void *vrock)
{
    struct findstage_cb_rock *rock = vrock;
    mbentry_t *mbentry = NULL;

    if (rec->part) return 0;
    // no point copying from archive, spool is on data
    if (rec->internal_flags & FLAG_INTERNAL_ARCHIVED) return 0;

    int r = mboxlist_lookup_by_guidrec(rec, &mbentry, NULL);
    if (r) return 0;

    if (!strcmp(rock->partition, mbentry->partition)) {
        struct stat sbuf;
        const char *msgpath = mbentry_datapath(mbentry, rec->uid);
        if (msgpath && !stat(msgpath, &sbuf)) {
            /* link the first stage part to the existing message file */
            r = cyrus_copyfile(msgpath, rock->stagefile, 0/*flags*/);
            if (r) {
                /* don't fail - worst case, we will use existing stage */
                r = 0;
            }
            else r = CYRUSDB_DONE;
        }
    }

    mboxlist_entry_free(&mbentry);

    return r;
}

/*
 * staging, to allow for single-instance store.  the complication here
 * is multiple partitions.
 *
 * Note: @user_annots needs to be freed by the caller but
 * may be modified during processing of callout responses.
 */
EXPORTED int append_fromstage_full(struct appendstate *as, struct body **body,
                                   struct stagemsg *stage,
                                   time_t internaldate, time_t savedate,
                                   modseq_t createdmodseq,
                                   const strarray_t *flags, int nolink,
                                   struct entryattlist **user_annotsp)
{
    struct mailbox *mailbox = as->mailbox;
    msgrecord_t *msgrec = NULL;
    const char *fname;
    int i, r;
    strarray_t *newflags = NULL;
    struct entryattlist *user_annots = user_annotsp ? *user_annotsp : NULL;
    struct entryattlist *system_annots = NULL;
    struct mboxevent *mboxevent = NULL;
#if defined ENABLE_OBJECTSTORE
    int object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;
#endif

    /* for staging */
    char stagefile[MAX_MAILBOX_PATH+1] = "";

    assert(stage != NULL && stage->parts.count);

    /* parse the first file */
    if (!*body) {
        FILE *file = fopen(stage->parts.data[0], "r");
        if (file) {
            r = message_parse_file(file, NULL, NULL, body, stage->parts.data[0]);
            fclose(file);
        }
        else
            r = IMAP_IOERROR;
        if (r) goto out;
    }

    /* xxx check errors */
    mboxlist_findstage(mailbox->name, stagefile, sizeof(stagefile));
    strlcat(stagefile, stage->fname, sizeof(stagefile));

    if (!nolink) {
        /* attempt to find an existing message with the same guid
           and use it as the stagefile */
        struct conversations_state *cstate = mailbox_get_cstate(mailbox);

        if (cstate) {
            struct findstage_cb_rock rock = { mailbox->part, stagefile };

            r = conversations_guid_foreach(cstate,
                                           message_guid_encode(&(*body)->guid),
                                           findstage_cb, &rock);
            if (r && r != CYRUSDB_DONE) {
                r = IMAP_IOERROR;
                goto out;
            }
        }
    }

    for (i = 0 ; i < stage->parts.count ; i++) {
        /* ok, we've successfully created the file */
        if (!strcmp(stagefile, stage->parts.data[i])) {
            /* aha, this is us */
            break;
        }
    }

    if (i == stage->parts.count) {
        /* ok, create this file, and copy the name of it into stage->parts. */

        /* create the new staging file from the first stage part */
        r = mailbox_copyfile(stage->parts.data[0], stagefile, 0);
        if (r) {
            /* maybe the directory doesn't exist? */
            char stagedir[MAX_MAILBOX_PATH+1];

            /* xxx check errors */
            mboxlist_findstage(mailbox->name, stagedir, sizeof(stagedir));
            if (mkdir(stagedir, 0755) != 0) {
                syslog(LOG_ERR, "couldn't create stage directory: %s: %m",
                       stagedir);
            } else {
                syslog(LOG_NOTICE, "created stage directory %s",
                       stagedir);
                r = mailbox_copyfile(stage->parts.data[0], stagefile, 0);
            }
        }
        if (r) {
            /* oh well, we tried */

            xsyslog(LOG_ERR, "IOERROR: creating message file",
                             "filename=<%s>", stagefile);
            unlink(stagefile);
            goto out;
        }

        strarray_append(&stage->parts, stagefile);
    }

    /* 'stagefile' contains the message and is on the same partition
       as the mailbox we're looking at */

    /* Setup */

    /* prepare a new notification for this appended message
     * the event type must be set with MessageNew or MessageAppend */
    if (as->event_type) {
        mboxevent = mboxevent_enqueue(as->event_type, &as->mboxevents);
    }

    uint32_t uid = as->baseuid + as->nummsg;

    /* we need to parse the record first */
    msgrec = msgrecord_new(mailbox);
    r = msgrecord_set_uid(msgrec, uid);
    if (r) goto out;
    r = msgrecord_set_internaldate(msgrec, internaldate);
    if (r) goto out;
    r = msgrecord_set_createdmodseq(msgrec, createdmodseq);
    if (r) goto out;
    r = msgrecord_set_bodystructure(msgrec, *body);
    if (r) goto out;
    if (savedate) {
        r = msgrecord_set_savedate(msgrec, savedate);
        if (r) goto out;
    }

    /* And make sure it has a timestamp */
    r = msgrecord_get_internaldate(msgrec, &internaldate);
    if (!r && !internaldate)
        r = msgrecord_set_internaldate(msgrec, time(NULL));
    if (r) goto out;

    /* should we archive it straight away? */
    if (msgrecord_should_archive(msgrec, NULL)) {
        r = msgrecord_add_internalflags(msgrec, FLAG_INTERNAL_ARCHIVED);
        if (r) goto out;
    }

    /* unlink BOTH potential destination files to clean up any past failure.
     * This was added because we found that a small message was partially
     * delivered and got uid X. - then later a large message was delivered
     * with the same UID which went straight to archive, and the file with
     * the same name was left lying around in the filesystem */
    mailbox_cleanup_uid(mailbox, uid, "ZZ");

    /* Create message file */
    as->nummsg++;
    r = msgrecord_get_fname(msgrec, &fname);
    if (r) goto out;

    r = mailbox_copyfile(stagefile, fname, nolink);
    if (r) goto out;

    FILE *destfile = fopen(fname, "r");
    if (destfile) {
        /* this will hopefully ensure that the link() actually happened
           and makes sure that the file actually hits disk */
        fsync(fileno(destfile));
        fclose(destfile);
    }
    else {
        r = IMAP_IOERROR;
        goto out;
    }

    if (config_getstring(IMAPOPT_ANNOTATION_CALLOUT)) {
        if (flags)
            newflags = strarray_dup(flags);
        else
            newflags = strarray_new();
        r = callout_run(fname, *body, &user_annots, &system_annots, newflags);
        if (r) {
            syslog(LOG_ERR, "Annotation callout failed, ignoring");
            r = 0;
        }
        flags = newflags;
        if (user_annotsp) *user_annotsp = user_annots;
    }

    /* straight to archive? */
    int in_object_storage = 0;
#if defined ENABLE_OBJECTSTORE

    if (object_storage_enabled)
    {
        uint32_t internal_flags;
        r = msgrecord_get_internalflags(msgrec, &internal_flags);
        if (r) goto out;

        if (internal_flags & FLAG_INTERNAL_ARCHIVED) {
            struct index_record record;
            r = msgrecord_get_index_record(msgrec, &record);
            if (!r) {
                r = objectstore_put(mailbox, &record, fname);
                if (!r) {
                    // file in object store now; must delete local copy
                    in_object_storage = 1;
                }
                else {
                    // didn't manage to store it, so remove the ARCHIVED flag
                    internal_flags &= ~FLAG_INTERNAL_ARCHIVED;
                    r = msgrecord_set_internalflags(msgrec, internal_flags);
                    if (r) goto out;
                }
            }
        }
    }
#endif

    /* Handle flags the user wants to set in the message */
    if (flags) {
        r = append_apply_flags(as, mboxevent, msgrec, flags);
        if (r) {
            syslog(LOG_ERR, "Annotation callout failed to apply flags %s", error_message(r));
            goto out;
        }
    }

    /* Write the new message record */
    r = msgrecord_append(msgrec);
    if (r) goto out;

    if (in_object_storage) {  // must delete local file
        if (unlink(fname) != 0) // unlink should do it.
            if (!remove (fname))  // we must insist
                syslog(LOG_ERR, "Removing local file <%s> error", fname);
    }

    /* Apply the annotations */
    if (user_annots || system_annots) {
        /* pretend to be admin to avoid ACL checks when writing annotations here, since there calling user
         * didn't control them */
        if (user_annots) {
           r = msgrecord_annot_set_auth(msgrec, /*isadmin*/1, as->userid, as->auth_state);
           if (!r) r = msgrecord_annot_writeall(msgrec, user_annots);
        }
        if (r) {
            syslog(LOG_ERR, "Annotation callout failed to apply user annots %s", error_message(r));
            goto out;
        }
        if (system_annots) {
           r = msgrecord_annot_set_auth(msgrec, /*isadmin*/1, as->userid, as->auth_state);
           if (!r) r = msgrecord_annot_writeall(msgrec, system_annots);
        }
        if (r) {
            syslog(LOG_ERR, "Annotation callout failed to apply system annots %s", error_message(r));
            goto out;
        }
    }

out:
    if (newflags)
        strarray_free(newflags);
    freeentryatts(system_annots);
    if (r) {
        append_abort(as);
        msgrecord_unref(&msgrec);
        return r;
    }

    /* finish filling the event notification */
    /* XXX avoid to parse ENVELOPE record since Message-Id is already
     * present in body structure ? */
    mboxevent_extract_msgrecord(mboxevent, msgrec);
    mboxevent_extract_mailbox(mboxevent, mailbox);
    mboxevent_set_access(mboxevent, NULL, NULL, as->userid, as->mailbox->name, 1);
    mboxevent_set_numunseen(mboxevent, mailbox, -1);

    msgrecord_unref(&msgrec);
    return r;
}

EXPORTED int append_removestage(struct stagemsg *stage)
{
    char *p;

    if (stage == NULL) return 0;

    while ((p = strarray_pop(&stage->parts))) {
        /* unlink the staging file */
        if (unlink(p) != 0) {
            xsyslog(LOG_ERR, "IOERROR: error unlinking file",
                             "filename=<%s>", p);
        }
        free(p);
    }

    strarray_fini(&stage->parts);
    free(stage);
    return 0;
}

/*
 * Append to 'mailbox' from the prot stream 'messagefile'.
 * 'mailbox' must have been opened with append_setup().
 * 'size' is the expected size of the message.
 * 'internaldate' specifies the internaldate for the new message.
 * 'flags' contains the names of the 'nflags' flags that the
 * user wants to set in the message.  If the '\Seen' flag is
 * in 'flags', then the 'userid' passed to append_setup controls whose
 * \Seen flag gets set.
 *
 * The message is not committed to the mailbox (nor is the mailbox
 * unlocked) until append_commit() is called.  multiple
 * append_onefromstream()s can be aborted by calling append_abort().
 */
EXPORTED int append_fromstream(struct appendstate *as, struct body **body,
                      struct protstream *messagefile,
                      unsigned long size,
                      time_t internaldate,
                      const strarray_t *flags)
{
    struct mailbox *mailbox = as->mailbox;
    const char *fname;
    msgrecord_t *msgrec = NULL;
    FILE *destfile;
    int r;
    struct mboxevent *mboxevent = NULL;

    assert(size != 0);

    /* Setup */
    msgrec = msgrecord_new(mailbox);
    r = msgrecord_set_uid(msgrec, as->baseuid + as->nummsg);
    if (r) goto out;
    r = msgrecord_set_internaldate(msgrec, internaldate);
    if (r) goto out;

    /* Create message file */
    r = msgrecord_get_fname(msgrec, &fname);
    if (r) goto out;
    as->nummsg++;

    unlink(fname);
    destfile = fopen(fname, "w+");
    if (!destfile) {
        xsyslog(LOG_ERR, "IOERROR: creating message file",
                         "filename=<%s>", fname);
        r = IMAP_IOERROR;
        goto out;
    }

    /* prepare a new notification for this appended message
     * the event type must be set with MessageNew or MessageAppend */
    if (as->event_type) {
        mboxevent = mboxevent_enqueue(as->event_type, &as->mboxevents);
    }

    /* XXX - also stream to stage directory and check out archive options */

    /* Copy and parse message */
    r = message_copy_strict(messagefile, destfile, size, 0);
    if (!r) {
        if (!*body || (as->nummsg - 1))
            r = message_parse_file(destfile, NULL, NULL, body, fname);
        if (!r) r = msgrecord_set_bodystructure(msgrec, *body);

        /* messageContent may be included with MessageAppend and MessageNew */
        if (!r)
            mboxevent_extract_content_msgrec(mboxevent, msgrec, destfile);
    }
    fclose(destfile);
    if (r) goto out;

    /* Handle flags the user wants to set in the message */
    if (flags) {
        r = append_apply_flags(as, mboxevent, msgrec, flags);
        if (r) goto out;
    }

    /* Write out index file entry; if we abort later, it's not
       important */
    r = msgrecord_append(msgrec);

out:
    if (r) {
        append_abort(as);
        return r;
    }

    /* finish filling the event notification */
    /* XXX avoid to parse ENVELOPE record since Message-Id is already
     * present in body structure */
    mboxevent_extract_msgrecord(mboxevent, msgrec);
    mboxevent_extract_mailbox(mboxevent, mailbox);
    mboxevent_set_access(mboxevent, NULL, NULL, as->userid, as->mailbox->name, 1);
    mboxevent_set_numunseen(mboxevent, mailbox, -1);
    msgrecord_unref(&msgrec);

    return 0;
}

HIDDEN int append_run_annotator(struct appendstate *as,
                                msgrecord_t *msgrec)
{
    FILE *f = NULL;
    const char *fname;
    struct entryattlist *user_annots = NULL;
    struct entryattlist *system_annots = NULL;
    strarray_t *flags = NULL;
    struct body *body = NULL;
    int r = 0;

    if (!config_getstring(IMAPOPT_ANNOTATION_CALLOUT))
        return 0;

    if (config_getswitch(IMAPOPT_ANNOTATION_CALLOUT_DISABLE_APPEND)) {
        syslog(LOG_DEBUG, "append_run_annotator: Append disabled.");
        return 0;
    }

    r = msgrecord_extract_flags(msgrec, as->userid, &flags);
    if (r) goto out;
    r = msgrecord_extract_annots(msgrec, &user_annots);
    if (r) goto out;

    r = msgrecord_get_fname(msgrec, &fname);
    if (r) goto out;

    f = fopen(fname, "r");
    if (!f) {
        r = IMAP_IOERROR;
        goto out;
    }

    r = message_parse_file(f, NULL, NULL, &body, fname);
    if (r) goto out;

    fclose(f);
    f = NULL;

    r = callout_run(fname, body, &user_annots, &system_annots, flags);
    if (r) goto out;

    /* Reset system flags */
    uint32_t system_flags;
    r = msgrecord_get_systemflags(msgrec, &system_flags);
    if (!r) {
        system_flags &= (FLAG_SEEN);
        r = msgrecord_set_systemflags(msgrec, system_flags);
    }
    if (r) goto out;

    /* Reset user flags */
    uint32_t user_flags[MAX_USER_FLAGS/32];
    memset(user_flags, 0, sizeof(user_flags));
    r = msgrecord_set_userflags(msgrec, user_flags);
    if (r) goto out;

    /* Apply annotator flags */
    r = append_apply_flags(as, NULL, msgrec, flags);
    if (r) {
        syslog(LOG_ERR, "Setting flags from annotator "
                        "callout failed (%s)",
                        error_message(r));
        goto out;
    }

    if (system_annots) {
        /* pretend to be admin to avoid ACL checks */
        r = msgrecord_annot_set_auth(msgrec, /*isadmin*/1, as->userid, as->auth_state);
        if (r) goto out;
        r = msgrecord_annot_writeall(msgrec, system_annots);
        if (r) {
            char *res = dumpentryatt(system_annots);
            syslog(LOG_ERR, "Setting system annotations from annotator "
                            "callout failed (%s) for %s",
                            error_message(r), res);
            free(res);
            goto out;
        }
    }

    r = msgrecord_rewrite(msgrec);

out:
    if (f) fclose(f);
    freeentryatts(user_annots);
    freeentryatts(system_annots);
    strarray_free(flags);
    if (body) {
        message_free_body(body);
        free(body);
    }
    return r;
}

/*
 * Append to 'as->mailbox' the 'nummsg' messages from the
 * mailbox 'mailbox' listed in the array pointed to by 'records'.
 * 'as' must have been opened with append_setup().  If the '\Seen'
 * flag is to be set anywhere then 'userid' passed to append_setup()
 * contains the name of the user whose \Seen flag gets set.
 */
EXPORTED int append_copy(struct mailbox *mailbox, struct appendstate *as,
                         ptrarray_t *msgrecs, int nolink, int is_same_user)
{
    int msg;
    char *srcfname = NULL;
    char *destfname = NULL;
    int object_storage_enabled = 0 ;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;
#endif
    int r = 0;
    int userflag;
    int i;
    struct mboxevent *mboxevent = NULL;
    msgrecord_t *dst_msgrec = NULL;

    if (!msgrecs->count) {
        append_abort(as);
        return 0;
    }

    /* prepare a single vnd.cmu.MessageCopy notification for all messages */
    if (as->event_type) {
        mboxevent = mboxevent_enqueue(as->event_type, &as->mboxevents);
    }

    /* Copy/link all files and cache info */
    for (msg = 0; msg < msgrecs->count; msg++) {
        msgrecord_t *src_msgrec = ptrarray_nth(msgrecs, msg);
        uint32_t src_uid;
        uint32_t src_system_flags;
        uint32_t src_internal_flags;

        r = msgrecord_get_uid(src_msgrec, &src_uid);
        if (r) goto out;
        r = msgrecord_get_systemflags(src_msgrec, &src_system_flags);
        if (r) goto out;
        r = msgrecord_get_internalflags(src_msgrec, &src_internal_flags);
        if (r) goto out;
        /* read in existing cache record BEFORE we copy data, so that the
         * mmap will be up to date even if it's the same mailbox for source
         * and destination */
        r = msgrecord_load_cache(src_msgrec);
        if (r) goto out;

        /* wipe out the bits that aren't magically copied */
        uint32_t dst_system_flags, dst_internal_flags;
        uint32_t dst_user_flags[MAX_USER_FLAGS/32];

        dst_msgrec = msgrecord_copy_msgrecord(as->mailbox, src_msgrec);

        /* clear savedate */
        r = msgrecord_set_savedate(dst_msgrec, 0);
        if (r) goto out;

        r = msgrecord_get_systemflags(dst_msgrec, &dst_system_flags);
        if (r) goto out;
        dst_system_flags &= ~FLAG_SEEN;

        r = msgrecord_get_internalflags(dst_msgrec, &dst_internal_flags);
        if (r) goto out;
        dst_internal_flags &= ~FLAG_INTERNAL_SNOOZED;

        for (i = 0; i < MAX_USER_FLAGS/32; i++) {
            dst_user_flags[i] = 0;
        }
        r = msgrecord_set_userflags(dst_msgrec, dst_user_flags);
        if (r) goto out;

        if (!is_same_user) {
            r = msgrecord_set_cid(dst_msgrec, NULLCONVERSATION);
            if (r) goto out;
        }

        r = msgrecord_set_cache_offset(dst_msgrec, 0);
        if (r) goto out;

        /* renumber the message into the new mailbox */
        uint32_t dst_uid = as->mailbox->i.last_uid + 1;
        r = msgrecord_set_uid(dst_msgrec, dst_uid);
        if (r) goto out;
        as->nummsg++;

        /* user flags are special - different numbers, so look them up */
        if (as->myrights & ACL_WRITE) {
            uint32_t src_user_flags[MAX_USER_FLAGS/32];

            r = msgrecord_get_userflags(src_msgrec, src_user_flags);
            if (r) goto out;

            for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
                bit32 flagmask = src_user_flags[userflag/32];
                if (mailbox->flagname[userflag] && (flagmask & (1<<(userflag&31)))) {
                    int num;
                    r = mailbox_user_flag(as->mailbox, mailbox->flagname[userflag], &num, 1);
                    if (r)
                        xsyslog(LOG_ERR, "IOERROR: unable to copy flag",
                                         "flag=<%s> src_mailbox=<%s> dest_mailbox=<%s>"
                                         " uid=<%u> error=<%s>",
                                         mailbox->flagname[userflag],
                                         mailbox->name,
                                         as->mailbox->name,
                                         src_uid,
                                         error_message(r));
                    else
                        dst_user_flags[num/32] |= 1<<(num&31);
                }
            }

            r = msgrecord_set_userflags(dst_msgrec, dst_user_flags);
            if (r) {
                xsyslog(LOG_ERR, "IOERROR: unable to copy user flags",
                                 "source=<%s> dest=<%s> uid=<%u> error=<%s>",
                                 mailbox->name, as->mailbox->name,
                                 src_uid, error_message(r));
            }
        }
        else {
            /* only flag allow to be kept without ACL_WRITE is DELETED */
            dst_system_flags &= FLAG_DELETED;
        }

        /* deleted flag has its own ACL */
        if (!(as->myrights & ACL_DELETEMSG)) {
            dst_system_flags &= ~FLAG_DELETED;
        }

        /* we're not modifying the ARCHIVED flag here, just keeping it */

        /* set system flags */
        r = msgrecord_set_systemflags(dst_msgrec, dst_system_flags);
        if (r) goto out;

        /* set internal flags */
        r = msgrecord_set_internalflags(dst_msgrec, dst_internal_flags);
        if (r) goto out;

        /* should this message be marked \Seen? */
        if (src_system_flags & FLAG_SEEN) {
            append_setseen(as, dst_msgrec);
        }

        /* Link/copy message file */
        free(srcfname);
        free(destfname);

        const char *tmp;
        r = msgrecord_get_fname(src_msgrec, &tmp);
        if (r) goto out;
        srcfname = xstrdup(tmp);

        r = msgrecord_get_fname(dst_msgrec, &tmp);
        if (r) goto out;
        destfname = xstrdup(tmp);

        if (!(object_storage_enabled &&
              src_internal_flags & FLAG_INTERNAL_ARCHIVED))   // if object storage do not move file
           r = mailbox_copyfile(srcfname, destfname, nolink);

        if (r) goto out;

#if defined ENABLE_OBJECTSTORE
        if (object_storage_enabled &&
            src_internal_flags & FLAG_INTERNAL_ARCHIVED) {
            struct index_record record;
            r = msgrecord_get_index_record(dst_msgrec, &record);
            if (!r) r = objectstore_put(as->mailbox, &record, destfname);   // put should just add the refcount.
        }
#endif

        /* Write out index file entry */
        r = msgrecord_append(dst_msgrec);
        if (r) goto out;

        /* ensure we have an astate connected to the destination
         * mailbox, so that the annotation txn will be committed
         * when we close the mailbox */
        annotate_state_t *astate = NULL;
        r = mailbox_get_annotate_state(as->mailbox, dst_uid, &astate);
        if (r) goto out;
        r = annotate_msg_copy(mailbox, src_uid,
                              as->mailbox, dst_uid,
                              as->userid);
        if (r) goto out;

        mboxevent_extract_msgrecord(mboxevent, dst_msgrec);
        mboxevent_extract_copied_msgrecord(mboxevent, src_msgrec);

        msgrecord_unref(&dst_msgrec);
    }

out:
    free(srcfname);
    free(destfname);
    msgrecord_unref(&dst_msgrec);

    if (r) {
        append_abort(as);
        return r;
    }

    mboxevent_extract_mailbox(mboxevent, as->mailbox);
    mboxevent_set_access(mboxevent, NULL, NULL, as->userid, as->mailbox->name, 1);
    mboxevent_set_numunseen(mboxevent, as->mailbox, -1);

    return 0;
}

static int append_setseen(struct appendstate *as, msgrecord_t *msgrec)
{
    int r = 0;
    if (as->internalseen) {
        r = msgrecord_add_systemflags(msgrec, FLAG_SEEN);
    }
    else {
        uint32_t uid;
        r = msgrecord_get_uid(msgrec, &uid);
        if (!r) seqset_add(as->seen_seq, uid, 1);
    }
    return r;
}

/*
 * Set the \Seen flag for 'userid' in 'mailbox' for the messages from
 * 'msgrange'.  the lowest msgrange must be larger than any previously
 * seen message.
 */
static int append_addseen(struct mailbox *mailbox,
                          const char *userid,
                          struct seqset *newseen)
{
    int r;
    struct seen *seendb = NULL;
    struct seendata sd = SEENDATA_INITIALIZER;
    struct seqset *oldseen;

    if (!newseen->len)
        return 0;

    r = seen_open(userid, SEEN_CREATE, &seendb);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: seen_open failed",
                         "userid=<%s>", userid);
        goto done;
    }

    r = seen_lockread(seendb, mailbox->uniqueid, &sd);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: seen_lockread failed",
                         "userid=<%s> uniqueid=<%s>",
                         userid, mailbox->uniqueid);
        goto done;
    }

    /* parse the old sequence */
    oldseen = seqset_parse(sd.seenuids, NULL, mailbox->i.last_uid);
    seen_freedata(&sd);

    /* add the extra items */
    seqset_join(oldseen, newseen);
    sd.seenuids = seqset_cstring(oldseen);
    seqset_free(oldseen);

    /* and write it out */
    sd.lastchange = time(NULL);
    r = seen_write(seendb, mailbox->uniqueid, &sd);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: seen_write failed",
                         "userid=<%s> uniqueid=<%s>",
                         userid, mailbox->uniqueid);
    }
    seen_freedata(&sd);

 done:
    seen_close(&seendb);
    return r;
}

EXPORTED const char *append_stagefname(struct stagemsg *stage)
{
    return strarray_nth(&stage->parts, 0);
}
