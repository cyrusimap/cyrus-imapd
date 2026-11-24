/* lmtp_emailpush.c -- JMAP email delivery push from lmtpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "conversations.h"
#include "jmap_mail_query.h"
#include "jmap_util.h"
#include "json_support.h"
#include "lmtp_emailpush.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "pushsub_db.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* The deliveries to one recipient */
static struct
{
    char *userid;
    char emailid[JMAP_MAX_EMAILID_SIZE];
    struct jmap_email_delivery delivery;
    strarray_t flags; /* the keywords of each delivered copy */
    size_t ncopies;
} cur;

static void reset(void)
{
    free(cur.userid);
    strarray_fini(&cur.delivery.mailboxids);
    strarray_fini(&cur.delivery.keywords);
    strarray_fini(&cur.flags);
    memset(&cur, 0, sizeof(cur));
}

EXPORTED void emailpush_begin(const char *userid)
{
    reset();

    if (userid && config_getswitch(IMAPOPT_JMAP_EMAILPUSH)) {
        cur.userid = xstrdup(userid);
    }
}

EXPORTED void emailpush_add(struct mailbox *mailbox, uint32_t uid)
{
    if (!cur.userid
        || !mboxname_userownsmailbox(cur.userid, mailbox_name(mailbox)))
    {
        return;
    }

    struct conversations_state *cstate = mailbox_get_cstate(mailbox);
    struct index_record record;
    mbentry_t *mbentry = NULL;

    int r = mailbox_find_index_record(mailbox, uid, &record);
    if (!r) {
        r = mboxlist_lookup(mailbox_name(mailbox), &mbentry, NULL);
    }
    if (r || !cstate) {
        xsyslog_ev(LOG_ERR, "lmtp.emailpush.record.failed",
                   lf_mailbox(mailbox),
                   lf_u("msg.imapuid", uid),
                   lf_err("error", r ? r : IMAP_INTERNAL));
        mboxlist_entry_free(&mbentry);
        return;
    }

    if (!cur.ncopies) {
        jmap_set_emailid(cstate,
                         &record.guid,
                         0,
                         &record.internaldate,
                         cur.emailid);
    }

    char mboxid[JMAP_MAX_MAILBOXID_SIZE];
    jmap_set_mailboxid(cstate, mbentry, mboxid);
    strarray_add(&cur.delivery.mailboxids, mboxid);
    mboxlist_entry_free(&mbentry);

    /* as Email/get reports them for the user's own mailboxes */
    if (record.system_flags & FLAG_DRAFT) {
        strarray_append(&cur.flags, "$draft");
    }
    if (record.system_flags & FLAG_FLAGGED) {
        strarray_append(&cur.flags, "$flagged");
    }
    if (record.system_flags & FLAG_ANSWERED) {
        strarray_append(&cur.flags, "$answered");
    }
    if (record.system_flags & FLAG_SEEN) {
        strarray_append(&cur.flags, "$seen");
    }
    for (int i = 0; i < MAX_USER_FLAGS; i++) {
        if (mailbox->h.flagname[i]
            && (record.user_flags[i / 32] & 1U << (i & 31)))
        {
            strarray_appendm(&cur.flags,
                             lcase(xstrdup(mailbox->h.flagname[i])));
        }
    }
    cur.ncopies++;
}

/* An Email has a keyword if any copy does, except $seen, which needs all */
static void set_keywords(void)
{
    const char *flag;
    int i;

    strarray_foreach(&cur.flags, i, flag)
    {
        if (strarray_contains(&cur.delivery.keywords, flag)) {
            continue;
        }
        if (!strcmp(flag, "$seen")) {
            size_t nseen = 0;
            const char *f;
            int j;
            strarray_foreach(&cur.flags, j, f)
            {
                nseen += !strcmp(f, "$seen");
            }
            if (nseen < cur.ncopies) {
                continue;
            }
        }
        strarray_append(&cur.delivery.keywords, flag);
    }
}

struct match_rock
{
    struct message_content *content;
    FILE *f;
    struct conversations_state *cstate;
    const struct auth_state *authstate;
    const struct namespace *ns;
    time_t now;
    json_t *matches;
};

static int match_subscription(void *vrock, struct pushsub_data *psdata)
{
    struct match_rock *rock = vrock;

    /* MUST NOT push before verification, nor after expiry */
    if (!psdata->isverified || psdata->expires <= rock->now) {
        return 0;
    }

    json_t *jpushsub = json_loads(psdata->subscription, 0, NULL);
    json_t *jconfig =
        json_object_get(json_object_get(jpushsub, "emailPush"), cur.userid);
    if (!json_is_object(jconfig)) {
        goto done;
    }

    json_t *jfilter = json_object_get(jconfig, "filter");
    bool matches = true;

    if (JNOTNULL(jfilter)) {
        struct message_content *content = rock->content;
        json_t *err = NULL;

        if (!content->body
            && message_parse_file_buf(rock->f,
                                      &content->map,
                                      &content->body,
                                      NULL))
        {
            matches = false;
        }
        else {
            if (!content->matchmime) {
                content->matchmime =
                    jmap_email_matchmime_new(&content->map, &err);
            }
            matches = content->matchmime
                      && jmap_email_matchmime(content->matchmime,
                                              jfilter,
                                              rock->cstate,
                                              cur.userid,
                                              rock->authstate,
                                              rock->ns,
                                              rock->now,
                                              &cur.delivery,
                                              &err);
        }

        if (err) {
            char *errstr = json_dumps(err, JSON_COMPACT);
            xsyslog_ev(LOG_ERR, "lmtp.emailpush.match.failed",
                       lf_s("u.username", cur.userid),
                       lf_s("jmap.pushsubid", psdata->id),
                       lf_s("error", errstr));
            free(errstr);
            json_decref(err);
            matches = false;
        }
    }

    if (matches) {
        json_array_append_new(rock->matches, json_string(psdata->id));
    }

done:
    json_decref(jpushsub);
    return 0;
}

EXPORTED void emailpush_end(struct message_content *content,
                            FILE *f,
                            const struct namespace *ns)
{
    if (!cur.userid || !cur.ncopies) {
        goto done;
    }

    /* skip users who have no subscriptions, without creating a DAV db */
    char *mboxname = pushsub_mboxname(cur.userid);
    int r = mboxlist_lookup(mboxname, NULL, NULL);
    free(mboxname);
    if (r) {
        goto done;
    }

    struct pushsub_db *db = pushsubdb_open_userid(cur.userid);
    if (!db) {
        goto done;
    }

    set_keywords();

    struct conversations_state *cstate = NULL;
    conversations_open_user(cur.userid, 1 /*shared*/, &cstate);
    struct auth_state *authstate = auth_newstate(cur.userid);
    struct match_rock rock = { content, f,          cstate,      authstate,
                               ns,      time(NULL), json_array() };

    pushsubdb_foreach(db, &match_subscription, &rock);
    pushsubdb_close(db);
    conversations_commit(&cstate);
    auth_freestate(authstate);

    if (json_array_size(rock.matches)) {
        json_t *jmboxids = json_object();
        const char *mboxid;
        int i;
        strarray_foreach(&cur.delivery.mailboxids, i, mboxid)
        {
            json_object_set_new(jmboxids, mboxid, json_true());
        }

        struct mboxevent *event = mboxevent_new(EVENT_EMAILPUSH);
        FILL_STRING_PARAM(event, EVENT_PUSHSUB_USERID, xstrdup(cur.userid));
        FILL_JSON_PARAM(event,
                        EVENT_PUSHSUB_CONTENT,
                        json_pack("{s:s s:s s:o s:O}",
                                  "accountId",
                                  cur.userid,
                                  "emailId",
                                  cur.emailid,
                                  "mailboxIds",
                                  jmboxids,
                                  "pushSubscriptionIds",
                                  rock.matches));
        mboxevent_notify(&event);
        mboxevent_free(&event);
    }
    json_decref(rock.matches);

done:
    reset();
}
