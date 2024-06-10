/* ctl_mboxlist.c -- do DB related operations on mboxlist
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

/* currently doesn't catch signals; probably SHOULD */

#include <config.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <getopt.h>
#include <inttypes.h>
#include <sysexits.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>

#include "assert.h"
#include "annotate.h"
#include "dlist.h"
#include "global.h"
#include "json_support.h"
#include "libcyr_cfg.h"
#include "mboxlist.h"
#include "mupdate.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/mupdate_err.h"
#include "lib/ptrarray.h"

enum mboxop { DUMP,
              M_POPULATE,
              UNDUMP,
              VERIFY,
              NONE };

struct dumprock {
    const char *partition;
    int purge;
    const char *sep;
};

struct popmupdaterock {
    mupdate_handle *h;
};

struct mb_node
{
    char mailbox[MAX_MAILBOX_BUFFER];
    char location[MAX_MAILBOX_BUFFER];
    char *acl;
    struct mb_node *next;
};

static struct mb_node *act_head = NULL, **act_tail = &act_head;
static struct mb_node *del_head = NULL;
static struct mb_node *wipe_head = NULL, *unflag_head = NULL;

/* assume the local copy is authoritative and that it should just overwrite
 * mupdate */
static int local_authoritative = 0;
static int warn_only = 0;
static int interactive = 0;

/* For each mailbox that this guy gets called for, check that
 * it is a mailbox that:
 * a) mupdate server thinks *we* host
 *    -> Because we were called, this is the case, provided we
 *    -> gave the prefix parameter to the remote.
 *    -> (And assuming bugs don't exist.)
 * b) we do not actually host
 *
 * if that's the case, enqueue a delete
 * otherwise, we both agree that it exists, but we still need
 * to verify that its info is up to date.
 */
static int mupdate_list_cb(struct mupdate_mailboxdata *mdata,
                           const char *cmd,
                           void *context __attribute__((unused)))
{
    int ret;

    /* the server thinks we have it, do we think we have it? */
    ret = mboxlist_lookup(mdata->mailbox, NULL, NULL);
    if (ret) {
        struct mb_node *next;

        next = xzmalloc(sizeof(struct mb_node));
        strlcpy(next->mailbox, mdata->mailbox, sizeof(next->mailbox));

        next->next = del_head;
        del_head = next;
    } else {
        /* we both agree that it exists */
        /* throw it onto the back of the activate queue */
        /* we may or may not need to send an update */
        struct mb_node *next;

        next = xzmalloc(sizeof(struct mb_node));
        strlcpy(next->mailbox, mdata->mailbox, sizeof(next->mailbox));
        strlcpy(next->location, mdata->location, sizeof(next->location));
        if (!strncmp(cmd, "MAILBOX", 7))
            next->acl = xstrdup(mdata->acl);

        *act_tail = next;
        act_tail = &(next->next);
    }
    return 0;
}

static int pop_mupdate_cb(const mbentry_t *mbentry, void *rockp)
{
    struct popmupdaterock *rock = (struct popmupdaterock *) rockp;
    int r = 0;

    if (mbentry->mbtype & MBTYPE_DELETED)
        return 0;

    /* realpart is 'hostname!partition' */
    char *realpart =
        strconcat(config_servername, "!", mbentry->partition, (char *)NULL);
    int skip_flag = 0;

    /* If it is marked MBTYPE_MOVING, and it DOES match the entry,
     * we need to unmark it.  If it does not match the entry in our
     * list, then we assume that it successfully made the move and
     * we delete it from the local disk */

    /* If they match, then we should check that we actually need
     * to update it.  If they *don't* match, then we believe that we
     * need to send fresh data.  There will be no point at which something
     * is in the act_head list that we do not have locally, because that
     * is a condition of being in the act_head list */
    if (act_head && !strcmp(mbentry->name, act_head->mailbox)) {
        struct mb_node *tmp;

        /* If this mailbox was moving, we want to unmark the movingness,
         * since the MUPDATE server agreed that it lives here. */
        /* (and later also force an mupdate push) */
        if (mbentry->mbtype & MBTYPE_MOVING) {
            struct mb_node *next;

            syslog(LOG_WARNING, "Remove remote flag on: %s", mbentry->name);

            if (warn_only) {
                printf("Remove remote flag on: %s\n", mbentry->name);
            } else {
                next = xzmalloc(sizeof(struct mb_node));
                strlcpy(next->mailbox, mbentry->name, sizeof(next->mailbox));
                next->next = unflag_head;
                unflag_head = next;
            }

            /* No need to update mupdate NOW, we'll get it when we
             * untag the mailbox */
            skip_flag = 1;
        } else if (act_head->acl) {
            if (
                    !strcmp(realpart, act_head->location) &&
                    !strcmp(mbentry->acl, act_head->acl)
                ) {

                /* Do not update if location does match, and there is an acl,
                 * and the acl matches */

                skip_flag = 1;
            }
        }

        /* in any case, free the node. */
        if (act_head->acl) free(act_head->acl);
        tmp = act_head;
        act_head = act_head->next;
        if (tmp) free(tmp);
    } else {
        /* if they do not match, do an explicit MUPDATE find on the
         * mailbox, and if it is living somewhere else, delete the local
         * data, if it is NOT living somewhere else, recreate it in
         * mupdate */
        struct mupdate_mailboxdata *mdata;

        /* if this is okay, we found it (so it is on another host, since
         * it wasn't in our list in this position) */
        if (!local_authoritative &&
            !mupdate_find(rock->h, mbentry->name, &mdata)) {
            /* since it lives on another server, schedule it for a wipe */
            struct mb_node *next;

            /*
             * Verify that what we found points at another host,
             * not back to this host.  Good idea, since if our assumption
             * if wrong, we'll end up removing the authoritative
             * mailbox.
             */
            if (strcmp(realpart, mdata->location) == 0 ) {
                if ( act_head ) {
                    fprintf( stderr, "mupdate said: %s %s %s\n",
                        act_head->mailbox, act_head->location, act_head->acl );
                }
                fprintf( stderr, "mailboxes.db said: %s %s %s\n",
                        mbentry->name, realpart, mbentry->acl );
                fprintf( stderr, "mupdate says: %s %s %s\n",
                        mdata->mailbox, mdata->location, mdata->acl );
                fatal("mupdate said not us before it said us", EX_SOFTWARE);
            }

            /*
             * Where does "unified" murder fit into ctl_mboxlist?
             * 1. Only check locally hosted mailboxes.
             * 2. Check everything.
             * Either way, this check is just wrong!
             */
            if (config_mupdate_config !=
                IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) {
                /* But not for a unified configuration */

                syslog(LOG_WARNING, "Remove Local Mailbox: %s", mbentry->name);

                if (warn_only) {
                    printf("Remove Local Mailbox: %s\n", mbentry->name);
                } else {
                    next = xzmalloc(sizeof(struct mb_node));
                    strlcpy(next->mailbox, mbentry->name, sizeof(next->mailbox));
                    next->next = wipe_head;
                    wipe_head = next;
                }
            }

            skip_flag = 1;
        } else {
            /* Check that it isn't flagged moving */
            if (mbentry->mbtype & MBTYPE_MOVING) {
                /* it's flagged moving, we'll fix it later (and
                 * push it then too) */
                struct mb_node *next;

                syslog(LOG_WARNING, "Remove remote flag on: %s", mbentry->name);

                if (warn_only) {
                    printf("Remove remote flag on: %s\n", mbentry->name);
                } else {
                    next = xzmalloc(sizeof(struct mb_node));
                    strlcpy(next->mailbox, mbentry->name, sizeof(next->mailbox));
                    next->next = unflag_head;
                    unflag_head = next;
                }

                /* No need to update mupdate now, we'll get it when we
                 * untag the mailbox */
                skip_flag = 1;
            }
        }
    }

    if (skip_flag) {
        free(realpart);
        return 0;
    }

    syslog(LOG_WARNING, "Force Activate: %s", mbentry->name);

    if (warn_only) {
        printf("Force Activate: %s\n", mbentry->name);
        free(realpart);
        return 0;
    }

    r = mupdate_activate(rock->h, mbentry->name, realpart, mbentry->acl);

    if (r == MUPDATE_NOCONN) {
        fprintf(stderr, "permanent failure storing '%s'\n", mbentry->name);
        r = IMAP_IOERROR;
    } else if (r == MUPDATE_FAIL) {
        fprintf(stderr,
                "temporary failure storing '%s' (update continuing)\n",
                mbentry->name);
        r = 0;
    } else if (r) {
        fprintf(
                stderr,
                "error storing '%s' (update continuing): %s\n",
                mbentry->name,
                error_message(r)
            );
        r = 0;
    }

    free(realpart);

    return r;
}

/*
 * True if user types Y\n or y\n.  Anything else is false.
 */
static int yes(void)
{
    int c, answer = 0;

    c = getchar();
    if (c == 'Y' || c == 'y') {
        answer = 1;

        while ((c = getchar()) != EOF) {
            if (c == '\n') {
                break;
            } else {
                answer = 0;
            }
        }
    }

    return(answer);
}

/* Resyncing with mupdate:
 *
 * If it is local and not present on mupdate at all, push to mupdate.
 * If it is local and present on mupdate for another host, delete local mailbox
 * If it is local and present on mupdate but with incorrect partition/acl,
 *    update mupdate.
 * If it is not local and present on mupdate for this host, delete it from
 *    mupdate.
 */
static void do_pop_mupdate(void)
{
    struct popmupdaterock popmupdaterock = {0};
    int ret;
    char buf[8192];

    ret = mupdate_connect(NULL, NULL, &(popmupdaterock.h), NULL);
    if (ret) {
        fprintf(stderr, "couldn't connect to mupdate server\n");
        exit(1);
    }

    /* now we need a list of what the remote thinks we have
        * To generate it, ask for a prefix of '<our hostname>!',
        * (to ensure we get exactly our hostname) */
    snprintf(buf, sizeof(buf), "%s!", config_servername);
    ret = mupdate_list(popmupdaterock.h, mupdate_list_cb, buf, NULL);
    if (ret) {
        fprintf(stderr, "couldn't do LIST command on mupdate server\n");
        exit(1);
    }

    /* Run pending mupdate deletes */
    while (del_head) {
        struct mb_node *me = del_head;
        del_head = del_head->next;

        syslog(LOG_WARNING, "Remove from MUPDATE: %s", me->mailbox);

        if (warn_only) {
            printf("Remove from MUPDATE: %s\n", me->mailbox);
        } else {
            ret = mupdate_delete(popmupdaterock.h, me->mailbox);
            if (ret) {
                fprintf(stderr,
                        "couldn't mupdate delete %s\n", me->mailbox);
                exit(1);
            }
        }

        free(me);
    }

    /* Run callback for mailboxes */
    int flags = MBOXTREE_TOMBSTONES;
    mboxlist_allmbox("", &pop_mupdate_cb, &popmupdaterock, flags);

    /* Remove MBTYPE_MOVING flags (unflag_head) */
    while (unflag_head) {
        mbentry_t *mbentry = NULL;
        struct mb_node *me = unflag_head;

        unflag_head = unflag_head->next;

        ret = mboxlist_lookup(me->mailbox, &mbentry, NULL);
        if (ret) {
            fprintf(stderr,
                    "couldn't perform lookup to un-remote-flag %s\n",
                    me->mailbox);
            exit(1);
        }

        /* Reset the partition! */
        free(mbentry->server);
        mbentry->server = NULL;
        mbentry->mbtype &= ~(MBTYPE_MOVING|MBTYPE_REMOTE);
        ret = mboxlist_updatelock(mbentry, 1);
        if (ret) {
            fprintf(stderr,
                    "couldn't perform update to un-remote-flag %s\n",
                    me->mailbox);
            exit(1);
        }

        /* force a push to mupdate */
        snprintf(buf, sizeof(buf), "%s!%s", config_servername, mbentry->partition);
        ret = mupdate_activate(popmupdaterock.h, me->mailbox, buf, mbentry->acl);
        if (ret) {
            fprintf(stderr,
                    "couldn't perform mupdatepush to un-remote-flag %s\n",
                    me->mailbox);
            exit(1);
        }

        mboxlist_entry_free(&mbentry);
        free(me);
    }

    /* Delete local mailboxes where needed (wipe_head) */
    if (interactive) {
        int count = 0;
        struct mb_node *me;

        for (me = wipe_head; me != NULL; me = me->next) count++;

        if ( count > 0 ) {
            fprintf(stderr, "OK to delete %d local mailboxes? ", count);
            if (!yes()) {
                fprintf(stderr, "Cancelled!\n");
                exit(1);
            }
        }
    }

    while (wipe_head) {
        struct mb_node *me = wipe_head;
        wipe_head = wipe_head->next;

        struct mboxlock *namespacelock = mboxname_usernamespacelock(me->mailbox);

        if (!mboxlist_delayed_delete_isenabled() ||
            mboxname_isdeletedmailbox(me->mailbox, NULL)) {
            ret = mboxlist_deletemailbox(me->mailbox, 1, "", NULL, NULL,
                    MBOXLIST_DELETE_LOCALONLY|MBOXLIST_DELETE_FORCE);
        } else {
            ret = mboxlist_delayed_deletemailbox(me->mailbox, 1, "", NULL, NULL,
                    MBOXLIST_DELETE_LOCALONLY|MBOXLIST_DELETE_FORCE);
        }

        mboxname_release(&namespacelock);

        if (ret) {
            fprintf(stderr, "couldn't delete defunct mailbox %s\n",
                    me->mailbox);
            exit(1);
        }

        free(me);
    }

    /* Done with mupdate */
    mupdate_disconnect(&(popmupdaterock.h));
    sasl_done();
}

/* XXX based on mailbox_acl_to_dlist. this should probably be in lib/acl.c! */
static json_t *acl_to_json(const char *aclstr)
{
    const char *p, *q;
    json_t *jacl = json_object();

    p = aclstr;

    while (p && *p) {
        char *name, *val;

        q = strchr(p, '\t');
        if (!q) break;

        name = xstrndup(p, q-p);
        q++;

        p = strchr(q, '\t');
        if (p) {
            val = xstrndup(q, p-q);
            p++;
        }
        else
            val = xstrdup(q);

        json_object_set_new(jacl, name, json_string(val));

        free(name);
        free(val);
    }

    return jacl;
}

static int dump_cb(const mbentry_t *mbentry, void *rockp)
{
    struct dumprock *d = (struct dumprock *) rockp;
    int i, r = 0;
    json_t *jparent, *jobj, *jname_history;
    char *output = NULL;
    static struct buf buf = BUF_INITIALIZER;

    /* skip if we're limiting by partition and this one doesn't match */
    if (d->partition && strcmpsafe(d->partition, mbentry->partition))
        return 0;

    jobj = json_object();

    /* char *name; */
    json_object_set_new(jobj, "name", json_string(mbentry->name));

    /* char *ext_name
     * this field is a place to cache a calculated value, not
     * a real value in mailboxes.db, so don't output it.
     */

    /* time_t mtime; */
    buf_reset(&buf);
    buf_printf(&buf, TIME_T_FMT, mbentry->mtime);
    json_object_set_new(jobj, "mtime", json_string(buf_cstring(&buf)));

    /* uint32_t uidvalidity; */
    buf_reset(&buf);
    buf_printf(&buf, "%" PRIu32, mbentry->uidvalidity);
    json_object_set_new(jobj, "uidvalidity", json_string(buf_cstring(&buf)));

    /* modseq_t createdmodseq; */
    buf_reset(&buf);
    buf_printf(&buf, MODSEQ_FMT, mbentry->createdmodseq);
    json_object_set_new(jobj, "createdmodseq", json_string(buf_cstring(&buf)));

    /* modseq_t foldermodseq; */
    buf_reset(&buf);
    buf_printf(&buf, MODSEQ_FMT, mbentry->foldermodseq);
    json_object_set_new(jobj, "foldermodseq", json_string(buf_cstring(&buf)));

    /* uint32_t mbtype; */
    json_object_set_new(jobj, "mbtype",
        json_string(mboxlist_mbtype_to_string(mbentry->mbtype)));

    /* char *partition; */
    json_object_set_new(jobj, "partition", json_string(mbentry->partition));

    /* char *server; */
    json_object_set_new(jobj, "server", json_string(mbentry->server));

    /* char *acl; */
    json_object_set_new(jobj, "acl", acl_to_json(mbentry->acl));

    /* char *uniqueid; */
    json_object_set_new(jobj, "uniqueid", json_string(mbentry->uniqueid));

    /* char *inboxid; */
    json_object_set_new(jobj, "inboxid", json_string(mbentry->inboxid));

    /* char *legacy_specialuse; */
    json_object_set_new(jobj, "legacy_specialuse",
                              json_string(mbentry->legacy_specialuse));

    /* ptrarray_t name_history; */
    jname_history = json_array();
    for (i = 0; i < mbentry->name_history.count; i++) {
        former_name_t *histitem = ptrarray_nth(&mbentry->name_history, i);
        json_t *jhistitem = json_object();

        json_object_set_new(jhistitem, "name", json_string(histitem->name));
        buf_reset(&buf);
        buf_printf(&buf, TIME_T_FMT, histitem->mtime);
        json_object_set_new(jhistitem, "mtime",
                                       json_string(buf_cstring(&buf)));
        buf_reset(&buf);
        buf_printf(&buf, "%" PRIu32, histitem->uidvalidity);
        json_object_set_new(jhistitem, "uidvalidity",
                                       json_string(buf_cstring(&buf)));
        buf_reset(&buf);
        buf_printf(&buf, MODSEQ_FMT, histitem->createdmodseq);
        json_object_set_new(jhistitem, "createdmodseq",
                                       json_string(buf_cstring(&buf)));
        buf_reset(&buf);
        buf_printf(&buf, MODSEQ_FMT, histitem->foldermodseq);
        json_object_set_new(jhistitem, "foldermodseq",
                                       json_string(buf_cstring(&buf)));
        json_object_set_new(jhistitem, "mbtype",
            json_string(mboxlist_mbtype_to_string(histitem->mbtype)));
        json_object_set_new(jhistitem, "partition",
                                       json_string(histitem->partition));

        json_array_append_new(jname_history, jhistitem);
    }
    json_object_set_new(jobj, "name_history", jname_history);

    jparent = json_object();
    json_object_set_new(jparent, mbentry->name, jobj);

    output = json_dumps(jparent, JSON_EMBED);
    if (!output) {
        xsyslog(LOG_ERR, "unable to stringify json object",
                         "mboxname=<%s>", mbentry->name);
        return IMAP_INTERNAL;
    }

    printf("%s%s", d->sep, output);

    if (d->sep && !*d->sep)
        d->sep = ",\n";

    free(output);
    json_decref(jparent);

    if (d->purge) {
        mboxlist_deletelock(mbentry);
    }

    return r;
}

static void do_dump(const char *part, int purge, int intermediary)
{
    struct dumprock d = { part, purge, "" };

    /* Dump Database */
    int flags = MBOXTREE_TOMBSTONES;
    if (intermediary) flags |= MBOXTREE_INTERMEDIATES;

    puts("{");
    mboxlist_allmbox("", &dump_cb, &d, flags);
    puts("\n}");
}

static void do_undump_legacy(void)
{
    char buf[16384];
    int line = 0;

    while (fgets(buf, sizeof(buf), stdin)) {
        mbentry_t *newmbentry = mboxlist_entry_create();
        line++;

        sscanf(buf, "%m[^\t]\t%d %ms %m[^>]>%ms " TIME_T_FMT " %" SCNu32
               " %llu %llu %m[^\n]\n", &newmbentry->name, &newmbentry->mbtype,
               &newmbentry->partition, &newmbentry->acl, &newmbentry->uniqueid,
               &newmbentry->mtime, &newmbentry->uidvalidity, &newmbentry->foldermodseq,
               &newmbentry->createdmodseq, &newmbentry->legacy_specialuse);

        if (!newmbentry->acl) {
           /*
            * This can be valid, e.g. for folders created by
            *  0000 CREATE #calendars (TYPE CALENDAR)
            *  0001 CREATE #addressbooks (TYPE ADDRESSBOOK)
            *  0002 CREATE #calendars/Shared (TYPE CALENDAR)
            *  0003 CREATE #addressbooks/Shared (TYPE ADDRESSBOOK)
            * For these read the uniqueid, mtime, etc.
            */
            mboxlist_entry_free(&newmbentry);
            newmbentry = mboxlist_entry_create();
            sscanf(buf, "%m[^\t]\t%d %ms >%ms " TIME_T_FMT " %" SCNu32
                   " %llu %llu %m[^\n]\n", &newmbentry->name, &newmbentry->mbtype,
                   &newmbentry->partition, &newmbentry->uniqueid,
                   &newmbentry->mtime, &newmbentry->uidvalidity, &newmbentry->foldermodseq,
                   &newmbentry->createdmodseq, &newmbentry->legacy_specialuse);
        }

        if (!newmbentry->partition) {
            fprintf(stderr, "line %d: no partition found\n", line);
            mboxlist_entry_free(&newmbentry);
            continue;
        }

        char *server_sep = strchr(newmbentry->partition, '!');
        if (server_sep) {
            *server_sep = '\0';
            newmbentry->server = newmbentry->partition;
            newmbentry->partition = xstrdup(server_sep + 1);
        }

        if (strlen(newmbentry->name) >= MAX_MAILBOX_BUFFER) {
            /* XXX should be MAX_MAILBOX_NAME, not MAX_MAILBOX_BUFFER? */
            fprintf(stderr, "line %d: mailbox name too long\n", line);
            mboxlist_entry_free(&newmbentry);
            continue;
        }
        if (strlen(newmbentry->partition) >= MAX_PARTITION_LEN) {
            fprintf(stderr, "line %d: partition name too long\n", line);
            mboxlist_entry_free(&newmbentry);
            continue;
        }

        /* generate a new entry */
        int r = mboxlist_updatelock(newmbentry, /*localonly*/1);
        mboxlist_entry_free(&newmbentry);

        if (r) break;
    }

    return;
}

static void undump_name_history(ptrarray_t *name_history,
                                const json_t *jname_history)
{
    size_t index;
    json_t *value;

    /* XXX check lengths of mailbox and partition names */

    json_array_foreach(jname_history, index, value) {
        former_name_t *histitem;
        const char *tmp;

        histitem = xzmalloc(sizeof(*histitem));

        /* char *name; */
        if ((tmp = json_string_value(json_object_get(value, "name")))) {
            histitem->name = xstrdup(tmp);
        }

        /* time_t mtime; */
        if ((tmp = json_string_value(json_object_get(value, "mtime")))) {
            histitem->mtime = atoi(tmp);
        }

        /* uint32_t uidvalidity; */
        if ((tmp = json_string_value(json_object_get(value, "uidvalidity")))) {
            histitem->uidvalidity = strtoul(tmp, NULL, 10);
        }

        /* modseq_t createdmodseq; */
        if ((tmp = json_string_value(json_object_get(value, "createdmodseq")))) {
            histitem->createdmodseq = atomodseq_t(tmp);
        }

        /* modseq_t foldermodseq; */
        if ((tmp = json_string_value(json_object_get(value, "foldermodseq")))) {
            histitem->foldermodseq = atomodseq_t(tmp);
        }

        /* uint32_t mbtype; */
        if ((tmp = json_string_value(json_object_get(value, "mbtype")))) {
            histitem->mbtype = mboxlist_string_to_mbtype(tmp);
        }

        /* char *partition; */
        if ((tmp = json_string_value(json_object_get(value, "partition")))) {
            histitem->partition = xstrdup(tmp);
        }

        ptrarray_append(name_history, histitem);
    }
}

static int do_undump(void)
{
    json_t *jmailboxes = NULL;
    json_error_t jerr;
    const char *key;
    json_t *value;

    jmailboxes = json_loadf(stdin, 0, &jerr);
    if (!jmailboxes) {
        fprintf(stderr, "parse error at line %d: %s\n", jerr.line, jerr.text);
        return -1;
    }

    json_object_foreach(jmailboxes, key, value) {
        mbentry_t *newmbentry = mboxlist_entry_create();
        const char *tmp;
        json_t *jtmp;

        /* char *name; */
        if (strlen(key) >= MAX_MAILBOX_NAME) {
            fprintf(stderr, "mailbox name too long: %s\n", key);
            goto skip;
        }
        newmbentry->name = xstrdup(key);

        /* char *ext_name
         * this field is a place to cache a calculated value, not
         * a real value in mailboxes.db, so don't expect it.
         */

        /* time_t mtime;
         * this field is ignored, the new mbentry will always be created with
         * the current time in its mtime field.
         */

        /* uint32_t uidvalidity; */
        if ((tmp = json_string_value(json_object_get(value, "uidvalidity")))) {
            newmbentry->uidvalidity = strtoul(tmp, NULL, 10);
        }
        else {
            fprintf(stderr, "missing uidvalidity for %s\n", key);
        }

        /* modseq_t createdmodseq; */
        if ((tmp = json_string_value(json_object_get(value, "createdmodseq")))) {
            newmbentry->createdmodseq = atomodseq_t(tmp);
        }
        else {
            fprintf(stderr, "missing createdmodseq for %s\n", key);
        }

        /* modseq_t foldermodseq; */
        if ((tmp = json_string_value(json_object_get(value, "foldermodseq")))) {
            newmbentry->foldermodseq = atomodseq_t(tmp);
        }
        else {
            fprintf(stderr, "missing foldermodseq for %s\n", key);
        }

        /* uint32_t mbtype; */
        if ((tmp = json_string_value(json_object_get(value, "mbtype")))) {
            newmbentry->mbtype = mboxlist_string_to_mbtype(tmp);
        }
        else {
            // XXX possibly infer mbtype from name
            // We might want to set/verify mbtype based on the name.  For
            // instance user.foo.#calendars* should be MBTYPE_CALENDAR,
            // user.foo.#jmap should be MBTYPE_COLLECTION, etc.
            fprintf(stderr, "missing mbtype for %s\n", key);
        }

        /* char *partition; */
        if ((tmp = json_string_value(json_object_get(value, "partition")))) {
            if (strlen(tmp) >= MAX_PARTITION_LEN) {
                fprintf(stderr, "partition too long for %s\n", key);
                goto skip;
            }
            newmbentry->partition = xstrdup(tmp);
        }
        else {
            fprintf(stderr, "missing mbtype for %s\n", key);
            goto skip;
        }

        /* char *server; */
        if ((tmp = json_string_value(json_object_get(value, "server")))) {
            newmbentry->server = xstrdup(tmp);
        }
        else {
            // XXX detect whether this needs to be present, whinge if it's not
            // Its mandatory for frontends and mupdate in a Murder.  Backends
            // shouldn't have this in a traditional (non-unified) Murder.
        }

        /* char *acl; */
        if ((jtmp = json_object_get(value, "acl"))) {
            const char *aclkey;
            json_t *aclvalue;
            struct buf buf = BUF_INITIALIZER;

            json_object_foreach(jtmp, aclkey, aclvalue) {
                buf_printf(&buf, "%s\t%s\t",
                                  aclkey,
                                  json_string_value(aclvalue));
            }
            newmbentry->acl = buf_release(&buf);
        }

        /* char *uniqueid; */
        if ((tmp = json_string_value(json_object_get(value, "uniqueid")))) {
           newmbentry->uniqueid = xstrdup(tmp);
        }
        else {
            /* XXX could potentially infer this if the mailbox is on disk */
            fprintf(stderr, "missing uniqueid for %s\n", key);
            goto skip;
        }

        /* char *legacy_specialuse; */
        if ((tmp = json_string_value(json_object_get(value, "legacy_specialuse")))) {
            newmbentry->legacy_specialuse = xstrdup(tmp);
        }

        /* ptrarray_t name_history; */
        if ((jtmp = json_object_get(value, "name_history"))) {
            undump_name_history(&newmbentry->name_history, jtmp);
        }

        /* generate a new entry */
        mboxlist_updatelock(newmbentry, /*localonly*/1);
        /* XXX should we auditlog something here? */

skip:
        mboxlist_entry_free(&newmbentry);
    }

    json_decref(jmailboxes);

    return 0;
}

enum {
    ROOT =      (1<<0),
    DOMAIN =    (1<<1),
    MBOX =      (1<<2),
    UUID =      (1<<3),
    MATCHED =   (1<<4)
};

struct found_data {
    int type;
    char mboxname[MAX_MAILBOX_BUFFER];
    char partition[MAX_MAILBOX_BUFFER];
    char path[MAX_MAILBOX_PATH+1];
};

static void add_path(ptrarray_t *found, int type,
              const char *name, const char *part, const char *path)
{
    struct found_data *new;

    new = xmalloc(sizeof(struct found_data));
    new->type = type;
    strcpy(new->mboxname, name);
    strcpy(new->partition, part);
    strcpy(new->path, path);

    /* add our new node to the end of the list */
    ptrarray_append(found, new);
}

static void add_part(ptrarray_t *found,
              const char *part, const char *path, int override)
{
    int i;
    struct found_data *entry;

    /* see if we already added a partition having this name */
    for (i = 0; i < ptrarray_size(found); i++){
        entry = ptrarray_nth(found, i);
        if (!strcmp(entry->partition, part)) {
            /* found it */
            if (override) {
                /* replace the path with the one containing cyrus.header */
                strcpy(entry->path, path);
            }

            /* we already have the proper path, so we're done */
            return;
        }
    }

    /* add the new partition path */
    add_path(found, ROOT, "", part, path);
}

static void get_partitions(const char *key, const char *value, void *rock)
{
    static int check_meta = -1;
    ptrarray_t *found = (ptrarray_t *) rock;

    if (check_meta == -1) {
        /* see if cyrus.header might be contained in a metapartition */
        check_meta = (config_metapartition_files &
                      IMAP_ENUM_METAPARTITION_FILES_HEADER);
    }

    if (!strncmp(key, "partition-", 10)) {
        add_part(found, key+10, value, 0);
    }
    else if (check_meta && !strncmp(key, "metapartition-", 14)) {
        add_part(found, key+14, value, 1);
    }
    /* skip any other overflow strings */
}

static int compar_mbox(const void **v1, const void **v2)
{
    struct found_data *d1 = (struct found_data *) *v1;
    struct found_data *d2 = (struct found_data *) *v2;

    /* non-mailboxes get pushed to the end of the array,
       otherwise we do an ASCII sort */
    if (d1->type & MBOX) {
        if (d2->type & MBOX) return strcmp(d1->mboxname, d2->mboxname);
        else return -1;
    }
    else if (d2->type & MBOX) return 1;
    else return 0;
}

static int add_mbox_cb(const mbentry_t *mbentry, void *rockp)
{
    // This function is called for every entry in the database,
    // and stores all mailboxes in &mboxes.

    ptrarray_t *mboxes = (ptrarray_t *) rockp;

    /* skip deleted mailboxes and mailboxes without partition
       as they cannot have a path in the filesystem */
    if (mbentry->partition == NULL ||
        mbentry->mbtype & MBTYPE_DELETED)
        return 0;

    if (mbentry->mbtype & MBTYPE_LEGACY_DIRS)
        add_path(mboxes, MBOX, mbentry->name, mbentry->partition, mbentry->uniqueid);
    else
        add_path(mboxes, MBOX | UUID, mbentry->uniqueid, mbentry->partition, mbentry->name);

    return 0;
}

static void verify_mboxes(ptrarray_t *mboxes, ptrarray_t *found, int *idx)
{
    int i;
    int r;
    char *mbname;
    struct found_data *found_mailbox_entry;
    struct found_data *found_path_entry;

    for (i = 0; i < ptrarray_size(mboxes); i++) {

        found_mailbox_entry = ptrarray_nth(mboxes, i);

        if (found_mailbox_entry->type & UUID)
            mbname = found_mailbox_entry->path;
        else
            mbname = found_mailbox_entry->mboxname;

        // Walk the directories to see if the mailbox does have
        // paths on the filesystem.
        do {
            r = -1;
	    found_path_entry = ptrarray_nth(found, *idx);
            if (
                    !(found_path_entry->type & MBOX) ||   /* end of mailboxes */
                    (r = strcmp(found_mailbox_entry->mboxname, found_path_entry->mboxname)) < 0
            ) {
                printf("'%s' has a DB entry but no directory on partition '%s'\n",
                        mbname, found_mailbox_entry->partition);
                break;
            }
            else if (r == 0) {
                if (found_path_entry->type & MATCHED) {
                    printf("'%s' has an additional match to DB entry of mailbox '%s' on partition '%s'\n",
                            found_path_entry->path, mbname, found_mailbox_entry->partition);
                }
                /* mark filesystem entry as matched */
                found_path_entry->type |= MATCHED;
            }
            (*idx)++;
        } while (r > 0);
    }

    /* now report all unmatched mailboxes found in filesystem */
    for (i = 0; i < ptrarray_size(found); i++) {
	found_path_entry = ptrarray_nth(found, i);
        if (!(found_path_entry->type & MBOX)) break;
        if (!(found_path_entry->type & MATCHED)) {
            printf("'%s' has a directory '%s' but no DB entry\n",
                    found_path_entry->mboxname,
                    found_path_entry->path
                );
        }
    }
}

static void do_verify(void)
{
    ptrarray_t *found;
    ptrarray_t *mboxes;
    int i;
    int idx = 0;

    found = ptrarray_new();
    ptrarray_init(found);
    mboxes = ptrarray_new();
    ptrarray_init(mboxes);

    /* gather a list of partition paths to search */
    config_foreachoverflowstring(get_partitions, found);

    /* scan all paths in our list, tagging valid mailboxes,
       and adding paths as we find them */
    for (i = 0; i < ptrarray_size(found); i++) {
        DIR *dirp;
        struct dirent *dirent;
        char name[MAX_MAILBOX_BUFFER];
        char part[MAX_MAILBOX_BUFFER];
        char path[MAX_MAILBOX_PATH+1];
        int type;
        struct found_data *entry = ptrarray_nth(found, i);

        if (config_hashimapspool && (entry->type & ROOT)) {
            /* need to add hashed directories */
            int config_fulldirhash = libcyrus_config_getswitch(CYRUSOPT_FULLDIRHASH);
            char *tail;
            int j, c;

            /* make the toplevel partition /a */
            if (config_fulldirhash) {
                strcat(entry->path, "/A");
                c = 'B';
            } else {
                strcat(entry->path, "/a");
                c = 'b';
            }
            type = (entry->type &= ~ROOT);

            /* make a template path for /b - /z */
            strcpy(name, entry->mboxname);
            strcpy(part, entry->partition);
            strcpy(path, entry->path);
            tail = path + strlen(path) - 1;

            for (j = 1; j < 26; j++, c++) {
                *tail = c;
                add_path(found, type, name, part, path);
            }

            if (config_virtdomains && !type) {
                /* need to add root domain directory */
                strcpy(tail, "domain");
                add_path(found, DOMAIN | ROOT, name, part, path);
            }

            /* need to add uuid directory */
            strcpy(tail, "uuid");
            add_path(found, type | UUID, name, part, path);
        }

        if (!(dirp = opendir(entry->path))) continue;
        while ((dirent = readdir(dirp))) {
            const char *fname = FNAME_HEADER;
            if (dirent->d_name[0] == '.') continue;
            else if (!strcmp(dirent->d_name, fname+1)) {
                /* XXX - check that it can be opened */
                entry->type |= MBOX;
                strcpy(name, entry->mboxname);
            }
            else if (!strchr(dirent->d_name, '.') ||
                     (entry->type & DOMAIN)) {
                /* probably a directory, add it to the array */
                type = 0;
                strcpy(name, entry->mboxname);

                if (config_virtdomains &&
                    (entry->type == ROOT) &&
                    !strcmp(dirent->d_name, "domain")) {
                    /* root domain directory */
                    type = DOMAIN | ROOT;
                }
                else if (!name[0] && entry->type & DOMAIN) {
                    /* toplevel domain directory */
                    strcat(name, dirent->d_name);
                    strcat(name, "!");
                    type = DOMAIN | ROOT;
                }
                else if (entry->type & UUID) {
                    /* possibly a mailbox directory, use directory name without ancestor information */
                    strcpy(name, dirent->d_name);
                }
                else {
                    /* possibly a mailbox directory */
                    if (name[0] && !(entry->type & DOMAIN)) strcat(name, ".");
                    strcat(name, dirent->d_name);
                }

                strcpy(part, entry->partition);
                strcpy(path, entry->path);
                strcat(path, "/");
                strcat(path, dirent->d_name);
                /* inherit UUID flag from parent entry */
                type = entry->type & UUID;
                add_path(found, type, name, part, path);
            }
        }

        closedir(dirp);
    }

    ptrarray_sort(found, compar_mbox);

    /* gather all mailboxes and sort them, so that UUID and non-UUID
       mailboxes are sorted in the way we need them to be to avoid
       full nested looping */

    mboxlist_allmbox("", &add_mbox_cb, mboxes, MBOXTREE_TOMBSTONES);

    ptrarray_sort(mboxes, compar_mbox);

    verify_mboxes(mboxes, found, &idx);
}

static void usage(void)
{
    fprintf(stderr, "DUMP:\n");
    fprintf(stderr, "  ctl_mboxlist [-C <alt_config>] -d [-x] [-y] [-p partition] [-f filename]\n");
    fprintf(stderr, "UNDUMP:\n");
    fprintf(stderr,
            "  ctl_mboxlist [-C <alt_config>] -u [-f filename] [-L]"
            "    [< mboxlist.dump]\n");
    fprintf(stderr, "MUPDATE populate:\n");
    fprintf(stderr, "  ctl_mboxlist [-C <alt_config>] -m [-a] [-w] [-i] [-f filename]\n");
    fprintf(stderr, "VERIFY:\n");
    fprintf(stderr, "  ctl_mboxlist [-C <alt_config>] -v [-f filename]\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    const char *partition = NULL;
    char *mboxdb_fname = NULL;
    int dopurge = 0;
    int opt;
    enum mboxop op = NONE;
    char *alt_config = NULL;
    int dointermediary = 0;
    int undump_legacy = 0;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:Ladf:imp:uvwxy";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "legacy", no_argument, NULL, 'L' },
        { "authoritative", no_argument, NULL, 'a' },
        { "dump", no_argument, NULL, 'd' },
        { "filename", required_argument, NULL, 'f' },
        { "interactive", no_argument, NULL, 'i' },
        { "sync-mupdate", no_argument, NULL, 'm' },
        { "partition", required_argument, NULL, 'p' },
        { "undump", no_argument, NULL, 'u' },
        { "verify", no_argument, NULL, 'v' },
        { "warn-only", no_argument, NULL, 'w' },
        { "remove-dumped", no_argument, NULL, 'x' },
        { "include-intermediaries", no_argument, NULL, 'y' },

        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'L':
            undump_legacy = 1;
            break;

        case 'f':
            if (!mboxdb_fname) {
                mboxdb_fname = optarg;
            } else {
                usage();
            }
            break;

        case 'd':
            if (op == NONE) op = DUMP;
            else usage();
            break;

        case 'u':
            if (op == NONE) op = UNDUMP;
            else usage();
            break;

        case 'm':
            if (op == NONE) op = M_POPULATE;
            else usage();
            break;

        case 'p':
            partition = optarg;
            break;

        case 'x':
            dopurge = 1;
            break;

        case 'a':
            local_authoritative = 1;
            break;

        case 'w':
            warn_only = 1;
            break;

        case 'v':
            if (op == NONE) op = VERIFY;
            else usage();
            break;

        case 'i':
            interactive = 1;
            break;

        case 'y':
            dointermediary = 1;
            break;

        default:
            usage();
            break;
        }
    }

    if (op != M_POPULATE && (local_authoritative || warn_only)) usage();
    if (op != DUMP && partition) usage();
    if (op != DUMP && dopurge) usage();
    if (op != DUMP && dointermediary) usage();
    if (op != UNDUMP && undump_legacy) usage();

    cyrus_init(alt_config, "ctl_mboxlist", 0, 0);
    global_sasl_init(1,0,NULL);

    switch (op) {
    case M_POPULATE:
        syslog(LOG_NOTICE, "%spopulating mupdate", warn_only ? "test " : "");
        mboxlist_init(0);
        mboxlist_open(mboxdb_fname);

        do_pop_mupdate();

        mboxlist_close();
        mboxlist_done();

        syslog(LOG_NOTICE, "done %spopulating mupdate", warn_only ? "test " : "");
        break;

    case DUMP:
        mboxlist_init(0);
        mboxlist_open(mboxdb_fname);

        do_dump(partition, dopurge, dointermediary);

        mboxlist_close();
        mboxlist_done();

        break;

    case UNDUMP:
        mboxlist_init(0);
        mboxlist_open(mboxdb_fname);

        if (undump_legacy) {
            do_undump_legacy();
        }
        else {
            do_undump();
        }

        mboxlist_close();
        mboxlist_done();
        break;

    case VERIFY:
        mboxlist_init(0);
        mboxlist_open(mboxdb_fname);

        do_verify();

        mboxlist_close();
        mboxlist_done();
        break;

    default:
        usage();
        cyrus_done();
        return 1;
    }

    cyrus_done();
    return 0;
}
