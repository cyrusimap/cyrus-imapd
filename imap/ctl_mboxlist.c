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
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>

#include "assert.h"
#include "annotate.h"
#include "dlist.h"
#include "exitcodes.h"
#include "global.h"
#include "libcyr_cfg.h"
#include "mboxlist.h"
#include "mupdate.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/mupdate_err.h"

extern int optind;
extern char *optarg;

enum mboxop { DUMP,
              M_POPULATE,
              RECOVER,
              CHECKPOINT,
              UNDUMP,
              VERIFY,
              NONE };

struct dumprock {
    enum mboxop op;

    const char *partition;
    int purge;

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

static int dump_cb(const mbentry_t *mbentry, void *rockp)
{
    struct dumprock *d = (struct dumprock *) rockp;
    int r = 0;

    switch (d->op) {
    case DUMP:
        if (!d->partition || !strcmpsafe(d->partition, mbentry->partition)) {
            printf("%s\t%d ", mbentry->name, mbentry->mbtype);
            if (mbentry->server) printf("%s!", mbentry->server);
            printf("%s %s\n", mbentry->partition, mbentry->acl);
            if (d->purge) {
                mboxlist_delete(mbentry->name);
            }
        }
        break;
    case M_POPULATE:
    {
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
               !mupdate_find(d->h, mbentry->name, &mdata)) {
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
                    fatal("mupdate said not us before it said us", EC_SOFTWARE);
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
            break;
        }

        syslog(LOG_WARNING, "Force Activate: %s", mbentry->name);

        if (warn_only) {
            printf("Force Activate: %s\n", mbentry->name);
            free(realpart);
            break;
        }

        r = mupdate_activate(d->h, mbentry->name, realpart, mbentry->acl);

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

        break;
    }

    default: /* yikes ! */
        abort();
        break;
    }

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

static void do_dump(enum mboxop op, const char *part, int purge)
{
    struct dumprock d;
    int ret;
    char buf[8192];

    assert(op == DUMP || op == M_POPULATE);
    assert(op == DUMP || !purge);
    assert(op == DUMP || !part);

    d.op = op;
    d.partition = part;
    d.purge = purge;

    if (op == M_POPULATE) {
        ret = mupdate_connect(NULL, NULL, &(d.h), NULL);
        if (ret) {
            fprintf(stderr, "couldn't connect to mupdate server\n");
            exit(1);
        }

        /* now we need a list of what the remote thinks we have
         * To generate it, ask for a prefix of '<our hostname>!',
         * (to ensure we get exactly our hostname) */
        snprintf(buf, sizeof(buf), "%s!", config_servername);
        ret = mupdate_list(d.h, mupdate_list_cb, buf, NULL);
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
                ret = mupdate_delete(d.h, me->mailbox);
                if (ret) {
                    fprintf(stderr,
                            "couldn't mupdate delete %s\n", me->mailbox);
                    exit(1);
                }
            }

            free(me);
        }
    }

    /* Dump Database */
    mboxlist_allmbox("", &dump_cb, &d, /*incdel*/1);

    if (op == M_POPULATE) {
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
            ret = mboxlist_update(mbentry, 1);
            if (ret) {
                fprintf(stderr,
                        "couldn't perform update to un-remote-flag %s\n",
                        me->mailbox);
                exit(1);
            }

            /* force a push to mupdate */
            snprintf(buf, sizeof(buf), "%s!%s", config_servername, mbentry->partition);
            ret = mupdate_activate(d.h, me->mailbox, buf, mbentry->acl);
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
            if (!mboxlist_delayed_delete_isenabled()) {
                ret = mboxlist_deletemailbox(me->mailbox, 1, "", NULL, NULL, 0, 1, 1);
            } else if (mboxname_isdeletedmailbox(me->mailbox, NULL)) {
                ret = mboxlist_deletemailbox(me->mailbox, 1, "", NULL, NULL, 0, 1, 1);
            } else {
                ret = mboxlist_delayed_deletemailbox(me->mailbox, 1, "", NULL, NULL, 0, 1, 1);
            }

            if (ret) {
                fprintf(stderr, "couldn't delete defunct mailbox %s\n",
                        me->mailbox);
                exit(1);
            }

            free(me);
        }

        /* Done with mupdate */
        mupdate_disconnect(&(d.h));
        sasl_done();
    }

    return;
}

static void do_undump(void)
{
    int r = 0;
    char buf[16384];
    int line = 0;
    const char *name, *partition, *acl;
    int mbtype;
    char *p;

    while (fgets(buf, sizeof(buf), stdin)) {
        mbentry_t *newmbentry = NULL;
        const char *server = NULL;

        line++;

        name = buf;
        for (p = buf; *p && *p != '\t'; p++) ;
        if (!*p) {
            fprintf(stderr, "line %d: no partition found\n", line);
            continue;
        }
        *p++ = '\0';
        if (Uisdigit(*p)) {
            /* new style dump */
            mbtype = strtol(p, &p, 10);
            /* skip trailing space */
            if (*p == ' ') p++;
        }
        else mbtype = 0;

        partition = p;
        for (; *p && (*p != ' ') && (*p != '\t'); p++) {
            if (*p == '!') {
                *p++ = '\0';
                server = partition;
                partition = p;
            }
        }
        if (!*p) {
            fprintf(stderr, "line %d: no acl found\n", line);
            continue;
        }
        *p++ = '\0';
        acl = p;
        /* chop off the newline */
        for (; *p && *p != '\r' && *p != '\n'; p++) ;
        *p++ = '\0';

        if (strlen(name) >= MAX_MAILBOX_BUFFER) {
            fprintf(stderr, "line %d: mailbox name too long\n", line);
            continue;
        }
        if (strlen(partition) >= MAX_PARTITION_LEN) {
            fprintf(stderr, "line %d: partition name too long\n", line);
            continue;
        }

        /* generate a new entry */
        newmbentry = mboxlist_entry_create();
        newmbentry->name = xstrdup(name);
        newmbentry->mbtype = mbtype;
        newmbentry->server = xstrdupnull(server);
        newmbentry->partition = xstrdupnull(partition);
        newmbentry->acl = xstrdupnull(acl);
        /* XXX - still missing all the new fields */

        r = mboxlist_update(newmbentry, /*localonly*/1);
        mboxlist_entry_free(&newmbentry);

        if (r) break;
    }

    return;
}

enum {
    ROOT =      (1<<0),
    DOMAIN =    (1<<1),
    MBOX =      (1<<2)
};

struct found_data {
    int type;
    char mboxname[MAX_MAILBOX_BUFFER];
    char partition[MAX_MAILBOX_BUFFER];
    char path[MAX_MAILBOX_PATH+1];
};

struct found_list {
    int idx;
    int size;
    int alloc;
    struct found_data *data;
};

static void add_path(struct found_list *found, int type,
              const char *name, const char *part, const char *path)
{
    struct found_data *new;

    if (found->size == found->alloc) {
        /* reached the end of our allocated array, double it */
        found->alloc *= 2;
        found->data = xrealloc(found->data,
                               found->alloc * sizeof(struct found_data));
    }

    /* add our new node to the end of the array */
    new = &found->data[found->size++];
    new->type = type;
    strcpy(new->mboxname, name);
    strcpy(new->partition, part);
    strcpy(new->path, path);
}

static void add_part(struct found_list *found,
              const char *part, const char *path, int override)
{
    int i;

    /* see if we already added a partition having this name */
    for (i = 0; i < found->size; i++){
        if (!strcmp(found->data[i].partition, part)) {
            /* found it */
            if (override) {
                /* replace the path with the one containing cyrus.header */
                strcpy(found->data[i].path, path);
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
    struct found_list *found = (struct found_list *) rock;

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

static int compar_mbox(const void *v1, const void *v2)
{
    struct found_data *d1 = (struct found_data *) v1;
    struct found_data *d2 = (struct found_data *) v2;

    /* non-mailboxes get pushed to the end of the array,
       otherwise we do an ASCII sort */
    if (d1->type & MBOX) {
        if (d2->type & MBOX) return strcmp(d1->mboxname, d2->mboxname);
        else return -1;
    }
    else if (d2->type & MBOX) return 1;
    else return 0;
}

static int verify_cb(const mbentry_t *mbentry, void *rockp)
{
    // This function is called for every entry in the database,
    // and supplied an inventory in &found. *data however does
    // not pass dlist_parsemap() unlike is the case with dump_db().

    struct found_list *found = (struct found_list *) rockp;
    int r = 0;

    if (r) {
        printf("'%s' has a directory '%s' but no DB entry\n",
                found->data[found->idx].mboxname,
                found->data[found->idx].path
            );
    } else {
        // Walk the directories to see if the mailbox from data does have
        // paths on the filesystem.
        do {
            r = -1;
            if (
                    (found->idx >= found->size) ||              /* end of array */
                    !(found->data[found->idx].type & MBOX) ||   /* end of mailboxes */
                    (r = strcmp(mbentry->name, found->data[found->idx].mboxname)) < 0
            ) {
                printf("'%s' has a DB entry but no directory on partition '%s'\n",
                        mbentry->name, mbentry->partition);

            }
            else if (r > 0) {
                printf("'%s' has a directory '%s' but no DB entry\n",
                        found->data[found->idx].mboxname,
                        found->data[found->idx].path
                    );

                found->idx++;
            }
            else found->idx++;
        } while (r > 0);

    }

    return 0;
}

static void do_verify(void)
{
    struct found_list found;
    int i;

    found.idx = 0;
    found.size = 0;
    found.alloc = 10;
    found.data = xmalloc(found.alloc * sizeof(struct found_data));

    /* gather a list of partition paths to search */
    config_foreachoverflowstring(get_partitions, &found);

    /* scan all paths in our list, tagging valid mailboxes,
       and adding paths as we find them */
    for (i = 0; i < found.size; i++) {
        DIR *dirp;
        struct dirent *dirent;
        char name[MAX_MAILBOX_BUFFER];
        char part[MAX_MAILBOX_BUFFER];
        char path[MAX_MAILBOX_PATH+1];
        int type;

        if (config_hashimapspool && (found.data[i].type & ROOT)) {
            /* need to add hashed directories */
            int config_fulldirhash = libcyrus_config_getswitch(CYRUSOPT_FULLDIRHASH);
            char *tail;
            int j, c;

            /* make the toplevel partition /a */
            if (config_fulldirhash) {
                strcat(found.data[i].path, "/A");
                c = 'B';
            } else {
                strcat(found.data[i].path, "/a");
                c = 'b';
            }
            type = (found.data[i].type &= ~ROOT);

            /* make a template path for /b - /z */
            strcpy(name, found.data[i].mboxname);
            strcpy(part, found.data[i].partition);
            strcpy(path, found.data[i].path);
            tail = path + strlen(path) - 1;

            for (j = 1; j < 26; j++, c++) {
                *tail = c;
                add_path(&found, type, name, part, path);
            }

            if (config_virtdomains && !type) {
                /* need to add root domain directory */
                strcpy(tail, "domain");
                add_path(&found, DOMAIN | ROOT, name, part, path);
            }
        }

        if (!(dirp = opendir(found.data[i].path))) continue;
        while ((dirent = readdir(dirp))) {
            if (dirent->d_name[0] == '.') continue;
            else if (!strcmp(dirent->d_name, FNAME_HEADER+1)) {
                /* XXX - check that it can be opened */
                found.data[i].type |= MBOX;
            }
            else if (!strchr(dirent->d_name, '.') ||
                     (found.data[i].type & DOMAIN)) {
                /* probably a directory, add it to the array */
                type = 0;
                strcpy(name, found.data[i].mboxname);

                if (config_virtdomains &&
                    (found.data[i].type == ROOT) &&
                    !strcmp(dirent->d_name, "domain")) {
                    /* root domain directory */
                    type = DOMAIN | ROOT;
                }
                else if (!name[0] && found.data[i].type & DOMAIN) {
                    /* toplevel domain directory */
                    strcat(name, dirent->d_name);
                    strcat(name, "!");
                    type = DOMAIN | ROOT;
                }
                else {
                    /* possibly a mailbox directory */
                    if (name[0] && !(found.data[i].type & DOMAIN)) strcat(name, ".");
                    strcat(name, dirent->d_name);
                }

                strcpy(part, found.data[i].partition);
                strcpy(path, found.data[i].path);
                strcat(path, "/");
                strcat(path, dirent->d_name);
                add_path(&found, type, name, part, path);
            }
        }

        closedir(dirp);
    }

    qsort(found.data, found.size, sizeof(struct found_data), compar_mbox);

    mboxlist_allmbox("", &verify_cb, &found, /*incdel*/1);
}

static void usage(void)
{
    fprintf(stderr, "DUMP:\n");
    fprintf(stderr, "  ctl_mboxlist [-C <alt_config>] -d [-x] [-p partition] [-f filename]\n");
    fprintf(stderr, "UNDUMP:\n");
    fprintf(stderr,
            "  ctl_mboxlist [-C <alt_config>] -u [-f filename]"
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

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
        fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:awmdurcxf:p:vi")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'r':
            /* deprecated, but we still support it */
            fprintf(stderr, "ctl_mboxlist -r is deprecated: "
                    "use ctl_cyrusdb -r instead\n");
            syslog(LOG_WARNING, "ctl_mboxlist -r is deprecated: "
                   "use ctl_cyrusdb -r instead");
            if (op == NONE) op = RECOVER;
            else usage();
            break;

        case 'c':
            /* deprecated, but we still support it */
            fprintf(stderr, "ctl_mboxlist -c is deprecated: "
                    "use ctl_cyrusdb -c instead\n");
            syslog(LOG_WARNING, "ctl_mboxlist -c is deprecated: "
                   "use ctl_cyrusdb -c instead");
            if (op == NONE) op = CHECKPOINT;
            else usage();
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

        default:
            usage();
            break;
        }
    }

    if (op != M_POPULATE && (local_authoritative || warn_only)) usage();
    if (op != DUMP && partition) usage();
    if (op != DUMP && dopurge) usage();

    if (op == RECOVER) {
        syslog(LOG_NOTICE, "running mboxlist recovery");
        libcyrus_config_setint(CYRUSOPT_DB_INIT_FLAGS, CYRUSDB_RECOVER);
    }

    cyrus_init(alt_config, "ctl_mboxlist", 0, 0);
    global_sasl_init(1,0,NULL);

    switch (op) {
    case RECOVER:
        /* this was done by the call to cyrus_init via libcyrus */
        syslog(LOG_NOTICE, "done running mboxlist recovery");
        break;

    case CHECKPOINT:
        syslog(LOG_NOTICE, "checkpointing mboxlist");
        mboxlist_init(MBOXLIST_SYNC);
        mboxlist_done();
        syslog(LOG_NOTICE, "done checkpointing mboxlist");
        break;

    case M_POPULATE:
        syslog(LOG_NOTICE, "%spopulating mupdate", warn_only ? "test " : "");

    case DUMP:
        mboxlist_init(0);
        mboxlist_open(mboxdb_fname);

        quotadb_init(0);
        quotadb_open(NULL);

        annotate_init(NULL, NULL);
        annotatemore_open();

        do_dump(op, partition, dopurge);

        annotatemore_close();
        annotate_done();

        quotadb_close();
        quotadb_done();

        mboxlist_close();
        mboxlist_done();

        if (op == M_POPULATE) {
            syslog(LOG_NOTICE,
                   "done %spopulating mupdate", warn_only ? "test " : "");
        }
        break;

    case UNDUMP:
        mboxlist_init(0);
        mboxlist_open(mboxdb_fname);

        quotadb_init(0);
        quotadb_open(NULL);

        annotate_init(NULL, NULL);
        annotatemore_open();

        do_undump();

        annotatemore_close();
        annotate_done();

        quotadb_close();
        quotadb_done();

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
