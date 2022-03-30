/* mbexamine.c -- examine the contents of a mailbox index and cache
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>

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

#include "assert.h"
#include "index.h"
#include "global.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "seen.h"
#include "util.h"
#include "times.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace mbexamine_namespace;

/* forward declarations */
static int do_examine(struct findall_data *data, void *rock);
static int do_quota(struct findall_data *data, void *rock);
static int do_compare(struct findall_data *data, void *rock);
static void usage(void);
void shut_down(int code);

static unsigned wantuid = 0;
static unsigned wantvalue = 0;

int main(int argc, char **argv)
{
    int opt, i, r;
    char buf[MAX_MAILBOX_PATH+1];
    char *alt_config = NULL;
    int (*cb)(struct findall_data *, void *) = &do_examine;
    int ok_count = 0;

    while ((opt = getopt(argc, argv, "C:u:s:qc")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'u':
            if(wantvalue) usage();
            wantuid = 1;
            wantvalue = atoi(optarg);
            break;

        case 's':
            if(wantvalue) usage();
            wantvalue = atoi(optarg);
            break;

        case 'q':
            cb = &do_quota;
            break;

        case 'c':
            cb = &do_compare;
            break;

        default:
            usage();
        }
    }

    cyrus_init(alt_config, "mbexamine", 0, 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&mbexamine_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (optind == argc) {
        strlcpy(buf, "*", sizeof(buf));
        r = mboxlist_findall(&mbexamine_namespace, buf, 1, 0, 0, cb, &ok_count);
        if (r) {
            fprintf(stderr, "%s: %s\n", buf, error_message(r));
        }
    }

    for (i = optind; i < argc; i++) {
        r = mboxlist_findall(&mbexamine_namespace, argv[i], 1, 0, 0, cb, &ok_count);
        if (r) {
            fprintf(stderr, "%s: %s\n", argv[i], error_message(r));
        }
    }

    cyrus_done();

    if (r && !ok_count) {
        return r;
    }
    else if (!ok_count) {
        fprintf(stderr, "No matching mailboxes found\n");
        return EX_NOUSER; /* XXX i guess? */
    }
    else {
        return 0;
    }
}

static void usage(void)
{
    fprintf(stderr,
            "usage: mbexamine [-C <alt_config>] [-s seqnum] mailbox...\n"
            "       mbexamine [-C <alt_config>] [-u uid] mailbox...\n"
            "       mbexamine [-C <alt_config>] -q mailbox...\n"
            "       mbexamine [-C <alt_config>] -c mailbox...\n");
    exit(EX_USAGE);
}

static void print_rec(const char *name, const struct buf *citem)
{
    printf(" %s>{" SIZE_T_FMT "}%.*s\n", name, citem->len, (int)citem->len, citem->s);
}

/*
 * mboxlist_findall() callback function to examine a mailbox
 */
static int do_examine(struct findall_data *data, void *rock)
{
    unsigned i, msgno;
    int r = 0;
    int flag = 0;
    struct mailbox *mailbox = NULL;
    int j;
    int *ok_count = (int *) rock;

    /* don't want partial matches */
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    signals_poll();

    /* Convert internal name to external */
    const char *extname = mbname_extname(data->mbname, &mbexamine_namespace, "cyrus");
    printf("Examining %s...", extname);

    const char *name = mbname_intname(data->mbname);

    /* Open/lock header */
    r = mailbox_open_irl(name, &mailbox);
    if (r) return r;

    printf(" Mailbox Header Info:\n");
    printf("  Path to mailbox: %s\n", mailbox_datapath(mailbox, 0));
    printf("  Mailbox ACL: %s\n", mailbox_acl(mailbox)); /* xxx parse */
    printf("  Unique ID: %s\n", mailbox_uniqueid(mailbox));
    printf("  User Flags: ");

    for (i = 0; i < MAX_USER_FLAGS; i++) {
        if (!mailbox->h.flagname[i]) break;
        printf("%s ", mailbox->h.flagname[i]);
    }

    if (!i) printf("[none]");

    printf("\n");

    printf("\n Index Header Info:\n");
    printf("  Generation Number: %d\n", mailbox->i.generation_no);
    printf("  Minor Version: %d\n", mailbox->i.minor_version);
    printf("  Header Size: %u bytes  Record Size: %u bytes\n",
           mailbox->i.start_offset, mailbox->i.record_size);
    printf("  Number of Messages: %u  Mailbox Size: " QUOTA_T_FMT " bytes  Annotations Size: " QUOTA_T_FMT " bytes\n",
           mailbox->i.exists, mailbox->i.quota_mailbox_used, mailbox->i.quota_annot_used);
    printf("  Last Append Date: (" TIME_T_FMT ") %s",
           mailbox->i.last_appenddate, ctime(&mailbox->i.last_appenddate));
    printf("  UIDValidity: %u  Last UID: %u\n",
           mailbox->i.uidvalidity, mailbox->i.last_uid);
    printf("  Deleted: %u  Answered: %u  Flagged: %u\n",
           mailbox->i.deleted, mailbox->i.answered, mailbox->i.flagged);
    printf("  Mailbox Options:");
    if (!mailbox->i.options) {
        printf(" NONE");
    } else {
        if (mailbox->i.options & OPT_POP3_NEW_UIDL) {
            printf(" POP3_NEW_UIDL");
        }
        if (mailbox->i.options & OPT_IMAP_SHAREDSEEN) {
            printf(" IMAP_SHAREDSEEN");
        }
        if (mailbox->i.options & OPT_IMAP_DUPDELIVER) {
            printf(" IMAP_DUPDELIVER");
        }
        if (mailbox->i.options & OPT_IMAP_HAS_ALARMS) {
            printf(" IMAP_HAS_ALARMS");
        }
    }
    printf("\n");
    printf("  Last POP3 Login: (" TIME_T_FMT ") %s", mailbox->i.pop3_last_login,
           ctime((const time_t *) &mailbox->i.pop3_last_login));
    printf("  Highest Mod Sequence: " MODSEQ_FMT "\n",
           mailbox->i.highestmodseq);

    printf("\n Message Info:\n");

    msgno = 1;
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (wantvalue) {
            if (wantuid) {
                if (record->uid != wantvalue) continue;
            } else {
                if (msgno != wantvalue) continue;
            }
            flag = 1;
        }

        printf("%06u> UID:%08u"
               "   INT_DATE:" TIME_T_FMT " SENTDATE:" TIME_T_FMT " SAVEDATE:" TIME_T_FMT " SIZE:%-6u\n",
               msgno, record->uid, record->internaldate,
               record->sentdate, record->savedate, record->size);
        printf("      > HDRSIZE:%-6u LASTUPD :" TIME_T_FMT " SYSFLAGS:%08X",
               record->header_size, record->last_updated,
               record->system_flags);

        if (mailbox->i.minor_version >= 6)
            printf("      > CACHEVER:%-2u", record->cache_version);

        if (mailbox->i.minor_version >= 7) {
            printf(" GUID:%s", message_guid_encode(&record->guid));
        }

        if (mailbox->i.minor_version >= 8) {
            printf(" MODSEQ:" MODSEQ_FMT, record->modseq);
        }

        if (mailbox->i.minor_version >= 13) {
            printf("  THRID: %llx", record->cid);
        }

        printf("\n");

        printf("      > INTERNALFLAGS:");
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED)
            printf(" FLAG_INTERNAL_EXPUNGED");
        if (record->internal_flags & FLAG_INTERNAL_UNLINKED)
            printf(" FLAG_INTERNAL_UNLINKED");
        if (record->internal_flags & FLAG_INTERNAL_ARCHIVED)
            printf(" FLAG_INTERNAL_ARCHIVED");
        if (record->internal_flags & FLAG_INTERNAL_NEEDS_CLEANUP)
            printf(" FLAG_INTERNAL_NEEDS_CLEANUP");
        if (record->internal_flags & FLAG_INTERNAL_SNOOZED)
            printf(" FLAG_INTERNAL_SNOOZED");

        printf("      > SYSTEMFLAGS:");
        if (record->system_flags & FLAG_SEEN) printf(" FLAG_SEEN");
        if (record->system_flags & FLAG_DRAFT) printf(" FLAG_DRAFT");
        if (record->system_flags & FLAG_DELETED) printf(" FLAG_DELETED");
        if (record->system_flags & FLAG_FLAGGED) printf(" FLAG_FLAGGED");
        if (record->system_flags & FLAG_ANSWERED) printf(" FLAG_ANSWERED");

        printf("\n");

        printf("      > USERFLAGS:");
        for (j=(MAX_USER_FLAGS/32)-1; j>=0; j--) {
            printf(" %08X", record->user_flags[j]);
        }
        printf("\n");

        if (!mailbox_cacherecord(mailbox, record)) {
            print_rec("Envel", cacheitem_buf(record, CACHE_ENVELOPE));
            print_rec("BdyStr", cacheitem_buf(record, CACHE_BODYSTRUCTURE));
            print_rec("Body", cacheitem_buf(record, CACHE_BODY));
            print_rec("CacHdr", cacheitem_buf(record, CACHE_HEADERS));
            print_rec("From", cacheitem_buf(record, CACHE_FROM));
            print_rec("To", cacheitem_buf(record, CACHE_TO));
            print_rec("Cc", cacheitem_buf(record, CACHE_CC));
            print_rec("Bcc", cacheitem_buf(record, CACHE_BCC));
            print_rec("Subjct", cacheitem_buf(record, CACHE_SUBJECT));
        }

        if (flag) break;
    }

    mailbox_iter_done(&iter);

    if (wantvalue && !flag) {
        printf("Desired message not found\n");
    }

    mailbox_close(&mailbox);

    if (!r && ok_count) (*ok_count) ++;

    return r;
}

/*
 * mboxlist_findall() callback function to examine a mailbox quota usage
 */
static int do_quota(struct findall_data *data, void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    quota_t total = 0;
    const char *fname;
    struct stat sbuf;
    int *ok_count = (int *) rock;

    /* don't want partial matches */
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    signals_poll();

    /* Convert internal name to external */
    const char *extname = mbname_extname(data->mbname, &mbexamine_namespace, "cyrus");
    printf("Examining %s...", extname);

    const char *name = mbname_intname(data->mbname);

    /* Open/lock header */
    r = mailbox_open_irl(name, &mailbox);
    if (r) return r;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        fname = mailbox_record_fname(mailbox, record);

        if (stat(fname, &sbuf) != 0) {
            syslog(LOG_WARNING,
                   "Can not open message file %s -- skipping", fname);
            continue;
        }

        if (record->size != (unsigned) sbuf.st_size) {
            printf("  Message %u has INCORRECT size in index record\n", record->uid);
            r = 0;
            mailbox_iter_done(&iter);
            goto done;
        }

        total += sbuf.st_size;
    }
    mailbox_iter_done(&iter);

    if (mailbox->i.quota_mailbox_used != total) {
        printf("  Mailbox has INCORRECT total quota usage\n");
    }
    else {
        printf("  Mailbox has CORRECT total quota usage\n");
    }

 done:
    mailbox_close(&mailbox);
    if (!r && ok_count) (*ok_count) ++;

    return r;
}

int numcmp(const void *a, const void *b)
{
    uint32_t *n1 = (uint32_t *) a;
    uint32_t *n2 = (uint32_t *) b;

    return (*n1 - *n2);
}

/*
 * mboxlist_findall() callback function to compare a mailbox
 */
static int do_compare(struct findall_data *data, void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    DIR *dirp;
    struct dirent *dirent;
    uint32_t *uids = NULL, nalloc, count = 0, msgno;
    int *ok_count = (int *) rock;

    /* don't want partial matches */
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    signals_poll();

    /* Convert internal name to external */
    const char *extname = mbname_extname(data->mbname, &mbexamine_namespace, "cyrus");
    printf("Examining %s...", extname);

    const char *name = mbname_intname(data->mbname);

    /* Open/lock header */
    r = mailbox_open_irl(name, &mailbox);
    if (r) return r;

    if (mailbox->i.minor_version < 7) {
        printf("Mailbox version is too old for comparison\n");
        goto done;
    }

    if (chdir(mailbox_datapath(mailbox, 0)) == -1) {
        r = IMAP_IOERROR;
        goto done;
    }

    /* Scan the mailbox spool directory */
    dirp = opendir(".");
    if (!dirp) {
        r = IMAP_IOERROR;
        goto done;
    }

    /* Build a sorted array of message UIDs */
    nalloc = mailbox->i.exists;
    uids = xzmalloc(nalloc * sizeof(uint32_t));

    while ((dirent = readdir(dirp))) {
        uint32_t uid;

        if (sscanf(dirent->d_name, "%u.", &uid) != 1) continue;
        
        if (count >= nalloc) {
            nalloc += 2;
            uids = xrealloc(uids, nalloc * sizeof(uint32_t));
        }
        uids[count++] = uid;
    }
    qsort(uids, count, sizeof(uint32_t), &numcmp);
    closedir(dirp);

    
    printf("\n Mailbox Header Info:\n");
    printf("  Path to mailbox: %s\n", mailbox_datapath(mailbox, 0));

    printf("\n%-56s\t%s\n", " Index Record Info:", "Message File Info:");

    msgno = 0;
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter)) || msgno < count) {
        const struct index_record *record = msg ? msg_record(msg) : NULL;

        r = 0;

        do {
            struct index_record fs_record = { .uid = 0 };
            const struct buf *citem, empty_buf = BUF_INITIALIZER;
            char sent[RFC5322_DATETIME_MAX+1] = "";

            if (msgno < count) {
                char fname[100];

                if (!record || uids[msgno] <= record->uid) {
                    fs_record.uid = uids[msgno++];

                    snprintf(fname, sizeof(fname), "%u.", fs_record.uid);
                    if (message_parse(fname, &fs_record)) {
                        message_guid_set_null(&fs_record.guid);
                    }

                    if (record && (record->uid == fs_record.uid) &&
                         message_guid_equal(&record->guid, &fs_record.guid)) {
                        /* Skip matches */
                        continue;
                    }
                }
            }

            printf("  UID: %08u\n", record ? record->uid : fs_record.uid);

            printf("   GUID: %-50s",
                   record ? message_guid_encode(&record->guid) : "");

            if (fs_record.uid) {
                printf("\t%-50s", message_guid_isnull(&fs_record.guid) ?
                       "Failed to parse file" :
                       message_guid_encode(&fs_record.guid));
            }
            printf("\n");

            printf("   Size: ");
            if (record) printf("%-50u", record->size);
            else printf("%-50s", "");

            if (fs_record.uid && !message_guid_isnull(&fs_record.guid))
                printf("\t%-50u", fs_record.size);
            printf("\n");

            if (record) time_to_rfc5322(record->sentdate, sent, sizeof(sent));
            printf("   Date: %-50s", sent);

            if (fs_record.uid && !message_guid_isnull(&fs_record.guid)) {
                time_to_rfc5322(fs_record.sentdate, sent, sizeof(sent));
                printf("\t%-50s", sent);
            }
            printf("\n");

            r = record ? mailbox_cacherecord(mailbox, record) : -1;

            citem = r ? &empty_buf : cacheitem_buf(record, CACHE_FROM);
            printf("   From: %-50.*s", (int) MIN(citem->len, 50), citem->s);

            if (fs_record.uid && !message_guid_isnull(&fs_record.guid)) {
                citem = cacheitem_buf(&fs_record, CACHE_FROM);
                printf("\t%-50.*s", (int) MIN(citem->len, 50), citem->s);
            }
            printf("\n");

            citem = r ? &empty_buf : cacheitem_buf(record, CACHE_SUBJECT);
            printf("   Subj: %-50.*s", (int) MIN(citem->len, 50), citem->s);

            if (fs_record.uid && !message_guid_isnull(&fs_record.guid)) {
                citem = cacheitem_buf(&fs_record, CACHE_SUBJECT);
                printf("\t%-50.*s", (int) MIN(citem->len, 50), citem->s);
            }
            printf("\n");
            printf("\n");

        } while ((msgno < count) && (!record || uids[msgno] <= record->uid));
    }

    mailbox_iter_done(&iter);

  done:
    mailbox_close(&mailbox);
    free(uids);

    if (!r && ok_count) (*ok_count) ++;

    return r;
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    mboxlist_close();
    mboxlist_done();
    exit(code);
}
