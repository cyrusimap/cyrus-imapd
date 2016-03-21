/* restore.c -- tool for restoring from replication-based backups
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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
 */
#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/exitcodes.h"

#include "imap/global.h"
#include "imap/imap_err.h"
#include "imap/mboxname.h"
#include "imap/message_guid.h"
#include "imap/sync_support.h"

#include "backup/backup.h"

EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    exit(code);
}

static const char *argv0 = NULL;
static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    exit(EC_USAGE);
}

static void save_argv0(const char *s)
{
    const char *slash = strrchr(s, '/');
    if (slash)
        argv0 = slash + 1;
    else
        argv0 = s;
}

enum restore_mode {
    RESTORE_MODE_UNSPECIFIED = 0,
    RESTORE_MODE_FILENAME,
    RESTORE_MODE_MBOXNAME,
    RESTORE_MODE_USERNAME,
};

enum restore_expunged_mode {
    RESTORE_EXPUNGED_OKAY = 0,
    RESTORE_EXPUNGED_EXCLUDE,
    RESTORE_EXPUNGED_ONLY,
};

struct restore_options {
    const char *override_acl;
    const char *override_mboxname;
    const char *override_partition;
    enum restore_expunged_mode expunged_mode;
    int do_submailboxes;
    int keep_uidvalidity;
    int trim_deletedprefix;
    int verbose;
};

#define HEX_DIGITS "0123456789abcdefghijklmnopqrstuvwxyz"

static int restore_add_object(const char *object_name,
                              const struct restore_options *options,
                              struct backup *backup,
                              struct backup_mailbox_list *mailbox_list,
                              struct sync_reserve_list *reserve_list);

int main(int argc, char **argv)
{
    save_argv0(argv[0]);

    const char *alt_config = NULL;
    const char *input_file = NULL;
    const char *backup_name = NULL;
    const char *servername = NULL;
    enum restore_mode mode = RESTORE_MODE_UNSPECIFIED;
    int local_only = 0;
    int require_compression = 0;
    int wait = 0;

    struct restore_options options = {0};
    options.expunged_mode = RESTORE_EXPUNGED_OKAY;
    options.trim_deletedprefix = 1;

    struct backup *backup = NULL;
    mbname_t *mbname = NULL;
    struct backup_mailbox_list *mailbox_list = NULL;
    struct sync_reserve_list *reserve_list = NULL;
    int opt, r;

    while ((opt = getopt(argc, argv, "A:C:DF:LM:P:S:UXf:m:ru:vw:xz")) != EOF) {
        switch (opt) {
        case 'A':
            if (options.keep_uidvalidity) usage();
            options.override_acl = optarg;
            break;
        case 'C':
            alt_config = optarg;
            break;
        case 'D':
            options.trim_deletedprefix = 0;
            break;
        case 'F':
            input_file = optarg;
            break;
        case 'L':
            local_only = 1;
            break;
        case 'M':
            if (options.keep_uidvalidity) usage();
            options.override_mboxname = optarg;
            break;
        case 'P':
            if (options.keep_uidvalidity) usage();
            options.override_partition = optarg;
            break;
        case 'S':
            servername = optarg;
            break;
        case 'U':
            if (options.override_acl || options.override_mboxname || options.override_partition)
                usage();
            options.keep_uidvalidity = 1;
            break;
        case 'X':
            if (options.expunged_mode != RESTORE_EXPUNGED_OKAY) usage();
            options.expunged_mode = RESTORE_EXPUNGED_EXCLUDE;
            break;
        case 'f':
            if (mode != RESTORE_MODE_UNSPECIFIED) usage();
            mode = RESTORE_MODE_FILENAME;
            backup_name = optarg;
            break;
        case 'm':
            if (mode != RESTORE_MODE_UNSPECIFIED) usage();
            mode = RESTORE_MODE_MBOXNAME;
            backup_name = optarg;
            break;
        case 'r':
            options.do_submailboxes = 1;
            break;
        case 'u':
            if (mode != RESTORE_MODE_UNSPECIFIED) usage();
            mode = RESTORE_MODE_USERNAME;
            backup_name = optarg;
            break;
        case 'v':
            options.verbose++;
            break;
        case 'w':
            wait = atoi(optarg);
            if (wait < 0) usage();
            break;
        case 'x':
            if (options.expunged_mode != RESTORE_EXPUNGED_OKAY) usage();
            options.expunged_mode = RESTORE_EXPUNGED_ONLY;
            break;
        case 'z':
            require_compression = 1;
            break;
        default:
            usage();
            break;
        }
    }

    /* we need a server name */
    if (!servername) usage();

    /* we need a source of backup data */
    if (!backup_name || mode == RESTORE_MODE_UNSPECIFIED) usage();

    /* we need either an input file or some objects to restore */
    if (!input_file && optind == argc) usage();
    /* and we can't have both because i said */
    if (input_file && optind < argc) usage();

    /* okay, arguments seem sane, we are go */
    cyrus_init(alt_config, "restore", 0, 0);

    /* wait here for gdb attach */
    if (wait) {
        fprintf(stderr, "Waiting for %d seconds for gdb attach...\n", wait);
        sleep(wait);
    }

    /* open backup */
    switch (mode) {
    case RESTORE_MODE_FILENAME:
        r = backup_open_paths(&backup, backup_name, NULL,
                              BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        break;
    case RESTORE_MODE_MBOXNAME:
        mbname = mbname_from_intname(backup_name);
        if (!mbname) usage();
        r = backup_open(&backup, mbname,
                        BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        break;
    case RESTORE_MODE_USERNAME:
        mbname = mbname_from_userid(backup_name);
        if (!mbname) usage();
        r = backup_open(&backup, mbname,
                        BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        break;
    default:
        usage();
        break;
    }

    if (r) goto done;

    /* scan for objects to restore */
    mailbox_list = xzmalloc(sizeof *mailbox_list);
    reserve_list = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    if (input_file) {
        char buf[MAX_MAILBOX_NAME + 2]; // \n\0
        size_t len;
        FILE *f;

        f = fopen(input_file, "r");
        if (!f) {
            fprintf(stderr, "fopen %s: %s", input_file, strerror(errno));
            goto done;// FIXME shut_down?
        }
        while (fgets(buf, sizeof(buf), f)) {
            len = strlen(buf);

            if (len > 0 && buf[len - 1] == '\n')
                buf[--len] = '\0';

            if (len == 0 || buf[0] == '#')
                continue;

            r = restore_add_object(buf, &options, backup,
                                   mailbox_list, reserve_list);

            // FIXME r
        }
        fclose(f);
    }
    else {
        int i;

        for (i = optind; i < argc; i++) {
            r = restore_add_object(argv[i], &options, backup,
                                   mailbox_list, reserve_list);

            // FIXME r
        }
    }

    /* building lists of restore info:
     *   mailboxes will have all messages added, modulo expunged_mode
     *   messages will be added individually with appropriate folder
     */

    /* need to build a sync_folder_list of the mailboxes
     * this will be something like find_reserve_all but using backup data
     * plus our options.
     */

    /* reserve:
     *   need to build a sync_reserve_list and then call sync_reserve_partition
     *   on each node.  the list internals will be updated to flag which
     *   messages need upload
     */

    /* message:
     *   something akin to sync_prepare_dlists (which creates an APPLY MAILBOX dlist
     *   plus a kupload list of the required APPLY MESSAGES), except that it should
     *   create a RESTORE MAILBOX instead.
     *   then send them (ala update_mailbox_once)
     */


done:
    if (r)
        fprintf(stderr, "%s: %s:\n", backup_name, error_message(r));

    if (mailbox_list) {
        backup_mailbox_list_empty(mailbox_list);
        free(mailbox_list);
    }

    if (reserve_list)
        sync_reserve_list_free(&reserve_list);

    if (mbname)
        mbname_free(&mbname);

    if (backup)
        backup_close(&backup);

    backup_cleanup_staging_path();
    cyrus_done();

    (void) local_only;
    (void) require_compression;

    exit(r ? EC_TEMPFAIL : EC_OK);
}

//static void my_folder_list_add(struct sync_folder_list *folder_list,
//                               const char *mboxname)
//{
//    struct sync_folder *folder;

//    /* don't add to the folder list if it's already in there */
//    for (folder = folder_list->head; folder; folder = folder->next) {
//        if (0 == strcmp(folder->name, mboxname)) break;
//    }
//    if (!folder) {
//        /* we only really care about the mboxname */
//        struct synccrcs tmp_synccrcs = { 0, 0 };

//        sync_folder_list_add(folder_list, NULL, mboxname,
//                             0, NULL, NULL, 0, 0, 0, 0, tmp_synccrcs,
//                             0, 0, 0, 0, NULL, 0);
//    }
//}

static void my_mailbox_list_add(struct backup_mailbox_list *mailbox_list,
                                struct backup_mailbox *mailbox)
{
    struct backup_mailbox *tmp;

    for (tmp = mailbox_list->head; tmp; tmp = tmp->next) {
        if (0 == strcmp(tmp->mboxname, mailbox->mboxname)) break;
    }

    if (tmp) {
        /* mailbox already in our list -- append the records to it */
        if (!tmp->records) {
            tmp->records = mailbox->records;
            mailbox->records = NULL;
        }
        else if (!tmp->records->head) {
            tmp->records->head = mailbox->records->head;
            tmp->records->tail = mailbox->records->tail;
            tmp->records->count = mailbox->records->count;
            memset(mailbox->records, 0, sizeof *mailbox->records);
        }
        else {
            tmp->records->tail->next = mailbox->records->head;
            tmp->records->tail = mailbox->records->tail;
            tmp->records->count += mailbox->records->count;
            memset(mailbox->records, 0, sizeof *mailbox->records);
        }
    }
    else {
        /* not already in our list -- just add it */
        backup_mailbox_list_add(mailbox_list, mailbox);
    }
}

static void apply_mailbox_options(struct backup_mailbox *mailbox,
                                  const struct restore_options *options)
{
    if (options->override_mboxname) {
        if (mailbox->mboxname) free(mailbox->mboxname);
        mailbox->mboxname = xstrdup(options->override_mboxname);
    }

    if (options->override_partition) {
        if (mailbox->partition) free(mailbox->partition);
        mailbox->partition = xstrdup(options->override_partition);
    }

    if (options->override_acl) {
        if (mailbox->acl) free(mailbox->acl);
        mailbox->acl = xstrdup(options->override_acl);
    }

    if (!options->keep_uidvalidity) {
        if (mailbox->uniqueid) free(mailbox->uniqueid);
        mailbox->uniqueid = NULL;
        mailbox->highestmodseq = 0;
        mailbox->uidvalidity = 0;
    }
}

static int restore_add_mailbox(struct backup_mailbox *mailbox,
                               const struct restore_options *options,
                               struct backup_mailbox_list *mailbox_list,
                               struct sync_reserve_list *reserve_list)
{
    apply_mailbox_options(mailbox, options);

    /* populate reserve list */
    if (mailbox->records) {
        struct sync_msgid_list *msgid_list = NULL;
        struct backup_mailbox_message *record = NULL;

        msgid_list = sync_reserve_partlist(reserve_list, mailbox->partition);
        for (record = mailbox->records->head; record; record = record->next) {
            sync_msgid_insert(msgid_list, &record->guid);
        }
    }

    /* populate mailbox list */
    my_mailbox_list_add(mailbox_list, mailbox);

    return 0;
}

static int restore_add_message(struct backup_message *message,
                               struct backup_mailbox_list *message_mailboxes,
                               const struct restore_options *options,
                               struct backup_mailbox_list *mailbox_list,
                               struct sync_reserve_list *reserve_list)
{
    struct sync_msgid_list *msgid_list = NULL;

    if (options->override_partition) {
        if (message->partition) free(message->partition);
        message->partition = xstrdup(options->override_partition);
    }

    /* add to reserve list */
    msgid_list = sync_reserve_partlist(reserve_list, message->partition);
    sync_msgid_insert(msgid_list, message->guid);

    /* add to mailboxes list */
    if (options->override_mboxname) {
        /* create a mailbox... */
        struct backup_mailbox *mailbox = xzmalloc(sizeof *mailbox);
        apply_mailbox_options(mailbox, options);

        /* ... containing this message */
        struct backup_mailbox_message *mailbox_message =
            xzmalloc(sizeof *mailbox_message);

        mailbox_message->guid = *message->guid;
        mailbox_message->size = message->length;

        mailbox->records = xzmalloc(sizeof *mailbox->records);
        mailbox->records->head = mailbox->records->tail = mailbox_message;
        mailbox->records->count = 1;

        my_mailbox_list_add(mailbox_list, mailbox);
    }
    else if (message_mailboxes) {
        while (message_mailboxes->head) {
            struct backup_mailbox *mailbox =
                backup_mailbox_list_remove(message_mailboxes, message_mailboxes->head);
            apply_mailbox_options(mailbox, options);
            my_mailbox_list_add(mailbox_list, mailbox);
        }
    }

    return 0;
}

struct submailbox_rock {
    const char *prefix;
    size_t prefix_len;
    const struct restore_options *options;
    struct backup_mailbox_list *mailbox_list;
    struct sync_reserve_list *reserve_list;
};

static int submailbox_cb(const struct backup_mailbox *mailbox, void *rock)
{
    struct submailbox_rock *smbrock = (struct submailbox_rock *) rock;

    if (0 == strncmp(smbrock->prefix, mailbox->mboxname, smbrock->prefix_len)) {
        /* XXX we need a non-const mailbox to for optional overrides */
        // FIXME this won't work, foreach will free it, we need to clone it */
        struct backup_mailbox *backdoor = (struct backup_mailbox *) mailbox;
        return restore_add_mailbox(backdoor,
                                   smbrock->options,
                                   smbrock->mailbox_list,
                                   smbrock->reserve_list);
    }

    return 0;
}

static int restore_add_object(const char *object_name,
                              const struct restore_options *options,
                              struct backup *backup,
                              struct backup_mailbox_list *mailbox_list,
                              struct sync_reserve_list *reserve_list)
{
    struct backup_mailbox *mailbox = NULL;
    struct backup_message *message = NULL;
    struct message_guid tmp_guid;
    size_t len;
    int r;

    /* try to work out what we're restoring */
    len = strlen(object_name);
    if (len == 24 && strspn(object_name, HEX_DIGITS) == len) {
        /* looks like a non-libuuid uniqueid */
        mailbox = backup_get_mailbox_by_uniqueid(backup, object_name, 1);
    }
    else if (len == 36 && strspn(object_name, "-" HEX_DIGITS) == len) {
        /* looks like a libuuid uniqueid */
        mailbox = backup_get_mailbox_by_uniqueid(backup, object_name, 1);
    }
    else if (message_guid_decode(&tmp_guid, object_name)) {
        /* looks like it's a message guid */
        message = backup_get_message(backup, &tmp_guid);
    }
    else if (strchr(object_name, '.')) {
        /* has a dot, might be an mboxname */
        mbname_t *mbname = mbname_from_intname(object_name);
        mailbox = backup_get_mailbox_by_name(backup, mbname, 1);
        mbname_free(&mbname);
    }
    else {
        /* not sure what it is, guess mboxname? */
        mbname_t *mbname = mbname_from_intname(object_name);
        mailbox = backup_get_mailbox_by_name(backup, mbname, 1);
        mbname_free(&mbname);
    }

    /* add it to the restore lists */
    if (mailbox) {
        r = restore_add_mailbox(mailbox, options, mailbox_list, reserve_list);

        if (!r && options->do_submailboxes) {
            char prefix[MAX_MAILBOX_NAME + 1];
            int len;

            len = snprintf(prefix, sizeof(prefix), "%s.", mailbox->mboxname);

            /* can only be submailboxes if parent's path is short enough... */
            if (len < MAX_MAILBOX_NAME) {
                struct submailbox_rock rock = {
                    prefix,
                    strlen(prefix),
                    options,
                    mailbox_list,
                    reserve_list,
                };

                r = backup_mailbox_foreach(backup, 0, 1, submailbox_cb, &rock);
            }
        }

        backup_mailbox_free(&mailbox);
    }
    else if (message) {
        struct backup_mailbox_list *mailboxes = NULL;

        if (!options->override_mboxname)
            mailboxes = backup_get_mailboxes_by_message(backup, message,
                                                        BACKUP_MAILBOX_MATCH_RECORDS);
        r = restore_add_message(message, mailboxes, options,
                                mailbox_list, reserve_list);

        if (mailboxes) {
            backup_mailbox_list_empty(mailboxes);
            free(mailboxes);
        }
        backup_message_free(&message);
    }
    else {
        r = IMAP_MAILBOX_NONEXISTENT;
    }

    return r;
}
