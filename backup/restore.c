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
#include <sysexits.h>
#include <unistd.h>


#include "imap/global.h"
#include "imap/imap_err.h"
#include "imap/imap_proxy.h"
#include "imap/mboxname.h"
#include "imap/message_guid.h"
#include "imap/sync_support.h"

#include "backup/backup.h"

static struct namespace restore_namespace;

EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    exit(code);
}

static const char *argv0 = NULL;
static __attribute__((noreturn)) void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [options] server [mode] backup [mboxname | uniqueid | guid]...\n", argv0);

    fprintf(stderr, "\n%s\n",
            "Options:\n"
            "    -A [acl]            # apply specified acl to restored mailboxes\n"
            "    -C alt_config       # alternate config file\n"
            "    -D                  # don't trim deletedprefix before restoring\n"
            "    -F input-file       # read mailboxes/messages from file rather than argv\n"
            "    -L                  # local mailbox operations only (no mupdate)\n"
            "    -M mboxname         # restore messages to specified mailbox\n"
            "    -P partition        # restore mailboxes to specified partition\n"
            "    -U                  # try to preserve uniqueid, uid, modseq, etc\n"
            "    -X                  # don't restore expunged messages\n"
            "    -a                  # try to restore all mailboxes in backup\n"
            "    -n                  # calculate work required but don't perform restoration\n"
            "    -r                  # recurse into submailboxes\n"
            "    -v                  # verbose (repeat for more verbosity)\n"
            "    -w seconds          # wait before starting (useful for attaching a debugger)\n"
            "    -x                  # only restore expunged messages\n"
            "    -z                  # require compression (abort if compression unavailable)\n"
    );

    fprintf(stderr, "%s\n",
            "Modes:\n"
            "    -f                  # specified backup interpreted as filename\n"
            "    -m                  # specified backup interpreted as mboxname\n"
            "    -u                  # specified backup interpreted as userid (default)\n"
    );

    exit(EX_USAGE);
}

static void save_argv0(const char *s)
{
    const char *slash = strrchr(s, '/');
    if (slash)
        argv0 = slash + 1;
    else
        argv0 = s;
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

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
    int require_compression;
    int trim_deletedprefix;
    int verbose;
};

#define HEX_DIGITS "0123456789abcdefghijklmnopqrstuvwxyz"

static int restore_add_object(const char *object_name,
                              const struct restore_options *options,
                              struct backup *backup,
                              struct backup_mailbox_list *mailbox_list,
                              struct sync_folder_list *reserve_folder_list,
                              struct sync_reserve_list *reserve_list);
static int restore_add_mailbox(const struct backup_mailbox *mailbox,
                               const struct restore_options *options,
                               struct backup_mailbox_list *mailbox_list,
                               struct sync_folder_list *reserve_folder_list,
                               struct sync_reserve_list *reserve_list);
static int restore_add_message(const struct backup_message *message,
                               const struct backup_mailbox_list *message_mailboxes,
                               const struct restore_options *options,
                               struct backup_mailbox_list *mailbox_list,
                               struct sync_folder_list *reserve_folder_list,
                               struct sync_reserve_list *reserve_list);

static struct sync_folder_list *restore_make_reserve_folder_list(
                              struct backup *backup);


int main(int argc, char **argv)
{
    save_argv0(argv[0]);

    const char *alt_config = NULL;
    const char *input_file = NULL;
    const char *backup_name = NULL;
    const char *servername = NULL;
    enum restore_mode mode = RESTORE_MODE_UNSPECIFIED;
    int local_only = 0;
    int wait = 0;
    int do_nothing = 0;
    int do_all_mailboxes = 0;

    struct restore_options options = {0};
    options.expunged_mode = RESTORE_EXPUNGED_OKAY;
    options.trim_deletedprefix = 1;

    struct backup *backup = NULL;
    mbname_t *mbname = NULL;
    struct backup_mailbox_list *mailbox_list = NULL;
    struct sync_folder_list *reserve_folder_list = NULL;
    struct sync_reserve_list *reserve_list = NULL;
    struct sync_client_state sync_cs = SYNC_CLIENT_STATE_INITIALIZER;
    struct dlist *upload = NULL;
    int opt, r = 0;

    while ((opt = getopt(argc, argv, ":A:C:DF:LM:P:UXaf:m:nru:vw:xz")) != EOF) {
        switch (opt) {
        case 'A':
            if (options.keep_uidvalidity) usage();
            options.override_acl = optarg;
            break;
        case 'C':
            alt_config = optarg;
            break;
        case 'D':
            /* XXX does this clash with keep_uidvalidity? */
            options.trim_deletedprefix = 0;
            break;
        case 'F':
            if (do_all_mailboxes) usage();
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
        case 'U':
            if (options.override_acl || options.override_mboxname || options.override_partition)
                usage();
            options.keep_uidvalidity = 1;
            break;
        case 'X':
            if (options.expunged_mode != RESTORE_EXPUNGED_OKAY) usage();
            options.expunged_mode = RESTORE_EXPUNGED_EXCLUDE;
            break;
        case 'a':
            if (input_file) usage();
            do_all_mailboxes = 1;
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
        case 'n':
            do_nothing = 1;
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
            options.require_compression = 1;
            break;
        case ':':
            if (optopt == 'A') options.override_acl = "";
            else usage();
            break;
        default:
            usage();
            break;
        }
    }

    /* we need a server name */
    if (optind == argc) usage();
    servername = argv[optind++];

    /* we need a source of backup data */
    if (mode == RESTORE_MODE_UNSPECIFIED) {
        if (optind == argc) usage();
        backup_name = argv[optind++];
        mode = RESTORE_MODE_USERNAME;
    }

    /* we need either an input file or some objects to restore */
    if (!do_all_mailboxes && !input_file && optind == argc) usage();
    /* and we can't have both because i said */
    if ((input_file || do_all_mailboxes) && optind < argc) usage();

    /* okay, arguments seem sane, we are go */
    cyrus_init(alt_config, "restore", 0, 0);

    if ((r = mboxname_init_namespace(&restore_namespace, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
    }
    mboxevent_setnamespace(&restore_namespace);

    /* load the SASL plugins */
    global_sasl_init(1, 0, mysasl_cb);

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
        mbname = mbname_from_extname(backup_name, &restore_namespace, NULL);
        if (!mbname) usage();
        r = backup_open(&backup, mbname,
                        BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        mbname_free(&mbname);
        break;
    case RESTORE_MODE_USERNAME:
        mbname = mbname_from_userid(backup_name);
        if (!mbname) usage();
        r = backup_open(&backup, mbname,
                        BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        mbname_free(&mbname);
        break;
    default:
        usage();
        break;
    }

    if (r) goto done;

    /* scan for objects to restore:
     *   mailboxes will have all messages added, modulo expunged_mode
     *   messages will be added individually with appropriate folder
     */
    mailbox_list = xzmalloc(sizeof *mailbox_list);
    reserve_folder_list = restore_make_reserve_folder_list(backup);
    reserve_list = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    if (input_file) {
        char buf[MAX_MAILBOX_NAME + 2]; // \n\0
        size_t len;
        FILE *f;

        if (0 != strcmp(input_file, "-")) {
            f = fopen(input_file, "r");
            if (!f) {
                fprintf(stderr, "fopen %s: %s\n", input_file, strerror(errno));
                goto done;// FIXME shut_down?
            }
        }
        else {
            f = stdin;
        }

        while (fgets(buf, sizeof(buf), f)) {
            len = strlen(buf);

            if (len > 0 && buf[len - 1] == '\n')
                buf[--len] = '\0';

            if (len == 0 || buf[0] == '#')
                continue;

            r = restore_add_object(buf, &options, backup, mailbox_list,
                                   reserve_folder_list, reserve_list);

            // FIXME r
        }
        fclose(f);
    }
    else if (do_all_mailboxes) {
        struct backup_mailbox_list *all_mailboxes;
        struct backup_mailbox *mailbox;

        all_mailboxes = backup_get_mailboxes(backup, 0,
                                             BACKUP_MAILBOX_ALL_RECORDS);

        for (mailbox = all_mailboxes->head; mailbox; mailbox = mailbox->next) {
            restore_add_mailbox(mailbox, &options, mailbox_list,
                                reserve_folder_list, reserve_list);
        }

        backup_mailbox_list_empty(all_mailboxes);
        free(all_mailboxes);
    }
    else {
        int i;

        for (i = optind; i < argc; i++) {
            r = restore_add_object(argv[i], &options, backup, mailbox_list,
                                   reserve_folder_list, reserve_list);

            // FIXME r
        }
    }

    if (do_nothing) {
        if (options.verbose)
            fprintf(stderr, "do nothing (-n) specified, exiting now\n");
        goto done;
    }

    /* connect to destination */
    sync_cs.servername = servername;
    sync_cs.flags = options.verbose ? SYNC_FLAG_VERBOSE : 0;
    sync_connect(&sync_cs);

    if (!sync_cs.backend) {
        // FIXME
        r = -1;
        goto done;
    }

    /* do the restore */
    struct sync_reserve *reserve;
    for (reserve = reserve_list->head; reserve; reserve = reserve->next) {
        /* send APPLY RESERVE and parse missing lists */
        r = sync_reserve_partition(&sync_cs, reserve->part,
                                   reserve_folder_list,
                                   reserve->list);
        if (r) goto done;

        /* send APPLY MESSAGEs */
        r = backup_prepare_message_upload(backup,
                                          reserve->part,
                                          reserve->list,
                                          &sync_msgid_lookup,
                                          &upload);
        if (r) goto done;
        /* upload in small(ish) blocks to avoid timeouts */
        while (upload->head) {
            struct dlist *block = dlist_splice(upload, 1024);
            sync_send_apply(block, sync_cs.backend->out);
            r = sync_parse_response("MESSAGE", sync_cs.backend->in, NULL);
            dlist_unlink_files(block);
            dlist_free(&block);
            if (r) goto done;
        }
    }

    /* sync_prepare_dlists needs to upload messages per-mailbox, because
     * it needs the mailbox to find the filename for the message.  but
     * we have no such limitation, so we can upload messages while
     * looping over the reserve_list instead, above.
     *
     * alternatively, if we do it on a per-mailbox basis then we can limit
     * the hit on the staging directory to only a mailbox worth of messages
     * at a time.  but we don't have a logical grouping that would make
     * this coherent
     */

    /* send RESTORE MAILBOXes */
    struct backup_mailbox *mailbox;
    for (mailbox = mailbox_list->head; mailbox; mailbox = mailbox->next) {
        /* XXX filter the mailbox records based on reserve/missing/upload */

        /* XXX does this sensibly handle mailbox objs with empty values? */
        struct dlist *dl = backup_mailbox_to_dlist(mailbox);
        if (!dl) continue;

        if (local_only) {
            free(dl->name);
            dl->name = xstrdup("LOCAL_MAILBOX");
        }

        sync_send_restore(dl, sync_cs.backend->out);
        r = sync_parse_response("MAILBOX", sync_cs.backend->in, NULL);
        dlist_free(&dl);
        if (r) goto done;
    }

done:
    if (r)
        fprintf(stderr, "%s: %s\n", backup_name, error_message(r));

    /* release lock asap */
    if (backup)
        backup_close(&backup);

    if (upload) {
        dlist_unlink_files(upload);
        dlist_free(&upload);
    }

    if (mailbox_list) {
        backup_mailbox_list_empty(mailbox_list);
        free(mailbox_list);
    }

    if (reserve_folder_list)
        sync_folder_list_free(&reserve_folder_list);

    if (reserve_list)
        sync_reserve_list_free(&reserve_list);

    sync_disconnect(&sync_cs);
    free(sync_cs.backend);

    backup_cleanup_staging_path();
    cyrus_done();

    exit(r ? EX_TEMPFAIL : EX_OK);
}

static void my_mailbox_list_add(struct backup_mailbox_list *mailbox_list,
                                struct backup_mailbox *mailbox)
{
    struct backup_mailbox *tmp;

    for (tmp = mailbox_list->head; tmp; tmp = tmp->next) {
        if (0 == strcmp(tmp->mboxname, mailbox->mboxname)) break;
    }

    if (tmp) {
        /* mailbox already in our list -- append the records to it */
        if (mailbox->records && mailbox->records->count) {
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

        /* release the mailbox we were given, since we're not holding it */
        backup_mailbox_free(&mailbox);
    }
    else {
        /* not already in our list -- just add it */
        backup_mailbox_list_add(mailbox_list, mailbox);
    }
}

static struct sync_folder_list *restore_make_reserve_folder_list(
    struct backup *backup)
{
    struct sync_folder_list *folder_list = sync_folder_list_create();
    struct backup_mailbox_list *mailboxes = NULL;
    struct backup_mailbox *iter;

    mailboxes = backup_get_mailboxes(backup, 0, BACKUP_MAILBOX_NO_RECORDS);

    if (mailboxes) {
        for (iter = mailboxes->head; iter; iter = iter->next) {
            const struct synccrcs synccrcs = { 0, 0 };

            /* we only care about mboxname here */
            sync_folder_list_add(folder_list, NULL, iter->mboxname,
                                0, NULL, NULL, 0, 0, 0, 0, synccrcs,
                                0, 0, 0, 0, NULL, 0, 0, 0, 0);
        }

        backup_mailbox_list_empty(mailboxes);
        free(mailboxes);
    }

    return folder_list;
}

static void apply_mailbox_options(struct backup_mailbox *mailbox,
                                  const struct restore_options *options)
{
    if (options->override_mboxname) {
        if (options->verbose) {
            fprintf(stderr, "%s: overriding mboxname with %s\n",
                    mailbox->mboxname, options->override_mboxname);
        }
        if (mailbox->mboxname) free(mailbox->mboxname);
        mailbox->mboxname = xstrdup(options->override_mboxname);
    }

    if (options->override_partition) {
        if (options->verbose) {
            fprintf(stderr, "%s: overriding partition with %s (was %s)\n",
                    mailbox->mboxname, options->override_partition, mailbox->partition);
        }
        if (mailbox->partition) free(mailbox->partition);
        mailbox->partition = xstrdup(options->override_partition);
    }

    if (options->override_acl) {
        if (options->verbose) {
            fprintf(stderr, "%s: overriding acl with '%s' (was '%s')\n",
                    mailbox->mboxname, options->override_acl, mailbox->acl);
        }
        if (mailbox->acl) free(mailbox->acl);

        /* treat empty override string as no ACL, resulting in the mailbox
         * being restored with the default ACL for its owner. */
        if (*options->override_acl) {
            mailbox->acl = xstrdup(options->override_acl);
        }
        else {
            mailbox->acl = NULL;
        }
    }

    if (!options->keep_uidvalidity) {
        if (options->verbose) {
            fprintf(stderr, "%s: not trying to keep uidvalidity\n",
                    mailbox->mboxname);
        }
        if (mailbox->uniqueid) free(mailbox->uniqueid);
        mailbox->uniqueid = NULL;
        mailbox->highestmodseq = 0;
        mailbox->uidvalidity = 0;
    }
    else if (options->verbose) {
        fprintf(stderr, "%s: trying to keep uidvalidity(%u), "
                        "uniqueid(%s), highestmodseq(" MODSEQ_FMT ")\n",
                mailbox->mboxname,
                mailbox->uidvalidity,
                mailbox->uniqueid,
                mailbox->highestmodseq);
    }

    if (mailbox->mboxname && options->trim_deletedprefix) {
        mbname_t *mbname = mbname_from_intname(mailbox->mboxname);
        if (mbname_isdeleted(mbname)) {
            char *freeme = mailbox->mboxname;
            mbname_set_isdeleted(mbname, 0);
            mailbox->mboxname = xstrdup(mbname_intname(mbname));
            if (options->verbose) {
                fprintf(stderr, "%s: removing deletedprefix (was %s)\n",
                        mailbox->mboxname, freeme);
            }
            free(freeme);
        }
        mbname_free(&mbname);
    }

    if (options->expunged_mode != RESTORE_EXPUNGED_OKAY) {
        struct backup_mailbox_message *iter, *tmp, *next;

        next = mailbox->records->head;
        while ((iter = next)) {
            next = iter->next;
            tmp = NULL;

            switch (options->expunged_mode) {
            case RESTORE_EXPUNGED_EXCLUDE:
                if (iter->expunged) {
                    tmp = backup_mailbox_message_list_remove(mailbox->records, iter);

                    if (options->verbose) {
                        fprintf(stderr, "%s: excluding expunged message: %s\n",
                                mailbox->mboxname,
                                message_guid_encode(&iter->guid));
                    }
                }
                break;
            case RESTORE_EXPUNGED_ONLY:
                if (!iter->expunged) {
                    tmp = backup_mailbox_message_list_remove(mailbox->records, iter);

                    if (options->verbose) {
                        fprintf(stderr, "%s: excluding unexpunged message: %s\n",
                                mailbox->mboxname,
                                message_guid_encode(&iter->guid));
                    }
                }
                break;
            default:
                break;
            }

            if (tmp)
                backup_mailbox_message_free(&tmp);
        }
    }
}

static int restore_add_mailbox(const struct backup_mailbox *mailbox,
                               const struct restore_options *options,
                               struct backup_mailbox_list *mailbox_list,
                               struct sync_folder_list *reserve_folder_list,
                               struct sync_reserve_list *reserve_list)
{
    struct backup_mailbox *clone = backup_mailbox_clone(mailbox);

    apply_mailbox_options(clone, options);

    /* populate reserve list */
    if (clone->records) {
        struct sync_msgid_list *msgid_list = NULL;
        struct backup_mailbox_message *record = NULL;

        msgid_list = sync_reserve_partlist(reserve_list, clone->partition);
        for (record = clone->records->head; record; record = record->next) {
            sync_msgid_insert(msgid_list, &record->guid);
        }
    }

    /* add to folder list if not already-extant folder */
    if (options->override_mboxname) {
        const struct synccrcs synccrcs = {0, 0};
        sync_folder_list_add(reserve_folder_list, NULL, clone->mboxname,
                             0, NULL, NULL, 0, 0, 0, 0, synccrcs,
                             0, 0, 0, 0, NULL, 0, 0, 0, 0);
    }

    /* populate mailbox list */
    my_mailbox_list_add(mailbox_list, clone);

    return 0;
}

static int restore_add_message(const struct backup_message *message,
                               const struct backup_mailbox_list *message_mailboxes,
                               const struct restore_options *options,
                               struct backup_mailbox_list *mailbox_list,
                               struct sync_folder_list *reserve_folder_list,
                               struct sync_reserve_list *reserve_list)
{
    struct sync_msgid_list *msgid_list = NULL;

    if (options->override_mboxname) {
        /* create a mailbox... */
        struct backup_mailbox *mailbox = xzmalloc(sizeof *mailbox);
        apply_mailbox_options(mailbox, options);
        if (!mailbox->partition)
            mailbox->partition = xstrdup(message->partition);

        /* ... containing this message */
        struct backup_mailbox_message *mailbox_message =
            xzmalloc(sizeof *mailbox_message);

        mailbox_message->guid = *message->guid;
        mailbox_message->size = message->length;

        mailbox->records = xzmalloc(sizeof *mailbox->records);
        mailbox->records->head = mailbox->records->tail = mailbox_message;
        mailbox->records->count = 1;

        /* add to reserve list */
        msgid_list = sync_reserve_partlist(reserve_list, mailbox->partition);
        sync_msgid_insert(msgid_list, message->guid);

        /* add to reserve folder list */
        const struct synccrcs synccrcs = {0, 0};
        sync_folder_list_add(reserve_folder_list, NULL, mailbox->mboxname,
                             0, NULL, NULL, 0, 0, 0, 0, synccrcs,
                             0, 0, 0, 0, NULL, 0, 0, 0, 0);

        /* add to mailbox list */
        my_mailbox_list_add(mailbox_list, mailbox);
    }
    else if (message_mailboxes) {
        struct backup_mailbox *iter;

        for (iter = message_mailboxes->head; iter; iter = iter->next) {
            struct backup_mailbox *clone = backup_mailbox_clone(iter);
            apply_mailbox_options(clone, options);

            /* add to reserve list */
            msgid_list = sync_reserve_partlist(reserve_list, clone->partition);
            sync_msgid_insert(msgid_list, message->guid);

            /* add to mailbox list */
            my_mailbox_list_add(mailbox_list, clone);
        }
    }

    return 0;
}

struct submailbox_rock {
    const char *prefix;
    size_t prefix_len;
    const struct restore_options *options;
    struct backup_mailbox_list *mailbox_list;
    struct sync_folder_list *reserve_folder_list;
    struct sync_reserve_list *reserve_list;
};

static int submailbox_cb(const struct backup_mailbox *mailbox, void *rock)
{
    struct submailbox_rock *smbrock = (struct submailbox_rock *) rock;

    if (0 == strncmp(smbrock->prefix, mailbox->mboxname, smbrock->prefix_len)) {
        return restore_add_mailbox(mailbox,
                                   smbrock->options,
                                   smbrock->mailbox_list,
                                   smbrock->reserve_folder_list,
                                   smbrock->reserve_list);
    }

    return 0;
}

static int restore_add_object(const char *object_name,
                              const struct restore_options *options,
                              struct backup *backup,
                              struct backup_mailbox_list *mailbox_list,
                              struct sync_folder_list *reserve_folder_list,
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
        mailbox = backup_get_mailbox_by_uniqueid(backup, object_name,
                                                 BACKUP_MAILBOX_ALL_RECORDS);
    }
    else if (len == 36 && strspn(object_name, "-" HEX_DIGITS) == len) {
        /* looks like a libuuid uniqueid */
        mailbox = backup_get_mailbox_by_uniqueid(backup, object_name,
                                                 BACKUP_MAILBOX_ALL_RECORDS);
    }
    else if (message_guid_decode(&tmp_guid, object_name)) {
        /* looks like it's a message guid */
        message = backup_get_message(backup, &tmp_guid);
    }
    else if (strchr(object_name, '.')) {
        /* has a dot, might be an mboxname */
        mbname_t *mbname = mbname_from_extname(object_name,
                                               &restore_namespace, NULL);
        mailbox = backup_get_mailbox_by_name(backup, mbname,
                                             BACKUP_MAILBOX_ALL_RECORDS);
        mbname_free(&mbname);
    }
    else {
        /* not sure what it is, guess mboxname? */
        mbname_t *mbname = mbname_from_extname(object_name,
                                               &restore_namespace, NULL);
        mailbox = backup_get_mailbox_by_name(backup, mbname,
                                             BACKUP_MAILBOX_ALL_RECORDS);
        mbname_free(&mbname);
    }

    /* add it to the restore lists */
    if (mailbox) {
        r = restore_add_mailbox(mailbox, options, mailbox_list,
                                reserve_folder_list, reserve_list);

        if (!r && options->do_submailboxes) {
            char prefix[MAX_MAILBOX_NAME + 1];
            int len;

            len = snprintf(prefix, sizeof(prefix), "%s.", mailbox->mboxname);

            /* can only be submailboxes if parent's name is short enough... */
            if (len < MAX_MAILBOX_NAME) {
                struct submailbox_rock rock = {
                    prefix,
                    strlen(prefix),
                    options,
                    mailbox_list,
                    reserve_folder_list,
                    reserve_list,
                };

                r = backup_mailbox_foreach(backup, 0,
                                           BACKUP_MAILBOX_ALL_RECORDS,
                                           submailbox_cb, &rock);
            }
        }

        backup_mailbox_free(&mailbox);
    }
    else if (message) {
        struct backup_mailbox_list *mailboxes = NULL;

        if (!options->override_mboxname)
            mailboxes = backup_get_mailboxes_by_message(backup, message,
                                                        BACKUP_MAILBOX_MATCH_RECORDS);
        r = restore_add_message(message, mailboxes, options, mailbox_list,
                                reserve_folder_list, reserve_list);

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
