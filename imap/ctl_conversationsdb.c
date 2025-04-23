/*
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <sys/stat.h>

/* cyrus includes */
#include "assert.h"
#include "bsearch.h"
#include "global.h"
#include "index.h"
#include "conversations.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "util.h"
#include "xmalloc.h"
#include "xunlink.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

enum { UNKNOWN, DUMP, UNDUMP, ZERO, BUILD, RECALC, AUDIT, CHECKFOLDERS, ZEROMODSEQ, UPGRADE };

static int verbose = 0;

static int mode = UNKNOWN;
static const char *audit_temp_directory;

static int recalc_silent = 1;
static hashu64_table *zerocids = NULL;

static int do_dump(const char *fname, const char *userid)
{
    struct conversations_state *state = NULL;
    struct stat sb;
    int r;

    /* What we really want here is read-only database access without
     * the create-if-nonexistent semantics.  However, the cyrusdb
     * interface makes it difficult to do that properly.  In the
     * meantime, we can just check if the file exists here. */
    r = stat(fname, &sb);
    if (r < 0) {
        perror(fname);
        return -1;
    }

    r = conversations_open_path(fname, userid, 0/*shared*/, &state);
    if (r) {
        fprintf(stderr, "Failed to open conversations database %s: %s\n",
                fname, error_message(r));
        return -1;
    }

    conversations_dump(state, stdout);

    conversations_commit(&state);
    return 0;
}

static int do_undump(const char *fname, const char *userid)
{
    struct conversations_state *state;
    int r;

    r = conversations_open_path(fname, userid, 0/*shared*/, &state);
    if (r) {
        fprintf(stderr, "Failed to open conversations database %s: %s\n",
                fname, error_message(r));
        return -1;
    }

    r = conversations_truncate(state);
    if (r) {
        fprintf(stderr, "Failed to truncate conversations database %s: %s\n",
                fname, error_message(r));
        goto out;
    }

    r = conversations_undump(state, stdin);
    if (r) {
        fprintf(stderr, "Failed to undump to conversations database %s: %s\n",
                fname, error_message(r));
        goto out;
    }

    r = conversations_commit(&state);
    if (r)
        fprintf(stderr, "Failed to commit conversations database %s: %s\n",
                fname, error_message(r));

out:
    conversations_abort(&state);
    return r;
}

static int zero_cid_cb(const mbentry_t *mbentry,
                       void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) {
        fprintf(stderr, "Failed to open mailbox %s, skipping\n", mbentry->name);
        return 0;
    }

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* already zero, fine */
        if (record->cid == NULLCONVERSATION)
            continue;

        /* if we're only doing some cids, check if this is one */
        if (zerocids && !hashu64_lookup(record->cid, zerocids))
            continue;

        struct index_record oldrecord = *record;
        oldrecord.cid = NULLCONVERSATION;
        oldrecord.basecid = NULLCONVERSATION;
        oldrecord.internal_flags &= ~FLAG_INTERNAL_SPLITCONVERSATION;
        r = mailbox_rewrite_index_record(mailbox, &oldrecord);
        if (r) break;
    }

    mailbox_iter_done(&iter);
    mailbox_close(&mailbox);
    return r;
}

static int delannot_cb(const char *mboxname,
                       uint32_t uid __attribute__((unused)),
                       const char *entry,
                       const char *userid,
                       const struct buf *value,
                       const struct annotate_metadata *mdata __attribute__((unused)),
                       void *rock)
{
    if (zerocids) {
        conversation_id_t keycid = NULLCONVERSATION;
        conversation_id_t valuecid = NULLCONVERSATION;

        parsehex(entry + strlen(IMAP_ANNOT_NS) + 7, NULL, 16, &keycid);
        parsehex(value->s, NULL, 16, &valuecid);

        // if neither are being zeroed, leave them
        if (!hashu64_lookup(keycid, zerocids) && !hashu64_lookup(valuecid, zerocids))
            return 0;
    }
    return annotatemore_write(mboxname, entry, userid, (const struct buf *)rock);
}


static int do_zero(const char *userid)
{
    struct conversations_state *state = NULL;
    int r;

    r = conversations_open_user(userid, 0/*shared*/, &state);
    if (r) return r;

    r = mboxlist_usermboxtree(userid, NULL, zero_cid_cb, NULL, 0);
    if (r) goto done;

    // remove all "newcid" mappings, since we've zeroed all the basecids already
    struct buf zerobuf = BUF_INITIALIZER;
    r = annotatemore_findall_mboxname(state->annotmboxname, /*uid*/0, IMAP_ANNOT_NS "newcid/%",
                                      /*modseq*/0, &delannot_cb, &zerobuf, /*flags*/0);
    if (r) goto done;

done:
    conversations_commit(&state);
    return r;
}

static int zero_modseq_cb(const mbentry_t *mbentry,
                          void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) {
        fprintf(stderr, "Failed to open mailbox %s, skipping\n", mbentry->name);
        return 0;
    }

    mailbox_modseq_dirty(mailbox);
    // update the header values
    mailbox->i.createdmodseq = 1;
    mailbox->i.highestmodseq = 1;
    mailbox->i.deletedmodseq = 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);

        if (record->modseq > 1) {
            struct index_record oldrecord = *record;
            oldrecord.modseq = 1;
            oldrecord.silentupdate = 1; // avoid bumping the highestmodseq!
            r = mailbox_rewrite_index_record(mailbox, &oldrecord);
            if (r) break;
        }
    }

    mailbox_iter_done(&iter);
    mailbox_close(&mailbox);

    if (r) return r;

    if (mbentry->createdmodseq > 1 || mbentry->foldermodseq > 1) {
        mbentry_t *copy = mboxlist_entry_copy(mbentry);
        copy->createdmodseq = 1;
        copy->foldermodseq = 1;
        r = mboxlist_update_full(copy, /*localonly*/1, /*silent*/1);
        mboxlist_entry_free(&copy);
    }

    return r;
}

static int do_zeromodseq(const char *userid)
{
    imaply_strict = 0;
    struct conversations_state *state = NULL;
    struct quota q;
    struct txn *txn = NULL;

    int r = conversations_open_user(userid, 0/*shared*/, &state);
    if (r) return r;

    r = mboxlist_usermboxtree(userid, NULL, zero_modseq_cb, NULL, 0);
    if (r) goto done;

    r = conversations_zero_modseq(state);
    if (r) goto done;

    char *inboxname = mboxname_user_mbox(userid, NULL);
    quota_init(&q, inboxname);
    r = quota_read(&q, &txn, 1);
    if (!r) {
        q.modseq = 1;
        r = quota_write(&q, /*silent*/1, &txn);
    }
    quota_free(&q);
    if (!r) {
        quota_commit(&txn);

        mboxname_zero_counters(inboxname);
    }
    free(inboxname);

  done:
    conversations_commit(&state);
    return r;
}


static int build_cid_cb(const mbentry_t *mbentry,
                        void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r = 0;
    int count = 1;
    struct conversations_state *cstate = conversations_get_mbox(mbentry->name);

    if (!cstate) return IMAP_CONVERSATIONS_NOT_OPEN;

    while (!r && count) {
        r = mailbox_open_iwl(mbentry->name, &mailbox);
        if (r) {
            fprintf(stderr, "Failed to open mailbox %s, skipping\n", mbentry->name);
            return 0;
        }

        count = 0;

        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            /* already assigned, fine */
            if (record->cid != NULLCONVERSATION)
                continue;

            struct index_record oldrecord = *record;
            r = mailbox_cacherecord(mailbox, &oldrecord);
            if (r) goto done;

            oldrecord.ignorelimits = 1;

            r = message_update_conversations(cstate, mailbox, &oldrecord, NULL);
            if (r) goto done;

            r = mailbox_rewrite_index_record(mailbox, &oldrecord);
            if (r) goto done;

            count++;
            /* batch so we don't lock for ages */
            if (count > 8192) break;
        }

        mailbox_iter_done(&iter);

    done:
        mailbox_close(&mailbox);
    }

    return r;
}

static int do_build(const char *userid)
{
    struct conversations_state *state = NULL;
    int r;

    r = conversations_open_user(userid, 0/*shared*/, &state);
    if (r) return r;

    r = mboxlist_usermboxtree(userid, NULL, build_cid_cb, NULL, 0);

    conversations_commit(&state);
    return r;
}

static int recalc_counts_cb(const mbentry_t *mbentry,
                            void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) return r;

    if (verbose)
        printf("%s\n", mbentry->name);

    r = mailbox_add_conversations(mailbox, recalc_silent);

    mailbox_close(&mailbox);
    return r;
}

static int audit_counts_cb(const mbentry_t *mbentry,
                           void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_irl(mbentry->name, &mailbox);
    if (r) return r;

    if (verbose)
        printf("%s\n", mbentry->name);

    r = mailbox_add_conversations(mailbox, /*silent*/1);

    mailbox_close(&mailbox);
    return r;
}

static int do_recalc(const char *userid, int force)
{
    struct conversations_state *state = NULL;

    int r = conversations_open_user(userid, 0/*shared*/, &state);
    if (r) return r;

    if (!force && state->version == CONVERSATIONS_VERSION) {
        if (verbose)
            printf("%s already version %d, skipping\n", userid, state->version);
        conversations_commit(&state);
        return 0;
    }

    // wipe if it's currently folders_byname, will recreate with byid
    int wipe = state->folders_byname;

    r = conversations_zero_counts(state, wipe);
    if (r) goto err;

    r = mboxlist_usermboxtree(userid, NULL, recalc_counts_cb, NULL, 0);
    if (r) goto err;

    r = conversations_cleanup_zero(state);
    if (r) goto err;

    conversations_commit(&state);
    return 0;

err:
    conversations_abort(&state);
    return r;
}

struct cursor
{
    struct db *db;
    struct txn **txnp;
    struct buf buf;
    const char *key; size_t keylen;
    const char *data; size_t datalen;
    int err;
};

static void cursor_init(struct cursor *c,
                        struct db *db, struct txn **txnp)
{
    memset(c, 0, sizeof(*c));
    c->db = db;
    c->txnp = txnp;
}

static void cursor_fini(struct cursor *c)
{
    buf_free(&c->buf);
}

static int cursor_next(struct cursor *c)
{
    if (!c->err) {
        c->err = cyrusdb_fetchnext(c->db,
                                   c->key, c->keylen,
                                   &c->key, &c->keylen,
                                   &c->data, &c->datalen,
                                   c->txnp);
    }
    if (!c->err) {
        // copy the key so it's safe for fetchnext even if the file is changed
        buf_setmap(&c->buf, c->key, c->keylen);
        c->key = c->buf.s;
    }
    return c->err;
}

static int blob_compare(const char *a, size_t alen,
                        const char *b, size_t blen)
{
    int d = memcmp(a, b, MIN(alen, blen));
    if (!d)
        d = alen - blen;
    return d;
}

static int next_diffable_record(struct cursor *c)
{
    for (;;)
    {
        int r = cursor_next(c);
        if (r) return r;

        /* skip < records, they won't be in the
         * temp database and we don't care so much */
        if (c->key[0] == '<')
            continue;

        /* Subject, not re-calculated */
        if (c->key[0] == 'S')
            continue;

        return 0;
    }
}

static void printer(const char *type, struct cursor *c)
{
    if (!verbose) return;
    static struct buf keybuf = BUF_INITIALIZER;
    static struct buf databuf = BUF_INITIALIZER;
    buf_reset(&keybuf);
    buf_reset(&databuf);
    size_t i;
    for (i = 0; i < c->keylen; i++) {
        if (c->key[i] > 31 && c->data[i] < 127)
            buf_putc(&keybuf, c->key[i]);
        else
            buf_printf(&keybuf, "<%d>", (int)c->key[i]);
    }
    for (i = 0; i < c->datalen; i++) {
        if (c->data[i] > 31 && c->data[i] < 127)
            buf_putc(&databuf, c->data[i]);
        else
            buf_printf(&databuf, "<%d>", (int)c->data[i]);
    }
    printf("%s: \"%s\" data \"%s\"\n", type, buf_cstring(&keybuf), buf_cstring(&databuf));
}

static unsigned int diff_records(struct conversations_state *a,
                                 struct conversations_state *b)
{
    unsigned int ndiffs = 0;
    int ra, rb;
    struct cursor ca, cb;
    int keydelta;
    int delta;

    cursor_init(&ca, a->db, &a->txn);
    ra = cursor_next(&ca);

    cursor_init(&cb, b->db, &b->txn);
    rb = cursor_next(&cb);

    while (!ra || !rb) {
        keydelta = blob_compare(ca.key, ca.keylen, cb.key, cb.keylen);
        if (rb || keydelta < 0) {
            if (ra) break;
            ndiffs++;
            printer("REALONLY", &ca);
            ra = next_diffable_record(&ca);
            continue;
        }
        if (ra || keydelta > 0) {
            if (rb) break;
            ndiffs++;
            printer("TEMPONLY", &cb);
            rb = next_diffable_record(&cb);
            continue;
        }

        /* both exist and are the same key */
        delta = blob_compare(ca.data, ca.datalen, cb.data, cb.datalen);
        if (delta) {
            ndiffs++;
            printer("REAL", &ca);
            printer("TEMP", &cb);
        }

        ra = next_diffable_record(&ca);
        rb = next_diffable_record(&cb);
    }

    cursor_fini(&ca);
    cursor_fini(&cb);

    return ndiffs;
}

static int fix_modseqs(struct conversations_state *a,
                       struct conversations_state *b)
{
    int ra, rb;
    struct cursor ca, cb;
    char buf[80];
    int keydelta;
    int r = 0;

    cursor_init(&ca, a->db, &a->txn);
    ra = cursor_next(&ca);

    cursor_init(&cb, b->db, &b->txn);
    rb = cursor_next(&cb);

    while (!ra || !rb) {
        keydelta = blob_compare(ca.key, ca.keylen, cb.key, cb.keylen);
        if (rb || keydelta < 0) {
            if (ra) break;
            if (ca.key[0] == 'F') {
                conv_status_t status = CONV_STATUS_INIT;
                /* need to add record if it's zero */
                r = conversation_parsestatus(ca.data, ca.datalen, &status);
                if (r) goto done;
                if (status.threadexists == 0) {
                    r = conversation_storestatus(b, ca.key, ca.keylen, &status);
                    if (r) {
                        fprintf(stderr, "Failed to store conversations "
                                        "record \"%.*s\" to %s: %s, giving up\n",
                                        (int)ca.keylen, ca.key,
                                        b->path, error_message(r));
                        goto done;
                    }
                }
                /* otherwise it's a bug, so leave it in for reporting */
            }
            ra = cursor_next(&ca);
            continue;
        }
        if (ra || keydelta > 0) {
            if (rb) break;
            rb = cursor_next(&cb);
            continue;
        }

        /* folders?  Just modseq check */
        if (ca.key[0] == 'F') {
            /* check if modseq is higher for real */
            conv_status_t statusa = CONV_STATUS_INIT;
            conv_status_t statusb = CONV_STATUS_INIT;
            /* need to add record if it's zero */
            r = conversation_parsestatus(ca.data, ca.datalen, &statusa);
            if (r) {
                fprintf(stderr, "Failed to parse conversations "
                                "record \"%.*s\" in %s: %s\n",
                                (int)ca.keylen, ca.key,
                                a->path, error_message(r));
                /* There's no need to report failure to the caller - the
                 * record diffing passing that occurs after this will
                 * also pick up the same problem */
                goto next;
            }
            r = conversation_parsestatus(cb.data, cb.datalen, &statusb);
            if (r) {
                fprintf(stderr, "Failed to parse conversations "
                                "record \"%.*s\" in %s: %s\n",
                                (int)cb.keylen, cb.key,
                                b->path, error_message(r));
                goto next;
            }
            if (statusa.threadmodseq > statusb.threadmodseq) {
                statusb.threadmodseq = statusa.threadmodseq;
                r = conversation_storestatus(b, cb.key, cb.keylen, &statusb);
                if (r) {
                    fprintf(stderr, "Failed to store conversations "
                                    "record \"%.*s\" to %s: %s, giving up\n",
                                    (int)cb.keylen, cb.key,
                                    b->path, error_message(r));
                    /* If we cannot write to the temp DB, something is
                     * drastically wrong and we need to report a failure */
                    goto done;
                }
            }
        }
        if (ca.key[0] == 'B') {
            /* B keys - check all the modseqs, both top level and per folder */
            conversation_t conva = CONVERSATION_INIT;
            conversation_t convb = CONVERSATION_INIT;
            conv_folder_t *foldera;
            conv_folder_t *folderb;
            conv_sender_t *sendera;
            conv_thread_t *threada;

            r = conversation_parse(ca.data, ca.datalen, &conva, CONV_WITHALL);
            if (r) {
                fprintf(stderr, "Failed to parse conversations "
                                "record \"%.*s\" in %s: %s\n",
                                (int)ca.keylen, ca.key,
                                a->path, error_message(r));
                goto next;
            }
            r = conversation_parse(cb.data, cb.datalen, &convb, CONV_WITHALL);
            if (r) {
                fprintf(stderr, "Failed to parse conversations "
                                "record \"%.*s\" in %s: %s\n",
                                (int)cb.keylen, cb.key,
                                b->path, error_message(r));
                conversation_fini(&conva);
                goto next;
            }

            /* because expunged messages could have had higher modseqs,
             * we need to re-copy any higher modseqs in */
            if (conva.modseq > convb.modseq)
                convb.modseq = conva.modseq;

            for (foldera = conva.folders; foldera; foldera = foldera->next) {
                folderb = conversation_get_folder(&convb, foldera->number, 1);
                if (folderb->modseq < foldera->modseq)
                    folderb->modseq = foldera->modseq;
            }

            /* senders are timestamped, and the timestamp might be for a
             * deleted message! */
            for (sendera = conva.senders; sendera; sendera = sendera->next) {
                /* always update!  The delta logic will ensure we don't add
                 * the record if it's not already at least present in the
                 * other conversation */
                conversation_update_sender(&convb, sendera->name, sendera->route,
                                           sendera->mailbox, sendera->domain,
                                           sendera->lastseen, /*delta_count*/0);
            }

            /* emails have modseqs, and the modseq might be for a deleted message */
            for (threada = conva.thread; threada; threada = threada->next) {
                /* always update!  The delta logic will ensure we don't add
                 * the record if it's not already at least present in the
                 * other conversation */
                conversation_update_thread(&convb, &threada->guid,
                                           threada->nano_internaldate,
                                           threada->createdmodseq, /*delta_exists*/0);
            }

            /* be nice to know if this is needed, but at least twoskip
             * will dedup for us */
            r = conversation_store(b, cb.key, cb.keylen, &convb);

            /* free first before checking for errors */
            conversation_fini(&conva);
            conversation_fini(&convb);

            if (r) {
                fprintf(stderr, "Failed to store conversations "
                                "record \"%.*s\" to %s: %s, giving up\n",
                                (int)cb.keylen, cb.key,
                                b->path, error_message(r));
                goto done;
            }
        }
        if (ca.key[0] == 'G') {
            // basecid might be different on the old record, so if they're both v3, then copy the data over
            if (ca.datalen >= 33 && cb.datalen >= 33 && ca.data[0] == (char)0x83 && cb.data[0] == (char)0x83) {
                if (memcmp(ca.data+25, cb.data+25, 8) && cb.datalen < 80) {
                    memcpy(buf, cb.data, cb.datalen);
                    memcpy(buf+25, ca.data+25, 8);
                    r = cyrusdb_store(b->db, cb.key, cb.keylen, buf, cb.datalen, &b->txn);
                    if (r) {
                         fprintf(stderr, "Failed to store conversations "
                                         "record \"%.*s\" to %s: %s, giving up\n",
                                         (int)cb.keylen, cb.key,
                                         b->path, error_message(r));
                        goto done;
                    }
                }
            }
        }

next:
        ra = cursor_next(&ca);
        rb = cursor_next(&cb);
    }

done:
    cursor_fini(&ca);
    cursor_fini(&cb);

    return r;
}

int do_checkfolders(const char *userid)
{
    int r;
    struct conversations_state *state = NULL;
    strarray_t *copy1, *copy2;

    /* open the DB */
    r = conversations_open_user(userid, 0/*shared*/, &state);
    if (r) {
        fprintf(stderr, "Cannot open conversations db %s: %s\n",
                userid, error_message(r));
        goto out;
    }

    /* don't mess with the original */
    copy1 = strarray_dup(state->folders);
    /* remove empty folders first, they will duplicate for sure */
    strarray_remove_all(copy1, "-");
    copy2 = strarray_dup(copy1);
    strarray_sort(copy2, cmpstringp_raw);
    strarray_uniq(copy2);
    if (copy1->count != copy2->count) {
        printf("DUPLICATE %s\n", userid);
    }
    else {
        printf("OK %s\n", userid);
    }
    strarray_free(copy1);
    strarray_free(copy2);

out:
    conversations_abort(&state);
    return r;
}

static int do_audit(const char *userid)
{
    int r;
    char temp_suffix[64];
    char *filename_temp = NULL;
    char *filename_real = NULL;
    struct conversations_state *state_temp = NULL;
    struct conversations_state *state_real = NULL;
    unsigned int ndiffs = 0;

    if (verbose)
        printf("User %s\n", userid);

    if (verbose)
        printf("Pass 1: recalculate counts into temporary db\n");

    /* Generate a unique suffix for the temp db */
    snprintf(temp_suffix, sizeof(temp_suffix),
             "conversations.audit.%d", (int)getpid());

    /* Get the filenames */
    filename_real = conversations_getuserpath(userid);
    conversations_set_suffix(temp_suffix);
    conversations_set_directory(audit_temp_directory);
    filename_temp = conversations_getuserpath(userid);
    conversations_set_suffix(NULL);
    conversations_set_directory(NULL);
    assert(strcmp(filename_temp, filename_real));

    /* Initialise the temp copy of the database */
    xunlink(filename_temp);
    r = cyrusdb_copyfile(filename_real, filename_temp);
    if (r) {
        fprintf(stderr, "Cannot make temp copy of conversations db %s: %s\n",
                filename_real, error_message(r));
        goto out;
    }

    /* Begin recalculating in the temp db */
    r = conversations_open_path(filename_temp, userid, 0/*shared*/, &state_temp);
    if (r) {
        fprintf(stderr, "Cannot open conversations db %s: %s\n",
                filename_temp, error_message(r));
        goto out;
    }

    r = conversations_zero_counts(state_temp, /*wipe*/0);
    if (r) {
        fprintf(stderr, "Failed to zero counts in %s: %s\n",
                filename_temp, error_message(r));
        goto out;
    }

    /*
     * Set the conversations db suffix during the recalc pass, so that
     * calls to conversations_open_mbox() from the mailbox code get
     * redirected to the temporary db.
     */
    conversations_set_suffix(temp_suffix);
    conversations_set_directory(audit_temp_directory);

    r = mboxlist_usermboxtree(userid, NULL, audit_counts_cb, NULL, 0);
    if (r) {
        fprintf(stderr, "Failed to recalculate counts in %s: %s\n",
                filename_temp, error_message(r));
        goto out;
    }

    r = conversations_cleanup_zero(state_temp);
    if (r) {
        fprintf(stderr, "Failed to cleanup zero counts in %s: %s\n",
                filename_temp, error_message(r));
        goto out;
    }

    conversations_set_suffix(NULL);
    conversations_set_directory(NULL);

    r = conversations_commit(&state_temp);
    if (r) {
        fprintf(stderr, "Cannot commit conversations db %s: %s\n",
                filename_temp, error_message(r));
        goto out;
    }

    if (verbose)
        printf("Pass 2: find differences from recalculated to live dbs\n");

    r = conversations_open_path(filename_temp, userid, 0/*shared*/, &state_temp);
    if (r) {
        fprintf(stderr, "Cannot open conversations db %s: %s\n",
                filename_temp, error_message(r));
        goto out;
    }

    r = conversations_open_path(filename_real, userid, 0/*shared*/, &state_real);
    if (r) {
        fprintf(stderr, "Cannot open conversations db %s: %s\n",
                filename_real, error_message(r));
        goto out;
    }

    r = fix_modseqs(state_real, state_temp);
    if (r) {
        /* Error reported in fix_modseqs() */
        goto out;
    }

    ndiffs += diff_records(state_real, state_temp);
    if (ndiffs)
        printf("%s is BROKEN (%u differences)\n", userid, ndiffs);
    else if (verbose)
        printf("%s is OK\n", userid);

out:
    if (state_temp)
        conversations_abort(&state_temp);
    if (state_real)
        conversations_abort(&state_real);
    conversations_set_suffix(NULL);
    conversations_set_directory(NULL);
    cyrusdb_unlink(config_conversations_db, filename_temp, 0);
    free(filename_temp);
    free(filename_real);
    return r;
}

static int usage(const char *name)
    __attribute__((noreturn));

static int do_user(const char *userid, void *rock __attribute__((unused)))
{
    char *fname;
    int r = 0;

    signals_poll();

    fname = conversations_getuserpath(userid);
    if (fname == NULL) {
        fprintf(stderr, "Unable to get conversations database "
                        "filename for userid \"%s\"\n",
                        userid);
        return EX_USAGE;
    }

    switch (mode)
    {
    case DUMP:
        if (do_dump(fname, userid))
            r = EX_NOINPUT;
        break;

    case UNDUMP:
        if (do_undump(fname, userid))
            r = EX_NOINPUT;
        break;

    case ZERO:
        if (do_zero(userid))
            r = EX_NOINPUT;
        break;

    case ZEROMODSEQ:
        if (do_zeromodseq(userid))
            r = EX_NOINPUT;
        break;

    case BUILD:
        if (do_build(userid))
            r = EX_NOINPUT;
        break;

    case RECALC:
        if (do_recalc(userid, /*force*/1))
            r = EX_NOINPUT;
        break;

    case AUDIT:
        if (do_audit(userid))
            r = EX_NOINPUT;
        break;

    case CHECKFOLDERS:
        if (do_checkfolders(userid))
            r = EX_NOINPUT;
        break;

    case UPGRADE:
        if (do_recalc(userid, /*force*/0))
            r = EX_NOINPUT;
        break;

    case UNKNOWN:
        fatal("UNKNOWN MODE", EX_SOFTWARE);
    }

    free(fname);

    return r;
}

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    libcyrus_run_delayed();

    cyrus_done();

    exit(code);
}

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    const char *userid = NULL;
    int recursive = 0;

    /* keep in alphabetical order */
    static const char short_options[] = "AC:FMRST:bdruUvzZ:";

    static const struct option long_options[] = {
        { "audit", no_argument, NULL, 'A' },
        /* n.b. no long option for -C */
        { "check-folders", no_argument, NULL, 'F' },
        { "clearmodseq", no_argument, NULL, 'M' },
        { "update-counts", no_argument, NULL, 'R' },
        { "split", no_argument, NULL, 'S' },
        { "audit-temp-directory", required_argument, NULL, 'T' },
        { "rebuild", no_argument, NULL, 'b' },
        { "dump", no_argument, NULL, 'd' },
        { "recursive", no_argument, NULL, 'r' },
        { "undump", no_argument, NULL, 'u' },
        { "upgrade", no_argument, NULL, 'U' },
        { "verbose", no_argument, NULL, 'v' },
        { "clear", no_argument, NULL, 'z' },
        { "clearcid", required_argument, NULL, 'Z' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (c = getopt_long(argc, argv,
                                  short_options, long_options, NULL)))
    {
        switch (c) {
        case 'd':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = DUMP;
            break;

        case 'r':
            recursive = 1;
            break;

        case 'u':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = UNDUMP;
            break;

        case 'z':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = ZERO;
            break;

        case 'Z':
            if (mode != UNKNOWN && mode != ZERO)
                usage(argv[0]);
            mode = ZERO;
            if (!zerocids) {
                zerocids = xzmalloc(sizeof(hashu64_table));
                construct_hashu64_table(zerocids, 256, 0);
            }
            strarray_t *ids = strarray_split(optarg, ",", 0);
            int i;
            for (i = 0; i < strarray_size(ids); i++) {
                conversation_id_t cid = NULLCONVERSATION;
                if (!conversation_id_decode(&cid, strarray_nth(ids, i)))
                    usage(argv[0]);
                if (cid)
                    hashu64_insert(cid, (void*)1, zerocids);
            }
            strarray_free(ids);
            break;

        case 'M':
            if (mode != UNKNOWN && mode != ZEROMODSEQ)
                usage(argv[0]);
            mode = ZEROMODSEQ;
            break;

        case 'b':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = BUILD;
            break;

        case 'R':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = RECALC;
            break;

        case 'A':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = AUDIT;
            break;

        case 'F':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = CHECKFOLDERS;
            break;

        case 'U':
            if (mode != UNKNOWN)
                usage(argv[0]);
            mode = UPGRADE;
            break;

        case 'v':
            verbose++;
            break;

        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'T': /* tmpfs directory for audit */
            audit_temp_directory = optarg;
            break;

        case 'S':
            recalc_silent = 0;
            break;

        default:
            usage(argv[0]);
            break;
        }
    }

    if (mode == UNKNOWN)
        usage(argv[0]);

    if (optind == argc-1)
        userid = argv[optind];
    else if (recursive)
        userid = "";
    else
        usage(argv[0]);

    cyrus_init(alt_config, "ctl_conversationsdb", 0, 0);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (recursive) {
        mboxlist_alluser(do_user, NULL);
    }
    else {
        do_user(userid, NULL);
    }

    if (zerocids) {
        free_hashu64_table(zerocids, NULL);
        free(zerocids);
    }

    shut_down(0);
}

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [options] [-u|-d|-z|-f] [-r] username\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "options are:\n");
    fprintf(stderr, "    -v             be more verbose\n");
    fprintf(stderr, "    -C altconfig   use altconfig instead of imapd.conf\n");
    fprintf(stderr, "    -u             undump the conversations database from stdin\n");
    fprintf(stderr, "    -d             dump the conversations database to stdout\n");
    fprintf(stderr, "    -z             zero the conversations DB (make all NULLs)\n");
    fprintf(stderr, "    -b             build conversations entries for any NULL records\n");
    fprintf(stderr, "    -R             recalculate all counts\n");
    fprintf(stderr, "    -A             audit conversations DB counts\n");
    fprintf(stderr, "    -F             check folder names\n");
    fprintf(stderr, "    -T dir         store temporary data for audit in dir\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -r             recursive mode: username is a prefix\n");

    exit(EX_USAGE);
}

EXPORTED void fatal(const char* s, int code)
{
    fprintf(stderr, "ctl_conversationsdb: %s\n", s);
    cyrus_done();

    if (code != EX_PROTOCOL && config_fatals_abort) abort();

    exit(code);
}
