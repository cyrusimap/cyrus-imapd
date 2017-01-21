/* conversations.c -- Routines for dealing with the conversation database
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "bsearch.h"
#include "charset.h"
#include "crc32.h"
#include "dlist.h"
#include "exitcodes.h"
#include "hash.h"
#include "global.h"
#include "imapd.h"
#include "lsort.h"
#include "mailbox.h"
#include "map.h"
#include "mboxname.h"
#include "message.h"
#include "parseaddr.h"
#include "search_engines.h"
#include "seen.h"
#include "strhash.h"
#include "stristr.h"
#include "sync_log.h"
#include "syslog.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "xstats.h"
#include "times.h"

#include "conversations.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define CONVERSATION_ID_STRMAX      (1+sizeof(conversation_id_t)*2)

/* per user conversations db extension */
#define FNAME_CONVERSATIONS_SUFFIX "conversations"
#define FNKEY "$FOLDER_NAMES"
#define CFKEY "$COUNTED_FLAGS"

#define DB config_conversations_db

#define CONVERSATIONS_VERSION 0

static conv_status_t NULLSTATUS = { 0, 0, 0};

static char *convdir = NULL;
static char *suffix = NULL;

static int check_msgid(const char *msgid, size_t len, size_t *lenp);
static int _conversations_parse(const char *data, size_t datalen,
                                arrayu64_t *cids, time_t *stampp);
static int _conversations_set_key(struct conversations_state *state,
                                  const char *key, size_t keylen,
                                  const arrayu64_t *cids, time_t stamp);

EXPORTED void conversations_set_directory(const char *dir)
{
    free(convdir);
    convdir = xstrdupnull(dir);
}

EXPORTED void conversations_set_suffix(const char *suff)
{
    free(suffix);
    suffix = xstrdupnull(suff);
}

static char *conversations_path(mbname_t *mbname)
{
    const char *suff = (suffix ? suffix : FNAME_CONVERSATIONS_SUFFIX);
    /* only users have conversations.  Later we may introduce the idea of
     * "conversationroot" in the same way we have quotaroot, but for now
     * it's hard-coded as the user */
    if (!mbname_userid(mbname))
        return NULL;
    if (convdir)
        return strconcat(convdir, "/", mbname_userid(mbname), ".", suff, (char *)NULL);
    return mboxname_conf_getpath(mbname, suff);
}

EXPORTED char *conversations_getuserpath(const char *username)
{
    mbname_t *mbname = mbname_from_userid(username);
    char *fname = conversations_path(mbname);

    mbname_free(&mbname);

    return fname;
}

EXPORTED char *conversations_getmboxpath(const char *mboxname)
{
    mbname_t *mbname = mbname_from_intname(mboxname);
    char *fname = conversations_path(mbname);

    mbname_free(&mbname);

    return fname;
}

static int _init_counted(struct conversations_state *state,
                         const char *val, int vallen)
{
    int r;

    if (!vallen) {
        val = config_getstring(IMAPOPT_CONVERSATIONS_COUNTED_FLAGS);
        if (!val) val = "";
        vallen = strlen(val);
        r = cyrusdb_store(state->db, CFKEY, strlen(CFKEY),
                          val, vallen, &state->txn);
        if (r) {
            syslog(LOG_ERR, "Failed to write counted_flags");
            return r;
        }
    }

    /* remove any existing value */
    if (state->counted_flags) {
        strarray_free(state->counted_flags);
        state->counted_flags = NULL;
    }

    /* add the value only if there's some flags set */
    if (vallen) {
        state->counted_flags = strarray_nsplit(val, vallen, " ", /*flags*/0);
    }

    return 0;
}

EXPORTED int conversations_open_path(const char *fname, struct conversations_state **statep)
{
    struct conversations_open *open = NULL;
    const char *val = NULL;
    size_t vallen = 0;
    int r = 0;

    if (!fname)
        return IMAP_MAILBOX_BADNAME;

    for (open = open_conversations; open; open = open->next) {
        if (!strcmp(open->s.path, fname))
            return IMAP_CONVERSATIONS_ALREADY_OPEN;
    }

    open = xzmalloc(sizeof(struct conversations_open));

    r = cyrusdb_open(DB, fname, CYRUSDB_CREATE | CYRUSDB_CONVERT, &open->s.db);
    if (r || open->s.db == NULL) {
        free(open);
        return IMAP_IOERROR;
    }

    open->s.path = xstrdup(fname);
    open->next = open_conversations;
    open_conversations = open;

    /* ensure a write lock immediately, and also load the counted flags */
    cyrusdb_fetchlock(open->s.db, CFKEY, strlen(CFKEY),
                      &val, &vallen, &open->s.txn);
    _init_counted(&open->s, val, vallen);

    /* we should just read the folder names up front too */
    open->s.folder_names = strarray_new();

    /* if there's a value, parse as a dlist */
    if (!cyrusdb_fetch(open->s.db, FNKEY, strlen(FNKEY),
                   &val, &vallen, &open->s.txn)) {
        struct dlist *dl = NULL;
        struct dlist *dp;
        dlist_parsemap(&dl, 0, val, vallen);
        for (dp = dl->head; dp; dp = dp->next) {
            strarray_append(open->s.folder_names, dlist_cstring(dp));
        }
        dlist_free(&dl);
    }

    /* create the status cache */
    construct_hash_table(&open->s.folderstatus, open->s.folder_names->count/4+4, 0);

    *statep = &open->s;

    return 0;
}

EXPORTED int conversations_open_user(const char *username, struct conversations_state **statep)
{
    char *path = conversations_getuserpath(username);
    int r;
    if (!path) return IMAP_MAILBOX_BADNAME;
    r = conversations_open_path(path, statep);
    free(path);
    return r;
}

EXPORTED int conversations_open_mbox(const char *mboxname, struct conversations_state **statep)
{
    char *path = conversations_getmboxpath(mboxname);
    int r;
    if (!path) return IMAP_MAILBOX_BADNAME;
    r = conversations_open_path(path, statep);
    free(path);
    return r;
}

EXPORTED struct conversations_state *conversations_get_path(const char *fname)
{
    struct conversations_open *open = NULL;

    for (open = open_conversations; open; open = open->next) {
        if (!strcmp(open->s.path, fname))
            return &open->s;
    }

    return NULL;
}

EXPORTED struct conversations_state *conversations_get_user(const char *username)
{
    struct conversations_state *state;
    char *path = conversations_getuserpath(username);
    if (!path) return NULL;
    state = conversations_get_path(path);
    free(path);
    return state;
}

EXPORTED struct conversations_state *conversations_get_mbox(const char *mboxname)
{
    struct conversations_state *state;
    char *path = conversations_getmboxpath(mboxname);
    if (!path) return NULL;
    state = conversations_get_path(path);
    free(path);
    return state;
}


static void _conv_remove(struct conversations_state *state)
{
    struct conversations_open **prevp = &open_conversations;
    struct conversations_open *cur;

    for (cur = open_conversations; cur; cur = cur->next) {
        if (state == &cur->s) {
            /* found it! */
            *prevp = cur->next;
            free(cur->s.path);
            if (cur->s.counted_flags)
                strarray_free(cur->s.counted_flags);
            if (cur->s.folder_names)
                strarray_free(cur->s.folder_names);
            free(cur);
            return;
        }
        prevp = &cur->next;
    }

    fatal("unknown conversation db closed", EC_SOFTWARE);
}

static void conversations_abortcache(struct conversations_state *state)
{
    /* still gotta clean up */
    free_hash_table(&state->folderstatus, free);
}

static void commitstatus_cb(const char *key, void *data, void *rock)
{
    conv_status_t *status = (conv_status_t *)data;
    struct conversations_state *state = (struct conversations_state *)rock;

    conversation_storestatus(state, key, strlen(key), status);
    /* just in case convdb has a higher modseq for any reason (aka deleted and
     * recreated while a replica was still valid with the old user) */
    mboxname_setmodseq(key+1, status->modseq, /*mbtype */0, /*dofolder*/0);
    sync_log_mailbox(key+1); /* skip the leading F */
}

static void conversations_commitcache(struct conversations_state *state)
{
    hash_enumerate(&state->folderstatus, commitstatus_cb, state);
    free_hash_table(&state->folderstatus, free);
}

EXPORTED int conversations_abort(struct conversations_state **statep)
{
    struct conversations_state *state = *statep;

    if (!state) return 0;

    *statep = NULL;

    /* clean up hashes */
    conversations_abortcache(state);

    if (state->db) {
        if (state->txn)
            cyrusdb_abort(state->db, state->txn);
        cyrusdb_close(state->db);
    }

    _conv_remove(state);

    return 0;
}

EXPORTED int conversations_commit(struct conversations_state **statep)
{
    struct conversations_state *state = *statep;
    int r = 0;

    if (!state) return 0;

    *statep = NULL;

    /* commit cache, writes to to DB */
    conversations_commitcache(state);

    /* finally it's safe to commit the DB itself */
    if (state->db) {
        if (state->txn)
            r = cyrusdb_commit(state->db, state->txn);
        cyrusdb_close(state->db);
    }

    _conv_remove(state);

    return r;
}

static int check_msgid(const char *msgid, size_t len, size_t *lenp)
{
    if (msgid == NULL)
        return IMAP_INVALID_IDENTIFIER;

    if (!len)
        len = strlen(msgid);

    if (msgid[0] != '<' || msgid[len-1] != '>' || strchr(msgid, '@') == NULL)
        return IMAP_INVALID_IDENTIFIER;

    if (lenp)
        *lenp = len;

    return 0;
}

static int _conversations_set_key(struct conversations_state *state,
                                  const char *key, size_t keylen,
                                  const arrayu64_t *cids, time_t stamp)
{
    int r;
    struct buf buf;
    int version = CONVERSATIONS_VERSION;
    int i;

    /* XXX: should this be a delete operation? */
    assert(cids->count);

    buf_init(&buf);

    if (state->db == NULL)
        return IMAP_IOERROR;

    buf_printf(&buf, "%d ", version);
    for (i = 0; i < cids->count; i++) {
        conversation_id_t cid = arrayu64_nth(cids, i);
        if (i) buf_putc(&buf, ',');
        buf_printf(&buf, CONV_FMT, cid);
    }
    buf_printf(&buf, " %lu", stamp);

    r = cyrusdb_store(state->db,
                      key, keylen,
                      buf.s, buf.len,
                      &state->txn);

    buf_free(&buf);
    if (r)
        return IMAP_IOERROR;

    return 0;
}

static int _sanity_check_counts(conversation_t *conv)
{
    conv_folder_t *folder;
    uint32_t num_records = 0;
    uint32_t exists = 0;

    for (folder = conv->folders; folder; folder = folder->next) {
        num_records += folder->num_records;
        exists += folder->exists;
    }

    if (num_records != conv->num_records)
        return IMAP_INTERNAL;

    if (exists != conv->exists)
        return IMAP_INTERNAL;

    return 0;
}


EXPORTED int conversations_add_msgid(struct conversations_state *state,
                                     const char *msgid,
                                     conversation_id_t cid)
{
    arrayu64_t cids = ARRAYU64_INITIALIZER;
    size_t keylen;
    int r = 0;

    r = check_msgid(msgid, 0, &keylen);
    if (r) goto done;

    r = conversations_get_msgid(state, msgid, &cids);

    /* read failure will mean cids is empty, but we can still add this one */
    if (r || arrayu64_find(&cids, cid, 0) < 0) {
        arrayu64_append(&cids, cid);
        r = _conversations_set_key(state, msgid, keylen, &cids, time(NULL));
    }

done:
    arrayu64_fini(&cids);
    return r;
}

static int _conversations_parse(const char *data, size_t datalen,
                                arrayu64_t *cids, time_t *stampp)
{
    const char *rest;
    size_t restlen;
    int r;
    conversation_id_t cid;
    bit64 tval;
    bit64 version;

    /* make sure we don't leak old data */
    arrayu64_truncate(cids, 0);

    r = parsenum(data, &rest, datalen, &version);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ')
        return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_VERSION) {
        /* XXX - an error code for "incorrect version"? */
        return IMAP_MAILBOX_BADFORMAT;
    }

    if (restlen < 17)
        return IMAP_MAILBOX_BADFORMAT;

    while (1) {
        r = parsehex(rest, &rest, 16, &cid);
        if (r) return IMAP_MAILBOX_BADFORMAT;
        arrayu64_append(cids, cid);
        if (rest[0] == ' ') break;
        if (rest[0] != ',') return IMAP_MAILBOX_BADFORMAT;
        rest++; /* skip comma */
    }

    if (rest[0] != ' ')
        return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    r = parsenum(rest, &rest, restlen, &tval);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    /* should have parsed to the end of the string */
    if (rest - data != (int)datalen)
        return IMAP_MAILBOX_BADFORMAT;

    if (stampp) *stampp = tval;

    return 0;
}

EXPORTED int conversations_get_msgid(struct conversations_state *state,
                                     const char *msgid,
                                     arrayu64_t *cids)
{
    size_t keylen;
    size_t datalen = 0;
    const char *data;
    int r;

    r = check_msgid(msgid, 0, &keylen);
    if (r)
        return r;

    r = cyrusdb_fetch(state->db,
                      msgid, keylen,
                      &data, &datalen,
                      &state->txn);

    if (!r) r = _conversations_parse(data, datalen, cids, NULL);

    if (r) arrayu64_truncate(cids, 0);

    return 0;
}

/*
 * Normalise a subject string, to a form which can be used for deciding
 * whether a message belongs in the same conversation as it's antecedent
 * messages.  What we're doing here is the same idea as the "base
 * subject" algorithm described in RFC5256 but slightly adapted from
 * experience.  Differences are:
 *
 *  - We eliminate all whitespace; RFC5256 normalises any sequence
 *    of whitespace characters to a single SP.  We do this because
 *    we have observed combinations of buggy client software both
 *    add and remove whitespace around folding points.
 *
 *  - Because we eliminate whitespace entirely, and whitespace helps
 *    delimit some of our other replacements, we do that whitespace
 *    step last instead of first.
 *
 *  - We eliminate leading tokens like Re: and Fwd: using a simpler
 *    and more generic rule than RFC5256's; this rule catches a number
 *    of semantically identical prefixes in other human languages, but
 *    unfortunately also catches lots of other things.  We think we can
 *    get away with this because the normalised subject is never directly
 *    seen by human eyes, so some information loss is acceptable as long
 *    as the subjects in different messages match correctly.
 *
 *  - We eliminate trailing tokens like [SEC=UNCLASSIFIED],
 *    [DLM=Sensitive], etc which are automatically added by Australian
 *    Government department email systems.  In theory there should be no
 *    more than one of these on an email subject but in practice multiple
 *    have been seen.
 *    http://www.finance.gov.au/files/2012/04/EPMS2012.3.pdf
 */
EXPORTED void conversation_normalise_subject(struct buf *s)
{
    static int initialised_res = 0;
    static regex_t whitespace_re;
    static regex_t relike_token_re;
    static regex_t blob_start_re;
    static regex_t blob_end_re;
    int r;

    if (!initialised_res) {
        r = regcomp(&whitespace_re, "[ \t\r\n]+", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&relike_token_re, "^[ \t]*[A-Za-z0-9]+(\\[[0-9]+\\])?:", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&blob_start_re, "^[ \t]*\\[[^]]+\\]", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&blob_end_re, "\\[(SEC|DLM)=[^]]+\\][ \t]*$", REG_EXTENDED);
        assert(r == 0);
        initialised_res = 1;
    }

    /* step 1 is to decode any RFC2047 MIME encoding of the header
     * field, but we assume that has already happened */

    /* step 2 is to eliminate all "Re:"-like tokens and [] blobs
     * at the start, and AusGov [] blobs at the end */
    while (buf_replace_one_re(s, &relike_token_re, NULL) ||
           buf_replace_one_re(s, &blob_start_re, NULL) ||
           buf_replace_one_re(s, &blob_end_re, NULL))
        ;

    /* step 3 is eliminating whitespace. */
    buf_replace_all_re(s, &whitespace_re, NULL);
}

static int write_folders(struct conversations_state *state)
{
    struct dlist *dl = dlist_newlist(NULL, NULL);
    struct buf buf = BUF_INITIALIZER;
    int r;
    int i;

    for (i = 0; i < state->folder_names->count; i++) {
        const char *fname = strarray_nth(state->folder_names, i);
        dlist_setatom(dl, NULL, fname);
    }

    dlist_printbuf(dl, 0, &buf);
    dlist_free(&dl);

    r = cyrusdb_store(state->db, FNKEY, strlen(FNKEY),
                      buf.s, buf.len, &state->txn);

    buf_free(&buf);

    return r;
}

static int folder_number(struct conversations_state *state,
                         const char *name,
                         int create_flag)
{
    int pos = strarray_find(state->folder_names, name, 0);
    int r;

    /* if we have to add it, then save the keys back */
    if (pos < 0 && create_flag) {
        /* replace the first unused if there is one */
        pos = strarray_find(state->folder_names, "-", 0);
        if (pos >= 0)
            strarray_set(state->folder_names, pos, name);
        /* otherwise append */
        else
            pos = strarray_append(state->folder_names, name);

        /* store must succeed */
        r = write_folders(state);
        if (r) abort();
    }

    return pos;
}

static int folder_number_rename(struct conversations_state *state,
                                const char *from_name,
                                const char *to_name)
{
    int pos = strarray_find(state->folder_names, from_name, 0);

    if (pos < 0) return 0; /* nothing to do! */

    /* replace the name  - set to '-' if deleted */
    strarray_set(state->folder_names, pos, to_name ? to_name : "-");

    return write_folders(state);
}

EXPORTED int conversation_storestatus(struct conversations_state *state,
                                      const char *key, size_t keylen,
                                      const conv_status_t *status)
{
    if (!status || !status->modseq) {
        return cyrusdb_delete(state->db,
                              key, keylen,
                              &state->txn, /*force*/1);
    }

    struct dlist *dl = dlist_newlist(NULL, NULL);
    dlist_setnum64(dl, "MODSEQ", status->modseq);
    dlist_setnum32(dl, "EXISTS", status->exists);
    dlist_setnum32(dl, "UNSEEN", status->unseen);

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%d ", CONVERSATIONS_VERSION);
    dlist_printbuf(dl, 0, &buf);
    dlist_free(&dl);

    int r = cyrusdb_store(state->db,
                          key, keylen,
                          buf.s, buf.len,
                          &state->txn);

    buf_free(&buf);

    return r;
}

EXPORTED int conversation_setstatus(struct conversations_state *state,
                                    const char *mboxname,
                                    const conv_status_t *status)
{
    char *key = strconcat("F", mboxname, (char *)NULL);
    conv_status_t *cachestatus = NULL;

    cachestatus = hash_lookup(key, &state->folderstatus);
    if (!cachestatus) {
        cachestatus = xzmalloc(sizeof(conv_status_t));
        hash_insert(key, cachestatus, &state->folderstatus);
    }

    /* either way it's in the hash, update the value */
    *cachestatus = status ? *status : NULLSTATUS;

    free(key);

    return 0;
}

EXPORTED int conversation_store(struct conversations_state *state,
                       const char *key, int keylen,
                       conversation_t *conv)
{
    struct dlist *dl, *n, *nn;
    struct buf buf = BUF_INITIALIZER;
    const conv_folder_t *folder;
    const conv_sender_t *sender;
    const conv_thread_t *thread;
    int version = CONVERSATIONS_VERSION;
    int i;
    int r;

    dl = dlist_newlist(NULL, NULL);
    dlist_setnum64(dl, "MODSEQ", conv->modseq);
    dlist_setnum32(dl, "NUMRECORDS", conv->num_records);
    dlist_setnum32(dl, "EXISTS", conv->exists);
    dlist_setnum32(dl, "UNSEEN", conv->unseen);
    n = dlist_newlist(dl, "COUNTS");
    if (state->counted_flags) {
        for (i = 0; i < state->counted_flags->count; i++) {
            const char *flag = strarray_nth(state->counted_flags, i);
            dlist_setnum32(n, flag, conv->counts[i]);
        }
    }

    n = dlist_newlist(dl, "FOLDER");
    for (folder = conv->folders ; folder ; folder = folder->next) {
        if (!folder->num_records)
            continue;
        nn = dlist_newlist(n, "FOLDER");
        dlist_setnum32(nn, "FOLDERNUM", folder->number);
        dlist_setnum64(nn, "MODSEQ", folder->modseq);
        dlist_setnum32(nn, "NUMRECORDS", folder->num_records);
        dlist_setnum32(nn, "EXISTS", folder->exists);
        dlist_setnum32(nn, "UNSEEN", folder->unseen);
    }

    n = dlist_newlist(dl, "SENDER");
    i = 0;
    for (sender = conv->senders ; sender ; sender = sender->next) {
        if (!sender->exists)
            continue;
        /* don't ever store more than 100 senders */
        if (++i >= 100) break;
        nn = dlist_newlist(n, "SENDER");
        /* envelope form */
        dlist_setatom(nn, "NAME", sender->name);
        dlist_setatom(nn, "ROUTE", sender->route);
        dlist_setatom(nn, "MAILBOX", sender->mailbox);
        dlist_setatom(nn, "DOMAIN", sender->domain);
        dlist_setnum32(nn, "LASTSEEN", sender->lastseen);
        dlist_setnum32(nn, "EXISTS", sender->exists);
    }

    dlist_setatom(dl, "SUBJECT", conv->subject);

    dlist_setnum32(dl, "SIZE", conv->size);

    n = dlist_newlist(dl, "THREAD");
    for (thread = conv->thread; thread; thread = thread->next) {
        if (!thread->exists)
            continue;
        nn = dlist_newlist(n, "THREAD");
        dlist_setguid(nn, "GUID", &thread->guid);
        dlist_setnum32(nn, "EXISTS", thread->exists);
        dlist_setnum32(nn, "INTERNALDATE", thread->internaldate);
        dlist_setnum32(nn, "MSGID", thread->msgid);
        if (thread->inreplyto) dlist_setnum32(nn, "INREPLYTO", thread->inreplyto);
    }

    buf_printf(&buf, "%d ", version);
    dlist_printbuf(dl, 0, &buf);
    dlist_free(&dl);

    if (_sanity_check_counts(conv)) {
        syslog(LOG_ERR, "IOERROR: conversations_audit on store: %s %.*s %.*s",
               state->path, keylen, key, (int)buf.len, buf.s);
    }

    r = cyrusdb_store(state->db, key, keylen, buf.s, buf.len, &state->txn);

    buf_free(&buf);

    return r;
}

static int _conversation_save(struct conversations_state *state,
                              const char *key, int keylen,
                              conversation_t *conv)
{
    const conv_folder_t *folder;
    int r;

    /* see if any 'F' keys need to be changed */
    for (folder = conv->folders ; folder ; folder = folder->next) {
        const char *mboxname = strarray_nth(state->folder_names, folder->number);
        int exists_diff = 0;
        int unseen_diff = 0;
        conv_status_t status = CONV_STATUS_INIT;

        /* case: full removal of conversation - make sure to remove
         * unseen as well */
        if (folder->exists) {
            if (folder->prev_exists) {
                /* both exist, just check for unseen changes */
                unseen_diff = !!conv->unseen - !!conv->prev_unseen;
            }
            else {
                /* adding, check if it's unseen */
                exists_diff = 1;
                if (conv->unseen) unseen_diff = 1;
            }
        }
        else if (folder->prev_exists) {
            /* removing, check if it WAS unseen */
            exists_diff = -1;
            if (conv->prev_unseen) unseen_diff = -1;
        }
        else {
            /* we don't care about unseen if the cid is not registered
             * in this folder, and wasn't previously either */
        }

        /* XXX - it's super inefficient to be doing this for
         * every cid in every folder in the transaction.  Big
         * wins available by caching these in memory and writing
         * once at the end of the transaction */
        r = conversation_getstatus(state, mboxname, &status);
        if (r) goto done;
        if (exists_diff || unseen_diff || status.modseq < conv->modseq) {
            if (status.modseq < conv->modseq)
                status.modseq = conv->modseq;
            status.exists += exists_diff;
            status.unseen += unseen_diff;
            r = conversation_setstatus(state, mboxname, &status);
            if (r) goto done;
        }
    }

    if (conv->num_records) {
        r = conversation_store(state, key, keylen, conv);
    }
    else {
        /* last existing record removed - clean up the 'B' record */
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, 1);
    }


done:
    if (!r)
        conv->dirty = 0;

    return r;
}

EXPORTED int conversation_save(struct conversations_state *state,
                      conversation_id_t cid,
                      conversation_t *conv)
{
    char bkey[CONVERSATION_ID_STRMAX+2];

    if (!conv)
        return IMAP_INTERNAL;
    if (!conv->dirty)
        return 0;

    /* old pre-conversations message, nothing to do */
    if (!cid)
        return 0;
    xstats_inc(CONV_SAVE);

    snprintf(bkey, sizeof(bkey), "B" CONV_FMT, cid);

    return _conversation_save(state, bkey, strlen(bkey), conv);
}

EXPORTED int conversation_parsestatus(const char *data, size_t datalen,
                                      conv_status_t *status)
{
    bit64 version;
    const char *rest;
    size_t restlen;
    struct dlist *dl = NULL;
    struct dlist *n;
    int r;

    status->modseq = 0;
    status->exists = 0;
    status->unseen = 0;

    r = parsenum(data, &rest, datalen, &version);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ')
        return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_VERSION) {
        /* XXX - an error code for "incorrect version"? */
        return IMAP_MAILBOX_BADFORMAT;
    }

    r = dlist_parsemap(&dl, 0, rest, restlen);
    if (r) return r;

    n = dl->head;
    if (n) {
        status->modseq = dlist_num(n);
        n = n->next;
    }
    if (n) {
        status->exists = dlist_num(n);
        n = n->next;
    }
    if (n) {
        status->unseen = dlist_num(n);
    }

    dlist_free(&dl);
    return 0;
}

EXPORTED int conversation_getstatus(struct conversations_state *state,
                                    const char *mboxname,
                                    conv_status_t *status)
{
    char *key = strconcat("F", mboxname, (char *)NULL);
    const char *data;
    size_t datalen;
    int r = 0;
    conv_status_t *cachestatus = NULL;

    cachestatus = hash_lookup(key, &state->folderstatus);
    if (cachestatus) {
        *status = *cachestatus;
        goto done;
    }

    *status = NULLSTATUS;

    if (!state->db) {
        r = IMAP_IOERROR;
        goto done;
    }

    r = cyrusdb_fetch(state->db,
                      key, strlen(key),
                      &data, &datalen,
                      &state->txn);

    if (r == CYRUSDB_NOTFOUND) {
        /* not existing is not an error */
        r = 0;
        goto done;
    }
    if (r) goto done;

    r = conversation_parsestatus(data, datalen, status);

 done:
    if (r)
        syslog(LOG_ERR, "IOERROR: conversations invalid status %s", mboxname);

    free(key);

    return r;
}

EXPORTED conv_folder_t *conversation_get_folder(conversation_t *conv,
                                       int number, int create_flag)
{
    conv_folder_t *folder, **nextp = &conv->folders;

    if (number < 0)
        return NULL;

    /* first check if it already exists */
    for (folder = conv->folders ; folder ; folder = folder->next) {
        if (folder->number < number)
            nextp = &folder->next;
        else if (folder->number == number)
            return folder;
        else
            break;
    }

    if (!create_flag)
        return NULL;

    /* not found, create a new one */
    folder = xzmalloc(sizeof(*folder));
    folder->number = number;
    folder->next = *nextp;
    *nextp = folder;
    conv->dirty = 1;

    return folder;
}

static conv_thread_t *parse_thread(struct dlist *dl)
{
    conv_thread_t *res = NULL;
    conv_thread_t **p = &res;
    struct dlist *item = dl->head;
    struct dlist *n;
    while (item) {
        conv_thread_t *thread = *p = xzmalloc(sizeof(conv_thread_t));
        p = &thread->next;
        n = dlist_getchildn(item, 0);
        if (n) {
            struct message_guid *guid = NULL;
            dlist_toguid(n, &guid);
            if (guid) message_guid_copy(&thread->guid, guid);
        }
        n = dlist_getchildn(item, 1);
        if (n) thread->exists = dlist_num(n);
        n = dlist_getchildn(item, 2);
        if (n) thread->internaldate = dlist_num(n);
        n = dlist_getchildn(item, 3);
        if (n) thread->msgid = dlist_num(n);
        n = dlist_getchildn(item, 4);
        if (n) thread->inreplyto = dlist_num(n);
        item = item->next;
    }

    return res;
}

EXPORTED int conversation_parse(struct conversations_state *state,
                       const char *data, size_t datalen,
                       conversation_t **convp)
{
    const char *rest;
    int i;
    int restlen;
    bit64 version;
    struct dlist *dl = NULL;
    struct dlist *n, *nn;
    conversation_t *conv;
    conv_folder_t *folder;
    int r;

    *convp = NULL;

    r = parsenum(data, &rest, datalen, &version);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ') return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_VERSION) return IMAP_MAILBOX_BADFORMAT;

    r = dlist_parsemap(&dl, 0, rest, restlen);
    if (r) return r;

    conv = conversation_new(state);

    n = dlist_getchildn(dl, 0);
    if (n)
        conv->modseq = dlist_num(n);
    n = dlist_getchildn(dl, 1);
    if (n)
        conv->num_records = dlist_num(n);
    n = dlist_getchildn(dl, 2);
    if (n)
        conv->exists = dlist_num(n);
    n = dlist_getchildn(dl, 3);
    if (n)
        conv->unseen = dlist_num(n);
    n = dlist_getchildn(dl, 4);
    if (state->counted_flags) {
        nn = n ? n->head : NULL;
        for (i = 0; i < state->counted_flags->count; i++) {
            if (nn) {
                conv->counts[i] = dlist_num(nn);
                nn = nn->next;
            }
            else
                conv->counts[i] = 0;
        }
    }

    n = dlist_getchildn(dl, 5);
    for (n = (n ? n->head : NULL) ; n ; n = n->next) {
        int number;
        nn = dlist_getchildn(n, 0);
        if (!nn)
            continue;
        number = dlist_num(nn);
        folder = conversation_get_folder(conv, number, 1);

        nn = dlist_getchildn(n, 1);
        if (nn)
            folder->modseq = dlist_num(nn);
        nn = dlist_getchildn(n, 2);
        if (nn)
            folder->num_records = dlist_num(nn);
        nn = dlist_getchildn(n, 3);
        if (nn)
            folder->exists = dlist_num(nn);
        nn = dlist_getchildn(n, 4);
        if (nn)
            folder->unseen = dlist_num(nn);

        folder->prev_exists = folder->exists;
    }

    n = dlist_getchildn(dl, 6);
    for (n = (n ? n->head : NULL) ; n ; n = n->next) {
        struct dlist *nn2, *nn3, *nn4, *nn5, *nn6;
        nn = dlist_getchildn(n, 0);
        nn2 = dlist_getchildn(n, 1);
        nn3 = dlist_getchildn(n, 2);
        nn4 = dlist_getchildn(n, 3);
        nn5 = dlist_getchildn(n, 4);
        nn6 = dlist_getchildn(n, 5);
        if (nn6)
            conversation_update_sender(conv, nn->sval, nn2->sval,
                                       nn3->sval, nn4->sval,
                                       dlist_num(nn5), dlist_num(nn6));
        else if (nn4) /* XXX: remove when cleaned up - handle old-style too */
            conversation_update_sender(conv, nn->sval, nn2->sval,
                                       nn3->sval, nn4->sval,
                                       0/*time_t*/, (1<<30)/*exists*/);
        /* INSANE EXISTS NUMBER MEANS IT NEVER GETS CLEANED UP */
    }

    n = dlist_getchildn(dl, 7);
    if (n) conv->subject = xstrdupnull(dlist_cstring(n));

    n = dlist_getchildn(dl, 8);
    if (n) conv->size = dlist_num(n);

    n = dlist_getchildn(dl, 9);
    if (n) conv->thread = parse_thread(n);

    conv->prev_unseen = conv->unseen;

    dlist_free(&dl);
    conv->dirty = 0;
    *convp = conv;
    return 0;
}

EXPORTED int conversation_load(struct conversations_state *state,
                      conversation_id_t cid,
                      conversation_t **convp)
{
    const char *data;
    size_t datalen;
    char bkey[CONVERSATION_ID_STRMAX+2];
    int r;

    snprintf(bkey, sizeof(bkey), "B" CONV_FMT, cid);
    r = cyrusdb_fetch(state->db,
                  bkey, strlen(bkey),
                  &data, &datalen,
                  &state->txn);

    if (r == CYRUSDB_NOTFOUND) {
        *convp = NULL;
        return 0;
    } else if (r != CYRUSDB_OK) {
        return r;
    }
    xstats_inc(CONV_LOAD);

    r = conversation_parse(state, data, datalen, convp);
    if (r) {
        syslog(LOG_ERR, "IOERROR: conversations invalid conversation "
               CONV_FMT, cid);
        *convp = NULL;
    }

    if (_sanity_check_counts(*convp)) {
        syslog(LOG_ERR, "IOERROR: conversations_audit on load: %s %s %.*s",
               state->path, bkey, (int)datalen, data);
    }

    return 0;
}

/* Parse just enough of the B record to retrieve the modseq.
 * Fortunately the modseq is the first field after the record version
 * number, given the way that _conversation_save() and dlist works.  See
 * _conversation_load() for the full shebang. */
static int _conversation_load_modseq(const char *data, int datalen,
                                     modseq_t *modseqp)
{
    const char *p = data;
    const char *end = data + datalen;
    bit64 version = ~0ULL;
    int r;

    r = parsenum(p, &p, (end-p), &version);
    if (r || version != CONVERSATIONS_VERSION)
        return IMAP_MAILBOX_BADFORMAT;

    if ((end - p) < 4 || p[0] != ' ' || p[1] != '(')
        return IMAP_MAILBOX_BADFORMAT;
    p += 2; /* skip space and left parenthesis */

    r = parsenum(p, &p, (end-p), modseqp);
    if ((end - p) < 1 || *p != ' ')
        return IMAP_MAILBOX_BADFORMAT;

    return 0;
}

EXPORTED int conversation_get_modseq(struct conversations_state *state,
                            conversation_id_t cid,
                            modseq_t *modseqp)
{
    const char *data;
    size_t datalen;
    char bkey[CONVERSATION_ID_STRMAX+2];
    int r;

    snprintf(bkey, sizeof(bkey), "B" CONV_FMT, cid);
    r = cyrusdb_fetch(state->db,
                  bkey, strlen(bkey),
                  &data, &datalen,
                  &state->txn);

    if (r == CYRUSDB_NOTFOUND) {
        *modseqp = 0;
        return 0;
    } else if (r != CYRUSDB_OK) {
        return r;
    }
    xstats_inc(CONV_GET_MODSEQ);

    r = _conversation_load_modseq(data, datalen, modseqp);
    if (r) {
        syslog(LOG_ERR, "IOERROR: conversation_get_modseq: invalid conversation "
               CONV_FMT, cid);
        *modseqp = 0;
    }

    return 0;
}

EXPORTED conv_folder_t *conversation_find_folder(struct conversations_state *state,
                                        conversation_t *conv,
                                        const char *mboxname)
{
    int number = folder_number(state, mboxname, /*create*/0);
    return conversation_get_folder(conv, number, /*create*/0);
}

/* Compare a sender vs a new sender key (mailbox and domain).
 * Returns 0 if identical, nonzero if different (sign indicates
 * sort order, like strcmp()).
 *
 * This is not quite RFC compliant: we are comparing the
 * localpart case insensitively even though the RFC says the
 * interpretation is up to the domain itself.  However this
 * seems to yield better results. [IRIS-1484] */
static int sender_cmp(const conv_sender_t *sender,
                      const char *mailbox,
                      const char *domain)
{
    int d = strcasecmp(sender->domain, domain);
    if (!d)
        d = strcasecmp(sender->mailbox, mailbox);
    return d;
}

/* Choose a preferred mailbox. Returns <0 if @a is preferred,
 * 0 if we don't care, and >0 if @b is preferred */
static int sender_preferred_mailbox(const char *a, const char *b)
{
    /* choosing the lexically earlier string tends to keep
     * capital letters, which is an arbitrary asthetic */
    return strcmpsafe(a, b);
}

/* Choose a preferred domain. Returns <0 if @a is preferred,
 * 0 if we don't care, and >0 if @b is preferred */
static int sender_preferred_domain(const char *a, const char *b)
{
    /* choosing the lexically earlier string tends to keep
     * capital letters, which is an arbitrary asthetic */
    return strcmpsafe(a, b);
}

/* Choose a preferred route. Returns <0 if @a is preferred,
 * 0 if we don't care, and >0 if @b is preferred */
static int sender_preferred_route(const char *a, const char *b)
{
    /* choosing the lexically earlier string tends to keep
     * capital letters, which is an arbitrary asthetic */
    return strcmpsafe(a, b);
}

static int has_non_ascii(const char *s)
{
    for ( ; *s ; s++) {
        if (*(unsigned char *)s > 0x7f)
            return 1;
    }
    return 0;
}

/* Choose a preferred name. Returns <0 if @a is preferred,
 * 0 if we don't care, and >0 if @b is preferred */
static int sender_preferred_name(const char *a, const char *b)
{
    int d;
    char *sa = NULL;
    char *sb = NULL;

    sa = charset_parse_mimeheader((a ? a : ""), charset_flags);
    sb = charset_parse_mimeheader((b ? b : ""), charset_flags);

    /* A name with characters > 0x7f is preferred to a flat
     * ascii one, on the assumption that this is more likely to
     * contain an actual name rather than a romanisation. */
    d = has_non_ascii(sb) - has_non_ascii(sa);

    /* A longer name is preferred over a shorter. */
    if (!d)
        d = strlen(sb) - strlen(sa);

    /* The lexically earlier name is preferred (earlier on the grounds
     * that's more likely to start with a capital letter) */
    if (!d)
        d = strcmp(sa, sb);

    if (!d)
        d = strcmpsafe(a, b);

    free(sa);
    free(sb);
    return d;
}

static void conversation_update_thread(conversation_t *conv,
                                       const struct message_guid *guid,
                                       time_t internaldate,
                                       const char *msgid,
                                       const char *inreplyto,
                                       int delta_exists)
{
    conv_thread_t *thread, *parent, **nextp = &conv->thread;

    for (thread = conv->thread; thread; thread = thread->next) {
        /* does it already exist? */
        if (message_guid_equal(guid, &thread->guid))
            break;
        nextp = &thread->next;
    }

    if (thread) {
        /* unstitch */
        *nextp = thread->next;
    }
    else {
        /* we start with zero */
        thread = xzmalloc(sizeof(*thread));
    }

    /* counts first, may be just removing it */
    if (thread->exists + delta_exists <= 0) {
        conv->dirty = 1;
        free(thread);
        return;
    }

    message_guid_copy(&thread->guid, guid);
    thread->internaldate = internaldate;
    thread->exists += delta_exists;
    /* just copy, it's not that expensive for a write */
    thread->msgid = msgid ? crc32_cstring(msgid) : 0;
    thread->inreplyto = inreplyto ? crc32_cstring(inreplyto) : 0;

    if (thread->inreplyto) {
        /* see if we can stitch it into the list behind the message it replies to */
        conv_thread_t *candidate = NULL;
        for (parent = conv->thread; parent; parent = parent->next) {
            if (thread->inreplyto == parent->msgid) {
                candidate = parent;
            }
            if (thread->inreplyto == parent->inreplyto) {
                if (parent->internaldate < internaldate)
                    candidate = parent;
            }
        }
        if (candidate) {
            thread->next = candidate->next;
            candidate->next = thread;
            return;
        }
    }

    /* OK, we didn't find a parent to attach to, so just go through by date and put it
     * after the last one with an earlier date */
    nextp = &conv->thread;
    for (parent = conv->thread; parent; parent = parent->next) {
        if (parent->internaldate > thread->internaldate) break;
        nextp = &parent->next;
    }

    thread->next = *nextp;
    *nextp = thread;
}

EXPORTED void conversation_update_sender(conversation_t *conv,
                                         const char *name,
                                         const char *route,
                                         const char *mailbox,
                                         const char *domain,
                                         time_t lastseen,
                                         int delta_exists)
{
    conv_sender_t *sender, *ptr, **nextp = &conv->senders;

    if (!mailbox || !domain) return;

    /* always re-stitch the found record, it's just simpler */
    for (sender = conv->senders; sender; sender = sender->next) {
        if (!sender_cmp(sender, mailbox, domain))
            break;
        nextp = &sender->next;
    }

    if (sender) {
        /* unstitch */
        *nextp = sender->next;
    }
    else {
        /* we start with zero */
        sender = xzmalloc(sizeof(*sender));
    }

    /* counts first, may be just removing it */
    if (delta_exists <= 0 && (uint32_t)(- delta_exists) >= sender->exists) {
        conv->dirty = 1;
        free(sender->name);
        free(sender->route);
        free(sender->mailbox);
        free(sender->domain);
        free(sender);
        return;
    }

    /* otherwise update the counter */
    sender->exists += delta_exists;

    /* ensure the database is consistent regardless
     * of message arrival order, update the record if the newly
     * seen values are more preferred */
    if (!sender->name || sender_preferred_name(sender->name, name) > 0) {
        free(sender->name);
        sender->name = xstrdupnull(name);
    }

    if (!sender->route || sender_preferred_route(sender->route, route) > 0) {
        free(sender->route);
        sender->route = xstrdupnull(route);
    }

    if (!sender->mailbox || sender_preferred_mailbox(sender->mailbox, mailbox) > 0) {
        free(sender->mailbox);
        sender->mailbox = xstrdup(mailbox);
    }

    if (!sender->domain || sender_preferred_domain(sender->domain, domain) > 0) {
        free(sender->domain);
        sender->domain = xstrdup(domain);
    }

    /* last seen for display sorting */
    if (sender->lastseen < lastseen) {
        sender->lastseen = lastseen;
    }

    /* now re-stitch it into place */
    nextp = &conv->senders;
    for (ptr = conv->senders; ptr; ptr = ptr->next) {
        if (ptr->lastseen < sender->lastseen)
            break;
        if (sender->lastseen == ptr->lastseen &&
            sender_cmp(ptr, mailbox, domain) > 0)
            break;
        nextp = &ptr->next;
    }

    sender->next = *nextp;
    *nextp = sender;

    conv->dirty = 1;
}

static void _apply_delta(uint32_t *valp, int delta)
{
    if (delta >= 0) {
        *valp += delta;
    }
    else {
        uint32_t decrease = -delta;
        /* let us die where it broke */
        if (decrease <= *valp)
            *valp -= decrease;
        else
            *valp = 0;
    }
}

EXPORTED const strarray_t *conversations_get_folders(struct conversations_state *state)
{
    return state->folder_names;
}

static int _match1(void *rock,
                   const char *key __attribute__((unused)),
                   size_t keylen __attribute__((unused)),
                   const char *data __attribute__((unused)),
                   size_t datalen __attribute__((unused)))
{
    int *match = (int *)rock;
    *match = 1;
    return CYRUSDB_DONE;
}

EXPORTED int conversations_guid_exists(struct conversations_state *state,
                                       const char *guidrep)
{
    int match = 0;

    char *key = strconcat("G", guidrep, (char *)NULL);
    cyrusdb_foreach(state->db, key, strlen(key), NULL, _match1, &match, NULL);
    free(key);

    return match;
}

struct guid_foreach_rock {
    struct conversations_state *state;
    int(*cb)(const conv_guidrec_t *, void *);
    void *cbrock;
};

static int _guid_one(const char *s, struct guid_foreach_rock *frock)
{
    const char *p, *err;
    conv_guidrec_t rec;
    uint32_t res;

    p = strchr(s, ':');
    if (!p) return IMAP_INTERNAL;

    /* mboxname */
    int r = parseuint32(s, &err, &res);
    if (r || err != p) return IMAP_INTERNAL;
    rec.mboxname = strarray_safenth(frock->state->folder_names, res);
    if (!rec.mboxname) return IMAP_INTERNAL;

    /* uid */
    r = parseuint32(p + 1, &err, &res);
    if (r) return IMAP_INTERNAL;
    rec.uid = res;
    p = err;

    /* part */
    rec.part = NULL;
    char *freeme = NULL;
    if (*p) {
        const char *end = strchr(p+1, ']');
        if (*p != '[' || !end || p+1 == end) {
            return IMAP_INTERNAL;
        }
        rec.part = freeme = xstrndup(p+1, end-p-1);
    }

    r = frock->cb(&rec, frock->cbrock);
    free(freeme);
    return r;
}

static int _guid_cb(void *rock,
                    const char *key,
                    size_t keylen,
                    const char *data,
                    size_t datalen)
{
    struct guid_foreach_rock *frock = (struct guid_foreach_rock *)rock;
    int r;

    if (keylen < 41)
        return IMAP_INTERNAL;

    // oldstyle key
    if (keylen == 41) {
        strarray_t *recs = strarray_nsplit(data, datalen, ",", /*flags*/0);
        int i;
        for (i = 0; i < recs->count; i++) {
            r = _guid_one(strarray_nth(recs, i), frock);
            if (r) break;
        }
        strarray_free(recs);
        return r;
    }

    // newstyle key
    if (key[41] != ':')
        return IMAP_INTERNAL;

    char *freeme = xstrndup(key+42, keylen-42);
    r = _guid_one(freeme, frock);
    free(freeme);

    return r;
}

EXPORTED int conversations_guid_foreach(struct conversations_state *state,
                                        const char *guidrep,
                                        int(*cb)(const conv_guidrec_t *, void *),
                                        void *cbrock)
{
    struct guid_foreach_rock rock;
    rock.state = state;
    rock.cb = cb;
    rock.cbrock = cbrock;

    char *key = strconcat("G", guidrep, (char *)NULL);
    int r = cyrusdb_foreach(state->db, key, strlen(key), NULL, _guid_cb, &rock, NULL);
    free(key);

    return r;
}

static int conversations_guid_setitem(struct conversations_state *state, const char *guidrep,
                                      const char *item, int add)
{
    struct buf key = BUF_INITIALIZER;
    buf_setcstr(&key, "G");
    buf_appendcstr(&key, guidrep);
    size_t datalen = 0;
    const char *data;

    // check if we have to upgrade anything?
    int r = cyrusdb_fetch(state->db, buf_base(&key), buf_len(&key), &data, &datalen, &state->txn);
    if (!r && datalen) {
        int i;
        buf_putc(&key, ':');

        /* add new keys for all the old values */
        strarray_t *old = strarray_nsplit(data, datalen, ",", /*flags*/0);
        for (i = 0; i < strarray_size(old); i++) {
            buf_truncate(&key, 42); // trim back to the colon
            buf_appendcstr(&key, strarray_nth(old, i));
            r = cyrusdb_store(state->db, buf_base(&key), buf_len(&key), "", 0, &state->txn);
            if (r) break;
        }
        strarray_free(old);
        if (r) goto done;

        buf_truncate(&key, 41); // trim back to original key

        /* remove the original key */
        r = cyrusdb_delete(state->db, buf_base(&key), buf_len(&key), &state->txn, /*force*/0);
        if (r) goto done;
    }

    buf_putc(&key, ':');
    buf_appendcstr(&key, item);

    if (add) {
        r = cyrusdb_store(state->db, buf_base(&key), buf_len(&key), "", 0, &state->txn);
    }
    else {
        r = cyrusdb_delete(state->db, buf_base(&key), buf_len(&key), &state->txn, /*force*/1);
    }

done:
    buf_free(&key);

    return r;
}

static int _guid_addbody(struct conversations_state *state, struct body *body,
                         const char *base, int add)
{
    int i;
    int r = 0;

    if (!body) return 0;

    if (!message_guid_isnull(&body->content_guid) && body->part_id) {
        struct buf buf = BUF_INITIALIZER;

        buf_setcstr(&buf, base);
        buf_printf(&buf, "[%s]", body->part_id);
        const char *guidrep = message_guid_encode(&body->content_guid);
        r = conversations_guid_setitem(state, guidrep, buf_cstring(&buf), add);
        buf_free(&buf);

        if (r) return r;
    }

    r = _guid_addbody(state, body->subpart, base, add);
    if (r) return r;

    for (i = 1; i < body->numparts; i++) {
        r = _guid_addbody(state, body->subpart + i, base, add);
        if (r) return r;
    }

    return 0;
}

static int conversations_set_guid(struct conversations_state *state,
                                  struct mailbox *mailbox,
                                  const struct index_record *record,
                                  int add)
{
    int folder = folder_number(state, mailbox->name, /*create*/1);
    struct buf item = BUF_INITIALIZER;
    struct body *body = NULL;
    int r = 0;

    r = mailbox_cacherecord(mailbox, record);
    if (r) return r;

    message_read_bodystructure(record, &body);

    /* process the GUID of the full message itself */
    buf_printf(&item, "%d:%u", folder, record->uid);
    const char *base = buf_cstring(&item);

    r = conversations_guid_setitem(state, message_guid_encode(&record->guid), base, add);
    if (!r) r = _guid_addbody(state, body, base, add);

    message_free_body(body);
    free(body);
    buf_free(&item);
    return r;
}

EXPORTED int conversations_update_record(struct conversations_state *cstate,
                                         struct mailbox *mailbox,
                                         const struct index_record *old,
                                         struct index_record *new)
{
    conversation_t *conv = NULL;
    int delta_num_records = 0;
    int delta_exists = 0;
    int delta_unseen = 0;
    int is_trash = 0;
    int delta_size = 0;
    int *delta_counts = NULL;
    int i;
    modseq_t modseq = 0;
    const struct index_record *record = NULL;
    int r = 0;

    if (old && new) {
        /* we're always moving forwards */
        assert(old->uid == new->uid);
        assert(old->modseq <= new->modseq);

        /* this flag cannot go away */
        if ((old->system_flags & FLAG_EXPUNGED))
            assert((new->system_flags & FLAG_EXPUNGED));

        /* we're changing the CID for any reason at all, treat as
         * a removal and re-add, so cache gets parsed and msgids
         * updated */
        if (old->cid != new->cid) {
            r = conversations_update_record(cstate, mailbox, old, NULL);
            if (r) return r;
            return conversations_update_record(cstate, mailbox, NULL, new);
        }
    }

    if (new && !old) {
        /* add the conversation */
        r = mailbox_cacherecord(mailbox, new); /* make sure it's loaded */
        if (r) return r;
        r = message_update_conversations(cstate, new, &conv);
        if (r) return r;
        record = new;
        /* possible if silent (i.e. replica) */
        if (!record->cid) return 0;
    }
    else {
        record = new ? new : old;
        /* skip out on non-CIDed records */
        if (!record->cid) return 0;

        r = conversation_load(cstate, record->cid, &conv);
        if (r) return r;
        if (!conv) {
            if (!new) {
                /* We're trying to delete a conversation that's already
                 * gone...don't try to hard */
                syslog(LOG_NOTICE, "conversation "CONV_FMT" already "
                                   "deleted, ignoring", record->cid);
                return 0;
            }
            conv = conversation_new(cstate);
        }
    }

    if (cstate->counted_flags)
        delta_counts = xzmalloc(sizeof(int) * cstate->counted_flags->count);

    /* IRIS-2534: check if it's the trash folder - XXX - should be separate
     * conversation root or similar more useful method in future */
    mbname_t *mbname = mbname_from_intname(mailbox->name);
    if (!mbname)
        return IMAP_MAILBOX_BADNAME;

    const strarray_t *boxes = mbname_boxes(mbname);
    if (strarray_size(boxes) == 1 && !strcmpsafe(strarray_nth(boxes, 0), "Trash"))
        is_trash = 1;

    mbname_free(&mbname);

    /* calculate the changes */
    if (old) {
        /* decrease any relevent counts */
        if (!(old->system_flags & FLAG_EXPUNGED)) {
            delta_exists--;
            delta_size -= old->size;
            /* drafts don't update the 'unseen' counter so that
             * they never turn a conversation "unread" */
            if (!is_trash && !(old->system_flags & (FLAG_SEEN|FLAG_DRAFT)))
                delta_unseen--;
            if (cstate->counted_flags) {
                for (i = 0; i < cstate->counted_flags->count; i++) {
                    const char *flag = strarray_nth(cstate->counted_flags, i);
                    if (mailbox_record_hasflag(mailbox, old, flag))
                        delta_counts[i]--;
                }
            }
        }
        delta_num_records--;
        modseq = MAX(modseq, old->modseq);
        if (!new) {
            r = conversations_set_guid(cstate, mailbox, old, /*add*/0);
            if (r) return r;
        }
    }

    if (new) {
        /* add any counts */
        if (!(new->system_flags & FLAG_EXPUNGED)) {
            delta_exists++;
            delta_size += new->size;
            /* drafts don't update the 'unseen' counter so that
             * they never turn a conversation "unread" */
            if (!is_trash && !(new->system_flags & (FLAG_SEEN|FLAG_DRAFT)))
                delta_unseen++;
            if (cstate->counted_flags) {
                for (i = 0; i < cstate->counted_flags->count; i++) {
                    const char *flag = strarray_nth(cstate->counted_flags, i);
                    if (mailbox_record_hasflag(mailbox, new, flag))
                        delta_counts[i]++;
                }
            }
        }
        delta_num_records++;
        modseq = MAX(modseq, new->modseq);
        if (!old) {
            r = conversations_set_guid(cstate, mailbox, new, /*add*/1);
            if (r) return r;
        }
    }

    /* XXX - combine this with the earlier cache parsing */
    if (!mailbox_cacherecord(mailbox, record)) {
        char *env = NULL;
        char *envtokens[NUMENVTOKENS];
        struct address addr = { NULL, NULL, NULL, NULL, NULL, NULL, 0 };

        /* Need to find the sender */

        /* +1 -> skip the leading paren */
        env = xstrndup(cacheitem_base(record, CACHE_ENVELOPE) + 1,
                       cacheitem_size(record, CACHE_ENVELOPE) - 1);

        parse_cached_envelope(env, envtokens, VECTOR_SIZE(envtokens));

        if (envtokens[ENV_FROM])
            message_parse_env_address(envtokens[ENV_FROM], &addr);

        const char *msgid = envtokens[ENV_MSGID];
        const char *inreplyto = NULL;
        if (record->system_flags & FLAG_DRAFT) {
            /* non-drafts don't get an inreplyto, using it as both a value AND a flag */
            inreplyto = envtokens[ENV_INREPLYTO];
        }

        /* XXX - internaldate vs gmtime? */
        conversation_update_sender(conv,
                                   addr.name, addr.route,
                                   addr.mailbox, addr.domain,
                                   record->gmtime, delta_exists);

        conversation_update_thread(conv,
                                   &record->guid,
                                   record->internaldate,
                                   msgid, inreplyto,
                                   delta_exists);
        free(env);
    }

    conversation_update(cstate, conv, mailbox->name,
                        delta_num_records,
                        delta_exists, delta_unseen,
                        delta_size, delta_counts, modseq);

    r = conversation_save(cstate, record->cid, conv);

    conversation_free(conv);
    free(delta_counts);
    return r;
}


EXPORTED void conversation_update(struct conversations_state *state,
                         conversation_t *conv, const char *mboxname,
                         int delta_num_records,
                         int delta_exists, int delta_unseen,
                         int delta_size, int *delta_counts,
                         modseq_t modseq)
{
    conv_folder_t *folder;
    int number = folder_number(state, mboxname, /*create*/1);
    int i;

    folder = conversation_get_folder(conv, number, /*create*/1);

    if (delta_num_records) {
        _apply_delta(&conv->num_records, delta_num_records);
        _apply_delta(&folder->num_records, delta_num_records);
        conv->dirty = 1;
    }
    if (delta_exists) {
        _apply_delta(&conv->exists, delta_exists);
        _apply_delta(&folder->exists, delta_exists);
        conv->dirty = 1;
    }
    if (delta_unseen) {
        _apply_delta(&conv->unseen, delta_unseen);
        _apply_delta(&folder->unseen, delta_unseen);
        conv->dirty = 1;
    }
    if (delta_size) {
        _apply_delta(&conv->size, delta_size);
        conv->dirty = 1;
    }
    if (state->counted_flags) {
        for (i = 0; i < state->counted_flags->count; i++) {
            if (delta_counts[i]) {
                _apply_delta(&conv->counts[i], delta_counts[i]);
                conv->dirty = 1;
            }
        }
    }
    if (modseq > conv->modseq) {
        conv->modseq = modseq;
        conv->dirty = 1;
    }
    if (modseq > folder->modseq) {
        folder->modseq = modseq;
        conv->dirty = 1;
    }
}

EXPORTED conversation_t *conversation_new(struct conversations_state *state)
{
    conversation_t *conv;

    conv = xzmalloc(sizeof(conversation_t));
    if (state->counted_flags)
        conv->counts = xzmalloc(sizeof(uint32_t) * state->counted_flags->count);
    conv->dirty = 1;
    xstats_inc(CONV_NEW);

    return conv;
}

EXPORTED void conversation_free(conversation_t *conv)
{
    conv_folder_t *folder;
    conv_sender_t *sender;
    conv_thread_t *thread;

    if (!conv) return;

    while ((folder = conv->folders)) {
        conv->folders = folder->next;
        free(folder);
    }

    while ((sender = conv->senders)) {
        conv->senders = sender->next;
        free(sender->name);
        free(sender->route);
        free(sender->mailbox);
        free(sender->domain);
        free(sender);
    }

    free(conv->subject);
    free(conv->counts);

    while ((thread = conv->thread)) {
        conv->thread = thread->next;
        free(thread);
    }

    free(conv);
}


struct prune_rock {
    struct conversations_state *state;
    time_t thresh;
    unsigned int nseen;
    unsigned int ndeleted;
};

static int prunecb(void *rock,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    struct prune_rock *prock = (struct prune_rock *)rock;
    arrayu64_t cids = ARRAYU64_INITIALIZER;
    time_t stamp;
    int r;

    prock->nseen++;
    r = check_msgid(key, keylen, NULL);
    if (r) goto done;

    r = _conversations_parse(data, datalen, &cids, &stamp);
    if (r) goto done;

    /* keep records newer than the threshold */
    if (stamp >= prock->thresh)
        goto done;

    prock->ndeleted++;

    r = cyrusdb_delete(prock->state->db,
                       key, keylen,
                       &prock->state->txn,
                       /*force*/1);

done:
    arrayu64_fini(&cids);
    return r;
}

EXPORTED int conversations_prune(struct conversations_state *state,
                                 time_t thresh, unsigned int *nseenp,
                                 unsigned int *ndeletedp)
{
    struct prune_rock rock = { state, thresh, 0, 0 };

    cyrusdb_foreach(state->db, "<", 1, NULL, prunecb, &rock, &state->txn);

    if (nseenp)
        *nseenp = rock.nseen;
    if (ndeletedp)
        *ndeletedp = rock.ndeleted;

    return 0;
}

/* NOTE: this makes an "ATOM" return */
EXPORTED const char *conversation_id_encode(conversation_id_t cid)
{
    static char text[2*sizeof(cid)+1];

    if (cid != NULLCONVERSATION) {
        snprintf(text, sizeof(text), CONV_FMT, cid);
    } else {
        strncpy(text, "NIL", sizeof(text));
    }

    return text;
}

EXPORTED int conversation_id_decode(conversation_id_t *cid, const char *text)
{
    if (!strcmp(text, "NIL")) {
        *cid = NULLCONVERSATION;
    } else {
        if (strlen(text) != 16) return 0;
        *cid = strtoull(text, 0, 16);
    }
    return 1;
}

static int folder_key_rename(struct conversations_state *state,
                             const char *from_name,
                             const char *to_name)
{
    conv_status_t status;
    int r = conversation_getstatus(state, from_name, &status);
    if (r) return r;

    if (to_name) {
        r = conversation_setstatus(state, to_name, &status);
        if (r) return r;
        return conversation_setstatus(state, from_name, NULL);
    }

    /* you can't delete a folder until the messages are cleared */
    assert(!status.exists);

    return 0;
}

EXPORTED int conversations_rename_folder(struct conversations_state *state,
                                const char *from_name,
                                const char *to_name)
{
    int r;

    assert(from_name);

    r = folder_number_rename(state, from_name, to_name);
    if (r) return r;

    r = folder_key_rename(state, from_name, to_name);
    if (r) return r;

    if (to_name) {
        syslog(LOG_NOTICE, "conversations_rename_folder: renamed %s to %s",
               from_name, to_name);
    }
    else {
        syslog(LOG_NOTICE, "conversations_rename_folder: deleted %s",
               from_name);
    }

    return 0;
}


static int zero_b_cb(void *rock,
                     const char *key,
                     size_t keylen,
                     const char *val,
                     size_t vallen)
{
    struct conversations_state *state = (struct conversations_state *)rock;
    conversation_t *conv = NULL;
    conv_folder_t *folder;
    conv_sender_t *sender;
    int r;
    int i;

    r = conversation_parse(state, val, vallen, &conv);
    if (r) {
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, /*force*/1);
        return r;
    }

    /* leave modseq untouched */
    conv->num_records = 0;
    conv->exists = 0;
    conv->unseen = 0;

    /* zero out all the counted counts */
    if (state->counted_flags) {
        for (i = 0; i < state->counted_flags->count; i++)
            conv->counts[i] = 0;
    }

    for (folder = conv->folders; folder; folder = folder->next) {
        /* keep the modseq */
        folder->num_records = 0;
        folder->exists = 0;
        folder->unseen = 0;
    }

    /* just zero out senders */
    while ((sender = conv->senders)) {
        conv->senders = sender->next;
        free(sender->name);
        free(sender->route);
        free(sender->mailbox);
        free(sender->domain);
        free(sender);
    }

    /* keep the subject of course */

    conv->size = 0;

    r = conversation_store(state, key, keylen, conv);
    conversation_free(conv);

    return r;
}

static int zero_f_cb(void *rock,
                     const char *key,
                     size_t keylen,
                     const char *val,
                     size_t vallen)
{
    struct conversations_state *state = (struct conversations_state *)rock;
    conv_status_t status;
    int r;

    r = conversation_parsestatus(val, vallen, &status);
    if (r) {
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, /*force*/1);
        return r;
    }

    /* leave modseq unchanged */
    status.exists = 0;
    status.unseen = 0;

    return conversation_storestatus(state, key, keylen, &status);
}

static int zero_g_cb(void *rock,
                     const char *key,
                     size_t keylen,
                     const char *val __attribute__((unused)),
                     size_t vallen __attribute__((unused)))
{
    struct conversations_state *state = (struct conversations_state *)rock;
    int r = cyrusdb_delete(state->db, key, keylen, &state->txn, /*force*/1);
    return r;
}

EXPORTED int conversations_zero_counts(struct conversations_state *state)
{
    int r = 0;

    /* wipe B counts */
    r = cyrusdb_foreach(state->db, "B", 1, NULL, zero_b_cb,
                        state, &state->txn);
    if (r) return r;

    /* wipe F counts */
    r = cyrusdb_foreach(state->db, "F", 1, NULL, zero_f_cb,
                        state, &state->txn);
    if (r) return r;

    /* wipe G keys (there's no modseq kept, so we can just wipe them) */
    r = cyrusdb_foreach(state->db, "G", 1, NULL, zero_g_cb,
                        state, &state->txn);
    if (r) return r;

    /* re-init the counted flags */
    r = _init_counted(state, NULL, 0);
    if (r) return r;

    return r;
}

static int cleanup_b_cb(void *rock,
                        const char *key,
                        size_t keylen,
                        const char *val,
                        size_t vallen)
{
    struct conversations_state *state = (struct conversations_state *)rock;
    conversation_t *conv = NULL;
    int r;

    r = conversation_parse(state, val, vallen, &conv);
    if (r) return r;

    /* should be gone, wipe it */
    if (!conv->num_records)
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, 1);

    conversation_free(conv);

    return r;
}

EXPORTED int conversations_cleanup_zero(struct conversations_state *state)
{
    /* check B counts */
    return cyrusdb_foreach(state->db, "B", 1, NULL, cleanup_b_cb,
                           state, &state->txn);
}

EXPORTED void conversations_dump(struct conversations_state *state, FILE *fp)
{
    cyrusdb_dumpfile(state->db, "", 0, fp, &state->txn);
}

EXPORTED int conversations_truncate(struct conversations_state *state)
{
    return cyrusdb_truncate(state->db, &state->txn);
}

EXPORTED int conversations_undump(struct conversations_state *state, FILE *fp)
{
    return cyrusdb_undumpfile(state->db, fp, &state->txn);
}



#undef DB
