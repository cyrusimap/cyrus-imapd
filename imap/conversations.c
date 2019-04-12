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
#include <sysexits.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "bsearch.h"
#include "charset.h"
#include "crc32.h"
#include "dlist.h"
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
#include "sync_log.h"
#include "syslog.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "xstats.h"
#include "times.h"
#include "vparse.h"
#include "vcard_support.h"

#include "conversations.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define CONVERSATION_ID_STRMAX      (1+sizeof(conversation_id_t)*2)

/* per user conversations db extension */
#define FNAME_CONVERSATIONS_SUFFIX "conversations"
#define FNKEY "$FOLDER_NAMES"
#define FIKEY "$FOLDER_IDS"
#define CFKEY "$COUNTED_FLAGS"
#define CONVSPLITFOLDER "#splitconversations"

#define DB config_conversations_db

struct conversations_open {
    struct conversations_state s;
    struct mboxlock *local_namespacelock;
    struct conversations_open *next;
};

static struct conversations_open *open_conversations;

static conv_status_t NULLSTATUS = CONV_STATUS_INIT;

static char *convdir = NULL;
static char *suffix = NULL;

static int check_msgid(const char *msgid, size_t len, size_t *lenp);
static int _conversations_parse(const char *data, size_t datalen,
                                arrayu64_t *cids, time_t *stampp);
static int _conversations_set_key(struct conversations_state *state,
                                  const char *key, size_t keylen,
                                  const arrayu64_t *cids, time_t stamp);

static void _conv_remove(struct conversations_state *state);

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
        if (vallen && !state->is_shared) {
            r = cyrusdb_store(state->db, CFKEY, strlen(CFKEY),
                    val, vallen, &state->txn);
            if (r) {
                syslog(LOG_ERR, "Failed to write counted_flags");
                return r;
            }
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
        if (state->counted_flags->count > 32) {
            syslog(LOG_ERR, "conversations: truncating counted_flags: %d (%.*s)",
                            state->counted_flags->count, vallen, val);
            strarray_truncate(state->counted_flags, 32);
        }
    }

    return 0;
}

int _saxfolder(int type, struct dlistsax_data *d)
{
    strarray_t *list = (strarray_t *)d->rock;
    if (type == DLISTSAX_STRING)
        strarray_append(list, d->data);
    return 0;
}

static int write_folders(struct conversations_state *state)
{
    struct dlist *dl = dlist_newlist(NULL, NULL);
    struct buf buf = BUF_INITIALIZER;
    int r;
    int i;

    for (i = 0; i < state->folders->count; i++) {
        const char *fname = strarray_nth(state->folders, i);
        dlist_setatom(dl, NULL, fname);
    }

    dlist_printbuf(dl, 0, &buf);
    dlist_free(&dl);

    const char *key = state->folders_byname ? FNKEY : FIKEY;
    r = cyrusdb_store(state->db, key, strlen(key),
                      buf.s, buf.len, &state->txn);

    buf_free(&buf);

    return r;
}

EXPORTED int conversation_folder_number(struct conversations_state *state,
                         const char *folder,
                         int create_flag)
{
    int pos = strarray_find(state->folders, folder, 0);
    int r;

    /* if we have to add it, then save the keys back */
    if (pos < 0 && create_flag) {
        /* replace the first unused if there is one */
        pos = strarray_find(state->folders, "-", 0);
        if (pos >= 0)
            strarray_set(state->folders, pos, folder);
        /* otherwise append */
        else
            pos = strarray_append(state->folders, folder);

        /* track the Trash folder number as it's added */
        if (!strcmpsafe(name, state->trashmboxname))
            state->trashfolder = pos;

        /* store must succeed */
        r = write_folders(state);
        if (r) abort();
    }

    return pos;
}

EXPORTED int conversations_num_folders(struct conversations_state *state)
{
    return strarray_size(state->folder_ids);
}

EXPORTED const char* conversations_folder_id(struct conversations_state *state,
                                             int foldernum)
{
    return strarray_safenth(state->folder_ids, foldernum);
}

EXPORTED size_t conversations_estimate_emailcount(struct conversations_state *state)
{
    int i;
    size_t count = 0;
    conv_status_t status;
    for (i = 0; i < strarray_size(state->folder_ids); i++) {
        const char *mboxid = strarray_nth(state->folder_ids, i);
        int r = conversation_getstatus(state, mboxid, &status);
        if (r) continue;
        count += status.emailexists;
    }
    return count;
}

EXPORTED int conversations_open_path(const char *fname, const char *userid, int shared,
                                     struct conversations_state **statep)
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
        syslog(LOG_NOTICE, "conversations_open_path: opening %s over %s", fname, open->s.path);
    }

    open = xzmalloc(sizeof(struct conversations_open));
    open->s.is_shared = shared;
    open->s.path = xstrdup(fname);
    open->next = open_conversations;
    open_conversations = open;

    /* first ensure that the usernamespace is locked */
    if (userid) {
        int haslock = user_isnamespacelocked(userid);
        if (haslock) {
            if (!shared) assert(haslock != LOCK_SHARED);
        }
        else {
            int locktype = shared ? LOCK_SHARED : LOCK_EXCLUSIVE;
            open->local_namespacelock = user_namespacelock_full(userid, locktype);
        }
    }

    /* open db */
    int flags = CYRUSDB_CREATE | (shared ? (CYRUSDB_SHARED|CYRUSDB_NOCRC) : CYRUSDB_CONVERT);
    r = cyrusdb_lockopen(DB, fname, flags, &open->s.db, &open->s.txn);
    if (r || open->s.db == NULL) {
        _conv_remove(&open->s);
        return IMAP_IOERROR;
    }

    /* load or initialize counted flags */
    cyrusdb_fetch(open->s.db, CFKEY, strlen(CFKEY), &val, &vallen, &open->s.txn);
    r = _init_counted(&open->s, val, vallen);
    if (r) {
        cyrusdb_abort(open->s.db, open->s.txn);
        _conv_remove(&open->s);
        return r;
    }

    /* we should just read the folder names up front too */
    open->s.folders = strarray_new();

    /* if there's a value, parse as a dlist */
    vallen = 0;
    r = cyrusdb_fetch(open->s.db, FIKEY, strlen(FIKEY),
                      &val, &vallen, &open->s.txn);
    if (r == CYRUSDB_NOTFOUND) {
        vallen = 0;
        r = cyrusdb_fetch(open->s.db, FNKEY, strlen(FNKEY),
                          &val, &vallen, &open->s.txn);
        if (!r) open->s.folders_byname = 1;
    }
    if (!r) {
        dlist_parsesax(val, vallen, 0, _saxfolder, open->s.folders);
    }

    if (userid)
        open->s.annotmboxname = mboxname_user_mbox(userid, CONVSPLITFOLDER);
    else
        open->s.annotmboxname = xstrdup(CONVSPLITFOLDER);

    char *trashmboxname = mboxname_user_mbox(userid, "Trash");
    open->s.trashfolder = conversation_folder_number(&open->s, trashmboxname, /*create*/0);
    open->s.trashmboxname = trashmboxname;

    /* create the status cache */
    construct_hash_table(&open->s.folderstatus, strarray_size(open->s.folders)/4+4, 0);

    *statep = &open->s;

    return 0;
}

EXPORTED int conversations_open_user(const char *userid, int shared,
                                     struct conversations_state **statep)
{
    char *path = conversations_getuserpath(userid);
    int r;
    if (!path) return IMAP_MAILBOX_BADNAME;
    r = conversations_open_path(path, userid, shared, statep);
    free(path);
    return r;
}

EXPORTED int conversations_open_mbox(const char *mboxname, int shared, struct conversations_state **statep)
{
    char *path = conversations_getmboxpath(mboxname);
    int r;
    if (!path) return IMAP_MAILBOX_BADNAME;
    char *userid = mboxname_to_userid(mboxname);
    r = conversations_open_path(path, userid, shared, statep);
    free(userid);
    free(path);
    return r;
    return 0;
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
            free(cur->s.annotmboxname);
            free(cur->s.path);
            free(cur->s.trashmboxname);
            if (cur->s.counted_flags)
                strarray_free(cur->s.counted_flags);
            if (cur->s.folders)
                strarray_free(cur->s.folders);
            if (cur->local_namespacelock)
                mboxname_release(&cur->local_namespacelock);
            free(cur);
            return;
        }
        prevp = &cur->next;
    }

    fatal("unknown conversation db closed", EX_SOFTWARE);
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
    mboxname_setmodseq(key+1, status->threadmodseq, /*mbtype */0, /*flags*/0);
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

static int _write_quota(struct conversations_state *state);
EXPORTED int conversations_commit(struct conversations_state **statep)
{
    struct conversations_state *state = *statep;
    int r = 0;

    if (!state) return 0;

    *statep = NULL;

    /* commit cache, writes to to DB */
    conversations_commitcache(state);

    r = _write_quota(state);
    if (r) return r;

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

    if (msgid[0] != '<' || msgid[len-1] != '>' || len < 3)
        return IMAP_INVALID_IDENTIFIER;

#if 0  /* XXX  This check results in messages with invalid Message-ID
          to be threadid incorrectly. */
    /* Leniently accept msg-id without @, but refuse multiple @ */
    if (memchr(msgid, '@', len) != memrchr(msgid, '@', len))
        return IMAP_INVALID_IDENTIFIER;
#endif

    /* Leniently accept specials, but refuse the outright broken */
    size_t i;
    for (i = 1; i < len - 1; i++) {
        if (!isprint(msgid[i]) || isspace(msgid[i]))
            return IMAP_INVALID_IDENTIFIER;
    }

    if (lenp)
        *lenp = len;

    return 0;
}

EXPORTED int conversations_check_msgid(const char *msgid, size_t len)
{
    return check_msgid(msgid, len, NULL);
}

static int _conversations_set_key(struct conversations_state *state,
                                  const char *key, size_t keylen,
                                  const arrayu64_t *cids, time_t stamp)
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    int version = CONVERSATIONS_KEY_VERSION;
    size_t i;

    /* XXX: should this be a delete operation? */
    assert(cids->count);

    if (state->db == NULL)
        return IMAP_IOERROR;

    buf_printf(&buf, "%d ", version);
    for (i = 0; i < cids->count; i++) {
        conversation_id_t cid = arrayu64_nth(cids, i);
        if (i) buf_putc(&buf, ',');
        buf_printf(&buf, CONV_FMT, cid);
    }
    buf_printf(&buf, " " TIME_T_FMT, stamp);

    r = cyrusdb_store(state->db,
                      key, keylen,
                      buf.s, buf.len,
                      &state->txn);

    buf_free(&buf);
    if (r)
        return IMAP_IOERROR;

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

    r = parsenum(data, &rest, datalen, &version);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ')
        return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_KEY_VERSION) {
        /* XXX - an error code for "incorrect version"? */
        return IMAP_MAILBOX_BADFORMAT;
    }

    if (restlen < 17)
        return IMAP_MAILBOX_BADFORMAT;

    while (1) {
        r = parsehex(rest, &rest, 16, &cid);
        if (r) return IMAP_MAILBOX_BADFORMAT;
        if (cids) arrayu64_append(cids, cid);
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

    if (r == CYRUSDB_NOTFOUND)
        return 0; /* not an error, but nothing more to do */

    /* make sure we don't leak old data */
    arrayu64_truncate(cids, 0);

    if (!r) r = _conversations_parse(data, datalen, cids, NULL);

    if (r) arrayu64_truncate(cids, 0);

    return r;
}

/*
 * Normalise a subject string, to a form which can be used for deciding
 * whether a message belongs in the same conversation as it's antecedent
 * messages.
 */
EXPORTED void conversation_normalise_subject(struct buf *s)
{
    static int initialised_res = 0;
    static regex_t whitespace_re;
    static regex_t bracket_re;
    static regex_t relike_token_re;
    int r;

    if (!initialised_res) {
        r = regcomp(&whitespace_re, "([ \t\r\n]+|\xC2\xA0)", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&bracket_re, "(\\[[^]\\[]*])|(^[^\\[]*])|(\\[[^]]*$)", REG_EXTENDED);
        assert(r == 0);
        r = regcomp(&relike_token_re, "^[ \\t]*[^ \\t\\r\\n\\f]+:", REG_EXTENDED);
        assert(r == 0);
        initialised_res = 1;
    }

    /* step 1 is to remove anything within (maybe unmatched) square brackets */
    while (buf_replace_one_re(s, &bracket_re, NULL))
        ;

    /* step 2 is to eliminate all "Re:"-like tokens */
    while (buf_replace_one_re(s, &relike_token_re, NULL))
        ;

    /* step 3 is eliminating whitespace. */
    buf_replace_all_re(s, &whitespace_re, NULL);
}

static int folder_number_rename(struct conversations_state *state,
                                const char *from_name,
                                const char *to_name)
{
    /* Do nothing if using folder ids */
    if (to_name && !state->folders_byname) return 0;

    int pos = strarray_find(state->folders, from_name, 0);

    if (pos < 0) return 0; /* nothing to do! */

    /* replace the name  - set to '-' if deleted */
    strarray_set(state->folders, pos, to_name ? to_name : "-");

    return write_folders(state);
}

EXPORTED int conversation_storestatus(struct conversations_state *state,
                                      const char *key, size_t keylen,
                                      const conv_status_t *status)
{
    if (!status || !status->threadmodseq) {
        return cyrusdb_delete(state->db,
                              key, keylen,
                              &state->txn, /*force*/1);
    }

    struct dlist *dl = dlist_newlist(NULL, NULL);
    dlist_setnum64(dl, "THREADMODSEQ", status->threadmodseq);
    dlist_setnum32(dl, "THREADEXISTS", status->threadexists);
    dlist_setnum32(dl, "THREADUNSEEN", status->threadunseen);
    dlist_setnum32(dl, "EMAILEXISTS", status->emailexists);
    dlist_setnum32(dl, "EMAILUNSEEN", status->emailunseen);

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%d ", CONVERSATIONS_STATUS_VERSION);
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
                                    const char *mailbox,
                                    const conv_status_t *status)
{
    char *key = strconcat("F", mailbox, (char *)NULL);
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

static void conv_to_buf(conversation_t *conv, struct buf *buf, int flagcount)
{
    struct dlist *dl, *n, *nn;
    const conv_folder_t *folder;
    const conv_sender_t *sender;
    const conv_thread_t *thread;
    int i;

    dl = dlist_newlist(NULL, NULL);
    dlist_setnum64(dl, "MODSEQ", conv->modseq);
    dlist_setnum32(dl, "NUMRECORDS", conv->num_records);
    dlist_setnum32(dl, "EXISTS", conv->exists);
    dlist_setnum32(dl, "UNSEEN", conv->unseen);
    n = dlist_newlist(dl, "COUNTS");
    for (i = 0; i < flagcount; i++) {
        dlist_setnum32(n, "flag", conv->counts[i]);
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
    }

    dlist_setnum64(dl, "CREATEDMODSEQ", conv->createdmodseq);

    buf_printf(buf, "%d ", conv->version);
    dlist_printbuf(dl, 0, buf);
    dlist_free(&dl);
}

EXPORTED int conversation_store(struct conversations_state *state,
                       const char *key, int keylen,
                       conversation_t *conv)
{
    struct buf buf = BUF_INITIALIZER;

    conv_to_buf(conv, &buf, state->counted_flags ? state->counted_flags->count : 0);

    int r = cyrusdb_store(state->db, key, keylen, buf.s, buf.len, &state->txn);

    buf_free(&buf);

    return r;
}

static void _apply_delta(uint32_t *valp, ssize_t delta)
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

static int _read_quota(struct conversations_state *state)
{
    const char *data = NULL;
    size_t datalen = 0;
    bit64 val = 0;
    int r = cyrusdb_fetch(state->db, "Q", 1, &data, &datalen, &state->txn);
    if (r) return r;
    if (datalen) {
        const char *rest;
        if (datalen < 12) return IMAP_MAILBOX_BADFORMAT;
        if (memcmp(data, "1 %(E ", 6)) return IMAP_MAILBOX_BADFORMAT;
        r = parsenum(data+6, &rest, datalen-6, &val);
        if (r) return r;

        state->quota.emails = val;

        datalen -= (rest - data);
        data = rest;
        if (datalen < 5) return IMAP_MAILBOX_BADFORMAT;
        if (memcmp(data, " S ", 3)) return IMAP_MAILBOX_BADFORMAT;
        r = parsenum(data+3, &rest, datalen-3, &val);
        if (r) return r;

        state->quota.storage = val;

        datalen -= (rest - data);
        if (datalen != 1) return IMAP_MAILBOX_BADFORMAT;
        if (*rest != ')') return IMAP_MAILBOX_BADFORMAT;
        return 0;
    }
    return CYRUSDB_NOTFOUND;
}

static int _write_quota(struct conversations_state *state)
{
    if (!state->quota_dirty) return 0;

    ssize_t emails = state->quota.emails;
    ssize_t storage = state->quota.storage;

    // can't go negative (could happen before a rebuild)
    if (emails < 0 || storage < 0) {
        syslog(LOG_ERR, "IOERROR: conversations_audit on quota store: %s (%lld %lld)",
               state->path, (long long)emails, (long long)storage);
        emails = 0;
        storage = 0;
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "1 %%(E %lld S %lld)", (long long)emails, (long long)storage);
    int r = cyrusdb_store(state->db, "Q", 1, buf.s, buf.len, &state->txn);
    buf_free(&buf);

    return r;
}

EXPORTED int conversations_read_quota(struct conversations_state *state, struct conv_quota *q)
{
    if (!state->quota_loaded) {
        memset(&state->quota, 0, sizeof(struct conv_quota));
        int r = _read_quota(state);
        if (r && r != CYRUSDB_NOTFOUND) return r;
        state->quota_loaded = 1;
    }
    if (q) *q = state->quota;
    return 0;
}

static int _update_quotaused(struct conversations_state *state, int existsdiff, ssize_t quotadiff)
{
    // no change?  No worries
    if (!existsdiff && !quotadiff) return 0;

    int r = conversations_read_quota(state, NULL);
    if (r) return r;

    state->quota.emails += existsdiff;
    state->quota.storage += quotadiff;
    state->quota_dirty = 1; // write on commit

    return 0;
}

static int _conversation_save(struct conversations_state *state,
                              const char *key, int keylen,
                              conversation_t *conv)
{
    int r;

    if (conv->num_records) {
        r = conversation_store(state, key, keylen, conv);
    }
    else {
        /* last existing record removed - clean up the 'B' record */
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, 1);
    }

    if (!r)
        conv->flags &= ~CONV_ISDIRTY;

    return r;
}

EXPORTED int conversation_save(struct conversations_state *state,
                      conversation_id_t cid,
                      conversation_t *conv)
{
    char bkey[CONVERSATION_ID_STRMAX+2];

    if (!conv)
        return IMAP_INTERNAL;
    if (!(conv->flags & CONV_ISDIRTY))
        return 0;

    /* old pre-conversations message, nothing to do */
    if (!cid)
        return 0;
    xstats_inc(CONV_SAVE);

    snprintf(bkey, sizeof(bkey), "B" CONV_FMT, cid);

    return _conversation_save(state, bkey, strlen(bkey), conv);
}

struct convstatusrock {
    conv_status_t *status;
    int state;
};

int _saxconvstatus(int type, struct dlistsax_data *d)
{
    struct convstatusrock *rock = (struct convstatusrock *)d->rock;
    if (type != DLISTSAX_STRING) return 0;
    switch (rock->state) {
    case 0:
        rock->status->threadmodseq = atomodseq_t(d->data);
        rock->state++;
        return 0;
    case 1:
        rock->status->threadexists = atol(d->data);
        rock->state++;
        return 0;
    case 2:
        rock->status->threadunseen = atol(d->data);
        rock->state++;
        return 0;
    case 3:
        rock->status->emailexists = atol(d->data);
        rock->state++;
        return 0;
    case 4:
        rock->status->emailunseen = atol(d->data);
        rock->state++;
        return 0;
    }
    return IMAP_MAILBOX_BADFORMAT;
}

EXPORTED int conversation_parsestatus(const char *data, size_t datalen,
                                      conv_status_t *status)
{
    struct convstatusrock rock = { status, 0 };
    bit64 version;
    const char *rest;
    size_t restlen;
    int r;

    status->threadmodseq = 0;
    status->threadexists = 0;
    status->threadunseen = 0;
    status->emailexists = 0;
    status->emailunseen = 0;

    r = parsenum(data, &rest, datalen, &version);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ')
        return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_STATUS_VERSION) {
        /* XXX - an error code for "incorrect version"? */
        return IMAP_MAILBOX_BADFORMAT;
    }

    return dlist_parsesax(rest, restlen, 0, _saxconvstatus, &rock);
}

EXPORTED int conversation_getstatus(struct conversations_state *state,
                                    const char *mailbox,
                                    conv_status_t *status)
{
    char *key = strconcat("F", mailbox, (char *)NULL);
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
        syslog(LOG_ERR, "IOERROR: conversations invalid status %s", mailbox);

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
    conv->flags |= CONV_ISDIRTY;

    return folder;
}

struct convparserock {
    conversation_t *conv;
    strarray_t strs;
    conv_folder_t *folder;
    conv_thread_t *thread;
    conv_thread_t **nextthread;
    int state;
    int substate;
    int flags;
};

int _saxconvparse(int type, struct dlistsax_data *d)
{
    struct convparserock *rock = (struct convparserock *)d->rock;
    switch (rock->state) {
    case 0:
        // initial dlist start
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 1;
        return 0;

    case 1:
        // modseq
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->modseq = atomodseq_t(d->data);
        rock->state = 2;
        return 0;

    case 2:
        // num_records
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->num_records = atol(d->data);
        rock->state = 3;
        return 0;

    case 3:
        // exists
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->exists = atol(d->data);
        rock->state = 4;
        return 0;

    case 4:
        // unseen
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->unseen = atol(d->data);
        rock->state = 5;
        return 0;

    case 5:
        // enter flagcounts
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 6;
        return 0;

    case 6:
        if (type == DLISTSAX_LISTEND) {
            // end of flagcounts
            rock->substate = 0;
            rock->state = 7;
            return 0;
        }
        // inside flagcounts
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->counts[rock->substate++] = atol(d->data);
        return 0;

    case 7:
        // start of folders list
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 8;
        return 0;

    case 8:
        if (type == DLISTSAX_LISTEND) {
            rock->state = 10; // finished folders list
            return 0;
        }
        // start of individual folder info
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 9;
        return 0;

    case 9:
        if (type == DLISTSAX_LISTEND) {
            rock->substate = 0;
            rock->state = 8; // back to folders list state
            return 0;
        }
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        if (!(rock->flags & CONV_WITHFOLDERS)) return 0;
        switch (rock->substate) {
        case 0:
            rock->folder = conversation_get_folder(rock->conv, atol(d->data), 1);
            rock->substate = 1;
            return 0;
        case 1:
            rock->folder->modseq = atomodseq_t(d->data);
            rock->substate = 2;
            return 0;
        case 2:
            rock->folder->num_records = atol(d->data);
            rock->substate = 3;
            return 0;
        case 3:
            rock->folder->exists = atol(d->data);
            rock->substate = 4;
            return 0;
        case 4:
            rock->folder->unseen = atol(d->data);
            rock->substate = 5;
            return 0;
        }
        return IMAP_MAILBOX_BADFORMAT;

    case 10:
        // start senders list
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 11;
        return 0;

    case 11:
        if (type == DLISTSAX_LISTEND) {
            // end of senders list
            rock->state = 13;
            return 0;
        }
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 12;
        return 0;

    case 12:
        // individual sender items
        if (type == DLISTSAX_LISTEND) {
            if (rock->flags & CONV_WITHSENDERS) {
                conversation_update_sender(rock->conv,
                                           strarray_nth(&rock->strs, 0),
                                           strarray_nth(&rock->strs, 1),
                                           strarray_nth(&rock->strs, 2),
                                           strarray_nth(&rock->strs, 3),
                                           atol(strarray_nth(&rock->strs, 4)),
                                           atol(strarray_nth(&rock->strs, 5)));
                strarray_fini(&rock->strs);
            }
            rock->substate = 0;
            rock->state = 11; // drop back to senders list
            return 0;
        }
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        if (rock->flags & CONV_WITHSENDERS)
            strarray_set(&rock->strs, rock->substate++, d->data);
        return 0;

    case 13:
        // encoded subject
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        if (rock->flags & CONV_WITHSUBJECT)
            rock->conv->subject = xstrdupnull(d->data);
        rock->state = 14;
        return 0;

    case 14:
        if (type == DLISTSAX_LISTEND) {
            rock->state = 20; // finish early
            return 0;
        }
        // conversation size
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->size = atol(d->data);
        rock->state = 15;
        return 0;

    case 15:
        if (type == DLISTSAX_LISTEND) {
            rock->state = 20; // finish early
            return 0;
        }
        // start thread list
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 16;
        rock->nextthread = &rock->conv->thread;
        return 0;

    case 16:
        if (type == DLISTSAX_LISTEND) {
            // end of thread list
            rock->state = 18;
            return 0;
        }
        if (type != DLISTSAX_LISTSTART) return IMAP_MAILBOX_BADFORMAT;
        if (rock->flags & CONV_WITHTHREAD)
            rock->thread = xzmalloc(sizeof(conv_thread_t));
        rock->state = 17;
        return 0;

    case 17:
        if (type == DLISTSAX_LISTEND) {
            // end of individual thread
            if (rock->flags & CONV_WITHTHREAD) {
                *rock->nextthread = rock->thread;
                rock->nextthread = &rock->thread->next;
                rock->thread = NULL;
            }
            rock->substate = 0;
            rock->state = 16;
            return 0;
        }
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        if (!(rock->flags & CONV_WITHTHREAD)) return 0;
        switch (rock->substate) {
        case 0:
            message_guid_decode(&rock->thread->guid, d->data);
            rock->substate = 1;
            return 0;

        case 1:
            rock->thread->exists = atol(d->data);
            rock->substate = 2;
            return 0;

        case 2:
            rock->thread->internaldate = atol(d->data);
            rock->substate = 3;
            return 0;
        }
        return 0; // there might be following fields that we ignore here

    case 18:
        if (type == DLISTSAX_LISTEND) {
            rock->state = 20; // finish early
            return 0;
        }
        if (type != DLISTSAX_STRING) return IMAP_MAILBOX_BADFORMAT;
        rock->conv->createdmodseq = atomodseq_t(d->data);
        rock->state = 19;
        return 0;

    case 19:
        if (type != DLISTSAX_LISTEND) return IMAP_MAILBOX_BADFORMAT;
        rock->state = 20;
        return 0;

    }

    // we should finish at createdmodseq
    return IMAP_MAILBOX_BADFORMAT;
}

EXPORTED int conversation_parse(const char *data, size_t datalen,
                                conversation_t *conv, int flags)
{
    const char *rest;
    int restlen;
    bit64 version;
    int r;

    r = parsenum(data, &rest, datalen, &version);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ') return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version > CONVERSATIONS_RECORD_VERSION) return IMAP_MAILBOX_BADFORMAT;

    struct convparserock rock = { conv, STRARRAY_INITIALIZER,
                                  NULL, NULL, NULL, 0, 0, flags };

    r = dlist_parsesax(rest, restlen, 0, _saxconvparse, &rock);
    if (r) return r;

    conv->flags = flags;
    conv->version = version;

    return 0;
}


EXPORTED int conversation_load_advanced(struct conversations_state *state,
                      conversation_id_t cid,
                      conversation_t *conv,
                      int flags)
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
        return IMAP_MAILBOX_NONEXISTENT;
    } else if (r != CYRUSDB_OK) {
        return IMAP_INTERNAL;
    }
    xstats_inc(CONV_LOAD);

    r = conversation_parse(data, datalen, conv, flags);

    if (r) {
        syslog(LOG_ERR, "IOERROR: conversations_audit parse error: %s %s %.*s",
               state->path, bkey, (int)datalen, data);
    }

    return r;
}

EXPORTED int conversation_load(struct conversations_state *state,
                      conversation_id_t cid,
                      conversation_t **convp)
{
    // we'll malloc one
    conversation_t *conv = conversation_new();
    int r = conversation_load_advanced(state, cid, conv, CONV_WITHALL);
    if (r) {
        // we still return success, just don't have any data
        conversation_free(conv);
        *convp = NULL;
    }
    else {
        *convp = conv;
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
    if (r || version > CONVERSATIONS_RECORD_VERSION)
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
    int number = conversation_folder_number(state, mboxname, /*create*/0);
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
     * capital letters, which is an arbitrary aesthetic */
    return strcmpsafe(a, b);
}

/* Choose a preferred domain. Returns <0 if @a is preferred,
 * 0 if we don't care, and >0 if @b is preferred */
static int sender_preferred_domain(const char *a, const char *b)
{
    /* choosing the lexically earlier string tends to keep
     * capital letters, which is an arbitrary aesthetic */
    return strcmpsafe(a, b);
}

/* Choose a preferred route. Returns <0 if @a is preferred,
 * 0 if we don't care, and >0 if @b is preferred */
static int sender_preferred_route(const char *a, const char *b)
{
    /* choosing the lexically earlier string tends to keep
     * capital letters, which is an arbitrary aesthetic */
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

static int _thread_datesort(const void **a, const void **b)
{
    const conv_thread_t *ta = (const conv_thread_t *)*a;
    const conv_thread_t *tb = (const conv_thread_t *)*b;

    int r = (ta->internaldate - tb->internaldate);
    if (r < 0) return -1;
    if (r > 0) return 1;

    return message_guid_cmp(&ta->guid, &tb->guid);
}

static void conversations_thread_sort(conversation_t *conv)
{
    conv_thread_t *thread;
    ptrarray_t items = PTRARRAY_INITIALIZER;

    for (thread = conv->thread; thread; thread = thread->next) {
        ptrarray_append(&items, thread);
    }

    ptrarray_sort(&items, _thread_datesort);

    conv_thread_t **nextp = &conv->thread;

    // relink the list
    int i;
    for (i = 0; i < ptrarray_size(&items); i++) {
        thread = ptrarray_nth(&items, i);
        *nextp = thread;
        nextp = &thread->next;
    }

    // finish the list
    *nextp = NULL;

    ptrarray_fini(&items);
}

static void conversation_update_thread(conversation_t *conv,
                                       const struct message_guid *guid,
                                       time_t internaldate,
                                       int delta_exists)
{
    conv_thread_t *thread, **nextp = &conv->thread;

    for (thread = conv->thread; thread; thread = thread->next) {
        /* does it already exist? */
        if (message_guid_equal(guid, &thread->guid))
            break;
        nextp = &thread->next;
    }

    if (!thread) {
        if (delta_exists <= 0) return; // no thread and no count, skip
        thread = xzmalloc(sizeof(*thread));
        *nextp = thread;
    }
    else if (thread->exists + delta_exists <= 0) {
        /* we're just removing the thread, this is always sort-safe */
        *nextp = thread->next;
        free(thread);
        conv->flags |= CONV_ISDIRTY;
        return;
    }

    message_guid_copy(&thread->guid, guid);
    thread->internaldate = internaldate;
    _apply_delta(&thread->exists, delta_exists);

    conversations_thread_sort(conv);
    // if we've sorted, it's probably dirty
    conv->flags |= CONV_ISDIRTY;
}

EXPORTED void conversation_update_sender(conversation_t *conv,
                                         const char *name,
                                         const char *route,
                                         const char *mailbox,
                                         const char *domain,
                                         time_t lastseen,
                                         ssize_t delta_exists)
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
        conv->flags |= CONV_ISDIRTY;
        free(sender->name);
        free(sender->route);
        free(sender->mailbox);
        free(sender->domain);
        free(sender);
        return;
    }

    /* otherwise update the counter */
    _apply_delta(&sender->exists, delta_exists);

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
        sender->mailbox = xstrdupnull(mailbox);
    }

    if (!sender->domain || sender_preferred_domain(sender->domain, domain) > 0) {
        free(sender->domain);
        sender->domain = xstrdupnull(domain);
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

    conv->flags |= CONV_ISDIRTY;
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
    const void *filterdata;
    int filternum;
    int filterpos;
    struct buf partbuf;
};

static int _guid_one(struct guid_foreach_rock *frock,
                     const char *key,
                     conversation_id_t cid,
                     uint32_t system_flags,
                     uint32_t internal_flags,
                     time_t internaldate,
                     char version)
{
    const char *p, *err;
    conv_guidrec_t rec;
    uint32_t res;

    /* Set G record values */
    rec.guidrep = key+1;
    rec.cid = cid;
    rec.system_flags = system_flags;
    rec.internal_flags = internal_flags;
    rec.internaldate = internaldate;
    rec.version = version;

    /* ensure a NULL terminated key string */
    buf_cstring(&frock->partbuf);
    char *item = frock->partbuf.s;

    /* Parse G record key */
    p = strchr(item, ':');
    if (!p) return IMAP_INTERNAL;

    /* mboxname */
    int r = parseuint32(item, &err, &res);
    if (r || err != p) return IMAP_INTERNAL;
    rec.foldernum = res;
    rec.mailbox = strarray_safenth(frock->state->folders, res);
    if (!rec.mailbox) return IMAP_INTERNAL;

    /* uid */
    r = parseuint32(p + 1, &err, &res);
    if (r) return IMAP_INTERNAL;
    rec.uid = res;
    p = err;

    /* part */
    rec.part = NULL;
    if (*p) {
        char *end = strchr(p+1, ']');
        if (*p != '[' || !end || p+1 == end) {
            return IMAP_INTERNAL;
        }
        // overwrite the end of the part in the buffer buffer to avoid double-dupe
        *end = '\0';
        rec.part = p+1;
    }

    r = frock->cb(&rec, frock->cbrock);
    return r;
}

static int _guid_filter_p(void *rock,
                          const char *key,
                          size_t keylen,
                          const char *data __attribute__((unused)),
                          size_t datalen __attribute__((unused)))
{
    if (keylen < 41) return 0; // bogus record??

    struct guid_foreach_rock *frock = (struct guid_foreach_rock *)rock;

    for (; frock->filterpos < frock->filternum; frock->filterpos++) {
        int cmp = memcmp(frock->filterdata + (41 * frock->filterpos), key+1, 40);
        if (cmp > 0) break; // definitely not a match
        if (cmp == 0) return 1; // match.
        /* We don't also increment for a match because multiple rows
         * could have the same GUID */
    }

    return 0;  // no match
}

static int _guid_cb(void *rock,
                    const char *key,
                    size_t keylen,
                    const char *data,
                    size_t datalen)
{
    struct guid_foreach_rock *frock = (struct guid_foreach_rock *)rock;
    int r = 0;

    if (keylen < 41)
        return IMAP_INTERNAL;

    // oldstyle key
    if (keylen == 41) {
        strarray_t *recs = strarray_nsplit(data, datalen, ",", /*flags*/0);
        int i;
        for (i = 0; i < recs->count; i++) {
            buf_setcstr(&frock->partbuf, strarray_nth(recs, i));
            r = _guid_one(frock, key, /*cid*/0,
                          /*system_flags*/0, /*internal_flags*/0,
                          /*internaldate*/0, /*version*/0);
            if (r) break;
        }
        strarray_free(recs);
        return r;
    }

    // newstyle key
    if (key[41] != ':')
        return IMAP_INTERNAL;

    conversation_id_t cid = 0;
    uint32_t system_flags = 0;
    uint32_t internal_flags = 0;
    time_t internaldate = 0;
    char version = 0;
    if (datalen >= 16) {
        const char *p = data;

        /* version */
        if (*p & 0x80) version = *p & 0x7f;
        if (version > 0) p++;

        if (version == 0) {
            /* cid */
            r = parsehex(p, &p, 16, &cid);
            if (r) return r;
        }
        else {
            /* cid */
            cid = ntohll(*((bit64*)p));
            p += 8;
            /* system_flags */
            system_flags = ntohl(*((bit32*)p));
            p += 4;
            /* internal flags */
            internal_flags = ntohl(*((bit32*)p));
            p += 4;
            /* internaldate*/
            internaldate = (time_t) ntohll(*((bit64*)p));
            p += 8;
        }
    }

    buf_setmap(&frock->partbuf, key+42, keylen-42);
    r = _guid_one(frock, key, cid, system_flags, internal_flags,
                  internaldate, version);

    return r;
}

static int _guid_foreach_helper(struct conversations_state *state,
                                const char *prefix,
                                int(*cb)(const conv_guidrec_t *, void *),
                                void *cbrock,
                                const void *data,
                                size_t num)
{
    struct guid_foreach_rock rock = {
        state, cb, cbrock, data, num, 0, BUF_INITIALIZER
    };

    foreach_p *filter = data ? _guid_filter_p : NULL;

    char *key = strconcat("G", prefix, (char *)NULL);
    int r = cyrusdb_foreach(state->db, key, strlen(key), filter, _guid_cb, &rock, &state->txn);
    free(key);

    buf_free(&rock.partbuf);

    return r;
}

EXPORTED int conversations_guid_foreach(struct conversations_state *state,
                                        const char *guidrep,
                                        int(*cb)(const conv_guidrec_t *, void *),
                                        void *cbrock)
{
    return _guid_foreach_helper(state, guidrep, cb, cbrock, NULL, 0);
}

EXPORTED int conversations_iterate_searchset(struct conversations_state *state,
                                             const void *data, size_t n,
                                             int(*cb)(const conv_guidrec_t*,void*),
                                             void *cbrock)
{
    // magic number to switch from index mode to scan mode
    size_t limit = config_getint(IMAPOPT_SEARCH_QUERYSCAN);
    if (limit && n > limit) {
        size_t estimate = conversations_estimate_emailcount(state);
        if (estimate > n*20) { // 5% matches is enough to to iterate!
            syslog(LOG_DEBUG, "conversation_iterate_searchset: %s falling back to index for %d/%d records",
                   state->path, (int)n, (int)estimate);
        }
        else {
            syslog(LOG_DEBUG, "conversation_iterate_searchset: %s using scan mode for %d/%d records",
                   state->path, (int)n, (int)estimate);
            return _guid_foreach_helper(state, "", cb, cbrock, data, n);
        }
    }
    else {
        syslog(LOG_DEBUG, "conversation_iterate_searchset: %s using indexed mode for %d records",
               state->path, (int)n);
    }
    size_t i;
    for (i = 0; i < n; i++) {
        const char *guidrep = data + (i*41);
        int r = conversations_guid_foreach(state, guidrep, cb, cbrock);
        if (r) return r;
    }
    return 0;
}

static int _getcid(const conv_guidrec_t *rec, void *rock)
{
    conversation_id_t *cidp = (conversation_id_t *)rock;
    if (!rec->part) {
        *cidp = rec->cid;
        return CYRUSDB_DONE;
    }
    return 0;
}

EXPORTED conversation_id_t conversations_guid_cid_lookup(struct conversations_state *state,
                                                         const char *guidrep)
{
    conversation_id_t cid = 0;
    conversations_guid_foreach(state, guidrep, _getcid, &cid);
    return cid;
}


static int conversations_guid_setitem(struct conversations_state *state,
                                      const char *guidrep,
                                      const char *item,
                                      conversation_id_t cid,
                                      uint32_t system_flags,
                                      uint32_t internal_flags,
                                      time_t internaldate,
                                      int add)
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
        /* When bumping the G value version, make sure to update _guid_cb */
        struct buf val = BUF_INITIALIZER;
        char version = (state->folders_byname) ?
            CONV_GUIDREC_BYNAME_VERSION : CONV_GUIDREC_VERSION;

        buf_putc(&val, 0x80 | version);
        buf_appendbit64(&val, cid);
        buf_appendbit32(&val, system_flags);
        buf_appendbit32(&val, internal_flags);
        buf_appendbit64(&val, (bit64)internaldate);
        r = cyrusdb_store(state->db, buf_base(&key), buf_len(&key),
                                     buf_base(&val), buf_len(&val),
                                     &state->txn);
        buf_free(&val);
    }
    else {
        r = cyrusdb_delete(state->db, buf_base(&key), buf_len(&key), &state->txn, /*force*/1);
    }

done:
    buf_free(&key);

    return r;
}

static int _guid_addbody(struct conversations_state *state,
                         conversation_id_t cid,
                         uint32_t system_flags, uint32_t internal_flags,
                         time_t internaldate,
                         struct body *body,
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
        r = conversations_guid_setitem(state, guidrep, buf_cstring(&buf), cid,
                                       system_flags, internal_flags, internaldate,
                                       add);
        buf_free(&buf);

        if (r) return r;
    }

    r = _guid_addbody(state, cid, system_flags, internal_flags, internaldate, body->subpart, base, add);
    if (r) return r;

    for (i = 1; i < body->numparts; i++) {
        r = _guid_addbody(state, cid, system_flags, internal_flags, internaldate, body->subpart + i, base, add);
        if (r) return r;
    }

    return 0;
}

static int conversations_set_guid(struct conversations_state *state,
                                  struct mailbox *mailbox,
                                  const struct index_record *record,
                                  int add)
{
    int folder = conversation_folder_number(state,
                                            CONV_FOLDER_KEY_MBOX(state, mailbox),
                                            /*create*/1);
    struct buf item = BUF_INITIALIZER;
    struct body *body = NULL;
    int r = 0;

    r = mailbox_cacherecord(mailbox, record);
    if (r) return r;

    message_read_bodystructure(record, &body);

    /* process the GUID of the full message itself */
    buf_printf(&item, "%d:%u", folder, record->uid);
    const char *base = buf_cstring(&item);

    r = conversations_guid_setitem(state, message_guid_encode(&record->guid),
                                   base, record->cid,
                                   record->system_flags,
                                   record->internal_flags,
                                   record->internaldate,
                                   add);
    if (!r) r = _guid_addbody(state, record->cid,
                              record->system_flags, record->internal_flags,
                              record->internaldate, body, base, add);

    message_free_body(body);
    free(body);
    buf_free(&item);
    return r;
}

static int _read_emailcounts_cb(const conv_guidrec_t *rec, void *rock)
{
    struct emailcounts *ecounts = (struct emailcounts *)rock;
    if (rec->part) return 0;

    struct emailcountitems *i = ecounts->ispost ? &ecounts->post : &ecounts->pre;

    i->numrecords++;
    if (rec->foldernum == ecounts->foldernum) i->foldernumrecords++;

    // the rest only counts non-deleted records
    if (rec->version > 0 &&
         (rec->system_flags & FLAG_DELETED ||
          rec->internal_flags & FLAG_INTERNAL_EXPUNGED))
        return 0;

    i->exists++;
    if (rec->foldernum == ecounts->foldernum) i->folderexists++;

    // not seen or unsure, count it as unseen
    if (rec->version == 0 || !(rec->system_flags & (FLAG_SEEN|FLAG_DRAFT))) {
        if (rec->foldernum != ecounts->trashfolder) i->unseen++;
        if (rec->foldernum == ecounts->foldernum) i->folderunseen++;
    }

    return 0;
}

EXPORTED int conversations_update_record(struct conversations_state *cstate,
                                         struct mailbox *mailbox,
                                         const struct index_record *old,
                                         struct index_record *new,
                                         int allowrenumber,
                                         int ignorelimits)
{
    conversation_t *conv = NULL;
    size_t delta_exists = 0;
    size_t delta_size = 0;
    int *delta_counts = NULL;
    int i;
    modseq_t modseq = 0;
    int r = 0;

    if (old && new) {
        /* we're always moving forwards */
        assert(old->uid == new->uid);
        assert(old->modseq <= new->modseq);

        /* this flag cannot go away */
        if (old->internal_flags & FLAG_INTERNAL_EXPUNGED)
                assert(new->internal_flags & FLAG_INTERNAL_EXPUNGED);

        /* we're changing the CID for any reason at all, treat as
         * a removal and re-add, so cache gets parsed and msgids
         * updated */
        if (old->cid != new->cid) {
            r = conversations_update_record(cstate, mailbox, old, NULL, 0, ignorelimits);
            if (r) return r;
            return conversations_update_record(cstate, mailbox, NULL, new, 0, ignorelimits);
        }
    }

    const struct index_record *record = new ? new : old;
    if (!record) return 0;

    if (new && !old && allowrenumber) {
        /* add the conversation */
        r = mailbox_cacherecord(mailbox, new); /* make sure it's loaded */
        if (r) goto done;
        r = message_update_conversations(cstate, mailbox, new, &conv);
        if (r) goto done;
    }
    else if (record->cid) {
        r = conversation_load(cstate, record->cid, &conv);
        if (r) goto done;
        /* add subject if it loses draft flag */
        if (conv && !conv->subject && !(record->system_flags & FLAG_DRAFT)) {
            r = mailbox_cacherecord(mailbox, record);
            if (r) goto done;
            conv->subject = message_extract_convsubject(record);
        }
        if (!conv) {
            if (!new) {
                /* We're trying to delete a conversation that's already
                 * gone...don't try to hard */
                syslog(LOG_NOTICE, "conversation "CONV_FMT" already "
                                   "deleted, ignoring", record->cid);
                goto done;
            }
            conv = conversation_new();
        }
    }

    struct emailcounts ecounts = EMAILCOUNTS_INIT;
    ecounts.foldernum = conversation_folder_number(cstate, mailbox->name, /*create*/1);
    ecounts.trashfolder = cstate->trashfolder;

    /* count the email state before making GUID changes */
    r = conversations_guid_foreach(cstate, message_guid_encode(&record->guid),
                                   _read_emailcounts_cb, &ecounts);
    if (r) goto done;

    // always update the GUID information first, as it's used for search
    // even if conversations have not been set on this email
    if (new) {
        if (!old || old->system_flags != new->system_flags ||
                    old->internal_flags != new->internal_flags ||
                    old->internaldate != new->internaldate) {
            r = conversations_set_guid(cstate, mailbox, new, /*add*/1);
            if (r) goto done;
        }
    }
    else {
        if (old) {
            r = conversations_set_guid(cstate, mailbox, old, /*add*/0);
            if (r) goto done;
        }
    }

    /* we've made any set_guid, so count the state again! */
    ecounts.ispost = 1;
    r = conversations_guid_foreach(cstate, message_guid_encode(&record->guid),
                                   _read_emailcounts_cb, &ecounts);
    if (r) goto done;

    // check sanity limits
    if (!ignorelimits && ecounts.post.numrecords > ecounts.pre.numrecords) {
        if (ecounts.post.numrecords > (size_t)config_getint(IMAPOPT_CONVERSATIONS_MAX_GUIDRECORDS))
            r = IMAP_CONVERSATION_GUIDLIMIT;
        if (ecounts.post.exists > (size_t)config_getint(IMAPOPT_CONVERSATIONS_MAX_GUIDEXISTS))
            r = IMAP_CONVERSATION_GUIDLIMIT;
        if (ecounts.post.folderexists > (size_t)config_getint(IMAPOPT_CONVERSATIONS_MAX_GUIDINFOLDER))
            r = IMAP_CONVERSATION_GUIDLIMIT;
        if (r) {
            syslog(LOG_ERR, "IOERROR: conversations GUID limit for %s/%u/%s (%llu %llu %llu)",
                   mailbox->name, record->uid,
                   message_guid_encode(&record->guid),
                   (long long unsigned)ecounts.post.numrecords,
                   (long long unsigned)ecounts.post.exists,
                   (long long unsigned)ecounts.post.folderexists);
            goto done;
        }
    }

    // set up deltas
    if (ecounts.pre.exists) {
        delta_exists -= 1;
        delta_size -= record->size;
    }
    if (ecounts.post.exists) {
        delta_exists += 1;
        delta_size += record->size;
    }

    // update quotas
    r = _update_quotaused(cstate, delta_exists, delta_size);
    if (r) goto done;

    // the rest is bookkeeping purely for CIDed messages
    if (!record->cid) goto done;

    if (cstate->counted_flags)
        delta_counts = xzmalloc(sizeof(int) * cstate->counted_flags->count);

    /* calculate the changes */
    if (old) {
        /* decrease any relevant counts */
        if (!(old->internal_flags & FLAG_INTERNAL_EXPUNGED) &&
            !(old->system_flags & FLAG_DELETED)) {
            if (cstate->counted_flags) {
                for (i = 0; i < cstate->counted_flags->count; i++) {
                    const char *flag = strarray_nth(cstate->counted_flags, i);
                    if (mailbox_record_hasflag(mailbox, old, flag))
                        delta_counts[i]--;
                }
            }
        }
        modseq = MAX(modseq, old->modseq);
    }

    if (new) {
        /* add any counts */
        if (!(new->internal_flags & FLAG_INTERNAL_EXPUNGED) &&
            !(new->system_flags & FLAG_DELETED)) {
            if (cstate->counted_flags) {
                for (i = 0; i < cstate->counted_flags->count; i++) {
                    const char *flag = strarray_nth(cstate->counted_flags, i);
                    if (mailbox_record_hasflag(mailbox, new, flag))
                        delta_counts[i]++;
                }
            }
        }
        modseq = MAX(modseq, new->modseq);
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

        /* XXX - internaldate vs gmtime? */
        conversation_update_sender(conv,
                                   addr.name, addr.route,
                                   addr.mailbox, addr.domain,
                                   record->gmtime, delta_exists);
        free(env);
    }


    conversation_update_thread(conv,
                               &record->guid,
                               record->internaldate,
                               delta_exists);

    r = conversation_update(cstate, conv, &ecounts,
                            delta_size, delta_counts,
                            modseq, record->createdmodseq);
    if (r) goto done;

    r = conversation_save(cstate, record->cid, conv);

done:
    conversation_free(conv);
    free(delta_counts);
    return r;
}


EXPORTED int conversation_update(struct conversations_state *state,
                         conversation_t *conv, struct emailcounts *ecounts,
                         ssize_t delta_size, int *delta_counts,
                         modseq_t modseq, modseq_t createdmodseq)
{
    conv_folder_t *folder = conversation_get_folder(conv, ecounts->foldernum, /*create*/1);

    // only count one per instance of the GUID in each folder, and in total
    int delta_num_records = !!ecounts->post.numrecords - !!ecounts->pre.numrecords;
    int delta_exists = !!ecounts->post.exists - !!ecounts->pre.exists;
    int delta_unseen = !!ecounts->post.unseen - !!ecounts->pre.unseen;
    int delta_folder_records = !!ecounts->post.foldernumrecords - !!ecounts->pre.foldernumrecords;
    int delta_folder_exists = !!ecounts->post.folderexists - !!ecounts->pre.folderexists;
    int delta_folder_unseen = !!ecounts->post.folderunseen - !!ecounts->pre.folderunseen;

    // version 0 counted every UID rather than by GUID
    if (conv->version < 1) {
        delta_num_records = ecounts->post.numrecords - ecounts->pre.numrecords;
        delta_exists = ecounts->post.exists - ecounts->pre.exists;
        delta_unseen = ecounts->post.unseen - ecounts->pre.unseen;
        delta_folder_records = ecounts->post.foldernumrecords - ecounts->pre.foldernumrecords;
        delta_folder_exists = ecounts->post.folderexists - ecounts->pre.folderexists;
        delta_folder_unseen = ecounts->post.folderunseen - ecounts->pre.folderunseen;
    }

    int oldfolderexists = folder->exists;
    int oldfolderunseen = folder->unseen;
    int oldunseen = conv->unseen;

    int is_trash = (ecounts->foldernum == state->trashfolder);

    /* update the conversation tracking values for the whole conversation */
    if (delta_num_records) {
        _apply_delta(&conv->num_records, delta_num_records);
        conv->flags |= CONV_ISDIRTY;
    }
    if (delta_exists) {
        _apply_delta(&conv->exists, delta_exists);
        conv->flags |= CONV_ISDIRTY;
    }
    if (delta_unseen) {
        _apply_delta(&conv->unseen, delta_unseen);
        conv->flags |= CONV_ISDIRTY;
    }
    if (delta_size) {
        _apply_delta(&conv->size, delta_size);
        conv->flags |= CONV_ISDIRTY;
    }
    if (delta_folder_records) {
        _apply_delta(&folder->num_records, delta_folder_records);
        conv->flags |= CONV_ISDIRTY;
    }
    if (delta_folder_exists) {
        _apply_delta(&folder->exists, delta_folder_exists);
        conv->flags |= CONV_ISDIRTY;
    }
    if (delta_folder_unseen) {
        _apply_delta(&folder->unseen, delta_folder_unseen);
        conv->flags |= CONV_ISDIRTY;
    }

    if (state->counted_flags) {
        int i;
        for (i = 0; i < state->counted_flags->count; i++) {
            if (delta_counts[i]) {
                _apply_delta(&conv->counts[i], delta_counts[i]);
                conv->flags |= CONV_ISDIRTY;
            }
        }
    }
    if (modseq > conv->modseq) {
        conv->modseq = modseq;
        conv->flags |= CONV_ISDIRTY;
    }
    if (modseq > folder->modseq) {
        folder->modseq = modseq;
        conv->flags |= CONV_ISDIRTY;
    }
    if (createdmodseq && (!conv->createdmodseq || createdmodseq < conv->createdmodseq)) {
        conv->createdmodseq = createdmodseq;
        conv->flags |= CONV_ISDIRTY;
    }

    // now update all the folder counts

    int dexists = !!ecounts->post.folderexists - !!ecounts->pre.folderexists;
    int dunseen = !!ecounts->post.folderunseen - !!ecounts->pre.folderunseen;
    int dthreadexists = !!folder->exists - !!oldfolderexists;
    int dthreadunseen = !!conv->unseen - !!oldunseen;
    if (is_trash) dthreadunseen = !!folder->unseen - !!oldfolderunseen;

    for (folder = conv->folders; folder; folder = folder->next) {
        conv_status_t status;
        const char *mboxname = strarray_nth(state->folder_names, folder->number);
        int r = conversation_getstatus(state, mboxname, &status);
        if (r) return r;

        int dirty = 0;

        // all counts apply to the current folder
        if (folder->number == ecounts->foldernum) {
            if (dexists) {
                _apply_delta(&status.emailexists, dexists);
                dirty = 1;
            }
            if (dunseen) {
                _apply_delta(&status.emailunseen, dunseen);
                dirty = 1;
            }
            if (dthreadexists) {
                _apply_delta(&status.threadexists, dthreadexists);
                dirty = 1;
            }

            // case - adding an seen email to a new folder, but the thread is unseen
            if (folder->exists && !oldfolderexists && (is_trash ? folder->unseen : conv->unseen)) {
                _apply_delta(&status.threadunseen, 1);
                dirty = 1;
            }
            // case - removing the last message from a folder, and the thread remains unseen
            else if (!folder->exists && oldfolderexists && (is_trash ? oldfolderunseen : oldunseen)) {
                _apply_delta(&status.threadunseen, -1);
                dirty = 1;
            }
            // case there's an email in this folder, and the thread has changed
            else if (folder->exists && dthreadunseen) {
                _apply_delta(&status.threadunseen, dthreadunseen);
                dirty = 1;
            }
        }
        // unseen changes apply to all other folders except trash if this isn't the trash folder
        else if (!is_trash && folder->number != state->trashfolder && folder->exists) {
            if (dthreadunseen) {
                _apply_delta(&status.threadunseen, dthreadunseen);
                dirty = 1;
            }

        }

        if (status.threadmodseq < modseq) {
            status.threadmodseq = modseq;
            dirty = 1;
        }

        if (dirty) {
            r = conversation_setstatus(state, mboxname, &status);
            if (r) return r;
        }
    }

    return 0;
}

EXPORTED conversation_t *conversation_new()
{
    conversation_t *conv;

    conv = xzmalloc(sizeof(conversation_t));
    conv->version = CONVERSATIONS_RECORD_VERSION;
    conv->flags |= CONV_ISDIRTY;
    xstats_inc(CONV_NEW);

    return conv;
}

EXPORTED void conversation_fini(conversation_t *conv)
{
    if (!conv) return;

    conv_folder_t *folder;
    while ((folder = conv->folders)) {
        conv->folders = folder->next;
        free(folder);
    }

    conv_sender_t *sender;
    while ((sender = conv->senders)) {
        conv->senders = sender->next;
        xfree(sender->name);
        xfree(sender->route);
        xfree(sender->mailbox);
        xfree(sender->domain);
        free(sender);
    }

    xzfree(conv->subject);

    conv_thread_t *thread;
    while ((thread = conv->thread)) {
        conv->thread = thread->next;
        free(thread);
    }
}

EXPORTED void conversation_free(conversation_t *conv)
{
    conversation_fini(conv);
    free(conv);
}

struct prune_rock {
    struct conversations_state *state;
    arrayu64_t *cidfilter;
    arrayu64_t cids;
    time_t thresh;
    unsigned int nseen;
    unsigned int ndeleted;
};

static int prunecb(void *rock,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    struct prune_rock *prock = (struct prune_rock *)rock;
    time_t stamp;
    int r;

    prock->nseen++;
    r = check_msgid(key, keylen, NULL);
    if (r) goto done;

    arrayu64_truncate(&prock->cids, 0);

    r = _conversations_parse(data, datalen, &prock->cids, &stamp);
    if (r) goto done;

    if (prock->cidfilter) {
        size_t i;
        for (i = 0; i < arrayu64_size(&prock->cids); i++) {
            if (arrayu64_bsearch(prock->cidfilter, arrayu64_nth(&prock->cids, i)))
                goto done; // found a match
        }
    }
    else {
        /* keep records newer than the threshold */
        if (stamp >= prock->thresh)
            goto done;
    }

    prock->ndeleted++;

    r = cyrusdb_delete(prock->state->db,
                       key, keylen,
                       &prock->state->txn,
                       /*force*/1);

done:
    return r;
}

static int addknowncid(void *rock,
                       const char *key, size_t keylen,
                       const char *data __attribute__((unused)),
                       size_t datalen __attribute__((unused)))
{
    arrayu64_t *knowncids = (arrayu64_t *)rock;
    conversation_id_t cid;
    const char *rest;

    // errors - just skip them, they won't be readable!
    if (keylen != 17 || key[0] != 'B') return 0;
    int r = parsehex(key+1, &rest, 16, &cid);
    if (!r) arrayu64_append(knowncids, cid);
    return 0;
}

EXPORTED int conversations_prune(struct conversations_state *state,
                                 time_t thresh, unsigned int *nseenp,
                                 unsigned int *ndeletedp)
{
    struct prune_rock rock = { state, NULL, ARRAYU64_INITIALIZER, thresh, 0, 0 };

    if (config_getswitch(IMAPOPT_CONVERSATIONS_KEEP_EXISTING)) {
        // these will be added in CID order, so we don't need to sort them
        rock.cidfilter = arrayu64_new();
        cyrusdb_foreach(state->db, "B", 1, NULL, addknowncid, rock.cidfilter, &state->txn);
    }

    cyrusdb_foreach(state->db, "<", 1, NULL, prunecb, &rock, &state->txn);

    arrayu64_fini(&rock.cids);
    if (rock.cidfilter) {
        arrayu64_fini(rock.cidfilter);
        free(rock.cidfilter);
    }

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
        /* Do nothing if using folder ids */
        if (!state->folders_byname) return 0;

        r = conversation_setstatus(state, to_name, &status);
        if (r) return r;
        return conversation_setstatus(state, from_name, NULL);
    }

    /* in theory there shouldn't be any EXISTS left because you've deleted the messages,
     * but DB corruption could mean this wasn't cleared - better to allow the rename to
     * succeed and clean up later */
    if (status.threadexists || status.emailexists) {
        syslog(LOG_ERR, "IOERROR: conversationsdb corruption %s still had %d/%d messages in folder key on delete",
               from_name, status.threadexists, status.emailexists);
    }

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
    conversation_t *conv = conversation_new();
    conv_folder_t *folder;
    int r;
    int i;

    r = conversation_parse(val, vallen, conv, CONV_WITHFOLDERS|CONV_WITHSUBJECT);
    if (r) {
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, /*force*/1);
        goto done;
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

    /* keep the subject of course */

    /* zero out the size */
    conv->size = 0;

    /* Update the version */
    conv->version = CONVERSATIONS_RECORD_VERSION;

    r = conversation_store(state, key, keylen, conv);

done:
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
    status.threadexists = 0;
    status.threadunseen = 0;
    status.emailexists = 0;
    status.emailunseen = 0;

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

    /* wipe quota (it's actually just one key) */
    r = cyrusdb_foreach(state->db, "Q", 1, NULL, zero_g_cb,
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
    conversation_t *conv = conversation_new();
    int r;

    r = conversation_parse(val, vallen, conv, /*flags*/0);
    if (r) goto done;

    /* should be gone, wipe it */
    if (!conv->num_records)
        r = cyrusdb_delete(state->db, key, keylen, &state->txn, 1);


done:
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
