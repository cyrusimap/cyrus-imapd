/* index.c -- Routines for dealing with the index file in the imapd
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
 *
 * $Id: index.c,v 1.259 2010/06/28 12:04:53 brong Exp $
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "charset.h"
#include "exitcodes.h"
#include "hash.h"
#include "imap_err.h"
#include "global.h"
#include "imapd.h"
#include "cyr_lock.h"
#include "lsort.h"
#include "mailbox.h"
#include "map.h"
#include "message.h"
#include "parseaddr.h"
#include "search_engines.h"
#include "seen.h"
#include "statuscache.h"
#include "strhash.h"
#include "stristr.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#include "index.h"
#include "sync_log.h"

/* Forward declarations */
static void index_refresh(struct index_state *state);
static void index_tellexists(struct index_state *state);
int index_lock(struct index_state *state);
void index_unlock(struct index_state *state);

int index_writeseen(struct index_state *state);
void index_fetchmsg(struct index_state *state,
		    const char *msg_base, unsigned long msg_size,
		    unsigned offset, unsigned size,
		    unsigned start_octet, unsigned octet_count);
static int index_fetchsection(struct index_state *state, const char *resp,
			      const char *msg_base, unsigned long msg_size,
			      char *section,
			      const char *cachestr, unsigned size,
			      unsigned start_octet, unsigned octet_count);
static void index_fetchfsection(struct index_state *state,
				const char *msg_base, unsigned long msg_size,
				struct fieldlist *fsection,
				const char *cachestr,
				unsigned start_octet, unsigned octet_count);
static char *index_readheader(const char *msg_base, unsigned long msg_size,
			      unsigned offset, unsigned size);
static void index_pruneheader(char *buf, struct strlist *headers,
			      struct strlist *headers_not);
static void index_fetchheader(struct index_state *state,
			      const char *msg_base, unsigned long msg_size,
			      unsigned size,
			      struct strlist *headers,
			      struct strlist *headers_not);
static void index_fetchcacheheader(struct index_state *state, struct index_record *record, 
				   struct strlist *headers, unsigned start_octet, 
				   unsigned octet_count);
static void index_listflags(struct index_state *state);
static void index_fetchflags(struct index_state *state, uint32_t msgno);
static int index_search_evaluate(struct index_state *state,
				 struct searchargs *searchargs,
				 uint32_t msgno, struct mapfile *msgfile);
static int index_searchmsg(char *substr, comp_pat *pat,
			   struct mapfile *msgfile,
			   int skipheader, const char *cachestr);
static int index_searchheader(char *name, char *substr, comp_pat *pat,
			      struct mapfile *msgfile,
			      int size);
static int index_searchcacheheader(struct index_state *state, uint32_t msgno, char *name, char *substr,
				   comp_pat *pat);
static int _index_search(unsigned **msgno_list, struct index_state *state,
			 struct searchargs *searchargs,
			 modseq_t *highestmodseq);

static int index_copysetup(struct index_state *state, uint32_t msgno, struct copyargs *copyargs);
static int index_storeflag(struct index_state *state, uint32_t msgno,
			   struct storeargs *storeargs);
static int index_fetchreply(struct index_state *state, uint32_t msgno,
			    struct fetchargs *fetchargs);
static void index_printflags(struct index_state *state, uint32_t msgno, int usinguid);
static void index_checkflags(struct index_state *state, int dirty);
static char *find_msgid(char *str, char **rem);
static char *get_localpart_addr(const char *header);
static char *get_displayname(const char *header);
static char *index_extract_subject(const char *subj, size_t len, int *is_refwd);
static char *_index_extract_subject(char *s, int *is_refwd);
static void index_get_ids(MsgData *msgdata,
			  char *envtokens[], const char *headers, unsigned size);
static MsgData *index_msgdata_load(struct index_state *state, unsigned *msgno_list, int n,
				   struct sortcrit *sortcrit);

static void *index_sort_getnext(MsgData *node);
static void index_sort_setnext(MsgData *node, MsgData *next);
static int index_sort_compare(MsgData *md1, MsgData *md2,
			      struct sortcrit *call_data);
static void index_msgdata_free(MsgData *md);

static void *index_thread_getnext(Thread *thread);
static void index_thread_setnext(Thread *thread, Thread *next);
static int index_thread_compare(Thread *t1, Thread *t2,
				struct sortcrit *call_data);
static void index_thread_orderedsubj(struct index_state *state,
				     unsigned *msgno_list, int nmsg,
				     int usinguid);
static void index_thread_sort(Thread *root, struct sortcrit *sortcrit);
static void index_thread_print(struct index_state *state,
			       Thread *threads, int usinguid);
static void index_thread_ref(struct index_state *state,
			     unsigned *msgno_list, int nmsg, int usinguid);

static void index_select(struct index_state *state);
static struct seqset *_index_vanished(struct index_state *state,
				      struct vanished_params *params);
static struct seqset *_parse_sequence(struct index_state *state,
				      const char *sequence, int usinguid);
static void massage_header(char *hdr);

/* NOTE: Make sure these are listed in CAPABILITY_STRING */
static const struct thread_algorithm thread_algs[] = {
    { "ORDEREDSUBJECT", index_thread_orderedsubj },
    { "REFERENCES", index_thread_ref },
    { NULL, NULL }
};


/*
 * A mailbox is about to be closed.
 */
int index_close(struct index_state **stateptr)
{
    unsigned i;
    struct index_state *state = *stateptr;

    free(state->userid);
    free(state->map);
    for (i = 0; i < MAX_USER_FLAGS; i++)
	free(state->flagname[i]);
    mailbox_close(&state->mailbox);
    free(state);

    *stateptr = NULL;

    return 0;
}

/*
 * A new mailbox has been selected, map it into memory and do the
 * initial CHECK.
 */
int index_open(const char *name, struct index_init *init,
	       struct index_state **stateptr)
{
    int r;
    struct index_state *state = xzmalloc(sizeof(struct index_state));
    struct seqset *vanishedlist = NULL;

    r = mailbox_open_iwl(name, &state->mailbox);
    if (r) goto fail;

    if (init) {
	state->myrights = cyrus_acl_myrights(init->authstate, state->mailbox->acl);
	if (init->examine_mode)
	    state->myrights &= ~ACL_READ_WRITE;

	state->authstate = init->authstate;
	state->userid = init->userid ? xstrdup(init->userid) : NULL;

	state->internalseen = mailbox_internal_seen(state->mailbox, state->userid);
	state->keepingseen = (state->myrights & ACL_SEEN);
	state->examining = init->examine_mode;

	state->out = init->out;
	state->qresync = init->qresync;
    }

    /* initialise the index_state */
    index_refresh(state);

    /* have to get the vanished list while we're still locked */
    if (init && init->vanished.uidvalidity == state->mailbox->i.uidvalidity) {
	vanishedlist = _index_vanished(state, &init->vanished);
    }

    index_unlock(state);

    if (init && init->select && state->myrights & ACL_READ) {
	index_select(state);

	if (init->vanished.uidvalidity == state->mailbox->i.uidvalidity) {
	    const char *sequence = init->vanished.sequence;
	    struct index_map *im;
	    uint32_t msgno;
	    struct seqset *seq = _parse_sequence(state, sequence, 1);

	    /* QRESYNC response:
	     * UID FETCH seq FLAGS (CHANGEDSINCE modseq VANISHED)
	     */

	    if (vanishedlist && vanishedlist->len) {
		char *vanished = seqset_cstring(vanishedlist);
		prot_printf(state->out, "* VANISHED (EARLIER) %s\r\n", vanished);
		free(vanished);
	    }

	    for (msgno = 1; msgno <= state->exists; msgno++) {
		im = &state->map[msgno-1];
		if (sequence && !seqset_ismember(seq, im->record.uid))
		    continue;
		if (im->record.modseq <= init->vanished.modseq)
		    continue;
		index_printflags(state, msgno, 1);
	    }

	    seqset_free(seq);
	}
    }

    seqset_free(vanishedlist);

    *stateptr = state;

    return 0;

fail:
    free(state->mailbox);
    free(state);
    return r;
}

int index_expunge(struct index_state *state, char *sequence)
{
    int r;
    uint32_t msgno;
    struct index_map *im;
    struct seqset *seq = NULL;
    int numexpunged = 0;

    r = index_lock(state);
    if (r) return r;

    /* XXX - earlier list if the sequence names UIDs that don't exist? */
    seq = _parse_sequence(state, sequence, 1);

    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];

	if (im->record.system_flags & FLAG_EXPUNGED)
	    continue; /* already expunged */

	if (!(im->record.system_flags & FLAG_DELETED))
	    continue; /* no \Deleted flag */

	/* if there is a sequence list, check it */
	if (sequence && !seqset_ismember(seq, im->record.uid))
	    continue; /* not in the list */

	if (!im->isseen)
	    state->numunseen--;

	if (im->isrecent)
	    state->numrecent--;

	im->record.system_flags |= FLAG_EXPUNGED;
        numexpunged++;

	r = mailbox_rewrite_index_record(state->mailbox, &im->record);
	if (r) break;
    }

    seqset_free(seq);

    /* unlock before responding */
    index_unlock(state);

    if (!r && (numexpunged > 0)) {
	syslog(LOG_NOTICE, "Expunged %d messages from %s",
	       numexpunged, state->mailbox->name);
    }
    return r;
}

char *index_buildseen(struct index_state *state, const char *oldseenuids)
{
    struct seqset *outlist;
    uint32_t msgno;
    unsigned oldmax;
    struct index_map *im;
    char *out;

    outlist = seqset_init(0, SEQ_MERGE); 
    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];
	seqset_add(outlist, im->record.uid, im->isseen);
    }

    /* there may be future already seen UIDs that this process isn't
     * allowed to know about, but we can't blat them either!  This is
     * a massive pain... */
    oldmax = seq_lastnum(oldseenuids, NULL);
    if (oldmax > state->last_uid) {
	struct seqset *seq = seqset_parse(oldseenuids, NULL, oldmax);
	uint32_t uid;

	/* for each future UID, copy the state in the old seenuids */
	for (uid = state->last_uid + 1; uid <= oldmax; uid++)
	    seqset_add(outlist, uid, seqset_ismember(seq, uid));

	seqset_free(seq);
    }

    out = seqset_cstring(outlist);
    seqset_free(outlist);

    return out;
}

int index_writeseen(struct index_state *state)
{
    int r;
    struct seen *seendb = NULL;
    struct seendata oldsd = SEENDATA_INITIALIZER;
    struct seendata sd = SEENDATA_INITIALIZER;
    struct mailbox *mailbox = state->mailbox;

    assert(mailbox->index_locktype == LOCK_EXCLUSIVE);

    if (!state->seen_dirty)
	return 0;

    state->seen_dirty = 0;

    /* only examining, can't write any changes */
    if (state->examining)
	return 0;

    /* already handled! Just update the header fields */
    if (state->internalseen) {
	mailbox_index_dirty(mailbox);
	mailbox->i.recenttime = time(0);
	if (mailbox->i.recentuid < state->last_uid)
	    mailbox->i.recentuid = state->last_uid;
	return 0;
    }

    r = seen_open(state->userid, SEEN_CREATE, &seendb);
    if (r) return r;

    r = seen_lockread(seendb, mailbox->uniqueid, &oldsd);
    if (r) {
	oldsd.lastread = 0;
	oldsd.lastuid = 0;
	oldsd.lastchange = 0;
	oldsd.seenuids = xstrdup("");
    }

    /* fields of interest... */
    sd.lastuid = oldsd.lastuid;
    sd.seenuids = index_buildseen(state, oldsd.seenuids);
    if (!sd.seenuids) sd.seenuids = xstrdup("");

    /* make comparison only catch some changes */
    sd.lastread = oldsd.lastread;
    sd.lastchange = oldsd.lastchange;

    /* update \Recent lowmark */
    if (sd.lastuid < state->last_uid)
	sd.lastuid = state->last_uid;

    /* only commit if interesting fields have changed */
    if (!seen_compare(&sd, &oldsd)) {
	sd.lastread = time(NULL);
	sd.lastchange = mailbox->i.last_appenddate;
	r = seen_write(seendb, mailbox->uniqueid, &sd);
    }

    seen_close(&seendb);

    seen_freedata(&oldsd);
    seen_freedata(&sd);

    return r;
}

/* caller must free the list with seqset_free() when done */
static struct seqset *_readseen(struct index_state *state, unsigned *recentuid)
{
    struct mailbox *mailbox = state->mailbox;
    struct seqset *seenlist = NULL;

    /* Obtain seen information */
    if (state->internalseen) {
	*recentuid = mailbox->i.recentuid;
    }
    else if (state->userid) {
	struct seen *seendb = NULL;
	struct seendata sd = SEENDATA_INITIALIZER;
	int r;

	r = seen_open(state->userid, SEEN_CREATE, &seendb);
	if (!r) r = seen_read(seendb, mailbox->uniqueid, &sd);
	seen_close(&seendb);

	/* handle no seen DB gracefully */
	if (r) {
	    *recentuid = mailbox->i.last_uid;
	    prot_printf(state->out, "* OK (seen state failure) %s: %s\r\n",
		   error_message(IMAP_NO_CHECKPRESERVE), error_message(r));
	    syslog(LOG_ERR, "Could not open seen state for %s (%s)",
		   state->userid, error_message(r));
	}
	else {
	    *recentuid = sd.lastuid;
	    seenlist = seqset_parse(sd.seenuids, NULL, *recentuid);
	    seen_freedata(&sd);
	}
    }
    else {
	*recentuid = mailbox->i.last_uid; /* nothing is recent! */
    }

    return seenlist;
}

void index_refresh(struct index_state *state)
{
    struct mailbox *mailbox = state->mailbox;
    uint32_t recno;
    uint32_t msgno = 1;
    uint32_t firstnotseen = 0;
    uint32_t numrecent = 0;
    uint32_t numunseen = 0;
    uint32_t recentuid;
    struct index_map *im;
    modseq_t delayed_modseq = 0;
    uint32_t need_records;
    struct seqset *seenlist;

    if (state->num_records) {
	need_records = mailbox->i.num_records -
		       state->num_records + state->exists;
    }
    else {
	/* init case */
	need_records = mailbox->i.exists;
    }

    /* make sure we have space */
    if (need_records >= state->mapsize) {
	state->mapsize = (need_records | 0xff) + 1; /* round up 1-256 */
	state->map = xrealloc(state->map,
			      state->mapsize * sizeof(struct index_map));
    }

    seenlist = _readseen(state, &recentuid);

    /* already known records - flag updates */
    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];
	if (mailbox_read_index_record(mailbox, im->record.recno, &im->record))
	    continue; /* bogus read... should probably be fatal */

	/* ignore expunged messages */
	if (im->record.system_flags & FLAG_EXPUNGED) {
	    /* http://www.rfc-editor.org/errata_search.php?rfc=5162
	     * Errata ID: 1809 - if there are expunged records we
	     * aren't telling about, need to make the highestmodseq
	     * be one lower so the client can safely resync */
	    if (!delayed_modseq || im->record.modseq < delayed_modseq)
		delayed_modseq = im->record.modseq - 1;
	    continue;
	}

	/* re-calculate seen flags */
	if (state->internalseen)
	    im->isseen = (im->record.system_flags & FLAG_SEEN) ? 1 : 0;
	else
	    im->isseen = seqset_ismember(seenlist, im->record.uid);

	/* track select values */
	if (!im->isseen) {
	    numunseen++;
	    if (!firstnotseen)
		firstnotseen = msgno;
	}
	if (im->isrecent) {
	    /* we don't need to dirty seen here, it's a refresh */
	    numrecent++;
	}
    }

    /* new records? */
    for (recno = state->num_records + 1; recno <= mailbox->i.num_records; recno++) {
	im = &state->map[msgno-1];
	if (mailbox_read_index_record(mailbox, recno, &im->record))
	    continue; /* bogus read... should probably be fatal */
	if (im->record.system_flags & FLAG_EXPUNGED)
	    continue;

	/* make sure we don't overflow the memory we mapped */
	if (msgno >= state->mapsize) {
	    char buf[2048];
	    sprintf(buf, "Exists wrong %u %u %u %u", msgno,
		    state->mapsize, mailbox->i.exists, mailbox->i.num_records);
	    fatal(buf, EC_IOERR);
	}

	/* calculate flags */
	if (state->internalseen)
	    im->isseen = (im->record.system_flags & FLAG_SEEN) ? 1 : 0;
	else
	    im->isseen = seqset_ismember(seenlist, im->record.uid);
	im->isrecent = (im->record.uid > recentuid) ? 1 : 0;

	/* track select values */
	if (!im->isseen) {
	    numunseen++;
	    if (!firstnotseen)
		firstnotseen = msgno;
	}
	if (im->isrecent) {
	    numrecent++;
	    state->seen_dirty = 1;
	}

	/* don't auto-tell */
	im->told_modseq = im->record.modseq;

	msgno++;
    }

    seqset_free(seenlist);

    /* update the header tracking data */
    state->oldexists = state->exists; /* we last knew about this many */
    state->exists = msgno - 1; /* we actually got this many */
    state->delayed_modseq = delayed_modseq;
    state->highestmodseq = mailbox->i.highestmodseq;
    state->last_uid = mailbox->i.last_uid;
    state->num_records = mailbox->i.num_records;
    state->firstnotseen = firstnotseen;
    state->numunseen = numunseen;
    state->numrecent = numrecent;
}

modseq_t index_highestmodseq(struct index_state *state)
{
    if (state->delayed_modseq)
	return state->delayed_modseq;
    return state->highestmodseq;
}

static void index_select(struct index_state *state)
{
    index_tellexists(state);

    /* always print flags */
    index_checkflags(state, 1);

    if (state->firstnotseen)
	prot_printf(state->out, "* OK [UNSEEN %u] Ok\r\n", 
		    state->firstnotseen);
    prot_printf(state->out, "* OK [UIDVALIDITY %u] Ok\r\n",
		state->mailbox->i.uidvalidity);
    prot_printf(state->out, "* OK [UIDNEXT %lu] Ok\r\n",
		state->last_uid + 1);
    prot_printf(state->out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "] Ok\r\n",
		state->highestmodseq);
    prot_printf(state->out, "* OK [URLMECH INTERNAL] Ok\r\n");
}

/*
 * Check for and report updates
 */
int index_check(struct index_state *state, int usinguid, int printuid)
{
    struct mailbox *mailbox = state->mailbox;
    int r;

    r = mailbox_lock_index(mailbox, LOCK_EXCLUSIVE);
    if (r) return r;

    /* Check for deleted mailbox  */
    if (mailbox->i.options & OPT_MAILBOX_DELETED) {
	/* Mailbox has been (re)moved */
	if (config_getswitch(IMAPOPT_DISCONNECT_ON_VANISHED_MAILBOX)) {
	    syslog(LOG_WARNING,
		   "Mailbox %s has been (re)moved out from under client",
		   mailbox->name);
	    mailbox_close(&mailbox);
	    fatal("Mailbox has been (re)moved", EC_IOERR);
	}

	if (state->exists && state->qresync) {
	    /* XXX - is it OK to just expand to entire possible range? */
	    prot_printf(state->out, "* VANISHED 1:%lu\r\n", state->last_uid);
	}
	else {
	    int exists;
	    for (exists = state->exists; exists > 0; exists--) {
		prot_printf(state->out, "* 1 EXPUNGE\r\n");
	    }
	}
	mailbox_unlock_index(mailbox, NULL);
	state->exists = 0;
	return IMAP_MAILBOX_NONEXISTENT;
    }

    index_refresh(state);

    /* any updates? */
    index_tellchanges(state, usinguid, printuid);

#if TOIMSP
    if (state->firstnotseen) {
	toimsp(mailbox->name, mailbox->i.uidvalidity, "SEENsnn", state->userid,
	       0, mailbox->i.recenttime, 0);
    }
    else {
	toimsp(mailbox->name, mailbox->i.uidvalidity, "SEENsnn", state->userid,
	       mailbox->last_uid, mailbox->i.recenttime, 0);
    }
#endif

    index_unlock(state);

    return r;
}

/*
 * Perform UID FETCH (VANISHED) on a sequence.
 */
static struct seqset *_index_vanished(struct index_state *state,
				      struct vanished_params *params)
{
    struct mailbox *mailbox = state->mailbox;
    struct index_record record;
    struct seqset *outlist;
    struct seqset *seq;
    uint32_t recno;

    /* No recently expunged messages */
    if (params->modseq >= state->highestmodseq) return NULL;

    outlist = seqset_init(0, SEQ_SPARSE);
    seq = _parse_sequence(state, params->sequence, 1);

    /* XXX - use match_seq and match_uid */

    if (params->modseq >= mailbox->i.deletedmodseq) {
	/* all records are significant */
	/* List only expunged UIDs with MODSEQ > requested */
	for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	    if (mailbox_read_index_record(mailbox, recno, &record))
		continue;
	    if (!(record.system_flags & FLAG_EXPUNGED))
		continue;
	    if (record.modseq <= params->modseq)
		continue;
	    if (!params->sequence || seqset_ismember(seq, record.uid))
		seqset_add(outlist, record.uid, 1);
	}
    }
    else {
	unsigned prevuid = 0;
	struct seqset *msgnolist;
	struct seqset *uidlist;
	uint32_t msgno;
	unsigned uid;

	syslog(LOG_NOTICE, "inefficient qresync ("
	       MODSEQ_FMT " > " MODSEQ_FMT ") %s",
	       mailbox->i.deletedmodseq, params->modseq,
	       mailbox->name);

	recno = 1;

	/* use the sequence to uid mapping provided by the client to
	 * skip over any initial matches - see RFC 5162 section 3.1 */
	if (params->match_seq && params->match_uid) {
	    msgnolist = _parse_sequence(state, params->match_seq, 0);
	    uidlist = _parse_sequence(state, params->match_uid, 1);
	    while ((msgno = seqset_getnext(msgnolist)) != 0) {
		uid = seqset_getnext(uidlist);
		/* first non-match, we'll start here */
		if (state->map[msgno-1].record.uid != uid)
		    break;
		/* ok, they matched - so we can start at the recno and UID
		 * first past the match */
		prevuid = uid;
		recno = state->map[msgno-1].record.recno + 1;
	    }
	    seqset_free(msgnolist);
	    seqset_free(uidlist);
	}

	/* possible efficiency improvement - use "seq_getnext" on seq
	 * to avoid incrementing through every single number for prevuid.
	 * Only really an issue if there's a giant block of thousands of
	 * expunged messages.  Only likely to be seen in the wild if
	 * last_uid winds up being bumped up a few million by a bug... */

	/* for the rest of the mailbox, we're just going to have to assume
	 * every record in the requested range which DOESN'T exist has been
	 * expunged, so build a complete sequence */
	for (; recno <= mailbox->i.num_records; recno++) {
	    if (mailbox_read_index_record(mailbox, recno, &record))
		continue;
	    if (record.system_flags & FLAG_EXPUNGED)
		continue;
	    while (++prevuid < record.uid) {
		if (!params->sequence || seqset_ismember(seq, prevuid))
		    seqset_add(outlist, prevuid, 1);
	    }
	    prevuid = record.uid;
	}

	/* include the space past the final record up to last_uid as well */
	while (++prevuid <= mailbox->i.last_uid) {
	    if (!params->sequence || seqset_ismember(seq, prevuid))
		seqset_add(outlist, prevuid, 1);
	}
    }

    seqset_free(seq);

    return outlist;
}

static int _fetch_setseen(struct index_state *state, uint32_t msgno)
{
    struct index_map *im = &state->map[msgno-1];
    int r;

    /* already seen */
    if (im->isseen)
	return 0;

    /* no rights to change it */
    if (!(state->myrights & ACL_SEEN))
	return 0;

    /* store in the record if it's internal seen */
    if (state->internalseen)
	im->record.system_flags |= FLAG_SEEN;

    /* need to bump modseq anyway, so always rewrite it */
    r = mailbox_rewrite_index_record(state->mailbox, &im->record);
    if (r) return r;

    /* track changes internally */
    state->numunseen--;
    state->seen_dirty = 1;
    im->isseen = 1;

    /* RFC2060 says:
     * The \Seen flag is implicitly set; if this causes
     * the flags to change they SHOULD be included as part
     * of the FETCH responses.   This is handled later by
     * always including flags if the modseq has changed.
     */

    return 0;
}

/*
 * Perform a FETCH-related command on a sequence.
 * Fetchedsomething argument is 0 if nothing was fetched, 1 if something was
 * fetched.  (A fetch command that fetches nothing is not a valid fetch
 * command.)
 */
int index_fetch(struct index_state *state,
		const char *sequence,
		int usinguid,
		struct fetchargs *fetchargs,
		int *fetchedsomething)
{
    struct seqset *seq;
    struct seqset *vanishedlist = NULL;
    uint32_t msgno, start, end;
    unsigned checkval;
    int r;
    struct index_map *im;
    int fetched = 0;

    r = index_lock(state);
    if (r) return r;

    seq = _parse_sequence(state, sequence, usinguid);

    start = 1;
    end = state->exists;

    /* compress the search range down if a sequence was given */
    if (seq) {
	unsigned first = seqset_first(seq);
	unsigned last = seqset_last(seq);

	if (usinguid) {
	    if (first > 1)
		start = index_finduid(state, first);
	    if (first == last)
		end = start;
	    else if (last < state->last_uid)
		end = index_finduid(state, last);
	}
	else {
	    start = first;
	    end = last;
	}
    }

    /* make sure we didn't go outside the range! */
    if (start < 1) start = 1;
    if (end > state->exists) end = state->exists;

    /* set the \Seen flag if necessary - while we still have the lock */
    if (fetchargs->fetchitems & FETCH_SETSEEN && !state->examining) {
	for (msgno = start; msgno <= end; msgno++) {
	    im = &state->map[msgno-1];
	    checkval = usinguid ? im->record.uid : msgno;
	    if (!seqset_ismember(seq, checkval))
		continue;
	    r = _fetch_setseen(state, msgno);   
	    if (r) break;
	}
    }

    if (fetchargs->vanished) {
	struct vanished_params v;
	v.sequence = sequence;;
	v.modseq = fetchargs->changedsince;
	v.match_seq = fetchargs->match_seq;
	v.match_uid = fetchargs->match_uid;
	/* XXX - return error unless usinguid? */
	vanishedlist = _index_vanished(state, &v);
    }

    index_unlock(state);

    index_checkflags(state, 0);

    if (vanishedlist && vanishedlist->len) {
	char *vanished = seqset_cstring(vanishedlist);
	prot_printf(state->out, "* VANISHED (EARLIER) %s\r\n", vanished);
	free(vanished);
    }

    seqset_free(vanishedlist);

    for (msgno = start; msgno <= end; msgno++) {
	im = &state->map[msgno-1];
	checkval = usinguid ? im->record.uid : msgno;
	if (!seqset_ismember(seq, checkval))
	    continue;
	r = index_fetchreply(state, msgno, fetchargs);
	if (r) break;
	fetched = 1;
    }

    seqset_free(seq);

    index_tellchanges(state, usinguid, usinguid);

    if (fetchedsomething) *fetchedsomething = fetched;

    return r;
}

/*
 * Perform a STORE command on a sequence
 */
int index_store(struct index_state *state, char *sequence, int usinguid,
		struct storeargs *storeargs, char **flag, int nflags)
{
    struct mailbox *mailbox = state->mailbox;
    int i, r = 0;
    uint32_t msgno;
    unsigned checkval;
    int userflag;
    struct seqset *seq;
    struct index_map *im;

    /* First pass at checking permission */
    if ((storeargs->seen && !(state->myrights & ACL_SEEN)) ||
	((storeargs->system_flags & FLAG_DELETED) &&
	 !(state->myrights & ACL_DELETEMSG)) ||
	(((storeargs->system_flags & ~FLAG_DELETED) || nflags) &&
	 !(state->myrights & ACL_WRITE))) {
	return IMAP_PERMISSION_DENIED;
    }

    r = index_lock(state);
    if (r) return r;

    seq = _parse_sequence(state, sequence, usinguid);

    for (i = 0; i < nflags; i++) {
	r = mailbox_user_flag(mailbox, flag[i], &userflag);
	if (r) goto fail;
	storeargs->user_flags[userflag/32] |= 1<<(userflag&31);
    }

    storeargs->update_time = time((time_t *)0);
    storeargs->usinguid = usinguid;

    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];
	checkval = usinguid ? im->record.uid : msgno;
	if (!seqset_ismember(seq, checkval))
	    continue;
	r = index_storeflag(state, msgno, storeargs);
	if (r) goto fail;
    }

fail:
    seqset_free(seq);
    index_unlock(state);
    index_tellchanges(state, usinguid, usinguid);

    return r;
}

static int index_scan_work(const char *s, unsigned long len,
			   const char *match, unsigned long min)
{
    while (len > min) {
        if (!strncasecmp(s, match, min)) return(1);
        s++;
        len--;
    }
    return(0);
}

/*
 * Guts of the SCAN command, lifted from _index_search()
 *
 * Returns 1 if we get a hit, otherwise returns 0.
 */
int index_scan(struct index_state *state, const char *contents)
{
    unsigned *msgno_list;
    uint32_t msgno;
    struct mapfile msgfile;
    int n = 0;
    int listindex;
    int listcount;
    struct searchargs searchargs;
    struct strlist strlist;
    unsigned long length;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im;

    if (!(contents && contents[0])) return(0);

    if (index_check(state, 0, 0))
	return 0;

    if (state->exists <= 0) return 0;

    length = strlen(contents);

    memset(&searchargs, 0, sizeof(struct searchargs));
    searchargs.text = &strlist;

    /* Use US-ASCII to emulate fgrep */
    strlist.s = charset_convert(contents, charset_lookupname("US-ASCII"),
				NULL, 0); 
    strlist.p = charset_compilepat(strlist.s);
    strlist.next = NULL;

    msgno_list = (unsigned *) xmalloc(state->exists * sizeof(unsigned));

    listcount = search_prefilter_messages(msgno_list, state, &searchargs);

    for (listindex = 0; !n && listindex < listcount; listindex++) {
        msgno = msgno_list[listindex];
	im = &state->map[msgno-1];

	msgfile.base = 0;
	msgfile.size = 0;

        if (mailbox_map_message(mailbox, im->record.uid,
                                &msgfile.base, &msgfile.size))
            continue;

        n += index_scan_work(msgfile.base, msgfile.size, contents, length);

        mailbox_unmap_message(mailbox, im->record.uid,
                              &msgfile.base, &msgfile.size);
    }

    free(strlist.s);
    free(strlist.p);
    free(msgno_list);

    return n;
}

/*
 * Guts of the SEARCH command.
 * 
 * Returns message numbers in an array.  This function is used by
 * SEARCH, SORT and THREAD.
 */
static int _index_search(unsigned **msgno_list, struct index_state *state,
			 struct searchargs *searchargs,
			 modseq_t *highestmodseq)
{
    uint32_t msgno;
    struct mapfile msgfile;
    int n = 0;
    int listindex, min;
    int listcount;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im;

    if (state->exists <= 0) return 0;

    *msgno_list = (unsigned *) xmalloc(state->exists * sizeof(unsigned));

    /* OK, so I'm being a bit clever here. We fill the msgno list with
       a list of message IDs returned by the search engine. Then we
       scan through the list and store matching message IDs back into the
       list. This is OK because we only overwrite message IDs that we've
       already looked at. */
    listcount = search_prefilter_messages(*msgno_list, state, searchargs);

    if (searchargs->returnopts == SEARCH_RETURN_MAX) {
	/* If we only want MAX, then skip forward search,
	   and do complete reverse search */
	listindex = listcount;
	min = 0;
    } else {
	/* Otherwise use forward search, potentially skipping reverse search */
	listindex = 0;
	min = listcount;
    }

    /* Forward search.  Used for everything other than MAX-only */
    for (; listindex < listcount; listindex++) {
	msgno = (*msgno_list)[listindex];
	im = &state->map[msgno-1];
	msgfile.base = 0;
	msgfile.size = 0;

	/* expunged messages never match */
	if (im->record.system_flags & FLAG_EXPUNGED)
	    continue;

	if (index_search_evaluate(state, searchargs, msgno, &msgfile)) {
	    (*msgno_list)[n++] = msgno;
	    if (highestmodseq && im->record.modseq > *highestmodseq) {
		*highestmodseq = im->record.modseq;
	    }

	    /* See if we should short-circuit
	       (we want MIN, but NOT COUNT or ALL) */
	    if ((searchargs->returnopts & SEARCH_RETURN_MIN) &&
		!(searchargs->returnopts & SEARCH_RETURN_COUNT) &&
		!(searchargs->returnopts & SEARCH_RETURN_ALL)) {

		if (searchargs->returnopts & SEARCH_RETURN_MAX) {
		    /* If we want MAX, setup for reverse search */
		    min = listindex;
		}
		/* We're done */
		listindex = listcount;
		if (highestmodseq)
		    *highestmodseq = im->record.modseq;
	    }
	}
	if (msgfile.base) {
	    mailbox_unmap_message(mailbox, im->record.uid,
				  &msgfile.base, &msgfile.size);
	}
    }

    /* Reverse search.  Stops at previously found MIN (if any) */
    for (listindex = listcount; listindex > min; listindex--) {
	msgno = (*msgno_list)[listindex-1];
	im = &state->map[msgno-1];
	msgfile.base = 0;
	msgfile.size = 0;

	/* expunged messages never match */
	if (im->record.system_flags & FLAG_EXPUNGED)
	    continue;

	if (index_search_evaluate(state, searchargs, msgno, &msgfile)) {
	    (*msgno_list)[n++] = msgno;
	    if (highestmodseq && im->record.modseq > *highestmodseq) {
		*highestmodseq = im->record.modseq;
	    }
	    /* We only care about MAX, so we're done on first match */
	    listindex = 0;
	}
	if (msgfile.base) {
	    mailbox_unmap_message(mailbox, im->record.uid,
				  &msgfile.base, &msgfile.size);
	}
    }

    /* if we didn't find any matches, free msgno_list */
    if (!n && *msgno_list) {
	free(*msgno_list);
	*msgno_list = NULL;
    }

    return n;
}

unsigned index_getuid(struct index_state *state, uint32_t msgno) {
  return state->map[msgno-1].record.uid;
}

/* 'uid_list' is malloc'd string representing the hits from searchargs;
   returns number of hits */
int index_getuidsequence(struct index_state *state,
			 struct searchargs *searchargs,
			 unsigned **uid_list)
{
    unsigned *msgno_list;
    int i, n;

    n = _index_search(&msgno_list, state, searchargs, NULL);
    if (n == 0) {
	*uid_list = NULL;
	return 0;
    }

    *uid_list = msgno_list;

    /* filthy in-place replacement */
    for (i = 0; i < n; i++)
	(*uid_list)[i] = index_getuid(state, msgno_list[i]);

    return n;
}

int index_lock(struct index_state *state)
{
    int r = mailbox_lock_index(state->mailbox, LOCK_EXCLUSIVE);
    if (!r) index_refresh(state);
    return r;
}

int index_status(struct index_state *state, struct statusdata *sdata)
{
    int items = STATUS_MESSAGES | STATUS_UIDNEXT | STATUS_UIDVALIDITY |
		STATUS_HIGHESTMODSEQ | STATUS_RECENT | STATUS_UNSEEN;
    statuscache_fill(sdata, state->userid, state->mailbox, items,
		     state->numrecent, state->numunseen);
    return 0;
}

void index_unlock(struct index_state *state)
{
    /* XXX - errors */

    index_writeseen(state);

    /* grab the latest modseq */
    state->highestmodseq = state->mailbox->i.highestmodseq;

    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	struct statusdata sdata;
	index_status(state, &sdata);
	/* RECENT is zero for everyone else because we wrote a new
	 * recentuid! */
	sdata.recent = 0;
	mailbox_unlock_index(state->mailbox, &sdata);
    }
    else
	mailbox_unlock_index(state->mailbox, NULL);
}

/*
 * Performs a SEARCH command.
 * This is a wrapper around _index_search() which simply prints the results.
 */
int index_search(struct index_state *state, struct searchargs *searchargs,
		 int usinguid)
{
    unsigned *list = NULL;
    int i, n;
    modseq_t highestmodseq = 0;

    /* update the index */
    if (index_check(state, 0, 0))
	return 0;

    /* now do the search */
    n = _index_search(&list, state, searchargs, 
		      searchargs->modseq ? &highestmodseq : NULL);

    /* replace the values now */
    if (usinguid)
	for (i = 0; i < n; i++)
	    list[i] = state->map[list[i]-1].record.uid;

    if (searchargs->returnopts) {
	prot_printf(state->out, "* ESEARCH");
	if (searchargs->tag) {
	    prot_printf(state->out, " (TAG \"%s\")", searchargs->tag);
	}
	if (n) {
	    if (usinguid) prot_printf(state->out, " UID");
	    if (searchargs->returnopts & SEARCH_RETURN_MIN)
		prot_printf(state->out, " MIN %u", list[0]);
	    if (searchargs->returnopts & SEARCH_RETURN_MAX)
		prot_printf(state->out, " MAX %u", list[n-1]);
	    if (highestmodseq)
		prot_printf(state->out, " MODSEQ " MODSEQ_FMT, highestmodseq);
	    if (searchargs->returnopts & SEARCH_RETURN_ALL) {
		struct seqset *seq;
		char *str;

		/* Create a sequence-set */
		seq = seqset_init(0, SEQ_SPARSE);
		for (i = 0; i < n; i++)
		    seqset_add(seq, list[i], 1);

		if (seq->len) {
		    str = seqset_cstring(seq);
		    prot_printf(state->out, " ALL %s", str);
		    free(str);
		}

		seqset_free(seq);
	    }
	}
	if (searchargs->returnopts & SEARCH_RETURN_COUNT) {
	    prot_printf(state->out, " COUNT %u", n);
	}
    }
    else {
	prot_printf(state->out, "* SEARCH");

	for (i = 0; i < n; i++)
	    prot_printf(state->out, " %u", list[i]);

	if (highestmodseq)
	    prot_printf(state->out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    if (n) free(list);

    prot_printf(state->out, "\r\n");

    return n;
}

/*
 * Performs a SORT command
 */
int index_sort(struct index_state *state, struct sortcrit *sortcrit,
	       struct searchargs *searchargs, int usinguid)
{
    unsigned *msgno_list;
    MsgData *msgdata = NULL, *freeme = NULL;
    int nmsg;
    clock_t start;
    modseq_t highestmodseq = 0;
    int i, modseq = 0;

    /* update the index */
    if (index_check(state, 0, 0))
	return 0;

    if(CONFIG_TIMING_VERBOSE)
	start = clock();

    if (searchargs->modseq) modseq = 1;
    else {
	for (i = 0; sortcrit[i].key != SORT_SEQUENCE; i++) {
	    if (sortcrit[i].key == SORT_MODSEQ) {
		modseq = 1;
		break;
	    }
	}
    }

    /* Search for messages based on the given criteria */
    nmsg = _index_search(&msgno_list, state, searchargs,
			 modseq ? &highestmodseq : NULL);

    prot_printf(state->out, "* SORT");

    if (nmsg) {
	/* Create/load the msgdata array */
	freeme = msgdata = index_msgdata_load(state, msgno_list, nmsg, sortcrit);
	free(msgno_list);

	/* Sort the messages based on the given criteria */
	msgdata = lsort(msgdata,
			(void * (*)(void*)) index_sort_getnext,
			(void (*)(void*,void*)) index_sort_setnext,
			(int (*)(void*,void*,void*)) index_sort_compare,
			sortcrit);

	/* Output the sorted messages */ 
	while (msgdata) {
	    unsigned no = usinguid ? state->map[msgdata->msgno-1].record.uid
				   : msgdata->msgno;
	    prot_printf(state->out, " %u", no);

	    /* free contents of the current node */
	    index_msgdata_free(msgdata);

	    msgdata = msgdata->next;
	}

	/* free the msgdata array */
	free(freeme);
    }

    if (highestmodseq)
	prot_printf(state->out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);

    prot_printf(state->out, "\r\n");

    /* debug */
    if (CONFIG_TIMING_VERBOSE) {
	int len;
	char *key_names[] = { "SEQUENCE", "ARRIVAL", "CC", "DATE", "FROM",
			      "SIZE", "SUBJECT", "TO", "ANNOTATION", "MODSEQ",
			      "DISPLAYFROM", "DISPLAYTO" };
	char buf[1024] = "";

	while (sortcrit->key && sortcrit->key < VECTOR_SIZE(key_names)) {
	    if (sortcrit->flags & SORT_REVERSE)
		strlcat(buf, "REVERSE ", sizeof(buf));

	    strlcat(buf, key_names[sortcrit->key], sizeof(buf));

	    switch (sortcrit->key) {
	    case SORT_ANNOTATION:
		len = strlen(buf);
		snprintf(buf + len, sizeof(buf) - len,
			 " \"%s\" \"%s\"",
			 sortcrit->args.annot.entry, sortcrit->args.annot.attrib);
		break;
	    }
	    if ((++sortcrit)->key) strlcat(buf, " ", sizeof(buf));
	}

	syslog(LOG_DEBUG, "SORT (%s) processing time: %d msg in %f sec",
	       buf, nmsg, (clock() - start) / (double) CLOCKS_PER_SEC);
    }

    return nmsg;
}

/*
 * Performs a THREAD command
 */
int index_thread(struct index_state *state, int algorithm,
		 struct searchargs *searchargs, int usinguid)
{
    unsigned *msgno_list;
    int nmsg;
    clock_t start;
    modseq_t highestmodseq = 0;

    /* update the index */
    if (index_check(state, 0, 0))
	return 0;
    
    if(CONFIG_TIMING_VERBOSE)
	start = clock();

    /* Search for messages based on the given criteria */
    nmsg = _index_search(&msgno_list, state, searchargs,
			 searchargs->modseq ? &highestmodseq : NULL);

    if (nmsg) {
	/* Thread messages using given algorithm */
	(*thread_algs[algorithm].threader)(state, msgno_list, nmsg, usinguid);

	free(msgno_list);

	if (highestmodseq)
	    prot_printf(state->out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    /* print an empty untagged response */
    else
	index_thread_print(state, NULL, usinguid);

    prot_printf(state->out, "\r\n");

    if (CONFIG_TIMING_VERBOSE) {
	/* debug */
	syslog(LOG_DEBUG, "THREAD %s processing time: %d msg in %f sec",
	       thread_algs[algorithm].alg_name, nmsg,
	       (clock() - start) / (double) CLOCKS_PER_SEC);
    }

    return nmsg;
}

/*
 * Performs a COPY command
 */
int
index_copy(struct index_state *state,
	   char *sequence, 
	   int usinguid,
	   char *name, 
	   char **copyuidp,
	   int nolink)
{
    static struct copyargs copyargs;
    int i;
    uquota_t totalsize = 0;
    int r;
    struct appendstate appendstate;
    uint32_t msgno, checkval;
    unsigned long uidvalidity;
    unsigned long startuid, num;
    unsigned baseuid;
    long docopyuid;
    struct seqset *seq;
    struct mailbox *mailbox = state->mailbox;
    struct mailbox *destmailbox = NULL;
    struct index_map *im;

    *copyuidp = NULL;

    copyargs.nummsg = 0;

    r = index_check(state, usinguid, usinguid);
    if (r) return r;

    seq = _parse_sequence(state, sequence, usinguid);

    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];
	checkval = usinguid ? im->record.uid : msgno;
	if (!seqset_ismember(seq, checkval))
	    continue;
	index_copysetup(state, msgno, &copyargs);
    }

    seqset_free(seq);

    if (copyargs.nummsg == 0) return IMAP_NO_NOSUCHMSG;

    for (i = 0; i < copyargs.nummsg; i++)
	totalsize += copyargs.copymsg[i].size;

    r = append_setup(&appendstate, name, state->userid,
		     state->authstate, ACL_INSERT, totalsize);
    if (r) return r;

    docopyuid = (appendstate.myrights & ACL_READ);
    baseuid = appendstate.mailbox->i.last_uid + 1;

    r = append_copy(mailbox, &appendstate, copyargs.nummsg,
		    copyargs.copymsg, nolink);
    if (!r) {
	r = append_commit(&appendstate, totalsize,
		      &uidvalidity, &startuid, &num, &destmailbox);
    }

    if (!r && docopyuid) {
	char *source;
	struct seqset *seq;
	unsigned uidvalidity = destmailbox->i.uidvalidity;

	seq = seqset_init(0, SEQ_SPARSE);

	for (i = 0; i < copyargs.nummsg; i++)
	    seqset_add(seq, copyargs.copymsg[i].uid, 1);

	source = seqset_cstring(seq);
	*copyuidp = xmalloc(strlen(source) + 50);

	if (appendstate.nummsg == 1)
	    sprintf(*copyuidp, "%u %s %u", uidvalidity, source, baseuid);
	else
	    sprintf(*copyuidp, "%u %s %u:%u", uidvalidity, source,
		    baseuid, baseuid + appendstate.nummsg - 1);

	free(source);
	seqset_free(seq);
    }

    if (!r) {
	/* we log the first name to get GUID-copy magic */
	mailbox_close(&destmailbox);
	sync_log_mailbox_double(mailbox->name, name);
    }

    return r;
}

/*
 * Helper function to multiappend a message to remote mailbox
 */
static int index_appendremote(struct index_state *state, uint32_t msgno, 
			      struct protstream *pout)
{
    struct mailbox *mailbox = state->mailbox;
    const char *msg_base = 0;
    unsigned long msg_size = 0;
    unsigned flag, flagmask;
    char datebuf[30];
    char sepchar = '(';
    struct index_map *im = &state->map[msgno-1];

    /* Open the message file */
    if (mailbox_map_message(mailbox, im->record.uid, &msg_base, &msg_size)) 
	return IMAP_NO_MSGGONE;

    /* start the individual append */
    prot_printf(pout, " ");

    /* add system flags */
    if (im->record.system_flags & FLAG_ANSWERED) {
	prot_printf(pout, "%c\\Answered", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_FLAGGED) {
	prot_printf(pout, "%c\\Flagged", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_DRAFT) {
	prot_printf(pout, "%c\\Draft", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_DELETED) {
	prot_printf(pout, "%c\\Deleted", sepchar);
	sepchar = ' ';
    }
    if (im->isseen) {
	prot_printf(pout, "%c\\Seen", sepchar);
	sepchar = ' ';
    }

    /* add user flags */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if ((flag & 31) == 0) {
	    flagmask = im->record.user_flags[flag/32];
	}
	if (state->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    prot_printf(pout, "%c%s", sepchar, state->flagname[flag]);
	    sepchar = ' ';
	}
    }

    /* add internal date */
    cyrus_ctime(im->record.internaldate, datebuf);
    prot_printf(pout, ") \"%s\" ", datebuf);

    /* message literal */
    index_fetchmsg(state, msg_base, msg_size, 0, im->record.size, 0, 0);

    /* close the message file */
    if (msg_base) 
	mailbox_unmap_message(mailbox, im->record.uid, &msg_base, &msg_size);

    return 0;
}

/*
 * Performs a COPY command from a local mailbox to a remote mailbox
 */
int index_copy_remote(struct index_state *state, char *sequence, 
		      int usinguid, struct protstream *pout)
{
    uint32_t msgno, checkval;
    struct seqset *seq;
    struct index_map *im;
    int r;

    r = index_check(state, usinguid, usinguid);
    if (r) return r;

    seq = _parse_sequence(state, sequence, usinguid);

    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];
	checkval = usinguid ? im->record.uid : msgno;
	if (!seqset_ismember(seq, checkval))
	    continue;
	index_appendremote(state, msgno, pout);
    }

    seqset_free(seq);

    return 0;
}

/*
 * Returns the msgno of the message with UID 'uid'.
 * If no message with UID 'uid', returns the message with
 * the higest UID not greater than 'uid'.
 */
unsigned index_finduid(struct index_state *state, unsigned uid)
{
    unsigned low = 1;
    unsigned high = state->exists;
    unsigned mid;
    unsigned miduid;

    while (low <= high) {
	mid = (high - low)/2 + low;
	miduid = index_getuid(state, mid);
	if (miduid == uid)
	    return mid;
	else if (miduid > uid)
	    high = mid - 1;
	else
	    low = mid + 1;
    }
    return high;
}

/* Helper function to determine domain of data */
enum {
    DOMAIN_7BIT = 0,
    DOMAIN_8BIT,
    DOMAIN_BINARY
};

static int data_domain(const char *p, size_t n)
{
    while (n--) {
	if (!*p) return DOMAIN_BINARY;
	if (*p & 0x80) return DOMAIN_8BIT;
	p++;
    }
 
    return DOMAIN_7BIT;
}

/*
 * Helper function to fetch data from a message file.  Writes a
 * quoted-string or literal containing data from 'msg_base', which is
 * of size 'msg_size', starting at 'offset' and containing 'size'
 * octets.  If 'octet_count' is nonzero, the data is
 * further constrained by 'start_octet' and 'octet_count' as per the
 * IMAP command PARTIAL.
 */
void
index_fetchmsg(state, msg_base, msg_size, offset, size,
	       start_octet, octet_count)
struct index_state *state;
const char *msg_base;
unsigned long msg_size;
unsigned offset;
unsigned size;     /* this is the correct size for a news message after
		      having LF translated to CRLF */
unsigned start_octet;
unsigned octet_count;
{
  unsigned n, domain;

    /* If no data, output NIL */
    if (!msg_base) {
	prot_printf(state->out, "NIL");
	return;
    }

    /* partial fetch: adjust 'size' */
    if (octet_count) {
	if (size <= start_octet) {
	    size = 0;
	}
	else {
	    size -= start_octet;
	}
	if (size > octet_count) size = octet_count;
    }

    /* If zero-length data, output empty quoted string */
    if (size == 0) {
	prot_printf(state->out, "\"\"");
	return;
    }

    /* Seek over PARTIAL constraint */
    offset += start_octet;
    n = size;
    if (offset + size > msg_size) {
	if (msg_size > offset) {
	    n = msg_size - offset;
	}
	else {
	    prot_printf(state->out, "\"\"");
	    return;
	}
    }

    /* Get domain of the data */
    domain = data_domain(msg_base + offset, n);

    if (domain == DOMAIN_BINARY) {
	/* Write size of literal8 */
	prot_printf(state->out, "~{%u}\r\n", size);
    } else {
	/* Write size of literal */
	prot_printf(state->out, "{%u}\r\n", size);
    }

    /* Non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(state->out);

    prot_write(state->out, msg_base + offset, n);
    while (n++ < size) {
	/* File too short, resynch client.
	 *
	 * This can only happen if the reported size of the part
	 * is incorrect and would push us past EOF.
	 */
	(void)prot_putc(' ', state->out);
    }

    /* End of non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(state->out);
}

/*
 * Helper function to fetch a body section
 */
static int index_fetchsection(struct index_state *state, const char *resp,
			      const char *msg_base, unsigned long msg_size,
			      char *section, const char *cachestr, unsigned size,
			      unsigned start_octet, unsigned octet_count)
{
    const char *p;
    int32_t skip = 0;
    int fetchmime = 0;
    unsigned offset = 0;
    char *decbuf = NULL;

    p = section;

    /* Special-case BODY[] */
    if (*p == ']') {
	if (strstr(resp, "BINARY.SIZE")) {
	    prot_printf(state->out, "%s%u", resp, size);
	} else {
	    prot_printf(state->out, "%s", resp);
	    index_fetchmsg(state, msg_base, msg_size, 0, size,
			   start_octet, octet_count);
	}
	return 0;
    }

    while (*p != ']' && *p != 'M') {
	int num_parts = CACHE_ITEM_BIT32(cachestr);
	int r;

	/* Generate the actual part number */
	r = parseint32(p, &p, &skip);
	if (*p == '.') p++;

	/* Handle .0, .HEADER, and .TEXT */
	if (r || skip == 0) {
	    skip = 0;
	    /* We don't have any digits, so its a string */
	    switch (*p) {
	    case 'H':
		p += 6;
		fetchmime++;	/* .HEADER maps internally to .0.MIME */
		break;

	    case 'T':
		p += 4;
		break;		/* .TEXT maps internally to .0 */

	    default:
		fetchmime++;	/* .0 maps internally to .0.MIME */
		break;
	    }
	} 

	/* section number too large */
	if (skip >= num_parts) goto badpart;

	if (*p != ']' && *p != 'M') {
	    /* We are NOT at the end of a part specification, so there's
	     * a subpart being requested.  Find the subpart in the tree. */

	    /* Skip the headers for this part, along with the number of
	     * sub parts */
	    cachestr += num_parts * 5 * 4 + CACHE_ITEM_SIZE_SKIP;

	    /* Skip to the correct part */
	    while (--skip) {
		if (CACHE_ITEM_BIT32(cachestr) > 0) {
		    /* Skip each part at this level */
		    skip += CACHE_ITEM_BIT32(cachestr)-1;
		    cachestr += CACHE_ITEM_BIT32(cachestr) * 5 * 4;
		}
		cachestr += CACHE_ITEM_SIZE_SKIP;
	    }
	}
    }

    if (*p == 'M') fetchmime++;

    cachestr += skip * 5 * 4 + CACHE_ITEM_SIZE_SKIP + (fetchmime ? 0 : 2 * 4);
    
    if (CACHE_ITEM_BIT32(cachestr + CACHE_ITEM_SIZE_SKIP) == (bit32) -1)
	goto badpart;

    offset = CACHE_ITEM_BIT32(cachestr);
    size = CACHE_ITEM_BIT32(cachestr + CACHE_ITEM_SIZE_SKIP);

    if (msg_base && (p = strstr(resp, "BINARY"))) {
	/* BINARY or BINARY.SIZE */
	int encoding = CACHE_ITEM_BIT32(cachestr + 2 * 4) & 0xff;
	size_t newsize;

	/* check that the offset isn't corrupt */
	if (offset + size > msg_size) {
	    syslog(LOG_ERR, "invalid part offset in %s", state->mailbox->name);
	    return IMAP_IOERROR;
	}

	msg_base = charset_decode_mimebody(msg_base + offset, size, encoding,
					   &decbuf, 0, &newsize);

	if (!msg_base) {
	    /* failed to decode */
	    if (decbuf) free(decbuf);
	    return IMAP_NO_UNKNOWN_CTE;
	}
	else if (p[6] == '.') {
	    /* BINARY.SIZE */
	    prot_printf(state->out, "%s%zd", resp, newsize);
	    if (decbuf) free(decbuf);
	    return 0;
	}
	else {
	    /* BINARY */
	    offset = 0;
	    size = newsize;
	    msg_size = newsize;
	}
    }

    /* Output body part */
    prot_printf(state->out, "%s", resp);
    index_fetchmsg(state, msg_base, msg_size, offset, size,
		   start_octet, octet_count);

    if (decbuf) free(decbuf);
    return 0;

 badpart:
    if (strstr(resp, "BINARY.SIZE"))
	prot_printf(state->out, "%s0", resp);
    else
	prot_printf(state->out, "%sNIL", resp);
    return 0;
}

/*
 * Helper function to fetch a HEADER.FIELDS[.NOT] body section
 */
static void index_fetchfsection(struct index_state *state,
				const char *msg_base,
				unsigned long msg_size,
				struct fieldlist *fsection,
				const char *cachestr,
				unsigned start_octet, unsigned octet_count)
{
    const char *p;
    int32_t skip = 0;
    int fields_not = 0;
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    char *buf;
    unsigned size;
    int r;

    /* If no data, output null quoted string */
    if (!msg_base) {
	prot_printf(state->out, "\"\"");
	return;
    }

    p = fsection->section;

    while (*p != 'H') {
	int num_parts = CACHE_ITEM_BIT32(cachestr);

	r = parseint32(p, &p, &skip);
	if (*p == '.') p++;

	/* section number too large */
	if (r || skip == 0 || skip >= num_parts) goto badpart;

	cachestr += num_parts * 5 * 4 + CACHE_ITEM_SIZE_SKIP;
	while (--skip) {
	    if (CACHE_ITEM_BIT32(cachestr) > 0) {
		skip += CACHE_ITEM_BIT32(cachestr)-1;
		cachestr += CACHE_ITEM_BIT32(cachestr) * 5 * 4;
	    }
	    cachestr += CACHE_ITEM_SIZE_SKIP;
	}
    }

    /* leaf object */
    if (0 == CACHE_ITEM_BIT32(cachestr)) goto badpart;

    cachestr += 4;

    if (CACHE_ITEM_BIT32(cachestr+CACHE_ITEM_SIZE_SKIP) == (bit32) -1)
	goto badpart;
	
    if (p[13]) fields_not++;	/* Check for "." after "HEADER.FIELDS" */

    buf = index_readheader(msg_base, msg_size, 
			   CACHE_ITEM_BIT32(cachestr),
			   CACHE_ITEM_BIT32(cachestr+CACHE_ITEM_SIZE_SKIP));

    if (fields_not) {
	index_pruneheader(buf, 0, fsection->fields);
    }
    else {
	index_pruneheader(buf, fsection->fields, 0);
    }
    size = strlen(buf);

    /* partial fetch: adjust 'size' */
    if (octet_count) {
	if (size <= start_octet) {
	    crlf_start = start_octet - size;
	    size = 0;
	    start_octet = 0;
	    if (crlf_size <= crlf_start) {
		crlf_size = 0;
	    }
	    else {
		crlf_size -= crlf_start;
	    }
	}
	else {
	    size -= start_octet;
	}
	if (size > octet_count) {
	    size = octet_count;
	    crlf_size = 0;
	}
	else if (size + crlf_size > octet_count) {
	    crlf_size = octet_count - size;
	}
    }

    /* If no data, output null quoted string */
    if (size + crlf_size == 0) {
	prot_printf(state->out, "\"\"");
	return;
    }

    /* Write literal */
    prot_printf(state->out, "{%u}\r\n", size + crlf_size);
    prot_write(state->out, buf + start_octet, size);
    prot_write(state->out, "\r\n" + crlf_start, crlf_size);

    return;

 badpart:
    prot_printf(state->out, "NIL");
}

/*
 * Helper function to read a header section into a static buffer
 */
static char *
index_readheader(msg_base, msg_size, offset, size)
const char *msg_base;
unsigned long msg_size;
unsigned offset;
unsigned size;
{
    static char *buf;
    static unsigned bufsize;

    if (offset + size > msg_size) {
	/* Message file is too short, truncate request */
	if (offset < msg_size) {
	    size = msg_size - offset;
	}
	else {
	    size = 0;
	}
    }

    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    msg_base += offset;

    memcpy(buf, msg_base, size);
    buf[size] = '\0';

    return buf;
}

/*
 * Prune the header section in buf to include only those headers
 * listed in headers or (if headers_not is non-empty) those headers
 * not in headers_not.
 */
static void
index_pruneheader(char *buf, struct strlist *headers,
		  struct strlist *headers_not)
{
    char *p, *colon, *nextheader;
    int goodheader;
    char *endlastgood = buf;
    struct strlist *l;
    
    p = buf;
    while (*p && *p != '\r') {
	colon = strchr(p, ':');
	if (colon && headers_not) {
	    goodheader = 1;
	    for (l = headers_not; l; l = l->next) {
		if ((size_t) (colon - p) == strlen(l->s) &&
		    !strncasecmp(p, l->s, colon - p)) {
		    goodheader = 0;
		    break;
		}
	    }
	} else {
	    goodheader = 0;
	}
	if (colon) {
	    for (l = headers; l; l = l->next) {
		if ((size_t) (colon - p) == strlen(l->s) &&
		    !strncasecmp(p, l->s, colon - p)) {
		    goodheader = 1;
		    break;
		}
	    }
	}

	nextheader = p;
	do {
	    nextheader = strchr(nextheader, '\n');
	    if (nextheader) nextheader++;
	    else nextheader = p + strlen(p);
	} while (*nextheader == ' ' || *nextheader == '\t');

	if (goodheader) {
	    if (endlastgood != p) {
		/* memmove and not strcpy since this is all within a
		 * single buffer */
		memmove(endlastgood, p, strlen(p) + 1);
		nextheader -= p - endlastgood;
	    }
	    endlastgood = nextheader;
	}
	p = nextheader;
    }
	    
    *endlastgood = '\0';
}

/*
 * Handle a FETCH RFC822.HEADER.LINES or RFC822.HEADER.LINES.NOT
 * that can't use the cacheheaders in cyrus.cache
 */
static void index_fetchheader(struct index_state *state,
			      const char *msg_base,
			      unsigned long msg_size,
			      unsigned size,
			      struct strlist *headers,
			      struct strlist *headers_not)
{
    char *buf;

    /* If no data, output null quoted string */
    if (!msg_base) {
	prot_printf(state->out, "\"\"");
	return;
    }

    buf = index_readheader(msg_base, msg_size, 0, size);

    index_pruneheader(buf, headers, headers_not);

    size = strlen(buf);
    prot_printf(state->out, "{%u}\r\n%s\r\n", size+2, buf);
}

/*
 * Handle a FETCH RFC822.HEADER.LINES that can use the
 * cacheheaders in cyrus.cache
 */
static void
index_fetchcacheheader(struct index_state *state, struct index_record *record,
		       struct strlist *headers, unsigned start_octet,
		       unsigned octet_count)
{
    static char *buf;
    static unsigned bufsize;
    unsigned size;
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    struct mailbox *mailbox = state->mailbox;

    if (mailbox_cacherecord(mailbox, record)) {
	/* bogus cache record */
	prot_printf(state->out, "\"\"");
	return;
    }

    size = cacheitem_size(record, CACHE_HEADERS);
    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    memcpy(buf, cacheitem_base(record, CACHE_HEADERS), size);
    buf[size] = '\0';

    index_pruneheader(buf, headers, 0);
    size = strlen(buf);

    /* partial fetch: adjust 'size' */
    if (octet_count) {
	if (size <= start_octet) {
	    crlf_start = start_octet - size;
	    size = 0;
	    start_octet = 0;
	    if (crlf_size <= crlf_start) {
		crlf_size = 0;
	    }
	    else {
		crlf_size -= crlf_start;
	    }
	}
	else {
	    size -= start_octet;
	}
	if (size > octet_count) {
	    size = octet_count;
	    crlf_size = 0;
	}
	else if (size + crlf_size > octet_count) {
	    crlf_size = octet_count - size;
	}
    }
	
    if (size + crlf_size == 0) {
	prot_printf(state->out, "\"\"");
    }
    else {
	prot_printf(state->out, "{%u}\r\n", size + crlf_size);
	prot_write(state->out, buf + start_octet, size);
	prot_write(state->out, "\r\n" + crlf_start, crlf_size);
    }
}

/*
 * Send a * FLAGS response.
 */
static void index_listflags(struct index_state *state)
{
    unsigned i;
    int cancreate = 0;
    char sepchar = '(';

    prot_printf(state->out, "* FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen");
    for (i = 0; i < MAX_USER_FLAGS; i++) {
	if (state->flagname[i]) {
	    prot_printf(state->out, " %s", state->flagname[i]);
	}
	else cancreate++;
    }
    prot_printf(state->out, ")\r\n* OK [PERMANENTFLAGS ");
    if (!state->examining) {
	if (state->myrights & ACL_WRITE) {
	    prot_printf(state->out, "%c\\Answered \\Flagged \\Draft", sepchar);
	    sepchar = ' ';
	}
	if (state->myrights & ACL_DELETEMSG) {
	    prot_printf(state->out, "%c\\Deleted", sepchar);
	    sepchar = ' ';
	}
	if (state->myrights & ACL_SEEN) {
	    prot_printf(state->out, "%c\\Seen", sepchar);
	    sepchar = ' ';
	}
	if (state->myrights & ACL_WRITE) {
	    for (i = 0; i < MAX_USER_FLAGS; i++) {
		if (state->flagname[i]) {
		    prot_printf(state->out, " %s", state->flagname[i]);
		}
	    }
	    if (cancreate) {
		prot_printf(state->out, " \\*");
	    }
	}
    }
    if (sepchar == '(') prot_printf(state->out, "(");
    prot_printf(state->out, ")] Ok\r\n");
}

static void index_checkflags(struct index_state *state, int dirty)
{
    struct mailbox *mailbox = state->mailbox;
    unsigned i;

    for (i = 0; i < MAX_USER_FLAGS; i++) {
	/* both empty */
	if (!mailbox->flagname[i] && !state->flagname[i])
	    continue;

	/* both same */
	if (mailbox->flagname[i] && state->flagname[i] &&
	    !strcmp(mailbox->flagname[i], state->flagname[i]))
	    continue;

	/* ok, got something to change! */
	if (state->flagname[i])
	    free(state->flagname[i]);
	if (mailbox->flagname[i])
	    state->flagname[i] = xstrdup(mailbox->flagname[i]);
	else
	    state->flagname[i] = NULL;

	dirty = 1;
    }

    if (dirty)
	index_listflags(state);
}

static void index_tellexpunge(struct index_state *state)
{
    unsigned oldmsgno;
    uint32_t msgno = 1;
    struct seqset *vanishedlist;
    struct index_map *im;
    unsigned exists = state->exists;

    vanishedlist = seqset_init(0, SEQ_SPARSE);

    for (oldmsgno = 1; oldmsgno <= exists; oldmsgno++) {
	im = &state->map[oldmsgno-1];

	/* inform about expunges */
	if (im->record.system_flags & FLAG_EXPUNGED) {
	    state->exists--;
	    /* they never knew about this one, skip */
	    if (msgno > state->oldexists)
		continue;
	    state->oldexists--;
	    if (state->qresync)
		seqset_add(vanishedlist, im->record.uid, 1);
	    else
		prot_printf(state->out, "* %u EXPUNGE\r\n", msgno);
	    continue;
	}

	/* copy back if necessary (after first expunge) */
	if (msgno < oldmsgno)
	    state->map[msgno-1] = *im;

	msgno++;
    }

    /* report all vanished if we're doing it this way */
    if (vanishedlist->len) {
	char *vanished = seqset_cstring(vanishedlist);
	prot_printf(state->out, "* VANISHED %s\r\n", vanished);
	free(vanished);
    }
    seqset_free(vanishedlist);

    /* highestmodseq can now come forward to real-time */
    state->highestmodseq = state->mailbox->i.highestmodseq;
}

static void index_tellexists(struct index_state *state)
{
    prot_printf(state->out, "* %u EXISTS\r\n", state->exists);
    prot_printf(state->out, "* %u RECENT\r\n", state->numrecent);
    state->oldexists = state->exists;
}

void index_tellchanges(struct index_state *state, int canexpunge,
		       int printuid)
{
    uint32_t msgno;
    struct index_map *im;

    if (canexpunge) index_tellexpunge(state);

    if (state->oldexists != state->exists) index_tellexists(state);

    index_checkflags(state, 0);

    /* print any changed message flags */
    for (msgno = 1; msgno <= state->exists; msgno++) {
	im = &state->map[msgno-1];

	/* we don't report flag updates if it's been expunged */
	if (im->record.system_flags & FLAG_EXPUNGED)
	    continue;

	/* report if it's changed since last told */
	if (im->record.modseq > im->told_modseq)
	    index_printflags(state, msgno, printuid);
    }
}
/*
 * Helper function to send * FETCH (FLAGS data.
 * Does not send the terminating close paren or CRLF.
 * Also sends preceeding * FLAGS if necessary.
 */
static void index_fetchflags(struct index_state *state,
			     uint32_t msgno)
{
    int sepchar = '(';
    unsigned flag;
    bit32 flagmask = 0;
    struct index_map *im = &state->map[msgno-1];

    prot_printf(state->out, "* %u FETCH (FLAGS ", msgno);

    if (im->isrecent) {
	prot_printf(state->out, "%c\\Recent", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_ANSWERED) {
	prot_printf(state->out, "%c\\Answered", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_FLAGGED) {
	prot_printf(state->out, "%c\\Flagged", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_DRAFT) {
	prot_printf(state->out, "%c\\Draft", sepchar);
	sepchar = ' ';
    }
    if (im->record.system_flags & FLAG_DELETED) {
	prot_printf(state->out, "%c\\Deleted", sepchar);
	sepchar = ' ';
    }
    if (im->isseen) {
	prot_printf(state->out, "%c\\Seen", sepchar);
	sepchar = ' ';
    }
    for (flag = 0; flag < VECTOR_SIZE(state->flagname); flag++) {
	if ((flag & 31) == 0) {
	    flagmask = im->record.user_flags[flag/32];
	}
	if (state->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    prot_printf(state->out, "%c%s", sepchar, state->flagname[flag]);
	    sepchar = ' ';
	}
    }
    if (sepchar == '(') (void)prot_putc('(', state->out);
    (void)prot_putc(')', state->out);
    im->told_modseq = im->record.modseq;
}

static void index_printflags(struct index_state *state,
			     uint32_t msgno, int usinguid)
{
    struct index_map *im = &state->map[msgno-1];

    index_fetchflags(state, msgno);
    /* http://www.rfc-editor.org/errata_search.php?rfc=5162
     * Errata ID: 1807 - MUST send UID and MODSEQ to all
     * untagged FETCH unsolicited responses */
    if (usinguid || state->qresync)
	prot_printf(state->out, " UID %u", im->record.uid);
    if (state->qresync)
	prot_printf(state->out, " MODSEQ (" MODSEQ_FMT ")", im->record.modseq);
    prot_printf(state->out, ")\r\n");
}

/*
 * Helper function to send requested * FETCH data for a message
 */
static int index_fetchreply(struct index_state *state, uint32_t msgno,
			    struct fetchargs *fetchargs)
{
    struct mailbox *mailbox = state->mailbox;
    int fetchitems = fetchargs->fetchitems;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    struct octetinfo *oi = NULL;
    int sepchar = '(';
    int started = 0;
    struct strlist *section, *field;
    struct fieldlist *fsection;
    char respbuf[100];
    int r = 0;
    struct index_map *im = &state->map[msgno-1];

    /* Check the modseq against changedsince */
    if (fetchargs->changedsince &&
	im->record.modseq <= fetchargs->changedsince) {
	return 0;
    }

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_RFC822)) ||
	fetchargs->cache_atleast > im->record.cache_version || 
	fetchargs->binsections || fetchargs->sizesections ||
	fetchargs->bodysections) {
	if (mailbox_map_message(mailbox, im->record.uid, &msg_base, &msg_size)) {
	    prot_printf(state->out, "* OK ");
	    prot_printf(state->out, error_message(IMAP_NO_MSGGONE), msgno);
	    prot_printf(state->out, "\r\n");
	    return 0;
	}
    }

    /* display flags if asked _OR_ if they've changed */
    if (fetchitems & FETCH_FLAGS || im->told_modseq < im->record.modseq) {
	index_fetchflags(state, msgno);
	sepchar = ' ';
    }
    else if ((fetchitems & ~FETCH_SETSEEN) ||  fetchargs->fsections ||
	     fetchargs->headers || fetchargs->headers_not) {
	/* these fetch items will always succeed, so start the response */
	prot_printf(state->out, "* %u FETCH ", msgno);
	started = 1;
    }
    if (fetchitems & FETCH_UID) {
	prot_printf(state->out, "%cUID %u", sepchar, im->record.uid);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_INTERNALDATE) {
	time_t msgdate = im->record.internaldate;
	char datebuf[30];

	cyrus_ctime(msgdate, datebuf);

	prot_printf(state->out, "%cINTERNALDATE \"%s\"",
		    sepchar, datebuf);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_MODSEQ) {
	prot_printf(state->out, "%cMODSEQ (" MODSEQ_FMT ")",
		    sepchar, im->record.modseq);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_SIZE) {
	prot_printf(state->out, "%cRFC822.SIZE %u", 
		    sepchar, im->record.size);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_ENVELOPE) {
        if (!mailbox_cacherecord(mailbox, &im->record)) {
	    prot_printf(state->out, "%cENVELOPE ", sepchar);
	    sepchar = ' ';
	    prot_putbuf(state->out, cacheitem_buf(&im->record, CACHE_ENVELOPE));
	}
    }
    if (fetchitems & FETCH_BODYSTRUCTURE) {
        if (!mailbox_cacherecord(mailbox, &im->record)) {
	    prot_printf(state->out, "%cBODYSTRUCTURE ", sepchar);
	    sepchar = ' ';
	    prot_putbuf(state->out, cacheitem_buf(&im->record, CACHE_BODYSTRUCTURE));
	}
    }
    if (fetchitems & FETCH_BODY) {
        if (!mailbox_cacherecord(mailbox, &im->record)) {
	    prot_printf(state->out, "%cBODY ", sepchar);
	    sepchar = ' ';
	    prot_putbuf(state->out, cacheitem_buf(&im->record, CACHE_BODY));
	}
    }

    if (fetchitems & FETCH_HEADER) {
	prot_printf(state->out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchmsg(state, msg_base, msg_size, 0,
		       im->record.header_size,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->start_octet : 0,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->octet_count : 0);
    }
    else if (fetchargs->headers || fetchargs->headers_not) {
	prot_printf(state->out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	if (fetchargs->cache_atleast > im->record.cache_version) {
	    index_fetchheader(state, msg_base, msg_size,
			      im->record.header_size,
			      fetchargs->headers, fetchargs->headers_not);
	} else {
	    index_fetchcacheheader(state, &im->record, fetchargs->headers, 0, 0);
	}
    }

    if (fetchitems & FETCH_TEXT) {
	prot_printf(state->out, "%cRFC822.TEXT ", sepchar);
	sepchar = ' ';
	index_fetchmsg(state, msg_base, msg_size,
		       im->record.header_size, im->record.size - im->record.header_size,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->start_octet : 0,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->octet_count : 0);
    }
    if (fetchitems & FETCH_RFC822) {
	prot_printf(state->out, "%cRFC822 ", sepchar);
	sepchar = ' ';
	index_fetchmsg(state, msg_base, msg_size, 0, im->record.size,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->start_octet : 0,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->octet_count : 0);
    }
    for (fsection = fetchargs->fsections; fsection; fsection = fsection->next) {
	prot_printf(state->out, "%cBODY[%s ", sepchar, fsection->section);
	sepchar = '(';
	for (field = fsection->fields; field; field = field->next) {
	    (void)prot_putc(sepchar, state->out);
	    sepchar = ' ';
	    prot_printastring(state->out, field->s);
	}
	(void)prot_putc(')', state->out);
	sepchar = ' ';

	oi = (struct octetinfo *)fsection->rock;

	prot_printf(state->out, "%s ", fsection->trail);

	if (fetchargs->cache_atleast > im->record.cache_version) {
	    if (!mailbox_cacherecord(mailbox, &im->record))
		index_fetchfsection(state, msg_base, msg_size,
				    fsection,
				    cacheitem_base(&im->record, CACHE_SECTION),
				    (fetchitems & FETCH_IS_PARTIAL) ?
				      fetchargs->start_octet : oi->start_octet,
				    (fetchitems & FETCH_IS_PARTIAL) ?
				      fetchargs->octet_count : oi->octet_count);
	    else
		prot_printf(state->out, "NIL");
	    
	}
	else {
	    index_fetchcacheheader(state, &im->record, fsection->fields,
				   (fetchitems & FETCH_IS_PARTIAL) ?
				     fetchargs->start_octet : oi->start_octet,
				   (fetchitems & FETCH_IS_PARTIAL) ?
				     fetchargs->octet_count : oi->octet_count);
	}
    }
    for (section = fetchargs->bodysections; section; section = section->next) {
	respbuf[0] = 0;
	if (sepchar == '(' && !started) {
	    /* we haven't output a fetch item yet, so start the response */
	    snprintf(respbuf, sizeof(respbuf), "* %u FETCH ", msgno);
	}
	snprintf(respbuf+strlen(respbuf), sizeof(respbuf)-strlen(respbuf),
		 "%cBODY[%s ", sepchar, section->s);

	oi = section->rock;

	if (!mailbox_cacherecord(mailbox, &im->record)) {
	    r = index_fetchsection(state, respbuf,
				   msg_base, msg_size,
				   section->s, cacheitem_base(&im->record, CACHE_SECTION),
				   im->record.size,
				   (fetchitems & FETCH_IS_PARTIAL) ?
				    fetchargs->start_octet : oi->start_octet,
				   (fetchitems & FETCH_IS_PARTIAL) ?
				    fetchargs->octet_count : oi->octet_count);
	    if (!r) sepchar = ' ';
	}
    }
    for (section = fetchargs->binsections; section; section = section->next) {
	respbuf[0] = 0;
	if (sepchar == '(' && !started) {
	    /* we haven't output a fetch item yet, so start the response */
	    snprintf(respbuf, sizeof(respbuf), "* %u FETCH ", msgno);
	}
	snprintf(respbuf+strlen(respbuf), sizeof(respbuf)-strlen(respbuf),
		 "%cBINARY[%s ", sepchar, section->s);

	if (!mailbox_cacherecord(mailbox, &im->record)) {
	    oi = section->rock;
	    r = index_fetchsection(state, respbuf,
				   msg_base, msg_size,
				   section->s, cacheitem_base(&im->record, CACHE_SECTION),
				   im->record.size,
				   (fetchitems & FETCH_IS_PARTIAL) ?
				    fetchargs->start_octet : oi->start_octet,
				   (fetchitems & FETCH_IS_PARTIAL) ?
				    fetchargs->octet_count : oi->octet_count);
	    if (!r) sepchar = ' ';
	}
    }
    for (section = fetchargs->sizesections; section; section = section->next) {
	respbuf[0] = 0;
	if (sepchar == '(' && !started) {
	    /* we haven't output a fetch item yet, so start the response */
	    snprintf(respbuf, sizeof(respbuf), "* %u FETCH ", msgno);
	}
	snprintf(respbuf+strlen(respbuf), sizeof(respbuf)-strlen(respbuf),
		 "%cBINARY.SIZE[%s ", sepchar, section->s);

        if (!mailbox_cacherecord(mailbox, &im->record)) {
	    r = index_fetchsection(state, respbuf,
				   msg_base, msg_size,
				   section->s, cacheitem_base(&im->record, CACHE_SECTION),
				   im->record.size,
				   fetchargs->start_octet, fetchargs->octet_count);
	    if (!r) sepchar = ' ';
	}
    }
    if (sepchar != '(') {
	/* finsh the response if we have one */
	prot_printf(state->out, ")\r\n");
    }
    if (msg_base) 
	mailbox_unmap_message(mailbox, im->record.uid, &msg_base, &msg_size);

    return r;
}

/*
 * Fetch the text data associated with an IMAP URL.
 *
 * If outsize is NULL, the data will be output as a literal (URLFETCH),
 * otherwise just the data will be output (CATENATE), and its size returned
 * in *outsize.
 *
 * This is an amalgamation of index_fetchreply(), index_fetchsection()
 * and index_fetchmsg().
 */
int index_urlfetch(struct index_state *state, uint32_t msgno,
		   unsigned params, const char *section,
		   unsigned long start_octet, unsigned long octet_count,
		   struct protstream *pout, unsigned long *outsize)
{
    const char *data, *msg_base = 0;
    unsigned long msg_size = 0;
    const char *cacheitem;
    int fetchmime = 0, domain = DOMAIN_7BIT;
    unsigned size;
    int32_t skip = 0;
    int n, r = 0;
    char *decbuf = NULL;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    if (outsize) *outsize = 0;

    r = mailbox_cacherecord(mailbox, &im->record);
    if (r) return r;

    /* Open the message file */
    if (mailbox_map_message(mailbox, im->record.uid, &msg_base, &msg_size))
	return IMAP_NO_MSGGONE;

    data = msg_base;
    size = im->record.size;

    if (size > msg_size) size = msg_size;

    cacheitem = cacheitem_base(&im->record, CACHE_SECTION);

    /* Special-case BODY[] */
    if (!section || !*section) {
	/* whole message, no further parsing */
    }
    else {
	const char *p = ucase((char *) section);

	while (*p && *p != 'M') {
	    int num_parts = CACHE_ITEM_BIT32(cacheitem);

	    /* Generate the actual part number */
	    r = parseint32(p, &p, &skip);
	    if (*p == '.') p++;

	    /* Handle .0, .HEADER, and .TEXT */
	    if (r || skip == 0) {
		skip = 0;
		/* We don't have any digits, so its a string */
		switch (*p) {
		case 'H':
		    p += 6;
		    fetchmime++;  /* .HEADER maps internally to .0.MIME */
		    break;

		case 'T':
		    p += 4;
		    break;	  /* .TEXT maps internally to .0 */

		default:
		    fetchmime++;  /* .0 maps internally to .0.MIME */
		    break;
		}
	    }

	    /* section number too large */
	    if (skip >= num_parts) {
		r = IMAP_BADURL;
		goto done;
	    }

	    if (*p && *p != 'M') {
		/* We are NOT at the end of a part specification, so there's
		 * a subpart being requested.  Find the subpart in the tree. */

		/* Skip the headers for this part, along with the number of
		 * sub parts */
		cacheitem += num_parts * 5 * 4 + CACHE_ITEM_SIZE_SKIP;

		/* Skip to the correct part */
		while (--skip) {
		    if (CACHE_ITEM_BIT32(cacheitem) > 0) {
			/* Skip each part at this level */
			skip += CACHE_ITEM_BIT32(cacheitem)-1;
			cacheitem += CACHE_ITEM_BIT32(cacheitem) * 5 * 4;
		    }
		    cacheitem += CACHE_ITEM_SIZE_SKIP;
		}
	    }
	}

	if (*p == 'M') fetchmime++;

	cacheitem += skip * 5 * 4 + CACHE_ITEM_SIZE_SKIP +
	    (fetchmime ? 0 : 2 * 4);
    
	if (CACHE_ITEM_BIT32(cacheitem + CACHE_ITEM_SIZE_SKIP) == (bit32) -1) {
	    r = IMAP_BADURL;
	    goto done;
	}

	data += CACHE_ITEM_BIT32(cacheitem);
	size = CACHE_ITEM_BIT32(cacheitem + CACHE_ITEM_SIZE_SKIP);
    }

    /* Handle extended URLFETCH parameters */
    if (params & URLFETCH_BODYPARTSTRUCTURE) {
	prot_printf(pout, " (BODYPARTSTRUCTURE");
	/* XXX Calculate body part structure */
	prot_printf(pout, " NIL");
	prot_printf(pout, ")");
    }

    if (params & URLFETCH_BODY) {
	prot_printf(pout, " (BODY");
    }
    else if (params & URLFETCH_BINARY) {
	int encoding = CACHE_ITEM_BIT32(cacheitem + 2 * 4) & 0xff;

	prot_printf(pout, " (BINARY");

	data = charset_decode_mimebody(data, size, encoding,
				       &decbuf, 0, (size_t *) &size);
	if (!data) {
	    /* failed to decode */
	    prot_printf(pout, " NIL)");
	    r = 0;
	    goto done;
	}
    }

    /* Handle PARTIAL request */
    n = octet_count ? octet_count : size;

    /* Sanity check the requested size */
    if (start_octet + n > size) n = size - start_octet;

    if (outsize) {
	/* Return size (CATENATE) */
	*outsize = n;
    } else {
	domain = data_domain(data + start_octet, n);

	if (domain == DOMAIN_BINARY) {
	    /* Write size of literal8 */
	    prot_printf(pout, " ~{%u}\r\n", n);
	} else {
	    /* Write size of literal */
	    prot_printf(pout, " {%u}\r\n", n);
	}
    }

    /* Non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(pout);

    prot_write(pout, data + start_octet, n);

    /* End of non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(pout);

    /* Complete extended URLFETCH response */
    if (params & (URLFETCH_BODY | URLFETCH_BINARY)) prot_printf(pout, ")");

    r = 0;

  done:
    /* Close the message file */
    mailbox_unmap_message(mailbox, im->record.uid, &msg_base, &msg_size);

    if (decbuf) free(decbuf);
    return r;
}

/*
 * Helper function to perform a generalized STORE command
 */
static int index_storeflag(struct index_state *state, uint32_t msgno,
			   struct storeargs *storeargs)
{
    bit32 old, new;
    unsigned i;
    int dirty = 0;
    modseq_t oldmodseq;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];
    int r;

    /* if it's changed already, skip out now */
    if (im->record.modseq > storeargs->unchangedsince) return 0;

    /* if it's expunged already, skip out now */
    if (im->record.system_flags & FLAG_EXPUNGED)
	return 0;

    oldmodseq = im->record.modseq;

    /* Change \Seen flag */
    if (state->myrights & ACL_SEEN) {
	old = im->isseen ? 1 : 0;
	new = old;
	if (storeargs->operation == STORE_REPLACE)
	    new = storeargs->seen ? 1 : 0;
	else if (storeargs->seen)
	    new = (storeargs->operation == STORE_ADD) ? 1 : 0;

	if (new != old) {
	    state->numunseen += (old - new);
	    im->isseen = new;
	    state->seen_dirty = 1;
	    dirty++;
	}
    }

    old = im->record.system_flags;
    new = storeargs->system_flags;

    if (storeargs->operation == STORE_REPLACE) {
	if (!(state->myrights & ACL_WRITE)) {
	    /* ACL_DELETE handled in index_store() */
	    if ((old & FLAG_DELETED) != (new & FLAG_DELETED)) {
		dirty++;
	        im->record.system_flags = (old & ~FLAG_DELETED) | (new & FLAG_DELETED);
	    }
	}
	else {
	    if (!(state->myrights & ACL_DELETEMSG)) {
		if ((old & ~FLAG_DELETED) != (new & ~FLAG_DELETED)) {
		    dirty++;
		    im->record.system_flags = (old & FLAG_DELETED) | (new & ~FLAG_DELETED);
		}
	    }
	    else {
		if (old != new) {
		    dirty++;
		    im->record.system_flags = new;
		}
	    }
	    for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
		if (im->record.user_flags[i] != storeargs->user_flags[i]) {
		    dirty++;
		    im->record.user_flags[i] = storeargs->user_flags[i];
		}
	    }
	}
    }
    else if (storeargs->operation == STORE_ADD) {
	if (~old & new) {
	    dirty++;
	    im->record.system_flags = old | new;
	}
	for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
	    if (~im->record.user_flags[i] & storeargs->user_flags[i]) {
		dirty++;
		im->record.user_flags[i] |= storeargs->user_flags[i];
	    }
	}
    }
    else { /* STORE_REMOVE */
	if (old & new) {
	    dirty++;
	    im->record.system_flags &= ~storeargs->system_flags;
	}
	for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
	    if (im->record.user_flags[i] & storeargs->user_flags[i]) {
		dirty++;
		im->record.user_flags[i] &= ~storeargs->user_flags[i];
	    }
	}
    }

    /* rfc4551:
     * 3.8.  Additional Quality-of-Implementation Issues
     *
     * Server implementations should follow the following rule, which
     * applies to any successfully completed STORE/UID STORE (with and
     * without UNCHANGEDSINCE modifier), as well as to a FETCH command that
     * implicitly sets \Seen flag:
     *
     *    Adding the flag when it is already present or removing when it is
     *    not present SHOULD NOT change the mod-sequence.
     *
     * This will prevent spurious client synchronization requests.
     */
    if (!dirty) return 0;

    if (state->internalseen) {
	/* set the seen flag */
	if (im->isseen)
	    im->record.system_flags |= FLAG_SEEN;
	else
	    im->record.system_flags &= ~FLAG_SEEN;
    }

    r = mailbox_rewrite_index_record(mailbox, &im->record);
    if (r) return r;

    /* if it's silent and unchanged, update the seen value, but
     * not if qresync is enabled - RFC 4551 says that the MODSEQ
     * must always been told, and we prefer just to tell flags
     * as well in this case, it's simpler and not much more
     * bandwidth */
    if (!state->qresync && storeargs->silent && im->told_modseq == oldmodseq)
	im->told_modseq = im->record.modseq;

    return 0;
}

int _search_searchbuf(char *s, comp_pat *p, struct buf *b)
{
    if (!b->len)
	return 0;

    return charset_searchstring(s, p, b->s, b->len);
}

/*
 * Evaluate a searchargs structure on a msgno
 *
 * Note: msgfile argument must be 0 if msg is not mapped in.
 */
static int index_search_evaluate(struct index_state *state,
				 struct searchargs *searchargs,
				 uint32_t msgno,
				 struct mapfile *msgfile)
{
    unsigned i;
    struct strlist *l, *h;
    struct searchsub *s;
    struct seqset *seq;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    if ((searchargs->flags & SEARCH_RECENT_SET) && !im->isrecent)
	return 0;
    if ((searchargs->flags & SEARCH_RECENT_UNSET) && im->isrecent)
	return 0;
    if ((searchargs->flags & SEARCH_SEEN_SET) && !im->isseen)
	return 0;
    if ((searchargs->flags & SEARCH_SEEN_UNSET) && im->isseen)
	return 0;

    if (searchargs->smaller && im->record.size >= searchargs->smaller)
	return 0;
    if (searchargs->larger && im->record.size <= searchargs->larger)
	return 0;

    if (searchargs->after && im->record.internaldate < searchargs->after)
	return 0;
    if (searchargs->before && im->record.internaldate >= searchargs->before)
	return 0;
    if (searchargs->sentafter && im->record.sentdate < searchargs->sentafter)
	return 0;
    if (searchargs->sentbefore && im->record.sentdate >= searchargs->sentbefore)
	return 0;

    if (searchargs->modseq && im->record.modseq < searchargs->modseq)
	return 0;

    if (~im->record.system_flags & searchargs->system_flags_set)
	return 0;
    if (im->record.system_flags & searchargs->system_flags_unset)
	return 0;

    for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
	if (~im->record.user_flags[i] & searchargs->user_flags_set[i])
	    return 0;
	if (im->record.user_flags[i] & searchargs->user_flags_unset[i])
	    return 0;
    }

    for (seq = searchargs->sequence; seq; seq = seq->nextseq) {
	if (!seqset_ismember(seq, msgno)) return 0;
    }
    for (seq = searchargs->uidsequence; seq; seq = seq->nextseq) {
	if (!seqset_ismember(seq, im->record.uid)) return 0;
    }

    if (searchargs->from || searchargs->to || searchargs->cc ||
	searchargs->bcc || searchargs->subject || searchargs->messageid) {

	if (mailbox_cacherecord(mailbox, &im->record))
	    return 0;

	if (searchargs->messageid) {
	    char *tmpenv;
	    char *envtokens[NUMENVTOKENS];
	    char *msgid;
	    int msgidlen;

	    /* must be long enough to actually HAVE some contents */
	    if (cacheitem_size(&im->record, CACHE_ENVELOPE) <= 2)
		return 0;

	    /* get msgid out of the envelope */

	    /* get a working copy; strip outer ()'s */
	    /* +1 -> skip the leading paren */
	    /* -2 -> don't include the size of the outer parens */
	    tmpenv = xstrndup(cacheitem_base(&im->record, CACHE_ENVELOPE) + 1, 
			      cacheitem_size(&im->record, CACHE_ENVELOPE) - 2);
	    parse_cached_envelope(tmpenv, envtokens, VECTOR_SIZE(envtokens));

	    if (!envtokens[ENV_MSGID]) {
		/* free stuff */
		free(tmpenv);
		return 0;
	    }

	    msgid = lcase(envtokens[ENV_MSGID]);
	    msgidlen = strlen(msgid);
	    for (l = searchargs->messageid; l; l = l->next) {
		if (!charset_searchstring(l->s, l->p, msgid, msgidlen))
		    break;
	    }

	    /* free stuff */
	    free(tmpenv);

	    if (l) return 0;
	}

	for (l = searchargs->from; l; l = l->next) {
	    if (!_search_searchbuf(l->s, l->p, cacheitem_buf(&im->record, CACHE_FROM)))
		return 0;
	}

	for (l = searchargs->to; l; l = l->next) {
	    if (!_search_searchbuf(l->s, l->p, cacheitem_buf(&im->record, CACHE_TO)))
		return 0;
	}

	for (l = searchargs->cc; l; l = l->next) {
	    if (!_search_searchbuf(l->s, l->p, cacheitem_buf(&im->record, CACHE_CC)))
		return 0;
	}

	for (l = searchargs->bcc; l; l = l->next) {
	    if (!_search_searchbuf(l->s, l->p, cacheitem_buf(&im->record, CACHE_BCC)))
		return 0;
	}

	for (l = searchargs->subject; l; l = l->next) {
	    if ((cacheitem_size(&im->record, CACHE_SUBJECT) == 3 && 
		!strncmp(cacheitem_base(&im->record, CACHE_SUBJECT), "NIL", 3)) ||
		!_search_searchbuf(l->s, l->p, cacheitem_buf(&im->record, CACHE_SUBJECT)))
		return 0;
	}
    }

    for (s = searchargs->sublist; s; s = s->next) {
	if (index_search_evaluate(state, s->sub1, msgno, msgfile)) {
	    if (!s->sub2) return 0;
	}
	else {
	    if (s->sub2 &&
		!index_search_evaluate(state, s->sub2, msgno, msgfile))
	      return 0;
	}
    }

    if (searchargs->body || searchargs->text ||
	searchargs->cache_atleast > im->record.cache_version) {
	if (!msgfile->size) { /* Map the message in if we haven't before */
	    if (mailbox_map_message(mailbox, im->record.uid,
				    &msgfile->base, &msgfile->size)) {
		return 0;
	    }
	}

	h = searchargs->header_name;
	for (l = searchargs->header; l; (l = l->next), (h = h->next)) {
	    if (!index_searchheader(h->s, l->s, l->p, msgfile,
				    im->record.header_size)) return 0;
	}

	if (mailbox_cacherecord(mailbox, &im->record))
	    return 0;

	for (l = searchargs->body; l; l = l->next) {
	    if (!index_searchmsg(l->s, l->p, msgfile, 1,
				 cacheitem_base(&im->record, CACHE_SECTION))) return 0;
	}
	for (l = searchargs->text; l; l = l->next) {
	    if (!index_searchmsg(l->s, l->p, msgfile, 0,
				 cacheitem_base(&im->record, CACHE_SECTION))) return 0;
	}
    }
    else if (searchargs->header_name) {
	h = searchargs->header_name;
	for (l = searchargs->header; l; (l = l->next), (h = h->next)) {
	    if (!index_searchcacheheader(state, msgno, h->s, l->s, l->p))
		return 0;
	}
    }

    return 1;
}

/*
 * Search part of a message for a substring.
 * Keep this in sync with index_getsearchtextmsg!
 */
static int
index_searchmsg(char *substr,
		comp_pat *pat,
		struct mapfile *msgfile,
		int skipheader,
		const char *cachestr)
{
    int partsleft = 1;
    int subparts;
    unsigned long start;
    int len, charset, encoding;
    char *p, *q;
    
    /* Won't find anything in a truncated file */
    if (msgfile->size == 0) return 0;

    while (partsleft--) {
	subparts = CACHE_ITEM_BIT32(cachestr);
	cachestr += 4;
	if (subparts) {
	    partsleft += subparts-1;

	    if (skipheader) {
		skipheader = 0; /* Only skip top-level message header */
	    }
	    else {
		len = CACHE_ITEM_BIT32(cachestr + CACHE_ITEM_SIZE_SKIP);
		if (len > 0) {
		    p = index_readheader(msgfile->base, msgfile->size,
					 CACHE_ITEM_BIT32(cachestr),
					 len);
		    q = charset_decode_mimeheader(p, NULL, 0);
		    if (charset_searchstring(substr, pat, q, strlen(q))) {
			free(q);
			return 1;
		    }
		    free(q);
		}
	    }
	    cachestr += 5*4;

	    while (--subparts) {
		start = CACHE_ITEM_BIT32(cachestr+2*4);
		len = CACHE_ITEM_BIT32(cachestr+3*4);
		charset = CACHE_ITEM_BIT32(cachestr+4*4) >> 16;
		encoding = CACHE_ITEM_BIT32(cachestr+4*4) & 0xff;

		if (start < msgfile->size && len > 0 &&
		    charset >= 0 && charset < 0xffff) {
		    if (charset_searchfile(substr, pat,
					   msgfile->base + start,
					   len, charset, encoding)) return 1;
		}
		cachestr += 5*4;
	    }
	}
    }

    return 0;
}
    
/*
 * Search named header of a message for a substring
 */
static int index_searchheader(char *name,
			      char *substr,
			      comp_pat *pat,
			      struct mapfile *msgfile,
			      int size)
{
    char *p, *q;
    int r;
    static struct strlist header;

    header.s = name;

    p = index_readheader(msgfile->base, msgfile->size, 0, size);
    index_pruneheader(p, &header, 0);
    if (!*p) return 0;		/* Header not present, fail */
    if (!*substr) return 1;	/* Only checking existence, succeed */
    q = charset_decode_mimeheader(strchr(p, ':') + 1, NULL, 0);
    r = charset_searchstring(substr, pat, q, strlen(q));
    free(q);
    return r;
}

/*
 * Search named cached header of a message for a substring
 */
static int index_searchcacheheader(struct index_state *state, uint32_t msgno,
				   char *name, char *substr, comp_pat *pat)
{
    char *q;
    static struct strlist header;
    static char *buf;
    static unsigned bufsize;
    unsigned size;
    int r;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    r = mailbox_cacherecord(mailbox, &im->record);
    if (r) return 0;

    size = cacheitem_size(&im->record, CACHE_HEADERS);
    if (!size) return 0;	/* No cached headers, fail */
    
    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    /* Copy this item to the buffer */
    memcpy(buf, cacheitem_base(&im->record, CACHE_HEADERS), size);
    buf[size] = '\0';

    header.s = name;

    index_pruneheader(buf, &header, 0);
    if (!*buf) return 0;	/* Header not present, fail */
    if (!*substr) return 1;	/* Only checking existence, succeed */
    /* XXX - we could do this in one pass maybe? charset_search_mimeheader */
    q = charset_decode_mimeheader(strchr(buf, ':') + 1, NULL, 0);
    r = charset_searchstring(substr, pat, q, strlen(q));
    free(q);
    return r;
}


/* This code was cribbed from index_searchmsg. Instead of checking for matches,
   we call charset_extractfile to send the entire text out to 'receiver'.
   Keep this in sync with index_searchmsg! */
static void index_getsearchtextmsg(struct index_state *state,
				   int uid,
				   index_search_text_receiver_t receiver,
				   void *rock,
				   char const *cachestr) {
  struct mapfile msgfile;
  int partsleft = 1;
  int subparts;
  unsigned long start;
  int len, charset, encoding;
  int partcount = 0;
  char *p, *q;
  struct mailbox *mailbox = state->mailbox;
  
  if (mailbox_map_message(mailbox, uid, &msgfile.base, &msgfile.size)) {
    return;
  }

  /* Won't find anything in a truncated file */
  if (msgfile.size > 0) {
    while (partsleft--) {
	subparts = CACHE_ITEM_BIT32(cachestr);
	cachestr += 4;
	if (subparts) {
	    partsleft += subparts-1;

            partcount++;

            len = CACHE_ITEM_BIT32(cachestr+4);
            if (len > 0) {
              p = index_readheader(msgfile.base, msgfile.size,
                                   CACHE_ITEM_BIT32(cachestr),
                                   len);
              q = charset_decode_mimeheader(p, NULL, 0);
              if (partcount == 1) {
                receiver(uid, SEARCHINDEX_PART_HEADERS,
                         SEARCHINDEX_CMD_STUFFPART, q, strlen(q), rock);
                receiver(uid, SEARCHINDEX_PART_BODY,
                         SEARCHINDEX_CMD_BEGINPART, NULL, 0, rock);
              } else {
                receiver(uid, SEARCHINDEX_PART_BODY,
                         SEARCHINDEX_CMD_APPENDPART, q, strlen(q), rock);
              }
              free(q);
            }
	    cachestr += 5*4;

	    while (--subparts) {
		start = CACHE_ITEM_BIT32(cachestr+2*4);
		len = CACHE_ITEM_BIT32(cachestr+3*4);
		charset = CACHE_ITEM_BIT32(cachestr+4*4) >> 16;
		encoding = CACHE_ITEM_BIT32(cachestr+4*4) & 0xff;

		if (start < msgfile.size && len > 0) {
		  charset_extractfile(receiver, rock, uid,
				      msgfile.base + start,
				      len, charset, encoding);
		}
		cachestr += 5*4;
	    }
	}
    }

    receiver(uid, SEARCHINDEX_PART_BODY,
             SEARCHINDEX_CMD_ENDPART, NULL, 0, rock);
  }
  
  mailbox_unmap_message(mailbox, uid, &msgfile.base, &msgfile.size);
}

void index_getsearchtext_single(struct index_state *state, uint32_t msgno,
				index_search_text_receiver_t receiver,
				void *rock) {
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    if (mailbox_cacherecord(mailbox, &im->record))
	return;

    index_getsearchtextmsg(state, im->record.uid, receiver, rock,
	     cacheitem_base(&im->record, CACHE_SECTION));
    receiver(im->record.uid, SEARCHINDEX_PART_FROM, SEARCHINDEX_CMD_STUFFPART,
	     cacheitem_base(&im->record, CACHE_FROM),
	     cacheitem_size(&im->record, CACHE_FROM), rock);
    receiver(im->record.uid, SEARCHINDEX_PART_TO, SEARCHINDEX_CMD_STUFFPART,
	     cacheitem_base(&im->record, CACHE_TO),
	     cacheitem_size(&im->record, CACHE_TO), rock);
    receiver(im->record.uid, SEARCHINDEX_PART_CC, SEARCHINDEX_CMD_STUFFPART,
	     cacheitem_base(&im->record, CACHE_CC),
	     cacheitem_size(&im->record, CACHE_CC), rock);
    receiver(im->record.uid, SEARCHINDEX_PART_BCC, SEARCHINDEX_CMD_STUFFPART,
	     cacheitem_base(&im->record, CACHE_BCC),
	     cacheitem_size(&im->record, CACHE_BCC), rock);
    receiver(im->record.uid, SEARCHINDEX_PART_SUBJECT, SEARCHINDEX_CMD_STUFFPART,
	     cacheitem_base(&im->record, CACHE_SUBJECT),
	     cacheitem_size(&im->record, CACHE_SUBJECT), rock);
}

void index_getsearchtext(struct index_state *state,
			 index_search_text_receiver_t receiver,
			 void *rock)
{
    uint32_t msgno;

    /* Send the converted text of every message out to the receiver. */
    for (msgno = 1; msgno <= state->exists; msgno++)
	index_getsearchtext_single(state, msgno, receiver, rock);
}

/*
 * Helper function to set up arguments to append_copy()
 */
#define COPYARGSGROW 30
static int index_copysetup(struct index_state *state, uint32_t msgno,
			   struct copyargs *copyargs)
{
    int flag = 0;
    int userflag;
    bit32 flagmask = 0;
    int r;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    r = mailbox_cacherecord(mailbox, &im->record);
    if (r) return r;

    if (copyargs->nummsg == copyargs->msgalloc) {
	copyargs->msgalloc += COPYARGSGROW;
	copyargs->copymsg = (struct copymsg *)
	  xrealloc((char *)copyargs->copymsg,
		   copyargs->msgalloc * sizeof(struct copymsg));
    }

    copyargs->copymsg[copyargs->nummsg].uid = im->record.uid;
    copyargs->copymsg[copyargs->nummsg].internaldate = im->record.internaldate;
    copyargs->copymsg[copyargs->nummsg].sentdate = im->record.sentdate;
    copyargs->copymsg[copyargs->nummsg].gmtime = im->record.gmtime;
    copyargs->copymsg[copyargs->nummsg].size = im->record.size;
    copyargs->copymsg[copyargs->nummsg].header_size = im->record.header_size;
    copyargs->copymsg[copyargs->nummsg].content_lines = im->record.content_lines;
    copyargs->copymsg[copyargs->nummsg].cache_version = im->record.cache_version;
    copyargs->copymsg[copyargs->nummsg].cache_crc = im->record.cache_crc;
    copyargs->copymsg[copyargs->nummsg].crec = im->record.crec;

    message_guid_copy(&copyargs->copymsg[copyargs->nummsg].guid,
		      &im->record.guid);

    copyargs->copymsg[copyargs->nummsg].system_flags = im->record.system_flags;
    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
	if ((userflag & 31) == 0) {
	    flagmask = im->record.user_flags[userflag/32];
	}
	if (mailbox->flagname[userflag] && (flagmask & (1<<(userflag&31)))) {
	    copyargs->copymsg[copyargs->nummsg].flag[flag++] =
		mailbox->flagname[userflag];
	}
    }
    copyargs->copymsg[copyargs->nummsg].flag[flag] = 0;

    /* grab seen from our state - it's different for different users */
    copyargs->copymsg[copyargs->nummsg].seen = im->isseen;

    copyargs->nummsg++;

    return 0;
}

/*
 * Creates a list of msgdata.
 *
 * We fill these structs with the processed info that will be needed
 * by the specified sort criteria.
 */
#define ANNOTGROWSIZE 10

static MsgData *index_msgdata_load(struct index_state *state,
				   unsigned *msgno_list, int n,
				   struct sortcrit *sortcrit)
{
    MsgData *md, *cur;
    int i, j;
    char *tmpenv;
    char *envtokens[NUMENVTOKENS];
    int did_cache, did_env, did_conv;
    int label;
    int annotsize;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im;

    if (!n) return NULL;

    /* create an array of MsgData to use as nodes of linked list */
    md = (MsgData *) xmalloc(n * sizeof(MsgData));
    memset(md, 0, n * sizeof(MsgData));

    for (i = 0, cur = md; i < n; i++, cur = cur->next) {
	/* set msgno */
	cur->msgno = msgno_list[i];
	im = &state->map[cur->msgno-1];
	cur->uid = im->record.uid;

	/* set pointer to next node */
	cur->next = (i+1 < n ? cur+1 : NULL);

	did_cache = did_env = did_conv = 0;
	tmpenv = NULL;
	annotsize = 0;

	for (j = 0; sortcrit[j].key; j++) {
	    label = sortcrit[j].key;

	    if ((label == SORT_CC || label == SORT_DATE ||
		 label == SORT_FROM || label == SORT_SUBJECT ||
		 label == SORT_TO || label == LOAD_IDS ||
		 label == SORT_DISPLAYFROM || label == SORT_DISPLAYTO) &&
		!did_cache) {

		/* fetch cached info */
		if (mailbox_cacherecord(mailbox, &im->record))
		    continue; /* can't do this with a broken cache */

		did_cache++;
	    }

	    if ((label == LOAD_IDS) && !did_env) {
		/* no point if we don't have enough data */
		if (cacheitem_size(&im->record, CACHE_ENVELOPE) <= 2)
		    continue;

		/* make a working copy of envelope -- strip outer ()'s */
		/* +1 -> skip the leading paren */
		/* -2 -> don't include the size of the outer parens */
		tmpenv = xstrndup(cacheitem_base(&im->record, CACHE_ENVELOPE) + 1, 
				  cacheitem_size(&im->record, CACHE_ENVELOPE) - 2);

		/* parse envelope into tokens */
		parse_cached_envelope(tmpenv, envtokens,
				      VECTOR_SIZE(envtokens));

		did_env++;
	    }

	    switch (label) {
	    case SORT_CC:
		cur->cc = get_localpart_addr(cacheitem_base(&im->record, CACHE_CC));
		break;
	    case SORT_DATE:
		cur->date = im->record.gmtime;
		/* fall through */
	    case SORT_ARRIVAL:
		cur->internaldate = im->record.internaldate;
		break;
	    case SORT_FROM:
		cur->from = get_localpart_addr(cacheitem_base(&im->record, CACHE_FROM));
		break;
	    case SORT_MODSEQ:
		cur->modseq = im->record.modseq;
		break;
	    case SORT_SIZE:
		cur->size = im->record.size;
		break;
	    case SORT_SUBJECT:
		cur->xsubj = index_extract_subject(cacheitem_base(&im->record, CACHE_SUBJECT),
						   cacheitem_size(&im->record, CACHE_SUBJECT),
						   &cur->is_refwd);
		cur->xsubj_hash = strhash(cur->xsubj);
		break;
	    case SORT_TO:
		cur->to = get_localpart_addr(cacheitem_base(&im->record, CACHE_TO));
		break;
 	    case SORT_ANNOTATION:
 		/* reallocate space for the annotation values if necessary */
 		if (cur->nannot == annotsize) {
 		    annotsize += ANNOTGROWSIZE;
 		    cur->annot = (char **)
 			xrealloc(cur->annot, annotsize * sizeof(char *));
 		}

 		/* fetch attribute value - we fake it for now */
 		cur->annot[cur->nannot] = xstrdup(sortcrit[j].args.annot.attrib);
 		cur->nannot++;
 		break;
	    case LOAD_IDS:
		index_get_ids(cur, envtokens, cacheitem_base(&im->record, CACHE_HEADERS),
					      cacheitem_size(&im->record, CACHE_HEADERS));
		break;
	    case SORT_DISPLAYFROM:
		cur->displayfrom = get_displayname(
				   cacheitem_base(&im->record, CACHE_FROM));
		break;
	    case SORT_DISPLAYTO:
		cur->displayto = get_displayname(
				 cacheitem_base(&im->record, CACHE_TO));
		break;
	    }
	}

	free(tmpenv);
    }

    return md;
}

static char *get_localpart_addr(const char *header)
{
    struct address *addr = NULL;
    char *ret = NULL;

    parseaddr_list(header, &addr);
    if (!addr) return NULL;

    if (addr->mailbox)
	ret = xstrdup(addr->mailbox);

    parseaddr_free(addr);

    return ret;
}

/*
 * Get the 'display-name' of an address from a header
 */
static char *get_displayname(const char *header)
{
    struct address *addr = NULL;
    char *ret = NULL;

    parseaddr_list(header, &addr);
    if (!addr) return NULL;

    if (addr->name && addr->name[0]) {
	char *p;
	ret = xstrdup(addr->name);
	for (p = ret; *p; p++)
	    *p = toupper(*p);
    }
    else if (addr->domain && addr->mailbox) {
	/* mailbox@domain */
	int len = strlen(addr->mailbox) + strlen(addr->domain) + 2;
	ret = xmalloc(len);
	snprintf(ret, len, "%s@%s", addr->mailbox, addr->domain);
    }
    else if (addr->mailbox) {
	ret = xstrdup(addr->mailbox);
    }

    parseaddr_free(addr);

    return ret;
}

/*
 * Extract base subject from subject header
 *
 * This is a wrapper around _index_extract_subject() which preps the
 * subj NSTRING and checks for Netscape "[Fwd: ]".
 */
static char *index_extract_subject(const char *subj, size_t len, int *is_refwd)
{
    char *buf, *s, *base;

    /* parse the subj NSTRING and make a working copy */
    if (!strcmp(subj, "NIL")) {		       	/* NIL? */
	return xstrdup("");			/* yes, return empty */
    } else if (*subj == '"') {			/* quoted? */
	buf = xstrndup(subj + 1, len - 2);	/* yes, strip quotes */
    } else {
	s = strchr(subj, '}') + 3;		/* literal, skip { }\r\n */
	buf = xstrndup(s, len - (s - subj));
    }

    for (s = buf;;) {
	base = _index_extract_subject(s, is_refwd);

	/* If we have a Netscape "[Fwd: ...]", extract the contents */
	if (!strncasecmp(base, "[fwd:", 5) &&
	    base[strlen(base) - 1]  == ']') {

	    /* inc refwd counter */
	    *is_refwd += 1;

	    /* trim "]" */
	    base[strlen(base) - 1] = '\0';

	    /* trim "[fwd:" */
	    s = base + 5;
	}
	else /* otherwise, we're done */
	    break;
    }

    base = xstrdup(base);

    free(buf);

    for (s = base; *s; s++) {
	*s = toupper(*s);
    }

    return base;
}

/*
 * Guts if subject extraction.
 *
 * Takes a subject string and returns a pointer to the base.
 */
static char *_index_extract_subject(char *s, int *is_refwd)
{
    char *base, *x;

    /* trim trailer
     *
     * start at the end of the string and work towards the front,
     * resetting the end of the string as we go.
     */
    for (x = s + strlen(s) - 1; x >= s;) {
	if (Uisspace(*x)) {                             /* whitespace? */
	    *x = '\0';					/* yes, trim it */
	    x--;					/* skip past it */
	}
	else if (x - s >= 4 &&
		 !strncasecmp(x-4, "(fwd)", 5)) {	/* "(fwd)"? */
	    *(x-4) = '\0';				/* yes, trim it */
	    x -= 5;					/* skip past it */
	    *is_refwd += 1;				/* inc refwd counter */
	}
	else
	    break;					/* we're done */
    }

    /* trim leader
     *
     * start at the head of the string and work towards the end,
     * skipping over stuff we don't care about.
     */
    for (base = s; base;) {
	if (Uisspace(*base)) base++;			/* whitespace? */

	/* possible refwd */
	else if ((!strncasecmp(base, "re", 2) &&	/* "re"? */
		  (x = base + 2)) ||			/* yes, skip past it */
		 (!strncasecmp(base, "fwd", 3) &&	/* "fwd"? */
		  (x = base + 3)) ||			/* yes, skip past it */
		 (!strncasecmp(base, "fw", 2) &&	/* "fw"? */
		  (x = base + 2))) {			/* yes, skip past it */
	    int count = 0;				/* init counter */
	    
	    while (Uisspace(*x)) x++;			/* skip whitespace */

	    if (*x == '[') {				/* start of blob? */
		for (x++; x;) {				/* yes, get count */
		    if (!*x) {				/* end of subj, quit */
			x = NULL;
			break;
		    }
		    else if (*x == ']') {		/* end of blob, done */
			break;
					/* if we have a digit, and we're still
					   counting, keep building the count */
		    } else if (cyrus_isdigit((int) *x) && count != -1) {
			count = count * 10 + *x - '0';
			if (count < 0) {                /* overflow */
			    count = -1; /* abort counting */
			}
		    } else {				/* no digit, */
			count = -1;			/*  abort counting */
		    }
		    x++;
		}

		if (x)					/* end of blob? */
		    x++;				/* yes, skip past it */
		else
		    break;				/* no, we're done */
	    }

	    while (Uisspace(*x)) x++;                   /* skip whitespace */

	    if (*x == ':') {				/* ending colon? */
		base = x + 1;				/* yes, skip past it */
		*is_refwd += (count > 0 ? count : 1);	/* inc refwd counter
							   by count or 1 */
	    }
	    else
		break;					/* no, we're done */
	}

#if 0 /* do nested blobs - wait for decision on this */
	else if (*base == '[') {			/* start of blob? */
	    int count = 1;				/* yes, */
	    x = base + 1;				/*  find end of blob */
	    while (count) {				/* find matching ']' */
		if (!*x) {				/* end of subj, quit */
		    x = NULL;
		    break;
		}
		else if (*x == '[')			/* new open */
		    count++;				/* inc counter */
		else if (*x == ']')			/* close */
		    count--;				/* dec counter */
		x++;
	    }

	    if (!x)					/* blob didn't close */
		break;					/*  so quit */

	    else if (*x)				/* end of subj? */
		base = x;				/* no, skip blob */
#else
	else if (*base == '[' &&			/* start of blob? */
		 (x = strpbrk(base+1, "[]")) &&		/* yes, end of blob */
		 *x == ']') {				/*  (w/o nesting)? */

	    if (*(x+1))					/* yes, end of subj? */
		base = x + 1;				/* no, skip blob */
#endif
	    else
		break;					/* yes, return blob */
	}
	else
	    break;					/* we're done */
    }

    return base;
}

/* Find a message-id looking thingy in a string.  Returns a pointer to the
 * alloc'd id and the remaining string is returned in the **loc parameter.
 *
 * This is a poor-man's way of finding the message-id.  We simply look for
 * any string having the format "< ... @ ... >" and assume that the mail
 * client created a properly formatted message-id.
 */
#define MSGID_SPECIALS "<> @\\"

static char *find_msgid(char *str, char **rem)
{
    char *msgid, *src, *dst, *cp;

    if (!str) return NULL;

    msgid = NULL;
    src = str;

    /* find the start of a msgid (don't go past the end of the header) */
    while ((cp = src = strpbrk(src, "<\r")) != NULL) {

	/* check for fold or end of header
	 *
	 * Per RFC 2822 section 2.2.3, a long header may be folded by
	 * inserting CRLF before any WSP (SP and HTAB, per section 2.2.2).
	 * Any other CRLF is the end of the header.
	 */
	if (*cp++ == '\r') {
	    if (*cp++ == '\n' && !(*cp == ' ' || *cp == '\t')) {
		/* end of header, we're done */
		break;
	    }

	    /* skip fold (or junk) */
	    src++;
	    continue;
	}

	/* see if we have (and skip) a quoted localpart */
	if (*cp == '\"') {
	    /* find the endquote, making sure it isn't escaped */
	    do {
		++cp; cp = strchr(cp, '\"');
	    } while (cp && *(cp-1) == '\\');

	    /* no endquote, so bail */
	    if (!cp) {
		src++;
		continue;
	    }
	}

	/* find the end of the msgid */
	if ((cp = strchr(cp, '>')) == NULL)
	    return NULL;

	/* alloc space for the msgid */
	dst = msgid = (char*) xrealloc(msgid, cp - src + 2);

	*dst++ = *src++;

	/* quoted string */
	if (*src == '\"') {
	    src++;
	    while (*src != '\"') {
		if (*src == '\\') {
		    src++;
		}
		*dst++ = *src++;
	    }
	    src++;
	}
	/* atom */
	else {
	    while (!strchr(MSGID_SPECIALS, *src))
		*dst++ = *src++;
	}

	if (*src != '@' || *(dst-1) == '<') continue;
	*dst++ = *src++;

	/* domain atom */
	while (!strchr(MSGID_SPECIALS, *src))
	    *dst++ = *src++;

	if (*src != '>' || *(dst-1) == '@') continue;
	*dst++ = *src++;
	*dst = '\0';

	if (rem) *rem = src;
	return msgid;
    }

    if (msgid) free(msgid);
    return NULL;
}

/* Get message-id, and references/in-reply-to */
#define REFGROWSIZE 20

void index_get_ids(MsgData *msgdata, char *envtokens[], const char *headers,
		   unsigned size)
{
    static char *buf;
    static unsigned bufsize;
    static struct strlist refhdr;
    char *refstr, *ref, *in_reply_to;
    int refsize = REFGROWSIZE;

    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    /* get msgid */
    msgdata->msgid = find_msgid(envtokens[ENV_MSGID], NULL);
     /* if we don't have one, create one */
    if (!msgdata->msgid) {
	snprintf(buf, bufsize, "<Empty-ID: %u>", msgdata->msgno);
	msgdata->msgid = xstrdup(buf);
    }

    /* Copy headers to the buffer */
    memcpy(buf, headers, size);
    buf[size] = '\0';

    /* grab the References header */
    refhdr.s = "references";
    index_pruneheader(buf, &refhdr, 0);
    if (*buf) {
	/* allocate some space for refs */
	msgdata->ref = (char **) xmalloc(refsize * sizeof(char *));
	/* find references */
	massage_header(buf);
	refstr = buf;
	while ((ref = find_msgid(refstr, &refstr)) != NULL) {
	    /* reallocate space for this msgid if necessary */
	    if (msgdata->nref == refsize) {
		refsize += REFGROWSIZE;
		msgdata->ref = (char **)
		    xrealloc(msgdata->ref, refsize * sizeof(char *));
	    }
	    /* store this msgid in the array */
	    msgdata->ref[msgdata->nref++] = ref;
	}
    }

    /* if we have no references, try in-reply-to */
    if (!msgdata->nref) {
	/* get in-reply-to id */
	in_reply_to = find_msgid(envtokens[ENV_INREPLYTO], NULL);
	/* if we have an in-reply-to id, make it the ref */
	if (in_reply_to) {
	    msgdata->ref = (char **) xmalloc(sizeof(char *));
	    msgdata->ref[msgdata->nref++] = in_reply_to;
	}
    }
}

/*
 * Getnext function for sorting message lists.
 */
static void *index_sort_getnext(MsgData *node)
{
    return node->next;
}

/*
 * Setnext function for sorting message lists.
 */
static void index_sort_setnext(MsgData *node, MsgData *next)
{
    node->next = next;
}

/*
 * Function for comparing two integers.
 */
static int numcmp(modseq_t n1, modseq_t n2)
{
    return ((n1 < n2) ? -1 : (n1 > n2) ? 1 : 0);
}

/*
 * Comparison function for sorting message lists.
 */
static int index_sort_compare(MsgData *md1, MsgData *md2,
			      struct sortcrit *sortcrit)
{
    int reverse, ret = 0, i = 0, ann = 0;

    do {
	/* determine sort order from reverse flag bit */
	reverse = sortcrit[i].flags & SORT_REVERSE;

	switch (sortcrit[i].key) {
	case SORT_SEQUENCE:
	    ret = numcmp(md1->msgno, md2->msgno);
	    break;
	case SORT_ARRIVAL:
	    ret = numcmp(md1->internaldate, md2->internaldate);
	    break;
	case SORT_CC:
	    ret = strcmpsafe(md1->cc, md2->cc);
	    break;
	case SORT_DATE: {
	    time_t d1 = md1->date ? md1->date : md1->internaldate;
	    time_t d2 = md2->date ? md2->date : md2->internaldate;
	    ret = numcmp(d1, d2);
	    break;
	}
	case SORT_FROM:
	    ret = strcmpsafe(md1->from, md2->from);
	    break;
	case SORT_SIZE:
	    ret = numcmp(md1->size, md2->size);
	    break;
	case SORT_SUBJECT:
	    ret = strcmpsafe(md1->xsubj, md2->xsubj);
	    break;
	case SORT_TO:
	    ret = strcmpsafe(md1->to, md2->to);
	    break;
	case SORT_ANNOTATION:
	    ret = strcmpsafe(md1->annot[ann], md2->annot[ann]);
	    ann++;
	    break;
	case SORT_MODSEQ:
	    ret = numcmp(md1->modseq, md2->modseq);
	    break;
	case SORT_DISPLAYFROM:
	    ret = strcmpsafe(md1->displayfrom, md2->displayfrom);
	    break;
	case SORT_DISPLAYTO:
	    ret = strcmpsafe(md1->displayto, md2->displayto);
	    break;
	}
    } while (!ret && sortcrit[i++].key != SORT_SEQUENCE);

    return (reverse ? -ret : ret);
}

/*
 * Free a msgdata node.
 */
static void index_msgdata_free(MsgData *md)
{
#define FREE(x)	if (x) free(x)
    int i;

    if (!md)
	return;
    FREE(md->cc);
    FREE(md->from);
    FREE(md->to);
    FREE(md->displayfrom);
    FREE(md->displayto);
    FREE(md->xsubj);
    FREE(md->msgid);
    for (i = 0; i < md->nref; i++)
	free(md->ref[i]);
    FREE(md->ref);
    for (i = 0; i < md->nannot; i++)
	free(md->annot[i]);
    FREE(md->annot);
}

/*
 * Getnext function for sorting thread lists.
 */
static void *index_thread_getnext(Thread *thread)
{
    return thread->next;
}

/*
 * Setnext function for sorting thread lists.
 */
static void index_thread_setnext(Thread *thread, Thread *next)
{
    thread->next = next;
}

/*
 * Comparison function for sorting threads.
 */
static int index_thread_compare(Thread *t1, Thread *t2,
				struct sortcrit *call_data)
{
    MsgData *md1, *md2;

    /* if the container is empty, use the first child's container */
    md1 = t1->msgdata ? t1->msgdata : t1->child->msgdata;
    md2 = t2->msgdata ? t2->msgdata : t2->child->msgdata;
    return index_sort_compare(md1, md2, call_data);
}

/*
 * Sort a list of threads.
 */
static void index_thread_sort(Thread *root, struct sortcrit *sortcrit)
{
    Thread *child;

    /* sort the grandchildren */
    child = root->child;
    while (child) {
	/* if the child has children, sort them */
	if (child->child)
	    index_thread_sort(child, sortcrit);
	child = child->next;
    }

    /* sort the children */
    root->child = lsort(root->child,
			(void * (*)(void*)) index_thread_getnext,
			(void (*)(void*,void*)) index_thread_setnext,
			(int (*)(void*,void*,void*)) index_thread_compare,
			sortcrit);
}

/*
 * Thread a list of messages using the ORDEREDSUBJECT algorithm.
 */
static void index_thread_orderedsubj(struct index_state *state, 
				     unsigned *msgno_list, int nmsg,
				     int usinguid)
{
    MsgData *msgdata, *freeme;
    struct sortcrit sortcrit[] = {{ SORT_SUBJECT,  0, {{NULL, NULL}} },
				  { SORT_DATE,     0, {{NULL, NULL}} },
				  { SORT_SEQUENCE, 0, {{NULL, NULL}} }};
    unsigned psubj_hash = 0;
    char *psubj;
    Thread *head, *newnode, *cur, *parent, *last;

    /* Create/load the msgdata array */
    freeme = msgdata = index_msgdata_load(state, msgno_list, nmsg, sortcrit);

    /* Sort messages by subject and date */
    msgdata = lsort(msgdata,
		    (void * (*)(void*)) index_sort_getnext,
		    (void (*)(void*,void*)) index_sort_setnext,
		    (int (*)(void*,void*,void*)) index_sort_compare,
		    sortcrit);

    /* create an array of Thread to use as nodes of thread tree
     *
     * we will be building threads under a dummy head,
     * so we need (nmsg + 1) nodes
     */
    head = (Thread *) xmalloc((nmsg + 1) * sizeof(Thread));
    memset(head, 0, (nmsg + 1) * sizeof(Thread));

    newnode = head + 1;	/* set next newnode to the second
			   one in the array (skip the head) */
    parent = head;	/* parent is the head node */
    psubj = NULL;	/* no previous subject */
    cur = NULL;		/* no current thread */
    last = NULL;	/* no last child */

    while (msgdata) {
	newnode->msgdata = msgdata;

	/* if no previous subj, or
	   current subj = prev subj (subjs have same hash, and
	   the strings are equal), then add message to current thread */
	if (!psubj ||
	    (msgdata->xsubj_hash == psubj_hash &&
	     !strcmp(msgdata->xsubj, psubj))) {
	    /* if no children, create first child */
	    if (!parent->child) {
		last = parent->child = newnode;
		if (!cur)		/* first thread */
		    parent = cur = parent->child;
	    }
	    /* otherwise, add to siblings */
	    else {
		last->next = newnode;
		last = last->next;
	    }
	}
	/* otherwise, create a new thread */
	else {
	    cur->next = newnode;	/* create and start a new thread */
	    parent = cur = cur->next;	/* now work with the new thread */
	}

	psubj_hash = msgdata->xsubj_hash;
	psubj = msgdata->xsubj;
	msgdata = msgdata->next;
	newnode++;
    }

    /* Sort threads by date */
    index_thread_sort(head, sortcrit+1);

    /* Output the threaded messages */ 
    index_thread_print(state, head, usinguid);

    /* free the thread array */
    free(head);

    /* free the msgdata array */
    free(freeme);
}

/*
 * Guts of thread printing.  Recurses over children when necessary.
 *
 * Frees contents of msgdata as a side effect.
 */
static void _index_thread_print(struct index_state *state,
				Thread *thread, int usinguid)
{
    Thread *child;

    /* for each thread... */
    while (thread) {
	/* start the thread */
	prot_printf(state->out, "(");

	/* if we have a message, print its identifier
	 * (do nothing for empty containers)
	 */
	if (thread->msgdata) {
	    prot_printf(state->out, "%u",
			usinguid ? thread->msgdata->uid :
			thread->msgdata->msgno);

	    /* if we have a child, print the parent-child separator */
	    if (thread->child) prot_printf(state->out, " ");

	    /* free contents of the current node */
	    index_msgdata_free(thread->msgdata);
	}

	/* for each child, grandchild, etc... */
	child = thread->child;
	while (child) {
	    /* if the child has siblings, print new branch and break */
	    if (child->next) {
		_index_thread_print(state, child, usinguid);
		break;
	    }
	    /* otherwise print the only child */
	    else {
		prot_printf(state->out, "%u",
			    usinguid ? child->msgdata->uid :
			    child->msgdata->msgno);

		/* if we have a child, print the parent-child separator */
		if (child->child) prot_printf(state->out, " ");

		/* free contents of the child node */
		index_msgdata_free(child->msgdata);

		child = child->child;
	    }
	}

	/* end the thread */
	prot_printf(state->out, ")");

	thread = thread->next;
    }
}

/*
 * Print a list of threads.
 *
 * This is a wrapper around _index_thread_print() which simply prints the
 * start and end of the untagged thread response.
 */
static void index_thread_print(struct index_state *state,
			       Thread *thread, int usinguid)
{
    prot_printf(state->out, "* THREAD");

    if (thread) {
	prot_printf(state->out, " ");
	_index_thread_print(state, thread->child, usinguid);
    }
}

/*
 * Find threading algorithm for given arg.
 * Returns index into thread_algs[], or -1 if not found.
 */
int find_thread_algorithm(char *arg)
{
    int alg;

    ucase(arg);
    for (alg = 0; thread_algs[alg].alg_name; alg++) {
	if (!strcmp(arg, thread_algs[alg].alg_name))
	    return alg;
    }
    return -1;
}

/*
 * The following code is an interpretation of JWZ's description
 * and pseudo-code in http://www.jwz.org/doc/threading.html.
 *
 * It has been modified to match the THREAD=REFERENCES algorithm.
 */

/*
 * Determines if child is a descendent of parent.
 *
 * Returns 1 if yes, 0 otherwise.
 */
static int thread_is_descendent(Thread *parent, Thread *child)
{
    Thread *kid;

    /* self */
    if (parent == child)
	return 1;

    /* search each child's decendents */
    for (kid = parent->child; kid; kid = kid->next) {
	if (thread_is_descendent(kid, child))
	    return 1;
    }
    return 0;
}

/*
 * Links child into parent's children.
 */
static void thread_adopt_child(Thread *parent, Thread *child)
{
    child->parent = parent;
    child->next = parent->child;
    parent->child = child;
}

/*
 * Unlinks child from it's parent's children.
 */
static void thread_orphan_child(Thread *child)
{
    Thread *prev, *cur;

    /* sanity check -- make sure child is actually a child of parent */
    for (prev = NULL, cur = child->parent->child;
	 cur != child && cur != NULL; prev = cur, cur = cur->next);

    if (!cur) {
	/* uh oh!  couldn't find the child in it's parent's children
	 * we should probably return NO to thread command
	 */
	return;
    }

    /* unlink child */
    if (!prev)	/* first child */
	child->parent->child = child->next;
    else
	prev->next = child->next;
    child->parent = child->next = NULL;
}

/*
 * Link messages together using message-id and references.
 */
static void ref_link_messages(MsgData *msgdata, Thread **newnode,
		       struct hash_table *id_table)
{
    Thread *cur, *parent, *ref;
    int dup_count = 0;
    char buf[100];
    int i;

    /* for each message... */
    while (msgdata) {
	/* fill the containers with msgdata
	 *
	 * if we already have a container, use it
	 */
	if ((cur = (Thread *) hash_lookup(msgdata->msgid, id_table))) {
	    /* If this container is not empty, then we have a duplicate
	     * Message-ID.  Make this one unique so that we don't stomp
	     * on the old one.
	     */
	    if (cur->msgdata) {
		snprintf(buf, sizeof(buf), "-dup%d", dup_count++);
		msgdata->msgid =
		    (char *) xrealloc(msgdata->msgid,
				      strlen(msgdata->msgid) + strlen(buf) + 1);
		strcat(msgdata->msgid, buf);
		/* clear cur so that we create a new container */
		cur = NULL;
	    }
	    else
		cur->msgdata = msgdata;
	}

	/* otherwise, make and index a new container */
	if (!cur) {
	    cur = *newnode;
	    cur->msgdata = msgdata;
	    hash_insert(msgdata->msgid, cur, id_table);
	    (*newnode)++;
	}

	/* Step 1.A */
	for (i = 0, parent = NULL; i < msgdata->nref; i++) {
	    /* if we don't already have a container for the reference,
	     * make and index a new (empty) container
	     */
	    if (!(ref = (Thread *) hash_lookup(msgdata->ref[i], id_table))) {
		ref = *newnode;
		hash_insert(msgdata->ref[i], ref, id_table);
		(*newnode)++;
	    }

	    /* link the references together as parent-child iff:
	     * - we won't change existing links, AND
	     * - we won't create a loop
	     */
	    if (!ref->parent &&
		parent && !thread_is_descendent(ref, parent)) {
		thread_adopt_child(parent, ref);
	    }

	    parent = ref;
	}

	/* Step 1.B
	 *
	 * if we have a parent already, it is probably bogus (the result
	 * of a truncated references field), so unlink from it because
	 * we now have the actual parent
	 */
	if (cur->parent) thread_orphan_child(cur);

	/* make the last reference the parent of our message iff:
	 * - we won't create a loop
	 */
	if (parent && !thread_is_descendent(cur, parent))
	    thread_adopt_child(parent, cur);

	msgdata = msgdata->next;
    }
}

/*
 * Gather orphan messages under the root node.
 */
static void ref_gather_orphans(const char *key __attribute__((unused)),
			       void *data, void *rock)
{
    Thread *node = (Thread *)data;
    struct rootset *rootset = (struct rootset *)rock;

    /* we only care about nodes without parents */
    if (!node->parent) {
	if (node->next) {
	    /* uh oh!  a node without a parent should not have a sibling
	     * we should probably return NO to thread command
	     */
	    return;
	}

	/* add this node to root's children */
	node->next = rootset->root->child;
	rootset->root->child = node;
	rootset->nroot++;
    }
}

/*
 * Prune tree of empty containers.
 */
static void ref_prune_tree(Thread *parent)
{
    Thread *cur, *prev, *next, *child;

    for (prev = NULL, cur = parent->child, next = cur->next;
	 cur;
	 prev = cur, cur = next, next = (cur ? cur->next : NULL)) {

retry:
	/* if we have an empty container with no children, delete it */
	if (!cur->msgdata && !cur->child) {
	    if (!prev)	/* first child */
		parent->child = cur->next;
	    else
		prev->next = cur->next;

	    /* we just removed cur from our list,
	     * so we need to keep the same prev for the next pass
	     */
	    cur = prev;
	}

	/* if we have an empty container with children, AND
	 * we're not at the root OR we only have one child,
	 * then remove the container but promote its children to this level
	 * (splice them into the current child list)
	 */
	else if (!cur->msgdata && cur->child &&
		 (cur->parent || !cur->child->next)) {
	    /* move cur's children into cur's place (start the splice) */
	    if (!prev)	/* first child */
		parent->child = cur->child;
	    else
		prev->next = cur->child;

	    /* make cur's parent the new parent of cur's children
	     * (they're moving in with grandma!)
	     */
	    child = cur->child;
	    do {
		child->parent = cur->parent;
	    } while (child->next && (child = child->next));

	    /* make the cur's last child point to cur's next sibling
	     * (finish the splice)
	     */
	    child->next = cur->next;

	    /* we just replaced cur with it's children
	     * so make it's first child the next node to process
	     */
	    next = cur->child;

	    /* make cur childless and siblingless */
	    cur->child = cur->next = NULL;

	    /* we just removed cur from our list,
	     * so we need to keep the same prev for the next pass
	     */
	    cur = prev;
	}

	/* if we have a message with children, prune it's children */
	else if (cur->child) {
	    ref_prune_tree(cur);
	    if (!cur->msgdata && !cur->child) {
		/* Did we end up with a completely empty node here?
		 * Go back and prune it too.  See Bug 3784.  */
		goto retry;
	    }
	}
    }
}

/*
 * Sort the messages in the root set by date.
 */
static void ref_sort_root(Thread *root)
{
    Thread *cur;
    struct sortcrit sortcrit[] = {{ SORT_DATE,     0, {{NULL, NULL}} },
				  { SORT_SEQUENCE, 0, {{NULL, NULL}} }};

    cur = root->child;
    while (cur) {
	/* if the message is a dummy, sort its children */
	if (!cur->msgdata) {
	    cur->child = lsort(cur->child,
			       (void * (*)(void*)) index_thread_getnext,
			       (void (*)(void*,void*)) index_thread_setnext,
			       (int (*)(void*,void*,void*)) index_thread_compare,
			       sortcrit);
	}
	cur = cur->next;
    }

    /* sort the root set */
    root->child = lsort(root->child,
			(void * (*)(void*)) index_thread_getnext,
			(void (*)(void*,void*)) index_thread_setnext,
			(int (*)(void*,void*,void*)) index_thread_compare,
			sortcrit);
}

/*
 * Group threads with same subject.
 */
static void ref_group_subjects(Thread *root, unsigned nroot, Thread **newnode)
{
    Thread *cur, *old, *prev, *next, *child;
    struct hash_table subj_table;
    char *subj;

    /* Step 5.A: create a subj_table with one bucket for every possible
     * subject in the root set
     */
    construct_hash_table(&subj_table, nroot, 1);

    /* Step 5.B: populate the table with a container for each subject
     * at the root
     */
    for (cur = root->child; cur; cur = cur->next) {
	/* Step 5.B.i: find subject of the thread
	 *
	 * if the container is not empty, use it's subject
	 */
	if (cur->msgdata)
	    subj = cur->msgdata->xsubj;
	/* otherwise, use the subject of it's first child */
	else
	    subj = cur->child->msgdata->xsubj;

	/* Step 5.B.ii: if subject is empty, skip it */
	if (!strlen(subj)) continue;

	/* Step 5.B.iii: lookup this subject in the table */
	old = (Thread *) hash_lookup(subj, &subj_table);

	/* Step 5.B.iv: insert the current container into the table iff:
	 * - this subject is not in the table, OR
	 * - this container is empty AND the one in the table is not
	 *   (the empty one is more interesting as a root), OR
	 * - the container in the table is a re/fwd AND this one is not
	 *   (the non-re/fwd is the more interesting of the two)
	 */
	if (!old ||
	    (!cur->msgdata && old->msgdata) ||
	    (old->msgdata && old->msgdata->is_refwd &&
	     cur->msgdata && !cur->msgdata->is_refwd)) {
	  hash_insert(subj, cur, &subj_table);
	}
    }

    /* 5.C - group containers with the same subject together */
    for (prev = NULL, cur = root->child, next = cur->next;
	 cur;
	 prev = cur, cur = next, next = (next ? next->next : NULL)) {	
	/* Step 5.C.i: find subject of the thread
	 *
	 * if container is not empty, use it's subject
	 */
	if (cur->msgdata)
	    subj = cur->msgdata->xsubj;
	/* otherwise, use the subject of it's first child */
	else
	    subj = cur->child->msgdata->xsubj;

	/* Step 5.C.ii: if subject is empty, skip it */
	if (!strlen(subj)) continue;

	/* Step 5.C.iii: lookup this subject in the table */
	old = (Thread *) hash_lookup(subj, &subj_table);

	/* Step 5.C.iv: if we found ourselves, skip it */
	if (!old || old == cur) continue;

	/* ok, we already have a container which contains our current subject,
	 * so pull this container out of the root set, because we are going to
	 * merge this node with another one
	 */
	if (!prev)	/* we're at the root */
	    root->child = cur->next;
	else
	    prev->next = cur->next;
	cur->next = NULL;

	/* if both containers are dummies, append cur's children to old's */
	if (!old->msgdata && !cur->msgdata) {
	    /* find old's last child */
	    for (child = old->child; child->next; child = child->next);

	    /* append cur's children to old's children list */
	    child->next = cur->child;

	    /* make old the parent of cur's children */
	    for (child = cur->child; child; child = child->next)
		child->parent = old;

	    /* make cur childless */
	    cur->child = NULL;
	}

	/* if:
	 * - old container is empty, OR
	 * - the current message is a re/fwd AND the old one is not,
	 * make the current container a child of the old one
	 *
	 * Note: we don't have to worry about the reverse cases
	 * because step 5.B guarantees that they won't happen
	 */
	else if (!old->msgdata ||
		 (cur->msgdata && cur->msgdata->is_refwd &&
		  !old->msgdata->is_refwd)) {
	    thread_adopt_child(old, cur);
	}

	/* if both messages are re/fwds OR neither are re/fwds,
	 * then make them both children of a new dummy container
	 * (we don't want to assume any parent-child relationship between them)
	 *
	 * perhaps we can create a parent-child relationship
	 * between re/fwds by counting the number of re/fwds
	 *
	 * Note: we need the hash table to still point to old,
	 * so we must make old the dummy and make the contents of the
	 * new container a copy of old's original contents
	 */
	else {
	    Thread *new = (*newnode)++;

	    /* make new a copy of old (except parent and next) */
 	    new->msgdata = old->msgdata;
	    new->child = old->child;
	    new->next = NULL;

	    /* make new the parent of it's newly adopted children */
	    for (child = new->child; child; child = child->next)
		child->parent = new;

	    /* make old the parent of cur and new */
	    cur->parent = old;
	    new->parent = old;

	    /* empty old and make it have two children (cur and new) */
	    old->msgdata = NULL;
	    old->child = cur;
	    cur->next = new;
	}

	/* we just removed cur from our list,
	 * so we need to keep the same prev for the next pass
	 */
	cur = prev;
    }

    free_hash_table(&subj_table, NULL);
}

/*
 * Free an entire thread.
 */
static void index_thread_free(Thread *thread)
{
    Thread *child;

    /* free the head node */
    if (thread->msgdata) index_msgdata_free(thread->msgdata);

    /* free the children recursively */
    child = thread->child;
    while (child) {
	index_thread_free(child);
	child = child->next;
    }
}

/*
 * Guts of thread searching.  Recurses over children when necessary.
 */
static int _index_thread_search(struct index_state *state,
				Thread *thread, int (*searchproc) (MsgData *))
{
    Thread *child;

    /* test the head node */
    if (thread->msgdata && searchproc(thread->msgdata)) return 1;

    /* test the children recursively */
    child = thread->child;
    while (child) {
	if (_index_thread_search(state, child, searchproc)) return 1;
	child = child->next;
    }

    /* if we get here, we struck out */
    return 0;
}

/*
 * Search a thread to see if it contains a message which matches searchproc().
 *
 * This is a wrapper around _index_thread_search() which iterates through
 * each thread and removes any which fail the searchproc().
 */
static void index_thread_search(struct index_state *state,
				Thread *root, int (*searchproc) (MsgData *))
{
    Thread *cur, *prev, *next;

    for (prev = NULL, cur = root->child, next = cur->next;
	 cur;
	 prev = cur, cur= next, next = (cur ? cur->next : NULL)) {
	if (!_index_thread_search(state, cur, searchproc)) {
	    /* unlink the thread from the list */
	    if (!prev)	/* first thread */
		root->child = cur->next;
	    else
		prev->next = cur->next;

	    /* free all nodes in the thread */
	    index_thread_free(cur);

	    /* we just removed cur from our list,
	     * so we need to keep the same prev for the next pass
	     */
	    cur = prev;
	}
    }
}

/*
 * Guts of the REFERENCES algorithms.  Behavior is tweaked with loadcrit[],
 * searchproc() and sortcrit[].
 */
static void _index_thread_ref(struct index_state *state, unsigned *msgno_list, int nmsg,
			      struct sortcrit loadcrit[],
			      int (*searchproc) (MsgData *),
			      struct sortcrit sortcrit[], int usinguid)
{
    MsgData *msgdata, *freeme, *md;
    int tref, nnode;
    Thread *newnode;
    struct hash_table id_table;
    struct rootset rootset;

    /* Create/load the msgdata array */
    freeme = msgdata = index_msgdata_load(state, msgno_list, nmsg, loadcrit);

    /* calculate the sum of the number of references for all messages */
    for (md = msgdata, tref = 0; md; md = md->next)
	tref += md->nref;

    /* create an array of Thread to use as nodes of thread tree (including
     * empty containers)
     *
     * - We will be building threads under a dummy root, so we need at least
     *   (nmsg + 1) nodes.
     * - We also will need containers for references to non-existent messages.
     *   To make sure we have enough, we will take the worst case and
     *   use the sum of the number of references for all messages.
     * - Finally, we will need containers to group threads with the same
     *   subject together.  To make sure we have enough, we will take the
     *   worst case which will be half of the number of messages.
     *
     * This is overkill, but it is the only way to make sure we have enough
     * ahead of time.  If we tried to use xrealloc(), the array might be moved,
     * and our parent/child/next pointers will no longer be correct
     * (been there, done that).
     */
    nnode = (int) (1.5 * nmsg + 1 + tref);
    rootset.root = (Thread *) xmalloc(nnode * sizeof(Thread));
    memset(rootset.root, 0, nnode * sizeof(Thread));

    newnode = rootset.root + 1;	/* set next newnode to the second
				   one in the array (skip the root) */

    /* Step 0: create an id_table with one bucket for every possible
     * message-id and reference (nmsg + tref)
     */
    construct_hash_table(&id_table, nmsg + tref, 1);

    /* Step 1: link messages together */
    ref_link_messages(msgdata, &newnode, &id_table);

    /* Step 2: find the root set (gather all of the orphan messages) */
    rootset.nroot = 0;
    hash_enumerate(&id_table, ref_gather_orphans, &rootset);

    /* discard id_table */
    free_hash_table(&id_table, NULL);

    /* Step 3: prune tree of empty containers - get our deposit back :^) */
    ref_prune_tree(rootset.root);

    /* Step 4: sort the root set */
    ref_sort_root(rootset.root);

    /* Step 5: group root set by subject */
    ref_group_subjects(rootset.root, rootset.nroot, &newnode);

    /* Optionally search threads (to be used by REFERENCES derivatives) */
    if (searchproc) index_thread_search(state, rootset.root, searchproc);

    /* Step 6: sort threads */
    if (sortcrit) index_thread_sort(rootset.root, sortcrit);

    /* Output the threaded messages */ 
    index_thread_print(state, rootset.root, usinguid);

    /* free the thread array */
    free(rootset.root);

    /* free the msgdata array */
    free(freeme);
}

/*
 * Thread a list of messages using the REFERENCES algorithm.
 */
static void index_thread_ref(struct index_state *state, unsigned *msgno_list, int nmsg, int usinguid)
{
    struct sortcrit loadcrit[] = {{ LOAD_IDS,      0, {{NULL,NULL}} },
				  { SORT_SUBJECT,  0, {{NULL,NULL}} },
				  { SORT_DATE,     0, {{NULL,NULL}} },
				  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};
    struct sortcrit sortcrit[] = {{ SORT_DATE,     0, {{NULL,NULL}} },
				  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};

    _index_thread_ref(state, msgno_list, nmsg, loadcrit, NULL, sortcrit, usinguid);
}

/*
 * NNTP specific stuff.
 */
char *index_get_msgid(struct index_state *state,
		      uint32_t msgno)
{
    char *env;
    char *envtokens[NUMENVTOKENS];
    char *msgid;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    if (mailbox_cacherecord(mailbox, &im->record))
	return NULL;

    if (cacheitem_size(&im->record, CACHE_ENVELOPE) <= 2)
	return NULL;

    /* get msgid out of the envelope
     *
     * get a working copy; strip outer ()'s
     * +1 -> skip the leading paren
     * -2 -> don't include the size of the outer parens
     */
    env = xstrndup(cacheitem_base(&im->record, CACHE_ENVELOPE) + 1,
		   cacheitem_size(&im->record, CACHE_ENVELOPE) - 2);
    parse_cached_envelope(env, envtokens, VECTOR_SIZE(envtokens));

    msgid = envtokens[ENV_MSGID] ? xstrdup(envtokens[ENV_MSGID]) : NULL;

    /* free stuff */
    free(env);

    return msgid;
}

static void massage_header(char *hdr)
{
    int n = 0;
    char *p, c;

    for (p = hdr; *p; p++) {
	if (*p == ' ' || *p == '\t' || *p == '\r') {
	    if (!n || *(p+1) == '\n') {
		/* no leading or trailing whitespace */
		continue;
	    }
	    /* replace with space */
	    c = ' ';
	}
	else if (*p == '\n') {
	    if (*(p+1) == ' ' || *(p+1) == '\t') {
		/* folded header */
		continue;
	    }
	    /* end of header */
	    break;
	}
	else
	    c = *p;

	hdr[n++] = c;
    }
    hdr[n] = '\0';
}

static char *parse_nstring(char **str)
{
    char *cp = *str, *val;

    if (*cp == '"') { /* quoted string */
	val = ++cp; /* skip " */
	do {
	    cp = strchr(cp, '"');
	    if (!cp) return NULL; /* whole thing is broken */
	} while (*(cp-1) == '\\'); /* skip escaped " */
	*cp++ = '\0';
    }
    else { /* NIL */
	val = NULL;
	cp += 3;
    }

    *str = cp;
    return val;
}

static void parse_env_address(char *str, struct address *addr)
{
    str++; /* skip ( */
    addr->name = parse_nstring(&str);
    str++; /* skip SP */
    addr->route = parse_nstring(&str);
    str++; /* skip SP */
    addr->mailbox = parse_nstring(&str);
    str++; /* skip SP */
    addr->domain = parse_nstring(&str);
}

extern struct nntp_overview *index_overview(struct index_state *state,
					    uint32_t msgno)
{
    static struct nntp_overview over;
    static char *env = NULL, *from = NULL, *hdr = NULL;
    static int envsize = 0, fromsize = 0, hdrsize = 0;
    int size;
    char *envtokens[NUMENVTOKENS];
    struct address addr = { NULL, NULL, NULL, NULL, NULL, NULL };
    static struct strlist refhdr;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    /* flush any previous data */
    memset(&over, 0, sizeof(struct nntp_overview));

    if (mailbox_cacherecord(mailbox, &im->record))
	return NULL; /* upper layers can cope! */

    /* make a working copy of envelope; strip outer ()'s */
    /* -2 -> don't include the size of the outer parens */
    /* +1 -> leave space for NUL */
    size = cacheitem_size(&im->record, CACHE_ENVELOPE) - 2 + 1;
    if (envsize < size) {
	envsize = size;
	env = xrealloc(env, envsize);
    }
    /* +1 -> skip the leading paren */
    strlcpy(env, cacheitem_base(&im->record, CACHE_ENVELOPE) + 1, size);

    /* make a working copy of headers */
    size = cacheitem_size(&im->record, CACHE_HEADERS);
    if (hdrsize < size+2) {
	hdrsize = size+100;
	hdr = xrealloc(hdr, hdrsize);
    }
    memcpy(hdr, cacheitem_base(&im->record, CACHE_HEADERS), size);
    hdr[size] = '\0';

    parse_cached_envelope(env, envtokens, VECTOR_SIZE(envtokens));

    over.uid = im->record.uid;
    over.bytes = im->record.size;
    over.lines = index_getlines(state, msgno);
    over.date = envtokens[ENV_DATE];
    over.msgid = envtokens[ENV_MSGID];

    /* massage subject */
    if ((over.subj = envtokens[ENV_SUBJECT]))
	massage_header(over.subj);

    /* build original From: header */
    if (envtokens[ENV_FROM]) /* paranoia */
	parse_env_address(envtokens[ENV_FROM], &addr);

    if (addr.mailbox && addr.domain) { /* paranoia */
	/* +3 -> add space for quotes and space */
	/* +4 -> add space for < @ > NUL */
	size = (addr.name ? strlen(addr.name) + 3 : 0) +
	    strlen(addr.mailbox) + strlen(addr.domain) + 4;
	if (fromsize < size) {
	    fromsize = size;
	    from = xrealloc(from, fromsize);
	}
	from[0] = '\0';
	if (addr.name) sprintf(from, "\"%s\" ", addr.name);
	snprintf(from + strlen(from), fromsize - strlen(from),
		 "<%s@%s>", addr.mailbox, addr.domain);

	over.from = from;
    }

    /* massage references */
    refhdr.s = "references";
    index_pruneheader(hdr, &refhdr, 0);
    if (*hdr) {
	over.ref = hdr + 11; /* skip over header name */
	massage_header(over.ref);
    }

    return &over;
}

extern char *index_getheader(struct index_state *state, uint32_t msgno,
			     char *hdr)
{
    static const char *msg_base = 0;
    static unsigned long msg_size = 0;
    struct strlist headers = { NULL, NULL, NULL, NULL };
    static char *alloc = NULL;
    static unsigned allocsize = 0;
    unsigned size;
    char *buf;
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im = &state->map[msgno-1];

    headers.s = hdr;

    if (msg_base) {
	mailbox_unmap_message(NULL, 0, &msg_base, &msg_size);
	msg_base = 0;
	msg_size = 0;
    }

    /* see if the header is cached */
    if (mailbox_cached_header(hdr) != BIT32_MAX &&
        !mailbox_cacherecord(mailbox, &im->record)) {
    
	size = cacheitem_size(&im->record, CACHE_HEADERS);
	if (allocsize < size+2) {
	    allocsize = size+100;
	    alloc = xrealloc(alloc, allocsize);
	}

	memcpy(alloc, cacheitem_base(&im->record, CACHE_HEADERS), size);
	alloc[size] = '\0';

	buf = alloc;
    }
    else {
	/* uncached header */
	if (mailbox_map_message(mailbox, im->record.uid, &msg_base, &msg_size))
	    return NULL;

	buf = index_readheader(msg_base, msg_size, 0, im->record.header_size);
    }

    index_pruneheader(buf, &headers, NULL);

    if (*buf) {
	buf += strlen(hdr) + 1; /* skip header: */
	massage_header(buf);
    }

    return buf;
}

extern unsigned long index_getsize(struct index_state *state,
				   uint32_t msgno)
{
    struct index_map *im = &state->map[msgno-1];
    return im->record.size;
}

extern unsigned long index_getlines(struct index_state *state, uint32_t msgno)
{
    struct index_map *im = &state->map[msgno-1];
    return im->record.content_lines;
}

/*
 * Parse a sequence into an array of sorted & merged ranges.
 */
static struct seqset *_parse_sequence(struct index_state *state,
				      const char *sequence, int usinguid)
{
    unsigned maxval = usinguid ? state->last_uid : state->exists;
    return seqset_parse(sequence, NULL, maxval);
}

void appendsequencelist(struct index_state *state,
			struct seqset **l,
			char *sequence, int usinguid)
{
    unsigned maxval = usinguid ? state->last_uid : state->exists;
    seqset_append(l, sequence, maxval);
}

void freesequencelist(struct seqset *l)
{
    seqset_free(l);
}
