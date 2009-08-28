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
 * $Id: index.c,v 1.254 2009/08/28 14:06:04 brong Exp $
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

extern void printastring (const char *s);

/* The index and cache files, mapped into memory */
static const char *index_base;
static unsigned long index_len;
static unsigned long index_dirty;
static const char *cache_base;
static unsigned long cache_len;
static unsigned long cache_end;
static unsigned long cache_dirty;

/* Attributes of memory-mapped index file */
static ino_t index_ino;
static unsigned long start_offset;
static unsigned long record_size;

static unsigned lastnotrecent;	/* Msgno of last non-\Recent message */

static time_t *flagreport;	/* Array for each msgno of last_updated when
				 * FLAGS data reported to client.
				 * Zero if FLAGS data never reported */
static unsigned char *seenflag;	/* Array for each msgno, nonzero if \Seen */
static time_t seen_last_change;	/* Last mod time of \Seen state change */
static int flagalloced = -1;	/* Allocated size of above two arrays */
struct seen *seendb;		/* Seen state database object */
static char *seenuids;		/* Sequence of UID's from last seen checkpoint */

/* Forward declarations */
typedef int index_sequenceproc_t(struct mailbox *mailbox, unsigned msgno,
				 void *rock);

static int index_forsequence(struct mailbox *mailbox, const char *sequence,
			     int usinguid,
			     index_sequenceproc_t *proc, void *rock,
			     int* fetchedsomething);
static int index_insequence(unsigned num, struct seq_set *set, int use_mark);

void index_fetchmsg(const char *msg_base, unsigned long msg_size,
		    int format, unsigned offset, unsigned size,
		    unsigned start_octet, unsigned octet_count,
		    struct protstream *pout);
static int index_fetchsection(const char *resp,
			      const char *msg_base, unsigned long msg_size,
			      int format, char *section,
			      const char *cachestr, unsigned size,
			      unsigned start_octet, unsigned octet_count);
static void index_fetchfsection(const char *msg_base,
				unsigned long msg_size,
				int format, struct fieldlist *fsection,
				const char *cachestr,
				unsigned start_octet, unsigned octet_count);
static char *index_readheader(const char *msg_base, unsigned long msg_size,
			      int format, unsigned offset, unsigned size);
static void index_pruneheader(char *buf, struct strlist *headers,
			      struct strlist *headers_not);
static void index_fetchheader(const char *msg_base, unsigned long msg_size,
				 int format, unsigned size,
				 struct strlist *headers,
				 struct strlist *headers_not);
static void index_fetchcacheheader(unsigned msgno, struct strlist *headers,
				   unsigned start_octet, unsigned octet_count);
static void index_listflags(struct mailbox *mailbox);
static void index_fetchflags(struct mailbox *mailbox, unsigned msgno,
				bit32 system_flags, bit32 *user_flags,
				time_t last_updated);
static index_sequenceproc_t index_fetchreply;
static index_sequenceproc_t index_storeseen;
static index_sequenceproc_t index_storeflag;
static int index_search_evaluate(struct mailbox *mailbox,
				 struct searchargs *searchargs,
				 unsigned msgno, struct mapfile *msgfile);
static int index_searchmsg(char *substr, comp_pat *pat,
			   struct mapfile *msgfile, int format,
			   int skipheader, const char *cachestr);
static int index_searchheader(char *name, char *substr, comp_pat *pat,
			      struct mapfile *msgfile, int format,
			      int size);
static int index_searchcacheheader(unsigned msgno, char *name, char *substr,
				   comp_pat *pat);
static index_sequenceproc_t index_copysetup;
static int _index_search(unsigned **msgno_list, struct mailbox *mailbox,
			 struct searchargs *searchargs,
			 modseq_t *highestmodseq);

static void parse_cached_envelope(char *env, char *tokens[], int tokens_size);
static char *find_msgid(char *str, char **rem);
static char *get_localpart_addr(const char *header);
static char *index_extract_subject(const char *subj, size_t len, int *is_refwd);
static char *_index_extract_subject(char *s, int *is_refwd);
static void index_get_ids(MsgData *msgdata,
			  char *envtokens[], const char *headers, unsigned size);
static MsgData *index_msgdata_load(unsigned *msgno_list, int n,
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
static void index_thread_orderedsubj(unsigned *msgno_list, int nmsg,
				     int usinguid);
static void index_thread_sort(Thread *root, struct sortcrit *sortcrit);
static void index_thread_print(Thread *threads, int usinguid);
static void index_thread_ref(unsigned *msgno_list, int nmsg, int usinguid);

/* NOTE: Make sure these are listed in CAPABILITY_STRING */
static const struct thread_algorithm thread_algs[] = {
    { "ORDEREDSUBJECT", index_thread_orderedsubj },
    { "REFERENCES", index_thread_ref },
    { NULL, NULL }
};

/*
 * A mailbox is about to be closed.
 */
void index_closemailbox(struct mailbox *mailbox)
{
    if (imapd_exists) {
	index_checkseen(mailbox, 1, 0, imapd_exists);
    }
    if (index_len) {
	/* So what happens if these weren't cloned from this mailbox? */
	if (index_dirty)
	    map_free(&index_base, &index_len); 
	if (cache_dirty)
	    map_free(&cache_base, &cache_len); 
	index_dirty = cache_dirty = index_len = cache_end = 0;
    }
}

/*
 * A new mailbox has been selected, map it into memory and do the
 * initial CHECK.
 */
void index_newmailbox(struct mailbox *mailbox, int examine_mode)
{
    mailbox->keepingseen = (mailbox->myrights & ACL_SEEN);
    mailbox->examining = examine_mode;
    index_listflags(mailbox);
    imapd_exists = -1;
    index_check(mailbox, 0, 1);
}

void index_operatemailbox(struct mailbox *mailbox)
{
    index_dirty = cache_dirty = 0;
    index_base = mailbox->index_base;
    index_len = mailbox->index_len;
    cache_base = mailbox->cache_base;
    cache_len = mailbox->cache_len;
    cache_end = mailbox->cache_size;

    index_ino = mailbox->index_ino;
    start_offset = mailbox->start_offset;
    record_size = mailbox->record_size;
    imapd_exists = mailbox->exists;
}

/*
 * Check for and report updates
 *
 * If checkseen is 0, \Seen state will not be checkpointed
 * If checkseen is 1, \Seen state will be checkpointed
 * If checkseen is 2, \Seen state will be quietly checkpointed
 */
void index_check(struct mailbox *mailbox, int usinguid, int checkseen)
{
    struct stat sbuf;
    int newexists, oldexists, oldmsgno, msgno, nexpunge, i, r;
    struct index_record record;
    time_t last_read;
    bit32 user_flags[MAX_USER_FLAGS/32];

    oldexists = imapd_exists;

    /* Check for expunge */
    if (index_len) {
	char fnamebuf[MAX_MAILBOX_PATH+1], *path;

	path = (mailbox->mpath &&
		(config_metapartition_files &
		 IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	    mailbox->mpath : mailbox->path;
	strlcpy(fnamebuf, path, sizeof(fnamebuf));
	strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));
	
	if (stat(fnamebuf, &sbuf) != 0) {
	    if (errno == ENOENT) {
		/* Mailbox has been deleted */
		for(;imapd_exists > 0; imapd_exists--) {
		    prot_printf(imapd_out, "* 1 EXPUNGE\r\n");
		}
		mailbox->exists = 0;
		imapd_exists = -1;
		if (seendb) {
		    seen_close(seendb);
		    seendb = 0;
		}
	    }
	}
	else if ((sbuf.st_ino != mailbox->index_ino) ||
	    (index_ino != mailbox->index_ino)) {
	    unsigned long olduidvalidity = mailbox->uidvalidity;

	    if (mailbox_open_index(mailbox)) {
		fatal("failed to reopen index file", EC_IOERR);
	    }

	    if (olduidvalidity == mailbox->uidvalidity) {
	        /* See if any messages have been expunged */
		for (oldmsgno = msgno = 1; oldmsgno <= imapd_exists;
		     oldmsgno++, msgno++) {
		    if ((unsigned) msgno <= mailbox->exists) {
			mailbox_read_index_record(mailbox, msgno, &record);
		    }
		    else {
			record.uid = mailbox->last_uid+1;
		    }

		    nexpunge = 0;
		    while (oldmsgno<=imapd_exists && UID(oldmsgno) < record.uid) {
			nexpunge++;
			oldmsgno++;
		    }
		    if (nexpunge) {
			memmove(flagreport+msgno, flagreport+msgno+nexpunge,
				(oldexists-msgno-nexpunge+1)*sizeof(*flagreport));
			memmove(seenflag+msgno, seenflag+msgno+nexpunge,
				(oldexists-msgno-nexpunge+1)*sizeof(*seenflag));
			oldexists -= nexpunge;
			while (nexpunge--) {
			    prot_printf(imapd_out, "* %u EXPUNGE\r\n", msgno);
			}
		    }
		}
	    }
	    else {
		/* Force a * OK [UIDVALIDITY n] message */
		oldexists = -1;
	    }

	    /* Force re-map of index/cache files */
	    map_free(&index_base, &index_len);
	    map_free(&cache_base, &cache_len);
	    cache_end = 0;
	    index_dirty = cache_dirty = 0;

	    /* Force a * n EXISTS message */
	    imapd_exists = -1;
	}
	else if (sbuf.st_mtime != mailbox->index_mtime
		 || sbuf.st_size != mailbox->index_size) {
	    mailbox_read_index_header(mailbox);
	}
    }
    index_ino = mailbox->index_ino;

    start_offset = mailbox->start_offset;
    record_size = mailbox->record_size;
    newexists = mailbox->exists;

    /* Refresh the index and cache files */
    map_refresh(mailbox->index_fd, 0, &index_base, &index_len,
		start_offset + newexists * record_size,
		"index", mailbox->name);
    index_dirty = 1;
    if (fstat(mailbox->cache_fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: stating cache file for %s: %m",
	       mailbox->name);
	fatal("failed to stat cache file", EC_IOERR);
    }
    if (cache_end < (unsigned long) sbuf.st_size) {
	cache_end = sbuf.st_size;
	map_refresh(mailbox->cache_fd, 0, &cache_base, &cache_len,
		    cache_end, "cache", mailbox->name);
	cache_dirty = 1;
    }

    /* If opening mailbox, get \Recent info */
    if (oldexists == -1 && mailbox->keepingseen) {
	r = seen_open(mailbox,
		      (mailbox->options & OPT_IMAP_SHAREDSEEN) ? "anyone" :
		      imapd_userid,
		      SEEN_CREATE, &seendb);
	if (!r) {
	    free(seenuids);
	    seenuids = NULL;
	    r = seen_lockread(seendb, &last_read, &mailbox->recentuid,
			      &seen_last_change, &seenuids);
	    if (r) {
		seen_close(seendb);
		seendb = 0;
	    }
	}
	if (r) {
	    seendb = 0;
	    prot_printf(imapd_out, "* OK (seen state failure) %s: %s\r\n",
		   error_message(IMAP_NO_CHECKPRESERVE), error_message(r));
	    syslog(LOG_ERR, "Could not open seen state for %s (%s)",
		   imapd_userid, error_message(r));
	}
	else {
	    /*
	     * Empty seenuids so that index_checkseen() will pick up the
	     * initial \Seen info.  Leave the database locked.
	     */
	    *seenuids = '\0';	
	}
    }

    /* If opening mailbox or had an EXPUNGE, find where \Recent starts */
    if (imapd_exists == -1) {
	imapd_exists = newexists;
	lastnotrecent = index_finduid(mailbox->recentuid);
	imapd_exists = -1;
    }
    
    /* If EXISTS changed, report it */
    if (newexists != imapd_exists) {
	/* Re-size flagreport and seenflag arrays if necessary */
	if (newexists > flagalloced) {
	    /* Double what we need in hopes we won't have to realloc again */
	    flagalloced = newexists * 2;
	    flagreport = (time_t *)
	      xrealloc((char *)flagreport, (flagalloced+1) * sizeof(time_t));
	    seenflag = xrealloc(seenflag, flagalloced+1);
	}

	/* Zero out array entry for newly arrived messages */
	for (i = oldexists+1; i <= newexists; i++) {
	    flagreport[i] = LAST_UPDATED(i);
	    seenflag[i] = 0;
	}

	checkseen = 1;
	imapd_exists = newexists;
	prot_printf(imapd_out, "* %u EXISTS\r\n* %u RECENT\r\n", imapd_exists,
	       imapd_exists-lastnotrecent);
    }

    /* Check Flags */
    if (checkseen) index_checkseen(mailbox, checkseen >> 1, usinguid, oldexists);
    else if (oldexists == -1) {
	seen_close(seendb);
	seendb = 0;
    }
    for (i = 1; i <= imapd_exists && seenflag[i]; i++);
    if (i == imapd_exists + 1) mailbox->allseen = mailbox->last_uid;
    if (oldexists == -1) {
	if (imapd_exists && i <= imapd_exists) {
	    prot_printf(imapd_out, "* OK [UNSEEN %u]  \r\n", i);
	}
        prot_printf(imapd_out, "* OK [UIDVALIDITY %lu]  \r\n",
		    mailbox->uidvalidity);
	prot_printf(imapd_out, "* OK [UIDNEXT %lu]  \r\n",
		    mailbox->last_uid + 1);
	if (mailbox->options & OPT_IMAP_CONDSTORE) {
	    prot_printf(imapd_out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]  \r\n",
			mailbox->highestmodseq);
	} else {
	    prot_printf(imapd_out, "* OK [NOMODSEQ] Sorry, modsequences have "
			"not been enabled on this mailbox\r\n");
	}
    }

    for (msgno = 1; msgno <= oldexists; msgno++) {
	if (flagreport[msgno] < LAST_UPDATED(msgno)) {
	    for (i = 0; (unsigned) i < VECTOR_SIZE(user_flags); i++) {
		user_flags[i] = USER_FLAGS(msgno, i);
	    }
	    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
			     LAST_UPDATED(msgno));
	    if ((mailbox->options & OPT_IMAP_CONDSTORE) &&
		imapd_condstore_client) {
		prot_printf(imapd_out, " MODSEQ (" MODSEQ_FMT ")", MODSEQ(msgno));
	    }
	    if (usinguid) prot_printf(imapd_out, " UID %u", UID(msgno));
	    prot_printf(imapd_out, ")\r\n");
	}
    }
}

/* Flush seen state (but only if anything changed) and check for flag/seen
 * updates from other processes.  Bails out if the cyrus.index file has
 * changed under our feet, which indicates an expunge from another process.
 * In this case pending updates will be flushed on the next index_check()
 */
void
index_check_existing(struct mailbox *mailbox, int usinguid, int checkseen)
{
    struct stat sbuf;
    int msgno;
    unsigned i;
    bit32 user_flags[MAX_USER_FLAGS/32];

    if (imapd_exists == -1)
        return;

    /* Check for expunge, just like index_check() */
    if (index_len) {
        char fnamebuf[MAX_MAILBOX_PATH+1], *path;

	path = (mailbox->mpath &&
		(config_metapartition_files &
		 IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	    mailbox->mpath : mailbox->path;
	strlcpy(fnamebuf, path, sizeof(fnamebuf));
	strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));

	if ((stat(fnamebuf, &sbuf) != 0) ||
            (sbuf.st_ino != mailbox->index_ino) ||
	    (index_ino != mailbox->index_ino))
            return;
    }

    if (checkseen)
        index_checkseen(mailbox, 0, usinguid, imapd_exists);

    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	if (flagreport[msgno] < LAST_UPDATED(msgno)) {
	    for (i = 0; i < VECTOR_SIZE(user_flags); i++) {
		user_flags[i] = USER_FLAGS(msgno, i);
	    }
	    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
			     LAST_UPDATED(msgno));
	    if (usinguid) prot_printf(imapd_out, " UID %u", UID(msgno));
	    prot_printf(imapd_out, ")\r\n");
	}
    }
}

/*
 * Checkpoint the user's \Seen state
 *
 * Format of the seenuids string:
 *
 * no whitespace, n:m indicates an inclusive range (n to m), otherwise
 * list is comma separated of single messages, e.g.:
 *
 * 1:16239,16241:17015,17019:17096,17098,17100
 *
 */
#define SAVEGROW 200
void
index_checkseen(mailbox, quiet, usinguid, oldexists)
struct mailbox *mailbox;
int quiet;
int usinguid;
int oldexists;
{
    int r;
    time_t last_read;
    unsigned last_uid;
    char *newseenuids;
    char *old, *new;
    unsigned oldnext = 0, oldseen = 0;
    unsigned newnext = 0, newseen = 0;
    int neweof = 0;
    unsigned uid, dirty = 0, i;
    int msgno;
    bit32 user_flags[MAX_USER_FLAGS/32];
    char *saveseenuids, *save;
    size_t savealloced;
    unsigned start, newallseen, inrange, usecomma;
    mailbox_notifyproc_t *updatenotifier;
    int dosync = 0;


    if (!mailbox->keepingseen) return;
    if (imapd_exists == 0) {
	if (seendb) {
	    seen_close(seendb);
	    seendb = 0;
	}
	return;
    }
    if (!seendb) {
	r = seen_open(mailbox,
		      (mailbox->options & OPT_IMAP_SHAREDSEEN) ? "anyone" :
		      imapd_userid,
		      SEEN_CREATE, &seendb);
	if (r) {
	    syslog(LOG_ERR, "Failed to open seen for %s", mailbox->name);
	    seendb = 0;
	    return;
	}
    }

    /* Lock \Seen database and read current values */
    r = seen_lockread(seendb, &last_read, &last_uid, &seen_last_change,
		      &newseenuids);
    if (r) {
	prot_printf(imapd_out, "* OK %s: %s\r\n",
	       error_message(IMAP_NO_CHECKSEEN), error_message(r));
	seen_close(seendb);
	seendb = 0;
	return;
    }

    /*
     * Propagate changes in the database to the seenflag[] array
     * and possibly to the client.
     */
    old = seenuids;
    new = newseenuids;
    while (cyrus_isdigit((int) *old)) oldnext = oldnext * 10 + *old++ - '0';
    while (cyrus_isdigit((int) *new)) newnext = newnext * 10 + *new++ - '0';

    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	uid = UID(msgno);
	while (oldnext <= uid) {
	    if (*old != ':' && !oldseen && oldnext == uid) {
		oldseen = 1;
		break;
	    }
	    else {
		oldseen = (*old == ':');
		oldnext = 0;
		if (!*old) {
		    oldnext = mailbox->last_uid+1;
		    /* just in case the index is corrupted, don't
		     * loop forever */
		    if (oldnext < uid) {
			syslog(LOG_ERR, "index corrupted, needs reconstruct %s",
			       mailbox->name);
			oldnext = uid;
		    }
		}
		else old++;
		while (cyrus_isdigit((int) *old)) {
		    oldnext = oldnext * 10 + *old++ - '0';
		}
		oldnext += oldseen;
	    }
	}
	while (newnext <= uid) {
	    if (*new != ':' && !newseen && newnext == uid) {
		newseen = 1;
		break;
	    }
	    else {
		newseen = (*new == ':');
		newnext = 0;
		if (!*new) {
		    newnext = mailbox->last_uid+1;
		    /* just in case the index is corrupted, don't
		     * loop forever */
		    if (newnext < uid) {
			syslog(LOG_ERR, "index corrupted, needs reconstruct %s",
			       mailbox->name);
			newnext = uid;
		    }
		    neweof++;
		}
		else new++;
		while (cyrus_isdigit((int) *new)) {
		    newnext = newnext * 10 + *new++ - '0';
		}
		newnext += newseen;
	    }
	}

	/* report flags that have changed */
	if (oldseen != newseen) {
	    if (seenflag[msgno] != newseen) {
		seenflag[msgno] = newseen;
		if (!quiet && msgno <= oldexists && oldexists != -1) {
		    for (i = 0; i < VECTOR_SIZE(user_flags); i++) {
			user_flags[i] = USER_FLAGS(msgno, i);
		    }
		    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), 
				     user_flags, LAST_UPDATED(msgno));
		    if ((mailbox->options & OPT_IMAP_CONDSTORE) &&
			imapd_condstore_client) {
			prot_printf(imapd_out, " MODSEQ (" MODSEQ_FMT ")",
				    MODSEQ(msgno));
		    }
		    if (usinguid) {
			prot_printf(imapd_out, " UID %u", UID(msgno));
		    }
		    prot_printf(imapd_out, ")\r\n");
		}
	    }
	}
	else if (seenflag[msgno] != newseen) {
	    dirty++;
	}
    }

    if (dirty) {
	seen_last_change = time((time_t *)0);
        dosync = 1;
    }

    if (!mailbox->examining && oldexists != imapd_exists) {
	/* If just did a SELECT, record time of our reading the mailbox */
	if (oldexists == -1) last_read = time((time_t *)0);

        /* Track last_uid changes, but not last_read. Tracking last_read
         * would cause a sync on every SELECT operation, and our (hacked)
         * FUD doesn't use the information anyway
         */
        if (last_uid != mailbox->last_uid)
            dosync = 1;

	/* Update the \Recent high-water mark */
	last_uid = mailbox->last_uid;
	dirty++;
    }

    /* If there's nothing to save back to the database, clean up and return */
    if (!dirty) {
	seen_close(seendb);
	seendb = 0;
	free(seenuids);
	seenuids = newseenuids;
	/* We might have deleted our last unseen message */
#if TOIMSP
	if (!mailbox->allseen) {
	    for (msgno = 1; msgno <= imapd_exists; msgno++) {
		if (!seenflag[msgno]) break;
	    }
	    if (msgno == imapd_exists + 1) {
		toimsp(mailbox->name, mailbox->uidvalidity,
		       "SEENsnn", imapd_userid, mailbox->last_uid,
		       seen_last_change, 0);
	    }
	}
#endif
	return;
    }
    
    /* Build the seenuids string to save to the database */
    start = 1;
    inrange = 1;
    newallseen = mailbox->last_uid;
    usecomma = 0;
    savealloced = SAVEGROW;
    save = saveseenuids = xmalloc(savealloced);
    *save = '\0';
    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	uid = UID(msgno);
	if (seenflag[msgno] != inrange) {
	    newallseen = 0;
	    if (inrange) {
		if (start == uid-1) {
		    if (usecomma++) *save++ = ',';
		    sprintf(save, "%u", start);
		    save += strlen(save);
		}
		else if (uid > 1) {
		    if (usecomma++) *save++ = ',';
		    sprintf(save, "%u:", start);
		    save += strlen(save);
		    sprintf(save, "%u", uid-1);
		    save += strlen(save);
		}
		inrange = 0;
	    }
	    else {
		start = uid;
		inrange = 1;
	    }
	}
	if ((size_t) (save - saveseenuids) > savealloced - 30) {
	    savealloced += SAVEGROW;
	    saveseenuids = xrealloc(saveseenuids, savealloced);
	    save = saveseenuids + strlen(saveseenuids);
	}
    }

    /* Any messages between uid+1 and mailbox->last_uid get same disposition
     * as uid
     */
    uid = mailbox->last_uid;
    while (newnext <= uid) {
	if (*new != ':' && !newseen && newnext == uid) {
	    newseen = 1;
	    break;
	}
	else {
	    newseen = (*new == ':');
	    newnext = 0;
	    if (!*new) {
		newnext = mailbox->last_uid+1;
		neweof++;
	    }
	    else new++;
	    while (cyrus_isdigit((int) *new)) newnext = newnext * 10 + *new++ - '0';
	    newnext += newseen;
	}
    }

    if (inrange) {
	/* Last message read. */
	if (newseen && newnext > uid+1) {
	    /* We parsed a range which went past uid.  Include it in output. */
	    uid = newnext-1;
	}
	else if (!neweof && !newseen && newnext == uid+1) {
	    /* We parsed ",N" where N is one past uid.  Include it
	     * in the output range */
	    if (*new == ':') {
		/* There's a ":M" after the ",N".  Parse/include that too. */
		new++;
		newnext = 0;
		while (cyrus_isdigit((int) *new)) newnext = newnext * 10 + *new++ - '0';
	    }
	    uid = newnext;
	    newseen++;		/* Forget we parsed ",N" */
	}

	if (!start && uid > 1) start = 1;
	if (usecomma++) *save++ = ',';
	if (start && start != uid) {
	    sprintf(save, "%u:", start);
	    save += strlen(save);
	}
	sprintf(save, "%u", uid);
	save += strlen(save);

	if (!neweof && !newseen) {
	    /* Parsed a lone number */
	    if (usecomma++) *save++ = ',';
	    sprintf(save, "%u", newnext);
	    save += strlen(save);
	}
    }
    else if (newseen && newnext > uid+1) {
	/* We parsed a range which went past uid.  Include it in output */
	if (usecomma++) *save++ = ',';
	if (newnext > uid+2) {
	    sprintf(save, "%u:", uid+1);
	    save += strlen(save);
	}
	sprintf(save, "%u", newnext-1);
	save += strlen(save);
    }
    else if (*new == ':') {
	/* Parsed first half of a range.  Write it out */
	if (usecomma++) *save++ = ',';
	sprintf(save, "%u", uid+1);
	save += strlen(save);
    }
    else if (!neweof && !newseen) {
	/* Parsed a lone number */
	if (usecomma++) *save++ = ',';
	sprintf(save, "%u", newnext);
	save += strlen(save);
    }

    if (*new) {
	if (save - saveseenuids + strlen(new) >= savealloced) {
	    savealloced += strlen(new);
	    saveseenuids = xrealloc(saveseenuids, savealloced);
	    save = saveseenuids + strlen(saveseenuids);
	}
	strcpy(save, usecomma ? new : new+1);
    }

    /* Write the changes, clean up, and return */
    r = seen_write(seendb, last_read, last_uid, seen_last_change, saveseenuids);
    seen_close(seendb);
    seendb = 0;
    free(seenuids);

    if (r) {
	prot_printf(imapd_out, "* OK %s: %s\r\n",
	       error_message(IMAP_NO_CHECKSEEN), error_message(r));
	free(saveseenuids);
	seenuids = newseenuids;
	return;
    }

    /* (oldexists == imapd_exists) => mailbox already open? */
    /* Has to be here:
     * imapd.c doesn't have enough context to work out where seen flags set.
     * Downside: we have to link sync_client, sync_server with sync_log */
    if (!r && dosync) {
        sync_log_seen((mailbox->options & OPT_IMAP_SHAREDSEEN) ? "anyone" :
		      imapd_userid, mailbox->name);
    }

#if TOIMSP
    if (newallseen) {
	toimsp(mailbox->name, mailbox->uidvalidity, "SEENsnn", imapd_userid,
	       mailbox->last_uid, seen_last_change, 0);
    }
    else if (mailbox->allseen == mailbox->last_uid) {
	toimsp(mailbox->name, mailbox->uidvalidity, "SEENsnn", imapd_userid,
	       0, seen_last_change, 0);
    }
#endif    

    free(newseenuids);
    seenuids = saveseenuids;

    updatenotifier = mailbox_get_updatenotifier();
    if (updatenotifier) updatenotifier(mailbox->name);
}


/*
 * Perform a FETCH-related command on a sequence.
 * Fetchedsomething argument is 0 if nothing was fetched, 1 if something was
 * fetched.  (A fetch command that fetches nothing is not a valid fetch
 * command.)
 */
int
index_fetch(struct mailbox* mailbox,
	    const char* sequence,
	    int usinguid,
	    struct fetchargs* fetchargs,
	    int* fetchedsomething)
{
    *fetchedsomething = 0;
    return index_forsequence(mailbox, sequence, usinguid, index_fetchreply,
			     (char *)fetchargs, fetchedsomething);
}

/*
 * Perform a STORE command on a sequence
 */
int
index_store(mailbox, sequence, usinguid, storeargs, flag, nflags)
struct mailbox *mailbox;
char *sequence;
int usinguid;
struct storeargs *storeargs;
char **flag;
int nflags;
{
    int i, r, emptyflag;
    unsigned userflag;
    int writeheader = 0;
    int newflag[MAX_USER_FLAGS];
    long myrights = mailbox->myrights;

    /* Handle simple case of just changing /Seen */
    if (!(mailbox->options & OPT_IMAP_CONDSTORE) &&
	storeargs->operation != STORE_REPLACE &&
	!storeargs->system_flags && !nflags) {
	if (!storeargs->seen) return 0; /* Nothing to change */
	if (!(myrights & ACL_SEEN)) return IMAP_PERMISSION_DENIED;
	storeargs->usinguid = usinguid;

	index_forsequence(mailbox, sequence, usinguid,
			  index_storeseen, (char *)storeargs, NULL);
	return 0;
    }

    mailbox_read_acl(mailbox, imapd_authstate);
    myrights &= mailbox->myrights;

    /* First pass at checking permission */
    if ((storeargs->seen && !(myrights & ACL_SEEN)) ||
	((storeargs->system_flags & FLAG_DELETED) &&
	 !(myrights & ACL_DELETEMSG)) ||
	(((storeargs->system_flags & ~FLAG_DELETED) || nflags) &&
	 !(myrights & ACL_WRITE))) {
	mailbox->myrights = myrights;
	return IMAP_PERMISSION_DENIED;
    }

    /* Check to see if we have to add new user flags */
    for (userflag=0; userflag < VECTOR_SIZE(newflag); userflag++)
      newflag[userflag] = 0;
    for (i=0; i < nflags; i++) {
	emptyflag = -1;
	for (userflag = 0; userflag < VECTOR_SIZE(mailbox->flagname); userflag++) {
	    if (mailbox->flagname[userflag]) {
		if (!strcasecmp(flag[i], mailbox->flagname[userflag]))
		  break;
	    }
	    else if (!newflag[userflag] && emptyflag == -1) {
		emptyflag = userflag;
	    }
	}
	if (userflag == MAX_USER_FLAGS) {
	    if (emptyflag == -1) {
		return IMAP_USERFLAG_EXHAUSTED;
	    }
	    newflag[emptyflag] = 1;
	    writeheader++;
	}
    }

    /* Add the new user flags */
    if (writeheader) {
	r = mailbox_lock_header(mailbox);
	if (r) return r;
	
	/*
	 * New flags might have been assigned since we last looked
	 * Do the assignment again.
	 */
	for (userflag=0; userflag < VECTOR_SIZE(newflag); userflag++)
	  newflag[userflag] = 0;
	for (i=0; i < nflags; i++) {
	    emptyflag = -1;
	    for (userflag = 0; userflag < VECTOR_SIZE(newflag); userflag++) {
		if (mailbox->flagname[userflag]) {
		    if (!strcasecmp(flag[i], mailbox->flagname[userflag]))
		      break;
		}
		else if (emptyflag == -1) {
		    emptyflag = userflag;
		}
	    }
	    if (userflag == MAX_USER_FLAGS) {
		if (emptyflag == -1) {
		    mailbox_unlock_header(mailbox);
		    mailbox->myrights = myrights;

		    /* Undo the new assignments */
		    for (userflag=0; userflag < VECTOR_SIZE(newflag); userflag++) {
			if (newflag[userflag] && mailbox->flagname[userflag]) {
			    free(mailbox->flagname[userflag]);
			    mailbox->flagname[userflag] = 0;
			}
		    }

		    /* Tell client about new flags we read while looking */
		    index_listflags(mailbox);

		    return IMAP_USERFLAG_EXHAUSTED;
		}
		mailbox->flagname[emptyflag] = xstrdup(flag[i]);
	    }
	}
		
	/* Tell client about new flags */
	index_listflags(mailbox);
	
	r = mailbox_write_header(mailbox);
	mailbox_unlock_header(mailbox);
	mailbox->myrights = myrights;
	if (r) return r;
    }
    /* Not reading header anymore--can put back our working ACL */
    mailbox->myrights = myrights;

    /* Now we know all user flags are in the mailbox header, find the bits */
    for (i=0; i < nflags; i++) {
	for (userflag = 0; userflag < VECTOR_SIZE(mailbox->flagname); userflag++) {
	    if (mailbox->flagname[userflag]) {
		if (!strcasecmp(flag[i], mailbox->flagname[userflag]))
		  break;
	    }
	}
	assert(userflag != MAX_USER_FLAGS);
	storeargs->user_flags[userflag/32] |= 1<<(userflag&31);
    }
    
    storeargs->update_time = time((time_t *)0);
    storeargs->usinguid = usinguid;

    r = mailbox_lock_index(mailbox);
    if (r) return r;

    r = index_forsequence(mailbox, sequence, usinguid,
			  index_storeflag, (char *)storeargs, NULL);

    /* note that index_forsequence() doesn't sync the index file;
       that's done below in mailbox_write_index_header() */
    if (mailbox->dirty) {
	if (mailbox->options & OPT_IMAP_CONDSTORE) {
	    /* bump HIGHESTMODSEQ */
	    mailbox->highestmodseq++;
	}
	/* xxx what to do on failure? */
	mailbox_write_index_header(mailbox);
	mailbox->dirty = 0;
    }

    mailbox_unlock_index(mailbox);

    /* Refresh the index file, for systems without mmap() */
    map_refresh(mailbox->index_fd, 0, &index_base, &index_len,
		start_offset + imapd_exists * record_size,
		"index", mailbox->name);
    index_dirty = 1;

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
int index_scan(struct mailbox *mailbox, const char *contents)
{
    unsigned *msgno_list;
    unsigned msgno;
    struct mapfile msgfile;
    int n = 0;
    int listindex;
    int listcount;
    struct searchargs searchargs;
    struct strlist strlist;
    struct index_record record;
    unsigned long length;

    if (!(contents && contents[0])) return(0);

    if (mailbox->exists <= 0) return 0;

    length = strlen(contents);

    memset(&searchargs, 0, sizeof(struct searchargs));
    searchargs.text = &strlist;

    /* Use US-ASCII to emulate fgrep */
    strlist.s = charset_convert(contents, charset_lookupname("US-ASCII"),
				NULL, 0); 
    strlist.p = charset_compilepat(strlist.s);
    strlist.next = NULL;

    msgno_list = (unsigned *) xmalloc(mailbox->exists * sizeof(unsigned));

    listcount = search_prefilter_messages(msgno_list, mailbox, &searchargs);

    for (listindex = 0; !n && listindex < listcount; listindex++) {
        msgno = msgno_list[listindex];

        if (mailbox_read_index_record(mailbox, msgno, &record))
            continue;

	msgfile.base = 0;
	msgfile.size = 0;

        if (mailbox_map_message(mailbox, record.uid,
                                &msgfile.base, &msgfile.size))
            continue;

        n += index_scan_work(msgfile.base, msgfile.size, contents, length);

        mailbox_unmap_message(mailbox, record.uid,
                              &msgfile.base, &msgfile.size);
    }

    free(strlist.s);
    free(strlist.p);
    free(msgno_list);

    return(n);
}

/*
 * Guts of the SEARCH command.
 * 
 * Returns message numbers in an array.  This function is used by
 * SEARCH, SORT and THREAD.
 */
static int _index_search(unsigned **msgno_list, struct mailbox *mailbox,
			 struct searchargs *searchargs,
			 modseq_t *highestmodseq)
{
    unsigned msgno;
    struct mapfile msgfile;
    int n = 0;
    int listindex;
    int listcount;

    if (imapd_exists <= 0) return 0;

    *msgno_list = (unsigned *) xmalloc(imapd_exists * sizeof(unsigned));

    /* OK, so I'm being a bit clever here. We fill the msgno list with
       a list of message IDs returned by the search engine. Then we
       scan through the list and store matching message IDs back into the
       list. This is OK because we only overwrite message IDs that we've
       already looked at. */
    listcount = search_prefilter_messages(*msgno_list, mailbox, searchargs);

    for (listindex = 0; listindex < listcount; listindex++) {
        msgno = (*msgno_list)[listindex];
	msgfile.base = 0;
	msgfile.size = 0;

	if (index_search_evaluate(mailbox, searchargs, msgno, &msgfile)) {
	    (*msgno_list)[n++] = msgno;
	    if (highestmodseq && (MODSEQ(msgno) > *highestmodseq)) {
		*highestmodseq = MODSEQ(msgno);
	    }
	}
	if (msgfile.base) {
	    mailbox_unmap_message(mailbox, UID(msgno),
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

unsigned index_getuid(unsigned msgno) {
  return UID(msgno);
}

/* 'uid_list' is malloc'd string representing the hits from searchargs;
   returns number of hits */
int index_getuidsequence(struct mailbox *mailbox, 
			 struct searchargs *searchargs,
			 unsigned **uid_list)
{
    unsigned *msgno_list;
    int i, n;

    n = _index_search(&msgno_list, mailbox, searchargs, NULL);
    if (n == 0) {
	*uid_list = NULL;
	return 0;
    }

    for (i = 0; i < n; i++) {
	msgno_list[i] = UID(msgno_list[i]);
    }

    *uid_list = msgno_list;
    return n;
}

/*
 * Performs a SEARCH command.
 * This is a wrapper around _index_search() which simply prints the results.
 */
int index_search(struct mailbox *mailbox, struct searchargs *searchargs,
		 int usinguid)
{
    unsigned *msgno_list;
    int i, n;
    modseq_t highestmodseq = 0;

    n = _index_search(&msgno_list, mailbox, searchargs,
		      searchargs->modseq ? &highestmodseq : NULL);

    prot_printf(imapd_out, "* SEARCH");

    for (i = 0; i < n; i++)
	prot_printf(imapd_out, " %u",
		    usinguid ? UID(msgno_list[i]) : msgno_list[i]);

    if (n) free(msgno_list);

    if (highestmodseq) {
	prot_printf(imapd_out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    prot_printf(imapd_out, "\r\n");

    return n;
}

/*
 * Performs a SORT command
 */
int index_sort(struct mailbox *mailbox, struct sortcrit *sortcrit,
	       struct searchargs *searchargs, int usinguid)
{
    unsigned *msgno_list;
    MsgData *msgdata = NULL, *freeme = NULL;
    int nmsg;
    clock_t start;
    modseq_t highestmodseq = 0;
    int i, modseq = 0;

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
    nmsg = _index_search(&msgno_list, mailbox, searchargs,
			 modseq ? &highestmodseq : NULL);

    prot_printf(imapd_out, "* SORT");

    if (nmsg) {
	/* Create/load the msgdata array */
	freeme = msgdata = index_msgdata_load(msgno_list, nmsg, sortcrit);
	free(msgno_list);

	/* Sort the messages based on the given criteria */
	msgdata = lsort(msgdata,
			(void * (*)(void*)) index_sort_getnext,
			(void (*)(void*,void*)) index_sort_setnext,
			(int (*)(void*,void*,void*)) index_sort_compare,
			sortcrit);

	/* Output the sorted messages */ 
	while (msgdata) {
	    prot_printf(imapd_out, " %u",
			usinguid ? UID(msgdata->msgno) : msgdata->msgno);

	    /* free contents of the current node */
	    index_msgdata_free(msgdata);

	    msgdata = msgdata->next;
	}

	/* free the msgdata array */
	free(freeme);
    }

    if (highestmodseq) {
	prot_printf(imapd_out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    prot_printf(imapd_out, "\r\n");

    /* debug */
    if (CONFIG_TIMING_VERBOSE) {
	int len;
	char *key_names[] = { "SEQUENCE", "ARRIVAL", "CC", "DATE", "FROM",
			      "SIZE", "SUBJECT", "TO", "ANNOTATION", "MODSEQ" };
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
int index_thread(struct mailbox *mailbox, int algorithm,
		 struct searchargs *searchargs, int usinguid)
{
    unsigned *msgno_list;
    int nmsg;
    clock_t start;
    modseq_t highestmodseq = 0;

    if(CONFIG_TIMING_VERBOSE)
	start = clock();

    /* Search for messages based on the given criteria */
    nmsg = _index_search(&msgno_list, mailbox, searchargs,
			 searchargs->modseq ? &highestmodseq : NULL);

    if (nmsg) {
	/* Thread messages using given algorithm */
	(*thread_algs[algorithm].threader)(msgno_list, nmsg, usinguid);

	free(msgno_list);

	if (highestmodseq) {
	    prot_printf(imapd_out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
	}
    }

    /* print an empty untagged response */
    else
	index_thread_print(NULL, usinguid);

    prot_printf(imapd_out, "\r\n");

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
index_copy(struct mailbox *mailbox, 
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
    struct appendstate append_mailbox;
    char *copyuid;
    int copyuid_len, copyuid_size;
    int sepchar;
    unsigned long uidvalidity;
    unsigned long startuid, num;
    long docopyuid;
    int haveseen = 0;

    *copyuidp = NULL;

    copyargs.nummsg = 0;
    index_forsequence(mailbox, sequence, usinguid, index_copysetup,
		      (char *)&copyargs, NULL);

    if (copyargs.nummsg == 0) return IMAP_NO_NOSUCHMSG;

    for (i = 0; i < copyargs.nummsg; i++) {
	totalsize += copyargs.copymsg[i].size;
	haveseen |= copyargs.copymsg[i].seen;
    }

    r = append_setup(&append_mailbox, name, MAILBOX_FORMAT_NORMAL,
		     imapd_userid, imapd_authstate, ACL_INSERT, totalsize);
    if (r) return r;

    docopyuid = (append_mailbox.m.myrights & ACL_READ);

    r = append_copy(mailbox, &append_mailbox, copyargs.nummsg,
		    copyargs.copymsg, nolink);
    if (!r) {
	int sharedseen = (append_mailbox.m.options & OPT_IMAP_SHAREDSEEN);

	r = append_commit(&append_mailbox, totalsize,
		      &uidvalidity, &startuid, &num);

	if (!r) {
	    sync_log_mailbox_double(mailbox->name, name);
	    /* if any messages are seen then we need to sync the seen state */
	    if (haveseen) {
		sync_log_seen(sharedseen ? "anyone" : imapd_userid, name);
	    }
	}
    }

    if (!r && docopyuid) {
	copyuid_size = 1024;
	copyuid = xmalloc(copyuid_size);
	snprintf(copyuid, copyuid_size, "%lu", uidvalidity);
	copyuid_len = strlen(copyuid);
	sepchar = ' ';

	for (i = 0; i < copyargs.nummsg; i++) {
	    if (copyuid_size < copyuid_len + 50) {
		copyuid_size += 1024;
		copyuid = xrealloc(copyuid, copyuid_size);
	    }
	    snprintf(copyuid+copyuid_len, copyuid_size-copyuid_len, 
		    "%c%lu", sepchar, copyargs.copymsg[i].uid);
	    copyuid_len += strlen(copyuid+copyuid_len);
	    if (i+1 < copyargs.nummsg &&
		copyargs.copymsg[i+1].uid == copyargs.copymsg[i].uid + 1) {
		do {
		    i++;
		} while (i+1 < copyargs.nummsg &&
			 copyargs.copymsg[i+1].uid == copyargs.copymsg[i].uid + 1);
		snprintf(copyuid+copyuid_len, copyuid_size-copyuid_len, ":%lu",
			copyargs.copymsg[i].uid);
		copyuid_len += strlen(copyuid+copyuid_len);
	    }
	    sepchar = ',';
	}
	if (num == 1) {
	    snprintf(copyuid+copyuid_len, copyuid_size-copyuid_len, " %lu",
		     startuid);
	} else {
	    snprintf(copyuid+copyuid_len, copyuid_size-copyuid_len, " %lu:%lu",
		    startuid, startuid + num - 1);
	}
	*copyuidp = copyuid;
    }

    return r;
}

/*
 * Helper function to multiappend a message to remote mailbox
 */
static int index_appendremote(struct mailbox *mailbox,
			      unsigned msgno, void *rock)
{
    struct protstream *pout = (struct protstream *) rock;
    const char *msg_base = 0;
    unsigned long msg_size = 0;
    bit32 system_flags;
    bit32 user_flags[MAX_USER_FLAGS/32];
    unsigned flag;
    bit32 flagmask = 0;
    char datebuf[30];
    char sepchar = '(';

    /* Open the message file */
    if (mailbox_map_message(mailbox, UID(msgno), &msg_base, &msg_size)) {
	return IMAP_NO_MSGGONE;
    }

    /* start the individual append */
    prot_printf(pout, " ");

    /* add system flags */
    system_flags = SYSTEM_FLAGS(msgno);
    if (system_flags & FLAG_ANSWERED) {
	prot_printf(pout, "%c\\Answered", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_FLAGGED) {
	prot_printf(pout, "%c\\Flagged", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_DRAFT) {
	prot_printf(pout, "%c\\Draft", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_DELETED) {
	prot_printf(pout, "%c\\Deleted", sepchar);
	sepchar = ' ';
    }
    if (seenflag[msgno]) {
	prot_printf(pout, "%c\\Seen", sepchar);
	sepchar = ' ';
    }

    /* add user flags */
    for (flag = 0; flag < VECTOR_SIZE(user_flags); flag++) {
	user_flags[flag] = USER_FLAGS(msgno, flag);
    }
    for (flag = 0; flag < VECTOR_SIZE(mailbox->flagname); flag++) {
	if ((flag & 31) == 0) {
	    flagmask = user_flags[flag/32];
	}
	if (mailbox->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    prot_printf(pout, "%c%s", sepchar, mailbox->flagname[flag]);
	    sepchar = ' ';
	}
    }

    /* add internal date */
    cyrus_ctime(INTERNALDATE(msgno), datebuf);
    prot_printf(pout, ") \"%s\" ", datebuf);

    /* message literal */
    index_fetchmsg(msg_base, msg_size, mailbox->format, 0, SIZE(msgno),
		   0, 0, pout);

    /* close the message file */
    if (msg_base) {
	mailbox_unmap_message(mailbox, UID(msgno), &msg_base, &msg_size);
    }

    return 0;
}

/*
 * Performs a COPY command from a local mailbox to a remote mailbox
 */
int index_copy_remote(struct mailbox *mailbox, char *sequence, 
		      int usinguid, struct protstream *pout)
{
    return index_forsequence(mailbox, sequence, usinguid, index_appendremote,
			     (void *) pout, NULL);
}

/*
 * Performs a STATUS command
 */
int index_status(char *mboxname, char *name, unsigned statusitems)
{
    int r;
    struct statuscache_data scdata;
    struct mailbox mailbox;
    int doclose = 0;
    int num_recent = 0;
    int num_unseen = 0;
    int sepchar;
    static struct seq_set seq_set = { NULL, 0, 0, 0 , NULL};

    /* Check status cache if possible */
    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	/* Do actual lookup of cache item. */
	r = statuscache_lookup(mboxname, imapd_userid, statusitems, &scdata);

	/* Seen/recent status uses "push" invalidation events from
	 * seen_db.c.   This avoids needing to open cyrus.header to get
	 * the mailbox uniqueid to open the seen db and get the
	 * unseen_mtime and recentuid.
	 */

	if (!r) {
	    syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'yes'",
		   mboxname, imapd_userid, statusitems);
	    goto statusdone;
	}

	syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'no'",
	       mboxname, imapd_userid, statusitems);
    }

    /* Missing or invalid cache entry */
    r = mailbox_open_header(mboxname, imapd_authstate, &mailbox);

    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mailbox);
    }

    if (!r && mailbox.exists != 0 &&
	(statusitems & (STATUS_RECENT | STATUS_UNSEEN))) {
	/* Read \Seen state */
	struct seen *status_seendb;
	time_t last_read, last_change = 0;
	unsigned last_uid;
	char *last_seenuids;

	r = seen_open(&mailbox,
		      (mailbox.options & OPT_IMAP_SHAREDSEEN) ? "anyone" :
		      imapd_userid,
		      SEEN_CREATE, &status_seendb);

	if (!r) {
	    r = seen_read(status_seendb, &last_read, &last_uid,
			      &last_change, &last_seenuids);
	    seen_close(status_seendb);
	}

	if (!r) {
	    const char *base;
	    unsigned long len = 0;
	    unsigned msg, uid;

	    map_refresh(mailbox.index_fd, 0, &base, &len,
			mailbox.start_offset +
			mailbox.exists * mailbox.record_size,
			"index", mailbox.name);

	    seq_set.len = seq_set.mark = 0;
	    index_parse_sequence(last_seenuids, 0, &seq_set);

	    for (msg = 0; msg < mailbox.exists; msg++) {
		uid = ntohl(*((bit32 *)(base + mailbox.start_offset +
					msg * mailbox.record_size +
					OFFSET_UID)));
		/* Always calculate num_recent,
		   even if only need num_unseen... for caching below */
		if (uid > last_uid) num_recent++;
		if ((statusitems & STATUS_UNSEEN) &&
		    !index_insequence(uid, &seq_set, 1)) num_unseen++;
		/* NB: The value of the third argument to index_insequence()
		 * above does not matter.
		 */
	    }
	    map_free(&base, &len);
	    free(last_seenuids);
	}
    }

    if (!r) {
	/* We always have message count, uidnext,
	   uidvalidity, and highestmodseq for cache */
	unsigned c_statusitems = statusitems | STATUS_MESSAGES |
	    STATUS_UIDNEXT | STATUS_UIDVALIDITY | STATUS_HIGHESTMODSEQ;

	/* If we calculated num_unseen, we implicitly calculated num_recent */
	if (c_statusitems & STATUS_UNSEEN) c_statusitems |= STATUS_RECENT;

	statuscache_fill(&scdata, &mailbox,
			 c_statusitems, num_recent, num_unseen);
    }

    if (doclose) mailbox_close(&mailbox);
    if (r) return r;

    /* Upate the statuscache entry */
    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	statuscache_update(mboxname, imapd_userid, &scdata);
    }

  statusdone:
    prot_printf(imapd_out, "* STATUS ");
    printastring(name);
    prot_printf(imapd_out, " ");
    sepchar = '(';

    if (statusitems & STATUS_MESSAGES) {
	prot_printf(imapd_out, "%cMESSAGES %lu", sepchar, scdata.messages);
	sepchar = ' ';
    }
    if (statusitems & STATUS_RECENT) {
	prot_printf(imapd_out, "%cRECENT %u", sepchar, scdata.recent);
	sepchar = ' ';
    }
    if (statusitems & STATUS_UIDNEXT) {
	prot_printf(imapd_out, "%cUIDNEXT %lu", sepchar, scdata.uidnext);
	sepchar = ' ';
    }
    if (statusitems & STATUS_UIDVALIDITY) {
	prot_printf(imapd_out, "%cUIDVALIDITY %lu", sepchar,
		    scdata.uidvalidity);
	sepchar = ' ';
    }
    if (statusitems & STATUS_UNSEEN) {
	prot_printf(imapd_out, "%cUNSEEN %u", sepchar, scdata.unseen);
	sepchar = ' ';
    }
    if (statusitems & STATUS_HIGHESTMODSEQ) {
	prot_printf(imapd_out, "%cHIGHESTMODSEQ " MODSEQ_FMT, sepchar,
		    scdata.highestmodseq);
	sepchar = ' ';
    }
    prot_printf(imapd_out, ")\r\n");
    return 0;
}

/*
 * Returns the msgno of the message with UID 'uid'.
 * If no message with UID 'uid', returns the message with
 * the higest UID not greater than 'uid'.
 */
unsigned index_finduid(unsigned uid)
{
    unsigned low=1, high=imapd_exists, mid;
    unsigned miduid;

    while (low <= high) {
	mid = (high - low)/2 + low;
	miduid = UID(mid);
	if (miduid == uid) {
	    return mid;
	}
	else if (miduid > uid) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    return high;
}

/*
 * Expunge decision procedure to get rid of articles
 * both \Deleted and listed in the sequence under 'rock'.
 */
unsigned index_expungeuidlist(struct mailbox *mailbox __attribute__((unused)),
			      void *rock,
			      unsigned char *indexbuf,
			      int expunge_flags __attribute__((unused)))
{
    struct seq_set *sequence = (struct seq_set *)rock;
    unsigned uid = ntohl(*((bit32 *)(indexbuf+OFFSET_UID)));

    /* Don't expunge if not \Deleted */
    if (!(ntohl(*((bit32 *)(indexbuf+OFFSET_SYSTEM_FLAGS))) & FLAG_DELETED))
	return 0;

    /* XXX  Can we use the previous range marker? */
    return index_insequence(uid, sequence, 0);
}

/*
 * Call a function 'proc' on each message in 'sequence'.  If 'usinguid'
 * is nonzero, 'sequence' is interpreted as a sequence of UIDs instead
 * of a sequence of msgnos.  'proc' is called with arguments 'mailbox',
 * the msgno, and 'rock'.  If any invocation of 'proc' returns nonzero,
 * returns the first such returned value.  Otherwise, returns zero.
 */
static int
index_forsequence(struct mailbox* mailbox,
		  const char* sequence,
		  int usinguid,
		  index_sequenceproc_t proc,
		  void* rock,
		  int* fetchedsomething)
{
    struct seq_set *seq;
    unsigned i, j;
    int r, result = 0;

    /* no messages, no calls. */
    if (!imapd_exists) return 0;

    seq = index_parse_sequence(sequence, usinguid, NULL);

    for (i = 0; i < seq->len; i++) {
	unsigned start = seq->set[i].low;
	unsigned end = seq->set[i].high;

	if (usinguid) {
	    j = index_finduid(start);
	    if (!j || start != UID(j)) j++;
	    start = j;
	    end = index_finduid(end);
	}
	if (start < 1) start = 1;
	if (end > (unsigned) imapd_exists) end = imapd_exists;

	for (j = start; j <= end; j++) {
	    if (fetchedsomething) *fetchedsomething = 1;
	    r = (*proc)(mailbox, j, rock);
	    if (r && !result) result = r;
	}
    }

    freesequencelist(seq);
    return result;
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
 * of size 'msg_size' and format 'format', starting at 'offset' and
 * containing 'size' octets.  If 'octet_count' is nonzero, the data is
 * further constrained by 'start_octet' and 'octet_count' as per the
 * IMAP command PARTIAL.
 */
void
index_fetchmsg(msg_base, msg_size, format, offset, size,
	       start_octet, octet_count, pout)
const char *msg_base;
unsigned long msg_size;
int format __attribute__((unused));
unsigned offset;
unsigned size;     /* this is the correct size for a news message after
		      having LF translated to CRLF */
unsigned start_octet;
unsigned octet_count;
struct protstream *pout;
{
  unsigned n, domain;

    /* If no data, output NIL */
    if (!msg_base) {
	prot_printf(pout, "NIL");
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
	prot_printf(pout, "\"\"");
	return;
    }

    /* Seek over PARTIAL constraint */
    offset += start_octet;
    n = size;
    if (offset + size > msg_size) {
	n = msg_size - offset;
    }

    /* Get domain of the data */
    domain = data_domain(msg_base + offset, n);

    if (domain == DOMAIN_BINARY) {
	/* Write size of literal8 */
	prot_printf(pout, "~{%u}\r\n", size);
    } else {
	/* Write size of literal */
	prot_printf(pout, "{%u}\r\n", size);
    }

    /* Non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(pout);

    prot_write(pout, msg_base + offset, n);
    while (n++ < size) {
	/* File too short, resynch client.
	 *
	 * This can only happen if the reported size of the part
	 * is incorrect and would push us past EOF.
	 */
	prot_putc(' ', pout);
    }

    /* End of non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(pout);
}

/*
 * Helper function to fetch a body section
 */
static int index_fetchsection(const char *resp,
			      const char *msg_base, unsigned long msg_size,
			      int format, char *section,
			      const char *cachestr, unsigned size,
			      unsigned start_octet, unsigned octet_count)
{
    char *p;
    unsigned skip = 0;
    int fetchmime = 0;
    unsigned offset = 0;
    char *decbuf = NULL;

    p = section;

    /* Special-case BODY[] */
    if (*p == ']') {
	if (strstr(resp, "BINARY.SIZE")) {
	    prot_printf(imapd_out, "%s%u", resp, size);
	} else {
	    prot_printf(imapd_out, "%s", resp);
	    index_fetchmsg(msg_base, msg_size, format, 0, size,
			   start_octet, octet_count, imapd_out);
	}
	return 0;
    }

    while (*p != ']' && *p != 'M') {
	/* Generate the actual part number */
	skip = 0;
	while (cyrus_isdigit((int) *p)) {
            skip = skip * 10 + *p++ - '0';
            /* xxx overflow */
        }
	if (*p == '.') p++;

	/* section number too large */
	if (skip >= CACHE_ITEM_BIT32(cachestr)) goto badpart;

	/* Handle .0, .HEADER, and .TEXT */
	if (!skip) {
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
	
	if (*p != ']' && *p != 'M') {
	    /* We are NOT at the end of a part specification, so there's
	     * a subpart being requested.  Find the subpart in the tree. */

	    /* Skip the headers for this part, along with the number of
	     * sub parts */
	    cachestr +=
		CACHE_ITEM_BIT32(cachestr) * 5 * 4 + CACHE_ITEM_SIZE_SKIP;

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

	msg_base = charset_decode_mimebody(msg_base + offset, size, encoding,
					   &decbuf, 0, (int *) &size);

	if (!msg_base) {
	    /* failed to decode */
	    if (decbuf) free(decbuf);
	    return IMAP_NO_UNKNOWN_CTE;
	}
	else if (p[6] == '.') {
	    /* BINARY.SIZE */
	    prot_printf(imapd_out, "%s%u", resp, size);
	    
	    if (decbuf) free(decbuf);
	    return 0;
	}
	else {
	    /* BINARY */
	    msg_size = size;
	    offset = 0;
	}
    }

    /* Output body part */
    prot_printf(imapd_out, "%s", resp);
    index_fetchmsg(msg_base, msg_size, format, offset, size,
		   start_octet, octet_count, imapd_out);

    if (decbuf) free(decbuf);
    return 0;

 badpart:
    if (strstr(resp, "BINARY.SIZE"))
	prot_printf(imapd_out, "%s0", resp);
    else
	prot_printf(imapd_out, "%sNIL", resp);
    return 0;
}

/*
 * Helper function to fetch a HEADER.FIELDS[.NOT] body section
 */
static void index_fetchfsection(const char *msg_base,
				unsigned long msg_size,
				int format,
				struct fieldlist *fsection,
				const char *cachestr,
				unsigned start_octet, unsigned octet_count)
{
    char *p;
    unsigned skip = 0;
    int fields_not = 0;
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    char *buf;
    unsigned size;

    /* If no data, output null quoted string */
    if (!msg_base) {
	prot_printf(imapd_out, "\"\"");
	return;
    }

    p = fsection->section;

    while (*p != 'H') {
	skip = 0;
	while (cyrus_isdigit((int) *p)) {
            skip = skip * 10 + *p++ - '0';
            /* xxx overflow */
        }
	if (*p == '.') p++;

	/* section number too large */
	if (skip >= CACHE_ITEM_BIT32(cachestr)) goto badpart;

	cachestr += CACHE_ITEM_BIT32(cachestr) * 5 * 4 + CACHE_ITEM_SIZE_SKIP;
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

    buf = index_readheader(msg_base, msg_size, format,
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
	prot_printf(imapd_out, "\"\"");
	return;
    }

    /* Write literal */
    prot_printf(imapd_out, "{%u}\r\n", size + crlf_size);
    prot_write(imapd_out, buf + start_octet, size);
    prot_write(imapd_out, "\r\n" + crlf_start, crlf_size);

    return;

 badpart:
    prot_printf(imapd_out, "NIL");
}

/*
 * Helper function to read a header section into a static buffer
 */
static char *
index_readheader(msg_base, msg_size, format, offset, size)
const char *msg_base;
unsigned long msg_size;
int format __attribute__((unused));
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
static void
index_fetchheader(msg_base, msg_size, format, size, headers, headers_not)
const char *msg_base;
unsigned long msg_size;
int format;
unsigned size;
struct strlist *headers;
struct strlist *headers_not;
{
    char *buf;

    /* If no data, output null quoted string */
    if (!msg_base) {
	prot_printf(imapd_out, "\"\"");
	return;
    }

    buf = index_readheader(msg_base, msg_size, format, 0, size);

    index_pruneheader(buf, headers, headers_not);

    size = strlen(buf);
    prot_printf(imapd_out, "{%u}\r\n%s\r\n", size+2, buf);
}

/*
 * Handle a FETCH RFC822.HEADER.LINES that can use the
 * cacheheaders in cyrus.cache
 */
static void
index_fetchcacheheader(unsigned msgno, struct strlist *headers,
		       unsigned start_octet, unsigned octet_count)
{
    static char *buf;
    static unsigned bufsize;
    cacherecord crec;
    unsigned size;
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;

    if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	/* bogus cache record */
	prot_printf(imapd_out, "\"\"");
	return;
    }

    size = crec[CACHE_HEADERS].l;
    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    memcpy(buf, crec[CACHE_HEADERS].s, size);
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
	prot_printf(imapd_out, "\"\"");
    }
    else {
	prot_printf(imapd_out, "{%u}\r\n", size + crlf_size);
	prot_write(imapd_out, buf + start_octet, size);
	prot_write(imapd_out, "\r\n" + crlf_start, crlf_size);
    }
}

/*
 * Send a * FLAGS response.
 */
static void index_listflags(struct mailbox *mailbox)
{
    unsigned i;
    int cancreate = 0;
    char sepchar = '(';

    prot_printf(imapd_out, "* FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen");
    for (i = 0; i < VECTOR_SIZE(mailbox->flagname); i++) {
	if (mailbox->flagname[i]) {
	    prot_printf(imapd_out, " %s", mailbox->flagname[i]);
	}
	else cancreate++;
    }
    prot_printf(imapd_out, ")\r\n* OK [PERMANENTFLAGS ");
    if (!mailbox->examining) {
	if (mailbox->myrights & ACL_WRITE) {
	    prot_printf(imapd_out, "%c\\Answered \\Flagged \\Draft", sepchar);
	    sepchar = ' ';
	}
	if (mailbox->myrights & ACL_DELETEMSG) {
	    prot_printf(imapd_out, "%c\\Deleted", sepchar);
	    sepchar = ' ';
	}
	if (mailbox->myrights & ACL_SEEN) {
	    prot_printf(imapd_out, "%c\\Seen", sepchar);
	    sepchar = ' ';
	}
	if (mailbox->myrights & ACL_WRITE) {
	    for (i = 0; i < VECTOR_SIZE(mailbox->flagname); i++) {
		if (mailbox->flagname[i]) {
		    prot_printf(imapd_out, " %s", mailbox->flagname[i]);
		}
	    }
	    if (cancreate) {
		prot_printf(imapd_out, " \\*");
	    }
	}
    }
    if (sepchar == '(') prot_printf(imapd_out, "(");
    prot_printf(imapd_out, ")]  \r\n");
}

/*
 * Helper function to send * FETCH (FLAGS data.
 * Does not send the terminating close paren or CRLF.
 * Also sends preceeding * FLAGS if necessary.
 */
static void index_fetchflags(struct mailbox *mailbox,
			     unsigned msgno,
			     bit32 system_flags,
			     bit32 user_flags[MAX_USER_FLAGS/32],
			     time_t last_updated)
{
    int sepchar = '(';
    unsigned flag;
    bit32 flagmask = 0;

    for (flag = 0; flag < VECTOR_SIZE(mailbox->flagname); flag++) {
	if ((flag & 31) == 0) {
	    flagmask = user_flags[flag/32];
	}
	if (!mailbox->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    mailbox_read_header(mailbox);
	    index_listflags(mailbox);
	    break;
	}
    }

    prot_printf(imapd_out, "* %u FETCH (FLAGS ", msgno);

    if (msgno > lastnotrecent) {
	prot_printf(imapd_out, "%c\\Recent", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_ANSWERED) {
	prot_printf(imapd_out, "%c\\Answered", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_FLAGGED) {
	prot_printf(imapd_out, "%c\\Flagged", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_DRAFT) {
	prot_printf(imapd_out, "%c\\Draft", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_DELETED) {
	prot_printf(imapd_out, "%c\\Deleted", sepchar);
	sepchar = ' ';
    }
    if (seenflag[msgno]) {
	prot_printf(imapd_out, "%c\\Seen", sepchar);
	sepchar = ' ';
    }
    for (flag = 0; flag < VECTOR_SIZE(mailbox->flagname); flag++) {
	if ((flag & 31) == 0) {
	    flagmask = user_flags[flag/32];
	}
	if (mailbox->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    prot_printf(imapd_out, "%c%s", sepchar, mailbox->flagname[flag]);
	    sepchar = ' ';
	}
    }
    if (sepchar == '(') prot_putc('(', imapd_out);
    prot_putc(')', imapd_out);

    assert(flagalloced > 0 || msgno < (unsigned) flagalloced);

    flagreport[msgno] = last_updated;
}

/*
 * Helper function to send requested * FETCH data for a message
 */
static int index_fetchreply(struct mailbox *mailbox,
			    unsigned msgno, void *rock)
{
    struct fetchargs *fetchargs = (struct fetchargs *)rock;    
    int fetchitems = fetchargs->fetchitems;
    const char *msg_base = 0;
    unsigned long msg_size = 0;
    struct octetinfo *oi = NULL;
    int sepchar = '(';
    int started = 0;
    unsigned i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    cacherecord crec;
    struct strlist *section, *field;
    struct fieldlist *fsection;
    char respbuf[100];
    int r = 0;

    /* Check the modseq against changedsince */
    if (fetchargs->changedsince &&
	MODSEQ(msgno) <= fetchargs->changedsince) {
	return 0;
    }

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_RFC822)) ||
	fetchargs->cache_atleast > CACHE_VERSION(msgno) ||
	fetchargs->binsections || fetchargs->sizesections ||
	fetchargs->bodysections) {
	if (mailbox_map_message(mailbox, UID(msgno), &msg_base, &msg_size)) {
	    prot_printf(imapd_out, "* OK ");
	    prot_printf(imapd_out, error_message(IMAP_NO_MSGGONE), msgno);
	    prot_printf(imapd_out, "\r\n");
	}
    }

    /* set the \Seen flag if necessary */
    if (fetchitems & FETCH_SETSEEN) {
	if (!seenflag[msgno] && (mailbox->myrights & ACL_SEEN)) {
	    seenflag[msgno] = 1;
	    fetchitems |= FETCH_FLAGS;
	}
    }

    if (fetchitems & FETCH_FLAGS) {
	for (i = 0; i < VECTOR_SIZE(user_flags); i++) {
	    user_flags[i] = USER_FLAGS(msgno, i);
	}
	index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
			 LAST_UPDATED(msgno));
	sepchar = ' ';
    }
    else if ((fetchitems & ~FETCH_SETSEEN) ||  fetchargs->fsections ||
	     fetchargs->headers || fetchargs->headers_not) {
	/* these fetch items will always succeed, so start the response */
	prot_printf(imapd_out, "* %u FETCH ", msgno);
	started = 1;
    }
    if (fetchitems & FETCH_UID) {
	prot_printf(imapd_out, "%cUID %u", sepchar, UID(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_INTERNALDATE) {
	time_t msgdate = INTERNALDATE(msgno);
	char datebuf[30];

	cyrus_ctime(msgdate, datebuf);

	prot_printf(imapd_out, "%cINTERNALDATE \"%s\"",
		    sepchar, datebuf);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_MODSEQ) {
	prot_printf(imapd_out, "%cMODSEQ (" MODSEQ_FMT ")",
		    sepchar, MODSEQ(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_SIZE) {
	prot_printf(imapd_out, "%cRFC822.SIZE %u", sepchar, SIZE(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_ENVELOPE) {
        if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	    prot_printf(imapd_out, "%cENVELOPE ", sepchar);
	    sepchar = ' ';
	    prot_write(imapd_out, crec[CACHE_ENVELOPE].s, crec[CACHE_ENVELOPE].l);
	}
    }
    if (fetchitems & FETCH_BODYSTRUCTURE) {
        if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	    prot_printf(imapd_out, "%cBODYSTRUCTURE ", sepchar);
	    sepchar = ' ';
	    prot_write(imapd_out, crec[CACHE_BODYSTRUCTURE].s, crec[CACHE_BODYSTRUCTURE].l);
	}
    }
    if (fetchitems & FETCH_BODY) {
        if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	    prot_printf(imapd_out, "%cBODY ", sepchar);
	    sepchar = ' ';
	    prot_write(imapd_out, crec[CACHE_BODY].s, crec[CACHE_BODY].l);
	}
    }

    if (fetchitems & FETCH_HEADER) {
	prot_printf(imapd_out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msg_base, msg_size, mailbox->format, 0,
		       HEADER_SIZE(msgno),
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->start_octet : 0,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->octet_count : 0,
		       imapd_out);
    }
    else if (fetchargs->headers || fetchargs->headers_not) {
	prot_printf(imapd_out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	if(fetchargs->cache_atleast > CACHE_VERSION(msgno)) {
	    index_fetchheader(msg_base, msg_size, mailbox->format,
			      HEADER_SIZE(msgno),
			      fetchargs->headers, fetchargs->headers_not);
	} else {
	    index_fetchcacheheader(msgno, fetchargs->headers, 0, 0);
	}
    }

    if (fetchitems & FETCH_TEXT) {
	prot_printf(imapd_out, "%cRFC822.TEXT ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msg_base, msg_size, mailbox->format,
		       CONTENT_OFFSET(msgno), SIZE(msgno) - HEADER_SIZE(msgno),
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->start_octet : 0,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->octet_count : 0,
		       imapd_out);
    }
    if (fetchitems & FETCH_RFC822) {
	prot_printf(imapd_out, "%cRFC822 ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msg_base, msg_size, mailbox->format, 0, SIZE(msgno),
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->start_octet : 0,
		       (fetchitems & FETCH_IS_PARTIAL) ?
		         fetchargs->octet_count : 0,
		       imapd_out);
    }
    for (fsection = fetchargs->fsections; fsection; fsection = fsection->next) {
	prot_printf(imapd_out, "%cBODY[%s ", sepchar, fsection->section);
	sepchar = '(';
	for (field = fsection->fields; field; field = field->next) {
	    prot_putc(sepchar, imapd_out);
	    sepchar = ' ';
	    printastring(field->s);
	}
	prot_putc(')', imapd_out);
	sepchar = ' ';

	oi = (struct octetinfo *)fsection->rock;

	prot_printf(imapd_out, "%s ", fsection->trail);

	if(fetchargs->cache_atleast > CACHE_VERSION(msgno)) {
	    if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
		index_fetchfsection(msg_base, msg_size, mailbox->format, fsection,
				    crec[CACHE_SECTION].s,
				    (fetchitems & FETCH_IS_PARTIAL) ?
				      fetchargs->start_octet : oi->start_octet,
				    (fetchitems & FETCH_IS_PARTIAL) ?
				      fetchargs->octet_count : oi->octet_count);
	    else
	    	prot_printf(imapd_out, "NIL");
	    
	}
	else {
	    index_fetchcacheheader(msgno, fsection->fields,
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

	if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	    r = index_fetchsection(respbuf, msg_base, msg_size, mailbox->format,
			           section->s, crec[CACHE_SECTION].s, SIZE(msgno),
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

	if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	    oi = section->rock;
	    r = index_fetchsection(respbuf, msg_base, msg_size, mailbox->format,
			           section->s, crec[CACHE_SECTION].s, SIZE(msgno),
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

	if (cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	    r = index_fetchsection(respbuf, msg_base, msg_size, mailbox->format,
			           section->s, crec[CACHE_SECTION].s, SIZE(msgno),
			           fetchargs->start_octet, fetchargs->octet_count);
	    if (!r) sepchar = ' ';
	}
    }
    if (sepchar != '(') {
	/* finsh the response if we have one */
	prot_printf(imapd_out, ")\r\n");
    }
    if (msg_base) {
	mailbox_unmap_message(mailbox, UID(msgno), &msg_base, &msg_size);
    }
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
int index_urlfetch(struct mailbox *mailbox, unsigned msgno,
		   const char *section,
		   unsigned long start_octet, unsigned long octet_count,
		   struct protstream *pout, unsigned long *outsize)
{
    const char *msg_base = 0;
    unsigned long msg_size = 0;
    cacherecord crec;
    const char *cachestr;
    int fetchmime = 0;
    unsigned size, offset = 0, skip = 0;
    int n, r = 0;

    if (outsize) *outsize = 0;

    /* Open the message file */
    if (mailbox_map_message(mailbox, UID(msgno), &msg_base, &msg_size)) {
	return IMAP_NO_MSGGONE;
    }

    if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
	return IMAP_NO_MSGGONE;
    }

    size = crec[CACHE_SECTION].l;
    cachestr = crec[CACHE_SECTION].s;

    /* Special-case BODY[] */
    if (!section || !*section) {
	/* whole message, no further parsing */
    }
    else {
	char *p = ucase((char *) section);

	while (*p && *p != 'M') {
	    /* Generate the actual part number */
	    skip = 0;
	    while (cyrus_isdigit((int) *p)) {
		skip = skip * 10 + *p++ - '0';
		/* xxx overflow */
	    }
	    if (*p == '.') p++;

	    /* section number too large */
	    if (skip >= CACHE_ITEM_BIT32(cachestr)) {
		r = IMAP_BADURL;
		goto done;
	    }

	    /* Handle .0, .HEADER, and .TEXT */
	    if (!skip) {
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
	
	    if (*p && *p != 'M') {
		/* We are NOT at the end of a part specification, so there's
		 * a subpart being requested.  Find the subpart in the tree. */

		/* Skip the headers for this part, along with the number of
		 * sub parts */
		cachestr +=
		    CACHE_ITEM_BIT32(cachestr) * 5 * 4 + CACHE_ITEM_SIZE_SKIP;

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

	cachestr += skip * 5 * 4 + CACHE_ITEM_SIZE_SKIP +
	    (fetchmime ? 0 : 2 * 4);
    
	if (CACHE_ITEM_BIT32(cachestr + CACHE_ITEM_SIZE_SKIP) == (bit32) -1) {
	    r = IMAP_BADURL;
	    goto done;
	}

	offset = CACHE_ITEM_BIT32(cachestr);
	size = CACHE_ITEM_BIT32(cachestr + CACHE_ITEM_SIZE_SKIP);
    }

    /* Handle PARTIAL request */
    offset += start_octet;
    if (octet_count) size = octet_count;

    /* Sanity check the requested size */
    if (size && (offset + size > msg_size))
	n = msg_size - offset;
    else
	n = size;

    if (outsize)
	*outsize = n;
    else
	prot_printf(pout, "{%u}\r\n", n);

    prot_write(pout, msg_base + offset, n);

  done:
    /* Close the message file */
    mailbox_unmap_message(mailbox, UID(msgno), &msg_base, &msg_size);

    return r;
}

/*
 * Helper function to perform a STORE command which only changes the
 * \Seen flag.
 */
static int index_storeseen(struct mailbox *mailbox, unsigned msgno, void *rock)
{
    struct storeargs *storeargs = (struct storeargs *)rock;
    int val = (storeargs->operation == STORE_ADD) ? 1 : 0;
    unsigned i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    
    if (seenflag[msgno] == val) return 0;
    seenflag[msgno] = val;

    if (storeargs->silent) return 0;

    for (i=0; i < VECTOR_SIZE(user_flags); i++) {
	user_flags[i] = USER_FLAGS(msgno, i);
    }
    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
		     LAST_UPDATED(msgno));
    if (storeargs->usinguid) {
	prot_printf(imapd_out, " UID %u", UID(msgno));
    }
    prot_printf(imapd_out, ")\r\n");

    return 0;
}

/*
 * Helper function to perform a generalized STORE command
 */
static int index_storeflag(struct mailbox *mailbox,
			   unsigned msgno, void *rock)
{
    struct storeargs *storeargs = (struct storeargs *)rock;
    unsigned i;
    struct index_record record;
    unsigned long uid = UID(msgno);
    unsigned low=1, high=mailbox->exists;
    unsigned mid = 0;
    int r;
    int firsttry = 1;
    int dirty = 0;
    bit32 oldflags;
    int sepchar = '(';

    /* Check the modseq against unchangedsince */
    if (MODSEQ(msgno) > storeargs->unchangedsince) return 0;

    /* Change \Seen flag */
    if (storeargs->operation == STORE_REPLACE && (mailbox->myrights & ACL_SEEN))
    {
	if (seenflag[msgno] != storeargs->seen) dirty++;
	seenflag[msgno] = storeargs->seen;
    }
    else if (storeargs->seen) {
	i = (storeargs->operation == STORE_ADD) ? 1 : 0;
	if (seenflag[msgno] != i) dirty++;
	seenflag[msgno] = i;
    }

    /* Find index record */
    while (low <= high) {
	if (firsttry && msgno == storeargs->last_msgno+1) {
	    /* Take "good" first guess */
	    mid = storeargs->last_found + 1;
	    if (mid > high) mid = high;
	}
	else {
	    mid = (high - low)/2 + low;
	}
	firsttry = 0;
	r = mailbox_read_index_record(mailbox, mid, &record);
	if (r) return r;
	if (record.uid == uid) {
	    break;
	}
	else if (record.uid > uid) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    storeargs->last_msgno = msgno;
    storeargs->last_found = mid;

    if (low > high) {
	/* Message was expunged. */
	if (storeargs->usinguid) {
	    /* We're going to * n EXPUNGE it */
	    return 0;
	}

	/* Fake setting the flags */
	mid = 0;
	storeargs->last_found = high;
	record.system_flags = SYSTEM_FLAGS(msgno);
	for (i = 0; i < VECTOR_SIZE(record.user_flags); i++) {
	    record.user_flags[i] = USER_FLAGS(msgno, i);
	}
    }

    /* save old */
    oldflags = record.system_flags;

    if (storeargs->operation == STORE_REPLACE) {
	if (!(mailbox->myrights & ACL_WRITE)) {
	    /* ACL_DELETE handled in index_store() */
	    if ((record.system_flags & FLAG_DELETED) !=
		(storeargs->system_flags & FLAG_DELETED)) {
		dirty++;
	    }
	    record.system_flags = (record.system_flags&~FLAG_DELETED) |
	      (storeargs->system_flags&FLAG_DELETED);
	}
	else {
	    if (!(mailbox->myrights & ACL_DELETEMSG)) {
		if ((record.system_flags & ~FLAG_DELETED) !=
		    (storeargs->system_flags & ~FLAG_DELETED)) {
		    dirty++;
		}
		record.system_flags = (record.system_flags&FLAG_DELETED) |
		  (storeargs->system_flags&~FLAG_DELETED);
	    }
	    else {
		if (record.system_flags != storeargs->system_flags) dirty++;
		record.system_flags = storeargs->system_flags;
	    }
	    for (i = 0; i < VECTOR_SIZE(record.user_flags); i++) {
		if (record.user_flags[i] != storeargs->user_flags[i]) dirty++;
		record.user_flags[i] = storeargs->user_flags[i];
	    }
	}
    }
    else if (storeargs->operation == STORE_ADD) {
	if (~record.system_flags & storeargs->system_flags) dirty++;

	record.system_flags |= storeargs->system_flags;
	for (i = 0; i < VECTOR_SIZE(record.user_flags); i++) {
	    if (~record.user_flags[i] & storeargs->user_flags[i]) dirty++;
	    record.user_flags[i] |= storeargs->user_flags[i];
	}
    }
    else {			/* STORE_REMOVE */
	if (record.system_flags & storeargs->system_flags) dirty++;

	/* change the individual entry */
	record.system_flags &= ~storeargs->system_flags;
	for (i = 0; i < VECTOR_SIZE(record.user_flags); i++) {
	    if (record.user_flags[i] & storeargs->user_flags[i]) dirty++;
	    record.user_flags[i] &= ~storeargs->user_flags[i];
	}
    }

    if (dirty) {
	if (mailbox->options & OPT_IMAP_CONDSTORE) {
	    /* bump MODSEQ */
	    record.modseq = mailbox->highestmodseq + 1;
	}

	/* update totals */
	if ( (record.system_flags & FLAG_DELETED) && !(oldflags & FLAG_DELETED))
	    mailbox->deleted++;
	if ( !(record.system_flags & FLAG_DELETED) && (oldflags & FLAG_DELETED))
	    mailbox->deleted--;

	if ( (record.system_flags & FLAG_ANSWERED) && !(oldflags & FLAG_ANSWERED))
	    mailbox->answered++;
	if ( !(record.system_flags & FLAG_ANSWERED) && (oldflags & FLAG_ANSWERED))
	    mailbox->answered--;

	if ( (record.system_flags & FLAG_FLAGGED) && !(oldflags & FLAG_FLAGGED))
	    mailbox->flagged++;
	if ( !(record.system_flags & FLAG_FLAGGED) && (oldflags & FLAG_FLAGGED))
	    mailbox->flagged--;

	/* either a system or user flag changed. need to at least touch acap
	   to change the modtime */
	mailbox->dirty = 1;

	/* If .SILENT, assume client has updated their cache */
	if (storeargs->silent && 
	    flagreport[msgno] == record.last_updated) {
	    flagreport[msgno] = 
		(record.last_updated >= storeargs->update_time) ?
		record.last_updated + 1 : storeargs->update_time;
	}
	
	record.last_updated =
	    (record.last_updated >= storeargs->update_time) ?
	    record.last_updated + 1 : storeargs->update_time;
    }
    
    if (!storeargs->silent) {
	index_fetchflags(mailbox, msgno, record.system_flags,
			 record.user_flags, record.last_updated);
	sepchar = ' ';
    }
    if ((mailbox->options & OPT_IMAP_CONDSTORE) && imapd_condstore_client) {
	if (sepchar == '(') {
	    /* we haven't output a fetch item yet, so start the response */
	    prot_printf(imapd_out, "* %u FETCH ", msgno);
	}
	prot_printf(imapd_out, "%cMODSEQ (" MODSEQ_FMT ")",
		    sepchar, record.modseq);
	sepchar = ' ';
    }
    if (sepchar != '(') {
	/* finsh the response if we have one */
	if (storeargs->usinguid) {
	    prot_printf(imapd_out, " UID %u", UID(msgno));
	}
	prot_printf(imapd_out, ")\r\n");
    }
    
    if (dirty && mid) {
	r = mailbox_write_index_record(mailbox, mid, &record, 0);
	if (r) return r;
    }
    
    return 0;
}

/*
 * Evaluate a searchargs structure on a msgno
 *
 * Note: msgfile argument must be 0 if msg is not mapped in.
 */
static int index_search_evaluate(struct mailbox *mailbox,
				 struct searchargs *searchargs,
				 unsigned msgno,
				 struct mapfile *msgfile)
{
    unsigned i;
    struct strlist *l, *h;
    cacherecord crec;
    struct searchsub *s;
    struct seq_set *seq;

    if ((searchargs->flags & SEARCH_RECENT_SET) && msgno <= lastnotrecent) 
	return 0;
    if ((searchargs->flags & SEARCH_RECENT_UNSET) && msgno > lastnotrecent) 
	return 0;
    if ((searchargs->flags & SEARCH_SEEN_SET) && !seenflag[msgno]) return 0;
    if ((searchargs->flags & SEARCH_SEEN_UNSET) && seenflag[msgno]) return 0;

    if (searchargs->smaller && SIZE(msgno) >= searchargs->smaller) return 0;
    if (searchargs->larger && SIZE(msgno) <= searchargs->larger) return 0;

    if (searchargs->after && (time_t) INTERNALDATE(msgno) < searchargs->after)
      return 0;
    if (searchargs->before && (time_t) INTERNALDATE(msgno) >= searchargs->before)
      return 0;
    if (searchargs->sentafter && (time_t) SENTDATE(msgno) < searchargs->sentafter)
      return 0;
    if (searchargs->sentbefore && (time_t) SENTDATE(msgno) >= searchargs->sentbefore)
      return 0;

    if (searchargs->modseq && MODSEQ(msgno) < searchargs->modseq) return 0;

    if (~SYSTEM_FLAGS(msgno) & searchargs->system_flags_set) return 0;
    if (SYSTEM_FLAGS(msgno) & searchargs->system_flags_unset) return 0;
	
    for (i = 0; i < VECTOR_SIZE(searchargs->user_flags_set); i++) {
	if (~USER_FLAGS(msgno,i) & searchargs->user_flags_set[i])
	  return 0;
	if (USER_FLAGS(msgno,i) & searchargs->user_flags_unset[i])
	  return 0;
    }

    for (seq = searchargs->sequence; seq; seq = seq->next) {
	if (!index_insequence(msgno, seq, 1)) return 0;
    }
    for (seq = searchargs->uidsequence; seq; seq = seq->next) {
	if (!index_insequence(UID(msgno), seq, 1)) return 0;
    }

    if (searchargs->from || searchargs->to || searchargs->cc ||
	searchargs->bcc || searchargs->subject || searchargs->messageid) {

	if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
	    return 0;

	if (searchargs->messageid) {
	    char *tmpenv;
	    char *envtokens[NUMENVTOKENS];
	    char *msgid;
	    int msgidlen;

	    /* get msgid out of the envelope */

	    /* get a working copy; strip outer ()'s */
	    /* +1 -> skip the leading paren */
	    /* -2 -> don't include the size of the outer parens */
	    tmpenv = xstrndup(crec[CACHE_ENVELOPE].s + 1, crec[CACHE_ENVELOPE].l - 2);
	    parse_cached_envelope(tmpenv, envtokens, VECTOR_SIZE(envtokens));

	    if (!envtokens[ENV_MSGID]) {
		/* free stuff */
		free(tmpenv);

		return 0;
	    }

	    msgid = lcase(envtokens[ENV_MSGID]);
	    msgidlen = strlen(msgid);
	    for (l = searchargs->messageid; l; l = l->next) {
		if (!charset_searchstring(l->s, l->p, msgid, msgidlen)) {
		    break;
		}
	    }

	    /* free stuff */
	    free(tmpenv);

	    if (l) return 0;
	}

	for (l = searchargs->from; l; l = l->next) {
	    if (!crec[CACHE_FROM].l ||
		!charset_searchstring(l->s, l->p,
				      crec[CACHE_FROM].s, crec[CACHE_FROM].l))
		return 0;
	}

	for (l = searchargs->to; l; l = l->next) {
	    if (!crec[CACHE_TO].l ||
		!charset_searchstring(l->s, l->p,
				      crec[CACHE_TO].s, crec[CACHE_TO].l))
		return 0;
	}

	for (l = searchargs->cc; l; l = l->next) {
	    if (!crec[CACHE_CC].l ||
		!charset_searchstring(l->s, l->p,
				      crec[CACHE_CC].s, crec[CACHE_CC].l))
		return 0;
	}

	for (l = searchargs->bcc; l; l = l->next) {
	    if (!crec[CACHE_BCC].l ||
		!charset_searchstring(l->s, l->p,
				      crec[CACHE_BCC].s, crec[CACHE_BCC].l))
		return 0;
	}

	for (l = searchargs->subject; l; l = l->next) {
	    if ((crec[CACHE_SUBJECT].l == 3 && 
		 !strncmp(crec[CACHE_SUBJECT].s, "NIL", 3)) ||
		!charset_searchstring(l->s, l->p,
				      crec[CACHE_SUBJECT].s, crec[CACHE_SUBJECT].l))
		return 0;
	}
    }

    for (s = searchargs->sublist; s; s = s->next) {
	if (index_search_evaluate(mailbox, s->sub1, msgno, msgfile)) {
	    if (!s->sub2) return 0;
	}
	else {
	    if (s->sub2 &&
		!index_search_evaluate(mailbox, s->sub2, msgno, msgfile))
	      return 0;
	}
    }

    if (searchargs->body || searchargs->text ||
	searchargs->cache_atleast > CACHE_VERSION(msgno)) {
	if (! msgfile->size) { /* Map the message in if we haven't before */
	    if (mailbox_map_message(mailbox, UID(msgno),
				    &msgfile->base, &msgfile->size)) {
		return 0;
	    }
	}

	h = searchargs->header_name;
	for (l = searchargs->header; l; (l = l->next), (h = h->next)) {
	    if (!index_searchheader(h->s, l->s, l->p, msgfile, mailbox->format,
				    HEADER_SIZE(msgno))) return 0;
	}

	if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
	    return 0;

	for (l = searchargs->body; l; l = l->next) {
	    if (!index_searchmsg(l->s, l->p, msgfile, mailbox->format, 1,
				 crec[CACHE_SECTION].s)) return 0;
	}
	for (l = searchargs->text; l; l = l->next) {
	    if (!index_searchmsg(l->s, l->p, msgfile, mailbox->format, 0,
				 crec[CACHE_SECTION].s)) return 0;
	}
    }
    else if (searchargs->header_name) {
	h = searchargs->header_name;
	for (l = searchargs->header; l; (l = l->next), (h = h->next)) {
	    if (!index_searchcacheheader(msgno, h->s, l->s, l->p)) return 0;
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
		int format,
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
		skipheader = 0;	/* Only skip top-level message header */
	    }
	    else {
		len = CACHE_ITEM_BIT32(cachestr + CACHE_ITEM_SIZE_SKIP);
		if (len > 0) {
		    p = index_readheader(msgfile->base, msgfile->size,
					 format, CACHE_ITEM_BIT32(cachestr),
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
					   format == MAILBOX_FORMAT_NETNEWS,
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
			      int format,
			      int size)
{
    char *p, *q;
    int r;
    static struct strlist header;

    header.s = name;

    p = index_readheader(msgfile->base, msgfile->size, format, 0, size);
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
static int index_searchcacheheader(unsigned msgno,
				   char *name, char *substr,
				   comp_pat *pat)
{
    char *q;
    static struct strlist header;
    static char *buf;
    static unsigned bufsize;
    cacherecord crec;
    unsigned size;
    int r;

    if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
	return 0;

    size = crec[CACHE_HEADERS].l;
    if (!size) return 0;	/* No cached headers, fail */
    
    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    /* Copy this item to the buffer */
    memcpy(buf, crec[CACHE_HEADERS].s, size);
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
static void index_getsearchtextmsg(struct mailbox* mailbox,
                                  int uid,
                                  index_search_text_receiver_t receiver,
                                  void* rock,
                                  char const* cachestr) {
  struct mapfile msgfile;
  int partsleft = 1;
  int subparts;
  unsigned long start;
  int len, charset, encoding;
  int partcount = 0;
  char *p, *q;
  int format = mailbox->format;
  
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
                                   format, CACHE_ITEM_BIT32(cachestr),
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

		if (start < msgfile.size && len > 0 &&
		    charset >= 0 && charset < 0xffff) {
                  charset_extractfile(receiver, rock, uid,
                                      msgfile.base + start,
                                      format == MAILBOX_FORMAT_NETNEWS,
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

void index_getsearchtext_single(struct mailbox* mailbox, unsigned msgno,
                                index_search_text_receiver_t receiver,
                                void* rock) {
    cacherecord crec;
    int uid = UID(msgno);

    if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
	return;

    index_getsearchtextmsg(mailbox, uid, receiver, rock, crec[CACHE_SECTION].s);
    
    receiver(uid, SEARCHINDEX_PART_FROM, SEARCHINDEX_CMD_STUFFPART,
             crec[CACHE_FROM].s, crec[CACHE_FROM].l, rock);

    receiver(uid, SEARCHINDEX_PART_TO, SEARCHINDEX_CMD_STUFFPART,
             crec[CACHE_TO].s, crec[CACHE_TO].l, rock);

    receiver(uid, SEARCHINDEX_PART_CC, SEARCHINDEX_CMD_STUFFPART,
             crec[CACHE_CC].s, crec[CACHE_CC].l, rock);

    receiver(uid, SEARCHINDEX_PART_BCC, SEARCHINDEX_CMD_STUFFPART,
             crec[CACHE_BCC].s, crec[CACHE_BCC].l, rock);

    receiver(uid, SEARCHINDEX_PART_SUBJECT, SEARCHINDEX_CMD_STUFFPART,
             crec[CACHE_SUBJECT].s, crec[CACHE_SUBJECT].l, rock);
}

void index_getsearchtext(struct mailbox* mailbox,
                         index_search_text_receiver_t receiver,
                         void* rock)
{
    int i;

    /* Send the converted text of every message out to the receiver. */
    for (i = 1; i <= imapd_exists; i++)
        index_getsearchtext_single(mailbox, i, receiver, rock);
}

/*
 * Helper function to set up arguments to append_copy()
 */
#define COPYARGSGROW 30
static int
index_copysetup(mailbox, msgno, rock)
struct mailbox *mailbox;
unsigned msgno;
void *rock;
{
    struct copyargs *copyargs = (struct copyargs *)rock;
    int flag = 0;
    unsigned userflag;
    bit32 flagmask = 0;

    if (copyargs->nummsg == copyargs->msgalloc) {
	copyargs->msgalloc += COPYARGSGROW;
	copyargs->copymsg = (struct copymsg *)
	  xrealloc((char *)copyargs->copymsg,
		   copyargs->msgalloc * sizeof(struct copymsg));
    }

    copyargs->copymsg[copyargs->nummsg].uid = UID(msgno);
    copyargs->copymsg[copyargs->nummsg].internaldate = INTERNALDATE(msgno);
    copyargs->copymsg[copyargs->nummsg].sentdate = SENTDATE(msgno);
    copyargs->copymsg[copyargs->nummsg].size = SIZE(msgno);
    copyargs->copymsg[copyargs->nummsg].header_size = HEADER_SIZE(msgno);
    copyargs->copymsg[copyargs->nummsg].content_lines = CONTENT_LINES(msgno);
    copyargs->copymsg[copyargs->nummsg].cache_version = CACHE_VERSION(msgno);
    copyargs->copymsg[copyargs->nummsg].cache_begin = cache_base + CACHE_OFFSET(msgno);
    message_guid_import(&copyargs->copymsg[copyargs->nummsg].guid,
                        (unsigned char *) /* YYY */
                        INDEC_OFFSET(msgno)+OFFSET_MESSAGE_GUID);

    if (mailbox->format != MAILBOX_FORMAT_NORMAL) {
	/* Force copy and re-parse of message */
	copyargs->copymsg[copyargs->nummsg].cache_len = 0;
    }
    else {
	copyargs->copymsg[copyargs->nummsg].cache_len =
	    mailbox_cacherecord_index(mailbox, msgno, 0);
    }
    copyargs->copymsg[copyargs->nummsg].seen = seenflag[msgno];
    copyargs->copymsg[copyargs->nummsg].system_flags = SYSTEM_FLAGS(msgno);

    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
	if ((userflag & 31) == 0) {
	    flagmask = USER_FLAGS(msgno,userflag/32);
	}
	if (!mailbox->flagname[userflag] && (flagmask & (1<<(userflag&31)))) {
	    mailbox_read_header(mailbox);
	    index_listflags(mailbox);
	    break;
	}
    }

    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
	if ((userflag & 31) == 0) {
	    flagmask = USER_FLAGS(msgno,userflag/32);
	}
	if (mailbox->flagname[userflag] && (flagmask & (1<<(userflag&31)))) {
	    copyargs->copymsg[copyargs->nummsg].flag[flag++] =
	      mailbox->flagname[userflag];
	}
    }
    copyargs->copymsg[copyargs->nummsg].flag[flag] = 0;

    copyargs->nummsg++;

    return 0;
}

/*
 * Creates a list of msgdata.
 *
 * We fill these structs with the processed info that will be needed
 * by the specified sort criteria.
 */
#define ANNOTGROWSIZE	10

static MsgData *index_msgdata_load(unsigned *msgno_list, int n,
				   struct sortcrit *sortcrit)
{
    MsgData *md, *cur;
    cacherecord crec;
    int i, j;
    char *tmpenv;
    char *envtokens[NUMENVTOKENS];
    int did_cache, did_env;
    int label;
    int annotsize;

    if (!n)
	return NULL;

    /* create an array of MsgData to use as nodes of linked list */
    md = (MsgData *) xmalloc(n * sizeof(MsgData));
    memset(md, 0, n * sizeof(MsgData));

    for (i = 0, cur = md; i < n; i++, cur = cur->next) {
	/* set msgno */
	cur->msgno = msgno_list[i];

	/* set pointer to next node */
	cur->next = (i+1 < n ? cur+1 : NULL);

	did_cache = did_env = 0;
	tmpenv = NULL;
	annotsize = 0;

	for (j = 0; sortcrit[j].key; j++) {
	    label = sortcrit[j].key;

	    if ((label == SORT_CC || label == SORT_DATE ||
		 label == SORT_FROM || label == SORT_SUBJECT ||
		 label == SORT_TO || label == LOAD_IDS) &&
		!did_cache) {

		/* fetch cached info */
		if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(cur->msgno), &crec))
		    continue; /* can't do this with a broken cache */
		
		did_cache++;
	    }

	    if ((label == SORT_DATE || label == LOAD_IDS) &&
		!did_env) {

		/* make a working copy of envelope -- strip outer ()'s */
		/* +1 -> skip the leading paren */
		/* -2 -> don't include the size of the outer parens */
		tmpenv = xstrndup(crec[CACHE_ENVELOPE].s + 1, 
				  crec[CACHE_ENVELOPE].l - 2);

		/* parse envelope into tokens */
		parse_cached_envelope(tmpenv, envtokens,
				      VECTOR_SIZE(envtokens));

		did_env++;
	    }

	    switch (label) {
	    case SORT_CC:
		cur->cc = get_localpart_addr(crec[CACHE_CC].s);
		break;
	    case SORT_DATE:
		cur->date = message_parse_date(envtokens[ENV_DATE],
					       PARSE_TIME | PARSE_ZONE
					       | PARSE_NOCREATE);
		break;
	    case SORT_FROM:
		cur->from = get_localpart_addr(crec[CACHE_FROM].s);
		break;
	    case SORT_SUBJECT:
		cur->xsubj = index_extract_subject(crec[CACHE_SUBJECT].s,
						   crec[CACHE_SUBJECT].l,
						   &cur->is_refwd);
		cur->xsubj_hash = strhash(cur->xsubj);
		break;
	    case SORT_TO:
		cur->to = get_localpart_addr(crec[CACHE_TO].s);
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
		index_get_ids(cur, envtokens, crec[CACHE_HEADERS].s, 
					      crec[CACHE_HEADERS].l);
		break;
	    }
	}

	if (tmpenv) free(tmpenv);
    }

    return md;
}

/*
 * Parse a cached envelope into individual tokens
 *
 * When inside a list (ncom > 0), we parse the individual tokens but don't
 * isolate them -- we return the entire list as a single token.
 */
static void parse_cached_envelope(char *env, char *tokens[], int tokens_size)
{
    char *c;
    int i = 0, ncom = 0, len;

    c = env;
    while (*c != '\0') {
	switch (*c) {
	case ' ':			/* end of token */
	    if (!ncom) *c = '\0';	/* mark end of token */
	    c++;
	    break;
	case 'N':			/* "NIL" */
	case 'n':
	    if (!ncom) {
		if(i>=tokens_size) break;
		tokens[i++] = NULL;	/* empty token */
	    }
	    c += 3;			/* skip "NIL" */
	    break;
	case '"':			/* quoted string */
	    c++;			/* skip open quote */
	    if (!ncom) {
		if(i>=tokens_size) break;
		tokens[i++] = c;	/* start of string */
	    }
	    while (*c != '"') {		/* find close quote */
		if (*c == '\0') {
		    /* Oops, bad string. */
		    fatal("Quoted string w/o end quote in parse_cached_envelope",
			  EC_SOFTWARE);
		}
		if (*c == '\\') c++;	/* skip quoted-specials */
		c++;
	    }
	    if (!ncom) *c = '\0';	/* end of string */
	    c++;			/* skip close quote */
	    break;
	case '{':			/* literal */
	    c++;			/* skip open brace */
	    len = 0;			/* determine length of literal */
	    while (cyrus_isdigit((int) *c)) {
		len = len*10 + *c - '0';
		c++;
	    }
	    c += 3;			/* skip close brace & CRLF */
	    if (!ncom){
		if(i>=tokens_size) break;
		tokens[i++] = c;	/* start of literal */
	    }
	    c += len;			/* skip literal */
	    break;
	case '(':			/* start of address */
	    c++;			/* skip open paren */
	    if (!ncom) {
		if(i>=tokens_size) break;
		tokens[i++] = c;	/* start of address list */
	    }
	    ncom++;			/* new open - inc counter */
	    break;
	case ')':			/* end of address */
	    c++;			/* skip close paren */
	    if (ncom) {			/* paranoia */
		ncom--;			/* close - dec counter */
		if (!ncom)		/* all open paren are closed */
		    *(c-1) = '\0';	/* end of list - trim close paren */
	    }
	    break;
	default:
	    /* yikes! unparsed junk, just skip it */
	    c++;
	    break;
	}
    }
}

/*
 * Get the 'local-part' of an address from a header
 */
static char *get_localpart_addr(const char *header)
{
    struct address *addr = NULL;
    char *ret;

    parseaddr_list(header, &addr);
    ret = xstrdup(addr && addr->mailbox ? addr->mailbox : "");
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
	else	/* otherwise, we're done */
	    break;
    }

    base = xstrdup(base);

    free(buf);

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
	    ret = numcmp(INTERNALDATE(md1->msgno), INTERNALDATE(md2->msgno));
	    break;
	case SORT_CC:
	    ret = strcmp(md1->cc, md2->cc);
	    break;
	case SORT_DATE: {
	    time_t d1 = md1->date ? md1->date : (time_t) INTERNALDATE(md1->msgno);
	    time_t d2 = md2->date ? md2->date : (time_t) INTERNALDATE(md2->msgno);
	    ret = numcmp(d1, d2);
	    break;
	}
	case SORT_FROM:
	    ret = strcmp(md1->from, md2->from);
	    break;
	case SORT_SIZE:
	    ret = numcmp(SIZE(md1->msgno), SIZE(md2->msgno));
	    break;
	case SORT_SUBJECT:
	    ret = strcmp(md1->xsubj, md2->xsubj);
	    break;
	case SORT_TO:
	    ret = strcmp(md1->to, md2->to);
	    break;
	case SORT_ANNOTATION:
	    ret = strcmp(md1->annot[ann], md2->annot[ann]);
	    ann++;
	    break;
	case SORT_MODSEQ:
	    ret = numcmp(MODSEQ(md1->msgno), MODSEQ(md2->msgno));
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
static void index_thread_orderedsubj(unsigned *msgno_list, int nmsg,
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
    freeme = msgdata = index_msgdata_load(msgno_list, nmsg, sortcrit);

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
    index_thread_print(head, usinguid);

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
static void _index_thread_print(Thread *thread, int usinguid)
{
    Thread *child;

    /* for each thread... */
    while (thread) {
	/* start the thread */
	prot_printf(imapd_out, "(");

	/* if we have a message, print its identifier
	 * (do nothing for empty containers)
	 */
	if (thread->msgdata) {
	    prot_printf(imapd_out, "%u",
			usinguid ? UID(thread->msgdata->msgno) :
			thread->msgdata->msgno);

	    /* if we have a child, print the parent-child separator */
	    if (thread->child) prot_printf(imapd_out, " ");

	    /* free contents of the current node */
	    index_msgdata_free(thread->msgdata);
	}

	/* for each child, grandchild, etc... */
	child = thread->child;
	while (child) {
	    /* if the child has siblings, print new branch and break */
	    if (child->next) {
		_index_thread_print(child, usinguid);
		break;
	    }
	    /* otherwise print the only child */
	    else {
		prot_printf(imapd_out, "%u",
			    usinguid ? UID(child->msgdata->msgno) :
			    child->msgdata->msgno);

		/* if we have a child, print the parent-child separator */
		if (child->child) prot_printf(imapd_out, " ");

		/* free contents of the child node */
		index_msgdata_free(child->msgdata);

		child = child->child;
	    }
	}

	/* end the thread */
	prot_printf(imapd_out, ")");

	thread = thread->next;
    }
}

/*
 * Print a list of threads.
 *
 * This is a wrapper around _index_thread_print() which simply prints the
 * start and end of the untagged thread response.
 */
static void index_thread_print(Thread *thread, int usinguid)
{
    prot_printf(imapd_out, "* THREAD");

    if (thread) {
	prot_printf(imapd_out, " ");
	_index_thread_print(thread->child, usinguid);
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
static void ref_gather_orphans(char *key __attribute__((unused)),
			       Thread *node,
			       struct rootset *rootset)
{
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
	else if (cur->child)
	    ref_prune_tree(cur);
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
	if (old == cur) continue;

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
static int _index_thread_search(Thread *thread, int (*searchproc) (MsgData *))
{
    Thread *child;

    /* test the head node */
    if (thread->msgdata && searchproc(thread->msgdata)) return 1;

    /* test the children recursively */
    child = thread->child;
    while (child) {
	if (_index_thread_search(child, searchproc)) return 1;
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
static void index_thread_search(Thread *root, int (*searchproc) (MsgData *))
{
    Thread *cur, *prev, *next;

    for (prev = NULL, cur = root->child, next = cur->next;
	 cur;
	 prev = cur, cur= next, next = (cur ? cur->next : NULL)) {
	if (!_index_thread_search(cur, searchproc)) {
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
static void _index_thread_ref(unsigned *msgno_list, int nmsg,
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
    freeme = msgdata = index_msgdata_load(msgno_list, nmsg, loadcrit);

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
    hash_enumerate(&id_table, (void (*)(char*,void*,void*)) ref_gather_orphans,
		   &rootset);

    /* discard id_table */
    free_hash_table(&id_table, NULL);

    /* Step 3: prune tree of empty containers - get our deposit back :^) */
    ref_prune_tree(rootset.root);

    /* Step 4: sort the root set */
    ref_sort_root(rootset.root);

    /* Step 5: group root set by subject */
    ref_group_subjects(rootset.root, rootset.nroot, &newnode);

    /* Optionally search threads (to be used by REFERENCES derivatives) */
    if (searchproc) index_thread_search(rootset.root, searchproc);

    /* Step 6: sort threads */
    if (sortcrit) index_thread_sort(rootset.root, sortcrit);

    /* Output the threaded messages */ 
    index_thread_print(rootset.root, usinguid);

    /* free the thread array */
    free(rootset.root);

    /* free the msgdata array */
    free(freeme);
}

/*
 * Thread a list of messages using the REFERENCES algorithm.
 */
static void index_thread_ref(unsigned *msgno_list, int nmsg, int usinguid)
{
    struct sortcrit loadcrit[] = {{ LOAD_IDS,      0, {{NULL,NULL}} },
				  { SORT_SUBJECT,  0, {{NULL,NULL}} },
				  { SORT_DATE,     0, {{NULL,NULL}} },
				  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};
    struct sortcrit sortcrit[] = {{ SORT_DATE,     0, {{NULL,NULL}} },
				  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};

    _index_thread_ref(msgno_list, nmsg, loadcrit, NULL, sortcrit, usinguid);
}

/*
 * NNTP specific stuff.
 */
char *index_get_msgid(struct mailbox *mailbox __attribute__((unused)),
		      unsigned msgno)
{
    cacherecord crec;
    char *env;
    char *envtokens[NUMENVTOKENS];
    char *msgid;

    if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
	return NULL;

    /* get msgid out of the envelope
     *
     * get a working copy; strip outer ()'s
     * +1 -> skip the leading paren
     * -2 -> don't include the size of the outer parens
     */
    env = xstrndup(crec[CACHE_ENVELOPE].s + 1, crec[CACHE_ENVELOPE].l - 2);
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

extern struct nntp_overview *index_overview(struct mailbox *mailbox,
					    unsigned msgno)
{
    static struct nntp_overview over;
    static char *env = NULL, *from = NULL, *hdr = NULL;
    static int envsize = 0, fromsize = 0, hdrsize = 0;
    cacherecord crec;
    int size;
    char *envtokens[NUMENVTOKENS];
    struct address addr = { NULL, NULL, NULL, NULL, NULL, NULL };
    static struct strlist refhdr;

    if (!cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec))
	return NULL; /* upper layers can cope! */

    /* make a working copy of envelope; strip outer ()'s */
    /* -2 -> don't include the size of the outer parens */
    /* +1 -> leave space for NUL */
    size = crec[CACHE_ENVELOPE].l - 2 + 1;
    if (envsize < size) {
	envsize = size;
	env = xrealloc(env, envsize);
    }
    /* +1 -> skip the leading paren */
    strlcpy(env, crec[CACHE_ENVELOPE].s + 1, size);

    /* make a working copy of headers */
    size = crec[CACHE_HEADERS].l;
    if (hdrsize < size+2) {
	hdrsize = size+100;
	hdr = xrealloc(hdr, hdrsize);
    }
    memcpy(hdr, crec[CACHE_HEADERS].s, size);
    hdr[size] = '\0';

    parse_cached_envelope(env, envtokens, VECTOR_SIZE(envtokens));

    over.uid = UID(msgno);
    over.bytes = SIZE(msgno);
    over.lines = index_getlines(mailbox, msgno);
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
    else
	over.from = NULL;

    /* massage references */
    refhdr.s = "references";
    index_pruneheader(hdr, &refhdr, 0);
    if (*hdr) {
	over.ref = hdr + 11; /* skip over header name */
	massage_header(over.ref);
    }

    return &over;
}

extern char *index_getheader(struct mailbox *mailbox, unsigned msgno,
			     char *hdr)
{
    static const char *msg_base = 0;
    static unsigned long msg_size = 0;
    struct strlist headers = { NULL, NULL, NULL, NULL };
    static char *alloc = NULL;
    static unsigned allocsize = 0;
    cacherecord crec;
    unsigned size;
    char *buf;

    headers.s = hdr;

    if (msg_base) {
	mailbox_unmap_message(NULL, 0, &msg_base, &msg_size);
	msg_base = 0;
	msg_size = 0;
    }

    /* see if the header is cached */
    if (mailbox_cached_header(hdr) != BIT32_MAX &&
        cache_parserecord(cache_base, cache_end, CACHE_OFFSET(msgno), &crec)) {
    
	size = crec[CACHE_HEADERS].l;
	if (allocsize < size+2) {
	    allocsize = size+100;
	    alloc = xrealloc(alloc, allocsize);
	}

	memcpy(alloc, crec[CACHE_HEADERS].s, size);
	alloc[size] = '\0';

	buf = alloc;
    }
    else {
	/* uncached header */
	if (mailbox_map_message(mailbox, UID(msgno), &msg_base, &msg_size))
	    return NULL;

	buf = index_readheader(msg_base, msg_size, mailbox->format, 0,
			       HEADER_SIZE(msgno));
    }

    index_pruneheader(buf, &headers, NULL);

    if (*buf) {
	buf += strlen(hdr) + 1; /* skip header: */
	massage_header(buf);
    }

    return buf;
}

extern unsigned long index_getsize(struct mailbox *mailbox __attribute__((unused)),
				   unsigned msgno)
{
    return SIZE(msgno);
}

extern unsigned long index_getlines(struct mailbox *mailbox, unsigned msgno)
{
    unsigned long lines = CONTENT_LINES(msgno);

    if (lines == BIT32_MAX) {
	int r;
	char fname[MAX_MAILBOX_PATH+1];
	FILE *msgfile;
	char buf[4096];
	struct index_record record;

	lines = 0;

	r = mailbox_lock_index(mailbox);
	if (r) return lines;

	/* get the existing record */
	r = mailbox_read_index_record(mailbox, msgno, &record);
	if (r) goto done;

	/* Open the message file */
	strlcpy(fname, mailbox->path, sizeof(fname));
	strlcat(fname, "/", sizeof(fname));
	mailbox_message_get_fname(mailbox, record.uid,
				  fname + strlen(fname),
				  sizeof(fname) - strlen(fname));

	msgfile = fopen(fname, "r");
	if (!msgfile) goto done;

	/* Find start of body */
	while (fgets(buf, sizeof(buf), msgfile)) {
	    if (buf[0] == '\r' && buf[1] == '\n') {
		/* blank line between header and body */
		break;
	    }
	}

	/* Count the number of lines in the message body */
	while (fgets(buf, sizeof(buf), msgfile)) {
	    while (buf[strlen(buf)-1] != '\n' &&
		   fgets(buf, sizeof(buf), msgfile));
	    lines++;
	}
	fclose(msgfile);

	/* Update the index record */
	record.content_lines = lines;
	record.last_updated = time(0);

	r = mailbox_write_index_record(mailbox, msgno, &record, 1);

      done:
	mailbox_unlock_index(mailbox);
    }

    return lines;
}

#define MAX(x, y) (x > y ? x : y)

/* Comparator function that sorts ranges by the low value,
   and coalesces intersecting ranges to have the same high value */
static int comp_coalesce(const void *v1, const void *v2)
{
    struct seq_range *r1 = (struct seq_range *) v1;
    struct seq_range *r2 = (struct seq_range *) v2;

    /* If ranges don't intersect, we're done */
    if (r1->high < r2->low) return -1;
    if (r1->low > r2->high) return 1;

    /* Ranges intersect, coalesce them */
    r1->high = r2->high = MAX(r1->high, r2->high);

    return r1->low - r2->low;;
}

#define SETGROWSIZE 100

/*
 * Parse a sequence into an array of sorted & merged ranges.
 */
struct seq_set *index_parse_sequence(const char *sequence, int usinguid,
				     struct seq_set *set)
{
    unsigned i, j, start, end, *num;

    if (!set) set = xzmalloc(sizeof(struct seq_set));

    start = end = 0;
    num = &start;
    for (;;) {
	if (cyrus_isdigit((int) *sequence)) {
	    *num = (*num)*10 + *sequence - '0';
	}
	else if (*sequence == '*') {
	    *num = usinguid ? UID(imapd_exists) : (unsigned) imapd_exists;
	}
	else if (*sequence == ':') {
	    num = &end;
	}
	else {
	    if (!end) end = start;
	    else if (start > end) {
		i = end;
		end = start;
		start = i;
	    }

	    if (set->len == set->alloc) {
		set->alloc += SETGROWSIZE;
		set->set =
		    xrealloc(set->set, set->alloc * sizeof(struct seq_range));
	    }
	    set->set[set->len].low = start;
	    set->set[set->len].high = end;
	    set->len++;

	    start = end = 0;
	    num = &start;

	    if (!*sequence) break;
	}
	sequence++;
    }

    /* Sort the ranges using our special comparator */
    qsort(set->set, set->len, sizeof(struct seq_range), comp_coalesce);

    /* Merge intersecting/adjacent ranges */
    for (i = 0, j = 1; j < set->len; j++) {
	if ((int)(set->set[j].low - set->set[i].high) <= 1) {
	    set->set[i].high = set->set[j].high;
	} else {
	    i++;
	    set->set[i].low = set->set[j].low;
	    set->set[i].high = set->set[j].high;
	}
    }
    set->len = i+1;

    return set;
}

/* Comparator function that checks if r1 is a subset of r2 */
static int comp_subset(const void *v1, const void *v2)
{
    struct seq_range *r1 = (struct seq_range *) v1;
    struct seq_range *r2 = (struct seq_range *) v2;

    if (r1->low < r2->low) return -1;
    if (r1->high > r2->high) return 1;
    return 0;
}

/*
 * Return nonzero iff 'num' is included in 'sequence'
 */
static int index_insequence(unsigned num, struct seq_set *set, int use_mark)
{
    if (!use_mark) set->mark = 0;

    /* Short circuit if we're outside all ranges */
    if ((num < set->set[set->mark].low) || (num > set->set[set->len-1].high)) {
	return 0;
    }
    else {
	/* Otherwise create a dummy range from our data point,
	   and see if it intersects with our set */
	struct seq_range key = { num, num };
	struct seq_range *found = bsearch(&key, set->set + set->mark,
					  set->len - set->mark,
					  sizeof(struct seq_range),
					  comp_subset);

	if (found) {
	    /* Set the mark to the index of the inclusive range */
	    set->mark = found - set->set;
	    return 1;
	}

	return 0;
    }
}

void appendsequencelist(struct seq_set **l, char *sequence, int usinguid)
{
    struct seq_set **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = index_parse_sequence(sequence, usinguid, NULL);
}

void freesequencelist(struct seq_set *l)
{
    struct seq_set *n;

    while(l) {
	n = l->next;
	free(l->set);
	free(l);
	l = n;
    }
}
