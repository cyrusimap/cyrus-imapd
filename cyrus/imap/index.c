/* index.c -- Routines for dealing with the index file in the imapd
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */
/*
 * $Id: index.c,v 1.118 2000/06/09 02:44:44 leg Exp $
 */
#include <config.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <ctype.h>

#include "acl.h"
#include "util.h"
#include "map.h"
#include "assert.h"
#include "exitcodes.h"
#include "gmtoff.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
#include "append.h"
#include "charset.h"
#include "xmalloc.h"
#include "seen.h"
#include "lsort.h"
#include "message.h"
#include "parseaddr.h"

extern int errno;

extern void printastring (const char *s);

/* The index and cache files, mapped into memory */
static const char *index_base;
static unsigned long index_len;
static const char *cache_base;
static unsigned long cache_len;
static unsigned long cache_end;

/* Attributes of memory-mapped index file */
static long index_ino;
static unsigned long start_offset;
static unsigned long record_size;

static unsigned recentuid;	/* UID of last non-\Recent message */
static unsigned lastnotrecent;	/* Msgno of last non-\Recent message */

static time_t *flagreport;	/* Array for each msgno of last_updated when
				 * FLAGS data reported to client.
				 * Zero if FLAGS data never reported */
static char *seenflag;		/* Array for each msgno, nonzero if \Seen */
static time_t seen_last_change;	/* Last mod time of \Seen state change */
static int flagalloced = -1;	/* Allocated size of above two arrays */
static int examining;		/* Nonzero if opened with EXAMINE command */
static int keepingseen;		/* Nonzero if /Seen is meaningful */
static unsigned allseen;	/* Last UID if all msgs /Seen last checkpoint */
struct seen *seendb;		/* Seen state database object */
static char *seenuids;		/* Sequence of UID's from last seen checkpoint */

/* Access macros for the memory-mapped index file data */
#define INDEC_OFFSET(msgno) (index_base+start_offset+(((msgno)-1)*record_size))
#define UID(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_UID)))
#define INTERNALDATE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_INTERNALDATE)))
#define SENTDATE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_SENTDATE)))
#define SIZE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_SIZE)))
#define HEADER_SIZE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_HEADER_SIZE)))
#define CONTENT_OFFSET(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_CONTENT_OFFSET)))
#define CACHE_OFFSET(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_CACHE_OFFSET)))
#define LAST_UPDATED(msgno) ((time_t)ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_LAST_UPDATED))))
#define SYSTEM_FLAGS(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_SYSTEM_FLAGS)))
#define USER_FLAGS(msgno,i) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_USER_FLAGS+((i)*4))))

/* Access assistance macros for memory-mapped cache file data */
#define CACHE_ITEM_BIT32(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_LEN(ptr) CACHE_ITEM_BIT32(ptr)
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

struct copyargs {
    struct copymsg *copymsg;
    int nummsg;
    int msgalloc;
};

struct mapfile {
    const char *base;
    unsigned long size;
};

struct msgdata {
    unsigned msgno;		/* message number */
    unsigned msgid;		/* hash of message ID */
    unsigned *ref;		/* hash of references */
    time_t arrival;		/* internal arrival date & time of message */
    time_t date;		/* sent date & time of message
				   from Date: header (adjusted by time zone) */
    char *cc;			/* local-part of first "cc" address */
    char *from;			/* local-part of first "from" address */
    char *to;			/* local-part of first "to" address */
    char *xsubj;		/* extracted subject text */
    unsigned xsubj_hash;	/* hash of extracted subject text */
    unsigned size;		/* size of message */
    struct msgdata *next;
};

struct thread {
    struct msgdata *msgdata;	/* message data */
    struct thread *parent;	/* parent message */
    struct thread *child;	/* first child message */
    struct thread *next;	/* next sibling message */
};

struct thread_algorithm {
    char *alg_name;
    struct thread *(*threader)(unsigned *msgno_list, int nmsg);
};

/* Forward declarations */
typedef int index_sequenceproc_t P((struct mailbox *mailbox, unsigned msgno,
				    void *rock));

static int index_forsequence(struct mailbox *mailbox, char *sequence,
			     int usinguid,
			     index_sequenceproc_t *proc, void *rock,
			     int* fetchedsomething);
static int index_insequence P((int num, char *sequence, int usinguid));

static void index_fetchmsg P((const char *msg_base, unsigned long msg_size,
			      int format, unsigned offset, unsigned size,
			      unsigned start_octet, unsigned octet_count));
static void index_fetchsection P((const char *msg_base, unsigned long msg_size,
				  int format, char *section,
				  const char *cacheitem, unsigned size,
				  unsigned start_octet, unsigned octet_count));
static void index_fetchfsection P((const char *msg_base,
				   unsigned long msg_size,
				   int format, struct fieldlist *fsection,
				   const char *cacheitem));
static char *index_readheader P((const char *msg_base, unsigned long msg_size,
				 int format, unsigned offset, unsigned size));
static void index_pruneheader P((char *buf, struct strlist *headers,
				 struct strlist *headers_not));
static void index_fetchheader P((const char *msg_base, unsigned long msg_size,
				 int format, unsigned size,
				 struct strlist *headers,
				 struct strlist *headers_not));
static void index_fetchcacheheader P((unsigned msgno, struct strlist *headers,
				      char *trail));
static void index_listflags P((struct mailbox *mailbox));
static void index_fetchflags P((struct mailbox *mailbox, unsigned msgno,
				bit32 system_flags, bit32 *user_flags,
				time_t last_updated));
static index_sequenceproc_t index_fetchreply;
static index_sequenceproc_t index_storeseen;
static index_sequenceproc_t index_storeflag;
static int index_search_evaluate P((struct mailbox *mailbox,
				    struct searchargs *searchargs,
				    unsigned msgno, struct mapfile *msgfile));
static int index_searchmsg P((char *substr, comp_pat *pat,
			      struct mapfile *msgfile, int format,
			      int skipheader, const char *cacheitem));
static int index_searchheader P((char *name, char *substr, comp_pat *pat,
				 struct mapfile *msgfile, int format,
				 int size));
static int index_searchcacheheader P((unsigned msgno, char *name, char *substr,
				      comp_pat *pat));
static index_sequenceproc_t index_copysetup;
static int _index_search P((unsigned **msgno_list, struct mailbox *mailbox,
			    struct searchargs *searchargs));

static char *index_extract_subject(const char *subj);
static struct msgdata *index_msgdata_load P((unsigned *msgno_list, int n,
					     signed char *sortcrit));

static void *index_sort_getnext P((struct msgdata *node));
static void index_sort_setnext P((struct msgdata *node, struct msgdata *next));
static int index_sort_compare P((struct msgdata *md1, struct msgdata *md2,
				 signed char *call_data));
static void index_sort_free P((struct msgdata *list));

static void *index_thread_getnext P((struct thread *thread));
static void index_thread_setnext P((struct thread *thread,
				    struct thread *next));
static int index_thread_compare P((struct thread *t1, struct thread *t2,
				   signed char *call_data));
static struct thread *index_thread_orderedsubj P((unsigned *msgno_list,
						  int nmsg));
static void index_thread_print P((struct thread *threads, int usinguid));
static void index_thread_free P((struct thread *threads));

static struct thread_algorithm thread_algs[] = {
    { "ORDEREDSUBJECT", index_thread_orderedsubj },
    { NULL, NULL }
};

/*
 * A mailbox is about to be closed.
 */
void
index_closemailbox(mailbox)
struct mailbox *mailbox;
{
    if (seendb) {
	index_checkseen(mailbox, 1, 0, imapd_exists);
	seen_close(seendb);
	seendb = 0;
    }
    if (index_len) {
	map_free(&index_base, &index_len);
	map_free(&cache_base, &cache_len);
	index_len = cache_end = 0;
    }
}

/*
 * A new mailbox has been selected, map it into memory and do the
 * initial CHECK.
 */
void
index_newmailbox(mailbox, examine_mode)
struct mailbox *mailbox;
int examine_mode;
{
    keepingseen = (mailbox->myrights & ACL_SEEN);
    examining = examine_mode;
    allseen = 0;
    recentuid = 0;
    index_listflags(mailbox);
    imapd_exists = -1;
    index_check(mailbox, 0, 1);
}

#define SLOP 50

/*
 * Check for and report updates
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
	if (stat(FNAME_INDEX+1, &sbuf) != 0) {
	    if (errno == ENOENT) {
		/* Mailbox has been deleted */
		while (imapd_exists--) {
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
	else if (sbuf.st_ino != mailbox->index_ino) {
	    if (mailbox_open_index(mailbox)) {
		fatal("failed to reopen index file", EC_IOERR);
	    }

	    for (oldmsgno = msgno = 1; oldmsgno <= imapd_exists;
		 oldmsgno++, msgno++) {
		if (msgno <= mailbox->exists) {
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

	    /* Force re-map of index/cache files */
	    map_free(&index_base, &index_len);
	    map_free(&cache_base, &cache_len);
	    cache_end = 0;

	    /* Force a * n EXISTS message */
	    imapd_exists = -1;
	}
	else if (sbuf.st_mtime != mailbox->index_mtime) {
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
    if (fstat(mailbox->cache_fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: stating cache file for %s: %m",
	       mailbox->name);
	fatal("failed to stat cache file", EC_IOERR);
    }
    if (cache_end < sbuf.st_size) {
	cache_end = sbuf.st_size;
	map_refresh(mailbox->cache_fd, 0, &cache_base, &cache_len,
		    cache_end, "cache", mailbox->name);
    }

    /* If opening mailbox, get \Recent info */
    if (oldexists == -1 && keepingseen) {
	r = seen_open(mailbox, imapd_userid, &seendb);
	if (!r) {
	    free(seenuids);
	    r = seen_lockread(seendb, &last_read, &recentuid,
			      &seen_last_change, &seenuids);
	    if (r) seen_close(seendb);
	}
	if (r) {
	    seendb = 0;
	    prot_printf(imapd_out, "* OK %s: %s\r\n",
		   error_message(IMAP_NO_CHECKPRESERVE), error_message(r));
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
	lastnotrecent = index_finduid(recentuid);
	imapd_exists = -1;
    }
    
    /* If EXISTS changed, report it */
    if (newexists != imapd_exists) {
	/* Re-size flagreport and seenflag arrays if necessary */
	if (newexists > flagalloced) {
	    flagalloced = newexists + SLOP;
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
    if (checkseen) index_checkseen(mailbox, 0, usinguid, oldexists);
    else if (oldexists == -1) seen_unlock(seendb);
    for (i = 1; i <= imapd_exists && seenflag[i]; i++);
    if (i == imapd_exists + 1) allseen = mailbox->last_uid;
    if (oldexists == -1) {
	if (imapd_exists && i <= imapd_exists) {
	    prot_printf(imapd_out, "* OK [UNSEEN %u]  \r\n", i);
	}
        prot_printf(imapd_out, "* OK [UIDVALIDITY %u]  \r\n",
		    mailbox->uidvalidity);
	prot_printf(imapd_out, "* OK [UIDNEXT %u]  \r\n",
		    mailbox->last_uid + 1);
    }

    for (msgno = 1; msgno <= oldexists; msgno++) {
	if (flagreport[msgno] < LAST_UPDATED(msgno)) {
	    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
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
    unsigned msgno, uid, dirty = 0;
    int i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    char *saveseenuids, *save;
    int savealloced;
    unsigned start, newallseen, inrange, usecomma;

    if (!keepingseen || !seendb) return;
    if (imapd_exists == 0) {
	seen_unlock(seendb);
	return;
    }

    /* Lock \Seen database and read current values */
    r = seen_lockread(seendb, &last_read, &last_uid, &seen_last_change,
		      &newseenuids);
    if (r) {
	prot_printf(imapd_out, "* OK %s: %s\r\n",
	       error_message(IMAP_NO_CHECKSEEN), error_message(r));
	return;
    }

    /*
     * Propagate changes in the database to the seenflag[] array
     * and possibly to the client.
     */
    old = seenuids;
    new = newseenuids;
    while (isdigit((int) *old)) oldnext = oldnext * 10 + *old++ - '0';
    while (isdigit((int) *new)) newnext = newnext * 10 + *new++ - '0';

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
		if (!*old) oldnext = mailbox->last_uid+1;
		else old++;
		while (isdigit((int) *old)) {
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
		    neweof++;
		}
		else new++;
		while (isdigit((int) *new)) {
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
		    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
			user_flags[i] = USER_FLAGS(msgno, i);
		    }
		    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), 
				     user_flags, LAST_UPDATED(msgno));
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
    }

    if (!examining && oldexists != imapd_exists) {
	/* If just did a SELECT, record time of our reading the mailbox */
	if (oldexists == -1) last_read = time((time_t *)0);

	/* Update the \Recent high-water mark */
	last_uid = mailbox->last_uid;
	dirty++;
    }

    /* If there's nothing to save back to the database, clean up and return */
    if (!dirty) {
	seen_unlock(seendb);
	free(seenuids);
	seenuids = newseenuids;
	/* We might have deleted our last unseen message */
	if (!allseen) {
	    for (msgno = 1; msgno <= imapd_exists; msgno++) {
		if (!seenflag[msgno]) break;
	    }
#if TOIMSP
	    if (msgno == imapd_exists + 1) {
		toimsp(mailbox->name, mailbox->uidvalidity,
		       "SEENsnn", imapd_userid, mailbox->last_uid,
		       seen_last_change, 0);
	    }
#endif
	}
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
	if (save - saveseenuids > savealloced - 30) {
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
	    while (isdigit((int) *new)) newnext = newnext * 10 + *new++ - '0';
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
		while (isdigit((int) *new)) newnext = newnext * 10 + *new++ - '0';
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
    seen_unlock(seendb);
    free(seenuids);
    if (r) {
	prot_printf(imapd_out, "* OK %s: %s\r\n",
	       error_message(IMAP_NO_CHECKSEEN), error_message(r));
	free(saveseenuids);
	seenuids = newseenuids;
	return;
    }

#if TOIMSP
    if (newallseen) {
	toimsp(mailbox->name, mailbox->uidvalidity, "SEENsnn", imapd_userid,
	       mailbox->last_uid, seen_last_change, 0);
    }
    else if (allseen == mailbox->last_uid) {
	toimsp(mailbox->name, mailbox->uidvalidity, "SEENsnn", imapd_userid,
	       0, seen_last_change, 0);
    }
#endif    

    free(newseenuids);
    seenuids = saveseenuids;
}


/*
 * Perform a FETCH-related command on a sequence.
 * Fetchedsomething argument is 0 if nothing was fetched, 1 if something was
 * fetched.  (A fetch command that fetches nothing is not a valid fetch
 * command.)
 */
void
index_fetch(struct mailbox* mailbox,
	    char* sequence,
	    int usinguid,
	    struct fetchargs* fetchargs,
	    int* fetchedsomething)
{
    *fetchedsomething = 0;
    index_forsequence(mailbox, sequence, usinguid,
		      index_fetchreply, (char *)fetchargs, fetchedsomething);
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
    int i, r, userflag, emptyflag;
    int writeheader = 0;
    int newflag[MAX_USER_FLAGS];
    long myrights = mailbox->myrights;

    /* Handle simple case of just changing /Seen */
    if (storeargs->operation != STORE_REPLACE &&
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
	 !(myrights & ACL_DELETE)) ||
	(((storeargs->system_flags & ~FLAG_DELETED) || nflags) &&
	 !(myrights & ACL_WRITE))) {
	mailbox->myrights = myrights;
	return IMAP_PERMISSION_DENIED;
    }

    /* Check to see if we have to add new user flags */
    for (userflag=0; userflag < MAX_USER_FLAGS; userflag++)
      newflag[userflag] = 0;
    for (i=0; i < nflags; i++) {
	emptyflag = -1;
	for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
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
	for (userflag=0; userflag < MAX_USER_FLAGS; userflag++)
	  newflag[userflag] = 0;
	for (i=0; i < nflags; i++) {
	    emptyflag = -1;
	    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
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
		    for (userflag=0; userflag < MAX_USER_FLAGS; userflag++) {
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
	for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
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


    if (mailbox->dirty==1)
    {
	/* xxx what to do on failure? */
	mailbox_write_index_header(mailbox);
	mailbox->dirty = 0;
    }

    mailbox_unlock_index(mailbox);

    /* Refresh the index file, for systems without mmap() */
    map_refresh(mailbox->index_fd, 0, &index_base, &index_len,
		start_offset + imapd_exists * record_size,
		"index", mailbox->name);

    return r;
}

/*
 * Guts of the SEARCH command.
 * 
 * Returns message numbers in an array.  This function is used by
 * SEARCH, SORT and THREAD.
 */
static int
_index_search(msgno_list, mailbox, searchargs)
unsigned **msgno_list;
struct mailbox *mailbox;
struct searchargs *searchargs;
{
    unsigned msgno;
    struct mapfile msgfile;
    int n = 0;

    *msgno_list = (unsigned *) xmalloc(imapd_exists * sizeof(unsigned));

    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	msgfile.base = 0;
	msgfile.size = 0;

	if (index_search_evaluate(mailbox, searchargs, msgno, &msgfile)) {
	    (*msgno_list)[n++] = msgno;
	}
	if (msgfile.base) {
	    mailbox_unmap_message(mailbox, UID(msgno),
				  &msgfile.base, &msgfile.size);
	}
    }
    return n;
}

/*
 * Performs a SEARCH command.
 * This is a wrapper around _index_search() which simply prints the results.
 */
void
index_search(mailbox, searchargs, usinguid)
struct mailbox *mailbox;
struct searchargs *searchargs;
int usinguid;
{
    unsigned *msgno_list;
    int i, n;

    n = _index_search(&msgno_list, mailbox, searchargs);

    prot_printf(imapd_out, "* SEARCH");

    for (i = 0; i < n; i++)
	prot_printf(imapd_out, " %u",
		    usinguid ? UID(msgno_list[i]) : msgno_list[i]);

    prot_printf(imapd_out, "\r\n");

    free(msgno_list);
}

/*
 * Performs a SORT command
 */
void
index_sort(struct mailbox *mailbox,
	   signed char *sortcrit,
	   struct searchargs *searchargs,
	   int usinguid)
{
    unsigned *msgno_list;
    struct msgdata *msgdata = NULL, *cur;
    int n;

    /* Search for messages based on the given criteria */
    n = _index_search(&msgno_list, mailbox, searchargs);

    if (n) {
	/* Create/load the msgdata array */
	msgdata = index_msgdata_load(msgno_list, n, sortcrit);
	free(msgno_list);
    }

    prot_printf(imapd_out, "* SORT");

    if (msgdata) {
	/* Sort the messages based on the given criteria */
	msgdata = lsort(msgdata,
			(void * (*)(void*)) index_sort_getnext,
			(void (*)(void*,void*)) index_sort_setnext,
			(int (*)(void*,void*,void*)) index_sort_compare,
			sortcrit);
	/* Output the sorted messages */ 
	cur = msgdata;
	while (cur) {
	    prot_printf(imapd_out, " %u",
			usinguid ? UID(cur->msgno) : cur->msgno);
	    cur = cur->next;
	}
	index_sort_free(msgdata);
    }

    prot_printf(imapd_out, "\r\n");
}

/*
 * Performs a THREAD command
 */
void index_thread(struct mailbox *mailbox, int algorithm,
		  struct searchargs *searchargs, int usinguid)
{
    struct thread *threads;
    unsigned *msgno_list;
    int nmsg;

    /* Search for messages based on the given criteria */
    nmsg = _index_search(&msgno_list, mailbox, searchargs);

    if (nmsg) {
	/* Thread messages using given algorithm. */
	threads = (*thread_algs[algorithm].threader)(msgno_list, nmsg);

	/* Output the threaded messages */ 
	prot_printf(imapd_out, "* THREAD ");

	index_thread_print(threads, usinguid);

	prot_printf(imapd_out, "\r\n");

	free(msgno_list);

	index_thread_free(threads);
    }
}

/*
 * Performs a COPY command
 */
int
index_copy(struct mailbox *mailbox, 
	   char *sequence, 
	   int usinguid,
	   char *name, 
	   char **copyuidp)
{
    static struct copyargs copyargs;
    int i;
    unsigned long totalsize = 0;
    int r;
    struct appendstate append_mailbox;
    char *copyuid;
    int copyuid_len, copyuid_size;
    int sepchar;
    unsigned long uidvalidity;
    unsigned long startuid, num;

    copyargs.nummsg = 0;
    index_forsequence(mailbox, sequence, usinguid, index_copysetup,
		      (char *)&copyargs, NULL);

    if (copyargs.nummsg == 0) {
	*copyuidp = 0;
	return 0;
    }

    for (i = 0; i < copyargs.nummsg; i++) {
	totalsize += copyargs.copymsg[i].size;
    }

    r = append_setup(&append_mailbox, name, MAILBOX_FORMAT_NORMAL,
		     imapd_authstate, ACL_INSERT, totalsize);
    if (r) return r;

    r = append_copy(mailbox, &append_mailbox, copyargs.nummsg,
		    copyargs.copymsg, imapd_userid);
    if (!r) append_commit(&append_mailbox, &uidvalidity, &startuid,
			  &num);
    if (!r) {
	copyuid_size = 1024;
	copyuid = xmalloc(copyuid_size);
	sprintf(copyuid, "%lu", uidvalidity);
	copyuid_len = strlen(copyuid);
	sepchar = ' ';

	for (i = 0; i < copyargs.nummsg; i++) {
	    if (copyuid_size < copyuid_len + 50) {
		copyuid_size += 1024;
		copyuid = xrealloc(copyuid, copyuid_size);
	    }
	    sprintf(copyuid+copyuid_len, "%c%lu", sepchar,
		    copyargs.copymsg[i].uid);
	    copyuid_len += strlen(copyuid+copyuid_len);
	    if (i+1 < copyargs.nummsg &&
		copyargs.copymsg[i+1].uid == copyargs.copymsg[i].uid + 1) {
		do {
		    i++;
		} while (i+1 < copyargs.nummsg &&
			 copyargs.copymsg[i+1].uid == copyargs.copymsg[i].uid + 1);
		sprintf(copyuid+copyuid_len, ":%lu",
			copyargs.copymsg[i].uid);
		copyuid_len += strlen(copyuid+copyuid_len);
	    }
	    sepchar = ',';
	}
	if (num == 1) {
	    sprintf(copyuid+copyuid_len, " %lu", startuid);
	} else {
	    sprintf(copyuid+copyuid_len, " %lu:%lu",
		    startuid, startuid + num - 1);
	}
	*copyuidp = copyuid;
    }

    return r;
}

/*
 * Performs a STATUS command
 */
int
index_status(mailbox, name, statusitems)
struct mailbox *mailbox;
char *name;
int statusitems;
{
    int r;
    struct seen *status_seendb;
    time_t last_read, last_change = 0;
    unsigned last_uid;
    char *last_seenuids;
    int num_recent = 0;
    int num_unseen = 0;
    int sepchar;

    if (mailbox->exists != 0 &&
	(statusitems &
	 (STATUS_RECENT | STATUS_UNSEEN))) {
	r = seen_open(mailbox, imapd_userid, &status_seendb);
	if (r) return r;

	r = seen_lockread(status_seendb, &last_read, &last_uid,
			  &last_change, &last_seenuids);
	seen_close(status_seendb);
	if (r) return r;

	if (statusitems & (STATUS_RECENT | STATUS_UNSEEN)) {
	    const char *base;
	    unsigned long len = 0;
	    int msg;
	    unsigned uid;

	    map_refresh(mailbox->index_fd, 0, &base, &len,
			mailbox->start_offset +
			mailbox->exists * mailbox->record_size,
			"index", mailbox->name);
	    for (msg = 0; msg < mailbox->exists; msg++) {
		uid = ntohl(*((bit32 *)(base + mailbox->start_offset +
					msg * mailbox->record_size +
					OFFSET_UID)));
		if (uid > last_uid) num_recent++;
		if ((statusitems & STATUS_UNSEEN) &&
		    !index_insequence(uid, last_seenuids, 0)) num_unseen++;
		/* NB: The value of the third argument to index_insequence()
		 * above does not matter.
		 */
	    }
	    map_free(&base, &len);
	    free(last_seenuids);
	}
    }

    prot_printf(imapd_out, "* STATUS ");
    printastring(name);
    prot_printf(imapd_out, " ");
    sepchar = '(';

    if (statusitems & STATUS_MESSAGES) {
	prot_printf(imapd_out, "%cMESSAGES %u", sepchar, mailbox->exists);
	sepchar = ' ';
    }
    if (statusitems & STATUS_RECENT) {
	prot_printf(imapd_out, "%cRECENT %u", sepchar, num_recent);
	sepchar = ' ';
    }
    if (statusitems & STATUS_UIDNEXT) {
	prot_printf(imapd_out, "%cUIDNEXT %u", sepchar, mailbox->last_uid+1);
	sepchar = ' ';
    }
    if (statusitems & STATUS_UIDVALIDITY) {
	prot_printf(imapd_out, "%cUIDVALIDITY %u", sepchar,
		    mailbox->uidvalidity);
	sepchar = ' ';
    }
    if (statusitems & STATUS_UNSEEN) {
	prot_printf(imapd_out, "%cUNSEEN %u", sepchar, num_unseen);
	sepchar = ' ';
    }
    prot_printf(imapd_out, ")\r\n");
    return 0;
}

/*
 * Performs a GETUIDS command
 */
int
index_getuids(mailbox, lowuid)
struct mailbox *mailbox;
unsigned lowuid;
{
    int msgno;
    unsigned firstuid = 0, lastuid = 0;


    prot_printf(imapd_out, "* GETUIDS");

    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	if (firstuid == 0) {
	    if (UID(msgno) >= lowuid) {
		prot_printf(imapd_out, " %u %u", msgno, UID(msgno));
		firstuid = lastuid = UID(msgno);
	    }
	}
	else {
	    if (UID(msgno) != ++lastuid) {
		if (lastuid-1 != firstuid) {
		    prot_printf(imapd_out, ":%u", lastuid-1);
		}
		firstuid = lastuid = UID(msgno);
		prot_printf(imapd_out, ",%u", firstuid);
	    }
	}
    }
    if (lastuid != firstuid) {
	prot_printf(imapd_out, ":%u", lastuid);
    }
    prot_printf(imapd_out, "\r\n");

    return 0;
}

/*
 * Performs a XGETSTATE command
 */
int
index_getstate(mailbox)
struct mailbox *mailbox;
{    

    prot_printf(imapd_out, "* XSTATE %u %u\r\n", mailbox->index_mtime,
		seen_last_change);

    return 0;
}

#if 0
/* What's this for?  Might as well keep it around. */
/*
 * Performs a XCHECKSTATE command
 */
int
index_checkstate(mailbox, indexdate, seendate)
struct mailbox *mailbox;
unsigned indexdate;
unsigned seendate;
{
    int r;
    int msgno;
    unsigned int startmsgno = 0;
    int sepchar = ' ';

    /* No messages == everything OK */
    if (imapd_exists < 1) {
	prot_printf(imapd_out, "* XCHECKSTATE\r\n");
	return 0;
    }
	
    /* If \Seen data changed, we don't know anything */
    if (seendate != seen_last_change) {
	if (imapd_exists == 1) {
	    prot_printf(imapd_out,
			"* XCHECKSTATE %u\r\n", UID(1));
	}
	else {
	    prot_printf(imapd_out,
			"* XCHECKSTATE %u:%u\r\n", UID(1), UID(imapd_exists));
	}
	return 0;
    }

    prot_printf(imapd_out, "* XCHECKSTATE");
    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	/*
	 * Below is >= instead of > because we can get
	 * two STORE commands within the same second.
	 */
	if (LAST_UPDATED(msgno) >= indexdate) {
	    if (startmsgno == 0) {
		prot_printf(imapd_out, "%c%u", sepchar, UID(msgno));
		sepchar = ',';
		startmsgno = msgno;
	    }
	}
	else {
	    if (startmsgno != 0 && startmsgno < msgno - 1) {
		prot_printf(imapd_out, ":%u", UID(msgno-1));
	    }
	    startmsgno = 0;
	}
    }

    if (startmsgno != 0 && startmsgno < imapd_exists) {
	prot_printf(imapd_out, ":%u", UID(imapd_exists));
    }

    prot_printf(imapd_out, "\r\n");
    return 0;
}
#endif

/*
 * Returns the msgno of the message with UID 'uid'.
 * If no message with UID 'uid', returns the message with
 * the higest UID not greater than 'uid'.
 */
int
index_finduid(uid)
unsigned uid;
{
    int low=1, high=imapd_exists, mid;
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
int index_expungeuidlist(rock, indexbuf)
void *rock;
char *indexbuf;
{
    char *sequence = (char *)rock;
    unsigned uid = ntohl(*((bit32 *)(indexbuf+OFFSET_UID)));

    /* Don't expunge if not \Deleted */
    if (!(ntohl(*((bit32 *)(indexbuf+OFFSET_SYSTEM_FLAGS))) & FLAG_DELETED))
	return 0;

    return index_insequence(uid, sequence, 1);
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
		  char* sequence,
		  int usinguid,
		  index_sequenceproc_t proc,
		  void* rock,
		  int* fetchedsomething)
{
    unsigned i, start = 0, end;
    int r, result = 0;

    /* no messages, no calls.  dumps core otherwise */
    if (! imapd_exists) {
	return 0;
    }

    for (;;) {
	if (isdigit((int) *sequence)) {
	    start = start*10 + *sequence - '0';
	}
	else if (*sequence == '*') {
	    start = usinguid ? UID(imapd_exists) : imapd_exists;
	}
	else if (*sequence == ':') {
	    end = 0;
	    sequence++;
	    while (isdigit((int) *sequence)) {
		end = end*10 + *sequence++ - '0';
	    }
	    if (*sequence == '*') {
		sequence++;
		end = usinguid ? UID(imapd_exists) : imapd_exists;
	    }
	    if (start > end) {
		i = end;
		end = start;
		start = i;
	    }
	    if (usinguid) {
		i = index_finduid(start);
		if (!i || start != UID(i)) i++;
		start = i;
		end = index_finduid(end);
	    }
	    if (start < 1) start = 1;
	    if (end > imapd_exists) end = imapd_exists;
	    for (i = start; i <= end; i++) {
		if (fetchedsomething) *fetchedsomething = 1;
		r = (*proc)(mailbox, i, rock);
		if (r && !result) result = r;
	    }
	    start = 0;
	    if (!*sequence) return result;
	}
	else {
	    if (start && usinguid) {
		i = index_finduid(start);
		if (!i || start != UID(i)) i = 0;
		start = i;
	    }
	    if (start > 0 && start <= imapd_exists) {
		if (fetchedsomething) *fetchedsomething = 1;
		r = (*proc)(mailbox, start, rock);
		if (r && !result) result = r;
	    }
	    start = 0;
	    if (!*sequence) return result;
	}
	sequence++;
    }
}

/*
 * Return nonzero iff 'num' is included in 'sequence'
 */
static int
index_insequence(num, sequence, usinguid)
int num;
char *sequence;
int usinguid;
{
    unsigned i, start = 0, end;

    for (;;) {
	if (isdigit((int) *sequence)) {
	    start = start*10 + *sequence - '0';
	}
	else if (*sequence == '*') {
	    sequence++;
	    start = usinguid ? UID(imapd_exists) : imapd_exists;
	}
	else if (*sequence == ':') {
	    end = 0;
	    sequence++;
	    while (isdigit((int) *sequence)) {
		end = end*10 + *sequence++ - '0';
	    }
	    if (*sequence == '*') {
		sequence++;
		end = usinguid ? UID(imapd_exists) : imapd_exists;
	    }
	    if (start > end) {
		i = end;
		end = start;
		start = i;
	    }
	    if (num >= start && num <= end) return 1;
	    start = 0;
	    if (!*sequence) return 0;
	}
	else {
	    if (num == start) return 1;
	    start = 0;
	    if (!*sequence) return 0;
	}
	sequence++;
    }
}    

/*
 * Helper function to fetch data from a message file.  Writes a
 * quoted-string or literal containing data from 'msg_base', which is
 * of size 'msg_size' and format 'format', starting at 'offset' and
 * containing 'size' octets.  If 'start_octet' is nonzero, the data is
 * further constrained by 'start_octet' and 'octet_count' as per the
 * IMAP command PARTIAL.
 */
static void
index_fetchmsg(msg_base, msg_size, format, offset, size,
	       start_octet, octet_count)
const char *msg_base;
unsigned long msg_size;
int format;
unsigned offset;
unsigned size;     /* this is the correct size for a news message after
		      having LF translated to CRLF */
unsigned start_octet;
unsigned octet_count;
{
    const char *line, *p;
    int n;

    /* partial fetch: adjust 'size', normalize 'start_octet' to be 0-based */
    if (start_octet) {
	start_octet--;
	if (size <= start_octet) {
	    size = 0;
	}
	else {
	    size -= start_octet;
	}
	if (size > octet_count) size = octet_count;
    }

    /* If no data, output null quoted string */
    if (!msg_base || size == 0) {
	prot_printf(imapd_out, "\"\"");
	return;
    }

    /* Write size of literal */
    prot_printf(imapd_out, "{%u}\r\n", size);

    if (format == MAILBOX_FORMAT_NETNEWS) {
	/* Have to fetch line-by-line, converting LF to CRLF */
	while (size) {
	    line = msg_base + offset;
	    p = memchr(line, '\n', msg_size - offset);
	    if (!p) {
		/* partial last line */
		p = msg_base + msg_size;
		offset--;	/* hack to keep from going off end
				 * of mapped region on next iteration */
		if (p == line) {
		    /* File too short, resynch client */
		    while (size--) prot_putc(' ', imapd_out);
		    return;
		}
	    }
	    n = p - line;
	    offset += n + 1;
	    if (start_octet >= n) {
		/* Skip over entire line */
		start_octet -= n;
		if (!start_octet--) {
		    start_octet = 0;
		    prot_putc('\r', imapd_out);
		    if (--size == 0) return;
		}
		if (!start_octet--) {
		    start_octet = 0;
		    prot_putc('\n', imapd_out);
		    size--;
		}
	    }
	    else {
		/* Skip over (possibly zero) first part of line */
		n -= start_octet;
		if (n > size) n = size;
		prot_write(imapd_out, line + start_octet, n);
		start_octet = 0;
		size -= n;
		if (!size--) return;
		prot_putc('\r', imapd_out);
		if (!size--) return;
		prot_putc('\n', imapd_out);
	    }
	}
    }
    else {
	/* Seek over PARTIAL constraint */
	offset += start_octet;
	n = size;
	if (offset + size > msg_size) {
	    n = msg_size - offset;
	}
	prot_write(imapd_out, msg_base + offset, n);
	while (n++ < size) {
	    /* File too short, resynch client */
	    prot_putc(' ', imapd_out);
	}
    }
}

/*
 * Helper function to fetch a body section
 */
static void
index_fetchsection(msg_base, msg_size, format, section, cacheitem, size,
		   start_octet, octet_count)
const char *msg_base;
unsigned long msg_size;
int format;
char *section;
const char *cacheitem;
unsigned size;
unsigned start_octet;
unsigned octet_count;
{
    char *p;
    int skip = 0;
    int fetchmime = 0;

    cacheitem += 4;
    p = section;

    /* Special-case BODY[] */
    if (*p == ']') {
	p++;
	if (*p == '<') {
	    p++;
	    start_octet = octet_count = 0;
	    while (isdigit((int) *p)) start_octet = start_octet * 10 + *p++ - '0';
	    p++;			/* Skip over '.' */
	    while (isdigit((int) *p)) octet_count = octet_count * 10 + *p++ - '0';
	    start_octet++;	/* Make 1-based */
	}

	index_fetchmsg(msg_base, msg_size, format, 0, size,
		       start_octet, octet_count);
	return;
    }

    while (*p != ']' && *p != 'M') {
	skip = 0;
	while (isdigit((int) *p)) skip = skip * 10 + *p++ - '0';
	if (*p == '.') p++;

	/* section number too large */
	if (skip >= CACHE_ITEM_BIT32(cacheitem)) goto badpart;

	/* Handle .0, .HEADER, and .TEXT */
	if (!skip) {
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
	    cacheitem += CACHE_ITEM_BIT32(cacheitem) * 5 * 4 + 4;
	    while (--skip) {
		if (CACHE_ITEM_BIT32(cacheitem) > 0) {
		    skip += CACHE_ITEM_BIT32(cacheitem)-1;
		    cacheitem += CACHE_ITEM_BIT32(cacheitem) * 5 * 4;
		}
		cacheitem += 4;
	    }
	}
    }

    if (*p == 'M') {
	p += 4;
	fetchmime++;
    }
    cacheitem += skip * 5 * 4 + 4 + (fetchmime ? 0 : 2 * 4);
    
    if (CACHE_ITEM_BIT32(cacheitem+4) == -1) goto badpart;
	
    p++;
    if (*p == '<') {
	p++;
	start_octet = octet_count = 0;
	while (isdigit((int) *p)) start_octet = start_octet * 10 + *p++ - '0';
	p++;			/* Skip over '.' */
	while (isdigit((int) *p)) octet_count = octet_count * 10 + *p++ - '0';
	start_octet++;		/* Make 1-based */
    }

    index_fetchmsg(msg_base, msg_size, format, CACHE_ITEM_BIT32(cacheitem),
		   CACHE_ITEM_BIT32(cacheitem+4),
		   start_octet, octet_count);
    return;

 badpart:
    prot_printf(imapd_out, "NIL");
}

/*
 * Helper function to fetch a HEADER.FIELDS[.NOT] body section
 */
static void
index_fetchfsection(msg_base, msg_size, format, fsection, cacheitem)
const char *msg_base;
unsigned long msg_size;
int format;
struct fieldlist *fsection;
const char *cacheitem;
{
    char *p;
    int skip = 0;
    int fields_not = 0;
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    int start_octet = 0;
    int octet_count = 0;
    char *buf;
    unsigned size;

    /* If no data, output null quoted string */
    if (!msg_base) {
	prot_printf(imapd_out, "\"\"");
	return;
    }

    cacheitem += 4;
    p = fsection->section;

    while (*p != 'H') {
	skip = 0;
	while (isdigit((int) *p)) skip = skip * 10 + *p++ - '0';
	if (*p == '.') p++;

	/* section number too large */
	if (skip >= CACHE_ITEM_BIT32(cacheitem)) goto badpart;

	cacheitem += CACHE_ITEM_BIT32(cacheitem) * 5 * 4 + 4;
	while (--skip) {
	    if (CACHE_ITEM_BIT32(cacheitem) > 0) {
		skip += CACHE_ITEM_BIT32(cacheitem)-1;
		cacheitem += CACHE_ITEM_BIT32(cacheitem) * 5 * 4;
	    }
	    cacheitem += 4;
	}
    }

    /* leaf object */
    if (0 == CACHE_ITEM_BIT32(cacheitem)) goto badpart;

    cacheitem += 4;

    if (CACHE_ITEM_BIT32(cacheitem+4) == -1) goto badpart;
	
    if (p[13]) fields_not++;	/* Check for "." after "HEADER.FIELDS" */

    p = fsection->trail;
    if (p[1] == '<') {
	p += 2;
	start_octet = octet_count = 0;
	while (isdigit((int) *p)) start_octet = start_octet * 10 + *p++ - '0';
	p++;			/* Skip over '.' */
	while (isdigit((int) *p)) octet_count = octet_count * 10 + *p++ - '0';
	start_octet++;		/* Make 1-based */
    }

    buf = index_readheader(msg_base, msg_size, format,
			   CACHE_ITEM_BIT32(cacheitem),
			   CACHE_ITEM_BIT32(cacheitem+4));

    if (fields_not) {
	index_pruneheader(buf, 0, fsection->fields);
    }
    else {
	index_pruneheader(buf, fsection->fields, 0);
    }
    size = strlen(buf);

    /* partial fetch: adjust 'size', normalize 'start_octet' to be 0-based */
    if (start_octet) {
	start_octet--;
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
int format;
unsigned offset;
unsigned size;
{
    static char *buf;
    static int bufsize;
    int linelen, left;
    char *p, *endline;

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

    if (format == MAILBOX_FORMAT_NETNEWS) {
	left = size;
	p = buf;
	while ((endline = memchr(msg_base, '\n', left))!=NULL) {
	    linelen = endline - msg_base;
	    memcpy(p, msg_base, linelen);
	    p += linelen;
	    msg_base += linelen+1;
	    *p++ = '\r';
	    *p++ = '\n';
	    left -= linelen + 1;
	    if (left) left--;
	}
	if (left) {
	    memcpy(p, msg_base, left);
	    p += left;
	}
	*p = '\0';
    }
    else {
	memcpy(buf, msg_base, size);
	buf[size] = '\0';
    }
    return buf;
}

/*
 * Prune the header section in buf to include only those headers
 * listed in headers or (if headers_not is non-empty) those headers
 * not in headers_not.
 */
static void
index_pruneheader(buf, headers, headers_not)
char *buf;
struct strlist *headers;
struct strlist *headers_not;
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
		if (colon - p == strlen(l->s) &&
		    !strncasecmp(p, l->s, colon - p)) {
		    goodheader = 0;
		    break;
		}
	    }
	}
	else {
	    goodheader = 0;
	}
	if (colon) {
	    for (l = headers; l; l = l->next) {
		if (colon - p == strlen(l->s) &&
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
		strcpy(endlastgood, p);
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
index_fetchcacheheader(msgno, headers, trail)
unsigned msgno;
struct strlist *headers;
char *trail;
{
    static char *buf;
    static int bufsize;
    const char *cacheitem;
    unsigned size;
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    int start_octet = 0;
    int octet_count = 0;

    cacheitem = cache_base + CACHE_OFFSET(msgno);
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip section */
    
    size = CACHE_ITEM_LEN(cacheitem);
    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    memcpy(buf, cacheitem+4, size);
    buf[size] = '\0';

    index_pruneheader(buf, headers, 0);
    size = strlen(buf);

    if (trail[1]) {
	/* Deal with ]<start.count> */
	trail += 2;
	while (isdigit((int) *trail)) start_octet = start_octet * 10 + *trail++ - '0';
	trail++;			/* Skip over '.' */
	while (isdigit((int) *trail)) octet_count = octet_count * 10 + *trail++ - '0';

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
    int i;
    int cancreate = 0;
    char sepchar = '(';

    prot_printf(imapd_out, "* FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen");
    for (i = 0; i < MAX_USER_FLAGS; i++) {
	if (mailbox->flagname[i]) {
	    prot_printf(imapd_out, " %s", mailbox->flagname[i]);
	}
	else cancreate++;
    }
    prot_printf(imapd_out, ")\r\n* OK [PERMANENTFLAGS ");
    if (mailbox->myrights & ACL_WRITE) {
	prot_printf(imapd_out, "%c\\Answered \\Flagged \\Draft", sepchar);
	sepchar = ' ';
    }
    if (mailbox->myrights & ACL_DELETE) {
	prot_printf(imapd_out, "%c\\Deleted", sepchar);
	sepchar = ' ';
    }
    if (mailbox->myrights & ACL_SEEN) {
	prot_printf(imapd_out, "%c\\Seen", sepchar);
	sepchar = ' ';
    }
    if (mailbox->myrights & ACL_WRITE) {
	for (i = 0; i < MAX_USER_FLAGS; i++) {
	    if (mailbox->flagname[i]) {
		prot_printf(imapd_out, " %s", mailbox->flagname[i]);
	    }
	}
	if (cancreate) {
	    prot_printf(imapd_out, " \\*");
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
static void
index_fetchflags(mailbox, msgno, system_flags, user_flags, last_updated)
struct mailbox *mailbox;
unsigned msgno;
bit32 system_flags;
bit32 user_flags[MAX_USER_FLAGS/32];
time_t last_updated;
{
    int sepchar = '(';
    unsigned flag;
    bit32 flagmask = 0;

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
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
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
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

    flagreport[msgno] = last_updated;
}

/*
 * Helper function to send requested * FETCH data for a message
 */
static int
index_fetchreply(mailbox, msgno, rock)
struct mailbox *mailbox;
unsigned msgno;
void *rock;
{
    struct fetchargs *fetchargs = (struct fetchargs *)rock;    
    int fetchitems = fetchargs->fetchitems;
    const char *msg_base = 0;
    unsigned long msg_size = 0;
    int sepchar;
    int i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    const char *cacheitem;
    struct strlist *section, *field;
    struct fieldlist *fsection;
    char *partialdot;

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_RFC822|FETCH_UNCACHEDHEADER)) ||
	fetchargs->bodysections) {
	if (mailbox_map_message(mailbox, 1, UID(msgno), &msg_base, &msg_size)) {
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
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    user_flags[i] = USER_FLAGS(msgno, i);
	}
	index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
			 LAST_UPDATED(msgno));
	sepchar = ' ';
    }
    else {
	prot_printf(imapd_out, "* %u FETCH ", msgno);
	sepchar = '(';
    }
    if (fetchitems & FETCH_UID) {
	prot_printf(imapd_out, "%cUID %u", sepchar, UID(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_INTERNALDATE) {
	time_t msgdate = INTERNALDATE(msgno);
	struct tm *tm = localtime(&msgdate);
	long gmtoff = gmtoff_of(tm, msgdate);
	int gmtnegative = 0;
	static char *monthname[] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	char datebuf[30];

	if (msgdate == 0 || tm->tm_year < 69) {
	    abort();
	}

	if (gmtoff < 0) {
	    gmtoff = -gmtoff;
	    gmtnegative = 1;
	}
	gmtoff /= 60;
	sprintf(datebuf, "%2u-%s-%u %.2u:%.2u:%.2u %c%.2lu%.2lu",
		tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		gmtnegative ? '-' : '+', gmtoff/60, gmtoff%60);
	prot_printf(imapd_out, "%cINTERNALDATE \"%s\"",
		    sepchar, datebuf);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_SIZE) {
	prot_printf(imapd_out, "%cRFC822.SIZE %u", sepchar, SIZE(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_ENVELOPE) {
	prot_printf(imapd_out, "%cENVELOPE ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	prot_write(imapd_out, cacheitem+4, CACHE_ITEM_LEN(cacheitem));
    }
    if (fetchitems & FETCH_BODYSTRUCTURE) {
	prot_printf(imapd_out, "%cBODYSTRUCTURE ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	prot_write(imapd_out, cacheitem+4, CACHE_ITEM_LEN(cacheitem));
    }
    if (fetchitems & FETCH_BODY) {
	prot_printf(imapd_out, "%cBODY ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	prot_write(imapd_out, cacheitem+4, CACHE_ITEM_LEN(cacheitem));
    }

    if (fetchitems & FETCH_HEADER) {
	prot_printf(imapd_out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msg_base, msg_size, mailbox->format, 0,
		       HEADER_SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    else if (fetchargs->headers || fetchargs->headers_not) {
	prot_printf(imapd_out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	if (fetchitems & FETCH_UNCACHEDHEADER) {
	    index_fetchheader(msg_base, msg_size, mailbox->format,
			      HEADER_SIZE(msgno),
			      fetchargs->headers, fetchargs->headers_not);
	}
	else {
	    index_fetchcacheheader(msgno, fetchargs->headers, "]");
	}
    }

    if (fetchitems & FETCH_TEXT) {
	prot_printf(imapd_out, "%cRFC822.TEXT ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msg_base, msg_size, mailbox->format,
		       CONTENT_OFFSET(msgno), SIZE(msgno) - HEADER_SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    if (fetchitems & FETCH_RFC822) {
	prot_printf(imapd_out, "%cRFC822 ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msg_base, msg_size, mailbox->format, 0, SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
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

	if (fsection->trail[1] == '<') {
	    /* Have to trim off the maximum number of octets from the reply */
	    partialdot = strrchr(fsection->trail, '.');
	    *partialdot = '\0';
	    prot_printf(imapd_out, "%s> ", fsection->trail);
	    *partialdot = '.';
	}
	else {
	    prot_printf(imapd_out, "%s ", fsection->trail);
	}

	if (fetchitems & FETCH_UNCACHEDHEADER) {
	    cacheitem = cache_base + CACHE_OFFSET(msgno);
	    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */

	    index_fetchfsection(msg_base, msg_size, mailbox->format, fsection,
				cacheitem);
	}
	else {
	    index_fetchcacheheader(msgno, fsection->fields, fsection->trail);
	}
    }
    for (section = fetchargs->bodysections; section; section = section->next) {
	if (section->s[strlen(section->s)-1] == '>') {
	    /* Have to trim off the maximum number of octets from the reply */
	    partialdot = strrchr(section->s, '.');
	    *partialdot = '\0';
	    prot_printf(imapd_out, "%cBODY[%s> ", sepchar, section->s);
	    *partialdot = '.';
	}
	else {
	    prot_printf(imapd_out, "%cBODY[%s ", sepchar, section->s);
	}
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */

	index_fetchsection(msg_base, msg_size, mailbox->format, section->s,
			   cacheitem, SIZE(msgno),
			   fetchargs->start_octet, fetchargs->octet_count);
    }
    prot_printf(imapd_out, ")\r\n");
    if (msg_base) {
	mailbox_unmap_message(mailbox, UID(msgno), &msg_base, &msg_size);
    }
    return 0;
}

/*
 * Helper function to perform a STORE command which only changes the
 * \Seen flag.
 */
static int
index_storeseen(mailbox, msgno, rock)
struct mailbox *mailbox;
unsigned msgno;
void *rock;
{
    struct storeargs *storeargs = (struct storeargs *)rock;
    int val = (storeargs->operation == STORE_ADD) ? 1 : 0;
    int i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    
    if (seenflag[msgno] == val) return 0;
    seenflag[msgno] = val;

    if (storeargs->silent) return 0;

    for (i=0; i < MAX_USER_FLAGS/32; i++) {
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
static int
index_storeflag(mailbox, msgno, rock)
struct mailbox *mailbox;
unsigned msgno;
void *rock;
{
    struct storeargs *storeargs = (struct storeargs *)rock;
    int i;
    struct index_record record;
    int uid = UID(msgno);
    int low=1, high=mailbox->exists;
    int mid = 0;
    int r;
    int firsttry = 1;
    int dirty = 0;
    bit32 oldflags;

    /* Change \Seen flag */
    if (storeargs->operation == STORE_REPLACE && (mailbox->myrights&ACL_SEEN))
    {
	seenflag[msgno] = storeargs->seen;
    }
    else if (storeargs->seen) {
	i = (storeargs->operation == STORE_ADD) ? 1 : 0;
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
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    record.user_flags[i] = USER_FLAGS(msgno, i);
	}
    }

    /* save old for acapmbox foo */
    oldflags = record.system_flags;

    if (storeargs->operation == STORE_REPLACE) {
	if (!(mailbox->myrights & ACL_WRITE)) {
	    record.system_flags = (record.system_flags&~FLAG_DELETED) |
	      (storeargs->system_flags&FLAG_DELETED);
	}
	else {
	    if (!(mailbox->myrights & ACL_DELETE)) {
		record.system_flags = (record.system_flags&FLAG_DELETED) |
		  (storeargs->system_flags&~FLAG_DELETED);
	    }
	    else {
		record.system_flags = storeargs->system_flags;
	    }
	    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
		record.user_flags[i] = storeargs->user_flags[i];
	    }
	}
	dirty++;		/* Don't try to be clever */
    }
    else if (storeargs->operation == STORE_ADD) {
	if (~record.system_flags & storeargs->system_flags) dirty++;

	record.system_flags |= storeargs->system_flags;
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    if (~record.user_flags[i] & storeargs->user_flags[i]) dirty++;
	    record.user_flags[i] |= storeargs->user_flags[i];
	}
    }
    else {			/* STORE_REMOVE */
	if (record.system_flags & storeargs->system_flags) dirty++;

	/* change the individual entry */
	record.system_flags &= ~storeargs->system_flags;
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    if (record.user_flags[i] & storeargs->user_flags[i]) dirty++;
	    record.user_flags[i] &= ~storeargs->user_flags[i];
	}
    }

    if (dirty) {
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
	if (storeargs->usinguid) {
	    prot_printf(imapd_out, " UID %u", UID(msgno));
	}
	prot_printf(imapd_out, ")\r\n");
    }
    
    if (dirty && mid) {
	r = mailbox_write_index_record(mailbox, mid, &record);
	if (r) return r;
    }
    
    return 0;
}

/*
 * Evaluate a searchargs structure on a msgno
 *
 * Note: msgfile argument must be 0 if msg is not mapped in.
 */
static int
index_search_evaluate(mailbox, searchargs, msgno, msgfile)
struct mailbox *mailbox;
struct searchargs *searchargs;
unsigned msgno;
struct mapfile *msgfile;
{
    int i;
    struct strlist *l, *h;
    const char *cacheitem;
    int cachelen;
    struct searchsub *s;

    if ((searchargs->flags & SEARCH_RECENT_SET) && msgno <= lastnotrecent) 
	return 0;
    if ((searchargs->flags & SEARCH_RECENT_UNSET) && msgno > lastnotrecent) 
	return 0;
    if ((searchargs->flags & SEARCH_SEEN_SET) && !seenflag[msgno]) return 0;
    if ((searchargs->flags & SEARCH_SEEN_UNSET) && seenflag[msgno]) return 0;

    if (searchargs->smaller && SIZE(msgno) >= searchargs->smaller) return 0;
    if (searchargs->larger && SIZE(msgno) <= searchargs->larger) return 0;

    if (searchargs->after && INTERNALDATE(msgno) < searchargs->after)
      return 0;
    if (searchargs->before && INTERNALDATE(msgno) > searchargs->before)
      return 0;
    if (searchargs->sentafter && SENTDATE(msgno) < searchargs->sentafter)
      return 0;
    if (searchargs->sentbefore && SENTDATE(msgno) > searchargs->sentbefore)
      return 0;

    if (~SYSTEM_FLAGS(msgno) & searchargs->system_flags_set) return 0;
    if (SYSTEM_FLAGS(msgno) & searchargs->system_flags_unset) return 0;
	
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	if (~USER_FLAGS(msgno,i) & searchargs->user_flags_set[i])
	  return 0;
	if (USER_FLAGS(msgno,i) & searchargs->user_flags_unset[i])
	  return 0;
    }

    for (l = searchargs->sequence; l; l = l->next) {
	if (!index_insequence(msgno, l->s, 0)) return 0;
    }
    for (l = searchargs->uidsequence; l; l = l->next) {
	if (!index_insequence(UID(msgno), l->s, 1)) return 0;
    }

    if (searchargs->from || searchargs->to ||searchargs->cc ||
	searchargs->bcc || searchargs->subject) {

	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip section */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip cacheheaders */
	cachelen = CACHE_ITEM_LEN(cacheitem);
	    
	for (l = searchargs->from; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen))
		return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip from */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->to; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) 
		return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip to */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->cc; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) 
		return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip cc */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->bcc; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) 
		return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bcc */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->subject; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) 
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
	(searchargs->flags & SEARCH_UNCACHEDHEADER)) {
	if (! msgfile->size) { /* Map the message in if we haven't before */
	    if (mailbox_map_message(mailbox, 1, UID(msgno),
				    &msgfile->base, &msgfile->size)) {
		return 0;
	    }
	}

	h = searchargs->header_name;
	for (l = searchargs->header; l; (l = l->next), (h = h->next)) {
	    if (!index_searchheader(h->s, l->s, l->p, msgfile, mailbox->format,
				    HEADER_SIZE(msgno))) return 0;
	}

	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */

	for (l = searchargs->body; l; l = l->next) {
	    if (!index_searchmsg(l->s, l->p, msgfile, mailbox->format, 1,
				 cacheitem)) return 0;
	}
	for (l = searchargs->text; l; l = l->next) {
	    if (!index_searchmsg(l->s, l->p, msgfile, mailbox->format, 0,
				  cacheitem)) return 0;
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
 * Search part of a message for a substring
 */
static int
index_searchmsg(substr, pat, msgfile, format, skipheader, cacheitem)
char *substr;
comp_pat *pat;
struct mapfile *msgfile;
int format;
int skipheader;
const char *cacheitem;
{
    int partsleft = 1;
    int subparts;
    int start, len, charset, encoding;
    char *p, *q;
    
    /* Won't find anything in a truncated file */
    if (msgfile->size == 0) return 0;

    cacheitem += 4;
    while (partsleft--) {
	subparts = CACHE_ITEM_BIT32(cacheitem);
	cacheitem += 4;
	if (subparts) {
	    partsleft += subparts-1;

	    if (skipheader) {
		skipheader = 0;	/* Only skip top-level message header */
	    }
	    else {
		len = CACHE_ITEM_BIT32(cacheitem+4);
		if (len > 0) {
		    p = index_readheader(msgfile->base, msgfile->size,
					 format, CACHE_ITEM_BIT32(cacheitem),
					 len);
		    q = charset_decode1522(p, NULL, 0);
		    if (charset_searchstring(substr, pat, q, strlen(q))) {
			free(q);
			return 1;
		    }
		    free(q);
		}
	    }
	    cacheitem += 5*4;

	    while (--subparts) {
		start = CACHE_ITEM_BIT32(cacheitem+2*4);
		len = CACHE_ITEM_BIT32(cacheitem+3*4);
		charset = CACHE_ITEM_BIT32(cacheitem+4*4) >> 16;
		encoding = CACHE_ITEM_BIT32(cacheitem+4*4) & 0xff;

		if (start < msgfile->size && len > 0 &&
		    charset >= 0 && charset < 0xffff) {
		    if (charset_searchfile(substr, pat,
					   msgfile->base + start,
					   format == MAILBOX_FORMAT_NETNEWS,
					   len, charset, encoding)) return 1;
		}
		cacheitem += 5*4;
	    }
	}
    }

    return 0;
}
	    
/*
 * Search named header of a message for a substring
 */
static int
index_searchheader(name, substr, pat, msgfile, format, size)
char *name;
char *substr;
comp_pat *pat;
struct mapfile *msgfile;
int format;
int size;
{
    char *p, *q;
    int r;
    static struct strlist header;

    header.s = name;

    p = index_readheader(msgfile->base, msgfile->size, format, 0, size);
    index_pruneheader(p, &header, 0);
    q = charset_decode1522(p, NULL, 0);
    r = charset_searchstring(substr, pat, q, strlen(q));
    free(q);
    return r;
}

/*
 * Search named cached header of a message for a substring
 */
static int
index_searchcacheheader(msgno, name, substr, pat)
unsigned msgno;
char *name;
char *substr;
comp_pat *pat;
{
    char *q;
    static struct strlist header;
    static char *buf;
    static int bufsize;
    const char *cacheitem;
    unsigned size;
    int r;

    cacheitem = cache_base + CACHE_OFFSET(msgno);
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */
    cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip section */
    
    size = CACHE_ITEM_LEN(cacheitem);
    if (!size) return 0;	/* No cached headers, fail */
    if (bufsize < size+2) {
	bufsize = size+100;
	buf = xrealloc(buf, bufsize);
    }

    memcpy(buf, cacheitem+4, size);
    buf[size] = '\0';

    header.s = name;

    index_pruneheader(buf, &header, 0);
    if (!*buf) return 0;	/* Header not present, fail */
    if (!*substr) return 1;	/* Only checking existence, succeed */
    q = charset_decode1522(buf, NULL, 0);
    r = charset_searchstring(substr, pat, q, strlen(q));
    free(q);
    return r;
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
    copyargs->copymsg[copyargs->nummsg].cache_begin = cache_base + CACHE_OFFSET(msgno);
    if (mailbox->format != MAILBOX_FORMAT_NORMAL) {
	/* Force copy and re-parse of message */
	copyargs->copymsg[copyargs->nummsg].cache_len = 0;
    }
    else if (msgno < imapd_exists) {
	copyargs->copymsg[copyargs->nummsg].cache_len =
	  CACHE_OFFSET(msgno+1) - CACHE_OFFSET(msgno);
    }
    else {
	copyargs->copymsg[copyargs->nummsg].cache_len =
	  cache_end - CACHE_OFFSET(msgno);
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
 * Hashes a string to produce an unsigned short, which should be
 * sufficient for most purposes.
 *
 * public domain code by Jerry Coffin, with improvements by HenkJan Wolthuis.
 *
 * Can we find a function that maintains alphabetical (ascii) ordering
 * between strings ( hash(abc) < hash(abd) < hash(abe) )?
 */

static unsigned hash(char *string)
{
    unsigned ret_val = 0;
    int i;

    while (*string) {
	i = (int) *string;
	ret_val ^= i;
	ret_val <<= 1;
	string ++;
    }
    return ret_val;
}

/*
 * Creates a list of msgdata.
 *
 * We fill these structs with the info that will be needed
 * by the specified sort criteria.
 */

#define NEWMSGDATA \
    (struct msgdata *) memset(xmalloc(sizeof(struct msgdata)), 0, \
			      sizeof(struct msgdata))

#define GETADDR(header)							\
    parseaddr_list((header)+4, &addr);					\
    cur->header = xstrdup(addr && addr->mailbox ? addr->mailbox : "");	\
    parseaddr_free(addr);						\
    addr=NULL

static struct msgdata *index_msgdata_load(unsigned *msgno_list, int n,
					  signed char *sortcrit)
{
    struct msgdata *md, *cur;
    const char *cacheitem, *env, *from, *to, *cc, *subj;
    struct address *addr;
    int i, j;

    if (!n)
	return NULL;

    cur = md = NEWMSGDATA;

    i = 0;
    do {
	/* set msgno */
	cur->msgno = msgno_list[i++];

	/* fetch cached info */
	env = cache_base + CACHE_OFFSET(cur->msgno);
	cacheitem = CACHE_ITEM_NEXT(env); /* bodystructure */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* body */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* section */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* cacheheaders */
	from = CACHE_ITEM_NEXT(cacheitem);
	to = CACHE_ITEM_NEXT(from);
	cc = CACHE_ITEM_NEXT(to);
	cacheitem = CACHE_ITEM_NEXT(cc); /* bcc */
	subj = CACHE_ITEM_NEXT(cacheitem);

	j = 0;
	while (sortcrit[j]) {
	    switch (abs(sortcrit[j++])) {
	    case SORT_ARRIVAL:
		cur->arrival = INTERNALDATE(cur->msgno);
		break;
	    case SORT_CC:
		GETADDR(cc);
		break;
	    case SORT_DATE:
		/* skip open paren and double-quote */
		cur->date = message_parse_date((char*) env+6,
					      PARSE_TIME | PARSE_ZONE);
		break;
	    case SORT_FROM:
		GETADDR(from);
		break;
	    case SORT_SIZE:
		cur->size = SIZE(cur->msgno);
		break;
	    case SORT_SUBJECT:
		cur->xsubj = index_extract_subject(subj+4);
		cur->xsubj_hash = hash(cur->xsubj);
		break;
	    case SORT_TO:
		GETADDR(to);
		break;
	    }
	}
    } while (i < n && (cur = cur->next = NEWMSGDATA));

    return md;
}

/* Extract base subject from subject header */
char *index_extract_subject(const char *subj)
{
    char *s, *base, *ret, *x;

    if (!strcmp(subj, "NIL"))				/* "NIL"? */
	return xstrdup("");				/* yes, return empty */

    /* make a working copy of subj - remove "'s if they exist */
    if (*subj == '"')
	s = xstrndup(subj+1, strlen(subj) - 2);
    else
	s = xstrdup(subj);

    /* trim trailer
     *
     * start at the end of the string and work towards the front,
     * resetting the end of the string as we go.
     */
    for (x = s + strlen(s) - 1; x >= s;) {
	if (isspace((int) *x)) {                        /* whitespace? */
	    *x = '\0';					/* yes, trim it */
	    x--;					/* skip past it */
	}
	else if (x - s >= 4 &&
		 !strncasecmp(x-4, "(fwd)", 5)) {	/* "(fwd)"? */
	    *(x-4) = '\0';				/* yes, trim it */
	    x -= 5;					/* skip past it */
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
	if (isspace((int) *base)) base++;		/* whitespace? */

	/* possible refwd */
	else if ((!strncasecmp(base, "re", 2) &&	/* "re"? */
		  (x = base + 2)) ||			/* yes, skip past it */
		 (!strncasecmp(base, "fwd", 3) &&	/* "fwd"? */
		  (x = base + 3)) ||			/* yes, skip past it */
		 (!strncasecmp(base, "fw", 2) &&	/* "fw"? */
		  (x = base + 2))) {			/* yes, skip past it */
	    
	    while (isspace((int) *x)) x++;		/* skip whitespace */

	    if (*x == '[') {				/* start of blob? */
		x = strchr(x, ']');
		if (x)			                /* yes, end of blob? */
		    x++;				/* yes, skip past it */
		else
		    break;				/* no, we're done */
	    }

	    while (isspace((int) *x)) x++;              /* skip whitespace */

	    if (*x == ':')				/* ending colon? */
		base = x + 1;				/* yes, skip past it */
	    else
		break;					/* no, we're done */
	}
	else if (*base == '[' &&			/* start of blob? */
		 (x = strchr(base, ']'))) {		/* yes, end of blob? */
	    if (*(x+1))					/* yes, end of string? */
		base = x + 1;				/* no, skip blob */

	    /* Hack to catch Netscape's wacky "[Fwd: message]" notation. */
	    else if (!strncasecmp(base+1, "fwd:", 4)) {
		char *blob;

		/* make a working copy of blob contents */
		blob = xstrndup(base+1, strlen(base) - 2);

		ret = index_extract_subject(blob);	/* extract blob-base */

		free(blob);
		free(s);

		return ret;				/* return blob-base */
	    }
	    else
		break;					/* yes, return blob */
	}
	else
	    break;					/* we're done */
    }

    /* make a copy of the extracted base */
    ret = xstrdup(base);

    free(s);

    return ret;
}

/*
 * Getnext function for sorting message lists.
 */
static void *index_sort_getnext(struct msgdata *node)
{
    return node->next;
}

/*
 * Setnext function for sorting message lists.
 */
static void index_sort_setnext(struct msgdata *node, struct msgdata *next)
{
    node->next = next;
}

/*
 * Comparison function for sorting message lists.
 */
static int numcmp(int x, int y)
{
    return ((x < y) ? -1 : (x > y) ? 1 : 0);
}

static int index_sort_compare(struct msgdata *md1, struct msgdata *md2,
			      signed char *sortcrit)
{
    int reverse, ret = 0, i = 0;
    int label;

    do {
	/* determine sort order from sign of criterion */
	if (sortcrit[i] < 0) {
	    label = -sortcrit[i];
	    reverse = 1;
	} else {
	    label = sortcrit[i];
	    reverse = 0;
	}

	switch (label) {
	case SORT_SEQUENCE:
	    ret = numcmp(md1->msgno, md2->msgno);
	    break;
	case SORT_ARRIVAL:
	    ret = numcmp(md1->arrival, md2->arrival);
	    break;
	case SORT_CC:
	    ret = strcmp(md1->cc, md2->cc);
	    break;
	case SORT_DATE:
	    ret = numcmp(md1->date, md2->date);
	    break;
	case SORT_FROM:
	    ret = strcmp(md1->from, md2->from);
	    break;
	case SORT_SIZE:
	    ret = numcmp(md1->size, md2->size);
	    break;
	case SORT_SUBJECT:
	    ret = strcmp(md1->xsubj, md2->xsubj);
	    break;
	case SORT_TO:
	    ret = strcmp(md1->to, md2->to);
	    break;
	}
    } while (!ret && sortcrit[i++] != SORT_SEQUENCE);

    return (reverse ? -ret : ret);
}

/*
 * Free a msgdata node.
 */
static void index_msgdata_free(struct msgdata *md)
{
#define FREE(x)	if (x) free(x)
    FREE(md->cc);
    FREE(md->from);
    FREE(md->to);
    FREE(md->xsubj);
    free(md);
}

/*
 * Free a list of sorted messages.
 */
static void index_sort_free(struct msgdata *list)
{

    struct msgdata *tmp;

    while (list) {
	tmp = list;
	list = list->next;
	index_msgdata_free(tmp);
    }
}

/*
 * Getnext function for sorting thread lists.
 */
static void *index_thread_getnext(struct thread *thread)
{
    return thread->next;
}

/*
 * Setnext function for sorting thread lists.
 */
static void index_thread_setnext(struct thread *thread, struct thread *next)
{
    thread->next = next;
}

/*
 * Comparison function for sorting threads.
 */
static int index_thread_compare(struct thread *t1, struct thread *t2,
				signed char *call_data)
{
  return index_sort_compare(t1->msgdata, t2->msgdata, call_data);
}

/*
 * Thread a list of messages using the ORDEREDSUBJECT algorithm.
 */
#define NEWTHREAD \
    (struct thread *) memset(xmalloc(sizeof(struct thread)), 0, \
			     sizeof(struct thread))

static struct thread *index_thread_orderedsubj(unsigned *msgno_list, int nmsg)
{
    struct msgdata *msgdata;
    signed char sortcrit[] = { SORT_SUBJECT, SORT_DATE, SORT_SEQUENCE };
    unsigned psubj_hash;
    char *psubj;
    struct thread *threads, *tmp, *cur, *parent;

    /* Create/load the msgdata array */
    msgdata = index_msgdata_load(msgno_list, nmsg, sortcrit);

    /* Sort messages by subject and date */
    msgdata = lsort(msgdata,
		    (void * (*)(void*)) index_sort_getnext,
		    (void (*)(void*,void*)) index_sort_setnext,
		    (int (*)(void*,void*,void*)) index_sort_compare,
		    sortcrit);

    /* build threads under a dummy head */
    tmp = cur = NEWTHREAD;
    parent = NULL;
    psubj_hash = msgdata->xsubj_hash + 1; /* guarantee psubj != first subj */
    psubj = NULL;
    while (msgdata) {
	/* if current subj == prev subj, then add message to current thread */
	if (msgdata->xsubj_hash == psubj_hash &&
	    !strcmp(msgdata->xsubj, psubj)) { /* if 2 subjs have same key */
	    parent->child = NEWTHREAD;
	    parent = parent->child; /* this'll be the parent 
				       next time around */
	    parent->msgdata = msgdata;
	}

	/* otherwise, create a new thread */
	else {
	    cur->next = NEWTHREAD; /* create a new entry */
	    parent = cur = cur->next; /* now work with the new entry */
	    cur->msgdata = msgdata;
	}

	psubj_hash = msgdata->xsubj_hash;
	psubj = msgdata->xsubj;
	msgdata = msgdata->next;
    }

    /* Sort threads by date */
    threads = lsort(tmp->next,
		    (void * (*)(void*)) index_thread_getnext,
		    (void (*)(void*,void*)) index_thread_setnext,
		    (int (*)(void*,void*,void*)) index_thread_compare,
		    sortcrit+1);

    /* free the dummy head */
    free(tmp);

    return threads;

}

/*
 * Print a list of threads.
 */
static void index_thread_print(struct thread *thread, int usinguid)
{
    struct thread *child;

    /* for each thread... */
    while (thread) {
	prot_printf(imapd_out, "(");

	prot_printf(imapd_out, "%u",
		    usinguid ? UID(thread->msgdata->msgno) :
		    thread->msgdata->msgno);

	/* for each child, grandchild, etc... */
	child = thread->child;
	while (child) {
	    prot_printf(imapd_out, " ");

	    /* if the child has siblings, print new branch and break */
	    if (child->next) {
		index_thread_print(child, usinguid);
		break;
	    }
	    /* otherwise print the only child */
	    else {
		prot_printf(imapd_out, "%u",
			    usinguid ? UID(child->msgdata->msgno) :
			    child->msgdata->msgno);
		child = child->child;
	    }
	}
	prot_printf(imapd_out, ")");

	thread = thread->next;
    }
}

/*
 * Free a list of threads.
 */
static void index_thread_free(struct thread *threads)
{
    struct thread *child, *tmp;

    /* for each thread... */
    while (threads) {

	/* for each child, grandchild, etc... */
	child = threads->child;
	while (child) {

	    /* if the child has siblings, free new branch and break */
	    if (child->next) {
		index_thread_free(child);
		break;
	    }
	    /* otherwise free the only child */
	    else {
		tmp = child;
		child = child->child;
		index_msgdata_free(tmp->msgdata);
		free(tmp);
	    }
	}
	tmp = threads;
	threads = threads->next;
	index_msgdata_free(tmp->msgdata);
	free(tmp);
    }
}

/*
 * List threading algorithms for CAPABILITY.
 */
void list_thread_algorithms()
{
    struct thread_algorithm *thr_alg;

    for (thr_alg = thread_algs; thr_alg->alg_name; thr_alg++)
	prot_printf(imapd_out, " THREAD=%s", thr_alg->alg_name);
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
