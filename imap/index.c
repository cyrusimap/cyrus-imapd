/* index.c -- Routines for dealing with the index file in the imapd
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
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

#include "acl.h"
#include "util.h"
#include "assert.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
#include "append.h"
#include "charset.h"
#include "xmalloc.h"

extern int errno;

/* The index and cache files, mapped into memory */
static char *index_base;
static unsigned long index_len;
static char *cache_base;
static unsigned long cache_len;
static unsigned long cache_end;

/* Attributes of memory-mapped index file */
static long index_ino;
static unsigned long start_offset;
static unsigned long record_size;

static unsigned recentuid;		/* UID of last non-\Recent message */
static unsigned lastnotrecent;	/* Msgno of last non-\Recent message */

static time_t *flagreport;	/* Array for each msgno of last_updated when
				 * FLAGS data reported to client.
				 * Zero if FLAGS data never reported */
static char *seenflag;		/* Array for each msgno, nonzero if \Seen */
static int flagalloced = -1;	/* Allocated size of above two arrays */
static int examining;		/* Nonzero if opened with EXAMINE command */
static int keepingseen;		/* Nonzero if /Seen is meaningful */
static unsigned allseen;	/* Last UID if all msgs /Seen last checkpoint */
struct seen *seendb;		/* Seen state database object */
static char *seenuids;		/* Sequence of UID's from last seen checkpoint */

/* Access macros for the memory-mapped index file data */
#define INDEX_OFFSET(msgno) (index_base+start_offset+(((msgno)-1)*record_size))
#define UID(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_UID)))
#define INTERNALDATE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_INTERNALDATE)))
#define SENTDATE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_SENTDATE)))
#define SIZE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_SIZE)))
#define HEADER_SIZE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_HEADER_SIZE)))
#define CONTENT_OFFSET(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_CONTENT_OFFSET)))
#define CACHE_OFFSET(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_CACHE_OFFSET)))
#define LAST_UPDATED(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_LAST_UPDATED)))
#define SYSTEM_FLAGS(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_SYSTEM_FLAGS)))
#define USER_FLAGS(msgno,i) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+OFFSET_USER_FLAGS+((i)*4))))

/* Access assistance macros for memory-mapped cache file data */
#define CACHE_ITEM_BIT32(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_LEN(ptr) CACHE_ITEM_BIT32(ptr)
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

/* Forward declarations */
static int index_forsequence(), index_insequence();
static int index_listflags();
static int index_fetchflags(), index_fetchreply();
static int index_storeseen(), index_storeflag();
static int index_search_evaluate();
static int index_searchmsg(), index_searchheader();
static int index_copysetup();

struct copyargs {
    struct copymsg *copymsg;
    int nummsg;
    int msgalloc;
};

struct mapfile {
    int fd;
    char *base;
    unsigned long size;
};

/*
 * A mailbox is about to be closed.
 */
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
index_check(mailbox, usinguid, checkseen)
struct mailbox *mailbox;
int usinguid;
int checkseen;
{
    struct stat sbuf;
    int newexists, oldexists, oldmsgno, msgno, nexpunge, i, r;
    struct index_record record;
    time_t last_read, last_change;
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
		fatal("failed to reopen index file", EX_IOERR);
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
    map_refresh(fileno(mailbox->index), 0, &index_base, &index_len,
		start_offset + newexists * record_size,
		"index", mailbox->name);
    if (fstat(fileno(mailbox->cache), &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: stating cache file for %s: %m",
	       mailbox->name);
	fatal("failed to stat cache file", EX_IOERR);
    }
    if (cache_end < sbuf.st_size) {
	cache_end = sbuf.st_size;
	map_refresh(fileno(mailbox->cache), 0, &cache_base, &cache_len,
		    cache_end, "cache", mailbox->name);
    }

    /* If opening mailbox, get \Recent info */
    if (oldexists == -1 && keepingseen) {
	r = seen_open(mailbox, imapd_userid, &seendb);
	if (!r) {
	    r = seen_lockread(seendb, &last_read, &recentuid, &last_change,
			      &seenuids);
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
	    flagreport[i] = 0;
	    seenflag[i] = 0;
	}

	checkseen = 1;
	imapd_exists = newexists;
	prot_printf(imapd_out, "* %u EXISTS\r\n* %u RECENT\r\n", imapd_exists,
	       imapd_exists-lastnotrecent);
    }

    /* Check Flags */
    if (checkseen) index_checkseen(mailbox, 0, usinguid, oldexists);
    for (i = 1; i <= imapd_exists && seenflag[i]; i++);
    if (i == imapd_exists + 1) allseen = mailbox->last_uid;
    if (oldexists == -1) {
	if (imapd_exists && i <= imapd_exists) {
	    prot_printf(imapd_out, "* OK [UNSEEN %u] \r\n", i);
	}
        prot_printf(imapd_out, "* OK [UIDVALIDITY %u] \r\n",
		    mailbox->uidvalidity);
    }

    for (msgno = 1; msgno <= oldexists; msgno++) {
	if (flagreport[msgno] && flagreport[msgno] < LAST_UPDATED(msgno)) {
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
index_checkseen(mailbox, quiet, usinguid, oldexists)
struct mailbox *mailbox;
int quiet;
int usinguid;
int oldexists;
{
    int r;
    time_t last_read, last_change;
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
    r = seen_lockread(seendb, &last_read, &last_uid, &last_change,
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
    while (isdigit(*old)) oldnext = oldnext * 10 + *old++ - '0';
    while (isdigit(*new)) newnext = newnext * 10 + *new++ - '0';

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
		while (isdigit(*old)) oldnext = oldnext * 10 + *old++ - '0';
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
		while (isdigit(*new)) newnext = newnext * 10 + *new++ - '0';
		newnext += newseen;
	    }
	}

	if (oldseen != newseen) {
	    if (seenflag[msgno] != newseen) {
		seenflag[msgno] = newseen;
		if (!quiet && msgno <= oldexists && flagreport[msgno]) {
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
	else if (seenflag[msgno] != newseen) {
	    dirty++;
	}
    }

    if (dirty) {
	last_change = time((time_t *)0);
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
	    if (msgno == imapd_exists + 1) {
		toimsp(mailbox->name, mailbox->uidvalidity,
		       "SEENsnn", imapd_userid, mailbox->last_uid,
		       last_change, 0);
	    }
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
	    while (isdigit(*new)) newnext = newnext * 10 + *new++ - '0';
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
		while (isdigit(*new)) newnext = newnext * 10 + *new++ - '0';
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
    r = seen_write(seendb, last_read, last_uid, last_change, saveseenuids);
    seen_unlock(seendb);
    free(seenuids);
    if (r) {
	prot_printf(imapd_out, "* OK %s: %s\r\n",
	       error_message(IMAP_NO_CHECKSEEN), error_message(r));
	free(saveseenuids);
	seenuids = newseenuids;
	return;
    }

    if (newallseen) {
	toimsp(mailbox->name, mailbox->uidvalidity, "SEENsnn", imapd_userid,
	       mailbox->last_uid, last_change, 0);
    }
    else if (allseen == mailbox->last_uid) {
	toimsp(mailbox->name, mailbox->uidvalidity, "SEENsnn", imapd_userid,
	       0, last_change, 0);
    }
    
    free(newseenuids);
    seenuids = saveseenuids;
}


/*
 * Perform a FETCH-related command on a sequence.
 */
index_fetch(mailbox, sequence, usinguid, fetchargs)
struct mailbox *mailbox;
char *sequence;
int usinguid;
struct fetchargs *fetchargs;
{
    index_forsequence(mailbox, sequence, usinguid,
		      index_fetchreply, (char *)fetchargs);
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
			  index_storeseen, (char *)storeargs);
	return 0;
    }

    mailbox_read_acl(mailbox);
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
		mailbox->flagname[emptyflag] = strsave(flag[i]);
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
			  index_storeflag, (char *)storeargs);

    mailbox_unlock_index(mailbox);

    /* Refresh the index file, for systems without mmap() */
    map_refresh(fileno(mailbox->index), 0, &index_base, &index_len,
		start_offset + imapd_exists * record_size,
		"index", mailbox->name);

    return r;
}

/*
 * Performs a SEARCH command
 */
index_search(mailbox, searchargs, usinguid)
struct mailbox *mailbox;
struct searchargs *searchargs;
int usinguid;
{
    unsigned msgno;
    struct mapfile msgfile;

    msgfile.fd = -1;
    msgfile.base = 0;
    msgfile.size = 0;

    prot_printf(imapd_out, "* SEARCH");

    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	if (index_search_evaluate(mailbox, searchargs, msgno, &msgfile)) {
	    prot_printf(imapd_out, " %u", usinguid ? UID(msgno) : msgno);
	}
	if (msgfile.fd != -1) {
	    map_free(&msgfile.base, &msgfile.size);
	    close(msgfile.fd);
	    msgfile.fd = -1;
	}
    }
    prot_printf(imapd_out, "\r\n");
}

/*
 * Performs a COPY command
 */
int
index_copy(mailbox, sequence, usinguid, name)
struct mailbox *mailbox;
char *sequence;
int usinguid;
char *name;
{
    static struct copyargs copyargs;
    int i;
    unsigned long totalsize = 0;
    int r;
    struct mailbox append_mailbox;

    copyargs.nummsg = 0;
    index_forsequence(mailbox, sequence, usinguid, index_copysetup,
		      (char *)&copyargs);

    for (i = 0; i < copyargs.nummsg; i++) {
	totalsize += copyargs.copymsg[i].size;
    }

    r = append_setup(&append_mailbox, name, MAILBOX_FORMAT_NORMAL,
		     ACL_INSERT, totalsize);
    if (r) return r;

    r = append_copy(mailbox, &append_mailbox, copyargs.nummsg,
		    copyargs.copymsg, imapd_userid);
    mailbox_close(&append_mailbox);

    return r;
}

/*
 * Performs a STATUS commadn
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
	    char *base;
	    unsigned long len = 0;
	    int msg;
	    unsigned uid;

	    map_refresh(fileno(mailbox->index), 0, &base, &len,
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
 * Returns the msgno of the message with UID 'uid'.
 * If no message with UID 'uid', returns the message with
 * the higest UID not greater than 'uid'.
 */
int
index_finduid(uid)
int uid;
{
    int low=1, high=imapd_exists;
    int mid, miduid;

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
 * Call a function 'proc' on each message in 'sequence'.  If 'usinguid'
 * is nonzero, 'sequence' is interpreted as a sequence of UIDs instead
 * of a sequence of msgnos.  'proc' is called with arguments 'mailbox',
 * the msgno, and 'rock'.  If any invocation of 'proc' returns nonzero,
 * returns the first such returned value.  Otherwise, returns zero.
 */
static int
index_forsequence(mailbox, sequence, usinguid, proc, rock)
struct mailbox *mailbox;
char *sequence;
int usinguid;
int (*proc)();
char *rock;
{
    int i, start = 0, end;
    int r, result = 0;

    for (;;) {
	if (isdigit(*sequence)) {
	    start = start*10 + *sequence - '0';
	}
	else if (*sequence == '*') {
	    sequence++;
	    start = usinguid ? UID(imapd_exists) : imapd_exists;
	}
	else if (*sequence == ':') {
	    end = 0;
	    sequence++;
	    while (isdigit(*sequence)) {
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
    int i, start = 0, end;

    for (;;) {
	if (isdigit(*sequence)) {
	    start = start*10 + *sequence - '0';
	}
	else if (*sequence == '*') {
	    sequence++;
	    start = usinguid ? UID(imapd_exists) : imapd_exists;
	}
	else if (*sequence == ':') {
	    end = 0;
	    sequence++;
	    while (isdigit(*sequence)) {
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
static
index_fetchmsg(msg_base, msg_size, format, offset, size,
	       start_octet, octet_count)
char *msg_base;
unsigned long msg_size;
int format;
unsigned offset;
unsigned size;
unsigned start_octet;
unsigned octet_count;
{
    char *line, *p;
    int n;

    /* partial fetch: adjust 'size', normalize 'start_octet' to be 0-based */
    if (start_octet) {
	if (size < start_octet) {
	    size = 0;
	}
	else {
	    size -= start_octet - 1;
	}
	if (size > octet_count) size = octet_count;
	start_octet--;
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
		else if (!start_octet--) {
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
static
index_fetchsection(msg_base, msg_size, format, section, cacheitem,
		   start_octet, octet_count)
char *msg_base;
unsigned long msg_size;
int format;
char *section;
char *cacheitem;
int start_octet;
int octet_count;
{
    char *p;
    int skip;
    int fetchmime = 0;

    cacheitem += 4;
    p = section;

    /* Special-case BODY[] */
    if (*p == ']') {
	p++;
	if (*p == '<') {
	    p++;
	    start_octet = octet_count = 0;
	    while (isdigit(*p)) start_octet = start_octet * 10 + *p++ - '0';
	    p++;			/* Skip over '.' */
	    while (isdigit(*p)) octet_count = octet_count * 10 + *p++ - '0';
	    start_octet++;
	}

	index_fetchmsg(msg_base, msg_size, format, 0, msg_size,
		       start_octet, octet_count);
	return;
    }

    while (*p != ']' && *p != 'M') {
	skip = 0;
	while (isdigit(*p)) skip = skip * 10 + *p++ - '0';
	if (*p == '.') p++;

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
	
	/* section number too large */
	if (skip >= CACHE_ITEM_BIT32(cacheitem)) goto badpart;

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
	while (isdigit(*p)) start_octet = start_octet * 10 + *p++ - '0';
	p++;			/* Skip over '.' */
	while (isdigit(*p)) octet_count = octet_count * 10 + *p++ - '0';
	start_octet++;
    }

    index_fetchmsg(msg_base, msg_size, format, CACHE_ITEM_BIT32(cacheitem),
		   CACHE_ITEM_BIT32(cacheitem+4),
		   start_octet, octet_count);
    return;

 badpart:
    prot_printf(imapd_out, "NIL");
}

/*
 * Helper function to read a header section into a static buffer
 */
static char *
index_readheader(msg_base, msg_size, format, offset, size)
char *msg_base;
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
	while (endline = memchr(msg_base, '\n', left)) {
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
static
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
static
index_fetchheader(msg_base, msg_size, format, size, headers, headers_not)
char *msg_base;
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
static
index_fetchcacheheader(msgno, headers)
unsigned msgno;
struct strlist *headers;
{
    static char *buf;
    static int bufsize;
    char *cacheitem;
    unsigned size;

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
    prot_printf(imapd_out, "{%u}\r\n%s\r\n", size+2, buf);
}

/*
 * Send a * FLAGS response.
 */
static int
index_listflags(mailbox)
struct mailbox *mailbox;
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
    prot_printf(imapd_out, ")] \r\n");
}

/*
 * Helper function to send * FETCH (FLAGS data.
 * Does not send the terminating close paren or CRLF.
 * Also sends preceeding * FLAGS if necessary.
 */
static int
index_fetchflags(mailbox, msgno, system_flags, user_flags, last_updated)
struct mailbox *mailbox;
unsigned msgno;
bit32 system_flags;
bit32 user_flags[MAX_USER_FLAGS/32];
time_t last_updated;
{
    int sepchar = '(';
    unsigned flag;
    bit32 flagmask;

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
int msgno;
char *rock;
{
    struct fetchargs *fetchargs = (struct fetchargs *)rock;    
    int fetchitems = fetchargs->fetchitems;
    int msgfd = -1;
    char *msg_base = 0;
    unsigned long msg_size = 0;
    struct stat sbuf;
    int sepchar;
    int i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    char *cacheitem;
    struct strlist *section;
    char *partialdot;

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_RFC822|FETCH_UNCACHEDHEADER)) ||
	fetchargs->bodysections || fetchargs->headers_not) {
	msgfd = open(mailbox_message_fname(mailbox, UID(msgno)), O_RDONLY,
		     0666);
	if (msgfd == -1) {
	    prot_printf(imapd_out, "* OK ");
	    prot_printf(imapd_out, error_message(IMAP_NO_MSGGONE), msgno);
	    prot_printf(imapd_out, "\r\n");
	}
	else {
	    if (fstat(msgfd, &sbuf) == -1) {
		syslog(LOG_ERR, "IOERROR: fstat on %s: %m",
		       mailbox_message_fname(mailbox, UID(msgno)));
		fatal("can't fstat message file", EX_OSFILE);
	    }
	    map_refresh(msgfd, 1, &msg_base, &msg_size, sbuf.st_size,
			"message file", mailbox->name);
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

	if (tm->tm_year < 80) {
	    abort();
	}
	if (gmtoff < 0) {
	    gmtoff = -gmtoff;
	    gmtnegative = 1;
	}
	gmtoff /= 60;
	sprintf(datebuf, "%2u-%s-%u %.2u:%.2u:%.2u %c%.2u%.2u",
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
    else if ((fetchitems & FETCH_UNCACHEDHEADER) || fetchargs->headers_not) {
	prot_printf(imapd_out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchheader(msg_base, msg_size, mailbox->format,
			  HEADER_SIZE(msgno),
			  fetchargs->headers, fetchargs->headers_not);
    }
    else if (fetchargs->headers) {
	prot_printf(imapd_out, "%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchcacheheader(msgno, fetchargs->headers);
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
			   cacheitem,
			   fetchargs->start_octet, fetchargs->octet_count);
    }
    prot_printf(imapd_out, ")\r\n");
    if (msgfd != -1) {
	map_free(&msg_base, &msg_size);
	close(msgfd);
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
int msgno;
char *rock;
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
int msgno;
char *rock;
{
    struct storeargs *storeargs = (struct storeargs *)rock;
    int i;
    struct index_record record;
    int uid = UID(msgno);
    int low=1, high=mailbox->exists;
    int mid;
    int r;
    int firsttry = 1;
    int seendirty = 0, dirty = 0;

    /* Change \Seen flag */
    if (storeargs->operation == STORE_REPLACE && (mailbox->myrights&ACL_SEEN)) {
	if (seenflag[msgno] != storeargs->seen) seendirty++;
	seenflag[msgno] = storeargs->seen;
    }
    else if (storeargs->seen) {
	i = (storeargs->operation == STORE_ADD) ? 1 : 0;
	if (seenflag[msgno] != i) seendirty++;
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
	record.system_flags &= ~storeargs->system_flags;
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    if (record.user_flags[i] & storeargs->user_flags[i]) dirty++;
	    record.user_flags[i] &= ~storeargs->user_flags[i];
	}
    }

    if (dirty || seendirty) {
	if (dirty) {
	    /* If .SILENT, assume client has updated their cache */
	    if (storeargs->silent && flagreport[msgno] &&
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
    }
    return 0;
}

/*
 * Evaluate a searchargs structure on a msgno
 */
static int
index_search_evaluate(mailbox, searchargs, msgno, msgfile)
struct mailbox *mailbox;
struct searchargs *searchargs;
int msgno;
struct mapfile *msgfile;
{
    int i;
    struct strlist *l, *h;
    char *cacheitem;
    int cachelen;
    struct searchsub *s;
    struct stat sbuf;

    if (searchargs->recent_set && msgno <= lastnotrecent) return 0;
    if (searchargs->recent_unset && msgno > lastnotrecent) return 0;
    if (searchargs->peruser_flags_set && !seenflag[msgno]) return 0;
    if (searchargs->peruser_flags_unset && seenflag[msgno]) return 0;

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
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip from */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->to; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip to */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->cc; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip cc */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->bcc; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) return 0;
	}

	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip subject */
	cachelen = CACHE_ITEM_LEN(cacheitem);

	for (l = searchargs->subject; l; l = l->next) {
	    if (!charset_searchstring(l->s, l->p, cacheitem+4, cachelen)) return 0;
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

    if (searchargs->body || searchargs->text || searchargs->header) {
	if (msgfile->fd == -1) {
	    msgfile->fd = open(mailbox_message_fname(mailbox, UID(msgno)),
			       O_RDONLY, 0666);
	    if (msgfile->fd == -1 || fstat(msgfile->fd, &sbuf) == -1) {
		return 0;
	    }
	    map_refresh(msgfile->fd, 1, &msgfile->base, &msgfile->size,
			sbuf.st_size, "message file", mailbox->name);
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
char *cacheitem;
{
    int partsleft = 1;
    int subparts;
    int start, len, charset, encoding;
    char *p;
    
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
		    p = charset_decode1522(p);
		    if (charset_searchstring(substr, pat, p, strlen(p))) {
			return 1;
		    }
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
    char *p;
    static struct strlist header;

    header.s = name;

    p = index_readheader(msgfile->base, msgfile->size, format, 0, size);
    index_pruneheader(p, &header, 0);
    p = charset_decode1522(p);
    return charset_searchstring(substr, pat, p, strlen(p));
}

/*
 * Helper function to set up arguments to append_copy()
 */
#define COPYARGSGROW 30
static int
index_copysetup(mailbox, msgno, rock)
struct mailbox *mailbox;
int msgno;
char *rock;
{
    struct copyargs *copyargs = (struct copyargs *)rock;
    int flag = 0;
    unsigned userflag;
    bit32 flagmask;

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
