/*
 * Routines for dealing with the index file in the imapd
 */
#include <stdio.h>
#include <time.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <com_err.h>

#include <acl.h>
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
#include "message.h"
#include "xmalloc.h"

/* The index and cache files, mapped into memory */
static char *index_base;
static unsigned long index_len;
static char *cache_base;
static unsigned long cache_len;

/* Attributes of memory-mapped index file */
static time_t index_ino;
static unsigned long start_offset;
static unsigned long record_size;

static unsigned recentuid;		/* UID of last non-\Recent message */
static unsigned lastnotrecent;	/* Msgno of last non-\Recent message */

static time_t *flagreport;	/* Array for each msgno of last_updated when
				 * FLAGS data reported to client.
				 * Zero if FLAGS data never reported */
static char *seenflag;		/* Array for each msgno, nonzero if \Seen */
static int flagalloced = -1;	/* Allocated size of above two arrays */
static int keepingseen;		/* Nonzero if /Seen is meaningful */
struct seen *seendb;		/* Seen state database object */
static char *seenuids;		/* Sequence of UID's from last seen checkpoint */

/* Access macros for the memory-mapped index file data */
#define INDEX_OFFSET(msgno) (index_base+start_offset+(((msgno)-1)*record_size))
#define UID(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno))))
#define INTERNALDATE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+4)))
#define SIZE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+8)))
#define HEADER_SIZE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+12)))
#define CONTENT_OFFSET(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+16)))
#define CACHE_OFFSET(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+20)))
#define LAST_UPDATED(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+24)))
#define SYSTEM_FLAGS(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+28)))
#define USER_FLAGS(msgno,i) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+32+((i)*4))))

/* Access assistance macros for memory-mapped cache file data */
#define CACHE_ITEM_LEN(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

/* Forward declarations */
static int index_fetchreply();
static int index_storeseen();
static int index_storeflag();

/*
 * A new mailbox has been selected, map it into memory and do the
 * initial CHECK.
 */
index_newmailbox(mailbox)
struct mailbox *mailbox;
{
    keepingseen = (mailbox->my_acl & ACL_SEEN);
    recentuid = 0;
    if (seendb) {
	seen_close(seendb);
	seendb = 0;
    }
    index_listflags(mailbox);
    if (index_len) {
	munmap(index_base, index_len);
	munmap(cache_base, cache_len);
	index_len = cache_len = 0;
    }
    imapd_exists = -1;

    index_check(mailbox, 0, 1);
}

#define SLOP 50
#define CACHESLOP (8*1024)

/*
 * Check for and report updates
 */
index_check(mailbox, usinguid, checkseen)
struct mailbox *mailbox;
int usinguid;
int checkseen;
{
    struct stat sbuf;
    int newexists, oldexists, msgno, i, r;
    time_t last_read;
    bit32 user_flags[MAX_USER_FLAGS/32];

    oldexists = imapd_exists;

#if 0	/* XXX implement when doing EXPUNGE */
    if (index_len && mailbox_new_index_header(mailbox)) {
	/* XXX send EXPUNGE oldexists-- */
	imapd_exists = -1;
    }
#else
    fstat(fileno(mailbox->index), &sbuf);
    if (mailbox->index_mtime != sbuf.st_mtime) {
	mailbox_read_index_header(mailbox);
    }
#endif
    index_ino = mailbox->index_ino;

    start_offset = mailbox->start_offset;
    record_size = mailbox->record_size;

    /* Re-mmap the index file if necessary */
    if (mailbox->index_size > index_len) {
	if (index_len) munmap(index_base, index_len);
	index_len =  mailbox->index_size + (SLOP*record_size);
	index_base = (char *)mmap((caddr_t)0, index_len, PROT_READ,
				  MAP_SHARED, fileno(mailbox->index), 0L);
    
	if (index_base == (char *)-1) {
	    fatal("failed to mmap index file", EX_IOERR);
	}
    }

    /* Re-mmap the cache file if necessary */
    if (fstat(fileno(mailbox->cache), &sbuf) == -1) {
	fatal("failed to stat cache file", EX_IOERR);
    }
    if (cache_len <= sbuf.st_size) {
	if (cache_len) munmap(cache_base, cache_len);
	cache_len = sbuf.st_size + CACHESLOP;
	cache_base = (char *)mmap((caddr_t)0, cache_len, PROT_READ,
				  MAP_SHARED, fileno(mailbox->cache), 0L);

	if (cache_base == (char *)-1) {
	    fatal("failed to mmap cache file", EX_IOERR);
	}
    }

    /* Calculate the new number of messages */
    newexists = (mailbox->index_size - start_offset) / record_size;

    /* If opening mailbox, get \Recent info */
    if (oldexists == -1 && keepingseen) {
	r = seen_open(mailbox, imapd_userid, &seendb);
	if (!r) {
	    r = seen_lockread(seendb, &last_read, &recentuid, &seenuids);
	    if (r) seen_close(seendb);
	}
	if (r) {
	    seendb = 0;
	    printf("* NO Unable to preserve \\Seen information: %s\r\n",
		   error_message(r));
	}
	else {
	    /* Record our reading the mailbox */
	    (void) seen_write(seendb, time((time_t *)0), mailbox->last_uid,
			      seenuids);
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

	for (i = imapd_exists+1; i <= newexists; i++) {
	    flagreport[i] = 0;
	    seenflag[i] = 0;
	}
	checkseen = 1;
	imapd_exists = newexists;
	printf("* %d EXISTS\r\n* %d RECENT\r\n", imapd_exists, imapd_exists-lastnotrecent);
    }

    /* Check Flags */
    if (checkseen) index_checkseen(mailbox, 0, usinguid, oldexists);
    for (msgno = 1; msgno <= oldexists; msgno++) {
	if (flagreport[msgno] && flagreport[msgno] < LAST_UPDATED(msgno)) {
	    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
		user_flags[i] = USER_FLAGS(msgno, i);
	    }
	    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
			     LAST_UPDATED(msgno));
	    if (usinguid) printf(" UID %d", UID(msgno));
	    printf(")\r\n");
	}
    }
}

/*
 * Checkpoint the user's \Seen state
 */
#define SAVEGROW 30 /* XXX 200 */
index_checkseen(mailbox, quiet, usinguid, oldexists)
struct mailbox *mailbox;
int quiet;
int usinguid;
int oldexists;
{
    int r;
    time_t last_time;
    unsigned last_uid;
    char *newseenuids;
    char *old, *new;
    int oldnext = 0, oldseen = 0;
    int newnext = 0, newseen = 0;
    int neweof = 0;
    int msgno, uid, dirty = 0;
    int i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    char *saveseenuids, *save;
    int savealloced;
    int start, inrange, usecomma;

    if (!keepingseen || !seendb) return;
    if (imapd_exists == 0) {
	seen_unlock(seendb);
	return;
    }

    /* Lock \Seen database and read current values */
    r = seen_lockread(seendb, &last_time, &last_uid, &newseenuids);
    if (r) {
	printf("* NO Unable to checkpoint \\Seen state: %s\r\n",
	       error_message(r));
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
		    if (usinguid) printf(" UID %d", UID(msgno));
		    printf(")\r\n");
		}
	    }
	}
	else if (seenflag[msgno] != newseen) {
	    dirty++;
	}
    }

    /* If there's nothing to save back to the database, clean up and return */
    if (!dirty) {
	seen_unlock(seendb);
	free(seenuids);
	seenuids = newseenuids;
	return;
    }
    
    /* Build the seenuids string to save to the database */
    start = 1;
    inrange = 1;
    usecomma = 0;
    savealloced = SAVEGROW;
    save = saveseenuids = xmalloc(savealloced);
    *save = '\0';
    for (msgno = 1; msgno <= imapd_exists; msgno++) {
	uid = UID(msgno);
	if (seenflag[msgno] != inrange) {
	    if (inrange) {
		if (start == uid-1) {
		    if (usecomma++) *save++ = ',';
		    sprintf(save, "%d", start);
		    save += strlen(save);
		}
		else if (uid > 1) {
		    if (usecomma++) *save++ = ',';
		    sprintf(save, "%d:", start);
		    save += strlen(save);
		    sprintf(save, "%d", uid-1);
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
	    sprintf(save, "%d:", start);
	    save += strlen(save);
	}
	sprintf(save, "%d", uid);
	save += strlen(save);

	if (!neweof && !newseen) {
	    /* Parsed a lone number */
	    if (usecomma++) *save++ = ',';
	    sprintf(save, "%d", newnext);
	    save += strlen(save);
	}
    }
    else if (newseen && newnext > uid+1) {
	/* We parsed a range which went past uid.  Include it in output */
	if (usecomma++) *save++ = ',';
	if (newnext > uid+2) {
	    sprintf(save, "%d:", uid+1);
	    save += strlen(save);
	}
	sprintf(save, "%d", newnext-1);
	save += strlen(save);
    }
    else if (*new == ':') {
	/* Parsed first half of a range.  Write it out */
	if (usecomma++) *save++ = ',';
	sprintf(save, "%d", uid+1);
	save += strlen(save);
    }
    else if (!neweof && !newseen) {
	/* Parsed a lone number */
	if (usecomma++) *save++ = ',';
	sprintf(save, "%d", newnext);
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
    r = seen_write(seendb, last_time, last_uid, saveseenuids);
    seen_unlock(seendb);
    free(seenuids);
    if (r) {
	printf("* NO Unable to checkpoint \\Seen state: %s\r\n",
	       error_message(r));
	free(saveseenuids);
	seenuids = newseenuids;
	return;
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
    long my_acl = mailbox->my_acl;

    /* Handle simple case of just changing /Seen */
    if (storeargs->operation != STORE_REPLACE &&
	!storeargs->system_flags && !nflags) {
	if (!storeargs->seen) return 0; /* Nothing to change */
	if (!(my_acl & ACL_SEEN)) return IMAP_PERMISSION_DENIED;
	storeargs->usinguid = usinguid;

	index_forsequence(mailbox, sequence, usinguid,
			  index_storeseen, (char *)storeargs);
	return 0;
    }

    mailbox_read_acl(mailbox);
    my_acl &= mailbox->my_acl;

    /* First pass at checking permission */
    if ((storeargs->seen && !(my_acl & ACL_SEEN)) ||
	((storeargs->system_flags & FLAG_DELETED) &&
	 !(my_acl & ACL_DELETE)) ||
	(((storeargs->system_flags & ~FLAG_DELETED) || nflags) &&
	 !(my_acl & ACL_WRITE))) {
	mailbox->my_acl = my_acl;
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
		    mailbox->my_acl = my_acl;

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
	mailbox->my_acl = my_acl;
	if (r) return r;
    }
    /* Not reading header anymore--can put back our working ACL */
    mailbox->my_acl = my_acl;

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
    storeargs->exists =
      (mailbox->index_size - mailbox->start_offset) / mailbox->record_size;
    storeargs->usinguid = usinguid;

    r = mailbox_lock_index(mailbox);
    if (r) return r;

    r = index_forsequence(mailbox, sequence, usinguid,
			  index_storeflag, (char *)storeargs);

    mailbox_unlock_index(mailbox);
    return r;
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
	else if (*sequence == ':') {
	    end = 0;
	    sequence++;
	    while (isdigit(*sequence)) {
		end = end*10 + *sequence++ - '0';
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
 * Helper function to fetch data from a message file.
 * Writes a quoted-string or literal containing data from
 * 'msgfile', which is of format 'format', starting at 'offset'
 * and containing 'size' octets.  If 'start_octet' is nonzero, the data
 * is further constrained by 'start_octet' and 'octet_count' as per
 * the IMAP command PARTIAL.
 */
static
index_fetchmsg(msgfile, format, offset, size, start_octet, octet_count)
FILE *msgfile;
int format;
int offset;
int size;
int start_octet;
int octet_count;
{
    char buf[4096], *p;
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
    if (!msgfile || size == 0) {
	printf("\"\"");
	return;
    }

    /* Write size of literal */
    printf("{%d}\r\n", size);

    if (format == MAILBOX_FORMAT_NETNEWS) {
	/* Have to fetch line-by-line, converting LF to CRLF */
	fseek(msgfile, offset, 0);
	while (size) {
	    if (!fgets(buf, sizeof(buf)-1, msgfile)) {
		/* Read error, resynch client */
		while (size--) putc(' ', stdout);
		return;
	    }
	    p = buf + strlen(buf);
	    if (p[-1] == '\n') {
		p[-1] = '\r';
		*p++ = '\n';
		*p = '\0';
	    }
	    n = p - buf;
	    if (start_octet >= n) {
		/* Skip over entire line */
		start_octet -= n;
	    }
	    else {
		/* Skip over (possibly zero) first part of line */
		n -= start_octet;
		fwrite(buf + start_octet, 1, n, stdout);
		start_octet = 0;
		size -= n;
	    }
	}
    }
    else {
	/* Seek over PARTIAL constraint, do fetch in buf-size chunks */
	offset += start_octet;
	fseek(msgfile, offset, 0);
	while (size) {
	    n = fread(buf, 1, size>sizeof(buf) ? sizeof(buf) : size, msgfile);
	    if (n == 0) {
		/* Read error, resynch client */
		while (size--) putc(' ', stdout);
		return;
	    }
	    fwrite(buf, 1, n, stdout);
	    size -= n;
	}
    }
}

/*
 * Send a * FLAGS response.
 */
static int
index_listflags(mailbox)
struct mailbox *mailbox;
{
    int i;

    printf("* FLAGS (\\Answered \\Flagged \\Deleted");
    if (keepingseen) {
	printf(" \\Seen");
    }
    for (i = 0; i < MAX_USER_FLAGS; i++) {
	if (mailbox->flagname[i]) {
	    printf(" %s", mailbox->flagname[i]);
	}
    }
    printf(")\r\n");
}

/*
 * Helper function to send * FETCH (FLAGS data.
 * Does not send the terminating close paren or CRLF.
 * Also sends preceeding * FLAGS if necessary.
 */
static int
index_fetchflags(mailbox, msgno, system_flags, user_flags, last_updated)
struct mailbox *mailbox;
int msgno;
bit32 system_flags;
bit32 user_flags[MAX_USER_FLAGS/32];
time_t last_updated;
{
    int sepchar = '(';
    unsigned flag;
    bit32 flagmask;
    long my_acl;

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if ((flag & 31) == 0) {
	    flagmask = user_flags[flag/32];
	}
	if (!mailbox->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    my_acl = mailbox->my_acl;
	    mailbox_read_header(mailbox);
	    mailbox->my_acl = my_acl;

	    index_listflags(mailbox);
	    break;
	}
    }

    printf("* %d FETCH (FLAGS ", msgno);

    if (msgno > lastnotrecent) {
	printf("%c\\Recent", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_ANSWERED) {
	printf("%c\\Answered", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_FLAGGED) {
	printf("%c\\Flagged", sepchar);
	sepchar = ' ';
    }
    if (system_flags & FLAG_DELETED) {
	printf("%c\\Deleted", sepchar);
	sepchar = ' ';
    }
    if (seenflag[msgno]) {
	printf("%c\\Seen", sepchar);
	sepchar = ' ';
    }
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if ((flag & 31) == 0) {
	    flagmask = user_flags[flag/32];
	}
	if (mailbox->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
	    printf("%c%s", sepchar, mailbox->flagname[flag]);
	    sepchar = ' ';
	}
    }
    if (sepchar == '(') putc('(', stdout);
    putc(')', stdout);

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
    FILE *msgfile = 0;
    int sepchar;
    int i;
    bit32 user_flags[MAX_USER_FLAGS/32];
    char *cacheitem;

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_RFC822)) ||
	fetchargs->bodyparts || fetchargs->headers || fetchargs->headers_not) {
	msgfile = fopen(message_fname(mailbox, UID(msgno)), "r");
	if (!msgfile) printf("* NO Message %d no longer exists\r\n", msgno);
    }

    /* set the \Seen flag if necessary */
    if ((fetchitems & (FETCH_TEXT|FETCH_RFC822)) || fetchargs->bodyparts) {
	if (!seenflag[msgno] && (mailbox->my_acl & ACL_SEEN)) {
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
	printf("* %d FETCH ", msgno);
	sepchar = '(';
    }
    if (fetchitems & FETCH_UID) {
	printf("%cUID %d", sepchar, UID(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_INTERNALDATE) {
	time_t msgdate = INTERNALDATE(msgno);
	struct tm *tm = localtime(&msgdate);
	long gmtoff = tm->tm_gmtoff;
	static char *monthname[] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	if (gmtoff < 0) gmtoff = -gmtoff;
	gmtoff /= 60;
	printf("%cINTERNALDATE \"%2d-%s-%d %.2d:%.2d:%.2d %c%.2d%.2d\"",
	       sepchar, tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
	       tm->tm_hour, tm->tm_min, tm->tm_sec,
	       tm->tm_gmtoff < 0 ? '-' : '+', gmtoff/60, gmtoff%60);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_SIZE) {
	printf("%cRFC822.SIZE %d", sepchar, SIZE(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_ENVELOPE) {
	printf("%cENVELOPE ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	fwrite(cacheitem+4, 1, CACHE_ITEM_LEN(cacheitem), stdout);
    }
    if (fetchitems & FETCH_BODYSTRUCTURE) {
	printf("%cBODYSTRUCTURE ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	fwrite(cacheitem+4, 1, CACHE_ITEM_LEN(cacheitem), stdout);
    }
    if (fetchitems & FETCH_BODY) {
	printf("%cBODY ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	fwrite(cacheitem+4, 1, CACHE_ITEM_LEN(cacheitem), stdout);
    }

    if (fetchitems & FETCH_HEADER) {
	printf("%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msgfile, mailbox->format, 0, HEADER_SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    else if (fetchargs->headers_not) {
	/* XXX todo */
    }
    else if (fetchargs->headers) {
	/* XXX todo */
    }

    if (fetchitems & FETCH_TEXT) {
	printf("%cRFC822.TEXT ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msgfile, mailbox->format, CONTENT_OFFSET(msgno),
		       SIZE(msgno) - HEADER_SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    if (fetchitems & FETCH_RFC822) {
	printf("%cRFC822 ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msgfile, mailbox->format, 0, SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    /* XXX body[x] */
    printf(")\r\n");
    if (msgfile) fclose(msgfile);
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

    for (i=0; i < MAX_USER_FLAGS/32; i++) {
	user_flags[i] = USER_FLAGS(msgno, i);
    }
    index_fetchflags(mailbox, msgno, SYSTEM_FLAGS(msgno), user_flags,
		     LAST_UPDATED(msgno));
    if (storeargs->usinguid) {
	printf(" UID %d", UID(msgno));
    }
    printf(")\r\n");

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
    int low=1, high=storeargs->exists;
    int mid;
    int r;
    int firsttry = 1;
    int seendirty = 0, dirty = 0;

    /* Change \Seen flag */
    if (storeargs->operation == STORE_REPLACE && (mailbox->my_acl&ACL_SEEN)) {
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
	if (!(mailbox->my_acl & ACL_WRITE)) {
	    record.system_flags = (record.system_flags&~FLAG_DELETED) |
	      (storeargs->system_flags&FLAG_DELETED);
	}
	else {
	    if (!(mailbox->my_acl & ACL_DELETE)) {
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
	    record.last_updated =
	      (record.last_updated >= storeargs->update_time) ?
		record.last_updated + 1 : storeargs->update_time;
	}
	index_fetchflags(mailbox, msgno, record.system_flags,
			 record.user_flags, record.last_updated);
	if (storeargs->usinguid) {
	    printf(" UID %d", UID(msgno));
	}
	printf(")\r\n");

	if (dirty && mid) {
	    r = mailbox_write_index_record(mailbox, mid, &record);
	    if (r) return r;
	}
    }
    return 0;
}

	
	    
