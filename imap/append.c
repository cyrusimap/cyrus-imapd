/* append.c -- Routines for appending messages to a mailbox
 * $Id: append.c,v 1.95 2002/12/02 22:30:22 leg Exp $
 *
 * Copyright (c)1998, 2000 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <com_err.h>
#include <sys/types.h>
#include <syslog.h>
#include <sys/stat.h>

#include "acl.h"
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "append.h"
#include "imapconf.h"
#include "prot.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "seen.h"
#include "retry.h"

struct stagemsg {
    char fname[1024];

    /* the parts buffer consists of
       /part1/stage./file \0
       /part2/stage./file \0
       ... \0
       \0
       
       the main invariant is double \0 at the end
    */
    char *parts; /* buffer of current stage parts */
    char *partend; /* end of buffer */
};

static int append_addseen(struct mailbox *mailbox, const char *userid,
			  const char *msgrange);
static void addme(char **msgrange, int *alloced, long uid);

#define zero_index(i) { memset(&i, 0, sizeof(struct index_record)); }

/*
 * Check to see if mailbox can be appended to
 *
 * Arguments:
 *	name	   - name of mailbox directory
 *	format     - mailbox must be of this format
 *	aclcheck   - user must have these rights on mailbox ACL
 *	quotacheck - mailbox must have this much quota left
 *		     (-1 means don't care about quota)
 *
 */
int append_check(const char *name, int format, 
		 struct auth_state *auth_state,
		 long aclcheck, long quotacheck)
{
    struct mailbox m;
    int r;
    int mbflags;
    
    /* Is mailbox moved? */
    r = mboxlist_detail(name, &mbflags, NULL, NULL, NULL, NULL);

    if (!r) {
	if(mbflags & MBTYPE_MOVING) return IMAP_MAILBOX_MOVED;
    } else {
	return r;
    }

    r = mailbox_open_header(name, auth_state, &m);
    if (r) return r;

    if ((m.myrights & aclcheck) != aclcheck) {
	r = (m.myrights & ACL_LOOKUP) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	mailbox_close(&m);
	return r;
    }

    r = mailbox_open_index(&m);
    if (r) {
	mailbox_close(&m);
	return r;
    }

    if (m.format != format) {
	mailbox_close(&m);
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    r = mailbox_read_quota(&m.quota);
    if (r) {
	mailbox_close(&m);
	return r;
    }

    if (m.quota.limit >= 0 && quotacheck >= 0 &&
	m.quota.used + quotacheck > 
	    ((unsigned) m.quota.limit * QUOTA_UNITS)) {
	mailbox_close(&m);
	return IMAP_QUOTA_EXCEEDED;
    }

    mailbox_close(&m);
    return 0;
}

/*
 * Open a mailbox for appending
 *
 * Arguments:
 *	name	   - name of mailbox directory
 *	format     - mailbox must be of this format
 *	aclcheck   - user must have these rights on mailbox ACL
 *	quotacheck - mailbox must have this much quota left
 *		     (-1 means don't care about quota)
 *
 * On success, the struct pointed to by 'as' is set up.
 *
 */
int append_setup(struct appendstate *as, const char *name,
		 int format, 
		 const char *userid, struct auth_state *auth_state,
		 long aclcheck, long quotacheck)
{
    int r;

    r = mailbox_open_header(name, auth_state, &as->m);
    if (r) return r;

    if ((as->m.myrights & aclcheck) != aclcheck) {
	r = (as->m.myrights & ACL_LOOKUP) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	mailbox_close(&as->m);
	return r;
    }

    r = mailbox_lock_header(&as->m);
    if (r) {
	mailbox_close(&as->m);
	return r;
    }

    r = mailbox_open_index(&as->m);
    if (r) {
	mailbox_close(&as->m);
	return r;
    }

    if (as->m.format != format) {
	mailbox_close(&as->m);
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    r = mailbox_lock_index(&as->m);
    if (r) {
	mailbox_close(&as->m);
	return r;
    }

    r = mailbox_lock_quota(&as->m.quota);
    if (r) {
	mailbox_close(&as->m);
	return r;
    }

    if (as->m.quota.limit >= 0 && quotacheck >= 0 &&
	as->m.quota.used + quotacheck > 
	    ((unsigned) as->m.quota.limit * QUOTA_UNITS)) {
	mailbox_close(&as->m);
	return IMAP_QUOTA_EXCEEDED;
    }

    if (userid) {
	strcpy(as->userid, userid);
    } else {
	as->userid[0] = '\0';
    }

    /* zero out metadata */
    as->orig_cache_len = as->m.cache_len;
    as->nummsg = as->numanswered = 
	as->numdeleted = as->numflagged = 0;
    as->quota_used = 0;
    as->writeheader = 0;
    as->seen_msgrange = NULL;
    as->seen_alloced = 0;

    as->s = APPEND_READY;
    
    return 0;
}

/* may return non-zero, indicating that the entire append has failed
 and the mailbox is probably in an inconsistent state. */
int append_commit(struct appendstate *as, 
		  unsigned long *uidvalidity, 
		  unsigned long *start,
		  unsigned long *num)
{
    int r = 0;
    
    if (as->s == APPEND_DONE) return 0;

    if (start) *start = as->m.last_uid + 1;
    if (num) *num = as->nummsg;
    if (uidvalidity) *uidvalidity = as->m.uidvalidity;

    /* write out the header if we created new user flags */
    if (as->writeheader && (r = mailbox_write_header(&as->m))) {
	syslog(LOG_ERR, "IOERROR: writing header for %s: %s",
	       as->m.name, error_message(r));
	append_abort(as);
	return r;
    }

    /* flush the new index records */
    if (fsync(as->m.index_fd)) {
	syslog(LOG_ERR, "IOERROR: writing index records for %s: %m",
	       as->m.name);
	append_abort(as);
	return IMAP_IOERROR;
    }

    /* Flush out the cache file data */
    if (fsync(as->m.cache_fd)) {
	syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
	       as->m.name);
	append_abort(as);
	return IMAP_IOERROR;
    }

    /* Calculate new index header information */
    as->m.exists += as->nummsg;
    as->m.last_uid += as->nummsg;
    
    as->m.answered += as->numanswered;
    as->m.deleted += as->numdeleted;
    as->m.flagged += as->numflagged;
    
    as->m.last_appenddate = time(0);
    as->m.quota_mailbox_used += as->quota_used;
    if (as->m.minor_version > MAILBOX_MINOR_VERSION) {
	as->m.minor_version = MAILBOX_MINOR_VERSION;
    }
    
    /* Write out index header & synchronize to disk.
       this writes to acappush too. */
    r = mailbox_write_index_header(&as->m);
    if (r) {
	syslog(LOG_ERR, "IOERROR: writing index header for %s: %s",
	       as->m.name, error_message(r));
	append_abort(as);
	return r;
    }

    /* Write out quota file */
    as->m.quota.used += as->quota_used;
    r = mailbox_write_quota(&as->m.quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record use of %u bytes in quota file %s",
	       as->quota_used, as->m.quota.root);
    }

    /* set seen state */
    if (as->seen_msgrange && as->userid[0]) {
	append_addseen(&as->m, as->userid, as->seen_msgrange);
    }
    if (as->seen_msgrange) {
	free(as->seen_msgrange);
    }

    mailbox_unlock_quota(&as->m.quota);
    mailbox_unlock_index(&as->m);
    mailbox_unlock_header(&as->m);
    mailbox_close(&as->m);

    as->s = APPEND_DONE;

    return 0;
}

/* may return non-zero, indicating an internal error of some sort. */
int append_abort(struct appendstate *as)
{
    int r = 0;
    unsigned long uid;

    if (as->s == APPEND_DONE) return 0;
    as->s = APPEND_DONE;

    /* unlink message files that were created */
    for (uid = as->m.last_uid + 1; uid <= as->m.last_uid + as->nummsg; uid++) {
	char fname[MAX_MAILBOX_PATH];

	/* Create message file */
	strcpy(fname, as->m.path);
	strcat(fname, "/");
	mailbox_message_get_fname(&as->m, uid, fname + strlen(fname));
	if (unlink(fname) < 0) {
	    /* hmmm, never got appended? */
	    /* r = IMAP_IOERROR; */
	}
    }

    /* truncate the cache */
    ftruncate(as->m.cache_fd, as->orig_cache_len);

    /* unlock mailbox */
    mailbox_unlock_quota(&as->m.quota);
    mailbox_unlock_index(&as->m);
    mailbox_unlock_header(&as->m);
    mailbox_close(&as->m);

    if (as->seen_msgrange) {
	free(as->seen_msgrange);
    }

    return r;
}

/*
 * Return the number of stage msgs
 */

int append_stageparts(struct stagemsg *stagep)
{
    if (!stagep) return 0;

    /* xxx count number of active parts */
    return -1;
}

/*
 * staging, to allow for single-instance store.  initializes the stage
 * with the file for the given mailboxname and returns the open file
 * so it can double as the spool file
 */
FILE *append_newstage(const char *mailboxname, time_t internaldate,
		      struct stagemsg **stagep)
{
    struct stagemsg *stage;
    char stagedir[1024], stagefile[1024];
    FILE *f;

    assert(mailboxname != NULL);
    assert(stagep != NULL);

    stage = xmalloc(sizeof(struct stagemsg));
    stage->parts = xzmalloc(5 * MAX_MAILBOX_PATH * sizeof(char));
    stage->partend = stage->parts + 5 * MAX_MAILBOX_PATH * sizeof(char);

    snprintf(stage->fname, sizeof(stage->fname), "%d-%d",
	     (int) getpid(), (int) internaldate);

    /* xxx check errors */
    mboxlist_findstage(mailboxname, stagedir);
    strcpy(stagefile, stagedir);
    strcat(stagefile, stage->fname);

    /* create this file and put it into stage->parts[0] */
    f = fopen(stagefile, "w+");
    if (!f) {
	if (mkdir(stagedir, 0755) != 0) {
	    syslog(LOG_ERR, "couldn't create stage directory: %s: %m",
		   stagedir);
	} else {
	    syslog(LOG_NOTICE, "created stage directory %s",
		   stagedir);
	    f = fopen(stagefile, "w+");
	}
    } 
    if (!f) {
	syslog(LOG_ERR, "IOERROR: creating message file %s: %m", 
	       stagefile);
	*stagep = NULL;
	return NULL;
    }

    strcpy(stage->parts, stagefile);
    /* make sure there's a NUL NUL at the end */
    stage->parts[strlen(stagefile) + 1] = '\0';

    *stagep = stage;
    return f;
}

/*
 * staging, to allow for single-instance store.  the complication here
 * is multiple partitions.
 */
int append_fromstage(struct appendstate *as,
		     struct protstream *messagefile,
		     unsigned long size, time_t internaldate,
		     const char **flag, int nflags,
		     struct stagemsg *stage)
{
    struct mailbox *mailbox = &as->m;
    struct index_record message_index;
    char fname[MAX_MAILBOX_PATH];
    FILE *destfile;
    int i, r;
    int userflag, emptyflag;

    /* for staging */
    char stagefile[MAX_MAILBOX_PATH];
    int sflen;
    char *p;

    assert(stage != NULL && stage->parts[0] != '\0');
    assert(mailbox->format == MAILBOX_FORMAT_NORMAL);
    assert(size != 0);

    zero_index(message_index);

    /* xxx check errors */
    mboxlist_findstage(mailbox->name, stagefile);
    strcat(stagefile, stage->fname);
    sflen = strlen(stagefile);

    p = stage->parts;
    while (p < stage->partend) {
	int sl = strlen(p);

	if (sl == 0) {
	    /* our partition isn't here */
	    break;
	}
	if (!strcmp(stagefile, p)) {
	    /* aha, this is us */
	    break;
	}
	
	p += sl + 1;
    }

    if (*p == '\0') {
	/* ok, create this file, and copy the name of it into 'p'.
	   make sure not to overwrite stage->partend */

	/* create the new staging file from the first stage part */
	r = mailbox_copyfile(stage->parts, stagefile);
	if (r) {
	    /* maybe the directory doesn't exist? */
	    char stagedir[1024];

	    /* xxx check errors */
	    mboxlist_findstage(mailbox->name, stagedir);
	    if (mkdir(stagedir, 0755) != 0) {
		syslog(LOG_ERR, "couldn't create stage directory: %s: %m",
		       stagedir);
	    } else {
		syslog(LOG_NOTICE, "created stage directory %s",
		       stagedir);
		r = mailbox_copyfile(stage->parts, stagefile);
	    }
	}
	if (r) {
	    /* oh well, we tried */

	    syslog(LOG_ERR, "IOERROR: creating message file %s: %m", 
		   stagefile);
	    unlink(stagefile);
	    return r;
	}
	
	if (p + sflen > stage->partend - 5) {
	    int cursize = stage->partend - stage->parts;
	    int curp = p - stage->parts;

	    /* need more room; double the buffer */
	    stage->parts = xrealloc(stage->parts, 2 * cursize);
	    stage->partend = stage->parts + 2 * cursize;
	    p = stage->parts + curp;
	}
	strcpy(p, stagefile);
	/* make sure there's a NUL NUL at the end */
	p[sflen + 1] = '\0';
    }

    /* 'p' contains the message and is on the same partition
       as the mailbox we're looking at */

    /* Setup */
    message_index.uid = mailbox->last_uid + as->nummsg + 1;
    message_index.last_updated = time(0);
    message_index.internaldate = internaldate;
    lseek(mailbox->cache_fd, 0L, SEEK_END);

    /* Create message file */
    as->nummsg++;
    strcpy(fname, mailbox->path);
    strcat(fname, "/");
    mailbox_message_get_fname(mailbox, message_index.uid, 
			      fname + strlen(fname));

    r = mailbox_copyfile(p, fname);
    destfile = fopen(fname, "r");
    if (!r && destfile) {
	/* ok, we've successfully created the file */
	r = message_parse_file(destfile, mailbox, &message_index);
    }
    if (destfile) {
	/* this will hopefully ensure that the link() actually happened
	   and makes sure that the file actually hits disk */
	fsync(fileno(destfile));
	fclose(destfile);
    }
    if (r) {
	append_abort(as);
	return r;
    }

    /* Handle flags the user wants to set in the message */
    for (i = 0; i < nflags; i++) {
	if (!strcmp(flag[i], "\\seen")) {
	    addme(&as->seen_msgrange, &as->seen_alloced, message_index.uid);
	}
	else if (!strcmp(flag[i], "\\deleted")) {
	    if (mailbox->myrights & ACL_DELETE) {
		message_index.system_flags |= FLAG_DELETED;
		as->numdeleted++;
	    }
	}
	else if (!strcmp(flag[i], "\\draft")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_DRAFT;
	    }
	}
	else if (!strcmp(flag[i], "\\flagged")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_FLAGGED;
		as->numflagged++;
	    }
	}
	else if (!strcmp(flag[i], "\\answered")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_ANSWERED;
		as->numanswered++;
	    }
	}
	else if (mailbox->myrights & ACL_WRITE) {
	    /* User flag */
	    emptyflag = -1;
	    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
		if (mailbox->flagname[userflag]) {
		    if (!strcasecmp(flag[i], mailbox->flagname[userflag]))
		      break;
		}
		else if (emptyflag == -1) emptyflag = userflag;
	    }

	    /* Flag is not defined--create it */
	    if (userflag == MAX_USER_FLAGS && emptyflag != -1) {
		userflag = emptyflag;
		mailbox->flagname[userflag] = xstrdup(flag[i]);
		as->writeheader++;
	    }

	    if (userflag != MAX_USER_FLAGS) {
		message_index.user_flags[userflag/32] |= 1<<(userflag&31);
	    }
	}
    }

    /* Write out index file entry */
    r = mailbox_append_index(mailbox, &message_index, 
			     mailbox->exists + as->nummsg - 1, 1, 0);
    if (r) {
	append_abort(as);
	return r;
    }

    /* ok, we've successfully added a message */
    as->quota_used += message_index.size;

    return 0;
}

int append_removestage(struct stagemsg *stage)
{
    char *p;

    if (stage == NULL) return 0;

    p = stage->parts;
    while (*p != '\0' && p < stage->partend) {
	/* unlink the staging file */
	if (unlink(p) != 0) {
	    syslog(LOG_ERR, "IOERROR: error unlinking file %s: %m", p);
	}
	p += strlen(p) + 1;
    }
    
    free(stage->parts);
    free(stage);
    return 0;
}

/*
 * Append to 'mailbox' from the prot stream 'messagefile'.
 * 'mailbox' must have been opened with append_setup().
 * 'size' is the expected size of the message.
 * 'internaldate' specifies the internaldate for the new message.
 * 'flags' contains the names of the 'nflags' flags that the
 * user wants to set in the message.  If the '\Seen' flag is
 * in 'flags', then the 'userid' passed to append_setup controls whose
 * \Seen flag gets set.
 * 
 * The message is not committed to the mailbox (nor is the mailbox
 * unlocked) until append_commit() is called.  multiple
 * append_onefromstream()s can be aborted by calling append_abort().
 */
int append_fromstream(struct appendstate *as, 
		      struct protstream *messagefile,
		      unsigned long size,
		      time_t internaldate,
		      const char **flag,
		      int nflags)
{
    struct mailbox *mailbox = &as->m;
    struct index_record message_index;
    char fname[MAX_MAILBOX_PATH];
    FILE *destfile;
    int i, r;
    int userflag, emptyflag;

    assert(mailbox->format == MAILBOX_FORMAT_NORMAL);
    assert(size != 0);

    zero_index(message_index);
    /* Setup */
    message_index.uid = mailbox->last_uid + as->nummsg + 1;
    message_index.last_updated = time(0);
    message_index.internaldate = internaldate;
    lseek(mailbox->cache_fd, 0L, SEEK_END);

    /* Create message file */
    strcpy(fname, mailbox->path);
    strcat(fname, "/");
    mailbox_message_get_fname(mailbox, message_index.uid, 
			      fname + strlen(fname));
    as->nummsg++;

    unlink(fname);
    destfile = fopen(fname, "w+");
    if (!destfile) {
	syslog(LOG_ERR, "IOERROR: creating message file %s: %m", fname);
	append_abort(as);
	return IMAP_IOERROR;
    }

    /* Copy and parse message */
    r = message_copy_strict(messagefile, destfile, size);
    if (!r) {
	r = message_parse_file(destfile, mailbox, &message_index);
    }
    fclose(destfile);
    if (r) {
	append_abort(as);
	return r;
    }

    /* Handle flags the user wants to set in the message */
    for (i = 0; i < nflags; i++) {
	if (!strcmp(flag[i], "\\seen")) {
	    addme(&as->seen_msgrange, &as->seen_alloced, message_index.uid);
	}
	else if (!strcmp(flag[i], "\\deleted")) {
	    if (mailbox->myrights & ACL_DELETE) {
		message_index.system_flags |= FLAG_DELETED;
		as->numdeleted++;
	    }
	}
	else if (!strcmp(flag[i], "\\draft")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_DRAFT;
	    }
	}
	else if (!strcmp(flag[i], "\\flagged")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_FLAGGED;
		as->numflagged++;
	    }
	}
	else if (!strcmp(flag[i], "\\answered")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_ANSWERED;
		as->numanswered++;
	    }
	}
	else if (mailbox->myrights & ACL_WRITE) {
	    /* User flag */
	    emptyflag = -1;
	    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
		if (mailbox->flagname[userflag]) {
		    if (!strcasecmp(flag[i], mailbox->flagname[userflag]))
		      break;
		}
		else if (emptyflag == -1) emptyflag = userflag;
	    }

	    /* Flag is not defined--create it */
	    if (userflag == MAX_USER_FLAGS && emptyflag != -1) {
		userflag = emptyflag;
		mailbox->flagname[userflag] = xstrdup(flag[i]);
		as->writeheader++;
	    }

	    if (userflag != MAX_USER_FLAGS) {
		message_index.user_flags[userflag/32] |= 1<<(userflag&31);
	    }
	}
    }

    /* Write out index file entry; if we abort later, it's not
       important */
    r = mailbox_append_index(mailbox, &message_index, 
			     mailbox->exists + as->nummsg - 1, 1, 0);
    if (r) {
	append_abort(as);
	return r;
    }
    
    /* ok, we've successfully added a message */
    as->quota_used += message_index.size;

    return 0;
}

/*
 * Append to 'append_mailbox' ('as') the 'nummsg' messages from the
 * mailbox 'mailbox' listed in the array pointed to by 'copymsg'.
 * 'as' must have been opened with append_setup().  If the '\Seen'
 * flag is to be set anywhere then 'userid' passed to append_setup()
 * contains the name of the user whose \Seen flag gets set.  
 */
int append_copy(struct mailbox *mailbox, 
		struct appendstate *as,
		int nummsg, 
		struct copymsg *copymsg)
{
    struct mailbox *append_mailbox = &as->m;
    int msg;
    struct index_record *message_index;
    char fname[MAX_MAILBOX_PATH];
    const char *src_base;
    unsigned long src_size;
    const char *startline, *endline;
    FILE *destfile;
    int r, n;
    int flag, userflag, emptyflag;
    
    assert(append_mailbox->format == MAILBOX_FORMAT_NORMAL);

    if (!nummsg) {
	append_abort(as);
	return 0;
    }

    lseek(append_mailbox->cache_fd, 0L, SEEK_END);
    message_index = (struct index_record *)
      xmalloc(nummsg * sizeof(struct index_record));

    /* Copy/link all files and cache info */
    for (msg = 0; msg < nummsg; msg++) {
	zero_index(message_index[msg]);
	message_index[msg].uid = append_mailbox->last_uid + 1 + as->nummsg;
	message_index[msg].last_updated = time(0);
	message_index[msg].internaldate = copymsg[msg].internaldate;
	as->nummsg++;

	strcpy(fname, append_mailbox->path);
	strcat(fname, "/");
	mailbox_message_get_fname(append_mailbox, message_index[msg].uid, 
				  fname + strlen(fname));

	if (copymsg[msg].cache_len) {
	    char fnamebuf[MAILBOX_FNAME_LEN];

	    mailbox_message_get_fname(mailbox, copymsg[msg].uid, fnamebuf);
	    /* Link/copy message file */
	    r = mailbox_copyfile(fnamebuf, fname);
	    if (r) goto fail;

	    /* Write out cache info, copy other info */
	    message_index[msg].cache_offset =
		lseek(append_mailbox->cache_fd, 0L, SEEK_CUR);
	    message_index[msg].sentdate = copymsg[msg].sentdate;
	    message_index[msg].size = copymsg[msg].size;
	    message_index[msg].header_size = copymsg[msg].header_size;
	    message_index[msg].content_offset = copymsg[msg].header_size;

	    n = retry_write(append_mailbox->cache_fd, copymsg[msg].cache_begin,
			    copymsg[msg].cache_len);
	    if (n == -1) {
		syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
		       append_mailbox->name);
		r = IMAP_IOERROR;
		goto fail;
	    }
	} else {
	    /*
	     * Have to copy the message, possibly converting LF to CR LF
	     * Then, we have to parse the message.
	     */
	    r = 0;
	    unlink(fname);
	    destfile = fopen(fname, "w+");
	    if (!destfile) {
		syslog(LOG_ERR, "IOERROR: writing message file %s: %m", fname);
		r = IMAP_IOERROR;
		goto fail;
	    }
	    if (mailbox_map_message(mailbox, 0, copymsg[msg].uid,
				    &src_base, &src_size) != 0) {
		fclose(destfile);
		syslog(LOG_ERR, "IOERROR: opening message file %lu of %s: %m",
		       copymsg[msg].uid, mailbox->name);
		r = IMAP_IOERROR;
		goto fail;
	    }

	    startline = src_base;
	    while ( (endline = memchr(startline, '\n',
				    src_size - (startline - src_base))) ) {
		fwrite(startline, 1, (endline - startline), destfile);
		if (endline == startline || endline[-1] != '\r') {
		    putc('\r', destfile);
		}
		putc('\n', destfile);
		startline = endline+1;
	    }
	    fwrite(startline, 1, src_size - (startline - src_base), destfile);

	    fflush(destfile);
	    if (ferror(destfile) || fsync(fileno(destfile))) {
		syslog(LOG_ERR, "IOERROR: writing message: %m");
		r = IMAP_IOERROR;
	    }

	    mailbox_unmap_message(mailbox, copymsg[msg].uid,
				  &src_base, &src_size);

	    if (!r) r = message_parse_file(destfile, append_mailbox,
					   &message_index[msg]);
	    fclose(destfile);
	    if (r) goto fail;
	}

	as->quota_used += message_index[msg].size;
	
	/* Handle any flags that need to be copied */
	if (append_mailbox->myrights & ACL_WRITE) {
	    message_index[msg].system_flags =
	      copymsg[msg].system_flags & ~FLAG_DELETED;

	    for (flag = 0; copymsg[msg].flag[flag]; flag++) {
		emptyflag = -1;
		for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
		    if (append_mailbox->flagname[userflag]) {
			if (!strcasecmp(copymsg[msg].flag[flag],
					append_mailbox->flagname[userflag]))
			  break;
		    }
		    else if (emptyflag == -1) emptyflag = userflag;
		}

		/* Flag is not defined--create it */
		if (userflag == MAX_USER_FLAGS && emptyflag != -1) {
		    userflag = emptyflag;
		    append_mailbox->flagname[userflag] =
		      xstrdup(copymsg[msg].flag[flag]);
		    as->writeheader++;
		}

		if (userflag != MAX_USER_FLAGS) {
		    message_index[msg].user_flags[userflag/32] |=
		      1<<(userflag&31);
		}
	    }
	}
	if (append_mailbox->myrights & ACL_DELETE) {
	    message_index[msg].system_flags |=
	      copymsg[msg].system_flags & FLAG_DELETED;
	}

	if (message_index[msg].system_flags & FLAG_DELETED) as->numdeleted++;
	if (message_index[msg].system_flags & FLAG_ANSWERED) as->numanswered++;
	if (message_index[msg].system_flags & FLAG_FLAGGED) as->numflagged++;

	/* should this message be marked \Seen? */
	if (copymsg[msg].seen) {
	    addme(&as->seen_msgrange, &as->seen_alloced, 
		  message_index[msg].uid);
	}
    }

    /* Write out index file entries */
    r = mailbox_append_index(append_mailbox, message_index,
			     append_mailbox->exists + as->nummsg - nummsg, 
			     nummsg, 0);

 fail:
    if (r) append_abort(as);
    free(message_index);

    return r;
}

/* add 'uid' to 'msgrange'.  'uid' should be larger than anything in
 * 'msgrange'.
 */
static void addme(char **msgrange, int *alloced, long uid)
{
    char *p;
    int wasrange;
    int len;

    assert(msgrange != NULL);
    len = *msgrange ? strlen(*msgrange) : 0;
    if (*alloced < len + 40) {
	*alloced += 40;
	*msgrange = (char *) xrealloc(*msgrange, sizeof(char *) * (*alloced));
    }

    p = *msgrange;

    if (!len) {
	/* first time */
	sprintf(*msgrange, "%ld", uid);
    } else {
	/* this is tricky if this is the second number we're adding */
	wasrange = 0;

	/* see what the last one is */
	p = *msgrange + len - 1;
	while (isdigit((int) *p) && p > *msgrange) p--;
	/* second time, p == msgrange here */
	if (*p == ':') wasrange = 1;
	p++;
	if (atoi(p) == uid - 1) {
	    if (!wasrange) {
		p = *msgrange + len;
		*p++ = ':';
	    } else {
		/* we'll just overwrite the current number */
	    }
	} else {
	    p = *msgrange + len;
	    *p++ = ',';
	}
	sprintf(p, "%ld", uid);
	return;
    }
}

/*
 * Set the \Seen flag for 'userid' in 'mailbox' for the messages from
 * 'msgrange'.  the lowest msgrange must be larger than any previously
 * seen message.
 */
static int append_addseen(struct mailbox *mailbox,
			  const char *userid,
			  const char *msgrange)
{
    int r;
    struct seen *seendb;
    time_t last_read, last_change;
    unsigned last_uid;
    char *seenuids;
    int last_seen;
    char *tail, *p;
    int oldlen;
    int start;
    
    /* what's the first uid in our new list? */
    start = atoi(msgrange);

    r = seen_open(mailbox, userid, &seendb);
    if (r) return r;
    
    r = seen_lockread(seendb, &last_read, &last_uid, &last_change, &seenuids);
    if (r) return r;
    
    oldlen = strlen(seenuids);
    seenuids = xrealloc(seenuids, oldlen + strlen(msgrange) + 10);

    tail = seenuids + oldlen;
    /* Scan back to last uid */
    while (tail > seenuids && isdigit((int) tail[-1])) tail--;
    for (p = tail, last_seen=0; *p; p++) last_seen = last_seen * 10 + *p - '0';
    if (last_seen && last_seen >= start-1) {
	if (tail > seenuids && tail[-1] == ':') p = tail - 1;
	*p++ = ':';
    }
    else {
	if (p > seenuids) *p++ = ',';
    }
    strcpy(p, msgrange);

    r = seen_write(seendb, last_read, last_uid, time(NULL), seenuids);
    seen_close(seendb);
    free(seenuids);
    return r;
}
	  
