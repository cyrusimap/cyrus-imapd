/* append.c -- Routines for appending messages to a mailbox
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <syslog.h>

#include "acl.h"
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "append.h"
#include "prot.h"
#include "xmalloc.h"

static int append_addseen();

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
 * On success, the struct pointed to by 'mailbox' is set up.
 *
 */
int append_setup(mailbox, name, format, aclcheck, quotacheck)
struct mailbox *mailbox;
char *name;
int format;
long aclcheck;
long quotacheck;
{
    int r;

    r = mailbox_open_header(name, mailbox);
    if (r) return r;

    if ((mailbox->myrights & aclcheck) != aclcheck) {
	r = (mailbox->myrights & ACL_LOOKUP) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	mailbox_close(mailbox);
	return r;
    }

    r = mailbox_lock_header(mailbox);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    r = mailbox_open_index(mailbox);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    if (mailbox->format != format) {
	mailbox_close(mailbox);
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    r = mailbox_lock_index(mailbox);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    r = mailbox_lock_quota(&mailbox->quota);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    if (mailbox->quota.limit >= 0 && quotacheck >= 0  &&
	mailbox->quota.used + quotacheck > mailbox->quota.limit * QUOTA_UNITS) {
	mailbox_close(mailbox);
	return IMAP_QUOTA_EXCEEDED;
    }

    return 0;
}

/*
 * Append to 'mailbox' from the prot stream 'messagefile'.
 * 'mailbox' must have been opened with append_setup().
 * If 'size', is nonzero it the expected size of the message.
 * If 'size' is zero, message may need LF to CRLF conversion.
 * 'internaldate' specifies the internaldate for the new message.
 * 'flags' contains the names of the 'nflags' flags that the
 * user wants to set in the message.  If the '\Seen' flag is
 * in 'flags', then 'userid' contains the name of the user whose
 * \Seen flag gets set.
 */
int
append_fromstream(mailbox, messagefile, size, internaldate, flag, nflags,
		  userid)
struct mailbox *mailbox;
struct protstream *messagefile;
unsigned size;
time_t internaldate;
char **flag;
int nflags;
char *userid;
{
    struct index_record message_index;
    static struct index_record zero_index;
    char fname[MAX_MAILBOX_PATH];
    FILE *destfile;
    int i, r;
    long last_cacheoffset;
    int setseen = 0, writeheader = 0;
    int userflag, emptyflag;

    assert(mailbox->format == MAILBOX_FORMAT_NORMAL);

    /* Setup */
    fseek(mailbox->cache, 0L, 2);
    last_cacheoffset = ftell(mailbox->cache);
    message_index = zero_index;
    message_index.uid = mailbox->last_uid + 1;
    message_index.last_updated = time(0);
    message_index.internaldate = internaldate;

    /* Create message file */
    strcpy(fname, mailbox->path);
    strcat(fname, "/");
    strcat(fname, mailbox_message_fname(mailbox, message_index.uid));
    destfile = fopen(fname, "w+");
    if (!destfile) {
	syslog(LOG_ERR, "IOERROR: creating message file %s: %m", fname);
	return IMAP_IOERROR;
    }

    /* Copy and parse message */
    if (size) {
	r = message_copy_strict(messagefile, destfile, size);
    }
    else {
	r = message_copy_byline(messagefile, destfile);
    }
    if (!r) r = message_parse(destfile, mailbox, &message_index);
    fclose(destfile);
    if (!r) {
	/* Flush out the cache file data */
	fflush(mailbox->cache);
	if (ferror(mailbox->cache) || fsync(fileno(mailbox->cache))) {
	    syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
		   mailbox->name);
	    r = IMAP_IOERROR;
	}
    }
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);
	return r;
    }

    /* Handle flags the user wants to set in the message */
    for (i = 0; i < nflags; i++) {
	if (!strcmp(flag[i], "\\seen")) setseen++;
	else if (!strcmp(flag[i], "\\deleted")) {
	    if (mailbox->myrights & ACL_DELETE) {
		message_index.system_flags |= FLAG_DELETED;
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
	    }
	}
	else if (!strcmp(flag[i], "\\answered")) {
	    if (mailbox->myrights & ACL_WRITE) {
		message_index.system_flags |= FLAG_ANSWERED;
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
		mailbox->flagname[userflag] = strsave(flag[i]);
		writeheader++;
	    }

	    if (userflag != MAX_USER_FLAGS) {
		message_index.user_flags[userflag/32] |= 1<<(userflag&31);
	    }
	}
    }

    /* Write out the header if we created a new user flag */
    if (writeheader) {
	r = mailbox_write_header(mailbox);
	if (r) {
	    unlink(fname);
	    ftruncate(fileno(mailbox->cache), last_cacheoffset);
	    return r;
	}
    }

    /* Write out index file entry */
    r = mailbox_append_index(mailbox, &message_index, mailbox->exists, 1);
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);
	return r;
    }
    
    /* Calculate new index header information */
    mailbox->exists++;
    mailbox->last_uid = message_index.uid;
    mailbox->last_appenddate = time(0);
    mailbox->quota_mailbox_used += message_index.size;
    if (mailbox->minor_version > MAILBOX_MINOR_VERSION) {
	mailbox->minor_version = MAILBOX_MINOR_VERSION;
    }

    /* Write out index header */
    r = mailbox_write_index_header(mailbox);
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);
	/* We don't ftruncate index file.  It doesn't matter */
	return r;
    }
    
    /* Write out quota file */
    mailbox->quota.used += message_index.size;
    r = mailbox_write_quota(&mailbox->quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record use of %u bytes in quota file %s",
	       message_index.size, mailbox->quota.root);
    }

    /* Set \Seen flag if necessary */
    if (setseen && userid && (mailbox->myrights & ACL_SEEN)) {
	append_addseen(mailbox, userid, message_index.uid, message_index.uid);
    }
    
    drop_last(mailbox->name, message_index.uid, mailbox->exists);

    return 0;
}

/*
 * Append to 'append_mailbox' the 'nummsg' messages from the mailbox
 * 'mailbox' listed in the array pointed to by 'copymsg'.  'mailbox'
 * must have been opened with append_setup().  If the '\Seen' flag is
 * to be set anywhere then 'userid' contains the name of the user
 * whose \Seen flag gets set.
 */
int
append_copy(mailbox, append_mailbox, nummsg, copymsg, userid)
struct mailbox *mailbox;
struct mailbox *append_mailbox;
int nummsg;
struct copymsg *copymsg;
char *userid;
{
    int msg;
    struct index_record *message_index;
    static struct index_record zero_index;
    unsigned long quota_usage = 0;
    char fname[MAX_MAILBOX_PATH];
    FILE *srcfile, *destfile;
    struct protstream *prot_src;
    int r;
    long last_cacheoffset;
    int writeheader = 0;
    int flag, userflag, emptyflag;
    int seenbegin;
    
    assert(append_mailbox->format == MAILBOX_FORMAT_NORMAL);

    if (!nummsg) return 0;

    fseek(append_mailbox->cache, 0L, 2);
    last_cacheoffset = ftell(append_mailbox->cache);
    message_index = (struct index_record *)
      xmalloc(nummsg * sizeof(struct index_record));

    /* Copy/link all files and cache info */
    for (msg = 0; msg < nummsg; msg++) {
	message_index[msg] = zero_index;
	message_index[msg].uid = append_mailbox->last_uid + 1 + msg;
	message_index[msg].last_updated = time(0);
	message_index[msg].internaldate = copymsg[msg].internaldate;

	strcpy(fname, append_mailbox->path);
	strcat(fname, "/");
	strcat(fname, mailbox_message_fname(append_mailbox,
					    message_index[msg].uid));

	if (copymsg[msg].cache_len) {
	    /* Link/copy message file */
	    r = mailbox_copyfile(mailbox_message_fname(mailbox,
						       copymsg[msg].uid),
				  fname);
	    if (r) goto fail;

	    /* Write out cache info, copy other info */
	    message_index[msg].cache_offset = ftell(append_mailbox->cache);
	    fwrite(copymsg[msg].cache_begin, 1, copymsg[msg].cache_len,
		   append_mailbox->cache);
	    message_index[msg].sentdate = copymsg[msg].sentdate;
	    message_index[msg].size = copymsg[msg].size;
	    message_index[msg].header_size = copymsg[msg].header_size;
	    message_index[msg].content_offset = copymsg[msg].header_size;
	}
	else {
	    /*
	     * Have to copy the message, possibly converting LF to CR LF
	     * Then, we have to parse the message.
	     */
	    destfile = fopen(fname, "w+");
	    if (!destfile) {
		syslog(LOG_ERR, "IOERROR: writing message file %s: %m", fname);
		r = IMAP_IOERROR;
		goto fail;
	    }
	    srcfile = fopen(mailbox_message_fname(mailbox, copymsg[msg].uid),
			    "r");
	    if (!srcfile) {
		fclose(destfile);
		syslog(LOG_ERR, "IOERROR: reading message file %s: %m",
		       mailbox_message_fname(mailbox, copymsg[msg].uid));
		r = IMAP_IOERROR;
		goto fail;
	    }
	    prot_src = prot_new(fileno(srcfile), 0);
	    r = message_copy_byline(prot_src, destfile);
	    prot_free(prot_src);
	    fclose(srcfile);
	    if (!r) r = message_parse(destfile, append_mailbox,
				      &message_index[msg]);
	    fclose(destfile);
	    if (r) goto fail;
	}

	quota_usage += message_index[msg].size;
	
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
		      strsave(copymsg[msg].flag[flag]);
		    writeheader++;
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
    }

    /* Flush out the cache file data */
    fflush(append_mailbox->cache);
    if (ferror(append_mailbox->cache) ||
	fsync(fileno(append_mailbox->cache))) {
	syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
	       append_mailbox->name);
	r = IMAP_IOERROR;
	goto fail;
    }

    /* Write out the header if we created a new user flag */
    if (writeheader) {
	r = mailbox_write_header(append_mailbox);
	if (r) goto fail;
    }

    /* Write out index file entries */
    r = mailbox_append_index(append_mailbox, message_index,
			     append_mailbox->exists, nummsg);
    if (r) goto fail;

    /* Calculate new index header information */
    append_mailbox->exists += nummsg;
    append_mailbox->last_uid += nummsg;
    append_mailbox->last_appenddate = time(0);
    append_mailbox->quota_mailbox_used += quota_usage;
    if (append_mailbox->minor_version > MAILBOX_MINOR_VERSION) {
	append_mailbox->minor_version = MAILBOX_MINOR_VERSION;
    }

    /* Write out index header */
    r = mailbox_write_index_header(append_mailbox);
    if (r) goto fail;
    
    /* Write out quota file */
    append_mailbox->quota.used += quota_usage;
    r = mailbox_write_quota(&append_mailbox->quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record use of %u bytes in quota file %s",
	       quota_usage, append_mailbox->quota.root);
    }
    
    /* Set \Seen flags if necessary */
    for (msg = seenbegin = 0; msg < nummsg; msg++) {
	if (!seenbegin && !copymsg[msg].seen) continue;
	if (seenbegin && copymsg[msg].seen) continue;

	if (!seenbegin) {
	    if (append_mailbox->myrights & ACL_SEEN) {
		seenbegin = msg+1;
	    }
	}
	else {
	    append_addseen(append_mailbox, userid,
			   message_index[seenbegin-1].uid,
			   message_index[msg-1].uid);
	    seenbegin = 0;
	}
    }
    if (seenbegin) {
	append_addseen(append_mailbox, userid, message_index[seenbegin-1].uid,
		       message_index[nummsg-1].uid);
    }

    drop_last(mailbox->name, message_index[nummsg-1].uid,
	      append_mailbox->exists);

    free(message_index);
    return 0;

 fail:
    /* Remove all new message files */
    for (msg = 0; msg < nummsg; msg++) {
	strcpy(fname, append_mailbox->path);
	strcat(fname, "/");
	strcat(fname, mailbox_message_fname(append_mailbox,
					 append_mailbox->last_uid + 1 + msg));
	unlink(fname);
    }

    ftruncate(fileno(append_mailbox->cache), last_cacheoffset);
    free(message_index);
    return r;
}

/*
 * Append the to 'mailbox' the index/cache entries for the netnews
 * articles which have recently arrived.  Articles up to and including
 * 'feeduid', as well as any existing consecutive articles after 'feeduid'
 * are appended.
 */
#define COLLECTGROW 20
int
append_collectnews(mailbox, feeduid)
struct mailbox *mailbox;
unsigned long feeduid;
{
    time_t curtime, internaldate;
    struct index_record *message_index;
    int size_message_index;
    static struct index_record zero_index;
    unsigned long quota_usage = 0;
    int msg = 0;
    int uid = mailbox->last_uid;
    FILE *f;
    int r;
    long last_cacheoffset;
    
    assert(mailbox->format == MAILBOX_FORMAT_NETNEWS);

    if (feeduid < mailbox->last_uid) feeduid = mailbox->last_uid;
    curtime = internaldate = time(0);
    fseek(mailbox->cache, 0L, 2);
    last_cacheoffset = ftell(mailbox->cache);

    size_message_index = feeduid - mailbox->last_uid + COLLECTGROW;
    message_index = (struct index_record *)
      xmalloc(size_message_index * sizeof(struct index_record));

    if (chdir(mailbox->path)) {
	syslog(LOG_ERR, "IOERROR: changing dir to %s: %m", mailbox->path);
	return IMAP_IOERROR;
    }

    /* Find and parse the new messages */
    for (;;) {
	uid++;
	f = fopen(mailbox_message_fname(mailbox, uid), "r");
	if (!f) {
	    if (uid < feeduid) continue;
	    break;
	}
	
	if (msg == size_message_index) {
	    size_message_index += COLLECTGROW;
	    message_index = (struct index_record *)
	      xrealloc((char *)message_index,
		       size_message_index * sizeof(struct index_record));
	}
	    
	message_index[msg] = zero_index;
	message_index[msg].uid = uid;
	message_index[msg].last_updated = curtime;
	message_index[msg].internaldate = internaldate++;
	r = message_parse(f, mailbox, &message_index[msg]);
	fclose(f);
	if (r) goto fail;
	quota_usage += message_index[msg].size;
	
	msg++;
    }

    /* Didn't find anything to append */
    if (msg == 0) {
	free(message_index);
	return 0;
    }

    /* Flush out the cache file data */
    fflush(mailbox->cache);
    if (ferror(mailbox->cache) || fsync(fileno(mailbox->cache))) {
	syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
	       mailbox->name);
	r = IMAP_IOERROR;
	goto fail;
    }

    /* Write out index file entries */
    r = mailbox_append_index(mailbox, message_index, mailbox->exists, msg);
    if (r) goto fail;

    /* Calculate new index header information */
    mailbox->exists += msg;
    mailbox->last_uid = uid-1;
    mailbox->last_appenddate = internaldate-1;
    mailbox->quota_mailbox_used += quota_usage;
    if (mailbox->minor_version > MAILBOX_MINOR_VERSION) {
	mailbox->minor_version = MAILBOX_MINOR_VERSION;
    }

    /* Write out index header */
    r = mailbox_write_index_header(mailbox);
    if (r) goto fail;
    
    /* Write out quota file */
    mailbox->quota.used += quota_usage;
    r = mailbox_write_quota(&mailbox->quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record use of %u bytes in quota file %s",
	       quota_usage, mailbox->quota.root);
    }
    
    free(message_index);

    drop_last(mailbox->name, uid-1, mailbox->exists);

    return 0;

 fail:
    ftruncate(fileno(mailbox->cache), last_cacheoffset);
    free(message_index);
    return r;
}


/*
 * Set the \Seen flag for 'userid' in 'mailbox' for the messages from
 * 'start' to 'end', inclusively.
 */
static int append_addseen(mailbox, userid, start, end)
struct mailbox *mailbox;
char *userid;
unsigned start;
unsigned end;
{
    int r;
    struct seen *seendb;
    time_t last_read, last_change;
    unsigned last_uid;
    char *seenuids;
    int last_seen;
    char *tail, *p;
    
    r = seen_open(mailbox, userid, &seendb);
    if (r) return r;
    
    r = seen_lockread(seendb, &last_read, &last_uid, &last_change, &seenuids);
    if (r) return r;
    
    seenuids = xrealloc(seenuids, strlen(seenuids)+40);

    tail = seenuids + strlen(seenuids);
    /* Scan back to last uid */
    while (tail > seenuids && isdigit(tail[-1])) tail--;
    for (p = tail, last_seen=0; *p; p++) last_seen = last_seen * 10 + *p - '0';
    if (last_seen == start-1) {
	if (tail > seenuids && tail[-1] == ':') p = tail - 1;
	*p++ = ':';
    }
    else {
	if (p > seenuids) *p++ = ',';
	if (start != end) {
	    sprintf(p, "%u:", start);
	    p += strlen(p);
	}
    }
    sprintf(p, "%u", end);

    r = seen_write(seendb, last_read, last_uid, time((time_t *)0), seenuids);
    seen_close(seendb);
    free(seenuids);
    return r;
}
	  
