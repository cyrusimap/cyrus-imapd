/* append.c -- Routines for appending messages to a mailbox
 $Id: append.c,v 1.57 2000/01/28 22:09:42 leg Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <sys/stat.h>

#include "acl.h"
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "append.h"
#include "config.h"
#include "prot.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "acapmbox.h"

extern acap_conn_t *acap_conn;

struct stagemsg {
    unsigned long size;
    time_t internaldate;
    char fname[1024];

    int num_parts;
    char parts[1][MAX_MAILBOX_PATH];
};

static int append_addseen(struct mailbox *mailbox, const char *userid,
			  unsigned start, unsigned end);

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
int append_setup(struct mailbox *mailbox, const char *name,
		 int format, struct auth_state *auth_state,
		 long aclcheck, long quotacheck)
{
    int r;

    r = mailbox_open_header(name, auth_state, mailbox);
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

extern int mboxlist_findstage(const char *name, char *stagedir);

/*
 * staging, to allow for single-instance store.  the complication here
 * is multiple partitions.
 */
int append_fromstage(struct mailbox *mailbox,
		     struct protstream *messagefile,
		     unsigned long size, time_t internaldate,
		     const char **flag, int nflags,
		     const char *userid,
		     struct stagemsg **stagep)
{
    struct index_record message_index;
    static struct index_record zero_index;
    char fname[MAX_MAILBOX_PATH];
    FILE *destfile;
    int i, r;
    long last_cacheoffset;
    int setseen = 0, writeheader = 0;
    int userflag, emptyflag;

    /* for staging */
    struct stagemsg *stage;
    char stagefile[1024];
    FILE *f;
    int sp;

    assert(stagep != NULL);
    assert(mailbox->format == MAILBOX_FORMAT_NORMAL);
    assert(size != 0);

    if (!*stagep) { /* create a new stage */
	stage = xmalloc(sizeof(struct stagemsg) +
			5 * MAX_MAILBOX_PATH * sizeof(char));

	stage->size = size;
	stage->internaldate = internaldate;
	sprintf(stage->fname, "%d-%d", getpid(), internaldate);
	stage->num_parts = 5; /* room for 5 paths */
	stage->parts[0][0] = '\0';
    } else {
	stage = *stagep; /* reuse existing stage */
    }

    mboxlist_findstage(mailbox->name, stagefile);
    strcat(stagefile, stage->fname);

    sp = 0;
    while (stage->parts[sp][0] != '\0') {
	if (!strcmp(stagefile, stage->parts[sp]))
	    break;
	sp++;
    }
    if (stage->parts[sp][0] == '\0') {
	/* ok, create this file and add put it into stage->parts[sp] */
	f = fopen(stagefile, "w+");
	if (!f) {
	    char stagedir[1024];

	    mboxlist_findstage(mailbox->name, stagedir);
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
	    return IMAP_IOERROR;
	}
	
	r = message_copy_strict(messagefile, f, size);
	fclose(f);
	if (r) {
	    unlink(stagefile);
	return r;
	}
	
	if (sp == stage->num_parts) {
	    /* need more room */
	    stage->num_parts += 5;
	    stage = xrealloc(stage, sizeof(struct stagemsg) +
			     stage->num_parts * MAX_MAILBOX_PATH * 
			     sizeof(char));
	}
	strcpy(stage->parts[sp], stagefile);
	stage->parts[sp+1][0] = '\0';
    }

    /* stage->parts[sp] contains the message and is on the same partition
       as the mailbox we're looking at */

    /* Setup */
    last_cacheoffset= lseek(mailbox->cache_fd, 0L, SEEK_END);
    message_index = zero_index;
    message_index.uid = mailbox->last_uid + 1;
    message_index.last_updated = time(0);
    message_index.internaldate = internaldate;

    /* Create message file */
    strcpy(fname, mailbox->path);
    strcat(fname, "/");
    strcat(fname, mailbox_message_fname(mailbox, message_index.uid));

    r = mailbox_copyfile(stage->parts[sp], fname);
    destfile = fopen(fname, "r");
    if (!r && destfile) {
	r = message_parse_file(destfile, mailbox, &message_index);
    }
    if (destfile) fclose(destfile);
    if (!r) {
	/* Flush out the cache file data */
	if (fsync(mailbox->cache_fd)) {
	    syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
		   mailbox->name);
	    r = IMAP_IOERROR;
	}
    }
    if (r) {
	unlink(fname);
	ftruncate(mailbox->cache_fd, last_cacheoffset);
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
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
		mailbox->flagname[userflag] = xstrdup(flag[i]);
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
	    ftruncate(mailbox->cache_fd, last_cacheoffset);
	    mailbox_unlock_quota(&mailbox->quota);
	    mailbox_unlock_index(mailbox);
	    mailbox_unlock_header(mailbox);
	    return r;
	}
    }

    /* Write out index file entry */
    r = mailbox_append_index(mailbox, &message_index, mailbox->exists, 1);
    if (r) {
	unlink(fname);
	ftruncate(mailbox->cache_fd, last_cacheoffset);
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
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
	ftruncate(mailbox->cache_fd, last_cacheoffset);
	/* We don't ftruncate index file.  It doesn't matter */
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
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

    if (mboxlist_acapinit() == 0)
    {
	if (acap_conn != NULL)
	    acapmbox_setproperty(acap_conn,
				 mailbox->name,
				 ACAPMBOX_TOTAL,
				 mailbox->exists);
	/* xxx what to do about errors? */
    }
    

    toimsp(mailbox->name, mailbox->uidvalidity,
	   "UIDNnn", message_index.uid, mailbox->exists, 0);

    mailbox_unlock_quota(&mailbox->quota);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);

    *stagep = stage;

    return 0;
}

int append_removestage(struct stagemsg *stage)
{
    int i;

    if (stage == NULL) return 0;

    i = 0;
    while (stage->parts[i][0] != '\0') {
	/* unlink the staging file */
	if (unlink(stage->parts[i]) != 0) {
	    syslog(LOG_ERR, "IOERROR: error unlinking file %s: %m",
		   stage->parts[i]);
	}
	i++;
    }

    free(stage);
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
unsigned long size;
time_t internaldate;
const char **flag;
int nflags;
const char *userid;
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
    assert(size != 0);

    /* Setup */
    last_cacheoffset= lseek(mailbox->cache_fd, 0L, SEEK_END);
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
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    /* Copy and parse message */
    r = message_copy_strict(messagefile, destfile, size);
    if (!r) {
	r = message_parse_file(destfile, mailbox, &message_index);
    }
    fclose(destfile);
    if (!r) {
	/* Flush out the cache file data */
	if (fsync(mailbox->cache_fd)) {
	    syslog(LOG_ERR, "IOERROR: writing cache file for %s: %m",
		   mailbox->name);
	    r = IMAP_IOERROR;
	}
    }
    if (r) {
	unlink(fname);
	ftruncate(mailbox->cache_fd, last_cacheoffset);
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
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
		mailbox->flagname[userflag] = xstrdup(flag[i]);
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
	    ftruncate(mailbox->cache_fd, last_cacheoffset);
	    mailbox_unlock_quota(&mailbox->quota);
	    mailbox_unlock_index(mailbox);
	    mailbox_unlock_header(mailbox);
	    return r;
	}
    }

    /* Write out index file entry */
    r = mailbox_append_index(mailbox, &message_index, mailbox->exists, 1);
    if (r) {
	unlink(fname);
	ftruncate(mailbox->cache_fd, last_cacheoffset);
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
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
	ftruncate(mailbox->cache_fd, last_cacheoffset);
	/* We don't ftruncate index file.  It doesn't matter */
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
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

    if (mboxlist_acapinit() == 0)
    {
	if (acap_conn != NULL)
	    acapmbox_setproperty(acap_conn,
				 mailbox->name,
				 ACAPMBOX_TOTAL,
				 mailbox->exists);
	/* xxx what to do about errors? */
    }    

    toimsp(mailbox->name, mailbox->uidvalidity,
	   "UIDNnn", message_index.uid, mailbox->exists, 0);

    mailbox_unlock_quota(&mailbox->quota);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
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
const char *userid;
{
    int msg;
    struct index_record *message_index;
    static struct index_record zero_index;
    unsigned long quota_usage = 0;
    char fname[MAX_MAILBOX_PATH];
    const char *src_base;
    unsigned long src_size;
    const char *startline, *endline;
    FILE *destfile;
    int r, n;
    long last_cacheoffset;
    int writeheader = 0;
    int flag, userflag, emptyflag;
    int seenbegin;
    
    assert(append_mailbox->format == MAILBOX_FORMAT_NORMAL);

    if (!nummsg) {
	mailbox_unlock_quota(&append_mailbox->quota);
	mailbox_unlock_index(append_mailbox);
	mailbox_unlock_header(append_mailbox);
	return 0;
    }

    
    last_cacheoffset = lseek(append_mailbox->cache_fd, 0L, SEEK_END);
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
	}
	else {
	    /*
	     * Have to copy the message, possibly converting LF to CR LF
	     * Then, we have to parse the message.
	     */
	    r = 0;
	    destfile = fopen(fname, "w+");
	    if (!destfile) {
		syslog(LOG_ERR, "IOERROR: writing message file %s: %m", fname);
		r = IMAP_IOERROR;
		goto fail;
	    }
	    if (mailbox_map_message(mailbox, 0, copymsg[msg].uid,
				    &src_base, &src_size) != 0) {
		fclose(destfile);
		syslog(LOG_ERR, "IOERROR: opening message file %u of %s: %m",
		       copymsg[msg].uid, mailbox->name);
		r = IMAP_IOERROR;
		goto fail;
	    }

	    startline = src_base;
	    while (endline = memchr(startline, '\n',
				    src_size - (startline - src_base))) {
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
		      xstrdup(copymsg[msg].flag[flag]);
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
    if (fsync(append_mailbox->cache_fd)) {
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

    if (mboxlist_acapinit() == 0)
    {
	if (acap_conn != NULL)
	    acapmbox_setproperty(acap_conn,
				 mailbox->name,
				 ACAPMBOX_TOTAL,
				 mailbox->exists);
	/* xxx what to do about errors? */
    }

    toimsp(mailbox->name, mailbox->uidvalidity,
	   "UIDNnn", message_index[nummsg-1].uid, append_mailbox->exists, 0);

    free(message_index);
    mailbox_unlock_quota(&append_mailbox->quota);
    mailbox_unlock_index(append_mailbox);
    mailbox_unlock_header(append_mailbox);
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

    ftruncate(append_mailbox->cache_fd, last_cacheoffset);
    free(message_index);
    mailbox_unlock_quota(&append_mailbox->quota);
    mailbox_unlock_index(append_mailbox);
    mailbox_unlock_header(append_mailbox);
    return r;
}

/*
 * Append the to 'mailbox' the index/cache entries for the netnews
 * articles which have recently arrived.  Articles up to and including
 * 'feeduid', as well as any existing consecutive articles after 'feeduid'
 * are appended.
 */
#define COLLECTGROW 50
int
append_collectnews(mailbox, group, feeduid)
struct mailbox *mailbox;
const char *group;
unsigned long feeduid;
{
    char newspath[4096], *end_newspath;
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
    struct stat sbuf;
    
    assert(mailbox->format == MAILBOX_FORMAT_NETNEWS);

    if (feeduid < mailbox->last_uid) feeduid = mailbox->last_uid;
    curtime = internaldate = time(0);
    last_cacheoffset = lseek(mailbox->cache_fd, 0L, SEEK_END);

    size_message_index = feeduid - mailbox->last_uid + COLLECTGROW;
    message_index = (struct index_record *)
      xmalloc(size_message_index * sizeof(struct index_record));

    if (config_newsspool) {
	strcpy(newspath, config_newsspool);
	end_newspath = newspath + strlen(newspath);
	if (end_newspath == newspath || end_newspath[-1] != '/') {
	    *end_newspath++ = '/';
	}
	strcpy(end_newspath, group);
	while (*end_newspath) {
	    if (*end_newspath == '.') *end_newspath = '/';
	    end_newspath++;
	}
	if (chdir(newspath)) {
	    syslog(LOG_ERR, "IOERROR: changing dir to %s: %m", newspath);
	    mailbox_unlock_quota(&mailbox->quota);
	    mailbox_unlock_index(mailbox);
	    mailbox_unlock_header(mailbox);
	    return IMAP_IOERROR;
	}
    }
    else if (chdir(mailbox->path)) {
	syslog(LOG_ERR, "IOERROR: changing dir to %s: %m", mailbox->path);
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    /* Find and parse the new messages */
    for (;;) {
	uid++;
	sprintf(newspath, "%u", uid);
	f = fopen(newspath, "r");
	if (!f) {
	    if (uid < feeduid) continue;
	    break;
	}
	
	if (fstat(fileno(f), &sbuf)) {
	  fclose(f);
	  continue;
	}

	if ((sbuf.st_mode & S_IFMT) == S_IFDIR) {
          /* This is in theory a subnewsgroup and should be left alone. */
	  fclose(f);
          continue;
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
	r = message_parse_file(f, mailbox, &message_index[msg]);
	fclose(f);
	if (r) goto fail;
	quota_usage += message_index[msg].size;
	
	msg++;
    }

    /* Didn't find anything to append */
    if (msg == 0) {
	free(message_index);
	mailbox_unlock_quota(&mailbox->quota);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return 0;
    }

    /* Flush out the cache file data */
    if (fsync(mailbox->cache_fd)) {
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

    if (mboxlist_acapinit() == 0)
    {	
	if (acap_conn != NULL)
	    acapmbox_setproperty(acap_conn,
				 mailbox->name,
				 ACAPMBOX_TOTAL,
				 mailbox->exists);
	/* xxx what to do about errors? */
    }

    toimsp(mailbox->name, mailbox->uidvalidity,
	   "UIDNnn", uid-1, mailbox->exists, 0);

    mailbox_unlock_quota(&mailbox->quota);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    return 0;

 fail:
    ftruncate(mailbox->cache_fd, last_cacheoffset);
    free(message_index);
    mailbox_unlock_quota(&mailbox->quota);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    return r;
}


/*
 * Set the \Seen flag for 'userid' in 'mailbox' for the messages from
 * 'start' to 'end', inclusively.
 */
static int append_addseen(mailbox, userid, start, end)
struct mailbox *mailbox;
const char *userid;
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
    if (last_seen && last_seen >= start-1) {
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
	  
