/*
 * Routines for appending messages to a mailbox
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <syslog.h>

#include <acl.h>
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "append.h"
#include "xmalloc.h"

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

    r = mailbox_lock_quota(mailbox);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    if (mailbox->quota_limit >= 0 && quotacheck >= 0  &&
	mailbox->quota_used + quotacheck > mailbox->quota_limit * QUOTA_UNITS) {
	return IMAP_QUOTA_EXCEEDED;
    }

    return 0;
}

/*
 * Append to 'mailbox' from the stdio stream 'messagefile'.
 * 'mailbox' must have been opened with append_setup().
 * If 'size', is nonzero it the expected size of the message.
 * If 'size' is zero, message may need LF to CRLF conversion.
 * 'flags' contains the names of the 'nflags' flags that the
 * user wants to set in the message.  If the '\Seen' flag is
 * in 'flags', then 'userid' contains the name of the user whose
 * \Seen flag gets set.
 */
int append_fromstream(mailbox, messagefile, size, flag, nflags, userid)
struct mailbox *mailbox;
FILE *messagefile;
unsigned size;
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

    message_index = zero_index;
    message_index.uid = mailbox->last_uid + 1;
    message_index.last_updated = message_index.internaldate = time(0);

    strcpy(fname, mailbox->path);
    strcat(fname, "/");
    strcat(fname, mailbox_message_fname(mailbox, message_index.uid));
    destfile = fopen(fname, "w+");
    if (!destfile) {
	return IMAP_IOERROR;
    }

    fseek(mailbox->cache, 0L, 2);
    last_cacheoffset = ftell(mailbox->cache);

    if (size) {
	r = message_copy_strict(messagefile, destfile, size);
    }
    else {
	r = message_copy_byline(messagefile, destfile);
    }
    if (!r) r = message_parse(destfile, mailbox, &message_index);
    fclose(destfile);
    if (r) {
	unlink(fname);
	return r;
    }

    for (i = 0; i < nflags; i++) {
	if (!strcmp(flag[i], "\\seen")) setseen++;
	else if (!strcmp(flag[i], "\\deleted")) {
	    if (mailbox->myrights & ACL_DELETE) {
		message_index.system_flags |= FLAG_DELETED;
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
	    emptyflag = -1;
	    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
		if (mailbox->flagname[userflag]) {
		    if (!strcasecmp(flag[i], mailbox->flagname[userflag]))
		      break;
		}
		else if (emptyflag == -1) emptyflag = userflag;
	    }

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
    if (writeheader) {
	r = mailbox_write_header(mailbox);
	if (r) {
	    unlink(fname);
	    ftruncate(fileno(mailbox->cache), last_cacheoffset);
	    return r;
	}
    }

    r = mailbox_append_index(mailbox, &message_index, mailbox->exists, 1);
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);
	return r;
    }
    
    mailbox->exists++;
    mailbox->last_uid = message_index.uid;
    mailbox->last_appenddate = time(0);
    mailbox->quota_mailbox_used += message_index.size;
    if (mailbox->minor_version > MAILBOX_MINOR_VERSION) {
	mailbox->minor_version = MAILBOX_MINOR_VERSION;
    }

    r = mailbox_write_index_header(mailbox);
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);
	/* We don't ftruncate index file.  It doesn't matter */
	return r;
    }
    
    mailbox->quota_used += message_index.size;
    r = mailbox_write_quota(mailbox);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record use of %d bytes in quota file %s",
	       message_index.size, mailbox->quota_path);
    }

    if (setseen && userid && (mailbox->myrights & ACL_SEEN)) {
	append_addseen(mailbox, userid, message_index.uid, message_index.uid);
    }
    
    return 0;
}

int
append_copy(mailbox, nummsg, copymsg, userid)
struct mailbox *mailbox;
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
    char buf[4096];
    int n, r;
    long last_cacheoffset;
    int writeheader = 0;
    int flag, userflag, emptyflag;
    int seenbegin;
    
    assert(mailbox->format == MAILBOX_FORMAT_NORMAL);

    if (!nummsg) return 0;

    fseek(mailbox->cache, 0L, 2);
    last_cacheoffset = ftell(mailbox->cache);

    message_index = (struct index_record *)
      xmalloc(nummsg * sizeof(struct index_record));

    for (msg = 0; msg < nummsg; msg++) {
	message_index[msg] = zero_index;
	message_index[msg].uid = mailbox->last_uid + 1 + msg;
	message_index[msg].last_updated = time(0);
	message_index[msg].internaldate = copymsg[msg].internaldate;

	if (copymsg[msg].cache_len) {
	    strcpy(fname, mailbox->path);
	    strcat(fname, "/");
	    strcat(fname, mailbox_message_fname(mailbox,
						message_index[msg].uid));
	    if (link(mailbox_message_fname(mailbox, copymsg[msg].uid),
		     fname)) {
		destfile = fopen(fname, "w");
		if (!destfile) {
		    r = IMAP_IOERROR;
		    goto fail;
		}
		srcfile = fopen(mailbox_message_fname(mailbox, copymsg[msg].uid), "r");
		if (!srcfile) {
		    fclose(destfile);
		    r = IMAP_IOERROR;
		    goto fail;
		}

		while (n = fread(buf, 1, sizeof(buf), srcfile)) {
		    fwrite(buf, 1, n, destfile);
		}
		fflush(destfile);
		if (ferror(destfile) || fsync(fileno(destfile))) {
		    fclose(srcfile);
		    fclose(destfile);
		    r = IMAP_IOERROR;
		    goto fail;
		}
		fclose(srcfile);
		fclose(destfile);
	    }
	    message_index[msg].cache_offset = ftell(mailbox->cache);
	    fwrite(copymsg[msg].cache_begin, 1, copymsg[msg].cache_len,
		   mailbox->cache);
	    message_index[msg].size = copymsg[msg].size;
	    message_index[msg].header_size = copymsg[msg].header_size;
	    message_index[msg].content_offset = copymsg[msg].header_size;
	}
	else {
	    destfile = fopen(fname, "w");
	    if (!destfile) {
		r = IMAP_IOERROR;
		goto fail;
	    }
	    srcfile = fopen(mailbox_message_fname(mailbox, copymsg[msg].uid),
			    "r");
	    if (!srcfile) {
		fclose(destfile);
		r = IMAP_IOERROR;
		goto fail;
	    }
	    r = message_copy_byline(srcfile, destfile);
	    fclose(srcfile);
	    if (!r) r = message_parse(destfile, mailbox, &message_index[msg]);
	    fclose(destfile);
	    if (r) goto fail;
	}

	quota_usage += message_index[msg].size;
	
	if (mailbox->myrights & ACL_WRITE) {
	    message_index[msg].system_flags =
	      copymsg[msg].system_flags & ~FLAG_DELETED;

	    for (flag = 0; copymsg[msg].flag[flag]; flag++) {
		emptyflag = -1;
		for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
		    if (mailbox->flagname[userflag]) {
			if (!strcasecmp(copymsg[msg].flag[flag],
					mailbox->flagname[userflag]))
			  break;
		    }
		    else if (emptyflag == -1) emptyflag = userflag;
		}

		if (userflag == MAX_USER_FLAGS && emptyflag != -1) {
		    userflag = emptyflag;
		    mailbox->flagname[userflag] =
		      strsave(copymsg[msg].flag[flag]);
		    writeheader++;
		}

		if (userflag != MAX_USER_FLAGS) {
		    message_index[msg].user_flags[userflag/32] |=
		      1<<(userflag&31);
		}
	    }
	}
	if (mailbox->myrights & ACL_DELETE) {
	    message_index[msg].system_flags |=
	      copymsg[msg].system_flags & FLAG_DELETED;
	}
    }

    if (writeheader) {
	r = mailbox_write_header(mailbox);
	if (r) goto fail;
    }

    r = mailbox_append_index(mailbox, message_index, mailbox->exists, nummsg);

    mailbox->exists += nummsg;
    mailbox->last_uid += nummsg;
    mailbox->last_appenddate = time(0);
    mailbox->quota_mailbox_used += quota_usage;
    if (mailbox->minor_version > MAILBOX_MINOR_VERSION) {
	mailbox->minor_version = MAILBOX_MINOR_VERSION;
    }

    r = mailbox_write_index_header(mailbox);
    if (r) goto fail;
    
    mailbox->quota_used += quota_usage;
    r = mailbox_write_quota(mailbox);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record use of %d bytes in quota file %s",
	       quota_usage, mailbox->quota_path);
    }
    
    /* Deal with \Seen */
    for (msg = seenbegin = 0; msg < nummsg; msg++) {
	if (!seenbegin && !copymsg[msg].seen) continue;
	if (seenbegin && copymsg[msg].seen) continue;

	if (!seenbegin) {
	    if (mailbox->myrights & ACL_SEEN) {
		seenbegin = msg+1;
	    }
	}
	else {
	    append_addseen(mailbox, userid, message_index[seenbegin-1].uid,
			   message_index[msg-1].uid);
	    seenbegin = 0;
	}
    }
    if (seenbegin) {
	append_addseen(mailbox, userid, message_index[seenbegin-1].uid,
		       message_index[nummsg-1].uid);
    }

    free(message_index);
    return 0;

 fail:
    for (msg = 0; msg < nummsg; msg++) {
	strcpy(fname, mailbox->path);
	strcat(fname, "/");
	strcat(fname, mailbox_message_fname(mailbox, mailbox->last_uid + 1 + msg));
	unlink(fname);
    }

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
int start;
int end;
{
    int r;
    struct seen *seendb;
    time_t last_time;
    unsigned last_uid;
    char *seenuids;
    int last_seen;
    char *tail, *p;
    
    r = seen_open(mailbox, userid, &seendb);
    if (r) return r;
    
    r = seen_lockread(seendb, &last_time, &last_uid, &seenuids);
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
	    sprintf(p, "%d:", start);
	    p += strlen(p);
	}
    }
    sprintf(p, "%d", end);

    r = seen_write(seendb, last_time, last_uid, seenuids);
    seen_close(seendb);
    free(seenuids);
    return r;
}
	  
