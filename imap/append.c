/*
 * Routines for appending messages to a mailbox
 */

#include <stdio.h>

#include <acl.h>
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"

/*
 * Open a mailbox for appending
 *
 * Arguments:
 *	path	   - pathname of mailbox directory
 *	format     - mailbox must be of this format
 *	aclcheck   - user must have these rights on mailbox ACL
 *	quotacheck - mailbox must have this much quota left
 *		     (-1 means don't care about quota)
 *
 * On success, the struct pointed to by 'mailbox' is set up.
 *
 */
int append_setup(mailbox, path, format, aclcheck, quotacheck)
struct mailbox *mailbox;
char *path;
int format;
long aclcheck;
long quotacheck;
{
    int r;

    r = mailbox_open_header(path, mailbox);
    if (r) return r;

    if ((mailbox->my_acl & aclcheck) != aclcheck) {
	mailbox_close(mailbox);
	return IMAP_PERMISSION_DENIED;
    }

    r = mailbox_lock_header(mailbox);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    /* In case it changed */
    if ((mailbox->my_acl & aclcheck) != aclcheck) {
	mailbox_close(mailbox);
	return IMAP_PERMISSION_DENIED;
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
 * Append to 'mailbox' from the stdio stream 'messagefile'
 * 'mailbox' must have been opened with append_setup()
 */
int append_fromstream(mailbox, messagefile)
struct mailbox *mailbox;
FILE *messagefile;
{
    struct index_record message_index;
    static struct index_record zero_index;
    char fname[MAX_MAILBOX_PATH];
    FILE *destfile;
    int r;
    long last_cacheoffset;

    assert(mailbox->format == MAILBOX_FORMAT_NORMAL);

    message_index = zero_index;
    message_index.uid = mailbox->last_uid + 1;
    message_index.last_updated = message_index.internaldate = time(0);
    if (message_index.internaldate <= mailbox->last_internaldate) {
	message_index.internaldate = mailbox->last_internaldate + 1; /* XXX needed? */
    }

    strcpy(fname, mailbox->path);
    strcat(fname, "/");
    strcat(fname, message_fname(mailbox, message_index.uid));
    destfile = fopen(fname, "w+");
    if (!destfile) {
	return IMAP_IOERROR;
    }

    fseek(mailbox->cache, 0L, 2);
    last_cacheoffset = ftell(mailbox->cache);

    r = message_copy_stream(messagefile, destfile);
    if (!r) r = message_parse(destfile, mailbox, &message_index);
    fclose(destfile);
    if (r) {
	unlink(fname);
	return r;
    }

    mailbox->last_uid = message_index.uid;
    mailbox->last_internaldate = message_index.internaldate;
    mailbox->quota_mailbox_used += message_index.size;

    r = mailbox_write_index_header(mailbox);
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);
	return r;
    }

    r = mailbox_append_index(mailbox, &message_index, 1);
    if (r) {
	unlink(fname);
	ftruncate(fileno(mailbox->cache), last_cacheoffset);

	/* Try to back out index header changes */
	mailbox->last_uid--;
	mailbox->quota_mailbox_used -= message_index.size;
	(void) mailbox_write_index_header(mailbox);

	return r;
    }
    
    
    mailbox->quota_used += message_index.size;
    r = mailbox_write_quota(mailbox);
    if (r) {
	/* XXX syslog it */
    }
    
    return 0;
}
