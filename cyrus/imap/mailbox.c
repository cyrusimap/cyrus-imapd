/* mailbox.c -- Mailbox manipulation routines
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
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/stat.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "config.h"
#include "acl.h"
#include "assert.h"
#include "util.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

static int mailbox_doing_reconstruct = 0;

/*
 * Names of the headers we cache in the cyrus.cache file.
 * Any changes to this list require corresponding changes to
 * message_parse_headers() in message.c
 */
char *mailbox_cache_header_name[] = {
/*    "in-reply-to", in ENVELOPE */
    "priority",
    "references",
};
int mailbox_num_cache_header =
  sizeof(mailbox_cache_header_name)/sizeof(char *);

/*
 * Calculate relative filename for the message with UID 'uid'
 * in 'mailbox'.  Returns pointer to static buffer.
 */
char *mailbox_message_fname(mailbox, uid)
struct mailbox *mailbox;
unsigned long uid;
{
    static char buf[64];

    sprintf(buf, "%lu%s", uid, mailbox->format == MAILBOX_FORMAT_NETNEWS ? "" : ".");
    return buf;
}

/*
 * Set the "reconstruct" mode.  Causes most errors to be ignored.
 */
int
mailbox_reconstructmode()
{
    mailbox_doing_reconstruct = 1;
    return 0;
}

/*
 * Open and read the header of the mailbox with name 'name'
 * The structure pointed to by 'mailbox' is initialized.
 */
int
mailbox_open_header(name, mailbox)
char *name;
struct mailbox *mailbox;
{
    char *path, *acl;
    int r;

    r = mboxlist_lookup(name, &path, &acl);
    if (r) return r;

    return mailbox_open_header_path(name, path, acl, mailbox, 0);
}

/*
 * Open and read the header of the mailbox with name 'name'
 * path 'path', and ACL 'acl'.
 * The structure pointed to by 'mailbox' is initialized.
 */
int
mailbox_open_header_path (name, path, acl, mailbox, suppresslog)
char *name;
char *path;
char *acl;
struct mailbox *mailbox;
int suppresslog;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    int r;
    static struct mailbox zeromailbox;

    *mailbox = zeromailbox;

    strcpy(fnamebuf, path);
    strcat(fnamebuf, FNAME_HEADER);
    mailbox->header = fopen(fnamebuf, "r+");
    
    if (!mailbox->header && !mailbox_doing_reconstruct) {
	if (!suppresslog) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	}
	return IMAP_IOERROR;
    }

    mailbox->name = strsave(name);
    mailbox->path = strsave(path);
    mailbox->acl = strsave(acl);
    mailbox->myrights = acl_myrights(mailbox->acl);

    if (!mailbox->header) return 0;

    r = mailbox_read_header(mailbox);
    if (r && !mailbox_doing_reconstruct) {
	mailbox_close(mailbox);
	return r;
    }

    return 0;
}

#define MAXTRIES 60

/*
 * Open the index and cache files for 'mailbox'.  Also 
 * read the index header.
 */
int 
mailbox_open_index(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    bit32 index_gen = 0, cache_gen = 0;
    int tries = 0;

    if (mailbox->index) fclose(mailbox->index);
    if (mailbox->cache) fclose(mailbox->cache);
    do {
	strcpy(fnamebuf, mailbox->path);
	strcat(fnamebuf, FNAME_INDEX);
	mailbox->index = fopen(fnamebuf, "r+");
	if (mailbox_doing_reconstruct) break;
	if (!mailbox->index) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	    return IMAP_IOERROR;
	}

	strcpy(fnamebuf, mailbox->path);
	strcat(fnamebuf, FNAME_CACHE);
	mailbox->cache = fopen(fnamebuf, "r+");
	if (!mailbox->cache) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	    return IMAP_IOERROR;
	}

	if (fread((char *)&index_gen, sizeof(index_gen), 1,
		  mailbox->index) != 1 ||
	    fread((char *)&cache_gen, sizeof(cache_gen), 1,
		  mailbox->cache) != 1) {
	    return IMAP_MAILBOX_BADFORMAT;
	}
	
	if (index_gen != cache_gen) {
	    fclose(mailbox->index);
	    fclose(mailbox->cache);
	    sleep(1);
	}
    } while (index_gen != cache_gen && tries++ < MAXTRIES);

    if (index_gen != cache_gen) {
	mailbox->index = mailbox->cache = NULL;
	return IMAP_MAILBOX_BADFORMAT;
    }
    mailbox->generation_no = index_gen;

    return mailbox_read_index_header(mailbox);
}

/*
 * Close the mailbox 'mailbox', freeing all associated resources.
 */
mailbox_close(mailbox)
struct mailbox *mailbox;
{
    static struct mailbox zeromailbox;
    int flag;

    fclose(mailbox->header);
    if (mailbox->index) fclose(mailbox->index);
    if (mailbox->cache) fclose(mailbox->cache);
    if (mailbox->quota.file) fclose(mailbox->quota.file);
    free(mailbox->name);
    free(mailbox->path);
    free(mailbox->acl);
    if (mailbox->quota.root) free(mailbox->quota.root);

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
    }

    *mailbox = zeromailbox;
    return 0;
}

/*
 * Read the header of 'mailbox'
 */
int
mailbox_read_header(mailbox)
struct mailbox *mailbox;
{
    char buf[4096];
    int flag;
    char *name, *p;
    struct stat sbuf;
    int n;

    /* Check magic number */
    n = fread(buf, 1, strlen(MAILBOX_HEADER_MAGIC), mailbox->header);
    buf[n] = '\0';
    if (n != strlen(MAILBOX_HEADER_MAGIC) || strcmp(buf, MAILBOX_HEADER_MAGIC)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    fstat(fileno(mailbox->header), &sbuf);
    mailbox->header_mtime = sbuf.st_mtime;

    /* Read quota file pathname */
    if (!fgets(buf, sizeof(buf), mailbox->header)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    buf[strlen(buf)-1] = '\0';
    if (mailbox->quota.root) {
	if (strcmp(mailbox->quota.root, buf) != 0) {
	    assert(mailbox->quota.lock_count == 0);
	    if (mailbox->quota.file) fclose(mailbox->quota.file);
	    mailbox->quota.file = NULL;
	}
	free(mailbox->quota.root);
    }
    if (buf[0]) {
	mailbox->quota.root = strsave(buf);
    }
    else {
	mailbox->quota.root = 0;
    }

    /* Read names of user flags */
    if (!fgets(buf, sizeof(buf), mailbox->header)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    buf[strlen(buf)-1] = '\0';
    name = buf;
    flag = 0;
    while (name && flag < MAX_USER_FLAGS) {
	p = strchr(name, ' ');
	if (p) *p++ = '\0';
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
	mailbox->flagname[flag++] = *name ? strsave(name) : NULL;
	name = p;
    }
    while (flag < MAX_USER_FLAGS) {
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
	mailbox->flagname[flag++] = NULL;
    }

    return 0;
}

/*
 * Read the acl out of the header of 'mailbox'
 */
int
mailbox_read_header_acl(mailbox)
struct mailbox *mailbox;
{
    char buf[4096];
    int n;

    rewind(mailbox->header);

    /* Check magic number */
    n = fread(buf, 1, strlen(MAILBOX_HEADER_MAGIC), mailbox->header);
    buf[n] = '\0';
    if (n != strlen(MAILBOX_HEADER_MAGIC) || strcmp(buf, MAILBOX_HEADER_MAGIC)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Read quota file pathname */
    if (!fgets(buf, sizeof(buf), mailbox->header)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Read names of user flags */
    if (!fgets(buf, sizeof(buf), mailbox->header)) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    /* Read ACL */
    if (!fgets(buf, sizeof(buf), mailbox->header)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    
    buf[strlen(buf)-1] = '\0';
    free(mailbox->acl);
    mailbox->acl = strsave(buf);

    return 0;
}

/*
 * Read the the ACL for 'mailbox'.
 */
int 
mailbox_read_acl(mailbox)
struct mailbox *mailbox;
{
    int r;
    char *acl;

    r = mboxlist_lookup(mailbox->name, (char **)0, &acl);
    if (r) return r;

    free(mailbox->acl);
    mailbox->acl = strsave(acl);
    mailbox->myrights = acl_myrights(mailbox->acl);

    return 0;
}

/*
 * Read the header of the index file for mailbox
 */
int 
mailbox_read_index_header(mailbox)
struct mailbox *mailbox;
{
    struct stat sbuf;
    char buf[INDEX_HEADER_SIZE];
    int n;

    if (!mailbox->index) return IMAP_MAILBOX_BADFORMAT;

    fstat(fileno(mailbox->index), &sbuf);
    mailbox->index_mtime = sbuf.st_mtime;
    mailbox->index_ino = sbuf.st_ino;

    rewind(mailbox->index);
    n = fread(buf, 1, INDEX_HEADER_SIZE, mailbox->index);
    if (n != INDEX_HEADER_SIZE &&
	(n < OFFSET_POP3_LAST_UID || n < ntohl(*((bit32 *)(buf+OFFSET_START_OFFSET))))) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    if (mailbox_doing_reconstruct) {
	mailbox->generation_no = ntohl(*((bit32 *)(buf+OFFSET_GENERATION_NO)));
    }
    mailbox->format = ntohl(*((bit32 *)(buf+OFFSET_FORMAT)));
    mailbox->minor_version = ntohl(*((bit32 *)(buf+OFFSET_MINOR_VERSION)));
    mailbox->start_offset = ntohl(*((bit32 *)(buf+OFFSET_START_OFFSET)));
    mailbox->record_size = ntohl(*((bit32 *)(buf+OFFSET_RECORD_SIZE)));
    mailbox->exists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS)));
    mailbox->last_appenddate = ntohl(*((bit32 *)(buf+OFFSET_LAST_APPENDDATE)));
    mailbox->last_uid = ntohl(*((bit32 *)(buf+OFFSET_LAST_UID)));
    mailbox->quota_mailbox_used = ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)));

    for (n = mailbox->start_offset; n < INDEX_HEADER_SIZE; n++) {
	if (n == OFFSET_UIDVALIDITY+3) {
	    buf[n] = 1;
	}
	else {
	    buf[n] = 0;
	}
    }

    mailbox->pop3_last_uid = ntohl(*((bit32 *)(buf+OFFSET_POP3_LAST_UID)));
    mailbox->uidvalidity = ntohl(*((bit32 *)(buf+OFFSET_UIDVALIDITY)));

    return 0;
}

/*
 * Read an index record from a mailbox
 */
int
mailbox_read_index_record(mailbox, msgno, record)
struct mailbox *mailbox;
unsigned msgno;
struct index_record *record;
{
    int n;
    char buf[INDEX_RECORD_SIZE];

    n = fseek(mailbox->index,
	      mailbox->start_offset + (msgno-1) * mailbox->record_size,
	      0);
    if (n == -1) {
	syslog(LOG_ERR, "IOERROR: seeking index record %u for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    n = fread(buf, 1, INDEX_RECORD_SIZE, mailbox->index);
    if (n != INDEX_RECORD_SIZE) {
	syslog(LOG_ERR,
	       "IOERROR: reading index record %u for %s: got %d of %d",
	       msgno, mailbox->name, n, INDEX_RECORD_SIZE);
	return IMAP_IOERROR;
    }

    record->uid = htonl(*((bit32 *)(buf+OFFSET_UID)));
    record->internaldate = htonl(*((bit32 *)(buf+OFFSET_INTERNALDATE)));
    record->sentdate = htonl(*((bit32 *)(buf+OFFSET_SENTDATE)));
    record->size = htonl(*((bit32 *)(buf+OFFSET_SIZE)));
    record->header_size = htonl(*((bit32 *)(buf+OFFSET_HEADER_SIZE)));
    record->content_offset = htonl(*((bit32 *)(buf+OFFSET_CONTENT_OFFSET)));
    record->cache_offset = htonl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));
    record->last_updated = htonl(*((bit32 *)(buf+OFFSET_LAST_UPDATED)));
    record->system_flags = htonl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));
    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
	record->user_flags[n] = htonl(*((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)));
    }
    return 0;
}

/*
 * Open and read the quota file 'quota'
 */
int
mailbox_read_quota(quota)
struct quota *quota;
{
    char buf[4096];

    if (!quota->root) {
	quota->used = 0;
	quota->limit = -1;
	return 0;
    }

    if (!quota->file) {
	sprintf(buf, "%s%s%s", config_dir, FNAME_QUOTADIR,
		quota->root);
	quota->file = fopen(buf, "r+");
	if (!quota->file) {
	    syslog(LOG_ERR, "IOERROR: opening quota file %s: %m", buf);
	    return IMAP_IOERROR;
	}
    }
    
    rewind(quota->file);
    if (!fgets(buf, sizeof(buf), quota->file)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    quota->used = atol(buf);
    if (!fgets(buf, sizeof(buf), quota->file)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    quota->limit = atoi(buf);

    return 0;
}

/*
 * Lock the header for 'mailbox'.  Reread header if necessary.
 */
int
mailbox_lock_header(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    char *lockfailaction;
    int r;

    if (mailbox->header_lock_count++) return 0;

    assert(mailbox->index_lock_count == 0);
    assert(mailbox->quota.lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_HEADER);

    r = lock_reopen(fileno(mailbox->header), fnamebuf, &sbuf, &lockfailaction);
    if (r) {
	mailbox->header_lock_count--;
	syslog(LOG_ERR, "IOERROR: %s header for %s: %m",
	       lockfailaction, mailbox->name);
	return IMAP_IOERROR;
    }

    rewind(mailbox->header);
    r = mailbox_read_header(mailbox);
    if (r && !mailbox_doing_reconstruct) {
	mailbox_unlock_header(mailbox);
	return r;
    }

    return 0;
}

/*
 * Lock the index file for 'mailbox'.  Reread index file header if necessary.
 */
int
mailbox_lock_index(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->index_lock_count++) return 0;

    assert(mailbox->quota.lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);

    
    for (;;) {
	r = lock_blocking(fileno(mailbox->index));
	if (r == -1) {
	    mailbox->index_lock_count--;
	    syslog(LOG_ERR, "IOERROR: locking index for %s: %m",
		   mailbox->name);
	    return IMAP_IOERROR;
	}

	fstat(fileno(mailbox->index), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating index for %s: %m",
		   mailbox->name);
	    mailbox_unlock_index(mailbox);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	if (r = mailbox_open_index(mailbox)) {
	    return r;
	}
    }

    rewind(mailbox->index);
    r = mailbox_read_index_header(mailbox);
    if (r && !mailbox_doing_reconstruct) {
	mailbox_unlock_index(mailbox);
	return r;
    }

    return 0;
}

/*
 * Place a POP lock on 'mailbox'.
 */
int
mailbox_lock_pop(mailbox)
struct mailbox *mailbox;
{
    int r = -1;

    if (mailbox->pop_lock_count++) return 0;

    r = lock_nonblocking(fileno(mailbox->cache));
    if (r == -1) {
	mailbox->pop_lock_count--;
	if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EACCES) {
	    return IMAP_MAILBOX_POPLOCKED;
	}
	syslog(LOG_ERR, "IOERROR: locking cache for %s: %m", mailbox->name);
	return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Lock the quota file 'quota'.  Reread quota file if necessary.
 */
int
mailbox_lock_quota(quota)
struct quota *quota;
{
    char quota_path[MAX_MAILBOX_PATH];
    char *lockfailaction;
    int r;

    /* assert(mailbox->header_lock_count != 0); */

    if (quota->lock_count++) return 0;

    /* assert(mailbox->seen_lock_count == 0); */

    if (!quota->root) {
	quota->used = 0;
	quota->limit = -1;
	return 0;
    }
    sprintf(quota_path, "%s%s%s", config_dir, FNAME_QUOTADIR, quota->root);
    if (!quota->file) {
	quota->file = fopen(quota_path, "r+");
	if (!quota->file) {
	    syslog(LOG_ERR, "IOERROR: opening quota file %s: %m", quota_path);
	    return IMAP_IOERROR;
	}
    }

    r = lock_reopen(fileno(quota->file), quota_path, 0, &lockfailaction);
    if (r == -1) {
	quota->lock_count--;
	syslog(LOG_ERR, "IOERROR: %s quota %s: %m", lockfailaction,
	       quota->root);
	return IMAP_IOERROR;
    }

    return mailbox_read_quota(quota);
}

/*
 * Release lock on the header for 'mailbox'
 */
mailbox_unlock_header(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->header_lock_count != 0);

    if (--mailbox->header_lock_count == 0) {
	lock_unlock(fileno(mailbox->header));
    }
    return 0;
}

/*
 * Release lock on the index file for 'mailbox'
 */
mailbox_unlock_index(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->index_lock_count != 0);

    if (--mailbox->index_lock_count == 0) {
	lock_unlock(fileno(mailbox->index));
    }
    return 0;
}

/*
 * Release POP lock for 'mailbox'
 */
mailbox_unlock_pop(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->pop_lock_count != 0);

    if (--mailbox->pop_lock_count == 0) {
	lock_unlock(fileno(mailbox->cache));
    }
    return 0;
}

/*
 * Release lock on the quota file 'quota'
 */
mailbox_unlock_quota(quota)
struct quota *quota;
{
    assert(quota->lock_count != 0);

    if (--quota->lock_count == 0 && quota->root) {
	lock_unlock(fileno(quota->file));
    }
    return 0;
}

/*
 * Write the header file for 'mailbox'
 */
int
mailbox_write_header(mailbox)
struct mailbox *mailbox;
{
    int flag;
    FILE *newheader;
    char fnamebuf[MAX_MAILBOX_PATH];
    char newfnamebuf[MAX_MAILBOX_PATH];

    assert(mailbox->header_lock_count != 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_HEADER);
    strcpy(newfnamebuf, fnamebuf);
    strcat(newfnamebuf, ".NEW");

    newheader = fopen(newfnamebuf, "w+");
    if (!newheader) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	return IMAP_IOERROR;
    }

    fputs(MAILBOX_HEADER_MAGIC, newheader);
    fprintf(newheader, "%s\n", mailbox->quota.root ? mailbox->quota.root : "");
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) {
	    fprintf(newheader, "%s ", mailbox->flagname[flag]);
	}
    }
    fprintf(newheader, "\n");
    fprintf(newheader, "%s\n", mailbox->acl);

    fflush(newheader);
    if (ferror(newheader) || fsync(fileno(newheader)) ||
	lock_blocking(fileno(newheader)) == -1 ||
	rename(newfnamebuf, fnamebuf) == -1) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	fclose(newheader);
	unlink(newfnamebuf);
	return IMAP_IOERROR;
    }
    if (mailbox->header) fclose(mailbox->header);
    mailbox->header = newheader;
    return 0;
}

/*
 * Write the index header for 'mailbox'
 */
int
mailbox_write_index_header(mailbox)
struct mailbox *mailbox;
{
    char buf[INDEX_HEADER_SIZE];
    int header_size = INDEX_HEADER_SIZE;
    int n;

    assert(mailbox->index_lock_count != 0);

    rewind(mailbox->index);
    
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = mailbox->generation_no;
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(mailbox->exists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox->last_uid);
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(mailbox->quota_mailbox_used);
    *((bit32 *)(buf+OFFSET_POP3_LAST_UID)) = htonl(mailbox->pop3_last_uid);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox->uidvalidity);

    if (mailbox->start_offset < header_size) header_size = mailbox->start_offset;

    n = fwrite(buf, 1, header_size, mailbox->index);
    if (n != header_size) {
	syslog(LOG_ERR, "IOERROR: writing index header for %s: %m",
	       mailbox->name);
	return IMAP_IOERROR;
    }
    fflush(mailbox->index);
    if (ferror(mailbox->index) || fsync(fileno(mailbox->index))) {
	syslog(LOG_ERR, "IOERROR: writing index header for %s: %m",
	       mailbox->name);
	return IMAP_IOERROR;
    }
    return 0;
}

/*
 * Read an index record from a mailbox
 */
int
mailbox_write_index_record(mailbox, msgno, record)
struct mailbox *mailbox;
unsigned msgno;
struct index_record *record;
{
    int n;
    char buf[INDEX_RECORD_SIZE];

    *((bit32 *)(buf+OFFSET_UID)) = htonl(record->uid);
    *((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(record->internaldate);
    *((bit32 *)(buf+OFFSET_SENTDATE)) = htonl(record->sentdate);
    *((bit32 *)(buf+OFFSET_SIZE)) = htonl(record->size);
    *((bit32 *)(buf+OFFSET_HEADER_SIZE)) = htonl(record->header_size);
    *((bit32 *)(buf+OFFSET_CONTENT_OFFSET)) = htonl(record->content_offset);
    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(record->cache_offset);
    *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(record->last_updated);
    *((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)) = htonl(record->system_flags);
    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
	*((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)) = htonl(record->user_flags[n]);
    }

    n = fseek(mailbox->index,
	      mailbox->start_offset + (msgno-1) * mailbox->record_size,
	      0);
    if (n == -1) {
	syslog(LOG_ERR, "IOERROR: seeking index record %u for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    n = fwrite(buf, 1, INDEX_RECORD_SIZE, mailbox->index);
    if (n != INDEX_RECORD_SIZE) {
	syslog(LOG_ERR, "IOERROR: writing index record %u for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }
    fflush(mailbox->index);
    if (ferror(mailbox->index) || fsync(fileno(mailbox->index))) {
	syslog(LOG_ERR, "IOERROR: writing index record %u for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Append a new record to the index file
 */
int
mailbox_append_index(mailbox, record, start, num)
struct mailbox *mailbox;
struct index_record *record;
int start;
int num;
{
    int i, j, len;
    char *buf, *p;
    long last_offset;

    assert(mailbox->index_lock_count != 0);

    if (mailbox->record_size < INDEX_RECORD_SIZE) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    len = num * mailbox->record_size;
    buf = xmalloc(len);
    memset(buf, 0, len);

    for (i = 0; i < num; i++) {
	p = buf + i*mailbox->record_size;
	*((bit32 *)(p+OFFSET_UID)) = htonl(record[i].uid);
	*((bit32 *)(p+OFFSET_INTERNALDATE)) = htonl(record[i].internaldate);
	*((bit32 *)(p+OFFSET_SENTDATE)) = htonl(record[i].sentdate);
	*((bit32 *)(p+OFFSET_SIZE)) = htonl(record[i].size);
	*((bit32 *)(p+OFFSET_HEADER_SIZE)) = htonl(record[i].header_size);
	*((bit32 *)(p+OFFSET_CONTENT_OFFSET)) = htonl(record[i].content_offset);
	*((bit32 *)(p+OFFSET_CACHE_OFFSET)) = htonl(record[i].cache_offset);
	*((bit32 *)(p+OFFSET_LAST_UPDATED)) = htonl(record[i].last_updated);
	*((bit32 *)(p+OFFSET_SYSTEM_FLAGS)) = htonl(record[i].system_flags);
	p += OFFSET_USER_FLAGS;
	for (j = 0; j < MAX_USER_FLAGS/32; j++, p += 4) {
	    *((bit32 *)p) = htonl(record[i].user_flags[j]);
	}
    }

    last_offset = mailbox->start_offset + start * mailbox->record_size;
    fseek(mailbox->index, last_offset, 0);
    fwrite(buf, len, 1, mailbox->index);
    fflush(mailbox->index);
    if (ferror(mailbox->index) || fsync(fileno(mailbox->index))) {
	syslog(LOG_ERR, "IOERROR: appending index records for %s: %m",
	       mailbox->name);
	ftruncate(fileno(mailbox->index), last_offset);
	return IMAP_IOERROR;
    }

    free(buf);
    return 0;
}

/*
 * Write out the quota 'quota'
 */
int
mailbox_write_quota(quota)
struct quota *quota;
{
    int r;
    char quota_path[MAX_MAILBOX_PATH];
    char new_quota_path[MAX_MAILBOX_PATH];
    FILE *newfile;

    assert(quota->lock_count != 0);

    if (!quota->root) return 0;

    sprintf(quota_path, "%s%s%s", config_dir, FNAME_QUOTADIR,
	    quota->root);
    strcpy(new_quota_path, quota_path);
    strcat(new_quota_path, ".NEW");

    newfile = fopen(new_quota_path, "w+");
    if (!newfile) {
	syslog(LOG_ERR, "IOERROR: creating quota file %s: %m", new_quota_path);
	return IMAP_IOERROR;
    }
    r = lock_blocking(fileno(newfile));
    if (r) {
	syslog(LOG_ERR, "IOERROR: locking quota file %s: %m",
	       new_quota_path);
	return IMAP_IOERROR;
    }

    fprintf(newfile, "%lu\n%d\n", quota->used, quota->limit);
    fflush(newfile);
    if (ferror(newfile) || fsync(fileno(newfile))) {
	syslog(LOG_ERR, "IOERROR: writing quota file %s: %m",
	       new_quota_path);
	return IMAP_IOERROR;
    }

    if (rename(new_quota_path, quota_path)) {
	syslog(LOG_ERR, "IOERROR: renaming quota file %s: %m",
	       quota_path);
	return IMAP_IOERROR;
    }
    if (quota->file) fclose(quota->file);
    quota->file = newfile;

    return 0;
}

/*
 * Perform an expunge operation on 'mailbox'.  If 'iscurrentdir' is nonzero,
 * the current directory is set to the mailbox directory.  If nonzero, the
 * function pointed to by 'decideproc' is called (with 'deciderock') to
 * determine which messages to expunge.  If 'decideproc' is a null pointer,
 * then messages with the \Deleted flag are expunged.
 */
mailbox_expunge(mailbox, iscurrentdir, decideproc, deciderock)
struct mailbox *mailbox;
int iscurrentdir;
int (*decideproc)();
char *deciderock;
{
    int r, n;
    char fnamebuf[MAX_MAILBOX_PATH], fnamebufnew[MAX_MAILBOX_PATH];
    FILE *newindex, *newcache;
    unsigned long *deleted;
    unsigned numdeleted = 0, quotadeleted = 0;
    unsigned newexists;
    char *buf;
    unsigned msgno;
    int lastmsgdeleted = 1;
    unsigned long cachediff = 0;
    unsigned long cachestart = sizeof(bit32);
    unsigned long cache_offset;
    long left;
    char cachebuf[4096];
    char *fnametail;

    /* Lock files and open new index/cache files */
    r = mailbox_lock_header(mailbox);
    if (r) return r;
    r = mailbox_lock_index(mailbox);
    if (r) {
	mailbox_unlock_header(mailbox);
	return r;
    }

    r = mailbox_lock_pop(mailbox);
    if (r) {
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return r;
    }

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);
    strcat(fnamebuf, ".NEW");
    newindex = fopen(fnamebuf, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	mailbox_unlock_pop(mailbox);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_CACHE);
    strcat(fnamebuf, ".NEW");
    newcache = fopen(fnamebuf, "w+");
    if (!newcache) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	fclose(newindex);
	mailbox_unlock_pop(mailbox);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
	return IMAP_IOERROR;
    }

    /* Allocate temporary buffers */
    deleted = (unsigned long *)xmalloc(mailbox->exists*sizeof(unsigned long));
    buf = xmalloc(mailbox->start_offset > mailbox->record_size ?
		  mailbox->start_offset : mailbox->record_size);

    /* Copy over headers */
    rewind(mailbox->index);
    n = fread(buf, 1, mailbox->start_offset, mailbox->index);
    if (n != mailbox->start_offset) {
	syslog(LOG_ERR,
	       "IOERROR: reading index header for %s: got %d of %d bytes",
	       mailbox->name, n, mailbox->start_offset);
	goto fail;
    }
    (*(bit32 *)buf)++;    /* Increment generation number */
    fwrite(buf, 1, mailbox->start_offset, newindex);
    /* Grow the index header if necessary */
    for (n = mailbox->start_offset; n < INDEX_HEADER_SIZE; n++) {
	if (n == OFFSET_UIDVALIDITY+3) {
	    putc(1, newindex);
	}
	else {
	    putc(0, newindex);
	}
    }
    fwrite(buf, 1, sizeof(bit32), newcache);

    /* Copy over records for nondeleted messages */
    for (msgno = 1; msgno <= mailbox->exists; msgno++) {
	n = fread(buf, 1, mailbox->record_size, mailbox->index);
	if (n != mailbox->record_size) {
	    syslog(LOG_ERR,
		   "IOERROR: reading index record %u for %s: got %d of %d bytes",
		   msgno, mailbox->name, n, mailbox->record_size);
	    goto fail;
	}
	
	/* XXX Sanity check */
	if (*((bit32 *)(buf+OFFSET_UID)) == 0) {
	    syslog(LOG_ERR, "IOERROR: %s zero index record %u/%u",
		   mailbox->name, msgno, mailbox->exists);
	    goto fail;
	}

	if (decideproc ? decideproc(deciderock, buf) :
	    (ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS))) & FLAG_DELETED)) {

	    /* Remember UID and size */
	    deleted[numdeleted++] = ntohl(*((bit32 *)(buf+OFFSET_UID)));
	    quotadeleted += ntohl(*((bit32 *)(buf+OFFSET_SIZE)));

	    /* Copy over cache file data */
	    if (!lastmsgdeleted) {
		cache_offset = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));
		left =  cache_offset - cachestart;
		fseek(mailbox->cache, cachestart, 0);
		while (left) {
		    n = fread(cachebuf, 1,
			      left>sizeof(cachebuf) ? sizeof(cachebuf) : left,
			      mailbox->cache);
		    if (!n) {
			syslog(LOG_ERR,
			       "IOERROR: reading cache for %s: end of file",
			       mailbox->name);
			goto fail;
		    }
		    fwrite(cachebuf, 1, n, newcache);
		    left -= n;
		}
		cachestart = cache_offset;
		lastmsgdeleted = 1;
	    }
	}
	else {
	    cache_offset = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));

	    /* Set up for copying cache file data */
	    if (lastmsgdeleted) {
		cachediff += cache_offset - cachestart;
		cachestart = cache_offset;
		lastmsgdeleted = 0;
	    }

	    /* Fix up cache file offset */
	    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(cache_offset - cachediff);

	    fwrite(buf, 1, mailbox->record_size, newindex);
	}
    }

    /* Copy over any remaining cache file data */
    if (!lastmsgdeleted) {
	fseek(mailbox->cache, cachestart, 0);
	while (n = fread(cachebuf, 1, sizeof(cachebuf), mailbox->cache)) {
	    fwrite(cachebuf, 1, n, newcache);
	}
    }

    /* Fix up information in index header */
    rewind(newindex);
    n = fread(buf, 1, mailbox->start_offset, newindex);
    if (n != mailbox->start_offset) {
	syslog(LOG_ERR, "IOERROR: reading index header for %s: got %d of %d",
	       mailbox->name, n, mailbox->start_offset);
	goto fail;
    }
    /* Fix up exists */
/*XXX use mailbox->exists - numdeleted*/
    newexists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS)))-numdeleted;
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);
    /* Fix up quota_mailbox_used */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
      htonl(ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)))-quotadeleted);
    /* Fix up start offset if necessary */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
	*((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }
	
    rewind(newindex);
    fwrite(buf, 1, mailbox->start_offset, newindex);
    
    /* Ensure everything made it to disk */
    fflush(newindex);
    fflush(newcache);
    if (ferror(newindex) || ferror(newcache) ||
	fsync(fileno(newindex)) || fsync(fileno(newcache))) {
	syslog(LOG_ERR, "IOERROR: writing index/cache for %s: %m",
	       mailbox->name);
	goto fail;
    }

    /* Record quota release */
    r = mailbox_lock_quota(&mailbox->quota);
    if (r) goto fail;
    if (mailbox->quota.used >= quotadeleted) {
	mailbox->quota.used -= quotadeleted;
    }
    else {
	mailbox->quota.used = 0;
    }
    r = mailbox_write_quota(&mailbox->quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record free of %u bytes in quota %s",
	       quotadeleted, mailbox->quota.root);
    }
    mailbox_unlock_quota(&mailbox->quota);

    strcpy(fnamebuf, mailbox->path);
    fnametail = fnamebuf + strlen(fnamebuf);
    strcpy(fnametail, FNAME_INDEX);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_ERR, "IOERROR: renaming index file for %s: %m",
	       mailbox->name);
	goto fail;
    }

    strcpy(fnametail, FNAME_CACHE);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_CRIT,
	       "CRITICAL IOERROR: renaming cache file for %s, need to reconstruct: %m",
	       mailbox->name);
	/* Fall through and delete message files anyway */
    }

    if (numdeleted) {
	drop_last(mailbox->name, mailbox->last_uid, newexists);
    }

    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    fclose(newindex);
    fclose(newcache);

    /* Delete message files */
    *fnametail++ = '/';
    for (msgno = 0; msgno < numdeleted; msgno++) {
	if (iscurrentdir) {
	    unlink(mailbox_message_fname(mailbox, deleted[msgno]));
	}
	else {
	    strcpy(fnametail, mailbox_message_fname(mailbox, deleted[msgno]));
	    unlink(fnamebuf);
	}
    }

    free(buf);
    free(deleted);

    return 0;

 fail:
    free(buf);
    free(deleted);
    fclose(newindex);
    fclose(newcache);
    mailbox_unlock_pop(mailbox);
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    return IMAP_IOERROR;
}

char *
mailbox_findquota(name)
char *name;
{
    static char quota_path[MAX_MAILBOX_PATH];
    char *start, *tail;
    struct stat sbuf;

    strcpy(quota_path, config_dir);
    strcat(quota_path, FNAME_QUOTADIR);
    start = quota_path + strlen(quota_path);
    strcpy(start, name);
    lcase(start);

    while (stat(quota_path, &sbuf) == -1) {
	tail = strrchr(start, '.');
	if (!tail) return 0;
	*tail = '\0';
    }
    return start;
}


int 
mailbox_create(name, path, acl, format, mailboxp)
char *name;
char *path;
char *acl;
int format;
struct mailbox *mailboxp;
{
    int r;
    char *p=path;
    char *quota_root;
    char fnamebuf[MAX_MAILBOX_PATH];
    static struct mailbox mailbox, zeromailbox;
    int save_errno;
    struct stat sbuf;

    while (p = strchr(p+1, '/')) {
	*p = '\0';
	if (mkdir(path, 0777) == -1 && errno != EEXIST) {
	    save_errno = errno;
	    if (stat(path, &sbuf) == -1) {
		errno = save_errno;
		syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
		return IMAP_IOERROR;
	    }
	}
	*p = '/';
    }
    if (mkdir(path, 0777) == -1 && errno != EEXIST) {
	save_errno = errno;
	if (stat(path, &sbuf) == -1) {
	    errno = save_errno;
	    syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
	    return IMAP_IOERROR;
	}
    }

    mailbox = zeromailbox;

    quota_root = mailbox_findquota(name);

    strcpy(fnamebuf, path);
    p = fnamebuf + strlen(fnamebuf);
    strcpy(p, FNAME_HEADER);
    mailbox.header = fopen(fnamebuf, "w");
    if (!mailbox.header) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	return IMAP_IOERROR;
    }

    mailbox.name = strsave(name);
    mailbox.path = strsave(path);
    mailbox.acl = strsave(acl);

    strcpy(p, FNAME_INDEX);
    mailbox.index = fopen(fnamebuf, "w");
    if (!mailbox.index) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    strcpy(p, FNAME_CACHE);
    mailbox.cache = fopen(fnamebuf, "w");
    if (!mailbox.cache) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    mailbox.header_lock_count = 1;
    mailbox.index_lock_count = 1;

    if (quota_root) mailbox.quota.root = strsave(quota_root);
    mailbox.generation_no = 0;
    mailbox.format = format;
    mailbox.minor_version = MAILBOX_MINOR_VERSION;
    mailbox.start_offset = INDEX_HEADER_SIZE;
    mailbox.record_size = INDEX_RECORD_SIZE;
    mailbox.exists = 0;
    mailbox.last_appenddate = 0;
    mailbox.last_uid = 0;
    mailbox.quota_mailbox_used = 0;
    mailbox.pop3_last_uid = 0;
    mailbox.uidvalidity = time(0);

    r = mailbox_write_header(&mailbox);
    if (!r) r = mailbox_write_index_header(&mailbox);
    if (!r) {
	fwrite((char *)&mailbox.generation_no, 1, 4, mailbox.cache);
	fflush(mailbox.cache);
	if (ferror(mailbox.cache) || fsync(fileno(mailbox.cache))) {
	    syslog(LOG_ERR, "IOERROR: writing initial cache for %s: %m",
		   mailbox.name);
	    r = IMAP_IOERROR;
	}
    }
    if (!r) r = seen_create(&mailbox);

    if (mailboxp) {
	*mailboxp = mailbox;
    }
    else {
	mailbox_close(&mailbox);
    }
    return r;
}

/*
 * Delete and close the mailbox 'mailbox'.  Closes 'mailbox' whether
 * or not the deletion was successful.
 */
int mailbox_delete(mailbox)
struct mailbox *mailbox;
{
    int r;
    DIR *dirp;
    struct dirent *f;
    char buf[MAX_MAILBOX_PATH];
    char *tail;

    /* Lock everything in sight */
    r =  mailbox_lock_header(mailbox);
    if (!r && !mailbox->index) r = mailbox_open_index(mailbox);
    if (!r) r = mailbox_lock_index(mailbox);
    if (!r) r = mailbox_lock_quota(&mailbox->quota);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    seen_delete(mailbox);

    /* Free any quota being used by this mailbox */
    if (mailbox->quota.used >= mailbox->quota_mailbox_used) {
	mailbox->quota.used -= mailbox->quota_mailbox_used;
    }
    else {
	mailbox->quota.used = 0;
    }
    r = mailbox_write_quota(&mailbox->quota);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record free of %u bytes in quota %s",
	       mailbox->quota_mailbox_used, mailbox->quota.root);
    }
    mailbox_unlock_quota(&mailbox->quota);

    /* remove all files in directory */
    strcpy(buf, mailbox->path);
    tail = buf + strlen(buf);
    *tail++ = '/';
    dirp = opendir(mailbox->path);
    if (dirp) {
	while (f = readdir(dirp)) {
	    strcpy(tail, f->d_name);
	    (void) unlink(buf);
	}
	closedir(dirp);
    }

    /* Remove empty directories, going up path */
    tail--;
    do {
	*tail = '\0';
    } while (rmdir(buf) == 0 && (tail = strrchr(buf, '/')));

    mailbox_close(mailbox);
    return 0;
}

/*
 * Expunge decision proc used by mailbox_rename() to expunge all messages
 * in INBOX
 */
static int expungeall(rock, index)
char *rock;
char *index;
{
    return 1;
}

mailbox_rename(oldname, newname, newpath, isinbox)
char *oldname;
char *newname;
char *newpath;
int isinbox;
{
    int r, r2;
    struct mailbox oldmailbox, newmailbox;
    int flag, msgno;
    struct index_record record;
    char oldfname[MAX_MAILBOX_PATH], newfname[MAX_MAILBOX_PATH];
    char *oldfnametail, *newfnametail;

    /* Open old mailbox and lock */
    r = mailbox_open_header(oldname, &oldmailbox);
    if (r) {
	return r;
    }
    r =  mailbox_lock_header(&oldmailbox);
    if (!r) r = mailbox_open_index(&oldmailbox);
    if (!r) r = mailbox_lock_index(&oldmailbox);
    if (r) {
	mailbox_close(&oldmailbox);
	return r;
    }

    /* Create new mailbox */
    r = mailbox_create(newname, newpath, oldmailbox.acl, oldmailbox.format,
		       &newmailbox);
    if (r) {
	mailbox_close(&oldmailbox);
	return r;
    }

    /* Copy flag names */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (oldmailbox.flagname[flag]) {
	    newmailbox.flagname[flag] = strsave(oldmailbox.flagname[flag]);
	}
    }
    r = mailbox_write_header(&newmailbox);
    if (r) {
	mailbox_close(&newmailbox);
	mailbox_close(&oldmailbox);
	return r;
    }

    /* Check quota if necessary */
    if (newmailbox.quota.root) {
	r = mailbox_lock_quota(&newmailbox.quota);
	if (!oldmailbox.quota.root ||
	    strcmp(oldmailbox.quota.root, newmailbox.quota.root) != 0) {
	    if (!r && newmailbox.quota.limit >= 0 &&
		newmailbox.quota.used + oldmailbox.quota_mailbox_used >
		newmailbox.quota.limit * QUOTA_UNITS) {
		r = IMAP_QUOTA_EXCEEDED;
	    }
	}
	if (r) {
	    mailbox_close(&newmailbox);
	    mailbox_close(&oldmailbox);
	    return r;
	}
    }

    strcpy(oldfname, oldmailbox.path);
    oldfnametail = oldfname + strlen(oldfname);
    strcpy(newfname, newmailbox.path);
    newfnametail = newfname + strlen(newfname);

    /* Copy over index/cache files */
    strcpy(oldfnametail, FNAME_INDEX);
    strcpy(newfnametail, FNAME_INDEX);
    unlink(newfname);		/* Make link() possible */
    r = mailbox_copyfile(oldfname, newfname);
    strcpy(oldfnametail, FNAME_CACHE);
    strcpy(newfnametail, FNAME_CACHE);
    unlink(newfname);
    if (!r) r = mailbox_copyfile(oldfname, newfname);
    if (r) {
	mailbox_close(&newmailbox);
	mailbox_close(&oldmailbox);
	return r;
    }

    /* Copy over message files */
    oldfnametail++;
    newfnametail++;
    for (msgno = 1; msgno <= oldmailbox.exists; msgno++) {
	r = mailbox_read_index_record(&oldmailbox, msgno, &record);
	if (r) break;
	strcpy(oldfnametail, mailbox_message_fname(&oldmailbox, record.uid));
	strcpy(newfnametail, oldfnametail);
	r = mailbox_copyfile(oldfname, newfname);
	if (r) break;
    }
    if (!r) r = seen_copy(&oldmailbox, &newmailbox);

    /* Record new quota usage */
    if (!r && newmailbox.quota.root) {
	newmailbox.quota_mailbox_used = oldmailbox.quota_mailbox_used;
	newmailbox.quota.used += oldmailbox.quota_mailbox_used;
	r = mailbox_write_quota(&newmailbox.quota);
	mailbox_unlock_quota(&newmailbox.quota);
    }
    if (r) goto fail;

    if (isinbox) {
	/* Expunge old mailbox */
	r = mailbox_expunge(&oldmailbox, 0, expungeall, (char *)0);
	mailbox_close(&oldmailbox);
    }
    else {
	r = mailbox_delete(&oldmailbox);
    }

    if (r && newmailbox.quota.root) {
	r2 = mailbox_lock_quota(&newmailbox.quota);
	newmailbox.quota.used += newmailbox.quota_mailbox_used;
	if (!r2) {
	    r2 = mailbox_write_quota(&newmailbox.quota);
	    mailbox_unlock_quota(&newmailbox.quota);
	}
	if (r2) {
	    syslog(LOG_ERR,
	      "LOSTQUOTA: unable to record use of %u bytes in quota %s",
		   newmailbox.quota_mailbox_used, newmailbox.quota.root);
	}
    }
    if (r) goto fail;

    mailbox_close(&newmailbox);
    return 0;

 fail:
    for (msgno = 1; msgno <= oldmailbox.exists; msgno++) {
	if (mailbox_read_index_record(&oldmailbox, msgno, &record)) continue;
	strcpy(newfnametail, mailbox_message_fname(&oldmailbox, record.uid));
	(void) unlink(newfname);
    }
    mailbox_close(&newmailbox);
    mailbox_close(&oldmailbox);
    return r;
}

    
/*
 * Copy (or link) the file 'from' to the file 'to'
 */
int mailbox_copyfile(from, to)
char *from;
char *to;
{
    int srcfd, destfd;
    struct stat sbuf;
    char *src_base = 0;
    unsigned long src_size = 0;
    int n;

    if (link(from, to) == 0) return 0;
    destfd = open(to, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (destfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", to);
	return IMAP_IOERROR;
    }

    srcfd = open(from, O_RDONLY, 0666);
    if (srcfd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", from);
	close(destfd);
	return IMAP_IOERROR;
    }


    if (fstat(srcfd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", from);
	close(srcfd);
	close(destfd);
	return IMAP_IOERROR;
    }
    map_refresh(srcfd, 1, &src_base, &src_size, sbuf.st_size, from, 0);
    
    n = retry_write(destfd, src_base, src_size);

    if (n == -1 || fsync(destfd)) {
	map_free(&src_base, &src_size);
	close(srcfd);
	close(destfd);
	syslog(LOG_ERR, "IOERROR: writing %s: %m", to);
	return IMAP_IOERROR;
    }
    map_free(&src_base, &src_size);
    close(srcfd);
    close(destfd);
    return 0;
}
