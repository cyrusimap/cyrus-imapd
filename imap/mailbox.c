/* mailbox.c -- Mailbox manipulation routines
 *
 *	(C) Copyright 1993 by Carnegie Mellon University
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
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <dirent.h>

#include "acl.h"
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

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
 * Open and read the header of the mailbox with pathname 'path'.
 * The structure pointed to by 'mailbox' is initialized.
 */
int
mailbox_open_header(name, mailbox)
char *name;
struct mailbox *mailbox;
{
    char *path, *acl;
    char fnamebuf[MAX_MAILBOX_PATH];
    int r;
    static struct mailbox zeromailbox;

    *mailbox = zeromailbox;

    r = mboxlist_lookup(name, &path, &acl);
    if (r) return r;

    strcpy(fnamebuf, path);
    strcat(fnamebuf, FNAME_HEADER);
    mailbox->header = fopen(fnamebuf, "r+");
    
    if (!mailbox->header) {
	return IMAP_IOERROR;
    }

    mailbox->name = strsave(name);
    mailbox->path = strsave(path);
    mailbox->acl = strsave(acl);
    mailbox->myrights = acl_myrights(mailbox->acl);

    r = mailbox_read_header(mailbox);
    if (r) {
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
    bit32 index_gen, cache_gen;
    int tries = 0;

    if (mailbox->index) fclose(mailbox->index);
    if (mailbox->cache) fclose(mailbox->cache);
    do {
	strcpy(fnamebuf, mailbox->path);
	strcat(fnamebuf, FNAME_INDEX);
	mailbox->index = fopen(fnamebuf, "r+");
    
	strcpy(fnamebuf, mailbox->path);
	strcat(fnamebuf, FNAME_CACHE);
	mailbox->cache = fopen(fnamebuf, "r+");
    
	if (!mailbox->index || !mailbox->cache) {
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
    if (mailbox->quota) fclose(mailbox->quota);
    free(mailbox->name);
    free(mailbox->path);
    free(mailbox->acl);
    if (mailbox->quota_path) free(mailbox->quota_path);

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
    if (mailbox->quota_path) {
	if (strcmp(mailbox->quota_path, buf) != 0) {
	    assert(mailbox->quota_lock_count != 0);
	    if (mailbox->quota) fclose(mailbox->quota);
	    mailbox->quota = NULL;
	}
	free(mailbox->quota_path);
    }
    if (buf[0]) {
	mailbox->quota_path = strsave(buf);
    }
    else {
	mailbox->quota_path = 0;
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

    fstat(fileno(mailbox->index), &sbuf);
    mailbox->index_mtime = sbuf.st_mtime;
    mailbox->index_ino = sbuf.st_ino;

    rewind(mailbox->index);
    n = fread(buf, 1, INDEX_HEADER_SIZE, mailbox->index);
    if (n != INDEX_HEADER_SIZE) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    mailbox->format = ntohl(*((bit32 *)(buf+4)));
    mailbox->minor_version = ntohl(*((bit32 *)(buf+8)));
    mailbox->start_offset = ntohl(*((bit32 *)(buf+12)));
    mailbox->record_size = ntohl(*((bit32 *)(buf+16)));
    mailbox->exists = ntohl(*((bit32 *)(buf+20)));
    mailbox->last_appenddate = ntohl(*((bit32 *)(buf+24)));
    mailbox->last_uid = ntohl(*((bit32 *)(buf+28)));
    mailbox->quota_mailbox_used = ntohl(*((bit32 *)(buf+32)));

    return 0;
}

/*
 * Read an index record from a mailbox
 */
int
mailbox_read_index_record(mailbox, msgno, record)
struct mailbox *mailbox;
int msgno;
struct index_record *record;
{
    int n;
    char buf[INDEX_RECORD_SIZE];

    n = fseek(mailbox->index,
	      mailbox->start_offset + (msgno-1) * mailbox->record_size,
	      0);
    if (n == -1) return IMAP_IOERROR;

    n = fread(buf, 1, INDEX_RECORD_SIZE, mailbox->index);
    if (n != INDEX_RECORD_SIZE) return IMAP_IOERROR;

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
 * Open and read the quota file for 'mailbox'
 */
int
mailbox_read_quota(mailbox)
struct mailbox *mailbox;
{
    char buf[4096];

    if (!mailbox->quota_path) {
	mailbox->quota_used = 0;
	mailbox->quota_limit = -1;
	return 0;
    }

    if (!mailbox->quota) {
	mailbox->quota = fopen(mailbox->quota_path, "r+");
	if (!mailbox->quota) return IMAP_IOERROR;
    }
    
    rewind(mailbox->quota);
    if (!fgets(buf, sizeof(buf), mailbox->quota)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    mailbox->quota_used = atol(buf);
    if (!fgets(buf, sizeof(buf), mailbox->quota)) {
	return IMAP_MAILBOX_BADFORMAT;
    }
    mailbox->quota_limit = atoi(buf);

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
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->header_lock_count++) return 0;

    assert(mailbox->index_lock_count == 0);
    assert(mailbox->quota_lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_HEADER);

    for (;;) {
	r = flock(fileno(mailbox->header), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    mailbox->header_lock_count--;
	    return IMAP_IOERROR;
	}

	fstat(fileno(mailbox->header), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    mailbox_unlock_header(mailbox);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(mailbox->header);
	mailbox->header = fopen(fnamebuf, "r+");
	if (!mailbox->header) {
	    return IMAP_IOERROR;
	}
    }

    if (sbuffd.st_mtime != mailbox->header_mtime) {
	rewind(mailbox->header);
	r = mailbox_read_header(mailbox);
	if (r) {
	    mailbox_unlock_header(mailbox);
	    return r;
	}
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

    assert(mailbox->quota_lock_count == 0);
    assert(mailbox->seen_lock_count == 0);

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);

    for (;;) {
	r = flock(fileno(mailbox->index), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    mailbox->index_lock_count--;
	    return IMAP_IOERROR;
	}

	fstat(fileno(mailbox->index), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    mailbox_unlock_index(mailbox);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	if (r = mailbox_open_index(mailbox)) {
	    return r;
	}
    }

    if (sbuffd.st_mtime != mailbox->index_mtime) {
	rewind(mailbox->index);
	r = mailbox_read_index_header(mailbox);
	if (r) {
	    mailbox_unlock_index(mailbox);
	    return r;
	}
    }

    return 0;
}

/*
 * Lock the quota file for 'mailbox'.  Reread quota file if necessary.
 */
int
mailbox_lock_quota(mailbox)
struct mailbox *mailbox;
{
    struct stat sbuffd, sbuffile;
    int r;

    assert(mailbox->header_lock_count != 0);

    if (mailbox->quota_lock_count++) return 0;

    assert(mailbox->seen_lock_count == 0);

    if (!mailbox->quota) {
	if (!mailbox->quota_path) {
	    mailbox->quota_used = 0;
	    mailbox->quota_limit = -1;
	    return 0;
	}
	mailbox->quota = fopen(mailbox->quota_path, "r+");
	if (!mailbox->quota) return IMAP_MAILBOX_BADFORMAT;
    }

    for (;;) {
	r = flock(fileno(mailbox->quota), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    mailbox->quota_lock_count--;
	    return IMAP_IOERROR;
	}
	fstat(fileno(mailbox->quota), &sbuffd);
	r = stat(mailbox->quota_path, &sbuffile);
	if (r == -1) {
	    mailbox_unlock_quota(mailbox);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(mailbox->quota);
	mailbox->quota = fopen(mailbox->quota_path, "r+");
	if (!mailbox->quota) {
	    return IMAP_IOERROR;
	}
    }
    return mailbox_read_quota(mailbox);
}

/*
 * Release lock on the header for 'mailbox'
 */
mailbox_unlock_header(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->header_lock_count != 0);

    if (--mailbox->header_lock_count == 0) {
	flock(fileno(mailbox->header), LOCK_UN);
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
	flock(fileno(mailbox->index), LOCK_UN);
    }
    return 0;
}

/*
 * Release lock on the quota file for 'mailbox'
 */
mailbox_unlock_quota(mailbox)
struct mailbox *mailbox;
{
    assert(mailbox->quota_lock_count != 0);

    if (--mailbox->quota_lock_count == 0 && mailbox->quota_path) {
	flock(fileno(mailbox->quota), LOCK_UN);
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
    if (!newheader) return IMAP_IOERROR;

    fputs(MAILBOX_HEADER_MAGIC, newheader);
    fprintf(newheader, "%s\n", mailbox->quota_path ? mailbox->quota_path : "");
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) {
	    fprintf(newheader, "%s ", mailbox->flagname[flag]);
	}
    }
    fprintf(newheader, "\n");

    fflush(newheader);
    if (ferror(newheader) || fsync(fileno(newheader)) ||
	flock(fileno(newheader), LOCK_EX) == -1 ||
	rename(newfnamebuf, fnamebuf) == -1) {
	fclose(newheader);
	unlink(newfnamebuf);
	return IMAP_IOERROR;
    }
    fclose(mailbox->header);
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
    int n;

    assert(mailbox->index_lock_count != 0);

    rewind(mailbox->index);
    
    *((bit32 *)buf) = mailbox->generation_no;
    *((bit32 *)(buf+4)) = htonl(mailbox->format);
    *((bit32 *)(buf+8)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+12)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+16)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+20)) = htonl(mailbox->exists);
    *((bit32 *)(buf+24)) = htonl(mailbox->last_appenddate);
    *((bit32 *)(buf+28)) = htonl(mailbox->last_uid);
    *((bit32 *)(buf+32)) = htonl(mailbox->quota_mailbox_used);

    n = fwrite(buf, 1, INDEX_HEADER_SIZE, mailbox->index);
    if (n != INDEX_HEADER_SIZE) {
	return IMAP_IOERROR;
    }
    fflush(mailbox->index);
    if (ferror(mailbox->index) || fsync(fileno(mailbox->index))) {
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
int msgno;
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
    if (n == -1) return IMAP_IOERROR;

    n = fwrite(buf, 1, INDEX_RECORD_SIZE, mailbox->index);
    if (n != INDEX_RECORD_SIZE) return IMAP_IOERROR;
    fflush(mailbox->index);
    if (ferror(mailbox->index) || fsync(fileno(mailbox->index))) {
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
    bzero(buf, len);

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
	ftruncate(fileno(mailbox->index), last_offset);
	return IMAP_IOERROR;
    }

    free(buf);
    return 0;
}

/*
 * Write out the quota file for 'mailbox'
 */
int
mailbox_write_quota(mailbox)
struct mailbox *mailbox;
{
    int r;
    char buf[MAX_MAILBOX_PATH];
    FILE *newfile;

    assert(mailbox->quota_lock_count != 0);

    if (!mailbox->quota_path) return 0;

    strcpy(buf, mailbox->quota_path);
    strcat(buf, ".NEW");

    newfile = fopen(buf, "w+");
    if (!newfile) {
	return IMAP_IOERROR;
    }
    r = flock(fileno(newfile), LOCK_EX);
    if (r) {
	return IMAP_IOERROR;
    }

    fprintf(newfile, "%lu\n%d\n", mailbox->quota_used, mailbox->quota_limit);
    fflush(newfile);
    if (ferror(newfile) || fsync(fileno(newfile))) {
	return IMAP_IOERROR;
    }

    if (rename(buf, mailbox->quota_path)) {
	return IMAP_IOERROR;
    }
    fclose(mailbox->quota);
    mailbox->quota = newfile;

    return 0;
}

/* XXX
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
    int numdeleted = 0, quotadeleted = 0;
    char *buf;
    int msgno;
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
    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_INDEX);
    strcat(fnamebuf, ".NEW");
    newindex = fopen(fnamebuf, "w+");
    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_CACHE);
    strcat(fnamebuf, ".NEW");
    newcache = fopen(fnamebuf, "w+");
    if (!newindex || !newcache) {
	if (newindex) fclose(newindex);
	mailbox_unlock_index(mailbox);
	mailbox_unlock_header(mailbox);
    }

    /* Allocate temporary buffers */
    deleted = (unsigned long *)xmalloc(mailbox->exists*sizeof(unsigned long));
    buf = xmalloc(mailbox->start_offset > mailbox->record_size ?
		  mailbox->start_offset : mailbox->record_size);

    /* Copy over headers */
    rewind(mailbox->index);
    n = fread(buf, 1, mailbox->start_offset, mailbox->index);
    if (n != mailbox->start_offset) {
	goto fail;
    }
    (*(bit32 *)buf)++;    /* Increment generation number */
    fwrite(buf, 1, mailbox->start_offset, newindex);
    fwrite(buf, 1, sizeof(bit32), newcache);

    /* Copy over records for nondeleted messages */
    for (msgno = 1; msgno <= mailbox->exists; msgno++) {
	n = fread(buf, 1, mailbox->record_size, mailbox->index);
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
		    if (!n) goto fail;
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
	goto fail;
    }
    /* Fix up exists */
    *((bit32 *)(buf+20)) = htonl(ntohl(*((bit32 *)(buf+20)))-numdeleted);
    /* Fix up quota_mailbox_used */
    *((bit32 *)(buf+32)) = htonl(ntohl(*((bit32 *)(buf+32)))-quotadeleted);
    rewind(newindex);
    fwrite(buf, 1, mailbox->start_offset, newindex);
    
    /* Ensure everything made it to disk */
    fflush(newindex);
    fflush(newcache);
    if (ferror(newindex) || ferror(newcache) ||
	fsync(fileno(newindex)) || fsync(fileno(newcache))) {
	goto fail;
    }

    /* Record quota release */
    r = mailbox_lock_quota(mailbox);
    if (r) goto fail;
    mailbox->quota_used -= quotadeleted;
    r = mailbox_write_quota(mailbox);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record free of %d bytes in quota file %s",
	       quotadeleted, mailbox->quota_path);
    }
    mailbox_unlock_quota(mailbox);

    strcpy(fnamebuf, mailbox->path);
    fnametail = fnamebuf + strlen(fnamebuf);
    strcpy(fnametail, FNAME_INDEX);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    rename(fnamebufnew, fnamebuf);

    strcpy(fnametail, FNAME_CACHE);
    strcpy(fnamebufnew, fnamebuf);
    strcat(fnamebufnew, ".NEW");
    if (rename(fnamebufnew, fnamebuf)) {
	/* XXX in serious trouble */
    }
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
    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);
    return IMAP_IOERROR;
}

static char *
mailbox_findquota(name)
char *name;
{
    return 0;
}

int 
mailbox_create(name, path, format, mailboxp)
char *name;
char *path;
int format;
struct mailbox *mailboxp;
{
    int r;
    char *p=path;
    char *quota_path;
    char fnamebuf[MAX_MAILBOX_PATH];
    static struct mailbox mailbox, zeromailbox;

    while (p = strchr(p+1, '/')) {
	*p = '\0';
	if (mkdir(path, 0777) == -1 && errno != EEXIST) {
	    return IMAP_IOERROR;
	}
	*p = '/';
    }
    if (mkdir(path, 0777) == -1 && errno != EEXIST) {
	return IMAP_IOERROR;
    }

    mailbox = zeromailbox;

    quota_path = mailbox_findquota(name);

    strcpy(fnamebuf, path);
    p = fnamebuf + strlen(fnamebuf);
    strcpy(p, FNAME_HEADER);
    mailbox.header = fopen(fnamebuf, "w");
    if (!mailbox.header) return IMAP_IOERROR;

    mailbox.name = strsave(name);
    mailbox.path = strsave(path);
    mailbox.acl = strsave("");

    strcpy(p, FNAME_INDEX);
    mailbox.index = fopen(fnamebuf, "w");
    if (!mailbox.index) {
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    strcpy(p, FNAME_CACHE);
    mailbox.cache = fopen(fnamebuf, "w");
    if (!mailbox.cache) {
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    mailbox.header_lock_count = 1;
    mailbox.index_lock_count = 1;

    if (quota_path) mailbox.quota_path = strsave(quota_path);
    mailbox.generation_no = 0;
    mailbox.format = format;
    mailbox.minor_version = MAILBOX_MINOR_VERSION;
    mailbox.start_offset = INDEX_HEADER_SIZE;
    mailbox.record_size = INDEX_RECORD_SIZE;
    mailbox.exists = 0;
    mailbox.last_appenddate = 0;
    mailbox.last_uid = 0;
    mailbox.quota_mailbox_used = 0;

    r = mailbox_write_header(&mailbox);
    if (!r) r = mailbox_write_index_header(&mailbox);
    if (!r) {
	fwrite((char *)&mailbox.generation_no, 1, 4, mailbox.cache);
	fflush(mailbox.cache);
	if (ferror(mailbox.cache) || fsync(fileno(mailbox.cache))) {
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
    if (!r) r = mailbox_lock_quota(mailbox);
    if (r) {
	mailbox_close(mailbox);
	return r;
    }

    seen_delete(mailbox);

    /* Free any quota being used by this mailbox */
    mailbox->quota_used -= mailbox->quota_mailbox_used;
    r = mailbox_write_quota(mailbox);
    if (r) {
	syslog(LOG_ERR,
	       "LOSTQUOTA: unable to record free of %d bytes in quota file %s",
	       mailbox->quota_mailbox_used, mailbox->quota_path);
    }
    mailbox_unlock_quota(mailbox);

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
static int expungeall(name, rock)
char *name;
char *rock;
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
    r = mailbox_create(newname, newpath, oldmailbox.format, &newmailbox);
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
    if (newmailbox.quota_path) {
	r = mailbox_lock_quota(&newmailbox);
	if (!oldmailbox.quota_path ||
	    strcmp(oldmailbox.quota_path, newmailbox.quota_path) != 0) {
	    if (!r && newmailbox.quota_limit >= 0 &&
		newmailbox.quota_used + oldmailbox.quota_mailbox_used >
		newmailbox.quota_limit * QUOTA_UNITS) {
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
    if (!r && newmailbox.quota_path) {
	newmailbox.quota_mailbox_used = oldmailbox.quota_mailbox_used;
	newmailbox.quota_used += oldmailbox.quota_mailbox_used;
	r = mailbox_write_quota(&newmailbox);
	mailbox_unlock_quota(&newmailbox);
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

    if (r && newmailbox.quota_path) {
	r2 = mailbox_lock_quota(&newmailbox);
	newmailbox.quota_used -= newmailbox.quota_mailbox_used;
	if (!r2) {
	    r2 = mailbox_write_quota(&newmailbox);
	    mailbox_unlock_quota(&newmailbox);
	}
	if (r2) {
	    syslog(LOG_ERR,
	      "LOSTQUOTA: unable to record free of %d bytes in quota file %s",
		   newmailbox.quota_mailbox_used, newmailbox.quota_path);
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
    FILE *srcfile, *destfile;
    char buf[4096];
    int n;

    if (link(from, to) == 0) return 0;
    destfile = fopen(from, "w");
    if (!destfile) return IMAP_IOERROR;
    srcfile = fopen(to, "r");
    if (!srcfile) {
	fclose(destfile);
	return IMAP_IOERROR;
    }

    while (n = fread(buf, 1, sizeof(buf), srcfile)) {
	fwrite(buf, 1, n, destfile);
    }
    fflush(destfile);
    if (ferror(destfile) || fsync(fileno(destfile))) {
	fclose(srcfile);
	fclose(destfile);
	return IMAP_IOERROR;
    }
    fclose(srcfile);
    fclose(destfile);
    return 0;
}
