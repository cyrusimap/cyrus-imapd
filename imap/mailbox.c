/*
 * Mailbox manipulation routines
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <acl.h>
#include "assert.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

/*
 * Open and read the header of the mailbox with pathname 'path'.
 * The structure pointed to by 'mailbox' is initialized.
 */
mailbox_open_header(name, mailbox)
char *name;
struct mailbox *mailbox;
{
    char *path;
    char fnamebuf[MAX_MAILBOX_PATH];
    int r;
    static struct mailbox zeromailbox;

    *mailbox = zeromailbox;

    r = mboxlist_nametopath(name, &path);
    if (r) return r;

    strcpy(fnamebuf, path);
    strcat(fnamebuf, FNAME_HEADER);
    mailbox->header = fopen(fnamebuf, "r+");
    
    if (!mailbox->header) {
	return IMAP_IOERROR;
    }

    mailbox->name = strsave(name);
    mailbox->path = strsave(path);

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
mailbox_open_index(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    bit32 index_gen, cache_gen;
    int tries = 0;

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
    if (mailbox->seen) fclose(mailbox->seen);
    if (mailbox->quota) fclose(mailbox->quota);
    free(mailbox->name);
    free(mailbox->path);
    if (mailbox->quota_path) free(mailbox->quota_path);

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) free(mailbox->flagname[flag]);
    }

    if (mailbox->acl) free(mailbox->acl);
    
    *mailbox = zeromailbox;
    return 0;
}

/*
 * Read the header of 'mailbox'
 */
mailbox_read_header(mailbox)
struct mailbox *mailbox;
{
    char buf[4096];
    int flag;
    char *name, *p;
    struct stat sbuf;
    int aclbufsize, n;

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
    mailbox->quota_path = strsave(buf);

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

    /* Read and interpret ACL */
    if (mailbox->acl) free(mailbox->acl);
    aclbufsize = 128;
    p = mailbox->acl = xmalloc(aclbufsize);
    while (fgets(p, aclbufsize - (p - mailbox->acl), mailbox->header)) {
	if (*p == '\n' && (p == mailbox->acl || p[-1] == '\n')) {
	    *p = '\0';
	    break;
	}
	p += strlen(p);
	if (p - mailbox->acl + 1 >= aclbufsize) {
	    n = p - mailbox->acl;
	    aclbufsize *= 2;
	    mailbox->acl = xrealloc(mailbox->acl, aclbufsize);
	    p = mailbox->acl + n;
	}
    }
    mailbox->my_acl = acl_myacl(mailbox->acl);

    return 0;
}

/*
 * Read the header of the index file for mailbox
 */
mailbox_read_index_header(mailbox)
struct mailbox *mailbox;
{
    struct stat sbuf;
    char buf[1024];
    int n;

    fstat(fileno(mailbox->index), &sbuf);
    mailbox->index_mtime = sbuf.st_mtime;
    mailbox->index_ino = sbuf.st_ino;
    mailbox->index_size = sbuf.st_size;

    rewind(mailbox->index);
    n = fread(buf, sizeof(bit32), 8, mailbox->index);
    if (n != 8) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    mailbox->format = ntohl(*((bit32 *)(buf+4)));
    mailbox->minor_version = ntohl(*((bit32 *)(buf+8)));
    mailbox->start_offset = ntohl(*((bit32 *)(buf+12)));
    mailbox->record_size = ntohl(*((bit32 *)(buf+16)));
    mailbox->last_internaldate = ntohl(*((bit32 *)(buf+20)));
    mailbox->last_uid = ntohl(*((bit32 *)(buf+24)));
    mailbox->quota_mailbox_used = ntohl(*((bit32 *)(buf+28)));

    return 0;
}

/*
 * Open and read the quota file for 'mailbox'
 */
mailbox_read_quota(mailbox)
struct mailbox *mailbox;
{
    char buf[4096];

    assert(mailbox->quota_path);

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
mailbox_lock_header(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->header_lock_count++) return 0;

    assert(mailbox->index_lock_count == 0);
    assert(mailbox->seen_lock_count == 0);
    assert(mailbox->quota_lock_count == 0);

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
mailbox_lock_index(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuffd, sbuffile;
    int r;

    if (mailbox->index_lock_count++) return 0;

    assert(mailbox->seen_lock_count == 0);
    assert(mailbox->quota_lock_count == 0);

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

	fclose(mailbox->index);
	fclose(mailbox->cache);
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
mailbox_lock_quota(mailbox)
struct mailbox *mailbox;
{
    struct stat sbuffd, sbuffile;
    int r;

    assert(mailbox->header_lock_count != 0);

    if (mailbox->quota_lock_count++) return 0;

    if (!mailbox->quota) {
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

    if (--mailbox->quota_lock_count == 0) {
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
    fprintf(newheader, "%s\n", mailbox->quota_path);
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (mailbox->flagname[flag]) {
	    fprintf(newheader, "%s ", mailbox->flagname[flag]);
	}
    }
    fprintf(newheader, "\n%s\n", mailbox->acl);

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
    char buf[1024];
    int n;

    assert(mailbox->index_lock_count != 0);

    rewind(mailbox->index);
    
    *((bit32 *)buf) = mailbox->generation_no;
    *((bit32 *)(buf+4)) = htonl(mailbox->format);
    *((bit32 *)(buf+8)) = htonl(mailbox->minor_version);
    *((bit32 *)(buf+12)) = htonl(mailbox->start_offset);
    *((bit32 *)(buf+16)) = htonl(mailbox->record_size);
    *((bit32 *)(buf+20)) = htonl(mailbox->last_internaldate);
    *((bit32 *)(buf+24)) = htonl(mailbox->last_uid);
    *((bit32 *)(buf+28)) = htonl(mailbox->quota_mailbox_used);

    n = fwrite(buf, sizeof(bit32), 8, mailbox->index);
    if (n != 8) {
	return IMAP_IOERROR;
    }
    fflush(mailbox->index);
    if (ferror(mailbox->index) || fsync(fileno(mailbox->index))) {
	return IMAP_IOERROR;
    }
    return 0;
}

/*
 * Append a new record to the index file
 */
mailbox_append_index(mailbox, record, num)
struct mailbox *mailbox;
struct index_record *record;
int num;
{
    int i, j, len;
    char *buf, *p;
    long last_offset;

    assert(mailbox->index_lock_count != 0);

    if (mailbox->record_size < (7 + (MAX_USER_FLAGS/32)) * 4) {
	return IMAP_MAILBOX_BADFORMAT;
    }

    len = num * mailbox->record_size;
    buf = xmalloc(len);
    bzero(buf, len);

    for (i = 0; i < num; i++) {
	p = buf + i*mailbox->record_size;
	*((bit32 *)p) = htonl(record[i].uid);
	*((bit32 *)(p+4)) = htonl(record[i].internaldate);
	*((bit32 *)(p+8)) = htonl(record[i].size);
	*((bit32 *)(p+12)) = htonl(record[i].header_size);
	*((bit32 *)(p+16)) = htonl(record[i].content_offset);
	*((bit32 *)(p+20)) = htonl(record[i].cache_offset);
	*((bit32 *)(p+24)) = htonl(record[i].last_updated);
	*((bit32 *)(p+28)) = htonl(record[i].system_flags);
	p += 32;
	for (j = 0; j < MAX_USER_FLAGS/32; j++, p += 4) {
	    *((bit32 *)p) = htonl(record[i].user_flags[j]);
	}
    }

    last_offset = fseek(mailbox->index, 0L, 2);
    fwrite(buf, len, 1, mailbox->index);
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
mailbox_write_quota(mailbox)
struct mailbox *mailbox;
{
    int r;
    char buf[MAX_MAILBOX_PATH];
    FILE *newfile;

    assert(mailbox->quota_lock_count != 0);

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


