/*
 * Storage for /Recent and /Seen state on local filesystem
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "assert.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xmalloc.h"

extern int errno;

#define FNAME_SEEN "/cyrus.seen"

struct seen {
    FILE *file;
    long offset;
    long length;
    long size;
    struct mailbox *mailbox;
    char *user;
};

/*
 * Open the database for 'user's state in 'mailbox'.
 * Returns pointer to abstract database type in buffer pointed to
 * by 'seendbptr'.
 */
int seen_open(mailbox, user, seendbptr)
struct mailbox *mailbox;
char *user;
struct seen **seendbptr;
{
    struct seen *seendb;
    char fnamebuf[MAX_MAILBOX_PATH];
    
    seendb = (struct seen *)xmalloc(sizeof(struct seen));
    seendb->mailbox = mailbox;
    seendb->user = strsave(user);
    
    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    seendb->file = fopen(fnamebuf, "r+");
    if (!seendb->file) {
	return IMAP_IOERROR;
    }

    seendb->offset = 0;
    seendb->mailbox->seen_lock_count = 0;
    *seendbptr = seendb;
    return 0;
}

/*
 * Lock the database (if it isn't locked already) and read the user's
 * entry, returning it in the buffers pointed to by 'lasttimeptr',
 * 'lastuidptr', and 'seenuidsptr'.  A malloc'ed string is placed in
 * the latter and the caller is responsible for freeing it.
 */
#define BUFGROW 512
int seen_lockread(seendb, lasttimeptr, lastuidptr, seenuidsptr)
struct seen *seendb;
time_t *lasttimeptr;
unsigned *lastuidptr;
char **seenuidsptr;
{
    int r;
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuffd, sbuffile;
    char *buf = 0, *p;
    unsigned long left;
    int length;
    
    strcpy(fnamebuf, seendb->mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    /* Lock the database, reopening it if it got replaced */
    while (!seendb->mailbox->seen_lock_count) {
	r = flock(fileno(seendb->file), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    return IMAP_IOERROR;
	}

	fstat(fileno(seendb->file), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    seen_unlock(seendb);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) {
	    seendb->mailbox->seen_lock_count = 1;
	    seendb->size = sbuffd.st_size;
	}
	else {
	    fclose(seendb->file);
	    seendb->file = fopen(fnamebuf, "r+");
	    if (!seendb->file) return IMAP_IOERROR;
	}
    }
    
    /* Find record for user */
    seendb->offset = n_binarySearchFD(fileno(seendb->file), seendb->user,
				      0, &buf, &left,
				      seendb->offset, seendb->size);

    if (seendb->offset == -1) {
	return IMAP_IOERROR;
    }

    *lasttimeptr = 0;
    *lastuidptr = 0;
    if (!left) {
	/* No record for user */
	seendb->length = 0;
	*seenuidsptr = strsave("");
	return 0;
    }

    /* Skip over username we know is there */
    length = strlen(seendb->user)+1;
    buf += length;
    left -= length;

    /* Parse last-read timestamp */
    while (left && isdigit(*buf)) {
	*lasttimeptr = *lasttimeptr * 10 + *buf++ - '0';
	left--;
	length++;
    }
    if (left && *buf != '\n') {
	left--;
	length++;
	buf++;
    }

    /* Parse last-read uid */
    while (left && isdigit(*buf)) {
	*lastuidptr = *lastuidptr * 10 + *buf++ - '0';
	left--;
	length++;
    }
    if (left && *buf != '\n') {
	left--;
	length++;
	buf++;
    }

    /* Scan for end of uids */
    p = buf;
    while (left && !isspace(*p)) {
	p++;
	left--;
	length++;
    }

    /* Copy what we have so far into malloc'ed space */
    *seenuidsptr = xmalloc(p - buf + 1);
    strncpy(*seenuidsptr, buf, p - buf);
    (*seenuidsptr)[p - buf] = '\0';

    while (!left) {
	/* Grow the malloc'ed space and read more data into it */
	*seenuidsptr = xrealloc(*seenuidsptr, strlen(*seenuidsptr)+BUFGROW+1);
	p = *seenuidsptr + strlen(*seenuidsptr);
	fseek(seendb->file, seendb->offset + length, 0);
	left = fread(p, 1, BUFGROW, seendb->file);

	/* Keep scanning for the end of uids */
	while (left && !isspace(*p)) {
	    p++;
	    left--;
	    length++;
	}
	if (!left) *p = '\0';
    }

    /* Scan for terminating newline */
    while (left && *p != '\n') {
	*p++ = '\0';		/* In case we have to terminate *seenuidsptr */
	left--;
	length++;
    }
    if (!left) {
	/* Read more data, keep scanning for terminating newline */
	fseek(seendb->file, seendb->offset + length, 0);
	left = fread(fnamebuf, 1, sizeof(fnamebuf), seendb->file);
	p = fnamebuf;
	
	while (left && *p != '\n') {
	    p++;
	    left--;
	    length++;
	}
    }
    *p = '\0';			/* In case we have to terminate *seenuidsptr */

    length++;			/* Count the terminating newline */
    seendb->length = length;
    return 0;
}

/*
 * Write out new data for the user
 */
#define PADSIZE 30
#define PRUNESIZE 100
int seen_write(seendb, lasttime, lastuid, seenuids)
struct seen *seendb;
time_t lasttime;
unsigned lastuid;
char *seenuids;
{
    char timeuidbuf[80];
    int length;
    FILE *writefile;
    int replace;
    char fnamebuf[MAX_MAILBOX_PATH];
    char newfnamebuf[MAX_MAILBOX_PATH];
    int n, left;
    char buf[4096];
    
    assert(seendb->mailbox->seen_lock_count != 0);

    sprintf(timeuidbuf, "%d %u", lasttime, lastuid);
    
    length = strlen(seendb->user)+1+strlen(timeuidbuf)+1+strlen(seenuids);

    /* Replace the entire file if existing record too short or too long */
    replace = (length >= seendb->length || length+PRUNESIZE < seendb->length);

    if (replace) {
	strcpy(fnamebuf, seendb->mailbox->path);
	strcat(fnamebuf, FNAME_SEEN);
	strcpy(newfnamebuf, fnamebuf);
	strcat(newfnamebuf, ".NEW");

	writefile = fopen(newfnamebuf, "w+");
	if (!writefile) return IMAP_IOERROR;

	/* Copy the part of file before the user's entry */
	fseek(seendb->file, 0, 0);
	left = seendb->offset;
	while (left) {
	    n = fread(buf, 1, left < sizeof(buf) ? left : sizeof(buf),
		      seendb->file);
	    if (n == 0) {
		fclose(writefile);
		unlink(newfnamebuf);
		return IMAP_IOERROR;
	    }
	    fwrite(buf, 1, n, writefile);
	    left -= n;
	}
    }
    else {
	/* Just seek to the user's old record */
	writefile = seendb->file;
	fseek(writefile, seendb->offset, 0);
    }

    fprintf(writefile, "%s\t%s %s", seendb->user, timeuidbuf, seenuids);

    if (replace) {
	/* Write out extra padding, newline, adjust length */
	for (n = 0; n < PADSIZE; n++) {
	    buf[n] = ' ';
	}
	buf[n] = '\n';
	fwrite(buf, 1, PADSIZE+1, writefile);
	length += PADSIZE+1;
	
	/* Skip over old record, Copy part of file after user's entry */
	if (seendb->length) fseek(seendb->file, seendb->length, 1);
	while (n = fread(buf, 1, sizeof(buf), seendb->file)) {
	    fwrite(buf, 1, n, writefile);
	}

	/* Flush and swap in the new file */
	fflush(writefile);
	if (ferror(writefile) || fsync(fileno(writefile)) ||
	    flock(fileno(writefile), LOCK_EX) == -1 ||
	    rename(newfnamebuf, fnamebuf) == -1) {
	    fclose(writefile);
	    unlink(newfnamebuf);
	    return IMAP_IOERROR;
	}
	fclose(seendb->file);
	seendb->file = writefile;
	seendb->length = length;
    }
    else {
	/* Write out extra padding */
	while (++length < seendb->length) putc(' ', writefile);

	fflush(writefile);
	if (ferror(writefile) || fsync(fileno(writefile))) {
	    return IMAP_IOERROR;
	}
    }
	
    return 0;
}

/*
 * Unlock the database
 */
int seen_unlock(seendb)
struct seen *seendb;
{
    int r;

    if (seendb->mailbox->seen_lock_count == 0) return 0;

    seendb->mailbox->seen_lock_count = 0;
    r = flock(fileno(seendb->file), LOCK_UN);

    if (r == -1) return IMAP_IOERROR;
    return 0;
}

/*
 * Close the database
 */
int seen_close(seendb)
struct seen *seendb;
{
    fclose(seendb->file);
    free(seendb->user);
    free((char *)seendb);
    return 0;
}

/*
 * Make the \Seen database for the newly created mailbox 'mailbox'.
 */
int
seen_create(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    FILE *f;

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);
    
    f = fopen(fnamebuf, "w");
    if (!f) return IMAP_IOERROR;
    fclose(f);
    return 0;
}

/*
 * Remove the \Seen database for the mailbox 'mailbox'.
 */
int
seen_delete(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    FILE *f;
    int r;
    struct stat sbuffd, sbuffile;

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);
    
    f = fopen(fnamebuf, "r+");
    if (!f) return IMAP_IOERROR;

    for (;;) {
	r = flock(fileno(f), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    fclose(f);
	    return IMAP_IOERROR;
	}

	fstat(fileno(f), &sbuffd);
	r = stat(fnamebuf, &sbuffile);
	if (r == -1) {
	    fclose(f);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) {
	    break;
	}
	else {
	    fclose(f);
	    f = fopen(fnamebuf, "r+");
	    if (!f) return IMAP_IOERROR;
	}
    }

    unlink(fnamebuf);
    fclose(f);
    return 0;
}

int seen_copy(oldmailbox, newmailbox)
struct mailbox *oldmailbox;
struct mailbox *newmailbox;
{
    char oldfname[MAX_MAILBOX_PATH];
    char newfname[MAX_MAILBOX_PATH];

    strcpy(oldfname, oldmailbox->path);
    strcat(oldfname, FNAME_SEEN);
    strcpy(newfname, newmailbox->path);
    strcat(newfname, FNAME_SEEN);
    return mailbox_copyfile(oldfname, newfname);
}

    
