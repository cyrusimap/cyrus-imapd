/* seen_local.c -- Storage for /Recent and /Seen state on local filesystem
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
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <syslog.h>

#include "assert.h"
#include "map.h"
#include "bsearch.h"
#include "lock.h"
#include "retry.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xmalloc.h"

extern int errno;

#define FNAME_SEEN "/cyrus.seen"

struct seen {
    int fd;
    const char *base;
    unsigned long size;
    long ino;
    long offset;
    long length;
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
const char *user;
struct seen **seendbptr;
{
    struct seen *seendb;
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    
    seendb = (struct seen *)xmalloc(sizeof(struct seen));
    seendb->mailbox = mailbox;
    seendb->user = xstrdup(user);
    
    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    seendb->fd = open(fnamebuf, O_RDWR, 0666);
    if (seendb->fd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	free(seendb->user);
	free((char *)seendb);
	return IMAP_IOERROR;
    }

    if (fstat(seendb->fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", fnamebuf);
	close(seendb->fd);
	free(seendb->user);
	free((char *)seendb);
	return IMAP_IOERROR;
    }
    seendb->ino = sbuf.st_ino;

    seendb->base = 0;
    seendb->size = 0;
    map_refresh(seendb->fd, 1, &seendb->base, &seendb->size, sbuf.st_size,
		fnamebuf, 0);

    seendb->offset = 0;
    seendb->mailbox->seen_lock_count = 0;
    *seendbptr = seendb;
    return 0;
}

/*
 * Lock the database (if it isn't locked already) and read the user's
 * entry, returning it in the buffers pointed to by 'lastreadptr',
 * 'lastuidptr', and 'seenuidsptr'.  A malloc'ed string is placed in
 * the latter and the caller is responsible for freeing it.
 */
#define BUFGROW 512
int seen_lockread(seendb, lastreadptr, lastuidptr, lastchangeptr, seenuidsptr)
struct seen *seendb;
time_t *lastreadptr;
unsigned *lastuidptr;
time_t *lastchangeptr;
char **seenuidsptr;
{
    int r;
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    const char *lockfailaction;
    const char *buf = 0, *p;
    unsigned long left;
    unsigned long length, namelen;
    
    strcpy(fnamebuf, seendb->mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    /* Lock the database */
    if (!seendb->mailbox->seen_lock_count) {
	r = lock_reopen(seendb->fd, fnamebuf, &sbuf, &lockfailaction);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fnamebuf);
	    return IMAP_IOERROR;
	}

	seendb->mailbox->seen_lock_count = 1;

	if (seendb->ino != sbuf.st_ino) {
	    map_free(&seendb->base, &seendb->size);
	    map_refresh(seendb->fd, 1, &seendb->base, &seendb->size,
			sbuf.st_size, fnamebuf, 0);
	}
    }
    
    /* Find record for user */
    seendb->offset = bsearch_mem(seendb->user, 1, seendb->base, seendb->size,
				 seendb->offset, &length);

    seendb->length = length;

    *lastreadptr = 0;
    *lastuidptr = 0;
    *lastchangeptr = 0;
    if (!length) {
	/* No record for user */
	*seenuidsptr = xstrdup("");
	return 0;
    }

    /* Skip over username we know is there */
    namelen = strlen(seendb->user)+1;
    buf = seendb->base + seendb->offset + namelen;
    left = length - namelen;

    /* Parse last-read timestamp */
    while (left && isdigit(*buf)) {
	*lastreadptr = *lastreadptr * 10 + *buf++ - '0';
	left--;
    }
    if (left && *buf != '\n') {
	left--;
	buf++;
    }

    /* Parse last-read uid */
    while (left && isdigit(*buf)) {
	*lastuidptr = *lastuidptr * 10 + *buf++ - '0';
	left--;
    }
    if (left && *buf != '\n') {
	left--;
	buf++;
    }

    /* Scan for end of uids or last-change timestamp */
    p = buf;
    while (left && !isspace(*p)) {
	p++;
	left--;
    }

    if (left > 1 && p[0] == ' ' && isdigit(p[1])) {
	/* Have a last-change timestamp */
	while (buf < p) {
	    *lastchangeptr = *lastchangeptr * 10 + *buf++ - '0';
	}
	buf++;
	p++;
	left--;

	/* Scan for end of uids */
	while (left && !isspace(*p)) {
	    p++;
	    left--;
	}
    }

    /* Copy uids into malloc'ed space */
    *seenuidsptr = xmalloc(p - buf + 1);
    strncpy(*seenuidsptr, buf, p - buf);
    (*seenuidsptr)[p - buf] = '\0';

    return 0;
}

/*
 * Write out new data for the user
 */
#define PADSIZE 30
int seen_write(seendb, lastread, lastuid, lastchange, seenuids)
struct seen *seendb;
time_t lastread;
unsigned lastuid;
time_t lastchange;
char *seenuids;
{
    char timeuidbuf[80];
    int length;
    int writefd;
    int replace;
    char fnamebuf[MAX_MAILBOX_PATH];
    char newfnamebuf[MAX_MAILBOX_PATH];
    int n;
    struct iovec iov[10];
    int num_iov;
    struct stat sbuf;
    static const char padbuf[/* 100 */] = {
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 
    };
#define PRUNESIZE sizeof(padbuf)

    assert(seendb->mailbox->seen_lock_count != 0);

    sprintf(timeuidbuf, "\t%u %u %u ", lastread, lastuid, lastchange);
    
    length = strlen(seendb->user)+strlen(timeuidbuf)+strlen(seenuids)+1;

    /* Replace the entire file if existing record too short or too long */
    replace = (length >= seendb->length || length+PRUNESIZE < seendb->length);

    num_iov = 0;

    if (replace) {
	strcpy(fnamebuf, seendb->mailbox->path);
	strcat(fnamebuf, FNAME_SEEN);
	strcpy(newfnamebuf, fnamebuf);
	strcat(newfnamebuf, ".NEW");

	writefd = open(newfnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
	if (writefd == -1) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", newfnamebuf);
	    return IMAP_IOERROR;
	}

	iov[num_iov].iov_base = (char *)seendb->base;
	iov[num_iov++].iov_len = seendb->offset;
    }
    iov[num_iov].iov_base = seendb->user;
    iov[num_iov++].iov_len = strlen(seendb->user);
    iov[num_iov].iov_base = timeuidbuf;
    iov[num_iov++].iov_len = strlen(timeuidbuf);
    iov[num_iov].iov_base = seenuids;
    iov[num_iov++].iov_len = strlen(seenuids);
    iov[num_iov].iov_base = (char *)padbuf;
    if (replace) {
	iov[num_iov++].iov_len = PADSIZE;
	length += PADSIZE;
    }
    else {
	iov[num_iov++].iov_len = seendb->length - length;
    }
    iov[num_iov].iov_base = "\n";
    iov[num_iov++].iov_len = 1;
    if (replace) {
	iov[num_iov].iov_base = (char *)seendb->base
	    + seendb->offset + seendb->length;
	iov[num_iov++].iov_len =
	    seendb->size - (seendb->offset + seendb->length);
    }

    if (replace) {
	n = retry_writev(writefd, iov, num_iov);

	/* Flush and swap in the new file */
	if (n == -1 || fsync(writefd) ||
	    lock_blocking(writefd) == -1 ||
	    fstat(seendb->fd, &sbuf) == -1 ||
	    rename(newfnamebuf, fnamebuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	    close(writefd);
	    unlink(newfnamebuf);
	    return IMAP_IOERROR;
	}
	close(seendb->fd);
	seendb->fd = writefd;
	seendb->length = length;
	map_free(&seendb->base, &seendb->size);
	map_refresh(seendb->fd, 1, &seendb->base, &seendb->size,
		    sbuf.st_size, fnamebuf, 0);
    }
    else {
	lseek(seendb->fd, seendb->offset, 0);
	n = retry_writev(seendb->fd, iov, num_iov);

	if (n == -1 || fsync(seendb->fd)) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
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
    r = lock_unlock(seendb->fd);

    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: unlocking seen db for %s: %m",
	       seendb->mailbox->name);
	return IMAP_IOERROR;
    }
    return 0;
}

/*
 * Close the database
 */
int seen_close(seendb)
struct seen *seendb;
{
    map_free(&seendb->base, &seendb->size);
    close(seendb->fd);
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
    int fd;

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);
    
    fd = open(fnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (fd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	return IMAP_IOERROR;
    }
    close(fd);
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
    int fd;
    int r;
    const char *lockfailaction;

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);
    
    fd = open(fnamebuf, O_RDWR, 0666);
    if (fd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	return IMAP_IOERROR;
    }

    r = lock_reopen(fd, fnamebuf, 0, &lockfailaction);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fnamebuf);
	close(fd);
	return IMAP_IOERROR;
    }

    unlink(fnamebuf);
    close(fd);
    return 0;
}

/*
 * Copy the seen database from 'oldmailbox' to 'newmailbox'
 */
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

/*
 * Reconstruct the seen database for 'mailbox'
 * We just make sure the file exists.
 */
int seen_reconstruct(mailbox)
struct mailbox *mailbox;
{
    char fnamebuf[MAX_MAILBOX_PATH];
    int fd;
    
    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    fd = open(fnamebuf, O_RDWR, 0666);
    if (fd != -1) {
	close(fd);
	return 0;
    }

    return seen_create(mailbox);
}

/*
 * Do usage counting and old entry pruning for the seen database
 * of 'mailbox'.  Users who have opened the mailbox since
 * 'report_time' are reported, users who have not opened the
 * mailbox since 'prune_time' have their entries removed from
 * the seen database.  Users are reported by calling 'proc' with
 * 'rock' and the userid.
 */
int seen_arbitron(mailbox, report_time, prune_time, proc, rock)
struct mailbox *mailbox;
time_t report_time;
time_t prune_time;
int (*proc)();
void *rock;
{
    int r;
    char fnamebuf[MAX_MAILBOX_PATH];
    char newfnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    const char *lockfailaction;
    FILE *seenfile;
    FILE *writefile = 0;
    unsigned n, left, skiplen;
    char buf[1024];
    char *p, *end_userid;
    time_t lastread;
    int c;

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    seenfile = fopen(fnamebuf, "r+");
    if (!seenfile) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", fnamebuf);
	return IMAP_IOERROR;
    }
    
    /* Lock the database */
    r = lock_reopen(fileno(seenfile), fnamebuf, &sbuf, &lockfailaction);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fnamebuf);
	fclose(seenfile);
	return IMAP_IOERROR;
    }

    while (fgets(buf, sizeof(buf), seenfile)) {
	/* Skip over username we know is there */
	p = strchr(buf, '\t');
	if (!p) {
	    /* remove bogus record */
	    goto removeline;
	}
	end_userid = p;
	p++;

	/* Parse the last selected time */
	lastread = 0;
	while (isdigit(*p)) {
	    lastread = lastread * 10 + *p++ - '0';
	}

	/* Report user if read recently enough */
	if (lastread > report_time) {
	    *end_userid = '\0';
	    (*proc)(rock, buf);
	    *end_userid = '\t';
	}

	/* Remove record if it's too old */
	if (lastread < prune_time) {
	  removeline:
	    if (!writefile) {
		/*
		 * This is the first record we have to prune from
		 * the file.  Open 'writefile' and copy what we have
		 * read so far into it.
		 */
		strcpy(newfnamebuf, fnamebuf);
		strcat(newfnamebuf, ".NEW");

		writefile = fopen(newfnamebuf, "w+");
		if (!writefile) {
		    syslog(LOG_ERR, "IOERROR: creating %s: %m", newfnamebuf);
		    fclose(seenfile);
		    return IMAP_IOERROR;
		}
		
		skiplen = strlen(buf);
		left = ftell(seenfile) - skiplen;

		rewind(seenfile);
		while (left) {
		    n = fread(buf, 1, left < sizeof(buf) ? left : sizeof(buf),
			      seenfile);
		    if (n == 0) {
			syslog(LOG_ERR, "IOERROR: reading %s: end of file",
			       fnamebuf);
			fclose(writefile);
			unlink(newfnamebuf);
			fclose(seenfile);
			return IMAP_IOERROR;
		    }
		    fwrite(buf, 1, n, writefile);
		    left -= n;
		}
		n = fread(buf, 1, skiplen, seenfile);
		if (n != skiplen) {
		    syslog(LOG_ERR, "IOERROR: reading %s: end of file",
			   fnamebuf);
		    fclose(writefile);
		    unlink(newfnamebuf);
		    fclose(seenfile);
		    return IMAP_IOERROR;
		}
	    }

	    /* Skip over and ignore the rest of the record */
	    if (buf[strlen(buf)-1] != '\n') {
		do {
		    c = getc(seenfile);
		} while (c != EOF && c != '\n');
	    }
    
	    continue;
	}
	
	/*
	 * If copying file, copy the current record
	 * In any case, skip over rest of the record.
	 */
	if (writefile) fputs(buf, writefile);
	if (buf[strlen(buf)-1] != '\n') {
	    do {
		c = getc(seenfile);
		if (writefile && c != EOF) {
		    putc(c, writefile);
		}
	    } while (c != EOF && c != '\n');
	}
    }

    /* If copying file, rename it into place */
    if (writefile) {
	/* Flush and swap in the new file */
	fflush(writefile);
	if (ferror(writefile) || fsync(fileno(writefile)) ||
	    rename(newfnamebuf, fnamebuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	    fclose(writefile);
	    unlink(newfnamebuf);
	    fclose(seenfile);
	    return IMAP_IOERROR;
	}
	fclose(writefile);
    }

    fclose(seenfile);
    return 0;
}

