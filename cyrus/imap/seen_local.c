/* seen_local.c -- Storage for /Recent and /Seen state on local filesystem
 $Id: seen_local.c,v 1.34 2002/07/24 19:30:39 rjs3 Exp $
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>

#include "assert.h"
#include "map.h"
#include "bsearch.h"
#include "lock.h"
#include "retry.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xmalloc.h"

#include "seen.h"

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
int seen_open(struct mailbox *mailbox, const char *user, struct seen **seendbptr)
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
int seen_lockread(struct seen *seendb, time_t *lastreadptr, unsigned int *lastuidptr, 
		  time_t *lastchangeptr, char **seenuidsptr)
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
	}
	map_refresh(seendb->fd, 1, &seendb->base, &seendb->size,
		    sbuf.st_size, fnamebuf, 0);
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
    while (left && isdigit((int) *buf)) {
	*lastreadptr = *lastreadptr * 10 + *buf++ - '0';
	left--;
    }
    if (left && *buf != '\n') {
	left--;
	buf++;
    }

    /* Parse last-read uid */
    while (left && isdigit((int) *buf)) {
	*lastuidptr = *lastuidptr * 10 + *buf++ - '0';
	left--;
    }
    if (left && *buf != '\n') {
	left--;
	buf++;
    }

    /* Scan for end of uids or last-change timestamp */
    p = buf;
    while (left && !isspace((int) *p)) {
	p++;
	left--;
    }

    if (left > 1 && p[0] == ' ' && isdigit((int) p[1])) {
	/* Have a last-change timestamp */
	while (buf < p) {
	    *lastchangeptr = *lastchangeptr * 10 + *buf++ - '0';
	}
	buf++;
	p++;
	left--;

	/* Scan for end of uids */
	while (left && !isspace((int) *p)) {
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
int seen_write(struct seen *seendb, time_t lastread, unsigned int lastuid, 
	       time_t lastchange, char *seenuids)
{
    char timeuidbuf[80];
    int length;
    int writefd = -1;
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

    snprintf(timeuidbuf, sizeof(timeuidbuf), "\t%u %u %u ", (unsigned int) lastread, lastuid, (unsigned int) lastchange);
    
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
	    fstat(writefd, &sbuf) == -1 ||
	    rename(newfnamebuf, fnamebuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	    close(writefd);
	    unlink(newfnamebuf);
	    return IMAP_IOERROR;
	}
	close(seendb->fd);
	seendb->fd = writefd;
	seendb->ino = sbuf.st_ino;
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
int seen_unlock(struct seen *seendb)
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
int seen_close(struct seen *seendb)
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
int seen_create(struct mailbox *mailbox)
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
int seen_delete(struct mailbox *mailbox)
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
int seen_copy(struct mailbox *oldmailbox,struct mailbox *newmailbox)
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
 * List of entries in reconstructed seen database
 */
#define NEWIOV_GROW 3 /* 1000 */
struct iovec *newiov;
char *freenew;
int newiov_num;
int newiov_alloc = 0;
int newiov_dirty;		/* set to 1 if something either
				 * malloced or not in sort order
				 */

/*
 * Insert a seen record 'line' with length 'len'
 * into the being-reconstructed seen database.
 * 'freeit' is nonzero if 'line' should be freed after use.
 */
void
newiov_insert(line, len, freeit)
const char *line;
unsigned len;
int freeit;
{
    int low=0;
    int high=newiov_num-1;
    int mid, cmp, i;

    if (newiov_num == newiov_alloc) {
	newiov_alloc += NEWIOV_GROW;
	newiov = (struct iovec *)xrealloc((char *)newiov,
					newiov_alloc * sizeof (struct iovec));
	freenew = xrealloc(freenew, newiov_alloc);
    }

    /* special-case -- appending to end */
    if (newiov_num == 0 ||
	bsearch_compare(line, newiov[newiov_num-1].iov_base) > 0) {
	newiov[newiov_num].iov_base = (char *)line;
	newiov[newiov_num].iov_len = len;
	freenew[newiov_num] = freeit;
	newiov_num++;
	if (freeit) newiov_dirty = 1;
	return;
    }
    
    newiov_dirty = 1;

    /* Binary-search for location */
    while (low <= high) {
	mid = (high - low)/2 + low;
	cmp = bsearch_compare(line, newiov[mid].iov_base);

	if (cmp == 0) return;

	if (cmp < 0) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    
    /* Open a slot for the new entry and insert entry into the list */
    for (i = newiov_num-1; i > high; i--) {
	newiov[i+1].iov_base = newiov[i].iov_base;
	newiov[i+1].iov_len = newiov[i].iov_len;
	freenew[i+1] = freenew[i];
    }
    newiov_num++;
    newiov[low].iov_base = (char *)line;
    newiov[low].iov_len = len;
    freenew[low] = freeit;
}

#define FIXING() \
	if (!dst) { \
	    fixedline = xmalloc(endline - line + 2 + PADSIZE); \
	    strncpy(fixedline, line, p - line); \
	    dst = fixedline + (p - line); \
        }

/*
 * Reconstruct the seen database for 'mailbox'.  Optionally does usage
 * counting and old entry pruning for the seen database of 'mailbox'.
 * Users who have opened the mailbox since 'report_time' are reported,
 * users who have not opened the mailbox since 'prune_time' have their
 * entries removed from the seen database.  Users are reported by
 * calling 'report_proc' with 'report_rock' and a pointer to the line
 * in the database.
 */
int seen_reconstruct(struct mailbox *mailbox,
		     time_t report_time,
		     time_t prune_time,
		     int (*report_proc)(),
		     void *report_rock)
{
    char fnamebuf[MAX_MAILBOX_PATH];
    char newfnamebuf[MAX_MAILBOX_PATH];
    int fd;
    struct stat sbuf;
    const char *lockfailaction;
    const char *base = 0;
    unsigned long size = 0;
    const char *line, *endline;
    const char *tab, *p, *space;
    time_t lastread;
    unsigned lastuidread;
    time_t lastchange;
    int r, i, n;
    unsigned lastuid, thisuid;
    unsigned uidtoobig = mailbox->last_uid;
    time_t now, nowplus1day;
    int lastsep;
    char *fixedline, *dst;
    int writefd;
    
    time(&now);
    nowplus1day = now + 24*60*60;

    strcpy(fnamebuf, mailbox->path);
    strcat(fnamebuf, FNAME_SEEN);

    fd = open(fnamebuf, O_RDWR, 0666);
    if (fd == -1) {
	return seen_create(mailbox);
    }

    r = lock_reopen(fd, fnamebuf, &sbuf, &lockfailaction);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fnamebuf);
	return IMAP_IOERROR;
    }

    map_refresh(fd, 1, &base, &size, sbuf.st_size, fnamebuf, 0);

    newiov_dirty = 0;
    newiov_num = 0;

    endline = base;
    while ((endline = memchr(line=endline, '\n', size - (endline - base)))) {
	endline++;

	/* Parse/check username */
	p = tab = memchr(line, '\t', endline - line);
	if (!tab /* XXX || badusername */) {
	    /* Cause line to be deleted */
	    newiov_dirty = 1;
	    continue;
	}

	/* Parse last-read timestamp */
	p++;
	lastread = 0;
	while (p < endline && isdigit((int) *p)) {
	    lastread = lastread * 10 + *p++ - '0';
	}
	if (p >= endline || *p++ != ' ') {
	    /* Cause line to be deleted */
	    newiov_dirty = 1;
	    continue;
	}
	if (lastread > nowplus1day) lastread = now;

	/* Report user if read recently enough */
	if (report_proc && lastread > report_time) {
	    (*report_proc)(report_rock, line);
	}

	/* Remove record if it's too old */
	if (lastread < prune_time) {
	    /* Cause line to be deleted */
	    newiov_dirty = 1;
	    continue;
	}

	
	/* Parse last-read uid */
	lastuidread = 0;
	while (p < endline && isdigit((int) *p)) {
	    lastuidread = lastuidread * 10 + *p++ - '0';
	}
	if (p >= endline || *p++ != ' ' || lastuidread > uidtoobig) {
	    /* Cause line to be deleted */
	    newiov_dirty = 1;
	    continue;
	}

	/* Scan for end of uids or last-change timestamp */
	lastchange = 0;
	fixedline = dst = 0;
	space = memchr(p, ' ', endline - p);

	if (space && space+1 < endline &&
	    space[0] == ' ' && isdigit((int) space[1])) {
	    /* Have a last-change timestamp */
	    while (p < space && isdigit((int) *p)) {
		lastchange = lastchange * 10 + *p++ - '0';
	    }
	    if (p != space) {
		/* Cause line to be deleted */
		newiov_dirty = 1;
		continue;
	    }
	    if (lastchange > nowplus1day) {
		lastchange = now;
	    }

	    p++;		/* Skip over space */
	    space = memchr(p, ' ', endline - p);
	    if (!space) space = endline - 1; /* The newline */
	}
	else {
	    FIXING();
	    *dst++ = '0';	/* Add a last-change timestamp of 0 */
	    *dst++ = ' ';
	}
	    
	/* Scan/scavenge uid list. */
	lastuid = 0;
	lastsep = ',';

	while (p < space) {
	    thisuid = 0;
	    while (p < space && isdigit((int) *p)) {
		if (dst) *dst++ = *p;
		thisuid = thisuid * 10 + *p++ - '0';
	    }

	    if (thisuid <= lastuid || thisuid > uidtoobig) {
		/* Remove this UID and trailing separator */
		FIXING();
		while (isdigit((int) dst[-1])) dst--;
		if (dst[-1] == ':') dst[-1] = ',';
	    }
	    else if (lastsep == ':' && *p == ':') {
		/* Change colon to comma */
		FIXING();
		*dst++ = lastsep = ',';
	    }
	    else if (*p == ':' || *p == ',') {
		lastsep = *p;
		if (dst) *dst++ = lastsep;
	    }
	    else break;

	    p++;
	}

	if (p[-1] == ':' || p[-1] == ',') {
	    FIXING();
	}
	if (dst && (dst[-1] == ':' || dst[-1] == ',')) {
	    dst[-1] = ' ';
	}

	while (p < endline) {
	    if (*p != ' ') {
		FIXING();
	    }
	    if (dst) *dst++ = ' ';
	    p++;
	}
	if (dst) {
	    *dst++ = '\n';
	    newiov_insert(fixedline, dst - fixedline, 1);
	}
	else {
	    newiov_insert(line, endline - line, 0);
	}
    }

    r = 0;

    if (newiov_dirty) {
	strcpy(newfnamebuf, fnamebuf);
	strcat(newfnamebuf, ".NEW");

	writefd = open(newfnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
	if (writefd == -1) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", newfnamebuf);
	    r = IMAP_IOERROR;
	    goto cleanup;
	}

	/* Simplify the iov by coalescing ajacent lines */
	for (i = 0; i < newiov_num - 1; i++) {
	    if ((char *)newiov[i].iov_base + newiov[i].iov_len == newiov[i+1].iov_base &&
		!freenew[i] && !freenew[i]) {
		newiov[i+1].iov_base = newiov[i].iov_base;
		newiov[i+1].iov_len += newiov[i].iov_len;
		newiov[i].iov_len = 0;
	    }
	}

	n = retry_writev(writefd, newiov, newiov_num);

	/* Flush and swap in the new file */
	if (n == -1 || fsync(writefd) ||
	    fstat(writefd, &sbuf) == -1 ||
	    rename(newfnamebuf, fnamebuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", newfnamebuf);
	    unlink(newfnamebuf);
	    r = IMAP_IOERROR;
	}
	close(writefd);

    cleanup:
	for (i = 0; i < newiov_num; i++) {
	    if (freenew[i]) free(newiov[i].iov_base);
	}
    }

    map_free(&base, &size);
    close(fd);
	
    return r;
}

/* done with all seen operations for this process */
int seen_done(void)
{
    return 0;
}

int seen_merge(const char *tmpfile, const char *tgtfile) 
{
    /* Not supported */
    return -1;
}
