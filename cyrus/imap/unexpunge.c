/* unexpunge.c -- Program to unexpunge messages
 *
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 * $Id: unexpunge.c,v 1.4 2007/02/07 14:27:52 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

#include "annotate.h"
#include "cyrusdb.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "imap_err.h"
#include "index.h"
#include "libcyr_cfg.h"
#include "lock.h"
#include "map.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

/* global state */
const int config_need_data = 0;

/* current namespace */
static struct namespace unex_namespace;

int verbose = 0;

void usage(void)
{
    fprintf(stderr,
	    "unexpunge [-C <altconfig>] -l <mailbox>\n"
	    "unexpunge [-C <altconfig>] -a [-d] [-v] <mailbox>\n"
	    "unexpunge [-C <altconfig>] -u [-d] [-v] <mailbox> <uid>...\n");
    exit(-1);
}

enum {
    MODE_UNKNOWN = -1,
    MODE_LIST,
    MODE_ALL,
    MODE_UID
};

struct msg {
    unsigned recno;
    unsigned long uid;
    int restore;
};

int compare_uid(const void *a, const void *b)
{
    return *((unsigned long *) a) - *((unsigned long *) b);
}

int compare_msg(const void *a, const void *b)
{
    return ((struct msg *) a)->uid - ((struct msg *) b)->uid;
}

void list_expunged(struct mailbox *mailbox,
		   struct msg *msgs, unsigned long exists,
		   const char *expunge_index_base)
{
    const char *rec;
    unsigned msgno;
    unsigned long uid, size, cache_offset;
    time_t internaldate, sentdate, last_updated;
    const char *cacheitem;

    for (msgno = 0; msgno < exists; msgno++) {
	/* Jump to index record for this message */
	rec = expunge_index_base + mailbox->start_offset +
	    msgs[msgno].recno * mailbox->record_size;

	uid = ntohl(*((bit32 *)(rec+OFFSET_UID)));
	internaldate = ntohl(*((bit32 *)(rec+OFFSET_INTERNALDATE)));
	sentdate = ntohl(*((bit32 *)(rec+OFFSET_SENTDATE)));
	size = ntohl(*((bit32 *)(rec+OFFSET_SIZE)));
	cache_offset = ntohl(*((bit32 *)(rec+OFFSET_CACHE_OFFSET)));
	last_updated = ntohl(*((bit32 *)(rec+OFFSET_LAST_UPDATED)));

	printf("UID: %lu\n", uid);
	printf("\tSize: %lu\n", size);
	printf("\tSent: %s", ctime(&sentdate));
	printf("\tRecv: %s", ctime(&internaldate));
	printf("\tExpg: %s", ctime(&last_updated));

	cacheitem = mailbox->cache_base + cache_offset;
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body structure */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip body */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip binary body */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip cached headers */

	printf("\tFrom: %s\n", cacheitem + CACHE_ITEM_SIZE_SKIP);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip from */
	printf("\tTo  : %s\n", cacheitem + CACHE_ITEM_SIZE_SKIP);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip to */
	printf("\tCc  : %s\n", cacheitem + CACHE_ITEM_SIZE_SKIP);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip cc */
	printf("\tBcc : %s\n", cacheitem + CACHE_ITEM_SIZE_SKIP);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bcc */
	printf("\tSubj: %s\n\n", cacheitem + CACHE_ITEM_SIZE_SKIP);
    }
}

int restore_expunged(struct mailbox *mailbox,
		     struct msg *msgs, unsigned long eexists,
		     const char *expunge_index_base,
		     unsigned *numrestored, int unsetdeleted)
{
    int r = 0;
    const char *irec;
    char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
	     INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
    char *path, fnamebuf[MAX_MAILBOX_PATH+1], fnamebufnew[MAX_MAILBOX_PATH+1];
    FILE *newindex = NULL, *newexpungeindex = NULL;
    unsigned emsgno, imsgno;
    unsigned long iexists, euid, iuid;
    uquota_t quotarestored = 0, newquotaused;
    unsigned numansweredflag = 0, numdeletedflag = 0, numflaggedflag = 0;
    unsigned newexists, newexpunged, newdeleted, newanswered, newflagged;
    time_t now = time(NULL);
    struct txn *tid = NULL;

    /* Open new index/expunge files */
    path = (mailbox->mpath &&
	    (config_metapartition_files & IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;

    strlcpy(fnamebufnew, path, sizeof(fnamebufnew));
    strlcat(fnamebufnew, FNAME_INDEX, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    newindex = fopen(fnamebufnew, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebufnew);
	return IMAP_IOERROR;
    }

    path = (mailbox->mpath &&
	    (config_metapartition_files & IMAP_ENUM_METAPARTITION_FILES_EXPUNGE)) ?
	mailbox->mpath : mailbox->path;

    strlcpy(fnamebufnew, path, sizeof(fnamebufnew));
    strlcat(fnamebufnew, FNAME_EXPUNGE_INDEX, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    newexpungeindex = fopen(fnamebufnew, "w+");
    if (!newindex) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebufnew);
	fclose(newindex);
	return IMAP_IOERROR;
    }

    /* Copy over index/expunge headers
     *
     * XXX do we want/need to bump the generation number?
     */
    fwrite(mailbox->index_base, 1, mailbox->start_offset, newindex);
    fwrite(expunge_index_base, 1, mailbox->start_offset, newexpungeindex);

    iexists = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_EXISTS)));

    for (imsgno = 0, emsgno = 0; emsgno < eexists; emsgno++) {
	/* Copy expunge index record for this message */
	memcpy(buf,
	       expunge_index_base + mailbox->start_offset +
	       msgs[emsgno].recno * mailbox->record_size,
	       mailbox->record_size);

	euid = ntohl(*((bit32 *)(buf+OFFSET_UID)));

	/* Write all cyrus.index records w/ iuid < euid to cyrus.index */
	for (; imsgno < iexists; imsgno++) {
	    /* Jump to index record for this message */
	    irec = mailbox->index_base + mailbox->start_offset +
		imsgno * mailbox->record_size;

	    iuid = ntohl(*((bit32 *)(irec+OFFSET_UID)));

	    if (iuid > euid) break;

	    fwrite(irec, 1, mailbox->record_size, newindex);
	}

	if (msgs[emsgno].restore) {
	    bit32 sysflags = ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));

	    if (verbose) {
		printf("\trestoring UID %ld\n", msgs[emsgno].uid);
		syslog(LOG_INFO, "restoring UID %ld in mailbox '%s'",
		       msgs[emsgno].uid, mailbox->name);
	    }

	    /* Update counts */
	    (*numrestored)++;
	    quotarestored += ntohl(*((bit32 *)(buf+OFFSET_SIZE)));
	    if (sysflags & FLAG_ANSWERED) numansweredflag++;
	    if (sysflags & FLAG_FLAGGED) numflaggedflag++;
	    if (unsetdeleted) {
		sysflags &= ~FLAG_DELETED;
		*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)) = htonl(sysflags);
	    }
	    else if (sysflags & FLAG_DELETED) numdeletedflag++;

	    /* Write record to cyrus.index */
	    *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(now);
	    fwrite(buf, 1, mailbox->record_size, newindex);
	}
	else {
	    /* Write record to cyrus.expunge */
	    fwrite(buf, 1, mailbox->record_size, newexpungeindex);
	}
    }

    /* Write all remaining cyrus.index records to cyrus.index */
    if (imsgno < iexists) {
	/* Jump to index record for next message */
	irec = mailbox->index_base + mailbox->start_offset +
	    imsgno * mailbox->record_size;

	fwrite(irec, 1, (iexists - imsgno) * mailbox->record_size, newindex);
    }

    /* Fix up information in index header */
    memcpy(buf, mailbox->index_base, mailbox->start_offset);

    /* Update uidvalidity */
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = now;

    /* Fix up exists */
    newexists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS))) + *numrestored;
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);

    /* Fix up expunged count */
    newexpunged = ntohl(*((bit32 *)(buf+OFFSET_LEAKED_CACHE))) - *numrestored;
    *((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(newexpunged);
	    
    /* Fix up other counts */
    newanswered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED))) + numansweredflag;
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(newanswered);
    newdeleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED))) + numdeletedflag;
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(newdeleted);
    newflagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED))) + numflaggedflag;
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(newflagged);

    /* Fix up quota_mailbox_used */
#ifdef HAVE_LONG_LONG_INT
    newquotaused =
	ntohll(*((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED64))) + quotarestored;
    *((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonll(newquotaused);
#else
    /* Zero the unused 32bits */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonl(0);
    newquotaused =
	ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED))) + quotarestored;
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(newquotaused);
#endif

    /* Write out new index header */
    rewind(newindex);
    fwrite(buf, 1, mailbox->start_offset, newindex);

    /* Ensure everything made it to disk */
    fflush(newindex);
    fclose(newindex);

    /* Fix up information in expunge index header */
    memcpy(buf, expunge_index_base, mailbox->start_offset);

    /* Update uidvalidity */
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = now;

    /* Fix up exists */
    newexists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS))) - *numrestored;
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);

    /* Fix up other counts */
    newanswered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED))) - numansweredflag;
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(newanswered);
    /* XXX we use the numrestored count here because we may have unset
     * the \Deleted flag when we copied the record to cyrus.index,
     * but we know that any message that has to be restored had the
     * \Deleted set in cyrus.expunge in the first place
     */
    newdeleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED))) - *numrestored;
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(newdeleted);
    newflagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED))) - numflaggedflag;
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(newflagged);

    /* Fix up quota_mailbox_used */
#ifdef HAVE_LONG_LONG_INT
    newquotaused =
	ntohll(*((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED64))) - quotarestored;
    *((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonll(newquotaused);
#else
    /* Zero the unused 32bits */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonl(0);
    newquotaused =
	ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED))) - quotarestored;
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(newquotaused);
#endif

    /* Write out new expunge index header */
    rewind(newexpungeindex);
    fwrite(buf, 1, mailbox->start_offset, newexpungeindex);

    /* Ensure everything made it to disk */
    fflush(newexpungeindex);
    fclose(newexpungeindex);

    /* Rename our files */
    path = (mailbox->mpath &&
	    (config_metapartition_files & IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;

    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));

    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_ERR, "IOERROR: renaming index file for %s: %m",
	       mailbox->name);
	return IMAP_IOERROR;
    }

    path = (mailbox->mpath &&
	    (config_metapartition_files & IMAP_ENUM_METAPARTITION_FILES_EXPUNGE)) ?
	mailbox->mpath : mailbox->path;

    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_EXPUNGE_INDEX, sizeof(fnamebuf));

    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    if (rename(fnamebufnew, fnamebuf)) {
	syslog(LOG_ERR, "IOERROR: renaming expunge index file for %s: %m",
	       mailbox->name);
	return IMAP_IOERROR;
    }

    /* Record quota restore */
    r = quota_read(&mailbox->quota, &tid, 1);
    if (!r) {
	mailbox->quota.used += quotarestored;
	r = quota_write(&mailbox->quota, &tid);
	if (!r) quota_commit(&tid);
	else {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record restore of " UQUOTA_T_FMT " bytes in quota %s",
		   quotarestored, mailbox->quota.root);
	}
    }
    else if (r == IMAP_QUOTAROOT_NONEXISTENT) r = 0;

    return r;
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt, r = 0;
    char *alt_config = NULL;
    char buf[MAX_MAILBOX_PATH+1];
    struct mailbox mailbox;
    int doclose = 0, mode = MODE_UNKNOWN, unsetdeleted = 0;
    char expunge_fname[MAX_MAILBOX_PATH+1];
    int expunge_fd = -1;
    struct stat sbuf;
    const char *lockfailaction;
    struct msg *msgs;
    unsigned numrestored = 0;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:laudv")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'l':
	    if (mode != MODE_UNKNOWN) usage();
	    mode = MODE_LIST;
	    break;
	
	case 'a':
	    if (mode != MODE_UNKNOWN) usage();
	    mode = MODE_ALL;
	    break;
	
	case 'u':
	    if (mode != MODE_UNKNOWN) usage();
	    mode = MODE_UID;
	    break;

	case 'd':
	    unsetdeleted = 1;
	    break;
	
	case 'v':
	    verbose = 1;
	    break;
	
	default:
	    usage();
	    break;
	}
    }

    /* sanity check */
    if (mode == MODE_UNKNOWN ||
	(optind + (mode == MODE_UID ? 1 : 0)) >= argc) usage();

    cyrus_init(alt_config, "unexpunge", 0);

    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&unex_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    /* Translate mailboxname */
    (*unex_namespace.mboxname_tointernal)(&unex_namespace, argv[optind],
					  NULL, buf);

    /* Open/lock header */
    r = mailbox_open_header(buf, 0, &mailbox);
    if (!r && mailbox.header_fd != -1) {
	doclose = 1;
	(void) mailbox_lock_header(&mailbox);
	mailbox.header_lock_count = 1;
    }

    /* Attempt to open/lock index */
    if (!r) r = mailbox_open_index(&mailbox);
    if (!r) {
	(void) mailbox_lock_index(&mailbox);
	mailbox.index_lock_count = 1;
    }
    if (!r) r = mailbox_lock_pop(&mailbox);

    /* Open expunge index */
    if (!r) {
	char *path =
	    (mailbox.mpath &&
	     (config_metapartition_files & IMAP_ENUM_METAPARTITION_FILES_EXPUNGE)) ?
	    mailbox.mpath : mailbox.path;

	strlcpy(expunge_fname, path, sizeof(expunge_fname));
	strlcat(expunge_fname, FNAME_EXPUNGE_INDEX, sizeof(expunge_fname));

	expunge_fd = open(expunge_fname, O_RDWR, 0666);
    }

    if (r || expunge_fd == -1) {
	/* mailbox corrupt/nonexistent -- skip it */
	syslog(LOG_WARNING, "unable to open/lock mailbox %s", argv[optind]);
	if (doclose) mailbox_close(&mailbox);
	return 0;
    }

    if ((r = lock_reopen(expunge_fd, expunge_fname, &sbuf, &lockfailaction))) {
	syslog(LOG_ERR, "IOERROR: %s expunge index for %s: %m",
	       lockfailaction, mailbox.name);
    }
    if (!r) {
	const char *expunge_index_base = NULL;
	unsigned long expunge_index_len = 0;	/* mapped size */
	unsigned long exists, uid;
	const char *rec;
	unsigned msgno;
	unsigned long *uids = NULL;
	unsigned nuids;

	map_refresh(expunge_fd, 1, &expunge_index_base,
		    &expunge_index_len, sbuf.st_size, "expunge",
		    mailbox.name);

	exists = ntohl(*((bit32 *)(expunge_index_base+OFFSET_EXISTS)));

	msgs = (struct msg *) xmalloc(exists * sizeof(struct msg));

	/* Get UIDs of messages to restore */
	if (mode == MODE_UID) {
	    int i;

	    nuids = argc - ++optind;
	    uids = (unsigned long *) xmalloc(nuids * sizeof(unsigned long));

	    for (i = 0; i < nuids; i++)
		uids[i] = strtoul(argv[optind+i], NULL, 10);

	    /* Sort the UIDs so we can binary search */
	    qsort(uids, nuids, sizeof(unsigned long), compare_uid);
	}

	/* Get UIDs of expunged messages */
	for (msgno = 0; msgno < exists; msgno++) {
	    /* Jump to index record for this message */
	    rec = expunge_index_base + mailbox.start_offset +
		msgno * mailbox.record_size;

	    uid = ntohl(*((bit32 *)(rec+OFFSET_UID)));

	    msgs[msgno].recno = msgno;
	    msgs[msgno].uid = uid;
	    switch (mode) {
	    case MODE_LIST: msgs[msgno].restore = 0; break;
	    case MODE_ALL: msgs[msgno].restore = 1; break;
	    case MODE_UID:
		/* see if this UID is in our list */
		msgs[msgno].restore = bsearch(&uid, uids, nuids,
					      sizeof(unsigned long),
					      compare_uid) != NULL;
		break;
	    }
	}
	if (uids) free(uids);

	/* Sort msgs by UID */
	qsort(msgs, exists, sizeof(struct msg), compare_msg);

	if (mode == MODE_LIST)
	    list_expunged(&mailbox, msgs, exists, expunge_index_base);
	else {
	    printf("restoring %sexpunged messages in mailbox '%s'\n",
		    mode == MODE_ALL ? "all " : "", mailbox.name);

	    r = restore_expunged(&mailbox, msgs, exists, expunge_index_base,
				 &numrestored, unsetdeleted);
	    if (!r) {
		printf("restored %u out of %lu expunged messages\n",
			numrestored, exists);
		syslog(LOG_NOTICE,
		       "restored %u out of %lu expunged messages in mailbox '%s'",
		       numrestored, exists, mailbox.name);
	    }
	}

	map_free(&expunge_index_base, &expunge_index_len);
	free(msgs);

	if (lock_unlock(expunge_fd))
	    syslog(LOG_ERR,
		   "IOERROR: unlocking expunge index of %s: %m", 
		   mailbox.name);
    }
    close(expunge_fd);

    mailbox_unlock_pop(&mailbox);
    mailbox_unlock_index(&mailbox);
    mailbox_unlock_header(&mailbox);
    mailbox_close(&mailbox);

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

    cyrus_done();

    exit(r);
}
