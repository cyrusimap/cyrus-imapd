/* upgrade_index.c -- Mailbox upgrade routines
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: mailbox.c,v 1.199 2010/01/06 17:01:36 murch Exp $
 */
#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#ifdef HAVE_DIRENT_H
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

#include "assert.h"
#include "crc32.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "lock.h"
#include "mailbox.h"
#include "message.h"
#include "map.h"
#include "retry.h"
#include "seen.h"
#include "util.h"
#include "sequence.h"
#include "xmalloc.h"

static int sort_record(const void *a, const void *b)
{
    struct index_record *ra = (struct index_record *)a;
    struct index_record *rb = (struct index_record *)b;
    return ra->uid - rb->uid;
}

static int update_record_from_cache(struct mailbox *mailbox,
				    struct index_record *record)
{
    int r;
    bit32 crc;

    r = mailbox_open_cache(mailbox);
    if (r) return r;

    if (!record->cache_offset)
	return IMAP_IOERROR;

    r = cache_parserecord(&mailbox->cache_buf,
			  record->cache_offset, &record->crec);
    if (r) return r;

    crc = crc32_buf(cache_buf(record));
    if (record->cache_crc) {
	if (crc != record->cache_crc)
	    return IMAP_MAILBOX_CRC;
    }
    else {
	record->cache_crc = crc;
    }

    /* extract the date for GMTIME field */
    if (cacheitem_size(record, CACHE_ENVELOPE) > 2) {
	char *envtokens[NUMENVTOKENS];
	char *tmpenv = xstrndup(cacheitem_base(record, CACHE_ENVELOPE) + 1,
				cacheitem_size(record, CACHE_ENVELOPE) - 2);
	parse_cached_envelope(tmpenv, envtokens, VECTOR_SIZE(envtokens));
	record->gmtime = message_parse_date(envtokens[ENV_DATE],
			 PARSE_TIME|PARSE_ZONE|PARSE_NOCREATE|PARSE_GMT);
	free(tmpenv);
    }
    else {
	/* better than nothing! */
	record->gmtime = record->internaldate;
    }

    return 0;
}

static int upgrade_index_record(struct mailbox *mailbox,
				const char *buf,
				int old_version,
				struct index_record *record,
				int record_size)
{
    indexbuffer_t rbuf;
    char *recordbuf = (char *)rbuf.buf;
    int recalc = 0;

    memset(recordbuf, 0, INDEX_RECORD_SIZE);
    if (INDEX_RECORD_SIZE < record_size)
	memcpy(recordbuf, buf, INDEX_RECORD_SIZE);
    else
	memcpy(recordbuf, buf, record_size);

    /* CONTENT_LINES added with minor version 5 */
    /* CACHE_VERSION added with minor version 6 */

    /* 12-byte GUIDs added with minor version 7 */
    /* GUIDs extended from 12 to 20 bytes with minor version 10 */
    if (old_version < 10)
	recalc = 1;
    else {
	/* if it's all zeros for the final 8 bits, it was probably upgraded
	 * and also needs recalculation */
	if (ntohl(*((bit32 *)(recordbuf+OFFSET_MESSAGE_GUID+12))) == 0 &&
	    ntohl(*((bit32 *)(recordbuf+OFFSET_MESSAGE_GUID+16))) == 0)
	    recalc = 1;
    }

    /* do the initial parse.  Ignore the result, crc32 will mismatch
     * for sure */
    mailbox_buf_to_index_record(recordbuf, record);

    if (!recalc && old_version < 12) {
	/* let's try a cheaper upgrade option - just reading the 
	   cache record for details */
	if (update_record_from_cache(mailbox, record))
	    recalc = 1;
    }

    if (recalc) {
	char *fname = mailbox_message_fname(mailbox, record->uid);
	return message_parse(fname, record);
    }

    return 0;
}

/*
 * Upgrade an index/expunge file for 'mailbox'
 */
int upgrade_index(struct mailbox *mailbox)
{
    unsigned recno, erecno;
    unsigned long oldmapnum;
    unsigned long oldnum_records;
    unsigned long expunge_num = 0;
    unsigned uid;
    bit32 oldminor_version, oldstart_offset, oldrecord_size;
    indexbuffer_t headerbuf;
    indexbuffer_t recordbuf;
    const char *bufp;
    char *hbuf = (char *)headerbuf.buf;
    char *rbuf = (char *)recordbuf.buf;
    int newindex_fd = -1;
    char *fname;
    struct seqset *seq = NULL;
    struct index_record record;
    struct index_record *expunge_records = NULL;
    struct index_record *recordptr;
    int r, n;

    if (mailbox->index_size < OFFSET_NUM_RECORDS)
	return IMAP_MAILBOX_BADFORMAT;

    oldminor_version = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_MINOR_VERSION)));
    oldstart_offset = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_START_OFFSET)));
    oldrecord_size = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_RECORD_SIZE)));
    oldnum_records = ntohl(*((bit32 *)(mailbox->index_base+OFFSET_NUM_RECORDS)));
    oldmapnum = (mailbox->index_size - oldstart_offset) / oldrecord_size;
    if (oldmapnum < oldnum_records) {
	syslog(LOG_ERR, "upgrade: %s map doesn't fit, shrinking index %lu to %lu",
	       mailbox->name, oldnum_records, oldmapnum);
	oldnum_records = oldmapnum;
    }

    /* check if someone else already upgraded the index! */
    if (oldminor_version == MAILBOX_MINOR_VERSION)
	goto done;

    /* Copy existing header so we can upgrade it */ 
    memset(hbuf, 0, INDEX_HEADER_SIZE);
    if (oldstart_offset > INDEX_HEADER_SIZE)
	memcpy(hbuf, mailbox->index_base, INDEX_HEADER_SIZE);
    else 
	memcpy(hbuf, mailbox->index_base, oldstart_offset);

    /* QUOTA_MAILBOX_USED64 added with minor version 6 */
    if (oldminor_version < 6) {
	/* upgrade quota to 64-bits (bump existing fields) */
	memmove(hbuf+OFFSET_QUOTA_MAILBOX_USED, hbuf+OFFSET_QUOTA_MAILBOX_USED64,
		INDEX_HEADER_SIZE - OFFSET_QUOTA_MAILBOX_USED);
	/* zero the unused 32-bits */
	*((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED64)) = htonl(0);
    }

    /* ignore the result - we EXPECT a CRC32 mismatch */
    mailbox_buf_to_index_header(&mailbox->i, hbuf);

    /* HIGHESTMODSEQ[_64] added with minor version 8 */
    if (oldminor_version < 8)
	mailbox->i.highestmodseq = 1;

    /* new version fields */
    mailbox->i.minor_version = MAILBOX_MINOR_VERSION;
    mailbox->i.start_offset = INDEX_HEADER_SIZE;
    mailbox->i.record_size = INDEX_RECORD_SIZE;

    /* upgrade other fields as necessary
     *
     * minor version wasn't updated religiously in the early days,
     * so we need to use the old offset instead */
    if (oldstart_offset < OFFSET_POP3_LAST_LOGIN)
	mailbox->i.pop3_last_login = 0;
    if (oldstart_offset < OFFSET_UIDVALIDITY)
	mailbox->i.uidvalidity = 1;
    if (oldstart_offset < OFFSET_MAILBOX_OPTIONS)
	mailbox->i.options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS);

    if (oldminor_version < 12) {
	struct seen *seendb;
	struct seendata sd;
	unsigned long erecno;
	unsigned long emapnum;
	bit32 eversion, eoffset, esize;
	char *owner_userid;
	struct stat sbuf;
	int expunge_fd = -1;
	const char *expunge_base = NULL;
	unsigned long expunge_len = 0;   /* mapped size */

	/* remove the CONDSTORE option - it's implicit now */
	mailbox->i.options &= ~OPT_IMAP_CONDSTORE;

	if (mailbox->i.options & OPT_IMAP_SHAREDSEEN)
	    owner_userid = "anyone";
	else
	    owner_userid = mboxname_to_userid(mailbox->name);

	r = mailbox_read_header(mailbox, NULL);
	if (r) goto fail;

	/* NEW HEADER FIELDS */

	/* we'll set this if there are expunged records */
	mailbox->i.first_expunged = 0;
	/* we can't know about deletions before the current modseq */
	mailbox->i.deletedmodseq = mailbox->i.highestmodseq;
	/* we're repacking now! */
	mailbox->i.last_repack_time = time(NULL);
	/* bootstrap CRC matching */
	mailbox->i.header_file_crc = mailbox->header_file_crc;

	/* set up seen tracking for user inside the mailbox */
	if (!owner_userid) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	} else {
	    r = seen_open(owner_userid, SEEN_SILENT, &seendb);
	    if (!r) {
		r = seen_read(seendb, mailbox->uniqueid, &sd);
		seen_close(seendb);
	    }
	}
	if (r) { /* no seen data? */
	    mailbox->i.recentuid = mailbox->i.last_uid;
	    mailbox->i.recenttime = time(NULL);
	}
	else {
	    mailbox->i.recentuid = sd.lastuid;
	    mailbox->i.recenttime = sd.lastchange;
	    seq = seqset_parse(sd.seenuids, NULL, sd.lastuid);
	    seen_freedata(&sd);
	}

	/* check for expunge */
	fname = mailbox_meta_fname(mailbox, META_EXPUNGE);
	expunge_fd = open(fname, O_RDWR, 0666);
	if (expunge_fd == -1) goto no_expunge;

	r = fstat(expunge_fd, &sbuf);
	if (r == -1) goto no_expunge;

	if (sbuf.st_size < INDEX_HEADER_SIZE) goto no_expunge;
	map_refresh(expunge_fd, 1, &expunge_base,
		    &expunge_len, sbuf.st_size, "expunge",
		    mailbox->name);

	/* use the expunge file's header information just in case
	 * versions are skewed for some reason */
	eversion = ntohl(*((bit32 *)(expunge_base+OFFSET_MINOR_VERSION)));
	eoffset = ntohl(*((bit32 *)(expunge_base+OFFSET_START_OFFSET)));
	esize = ntohl(*((bit32 *)(expunge_base+OFFSET_RECORD_SIZE)));
	expunge_num = ntohl(*((bit32 *)(expunge_base+OFFSET_NUM_RECORDS)));
	expunge_records = xmalloc(expunge_num * sizeof(struct index_record));
	emapnum = (sbuf.st_size - eoffset) / esize;
	if (emapnum < expunge_num) {
	    syslog(LOG_ERR, "IOERROR: %s map doesn't fit, shrinking expunge %lu to %lu",
		   mailbox->name, expunge_num, emapnum);
	    expunge_num = emapnum;
	}

	for (erecno = 1; erecno <= expunge_num; erecno++) {
	    struct index_record *record = &expunge_records[erecno-1];
	    bufp = expunge_base + eoffset + (erecno-1)*esize;
	    upgrade_index_record(mailbox, bufp, eversion, record, esize);
	    record->system_flags |= FLAG_EXPUNGED;
	    if (!mailbox->i.first_expunged ||
		mailbox->i.first_expunged > record->last_updated)
		mailbox->i.first_expunged = record->last_updated;
	}

	/* expunge files were not sorted.  So sort them now for easier
	 * interleaving */
	qsort(expunge_records, expunge_num, 
	      sizeof(struct index_record), &sort_record);

no_expunge:
	if (expunge_fd != -1) close(expunge_fd);
	if (expunge_base) map_free(&expunge_base, &expunge_len);
    }

    /* update buffer with upgraded values */
    mailbox_index_header_to_buf(&mailbox->i, (unsigned char *)hbuf);

    /* open the new index file */
    fname = mailbox_meta_newfname(mailbox, META_INDEX);
    newindex_fd = open(fname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newindex_fd == -1) goto fail;

    /* Write new header - first pass only */
    n = retry_write(newindex_fd, hbuf, INDEX_HEADER_SIZE);
    if (n == -1) goto fail;

    /* initialise counters */
    mailbox->i.quota_mailbox_used = 0;
    mailbox->i.num_records = 0;
    mailbox->i.sync_crc = 0; /* no records is blank */
    mailbox->i.answered = 0;
    mailbox->i.deleted = 0;
    mailbox->i.flagged = 0;
    mailbox->i.exists = 0;

    /* Write the rest of new index */
    recno = 1;
    erecno = 1;
    while (recno <= oldnum_records || erecno <= expunge_num) {
	/* read the uid */
	if (recno <= oldnum_records) {
	    bufp = mailbox->index_base + oldstart_offset + (recno-1)*oldrecord_size;
	    uid = ntohl(*((bit32 *)(bufp+OFFSET_UID)));
	}

	/* case: only expunge records left */
	if (recno > oldnum_records) {
	    recordptr = &expunge_records[erecno-1];
	    erecno++;
	}

	/* case: index record is lower uid */
	else if (erecno > expunge_num || uid <= expunge_records[erecno-1].uid) {
	    upgrade_index_record(mailbox, bufp, oldminor_version, &record,
				 oldrecord_size);
	    recno++;
	    if (erecno <= expunge_num && uid == expunge_records[erecno-1].uid)
		erecno++; /* duplicate UID - skip expunge record */
	    recordptr = &record;
	}

	/* case: expunge record is lower uid */
	else {
	    recordptr = &expunge_records[erecno-1];
	    erecno++;
	}

	if (oldminor_version < 12 && seqset_ismember(seq, recordptr->uid))
	    recordptr->system_flags |= FLAG_SEEN;

	/* write the cache record if necessary */
	r = mailbox_append_cache(mailbox, recordptr);
	if (r) goto fail;

	mailbox_index_update_counts(mailbox, recordptr, 1);
	mailbox_index_record_to_buf(recordptr, (unsigned char *)rbuf);

	n = retry_write(newindex_fd, rbuf, INDEX_RECORD_SIZE);
	if (n == -1) goto fail;

	mailbox->i.num_records++;
    }

    mailbox_index_header_to_buf(&mailbox->i, (unsigned char *)hbuf);

    lseek(newindex_fd, 0L, SEEK_SET);
    n = retry_write(newindex_fd, hbuf, INDEX_HEADER_SIZE);
    if (n == -1) goto fail;

    r = fsync(newindex_fd);
    if (r == -1) goto fail;
    close(newindex_fd);

    r = mailbox_meta_rename(mailbox, META_INDEX);
    if (r == -1) goto fail;

    /* don't need this file any more! */
    unlink(mailbox_meta_fname(mailbox, META_EXPUNGE));

    /* XXX - remove seen record */

    syslog(LOG_INFO, "Index upgrade: %s (%d -> %d)", mailbox->name, 
	   oldminor_version, MAILBOX_MINOR_VERSION);

done:
    seqset_free(seq);
    free(expunge_records);

    /* commit the cache first so it doesn't stay "dirty" */
    mailbox_commit_cache(mailbox);

    /* special case, completely forgiven from being clean... */
    mailbox->i.dirty = 0;
    mailbox->quota_dirty = 0;
    mailbox->modseq_dirty = 0;

    /* it's definitely changed! */
    r = mailbox_open_index(mailbox);
    if (r) return r;

    return 0;

fail:
    if (newindex_fd != -1) close(newindex_fd);
    seqset_free(seq);
    free(expunge_records);

    syslog(LOG_ERR, "Index upgrade failed: %s", mailbox->name);

    return IMAP_IOERROR;
}

