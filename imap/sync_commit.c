/* sync_commit.c -- Cyrus synchonization mailbox functions
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
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 *
 * $Id: sync_commit.c,v 1.11 2007/10/04 19:22:39 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "util.h"
#include "retry.h"
#include "lock.h"
#include "sync_support.h"
#include "sync_commit.h"

/* A few support functions for sync_combine_commit() */

/* uiditem used to generate list of msgnos sorted by ascending UID */
struct uiditem {
    unsigned long msgno;
    unsigned long uid;
};

static int compare_uiditem(const void *a0, const void *b0)
{
    struct uiditem *a = (struct uiditem *) a0;
    struct uiditem *b = (struct uiditem *) b0;

    return ((a->uid) - (b->uid));
}

/* ---------------------------------------------------------------------- */

/* Running counts which will go into the index and expunge headers */
struct sync_counts {
    unsigned long newexists;
    uquota_t      newquota_used;
    unsigned long newanswered;
    unsigned long newflagged;
    unsigned long newdeleted;
    modseq_t      newhighestmodseq;
};

static void sync_counts_clear(struct sync_counts *c)
{
    memset(c, 0, sizeof(struct sync_counts));
}


static void sync_counts_update(struct sync_counts *c, struct index_record *p)
{
    c->newexists++;
    c->newquota_used += p->size;

    if (p->system_flags & FLAG_ANSWERED) c->newanswered++;
    if (p->system_flags & FLAG_DELETED)  c->newdeleted++;
    if (p->system_flags & FLAG_FLAGGED)  c->newflagged++;

    if (p->modseq > c->newhighestmodseq) c->newhighestmodseq = p->modseq;
}

static void sync_counts_write(unsigned char *buf, struct sync_counts *c,
			      time_t last_appenddate, unsigned long last_uid)
{
#if 0
    /* XXX Historical?
     * XXX Not clear why we do this in mailbox_expunge() etc.
     * XXX OFFSET_MINOR version etc are not updated
     */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
        *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }
#endif

    /* Fix up exists and other counts */
    *((bit32 *)(buf+OFFSET_EXISTS))   = htonl(c->newexists);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(c->newanswered);
    *((bit32 *)(buf+OFFSET_DELETED))  = htonl(c->newdeleted);
    *((bit32 *)(buf+OFFSET_FLAGGED))  = htonl(c->newflagged);

    /* Fix up quota_mailbox_used */
#ifdef HAVE_LONG_LONG_INT
    *((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonll(c->newquota_used);
#else
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED64)) = htonl(0);
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED))   = htonl(c->newquota_used);
#endif

    /* Fix up last_append time */
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(last_appenddate);

    /* Fix up last_uid */
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(last_uid);

    /* Fix up highest modseq */
#ifdef HAVE_LONG_LONG_INT
    align_htonll(buf+OFFSET_HIGHESTMODSEQ_64, c->newhighestmodseq);
#else
    *((bit32 *)(buf+OFFSET_HIGHESTMODSEQ_64)) = htonl(0);
    *((bit32 *)(buf+OFFSET_HIGHESTMODSEQ))    = htonl(c->newhighestmodseq);
#endif
}

/* ---------------------------------------------------------------------- */

/* Code which is typically reused for index,expunge and cache files */

static void sync_make_path(char *buf, int size, struct mailbox *mailbox,
			   int mask, char *name)
{
    char *path = (mailbox->mpath && (config_metapartition_files & mask))
	? mailbox->mpath : mailbox->path;

    strlcpy(buf, path, size);
    strlcat(buf, name, size);
}

static int sync_open_expunge(struct mailbox *mailbox, int *fdp,
			     unsigned long *lenp)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    const char *lockfailaction;
    int r;

    sync_make_path(fnamebuf, sizeof(fnamebuf), mailbox,
                   IMAP_ENUM_METAPARTITION_FILES_EXPUNGE, FNAME_EXPUNGE_INDEX);
    *fdp = -1;
    if ((stat(fnamebuf, &sbuf) < 0) ||
        (sbuf.st_size < (int) INDEX_HEADER_SIZE) ||
        ((*fdp = open(fnamebuf, O_RDWR, 0666)) < 0)) {
	unlink(fnamebuf);
        return(0);
    }
    *lenp = sbuf.st_size;

    if ((r = lock_reopen(*fdp, fnamebuf, &sbuf, &lockfailaction)))
         syslog(LOG_ERR, "IOERROR: %s expunge index for %s: %m",
                lockfailaction, mailbox->name);
    return(r);
}

/* Open a single index/expunge/cache file for writing */
static int sync_open_single(FILE **filep, struct mailbox *mailbox, int mask,
			    char *filename, char *suffix)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];

    sync_make_path(fnamebuf, sizeof(fnamebuf), mailbox, mask, filename);

    if (suffix && suffix[0])
        strlcat(fnamebuf, suffix, sizeof(fnamebuf));

    if ((*filep = fopen(fnamebuf, "w+")))
        return(0);

    syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
    return(IMAP_IOERROR);
}

/* Commit a single index/expunge/cache file */
static int sync_rename_single(struct mailbox *mailbox, int mask, char *filename)
{
    char fnamebuf[MAX_MAILBOX_PATH+1], fnamebufnew[MAX_MAILBOX_PATH+1];

    sync_make_path(fnamebuf, sizeof(fnamebuf), mailbox, mask, filename);

    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));

    if (rename(fnamebufnew, fnamebuf)) {
        syslog(LOG_ERR, "IOERROR: renaming %s for %s: %m",
               filename, mailbox->name);
        return(IMAP_IOERROR);
    }
    return(0);
}

/* Delete a single index/expunge/cache file */
static int sync_delete_single(struct mailbox *mailbox, int mask,
			      char *filename, char *suffix)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];

    sync_make_path(fnamebuf, sizeof(fnamebuf), mailbox, mask, filename);

    if (suffix && suffix[0])
        strlcat(fnamebuf, suffix, sizeof(fnamebuf));

    return ((unlink(fnamebuf) < 0) ? IMAP_IOERROR : 0);
}

/* Update index/expunge/cache header */
static void sync_write_header(struct mailbox *mailbox,
			      const char *index_base,
			      FILE *file)
{
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    unsigned long n;

    memcpy(buf, index_base, mailbox->start_offset);
    *((bit32 *)buf+OFFSET_GENERATION_NO) = htonl(mailbox->generation_no+1);
    fwrite(buf, 1, mailbox->start_offset, file);

    /* Grow the index header if necessary */
    for (n = mailbox->start_offset; n < INDEX_HEADER_SIZE; n++) {
        if (n == OFFSET_UIDVALIDITY+3) {
            putc(1, file);
        } else {
            putc(0, file);
        }
    }
}

/* Combine constant and variable components of uploaded message into
   a single index_record, which can then be written to index/cache */
static void sync_make_index_record(struct index_record *p,
				   struct sync_upload_item *item)
{
    struct sync_message *message = item->message;
    int n;

    memset(p, 0, sizeof(struct index_record));

    p->uid            = item->uid;
    p->internaldate   = item->internaldate;
    p->sentdate       = item->sentdate;

    /* XXX Should really have separate message->content_offset, even though
     * XXX header_size and content_offset always seem to match */

    p->size           = message->msg_size;
    p->header_size    = message->hdr_size;
    p->content_offset = message->hdr_size;
    p->cache_offset   = message->cache_offset;

    p->last_updated   = item->last_updated; 

    p->system_flags   = item->flags.system_flags;
    for (n = 0; n < MAX_USER_FLAGS/32; n++)
        p->user_flags[n] = item->flags.user_flags[n];

    p->content_lines = message->content_lines;
    p->cache_version = message->cache_version;

    message_guid_copy(&p->guid, &item->guid);
    p->modseq = item->modseq;
}

#include "index.h"

static unsigned long sync_cacheitem_size(const char *cacheitem)
{
    unsigned int cache_ent;
    const char *cacheitembegin = cacheitem;

    for (cache_ent = 0; cache_ent < NUM_CACHE_FIELDS; cache_ent++) {
        cacheitem = CACHE_ITEM_NEXT(cacheitem);
    }
    return(cacheitem - cacheitembegin); /* Compute size of this record */
}

static void sync_cacheitem_write(const char *cacheitem, FILE *newcache)
{
    fwrite(cacheitem, 1, sync_cacheitem_size(cacheitem), newcache);
}

/* ====================================================================== */

/* sync_combine_commit() is a three way combine on an open mailbox, the
 * mailbox's cyrus.expunge and a list of messages to upload.
 * Duplicate UIDs should be eliminated, with upload_list taking precedence.
 *
 * Inputs:
 *   mailbox :: Target mailbox, in ascending UID order.
 *   upload_list :: List of new messages to commit, in ascending UID order
 *   message_list :: List of all messages recently uploaded or reserved on
 *     server. Only needed for the mmap()ed cache file, which
 *     is referenced by upload_list. Possible cleanup here.
 *
 * Additional input:
 *   cyrus.expunge is a list of expunged messages in mailbox
 *
 * mmap() cyrus.expunge and generate an array of expunged UIDs sorted
 * into ascending UID so that we can track all three sources in order.
 *
 * mailbox has cyrus.index and cyrus.cache mmap()ed for reading. Open
 * cyrus.index.NEW, cyrus.cache.NEW, expunge.index.NEW for writing.
 *
 * Copy message files on upload_list into target mailbox. Will replace
 * messages that are already there on GUID mismatch, as before.
 *
 * While messages left in mailbox or expunge list or upload_list:
 *   if (next message from expunge list (if any) has UID less than
 *       next message from upload_list (if any) or mailbox (if any)):
 *     Add that message to cyrus.expunge.NEW and cyrus.cache.NEW
 *
 *   else if (next message from mailbox (if any) has UID less than next
 *            message from upload_list (if any)):
 *     Add that message to cyrus.index.NEW and cyrus.cache.NEW
 *
 *     If message matches next UID on expunge list (if any) then skip
 *     that entry on the expunge list.
 *
 *   else
 *     Add message from upload_list to cyrus.index.NEW and cyrus.cache.NEW
 *
 *     If message matches next UID on expunge list (if any) then skip
 *     that entry on the expunge list.
 *
 *     If message matches next UID in mailbox (if any) then skip
 *     that entry in mailbox
 *
 * Update cyrus.index and expunge.index headers, quota.
 *
 * fflush, fsync and commit new index, expunge and cache files
 *
 * Cleanup and exit.
*/

static int sync_combine_commit(struct mailbox *mailbox,
			       time_t last_appenddate,
			       struct sync_upload_list  *upload_list,
			       struct sync_message_list *message_list)
{
    FILE *newindex = NULL;
    FILE *newcache = NULL;
    FILE *newexpunge = NULL;
    uquota_t original_quota = mailbox->quota_mailbox_used;
    struct txn *tid = NULL;
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    struct sync_upload_item *item;
    int r = 0;
    unsigned n;
    int expunge_fd = -1;
    const char *expunge_base = NULL;
    unsigned long expunge_len = 0;
    unsigned long expunge_exists = 0;
    struct uiditem *expunge_uidmap = NULL;
    time_t expunge_last_appenddate = 0;
    unsigned long index_msgno, expunge_msgno, size = 0;
    struct index_record index_record, expunge_record, tmp_record;
    struct sync_counts index, expunge;

    if (upload_list->count == 0) return(0);   /* NOOP */

    sync_counts_clear(&index);
    sync_counts_clear(&expunge);

    /* Map cyrus.expunge file if it exists */
    if ((r = sync_open_expunge(mailbox, &expunge_fd, &size)))
        goto bail;

    if (expunge_fd != -1) {
        map_refresh(expunge_fd, 1, &expunge_base, &expunge_len, size,
                    "expunge", mailbox->name);
    }

    if (expunge_base && (expunge_len >= INDEX_HEADER_SIZE)) {
        expunge_exists = ntohl(*((bit32 *)(expunge_base+OFFSET_EXISTS)));
        expunge_last_appenddate
            = ntohl(*((bit32 *)(expunge_base+OFFSET_LAST_APPENDDATE)));
    }

    /* expunge_uidmap is list of msgnos sorted in ascending UID */
    if (expunge_exists > 0) {
        expunge_uidmap = xmalloc(expunge_exists * sizeof(struct uiditem));
        
        for (expunge_msgno = 1 ;
             expunge_msgno <= expunge_exists; expunge_msgno++) {
            r = mailbox_read_index_record_from_mapped
                (mailbox, expunge_base, expunge_len,
                 expunge_msgno, &expunge_record);
                 
            if (r) goto bail;
                
            expunge_uidmap[expunge_msgno-1].msgno = expunge_msgno;
            expunge_uidmap[expunge_msgno-1].uid   = expunge_record.uid;
        }
        qsort(expunge_uidmap, expunge_exists,
              sizeof(struct uiditem), compare_uiditem);
    }

    /* Open cyrus.index.NEW, cyrus.cache.NEW, cyrus.expunge.NEW */
    if (!r)
        r=sync_open_single(&newindex, mailbox,
                           IMAP_ENUM_METAPARTITION_FILES_INDEX,
                           FNAME_INDEX, ".NEW");
    if (!r)
        r=sync_open_single(&newcache, mailbox,
                           IMAP_ENUM_METAPARTITION_FILES_CACHE,
                           FNAME_CACHE, ".NEW");
    if (!r)
        r=sync_open_single(&newexpunge, mailbox,
                           IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                           FNAME_EXPUNGE_INDEX, ".NEW");
    if (r) goto bail;
                            
    /* Record new flag names before we try to use them (cyrus.header) */
    if (upload_list->meta.newflags) {
        sync_flags_meta_to_list(&upload_list->meta, mailbox->flagname);
	mailbox_write_header(mailbox);
    }

    /* Copy index, expunge, cache headers across */
    sync_write_header(mailbox, mailbox->index_base, newindex);
    if (expunge_base)
        sync_write_header(mailbox, expunge_base, newexpunge);
    /* XXX OFFSET_GENERATION_NO can only be zero */
    *((bit32 *)buf+OFFSET_GENERATION_NO) = htonl(mailbox->generation_no+1);
    fwrite(buf, 1, sizeof(bit32), newcache);

    /* Copy messages into target mailfolder (blat existing messages:
     * caused by GUID conflict on messages: sync_client wins) */
    for (item = upload_list->head ; item ; item = item->next) {
	if (sync_message_copy_fromstage(item->message, mailbox, item->uid)) {
            r = IMAP_IOERROR;
	    goto bail;
	}
    }

    /* Time to start the three way merge */
    item = upload_list->head;
    index_msgno = 0;
    expunge_msgno = 0;
    
    if (++index_msgno <= mailbox->exists)
        mailbox_read_index_record(mailbox, index_msgno, &index_record);

    if (++expunge_msgno <= expunge_exists)
        mailbox_read_index_record_from_mapped
            (mailbox, expunge_base, expunge_len,
             expunge_uidmap[expunge_msgno-1].msgno, &expunge_record);
                               
    r = 0;
    while (!r) {
        int have_index   = (index_msgno   <= mailbox->exists);
        int have_expunge = (expunge_msgno <= expunge_exists);

        if (!item && !have_index && !have_expunge)
            break;

        if (have_expunge &&
            (!have_index || (expunge_record.uid < index_record.uid)) &&
            (!item       || (expunge_record.uid < item->uid))) {
            /* Add expunged item to cyrus.expunge, cyrus.cache */
	    mailbox_index_record_to_buf(&expunge_record, buf);
            *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(ftell(newcache));

            sync_cacheitem_write
                (mailbox->cache_base+expunge_record.cache_offset, newcache);
            fwrite(buf, 1, mailbox->record_size, newexpunge);
            sync_counts_update(&expunge, &expunge_record);

            if (++expunge_msgno <= expunge_exists)
                mailbox_read_index_record_from_mapped
                    (mailbox, expunge_base, expunge_len,
                     expunge_uidmap[expunge_msgno-1].msgno, &expunge_record);
        } else if ((index_msgno <= mailbox->exists) &&
                   ((item == NULL) || (index_record.uid < item->uid))) {
            /* Add existing item from mailbox to cyrus.index, cyrus.cache */
	    mailbox_index_record_to_buf(&index_record, buf);
            *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(ftell(newcache));

            sync_cacheitem_write
                (mailbox->cache_base+index_record.cache_offset, newcache);
            fwrite(buf, 1, mailbox->record_size, newindex);
            sync_counts_update(&index, &index_record);

            /* Discard message from expunge list because of UID conflict */
            if (have_expunge && (index_record.uid == expunge_record.uid) &&
                (++expunge_msgno <= expunge_exists))
                mailbox_read_index_record_from_mapped
                    (mailbox, expunge_base, expunge_len,
                     expunge_uidmap[expunge_msgno-1].msgno, &expunge_record);
                
            if (++index_msgno <= mailbox->exists)
                mailbox_read_index_record(mailbox, index_msgno, &index_record);
        } else {
            /* Use item from upload list (may replace existing msg) */
            sync_make_index_record(&tmp_record, item);
	    mailbox_index_record_to_buf(&tmp_record, buf);
            *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(ftell(newcache));

            sync_cacheitem_write
                (message_list->cache_base+tmp_record.cache_offset, newcache);
            fwrite(buf, 1, mailbox->record_size, newindex);
            sync_counts_update(&index, &tmp_record);

            /* Discard existing msg on server because of UID conflict */
            if (have_index && (item->uid == index_record.uid) &&
                (++index_msgno <= mailbox->exists))
                mailbox_read_index_record(mailbox, index_msgno, &index_record);

            /* Discard message from expunge list because of UID conflict */
            if (have_expunge && (item->uid == expunge_record.uid) &&
                (++expunge_msgno <= expunge_exists))
                mailbox_read_index_record_from_mapped
                    (mailbox, expunge_base, expunge_len,
                     expunge_uidmap[expunge_msgno-1].msgno, &expunge_record);
                     
            item = item->next;
        }
    }
    if (r) goto bail;

    /* Fix up information in index header */
    rewind(newindex);
    n = fread(buf, 1, mailbox->start_offset, newindex);
    if ((unsigned long)n != mailbox->start_offset) {
        syslog(LOG_ERR, "IOERROR: reading index header for %s: got %d of %ld",
               mailbox->name, n, mailbox->start_offset);
        r = IMAP_IOERROR;
        goto bail;
    }
    sync_counts_write(buf, &index, last_appenddate, upload_list->new_last_uid);
    rewind(newindex);
    fwrite(buf, 1, mailbox->start_offset, newindex);

    /* Fix up information in expunge index header */
    if (expunge_base) {
        rewind(newexpunge);
        n = fread(buf, 1, mailbox->start_offset, newexpunge);
        if ((unsigned long)n != mailbox->start_offset) {
            syslog(LOG_ERR,
                   "IOERROR: reading expunge index header for %s:"
                   "got %d of %ld",
                   mailbox->name, n, mailbox->start_offset);
            r = IMAP_IOERROR;
            goto bail;
        }
        sync_counts_write(buf, &expunge, expunge_last_appenddate,
                          upload_list->new_last_uid);
        rewind(newexpunge);
        fwrite(buf, 1, mailbox->start_offset, newexpunge);
    }

    /* Ensure everything made it to disk */
    if (fflush(newexpunge) || fsync(fileno(newexpunge)) ||
        fflush(newindex)   || fsync(fileno(newindex)) ||
        fflush(newcache)   || fsync(fileno(newcache))) {
        syslog(LOG_ERR, "IOERROR: writing index/cache/expunge for %s: %m",
               mailbox->name);
        r = IMAP_IOERROR;
        goto bail;
    }

    /* Record quota addition */
    if (!r && mailbox->quota.root) {
	r = quota_read(&mailbox->quota, &tid, 1);
	if (!r) {
	    mailbox->quota.used = index.newquota_used;
	    r = quota_write(&mailbox->quota, &tid);
	    if (!r) quota_commit(&tid);
	}
	else if (r == IMAP_QUOTAROOT_NONEXISTENT) r = 0;

	if (r) {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record add of " QUOTA_T_FMT
                   " bytes in quota %s",
		   index.newquota_used - original_quota, mailbox->quota.root);
	}
    }

    /* Commit the new cyrus.index, cyrus.cache and cyrus.expunge files */
    if (!r)
        r = sync_rename_single(mailbox, IMAP_ENUM_METAPARTITION_FILES_INDEX,
                               FNAME_INDEX);
    if (!r)
        r = sync_rename_single(mailbox, IMAP_ENUM_METAPARTITION_FILES_CACHE,
                               FNAME_CACHE);

    if (expunge_exists == 0) {
        sync_delete_single(mailbox, IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                           FNAME_EXPUNGE_INDEX, ".NEW");
    } else if (!r)
        r = sync_rename_single(mailbox,
                               IMAP_ENUM_METAPARTITION_FILES_EXPUNGE,
                               FNAME_EXPUNGE_INDEX);

 bail:
    if (newexpunge) fclose(newexpunge);
    if (newcache)   fclose(newcache);
    if (newindex)   fclose(newindex);

    if (expunge_uidmap) free(expunge_uidmap);
    if (expunge_fd)     close(expunge_fd);
    if (expunge_base)   map_free(&expunge_base, &expunge_len);

    return(r);
}

/* ====================================================================== */
/* ====================================================================== */

static int sync_append_commit(struct mailbox *mailbox,
			      time_t last_appenddate,
			      struct sync_upload_list  *upload_list,
			      struct sync_message_list *message_list)
{
    unsigned char *index_chunk, *record;
    indexbuffer_t ibuf;
    unsigned char *hbuf = ibuf.buf;
    struct iovec  *cache_iovec, *cachev;
    struct sync_upload_item *item;
    struct sync_message     *message;
    unsigned long cache_size;
    uquota_t      quota_add       = 0;
    unsigned long numansweredflag = 0;
    unsigned long numdeletedflag  = 0;
    unsigned long numflaggedflag  = 0;
    unsigned long newexists;
    unsigned long newdeleted;
    unsigned long newanswered;
    unsigned long newflagged;
    int   n, r = 0;
    long last_offset;
    struct txn *tid = NULL;
    modseq_t highestmodseq = 0;

    if (upload_list->count == 0) return(0);   /* NOOP */

    /* Set up contiguous block for index append, iovec for cache append   */
    /* Record various message count deltas as we go so that we can update */

    index_chunk = xzmalloc(upload_list->count * INDEX_RECORD_SIZE);
    cache_iovec = xzmalloc(upload_list->count * sizeof(struct iovec));

    record = index_chunk;
    cachev = cache_iovec;

    cache_size = mailbox->cache_size;

    for (item = upload_list->head ; item ; item = item->next) {
        message = item->message;

        cachev->iov_base
            = (char *)(message_list->cache_base + message->cache_offset);
        cachev->iov_len  = message->cache_size;

        *((bit32 *)(record+OFFSET_UID))            = htonl(item->uid);
        *((bit32 *)(record+OFFSET_INTERNALDATE))   = htonl(item->internaldate);
        *((bit32 *)(record+OFFSET_SENTDATE))       = htonl(item->sentdate);
        *((bit32 *)(record+OFFSET_SIZE))           = htonl(message->msg_size);
        *((bit32 *)(record+OFFSET_HEADER_SIZE))    = htonl(message->hdr_size);
        *((bit32 *)(record+OFFSET_CONTENT_OFFSET)) = htonl(message->hdr_size);
        *((bit32 *)(record+OFFSET_CACHE_OFFSET))   = htonl(cache_size);
        *((bit32 *)(record+OFFSET_LAST_UPDATED))   = htonl(item->last_updated);
        *((bit32 *)(record+OFFSET_SYSTEM_FLAGS))
            = htonl(item->flags.system_flags);

        for (n = 0; n < MAX_USER_FLAGS/32; n++) {
            *((bit32 *)(record+OFFSET_USER_FLAGS+4*n))
                = htonl(item->flags.user_flags[n]);
        }
        *((bit32 *)(record+OFFSET_CONTENT_LINES))
	    = htonl(message->content_lines);
        *((bit32 *)(record+OFFSET_CACHE_VERSION))
	    = htonl(message->cache_version);
        message_guid_export(&item->guid, record+OFFSET_MESSAGE_GUID);

#ifdef HAVE_LONG_LONG_INT
            *((bit64 *)(record+OFFSET_MODSEQ_64)) = htonll(item->modseq);
#else
	    /* zero the unused 32bits */
            *((bit32 *)(record+OFFSET_MODSEQ_64)) = htonl(0);
            *((bit32 *)(record+OFFSET_MODSEQ)) = htonl(item->modseq);
#endif

	if (item->modseq > highestmodseq) highestmodseq = item->modseq;

        cache_size += message->cache_size;
        quota_add  += message->msg_size;

        if (item->flags.system_flags & FLAG_ANSWERED) numansweredflag++;
        if (item->flags.system_flags & FLAG_DELETED)  numdeletedflag++;
        if (item->flags.system_flags & FLAG_FLAGGED)  numflaggedflag++;

        record += INDEX_RECORD_SIZE;
        cachev++;
    }

    /* Copy messages into target mailfolder */
    for (item = upload_list->head ; item ; item = item->next) {
#if 0
        snprintf(target, MAX_MAILBOX_PATH,
                 "%s/%lu.", mailbox->path, (unsigned long)item->uid);

        if (mailbox_copyfile(item->message->msg_path, target, 0) != 0) {
            /* Attempt undo before we bail out */
            for (item = upload_list->head ; item != item; item = item->next)
                unlink(item->message->msg_path);

            goto fail;
        }
#else
	if (sync_message_copy_fromstage(item->message, mailbox, item->uid)) {
	    goto fail;
	}
#endif
    }

    /* Make sure that new flag names recorded before we try to use them */
    if (upload_list->meta.newflags) {
        sync_flags_meta_to_list(&upload_list->meta, mailbox->flagname);
	mailbox_write_header(mailbox);
    }

    /* Append to index and cache files */
    lseek(mailbox->cache_fd, mailbox->cache_size, SEEK_SET);
    if (retry_writev(mailbox->cache_fd, cache_iovec, upload_list->count) < 0)
        goto fail;

    
    last_offset = mailbox->start_offset + mailbox->exists * mailbox->record_size;
    lseek(mailbox->index_fd, last_offset, SEEK_SET);
    if (retry_write(mailbox->index_fd, index_chunk,
                    upload_list->count * mailbox->record_size) < 0)
        goto fail;


    /* Critical region starts here! */
    /* Fix up information in index header */
    lseek(mailbox->index_fd, 0L, SEEK_SET);

    n = read(mailbox->index_fd, hbuf, mailbox->start_offset);
    if ((unsigned long)n != mailbox->start_offset) {
        syslog(LOG_ERR,
               "IOERROR: reading expunge index header for %s: got %d of %lu",
               mailbox->name, n, mailbox->start_offset);
        goto fail;
    }

    /* Fix up last_uid */
    *((bit32 *)(hbuf+OFFSET_LAST_UID)) = htonl(upload_list->new_last_uid);

    /* Fix up exists */
    newexists = ntohl(*((bit32 *)(hbuf+OFFSET_EXISTS))) + upload_list->count;
    *((bit32 *)(hbuf+OFFSET_EXISTS)) = htonl(newexists);
    /* fix up other counts */
    newanswered = ntohl(*((bit32 *)(hbuf+OFFSET_ANSWERED)))+numansweredflag;
    *((bit32 *)(hbuf+OFFSET_ANSWERED)) = htonl(newanswered);
    newdeleted = ntohl(*((bit32 *)(hbuf+OFFSET_DELETED)))+numdeletedflag;
    *((bit32 *)(hbuf+OFFSET_DELETED)) = htonl(newdeleted);
    newflagged = ntohl(*((bit32 *)(hbuf+OFFSET_FLAGGED)))+numflaggedflag;
    *((bit32 *)(hbuf+OFFSET_FLAGGED)) = htonl(newflagged);

    /* Fix up quota_mailbox_used */
#ifdef HAVE_LONG_LONG_INT
    *((bit64 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED64)) = 
      htonll(ntohll(*((bit64 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED64)))+quota_add);
#else
    *((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED64)) = htonl(0);
    *((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED)) =
        htonl(ntohl(*((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED)))+quota_add);
#endif

    /* Fix up start offset if necessary */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
        *((bit32 *)(hbuf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }

    /* Fix up last_append time */
    *((bit32 *)(hbuf+OFFSET_LAST_APPENDDATE)) = htonl(last_appenddate);
	
    /* Fix up highest modseq */
#ifdef HAVE_LONG_LONG_INT
    if (highestmodseq > align_ntohll(hbuf+OFFSET_HIGHESTMODSEQ_64)) {
	align_htonll(hbuf+OFFSET_HIGHESTMODSEQ_64, highestmodseq);
    }
#else
    if (highestmodseq > ntohl(*((bit32 *)(hbuf+OFFSET_HIGHESTMODSEQ)))) {
	*((bit32 *)(hbuf+OFFSET_HIGHESTMODSEQ_64)) = htonl(0);
	*((bit32 *)(hbuf+OFFSET_HIGHESTMODSEQ)) = htonl(highestmodseq);
    }
#endif

    /* And write it back out */
    lseek(mailbox->index_fd, 0L, SEEK_SET);

    n = retry_write(mailbox->index_fd, hbuf, mailbox->start_offset);
    if ((unsigned long)n != mailbox->start_offset) {
        syslog(LOG_ERR, "IOERROR: writing out new expunge header for %s",
               mailbox->name);
        goto fail;
    }
    
    /* Ensure everything made it to disk */
    if (fsync(mailbox->index_fd) || fsync(mailbox->cache_fd)) {
        syslog(LOG_ERR, "IOERROR: writing expunge index/cache for %s: %m",
               mailbox->name);
        goto fail;
    }

    /* Record quota addition */
    if (mailbox->quota.root) {
	r = quota_read(&mailbox->quota, &tid, 1);
	if (!r) {
	    mailbox->quota.used += quota_add;
	    r = quota_write(&mailbox->quota, &tid);
	    if (!r) quota_commit(&tid);
	}
	else if (r == IMAP_QUOTAROOT_NONEXISTENT) r = 0;

	if (r) {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record add of " UQUOTA_T_FMT
                   " bytes in quota %s",
		   quota_add, mailbox->quota.root);
	}
    }

    free(index_chunk);
    free(cache_iovec);
    return(r);

 fail:
    /* Attempt undo. Is this safe? */
    ftruncate(mailbox->cache_fd, mailbox->cache_size);
    ftruncate(mailbox->index_fd, mailbox->index_size);

    free(index_chunk);
    free(cache_iovec);
    return(IMAP_IOERROR);
}

/* ====================================================================== */

int sync_upload_commit(struct mailbox *mailbox,
		       time_t last_appenddate,
		       struct sync_upload_list  *upload_list,
		       struct sync_message_list *message_list)
{
    struct sync_upload_item *head = upload_list->head;
    int r;

    if (head == NULL)
        return(0);

    if (message_list->cache_fd >= 0) {
        struct stat sbuf;

        if ((fstat(message_list->cache_fd, &sbuf) < 0)) {
            syslog(LOG_ERR, "Failed to stat temporary cache file: %m");
            return(IMAP_IOERROR);
        }
        
        map_refresh(message_list->cache_fd, 1,
                    &message_list->cache_base, &message_list->cache_len,
                    sbuf.st_size,
                    "new message", mailbox->name);
    }

    /* Acquire mailbox lock */
    if ((r=mailbox_lock_header(mailbox)))
        return(r);

    if ((r=mailbox_lock_index(mailbox))) {
	mailbox_unlock_header(mailbox);
        return(r);
    }

    if (mailbox->last_uid >= head->uid)
	r = sync_combine_commit(mailbox, last_appenddate,
				upload_list, message_list);
    else
        r = sync_append_commit(mailbox, last_appenddate,
                               upload_list, message_list);

    mailbox_unlock_index(mailbox);
    mailbox_unlock_header(mailbox);

    /* Update mailbox internal index to reflect change */
    if (!r)
        r = mailbox_open_index(mailbox);   

    return(r);
}

/* ====================================================================== */
/* ====================================================================== */

int sync_uidlast_commit(struct mailbox *mailbox,
			unsigned long last_uid,
			time_t last_appenddate)
{
    unsigned char *hbuf = xmalloc(mailbox->start_offset);
    int n;

    /* Fix up information in index header */
    lseek(mailbox->index_fd, 0L, SEEK_SET);

    n = read(mailbox->index_fd, hbuf, mailbox->start_offset);
    if ((unsigned long)n != mailbox->start_offset) {
        free(hbuf);
        syslog(LOG_ERR,
               "IOERROR: reading expunge index header for %s: got %d of %lu",
               mailbox->name, n, mailbox->start_offset);
        return(IMAP_IOERROR);
    }

    /* Fix up last_uid */
    *((bit32 *)(hbuf+OFFSET_LAST_UID)) = htonl(last_uid);

    /* Fix up last_append time */
    *((bit32 *)(hbuf+OFFSET_LAST_APPENDDATE)) = htonl(last_appenddate);

    /* And write it back out */
    lseek(mailbox->index_fd, 0L, SEEK_SET);

    n = retry_write(mailbox->index_fd, hbuf, mailbox->start_offset);

    free(hbuf);
    if ((unsigned long)n != mailbox->start_offset) {
        syslog(LOG_ERR, "IOERROR: writing out new expunge header for %s",
               mailbox->name);
        return(IMAP_IOERROR);
    }
    
    /* Ensure everything made it to disk */
    if (fsync(mailbox->index_fd)) {
        syslog(LOG_ERR, "IOERROR: writing expunge index/cache for %s: %m",
               mailbox->name);
        return(IMAP_IOERROR);
    }
    return(0);
}

int sync_uidvalidity_commit(struct mailbox *mailbox,
			    unsigned long uidvalidity)
{
    unsigned char *hbuf = xmalloc(mailbox->start_offset);
    int n;

    /* Fix up information in index header */
    lseek(mailbox->index_fd, 0L, SEEK_SET);

    n = read(mailbox->index_fd, hbuf, mailbox->start_offset);
    if ((unsigned long)n != mailbox->start_offset) {
        free(hbuf);
        syslog(LOG_ERR,
               "IOERROR: reading index header for %s: got %d of %lu",
               mailbox->name, n, mailbox->start_offset);
        return(IMAP_IOERROR);
    }

    /* Fix up uidvalidity */
    *((bit32 *)(hbuf+OFFSET_UIDVALIDITY)) = htonl(uidvalidity);

    /* And write it back out */
    lseek(mailbox->index_fd, 0L, SEEK_SET);

    n = retry_write(mailbox->index_fd, hbuf, mailbox->start_offset);

    free(hbuf);
    if ((unsigned long)n != mailbox->start_offset) {
        syslog(LOG_ERR, "IOERROR: writing out new index header for %s",
               mailbox->name);
        return(IMAP_IOERROR);
    }
    
    /* Ensure everything made it to disk */
    if (fsync(mailbox->index_fd)) {
        syslog(LOG_ERR, "IOERROR: writing index for %s: %m",
               mailbox->name);
        return(IMAP_IOERROR);
    }
    return(0);
}

/* ====================================================================== */

int sync_setflags_commit(struct mailbox *mailbox,
			 struct sync_flag_list *flag_list)
{
    struct index_record record;
    struct sync_flag_item *item = flag_list->head;
    unsigned long msgno = 1;
    int n, r = 0;
    time_t now = time(NULL);

    if (!r) r = mailbox_lock_header(mailbox);
    if (!r) r = mailbox_lock_index(mailbox);

    if (r) return(r);

    /* Make sure that new flag names recorded before we try to use them */
    if (flag_list->meta.newflags) {
        sync_flags_meta_to_list(&flag_list->meta, mailbox->flagname);
	mailbox_write_header(mailbox);
    }

    while (item && (msgno <= mailbox->exists)) {
        r = mailbox_read_index_record(mailbox, msgno, &record);

        if (r) return(r);

        if (record.uid == item->uid) {
            bit32 old = record.system_flags;
            bit32 new = item->flags.system_flags;

            if (!(old & FLAG_ANSWERED) && (new & FLAG_ANSWERED))
                mailbox->answered++;
            else if ((old & FLAG_ANSWERED) && !(new & FLAG_ANSWERED))
                mailbox->answered--;

            if (!(old & FLAG_FLAGGED) && (new & FLAG_FLAGGED))
                mailbox->flagged++;
            else if ((old & FLAG_FLAGGED) && !(new & FLAG_FLAGGED))
                mailbox->flagged--;

            if (!(old & FLAG_DELETED) && (new & FLAG_DELETED))
                mailbox->deleted++;
            else if ((old & FLAG_DELETED) && !(new & FLAG_DELETED))
                mailbox->deleted--;

            record.system_flags = item->flags.system_flags;
            for (n = 0; n < MAX_USER_FLAGS/32; n++) {
                record.user_flags[n] = item->flags.user_flags[n];
            }
            record.last_updated = ((record.last_updated >= now) ?
                                   record.last_updated + 1 : now);
            mailbox_write_index_record(mailbox, msgno, &record, 0);
            item = item->next;
        }
        msgno++;
    }

    if (!r) r = mailbox_write_index_header(mailbox);
    if (!r) mailbox_unlock_index(mailbox);
    if (!r) mailbox_unlock_header(mailbox);

    if (fsync(mailbox->index_fd)) {
	syslog(LOG_ERR, "IOERROR: writing index record %lu for %s: %m",
	       msgno, mailbox->name);
	return IMAP_IOERROR;
    }

    r = mailbox_open_index(mailbox);   /* Update internal index */
    return(r);
}

/* ====================================================================== */

#define DB config_mboxlist_db

int sync_create_commit(char *name, char *partition, char *uniqueid, char *acl,
		       int mbtype, unsigned long options,
		       unsigned long uidvalidity,
		       int isadmin __attribute__((unused)),
		       char *userid __attribute__((unused)),
		       struct auth_state *auth_state __attribute__((unused)))
{
    int r;
    int free_uniqueid = 0;
    char *newpartition = NULL;
    char *mboxent = NULL;
    int newreserved = 0; /* made reserved entry in local mailbox list */
    int mboxopen = 0;
    struct mailbox m;
#if 0  /* XXX  is this really necessary since only sync_client talks to us? */
    /* Need an extra sanity check here as normal ACL logic is bypassed */
    r = mboxname_policycheck(name);
    if (r) return r;
#endif
    if (!uniqueid) {
	uniqueid = xmalloc(sizeof(char) * 32);
	mailbox_make_uniqueid(name, uidvalidity, uniqueid, 32); /* YYY */
        free_uniqueid = 1;
    }

    r = mboxlist_createmailboxcheck(name, 0, partition, 1,
                                    imapd_userid, imapd_authstate,
                                    NULL, &newpartition, 1);
    if (r) goto done;

    mboxent = mboxlist_makeentry(mbtype | MBTYPE_RESERVE, newpartition, acl);
    r = DB->store(mbdb, name, strlen(name), mboxent, strlen(mboxent), NULL);
    free(mboxent);
    mboxent = NULL;

    /* 3b. Unlock mailbox list (before calling out to mupdate) */
    if(r) {
	syslog(LOG_ERR, "Could not reserve mailbox %s during create", name);
	goto done;
    } else {
	newreserved = 1;
    }

 done: /* All checks compete.  Time to fish or cut bait. */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	/* Create new mailbox in the filesystem */
	r = mailbox_create(name, newpartition, acl, uniqueid,
			   ((mbtype & MBTYPE_NETNEWS) ?
			    MAILBOX_FORMAT_NETNEWS :
			    MAILBOX_FORMAT_NORMAL), 
			   NULL);
    }
    
    if (r) { /* CREATE failed */ 
	int r2 = 0;

	if(newreserved) {
	    /* remove the RESERVED mailbox entry if we failed */
	    r2 = DB->delete(mbdb, name, strlen(name), NULL, 0);
	    if(r2) {
		syslog(LOG_ERR,
		       "DBERROR: can't remove RESERVE entry for %s (%s)",
		       name, cyrusdb_strerror(r2));
	    }
	}

    } else { /* all is well - activate the mailbox */
	mboxent = mboxlist_makeentry(mbtype, newpartition, acl);

	switch(r = DB->store(mbdb, name, strlen(name),
			     mboxent, strlen(mboxent), NULL)) {
	case 0: 
	    break;
	default:
	    /* xxx This leaves a reserved entry around, it is unclear
	     * that a DB->delete would work though */
	    syslog(LOG_ERR, "DBERROR: failed on activation: %s", 
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
    }
    if (mboxent) free(mboxent);
    if (newpartition) free(newpartition);

    /* Fix options and UIDvalidity */
    if (!r) r = mailbox_open_header(name, 0, &m);
    if (!r) mboxopen = 1;
    if (!r) r = mailbox_lock_header(&m);
    if (!r) r = mailbox_open_index(&m);
    if (!r) r = mailbox_lock_index(&m);
    if (!r) {
	m.options = options;
	m.uidvalidity = uidvalidity;
    }
    if (!r) mailbox_write_index_header(&m);

    if (mboxopen) mailbox_close(&m);

    if (free_uniqueid) free(uniqueid);

    return(r);
}
