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
 * $Id: sync_commit.c,v 1.1.2.5 2005/04/08 18:01:40 ken3 Exp $
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
#include <com_err.h>
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
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "util.h"
#include "retry.h"
#include "sync_support.h"
#include "sync_commit.h"

/* ====================================================================== */

static int
sync_combine_commit(struct mailbox *mailbox,
                    time_t last_appenddate,
                    struct sync_upload_list  *upload_list,
                    struct sync_message_list *message_list)
{
    char fnamebuf[MAX_MAILBOX_PATH+1], fnamebufnew[MAX_MAILBOX_PATH+1];
    char *path;
    FILE *newindex = NULL;
    FILE *newcache = NULL;
    unsigned char *buf  = NULL;
    struct sync_upload_item *item;
    struct sync_message     *message;
    long quota_add       = 0;  /* Following may be negative on UUID conflict */
    long numansweredflag = 0;
    long numdeletedflag  = 0;
    long numflaggedflag  = 0;
    unsigned long newexists = 0;
    unsigned long newdeleted;
    unsigned long newanswered;
    unsigned long newflagged;
    unsigned long msgno;
    char  target[MAX_MAILBOX_PATH+1];
    struct index_record record;
    int   n, r = 0, rc;
    struct txn *tid = NULL;

    if (upload_list->count == 0) return(0);   /* NOOP */

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));
    strlcat(fnamebuf, ".NEW", sizeof(fnamebuf));
    newindex = fopen(fnamebuf, "w+");
    if (!newindex) {
        syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
        return IMAP_IOERROR;
    }

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_CACHE)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_CACHE, sizeof(fnamebuf));
    strlcat(fnamebuf, ".NEW", sizeof(fnamebuf));
    newcache = fopen(fnamebuf, "w+");
    if (!newcache) {
        syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
        fclose(newindex);
        return IMAP_IOERROR;
    }

    /* Copy messages into target mailfolder (blat existing messages:
     * caused by UUID conflict on messages: sync_client wins) */
    for (item = upload_list->head ; item ; item = item->next) {
        snprintf(target, MAX_MAILBOX_PATH,
                 "%s/%lu.", mailbox->path, (unsigned long)item->uid);

        if (mailbox_copyfile(item->message->msg_path, target, 0) != 0) {
            /* Attempt undo before we bail out */
            for (item=upload_list->head ; item != item; item = item->next)
                unlink(item->message->msg_path);

            goto fail;
        }
    }

    /* Make sure that new flag names recorded before we try to use them */
    if (upload_list->meta.newflags) {
        sync_flags_meta_to_list(&upload_list->meta, mailbox->flagname);
	mailbox_write_header(mailbox);
    }

    buf = xmalloc(mailbox->start_offset > mailbox->record_size ?
                  mailbox->start_offset : mailbox->record_size);

    /* Copy index header across */
    memcpy(buf, mailbox->index_base, mailbox->start_offset);
    (*(bit32 *)buf)++;    /* Increment generation number */
    fwrite(buf, 1, mailbox->start_offset, newindex);

    /* Grow the index header if necessary */
    for (n = mailbox->start_offset; n < INDEX_HEADER_SIZE; n++) {
        if (n == OFFSET_UIDVALIDITY+3) {
            putc(1, newindex);
        } else {
            putc(0, newindex);
        }
    }

    /* Cache header is generation number only */
    fwrite(buf, 1, sizeof(bit32), newcache);

    item  = upload_list->head;
    msgno = 0;
    
    if (++msgno <= mailbox->exists)
        mailbox_read_index_record(mailbox, msgno, &record);

    while (item || (msgno <= mailbox->exists)) {
        newexists++;

        if ((msgno <= mailbox->exists) &&
            ((item == NULL) || (record.uid < item->uid))) {
            /* Use record item from existing mailbox */
#if 0
            *((bit32 *)(buf+OFFSET_UID))          = htonl(record.uid);
            *((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(record.internaldate);
            *((bit32 *)(buf+OFFSET_SENTDATE))     = htonl(record.sentdate);
            *((bit32 *)(buf+OFFSET_SIZE))         = htonl(record.size);
            *((bit32 *)(buf+OFFSET_HEADER_SIZE))  = htonl(record.header_size);
            *((bit32 *)(buf+OFFSET_CONTENT_OFFSET))=htonl(record.header_size);
            *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(record.last_updated);

            *((bit32 *)(buf+OFFSET_SYSTEM_FLAGS))
                = htonl(record.system_flags);
            
            for (n = 0; n < MAX_USER_FLAGS/32; n++) {
                *((bit32 *)(buf+OFFSET_USER_FLAGS+4*n))
                    = htonl(record.user_flags[n]);
            }
            *((bit32 *)(buf+OFFSET_CONTENT_LINES))=htonl(record.content_lines);
            *((bit32 *)(buf+OFFSET_CACHE_VERSION))=htonl(record.cache_version);
            message_uuid_pack(&record.uuid, buf+OFFSET_MESSAGE_UUID);
#else
	    mailbox_index_record_to_buf(&record, buf);
#endif
            /* Write out message cache and index */
            /* Fix up cache file offset */
            *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(ftell(newcache));

            fwrite(mailbox->cache_base + record.cache_offset,
                   1, mailbox_cache_size(mailbox, msgno), newcache);
            fwrite(buf, 1, mailbox->record_size, newindex);

            if (++msgno <= mailbox->exists)
                mailbox_read_index_record(mailbox, msgno, &record);
        } else {
            /* Use List item from upload list (may replace existing msg) */
            message = item->message;

            *((bit32 *)(buf+OFFSET_UID))          = htonl(item->uid);
            *((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(item->internaldate);
            *((bit32 *)(buf+OFFSET_SENTDATE))     = htonl(item->sentdate);
            *((bit32 *)(buf+OFFSET_SIZE))         = htonl(message->msg_size);
            *((bit32 *)(buf+OFFSET_HEADER_SIZE))  = htonl(message->hdr_size);
            *((bit32 *)(buf+OFFSET_CONTENT_OFFSET)) = htonl(message->hdr_size);
            *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(item->last_updated);
            *((bit32 *)(buf+OFFSET_SYSTEM_FLAGS))
                = htonl(item->flags.system_flags);
            
            for (n = 0; n < MAX_USER_FLAGS/32; n++) {
                *((bit32 *)(buf+OFFSET_USER_FLAGS+4*n))
                    = htonl(item->flags.user_flags[n]);
            }
            *((bit32 *)(buf+OFFSET_CONTENT_LINES))
		= htonl(message->content_lines);
            *((bit32 *)(buf+OFFSET_CACHE_VERSION))
		= htonl(message->cache_version);

            message_uuid_pack(&item->uuid, buf+OFFSET_MESSAGE_UUID);
            quota_add  += message->msg_size;

            if (item->flags.system_flags & FLAG_ANSWERED) numansweredflag++;
            if (item->flags.system_flags & FLAG_DELETED)  numdeletedflag++;
            if (item->flags.system_flags & FLAG_FLAGGED)  numflaggedflag++;

            /* Write out message cache and index */
            /* Fix up cache file offset */
            *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(ftell(newcache));

            fwrite((message_list->cache_base+message->cache_offset), 1, 
                   message->cache_size, newcache);

            fwrite(buf, 1, mailbox->record_size, newindex);

            /* Discard existing msg on server because of UUID conflict */
            /* Need to reclaim allocated space and resources */
            if (record.uid == item->uid) {
                quota_add -= record.size;
                if (record.system_flags & FLAG_ANSWERED) numansweredflag--;
                if (record.system_flags & FLAG_DELETED)  numdeletedflag--;
                if (record.system_flags & FLAG_FLAGGED)  numflaggedflag--;

                if (++msgno <= mailbox->exists)
                    mailbox_read_index_record(mailbox, msgno, &record);
            }

            item = item->next;
        }
    }

    /* Fix up information in index header */
    rewind(newindex);
    n = fread(buf, 1, mailbox->start_offset, newindex);
    if ((unsigned long)n != mailbox->start_offset) {
        syslog(LOG_ERR, "IOERROR: reading index header for %s: got %d of %ld",
               mailbox->name, n, mailbox->start_offset);
        goto fail;
    }

    /* Fix up last_uid */
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(upload_list->new_last_uid);

    /* Fix up exists */
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(newexists);
    /* fix up other counts */
    newanswered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED)))+numansweredflag;
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(newanswered);
    newdeleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED)))+numdeletedflag;
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(newdeleted);
    newflagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED)))+numflaggedflag;
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(newflagged);

    /* Fix up quota_mailbox_used */
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) =
        htonl(ntohl(*((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED))) + quota_add );
    /* Fix up start offset if necessary */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
        *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }

    /* Fix up last_append time */
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(last_appenddate);

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
		   "LOSTQUOTA: unable to record add of %lu bytes in quota %s",
		   quota_add, mailbox->quota.root);
	}
    }

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_INDEX)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_INDEX, sizeof(fnamebuf));

    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));
    if (rename(fnamebufnew, fnamebuf)) {
        syslog(LOG_ERR, "IOERROR: renaming index file for %s: %m",
               mailbox->name);
        goto fail;
    }

    path = (mailbox->mpath &&
	    (config_metapartition_files &
	     IMAP_ENUM_METAPARTITION_FILES_CACHE)) ?
	mailbox->mpath : mailbox->path;
    strlcpy(fnamebuf, path, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_CACHE, sizeof(fnamebuf));

    strlcpy(fnamebufnew, fnamebuf, sizeof(fnamebufnew));
    strlcat(fnamebufnew, ".NEW", sizeof(fnamebufnew));
    if (rename(fnamebufnew, fnamebuf)) {
        syslog(LOG_CRIT, ("CRITICAL IOERROR: renaming cache file for %s, "
                          "need to reconstruct: %m"), mailbox->name);
        goto fail;
    }

    /* No more fail clauses after this point: just clean up */
    free(buf);
    fclose(newindex);
    fclose(newcache);
    return(r);

 fail:
    if (buf) free(buf);
    if (newindex) fclose(newindex);
    if (newcache) fclose(newcache);

    return IMAP_IOERROR;
}

/* ====================================================================== */

/* Couple of helper routines to clear out expunged messages that we want to
 * upload again to resolve inconsistent state. upload_list should be in
 * correct UID order, unsorted expunge index may be in any order (and we
 * want to preserve that order as expunge index is FIFO list).  Simplest
 * (reasonably efficient) solution is to convert upload_list linked list
 * into flat array of unsigned long "uid_array" and search with binary chop.
 */

struct uid_array {
    unsigned long *array;
    unsigned long size;
};

static struct uid_array *
uid_array_create(struct sync_upload_list *upload_list)
{
    struct uid_array *uid_array;
    struct sync_upload_item *current;
    unsigned long *array, i, size, lastuid = 0;

    uid_array = xmalloc(sizeof(struct uid_array));
    uid_array->array = xmalloc((upload_list->count+1) * sizeof(unsigned long));
    uid_array->size  = upload_list->count;

    current = upload_list->head;
    size  = uid_array->size;
    array = uid_array->array;

    for (i = 0; current && (i < size); i++, current = current->next) {
        if ((i > 0) && (lastuid > current->uid))
            break;

        lastuid = array[i] = current->uid;
    }

    if ((current != NULL) || (i < size)) {
        syslog(LOG_ERR, "uid_array_create(): Invalid sequence");
        free(uid_array->array);
        free(uid_array);
        return(NULL);
    }
    uid_array->array[size] = 0;

    return(uid_array);
}

static void
uid_array_free(struct uid_array *uid_array)
{
    free(uid_array->array);
    free(uid_array);
}

/* ====================================================================== */

static int
sync_append_commit(struct mailbox *mailbox,
                   time_t last_appenddate,
                   struct sync_upload_list  *upload_list,
                   struct sync_message_list *message_list)
{
    unsigned char *index_chunk, *record;
    unsigned char *hbuf = xmalloc(mailbox->start_offset);
    struct iovec  *cache_iovec, *cachev;
    struct sync_upload_item *item;
    struct sync_message     *message;
    unsigned long cache_size;
    unsigned long quota_add       = 0;
    unsigned long numansweredflag = 0;
    unsigned long numdeletedflag  = 0;
    unsigned long numflaggedflag  = 0;
    unsigned long newexists;
    unsigned long newdeleted;
    unsigned long newanswered;
    unsigned long newflagged;
    char  target[MAX_MAILBOX_PATH];
    int   n, r = 0;
    struct txn *tid = NULL;

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
        message_uuid_pack(&item->uuid, record+OFFSET_MESSAGE_UUID);

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
        snprintf(target, MAX_MAILBOX_PATH,
                 "%s/%lu.", mailbox->path, (unsigned long)item->uid);

        if (mailbox_copyfile(item->message->msg_path, target, 0) != 0) {
            /* Attempt undo before we bail out */
            for (item = upload_list->head ; item != item; item = item->next)
                unlink(item->message->msg_path);

            goto fail;
        }
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

    lseek(mailbox->index_fd, mailbox->index_size, SEEK_SET);
    if (retry_write(mailbox->index_fd, index_chunk,
                    upload_list->count * INDEX_RECORD_SIZE) < 0)
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
    *((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED)) =
        htonl(ntohl(*((bit32 *)(hbuf+OFFSET_QUOTA_MAILBOX_USED)))+quota_add);

    /* Fix up start offset if necessary */
    if (mailbox->start_offset < INDEX_HEADER_SIZE) {
        *((bit32 *)(hbuf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    }

    /* Fix up last_append time */
    *((bit32 *)(hbuf+OFFSET_LAST_APPENDDATE)) = htonl(last_appenddate);
	
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
		   "LOSTQUOTA: unable to record add of %lu bytes in quota %s",
		   quota_add, mailbox->quota.root);
	}
    }

    free(hbuf);
    free(index_chunk);
    free(cache_iovec);
    return(r);

 fail:
    /* Attempt undo. Is this safe? */
    ftruncate(mailbox->cache_fd, mailbox->cache_size);
    ftruncate(mailbox->index_fd, mailbox->index_size);

    free(hbuf);
    free(index_chunk);
    free(cache_iovec);
    return(IMAP_IOERROR);
}

/* ====================================================================== */

int
sync_upload_commit(struct mailbox *mailbox,
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

    if (mailbox->last_uid >= head->uid) {
	/* Note for Ken:
	 *
	 * HERMES_TWO_PHASE_EXPUNGE has some code here to expire messages
	 * which have been expunged but not expired before uploading them
	 * again. This is to make sure that a message with a given UID
	 * never ends up in both the live and expunged version of a given
	 * mailbox. Something similar might be needed with the lazy
	 * expunge code in Cyrus 2.3
	 */
	r = sync_combine_commit(mailbox, last_appenddate,
				upload_list, message_list);
    } else
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

int
sync_uidlast_commit(struct mailbox *mailbox,
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

/* ====================================================================== */

int
sync_setflags_commit(struct mailbox *mailbox, struct sync_flag_list *flag_list)
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

int
sync_create_commit(char *name, char *uniqueid, char *acl,
                   int mbtype, unsigned long uidvalidity,
                   int isadmin, char *userid, struct auth_state *auth_state)
{
    int r;
    int free_uniqueid = 0;
    char *partition = (char *)config_defpartition;
    const char *root = NULL;
    char *newpartition;
    char *mboxent = NULL;
    int newreserved = 0; /* made reserved entry in local mailbox list */
    int mboxopen = 0;
    struct mailbox m;
    /* Must be atleast MAX_PARTITION_LEN + 30 for partition, need
     * MAX_PARTITION_LEN + HOSTNAME_SIZE + 2 for mupdate location */
    char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];

    /* Need an extra sanity check here as normal ACL logic is bypassed */
    r = mboxname_policycheck(name);
    if (r) return r;

    if (!uniqueid) {
	uniqueid = xmalloc(sizeof(char) * 32);
	mailbox_make_uniqueid(name, uidvalidity, uniqueid, 32); /* YYY */
        free_uniqueid = 1;
    }

    r = mboxlist_createmailboxcheck(name, 0, partition, 1,
                                    imapd_userid, imapd_authstate,
                                    NULL, &newpartition);
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

    /* Fix UIDvalidity */
    if (!r) r = mailbox_open_header(name, 0, &m);
    if (!r) mboxopen = 1;
    if (!r) r = mailbox_lock_header(&m);
    if (!r) r = mailbox_open_index(&m);
    if (!r) r = mailbox_lock_index(&m);
    if (!r) m.uidvalidity = uidvalidity;
    if (!r) mailbox_write_index_header(&m);

    if (mboxopen) mailbox_close(&m);

    if (free_uniqueid) free(uniqueid);

    return(r);
}
