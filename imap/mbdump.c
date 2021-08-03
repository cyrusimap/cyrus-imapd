/* mbdump.c -- Mailbox dump routines
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <utime.h>

#include "annotate.h"
#ifdef WITH_DAV
#include "dav_util.h"
#endif
#include "global.h"
#include "map.h"
#include "mappedfile.h"
#include "mbdump.h"
#include "mboxkey.h"
#include "mboxlist.h"
#include "quota.h"
#include "retry.h"
#include "seen.h"
#include "seqset.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "user.h"
#include "util.h"
#include "index.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int dump_file(int first, int sync,
                     struct protstream *pin, struct protstream *pout,
                     const char *filename, const char *ftag,
                     const char *fbase, unsigned long flen);

static void downgrade_header(struct index_header *i, char *buf, int version,
                             int header_size, int record_size)
                             __attribute__((noinline));
static void header_set_num_records(char *buf, unsigned int nrecords)
                             __attribute__((noinline));

/* support for downgrading index files on copying back to an
 * earlier version of Cyrus */
static void downgrade_header(struct index_header *i, char *buf, int version,
                             int header_size, int record_size)
{
    unsigned UP_version = version;
    unsigned UP_validopts = 15;
    unsigned UP_num_records = i->exists;

    memset(buf, 0, INDEX_HEADER_SIZE);

    if (version < 10)
        UP_validopts = 3;
    /* was just called POP3_NEW_UIDL back then, single value */
    if (version < 8)
        UP_validopts = 1;

    /* has to match cyrus.cache still */
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = htonl(i->generation_no);
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(i->format);
    /* version is changed of course */
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(UP_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(header_size);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(record_size);
    /* NUM_RECORDS replaces "exists" in the older headers */
    *((bit32 *)(buf+OFFSET_NUM_RECORDS)) = htonl(UP_num_records);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(i->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(i->last_uid);

    /* quotas may be 64bit now */
    *((bit64 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonll(i->quota_mailbox_used);

    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(i->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(i->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(i->deleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(i->answered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(i->flagged);
    *((bit32 *)(buf+OFFSET_MAILBOX_OPTIONS)) = htonl(i->options & UP_validopts);
    *((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(i->leaked_cache_records);
    /* don't put values in the "SPARE" spots */
    if (version < 8) return;
    align_htonll(buf+OFFSET_HIGHESTMODSEQ, i->highestmodseq);
}

static void downgrade_record(const struct index_record *record, char *buf,
                             int version)
{
    int n;
    unsigned UP_content_offset = record->header_size;
    unsigned UP_validflags = 15;
    unsigned UP_modseqbase = OFFSET_MODSEQ;

    /* GUID was UUID and only 12 bytes long in versions 8 and 9.
     * it doesn't hurt to write it to the buffer in older versions,
     * because it won't be written out to file anyway due to the
     * record_size value. */
    if (version < 10)
        UP_modseqbase = OFFSET_MESSAGE_GUID+12;

    *((bit32 *)(buf+OFFSET_UID)) = htonl(record->uid);
    *((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(record->internaldate);
    *((bit32 *)(buf+OFFSET_SENTDATE)) = htonl(record->sentdate);
    *((bit32 *)(buf+OFFSET_SIZE)) = htonl(record->size);
    *((bit32 *)(buf+OFFSET_HEADER_SIZE)) = htonl(record->header_size);
    /* content_offset in previous versions, identical to header_size */
    *((bit32 *)(buf+OFFSET_GMTIME)) = htonl(UP_content_offset);
    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(record->cache_offset);
    *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(record->last_updated);
    *((bit32 *)(buf+OFFSET_SYSTEM_FLAGS))
        = htonl(record->system_flags & UP_validflags);
    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
        *((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)) = htonl(record->user_flags[n]);
    }
    *((bit32 *)(buf+OFFSET_SAVEDATE)) = 0;
    *((bit32 *)(buf+OFFSET_CACHE_VERSION)) = htonl(record->cache_version);
    message_guid_export(&record->guid, buf+OFFSET_MESSAGE_GUID);
    *((bit64 *)(buf+UP_modseqbase)) = htonll(record->modseq);
}

static void header_set_num_records(char *buf, unsigned int nrecords)
{
    *((bit32 *)(buf+OFFSET_NUM_RECORDS)) = htonl(nrecords);
}

/* create a downgraded index file in cyrus.index.  We don't copy back
 * expunged messages, sorry */
static int dump_index(struct mailbox *mailbox, int oldversion,
                      seqset_t *expunged_seq, int first, int sync,
                      struct protstream *pin, struct protstream *pout)
{
    char oldname[MAX_MAILBOX_PATH];
    const char *fname;
    int oldindex_fd = -1;
    indexbuffer_t headerbuf;
    indexbuffer_t recordbuf;
    char *hbuf = (char *)headerbuf.buf;
    char *rbuf = (char *)recordbuf.buf;
    int header_size;
    int record_size;
    int n, r;

    if (oldversion == 6) {
        header_size = 76;
        record_size = 60;
    }
    else if (oldversion == 7) {
        header_size = 76;
        record_size = 72;
    }
    else if (oldversion == 8) {
        header_size = 92;
        record_size = 80;
    }
    else if (oldversion == 9) {
        header_size = 96;
        record_size = 80;
    }
    else if (oldversion == 10) {
        header_size = 96;
        record_size = 88;
    }
    else {
        return IMAP_MAILBOX_BADFORMAT;
    }

    fname = mailbox_meta_fname(mailbox, META_INDEX);
    snprintf(oldname, MAX_MAILBOX_PATH, "%s.OLD", fname);

    oldindex_fd = open(oldname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (oldindex_fd == -1) goto fail;

    downgrade_header(&mailbox->i, hbuf, oldversion,
                     header_size, record_size);

    /* Write header - everything we'll say */
    n = retry_write(oldindex_fd, hbuf, header_size);
    if (n == -1) goto fail;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* we have to make sure expunged records don't get the
         * file copied, or a reconstruct could bring them back
         * to life!  It we're not creating an expunged file... */
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            if (oldversion < 9) seqset_add(expunged_seq, record->uid, 1);
            continue;
        }
        /* not making sure exists matches, we do trust a bit */
        downgrade_record(record, rbuf, oldversion);
        n = retry_write(oldindex_fd, rbuf, record_size);
        if (n == -1) break;
    }
    mailbox_iter_done(&iter);
    if (n == -1) goto fail;

    close(oldindex_fd);
    r = dump_file(first, sync, pin, pout, oldname, "cyrus.index", NULL, 0);
    unlink(oldname);
    if (r) return r;

    /* create cyrus.expunge */
    if (oldversion > 8 && mailbox->i.num_records > mailbox->i.exists) {
        int nexpunge = mailbox->i.num_records - mailbox->i.exists;
        fname = mailbox_meta_fname(mailbox, META_EXPUNGE);
        snprintf(oldname, MAX_MAILBOX_PATH, "%s.OLD", fname);

        oldindex_fd = open(oldname, O_RDWR|O_TRUNC|O_CREAT, 0666);
        if (oldindex_fd == -1) goto fail;

        header_set_num_records(hbuf, nexpunge);

        /* Write header - everything we'll say */
        n = retry_write(oldindex_fd, hbuf, header_size);
        if (n == -1) goto fail;

        iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            /* ignore non-expunged records */
            if (!(record->internal_flags & FLAG_INTERNAL_EXPUNGED))
                continue;
            downgrade_record(record, rbuf, oldversion);
            n = retry_write(oldindex_fd, rbuf, record_size);
            if (n == -1) goto fail;
        }

        close(oldindex_fd);
        r = dump_file(first, sync, pin, pout, oldname, "cyrus.expunge", NULL, 0);
        unlink(oldname);
        if (r) return r;
    }

    return 0;

fail:
    if (oldindex_fd != -1)
        close(oldindex_fd);
    unlink(oldname);

    return IMAP_IOERROR;
}

/* is this the active script? */
static int sieve_isactive(const char *sievepath, const char *name)
{
    char filename[1024];
    char linkname[1024];
    char activelink[1024];
    char *file, *link;
    int len;

    snprintf(filename, sizeof(filename), "%s/%s", sievepath, name);
    snprintf(linkname, sizeof(linkname), "%s/defaultbc", sievepath);

    len = readlink(linkname, activelink, sizeof(activelink)-1);
    if(len < 0) {
        if(errno != ENOENT) syslog(LOG_ERR, "readlink(defaultbc): %m");
        return 0;
    }

    activelink[len] = '\0';

    /* Only compare the part of the file after the last /,
     * since that is what timsieved does */
    file = strrchr(filename, '/');
    link = strrchr(activelink, '/');
    if(!file) file = filename;
    else file++;
    if(!link) link = activelink;
    else link++;

    if (!strcmp(file, link)) {
        return 1;
    } else {
        return 0;
    }
}

struct dump_annotation_rock
{
    struct protstream *pout;
    const char *tag;
};

static int dump_annotations(const char *mailbox __attribute__((unused)),
                            uint32_t uid  __attribute__((unused)),
                            const char *entry,
                            const char *userid,
                            const struct buf *value,
                            const struct annotate_metadata *mdata __attribute__((unused)),
                            void *rock)
{
    struct dump_annotation_rock *ctx = (struct dump_annotation_rock *)rock;

    /* "A-" userid entry */
    /* entry is delimited by its leading / */
    char *ename;
    static const char contenttype[] = "text/plain"; /* fake */

    /* Transfer all attributes for this annotation, don't transfer size
     * separately since that can be implicitly determined */

    prot_putc(' ', ctx->pout);
    ename = strconcat("A-", userid, entry, (char *)NULL);
    prot_printliteral(ctx->pout, ename, strlen(ename));
    free(ename);

    prot_printf(ctx->pout, " (%ld ", 0L);  /* was modifiedsince */
    prot_printliteral(ctx->pout, value->s, value->len);
    prot_putc(' ', ctx->pout);
    prot_printliteral(ctx->pout, contenttype, strlen(contenttype));
    prot_putc(')', ctx->pout);

    return 0;
}

static int dump_file(int first, int sync,
                     struct protstream *pin, struct protstream *pout,
                     const char *filename, const char *ftag,
                     const char *fbase, unsigned long flen)
{
    int filefd;
    const char *base;
    size_t len;
    struct stat sbuf;
    int c;

    /* map file */
    syslog(LOG_DEBUG, "wanting to dump %s", filename);
    if (fbase) {
        /* already mapped */
        base = fbase;

        /* we need to check real file size since actual mmap size may be larger */
        if (stat(filename, &sbuf) == -1) {
            syslog(LOG_ERR, "IOERROR: stat on %s: %m", filename);
            fatal("can't stat message file", EX_OSFILE);
        }
        if ((unsigned long)sbuf.st_size > flen) {
           syslog(LOG_ERR, "IOERROR: size mismatch on %s", filename);
           return IMAP_SYS_ERROR;
        }
        len = sbuf.st_size;
    }
    else {
        filefd = open(filename, O_RDONLY, 0666);
        if (filefd == -1) {
            /* If an optional file doesn't exist, skip it */
            if (errno == ENOENT) return 0;
            syslog(LOG_ERR, "IOERROR: open on %s: %m", filename);
            return IMAP_SYS_ERROR;
        }

        if (fstat(filefd, &sbuf) == -1) {
            syslog(LOG_ERR, "IOERROR: fstat on %s: %m", filename);
            fatal("can't fstat message file", EX_OSFILE);
        }

        base = NULL;
        len = 0;

        map_refresh(filefd, 1, &base, &len, sbuf.st_size, filename, NULL);

        close(filefd);
    }

    /* send: name, size, and contents */
    if (first) {
        prot_printf(pout, " {" SIZE_T_FMT "}\r\n", strlen(ftag));

        if (sync) {
            /* synchronize */
            c = prot_getc(pin);
            eatline(pin, c); /* We eat it no matter what */
            if (c != '+') {
                /* Synchronization Failure, Abort! */
                syslog(LOG_ERR, "Sync Error: expected '+' got '%c'",c);
                return IMAP_SERVER_UNAVAILABLE;
            }
        }

        prot_printf(pout, "%s {%lu%s}\r\n",
                    ftag, (long unsigned)len, (sync ? "+" : ""));
    } else {
        prot_printf(pout, " {" SIZE_T_FMT "%s}\r\n%s {%lu%s}\r\n",
                    strlen(ftag), (sync ? "+" : ""),
                    ftag, (long unsigned)len, (sync ? "+" : ""));
    }
    prot_write(pout, base, len);
    if (!fbase) map_free(&base, &len);

    return 0;
}

struct data_file {
    int metaname;
    char *fname;
};

/* even though 2.4.x doesn't use cyrus.expunge, we need to be aware
 * that it may exist so XFER from any 2.3.x server will work
 */
static struct data_file data_files[] = {
    { META_HEADER,  "cyrus.header"  },
    { META_INDEX,   "cyrus.index"   },
    { META_CACHE,   "cyrus.cache"   },
    { META_EXPUNGE, "cyrus.expunge" },
#ifdef WITH_DAV
    { META_DAV,     "cyrus.dav"     },
#endif
    { 0, NULL }
};

enum { SEEN_DB = 0, SUBS_DB = 1, MBOXKEY_DB = 2, DAV_DB = 3 };
static int NUM_USER_DATA_FILES = 4;

EXPORTED int dump_mailbox(const char *tag, struct mailbox *mailbox, uint32_t uid_start,
                 int oldversion,
                 struct protstream *pin, struct protstream *pout,
                 struct auth_state *auth_state __attribute((unused)))
{
    DIR *mbdir = NULL;
    int r = 0;
    struct dirent *next = NULL;
    char filename[MAX_MAILBOX_PATH + 1024];
    const char *fname;
    int first = 1;
    int i;
    char *userid = NULL;
    struct quota q;
    struct data_file *df;
    seqset_t *expunged_seq = NULL;
    const char *dirpath = mailbox_datapath(mailbox, 0);

    /* XXX - archivepath */

    mbdir = opendir(dirpath);
    if (!mbdir && errno == EACCES) {
        syslog(LOG_ERR,
               "could not dump mailbox %s (permission denied)", mailbox_name(mailbox));
        return IMAP_PERMISSION_DENIED;
    } else if (!mbdir) {
        syslog(LOG_ERR,
               "could not dump mailbox %s (unknown error)", mailbox_name(mailbox));
        return IMAP_SYS_ERROR;
    }

    /* after this point we have to both close the directory and unlock
     * the mailbox */

    if (tag) prot_printf(pout, "%s DUMP ", tag);
    (void)prot_putc('(', pout);

    /* The first member is either a number (if it is a quota root), or NIL
     * (if it isn't) */
    {
        quota_init(&q, mailbox_name(mailbox));
        r = quota_read(&q, NULL, 0);

        if (!r) {
            prot_printf(pout, QUOTA_T_FMT, q.limits[QUOTA_STORAGE]);
        } else {
            prot_printf(pout, "NIL");
            if (r == IMAP_QUOTAROOT_NONEXISTENT) r = 0;
            /* do not send other quota data later */
            quota_free(&q);
        }
    }

    /* Dump cyrus data files */
    for (df = data_files; df->metaname; df++) {
        const char *fbase = NULL;
        unsigned long flen = 0;

        switch (df->metaname) {
        case META_INDEX:
            if (mailbox->index_base) {
                fbase = mailbox->index_base;
                flen = mailbox->index_len;
            }
            break;

        case META_CACHE:
            {
                /* XXX - multi-cache-file support */
                struct mappedfile *cachefile = ptrarray_nth(&mailbox->caches, 0);
                if (cachefile) {
                    fbase = mappedfile_base(cachefile);
                    flen = mappedfile_size(cachefile);
                }
            }
            break;

        default:
            break;
        }

        if (df->metaname == META_INDEX && oldversion < MAILBOX_MINOR_VERSION) {
            expunged_seq = seqset_init(mailbox->i.last_uid, SEQ_SPARSE);
            syslog(LOG_NOTICE, "%s downgrading index to version %d for XFER",
                   mailbox_name(mailbox), oldversion);

            r = dump_index(mailbox, oldversion, expunged_seq,
                           first, !tag, pin, pout);
            if (r) goto done;

        } else {
            fname = mailbox_meta_fname(mailbox, df->metaname);
            r = dump_file(first, !tag, pin, pout, fname, df->fname, fbase, flen);
            if (r) goto done;
        }

        first = 0;
    }

    /* Dump message files */
    while ((next = readdir(mbdir)) != NULL) {
        char *name = next->d_name;  /* Alias */
        char *p = name;
        char *fullpath;
        uint32_t uid;

        /* special case for '.' (well, it gets '..' too) */
        if (name[0] == '.') continue;

        /* skip non-message files */
        while (*p && Uisdigit(*p)) p++;
        if (p[0] != '.' || p[1] != '\0') continue;

        /* ensure (number) is >= our target uid */
        uid = atoi(name);
        if (uid < uid_start) continue;

        /* ensure uid is not in the expunged records that got skipped
         * in a downgraded index file */
        if (seqset_ismember(expunged_seq, uid))
           continue;

        /* construct path/filename */
        fullpath = strconcat(dirpath, "/", name, (char *)NULL);
        r = dump_file(0, !tag, pin, pout, fullpath, name, NULL, 0);
        free(fullpath);

        if (r) goto done;
    }

    closedir(mbdir);
    mbdir = NULL;

    /* Dump annotations */
    {
        struct dump_annotation_rock actx;
        actx.tag = tag;
        actx.pout = pout;
        annotatemore_findall_mailbox(mailbox, 0, "*", /*modseq*/0,
                             dump_annotations, (void *) &actx, /*flags*/0);
    }

    /* Dump user files if this is an inbox */
    if (mboxname_isusermailbox(mailbox_name(mailbox), 1)) {
        userid = mboxname_to_userid(mailbox_name(mailbox));
        int sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);
        char *fname = NULL, *ftag = NULL;

        /* Dump seen and subs files */
        for (i = 0; i< NUM_USER_DATA_FILES; i++) {

            /* construct path/filename */
            switch (i) {
            case SEEN_DB:
                fname = seen_getpath(userid);
                ftag = "SEEN";
                break;
            case SUBS_DB:
                fname = user_hash_subs(userid);
                ftag = "SUBS";
                break;
            case MBOXKEY_DB:
                fname = mboxkey_getpath(userid);
                ftag = "MBOXKEY";
                break;
            case DAV_DB: {
#ifdef WITH_DAV
                struct buf dav_file = BUF_INITIALIZER;

                dav_getpath_byuserid(&dav_file, userid);
                fname = (char *) buf_cstring(&dav_file);
                ftag = "DAV";
#else
                continue;
#endif
                break;
            }
            default:
                fatal("unknown user data file", EX_OSFILE);
            }

            r = dump_file(0, !tag, pin, pout, fname, ftag, NULL, 0);
            free(fname);
            if (r) goto done;
        }

        /* Dump sieve files
         *
         * xxx can't use home directories currently
         * (it makes almost no sense in the conext of a murder) */
        if (!sieve_usehomedir) {
            const char *sieve_path = user_sieve_path(userid);
            mbdir = opendir(sieve_path);

            if (!mbdir) {
                if (errno != ENOENT)
                    syslog(LOG_ERR,
                           "could not dump sieve scripts in %s: %m)", sieve_path);
            } else {
                char tag_fname[2048];

                while((next = readdir(mbdir)) != NULL) {
                    int length=strlen(next->d_name);
                    /* 7 == strlen(".script"); 3 == strlen(".bc") */
                    if ((length >= 7 &&
                         !strcmp(next->d_name + (length - 7), ".script")) ||
                        (length >= 3 &&
                         !strcmp(next->d_name + (length - 3), ".bc")))
                    {
                        /* create tagged name */
                        if(sieve_isactive(sieve_path, next->d_name)) {
                            snprintf(tag_fname, sizeof(tag_fname),
                                     "SIEVED-%s", next->d_name);
                        } else {
                            snprintf(tag_fname, sizeof(tag_fname),
                                     "SIEVE-%s", next->d_name);
                        }

                        /* construct path/filename */
                        snprintf(filename, sizeof(filename), "%s/%s",
                                 sieve_path, next->d_name);

                        /* dump file */
                        r = dump_file(0, !tag, pin, pout, filename, tag_fname, NULL, 0);
                        if (r) goto done;
                    }
                }

                closedir(mbdir);
                mbdir = NULL;
            }
        } /* end if !sieve_userhomedir */

    } /* end if user INBOX */

    /* Dump quota data */
    if (q.root) {
        const char *ename = "X-QUOTA";
        int res;

        /* ensure there is data to transmit */
        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            /* STORAGE quota was already sent */
            if ((res != QUOTA_STORAGE) && (q.limits[res] >= 0)) {
                break;
            }
        }

        if (res < QUOTA_NUMRESOURCES) {
            int sent = 0;

            prot_putc(' ', pout);
            prot_printliteral(pout, ename, strlen(ename));
            prot_printf(pout, " (");

            for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                if (q.limits[res] < 0) {
                    continue;
                }
                if (sent++) {
                    prot_putc(' ', pout);
                }
                prot_printliteral(pout, quota_names[res], strlen(quota_names[res]));
                prot_putc(' ', pout);
                prot_printf(pout, QUOTA_T_FMT, q.limits[res]);
            }
            prot_putc(')', pout);
        }
        quota_free(&q);
    }

 done:

    prot_printf(pout,")\r\n");

    prot_flush(pout);

    if (mbdir) closedir(mbdir);
    seqset_free(&expunged_seq);
    free(userid);

    return r;
}

static int cleanup_seen_cb(const mbentry_t *mbentry, void *rock)
{
    struct seen *seendb = (struct seen *)rock;
    int r;
    seqset_t *seq = NULL;
    struct mailbox *mailbox = NULL;
    const message_t *msg;
    struct seendata sd = SEENDATA_INITIALIZER;

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) goto done;

    /* read in the seen data from the seendb */
    r = seen_read(seendb, mailbox_uniqueid(mailbox), &sd);
    if (r) goto done;

    seq = seqset_parse(sd.seenuids, NULL, sd.lastuid);
    seen_freedata(&sd);

    /* update all the seen records */
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (record->system_flags & FLAG_SEEN)
            continue; /* no need to rewrite */
        if (!seqset_ismember(seq, record->uid))
            continue;
        struct index_record copy = *record;
        copy.system_flags |= FLAG_SEEN;
        r = mailbox_rewrite_index_record(mailbox, &copy);
        if (r) break;
    }
    mailbox_iter_done(&iter);

    /* and the header values */
    mailbox_index_dirty(mailbox);
    if (mailbox->i.recentuid < sd.lastuid)
        mailbox->i.recentuid = sd.lastuid;
    if (mailbox->i.recenttime < sd.lastread)
        mailbox->i.recenttime = sd.lastread;

 done:
    seqset_free(&seq);
    mailbox_close(&mailbox);
    return r;
}

static int cleanup_seen_subfolders(const char *mbname)
{
    char *userid = mboxname_to_userid(mbname);
    struct seen *seendb = NULL;
    char buf[MAX_MAILBOX_NAME];
    int r;

    /* not owned by a user */
    if (!userid) return 0;

    /* no need to do inbox, it will have upgraded OK, just
     * the subfolders */

    snprintf(buf, sizeof(buf), "%s.", mbname);

    r = seen_open(userid, SEEN_SILENT, &seendb);
    if (!r) mboxlist_allmbox(buf, cleanup_seen_cb, seendb, /*flags*/0);
    seen_close(&seendb);

    free(userid);

    return 0;
}

EXPORTED int undump_mailbox(const char *mbname,
                   struct protstream *pin, struct protstream *pout,
                   struct auth_state *auth_state __attribute((unused)))
{
    struct buf file = BUF_INITIALIZER;
    struct buf data = BUF_INITIALIZER;
    int c;
    int r = 0;
    int curfile = -1;
    struct mailbox *mailbox = NULL;
    const char *sieve_path = NULL;
    int sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);
    char *userid = NULL;
    int first_annotation = 1;
    char *annotation = NULL;
    struct buf content = BUF_INITIALIZER;
    char *seen_file = NULL;
    char *mboxkey_file = NULL;
    quota_t old_quota_usage[QUOTA_NUMRESOURCES];
    int res;
    quota_t newquotas[QUOTA_NUMRESOURCES];
    quota_t quotalimit = -1;
    annotate_state_t *astate = NULL;

    /* Set a Quota (may be -1 for "unlimited") */
    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
       newquotas[res] = QUOTA_UNLIMITED;
    }

    if (mboxname_isusermailbox(mbname, 1)) {
        userid = mboxname_to_userid(mbname);
        if(!sieve_usehomedir) {
            sieve_path = user_sieve_path(userid);
        }
    }

    c = getword(pin, &data);

    /* we better be in a list now */
    if (c != '(' || data.s[0]) {
        buf_free(&data);
        free(userid);
        eatline(pin, c);
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    /* We should now have a number or a NIL */
    c = getword(pin, &data);
    if (!strcmp(data.s, "NIL")) {
        /* Remove any existing quotaroot */
        mboxlist_unsetquota(mbname);
    } else if (sscanf(data.s, QUOTA_T_FMT, &quotalimit) == 1) {
        /* quota will actually be applied later */
        newquotas[QUOTA_STORAGE] = quotalimit;
    } else {
        /* Huh? */
        buf_free(&data);
        free(userid);
        eatline(pin, c);
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    if(c != ' ' && c != ')') {
        buf_free(&data);
        free(userid);
        eatline(pin, c);
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    } else if(c == ')') {
        goto done;
    }

    r = mailbox_open_exclusive(mbname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        mbentry_t *mbentry = NULL;
        r = mboxlist_lookup(mbname, &mbentry, NULL);
        if (!r) r = mailbox_create(mbname, mbentry->mbtype,
                                   mbentry->partition, mbentry->acl,
                                   mbentry->uniqueid, 0, 0, 0, 0, &mailbox);
        mboxlist_entry_free(&mbentry);
    }
    if(r) goto done;

    /* track quota use */
    mailbox_get_usage(mailbox, old_quota_usage);

    astate = annotate_state_new();

    while(1) {
        char fnamebuf[MAX_MAILBOX_PATH + 1024];
        int isnowait, sawdigit;
        unsigned long size;
        unsigned long cutoff = ULONG_MAX / 10;
        unsigned digit, cutlim = ULONG_MAX % 10;
        annotation = NULL;
        buf_reset(&content);
        seen_file = NULL;
        mboxkey_file = NULL;

        c = getastring(pin, pout, &file);
        if(c != ' ') {
            r = IMAP_PROTOCOL_ERROR;
            goto done;
        }

        if(!strncmp(file.s, "A-", 2)) {
            /* Annotation */
            int i;
            char *tmpuserid;

            /* is this the first annotation? re-read cyrus.header/index */
            if (first_annotation) {
                first_annotation = 0;
                mailbox_close(&mailbox);
                r = mailbox_open_exclusive(mbname, &mailbox);
                if (r) goto done;
                r = annotate_state_set_mailbox(astate, mailbox);
                if (r) goto done;
            }

            for(i=2; file.s[i]; i++) {
                if(file.s[i] == '/') break;
            }
            if(!file.s[i]) {
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }
            tmpuserid = xmalloc(i-2+1);

            memcpy(tmpuserid, &(file.s[2]), i-2);
            tmpuserid[i-2] = '\0';

            annotation = xstrdup(&(file.s[i]));

            if(prot_getc(pin) != '(') {
                r = IMAP_PROTOCOL_ERROR;
                free(tmpuserid);
                goto done;
            }

            /* Parse the modtime...and ignore it */
            c = getword(pin, &data);
            if (c != ' ')  {
                r = IMAP_PROTOCOL_ERROR;
                free(tmpuserid);
                goto done;
            }

            c = getbastring(pin, pout, &content);
            /* xxx binary */

            if(c != ' ') {
                r = IMAP_PROTOCOL_ERROR;
                free(tmpuserid);
                goto done;
            }

            /* got the contenttype...and ignore it */
            c = getastring(pin, pout, &data);

            if(c != ')') {
                r = IMAP_PROTOCOL_ERROR;
                free(tmpuserid);
                goto done;
            }

            annotate_state_write(astate, annotation, tmpuserid,
                                     &content);

            free(tmpuserid);
            free(annotation);
            annotation = NULL;
            buf_reset(&content);

            c = prot_getc(pin);
            if(c == ')') break; /* that was the last item */
            else if(c != ' ') {
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }

            continue;
        }
        else if (!strcmp(file.s, "X-QUOTA")) {
            /* Quota */
            if (prot_getc(pin) != '(') {
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }

            for (;;) {
                /* XXX - limit is actually stored in an int value */
                int32_t limit = 0;

                c = getastring(pin, pout, &content);
                if (c != ' ') {
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                }
                /* ignore unknown resources */
                res = quota_name_to_resource(content.s);

                c = getint32(pin, &limit);
                if (res >= 0) {
                    newquotas[res] = limit;
                }

                if (c == ')') break;
                else if (c != ' ') {
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                }
            }

            c = prot_getc(pin);
            if (c == ')') break; /* that was the last item */
            else if (c != ' ') {
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }

            continue;
        }

        /* read size of literal */
        c = prot_getc(pin);
        if (c != '{') {
            r = IMAP_PROTOCOL_ERROR;
            goto done;
        }

        size = isnowait = sawdigit = 0;
        while ((c = prot_getc(pin)) != EOF && isdigit(c)) {
            sawdigit = 1;
            digit = c - '0';
            /* check for overflow */
            if (size > cutoff || (size == cutoff && digit > cutlim)) {
                fatal("literal too big", EX_IOERR);
            }
            size = size*10 + digit;
        }
        if (c == '+') {
            isnowait++;
            c = prot_getc(pin);
        }
        if (c == '}') {
            c = prot_getc(pin);
            if (c == '\r') c = prot_getc(pin);
        }
        if (!sawdigit || c != '\n') {
            r = IMAP_PROTOCOL_ERROR;
            goto done;
        }

        if (!isnowait) {
            /* Tell client to send the message */
            prot_printf(pout, "+ go ahead\r\n");
            prot_flush(pout);
        }

        if (userid && !strcmp(file.s, "SUBS")) {
            /* overwriting this outright is absolutely what we want to do */
            char *s = user_hash_subs(userid);
            strlcpy(fnamebuf, s, sizeof(fnamebuf));
            free(s);
#ifdef WITH_DAV
        } else if (userid && !strcmp(file.s, "DAV")) {
            /* overwriting this outright is absolutely what we want to do */
            struct buf dav_file = BUF_INITIALIZER;
            dav_getpath_byuserid(&dav_file, userid);
            strlcpy(fnamebuf, buf_cstring(&dav_file), sizeof(fnamebuf));
            buf_free(&dav_file);
#endif
        } else if (userid && !strcmp(file.s, "SEEN")) {
            seen_file = seen_getpath(userid);

            snprintf(fnamebuf,sizeof(fnamebuf),"%s.%d",seen_file,getpid());
        } else if (userid && !strcmp(file.s, "MBOXKEY")) {
            mboxkey_file = mboxkey_getpath(userid);

            snprintf(fnamebuf,sizeof(fnamebuf),"%s.%d",mboxkey_file,getpid());
        } else if (userid && !strncmp(file.s, "SIEVE", 5)) {
            int isdefault = !strncmp(file.s, "SIEVED", 6);
            char *realname;
            int ret;

            /* skip prefixes */
            if(isdefault) realname = file.s + 7;
            else realname = file.s + 6;

            if(sieve_usehomedir) {
                /* xxx! */
                syslog(LOG_ERR,
                       "dropping sieve file %s since this host is " \
                       "configured for sieve_usehomedir",
                       realname);
                continue;
            } else {
                if(snprintf(fnamebuf, sizeof(fnamebuf),
                            "%s/%s", sieve_path, realname) == -1) {
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                } else if(isdefault) {
                    char linkbuf[2048];

                    snprintf(linkbuf, sizeof(linkbuf), "%s/defaultbc",
                             sieve_path);
                    ret = symlink(realname, linkbuf);
                    if(ret && errno == ENOENT) {
                        if(cyrus_mkdir(linkbuf, 0750) == 0) {
                            ret = symlink(realname, linkbuf);
                        }
                    }
                    if(ret) {
                        syslog(LOG_ERR, "symlink(%s, %s): %m", realname,
                               linkbuf);
                        /* Non-fatal,
                           let's get the file transferred if we can */
                    }

                }
            }
        } else {
            struct data_file *df;
            const char *path = NULL;

            /* see if its one of our datafiles */
            for (df = data_files; df->fname && strcmp(df->fname, file.s); df++);
            if (df->metaname) {
                path = mailbox_meta_fname(mailbox, df->metaname);
            } else {
                uint32_t uid;
                const char *ptr = NULL;
                if (!parseuint32(file.s, &ptr, &uid)) {
                    /* is it really a data file? */
                    if (ptr && ptr[0] == '.' && ptr[1] == '\0')
                        path = mailbox_datapath(mailbox, uid);
                }
            }
            if (!path) {
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }
            strncpy(fnamebuf, path, MAX_MAILBOX_PATH);
        }

        /* if we haven't opened it, do so */
        curfile = open(fnamebuf, O_WRONLY|O_TRUNC|O_CREAT, 0640);
        if(curfile == -1 && errno == ENOENT) {
            if(cyrus_mkdir(fnamebuf, 0750) == 0) {
                curfile = open(fnamebuf, O_WRONLY|O_TRUNC|O_CREAT, 0640);
            }
        }

        if(curfile == -1) {
            syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
            r = IMAP_IOERROR;
            goto done;
        }

        /* write data to file */
        while (size) {
            char buf[4096+1];
            int n = prot_read(pin, buf, size > 4096 ? 4096 : size);
            if (!n) {
                syslog(LOG_ERR,
                       "IOERROR: reading message: unexpected end of file");
                r = IMAP_IOERROR;
                goto done;
            }

            size -= n;

            if (write(curfile, buf, n) != n) {
                syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
                r = IMAP_IOERROR;
                goto done;
            }
        }

        close(curfile);

        /* we were operating on the seen state, so merge it and cleanup */
        if (seen_file) {
            struct seen *seendb = NULL;
            r = seen_open(userid, SEEN_CREATE, &seendb);
            if (!r) r = seen_merge(seendb, fnamebuf);
            seen_close(&seendb);

            free(seen_file);
            seen_file = NULL;
            unlink(fnamebuf);

            if (r) goto done;
        }
        /* we were operating on the seen state, so merge it and cleanup */
        else if (mboxkey_file) {
            mboxkey_merge(fnamebuf, mboxkey_file);
            free(mboxkey_file);
            mboxkey_file = NULL;

            unlink(fnamebuf);
        }

        c = prot_getc(pin);
        if (c == ')') break;
        if (c != ' ') {
            r = IMAP_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* patch up seen data for subfolders */
    if (userid) {
        r = cleanup_seen_subfolders(mbname);
        /* XXX - patch up seen data here */
    }

 done:
    /* eat the rest of the line, we have atleast a \r\n coming */
    eatline(pin, c);
    buf_free(&file);
    buf_free(&data);

    if (r)
        annotate_state_abort(&mailbox->annot_state);

    if (curfile >= 0) close(curfile);
    /* we fiddled the files under the hood, so we can't do anything
     * BUT close it */
    mailbox_close(&mailbox);

    /* time to apply quota (mailbox must be unlocked) */
    if (!r) {
        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            if (newquotas[res] != QUOTA_UNLIMITED) {
                break;
            }
        }
        if (res < QUOTA_NUMRESOURCES) {
            mboxlist_setquotas(mbname, newquotas, 0, 0);
        }
    }

    /* let's make sure the modification times are right */
    if (!r) {
        struct utimbuf settime;
        const char *fname;

        /* cheeky - we're not actually changing anything real */
        r = mailbox_open_irl(mbname, &mailbox);
        if (r) {
            r = 0; /* no point throwing errors */
            goto done2;
        }

        /* update the quota if necessary */
        if (mailbox->quotaroot) {
            quota_t quota_usage[QUOTA_NUMRESOURCES];
            int res;
            int changed = 0;

            mailbox_get_usage(mailbox, quota_usage);
            for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                quota_usage[res] -= old_quota_usage[res];
                if (quota_usage[res] != 0) {
                    changed++;
                }
            }

            if (changed) {
                r = quota_update_useds(mailbox->quotaroot, quota_usage, NULL, 0);
                if (r) goto done2;
            }
        }

        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            fname = mailbox_record_fname(mailbox, record);
            settime.actime = settime.modtime = record->internaldate;
            if (utime(fname, &settime) == -1) {
                r = IMAP_IOERROR;
                goto done2;
            }
        }
        mailbox_iter_done(&iter);
    }

 done2:
    /* just in case we failed during the modifications, close again */
    mailbox_close(&mailbox);
    if (!r)
        r = annotate_state_commit(&astate);
    else
        annotate_state_abort(&astate);
    free(annotation);
    buf_free(&content);
    free(seen_file);
    free(mboxkey_file);
    free(userid);

    return r;
}
