/* dav_util.c -- utility functions for dealing with DAV database
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#include <string.h>

#include "append.h"
#include "dav_db.h"
#include "dav_util.h"
#include "global.h"
#include "mailbox.h"
#include "mboxname.h"
#include "strhash.h"
#include "syslog.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "xstrnchr.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"


EXPORTED int dav_get_validators(struct mailbox *mailbox, void *data,
                                const char *userid __attribute__((unused)),
                                struct index_record *record,
                                const char **etag, time_t *lastmod)
{
    const struct dav_data *ddata = (const struct dav_data *) data;

    memset(record, 0, sizeof(struct index_record));

    if (!ddata->alive) {
        /* New resource */
        if (etag) *etag = NULL;
        if (lastmod) *lastmod = 0;
    }
    else if (ddata->imap_uid) {
        /* Mapped URL */
        int r;

        /* Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, record);
        if (r) {
            syslog(LOG_ERR, "mailbox_find_index_record(%s, %u) failed: %s",
                   mailbox_name(mailbox), ddata->imap_uid, error_message(r));
            return r;
        }

        if (etag) *etag = message_guid_encode(&record->guid);
        if (lastmod) *lastmod = record->internaldate;
    }
    else {
        /* Unmapped URL (empty resource) */
        if (etag) *etag = NULL;
        if (lastmod) *lastmod = ddata->creationdate;
    }

    return 0;
}


EXPORTED int dav_store_resource(struct transaction_t *txn,
                                const char *data, size_t datalen,
                                struct mailbox *mailbox,
                                struct index_record *oldrecord,
                                modseq_t createdmodseq,
                                const strarray_t *add_imapflags,
                                const strarray_t *del_imapflags)
{
    int ret = HTTP_CREATED, r;
    hdrcache_t hdrcache = txn->req_hdrs;
    struct stagemsg *stage;
    FILE *f = NULL;
    const char **hdr, *cte;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    time_t now = time(NULL);
    struct appendstate as;
    const char *mboxname = mailbox_name(mailbox);

    /* Prepare to stage the message */
    if (!(f = append_newstage(mboxname, now,
                              strhash(mboxname), /* unique msgnum to avoid clash
                                                    during iMIP processing */
                              &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mailbox));
        txn->error.desc = "append_newstage() failed";
        return HTTP_SERVER_ERROR;
    }

    /* Create RFC 5322 header for resource */
    if ((hdr = spool_getheader(hdrcache, "User-Agent"))) {
        fprintf(f, "User-Agent: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "From"))) {
        fprintf(f, "From: %s\r\n", hdr[0]);
    }
    else {
        char *mimehdr;

        assert(!buf_len(&txn->buf));
        if (strchr(txn->userid, '@')) {
            /* XXX  This needs to be done via an LDAP/DB lookup */
            buf_printf(&txn->buf, "<%s>", txn->userid);
        }
        else {
            buf_printf(&txn->buf, "<%s@%s>", txn->userid, config_servername);
        }

        mimehdr = charset_encode_mimeheader(buf_cstring(&txn->buf),
                                            buf_len(&txn->buf), 0);
        fprintf(f, "From: %s\r\n", mimehdr);
        free(mimehdr);
        buf_reset(&txn->buf);
    }

    if ((hdr = spool_getheader(hdrcache, "Subject"))) {
        fprintf(f, "Subject: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "Date"))) {
        fprintf(f, "Date: %s\r\n", hdr[0]);
    }
    else {
        char datestr[80];       /* XXX: Why do we need 80 character buffer? */
        time_to_rfc5322(now, datestr, sizeof(datestr));
        fprintf(f, "Date: %s\r\n", datestr);
    }

    if ((hdr = spool_getheader(hdrcache, "Message-ID"))) {
        fprintf(f, "Message-ID: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "X-Schedule-User-Address"))) {
        fprintf(f, "X-Schedule-User-Address: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "Content-Type"))) {
        fprintf(f, "Content-Type: %s\r\n", hdr[0]);
    }
    else fputs("Content-Type: application/octet-stream\r\n", f);

    if (!datalen) {
        datalen = strlen(data);
        cte = "8bit";
    }
    else {
        cte = strnchr(data, '\0', datalen) ? "binary" : "8bit";
    }
    fprintf(f, "Content-Transfer-Encoding: %s\r\n", cte);

    if ((hdr = spool_getheader(hdrcache, "Content-Disposition"))) {
        fprintf(f, "Content-Disposition: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "Content-Description"))) {
        fprintf(f, "Content-Description: %s\r\n", hdr[0]);
    }

    fprintf(f, "Content-Length: %u\r\n", (unsigned) datalen);

    fputs("MIME-Version: 1.0\r\n\r\n", f);

    /* Write the data to the file */
    fwrite(data, datalen, 1, f);
    qdiffs[QUOTA_STORAGE] = ftell(f);

    fclose(f);

    qdiffs[QUOTA_MESSAGE] = 1;

    /* Prepare to append the message to the mailbox */
    if ((r = append_setup_mbox(&as, mailbox, txn->userid, txn->authstate,
                          0, qdiffs, 0, 0, EVENT_MESSAGE_NEW|EVENT_CALENDAR))) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
        if (r == IMAP_QUOTA_EXCEEDED) {
            /* DAV:quota-not-exceeded */
            txn->error.precond = DAV_OVER_QUOTA;
            ret = HTTP_NO_STORAGE;
        } else {
            ret = HTTP_SERVER_ERROR;
        }
        txn->error.desc = "append_setup() failed";
    }
    else {
        struct body *body = NULL;

        strarray_t *flaglist = NULL;
        struct entryattlist *annots = NULL;

        if (oldrecord) {
            flaglist = mailbox_extract_flags(mailbox, oldrecord, txn->userid);
            mailbox_get_annotate_state(mailbox, oldrecord->uid, NULL);
            annots = mailbox_extract_annots(mailbox, oldrecord);
        }

        /* XXX - casemerge?  Doesn't matter with flags */
        if (add_imapflags) {
            if (flaglist)
                strarray_cat(flaglist, add_imapflags);
            else
                flaglist = strarray_dup(add_imapflags);
        }
        if (del_imapflags && flaglist) {
            int i;
            for (i = 0; i < strarray_size(del_imapflags); i++) {
                strarray_remove_all_case(flaglist, strarray_nth(del_imapflags, i));
            }
        }

        /* Append the message to the mailbox */
        if ((r = append_fromstage(&as, &body, stage, now, createdmodseq, flaglist, 0, &annots))) {
            syslog(LOG_ERR, "append_fromstage(%s) failed: %s",
                   mailbox_name(mailbox), error_message(r));
            ret = HTTP_SERVER_ERROR;
            txn->error.desc = "append_fromstage() failed";
        }
        if (body) {
            message_free_body(body);
            free(body);
        }
        strarray_free(flaglist);
        freeentryatts(annots);

        if (r) append_abort(&as);
        else {
            /* Commit the append to the mailbox */
            if ((r = append_commit(&as))) {
                syslog(LOG_ERR, "append_commit(%s) failed: %s",
                       mailbox_name(mailbox), error_message(r));
                ret = HTTP_SERVER_ERROR;
                txn->error.desc = "append_commit() failed";
            }
            else {
                if (oldrecord) {
                    /* Now that we have the replacement message in place
                       expunge the old one. */
                    int userflag;

                    ret = HTTP_NO_CONTENT;

                    /* Perform the actual expunge */
                    r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
                    if (!r) {
                        oldrecord->user_flags[userflag/32] |= 1 << (userflag & 31);
                        oldrecord->internal_flags |= FLAG_INTERNAL_EXPUNGED;
                        r = mailbox_rewrite_index_record(mailbox, oldrecord);
                    }
                    if (r) {
                        syslog(LOG_ERR, "expunging record (%s) failed: %s",
                               mailbox_name(mailbox), error_message(r));
                        txn->error.desc = error_message(r);
                        ret = HTTP_SERVER_ERROR;
                    }
                }

                if (!r) {
                    /* Read index record for new message (always the last one) */
                    struct index_record newrecord;
                    struct dav_data ddata;
                    static char etagbuf[256];
                    const char *etag;

                    ddata.alive = 1;
                    ddata.imap_uid = mailbox->i.last_uid;
                    dav_get_validators(mailbox, &ddata, txn->userid, &newrecord,
                                       &etag, &txn->resp_body.lastmod);
                    strncpy(etagbuf, etag, 255);
                    etagbuf[255] = 0;
                    txn->resp_body.etag = etagbuf;
                }
            }
        }
    }

    append_removestage(stage);

    return ret;
}
