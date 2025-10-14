/* blobstore_openio.h
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 * Copyright (c) 2015 OpenIO, as a part of Cyrus
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
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>

#include <core/oiourl.h>
#include <oio_sds.h>

#include "mailbox.h"
#include "mboxname.h"
#include "libconfig.h"
#include "objectstore.h"
#include "objectstore_db.h"

static struct oio_sds_s *sds = NULL;
static const char *namespace = NULL;
static const char *account = NULL;

static int openio_sds_lazy_init(void)
{
    struct oio_error_s *err = NULL;
    int v, rc;

    if (sds) {
        return 0;
    }

    /* Turn the OIO logging ON/OFF */

    const char *verbosity = config_getstring(IMAPOPT_OPENIO_VERBOSITY);
    if (!verbosity) {
        oio_log_to_syslog(); // let the default (warn)
        oio_log_more();
    }
    else {
        int found = 0;
        oio_log_to_syslog();
        switch (*verbosity) {
        case 'q':
        case 'Q':
            if (!strcasecmp(verbosity, "quiet")) {
                oio_log_nothing();
            }
            break;
        case 't':
        case 'T':
            if (!found && strcasecmp(verbosity, "trace")) {
                break;
            }
            found = 1;
            oio_log_more();
            // FALLTHROUGH
        case 'd':
        case 'D':
            if (!found && strcasecmp(verbosity, "debug")) {
                break;
            }
            found = 1;
            oio_log_more();
            // FALLTHROUGH
        case 'i':
        case 'I':
            if (!found && strcasecmp(verbosity, "info")) {
                break;
            }
            found = 1;
            oio_log_more();
            // FALLTHROUGH
        case 'n':
        case 'N':
            if (!found && strcasecmp(verbosity, "notice")) {
                break;
            }
            found = 1;
            oio_log_more();
            // one more call to pass from ERR to WARN
            oio_log_more();
        }
    }

    if (!namespace) {
        namespace = config_getstring(IMAPOPT_OPENIO_NAMESPACE);
    }
    if (!account) {
        account = config_getstring(IMAPOPT_OPENIO_ACCOUNT);
    }

    if (!namespace || !*namespace) {
        syslog(LOG_ERR, "OIOSDS: no namespace configured");
        return ENOTSUP;
    }

    err = oio_sds_init(&sds, namespace);
    if (err) {
        syslog(LOG_ERR,
               "OIOSDS: NS init failure %s : (%d) %s",
               namespace,
               oio_error_code(err),
               oio_error_message(err));
        oio_error_pfree(&err);
        return ENOTSUP;
    }

    v = config_getduration(IMAPOPT_OPENIO_RAWX_TIMEOUT, 's');
    rc = oio_sds_configure(sds, OIOSDS_CFG_TIMEOUT_RAWX, &v, sizeof(int));
    if (0 != rc) {
        syslog(LOG_WARNING,
               "OIOSDS: could not set the query timeout to rawx services: %m");
    }

    v = config_getduration(IMAPOPT_OPENIO_PROXY_TIMEOUT, 's');
    rc = oio_sds_configure(sds, OIOSDS_CFG_TIMEOUT_PROXY, &v, sizeof(int));
    if (0 != rc) {
        syslog(LOG_WARNING,
               "OIOSDS: could not set the query timeout to proxy services: %m");
    }

    syslog(LOG_DEBUG, "OIOSDS: client ready to namespace %s", namespace);
    return 0;
}

static const char *mailbox_record_blobname(struct mailbox *mailbox,
                                           const struct index_record *record)
{
    return message_guid_encode(&record->guid);
}

static struct oio_url_s *mailbox_openio_name(struct mailbox *mailbox,
                                             const struct index_record *record)
{
    struct oio_url_s *url;
    const char *filename = mailbox_record_blobname(mailbox, record);

    url = oio_url_empty();
    oio_url_set(url, OIOURL_NS, namespace);
    if (account) {
        oio_url_set(url, OIOURL_ACCOUNT, account);
    }
    oio_url_set(url, OIOURL_USER, mboxname_to_userid(mailbox->name));
    oio_url_set(url, OIOURL_PATH, filename);
    return url;
}

int objectstore_put(struct mailbox *mailbox,
                    const struct index_record *record,
                    const char *fname)
{
    struct oio_error_s *err = NULL;
    struct oio_url_s *url = NULL;
    int rc, already_saved = 0;

    rc = openio_sds_lazy_init();
    if (rc) {
        return rc;
    }

    rc = objectstore_is_filename_in_container(mailbox, record, &already_saved);
    if (rc) {
        return rc;
    }

    add_message_guid(mailbox, record);

    url = mailbox_openio_name(mailbox, record);
    if (already_saved) {
        syslog(LOG_DEBUG,
               "OIOSDS: blob %s already uploaded for %u",
               oio_url_get(url, OIOURL_WHOLE),
               record->uid);
        oio_url_pclean(&url);
        return 0;
    }

    /* Then upload it */
    struct oio_sds_ul_dst_s ul_dst = {
        .url = url,
        .autocreate = 1,
        .out_size = 0,
        .content_id = 0,
    };
    err = oio_sds_upload_from_file(sds, &ul_dst, fname, 0, 0);

    if (!err) {
        syslog(LOG_INFO,
               "OIOSDS: blob %s uploaded for %u",
               oio_url_get(url, OIOURL_WHOLE),
               record->uid);
        rc = 0;
    }
    else {
        syslog(LOG_ERR,
               "OIOSDS: blob %s upload error for %u: (%d) %s",
               oio_url_get(url, OIOURL_WHOLE),
               record->uid,
               oio_error_code(err),
               oio_error_message(err));
        oio_error_pfree(&err);
        rc = EAGAIN;

        //  could not upload to object storage...   update database.
        int count = 0;
        delete_message_guid(mailbox, record, &count);
    }

    oio_url_pclean(&url);
    return rc;
}

int objectstore_get(struct mailbox *mailbox,
                    const struct index_record *record,
                    const char *fname)
{
    struct oio_error_s *err = NULL;
    struct oio_url_s *url;
    int rc;

    rc = openio_sds_lazy_init();
    if (rc) {
        return rc;
    }

    url = mailbox_openio_name(mailbox, record);

    err = oio_sds_download_to_file(sds, url, fname);
    if (!err) {
        syslog(LOG_INFO,
               "OIOSDS: blob %s downloaded for %u",
               oio_url_get(url, OIOURL_WHOLE),
               record->uid);
        rc = 0;
    }
    else {
        syslog(LOG_ERR,
               "OIOSDS: blob %s download error for %u : (%d) %s",
               oio_url_get(url, OIOURL_WHOLE),
               record->uid,
               oio_error_code(err),
               oio_error_message(err));
        oio_error_pfree(&err);
        rc = EAGAIN;
    }

    oio_url_pclean(&url);
    return rc;
}

int objectstore_delete(struct mailbox *mailbox,
                       const struct index_record *record)
{
    struct oio_error_s *err;
    struct oio_url_s *url;
    int rc;

    rc = openio_sds_lazy_init();
    if (rc) {
        return rc;
    }

    url = mailbox_openio_name(mailbox, record);

    int count = 0;
    delete_message_guid(mailbox, record, &count);
    if (!count) {
        err = oio_sds_delete(sds, url);
        if (!err) {
            syslog(LOG_INFO,
                   "OIOSDS: blob %s deleted for %u",
                   oio_url_get(url, OIOURL_WHOLE),
                   record->uid);
            rc = 0;
        }
        else {
            syslog(LOG_ERR,
                   "OIOSDS: blob %s delete error : [record:%u] (%d) %s",
                   oio_url_get(url, OIOURL_WHOLE),
                   record->uid,
                   oio_error_code(err),
                   oio_error_message(err));
            oio_error_pfree(&err);
            rc = EAGAIN;
        }
    }

    oio_url_pclean(&url);
    return rc;
}

int objectstore_is_filename_in_container(struct mailbox *mailbox,
                                         const struct index_record *record,
                                         int *phas)
{
    struct oio_error_s *err;
    struct oio_url_s *url;
    int rc, has;

    assert(phas != NULL);
    *phas = 0;

    rc = openio_sds_lazy_init();
    if (rc) {
        return rc;
    }

    url = mailbox_openio_name(mailbox, record);

    err = oio_sds_has(sds, url, &has);
    if (!err) {
        rc = 0;
        *phas = has;
    }
    else {
        syslog(LOG_ERR,
               "OIOSDS: blob %s check error : [record:%u] (%d) %s",
               oio_url_get(url, OIOURL_WHOLE),
               record->uid,
               oio_error_code(err),
               oio_error_message(err));
        oio_error_pfree(&err);
        rc = EAGAIN;
    }

    oio_url_pclean(&url);
    return rc;
}
