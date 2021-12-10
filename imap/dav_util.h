/* dav_util.h -- utility functions for dealing with DAV database
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

#ifndef DAV_UTIL_H
#define DAV_UTIL_H

#include "httpd.h"
#include "mailbox.h"
#include "util.h"

#define FNAME_DAVSUFFIX "dav" /* per-user DAV DB extension */

/* XML namespace URIs */
#define XML_NS_DAV      "DAV:"
#define XML_NS_CALDAV   "urn:ietf:params:xml:ns:caldav"
#define XML_NS_CARDDAV  "urn:ietf:params:xml:ns:carddav"
#define XML_NS_ISCHED   "urn:ietf:params:xml:ns:ischedule"
#define XML_NS_CS       "http://calendarserver.org/ns/"
#define XML_NS_MECOM    "http://me.com/_namespace/"
#define XML_NS_MOBME    "urn:mobileme:davservices"
#define XML_NS_APPLE    "http://apple.com/ns/ical/"
#define XML_NS_USERFLAG "http://cyrusimap.org/ns/userflag/"
#define XML_NS_SYSFLAG  "http://cyrusimap.org/ns/sysflag/"
#define XML_NS_DAVMOUNT "http://purl.org/NET/webdav/mount/"
#define XML_NS_JMAPCAL  "urn:ietf:params:jmap:calendars"

/* Index into preconditions array */
enum {
    /* WebDAV (RFC 4918) preconditions */
    DAV_PROT_PROP = 1,
    DAV_BAD_LOCK_TOKEN,
    DAV_NEED_LOCK_TOKEN,
    DAV_LOCKED,
    DAV_FINITE_DEPTH,

    /* WebDAV Versioning (RFC 3253) preconditions */
    DAV_SUPP_REPORT,
    DAV_RES_EXISTS,

    /* WebDAV ACL (RFC 3744) preconditions */
    DAV_NEED_PRIVS,
    DAV_NO_INVERT,
    DAV_NO_ABSTRACT,
    DAV_SUPP_PRIV,
    DAV_RECOG_PRINC,
    DAV_ALLOW_PRINC,
    DAV_GRANT_ONLY,

    /* WebDAV Quota (RFC 4331) preconditions */
    DAV_OVER_QUOTA,
    DAV_NO_DISK_SPACE,

    /* WebDAV Extended MKCOL (RFC 5689) preconditions */
    DAV_VALID_RESTYPE,

    /* WebDAV Sync (RFC 6578) preconditions */
    DAV_SYNC_TOKEN,
    DAV_OVER_LIMIT,

    /* CalDAV (RFC 4791) preconditions */
    CALDAV_SUPP_DATA,
    CALDAV_VALID_DATA,
    CALDAV_VALID_OBJECT,
    CALDAV_SUPP_COMP,
    CALDAV_LOCATION_OK,
    CALDAV_UID_CONFLICT,
    CALDAV_SUPP_FILTER,
    CALDAV_VALID_FILTER,
    CALDAV_SUPP_COLLATION,
    CALDAV_MAX_SIZE,

    /* RSCALE (RFC 7529) preconditions */
    CALDAV_SUPP_RSCALE,

    /* Time Zones by Reference (RFC 7809) preconditions */
    CALDAV_VALID_TIMEZONE,

    /* Managed Attachments (RFC8607) preconditions */
    CALDAV_VALID_MANAGEDID,

    /* Bulk Change (draft-daboo-calendarserver-bulk-change) preconditions */
    CALDAV_CTAG_OK,

    /* CalDAV Scheduling (RFC 6638) preconditions */
    CALDAV_VALID_SCHED,
    CALDAV_VALID_ORGANIZER,
    CALDAV_UNIQUE_OBJECT,
    CALDAV_SAME_ORGANIZER,
    CALDAV_ALLOWED_ORG_CHANGE,
    CALDAV_ALLOWED_ATT_CHANGE,
    CALDAV_DEFAULT_NEEDED,
    CALDAV_VALID_DEFAULT,

    /* iSchedule (draft-desruisseaux-ischedule) preconditions */
    ISCHED_UNSUPP_VERSION,
    ISCHED_UNSUPP_DATA,
    ISCHED_INVALID_DATA,
    ISCHED_INVALID_SCHED,
    ISCHED_ORIG_MISSING,
    ISCHED_MULTIPLE_ORIG,
    ISCHED_ORIG_INVALID,
    ISCHED_ORIG_DENIED,
    ISCHED_RECIP_MISSING,
    ISCHED_RECIP_MISMATCH,
    ISCHED_VERIFICATION_FAILED,

    /* CardDAV (RFC 6352) preconditions */
    CARDDAV_SUPP_DATA,
    CARDDAV_VALID_DATA,
    CARDDAV_UID_CONFLICT,
    CARDDAV_LOCATION_OK,
    CARDDAV_SUPP_FILTER,
    CARDDAV_SUPP_COLLATION,
    CARDDAV_MAX_SIZE,
};

int dav_get_validators(struct mailbox *mailbox, void *data,
                       const char *userid, struct index_record *record,
                       const char **etag, time_t *lastmod);

int dav_store_resource(struct transaction_t *txn,
                       const char *data, size_t datalen,
                       struct mailbox *mailbox, struct index_record *oldrecord,
                       modseq_t createdmodseq,
                       const strarray_t *add_imapflags,
                       const strarray_t *del_imapflags);

#endif /* DAV_UTIL_H */
