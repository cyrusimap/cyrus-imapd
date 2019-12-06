/* caldav_util.h -- utility functions for dealing with CALDAV database
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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

#ifndef CALDAV_UTIL_H
#define CALDAV_UTIL_H

#include <libical/ical.h>

#include "caldav_db.h"
#include "hash.h"
#include "httpd.h"
#include "mailbox.h"
#include "strarray.h"


#define NEW_STAG (1<<8)         /* Make sure we skip over PREFER bits */
#define TZ_STRIP (1<<9)

#define SHARED_MODSEQ \
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">shared-modseq"


extern void replace_tzid_aliases(icalcomponent *ical,
                                 struct hash_table *tzid_table);

extern void strip_vtimezones(icalcomponent *ical);

extern void add_personal_data(icalcomponent *ical, struct buf *userdata);

extern int caldav_is_personalized(struct mailbox *mailbox,
                                  const struct caldav_data *cdata,
                                  const char *userid,
                                  struct buf *userdata);

extern icalcomponent *caldav_record_to_ical(struct mailbox *mailbox,
                                            const struct caldav_data *cdata,
                                            const char *userid,
                                            strarray_t *schedule_addresses);

extern int caldav_get_validators(struct mailbox *mailbox, void *data,
                                 const char *userid, struct index_record *record,
                                 const char **etag, time_t *lastmod);

extern int caldav_store_resource(struct transaction_t *txn, icalcomponent *ical,
                                 struct mailbox *mailbox, const char *resource,
                                 modseq_t createdmodseq, struct caldav_db *caldavdb,
                                 unsigned flags, const char *userid,
                                 const strarray_t *add_imapflags,
                                 const strarray_t *del_imapflags,
                                 const strarray_t *schedule_addresses);

/* Create the calendar home, default calendars and scheduling
 * boxes for userid, if they don't already exist. */
extern unsigned long config_types_to_caldav_types(void);
extern int caldav_create_defaultcalendars(const char *userid,
                                          const struct namespace *namespace,
                                          const struct auth_state *authstate,
                                          mbentry_t **mbentryp);

#endif /* CALDAV_UTIL_H */
