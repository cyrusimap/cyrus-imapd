/* defaultalarms.h -- functions for dealing with default calendar alarms
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

#ifndef DEFAULTALARMS_H
#define DEFAULTALARMS_H

#include <libical/ical.h>

#include "dav_util.h"
#include "mailbox.h"

#define DEFAULTALARMS_INITIALIZER { \
    {NULL, MESSAGE_GUID_INITIALIZER, NULL}, \
    {NULL, MESSAGE_GUID_INITIALIZER, NULL}  \
}

struct defaultalarms_record {
    icalcomponent *ical;
    struct message_guid guid;
    char *atag; // a ETag-like tag to detect CalDAV client changes
};

struct defaultalarms {
    struct defaultalarms_record with_time;
    struct defaultalarms_record with_date;
};

extern int defaultalarms_load(const char *mboxname, const char *userid,
                              struct defaultalarms *alarms);

extern int defaultalarms_save(struct mailbox *mbox, const char *userid,
                              icalcomponent *with_time,
                              icalcomponent *with_date);

extern void defaultalarms_fini(struct defaultalarms *defalarms);

extern void defaultalarms_insert(struct defaultalarms *defalarms,
                                 icalcomponent *ical,
                                 int set_atag);

extern int defaultalarms_matches_atag(icalcomponent *comp, const char *atag);

// Migration functions for Cyrus version 3.9

enum defaultalarms_migrate39_flags {
    DEFAULTALARMS_MIGRATE_NOFLAG             = 0,
    DEFAULTALARMS_MIGRATE_KEEP_CALDAV_ALARMS = 1 << 0,
};

extern void defaultalarms_migrate39(const mbentry_t *mbentry,
                                    enum defaultalarms_migrate39_flags flags,
                                    json_t **errp);

#endif /* DEFAULTALARMS_H */
