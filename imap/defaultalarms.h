/* defaultalarms.h -- functions for dealing with default calendar alarms */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
