/* mboxevent.h -- interface for message store event notifications
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
 * Author: Sébastien Michel from Atos Worldline
 */

#ifndef _MBOXEVENT_H
#define _MBOXEVENT_H

#include <jansson.h>

#include "strarray.h"

#include "mailbox.h"
#include "mboxname.h"

/* Forward declaration to avoid circular dependency */
typedef struct msgrecord msgrecord_t;

/*
 * event types defined in RFC 5423 - Internet Message Store Events
 */
enum event_type {
    EVENT_CANCELLED           = (0),
    /* Message Addition and Deletion */
    EVENT_MESSAGE_APPEND      = (1<<0),
    EVENT_MESSAGE_EXPIRE      = (1<<1),
    EVENT_MESSAGE_EXPUNGE     = (1<<2),
    EVENT_MESSAGE_NEW         = (1<<3),
    EVENT_MESSAGE_COPY        = (1<<4), /* additional event type to notify IMAP COPY */
    EVENT_MESSAGE_MOVE        = (1<<5), /* additional event type to notify IMAP MOVE */
    EVENT_QUOTA_EXCEED        = (1<<6),
    EVENT_QUOTA_WITHIN        = (1<<7),
    EVENT_QUOTA_CHANGE        = (1<<8),
    /* Message Flags */
    EVENT_MESSAGE_READ        = (1<<9),
    EVENT_MESSAGE_TRASH       = (1<<10),
    EVENT_FLAGS_SET           = (1<<11),
    EVENT_FLAGS_CLEAR         = (1<<12),
    /* Access Accounting */
    EVENT_LOGIN               = (1<<13),
    EVENT_LOGOUT              = (1<<14),
    /* Mailbox Management */
    EVENT_MAILBOX_CREATE      = (1<<15),
    EVENT_MAILBOX_DELETE      = (1<<16),
    EVENT_MAILBOX_RENAME      = (1<<17),
    EVENT_MAILBOX_SUBSCRIBE   = (1<<18),
    EVENT_MAILBOX_UNSUBSCRIBE = (1<<19),
    EVENT_ACL_CHANGE          = (1<<20),
    EVENT_CALENDAR            = (1<<21),
    EVENT_CALENDAR_ALARM      = (1<<22),
    /* Other */
    EVENT_APPLEPUSHSERVICE     = (1<<23),
    EVENT_APPLEPUSHSERVICE_DAV = (1<<24),
    EVENT_MAILBOX_MODSEQ       = (1<<25),
    EVENT_MESSAGES_UNSCHEDULED = (1<<26),
};

/*
 * event parameters defined in RFC 5423 - Internet Message Store Events
 *
 * ordered to optimize the parsing of the notification message
 *
 * NOTE that the order here needs to be the exact same as the order in
 * mboxevent.c's event_template mboxevent struct
 */
enum event_param {
    /*  0 */ EVENT_TIMESTAMP,
    /*  1 */ EVENT_SERVICE,
    /*  2 */ EVENT_SERVER_ADDRESS, /* gather serverDomain and serverPort together */
    /*  3 */ EVENT_CLIENT_ADDRESS, /* gather clientIP and clientPort together */
    /*  4 */ EVENT_OLD_MAILBOX_ID,
    /*  5 */ EVENT_OLD_UIDSET,
    /*  6 */ EVENT_MAILBOX_ID,
    /*  7 */ EVENT_URI,
    /*  8 */ EVENT_MODSEQ,
    /*  9 */ EVENT_QUOTA_STORAGE,
    /* 10 */ EVENT_DISK_USED,
    /* 11 */ EVENT_QUOTA_MESSAGES,
    /* 12 */ EVENT_MESSAGES,
    /* 13 */ EVENT_UNSEEN_MESSAGES,
    /* 14 */ EVENT_UIDNEXT,
    /* 15 */ EVENT_UIDSET,
    /* 16 */ EVENT_MIDSET,
    /* 17 */ EVENT_FLAG_NAMES,
    /* 18 */ EVENT_PID,
    /* 19 */ EVENT_ACL_SUBJECT,
    /* 20 */ EVENT_ACL_RIGHTS,
    /* 21 */ EVENT_USER,
    /* 22 */ EVENT_MESSAGE_SIZE,
    /* 23 */ EVENT_MBTYPE,
    EVENT_SERVERFQDN,
    EVENT_MAILBOX_ACL,
    /* 24 */ EVENT_DAV_FILENAME,
    /* 25 */ EVENT_DAV_UID,
    /* 26 */ EVENT_ENVELOPE,
    /* 27 */ EVENT_SESSIONID,
    /* 28 */ EVENT_BODYSTRUCTURE,
    /* 29 */ EVENT_CLIENT_ID,
    /* 30 */ EVENT_SESSION_ID,
    EVENT_CONVEXISTS,
    EVENT_CONVUNSEEN,
    EVENT_MESSAGE_CID,
    EVENT_COUNTERS,
    EVENT_MESSAGE_EMAILID,
    EVENT_MESSAGE_THREADID,
    EVENT_JMAP_EMAIL,
    EVENT_JMAP_STATES,
    EVENT_CALENDAR_ALARM_TIME,
    EVENT_CALENDAR_ALARM_RECIPIENTS,
    EVENT_CALENDAR_ALERTID,
    EVENT_CALENDAR_USER_ID,
    EVENT_CALENDAR_CALENDAR_ID,
    EVENT_CALENDAR_CALENDAR_NAME,
    EVENT_CALENDAR_CALENDAR_COLOR,
    EVENT_CALENDAR_UID,
    EVENT_CALENDAR_RECURID,
    EVENT_CALENDAR_EVENTID,
    EVENT_CALENDAR_ACTION,
    EVENT_CALENDAR_SUMMARY,
    EVENT_CALENDAR_DESCRIPTION,
    EVENT_CALENDAR_LOCATION,
    EVENT_CALENDAR_TIMEZONE,
    EVENT_CALENDAR_START,
    EVENT_CALENDAR_END,
    EVENT_CALENDAR_ALLDAY,
    EVENT_CALENDAR_ATTENDEE_NAMES,
    EVENT_CALENDAR_ATTENDEE_EMAILS,
    EVENT_CALENDAR_ATTENDEE_STATUS,
    EVENT_CALENDAR_ORGANIZER,
    EVENT_APPLEPUSHSERVICE_VERSION,
    EVENT_APPLEPUSHSERVICE_ACCOUNT_ID,
    EVENT_APPLEPUSHSERVICE_DEVICE_TOKEN,
    EVENT_APPLEPUSHSERVICE_SUBTOPIC,
    EVENT_APPLEPUSHSERVICE_MAILBOXES,
    EVENT_APPLEPUSHSERVICE_DAV_TOPIC,
    EVENT_APPLEPUSHSERVICE_DAV_DEVICE_TOKEN,
    EVENT_APPLEPUSHSERVICE_DAV_MAILBOX_USER,
    EVENT_APPLEPUSHSERVICE_DAV_MAILBOX_UNIQUEID,
    EVENT_APPLEPUSHSERVICE_DAV_EXPIRY,
    EVENT_MESSAGES_UNSCHEDULED_USERID,
    EVENT_MESSAGES_UNSCHEDULED_COUNT,
    /* 31 */ EVENT_MESSAGE_CONTENT
};

/* messageContent number that is always the last */
#define MAX_PARAM EVENT_MESSAGE_CONTENT

enum event_param_type {
    EVENT_PARAM_INT,
    EVENT_PARAM_STRING,
    EVENT_PARAM_ARRAY,
    EVENT_PARAM_JSON
};

struct event_parameter {
    enum event_param id;
    const char *name;
    enum event_param_type type;
    union {
        char *s;
        uint64_t u;
        strarray_t *a;
        json_t *j;
    } value;
    int filled;
};

struct mboxevent {
    enum event_type type;       /* event type */

    /* array of event parameters */
    struct event_parameter params[MAX_PARAM+1];

    strarray_t flagnames;
    struct timeval timestamp;
    seqset_t *uidset;
    strarray_t midset;
    seqset_t *olduidset;

    struct mboxevent *prev;
    struct mboxevent *next;
};


#define FILL_STRING_PARAM(e,p,v) do { \
    e->params[p].value.s = v; \
    e->params[p].type = EVENT_PARAM_STRING; \
    e->params[p].filled = 1; \
} while(0)
#define FILL_ARRAY_PARAM(e,p,v) do { \
    e->params[p].value.a = v; \
    e->params[p].type = EVENT_PARAM_ARRAY; \
    e->params[p].filled = 1; \
} while (0)
#define FILL_UNSIGNED_PARAM(e,p,v) do { \
    e->params[p].value.u = v; \
    e->params[p].type = EVENT_PARAM_INT; \
    e->params[p].filled = 1; \
} while (0)
#define FILL_JSON_PARAM(e,p,v) do { \
    e->params[p].value.j = v; \
    e->params[p].type = EVENT_PARAM_JSON; \
    e->params[p].filled = 1; \
} while (0)

/*
 * Call this initializer once only at start
 */
int mboxevent_init();

/*
 * Set the namespace to translate internal mailbox name to external name
 */
void mboxevent_setnamespace(struct namespace *n);

/*
 * Create a new mboxevent structure for the given event type.
 * Allocate resources for configured extra parameters.
 *
 * return the initialized event state or NULL if notification is disabled
 */
struct mboxevent *mboxevent_new(enum event_type type);

/*
 * Create a new mboxevent structure for the given event type.
 * Append this new structure at end of the given mboxevent list.
 * Allocate resources for configured extra parameters.
 *
 * return the initialized event state or NULL if notification is disabled
 */
struct mboxevent *mboxevent_enqueue(enum event_type type,
                                    struct mboxevent **events);

/*
 * Send the queue of event notifications
 */
void mboxevent_notify(struct mboxevent **mboxevents);

/*
 * Release any allocated resources of this given event
 */
void mboxevent_free(struct mboxevent **event);

/*
 * Release any allocated resources of this given list of events
 */
void mboxevent_freequeue(struct mboxevent **event);

/*
 * Add this set of system flags and user flags to flagNames parameter.
 * Exclude flags present in event_exclude_flags setting.
 */
void mboxevent_add_flags(struct mboxevent *event, char *flagnames[MAX_USER_FLAGS],
                         bit32 system_flags, bit32 user_flags[MAX_USER_FLAGS/32]);

/*
 * Add the given flag to flagNames parameter.
 * event_exclude_flags doesn't apply here
 */
void mboxevent_add_flag(struct mboxevent *event, const char *flag);

/*
 * Extract data related to message store access accounting
 */
void mboxevent_set_access(struct mboxevent *event,
                          const char *serveraddr, const char *clientaddr,
                          const char *userid, const char *mailboxname, const int ext_name);

/*
 * Shortcut to setting event notification parameters
 */
void mboxevent_set_acl(struct mboxevent *event, const char *identifier,
                           const char *rights);

/*
 * Extract data from the given record to fill these event parameters :
 * - uidset from UID
 * - vnd.cmu.midset from Message-Id in ENVELOPE structure
 * - messageSize
 * - bodyStructure
 * - vnd.cmu.jmapEmail
 *
 * Called once per message and always before mboxevent_extract_mailbox
 */
void mboxevent_extract_record(struct mboxevent *event,
                              struct mailbox *mailbox,
                              struct index_record *record);

/*
 * Extract data from the given message record to fill these event parameters :
 * - uidset from UID
 * - vnd.cmu.midset from Message-Id in ENVELOPE structure
 * - messageSize
 * - bodyStructure
 * - vnd.cmu.jmapEmail
 *
 * Called once per message and always before mboxevent_extract_mailbox
 */
void mboxevent_extract_msgrecord(struct mboxevent *event, msgrecord_t *msgrec);


/*
 * Fill event parameter about the copied message.
 * Called once per message and always before mboxevent_extract_mailbox
 */
void mboxevent_extract_copied_record(struct mboxevent *event,
                                     const struct mailbox *mailbox, struct index_record *record);

extern void mboxevent_extract_copied_msgrecord(struct mboxevent *event, msgrecord_t *msgrec);

/*
 * Extract message content to include to event notification
 */
void mboxevent_extract_content(struct mboxevent *event,
                               const struct index_record *record, FILE* content);

/*
 * Extract message content to include to event notification
 */
void mboxevent_extract_content_msgrec(struct mboxevent *event,
                               msgrecord_t *msgrec, FILE* content);

/*
 * Extract quota limit, quota usage and quota root to include to event
 * notification
 */
void mboxevent_extract_quota(struct mboxevent *event, const struct quota *quota,
                             enum quota_resource res);

/*
 * Set the given number of unseen message if positive or scan the entire mailbox
 * to count it.
 */
void mboxevent_set_numunseen(struct mboxevent *event, struct mailbox *mailbox,
                             int numunseen);
/*
 * Extract meta-data from the given mailbox to fill mailboxID event parameter and
 * optionally these ones depending the type of the event:
 * - messages
 * - uidnext
 * - vnd.cmu.unseenMessages
 *
 * Must be called once per event or the notification will failed (Except for
 * Login and Logout events)
 * Mailbox must be locked to count the number of \Seen flags
 *
 * It is necessary to call this function after all changes on mailbox to get the
 * right values of messages, uidnext and vnd.cmu.unseenMessages event parameters
 */
void mboxevent_extract_mailbox(struct mboxevent *event, struct mailbox *mailbox);

/*
 * Extract meta-data from the given mailbox to fill oldMailboxID event parameter
 */
void mboxevent_extract_old_mailbox(struct mboxevent *event,
                                   const struct mailbox *mailbox);

/*
 * set the client tag used by vnd.fastmail.clientTagj
 */
void mboxevent_set_client_id(const char *);

/* Arguments to XAPPLEPUSHSERVICE */
struct applepushserviceargs {
    unsigned int aps_version;
    struct buf   aps_account_id;
    struct buf   aps_device_token;
    struct buf   aps_subtopic;
    strarray_t   mailboxes;
};

/*
 * send event with APS channel data in it for the push service to sort out
 */
void mboxevent_set_applepushservice(struct mboxevent *event,
                                    struct applepushserviceargs *applepushserviceargs,
                                    strarray_t *mailboxes,
                                    const char *userid);

/*
 * APS subscription for DAV collection
 */
void mboxevent_set_applepushservice_dav(struct mboxevent *event,
                                        const char *aps_topic,
                                        const char *device_token,
                                        const char *userid,
                                        const char *mailbox_userid,
                                        const char *mailbox_uniqueid,
                                        int mbtype,
                                        unsigned int expiry);

#endif /* _MBOXEVENT_H */
