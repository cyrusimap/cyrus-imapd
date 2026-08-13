/* jmap_ical.c - Common code for JMAP for Calendars */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAPICAL_H
#define JMAPICAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <libical/ical.h>

#include "jmap_api.h"
#include "jmap_util.h"


struct jmapical_ctx {
    jmap_req_t *req;
    struct {
        struct buf url;
        struct webdav_db *db;
        struct mailbox *mbox;
        int lock;
        int err;
    } attachments;
    struct {
        json_t *serverset;
        json_t *replyto;
        char *emailalert_recipient;
    } to_ical;
    struct {
        struct {
            const char *mboxid;
            uint32_t uid;
            const char *partid;
        } cyrus_msg;
        unsigned want_icalprops : 1;
    } from_ical;
    const strarray_t *schedule_addresses;
    bool (*jsevent_is_origin_cb)(json_t *jsevent, const strarray_t *schedule_addresses);
};

extern struct jmapical_ctx *jmapical_context_new(jmap_req_t *req,
        const strarray_t *schedule_addresses);

extern void jmapical_context_free(struct jmapical_ctx**);

extern int jmapical_context_open_attachments(struct jmapical_ctx *jmapctx);


extern void jmapical_remove_peruserprops(json_t *jevent);


#ifdef __cplusplus
}
#endif

#endif 
