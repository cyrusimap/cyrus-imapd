/* jmap_push.c -- Routines for handling JMAP Push API requests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <limits.h>
#include <syslog.h>
#include <time.h>

#include "jmap_push.h"


int jmap_push_poll = 0;


static const struct datatype_t {
    const char *name;
    size_t offset;
} dataTypes[] = {
    { "Mailbox",         offsetof(struct mboxname_counters, mailfoldersmodseq)   },
    { "Email",           offsetof(struct mboxname_counters, mailmodseq)          },
    { "EmailSubmission", offsetof(struct mboxname_counters, submissionmodseq)    },
    { "Calendar",        offsetof(struct mboxname_counters, caldavfoldersmodseq) },
    { "CalendarEvent",   offsetof(struct mboxname_counters, caldavmodseq)        },
    { "AddressBook",     offsetof(struct mboxname_counters, carddavfoldersmodseq)},
    { "ContactCard",     offsetof(struct mboxname_counters, carddavmodseq)       },
    { "SieveScript",     offsetof(struct mboxname_counters, sievemodseq)         },
    /* legacy/non-standard types */
    { "Contact",         offsetof(struct mboxname_counters, carddavmodseq)       },
    { "Note",            offsetof(struct mboxname_counters, notesmodseq)         },
    { NULL,              0 }
};

EXPORTED jmap_push_ctx_t *jmap_push_init(struct transaction_t *txn,
                                         const char *accountid,
                                         strarray_t *types, modseq_t lastmodseq,
                                         prot_waiteventcallback_t *ev)
{
    jmap_push_ctx_t *jpush = (jmap_push_ctx_t *) txn->push_ctx;
    struct mboxname_counters cur_counters;
    const struct datatype_t *dtype;

    if (!jpush) {
        jpush = xzmalloc(sizeof(jmap_push_ctx_t));

        jpush->accountid = xstrdup(accountid);
        jpush->inboxname = mboxname_user_mbox(jpush->accountid, NULL);
    }

    if (lastmodseq == ULLONG_MAX) {
        if (mboxname_read_counters(jpush->inboxname, &cur_counters)) {
            /* Something went wrong */
            jmap_push_done(txn);
            return NULL;
        }
    }

    /* Initialize our tracking modseqs to the maximum value */
    for (dtype = dataTypes; dtype->name; dtype++) {
        modseq_t *modseq =
            (modseq_t *)((size_t) &jpush->counters + dtype->offset);
        *modseq = ULLONG_MAX;
    }

    /* Set the start modseq for the specified types */
    int i;
    for (i = 0; i < strarray_size(types); i++) {
        const char *type = strarray_nth(types, i);

        for (dtype = dataTypes; dtype->name; dtype++) {
            if (!strcmpsafe(type, dtype->name) || !strcmpsafe(type, "*")) {
                modseq_t *modseq =
                    (modseq_t *)((size_t) &jpush->counters + dtype->offset);

                if (lastmodseq == ULLONG_MAX) {
                    modseq_t *cur_modseq =
                        (modseq_t *)((size_t) &cur_counters + dtype->offset);
                    *modseq = *cur_modseq;
                }
                else {
                    *modseq = lastmodseq;
                }

                if (*type != '*') break;
            }
        }
    }

    if (!jpush->wait) {
        /* Schedule our first update */
        jpush->wait = prot_addwaitevent(txn->conn->pin,
                                        time(NULL) + jmap_push_poll, ev, txn);
    }

    txn->push_ctx = jpush;
    ptrarray_add(&txn->done_callbacks, &jmap_push_done);

    return jpush;
}

EXPORTED void jmap_push_done(struct transaction_t *txn)
{
    jmap_push_ctx_t *jpush = (jmap_push_ctx_t *) txn->push_ctx;

    if (!jpush) return;

    if (jpush->wait) prot_removewaitevent(txn->conn->pin, jpush->wait);
    free(jpush->accountid);
    free(jpush->inboxname);
    buf_free(&jpush->buf);
    free(jpush);

    txn->push_ctx = NULL;
}

EXPORTED json_t *jmap_push_get_state(jmap_push_ctx_t *jpush)
{
    struct mboxname_counters cur_counters;
    struct buf *buf = &jpush->buf;
    json_t *jstate = NULL;

    if (mboxname_read_counters(jpush->inboxname, &cur_counters)) {
        /* Something went wrong - don't reschedule */
        xsyslog(LOG_NOTICE, "Failed to read counters",
                "accountid=<%s>", jpush->accountid);
        return NULL;
    }

    /* See if anything has changed */
    json_t *changed = json_object();
    const struct datatype_t *dtype;
    for (dtype = dataTypes; dtype->name; dtype++) {
        modseq_t *modseq =
            (modseq_t *)((size_t) &jpush->counters + dtype->offset);
        modseq_t *cur_modseq =
            (modseq_t *)((size_t) &cur_counters + dtype->offset);

        if (*modseq < *cur_modseq) {
            *modseq = *cur_modseq;

            buf_reset(buf);
            buf_printf(buf, MODSEQ_FMT, *modseq);
            json_object_set_new(changed, dtype->name, json_string(buf_cstring(buf)));
        }
    }

    jpush->counters.highestmodseq = cur_counters.highestmodseq;

    if (json_object_size(changed)) {
        jstate = json_pack("{ s:s s:{ s:o } }",
                                   "@type", "StateChange",
                                   "changed", jpush->accountid, changed);
    }
    else {
        json_decref(changed);
    }

    return jstate;
}
