/* jmap_push.c - Routines for handling JMAP Push API requests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <limits.h>
#include <syslog.h>
#include <time.h>

#include "jmap_api.h"
#include "jmap_push.h"


int jmap_push_poll = 0;


typedef struct {
    const jmap_data_type_t *data_type;
    modseq_t lastmodseq;
} jmap_type_state_t;

struct add_type_rock {
    ptrarray_t *type_states;
    struct mboxname_counters *cur_counters;
    modseq_t lastmodseq;
};

static void add_type_cb(const jmap_data_type_t *dtype, void *rock)
{
    if (dtype->modseq_offset >= 0) {
        jmap_type_state_t *state = xmalloc(sizeof(jmap_type_state_t));
        struct add_type_rock *arock = rock;

        state->data_type = dtype;

        if (arock->lastmodseq == ULLONG_MAX) {
            modseq_t *cur_modseq =
                (modseq_t *)((off_t) arock->cur_counters + dtype->modseq_offset);
            state->lastmodseq = *cur_modseq;
        }
        else {
            state->lastmodseq = arock->lastmodseq;
        }

        ptrarray_append(arock->type_states, state);
    }
}

EXPORTED jmap_push_ctx_t *jmap_push_init(struct transaction_t *txn,
                                         const char *accountid,
                                         strarray_t *types, modseq_t lastmodseq,
                                         prot_waiteventcallback_t *ev)
{
    jmap_push_ctx_t *jpush = (jmap_push_ctx_t *) txn->push_ctx;
    struct mboxname_counters cur_counters;

    if (!jpush) {
        struct conversations_state *cstate = NULL;

        /* Need cstate for state string generation */
        if (conversations_open_user(accountid, 1/*shared*/, &cstate)) {
            /* Something went wrong */
            jmap_push_done(txn);
            return NULL;
        }

        jpush = xzmalloc(sizeof(jmap_push_ctx_t));

        jpush->accountid = xstrdup(accountid);
        jpush->inboxname = mboxname_user_mbox(jpush->accountid, NULL);
        jpush->req.userid = jpush->req.accountid = jpush->accountid;
        jpush->req.cstate = cstate;
    }

    if (lastmodseq == ULLONG_MAX) {
        if (mboxname_read_counters(jpush->inboxname, &cur_counters)) {
            /* Something went wrong */
            jmap_push_done(txn);
            return NULL;
        }
    }

    /* Build an array of states (with start modseq) for the specified types */
    struct add_type_rock arock =
        { &jpush->type_states, &cur_counters, lastmodseq };
    if (strarray_find(types, "*", 0) >= 0) {
        jmap_data_types_foreach(&add_type_cb, &arock);
    }
    else {
        for (int i = 0; i < strarray_size(types); i++) {
            const char *type = strarray_nth(types, i);
            const jmap_data_type_t *dtype =
                jmap_data_types_lookup(type, strlen(type));

            if (dtype) add_type_cb(dtype, &arock);
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

    /* Free the array of type states */
    ptrarray_t *states = &jpush->type_states;
    for (int i = 0; i < ptrarray_size(states); i++) {
        free(ptrarray_nth(states, i));
    }
    ptrarray_fini(states);

    /* Close cstate */
    conversations_abort(&jpush->req.cstate);

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
    json_t *jstate = NULL;

    if (mboxname_read_counters(jpush->inboxname, &cur_counters)) {
        /* Something went wrong - don't reschedule */
        xsyslog(LOG_NOTICE, "Failed to read counters",
                "accountid=<%s>", jpush->accountid);
        return NULL;
    }

    /* See if anything has changed */
    json_t *changed = json_object();
    ptrarray_t *states = &jpush->type_states;
    for (int i = 0; i < ptrarray_size(states); i++) {
        jmap_type_state_t *tstate = ptrarray_nth(states, i);;
        modseq_t *cur_modseq =
            (modseq_t *)((off_t) &cur_counters + tstate->data_type->modseq_offset);

        if (tstate->lastmodseq < *cur_modseq) {
            tstate->lastmodseq = *cur_modseq;

            char *newstate = jmap_state_string(&jpush->req, *cur_modseq,
                                               tstate->data_type->mbtype, 0);
            json_object_set_new(changed, tstate->data_type->name,
                                json_string(newstate));
            free(newstate);
        }
    }

    jpush->highestmodseq = cur_counters.highestmodseq;

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
