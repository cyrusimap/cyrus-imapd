/* jmap_common.c -- Helper routines for JMAP message processors
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

#include <syslog.h>

#include "hash.h"
#include "httpd.h"
#include "http_dav.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "http_jmap.h"
#include "jmap_common.h"

/* FIXME DUPLICATE START */

static int readprop_full(json_t *root,
                         const char *prefix,
                         const char *name,
                         int mandatory,
                         json_t *invalid,
                         const char *fmt,
                         void *dst)
{
    int r = 0;
    json_t *jval = json_object_get(root, name);
    if (!jval && mandatory) {
        r = -1;
    } else if (jval) {
        json_error_t err;
        if (json_unpack_ex(jval, &err, 0, fmt, dst)) {
            r = -2;
        } else {
            r = 1;
        }
    }
    if (r < 0 && prefix) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s.%s", prefix, name);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_free(&buf);
    } else if (r < 0) {
        json_array_append_new(invalid, json_string(name));
    }
    return r;
}

#define readprop(root, name,  mandatory, invalid, fmt, dst) \
    readprop_full((root), NULL, (name), (mandatory), (invalid), (fmt), (dst))

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

/* FIXME DUPLICATE END */

EXPORTED int jmap_filter_match(jmap_filter *f, jmap_filtermatch_cb *match, void *rock)
{
    if (f->kind == JMAP_FILTER_KIND_OPER) {
        size_t i;
        for (i = 0; i < f->n_conditions; i++) {
            int m = jmap_filter_match(f->conditions[i], match, rock);
            if (m && f->op == JMAP_FILTER_OP_OR) {
                return 1;
            } else if (m && f->op == JMAP_FILTER_OP_NOT) {
                return 0;
            } else if (!m && f->op == JMAP_FILTER_OP_AND) {
                return 0;
            }
        }
        return f->op == JMAP_FILTER_OP_AND || f->op == JMAP_FILTER_OP_NOT;
    } else {
        return match(f->cond, rock);
    }
}

EXPORTED void jmap_filter_free(jmap_filter *f, jmap_filterfree_cb *freecond)
{
    size_t i;
    for (i = 0; i < f->n_conditions; i++) {
        jmap_filter_free(f->conditions[i], freecond);
    }
    if (f->conditions) free(f->conditions);
    if (f->cond && freecond) {
        freecond(f->cond);
    }
    free(f);
}

/* FIXME use property context instead of invalid/prefix */
EXPORTED jmap_filter *jmap_filter_parse(json_t *arg,
                                        const char *prefix,
                                        json_t *invalid,
                                        jmap_filterparse_cb *parse)
{
    jmap_filter *f = (jmap_filter *) xzmalloc(sizeof(struct jmap_filter));
    int pe;
    const char *val;
    struct buf buf = BUF_INITIALIZER;
    int iscond = 1;

    /* operator */
    pe = readprop_full(arg, prefix, "operator", 0 /*mandatory*/, invalid, "s", &val);
    if (pe > 0) {
        f->kind = JMAP_FILTER_KIND_OPER;
        if (!strncmp("AND", val, 3)) {
            f->op = JMAP_FILTER_OP_AND;
        } else if (!strncmp("OR", val, 2)) {
            f->op = JMAP_FILTER_OP_OR;
        } else if (!strncmp("NOT", val, 3)) {
            f->op = JMAP_FILTER_OP_NOT;
        } else {
            buf_printf(&buf, "%s.%s", prefix, "operator");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    iscond = f->kind == JMAP_FILTER_KIND_COND;

    /* conditions */
    json_t *conds = json_object_get(arg, "conditions");
    if (conds && !iscond && json_array_size(conds)) {
        f->n_conditions = json_array_size(conds);
        f->conditions = xmalloc(sizeof(struct jmap_filter) * f->n_conditions);
        size_t i;
        for (i = 0; i < f->n_conditions; i++) {
            json_t *cond = json_array_get(conds, i);
            buf_printf(&buf, "%s.conditions[%zu]", prefix, i);
            f->conditions[i] = jmap_filter_parse(cond, buf_cstring(&buf), invalid, parse);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(conds)) {
        buf_printf(&buf, "%s.%s", prefix, "conditions");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    if (iscond) {
        f->cond = parse(arg, prefix, invalid);
    }

    buf_free(&buf);
    return f;
}

EXPORTED int jmap_checkstate(json_t *state, int mbtype, struct jmap_req *req) {
    if (JNOTNULL(state)) {
        const char *s = json_string_value(state);
        if (!s) {
            return -1;
        }
        modseq_t clientState = atomodseq_t(s);
        switch (mbtype) {
         case MBTYPE_CALENDAR:
             return clientState != req->counters.caldavmodseq;
         case MBTYPE_ADDRESSBOOK:
             return clientState != req->counters.carddavmodseq;
         default:
             return clientState != req->counters.mailmodseq;
        }
    }
    return 0;
}

EXPORTED json_t* jmap_getstate(int mbtype, struct jmap_req *req) {
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    modseq_t modseq;

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        default:
            modseq = req->counters.highestmodseq;
    }

    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);

    return state;
}

EXPORTED int jmap_bumpstate(int mbtype, struct jmap_req *req) {
    int r = 0;
    modseq_t modseq;
    char *mboxname = mboxname_user_mbox(req->userid, NULL);

    /* Read counters. */
    r = mboxname_read_counters(mboxname, &req->counters);
    if (r) goto done;

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        default:
            modseq = req->counters.highestmodseq;
    }

    modseq = mboxname_nextmodseq(mboxname, modseq, mbtype, 1);
    r = mboxname_read_counters(mboxname, &req->counters);
    if (r) goto done;

done:
    free(mboxname);
    return r;
}

EXPORTED char *jmap_xhref(const char *mboxname, const char *resource)
{
    /* XXX - look up root path from namespace? */
    struct buf buf = BUF_INITIALIZER;
    char *userid = mboxname_to_userid(mboxname);

    const char *prefix = NULL;
    if (mboxname_isaddressbookmailbox(mboxname, 0)) {
        prefix = namespace_addressbook.prefix;
    }
    else if (mboxname_iscalendarmailbox(mboxname, 0)) {
        prefix = namespace_calendar.prefix;
    }

    if (strchr(userid, '@') || !httpd_extradomain) {
        buf_printf(&buf, "%s/%s/%s/%s", prefix, USER_COLLECTION_PREFIX,
                   userid, strrchr(mboxname, '.')+1);
    }
    else {
        buf_printf(&buf, "%s/%s/%s@%s/%s", prefix, USER_COLLECTION_PREFIX,
                   userid, httpd_extradomain, strrchr(mboxname, '.')+1);
    }
    if (resource)
        buf_printf(&buf, "/%s", resource);
    free(userid);
    return buf_release(&buf);
}

