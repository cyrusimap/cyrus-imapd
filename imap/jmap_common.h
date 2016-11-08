/* jmap_common.h -- Helper routines for JMAP message processors
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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

#ifndef JMAP_COMMON_H
#define JMAP_COMMON_H

#include <jansson.h>

#include "auth.h"
#include "httpd.h"
#include "mailbox.h"
#include "mboxname.h"

#include "http_jmap.h"

/* Manage the state of mailboxes of type mbtype for req's userid */
extern json_t* jmap_getstate(int mbtype, struct jmap_req *req);
extern int jmap_bumpstate(int mbtype, struct jmap_req *req);
extern int jmap_checkstate(json_t *state, int mbtype, struct jmap_req *req);

enum jmap_filter_kind {
    JMAP_FILTER_KIND_COND = 0,
    JMAP_FILTER_KIND_OPER
};

enum jmap_filter_op   {
    JMAP_FILTER_OP_NONE = 0,
    JMAP_FILTER_OP_AND,
    JMAP_FILTER_OP_OR,
    JMAP_FILTER_OP_NOT
};

typedef struct jmap_filter {
    enum jmap_filter_kind kind;
    enum jmap_filter_op op;
    struct jmap_filter **conditions;
    size_t n_conditions;
    void *cond;
} jmap_filter;

/* Callbacks for JMAP type conditions */
typedef void* jmap_filterparse_cb(json_t* arg, const char* prefix, json_t*invalid);
typedef int   jmap_filtermatch_cb(void* cond, void* rock);
typedef void  jmap_filterfree_cb(void* cond);

/* Parse JMAP filter arg. Use cb to parse filter conditions and report
 * invalid argument names as prefix JSON strings in array invalid. */
extern jmap_filter *jmap_filter_parse(json_t *arg, const char *prefix,
                                      json_t *invalid,
                                      jmap_filterparse_cb *cb);
extern int jmap_filter_match(jmap_filter *f, jmap_filtermatch_cb *match, void *rock);
extern void jmap_filter_free(jmap_filter *f, jmap_filterfree_cb *freecond);

/* Helpers for DAV-based JMAP types */
extern char *jmap_xhref(const char *mboxname, const char *resource);

#endif /* JMAP_COMMON_H */
