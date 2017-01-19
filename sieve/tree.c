/* tree.c -- abstract syntax tree handling
 * Larry Greenfield
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include "xmalloc.h"

#include "tree.h"
#include "sieve/sieve_interface.h"
#include "sieve/sieve.h"

tag_t *new_tag(int type, char *s)
{
    tag_t *p = (tag_t *) xzmalloc(sizeof(tag_t));
    p->type = type;
    p->arg = s;
    return p;
}

taglist_t *new_taglist(tag_t *t, taglist_t *n)
{
    taglist_t *p = (taglist_t *) xzmalloc(sizeof(taglist_t));
    p->t = t;
    p->next = n;
    return p;
}

test_t *new_test(int type)
{
    test_t *p = (test_t *) xzmalloc(sizeof(test_t));
    p->type = type;
    return p;
}

testlist_t *new_testlist(test_t *t, testlist_t *n)
{
    testlist_t *p = (testlist_t *) xmalloc(sizeof(testlist_t));
    p->t = t;
    p->next = n;
    return p;
}

commandlist_t *new_command(int type)
{
    commandlist_t *p = (commandlist_t *) xzmalloc(sizeof(commandlist_t));
    p->type = type;
    p->next = NULL;
    return p;
}

commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n)
{
    commandlist_t *p = (commandlist_t *) xzmalloc(sizeof(commandlist_t));
    p->type = IF;
    p->u.i.t = t;
    p->u.i.do_then = y;
    p->u.i.do_else = n;
    p->next = NULL;
    return p;
}

void free_test(test_t *t);

static void free_tl(testlist_t *tl)
{
    testlist_t *tl2;

    while (tl) {
        tl2 = tl->next;

        if (tl->t) free_test(tl->t);

        free(tl);
        tl = tl2;
    }
}

void free_test(test_t *t)
{
    if (t == NULL) return;

    switch (t->type) {
    case ANYOF:
    case ALLOF:
        free_tl(t->u.tl);
        break;

    case EXISTS:
        strarray_free(t->u.sl);
        break;

    case SIZE:
    case SFALSE:
    case STRUE:
        break;

    case HASFLAG:
    case HEADER:
        free(t->u.h.comparator);
        strarray_free(t->u.h.sl);
        strarray_free(t->u.h.pl);
        break;

    case ADDRESS:
    case ENVELOPE:
        free(t->u.ae.comparator);
        strarray_free(t->u.ae.sl);
        strarray_free(t->u.ae.pl);
        break;

    case BODY:
        free(t->u.b.comparator);
        strarray_free(t->u.b.content_types);
        strarray_free(t->u.b.pl);
        break;

    case NOT:
        free_test(t->u.t);
        break;

    case DATE:
        free(t->u.dt.header_name);
        /* fall-through */
    case CURRENTDATE:
        free(t->u.dt.comparator);
        free(t->u.dt.zone);
        strarray_free(t->u.dt.kl);
        break;

    case MAILBOXEXISTS:
    case METADATA:
    case METADATAEXISTS:
    case SERVERMETADATA:
    case SERVERMETADATAEXISTS:
        free(t->u.mbx.extname);
        free(t->u.mbx.keyname);
        strarray_free(t->u.mbx.keylist);
        free(t->u.mbx.comparator);
        break;
    }

    free(t);
}

void free_tree(commandlist_t *cl)
{
    commandlist_t *cl2;

    while (cl != NULL) {
        cl2 = cl->next;
        switch (cl->type) {
        case IF:
            free_test(cl->u.i.t);
            free_tree(cl->u.i.do_then);
            free_tree(cl->u.i.do_else);
            break;

        case INCLUDE:
            free(cl->u.inc.script);
            break;

        case SETFLAG:
        case ADDFLAG:
        case REMOVEFLAG:
            free(cl->u.fl.variable);
            strarray_free(cl->u.fl.flags);
            break;

        case FILEINTO:
            free(cl->u.f.folder);
            strarray_free(cl->u.f.flags);
            break;

        case REDIRECT:
            free(cl->u.r.address);
            break;

        case REJCT:
        case EREJECT:
            free(cl->u.reject);
            break;

        case VACATION:
            free(cl->u.v.subject);
            strarray_free(cl->u.v.addresses);
            free(cl->u.v.message);
            break;

        case KEEP:
            strarray_free(cl->u.k.flags);
            break;

        case STOP:
        case DISCARD:
        case RETURN:
            break;

        case NOTIFY:
            if (cl->u.n.method) free(cl->u.n.method);
            if (cl->u.n.id) free(cl->u.n.id);
            if (cl->u.n.options) strarray_free(cl->u.n.options);
            if (cl->u.n.message) free(cl->u.n.message);
            break;

        case DENOTIFY:
            if (cl->u.d.pattern) {
#ifdef ENABLE_REGEX
                if (cl->u.d.comptag == REGEX) {
                    regfree((regex_t *) cl->u.d.pattern);
                }
#endif
                free(cl->u.d.pattern);
            }
            break;
        }

        free(cl);
        cl = cl2;
    }
}
