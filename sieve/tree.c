/* tree.c -- abstract syntax tree handling
 * Larry Greenfield
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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
#include "script.h"
#include "sieve/sieve_interface.h"
#include "sieve/sieve.h"

extern void sieveerror_c(sieve_script_t *parse_script, int code, ...);

static void init_comptags(comp_t *c)
{
    c->match = c->relation = c->collation = -1;
}

comp_t *canon_comptags(comp_t *c)
{
    if (c->match == -1) c->match = IS;
    if (c->collation == -1) c->collation = ASCIICASEMAP;
    return c;
}

test_t *new_test(int type, sieve_script_t *parse_script)
{
    test_t *p = (test_t *) xzmalloc(sizeof(test_t));
    const char *capability = "";
    int supported = 1;

    p->type = type;

    switch (p->type) {
    case HEADER:
        init_comptags(&p->u.hhs.comp);
        break;

    case HASFLAG:
        capability = "imap4flags";
        supported = parse_script->support.imap4flags;

        init_comptags(&p->u.hhs.comp);
        break;

    case STRINGT:
        capability = "variables";
        supported = parse_script->support.variables;

        init_comptags(&p->u.hhs.comp);
        break;

    case ENVELOPE:
        capability = "envelope";
        supported = parse_script->support.envelope;

    case ADDRESS:
        init_comptags(&p->u.ae.comp);
        p->u.ae.addrpart = -1;
        break;

    case BODY:
        capability = "body";
        supported = parse_script->support.body;

        init_comptags(&p->u.b.comp);
        p->u.b.transform = p->u.b.offset = -1;
        break;

    case DATE:
    case CURRENTDATE:
        capability = "date";
        supported = parse_script->support.date;

        init_comptags(&p->u.dt.comp);
        p->u.dt.zonetag = -1;
        break;

    case MAILBOXEXISTS:
        capability = "mailbox";
        supported = parse_script->support.mailbox;
        break;

    case METADATA:
        init_comptags(&p->u.mm.comp);

    case METADATAEXISTS:
        capability = "mboxmetadata";
        supported = parse_script->support.mboxmetadata;
        break;

    case SERVERMETADATA:
        init_comptags(&p->u.mm.comp);

    case SERVERMETADATAEXISTS:
        capability = "servermetadata";
        supported = parse_script->support.servermetadata;
        break;

    case VALIDEXTLIST:
        capability = "extlists";
        supported = parse_script->support.extlists;
        break;
    }

    if (!supported) {
        sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, capability);
        free_test(p);
        return NULL;
    }

    return p;
}

testlist_t *new_testlist(test_t *t, testlist_t *n)
{
    testlist_t *p = (testlist_t *) xmalloc(sizeof(testlist_t));
    p->t = t;
    p->next = n;
    return p;
}

commandlist_t *new_command(int type, sieve_script_t *parse_script)
{
    commandlist_t *p = (commandlist_t *) xzmalloc(sizeof(commandlist_t));
    const char *capability = "";
    int supported = 1;

    p->type = type;
    p->next = NULL;

    switch (type) {
    case FILEINTO:
        capability = "fileinto";
        supported = parse_script->support.fileinto;
        break;

    case REJCT:
        capability = "reject";
        supported = parse_script->support.reject;
        break;

    case EREJECT:
        capability = "ereject";
        supported = parse_script->support.ereject;
        break;

    case VACATION:
        capability = "vacation";
        supported = parse_script->support.vacation;

        p->u.v.seconds = p->u.v.mime = -1;
        break;

    case SETFLAG:
    case ADDFLAG:
    case REMOVEFLAG:
        capability = "imap[4]flags";
        supported =
            parse_script->support.imapflags || parse_script->support.imap4flags;
        break;

    case MARK:
    case UNMARK:
        capability = "imapflags";
        supported = parse_script->support.imapflags;
        break;

    case DENOTIFY:
        init_comptags(&p->u.d.comp);
        p->u.d.comp.collation = ASCIICASEMAP;

    case NOTIFY:
        capability = "notify";
        supported = parse_script->support.notify;

        p->u.n.priority = -1;
        break;

    case INCLUDE:
        p->u.inc.once = p->u.inc.location = p->u.inc.optional = -1;

    case RETURN:
        capability = "include";
        supported = parse_script->support.include;
        break;

    case SET:
        capability = "variables";
        supported = parse_script->support.variables;
        break;

    case DELETEHEADER:
        init_comptags(&p->u.dh.comp);

    case ADDHEADER:
        capability = "editheader";
        supported = parse_script->support.editheader;
        break;
    }

    if (!supported) {
        sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, capability);
        free_tree(p);
        return NULL;
    }

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
    case STRINGT:
        strarray_free(t->u.hhs.sl);
        strarray_free(t->u.hhs.pl);
        break;

    case ADDRESS:
    case ENVELOPE:
        strarray_free(t->u.ae.sl);
        strarray_free(t->u.ae.pl);
        break;

    case BODY:
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
        strarray_free(t->u.dt.kl);
        break;

    case MAILBOXEXISTS:
    case METADATA:
    case METADATAEXISTS:
    case SERVERMETADATA:
    case SERVERMETADATAEXISTS:
        free(t->u.mm.extname);
        free(t->u.mm.keyname);
        strarray_free(t->u.mm.keylist);
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
            free(cl->u.v.from);
            free(cl->u.v.handle);
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
                if (cl->u.d.comp.match == REGEX) {
                    regfree((regex_t *) cl->u.d.pattern);
                }
#endif
                free(cl->u.d.pattern);
            }
            break;

        case DELETEHEADER:
            strarray_free(cl->u.dh.values);
            break;
        }

        free(cl);
        cl = cl2;
    }
}
