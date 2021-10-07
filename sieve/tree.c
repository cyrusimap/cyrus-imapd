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
#include "sieve/bytecode.h"

extern void sieveerror_c(sieve_script_t *parse_script, int code, ...);

static void init_comptags(comp_t *c)
{
    c->match = c->relation = c->collation = -1;
}

comp_t *canon_comptags(comp_t *c, sieve_script_t *parse_script)
{
    if (c->match == -1) c->match = B_IS;
    if (c->collation == -1) c->collation = B_ASCIICASEMAP;

    /* i;ascii-numeric is only supported for IS, COUNT, and VALUE match-types */
    if (c->collation == B_ASCIINUMERIC) {
        const char *invalid_match = NULL;

        switch (c->match) {
        case B_CONTAINS: invalid_match = ":contains"; break;
        case B_MATCHES:  invalid_match = ":matches";  break;
        case B_REGEX:    invalid_match = ":regex";    break;
        }

        if (invalid_match) {
            sieveerror_c(parse_script, SIEVE_MATCH_INCOMPAT,
                         invalid_match, "i;ascii-numeric");
        }
    }
    else if (c->match == B_COUNT) {
        sieveerror_c(parse_script, SIEVE_MATCH_INCOMPAT, ":count",
                     c->collation == B_OCTET ? "i;octet" : "i;ascii-casemap");
    }

    return c;
}

test_t *new_test(int type, sieve_script_t *parse_script)
{
    test_t *p = (test_t *) xzmalloc(sizeof(test_t));
    const char *capability = "";
    unsigned long long supported = SIEVE_CAPA_BASE;

    p->type = type;

    switch (p->type) {
    case BC_HEADER:
        init_comptags(&p->u.hhs.comp);
        break;

    case BC_HASFLAG:
        capability = "imap4flags";
        supported = parse_script->support & SIEVE_CAPA_IMAP4FLAGS;

        init_comptags(&p->u.hhs.comp);
        break;

    case BC_STRING:
        capability = "variables";
        supported = parse_script->support & SIEVE_CAPA_VARIABLES;

        init_comptags(&p->u.hhs.comp);
        break;

    case BC_ENVELOPE:
        capability = "envelope";
        supported = parse_script->support & SIEVE_CAPA_ENVELOPE;
        GCC_FALLTHROUGH

    case BC_ADDRESS:
        init_comptags(&p->u.ae.comp);
        p->u.ae.addrpart = -1;
        break;

    case BC_ENVIRONMENT:
        capability = "environment";
        supported = parse_script->support & SIEVE_CAPA_ENVIRONMENT;

        init_comptags(&p->u.mm.comp);
        break;

    case BC_BODY:
        capability = "body";
        supported = parse_script->support & SIEVE_CAPA_BODY;

        init_comptags(&p->u.b.comp);
        p->u.b.transform = p->u.b.offset = -1;
        break;

    case BC_DATE:
    case BC_CURRENTDATE:
        capability = "date";
        supported = parse_script->support & SIEVE_CAPA_DATE;

        init_comptags(&p->u.dt.comp);
        p->u.dt.zone.tag = -1;
        break;

    case BC_NOTIFYMETHODCAPABILITY:
        init_comptags(&p->u.mm.comp);
        GCC_FALLTHROUGH

    case BC_VALIDNOTIFYMETHOD:
        capability = "enotify";
        supported = parse_script->support & SIEVE_CAPA_ENOTIFY;
        break;

    case BC_IHAVE:
        capability = "ihave";
        supported = parse_script->support & SIEVE_CAPA_IHAVE;
        break;

    case BC_MAILBOXEXISTS:
        capability = "mailbox";
        supported = parse_script->support & SIEVE_CAPA_MAILBOX;
        break;

    case BC_METADATA:
        init_comptags(&p->u.mm.comp);
        GCC_FALLTHROUGH

    case BC_METADATAEXISTS:
        capability = "mboxmetadata";
        supported = parse_script->support & SIEVE_CAPA_MBOXMETA;
        break;

    case BC_SERVERMETADATA:
        init_comptags(&p->u.mm.comp);
        GCC_FALLTHROUGH

    case BC_SERVERMETADATAEXISTS:
        capability = "servermetadata";
        supported = parse_script->support & SIEVE_CAPA_SERVERMETA;
        break;

    case BC_VALIDEXTLIST:
        capability = "extlists";
        supported = parse_script->support & SIEVE_CAPA_EXTLISTS;
        break;

    case BC_DUPLICATE:
        capability = "duplicate";
        supported = parse_script->support & SIEVE_CAPA_DUPLICATE;
        p->u.dup.idtype = p->u.dup.seconds = -1;
        break;

    case BC_SPECIALUSEEXISTS:
        capability = "special-use";
        supported = parse_script->support & SIEVE_CAPA_SPECIAL_USE;
        init_comptags(&p->u.mm.comp);
        break;

    case BC_MAILBOXIDEXISTS:
        capability = "mailboxid";
        supported = parse_script->support & SIEVE_CAPA_MAILBOXID;
        break;

    case BC_JMAPQUERY:
        capability = "vnd.cyrus.jmapquery";
        supported = parse_script->support & SIEVE_CAPA_JMAPQUERY;
        break;
    }

    if (!supported) {
        sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, capability);
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
    unsigned long long  supported = SIEVE_CAPA_BASE;

    p->type = type;
    p->next = NULL;

    switch (type) {
    case B_FILEINTO:
        capability = "fileinto";
        supported = parse_script->support & SIEVE_CAPA_FILEINTO;
        break;

    case B_REJECT:
        capability = "reject";
        supported = parse_script->support & SIEVE_CAPA_REJECT;
        break;

    case B_EREJECT:
        capability = "ereject";
        supported = parse_script->support & SIEVE_CAPA_EREJECT;
        break;

    case B_VACATION:
        capability = "vacation";
        supported = parse_script->support & SIEVE_CAPA_VACATION;

        p->u.v.seconds = p->u.v.mime = -1;
        break;

    case B_SETFLAG:
    case B_ADDFLAG:
    case B_REMOVEFLAG:
        capability = "imap4flags";
        supported = parse_script->support & SIEVE_CAPA_IMAP4FLAGS;
        break;

    case B_DENOTIFY:
        capability = "notify";
        supported = parse_script->support & SIEVE_CAPA_NOTIFY;
        init_comptags(&p->u.d.comp);
        p->u.d.comp.collation = B_ASCIICASEMAP;
        p->u.d.priority = -1;
        break;

    case B_NOTIFY:
    case B_ENOTIFY:
        /* actual type and availability will be determined by parser */
        p->u.n.priority = -1;
        break;

    case B_ERROR:
        capability = "ihave";
        supported = parse_script->support & SIEVE_CAPA_IHAVE;
        break;

    case B_INCLUDE:
        p->u.inc.once = p->u.inc.location = p->u.inc.optional = -1;
        GCC_FALLTHROUGH

    case B_RETURN:
        capability = "include";
        supported = parse_script->support & SIEVE_CAPA_INCLUDE;
        break;

    case B_SET:
        capability = "variables";
        supported = parse_script->support & SIEVE_CAPA_VARIABLES;
        break;

    case B_DELETEHEADER:
        init_comptags(&p->u.dh.comp);
        GCC_FALLTHROUGH

    case B_ADDHEADER:
        capability = "editheader";
        supported = parse_script->support & SIEVE_CAPA_EDITHEADER;
        break;

    case B_LOG:
        capability = "vnd.cyrus.log";
        supported = parse_script->support & SIEVE_CAPA_LOG;
        break;

    case B_SNOOZE:
        capability = "vnd.cyrus.snooze";
        supported = parse_script->support & SIEVE_CAPA_SNOOZE;
        break;

    case B_PROCESSIMIP:
        capability = "vnd.cyrus.imip";
        supported = parse_script->support & SIEVE_CAPA_IMIP;
        break;
    }

    if (!supported) {
        sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, capability);
    }

    return p;
}

commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n)
{
    commandlist_t *p = (commandlist_t *) xzmalloc(sizeof(commandlist_t));

    p->type = B_IF;
    p->u.i.t = t;
    p->u.i.do_then = y;
    p->u.i.do_else = n;
    p->next = NULL;

    return p;
}

void free_testlist(testlist_t *tl)
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
    case BC_ANYOF:
    case BC_ALLOF:
        free_testlist(t->u.tl);
        break;

    case BC_NOT:
        free_test(t->u.t);
        break;

    case BC_EXISTS:
    case BC_IHAVE:
    case BC_VALIDEXTLIST:
    case BC_VALIDNOTIFYMETHOD:
        strarray_free(t->u.sl);
        break;

    case BC_SIZE:
    case BC_FALSE:
    case BC_TRUE:
        break;

    case BC_HASFLAG:
    case BC_HEADER:
    case BC_HEADER_PRE_INDEX:
    case BC_STRING:
        strarray_free(t->u.hhs.sl);
        strarray_free(t->u.hhs.pl);
        break;

    case BC_ADDRESS:
    case BC_ADDRESS_PRE_INDEX:
    case BC_ENVELOPE:
        strarray_free(t->u.ae.sl);
        strarray_free(t->u.ae.pl);
        break;

    case BC_BODY:
        strarray_free(t->u.b.content_types);
        strarray_free(t->u.b.pl);
        break;

    case BC_DATE:
    case BC_CURRENTDATE:
        free(t->u.dt.zone.offset);
        free(t->u.dt.header_name);
        strarray_free(t->u.dt.kl);
        break;

    case BC_ENVIRONMENT:
    case BC_MAILBOXEXISTS:
    case BC_MAILBOXIDEXISTS:
    case BC_METADATA:
    case BC_METADATAEXISTS:
    case BC_SERVERMETADATA:
    case BC_SERVERMETADATAEXISTS:
    case BC_SPECIALUSEEXISTS:
    case BC_NOTIFYMETHODCAPABILITY:
        free(t->u.mm.extname);
        free(t->u.mm.keyname);
        strarray_free(t->u.mm.keylist);
        break;

    case BC_DUPLICATE:
        free(t->u.dup.idval);
        free(t->u.dup.handle);
        break;

    case BC_JMAPQUERY:
        free(t->u.jquery);
        break;
    }

    free(t);
}

static void free_fileinto(struct Fileinto *f)
{
    free(f->folder);
    free(f->specialuse);
    free(f->mailboxid);
    strarray_free(f->flags);
}

void free_tree(commandlist_t *cl)
{
    commandlist_t *cl2;

    while (cl != NULL) {
        cl2 = cl->next;
        switch (cl->type) {
        case B_IF:
            free_test(cl->u.i.t);
            free_tree(cl->u.i.do_then);
            free_tree(cl->u.i.do_else);
            break;

        case B_INCLUDE:
            free(cl->u.inc.script);
            break;

        case B_SETFLAG:
        case B_ADDFLAG:
        case B_REMOVEFLAG:
            free(cl->u.fl.variable);
            strarray_free(cl->u.fl.flags);
            break;

        case B_FILEINTO:
            free_fileinto(&cl->u.f);
            break;

        case B_REDIRECT:
            free(cl->u.r.address);
            free(cl->u.r.bytime);
            free(cl->u.r.bymode);
            free(cl->u.r.dsn_notify);
            free(cl->u.r.dsn_ret);
            break;

        case B_REJECT:
        case B_EREJECT:
        case B_ERROR:
            free(cl->u.str);
            break;

        case B_VACATION:
            free(cl->u.v.subject);
            strarray_free(cl->u.v.addresses);
            free(cl->u.v.message);
            free(cl->u.v.from);
            free(cl->u.v.handle);
            free_fileinto(&cl->u.v.fcc);
            break;

        case B_KEEP:
            strarray_free(cl->u.k.flags);
            break;

        case B_STOP:
        case B_DISCARD:
        case B_RETURN:
            break;

        case B_ENOTIFY:
        case B_NOTIFY:
            free(cl->u.n.method);
            free(cl->u.n.id);
            free(cl->u.n.from);
            strarray_free(cl->u.n.options);
            free(cl->u.n.message);
            free_fileinto(&cl->u.n.fcc);
            break;

        case B_DENOTIFY:
            free(cl->u.d.pattern);
            break;

        case B_SET:
            free(cl->u.s.variable);
            free(cl->u.s.value);
            break;

        case B_ADDHEADER:
            free(cl->u.ah.name);
            free(cl->u.ah.value);
            break;

        case B_DELETEHEADER:
            free(cl->u.dh.name);
            strarray_free(cl->u.dh.values);
            break;

        case B_SNOOZE:
            free_fileinto(&cl->u.sn.f);
            strarray_free(cl->u.sn.addflags);
            strarray_free(cl->u.sn.removeflags);
            arrayu64_free(cl->u.sn.times);
            free(cl->u.sn.tzid);
            break;

        case B_PROCESSIMIP:
            free(cl->u.imip.calendarid);
            free(cl->u.imip.status);
            break;
        }

        free(cl);
        cl = cl2;
    }
}
