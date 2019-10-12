/* bc_parse.c -- sieve bytecode - pass 1 of the decompiler
 * Ken Murchison
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#include <netinet/in.h>
#include <string.h>

#include "bc_parse.h"
#include "strarray.h"
#include "times.h"


/* Given a bytecode_input_t at the beginning of a file,
 * return the version, the required extensions,
 * and the bytecode index of the first item */
EXPORTED int bc_header_parse(bytecode_input_t *bc, int *version, int *requires)
{
    int pos = 0;

    *version = 0;
    if (requires) *requires = 0;

    if (memcmp(bc, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN)) return -1;

    pos = BYTECODE_MAGIC_LEN / sizeof(bytecode_input_t);

    *version = ntohl(bc[pos++].value);
    if (*version >= 0x11) {
        int req = ntohl(bc[pos++].value);

        if (requires) *requires = req;
    }

    return pos;
}

/* Given a bytecode_input_t at the beginning of a string (the len block),
 * return the string, the length, and the bytecode index of the NEXT item */
static int bc_string_parse(bytecode_input_t *bc, int pos, char **str)
{
    int len = ntohl(bc[pos++].value);

    if (len == -1) {
         /* -1 length indicates NULL */
         *str = NULL;
    } else {
        /* This cast is ugly, but necessary */
        *str = (char *) &bc[pos].str;

        /* Compute the next index */
        pos += ((ROUNDUP(len+1)) / sizeof(bytecode_input_t));
    }

    return pos;
}

/* Given a bytecode_input_t at the beginning of a stringlist (the len block),
 * return the stringlist, and the bytecode index of the NEXT item */
static int bc_stringlist_parse(bytecode_input_t *bc, int pos,
                                  strarray_t **strlist)
{
    int len = ntohl(bc[pos++].listlen);

    pos++; /* Skip Total Byte Length */

    *strlist = strarray_new();

    while (len--) {
        char *str;

        pos = bc_string_parse(bc, pos, &str);
        strarray_appendm(*strlist, str);
    }

    return pos;
}

/* Given a bytecode_input_t at the beginning of a valuelist (the len block),
 * return the vallist, and the bytecode index of the NEXT item */
static int bc_vallist_parse(bytecode_input_t *bc, int pos,
                            arrayu64_t **vallist)
{
    int len = ntohl(bc[pos++].listlen);

    pos++; /* Skip Total Byte Length */

    *vallist = arrayu64_new();

    while (len--) {
        arrayu64_append(*vallist, ntohl(bc[pos++].value));
    }

    return pos;
}

static int bc_comparator_parse(bytecode_input_t *bc, int pos, comp_t *comp)
{
    comp->match = ntohl(bc[pos++].value);
    comp->relation = ntohl(bc[pos++].value);
    comp->collation = ntohl(bc[pos++].value);

    return pos;
}

EXPORTED int bc_action_parse(bytecode_input_t *bc, int pos, int version,
                              commandlist_t *cmd)
{
    int bits;

    memset(cmd, 0, sizeof(commandlist_t));
    cmd->type = ntohl(bc[pos++].op);

    /* When a case is switch'ed to, pos points to the first parameter
     * of the action.  This makes it easier to add future extensions.
     * Extensions that change an existing action should add any new
     * parameters to the beginning of the particular action's bytecode.
     * This will allow the new code to fall through to the  older
     * code, which will then parse the older parameters and should
     * require only a minimal set of changes to support any new extension. 
     */
    switch (cmd->type) {
    case B_STOP:            /* 0 */
        break;


    case B_KEEP_ORIG:       /* 1 */
        break;

    case B_KEEP_COPY:       /* 22 */
    case B_KEEP:            /* 35 */
        pos = bc_stringlist_parse(bc, pos, &cmd->u.k.flags);

        if (cmd->type == B_KEEP_COPY) pos++;  /* skip legacy :copy */
        break;

        
    case B_DISCARD:         /* 2 */
        break;


    case B_REJECT:          /* 3 */
    case B_EREJECT:         /* 31 */
        pos = bc_string_parse(bc, pos, &cmd->u.str);
        break;


    case B_FILEINTO:        /* 41 */
        pos = bc_string_parse(bc, pos, &cmd->u.f.mailboxid);
        GCC_FALLTHROUGH

    case B_FILEINTO_SPECIALUSE:        /* 38 */
        pos = bc_string_parse(bc, pos, &cmd->u.f.specialuse);

        GCC_FALLTHROUGH

    case B_FILEINTO_CREATE: /* 24 */
        cmd->u.f.create = ntohl(bc[pos++].value);

        GCC_FALLTHROUGH

    case B_FILEINTO_FLAGS:  /* 23 */
        pos = bc_stringlist_parse(bc, pos, &cmd->u.f.flags);

        GCC_FALLTHROUGH

    case B_FILEINTO_COPY :  /* 19 */
        cmd->u.f.copy = ntohl(bc[pos++].value);

        GCC_FALLTHROUGH

    case B_FILEINTO_ORIG:   /* 4 */
        pos = bc_string_parse(bc, pos, &cmd->u.f.folder);
        break;


    case B_REDIRECT:        /* 39 */
        pos = bc_string_parse(bc, pos, &cmd->u.r.bytime);
        pos = bc_string_parse(bc, pos, &cmd->u.r.bymode);
        cmd->u.r.bytrace = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &cmd->u.r.dsn_notify);
        pos = bc_string_parse(bc, pos, &cmd->u.r.dsn_ret);

        GCC_FALLTHROUGH

    case B_REDIRECT_LIST:   /* 32 */
        cmd->u.r.list = ntohl(bc[pos++].value);

        GCC_FALLTHROUGH

    case B_REDIRECT_COPY:   /* 20 */
        cmd->u.r.copy = ntohl(bc[pos++].value);

        GCC_FALLTHROUGH

    case B_REDIRECT_ORIG:   /* 5 */
        pos = bc_string_parse(bc, pos, &cmd->u.r.address);
        break;


    case B_IF:              /* 6 */
        cmd->u.i.testend = ntohl(bc[pos++].value);
        /* Tests are parsed by caller */
        break;


    case B_MARK:            /* 7 */
    case B_UNMARK:          /* 8 */
        break;


    case B_ADDFLAG:         /* 26 */
    case B_SETFLAG:         /* 27 */
    case B_REMOVEFLAG:      /* 28 */
        pos = bc_string_parse(bc, pos, &cmd->u.fl.variable);

        GCC_FALLTHROUGH

    case B_ADDFLAG_ORIG:    /* 9 */
    case B_SETFLAG_ORIG:    /* 10 */
    case B_REMOVEFLAG_ORIG: /* 11 */
        pos = bc_stringlist_parse(bc, pos, &cmd->u.fl.flags);
        break;


    case B_NOTIFY:          /* 12 */
    case B_ENOTIFY:         /* 33 */
        pos = bc_string_parse(bc, pos, &cmd->u.n.method);
        pos = bc_string_parse(bc, pos, (cmd->type == B_ENOTIFY) ?
                               &cmd->u.n.from : &cmd->u.n.id);
        pos = bc_stringlist_parse(bc, pos, &cmd->u.n.options);
        cmd->u.n.priority = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &cmd->u.n.message);
        break;


    case B_DENOTIFY:        /* 13 */
        cmd->u.d.priority = ntohl(bc[pos++].value);
        cmd->u.d.comp.match = ntohl(bc[pos++].value);
        cmd->u.d.comp.relation = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &cmd->u.d.pattern);
        break;


    case B_VACATION_ORIG:   /* 14 */
    case B_VACATION_SEC:    /* 21 */
    case B_VACATION_FCC:    /* 36 */
    case B_VACATION:        /* 37 */
        pos = bc_stringlist_parse(bc, pos, &cmd->u.v.addresses);
        pos = bc_string_parse(bc, pos, &cmd->u.v.subject);
        pos = bc_string_parse(bc, pos, &cmd->u.v.message);
        cmd->u.v.seconds = ntohl(bc[pos++].value);
        cmd->u.v.mime = ntohl(bc[pos++].value);

        if (version >= 0x05) {
            pos = bc_string_parse(bc, pos, &cmd->u.v.from);
            pos = bc_string_parse(bc, pos, &cmd->u.v.handle);

            if (cmd->type >= B_VACATION_FCC) {
                pos = bc_string_parse(bc, pos, &cmd->u.v.fcc.folder);

                if (cmd->u.v.fcc.folder) {
                    cmd->u.v.fcc.create = ntohl(bc[pos++].value);
                    pos = bc_stringlist_parse(bc, pos, &cmd->u.v.fcc.flags);

                    if (cmd->type == B_VACATION) {
                        pos = bc_string_parse(bc, pos,
                                               &cmd->u.v.fcc.specialuse);
                    }
                }
            }
        }
        break;


    case B_NULL:            /* 15 */
        break;


    case B_JUMP:            /* 16 */
        cmd->u.jump = ntohl(bc[pos++].value);
        break;


    case B_INCLUDE:         /* 17 */
        bits = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &cmd->u.inc.script);

        cmd->u.inc.location = bits & INC_LOCATION_MASK;
        cmd->u.inc.optional = bits & INC_OPTIONAL_MASK;
        cmd->u.inc.once     = bits & INC_ONCE_MASK;
        break;


    case B_RETURN:          /* 18 */
        break;


    case B_SET:             /* 25 */
        bits = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &cmd->u.s.variable);
        pos = bc_string_parse(bc, pos, &cmd->u.s.value);

        cmd->u.s.mod40 = bits & BFV_MOD40_MASK;
        cmd->u.s.mod30 = bits & BFV_MOD30_MASK;
        cmd->u.s.mod20 = bits & BFV_MOD20_MASK;
        cmd->u.s.mod15 = bits & BFV_MOD15_MASK;
        cmd->u.s.mod10 = bits & BFV_MOD10_MASK;
        break;


    case B_ADDHEADER:       /* 29 */
        cmd->u.ah.index = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &cmd->u.ah.name);
        pos = bc_string_parse(bc, pos, &cmd->u.ah.value);
        break;


    case B_DELETEHEADER:    /* 30 */
        cmd->u.dh.comp.index = ntohl(bc[pos++].value);
        pos = bc_comparator_parse(bc, pos, &cmd->u.dh.comp);
        pos = bc_string_parse(bc, pos, &cmd->u.dh.name);
        pos = bc_stringlist_parse(bc, pos, &cmd->u.dh.values);
        break;


    case B_LOG:
        pos = bc_string_parse(bc, pos, &cmd->u.l.text);
        break;


    case B_ERROR:           /* 34 */
        pos = bc_string_parse(bc, pos, &cmd->u.str);
        break;


    case B_SNOOZE:          /* 42 */
        pos = bc_string_parse(bc, pos, &cmd->u.sn.mailbox);
        pos = bc_stringlist_parse(bc, pos, &cmd->u.sn.addflags);
        pos = bc_stringlist_parse(bc, pos, &cmd->u.sn.removeflags);
        cmd->u.sn.days = ntohl(bc[pos++].value);
        pos = bc_vallist_parse(bc, pos, &cmd->u.sn.times);
        break;


    default:
        /* Unknown opcode? */
        pos = -1;
        break;
    }

    return pos;
}

EXPORTED int bc_test_parse(bytecode_input_t *bc, int pos, int version,
                           test_t *test)
{
    int opcode = ntohl(bc[pos++].op);
    int has_index = 0;

    if (version == 0x07 &&
        (opcode == BC_ADDRESS_PRE_INDEX || opcode == BC_HEADER_PRE_INDEX)) {
        /* There was a version of the bytecode that had the index extension
         * but did not update the bytecode codepoints, nor did it increment
         * the bytecode version number.  This tests if the index extension
         * was in the bytecode based on the position of the match-type
         * argument.
         * We test for the applicable version number explicitly.
         */
        switch (ntohl(bc[pos+1].value)) {
        case B_IS:
        case B_CONTAINS:
        case B_MATCHES:
        case B_REGEX:
        case B_COUNT:
        case B_VALUE:
            if (opcode == BC_ADDRESS_PRE_INDEX) opcode = BC_ADDRESS;
            else opcode = BC_HEADER;
            break;
        }
    }

    memset(test, 0, sizeof(test_t));
    test->type = opcode;

    /* When a case is switch'ed to, pos points to the first parameter
     * of the test.  This makes it easier to add future extensions.
     * Extensions that change an existing test should add any new
     * parameters to the beginning of the particular test's bytecode.
     * This will allow the new code to fall through to the  older
     * code, which will then parse the older parameters and should
     * require only a minimal set of changes to support any new extension. 
     */
    switch (opcode) {
    case BC_FALSE:                /* 0 */
    case BC_TRUE:                 /* 1 */
    case BC_NOT:                  /* 2 */
        break;


    case BC_ANYOF:                /* 5 */
    case BC_ALLOF:                /* 6 */
        test->u.aa.ntests = ntohl(bc[pos++].listlen);
        test->u.aa.endtests = ntohl(bc[pos++].value) / sizeof(bytecode_input_t);
        /* Tests are parsed by caller */
        break;


    case BC_EXISTS:               /* 3 */
    case BC_VALIDEXTLIST:         /* 22 */
    case BC_IHAVE:                /* 24 */
    case BC_VALIDNOTIFYMETHOD:    /* 27 */
        pos = bc_stringlist_parse(bc, pos, &test->u.sl);
        break;


    case BC_SIZE:                 /* 4 */
        test->u.sz.t = ntohl(bc[pos++].value);
        test->u.sz.n = ntohl(bc[pos++].value);
        break;


    case BC_ADDRESS:              /* 13 */
        test->u.ae.comp.index = ntohl(bc[pos++].value);

        GCC_FALLTHROUGH

    case BC_ADDRESS_PRE_INDEX:    /* 7 */
    case BC_ENVELOPE:             /* 8 */
        pos = bc_comparator_parse(bc, pos, &test->u.ae.comp);
        test->u.ae.addrpart = ntohl(bc[pos++].value);
        pos = bc_stringlist_parse(bc, pos, &test->u.ae.sl);
        pos = bc_stringlist_parse(bc, pos, &test->u.ae.pl);
        break;


    case BC_HEADER:               /* 14 */
        test->u.hhs.comp.index = ntohl(bc[pos++].value);

        GCC_FALLTHROUGH

    case BC_HEADER_PRE_INDEX:     /* 9 */
    case BC_HASFLAG:              /* 15 */
    case BC_STRING:               /* 21 */
        pos = bc_comparator_parse(bc, pos, &test->u.hhs.comp);
        pos = bc_stringlist_parse(bc, pos, &test->u.hhs.sl);
        pos = bc_stringlist_parse(bc, pos, &test->u.hhs.pl);
        break;


    case BC_BODY:                 /* 10 */
        pos = bc_comparator_parse(bc, pos, &test->u.b.comp);
        test->u.b.transform = ntohl(bc[pos++].value);
        test->u.b.offset = ntohl(bc[pos++].value);
        pos = bc_stringlist_parse(bc, pos, &test->u.b.content_types);
        pos = bc_stringlist_parse(bc, pos, &test->u.b.pl);
        break;


    case BC_DATE:                 /* 11 */
        has_index = 1;

        GCC_FALLTHROUGH

    case BC_CURRENTDATE:          /* 12 */
        if (version == 0x07) {
            /* There was a version of the bytecode that had the index extension
             * but did not update the bytecode codepoints, nor did it increment
             * the bytecode version number.  This tests if the index extension
             * was in the bytecode based on the position of the match-type
             * or comparator argument.  This will correctly identify whether
             * the index extension was supported in every case except the case
             * of a timezone that is 61 minutes offset (since 61 corresponds to
             * B_ORIGINALZONE).
             * There was also an unnumbered version of BC_CURRENTDATE that did
             * allow :index.  This also covers that case.
             * We test for the applicable version number explicitly.
             */
            switch (ntohl(bc[pos+3].value)) {
                /* if the 3rd parameter is a comparator,
                 * we have neither :index nor :zone tags.
                 * B_ORIGINALZONE is the first parameter.
                 */
            case B_ASCIICASEMAP:
            case B_OCTET:
            case B_ASCIINUMERIC:
                has_index = 0;
                break;
            default:
                /* otherwise, we either have a :zone tag, an :index tag, or
                 * both
                 */
                switch (ntohl(bc[pos+4].value)) {
                    /* if the 4th paramater is a comparator,
                     * we have either :index or :zone, but not both.
                     */
                case B_ASCIICASEMAP:
                case B_OCTET:
                case B_ASCIINUMERIC:
                    /* The ambiguous case is B_TIMEZONE as 1st parameter and
                     * B_ORIGINALZONE as second parameter, which could mean
                     * either ':index 60 :originalzone' or ':zone "+0101"'
                     */
                    if (B_TIMEZONE == ntohl(bc[pos].value) &&
                        B_ORIGINALZONE == ntohl(bc[pos+1].value)) {
                        /* This is the ambiguous case.  Resolve the ambiguity
                         * by assuming that there is no :index tag since the
                         * unnumbered bytecode that shipped with Kolab
                         * Groupware 3.3 included support for the date
                         * extension, but not for the index extension.
                         */
                        has_index = 0;

                    } else if (B_TIMEZONE == ntohl(bc[pos].value)) {
                        /* if the first parameter is B_TIMEZONE, and the above
                         * test was false, it must be a :zone tag, and we
                         * don't have :index.
                         */
                        has_index = 0;
                    } else {
                        /* if the first parameter is not B_TIMEZONE, it must
                         * be an :index tag, and we don't have :zone.
                         */
                        has_index = 1;
                    }
                    break;
                default:
                    /* if the 4th parameter is not a comparator, the 5th is,
                     * and we have both :index and :zone
                     */
                    has_index = 1;
                    break;
                }
                break;
            }
        }

        if (has_index) test->u.dt.comp.index = ntohl(bc[pos++].value);

        test->u.dt.zonetag = ntohl(bc[pos++].value);
        if (test->u.dt.zonetag == B_TIMEZONE)
            test->u.dt.zone = ntohl(bc[pos++].value);

        pos = bc_comparator_parse(bc, pos, &test->u.dt.comp);
        test->u.dt.date_part = ntohl(bc[pos++].value);

        if (opcode == BC_DATE)
            pos = bc_string_parse(bc, pos, &test->u.dt.header_name);
        pos = bc_stringlist_parse(bc, pos, &test->u.dt.kl);
        break;


    case BC_METADATAEXISTS:       /* 18 */
    case BC_SPECIALUSEEXISTS:     /* 25 */
        pos = bc_string_parse(bc, pos, &test->u.mm.extname);

        GCC_FALLTHROUGH

    case BC_MAILBOXEXISTS:        /* 16 */
    case BC_SERVERMETADATAEXISTS: /* 20 */
    case BC_MAILBOXIDEXISTS:      /* 29 */
        pos = bc_stringlist_parse(bc, pos, &test->u.mm.keylist);
        break;


    case BC_METADATA:             /* 17 */
    case BC_NOTIFYMETHODCAPABILITY:/* 28 */
        pos = bc_comparator_parse(bc, pos, &test->u.mm.comp);
        pos = bc_string_parse(bc, pos, &test->u.mm.extname);
        pos = bc_string_parse(bc, pos, &test->u.mm.keyname);
        pos = bc_stringlist_parse(bc, pos, &test->u.mm.keylist);
        break;


    case BC_SERVERMETADATA:       /* 19 */
    case BC_ENVIRONMENT:          /* 26 */
        pos = bc_comparator_parse(bc, pos, &test->u.mm.comp);
        pos = bc_string_parse(bc, pos, &test->u.mm.keyname);
        pos = bc_stringlist_parse(bc, pos, &test->u.mm.keylist);
        break;


    case BC_DUPLICATE:            /* 23 */
        test->u.dup.idtype = ntohl(bc[pos++].value);
        pos = bc_string_parse(bc, pos, &test->u.dup.idval);
        pos = bc_string_parse(bc, pos, &test->u.dup.handle);
        test->u.dup.seconds = ntohl(bc[pos++].value);
        test->u.dup.last = ntohl(bc[pos++].value);
        break;


    case BC_JMAPQUERY:            /* 30 */
        pos = bc_string_parse(bc, pos, &test->u.jquery);
        break;


    default:
        /* Unknown opcode? */
        pos = -1;
        break;
    }

    return pos;
}
