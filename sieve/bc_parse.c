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

#include "bc_parse.h"
#include "strarray.h"
#include "arrayu64.h"

#define MAX_ARGS  10  /* vacation currently uses 9 */

struct args_t {
    unsigned type;
    const char *fmt;
    const size_t offsets[MAX_ARGS];
};

static const struct args_t cmd_args_table[] = {
    { B_STOP,                    "", { 0 } },                            /*  0 */
    { B_KEEP_ORIG,               "", { 0 } },                            /*  1 */
    { B_DISCARD,                 "", { 0 } },                            /*  2 */
    { B_REJECT,                  "s",                                    /*  3 */
      { offsetof(struct Commandlist, u.str)
      } },
    { B_FILEINTO_ORIG,           "s",                                    /*  4 */
      { offsetof(struct Commandlist, u.f.folder)
      } },
    { B_REDIRECT_ORIG,           "s",                                    /*  5 */
      { offsetof(struct Commandlist, u.r.address)
      } },
    { B_IF,                      "i",                                    /*  6 */
      { offsetof(struct Commandlist, u.i.testend)
        /* Tests are parsed by caller */
      } },
    { B_MARK,                    "", { 0 } },                            /*  7 */
    { B_UNMARK,                  "", { 0 } },                            /*  8 */
    { B_ADDFLAG_ORIG,            "S",                                    /*  9 */
      { offsetof(struct Commandlist, u.fl.flags)
      } },
    { B_SETFLAG_ORIG,            "S",                                    /* 10 */
      { offsetof(struct Commandlist, u.fl.flags)
      } },
    { B_REMOVEFLAG_ORIG,         "S",                                    /* 11 */
      { offsetof(struct Commandlist, u.fl.flags)
      } },
    { B_NOTIFY,                  "ssSis",                                /* 12 */
      { offsetof(struct Commandlist, u.n.method),
        offsetof(struct Commandlist, u.n.id),
        offsetof(struct Commandlist, u.n.options),
        offsetof(struct Commandlist, u.n.priority),
        offsetof(struct Commandlist, u.n.message)
      } },
    { B_DENOTIFY,                "iiis",                                 /* 13 */
      { offsetof(struct Commandlist, u.d.priority),
        offsetof(struct Commandlist, u.d.comp.match),
        offsetof(struct Commandlist, u.d.comp.relation),
        offsetof(struct Commandlist, u.d.pattern)
      } },
    { B_VACATION_ORIG,           "Sssii",                                /* 14 */
      { offsetof(struct Commandlist, u.v.addresses),
        offsetof(struct Commandlist, u.v.subject),
        offsetof(struct Commandlist, u.v.message),
        offsetof(struct Commandlist, u.v.seconds),
        offsetof(struct Commandlist, u.v.mime)
      } },
    { B_NULL,                    "", { 0 } },                            /* 15 */
    { B_JUMP,                    "i",                                    /* 16 */
      { offsetof(struct Commandlist, u.jump)
      } },
    { B_INCLUDE,                 "B3s",                                  /* 17 */
      { offsetof(struct Commandlist, u.inc.location), INC_LOCATION_MASK,
        offsetof(struct Commandlist, u.inc.optional), INC_OPTIONAL_MASK,
        offsetof(struct Commandlist, u.inc.once),     INC_ONCE_MASK,
        offsetof(struct Commandlist, u.inc.script)
      } },
    { B_RETURN,                  "", { 0 } },                            /* 18 */
    { B_FILEINTO_COPY,           "is",                                   /* 19 */
      { offsetof(struct Commandlist, u.f.copy),
        offsetof(struct Commandlist, u.f.folder)
      } },
    { B_REDIRECT_COPY,           "is",                                   /* 20 */
      { offsetof(struct Commandlist, u.r.copy),
        offsetof(struct Commandlist, u.r.address)
      } },
    { B_VACATION_SEC,            "Sssiiss",                              /* 21 */
      { offsetof(struct Commandlist, u.v.addresses),
        offsetof(struct Commandlist, u.v.subject),
        offsetof(struct Commandlist, u.v.message),
        offsetof(struct Commandlist, u.v.seconds),
        offsetof(struct Commandlist, u.v.mime),
        offsetof(struct Commandlist, u.v.from),
        offsetof(struct Commandlist, u.v.handle)
      } },
    { B_KEEP_COPY,               "S_",                                   /* 22 */
      { offsetof(struct Commandlist, u.k.flags)
      } },
    { B_FILEINTO_FLAGS,          "Sis",                                  /* 23 */
      { offsetof(struct Commandlist, u.f.flags),
        offsetof(struct Commandlist, u.f.copy),
        offsetof(struct Commandlist, u.f.folder)
      } },
    { B_FILEINTO_CREATE,         "iSis",                                 /* 24 */
      { offsetof(struct Commandlist, u.f.create),
        offsetof(struct Commandlist, u.f.flags),
        offsetof(struct Commandlist, u.f.copy),
        offsetof(struct Commandlist, u.f.folder)
      } },
    { B_SET,                     "iss",                                  /* 25 */
      { offsetof(struct Commandlist, u.s.modifiers),
        offsetof(struct Commandlist, u.s.variable),
        offsetof(struct Commandlist, u.s.value)
      } },
    { B_ADDFLAG,                 "sS",                                   /* 26 */
      { offsetof(struct Commandlist, u.fl.variable),
        offsetof(struct Commandlist, u.fl.flags)
      } },
    { B_SETFLAG,                 "sS",                                   /* 27 */
      { offsetof(struct Commandlist, u.fl.variable),
        offsetof(struct Commandlist, u.fl.flags)
      } },
    { B_REMOVEFLAG,              "sS",                                   /* 28 */
      { offsetof(struct Commandlist, u.fl.variable),
        offsetof(struct Commandlist, u.fl.flags)
      } },
    { B_ADDHEADER,               "iss",                                  /* 29 */
      { offsetof(struct Commandlist, u.ah.index),
        offsetof(struct Commandlist, u.ah.name),
        offsetof(struct Commandlist, u.ah.value)
      } },
    { B_DELETEHEADER,            "iCsS",                                 /* 30 */
      { offsetof(struct Commandlist, u.dh.comp.index),
        offsetof(struct Commandlist, u.dh.comp),
        offsetof(struct Commandlist, u.dh.name),
        offsetof(struct Commandlist, u.dh.values)
      } },
    { B_EREJECT,                 "s",                                    /* 31 */
      { offsetof(struct Commandlist, u.str)
      } },
    { B_REDIRECT_LIST,           "iis",                                  /* 32 */
      { offsetof(struct Commandlist, u.r.list),
        offsetof(struct Commandlist, u.r.copy),
        offsetof(struct Commandlist, u.r.address)
      } },
    { B_ENOTIFY,                 "ssSis",                                /* 33 */
      { offsetof(struct Commandlist, u.n.method),
        offsetof(struct Commandlist, u.n.from),
        offsetof(struct Commandlist, u.n.options),
        offsetof(struct Commandlist, u.n.priority),
        offsetof(struct Commandlist, u.n.message)
      } },
    { B_ERROR,                   "",                                     /* 34 */
      { offsetof(struct Commandlist, u.str)
      } },
    { B_KEEP,                    "S",                                    /* 35 */
      { offsetof(struct Commandlist, u.k.flags) } },
    { B_VACATION_FCC_ORIG,       "SssiissF",                             /* 36 */
      { offsetof(struct Commandlist, u.v.addresses),
        offsetof(struct Commandlist, u.v.subject),
        offsetof(struct Commandlist, u.v.message),
        offsetof(struct Commandlist, u.v.seconds),
        offsetof(struct Commandlist, u.v.mime),
        offsetof(struct Commandlist, u.v.from),
        offsetof(struct Commandlist, u.v.handle),
        offsetof(struct Commandlist, u.v.fcc)
      } },
    { B_VACATION_FCC_SPLUSE,     "SssiissF$",                            /* 37 */
      { offsetof(struct Commandlist, u.v.addresses),
        offsetof(struct Commandlist, u.v.subject),
        offsetof(struct Commandlist, u.v.message),
        offsetof(struct Commandlist, u.v.seconds),
        offsetof(struct Commandlist, u.v.mime),
        offsetof(struct Commandlist, u.v.from),
        offsetof(struct Commandlist, u.v.handle),
        offsetof(struct Commandlist, u.v.fcc)
      } },
    { B_FILEINTO_SPECIALUSE,     "siSis",                                /* 38 */
      { offsetof(struct Commandlist, u.f.specialuse),
        offsetof(struct Commandlist, u.f.create),
        offsetof(struct Commandlist, u.f.flags),
        offsetof(struct Commandlist, u.f.copy),
        offsetof(struct Commandlist, u.f.folder)
      } },
    { B_REDIRECT,                "ssissiis",                             /* 39 */
      { offsetof(struct Commandlist, u.r.bytime),
        offsetof(struct Commandlist, u.r.bymode),
        offsetof(struct Commandlist, u.r.bytrace),
        offsetof(struct Commandlist, u.r.dsn_notify),
        offsetof(struct Commandlist, u.r.dsn_ret),
        offsetof(struct Commandlist, u.r.list),
        offsetof(struct Commandlist, u.r.copy),
        offsetof(struct Commandlist, u.r.address)
      } },
    { B_FILEINTO,                "ssiSis",                               /* 40 */
      { offsetof(struct Commandlist, u.f.mailboxid),
        offsetof(struct Commandlist, u.f.specialuse),
        offsetof(struct Commandlist, u.f.create),
        offsetof(struct Commandlist, u.f.flags),
        offsetof(struct Commandlist, u.f.copy),
        offsetof(struct Commandlist, u.f.folder)
      } },
    { B_LOG,                     "s",                                    /* 41 */
      { offsetof(struct Commandlist, u.l.text)
      } },
    { B_SNOOZE_ORIG,             "sSSB2U",                               /* 42 */
      { offsetof(struct Commandlist, u.sn.f.folder),
        offsetof(struct Commandlist, u.sn.addflags),
        offsetof(struct Commandlist, u.sn.removeflags),
        offsetof(struct Commandlist, u.sn.days),      SNOOZE_WDAYS_MASK,
        offsetof(struct Commandlist, u.sn.is_mboxid), SNOOZE_IS_ID_MASK,
        offsetof(struct Commandlist, u.sn.times)
      } },
    { B_SNOOZE_TZID,             "ssSSB2U",                              /* 43 */
      { offsetof(struct Commandlist, u.sn.tzid),
        offsetof(struct Commandlist, u.sn.f.folder),
        offsetof(struct Commandlist, u.sn.addflags),
        offsetof(struct Commandlist, u.sn.removeflags),
        offsetof(struct Commandlist, u.sn.days),      SNOOZE_WDAYS_MASK,
        offsetof(struct Commandlist, u.sn.is_mboxid), SNOOZE_IS_ID_MASK,
        offsetof(struct Commandlist, u.sn.times)
      } },
    { B_SNOOZE,                  "sssiSSisU",                            /* 44 */
      { offsetof(struct Commandlist, u.sn.f.folder),
        offsetof(struct Commandlist, u.sn.f.mailboxid),
        offsetof(struct Commandlist, u.sn.f.specialuse),
        offsetof(struct Commandlist, u.sn.f.create),
        offsetof(struct Commandlist, u.sn.addflags),
        offsetof(struct Commandlist, u.sn.removeflags),
        offsetof(struct Commandlist, u.sn.days),
        offsetof(struct Commandlist, u.sn.tzid),
        offsetof(struct Commandlist, u.sn.times)
      } },
    { B_VACATION,                "SssiissF!",                            /* 45 */
      { offsetof(struct Commandlist, u.v.addresses),
        offsetof(struct Commandlist, u.v.subject),
        offsetof(struct Commandlist, u.v.message),
        offsetof(struct Commandlist, u.v.seconds),
        offsetof(struct Commandlist, u.v.mime),
        offsetof(struct Commandlist, u.v.from),
        offsetof(struct Commandlist, u.v.handle),
        offsetof(struct Commandlist, u.v.fcc)
      } },
    { B_PROCESSIMIP,             "si",                                   /* 46 */
      { offsetof(struct Commandlist, u.imip.status),
        offsetof(struct Commandlist, u.imip.updates_only)
      } },
};

static const struct args_t test_args_table[] = {
    { BC_FALSE,                  "", { 0 } },                            /*  0 */
    { BC_TRUE,                   "", { 0 } },                            /*  1 */
    { BC_NOT,                    "", { 0 } },                            /*  2 */
    { BC_EXISTS,                 "S",                                    /*  3 */
      { offsetof(struct Test, u.sl)
      } },
    { BC_SIZE,                   "ii",                                   /*  4 */
      { offsetof(struct Test, u.sz.t),
        offsetof(struct Test, u.sz.n)
      } },
    { BC_ANYOF,                  "A", { 0 } },                           /*  5 */
    { BC_ALLOF,                  "A", { 0 } },                           /*  6 */
    { BC_ADDRESS_PRE_INDEX,      "CiSS",                                 /*  7 */
      { offsetof(struct Test, u.ae.comp),
        offsetof(struct Test, u.ae.addrpart),
        offsetof(struct Test, u.ae.sl),
        offsetof(struct Test, u.ae.pl)
      } },
    { BC_ENVELOPE,               "CiSS",                                 /*  8 */
      { offsetof(struct Test, u.ae.comp),
        offsetof(struct Test, u.ae.addrpart),
        offsetof(struct Test, u.ae.sl),
        offsetof(struct Test, u.ae.pl)
      } },
    { BC_HEADER_PRE_INDEX,       "CSS",                                  /*  9 */
      { offsetof(struct Test, u.hhs.comp),
        offsetof(struct Test, u.hhs.sl),
        offsetof(struct Test, u.hhs.pl)
      } },
    { BC_BODY,                   "CiiSS",                                /* 10 */
      { offsetof(struct Test, u.b.comp),
        offsetof(struct Test, u.b.transform),
        offsetof(struct Test, u.b.offset),
        offsetof(struct Test, u.b.content_types),
        offsetof(struct Test, u.b.pl)
      } },
    { BC_DATE_ORIG,              "izCisS",                               /* 11 */
      { offsetof(struct Test, u.dt.comp.index),
        offsetof(struct Test, u.dt.zone),
        offsetof(struct Test, u.dt.comp),
        offsetof(struct Test, u.dt.date_part),
        offsetof(struct Test, u.dt.header_name),
        offsetof(struct Test, u.dt.kl)
      } },
    { BC_CURRENTDATE_ORIG,       "zCiS",                                 /* 12 */
      { offsetof(struct Test, u.dt.zone),
        offsetof(struct Test, u.dt.comp),
        offsetof(struct Test, u.dt.date_part),
        offsetof(struct Test, u.dt.kl)
      } },
    { BC_ADDRESS,                "iCiSS",                                /* 13 */
      { offsetof(struct Test, u.ae.comp.index),
        offsetof(struct Test, u.ae.comp),
        offsetof(struct Test, u.ae.addrpart),
        offsetof(struct Test, u.ae.sl),
        offsetof(struct Test, u.ae.pl)
      } },
    { BC_HEADER,                 "iCSS",                                 /* 14 */
      { offsetof(struct Test, u.hhs.comp.index),
        offsetof(struct Test, u.hhs.comp),
        offsetof(struct Test, u.hhs.sl),
        offsetof(struct Test, u.hhs.pl)
      } },
    { BC_HASFLAG,                "CSS",                                  /* 15 */
      { offsetof(struct Test, u.hhs.comp),
        offsetof(struct Test, u.hhs.sl),
        offsetof(struct Test, u.hhs.pl)
      } },
    { BC_MAILBOXEXISTS,          "S",                                    /* 16 */
      { offsetof(struct Test, u.mm.keylist)
      } },
    { BC_METADATA,               "CssS",                                 /* 17 */
      { offsetof(struct Test, u.mm.comp),
        offsetof(struct Test, u.mm.extname),
        offsetof(struct Test, u.mm.keyname),
        offsetof(struct Test, u.mm.keylist)
      } },
    { BC_METADATAEXISTS,         "sS",                                   /* 18 */
      { offsetof(struct Test, u.mm.extname),
        offsetof(struct Test, u.mm.keylist)
      } },
    { BC_SERVERMETADATA,         "CsS",                                  /* 19 */
      { offsetof(struct Test, u.mm.comp),
        offsetof(struct Test, u.mm.keyname),
        offsetof(struct Test, u.mm.keylist)
      } },
    { BC_SERVERMETADATAEXISTS,   "S",                                    /* 20 */
      { offsetof(struct Test, u.mm.keylist)
      } },
    { BC_STRING,                 "CSS",                                  /* 21 */
      { offsetof(struct Test, u.hhs.comp),
        offsetof(struct Test, u.hhs.sl),
        offsetof(struct Test, u.hhs.pl)
      } },
    { BC_VALIDEXTLIST,           "S",                                    /* 22 */
      { offsetof(struct Test, u.sl)
      } },
    { BC_DUPLICATE,              "issii",                                /* 23 */
      { offsetof(struct Test, u.dup.idtype),
        offsetof(struct Test, u.dup.idval),
        offsetof(struct Test, u.dup.handle),
        offsetof(struct Test, u.dup.seconds),
        offsetof(struct Test, u.dup.last)
      } },
    { BC_IHAVE,                  "S",                                    /* 24 */
      { offsetof(struct Test, u.sl)
      } },
    { BC_SPECIALUSEEXISTS,       "sS",                                   /* 25 */
      { offsetof(struct Test, u.mm.extname),
        offsetof(struct Test, u.mm.keylist)
      } },
    { BC_ENVIRONMENT,            "CsS",                                  /* 26 */
      { offsetof(struct Test, u.mm.comp),
        offsetof(struct Test, u.mm.keyname),
        offsetof(struct Test, u.mm.keylist)
      } },
    { BC_VALIDNOTIFYMETHOD,      "S",                                    /* 27 */
      { offsetof(struct Test, u.sl)
      } },
    { BC_NOTIFYMETHODCAPABILITY, "CssS",                                 /* 28 */
      { offsetof(struct Test, u.mm.comp),
        offsetof(struct Test, u.mm.extname),
        offsetof(struct Test, u.mm.keyname),
        offsetof(struct Test, u.mm.keylist)
      } },
    { BC_MAILBOXIDEXISTS,        "S",                                    /* 29 */
      { offsetof(struct Test, u.mm.keylist)
      } },
    { BC_JMAPQUERY,              "s",                                    /* 30 */
      { offsetof(struct Test, u.jquery)
      } },
    { BC_DATE,                   "iZCisS",                               /* 31 */
      { offsetof(struct Test, u.dt.comp.index),
        offsetof(struct Test, u.dt.zone),
        offsetof(struct Test, u.dt.comp),
        offsetof(struct Test, u.dt.date_part),
        offsetof(struct Test, u.dt.header_name),
        offsetof(struct Test, u.dt.kl)
      } },
    { BC_CURRENTDATE,            "ZCiS",                                 /* 32 */
      { offsetof(struct Test, u.dt.zone),
        offsetof(struct Test, u.dt.comp),
        offsetof(struct Test, u.dt.date_part),
        offsetof(struct Test, u.dt.kl)
      } },
};

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

static int bc_args_parse(bytecode_input_t *bc, int pos, const char *fmt,
                         void *base, const size_t * offsets)
{
    while (*fmt) {
        switch (*fmt++) {
            /* skip and ignore */
        case '_':
            pos++;
            break;

            /* integer */
        case 'i':
            *((int *) (base + *offsets++)) = ntohl(bc[pos++].value);
            break;

            /* string */
        case 's':
            pos = bc_string_parse(bc, pos, base + *offsets++);
            break;

            /* string list */
        case 'S':
            pos = bc_stringlist_parse(bc, pos, base + *offsets++);
            break;

            /* u64 value list */
        case 'U':
            pos = bc_vallist_parse(bc, pos, base + *offsets++);
            break;

            /* allof/anyof test */
        case 'A':
            ((struct Test *) base)->u.aa.ntests = ntohl(bc[pos++].listlen);
            ((struct Test *) base)->u.aa.endtests =
                ntohl(bc[pos++].value) / sizeof(bytecode_input_t);
            break;

            /* bitmask - one set of bits split into N (2-9) values
               represented by N {offset to field, bitmask} pairs */
        case 'B': {
            unsigned bits = ntohl(bc[pos++].value);
            unsigned n = *fmt++ - '0';  /* only supports single digit */

            while (n--) {
                *((int *) (base + offsets[0])) = bits & offsets[1];
                offsets += 2;
            }
            break;
        }

            /* comparator */
        case 'C':
            pos = bc_comparator_parse(bc, pos, base + *offsets++);
            break;

            /* fccfolder [create flags [special-use [mailboxid] ] ] */
        case 'F': {
            struct Fileinto *fcc = base + *offsets++;
            int have_specialuse = 0, have_mailboxid = 0;

            switch (*fmt) {
            case '!':
                have_mailboxid = 1;

                GCC_FALLTHROUGH

            case '$':
                have_specialuse = 1;
                fmt++;
                break;
            }

            pos = bc_string_parse(bc, pos, &fcc->folder);
            if (fcc->folder) {
                fcc->create = ntohl(bc[pos++].value);
                pos = bc_stringlist_parse(bc, pos, &fcc->flags);
                if (have_specialuse) {
                    pos = bc_string_parse(bc, pos, &fcc->specialuse);
                    if (have_mailboxid) {
                        pos = bc_string_parse(bc, pos, &fcc->mailboxid);
                    }
                }
            }
            break;
        }

            /* zonetag [tzoffset (as integer)] */
        case 'z': {
            zone_t *z = base + *offsets++;

            z->tag = ntohl(bc[pos++].value);

            if (z->tag == B_TIMEZONE) {
                int offset = ntohl(bc[pos++].value);
                struct buf buf = BUF_INITIALIZER;

                buf_printf(&buf, "%+03d%02u", offset / 60, abs(offset % 60));
                z->offset = buf_release(&buf);
            }
            break;
        }


            /* zonetag [tzoffset (as string)] */
        case 'Z': {
            zone_t *z = base + *offsets++;

            z->tag = ntohl(bc[pos++].value);

            if (z->tag == B_TIMEZONE)
                pos = bc_string_parse(bc, pos, &z->offset);
            break;
        }

        default:
            pos = -1;
            break;
        }
    }

    return pos;
}

EXPORTED int bc_action_parse(bytecode_input_t *bc, int pos, int version,
                             commandlist_t *cmd)
{
    memset(cmd, 0, sizeof(commandlist_t));
    cmd->type = ntohl(bc[pos++].op);

    if (cmd->type >= B_ILLEGAL_VALUE) {
        /* Unknown opcode */
        return -1;
    }

    const char *fmt = cmd_args_table[cmd->type].fmt;
    const size_t *offsets = cmd_args_table[cmd->type].offsets;

    if (cmd->type == B_VACATION_ORIG && version >= 0x05) {
        /* Includes :from and :handle */
        fmt = cmd_args_table[B_VACATION_SEC].fmt;
        offsets = cmd_args_table[B_VACATION_SEC].offsets;
    }

    return bc_args_parse(bc, pos, fmt, cmd, offsets);
}

EXPORTED int bc_test_parse(bytecode_input_t *bc, int pos, int version,
                           test_t *test)
{
    int opcode = ntohl(bc[pos++].op);
    int has_index = 0;

    if (opcode >= BC_ILLEGAL_VALUE) {
        /* Unknown opcode */
        return -1;
    }

    const char *fmt = test_args_table[opcode].fmt;
    const size_t *offsets = test_args_table[opcode].offsets;

    if (version == 0x07) {
        switch (opcode) {
        case BC_HEADER_PRE_INDEX:
        case BC_ADDRESS_PRE_INDEX:
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

                fmt = cmd_args_table[opcode].fmt;
                offsets = cmd_args_table[opcode].offsets;
                break;
            }
            break;

        case BC_DATE:
            has_index = 1;

            GCC_FALLTHROUGH

        case BC_CURRENTDATE:
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

            if (has_index) {
                if (opcode == BC_CURRENTDATE) {
                    /* parse, but ignore, index as first argument */
                    static char buf[MAX_ARGS+1] = "_";

                    fmt = strcat(buf, fmt);
                }
            }
            else if (opcode == BC_DATE) {
                /* skip index (first argument) */
                fmt++;
                offsets++;
            }
            break;
        }
    }

    memset(test, 0, sizeof(test_t));
    test->type = opcode;

    return bc_args_parse(bc, pos, fmt, test, offsets);
}
