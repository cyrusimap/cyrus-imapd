/* sieved.c -- bytecode decompiler
 * Jen Smith
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

#include "sieve_interface.h"

#include "bc_parse.h"
#include "bytecode.h"
#include "script.h"
#include "interp.h"

#include "xmalloc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <string.h>

#include "map.h"
#include "times.h"

static void dump2(bytecode_input_t *d, int len);
static void generate_script(bytecode_input_t *d, int len);

/*this is called by xmalloc*/
EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s (%d)\r\n", s, code);

    exit(1);
}

static int load(int fd, bytecode_input_t ** d)
{
    const char * data=NULL;
    struct stat sbuf;
    size_t len=0;

    if (fstat(fd, &sbuf) == -1) {
        fprintf(stderr, "IOERROR: fstating sieve script: %m");
        return SIEVE_FAIL;
    }

    /*this reads in data and length from file*/
    map_refresh(fd, 1, &(data), &len, sbuf.st_size,
                "sievescript", "");
    *d=(bytecode_input_t *)data;

    printf("\n");

    return (len/sizeof(int));
}


int main(int argc, char * argv[])
{
    bytecode_input_t *bc = NULL;
    int script_fd;
    int c, usage_error = 0, gen_script = 0;

    unsigned long len;

    while ((c = getopt(argc, argv, "s")) != EOF)
        switch (c) {
        case 's':
            gen_script = 1;
            break;
        default:
            usage_error = 1;
            break;
        }

    if (usage_error || (argc - optind) < 1) {
        fprintf(stderr, "Syntax: %s [-s] <bytecode-file>\n",
               argv[0]);
        exit(1);
    }

    /*get script*/
    script_fd = open(argv[optind++], O_RDONLY);
    if (script_fd == -1)
    {
        fprintf(stderr, "can not open script '%s'\n", argv[1]);
        exit(1);
    }

    len=load(script_fd,&bc);
    close(script_fd);

    if (bc) {
        if (gen_script) generate_script(bc, len);
        else dump2(bc, len);
        exit(0);
    } else {
        exit(1);
    }
}

static void print_string(const char *label, const char *str)
{
    size_t len;

    if (str) len = strlen(str);
    else {
        str = "[nil]";
        len = -1;
    }

    printf("%s({%zd}%s)", label, len, str);
}

static void print_stringlist(const char *label, strarray_t *list)
{
    int x, list_len = strarray_size(list);

    printf("%s{%d} [", label, list_len);

    for (x = 0; x < list_len; x++) {
        const char *str = strarray_nth(list, x);

        if (!(x % 5)) printf("\n\t\t");
        print_string(" ", str);
    }
    printf("\n\t]");

    free(strarray_takevf(list));
}

static void print_time(uint64_t t)
{
    printf(" %02" PRIu64 ":%02" PRIu64 ":%02" PRIu64, t / 3600, (t % 3600) / 60, t % 60);
}

static void print_vallist(const char *label, arrayu64_t *list,
                          void (*print_cb)(uint64_t))
{
    int x, list_len = arrayu64_size(list);

    printf("%s{%d} [", label, list_len);

    for (x = 0; x < list_len; x++) {
        uint64_t i = arrayu64_nth(list, x);

        if (!(x % 5)) printf("\n\t\t");
        if (print_cb) print_cb(i);
        else printf(" %" PRIu64, i);
    }
    printf("\n\t]");

    arrayu64_free(list);
}

static void print_comparator(comp_t *comp)
{
    printf(" COMPARATOR [ ");

    switch (comp->match) {
    case B_IS:       printf("Is");       break;
    case B_CONTAINS: printf("Contains"); break;
    case B_MATCHES:  printf("Matches");  break;
    case B_REGEX:    printf("Regex");    break;
    case B_LIST:     printf("List");     break;
    case B_COUNT:
    case B_VALUE:
        printf("%s", comp->match == B_COUNT ? "Count" : "Value");

        switch (comp->relation) {
        case B_GT: printf(" >");  break;
        case B_GE: printf(" >="); break;
        case B_LT: printf(" <");  break;
        case B_LE: printf(" <="); break;
        case B_NE: printf(" !="); break;
        case B_EQ: printf(" =="); break;
        }
        break;

    default: exit(1);
    }

    switch (comp->collation) {
    case B_OCTET:        printf(" (octet)");         break;
    case B_ASCIICASEMAP: printf(" (ascii-casemap)"); break;
    case B_ASCIINUMERIC: printf(" (ascii-numeric)"); break;
    }

    printf(" ]");
}

static const char *addrpart_to_string(int part)
{
    switch (part) {
    case B_ALL:       return "all";
    case B_LOCALPART: return "localpart";
    case B_DOMAIN:    return "domain";
    case B_USER:      return "user";
    case B_DETAIL:    return "detail";
    default:          return NULL;
    }
}

static const char *transform_to_string(int transform)
{
    switch (transform) {
    case B_RAW:     return "raw";
    case B_TEXT:    return "text";
    case B_CONTENT: return "content";
    default:        return NULL;
    }
}

static const char *datepart_to_string(int part)
{
    switch (part) {
    case B_YEAR:    return "year";
    case B_MONTH:   return "month";
    case B_DAY:     return "day";
    case B_DATE:    return "date";
    case B_JULIAN:  return "julian";
    case B_HOUR:    return "hour";
    case B_MINUTE:  return "minute";
    case B_SECOND:  return "second";
    case B_TIME:    return "time";
    case B_ISO8601: return "iso8601";
    case B_STD11:   return "std11";
    case B_ZONE:    return "zone";
    case B_WEEKDAY: return "weekday";
    default:        return NULL;
    }
}

static void print_zone(struct Zone *zone)
{
    if (zone->tag == B_TIMEZONE) {
        print_string("ZONE", zone->offset);
    }
    else {
        printf(" ZONE(ORIGINAL)");
    }
}

static void print_test(test_t *test)
{
    switch (test->type) {
    case BC_FALSE:
        printf("FALSE");
        break;

    case BC_TRUE:
        printf("TRUE");
        break;

    case BC_EXISTS:
        print_stringlist("EXISTS", test->u.sl);
        break;

    case BC_SIZE:
        printf("SIZE %s %d",
               (test->u.sz.t == B_OVER) ? "over" : "under", test->u.sz.n);
        break;

    case BC_ADDRESS:
        printf("ADDRESS");
        printf(" ADDRPART(%s)", addrpart_to_string(test->u.ae.addrpart));
        if (test->u.ae.comp.index) {
            printf(" INDEX(%d %s)", abs(test->u.ae.comp.index),
                   (test->u.ae.comp.index < 0) ? "[LAST]" : "");
        }
        print_comparator(&test->u.ae.comp);
        print_stringlist("\n\tHEADERS", test->u.ae.sl);
        print_stringlist(" PATTERNS", test->u.ae.pl);
        break;

    case BC_ENVELOPE:
        printf("ENVELOPE");
        printf(" ADDRPART(%s)", addrpart_to_string(test->u.ae.addrpart));
        print_comparator(&test->u.ae.comp);
        print_stringlist("\n\tHEADERS", test->u.ae.sl);
        print_stringlist(" PATTERNS", test->u.ae.pl);
        break;

    case BC_HEADER:
        printf("HEADER");
        if (test->u.hhs.comp.index) {
            printf(" INDEX(%d %s)", abs(test->u.hhs.comp.index),
                   (test->u.hhs.comp.index < 0) ? "[LAST]" : "");
        }
        print_comparator(&test->u.hhs.comp);
        print_stringlist("\n\tHEADERS", test->u.hhs.sl);
        print_stringlist(" PATTERNS", test->u.hhs.pl);
        break;

    case BC_BODY:
        printf("BODY");
        print_comparator(&test->u.b.comp);
        printf("\n\tTRANSFORM(%s)", transform_to_string(test->u.b.transform));
        printf(" OFFSET(%d)", test->u.b.offset);
        print_stringlist(" CONTENT-TYPES", test->u.b.content_types);
        print_stringlist(" PATTERNS", test->u.b.pl);
        break;

    case BC_DATE_ORIG:
    case BC_DATE:
        printf("DATE");
        if (test->u.dt.comp.index) {
            printf(" INDEX(%d %s)", abs(test->u.dt.comp.index),
                   (test->u.dt.comp.index < 0) ? "[LAST]" : "");
        }
        print_zone(&test->u.dt.zone);
        print_comparator(&test->u.dt.comp);
        printf("\n\tDATEPART(%s)", datepart_to_string(test->u.dt.date_part));
        print_string(" HEADER", test->u.dt.header_name);
        print_stringlist(" KEYS", test->u.dt.kl);
        break;

    case BC_CURRENTDATE_ORIG:
    case BC_CURRENTDATE:
        printf("CURRENTDATE");
        print_zone(&test->u.dt.zone);
        print_comparator(&test->u.dt.comp);
        printf("\n\tDATEPART(%s)", datepart_to_string(test->u.dt.date_part));
        print_stringlist(" KEYS", test->u.dt.kl);
        break;

    case BC_HASFLAG:
        printf("HASFLAG");
        print_comparator(&test->u.hhs.comp);
        print_stringlist("\n\tVARIABLES", test->u.hhs.sl);
        print_stringlist(" PATTERNS", test->u.hhs.pl);
        break;

    case BC_MAILBOXEXISTS:
        print_stringlist("MAILBOXEXISTS", test->u.mm.keylist);
        break;

    case BC_MAILBOXIDEXISTS:
        print_stringlist("MAILBOXIDEXISTS", test->u.mm.keylist);
        break;

    case BC_METADATA:
        printf("METADATA");
        print_comparator(&test->u.mm.comp);
        print_string("\n\tMAILBOX", test->u.mm.extname);
        print_string(" ANNOTATION", test->u.mm.keyname);
        print_stringlist(" PATTERNS", test->u.mm.keylist);
        break;

    case BC_METADATAEXISTS:
        printf("METAEXISTS");
        print_string("MAILBOX", test->u.mm.extname);
        print_stringlist(" ANNOTATIONS", test->u.mm.keylist);
        break;

    case BC_SERVERMETADATA:
        printf("SERVERMETADATA");
        print_comparator(&test->u.mm.comp);
        print_string("\n\tANNOTATION", test->u.mm.keyname);
        print_stringlist(" PATTERNS", test->u.mm.keylist);
        break;

    case BC_SERVERMETADATAEXISTS:
        print_stringlist("SERVERMETADATAEXISTS", test->u.mm.keylist);
        break;

    case BC_STRING:
        printf("STRING");
        print_comparator(&test->u.hhs.comp);
        print_stringlist("\n\tVARIABLES", test->u.hhs.sl);
        print_stringlist(" PATTERNS", test->u.hhs.pl);
        break;

    case BC_VALIDEXTLIST:
        print_stringlist("VALIDEXTLIST", test->u.sl);
        break;

    case BC_VALIDNOTIFYMETHOD:
        print_stringlist("VALIDNOTIFYMETHOD", test->u.sl);
        break;

    case BC_NOTIFYMETHODCAPABILITY:
        printf("NOTIFYMETHODCAPABILITY");
        print_comparator(&test->u.mm.comp);
        print_string("\n\tURI", test->u.mm.extname);
        print_string(" CAPABILITY", test->u.mm.keyname);
        print_stringlist(" KEYS", test->u.mm.keylist);
        break;

    case BC_DUPLICATE:
        printf("DUPLICATE");
        print_string((test->u.dup.idtype == B_UNIQUEID) ?
                     " UNIQUEID" : " HDRNAME", test->u.dup.idval);
        print_string(" HANDLE", test->u.dup.handle);
        printf("\n\tSECONDS(%d) LAST(%d)",
                     test->u.dup.seconds, test->u.dup.last);
        break;

    case BC_IHAVE:
        print_stringlist("IHAVE", test->u.sl);
        break;

    case BC_SPECIALUSEEXISTS:
        printf("SPECIALUSEEXISTS");
        print_string("MAILBOX", test->u.mm.extname);
        print_stringlist(" FLAGS", test->u.mm.keylist);
        break;

    case BC_ENVIRONMENT:
        printf("ENVIRONMENT");
        print_comparator(&test->u.mm.comp);
        print_string("\n\tITEM", test->u.mm.keyname);
        print_stringlist(" KEYS", test->u.mm.keylist);
        break;

    case BC_PROCESSIMIP:
        printf("PROCESSIMIP INVITESONLY(%d) UPDATESONLY(%d) DELETECANCELED(%d)",
               !!test->u.imip.invites_only,
               !!test->u.imip.updates_only, !!test->u.imip.delete_canceled);
        print_string(" CALENDARID", test->u.imip.calendarid);
        print_string(" ERRSTR", test->u.imip.errstr_var);
        break;

#ifdef WITH_JMAP
    case BC_JMAPQUERY: {
        json_error_t jerr;
        json_t *jquery = json_loads(test->u.jquery, 0, &jerr);
        char *json = json_dumps(jquery, JSON_INDENT(2));

        printf("JMAPQUERY");
        print_string(" ", json);
        json_decref(jquery);
        free(json);
        break;
    }
#endif
    }

    printf("\n");
}

static int dump2_test(bytecode_input_t *d, int i, int version)
{
    test_t test;
    int len;

    /* there is no short circuiting involved here */
    i = bc_test_parse(d, i, version, &test);

    switch (test.type) {
    case BC_NOT:
        printf("NOT ");
        i = dump2_test(d, i, version);
        break;

    case BC_ANYOF:
    case BC_ALLOF:
        len = test.u.aa.ntests;

        printf("%s({%d}\n\t",
               (test.type == BC_ANYOF) ? "ANYOF" : "ALLOF", len);

        while (len--) {
            i = dump2_test(d, i, version);
            printf("\t");
        }
        printf(")\n");
        break;

    default:
        print_test(&test);
        break;
    }

    return i;
}

static void dump2(bytecode_input_t *d, int bc_len)
{
    int i;
    int version, requires;

    if (!d) return;

    i = bc_header_parse(d, &version, &requires);
    if (i <  0) {
        printf("not a bytecode file [magic number test failed]\n");
        return;
    }

    printf("Bytecode version: %d\n", version);
    if (version >= 0x11) {
        printf("Require:");
        if (requires & BFE_VARIABLES) printf(" Variables");
        printf("\n");
    }
    printf("\n");

    while (i < bc_len) {
        commandlist_t cmd;

        printf("%04d: ", i);

        i = bc_action_parse(d, i, version, &cmd);

        switch (cmd.type) {
        case B_STOP:
            printf("STOP");
            break;

            
        case B_KEEP_ORIG:
        case B_KEEP_COPY:
        case B_KEEP:
            printf("KEEP");
            if (cmd.type >= B_KEEP_COPY) {
                print_stringlist(" FLAGS", cmd.u.k.flags);
            }
            break;


        case B_DISCARD:
            printf("DISCARD");
            break;


        case B_EREJECT:
            printf("E");

            GCC_FALLTHROUGH

        case B_REJECT:
            print_string("REJECT ", cmd.u.str);
            break;


        case B_ERROR:
            print_string("ERROR ", cmd.u.str);
            break;


        case B_FILEINTO_ORIG:
        case B_FILEINTO_COPY:
        case B_FILEINTO_FLAGS:
        case B_FILEINTO_CREATE:
        case B_FILEINTO_SPECIALUSE:
        case B_FILEINTO:
            printf("FILEINTO");
            if (cmd.type >= B_FILEINTO_COPY) {
                printf(" COPY(%d)", cmd.u.f.copy);

                if (cmd.type >= B_FILEINTO_FLAGS) {
                    print_stringlist(" FLAGS", cmd.u.f.flags);

                    if (cmd.type >= B_FILEINTO_CREATE) {
                        printf("\n\tCREATE(%d)", cmd.u.f.create);

                        if (cmd.type >= B_FILEINTO_SPECIALUSE) {
                            print_string(" SPECIALUSE", cmd.u.f.specialuse);

                            if (cmd.type >= B_FILEINTO) {
                                print_string(" MAILBOXID", cmd.u.f.mailboxid);
                            }
                        }
                    }
                }
            }
            print_string(" FOLDER", cmd.u.f.folder);
            break;


        case B_REDIRECT_ORIG:
        case B_REDIRECT_COPY:
        case B_REDIRECT_LIST:
        case B_REDIRECT:
            printf("REDIRECT");
            if (cmd.type >= B_REDIRECT_COPY) {
                printf(" COPY(%d)", cmd.u.r.copy);

                if (cmd.type >= B_REDIRECT_LIST) {
                    printf( "LIST(%d)", cmd.u.r.list);

                    if (cmd.type >= B_REDIRECT) {
                        print_string(" BYTIME", cmd.u.r.bytime);
                        print_string(" BYMODE", cmd.u.r.bymode);
                        printf(" BYTRACE(%d)", cmd.u.r.bytrace);
                        print_string("\n\tDSN-NOTIFY", cmd.u.r.dsn_notify);
                        print_string(" DSN-RET", cmd.u.r.dsn_ret);
                    }
                }
            }
            print_string(" ADDRESS", cmd.u.r.address);
            break;


        case B_IF:
            printf("IF (ends at %d) ", cmd.u.i.testend);
            i = dump2_test(d, i, version);
            break;


        case B_MARK:
            printf("MARK");
            break;


        case B_UNMARK:
            printf("UNMARK");
            break;


        case B_ADDFLAG_ORIG:
        case B_ADDFLAG:
            printf("ADDFLAG");
            if (cmd.type >= B_ADDFLAG)
                print_string(" VARIABLE", cmd.u.fl.variable);
            print_stringlist(" FLAGS", cmd.u.fl.flags);
            break;


        case B_SETFLAG_ORIG:
        case B_SETFLAG:
            printf("SETFLAG");
            if (cmd.type >= B_SETFLAG)
                print_string(" VARIABLE", cmd.u.fl.variable);
            print_stringlist(" FLAGS", cmd.u.fl.flags);
            break;


        case B_REMOVEFLAG_ORIG:
        case B_REMOVEFLAG:
            printf("REMOVEFLAG");
            if (cmd.type >= B_REMOVEFLAG)
                print_string(" VARIABLE", cmd.u.fl.variable);
            print_stringlist(" FLAGS", cmd.u.fl.flags);
            break;


        case B_DENOTIFY:
            printf("DENOTIFY PRIORITY(%d)", cmd.u.d.priority);
            if (cmd.u.d.pattern) {
                print_comparator(&cmd.u.d.comp);
                print_string("\n\tPATTERN", cmd.u.d.pattern);
            }
            break;


        case B_ENOTIFY:
            printf("E");

            GCC_FALLTHROUGH

        case B_NOTIFY:
            printf("NOTIFY ");
            print_string(" METHOD", cmd.u.n.method);
            if (cmd.type == B_ENOTIFY) {
                printf(" IMPORTANCE(%d)", cmd.u.n.priority);
                print_string(" FROM", cmd.u.n.from);
            }
            else {
                printf(" PRIORITY(%d)", cmd.u.n.priority);
                print_string(" ID", cmd.u.n.id);
            }
            print_stringlist(" OPTIONS", cmd.u.n.options);
            print_string("\n\tMESSAGE", cmd.u.n.message);
            break;


        case B_VACATION_ORIG:
        case B_VACATION_SEC:
        case B_VACATION_FCC_ORIG:
        case B_VACATION_FCC_SPLUSE:
        case B_VACATION:
            printf("VACATION");
            print_stringlist(" ADDR", cmd.u.v.addresses);
            print_string("\n\tSUBJ", cmd.u.v.subject);
            print_string("\n\tMESG", cmd.u.v.message);
            printf("\n\tSECONDS(%d) MIME(%d)",
                   cmd.u.v.seconds * (cmd.type == B_VACATION_ORIG ? DAY2SEC : 1),
                   cmd.u.v.mime);

            if (version >= 0x05) {
                print_string(" FROM", cmd.u.v.from);
                print_string(" HANDLE", cmd.u.v.handle);

                if (cmd.type >= B_VACATION_FCC_ORIG) {
                    print_string("\n\tFCC", cmd.u.v.fcc.folder);

                    if (cmd.u.v.fcc.folder) {
                        printf(" CREATE(%d)", cmd.u.v.fcc.create);
                        print_stringlist(" FLAGS", cmd.u.v.fcc.flags);

                        if (cmd.type >= B_VACATION_FCC_SPLUSE) {
                            print_string("\n\tSPECIALUSE",
                                         cmd.u.v.fcc.specialuse);

                            if (cmd.type >= B_VACATION) {
                                print_string(" MAILBOXID",
                                             cmd.u.v.fcc.mailboxid);
                            }
                        }
                    }
                }
            }
            break;


        case B_NULL:
            printf("NULL");
            break;


        case B_JUMP:
            printf("JUMP %d", cmd.u.jump);
            break;


        case B_INCLUDE:
            printf("INCLUDE LOCATION(%s) ONCE(%d) OPTIONAL(%d)",
                   (cmd.u.inc.location == B_PERSONAL) ? "Personal" : "Global",
                   !!cmd.u.inc.once, !!cmd.u.inc.optional);
            print_string("\n\tSCRIPT", cmd.u.inc.script);
            break;


        case B_SET:
            printf("SET LOWER(%d) UPPER(%d)",
                   cmd.u.s.modifiers & BFV_LOWER,
                   cmd.u.s.modifiers & BFV_UPPER);
            printf(" LOWERFIRST(%d) UPPERFIRST(%d)",
                   cmd.u.s.modifiers & BFV_LOWERFIRST,
                   cmd.u.s.modifiers & BFV_UPPERFIRST);
            printf("\n\tQUOTEWILDCARD(%d) QUOTEREGEX(%d)",
                   cmd.u.s.modifiers & BFV_QUOTEWILDCARD,
                   cmd.u.s.modifiers & BFV_QUOTEREGEX);
            printf(" ENCODEURL(%d) LENGTH(%d)",
                   cmd.u.s.modifiers & BFV_ENCODEURL,
                   cmd.u.s.modifiers & BFV_LENGTH);
            print_string("\n\tVARIABLE", cmd.u.s.variable);
            print_string(" VALUE", cmd.u.s.value);
            break;


        case B_ADDHEADER:
            printf("ADDHEADER INDEX(%d)", cmd.u.ah.index);
            print_string(" NAME", cmd.u.ah.name);
            print_string(" VALUE", cmd.u.ah.value);
            break;


        case B_DELETEHEADER:
            printf("DELETEHEADER INDEX(%d)", cmd.u.dh.comp.index);
            print_comparator(&cmd.u.dh.comp);
            print_string("\n\tNAME", cmd.u.dh.name);
            print_stringlist(" VALUES", cmd.u.dh.values);
            break;


        case B_LOG:
            printf("LOG TEXT(%s)", cmd.u.l.text);
            break;


        case B_RETURN:
            printf("RETURN");
            break;


        case B_SNOOZE_ORIG:
        case B_SNOOZE_TZID:
        case B_SNOOZE: {
            const char *sep = "";
            int i;

            printf("SNOOZE");
            if (cmd.type >= B_SNOOZE_TZID) {
                if (cmd.type >= B_SNOOZE) {
                    print_string(" MAILBOX", cmd.u.sn.f.folder);
                    print_string(" MAILBOXID", cmd.u.sn.f.mailboxid);
                    print_string(" SPECIALUSE", cmd.u.sn.f.specialuse);
                    printf(" CREATE(%d)", cmd.u.sn.f.create);
                }
                else {
                    print_string(cmd.u.sn.is_mboxid ? " MAILBOXID" : " MAILBOX",
                                 cmd.u.sn.f.folder);
                }

                print_string(" TZID", cmd.u.sn.tzid);
            }
            print_stringlist("\n\tADDFLAGS", cmd.u.sn.addflags);
            print_stringlist("\n\tREMOVEFLAGS", cmd.u.sn.removeflags);
            printf("\n\tWEEKDAYS [");
            for (i = 0; i < 7; i++) {
                if (cmd.u.sn.days & (1<<i)) {
                    printf("%s %u", sep, i);
                    sep = ",";
                }
            }
            printf(" ]");
            print_vallist("\n\tTIMES", cmd.u.sn.times, &print_time);
            break;
        }


        default:
            printf("%d (NOT AN OP)\n", cmd.type);
            exit(1);
        }

        printf("\n");
    }

    printf("full len is: %d\n", bc_len);
}


/***********  Functions for generating a Sieve script from bytecode  ***********/


static void generate_token(const char *token, unsigned indent, struct buf *buf)
{
    if (token) buf_printf(buf, "%*s%s", indent, "", token);
}

static void generate_number(const char *tag, unsigned n, struct buf *buf)
{
    if (tag) buf_printf(buf, " %s", tag);
    buf_printf(buf, " %d", n);
}

static void generate_switch_capa(const char *tag, int i,
                                 unsigned long long capa,
                                 unsigned long long *requires,
                                 struct buf *buf)
{
    if (i) {
        if (requires) *requires |= capa;

        buf_printf(buf, " %s", tag);
    }
}

static void generate_switch(const char *tag, int i, struct buf *buf)
{
    generate_switch_capa(tag, i, 0, NULL, buf);
}

static void generate_string_capa(const char *tag, const char *s,
                                 unsigned long long capa,
                                 unsigned long long *requires,
                                 struct buf *buf)
{
    if (s && *s) {
        char *has_lf = strrchr(s, '\n');

        if (requires) *requires |= capa;

        generate_token(tag, 1, buf);
        if (has_lf) {
            buf_printf(buf, " text:\n%s%s.\n", s,
                       (size_t) (has_lf - s) == strlen(s) - 1 ? "" : "\n");
        }
        else buf_printf(buf, " \"%s%s\"", *s == '\\' ? "\\" : "", s);
    }
}

static void generate_string(const char *tag, const char *s,
                            struct buf *buf)
{
    generate_string_capa(tag, s, 0, NULL, buf);
}

static void generate_stringlist_capa(const char *tag, const strarray_t *sl,
                                     unsigned long long capa,
                                     unsigned long long *requires,
                                     struct buf *buf)
{
    int i, len = strarray_size(sl);
    const char *sep = " [";

    if (!len) return;

    if (requires) *requires |= capa;

    if (tag) buf_printf(buf, " %s", tag);

    if (len == 1) sep = " ";
    for (i = 0; i < len; i++) {
        const char *s = strarray_nth(sl, i);

        buf_printf(buf, "%s\"%s%s\"", sep, *s == '\\' ? "\\" : "", s);
        sep = ", ";
    }
    if (len > 1) buf_putc(buf, ']');
}

static void generate_stringlist(const char *tag, const strarray_t *sl,
                                struct buf *buf)
{
    generate_stringlist_capa(tag, sl, 0, NULL, buf);
}

static void generate_time(uint64_t t, struct buf *buf)
{
    buf_printf(buf, "\"%02" PRIu64 ":%02" PRIu64 ":%02" PRIu64 "\"",
                    t / 3600, (t % 3600) / 60, t % 60);
}

static void generate_valuelist(const char *name, const arrayu64_t *vl,
                               void (*gen_cb)(uint64_t, struct buf *),
                               struct buf *buf)
{
    int i, len = arrayu64_size(vl);
    const char *sep = " [";

    if (!len) return;

    if (name) buf_printf(buf, " %s", name);

    if (len == 1) sep = " ";
    for (i = 0; i < len; i++) {
        const uint64_t u = arrayu64_nth(vl, i);

        if (gen_cb) {
            buf_appendcstr(buf, sep);
            gen_cb(u, buf);
        }
        else buf_printf(buf, "%s%" PRIu64, sep, u);
        sep = ", ";
    }
    if (len > 1) buf_putc(buf, ']');
}

static void generate_index(int index,
                           unsigned long long *requires, struct buf *buf)
{
    if (index) {
        if (requires) *requires |= SIEVE_CAPA_INDEX;
        generate_number(":index", abs(index), buf);
        generate_switch(":last", (index < 0), buf);
    }
}

static void generate_comparator(const comp_t *c,
                                unsigned long long *requires, struct buf *buf)
{
    switch (c->match) {
    case B_IS: /* default */
        break;
    case B_CONTAINS:
        buf_printf(buf, " :contains");
        break;
    case B_MATCHES:
        buf_printf(buf, " :matches");
        break;
    case B_REGEX:
        buf_printf(buf, " :regex");
        *requires |= SIEVE_CAPA_REGEX;
        break;
    case B_LIST:
        buf_printf(buf, " :list");
        *requires |= SIEVE_CAPA_EXTLISTS;
        break;
    case B_COUNT:
    case B_VALUE:
        buf_printf(buf, " :%s", c->match == B_COUNT ? "count" : "value");
        *requires |= SIEVE_CAPA_RELATIONAL;

        switch (c->relation) {
        case B_GT: buf_printf(buf, " \"gt\""); break;
        case B_GE: buf_printf(buf, " \"ge\""); break;
        case B_LT: buf_printf(buf, " \"lt\""); break;
        case B_LE: buf_printf(buf, " \"le\""); break;
        case B_NE: buf_printf(buf, " \"ne\""); break;
        case B_EQ: buf_printf(buf, " \"eq\""); break;
        }
        break;
    }

    switch (c->collation) {
    case B_ASCIICASEMAP: /* default */
        break;
    case B_OCTET:
        buf_printf(buf, " :comparator \"i;octet\"");
        break;
    case B_ASCIINUMERIC:
        buf_printf(buf, " :comparator \"i;ascii-numeric\"");
        *requires |= SIEVE_CAPA_COMP_NUMERIC;
        break;
    }
}

static void generate_fileinto(struct Fileinto *f,
                              int is_fcc,
                              unsigned long long *requires,
                              struct buf *buf)
{
    if (is_fcc) {
        /* Put :fcc first */
        generate_string(":fcc", f->folder, buf);
        *requires |= SIEVE_CAPA_FCC;
    }
    generate_switch_capa(":copy", f->copy,
                         SIEVE_CAPA_COPY, requires, buf);
    generate_switch_capa(":create", f->create,
                         SIEVE_CAPA_MAILBOX, requires, buf);
    generate_string_capa(":specialuse", f->specialuse,
                         SIEVE_CAPA_SPECIAL_USE, requires, buf);
    generate_string_capa(":mailboxid", f->mailboxid,
                         SIEVE_CAPA_MAILBOXID, requires, buf);
    generate_stringlist_capa(":flags", f->flags,
                             SIEVE_CAPA_IMAP4FLAGS, requires, buf);
    if (!is_fcc) {
        /* folder is positional and MUST be last for fileinto */
        generate_string(NULL, f->folder, buf);
    }
}

static void generate_zone(struct Zone *zone, struct buf *buf)
{
    if (zone->tag == B_TIMEZONE) {
        generate_string(":zone", zone->offset, buf);
    }
    else {
        generate_switch(":originalzone",
                        zone->tag == B_ORIGINALZONE, buf);
    }
}


#define INSERT_FOLD(indent, buf) buf_printf(buf, "\n%*s", indent, "");

static int generate_test(bytecode_input_t *bc, int pos, int version,
                         unsigned indent, unsigned long long *requires,
                         struct buf *buf)
{
    test_t test;

    /* there is no short circuiting involved here */
    pos = bc_test_parse(bc, pos, version, &test);

    switch (test.type) {
    case BC_NOT:
        buf_appendcstr(buf, "not ");
        pos = generate_test(bc, pos, version, indent, requires, buf);
        break;

    case BC_ANYOF:
    case BC_ALLOF: {
        int len = test.u.aa.ntests;
        char sep = 0;

        buf_printf(buf, "%s (", (test.type == BC_ANYOF) ? "anyof" : "allof");

        while (len--) {
            if (sep) {
                buf_putc(buf, sep);
                INSERT_FOLD(indent, buf);
            }
            pos = generate_test(bc, pos, version, indent, requires, buf);
            sep = ',';
        }
        buf_putc(buf, ')');
        break;
    }

    case BC_FALSE:
        generate_token("false", 0, buf);
        break;

    case BC_TRUE:
        generate_token("true", 0, buf);
        break;

    case BC_EXISTS:
        generate_token("exists", 0, buf);
        generate_stringlist(NULL, test.u.sl, buf);
        break;

    case BC_SIZE:
        generate_token("size", 0, buf);
        generate_number((test.u.sz.t == B_OVER) ? ":over" : ":under",
                        test.u.sz.n, buf);
        break;

    case BC_ADDRESS:
        generate_token("address", 0, buf);
        generate_index(test.u.ae.comp.index, requires, buf);
        generate_comparator(&test.u.ae.comp, requires, buf);
        if (test.u.ae.addrpart != B_ALL) {
            buf_printf(buf, " :%s", addrpart_to_string(test.u.ae.addrpart));
        }
        generate_stringlist(NULL, test.u.ae.sl, buf);
        generate_stringlist(NULL, test.u.ae.pl, buf);
        break;

    case BC_ENVELOPE:
        *requires |= SIEVE_CAPA_ENVELOPE;
        generate_token("envelope", 0, buf);
        if (test.u.ae.addrpart != B_ALL) {
            buf_printf(buf, " :%s", addrpart_to_string(test.u.ae.addrpart));
        }
        generate_comparator(&test.u.ae.comp, requires, buf);
        generate_stringlist(NULL, test.u.ae.sl, buf);
        generate_stringlist(NULL, test.u.ae.pl, buf);
        break;

    case BC_HEADER:
        generate_token("header", 0, buf);
        generate_index(test.u.hhs.comp.index, requires, buf);
        generate_comparator(&test.u.hhs.comp, requires, buf);
        generate_stringlist(NULL, test.u.hhs.sl, buf);
        generate_stringlist(NULL, test.u.hhs.pl, buf);
        break;

    case BC_BODY:
        *requires |= SIEVE_CAPA_BODY;
        generate_token("body", 0, buf);
        generate_comparator(&test.u.b.comp, requires, buf);
        if (test.u.b.transform != B_TEXT) {
            buf_printf(buf, " :%s", transform_to_string(test.u.b.transform));
            generate_stringlist(NULL, test.u.b.content_types, buf);
        }
        generate_stringlist(NULL, test.u.b.pl, buf);
        break;

    case BC_DATE_ORIG:
    case BC_DATE:
        *requires |= SIEVE_CAPA_DATE;
        generate_token("date", 0, buf);
        generate_index(test.u.hhs.comp.index, requires, buf);
        generate_zone(&test.u.dt.zone, buf);
        generate_comparator(&test.u.dt.comp, requires, buf);
        generate_string(NULL, datepart_to_string(test.u.dt.date_part), buf);
        generate_stringlist(NULL, test.u.dt.kl, buf);
        break;

    case BC_CURRENTDATE_ORIG:
    case BC_CURRENTDATE:
        *requires |= SIEVE_CAPA_DATE;
        generate_token("currentdate", 0, buf);
        generate_zone(&test.u.dt.zone, buf);
        generate_comparator(&test.u.dt.comp, requires, buf);
        generate_string(NULL, datepart_to_string(test.u.dt.date_part), buf);
        generate_stringlist(NULL, test.u.dt.kl, buf);
        break;

    case BC_HASFLAG:
        *requires |= SIEVE_CAPA_IMAP4FLAGS;
        generate_token("hasflag", 0, buf);
        generate_comparator(&test.u.hhs.comp, requires, buf);
        generate_stringlist(NULL, test.u.hhs.sl, buf);
        generate_stringlist(NULL, test.u.hhs.pl, buf);
        break;

    case BC_MAILBOXEXISTS:
        *requires |= SIEVE_CAPA_MAILBOX;
        generate_token("mailboxexists", 0, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_MAILBOXIDEXISTS:
        *requires |= SIEVE_CAPA_MAILBOXID;
        generate_token("mailboxidexists", 0, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_METADATA:
        *requires |= SIEVE_CAPA_MBOXMETA;
        generate_token("metadata", 0, buf);
        generate_comparator(&test.u.mm.comp, requires, buf);
        generate_string(NULL, test.u.mm.extname, buf);
        generate_string(NULL, test.u.mm.keyname, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_METADATAEXISTS:
        *requires |= SIEVE_CAPA_MBOXMETA;
        generate_token("metadataexists", 0, buf);
        generate_string(NULL, test.u.mm.extname, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_SERVERMETADATA:
        *requires |= SIEVE_CAPA_SERVERMETA;
        generate_token("servermetadata", 0, buf);
        generate_comparator(&test.u.mm.comp, requires, buf);
        generate_string(NULL, test.u.mm.keyname, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_SERVERMETADATAEXISTS:
        *requires |= SIEVE_CAPA_SERVERMETA;
        generate_token("servermetadataexists", 0, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_STRING:
        *requires |= SIEVE_CAPA_VARIABLES;
        generate_token("string", 0, buf);
        generate_comparator(&test.u.hhs.comp, requires, buf);
        generate_stringlist(NULL, test.u.hhs.sl, buf);
        generate_stringlist(NULL, test.u.hhs.pl, buf);
        break;

    case BC_VALIDEXTLIST:
        *requires |= SIEVE_CAPA_EXTLISTS;
        generate_token("validlistext", 0, buf);
        generate_stringlist(NULL, test.u.sl, buf);
        break;

    case BC_VALIDNOTIFYMETHOD:
        *requires |= SIEVE_CAPA_ENOTIFY;
        generate_token("validnotifymethod", 0, buf);
        generate_stringlist(NULL, test.u.sl, buf);
        break;

    case BC_NOTIFYMETHODCAPABILITY:
        *requires |= SIEVE_CAPA_ENOTIFY;
        generate_token("notifymethodcapability", 0, buf);
        generate_comparator(&test.u.mm.comp, requires, buf);
        generate_string(NULL, test.u.mm.extname, buf);
        generate_string(NULL, test.u.mm.keyname, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_DUPLICATE:
        *requires |= SIEVE_CAPA_DUPLICATE;
        generate_token("duplicate", 0, buf);
        generate_string(":handle", test.u.dup.handle, buf);
        generate_string(test.u.dup.idtype == B_UNIQUEID ?
                        ":uniqueid" : ":header",
                        test.u.dup.idval, buf);
        generate_number(":seconds", test.u.dup.seconds, buf);
        generate_switch(":last", test.u.dup.last, buf);
        break;

    case BC_IHAVE:
        *requires |= SIEVE_CAPA_IHAVE;
        generate_token("ihave", 0, buf);
        generate_stringlist(NULL, test.u.sl, buf);
        break;

    case BC_SPECIALUSEEXISTS:
        *requires |= SIEVE_CAPA_SPECIAL_USE;
        generate_token("specialuseexists", 0, buf);
        generate_string(NULL, test.u.mm.extname, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_ENVIRONMENT:
        *requires |= SIEVE_CAPA_ENVIRONMENT;
        generate_token("environment", 0, buf);
        generate_comparator(&test.u.mm.comp, requires, buf);
        generate_string(NULL, test.u.mm.keyname, buf);
        generate_stringlist(NULL, test.u.mm.keylist, buf);
        break;

    case BC_PROCESSIMIP:
        *requires |= SIEVE_CAPA_IMIP;
        generate_token("processimip", 0, buf);
        generate_switch(":invitesonly", test.u.imip.invites_only, buf);
        generate_switch(":updatesonly", test.u.imip.updates_only, buf);
        generate_switch(":deletecanceled", test.u.imip.delete_canceled, buf);
        generate_string(":calendarid", test.u.imip.calendarid, buf);
        generate_string(":errstr", test.u.imip.errstr_var, buf);
        break;

#ifdef WITH_JMAP
    case BC_JMAPQUERY: {
        json_error_t jerr;
        json_t *jquery = json_loads(test.u.jquery, 0, &jerr);
        char *json = json_dumps(jquery, JSON_INDENT(2));

        *requires |= SIEVE_CAPA_JMAPQUERY;
        generate_token("jmapquery", 0, buf);
        generate_string(NULL, json, buf);
        json_decref(jquery);
        free(json);
        break;
    }
#endif
    }

    return pos;
}

static int generate_block(bytecode_input_t *bc, int pos, int end,
                          int version, int elsif, int indent,
                          unsigned long long *requires, struct buf *buf)
{
    while (pos < end) {
        commandlist_t cmd;

        pos = bc_action_parse(bc, pos, version, &cmd);

        switch (cmd.type) {
        case B_IF:
            generate_token(elsif ? "elsif " : "if ", indent, buf);
            pos = generate_test(bc, pos, version,
                                indent + 10 + 3 * elsif /* align tests */,
                                requires, buf);
            buf_appendcstr(buf, " {\n");

            /* then block */
            pos = bc_action_parse(bc, pos, version, &cmd);
            pos = generate_block(bc, pos, cmd.u.jump,
                                 version, 0, indent + 4, requires, buf);
            if (!elsif) generate_token("}\n", indent, buf);
            continue;

        case B_JUMP:
            /* else block */
            generate_token("}\n", indent - 4, buf);
            if (ntohl(bc[pos].op) == B_IF) {
                elsif = 1;
                indent -= 4;
            }
            else generate_token("else {\n", indent - 4, buf);

            pos = generate_block(bc, pos, cmd.u.jump,
                                 version, elsif, indent, requires, buf);
            continue;

        case B_STOP:
            generate_token("stop", indent, buf);
          break;
            
        case B_KEEP_ORIG:
        case B_KEEP_COPY:
        case B_KEEP:
            generate_token("keep", indent, buf);
            generate_stringlist_capa(":flags", cmd.u.k.flags,
                                     SIEVE_CAPA_IMAP4FLAGS, requires, buf);
            break;

        case B_DISCARD:
            generate_token("discard", indent, buf);
            break;

        case B_EREJECT:
            *requires |= SIEVE_CAPA_EREJECT;
            generate_token("ereject", indent, buf);
            generate_string(NULL, cmd.u.str, buf);
            break;

        case B_REJECT:
            *requires |= SIEVE_CAPA_REJECT;
            generate_token("reject", indent, buf);
            generate_string(NULL, cmd.u.str, buf);
            break;

        case B_ERROR:
            *requires |= SIEVE_CAPA_IHAVE;
            generate_token("error", indent, buf);
            generate_string(NULL, cmd.u.str, buf);
            break;

        case B_FILEINTO_ORIG:
        case B_FILEINTO_COPY:
        case B_FILEINTO_FLAGS:
        case B_FILEINTO_CREATE:
        case B_FILEINTO_SPECIALUSE:
        case B_FILEINTO:
            *requires |= SIEVE_CAPA_FILEINTO;
            generate_token("fileinto", indent, buf);
            generate_fileinto(&cmd.u.f, 0, requires, buf);
            break;

        case B_REDIRECT_ORIG:
        case B_REDIRECT_COPY:
        case B_REDIRECT_LIST:
        case B_REDIRECT:
            generate_switch_capa(":copy", cmd.u.r.copy,
                                 SIEVE_CAPA_COPY, requires, buf);
            generate_switch_capa(":list", cmd.u.r.list,
                                 SIEVE_CAPA_EXTLISTS, requires, buf);
            generate_string_capa(":notify", cmd.u.r.dsn_notify,
                                 SIEVE_CAPA_REDIR_DSN, requires, buf);
            generate_string_capa(":ret", cmd.u.r.dsn_ret,
                                 SIEVE_CAPA_REDIR_DSN, requires, buf); 
            if (cmd.u.r.bytime) {
                *requires |= SIEVE_CAPA_REDIR_DELBY;
                if (*cmd.u.r.bytime == '+') {
                    generate_number(":byrelativetime",
                                    strtoul(cmd.u.r.bytime, NULL, 10), buf);
                }
                else generate_string(":byabsolutetime", cmd.u.r.bytime, buf);
                INSERT_FOLD(indent + 4, buf);
            }
            generate_string_capa(":bymode", cmd.u.r.bymode,
                                 SIEVE_CAPA_REDIR_DELBY, requires, buf);
            generate_switch_capa(":bytrace", cmd.u.r.bytrace,
                                 SIEVE_CAPA_REDIR_DELBY, requires, buf);
            generate_string(NULL, cmd.u.r.address, buf);
            break;

        case B_MARK:
            *requires |= SIEVE_CAPA_IMAPFLAGS;
            generate_token("mark", indent, buf);
            break;

        case B_UNMARK:
            *requires |= SIEVE_CAPA_IMAPFLAGS;
            generate_token("unmark", indent, buf);
            break;

        case B_ADDFLAG_ORIG:
        case B_ADDFLAG:
            *requires |= SIEVE_CAPA_IMAP4FLAGS;
            generate_token("addflag", indent, buf);
            generate_string_capa(NULL, cmd.u.fl.variable,
                                 SIEVE_CAPA_VARIABLES, requires, buf);
            generate_stringlist(NULL, cmd.u.fl.flags, buf);
            break;

        case B_SETFLAG_ORIG:
        case B_SETFLAG:
            *requires |= SIEVE_CAPA_IMAP4FLAGS;
            generate_token("setflag", indent, buf);
            generate_string_capa(NULL, cmd.u.fl.variable,
                                 SIEVE_CAPA_VARIABLES, requires, buf);
            generate_stringlist(NULL, cmd.u.fl.flags, buf);
            break;

        case B_REMOVEFLAG_ORIG:
        case B_REMOVEFLAG:
            *requires |= SIEVE_CAPA_IMAP4FLAGS;
            generate_token("removeflag", indent, buf);
            generate_string_capa(NULL, cmd.u.fl.variable,
                                 SIEVE_CAPA_VARIABLES, requires, buf);
            generate_stringlist(NULL, cmd.u.fl.flags, buf);
            break;

        case B_DENOTIFY:
            *requires |= SIEVE_CAPA_NOTIFY;
            generate_token("denotify", indent, buf);
            if (cmd.u.d.pattern) {
                generate_comparator(&cmd.u.d.comp, requires, buf);
                generate_string(NULL, cmd.u.d.pattern, buf);
            }
            if (cmd.u.n.priority != B_NORMAL) {
                generate_switch(":low", cmd.u.d.priority == B_LOW, buf);
                generate_switch(":high", cmd.u.d.priority == B_HIGH, buf);
            }
            break;

        case B_ENOTIFY:
            *requires |= SIEVE_CAPA_ENOTIFY;
            generate_token("notify", indent, buf);
            generate_string(":from", cmd.u.n.from, buf);
            if (cmd.u.n.priority != B_NORMAL) {
                generate_string(":importance",
                                cmd.u.n.priority == B_LOW ? "1" : "3", buf);
            }
            generate_stringlist(":options", cmd.u.n.options, buf);
            generate_string(":message", cmd.u.n.message, buf);
            generate_string(NULL, cmd.u.n.method, buf);
            break;

        case B_NOTIFY:
            *requires |= SIEVE_CAPA_NOTIFY;
            generate_token("notify", indent, buf);
            generate_string(":method", cmd.u.n.method, buf);
            generate_string(":id", cmd.u.n.id, buf);
            if (cmd.u.n.priority != B_NORMAL) {
                generate_switch(":low", cmd.u.n.priority == B_LOW, buf);
                generate_switch(":high", cmd.u.n.priority == B_HIGH, buf);
            }
            generate_stringlist(":options", cmd.u.n.options, buf);
            generate_string(":message", cmd.u.n.message, buf);
            break;

        case B_VACATION_ORIG:
        case B_VACATION_SEC:
        case B_VACATION_FCC_ORIG:
        case B_VACATION_FCC_SPLUSE:
        case B_VACATION:
            *requires |= SIEVE_CAPA_VACATION;
            generate_token("vacation", indent, buf);
            if (!(cmd.u.v.seconds % 86400))
                generate_number(":days", cmd.u.v.seconds / 86400, buf);
            else {
                *requires |= SIEVE_CAPA_VACATION_SEC;
                generate_number(":seconds", cmd.u.v.seconds, buf);
            }
            generate_string(":subject", cmd.u.v.subject, buf);
            generate_string(":from", cmd.u.v.from, buf);
            generate_string(":handle", cmd.u.v.handle, buf);
            generate_stringlist(":addresses", cmd.u.v.addresses, buf);
            if (cmd.u.v.fcc.folder) {
                INSERT_FOLD(indent + 4, buf);
                generate_fileinto(&cmd.u.v.fcc, 1, requires, buf);
            }
            generate_switch(":mime", cmd.u.v.mime, buf);
            if (!strrchr(cmd.u.v.message, '\n')) INSERT_FOLD(indent + 4, buf);
            generate_string(NULL, cmd.u.v.message, buf);
            break;

        case B_NULL:
            break;

        case B_INCLUDE:
            *requires |= SIEVE_CAPA_INCLUDE;
            generate_token("include", indent, buf);
            if (cmd.u.inc.location == B_GLOBAL)
                generate_switch(":global", 1, buf);
            generate_switch(":once", cmd.u.inc.once, buf);
            generate_switch(":optional", cmd.u.inc.optional, buf);
            generate_string(NULL, cmd.u.inc.script, buf);
            break;

        case B_SET:
            *requires |= SIEVE_CAPA_VARIABLES;
            generate_token("set", indent, buf);
            generate_switch(":lower", cmd.u.s.modifiers & BFV_LOWER, buf);
            generate_switch(":upper", cmd.u.s.modifiers & BFV_UPPER, buf);
            generate_switch(":lowerfirst",
                            cmd.u.s.modifiers & BFV_LOWERFIRST, buf);
            generate_switch(":upperfirst",
                            cmd.u.s.modifiers & BFV_UPPERFIRST, buf);
            generate_switch(":quotewildcard",
                            cmd.u.s.modifiers & BFV_QUOTEWILDCARD, buf);
            generate_switch_capa(":quoteregex",
                                 cmd.u.s.modifiers & BFV_QUOTEREGEX,
                                 SIEVE_CAPA_REGEX, requires, buf);
            generate_switch_capa(":encodeurl",
                                 cmd.u.s.modifiers & BFV_ENCODEURL,
                                 SIEVE_CAPA_ENOTIFY, requires, buf);
            generate_switch(":length", cmd.u.s.modifiers & BFV_LENGTH, buf);
            generate_string(NULL, cmd.u.s.variable, buf);
            generate_string(NULL, cmd.u.s.value, buf);
            break;

        case B_ADDHEADER:
            *requires |= SIEVE_CAPA_EDITHEADER;
            generate_token("addheader", indent, buf);
            generate_switch(":last", (cmd.u.ah.index < 0), buf);
            generate_string(NULL, cmd.u.ah.name, buf);
            generate_string(NULL, cmd.u.ah.value, buf);
            break;

        case B_DELETEHEADER:
            *requires |= SIEVE_CAPA_EDITHEADER;
            generate_token("deleteheader", indent, buf);
            generate_index(cmd.u.dh.comp.index, NULL, buf);
            generate_comparator(&cmd.u.dh.comp, requires, buf);
            generate_string(NULL, cmd.u.dh.name, buf);
            generate_stringlist(NULL, cmd.u.dh.values, buf);
            break;

        case B_LOG:
            *requires |= SIEVE_CAPA_LOG;
            generate_token("log", indent, buf);
            generate_string(NULL, cmd.u.l.text, buf);
            break;

        case B_RETURN:
            *requires |= SIEVE_CAPA_INCLUDE;
            generate_token("return", indent, buf);
            break;

        case B_SNOOZE_ORIG:
        case B_SNOOZE_TZID:
        case B_SNOOZE:
            *requires |= SIEVE_CAPA_SNOOZE;
            if (cmd.u.sn.is_mboxid) {
                cmd.u.sn.f.mailboxid = cmd.u.sn.f.folder;
                cmd.u.sn.f.folder = NULL;
            }

            generate_token("snooze", indent, buf);
            generate_string(":mailbox", cmd.u.sn.f.folder, buf);
            generate_string_capa(":mailboxid", cmd.u.sn.f.mailboxid,
                                 SIEVE_CAPA_MAILBOXID, requires, buf);
            generate_string_capa(":specialuse", cmd.u.sn.f.specialuse,
                                 SIEVE_CAPA_SPECIAL_USE, requires, buf);
            generate_switch_capa(":create", cmd.u.sn.f.create,
                                 SIEVE_CAPA_MAILBOX, requires, buf);
            generate_stringlist_capa(":addflags", cmd.u.sn.addflags,
                                     SIEVE_CAPA_IMAP4FLAGS, requires, buf);
            generate_stringlist_capa(":removeflags", cmd.u.sn.removeflags,
                                     SIEVE_CAPA_IMAP4FLAGS, requires, buf);
            if (cmd.u.sn.days != SNOOZE_WDAYS_MASK) {
                const char *sep = " [";
                unsigned i;

                INSERT_FOLD(indent + 4, buf);
                generate_token(":weekdays", 1, buf);
                for (i = 0; i < 7; i++) {
                    if (cmd.u.sn.days & (1 << i)) {
                        buf_printf(buf, "%s\"%u\"", sep, i);
                        sep = ", ";
                    }
                }
                buf_putc(buf, ']');
            }
            generate_string(":tzid", cmd.u.sn.tzid, buf);
            generate_valuelist(NULL, cmd.u.sn.times, &generate_time, buf);
            break;

        default:
            fprintf(stderr, "%d (NOT AN OP)\n", cmd.type);
            exit(1);
        }

        buf_appendcstr(buf, ";\n");
    }

    return pos;
}

static void generate_script(bytecode_input_t *d, int bc_len)
{
    int i, version, req;
    unsigned long long requires = 0;
    struct buf buf = BUF_INITIALIZER;

    if (!d) return;

    i = bc_header_parse(d, &version, &req);
    if (i <  0) {
        fprintf(stderr, "not a bytecode file [magic number test failed]\n");
        return;
    }

    if (req & BFE_VARIABLES) requires |= SIEVE_CAPA_VARIABLES;

    generate_block(d, i, bc_len, version, 0, 0, &requires, &buf);

    if (requires) {
        unsigned long long capa;
        char *sep = "";
        int n;

        printf("require [");
        for (i = 0, n = 0, capa = 0x1; i < 64; capa <<= 1, i++) {
            if (requires & capa) {
                if (n && (n > 60)) {
                    sep = ",\n          ";
                    n = 0;
                }
                n += printf("%s\"%s\"", sep, lookup_capability_string(capa));
                sep = ", ";
            }
        }
        printf("];\n\n");
    }

    printf("%s", buf_cstring(&buf));
    buf_free(&buf);
}
