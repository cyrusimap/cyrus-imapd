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

#include "xmalloc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#include <string.h>

#include "map.h"
#include "times.h"

static void dump2(bytecode_input_t *d, int len);

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

    unsigned long len;

    if (argc!=2) {
         fprintf(stderr, "usage:\n %s script\n", argv[0]);
         exit(1);
    }

    /*get script*/
    script_fd = open(argv[1], O_RDONLY);
    if (script_fd == -1)
    {
        fprintf(stderr, "can not open script '%s'\n", argv[1]);
        exit(1);
    }

    len=load(script_fd,&bc);
    close(script_fd);

    if (bc) {
        dump2(bc, len );
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

    case BC_DATE:
        printf("DATE");
        if (test->u.dt.comp.index) {
            printf(" INDEX(%d %s)", abs(test->u.dt.comp.index),
                   (test->u.dt.comp.index < 0) ? "[LAST]" : "");
        }
        if (test->u.dt.zonetag == B_TIMEZONE)
            printf(" ZONE(%+dmin)", test->u.dt.zone);
        else
            printf(" ZONE(ORIGINAL)");
        print_comparator(&test->u.dt.comp);
        printf("\n\tDATEPART(%s)", datepart_to_string(test->u.dt.date_part));
        print_string(" HEADER", test->u.dt.header_name);
        print_stringlist(" KEYS", test->u.dt.kl);
        break;

    case BC_CURRENTDATE:
        printf("CURRENTDATE");
        if (test->u.dt.zonetag == B_TIMEZONE)
            printf(" ZONE(%+dmin)", test->u.dt.zone);
        else
            printf(" ZONE(ORIGINAL)");
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
        case B_VACATION_FCC:
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

                if (cmd.type >= B_VACATION_FCC) {
                    print_string("\n\tFCC", cmd.u.v.fcc.folder);

                    if (cmd.u.v.fcc.folder) {
                        printf(" CREATE(%d)", cmd.u.v.fcc.create);
                        print_stringlist(" FLAGS", cmd.u.v.fcc.flags);

                        if (cmd.type >= B_VACATION) {
                            print_string("\n\tSPECIALUSE",
                                         cmd.u.v.fcc.specialuse);
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
                   (cmd.u.inc.location = B_PERSONAL) ? "Personal" : "Global",
                   cmd.u.inc.once, cmd.u.inc.optional);
            print_string("\n\tSCRIPT", cmd.u.inc.script);
            break;


        case B_SET:
            printf("SET LOWER(%d) UPPER(%d)",
                   cmd.u.s.mod40 & BFV_LOWER, cmd.u.s.mod40 & BFV_UPPER);
            printf(" LOWERFIRST(%d) UPPERFIRST(%d)",
                   cmd.u.s.mod30 & BFV_LOWERFIRST,
                   cmd.u.s.mod30 & BFV_UPPERFIRST);
            printf("\n\tQUOTEWILDCARD(%d) QUOTEREGEX(%d)",
                   cmd.u.s.mod20 & BFV_QUOTEWILDCARD,
                   cmd.u.s.mod20 & BFV_QUOTEREGEX);
            printf(" ENCODEURL(%d) LENGTH(%d)",
                   cmd.u.s.mod15 & BFV_ENCODEURL, cmd.u.s.mod10 & BFV_LENGTH);
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


        default:
            printf("%d (NOT AN OP)\n", cmd.type);
            exit(1);
        }

        printf("\n");
    }

    printf("full len is: %d\n", bc_len);
}
