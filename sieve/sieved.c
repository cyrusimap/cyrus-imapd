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

static void dump2(bytecode_input_t *d, int len);
static int dump2_test(bytecode_input_t * d, int i, int version);

/* from bc_eval.c */
int unwrap_string(bytecode_input_t *bc, int pos, const char **str, int *len);

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

static int write_list(int list_len, int i, bytecode_input_t * d)
{
    int x;
    i++;
    for (x=0; x<list_len; x++)
    {
        const char *data;
        int len;

        i = unwrap_string(d, i, &data, &len);

        printf("{%d}%s\n", len, data);
    }
    return i;
}

static int printComparison(bytecode_input_t *d ,int i)
{
    printf("Comparison: ");
    switch(ntohl(d[i].value))
    {
    case B_IS: printf("Is"); break;
    case B_CONTAINS:printf("Contains"); break;
    case B_MATCHES: printf("Matches"); break;
    case B_REGEX: printf("Regex"); break;
    case B_LIST: printf("List"); break;
    case B_COUNT:
        printf("Count");

        switch(ntohl(d[i+1].value))
        {
        case B_GT: printf(" greater than "); break;
        case B_GE: printf(" greater than or equal "); break;
        case B_LT: printf(" less than "); break;
        case B_LE: printf(" less than or equal "); break;
        case B_NE: printf(" not equal "); break;
        case B_EQ: printf(" equal "); break;
        }

        break;
    case B_VALUE:
        printf("Value");

        switch(ntohl(d[i+1].value))
        {
        case B_GT: printf(" greater than "); break;
        case B_GE: printf(" greater than or equal ");break;
        case B_LT: printf(" less than ");    break;
        case B_LE: printf(" less than or equal ");break;
        case B_NE: printf(" not equal ");    break;
        case B_EQ: printf(" equal ");break;
        }

        break;
    default:
        exit(1);
    }

    switch (ntohl(d[i+2].value))
    {
    case B_ASCIICASEMAP: printf("   (ascii-casemap) "); break;
    case B_OCTET: printf("    (octet) "); break;
    case B_ASCIINUMERIC:  printf("   (ascii-numeric) "); break;
    default: exit(1);
    }

    printf("\n");
    return i+3;
}


static int dump2_test(bytecode_input_t * d, int i, int version)
{
    int l,x,index;
    int opcode;
    int has_index=0;/* used to differentiate between pre and post index tests */

    opcode = ntohl(d[i].value);
    switch(opcode) {
    case BC_FALSE:
        printf("false");
        i++;
        break;
    case BC_TRUE:
        printf("true");
        i++;
        break;
    case BC_NOT:/*2*/
        /* XXX
           there is a value being skipped in the second pass...
           no idea what it does, but it isn't carried to here...
           see bytecodee.c */
        printf(" not(");
        i=dump2_test(d, i+1, version);
        printf(")\n");
        break;
    case BC_EXISTS:
        printf("exists");
        i=write_list(ntohl(d[i+1].len), i+2, d);
        break;
    case BC_SIZE:
        printf("size");
        if (ntohl(d[i+1].value)==B_OVER) {
            /* over */
            printf("over %d", ntohl(d[i+2].value));
        } else {
            /* under */
            printf("under %d", ntohl(d[i+2].value));
        }
        i+=3;
        break;
    case BC_ANYOF:/*5*/
        printf("any of \n(");
        l=ntohl(d[i+1].len);
        i+=3;

        for (x=0; x<l; x++)
        {
            i=dump2_test(d, i, version);
            if((x+1)<l)
                printf(" OR ");
        }

        printf(")\n");
        break;
    case BC_ALLOF:/*6*/
        printf("all of \n(");
        l=ntohl(d[i+1].len);
        i+=3;

        for (x=0; x<l; x++)
        {
            i=dump2_test(d, i, version);
            if((x+1)<l)
                printf(" AND ");
        }

        printf(")\n");
        break;
    case BC_ADDRESS:/*13*/
        has_index=1;
        /*fall-through*/
    case BC_ADDRESS_PRE_INDEX:/*7*/
        if (0x07 == version && BC_ADDRESS_PRE_INDEX == opcode) {
            /* There was a version of the bytecode that had the index extension
             * but did not update the bytecode codepoints, nor did it increment
             * the bytecode version number.  This tests if the index extension
             * was in the bytecode based on the position of the match-type
             * argument.
             * We test for the applicable version number explicitly.
             */
            switch (ntohl(d[i+2].value)) {
            case B_IS:
            case B_CONTAINS:
            case B_MATCHES:
            case B_REGEX:
            case B_COUNT:
            case B_VALUE:
                has_index = 1;
                break;
            default:
                has_index = 0;
            }
        }
        printf("Address [");
        index = has_index ? ntohl(d[++i].value) : 0;
        i=printComparison(d, i+1);
        printf("               type: ");
        switch(ntohl(d[i++].value))
        {
        case B_ALL: printf("all"); break;
        case B_LOCALPART:printf("localpart"); break;
        case B_DOMAIN:printf("domain"); break;
        case B_USER:printf("user"); break;
        case B_DETAIL:printf("detail"); break;
        }
        printf("\n");
        if (index != 0) {
                printf("              Index: %d %s\n",
                    abs(index), index < 0 ? "[LAST]" : "");
        }
        printf("              Headers:");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("              Data:");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("             ]\n");
        break;
    case BC_ENVELOPE:/*8*/
        printf("Envelope [");
        i=printComparison(d, i+1);
        printf("                type: ");
        switch(ntohl(d[i++].value))
        {
        case B_ALL: printf("all"); break;
        case B_LOCALPART:printf("localpart"); break;
        case B_DOMAIN:printf("domain"); break;
        case B_USER:printf("user"); break;
        case B_DETAIL:printf("detail"); break;
        }
        printf("              Headers:");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("              Data:");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("             ]\n");
        break;
    case BC_HEADER:/*14*/
        has_index=1;
        /*fall-through*/
    case BC_HEADER_PRE_INDEX:/*9*/
        if (0x07 == version && BC_HEADER_PRE_INDEX == opcode) {
            /* There was a version of the bytecode that had the index extension
             * but did not update the bytecode codepoints, nor did it increment
             * the bytecode version number.  This tests if the index extension
             * was in the bytecode based on the position of the match-type
             * argument.
             * We test for the applicable version number explicitly.
             */
            switch (ntohl(d[i+2].value)) {
            case B_IS:
            case B_CONTAINS:
            case B_MATCHES:
            case B_REGEX:
            case B_COUNT:
            case B_VALUE:
                    has_index = 1;
                    break;
            default:
                    has_index = 0;
            }
        }
        printf("Header [");
        index = has_index ? ntohl(d[++i].value) : 0;
        i= printComparison(d, i+1);
        if (index != 0) {
                printf("              Index: %d %s\n",
                    abs(index), index < 0 ? "[LAST]" : "");
        }
        printf("              Headers: ");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("              Data: ");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("             ]\n");
        break;
    case BC_HASFLAG:/*15*/
    case BC_STRING:/*21*/
        if (BC_HASFLAG == opcode) {
            printf("Hasflag [");
        } else {
            printf("String [");
        }
        i= printComparison(d, i+1);
        printf("              Variables: ");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("              Data: ");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("             ]\n");
        break;
    case BC_BODY:/*10*/
        printf("Body [");
        i=printComparison(d, i+1);
        printf("              Transform: ");
        switch(ntohl(d[i++].value))
        {
        case B_RAW: printf("raw"); break;
        case B_TEXT:printf("text"); break;
        case B_CONTENT:printf("content"); break;
        }
        printf("\tOffset: %d\n", ntohl(d[i++].value));
        printf("              Content-Types:");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("              Data:");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("             ]\n");
        break;
    case BC_DATE:/*11*/
        has_index=1;
    case BC_CURRENTDATE:/*12*/
        if (0x07 == version) {
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
            switch (ntohl(d[i+4].value)) {
            /* if the 4th parameter is a comparator, we have neither :index nor
             *  :zone tags.  B_ORIGINALZONE is the first parameter.
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
                switch (ntohl(d[i+5].value)) {
                /* if the 5th paramater is a comparator, we have either :index
                 * or :zone, but not both.
                 */
                case B_ASCIICASEMAP:
                case B_OCTET:
                case B_ASCIINUMERIC:
                    /* The ambiguous case is B_TIMEZONE as 1st parameter and
                     * B_ORIGINALZONE as second parameter, which could mean
                     * either ':index 60 :originalzone' or ':zone "+0101"'
                     */
                    if (B_TIMEZONE == ntohl(d[i+1].value) &&
                            B_ORIGINALZONE == ntohl(d[i+2].value)) {
                        /* This is the ambiguous case.  Resolve the ambiguity
                         * by assuming that there is no :index tag since the
                         * unnumbered bytecode that shipped with Kolab
                         * Groupware 3.3 included support for the date
                         * extension, but not for the index extension.
                         */
                        has_index = 0;

                    } else if (B_TIMEZONE == ntohl(d[i+1].value)) {
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
                    /* if the 5th parameter is not a comparator, the 6th is,
                     * and we have both :index and :zone
                     */
                    has_index = 1;
                }
            }
        }
        ++i; /* skip opcode */

        if (BC_DATE == opcode) {
                printf("date [");
        }
        else {
                printf("currentdate [");
        }

        /* index */
        index = has_index ? ntohl(d[i++].value) : 0;
        if (index != 0) {
                printf("              Index: %d %s\n",
                    abs(index), index < 0 ? "[LAST]" : "");
        }

        /* zone tag */
        {
                printf("Zone-Tag: ");
                switch (ntohl(d[i++].value)) {
                case B_TIMEZONE:
                        printf("Specific timezone: offset by %d minutes.\n", ntohl(d[i++].value));
                        break;
                case B_ORIGINALZONE:
                        printf("Original zone.\n");
                        break;
                }
        }

        i=printComparison(d, i);

        printf("              Date-Type: ");
        switch(ntohl(d[i++].value))
        {
        case B_YEAR: printf("year\n"); break;
        case B_MONTH: printf("month\n"); break;
        case B_DAY: printf("day\n"); break;
        case B_JULIAN: printf("julian\n"); break;
        case B_HOUR: printf("hour\n"); break;
        case B_MINUTE: printf("minute\n"); break;
        case B_SECOND: printf("second\n"); break;
        case B_TIME: printf("time\n"); break;
        case B_ISO8601: printf("iso8601\n"); break;
        case B_STD11: printf("std11\n"); break;
        case B_ZONE: printf("zone\n"); break;
        case B_WEEKDAY: printf("weekday\n"); break;
        }

        /* header name */
        if (BC_DATE == opcode) {
                const char *data;
                int len;
                i = unwrap_string(d, i, &data, &len);
                printf("              Header Name: {%d}%s\n", len, data);
        }

        printf("              Key List: ");
        i=write_list(ntohl(d[i].len), i+1, d);
        printf("             ]\n");
        break;
    default:
        printf("WERT %d ", ntohl(d[i].value));
    }
    return i;
}

static void dump2(bytecode_input_t *d, int bc_len)
{
    int i;
    int version;
    const char *data;
    int len;

    if (!d) return;

    if (memcmp(d, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN)) {
        printf("not a bytecode file [magic number test failed]\n");
        return;
    }

    i = BYTECODE_MAGIC_LEN / sizeof(bytecode_input_t);

    version = ntohl(d[i].op);
    printf("Sievecode version %d\n", version);
    if (version >= 0x11 && ntohl(d[++i].value) & BFE_VARIABLES) {
        printf("Require Variables\n");
    }
    
    for(i++; i<bc_len;) 
    {
        int op;
        int copy = 0;
        int create = 0;
        int supports_variables = 0;

        printf("%d: ",i);

        op = ntohl(d[i++].op);
        switch (op) {

        case B_STOP:/*0*/
            printf("STOP\n");
            break;

        case B_KEEP:/*22*/
            printf("KEEP FLAGS {%d}\n", ntohl(d[i].listlen));
            i=write_list(ntohl(d[i].listlen), i+1, d);
            copy = ntohl(d[i++].value);
            printf("              COPY(%d)\n",copy);
            break;
        case B_KEEP_ORIG:/*1*/
            printf("KEEP\n");
            break;

        case B_DISCARD:/*2*/
            printf("DISCARD\n");
            break;

        case B_REJECT:/*3*/
        case B_EREJECT:/*31*/
            i = unwrap_string(d, i, &data, &len);
            printf("%s {%d}%s\n", (op == B_EREJECT) ? "EREJECT" : "REJECT",
                   len, data);
            break;

        case B_FILEINTO: /*24*/
            create = ntohl(d[i++].value);
            /* fall through */
        case B_FILEINTO_FLAGS:/*23*/
            printf("FILEINTO FLAGS {%d}\n", ntohl(d[i].listlen));
            i=write_list(ntohl(d[i].listlen), i+1, d);
            copy = ntohl(d[i++].value);
            i = unwrap_string(d, i, &data, &len);
            printf("              CREATE(%d) COPY(%d) FOLDER({%d}%s)\n",
                    create, copy, len, data);
            break;

        case B_FILEINTO_COPY : /*19*/
            copy = ntohl(d[i++].value);
            /* fall through */
        case B_FILEINTO_ORIG: /*4*/
            i = unwrap_string(d, i, &data, &len);
            printf("FILEINTO COPY(%d) CREATE(%d) FOLDER({%d}%s)\n",copy,create,len,data);
            break;

        case B_REDIRECT: /*20*/
            copy = ntohl(d[i++].value);
            /* fall through */
        case B_REDIRECT_ORIG: /*5*/
            i = unwrap_string(d, i, &data, &len);
            printf("REDIRECT COPY(%d) ADDRESS({%d}%s)\n",copy,len,data);
            break;

        case B_IF:/*6*/
            printf("IF (ends at %d)", ntohl(d[i].value));

            /* there is no short circuiting involved here*/
            i = dump2_test(d, i+1, version);
            printf("\n");

            break;

        case B_MARK:/*7*/
            printf("MARK\n");
            break;

        case B_UNMARK:/*8*/
            printf("UNMARK\n");
            break;

        case B_ADDFLAG: /*26*/
        case B_SETFLAG: /*27*/
        case B_REMOVEFLAG: /*28*/
            i = unwrap_string(d, i, &data, &len);
            supports_variables = 1;
            /* fall through */
        case B_ADDFLAG_ORIG: /*9*/
        case B_SETFLAG_ORIG: /*10*/
        case B_REMOVEFLAG_ORIG: /*11*/
            switch (op) {
            case B_ADDFLAG_ORIG:
            case B_ADDFLAG:
                printf("ADDFLAG ");
                break;
            case B_SETFLAG:
            case B_SETFLAG_ORIG:
                printf("SETFLAG ");
                break;
            case B_REMOVEFLAG:
            case B_REMOVEFLAG_ORIG:
                printf("REMOVEFLAG ");
                break;
            }
            if (supports_variables) {
                printf("VARIABLE({%d}%s) ", len, data);
            }
            printf("FLAGS {%d}\n",ntohl(d[i].len));
            i=write_list(ntohl(d[i].len),i+1,d);
            break;

        case B_DENOTIFY:/*12*/
            printf("DENOTIFY\n");
            printf("            PRIORITY(%d) Comparison type %d (relat %d)\n",
                   ntohl(d[i].value), ntohl(d[i+1].value), ntohl(d[i+2].value));
            i+=3;

            i = unwrap_string(d, i, &data, &len);

            printf("           ({%d}%s)\n", len, (!data ? "[nil]" : data));
            break;

        case B_NOTIFY: /*13*/
            i = unwrap_string(d, i, &data, &len);

            printf("NOTIFY METHOD({%d}%s)\n",len,data);

            i = unwrap_string(d, i, &data, &len);

            printf("            ID({%d}%s) OPTIONS ", len,
                   (!data ? "[nil]" : data));

            i=write_list(ntohl(d[i].len),i+1,d);

            printf("            PRIORITY(%d)\n", ntohl(d[i].value));
            i++;

            i = unwrap_string(d, i, &data, &len);

            printf("            MESSAGE({%d}%s)\n", len, data);

            break;

        case B_VACATION_ORIG:/*14*/
        case B_VACATION:/*22*/
            printf("VACATION\n");
            /*add address list here!*/
            i=write_list(ntohl(d[i].len),i+1,d);

            i = unwrap_string(d, i, &data, &len);

            printf("%d SUBJ({%d}%s) \n",i, len, (!data ? "[nil]" : data));

            i = unwrap_string(d, i, &data, &len);

            printf("%d MESG({%d}%s) \n", i, len, (!data ? "[nil]" : data));

            printf("SECONDS(%d) MIME(%d)\n", ntohl(d[i].value) * (op == B_VACATION ? 1: 24 * 60 * 60 /* 1 day */), ntohl(d[i+1].value));
            i+=2;

            if (version >= 0x05) {
                i = unwrap_string(d, i, &data, &len);

                printf("%d FROM({%d}%s) \n",i, len, (!data ? "[nil]" : data));

                i = unwrap_string(d, i, &data, &len);

                printf("%d HANDLE({%d}%s) \n",i, len, (!data ? "[nil]" : data));
            }

            break;
        case B_NULL:/*15*/
            printf("NULL\n");
            break;
        case B_JUMP:/*16*/
            printf("JUMP %d\n", ntohl(d[i].jump));
            i+=1;
            break;

        case B_INCLUDE:/*17*/
            printf("INCLUDE ");
            switch (ntohl(d[i].value) & 63) {
            case B_PERSONAL: printf("Personal"); break;
            case B_GLOBAL: printf("Global"); break;
            }
            printf(" once:%s optional:%s",
                ntohl(d[i].value) & 64 ? "yes" : "no",
                ntohl(d[i].value) & 128 ? "yes" : "no");
            i = unwrap_string(d, i+1, &data, &len);
            printf(" {%d}%s\n", len, data);
            break;

        case B_SET: /*25*/
        {
            int m = ntohl(d[i++].value);
            i = unwrap_string(d, i, &data, &len);
            printf("SET ");
            printf("LOWER(%d) UPPER(%d) LOWERFIRST(%d) UPPERFIRST(%d) "
                   "QUOTEWILDCARD(%d) LENGTH(%d)\n",
		   m & BFV_LOWER, m & BFV_UPPER, m & BFV_LOWERFIRST,
		   m & BFV_UPPERFIRST, m & BFV_QUOTEWILDCARD, m & BFV_LENGTH);
            printf("              VARS({%d}%s)", len, data);
            i = unwrap_string(d, i, &data, &len);
            printf(" VALS({%d}%s)\n", len, data);
        }
            break;

        case B_ADDHEADER: /*29*/
        {
            int m = ntohl(d[i++].value);
            printf("ADDHEADER ");
            printf("INDEX(%d)\n", m);
            i = unwrap_string(d, i, &data, &len);
            printf("              NAME({%d}%s)", len, data);
            i = unwrap_string(d, i, &data, &len);
            printf(" VAL({%d}%s)\n", len, data);
        }
            break;

        case B_DELETEHEADER: /*30*/
        {
            int m = ntohl(d[i++].value);
            printf("DELETEHEADER ");
            printf("INDEX(%d)\n", m);
            i = printComparison(d, i);
            i = unwrap_string(d, i, &data, &len);
            printf("              NAME({%d}%s)\n", len, data);
            printf("              VALS(");
            i=write_list(ntohl(d[i].len), i+1, d);
            printf(")\n");
        }
            break;

        case B_RETURN:/*18*/
            printf("RETURN\n");
            break;

        default:
            printf("%d (NOT AN OP)\n",ntohl(d[i-1].op));
            exit(1);
        }
    }
    printf("full len is: %d\n", bc_len);
}


