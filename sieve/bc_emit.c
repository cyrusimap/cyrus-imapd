/* bc_emit.c -- sieve bytecode - pass 2 of the compiler
 * Rob Siemborski
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

#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>


#if DUMPCODE
void dump(bytecode_info_t *d, int level);
#endif

static inline int write_int (int fd, int x)
{
    int y=htonl(x);
    return (write(fd, &y, sizeof(int)));
}


/* Pad null bytes onto the end of the string we just wrote */
/* returns -1 on failure or number of bytes written on success */
static int align_string(int fd, int string_len)
{
    /* Keep in mind that we always want to pad a string with *at least*
     * one zero, that's why sometimes we have to pad with 4 */
    int needed = sizeof(int) - (string_len % sizeof(int));
    if (needed>= 0 && needed <=4)
    {
        if (write(fd, "\0\0\0\0", needed) == -1) return -1;
    }
    return needed;
}

/*all functions keep codep up to date as they use it.
  the amount that has been written to the file is maintained by the
  filelen variable in bc_action_emit
  the other bc_xxx_emit funtions keep track of how much they (and any functions
  they call) have written and return this value
*/


/* Write out a stringlist to a given file descriptor.
 * return # of bytes written on success and -1 on error */

/* stringlist: <# listitems>
               <pos of listend (bytes)>
               <string:(size)(aligned string)>
*/
static int bc_stringlist_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int len = bc->data[(*codep)++].len;
    int i;
    int ret;
    int wrote = 2*sizeof(int);
    int begin,end;

    /* Write out number of items in the list */
    if (write_int(fd, len)== -1) return -1 ;

    /* skip one spot end of list position*/
    begin=lseek(fd,0,SEEK_CUR);
    lseek(fd,sizeof(int),SEEK_CUR);

    /* Loop through all the items of the list, writing out length and string
     * in sequence */
    for(i=0; i < len; i++)
    {
        int datalen = bc->data[(*codep)++].len;

        if(write_int(fd, datalen) == -1) return -1;
        wrote += sizeof(int);

        if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return -1;
        wrote += datalen;

        ret = align_string(fd,datalen);
        if(ret == -1) return -1;

        wrote+=ret;
    }
    end=lseek(fd,0,SEEK_CUR);
    if (end < 0) return -1;

    /* go back and write end of list position */
    lseek(fd,begin,SEEK_SET);
    if(write_int(fd, end) == -1) return -1;

    /* return to the end */
    lseek(fd,end,SEEK_SET);
    return wrote;
}

static int bc_test_emit(int fd, int *codep, bytecode_info_t *bc);

/* Write out a testlist to a given file descriptor.
 * return # of bytes written on success and -1 on error */
static int bc_testlist_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int len = bc->data[(*codep)++].len;
    int i;
    int ret;
    int begin, end;
    int wrote = 2*sizeof(int);

    /* Write out number of items in the list */
    if(write_int(fd, len)== -1) return -1;

    /* skip one spot for end of list position*/
    begin = lseek(fd, 0, SEEK_CUR);
    lseek(fd, sizeof(int), SEEK_CUR);

    /* Loop through all the items of the list, writing out each
     * test as we reach it in sequence. */
    for(i=0; i < len; i++) {
        int nextcodep = bc->data[(*codep)++].jump;

        ret = bc_test_emit(fd, codep, bc);
        if(ret < 0 ) return -1;

        wrote+=ret;
        *codep = nextcodep;
    }
    end = lseek(fd, 0, SEEK_CUR);
    if (end < 0) return -1;

    /* go back and write the end of list position */
    lseek(fd,begin,SEEK_SET);
    if(write_int(fd, end) == -1) return -1;

    /*return to the end */
    lseek(fd,end,SEEK_SET);

    return wrote;
}

/* emit the bytecode for a test.  returns -1 on failure or size of
 * emitted bytecode on success */
static int bc_test_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int opcode;
    int wrote=0;/* Relative offset to account for interleaved strings */

    int ret; /* Temporary Return Value Variable */

    /* Output this opcode */
    opcode = bc->data[(*codep)++].op;
    if(write_int(fd, opcode) == -1)
        return -1;
    wrote += sizeof(int);

    switch(opcode) {
    case BC_TRUE:
    case BC_FALSE:
        /* No parameter opcodes */
        break;

    case BC_NOT:
    {
        /* Single parameter: another test */
        ret = bc_test_emit(fd, codep, bc);
        if(ret < 0)
            return -1;
        else
            wrote+=ret;
        break;
    }

    case BC_ALLOF:
    case BC_ANYOF:
        /*where we jump to?*/
        /* Just drop a testlist */
        ret = bc_testlist_emit(fd, codep, bc);
        if(ret < 0)
            return -1;
        else
            wrote+=ret;
        break;

    case BC_SIZE:
        /* Drop tag and number */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        if(write_int(fd, bc->data[(*codep)+1].value) == -1)
            return -1;

        wrote += 2 * sizeof(int);
        (*codep) += 2;
        break;

    case BC_EXISTS:
    case BC_VALIDEXTLIST:
    {
        int ret;
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote += ret;
        break;
    }

    case BC_HEADER:
    case BC_HASFLAG:
    case BC_STRING:
    {
        int ret;
        if (BC_HEADER == opcode) {
        /* drop index */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        }
        /* Drop match type */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop relation*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*drop comparator */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /* Now drop haystacks */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;
        /* Now drop needles */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;
        break;
    }

    case BC_ADDRESS:
        /* drop index */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* fall-through */
    case BC_ENVELOPE:
    {
        int ret;
        /* Drop match type */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*drop comparator */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop relation*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop address part*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /* Now drop headers */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;
        /* Now drop data */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;
        break;
    }

    case BC_BODY:
    {
        int ret;
        /* Drop match type */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*drop comparator */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop relation*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop transform*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop offset*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop content-types*/
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;
        /* Now drop data */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;
        break;
    }

    case BC_MAILBOXEXISTS:
    {
        int ret;

        /* drop keylist */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;

        break;
    }
    case BC_METADATA:
    {
        int ret;
        int datalen;

        /* Drop match type */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop relation*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*drop comparator */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* drop extname */
        datalen = bc->data[(*codep)++].len;

        if(write_int(fd, datalen) == -1) return -1;
        wrote += sizeof(int);

        if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return -1;
        wrote += datalen;
        ret = align_string(fd,datalen);
        if(ret == -1) return -1;
        wrote+=ret;

        /* drop keyname */
        datalen = bc->data[(*codep)++].len;

        if(write_int(fd, datalen) == -1) return -1;
        wrote += sizeof(int);

        if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return -1;
        wrote += datalen;
        ret = align_string(fd,datalen);
        if(ret == -1) return -1;
        wrote+=ret;

        /* drop keylist */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;

        break;
    }
    case BC_METADATAEXISTS:
    {
        int ret;
        int datalen;

        /* drop extname */
        datalen = bc->data[(*codep)++].len;

        if(write_int(fd, datalen) == -1) return -1;
        wrote += sizeof(int);

        if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return -1;
        wrote += datalen;
        ret = align_string(fd,datalen);
        if(ret == -1) return -1;
        wrote+=ret;

        /* drop keylist */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;

        break;
    }
    case BC_SERVERMETADATA:
    {
        int ret;
        int datalen;

        /* Drop match type */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*now drop relation*/
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;
        /*drop comparator */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* drop keyname */
        datalen = bc->data[(*codep)++].len;

        if(write_int(fd, datalen) == -1) return -1;
        wrote += sizeof(int);

        if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return -1;
        wrote += datalen;
        ret = align_string(fd,datalen);
        if(ret == -1) return -1;
        wrote+=ret;

        /* drop keylist */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;

        break;
    }
    case BC_SERVERMETADATAEXISTS:
    {
        int ret;

        /* drop keylist */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;

        break;
    }

    case BC_DATE:
    case BC_CURRENTDATE:
    {
        int ret;
        int datalen;
        int tmp;

        /* drop index */
        if(BC_DATE == opcode) {
                if(write_int(fd, bc->data[(*codep)].value) == -1)
                    return -1;
                wrote += sizeof(int);
                (*codep)++;
        }

        /* drop zone tag */
        tmp = bc->data[(*codep)].value;
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* drop timezone offset */
        if (tmp == B_TIMEZONE) {
                if(write_int(fd, bc->data[(*codep)].value) == -1)
                    return -1;
                wrote += sizeof(int);
                (*codep)++;
        }

        /* drop match type */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* drop relation */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* drop comparator */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        /* drop date-part */
        if(write_int(fd, bc->data[(*codep)].value) == -1)
            return -1;
        wrote += sizeof(int);
        (*codep)++;

        if (BC_DATE == opcode) {
                /* drop header-name */
                datalen = bc->data[(*codep)++].len;

                if(write_int(fd, datalen) == -1) return -1;
                wrote += sizeof(int);

                if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return -1;
                wrote += datalen;

                ret = align_string(fd,datalen);
                if(ret == -1) return -1;

                wrote+=ret;
        }

        /* drop keywords */
        ret = bc_stringlist_emit(fd, codep, bc);
        if(ret < 0) return -1;
        wrote+=ret;

        break;
    }

    default:
        /* Unknown testcode? */
        return -1;
    }
    return wrote;
}

/* emit the bytecode to a file descriptor given a flattened parse tree
 * returns -1 on failure, size of emitted bytecode on success.
 *
 * this takes care of everything except the comparisons */
static int bc_action_emit(int fd, int codep, int stopcodep,
                          bytecode_info_t *bc, int filelen)
{
    int len; /* Temporary Length Variable */
    int ret; /* Temporary Return Value Variable */
    int start_filelen = filelen;
    int i;

    /*debugging variable to check filelen*/
    /*int location;*/

    syslog(LOG_DEBUG, "entered bc_action_emit with filelen: %d", filelen);

    /* All non-string data MUST be sizeof(int)
       byte alligned so the end of each string may require a pad */
    /*
     * Note that for purposes of jumps you must multiply codep by sizeof(int)
     */
    while(codep < stopcodep) {
        /* Output this opcode */
        if(write_int(fd, bc->data[codep].op) == -1)
            return -1;

        filelen+=sizeof(int);

        switch(bc->data[codep++].op) {

        case B_IF:
        {
            /* IF
             *  test
             *  jump (false condition)
             *  then
             * (if there is an else) jump(finish)
             * (if there is an else) else
             */

            int testEndLoc=-1;
            int testdist, thendist, elsedist;
            int c;

            int jumpFalseLoc=-1;/*this is the location that is being reserved
                                  for the first jump command
                                  we jump to the false condition of the test*/

            int jumpEndLoc=-1; /* this is the location that is being reserved
                                  for the optional jump command
                                  it jumps over the else statement to the end*/
            int jumpto=-1;
            int jumpop= B_JUMP;

            /*leave space to store the location of end of the test*/
            ret = lseek(fd, sizeof(int), SEEK_CUR);
            if(ret == -1) return ret;

            testEndLoc=filelen;
            filelen+=sizeof(int);

            /* spew the test */

            c=codep+3;
            testdist = bc_test_emit(fd, &c, bc);
            if(testdist == -1)return -1;
            filelen +=testdist;

            /*store the location for the end of the test
             *this is important for short circuiting of allof/anyof*/
            jumpto=filelen/4;
            if(lseek(fd, testEndLoc, SEEK_SET) == -1)
                return -1;
            if(write_int(fd,jumpto) == -1)
                return -1;

            if(lseek(fd,filelen,SEEK_SET) == -1)
                return -1;

            /* leave space for jump */
            if(write_int(fd, jumpop) == -1)
                return -1;
            ret = lseek(fd, sizeof(int), SEEK_CUR);
            if(ret == -1)
                return ret;
            jumpFalseLoc=filelen+sizeof(int);

            filelen +=2*sizeof(int); /*jumpop + jump*/

            /* spew the then code */
            thendist = bc_action_emit(fd, bc->data[codep].value,
                                      bc->data[codep+1].value, bc,
                                      filelen);

            filelen+=thendist;

            /* there is an else case */
            if(bc->data[codep+2].value != -1)
            {
                /* leave space for jump */
                if(write_int(fd, jumpop) == -1)
                    return -1;
                ret = lseek(fd, sizeof(int), SEEK_CUR);
                if(ret == -1)
                    return ret;

                jumpEndLoc=filelen+sizeof(int);
                filelen+=2*sizeof(int);/*jumpop + jump*/
            }

            /*put previous jump to the end of the then code,
             *or the end of the jump if there is an else case */
            jumpto=filelen/4;
            if(lseek(fd, jumpFalseLoc, SEEK_SET) == -1)
                return -1;
            if(write_int(fd,jumpto) == -1)
                return -1;
            if(lseek(fd,filelen,SEEK_SET) == -1)
                return -1;

            /* there is an else case */
            if(bc->data[codep+2].value != -1) {
                /* spew the else code */
                elsedist = bc_action_emit(fd, bc->data[codep+1].value,
                                         bc->data[codep+2].value, bc,
                                         filelen);

                filelen+=elsedist;

                /*put jump to the end of the else code*/
                jumpto=filelen/4;
                if(lseek(fd, jumpEndLoc, SEEK_SET) == -1)
                    return -1;
                if(write_int(fd,jumpto) == -1)
                    return -1;
                if(lseek(fd,filelen,SEEK_SET) == -1)
                    return -1;

                codep = bc->data[codep+2].value;
            } else {
                codep = bc->data[codep+1].value;
            }

            break;
        }

        case B_KEEP:
            /* Flags Stringlist, Copy (word) */

            /* Dump a stringlist of flags */
            ret = bc_stringlist_emit(fd, &codep, bc);
            if(ret < 0)
                return -1;
            filelen += ret;

            if(write_int(fd,bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);
            break;

        case B_FILEINTO:
            /* Create (word), Flags Stringlist, Copy (word), Folder String */

            /* Write create */
            if(write_int(fd,bc->data[codep++].value) == -1)
                return -1;
            filelen += sizeof(int);

            /* Dump a stringlist of flags */
            ret = bc_stringlist_emit(fd, &codep, bc);
            if(ret < 0)
                return -1;
            filelen += ret;

            /* Write Copy */
            if(write_int(fd,bc->data[codep++].value) == -1)
                return -1;
            filelen += sizeof(int);

            /* Write string length of Folder */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            /* Write Folder */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            break;

        case B_REDIRECT:
            /* Copy (word), Address String */

            if(write_int(fd,bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            break;

        case B_REJECT:
        case B_EREJECT:
            /*just a string*/
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            break;

        case B_SETFLAG:
        case B_ADDFLAG:
        case B_REMOVEFLAG:
            /* Variablename String, Flags Stringlist */

            /* Write string length of Variablename */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            /* Write Folder */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            ret = bc_stringlist_emit(fd, &codep, bc);
            if(ret < 0)
                return -1;
            filelen += ret;
            break;

        case B_NOTIFY:
            /* method string, id string, options string list,
               priotity, Message String */
            /*method and id*/
            for(i=0; i<2; i++) {
                len = bc->data[codep++].len;
                if(write_int(fd,len) == -1)
                    return -1;
                filelen += sizeof(int);
                if(len == -1)
                {
                    /* this will probably only happen for the id */
                    /* this is a nil string */
                    /* skip the null pointer and make up for it
                     * by adjusting the offset */
                    codep++;
                }
                else
                {
                    if(write(fd,bc->data[codep++].str,len) == -1)
                        return -1;

                    ret = align_string(fd, len);
                    if(ret == -1)
                        return -1;

                    filelen += len + ret;
                }

            }
            /*options */
            ret = bc_stringlist_emit(fd, &codep, bc);
            if(ret < 0)
                return -1;
            filelen+=ret;

            /*priority*/
            if(write_int(fd, bc->data[codep].value) == -1)
                return -1;
            codep++;
            filelen += sizeof(int);

            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;
            filelen += sizeof(int);

            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1) return -1;

            filelen += len + ret;
            break;


        case B_DENOTIFY:
            /* priority num,comptype  num,relat num, comp string*/

            /* priority*/
            if(write_int(fd, bc->data[codep].value) == -1)
                return -1;
            filelen += sizeof(int);
            codep++;
            /* comptype */
            if(write_int(fd, bc->data[codep].value) == -1)
                return -1;
            filelen += sizeof(int);
            codep++;
            /* relational*/
            if(write_int(fd, bc->data[codep].value) == -1)
                return -1;
            filelen += sizeof(int);
            codep++;
            /* comp string*/

            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;
            filelen += sizeof(int);

            if(len == -1)
            {
                /* this is a nil string */
                /* skip the null pointer and make up for it
                 * by adjusting the offset */
                codep++;
            }
            else
            {
                if(write(fd,bc->data[codep++].str,len) == -1)
                    return -1;

                ret = align_string(fd, len);
                if(ret == -1) return -1;

                filelen += len + ret;
            }
                    break;
        case B_VACATION:
            /* Address list, Subject String, Message String,
               Seconds (word), Mime (word), From String, Handle String */

                /*new code-this might be broken*/
            ret = bc_stringlist_emit(fd, &codep, bc);
            if(ret < 0) return -1;
            filelen += ret;
            /*end of new code*/

            for(i=0; i<2; i++) {/*writing strings*/

                /*write length of string*/
                len = bc->data[codep++].len;
                if(write_int(fd,len) == -1)
                    return -1;
                filelen += sizeof(int);

                if(len == -1)
                {
                    /* this is a nil string */
                    /* skip the null pointer and make up for it
                     * by adjusting the offset */
                    codep++;
                }
                else
                {
                    /*write string*/
                    if(write(fd,bc->data[codep++].str,len) == -1)
                        return -1;

                    ret = align_string(fd, len);
                    if(ret == -1) return -1;

                    filelen += len + ret;
                }

            }
            /* Seconds*/
            if(write_int(fd,bc->data[codep].value) == -1)
                return -1;
            codep++;
            filelen += sizeof(int);
            /*Mime */
            if(write_int(fd,bc->data[codep].value) == -1)
                return -1;
            codep++;

            for(i=0; i<2; i++) {/*writing strings*/

                /*write length of string*/
                len = bc->data[codep++].len;
                if(write_int(fd,len) == -1)
                    return -1;
                filelen += sizeof(int);

                if(len == -1)
                {
                    /* this is a nil string */
                    /* skip the null pointer and make up for it
                     * by adjusting the offset */
                    codep++;
                }
                else
                {
                    /*write string*/
                    if(write(fd,bc->data[codep++].str,len) == -1)
                        return -1;

                    ret = align_string(fd, len);
                    if(ret == -1) return -1;

                    filelen += len + ret;
                }

            }
            filelen += sizeof(int);

            break;
        case B_INCLUDE:
            /* Location + (Once<<6) + (Optional<<7) (word), Filename String */

            /* Location + (Once<<6) + (Optional<<7) */
            if(write_int(fd, bc->data[codep].value) == -1)
                return -1;
            filelen += sizeof(int);
            codep++;
            /* Filename */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen += sizeof(int);

            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1) return -1;

            filelen += len + ret;
            break;

        case B_SET:
            /* BITFIELD modifiers
               STRING variable
               STRING value
            */
            /* write modifiers */
            if(write_int(fd,bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            /* write string length of variable */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            /* write variable */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            /* write string length of value */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            /* write value */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            break;

        case B_ADDHEADER:
            /* NUMBER index
               STRING name
               STRING value
            */
            /* write index */
            if(write_int(fd,bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            /* write string length of name */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            /* write name */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            /* write string length of value */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen+=sizeof(int);

            /* write value */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            break;

        case B_DELETEHEADER:
            /* NUMBER index
               COMPARATOR
               STRING name
               STRINGLIST value-patterns
            */
            /* write index */
            if(write_int(fd, bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            /* write match type */
            if(write_int(fd, bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            /* write relation */
            if(write_int(fd, bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            /* write comparator */
            if(write_int(fd, bc->data[codep++].value) == -1)
                return -1;

            filelen += sizeof(int);

            /* write string length of name */
            len = bc->data[codep++].len;
            if(write_int(fd,len) == -1)
                return -1;

            filelen += sizeof(int);

            /* write name */
            if(write(fd,bc->data[codep++].str,len) == -1)
                return -1;

            ret = align_string(fd, len);
            if(ret == -1)
                return -1;

            filelen += len + ret;

            /* write value patterns */
            ret = bc_stringlist_emit(fd, &codep, bc);
            if (ret < 0) return -1;
            filelen += ret;

            break;

        case B_NULL:
        case B_STOP:
        case B_DISCARD:
        case B_MARK:
        case B_UNMARK:
        case B_RETURN:
            /* No Parameters! */
            break;

        default:
            /* Unknown opcode? */
            return -1;
        }
    }
    return filelen - start_filelen;
}

/* spew the bytecode to disk */
EXPORTED int sieve_emit_bytecode(int fd, bytecode_info_t *bc)
{
    int codep = 0;

    /* First output version number (4 bytes) */
    int data = BYTECODE_VERSION;

    /*this is a string, so it is happy*/
    if(write(fd, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN) == -1)
        return -1;

    if(write_int(fd, data) == -1) return -1;

    /* write extensions bitfield */
    if (write_int(fd, bc->data[codep++].value) == -1) return -1;

#if DUMPCODE
    dump(bc, 0);
#endif

    /* the 2*sizeof(int) is to account for the version number and requires at
     * the beginning
     */
    return bc_action_emit(fd, codep, bc->scriptend, bc,
                          2*sizeof(int) + BYTECODE_MAGIC_LEN);
}

