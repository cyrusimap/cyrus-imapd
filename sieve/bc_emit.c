/* bc_emit.c -- sieve bytecode - pass 2 of the compiler
 * Rob Siemborski
 * Jen Smith
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

#include "sieve_interface.h"


#include "bytecode.h"

#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>


#if DUMPCODE
void dump(bytecode_info_t *d, int level);
#endif

static inline int write_int(int fd, int x)
{
    int y = htonl(x);
    return (write(fd, &y, sizeof(int)));
}


/* Pad null bytes onto the end of the string we just wrote */
/* returns -1 on failure or number of bytes written on success */
static int align_string(int fd, int string_len)
{
    /* Keep in mind that we always want to pad a string with *at least*
     * one zero, that's why sometimes we have to pad with 4 */
    int needed = sizeof(int) - (string_len % sizeof(int));
    if (needed >= 0 && needed <= 4) {
        if (write(fd, "\0\0\0\0", needed) == -1) return -1;
    }
    return needed;
}

/* all functions keep codep up to date as they use it.
   the amount that has been written to the file is maintained by the
   filelen variable in bc_action_emit
   the other bc_xxx_emit functions keep track of how much they (and any functions
   they call) have written and return this value
*/


/* Write out a string to a given file descriptor.
 * return # of bytes written on success and -1 on error

 * <string:(size)(aligned string)>
 */
static int bc_string_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int len = bc->data[*codep].u.str ? (int) strlen(bc->data[*codep].u.str) : -1;
    int wrote = 0;

    /* Write string length */
    if (write_int(fd, len) == -1) return -1;

    wrote += sizeof(int);

    if (len == -1) {
        /* This is a nil string */
        /* Skip the null pointer and make up for it
         * by adjusting the offset */
        (*codep)++;
    }
    else {
        int ret;

        /* Write string */
        if (write(fd, bc->data[(*codep)++].u.str, len) == -1) return -1;

        ret = align_string(fd, len);
        if (ret < 0) return -1;

        wrote += len + ret;
    }

    return wrote;
}

/* Write out a stringlist to a given file descriptor.
 * return # of bytes written on success and -1 on error */

/* stringlist: <# listitems>
               <pos of listend (bytes)>
               <string:(size)(aligned string)>
*/
static int bc_stringlist_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int len = bc->data[(*codep)++].u.listlen;
    int i;
    int ret;
    int wrote = 2*sizeof(int);
    int begin,end;

    /* Write out number of items in the list */
    if (write_int(fd, len)== -1) return -1 ;

    /* skip one spot end of list position*/
    begin = lseek(fd, 0, SEEK_CUR);
    lseek(fd, sizeof(int), SEEK_CUR);

    /* Loop through all the items of the list, writing out length and string
     * in sequence */
    for (i = 0; i < len; i++) {
        ret = bc_string_emit(fd, codep, bc);
        if (ret == -1) return -1;

        wrote += ret;
    }
    end = lseek(fd, 0, SEEK_CUR);
    if (end < 0) return -1;

    /* go back and write end of list position */
    lseek(fd, begin, SEEK_SET);
    if (write_int(fd, end) == -1) return -1;

    /* return to the end */
    lseek(fd, end, SEEK_SET);
    return wrote;
}

/* Write out a valuelist to a given file descriptor.
 * return # of bytes written on success and -1 on error */

/* valuelist: <# listitems>
              <pos of listend (bytes)>
              <int value>
*/
static int bc_vallist_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int len = bc->data[(*codep)++].u.listlen;
    int i;
    int ret;
    int wrote = 2*sizeof(int);
    int begin,end;

    /* Write out number of items in the list */
    if (write_int(fd, len)== -1) return -1 ;

    /* skip one spot end of list position*/
    begin = lseek(fd, 0, SEEK_CUR);
    lseek(fd, sizeof(int), SEEK_CUR);

    /* Loop through all the items of the list, writing out length and string
     * in sequence */
    for (i = 0; i < len; i++) {
        ret = write_int(fd, bc->data[(*codep)++].u.value);
        if (ret == -1) return -1;

        wrote += ret;
    }
    end = lseek(fd, 0, SEEK_CUR);
    if (end < 0) return -1;

    /* go back and write end of list position */
    lseek(fd, begin, SEEK_SET);
    if (write_int(fd, end) == -1) return -1;

    /* return to the end */
    lseek(fd, end, SEEK_SET);
    return wrote;
}

static int bc_params_emit(int fd, int *codep, int stopcodep, bytecode_info_t *bc)
{
    int ret;
    int wrote = 0;

    while (*codep < stopcodep) {
        switch (bc->data[*codep].type) {
        case BT_OPCODE:
        case BT_JUMP:
            /* Next command (end of parameters) */
            return wrote;

        case BT_VALUE:
            ret = write_int(fd, bc->data[(*codep)++].u.value);
            break;

        case BT_STR:
            ret = bc_string_emit(fd, codep, bc);
            break;

        case BT_STRLISTLEN:
            ret = bc_stringlist_emit(fd, codep, bc);
            break;

        case BT_VALLISTLEN:
            ret = bc_vallist_emit(fd, codep, bc);
            break;

        default:
            /* Should never get here */
            ret = -1;
            break;
        }

        if (ret < 0) return -1;

        wrote += ret;
    }

    return wrote;
}

static int bc_test_emit(int fd, int *codep, int stopcodep, bytecode_info_t *bc);

/* Write out a testlist to a given file descriptor.
 * return # of bytes written on success and -1 on error */
static int bc_testlist_emit(int fd, int *codep, bytecode_info_t *bc)
{
    int len = bc->data[(*codep)++].u.listlen;
    int i;
    int ret;
    int begin, end;
    int wrote = 2*sizeof(int);

    assert(bc->data[*codep].type == BT_STRLISTLEN);

    /* Write out number of items in the list */
    if (write_int(fd, len)== -1) return -1;

    /* skip one spot for end of list position*/
    begin = lseek(fd, 0, SEEK_CUR);
    lseek(fd, sizeof(int), SEEK_CUR);

    /* Loop through all the items of the list, writing out each
     * test as we reach it in sequence. */
    for (i = 0; i < len; i++) {
        int nextcodep = bc->data[(*codep)++].u.jump;

        assert(bc->data[*codep].type == BT_JUMP);

        ret = bc_test_emit(fd, codep, nextcodep, bc);
        if (ret < 0 ) return -1;

        wrote += ret;
        *codep = nextcodep;
    }
    end = lseek(fd, 0, SEEK_CUR);
    if (end < 0) return -1;

    /* go back and write the end of list position */
    lseek(fd, begin, SEEK_SET);
    if (write_int(fd, end) == -1) return -1;

    /*return to the end */
    lseek(fd, end, SEEK_SET);

    return wrote;
}

/* emit the bytecode for a test.  returns -1 on failure or size of
 * emitted bytecode on success */
static int bc_test_emit(int fd, int *codep, int stopcodep, bytecode_info_t *bc)
{
    int opcode;
    int wrote = 0;/* Relative offset to account for interleaved strings */

    int ret; /* Temporary Return Value Variable */

    assert(bc->data[*codep].type == BT_OPCODE);

    /* Output this opcode */
    opcode = bc->data[(*codep)++].u.op;
    ret = write_int(fd, opcode);
    if (ret < 0) return -1;

    wrote += ret;

    switch (opcode) {
    case BC_NOT:
        /* Single parameter: another test */
        ret = bc_test_emit(fd, codep, stopcodep, bc);
        break;

    case BC_ALLOF:
    case BC_ANYOF:
        /* Just drop a testlist */
        ret = bc_testlist_emit(fd, codep, bc);
        break;

    case BC_TRUE:
    case BC_FALSE:
    case BC_SIZE:
    case BC_EXISTS:
    case BC_IHAVE:
    case BC_VALIDEXTLIST:
    case BC_VALIDNOTIFYMETHOD:
    case BC_NOTIFYMETHODCAPABILITY:
    case BC_HEADER:
    case BC_HASFLAG:
    case BC_STRING:
    case BC_ADDRESS:
    case BC_ENVELOPE:
    case BC_BODY:
    case BC_MAILBOXEXISTS:
    case BC_MAILBOXIDEXISTS:
    case BC_METADATA:
    case BC_METADATAEXISTS:
    case BC_SPECIALUSEEXISTS:
    case BC_SERVERMETADATA:
    case BC_ENVIRONMENT:
    case BC_SERVERMETADATAEXISTS:
    case BC_DATE:
    case BC_CURRENTDATE:
    case BC_DUPLICATE:
    case BC_JMAPQUERY:
        ret = bc_params_emit(fd, codep, stopcodep, bc);
        break;

    default:
        /* Unknown testcode? */
        ret = -1;
        break;
    }

    if (ret < 0) return -1;

    wrote += ret;

    return wrote;
}

/* emit the bytecode to a file descriptor given a flattened parse tree
 * returns -1 on failure, size of emitted bytecode on success.
 *
 * this takes care of everything except the comparisons */
static int bc_action_emit(int fd, int codep, int stopcodep,
                          bytecode_info_t *bc, int filelen)
{
    int ret; /* Temporary Return Value Variable */
    int start_filelen = filelen;

    /*debugging variable to check filelen*/
    /*int location;*/

    syslog(LOG_DEBUG, "entered bc_action_emit with filelen: %d", filelen);

    /* All non-string data MUST be sizeof(int)
       byte aligned so the end of each string may require a pad */
    /*
     * Note that for purposes of jumps you must multiply codep by sizeof(int)
     */
    while(codep < stopcodep) {
        assert(bc->data[codep].type == BT_OPCODE);

        /* Output this opcode */
        if (write_int(fd, bc->data[codep].u.op) == -1) return -1;

        filelen += sizeof(int);

        switch (bc->data[codep++].u.op) {

        case B_IF:
        {
            /* IF
             *  pos of testend (bytes)
             *  test
             *  jump (false condition)
             *  then
             * (if there is an else) jump(finish)
             * (if there is an else) else
             */

            int testEndLoc = -1;
            int testdist, thendist, elsedist;
            int c;

            int jumpFalseLoc = -1;/* this is the location that is being reserved
                                     for the first jump command
                                     we jump to the false condition of the test */

            int jumpEndLoc = -1; /* this is the location that is being reserved
                                    for the optional jump command
                                    it jumps over the else statement to the end */
            int jumpto = -1;
            int jumpop = B_JUMP;

            /* leave space to store the location of end of the test */
            ret = lseek(fd, sizeof(int), SEEK_CUR);
            if (ret == -1) return ret;

            testEndLoc = filelen;
            filelen += sizeof(int);

            /* spew the test */

            c = codep+3;
            testdist = bc_test_emit(fd, &c, bc->data[codep].u.jump, bc);
            if (testdist == -1) return -1;
            filelen += testdist;

            /* store the location for the end of the test
             * this is important for short circuiting of allof/anyof */
            jumpto = filelen/4;
            if (lseek(fd, testEndLoc, SEEK_SET) == -1) return -1;
            if (write_int(fd, jumpto) == -1) return -1;

            if (lseek(fd, filelen, SEEK_SET) == -1) return -1;

            /* leave space for jump */
            if (write_int(fd, jumpop) == -1) return -1;
            ret = lseek(fd, sizeof(int), SEEK_CUR);
            if (ret == -1) return ret;
            jumpFalseLoc = filelen + sizeof(int);

            filelen += 2*sizeof(int); /* jumpop + jump */

            /* spew the then code */
            thendist = bc_action_emit(fd, bc->data[codep].u.jump,
                                      bc->data[codep+1].u.jump, bc,
                                      filelen);

            filelen += thendist;

            /* there is an else case */
            if (bc->data[codep+2].u.jump != -1) {
                /* leave space for jump */
                if (write_int(fd, jumpop) == -1) return -1;
                ret = lseek(fd, sizeof(int), SEEK_CUR);
                if (ret == -1) return ret;

                jumpEndLoc = filelen + sizeof(int);
                filelen += 2*sizeof(int); /* jumpop + jump */
            }

            /* put previous jump to the end of the then code,
             * or the end of the jump if there is an else case */
            jumpto = filelen/4;
            if (lseek(fd, jumpFalseLoc, SEEK_SET) == -1) return -1;
            if (write_int(fd, jumpto) == -1) return -1;
            if (lseek(fd, filelen, SEEK_SET) == -1) return -1;

            /* there is an else case */
            if (bc->data[codep+2].u.jump != -1) {
                /* spew the else code */
                elsedist = bc_action_emit(fd, bc->data[codep+1].u.jump,
                                          bc->data[codep+2].u.jump, bc,
                                          filelen);

                filelen += elsedist;

                /* put jump to the end of the else code */
                jumpto = filelen/4;
                if (lseek(fd, jumpEndLoc, SEEK_SET) == -1) return -1;
                if (write_int(fd, jumpto) == -1) return -1;
                if (lseek(fd, filelen, SEEK_SET) == -1) return -1;

                codep = bc->data[codep+2].u.jump;
            } else {
                codep = bc->data[codep+1].u.jump;
            }

            break;
        }

        case B_KEEP:
        case B_FILEINTO:
        case B_REDIRECT:
        case B_REJECT:
        case B_EREJECT:
        case B_ERROR:
        case B_SETFLAG:
        case B_ADDFLAG:
        case B_REMOVEFLAG:
        case B_ENOTIFY:
        case B_NOTIFY:
        case B_DENOTIFY:
        case B_VACATION:
        case B_INCLUDE:
        case B_SET:
        case B_ADDHEADER:
        case B_DELETEHEADER:
        case B_LOG:
        case B_NULL:
        case B_STOP:
        case B_DISCARD:
        case B_MARK:
        case B_UNMARK:
        case B_RETURN:
        case B_SNOOZE:
            /* Spew the action parameters */
            ret = bc_params_emit(fd, &codep, stopcodep, bc);
            if (ret < 0) return -1;

            filelen += ret;

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
    if (write(fd, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN) == -1) return -1;

    if (write_int(fd, data) == -1) return -1;

    /* write extensions bitfield */
    if (write_int(fd, bc->data[codep++].u.value) == -1) return -1;

#if DUMPCODE
    dump(bc, 0);
#endif

    /* the 2*sizeof(int) is to account for the version number and requires at
     * the beginning
     */
    return bc_action_emit(fd, codep, bc->scriptend, bc,
                          2*sizeof(int) + BYTECODE_MAGIC_LEN);
}
