/* bc_eval.c - evaluate the bytecode
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
#include "interp.h"
#include "message.h"
#include "script.h"
#include "parseaddr.h"
#include "flags.h"
#include "variables.h"

#include "bytecode.h"

#include "charset.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "util.h"
#include "times.h"

#include <string.h>

/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************EXECUTING BYTECODE******************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/

/* Given a bytecode_input_t at the beginning of a string (the len block),
 * return the string, the length, and the bytecode index of the NEXT
 * item */
EXPORTED int unwrap_string(bytecode_input_t *bc, int pos, const char **str, int *len)
{
    int local_len = ntohl(bc[pos].value);

    pos++;

    if(local_len == -1) {
        /* -1 length indicates NULL */
        *str = NULL;
    } else {
        /* This cast is ugly, but necessary */
        *str = (const char *)&bc[pos].str;

        /* Compute the next index */
        pos += ((ROUNDUP(local_len+1))/sizeof(bytecode_input_t));
    }

    if(len) *len = local_len;

    return pos;
}


/* this is used by notify to pass the options list to do_notify
 * do_notify needs null-terminated (char *)[],
 *  we have a stringlist, the beginning of which is pointed at by pos */
static const char ** bc_makeArray(bytecode_input_t *bc, int *pos)
{
    int i;
    const char** array;
    int len = ntohl(bc[*pos].value);

    (*pos)+=2; /* Skip # Values and Total Byte Length */

    array=(const char **)xmalloc((len+1) * sizeof(char *));

    for (i=0; i<len; i++) {
        *pos = unwrap_string(bc, *pos, &(array[i]), NULL);
    }

    array[i] = NULL;

    return array;
}

/* Compile a regular expression for use during parsing */
static regex_t * bc_compile_regex(const char *s, int ctag,
                                  char *errmsg, size_t errsiz)
{
    int ret;
    regex_t *reg = (regex_t *) xmalloc(sizeof(regex_t));

#ifdef HAVE_PCREPOSIX_H
    /* support UTF8 comparisons */
    ctag |= REG_UTF8;
#endif
    if ( (ret=regcomp(reg, s, ctag)) != 0)
    {
        (void) regerror(ret, reg, errmsg, errsiz);
        free(reg);
        return NULL;
    }
    return reg;
}

/* Determine if addr is a system address */
static int sysaddr(const char *addr)
{
    if (!strncasecmp(addr, "MAILER-DAEMON", 13))
        return 1;

    if (!strncasecmp(addr, "LISTSERV", 8))
        return 1;

    if (!strncasecmp(addr, "majordomo", 9))
        return 1;

    if (strstr(addr, "-request@"))
        return 1;

    if (!strncmp(addr, "owner-", 6))
        return 1;

    return 0;
}

/* look for myaddr and myaddrs in the body of a header - return the match */
static char* look_for_me(char *myaddr, int numaddresses,
			       bytecode_input_t *bc, int i, const char **body,
			       variable_list_t *variables, int requires)
{
    char *found = NULL;
    int l;
    int curra,x ;

    /* loop through each TO header */
    for (l = 0; body[l] != NULL && !found; l++) {
        struct address_itr ai;
        const struct address *a;

        address_itr_init(&ai, body[l]);

        /* loop through each address in the header */
        while (!found && (a = address_itr_next(&ai)) != NULL) {
            char *addr = address_get_all(a, 0);
            if (!addr) addr = xstrdup("");

            if (!strcasecmp(addr, myaddr)) {
                free(addr);
                found = xstrdup(myaddr);
                break;
            }

            curra=i;

            for(x=0; x<numaddresses; x++)
            {
                char *altaddr;
                const char *str;

                curra = unwrap_string(bc, curra, &str, NULL);

                if (requires & BFE_VARIABLES) {
                    str = parse_string(str, variables);
                }

                /* is this address one of my addresses? */
                altaddr = address_canonicalise(str);

                if (!strcasecmp(addr,altaddr)) {
                    free(altaddr);
                    found=xstrdup(str);
                    break;
                }
                free(altaddr);
            }
            free(addr);
        }
        address_itr_fini(&ai);
    }

    return found;
}

/* Determine if we should respond to a vacation message */
static int shouldRespond(void * m, sieve_interp_t *interp,
                         int numaddresses, bytecode_input_t* bc,
			 int i, char **from, char **to,
			 variable_list_t *variables, int requires)
{
    const char **body;
    char *myaddr = NULL;
    int l = SIEVE_DONE, j;
    int curra, x;
    char *found = NULL;
    char *reply_to = NULL;
    static const char * const list_fields[] = {
        "list-id",
        "list-help",
        "list-subscribe",
        "list-unsubscribe",
        "list-post",
        "list-owner",
        "list-archive",
        NULL
    };

    /* Implementations SHOULD NOT respond to any message that contains a
       "List-Id" [RFC2919], "List-Help", "List-Subscribe", "List-
       Unsubscribe", "List-Post", "List-Owner" or "List-Archive" [RFC2369]
       header field. */
    for (j = 0; list_fields[j]; j++) {
        if (interp->getheader(m, list_fields[j], &body) == SIEVE_OK)
            goto out;
    }

    /* If the sender has requested no vacation response */
    if (interp->getheader(m, "x-ignorevacation", &body) == SIEVE_OK) {
        /* we don't deal with comments, etc. here */
        /* skip leading white-space */
        while (*body[0] && Uisspace(*body[0])) body[0]++;
        if (strcasecmp(body[0], "no"))
            goto out;
    }

    /* Implementations SHOULD NOT respond to any message that has an
       "Auto-submitted" header field with a value other than "no".
       This header field is described in [RFC3834]. */
    if (interp->getheader(m, "auto-submitted", &body) == SIEVE_OK) {
        /* we don't deal with comments, etc. here */
        /* skip leading white-space */
        while (*body[0] && Uisspace(*body[0])) body[0]++;
        if (strcasecmp(body[0], "no"))
            goto out;
    }

    /* is there a Precedence keyword of "junk | bulk | list"? */
    /* XXX  non-standard header, but worth checking */
    if (interp->getheader(m, "precedence", &body) == SIEVE_OK) {
        /* we don't deal with comments, etc. here */
        /* skip leading white-space */
        while (*body[0] && Uisspace(*body[0])) body[0]++;
        if (!strcasecmp(body[0], "junk") ||
            !strcasecmp(body[0], "bulk") ||
            !strcasecmp(body[0], "list"))
            goto out;
    }

    /* Note: the domain-part of all addresses are canonicalized */
    /* grab my address from the envelope */
    l = interp->getenvelope(m, "to", &body);
    if (l != SIEVE_OK)
        goto out;
    l = SIEVE_DONE;
    if (!body[0])
        goto out;
    myaddr = address_canonicalise(body[0]);

    l = interp->getenvelope(m, "from", &body);
    if (l != SIEVE_OK)
        goto out;
    l = SIEVE_DONE;
    if (!body[0])
        goto out;
    /* we have to parse this address & decide whether we
       want to respond to it */
    reply_to = address_canonicalise(body[0]);

    /* first, is there a reply-to address? */
    if (reply_to == NULL)
        goto out;

    /* is it from me? */
    if (myaddr && !strcmp(myaddr, reply_to))
        goto out;

    /* ok, is it any of the other addresses i've
       specified? */
    curra=i;
    for(x=0; x<numaddresses; x++) {
        const char *address;

        curra = unwrap_string(bc, curra, &address, NULL);

        if (requires & BFE_VARIABLES) {
            address = parse_string(address, variables);
        }

        if (!strcmp(address, reply_to))
            goto out;
    }

    /* ok, is it a system address? */
    if (sysaddr(reply_to))
        goto out;

    /* ok, we're willing to respond to the sender.
       but is this message to me?  that is, is my address
       in the [Resent]-To, [Resent]-Cc or [Resent]-Bcc fields? */
    if (interp->getheader(m, "to", &body) == SIEVE_OK)
	found = look_for_me(myaddr, numaddresses, bc, i, body, variables, requires);
    if (!found && interp->getheader(m, "cc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, numaddresses, bc, i, body, variables, requires);
    if (!found && interp->getheader(m, "bcc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, numaddresses, bc, i, body, variables, requires);
    if (!found && interp->getheader(m, "resent-to", &body) == SIEVE_OK)
	found = look_for_me(myaddr, numaddresses ,bc, i, body, variables, requires);
    if (!found && interp->getheader(m, "resent-cc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, numaddresses, bc, i, body, variables, requires);
    if (!found && interp->getheader(m, "resent-bcc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, numaddresses, bc, i, body, variables, requires);
    if (found)
        l = SIEVE_OK;

    /* ok, ok, if we got here maybe we should reply */
out:
    free(myaddr);
    if (l == SIEVE_OK) {
        *from = found;
        *to = reply_to;
    }
    else {
        free(found);
        free(reply_to);
    }

    return l;
}

static int regcomp_flags(int comparator, int requires)
{
    int cflags = REG_EXTENDED;

    if (comparator == B_ASCIICASEMAP) cflags |= REG_ICASE;
    if (!(requires & BFE_VARIABLES))  cflags |= REG_NOSUB;

    return cflags;
}

/* Evaluate a bytecode test */
static int eval_bc_test(sieve_interp_t *interp, void* m, void *sc,
                        bytecode_input_t * bc, int * ip,
			variable_list_t *variables, int version, int requires)
{
    int res=0;
    int i=*ip;
    int x,y,z;/* loop variable */
    int list_len; /* for allof/anyof/exists */
    int list_end; /* for allof/anyof/exists */
    int address=0;/*to differentiate between address and envelope*/
    int has_index=0;/* used to differentiate between pre and post index tests */
    int is_string = 0; /* differentiate between string and hasflag tests */
    comparator_t * comp=NULL;
    void * comprock=NULL;
    int op= ntohl(bc[i].op);
    #define SCOUNT_SIZE 20
    char scount[SCOUNT_SIZE];

    switch(op)
    {
    case BC_FALSE:/*0*/
        res=0; i++; break;

    case BC_TRUE:/*1*/
        res=1; i++; break;

    case BC_NOT:/*2*/
        i+=1;
        res = eval_bc_test(interp, m, sc, bc, &i, variables, version, requires);
        if(res >= 0) res = !res; /* Only invert in non-error case */
        break;

    case BC_EXISTS:/*3*/
    {
        int headersi=i+1;
        const char** val;
        int currh;

        res=1;

        list_len=ntohl(bc[headersi].len);
        list_end=ntohl(bc[headersi+1].value)/4;

        currh=headersi+2;

        for(x=0; x<list_len && res; x++)
        {
            const char *str;

            currh = unwrap_string(bc, currh, &str, NULL);

            if (requires & BFE_VARIABLES) {
                str = parse_string(str, variables);
            }

            if(interp->getheader(m,str, &val) != SIEVE_OK)
                res = 0;
        }

        i=list_end; /* adjust for short-circuit */
        break;
    }
    case BC_SIZE:/*4*/
    {
        int s;
        int sizevar=ntohl(bc[i+1].value);
        int x=ntohl(bc[i+2].value);

        if (interp->getsize(m, &s) != SIEVE_OK)
            break;

        if (sizevar ==B_OVER) {
            /* over */
            res= s > x;
        } else {
            /* under */
            res= s < x;
        }
        i+=3;
        break;
    }
    case BC_ANYOF:/*5*/
        res = 0;
        list_len=ntohl(bc[i+1].len);
        list_end=ntohl(bc[i+2].len)/4;
        i+=3;

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x=0; x<list_len && !res; x++) {
            int tmp;
            tmp = eval_bc_test(interp, m, sc, bc, &i, variables, version, requires);
            if(tmp < 0) {
                res = tmp;
                break;
            }
            res = res || tmp;
        }

        i = list_end; /* handle short-circuting */

        break;
    case BC_ALLOF:/*6*/
        res = 1;
        list_len=ntohl(bc[i+1].len);
        list_end=ntohl(bc[i+2].len)/4;
        i+=3;

        /* return 1 unless you find one that isn't true, then return 0 */
        for (x=0; x<list_len && res; x++) {
            int tmp;
            tmp = eval_bc_test(interp, m, sc, bc, &i, variables, version, requires);
            if(tmp < 0) {
                res = tmp;
                break;
            }
            res = res && tmp;
        }

        i = list_end; /* handle short-circuiting */

        break;
    case BC_ADDRESS:/*13*/
        has_index=1;
        /* fall through */
    case BC_ADDRESS_PRE_INDEX:/*7*/
        address=1;
        if (0x07 == version && BC_ADDRESS_PRE_INDEX == op) {
            /* There was a version of the bytecode that had the index extension
             * but did not update the bytecode codepoints, nor did it increment
             * the bytecode version number.  This tests if the index extension
             * was in the bytecode based on the position of the match-type
             * argument.
             * We test for the applicable version number explicitly.
             */
            switch (ntohl(bc[i+2].value)) {
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
        /* fall through */
    case BC_ENVELOPE:/*8*/
    {
        const char ** val;
        struct address_itr ai;
        const struct address *a;
        char *addr;

        int headersi=has_index+i+5;/* the i value for the beginning of the headers */
        int datai=(ntohl(bc[headersi+1].value)/4);

        int numheaders=ntohl(bc[headersi].len);
        int numdata=ntohl(bc[datai].len);

        int currh, currd; /* current header, current data */

        int header_count;
        int index=has_index ? ntohl(bc[i+1].value) : 0; // used for address only
        int match=ntohl(bc[has_index+i+1].value);
        int relation=ntohl(bc[has_index+i+2].value);
        int comparator=ntohl(bc[has_index+i+3].value);
        int apart=ntohl(bc[has_index+i+4].value);
        int count=0;
        int isReg = (match==B_REGEX);
        int ctag = 0;
        regex_t *reg;
        char errbuf[100]; /* Basically unused, as regexps are tested at compile */

        /* set up variables needed for compiling regex */
        if (isReg) {
            ctag = regcomp_flags(comparator, requires);
        }

        /*find the correct comparator fcn*/
        comp = lookup_comp(comparator, match, relation, &comprock);

        if(!comp) {
            res = SIEVE_RUN_ERROR;
            break;
        }
        if (!comprock) {
            comprock = varlist_select(variables, VL_MATCH_VARS)->var;
        }

        /*loop through all the headers*/
        currh=headersi+2;
#if VERBOSE
        printf("about to process %d headers\n", numheaders);
#endif
        for (x=0; x<numheaders && !res; x++)
        {
            const char *this_header;

            currh = unwrap_string(bc, currh, &this_header, NULL);

            if (requires & BFE_VARIABLES) {
                this_header = parse_string(this_header, variables);
            }

            /* Try the next string if we don't have this one */
            if(address) {
                /* Header */
                if(interp->getheader(m, this_header, &val) != SIEVE_OK)
                    continue;
#if VERBOSE
                printf(" [%d] header %s is %s\n", x, this_header, val[0]);
#endif
            } else {
                /* Envelope */
                if(interp->getenvelope(m, this_header, &val) != SIEVE_OK)
                    continue;
            }

            /* count results */
            header_count = 0;
            while (val[header_count] != NULL) {
                ++header_count;
            }

            /* convert index argument value to array index */
            if (index > 0) {
                --index;
                if (index >= header_count) {
                        res = 0;
                        break;
                }
                header_count = index + 1;
            }
            else if (index < 0) {
                index += header_count;
                if (index < 0) {
                        res = 0;
                        break;
                }
                header_count = index + 1;
            }

            /*header exists, now to test it*/
            /*search through all the headers that match*/

            for (y = index; y < header_count && !res; y++) {
#if VERBOSE
                printf("about to parse %s\n", val[y]);
#endif

                address_itr_init(&ai, val[y]);

                while (!res && (a = address_itr_next(&ai)) != NULL) {
#if VERBOSE
                    printf("working addr %s\n", (addr ? addr : "[nil]"));
#endif
                    /*find the part of the address that we want*/
                    switch(apart)
                    {
                    case B_ALL:
                        addr = address_get_all(a, /*canon_domain*/0);
                        break;
                    case B_LOCALPART:
                        addr = address_get_localpart(a);
                        break;
                    case B_DOMAIN:
                        addr = address_get_domain(a, /*canon_domain*/0);
                        break;
                    case B_USER:
                        addr = address_get_user(a);
                        break;
                    case B_DETAIL:
                        addr = address_get_detail(a);
                        break;
                    default:
                        /* this shouldn't happen with correct bytecode */
                        res = SIEVE_RUN_ERROR;
                        goto envelope_err;
                    }

                    if (!addr) addr = xstrdup("");

                    if (match == B_COUNT) {
                        count++;
                    } else {
                        /*search through all the data*/
                        currd=datai+2;
                        for (z=0; z<numdata && !res; z++)
                        {
                            const char *data_val;

                            currd = unwrap_string(bc, currd, &data_val, NULL);

                            if (requires & BFE_VARIABLES) {
                                data_val = parse_string(data_val, variables);
                            }

                            if (isReg) {
                                reg = bc_compile_regex(data_val, ctag,
                                                       errbuf, sizeof(errbuf));
                                if (!reg) {
                                    /* Oops */
                                    free(addr);
                                    res=-1;
                                    goto alldone;
                                }

                                res |= comp(addr, strlen(addr),
                                            (const char *)reg, comprock);
                                free(reg);
                            } else {
#if VERBOSE
                                printf("%s compared to %s(from script)\n",
                                       addr, data_val);
#endif
                                res |= comp(addr, strlen(addr),
                                            data_val, comprock);
                            }
                        } /* For each data */
                    }
                    free(addr);
                } /* For each address */

                address_itr_fini(&ai);
            }/* For each message header */

#if VERBOSE
            printf("end of loop, res is %d, x is %d (%d)\n", res, x, numheaders);
#endif
        } /* For each script header */

        if  (match == B_COUNT)
        {
            snprintf(scount, SCOUNT_SIZE, "%u", count);
            /* search through all the data */
            currd=datai+2;
            for (z=0; z<numdata && !res; z++)
            {
                const char *data_val;

                currd = unwrap_string(bc, currd, &data_val, NULL);

                if (requires & BFE_VARIABLES) {
                    data_val = parse_string(data_val, variables);
                }

                res |= comp(scount, strlen(scount), data_val, comprock);
            }
        }

        /* Update IP */
        i=(ntohl(bc[datai+1].value)/4);

envelope_err:
        break;
    }
    case BC_HEADER:/*14*/
        has_index=1;
        /* fall through */
    case BC_HEADER_PRE_INDEX:/*9*/
        if (0x07 == version && BC_HEADER_PRE_INDEX == op) {
            /* There was a version of the bytecode that had the index extension
             * but did not update the bytecode codepoints, nor did it increment
             * the bytecode version number.  This tests if the index extension
             * was in the bytecode based on the position of the match-type
             * argument.
             * We test for the applicable version number explicitly.
             */
            switch (ntohl(bc[i+2].value)) {
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
    {
        const char** val;

        int headersi=has_index+i+4;/*the i value for the beginning of the headers*/
        int datai=(ntohl(bc[headersi+1].value)/4);

        int numheaders=ntohl(bc[headersi].len);
        int numdata=ntohl(bc[datai].len);

        int currh, currd; /*current header, current data*/

        int header_count;
        int index=has_index ? ntohl(bc[i+1].value) : 0;
        int match=ntohl(bc[has_index+i+1].value);
        int relation=ntohl(bc[has_index+i+2].value);
        int comparator=ntohl(bc[has_index+i+3].value);
        int count=0;
        int isReg = (match==B_REGEX);
        int ctag = 0;
        regex_t *reg;
        char errbuf[100]; /* Basically unused, regexps tested at compile */
        char *decoded_header;

        /* set up variables needed for compiling regex */
        if (isReg) {
            ctag = regcomp_flags(comparator, requires);
        }

        /*find the correct comparator fcn*/
        comp=lookup_comp(comparator, match, relation, &comprock);

        if(!comp) {
            res = SIEVE_RUN_ERROR;
            break;
        }
        if (!comprock) {
            comprock = varlist_select(variables, VL_MATCH_VARS)->var;
        }

        /*search through all the flags for the header*/
        currh=headersi+2;
        for(x=0; x<numheaders && !res; x++)
        {
            const char *this_header;

            currh = unwrap_string(bc, currh, &this_header, NULL);

            if (requires & BFE_VARIABLES) {
                this_header = parse_string(this_header, variables);
            }

            if(interp->getheader(m, this_header, &val) != SIEVE_OK) {
                continue; /*this header does not exist, search the next*/
            }
#if VERBOSE
            printf ("val %s %s %s\n", val[0], val[1], val[2]);
#endif

            /* count results */
            header_count = 0;
            while (val[header_count] != NULL) {
                ++header_count;
            }

            /* convert index argument value to array index */
            if (index > 0) {
                --index;
                if (index >= header_count) {
                        res = 0;
                        break;
                }
                header_count = index + 1;
            }
            else if (index < 0) {
                index += header_count;
                if (index < 0) {
                        res = 0;
                        break;
                }
                header_count = index + 1;
            }

            /* search through all the headers that match */

            for (y = index; y < header_count && !res; y++)
            {
                if  (match == B_COUNT) {
                    count++;
                } else {
                    decoded_header = charset_parse_mimeheader(val[y], 0 /*flags*/);
                    /*search through all the data*/
                    currd=datai+2;
                    for (z=0; z<numdata && !res; z++)
                    {
                        const char *data_val;

                        currd = unwrap_string(bc, currd, &data_val, NULL);

                        if (requires & BFE_VARIABLES) {
                            data_val = parse_string(data_val, variables);
                        }

                        if (isReg) {
                            reg= bc_compile_regex(data_val, ctag, errbuf,
                                                  sizeof(errbuf));
                            if (!reg)
                            {
                                /* Oops */
                                res=-1;
                                goto alldone;
                            }

                            res |= comp(decoded_header, strlen(decoded_header),
                                        (const char *)reg, comprock);
                            free(reg);
                        } else {
                            res |= comp(decoded_header, strlen(decoded_header),
                                        data_val, comprock);
                        }
                    }
                    free(decoded_header);
                }
            }
        }

        if  (match == B_COUNT )
        {
            snprintf(scount, SCOUNT_SIZE, "%u", count);
            /*search through all the data*/
            currd=datai+2;
            for (z=0; z<numdata && !res; z++)
            {
                const char *data_val;

                currd = unwrap_string(bc, currd, &data_val, NULL);

                if (requires & BFE_VARIABLES) {
                    data_val = parse_string(data_val, variables);
                }

#if VERBOSE
                printf("%d, %s \n", count, data_val);
#endif
                res |= comp(scount, strlen(scount), data_val, comprock);
            }

        }

        /* Update IP */
        i=(ntohl(bc[datai+1].value)/4);

        break;
    }
    case BC_STRING:/*21*/
        is_string = 1;

    case BC_HASFLAG:/*15*/
    {
        int haystacksi=i+4;/*the i value for the beginning of the variables*/
        int needlesi=(ntohl(bc[haystacksi+1].value)/4);

        int numhaystacks=ntohl(bc[haystacksi].len); // number of vars to search
        int numneedles=ntohl(bc[needlesi].len); // number of search flags

        int currneedle; /* current needle */
        int currhaystack; /* current needle */

        int match=ntohl(bc[i+1].value);
        int relation=ntohl(bc[i+2].value);
        int comparator=ntohl(bc[i+3].value);
        int count=0;
        int isReg = (match==B_REGEX);
        int ctag = 0;
        regex_t *reg;
        char errbuf[100]; /* Basically unused, regexps tested at compile */

        /* set up variables needed for compiling regex */
        if (isReg) {
            ctag = regcomp_flags(comparator, requires);
        }

        /*find the correct comparator fcn*/
        comp=lookup_comp(comparator, match, relation, &comprock);

        if(!comp) {
            res = SIEVE_RUN_ERROR;
            break;
        }
        if (!comprock) {
            comprock = varlist_select(variables, VL_MATCH_VARS)->var;
        }

        /* loop on each haystack */
        currhaystack = haystacksi+2;
        for (z = 0; z < (is_string ? numhaystacks :
                         numhaystacks ? numhaystacks : 1); z++) {
            const char *this_haystack;
            strarray_t *this_var;

            if (numhaystacks) {
                currhaystack = unwrap_string(bc, currhaystack, &this_haystack,
                                             NULL);
            }

            if (is_string) {
                if (requires & BFE_VARIABLES) {
                    this_haystack = parse_string(this_haystack, variables);
                }
	    } else if (numhaystacks) { // select the var
		variable_list_t *vl;
		vl = varlist_select(variables, this_haystack);
		if (!vl) {
		    vl = varlist_extend(variables);
		    vl->name = xstrdup(this_haystack);
		} else {
		    variable_list_t *vl_temp = varlist_extend(variables);
		    strarray_free(vl_temp->var);
		    vl_temp->var = strarray_dup(vl->var);
		    verify_flaglist(vl_temp->var);
		    vl = vl_temp;
		}
		this_var = vl->var;
            } else { // internal variable
                this_var = variables->var;
            }

	    if (match == B_COUNT) {
                if (is_string) {
                    if (this_haystack[0] != '\0') {
                        count += 1;
                    }
                } else {
                    count += this_var->count;
                }
                /* don't compare the values until all haystacks have been
                 * counted.
                 */
                if (z < numhaystacks - 1) {
                    continue;
                }

		snprintf(scount, SCOUNT_SIZE, "%u", count);
		/*search through all the data*/
		currneedle=needlesi+2;
		for (z=0; z<numneedles && !res; z++) {
		    const char *this_needle;

		    currneedle = unwrap_string(bc, currneedle, &this_needle,
                                               NULL);

		    if (requires & BFE_VARIABLES) {
			this_needle = parse_string(this_needle, variables);
		    }

#if VERBOSE
		    printf("%d, %s \n", count, data_val);
#endif
		    res |= comp(scount, strlen(scount), this_needle, comprock);
		}
                break;
            }

            /* search through the haystack for the needles */
            currneedle=needlesi+2;
            for(x=0; x<numneedles && !res; x++)
                {
                    const char *this_needle;

                    currneedle = unwrap_string(bc, currneedle, &this_needle, NULL);

                    if (requires & BFE_VARIABLES) {
                        this_needle = parse_string(this_needle, variables);
                    }

#if VERBOSE
                    printf ("val %s %s %s\n", val[0], val[1], val[2]);
#endif

                    if (is_string) {
                        if (isReg) {
                            reg = bc_compile_regex(this_needle, ctag, errbuf,
                                                   sizeof(errbuf));
                            if (!reg)
                                {
                                    /* Oops */
                                    res=-1;
                                    goto alldone;
                                }

                            res |= comp(this_haystack, strlen(this_haystack),
                                        (const char *)reg, comprock);
                            free(reg);
                        } else {
                            res |= comp(this_haystack, strlen(this_haystack),
                                        this_needle, comprock);
                        }
                    } else {
                        /* search through all the flags */

                        for (y=0; y < this_var->count && !res; y++)
                            {
                                const char *active_flag;

                                active_flag = this_var->data[y];

                                if (isReg) {
                                    reg= bc_compile_regex(this_needle, ctag, errbuf,
                                                          sizeof(errbuf));
                                    if (!reg)
                                        {
                                            /* Oops */
                                            res=-1;
                                            goto alldone;
                                        }

                                    res |= comp(active_flag, strlen(active_flag),
                                                (const char *)reg, comprock);
                                    free(reg);
                                } else {
                                    res |= comp(active_flag, strlen(active_flag),
                                                this_needle, comprock);
                                }
                            }
                    } // (is_string) else

                } // loop on each item of the current haystack
#if VERBOSE
            {
                /* for debugging purposes only */
                char *temp;
                temp = strarray_join(varlist_select(variables, VL_MATCH_VARS)->var,
                                     ", ");
                printf((!is_string ? "B_hasflag:" : "B_STRING"));
                printf(" %s\n\n", temp);
                free (temp);
            }
#endif
	} // loop on each variable or string

        /* Update IP */
        i=(ntohl(bc[needlesi+1].value)/4);

        break;
    }
    case BC_BODY:/*10*/
    {
        sieve_bodypart_t ** val;
        const char **content_types = NULL;

        int typesi=i+6;/* the i value for the beginning of the content-types */
        int datai=(ntohl(bc[typesi+1].value)/4);

        int numdata=ntohl(bc[datai].len);

        int currd; /* current data */

        int match=ntohl(bc[i+1].value);
        int relation=ntohl(bc[i+2].value);
        int comparator=ntohl(bc[i+3].value);
        int transform=ntohl(bc[i+4].value);
        /* ntohl(bc[i+5].value) is the now unused 'offset' */
        int count=0;
        int isReg = (match==B_REGEX);
        int ctag = 0;
        regex_t *reg;
        char errbuf[100]; /* Basically unused, as regexps are tested at compile */

        /* set up variables needed for compiling regex */
        if (isReg) {
            ctag = regcomp_flags(comparator, requires);
        }

        /*find the correct comparator fcn*/
        comp = lookup_comp(comparator, match, relation, &comprock);

        if(!comp) {
            res = SIEVE_RUN_ERROR;
            break;
        }
	/*
          RFC 5173         Sieve Email Filtering: Body Extension        April 2008

          6. Interaction with Other Sieve Extensions

          Any extension that extends the grammar for the COMPARATOR or MATCH-
          TYPE nonterminals will also affect the implementation of "body".

          Wildcard expressions used with "body" are exempt from the side
          effects described in [VARIABLES].  That is, they MUST NOT set match
          variables (${1}, ${2}...) to the input values corresponding to
          wildcard sequences in the matched pattern.  However, if the extension
          is present, variable references in the key strings or content type
          strings are evaluated as described in this document
        */

        if (transform == B_RAW) {
            /* XXX - we never handled this properly, it has to search the
             * RAW message body, totally un-decoded, as a single string
             *
             * ignore - or just search in the UTF-8.  I think the UTF-8 makes more sense
             */
             /* break; */
        }

        /*find the part(s) of the body that we want*/
        content_types = bc_makeArray(bc, &typesi);
        if(interp->getbody(m, content_types, &val) != SIEVE_OK) {
            res = SIEVE_RUN_ERROR;
            break;
        }
        free(content_types);

        /* bodypart(s) exist, now to test them */

        for (y = 0; val && val[y] && !res; y++) {

            if (match == B_COUNT) {
                count++;
            } else if (val[y]->decoded_body) {
                const char *content = val[y]->decoded_body;

                /* search through all the data */
                currd=datai+2;
                for (z=0; z<numdata && !res; z++)
                {
                    const char *data_val;

                    currd = unwrap_string(bc, currd, &data_val, NULL);

                    if (requires & BFE_VARIABLES) {
                        data_val = parse_string(data_val, variables);
                    }

                    if (isReg) {
                        reg = bc_compile_regex(data_val, ctag,
                                               errbuf, sizeof(errbuf));
                        if (!reg) {
                            /* Oops */
                            res=-1;
                            goto alldone;
                        }

                        res |= comp(content, strlen(content), (const char *)reg, comprock);
                        free(reg);
                    } else {
                        res |= comp(content, strlen(content), data_val, comprock);
                    }
                } /* For each data */
            }

            /* free the bodypart */
            free(val[y]);

        } /* For each body part */

        /* free the bodypart array */
        if (val) free(val);

        if  (match == B_COUNT)
        {
            snprintf(scount, SCOUNT_SIZE, "%u", count);
            /* search through all the data */
            currd=datai+2;
            for (z=0; z<numdata && !res; z++)
            {
                const char *data_val;

                currd = unwrap_string(bc, currd, &data_val, NULL);

                if (requires & BFE_VARIABLES) {
                    data_val = parse_string(data_val, variables);
                }

                res |= comp(scount, strlen(scount), data_val, comprock);
            }
        }

        /* Update IP */
        i=(ntohl(bc[datai+1].value)/4);

        break;
    }
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
            switch (ntohl(bc[i+4].value)) {
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
                switch (ntohl(bc[i+5].value)) {
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
                    if (B_TIMEZONE == ntohl(bc[i+1].value) &&
                            B_ORIGINALZONE == ntohl(bc[i+2].value)) {
                        /* This is the ambiguous case.  Resolve the ambiguity
                         * by assuming that there is no :index tag since the
                         * unnumbered bytecode that shipped with Kolab
                         * Groupware 3.3 included support for the date
                         * extension, but not for the index extension.
                         */
                        has_index = 0;

                    } else if (B_TIMEZONE == ntohl(bc[i+1].value)) {
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
    {
        char buffer[64];
        const char **headers = NULL;
        const char **key;
        const char **keylist = NULL;
        const char *header = NULL;
        const char *header_data;
        const char *header_name = NULL;
        int comparator;
        int date_part;
        int header_count;
        int index;
        int match;
        int relation;
        int timezone_offset = 0;
        int zone;
        struct tm tm;
        time_t t;

        ++i; /* BC_DATE | BC_CURRENTDATE */

        /* index */
        index = has_index ? ntohl(bc[i++].value) : 0;

        /* zone tag */
        zone = ntohl(bc[i++].value);

        /* timezone offset */
        if (zone == B_TIMEZONE) {
                timezone_offset = ntohl(bc[i++].value);
        }

        /* comparator */
        match = ntohl(bc[i++].value);
        relation = ntohl(bc[i++].value);
        comparator = ntohl(bc[i++].value);

        /* find comparator function */
        comp = lookup_comp(comparator, match, relation, &comprock);
        if(!comp) {
                res = SIEVE_RUN_ERROR;
                break;
        }
        if (!comprock) {
            comprock = varlist_select(variables, VL_MATCH_VARS)->var;
        }

        /* date-part */
        date_part = ntohl(bc[i++].value);

        if (BC_DATE == op) {
                /* header name */
                i = unwrap_string(bc, i, &header_name, NULL);

                if (requires & BFE_VARIABLES) {
                    header_name = parse_string(header_name, variables);
                }

                /*
                 * Process header
                 */

                if (interp->getheader(m, header_name, &headers) != SIEVE_OK) {
                        res = 0;
                        free(bc_makeArray(bc, &i));
                        break;
                }

                /* count results */
                header_count = 0;
                while (headers[header_count] != NULL) {
                        ++header_count;
                }

                /* convert index argument value to array index */
                if (index > 0) {
                        --index;
                        if (index >= header_count) {
                                res = 0;
                                free(bc_makeArray(bc, &i));
                                break;
                        }
                        header_count = index + 1;
                }
                else if (index < 0) {
                        index += header_count;
                        if (index < 0) {
                                res = 0;
                                free(bc_makeArray(bc, &i));
                                break;
                        }
                        header_count = index + 1;
                }

                /* check if index is out of bounds */
                if (index < 0 || index >= header_count) {
                        res = 0;
                        free(bc_makeArray(bc, &i));
                        break;
                }
                header = headers[index];

                /* look for separator */
                header_data = strrchr(header, ';');
                if (header_data) {
                        /* separator found, skip character and continue */
                        ++header_data;
                }
                else {
                        /* separator not found, use full header */
                        header_data = header;
                }

                if (-1 == time_from_rfc822(header_data, &t)) {
                        res = 0;
                        free(bc_makeArray(bc, &i));
                        break;
                }

                /* timezone offset */
                if (zone == B_ORIGINALZONE) {
                        char *zone;
                        char sign;
                        int hours;
                        int minutes;

                        zone = strrchr(header, ' ');
                        if (!zone ||
                            3 != sscanf(zone + 1, "%c%02d%02d", &sign, &hours, &minutes)) {
                                res = 0;
                                free(bc_makeArray(bc, &i));
                                break;
                        }

                        timezone_offset = (sign == '-' ? -1 : 1) * ((hours * 60) + (minutes));
                }
        }
        else { /* CURRENTDATE */
                t = interp->time;
        }

        /* apply timezone_offset (if any) */
        t += timezone_offset * 60;

        /* get tm struct */
        gmtime_r(&t, &tm);


        /*
         * Tests
         */

        if (match == B_COUNT) {
                res = SIEVE_OK;
                goto alldone;
        }

        keylist = bc_makeArray(bc, &i);
        for (key = keylist; *key; ++key) {
                switch (date_part) {
                case B_YEAR:
                        snprintf(buffer, sizeof(buffer), "%04d", 1900 + tm.tm_year);
                        break;
                case B_MONTH:
                        snprintf(buffer, sizeof(buffer), "%02d", 1 + tm.tm_mon);
                        break;
                case B_DAY:
                        snprintf(buffer, sizeof(buffer), "%02d", tm.tm_mday);
                        break;
                case B_DATE:
                        snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d",
                            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday);
                        break;
                case B_JULIAN: {
                        int month, year;
                        int c, ya;

                        month = 1 + tm.tm_mon;
                        year = 1900 + tm.tm_year;

                        if (month > 2) {
                            month -= 3;
                        }
                        else {
                            month += 9;
                            --year;
                        }
                        c = year / 100;
                        ya = year - c * 100;

                        snprintf(buffer, sizeof(buffer), "%d",
                            (c * 146097 / 4 + ya * 1461 / 4 +
                              (month * 153 + 2) / 5 + tm.tm_mday + 1721119));
                        } break;
                case B_HOUR:
                        snprintf(buffer, sizeof(buffer), "%02d", tm.tm_hour);
                        break;
                case B_MINUTE:
                        snprintf(buffer, sizeof(buffer), "%02d", tm.tm_min);
                        break;
                case B_SECOND:
                        snprintf(buffer, sizeof(buffer), "%02d", tm.tm_sec);
                        break;
                case B_TIME:
                        snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d",
                            tm.tm_hour, tm.tm_min, tm.tm_sec);
                        break;
                case B_ISO8601:
                        time_to_iso8601(t, buffer, sizeof(buffer), 1);
                        break;
                case B_STD11:
                        time_to_rfc822(t, buffer, sizeof(buffer));
                        break;
                case B_ZONE:
                        snprintf(buffer, sizeof(buffer), "%c%02d%02d",
                            timezone_offset >= 0 ? '+' : '-',
                            abs(timezone_offset) / 60,
                            abs(timezone_offset) % 60);
                        break;
                case B_WEEKDAY:
                        snprintf(buffer, sizeof(buffer), "%1d", tm.tm_wday);
                        break;
                }

                res |= comp(buffer, strlen(buffer), *key, comprock);
        }
        free(keylist);
        break;
    }
    case BC_MAILBOXEXISTS:/*16*/
        res = 0;
        i++;
        list_len=ntohl(bc[i++].len);
        list_end=ntohl(bc[i++].len)/4;

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x=0; x<list_len && !res; x++) {
            const char *extname;

            /* this is a mailbox name in external namespace */
            i = unwrap_string(bc, i, &extname, NULL);
            res = interp->getmailboxexists(sc, extname);
            if (res) break;
        }

        i = list_end; /* handle short-circuting */
        break;

    case BC_METADATA:/*17*/
    {
        res = 0;
        const char *extname = NULL;
        const char *keyname = NULL;
        char *val = NULL;
        i++;
        int match=ntohl(bc[i++].value);
        int relation=ntohl(bc[i++].value);
        int comparator=ntohl(bc[i++].value);
        int isReg = (match==B_REGEX);
        int ctag = 0;
        regex_t *reg;
        char errbuf[100]; /* Basically unused, regexps tested at compile */

        /* set up variables needed for compiling regex */
        if (isReg) {
            ctag = regcomp_flags(comparator, requires);
        }

        /*find the correct comparator fcn*/
        comp=lookup_comp(comparator, match, relation, &comprock);

        if(!comp) {
            res = SIEVE_RUN_ERROR;
            break;
        }

        i = unwrap_string(bc, i, &extname, NULL);
        i = unwrap_string(bc, i, &keyname, NULL);
        /* unpack the world */
        list_len=ntohl(bc[i++].len);
        list_end=ntohl(bc[i++].len)/4;

        interp->getmetadata(sc, extname, keyname, &val);

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x=0; val && x<list_len; x++) {
            const char *testval;

            /* this is a mailbox name in external namespace */
            i = unwrap_string(bc, i, &testval, NULL);

            if (isReg) {
                reg = bc_compile_regex(testval, ctag,
                                       errbuf, sizeof(errbuf));
                if (!reg) {
                    /* Oops */
                    free(val);
                    res=-1;
                    goto alldone;
                }

                res |= comp(val, strlen(val),
                            (const char *)reg, comprock);
                free(reg);
            } else {
#if VERBOSE
                printf("%s compared to %s(from script)\n",
                       val, testval);
#endif
                res |= comp(val, strlen(val),
                            testval, comprock);
            }
            if (res) break;
        }

        i = list_end; /* handle short-circuting */
        free(val);
        break;
    }

    case BC_METADATAEXISTS:/*18*/
    {
        res = 1;
        const char *extname = NULL;
        i++;
        i = unwrap_string(bc, i, &extname, NULL);
        /* unpack the world */
        list_len=ntohl(bc[i++].len);
        list_end=ntohl(bc[i++].len)/4;

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x=0; x<list_len; x++) {
            const char *keyname = NULL;
            char *val = NULL;

            /* this is an annotation name */
            i = unwrap_string(bc, i, &keyname, NULL);

            interp->getmetadata(sc, extname, keyname, &val);
            if (!val) res = 0;
            free(val);
            if (!res) break;
        }

        i = list_end; /* handle short-circuting */
        break;
    }

    case BC_SERVERMETADATA:/*19*/
    {
        res = 0;
        const char *keyname = NULL;
        char *val = NULL;
        i++;
        int match=ntohl(bc[i++].value);
        int relation=ntohl(bc[i++].value);
        int comparator=ntohl(bc[i++].value);
        int isReg = (match==B_REGEX);
        int ctag = 0;
        regex_t *reg;
        char errbuf[100]; /* Basically unused, regexps tested at compile */

        /* set up variables needed for compiling regex */
        if (isReg) {
            ctag = regcomp_flags(comparator, requires);
        }

        /*find the correct comparator fcn*/
        comp=lookup_comp(comparator, match, relation, &comprock);

        if(!comp) {
            res = SIEVE_RUN_ERROR;
            break;
        }
        i = unwrap_string(bc, i, &keyname, NULL);
        /* unpack the world */
        list_len=ntohl(bc[i++].len);
        list_end=ntohl(bc[i++].len)/4;

        interp->getmetadata(sc, NULL, keyname, &val);

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x=0; val && x<list_len; x++) {
            const char *testval;

            /* this is a mailbox name in external namespace */
            i = unwrap_string(bc, i, &testval, NULL);

            if (isReg) {
                reg = bc_compile_regex(testval, ctag,
                                       errbuf, sizeof(errbuf));
                if (!reg) {
                    /* Oops */
                    free(val);
                    res=-1;
                    goto alldone;
                }

                res |= comp(val, strlen(val),
                            (const char *)reg, comprock);
                free(reg);
            } else {
#if VERBOSE
                printf("%s compared to %s(from script)\n",
                       val, testval);
#endif
                res |= comp(val, strlen(val),
                            testval, comprock);
            }
            if (res) break;
        }

        i = list_end; /* handle short-circuting */
        free(val);
        break;
    }

    case BC_SERVERMETADATAEXISTS:/*20*/
    {
        res = 1;
        /* unpack the world */
        i++;
        list_len=ntohl(bc[i++].len);
        list_end=ntohl(bc[i++].len)/4;

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x=0; x<list_len; x++) {
            const char *keyname = NULL;
            char *val = NULL;

            /* this is an annotation name */
            i = unwrap_string(bc, i, &keyname, NULL);

            interp->getmetadata(sc, NULL, keyname, &val);
            if (!val) res = 0;
            free(val);
            if (!res) break;
        }

        i = list_end; /* handle short-circuting */
        break;
    }

    default:
#if VERBOSE
        printf("WERT, can't evaluate if statement. %d is not a valid command",
               op);
#endif
        return SIEVE_RUN_ERROR;
    }


 alldone:

    *ip=i;
    return res;
}

int sieve_bytecode_version(const sieve_bytecode_t *bc)
{
    if (!bc) return 0;

    int version, v_index;
    const bytecode_input_t *input = (bytecode_input_t *) bc->data;

    v_index = BYTECODE_MAGIC_LEN / sizeof(bytecode_input_t);
    version = ntohl(input[v_index].op);

    /* XXX may need to convert value "1" from host byte order? */
    return version;
}

/* The entrypoint for bytecode evaluation */
int sieve_eval_bc(sieve_execute_t *exe, int is_incl, sieve_interp_t *i,
                  void *sc, void *m,
                  variable_list_t *variables, action_list_t *actions,
                  notify_list_t *notify_list, const char **errmsg)
{
    const char *data;
    int res=0;
    int op;
    int version;
    int requires = 0;

    sieve_bytecode_t *bc_cur = exe->bc_cur;
    bytecode_input_t *bc = (bytecode_input_t *) bc_cur->data;
    int ip = 0, ip_max = (bc_cur->len/sizeof(bytecode_input_t));

    if (bc_cur->is_executing) {
        *errmsg = "Recursive Include";
        return SIEVE_RUN_ERROR;
    }
    bc_cur->is_executing = 1;

    /* Check that we
     * a) have bytecode
     * b) it is atleast long enough for the magic number, the version
     *    and one opcode */
    if(!bc) return SIEVE_FAIL;
    if(bc_cur->len < (BYTECODE_MAGIC_LEN + 2*sizeof(bytecode_input_t)))
       return SIEVE_FAIL;

    if(memcmp(bc, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN)) {
        *errmsg = "Not a bytecode file";
        return SIEVE_FAIL;
    }

    ip = BYTECODE_MAGIC_LEN / sizeof(bytecode_input_t);

    version = sieve_bytecode_version(bc_cur);

    /* this is because there was a time where integers were not network byte
       order.  all the scripts written then would have version 0x01 written
       in host byte order.*/

     if(version == (int)ntohl(1)) {
        if(errmsg) {
            *errmsg =
                "Incorrect Bytecode Version, please recompile (use sievec)";

        }
        return SIEVE_FAIL;
    }

    if((version < BYTECODE_MIN_VERSION) || (version > BYTECODE_VERSION)) {
        if(errmsg) {
            *errmsg =
                "Incorrect Bytecode Version, please recompile (use sievec)";
        }
        return SIEVE_FAIL;
    }

#if VERBOSE
    printf("version number %d\n",version);
#endif

    if (version >= 0x11) {
        requires = ntohl(bc[++ip].value);
    }

    for(ip++; ip<ip_max; ) {
        /* In this loop, when a case is switch'ed to, ip points to the first
         * parameter of the action.  This makes it easier to add future
         * extensions.  Extensions that change an existing action should add
         * any new parameters to the beginning of the particular action's
         * bytecode.  This will allow the new code to fall through to the
         * older code, which will then parse the older parameters and should
         * require only a minimal set of changes to support any new extension.
         */
        int copy = 0;
        int create = 0;
        strarray_t *actionflags = NULL;
        variable_list_t *variable = NULL;

        op=ntohl(bc[ip++].op);
        switch(op) {
        case B_STOP:/*0*/
            res=1;
            break;

        case B_KEEP:/*22*/
        {
            int x;
            int list_len=ntohl(bc[ip].len);

            ip+=2; /* skip opcode, list_len, and list data len */

            if (list_len) {
                actionflags = (varlist_extend(variables))->var;
            }
            for (x=0; x<list_len; x++) {
                const char *flag;
                ip = unwrap_string(bc, ip, &flag, NULL);

                if (requires & BFE_VARIABLES) {
                    flag = parse_string(flag, variables);
                }

                if (flag[0]) {
                strarray_add_case(actionflags,flag);
                }
            }
        }
            copy = ntohl(bc[ip++].value);
            /* fall through */
        case B_KEEP_ORIG:/*1*/
            /* if there's no :flags parameter, use the internal flags var*/
            if (!actionflags) {
                variable_list_t *temp = varlist_extend(variables);
                actionflags = strarray_dup(variables->var);
                strarray_free(temp->var);
                temp->var = actionflags;
            }
            verify_flaglist(actionflags);

            res = do_keep(actions, !copy, actionflags);
            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Keep can not be used with Reject";
            actionflags = NULL;
            break;

        case B_DISCARD:/*2*/
            res=do_discard(actions);
            break;

        case B_REJECT:/*3*/
        case B_EREJECT:/*31*/
            ip = unwrap_string(bc, ip, &data, NULL);

            if (requires & BFE_VARIABLES) {
                data = parse_string(data, variables);
            }

            res = do_reject(actions,
                            (op == B_EREJECT) ? ACTION_EREJECT : ACTION_REJECT,
                            data);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "[e]Reject can not be used with any other action";

            break;

        case B_FILEINTO:/*24*/
            create = ntohl(bc[ip].value);
            ip+=1;

            /* fall through */
        case B_FILEINTO_FLAGS:/*23*/
        {
            int x;
            int list_len=ntohl(bc[ip].len);

            ip+=2; /* skip opcode, list_len, and list data len */

            if (list_len) {
                actionflags = (varlist_extend(variables))->var;
            }
            for (x=0; x<list_len; x++) {
                const char *flag;
                ip = unwrap_string(bc, ip, &flag, NULL);

                if (requires & BFE_VARIABLES) {
                    flag = parse_string(flag, variables);
                }

                if (flag[0]) {
                strarray_add_case(actionflags,flag);
                }
            }
        }
            /* fall through */
        case B_FILEINTO_COPY:/*19*/
            copy = ntohl(bc[ip].value);
            ip+=1;

            /* fall through */
        case B_FILEINTO_ORIG:/*4*/
        {
            /* if there's no :flags parameter, use the internal flags var*/
            if (!actionflags) {
                variable_list_t *temp = varlist_extend(variables);
                actionflags = strarray_dup(variables->var);
                strarray_free(temp->var);
                temp->var = actionflags;
            }
            verify_flaglist(actionflags);

            ip = unwrap_string(bc, ip, &data, NULL);

            if (requires & BFE_VARIABLES) {
                data = parse_string(data, variables);
            }

            res = do_fileinto(actions, data, !copy, create, actionflags);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Fileinto can not be used with Reject";

            actionflags = NULL;
            break;
        }

        case B_REDIRECT:/*20*/
            copy = ntohl(bc[ip].value);
            ip+=1;

            /* fall through */
        case B_REDIRECT_ORIG:/*5*/
        {
            ip = unwrap_string(bc, ip, &data, NULL);

            if (requires & BFE_VARIABLES) {
                data = parse_string(data, variables);
            }

            res = do_redirect(actions, data, !copy);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Redirect can not be used with Reject";

            break;
        }

        case B_IF:/*6*/
        {
            int testend=ntohl(bc[ip].value);
            int result;

            ip+=1;
            result=eval_bc_test(i, m, sc, bc, &ip, variables, version, requires);

            if (result<0) {
                *errmsg = "Invalid test";
                return SIEVE_FAIL;
            } else if (result) {
                /*skip over jump instruction*/
                testend+=2;
            }
            ip=testend;

            break;
        }

        case B_MARK:/*7*/
        {
            int n = i->markflags->count;
            while (n) {
                strarray_add_case(variables->var, i->markflags->data[--n]);
            }
        }
            break;

        case B_UNMARK:/*8*/
        {
            int n = i->markflags->count;
            while (n) {
                strarray_remove_all_case(variables->var,
                        i->markflags->data[--n]);
            }
        }
            break;

        case B_ADDFLAG:/*26*/
            /* get the variable name */
            ip = unwrap_string(bc, ip, &data, NULL);
            /* RFC 5229, 3. Interpretation of Strings
               Strings where no variable substitutions take place are referred to as
               constant strings.  Future extensions may specify that passing non-
               constant strings as arguments to its actions or tests is an error.

               The name MUST be a constant string and conform
               to the syntax of variable-name.
               (this is done in the parser in sieve.y)
            */

            /* select or create the variable */
            variable = varlist_select(variables, data);
            if (variable) {
                actionflags = variable->var;
            } else {
                actionflags = (variable = varlist_extend(variables))->var;
                variable->name = xstrdup(data);
            }

            /* fall through */
        case B_ADDFLAG_ORIG:/*9*/
        {
            int x;
            int list_len=ntohl(bc[ip].len);

            ip+=2; /* skip opcode, list_len, and list data len */

            if (!actionflags) {
                actionflags = variables->var;
            }

            for (x=0; x<list_len; x++) {
                ip = unwrap_string(bc, ip, &data, NULL);

                if (requires & BFE_VARIABLES) {
                    data = parse_string(data, variables);
                }
                strarray_add_case(actionflags, data);
            }
            verify_flaglist(actionflags);
            break;
        }

        case B_SETFLAG:/*27*/
            /* get the variable name */
            ip = unwrap_string(bc, ip, &data, NULL);
            /* RFC 5229, 3. Interpretation of Strings
               Strings where no variable substitutions take place are referred to as
               constant strings.  Future extensions may specify that passing non-
               constant strings as arguments to its actions or tests is an error.

               The name MUST be a constant string and conform
               to the syntax of variable-name.
               (this is done in the parser in sieve.y)
            */

            /* select or create the variable */
            variable = varlist_select(variables, data);
            if (variable) {
                actionflags = variable->var;
            } else {
                actionflags = (variable = varlist_extend(variables))->var;
                variable->name = xstrdup(data);
            }

            /* fall through */
        case B_SETFLAG_ORIG:/*10*/
        {
            int x;
            int list_len=ntohl(bc[ip].len);

            ip+=2; /* skip opcode, list_len, and list data len */

            if (!actionflags) {
                actionflags = variables->var;
            }

            strarray_fini(actionflags);

            for (x=0; x<list_len; x++) {
                ip = unwrap_string(bc, ip, &data, NULL);

                if (requires & BFE_VARIABLES) {
                    data = parse_string(data, variables);
                }

                if (data[0]) {
                    strarray_add_case(actionflags, data);
                }
            }

	    verify_flaglist(actionflags);
            break;
        }

        case B_REMOVEFLAG:/*28*/
            /* get the variable name */
            ip = unwrap_string(bc, ip, &data, NULL);
            /* RFC 5229, 3. Interpretation of Strings
               Strings where no variable substitutions take place are referred to as
               constant strings.  Future extensions may specify that passing non-
               constant strings as arguments to its actions or tests is an error.

               The name MUST be a constant string and conform
               to the syntax of variable-name.
               (this is done in the parser in sieve.y)
            */

            /* select or create the variable */
            variable = varlist_select(variables, data);
            if (variable) {
                actionflags = variable->var;
            } else {
                /* variable doesn't exist, so we're done */
                break;
            }

            /* fall through */
        case B_REMOVEFLAG_ORIG:/*11*/
        {
          int x, y;
            int list_len=ntohl(bc[ip].len);
            strarray_t temp = STRARRAY_INITIALIZER;

            ip+=2; /* skip opcode, list_len, and list data len */

            if (!actionflags) {
                actionflags = variables->var;
            }
	    verify_flaglist(actionflags);

            for (x=0; x<list_len; x++) {
                ip = unwrap_string(bc, ip, &data, NULL);

                if (requires & BFE_VARIABLES) {
                    data = parse_string(data, variables);
                }

                strarray_append(&temp, data);
                verify_flaglist(&temp);

                for (y = 0; y < temp.count; y++) {
                    data = temp.data[y];
                    strarray_remove_all_case(actionflags, data);
                }

		strarray_fini(&temp);
	    } 
            break;
        }

        case B_NOTIFY:/*12*/
        {
            const char * id;
            const char * method;
            const char **options = NULL;
            const char *priority = NULL;
            const char * message;
            int pri;

            /* method */
            ip = unwrap_string(bc, ip, &method, NULL);

            /* RFC 5435 (Sieve Extension: Notifications)
             * Section 8. Security Considerations
             * implementations SHOULD NOT allow the use of variables containing
             * values extracted from the email message in the "method" parameter to
             * the "notify" action.
             */

            /* id */
            ip = unwrap_string(bc, ip, &id, NULL);

	    /* draft-ietf-sieve-notify-12:
	     * Changes since draft-ietf-sieve-notify-00
	     * Removed the :id parameter to the notify action. */

            /*options*/
            options=bc_makeArray(bc, &ip);

            /* priority */
            pri=ntohl(bc[ip].value);
            ip++;

            switch (pri)
            {
            case B_LOW:
                priority="low";
                break;
            case B_NORMAL:
                priority="normal";
                break;
            case B_HIGH:
                priority="high";
                break;
            case B_ANY:
                priority="any";
                break;
            default:
                res=SIEVE_RUN_ERROR;
            }

            /* message */
            ip = unwrap_string(bc, ip, &message, NULL);

            if (requires & BFE_VARIABLES) {
                message = parse_string(message, variables);
            }

            res = do_notify(notify_list, id, method, options,
                            priority, message);

            break;
        }
        case B_DENOTIFY:/*13*/
        {
         /*
          * i really have no idea what the count matchtype should do here.
          * the sanest thing would be to use 1.
          * however that would require passing on the match type to do_notify.
          *  -jsmith2
          */

            comparator_t *comp = NULL;

            const char *pattern;
            regex_t *reg;

            const char *priority = NULL;
            void *comprock = NULL;

            int comparator;
            int pri;

            pri=ntohl(bc[ip].value);
            ip++;

            switch (pri)
            {
            case B_LOW:
                priority="low";
                break;
            case B_NORMAL:
                priority="normal";
                break;
            case B_HIGH:
                priority="high";
                break;
            case B_ANY:
                priority="any";
                break;
            default:
                res=SIEVE_RUN_ERROR;
            }

            if(res == SIEVE_RUN_ERROR)
                break;

            comparator =ntohl( bc[ip].value);
            ip++;

            if (comparator == B_ANY)
            {
                ip++;/* skip placeholder this has no comparator function */
                comp=NULL;
            } else {
                int x= ntohl(bc[ip].value);
                ip++;

                comp=lookup_comp(B_ASCIICASEMAP,comparator,
                                 x, &comprock);
                if (!comprock) {
                    comprock = varlist_select(variables, VL_MATCH_VARS)->var;
                }
            }

            ip = unwrap_string(bc, ip, &pattern, NULL);

	    /* draft-ietf-sieve-notify-12:
	     * Changes since draft-ietf-sieve-notify-00
	     * Removed denotify action. */
	  
            if (comparator == B_REGEX)
            {
                char errmsg[1024]; /* Basically unused */

                reg=bc_compile_regex(pattern,
                                     REG_EXTENDED | REG_NOSUB | REG_ICASE,
                                     errmsg, sizeof(errmsg));
                if (!reg) {
                    res = SIEVE_RUN_ERROR;
                } else {
                    res = do_denotify(notify_list, comp, reg,
                                      comprock, priority);
                    free(reg);
                }
            } else {
                res = do_denotify(notify_list, comp, pattern,
                                  comprock, priority);
            }

            break;
        }
        case B_VACATION_ORIG:/*14*/
        case B_VACATION:/*21*/
        {
            int respond;
            char *fromaddr = NULL; /* relative to message we send */
            char *toaddr = NULL; /* relative to message we send */
            const char *handle = NULL;
            const char *message = NULL;
            int seconds, mime;
            char buf[128];
            char subject[1024];
            int x;

            x = ntohl(bc[ip].len);

            respond = shouldRespond(m, i, x, bc, ip+2,
				    &fromaddr, &toaddr, variables, requires);

            ip = ntohl(bc[ip+1].value) / 4;
            if (respond==SIEVE_OK)
            {
                ip = unwrap_string(bc, ip, &data, NULL);

                if (requires & BFE_VARIABLES) {
                    data = parse_string(data, variables);
                }

                if (!data)
                {
                    /* we have to generate a subject */
                    const char **s;
                    strlcpy(buf, "subject", sizeof(buf));
                    if (i->getheader(m, buf, &s) != SIEVE_OK ||
                        s[0] == NULL) {
                        strlcpy(subject, "Automated reply", sizeof(subject));
                    } else {
                        /* s[0] contains the original subject */
                        const char *origsubj = s[0];
                        snprintf(subject, sizeof(subject), "Auto: %s", origsubj);
                    }
                } else {
                    /* user specified subject */
                    strlcpy(subject, data, sizeof(subject));
                }

                ip = unwrap_string(bc, ip, &message, NULL);

                if (requires & BFE_VARIABLES) {
                    message = parse_string(message, variables);
                }

                seconds = ntohl(bc[ip].value);
                if (op == B_VACATION_ORIG) {
                    seconds *= DAY2SEC;
                }
                mime = ntohl(bc[ip+1].value);

                ip+=2;

                if (version >= 0x05) {
                    ip = unwrap_string(bc, ip, &data, NULL);

                    if (requires & BFE_VARIABLES) {
                        data = parse_string(data, variables);
                    }

                    if (data) {
                        /* user specified from address */
                        free(fromaddr);
                        fromaddr = xstrdup(data);
                    }

                    ip = unwrap_string(bc, ip, &data, NULL);

                    if (requires & BFE_VARIABLES) {
                        data = parse_string(data, variables);
                    }

                    if (data) {
                        /* user specified handle */
                        handle = data;
                    }
                }

                res = do_vacation(actions, toaddr, fromaddr, xstrdup(subject),
                                  message, seconds, mime, handle);

                if (res == SIEVE_RUN_ERROR)
                    *errmsg = "Vacation can not be used with Reject or Vacation";
            } else if (respond == SIEVE_DONE) {
                /* skip subject and message */

                ip = unwrap_string(bc, ip, &data, NULL);
                ip = unwrap_string(bc, ip, &data, NULL);

                ip+=2;/*skip days and mime flag*/

                if (version >= 0x05) {
                    /* skip from and handle */
                    ip = unwrap_string(bc, ip, &data, NULL);
                    ip = unwrap_string(bc, ip, &data, NULL);
                }
            } else {
                res = SIEVE_RUN_ERROR; /* something is bad */
            }

            break;
        }
        case B_NULL:/*15*/
            break;

        case B_JUMP:/*16*/
            ip= ntohl(bc[ip].jump);
            break;

        case B_INCLUDE:/*17*/
        {
            int isglobal = (ntohl(bc[ip].value) & 63) == B_GLOBAL;
            int once = ntohl(bc[ip].value) & 64 ? 1 : 0;
            int isoptional = ntohl(bc[ip].value) & 128 ? 1 : 0;
            char fpath[4096];

            ip = unwrap_string(bc, ip+1, &data, NULL);

            if (requires & BFE_VARIABLES) {
                data = parse_string(data, variables);
            }

            res = i->getinclude(sc, data, isglobal, fpath, sizeof(fpath));
            if (res != SIEVE_OK) {
                if (isoptional == 0)
                    *errmsg = "Include can not find script";
                else
                    res = SIEVE_OK;
                break;
            }
            res = sieve_script_load(fpath, &exe);
            if (res == SIEVE_SCRIPT_RELOADED) {
                if (once == 1) {
                    res = SIEVE_OK;
                    break;
                }
            } else if (res != SIEVE_OK) { /* SIEVE_FAIL */
                if (isoptional == 0)
                    *errmsg = "Include can not load script";
                else
                    res = SIEVE_OK;
                break;
            }

            res = sieve_eval_bc(exe, 1, i,
				sc, m, variables, actions,
				notify_list, errmsg);
            break;
        }

        case B_RETURN:/*18*/
            if (is_incl)
                goto done;
            else
                res=1;
            break;

        case B_SET:/*25*/
        {
            int modifiers = ntohl(bc[ip++].value);

            /* get the variable name */
            ip = unwrap_string(bc, ip, &data, NULL);
	    /* RFC 5229, 3. Interpretation of Strings
               Strings where no variable substitutions take place are referred to as
               constant strings.  Future extensions may specify that passing non-
               constant strings as arguments to its actions or tests is an error.

               The name MUST be a constant string and conform
               to the syntax of variable-name.
               (this is done in the parser in sieve.y)
            */

            /* select or create the variable */
            variable = varlist_select(variables, data);
            if (variable) {
                actionflags = variable->var;
            } else {
                actionflags = (variable = varlist_extend(variables))->var;
                variable->name = xstrdup(data);
            }

            /* get the variable value */
            ip = unwrap_string(bc, ip, &data, NULL);

            strarray_fini(variable->var);
            data = parse_string(data, variables);
            strarray_appendm(variable->var,
                             variables_modify_string(data, modifiers));
#if VERBOSE
	    printf("\nB_SET:%s\n\n", strarray_nth(variable->var, -1));
#endif
            actionflags = NULL;
            break;
        }

        case B_ADDHEADER:/*29*/
        {
            const char *name, *value, *h;
            int index = ntohl(bc[ip++].value);

            /* get the header name */
            ip = unwrap_string(bc, ip, &name, NULL);

            if (requires & BFE_VARIABLES) {
                name = parse_string(name, variables);
            }

            /* validate header name */
            for (h = name; *h; h++) {
                /* field-name      =       1*ftext
                   ftext           =       %d33-57 / %d59-126
                   ; Any character except
                   ;  controls, SP, and
                   ;  ":". */
                if (!((*h >= 33 && *h <= 57) || (*h >= 59 && *h <= 126))) {
                    *errmsg = "Invalid header field name in Addheader";
                    return SIEVE_RUN_ERROR;
                }
            }
            
            /* get the header value */
            ip = unwrap_string(bc, ip, &value, NULL);

            if (requires & BFE_VARIABLES) {
                value = parse_string(value, variables);
            }

            i->addheader(sc, m, name, value, index);
            break;
        }

        case B_DELETEHEADER:/*30*/
        {
            const char *name;
            int index = ntohl(bc[ip++].value);
            int match = ntohl(bc[ip++].value);
            int relation = ntohl(bc[ip++].value);
            int comparator = ntohl(bc[ip++].value);
            comparator_t *comp = NULL;
            void *comprock = NULL;
            int npat;

            /* find comparator function */
            comp = lookup_comp(comparator, match, relation, &comprock);
            if (!comp) {
                res = SIEVE_RUN_ERROR;
                break;
            }

            /* get the header name */
            ip = unwrap_string(bc, ip, &name, NULL);

            if (requires & BFE_VARIABLES) {
                name = parse_string(name, variables);
            }
            if (!strcasecmp("Received", name) ||
                !strcasecmp("Auto-Submitted", name)) {
                /* MUST NOT delete -- ignore */
                name = NULL;
            }

            /* get number of value patterns */
            npat = ntohl(bc[ip++].value);

            /* skip end of list marker */
            ip++;

            if (!npat) {
                if (name) i->deleteheader(sc, m, name, index);
            }
            else {
                const char **vals, *pat;
                strarray_t decoded_vals = STRARRAY_INITIALIZER;
                int p, v, nval = 0, first_val = 0, ctag = 0;
                unsigned long delete_mask = 0;
                char scount[20];

                /* get the header values */
                if (name && i->getheader(m, name, &vals) == SIEVE_OK) {
                    for (nval = 0; vals[nval]; nval++) {
                        if (match == B_COUNT) continue;  /* count only */

                        /* decode header value and add to strarray_t */
                        strarray_appendm(&decoded_vals,
                                         charset_parse_mimeheader(vals[nval],
                                                                  0 /*flags*/));
                    }

                    if (match == B_COUNT) {
                        /* convert number of headers to a string.
                           Note: use of :index restricts count to at most 1 */
                        snprintf(scount, sizeof(scount), "%u",
                                 index ? 1 : nval);
                    }
                    else if (match == B_REGEX) {
                        /* set up options needed for compiling regex */
                        ctag = regcomp_flags(comparator, requires);
                    }

                    if (nval && index) {
                        /* normalize index */
                        index += (index < 0) ? nval : -1;  /* 0-based */
                        if (index < 0 || index >= nval) {
                            /* index out of range */
                            nval = 0;
                        }
                        else {
                            /* target single instance */
                            first_val = index;
                            nval = index + 1;
                        }
                    }
                }

                /* get (and optionally compare) each value pattern */
                for (p = 0; p < npat; p++) {
                    ip = unwrap_string(bc, ip, &pat, NULL);

                    for (v = first_val; v < nval; v++) {
                        if (!(delete_mask & (1<<v))) {
                            const char *val;
                            regex_t *reg = NULL;

                            if (requires & BFE_VARIABLES) {
                                pat = parse_string(pat, variables);
                            }

                            if (match == B_COUNT) {
                                val = scount;
                            }
                            else {
                                val = strarray_nth(&decoded_vals, v);

                                if (match == B_REGEX) {
                                    char errbuf[100];

                                    reg = bc_compile_regex(pat, ctag,
                                                           errbuf,
                                                           sizeof(errbuf));
                                    if (!reg) continue;
                                    else pat = (const char *) reg;
                                }
                            }

                            if (comp(val, strlen(val), pat, comprock)) {
                                /* flag the header for deletion */
                                delete_mask |= (1<<v);
                            }

                            if (reg) {
                                regfree(reg);
                                free(reg);
                            }
                        }
                    }
                }
                strarray_fini(&decoded_vals);

                /* delete flagged headers in reverse order
                   (so indexing is consistent) */
                for (v = nval - 1; v >= first_val; v--) {
                    if (delete_mask & (1<<v)) {
                        i->deleteheader(sc, m, name, v+1 /* 1-based */);
                    }
                }
            }
            break;
        }

        default:
            if(errmsg) *errmsg = "Invalid sieve bytecode";
            return SIEVE_FAIL;
        }

        if (res) /* we've either encountered an error or a stop */
            break;
    }

  done:
    bc_cur->is_executing = 0;

    return res;
}
