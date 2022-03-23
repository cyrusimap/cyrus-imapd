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
#include "grammar.h"
#include "interp.h"
#include "message.h"
#include "script.h"
#include "parseaddr.h"
#include "flags.h"
#include "variables.h"
#include "varlist.h"

#include "bytecode.h"
#include "bc_parse.h"

#include "gmtoff.h"
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

/* Compile a regular expression for use during parsing */
static regex_t * bc_compile_regex(const char *s, int ctag,
                                  char *errmsg, size_t errsiz)
{
    int ret;
    regex_t *reg = (regex_t *) xzmalloc(sizeof(regex_t));

    if ((ret = regcomp(reg, s, ctag)) != 0) {
        (void) regerror(ret, reg, errmsg, errsiz);
        regfree(reg);
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
static char* look_for_me(char *myaddr, strarray_t *addresses, const char **body,
			       variable_list_t *variables, int requires)
{
    int numaddresses = strarray_size(addresses);
    char *found = NULL;
    int l;
    int x;

    /* loop through each TO header */
    for (l = 0; body[l] != NULL && !found; l++) {
        struct address_itr ai;
        const struct address *a;

        address_itr_init(&ai, body[l], 0);

        /* loop through each address in the header */
        while (!found && (a = address_itr_next(&ai)) != NULL) {
            char *addr = address_get_all(a, 0);
            if (!addr) addr = xstrdup("");

            if (!strcasecmp(addr, myaddr)) {
                free(addr);
                found = xstrdup(myaddr);
                break;
            }

            for(x = 0; x < numaddresses; x++) {
                char *altaddr;
                const char *str;

                str = strarray_nth(addresses, x);

                if (requires & BFE_VARIABLES) {
                    str = parse_string(str, variables);
                }

                /* is this address one of my addresses? */
                altaddr = address_canonicalise(str);

                if (altaddr && !strcasecmp(addr, altaddr)) {
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
                         strarray_t *addresses, char **from, char **to,
			 variable_list_t *variables, int requires)
{
    int numaddresses = strarray_size(addresses);
    const char **body;
    char *myaddr = NULL;
    int l = SIEVE_DONE, j;
    int x;
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
       "List-Id" [RFC 2919], "List-Help", "List-Subscribe", "List-
       Unsubscribe", "List-Post", "List-Owner" or "List-Archive" [RFC 2369]
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
       This header field is described in [RFC 3834]. */
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
    for(x = 0; x < numaddresses; x++) {
        const char *address;

        address = strarray_nth(addresses, x);

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
	found = look_for_me(myaddr, addresses, body, variables, requires);
    if (!found && interp->getheader(m, "cc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, addresses, body, variables, requires);
    if (!found && interp->getheader(m, "bcc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, addresses, body, variables, requires);
    if (!found && interp->getheader(m, "resent-to", &body) == SIEVE_OK)
	found = look_for_me(myaddr, addresses ,body, variables, requires);
    if (!found && interp->getheader(m, "resent-cc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, addresses, body, variables, requires);
    if (!found && interp->getheader(m, "resent-bcc", &body) == SIEVE_OK)
	found = look_for_me(myaddr, addresses, body, variables, requires);
    if (found)
        l = SIEVE_OK;

    /* ok, ok, if we got here maybe we should reply */
out:
    free(strarray_takevf(addresses));
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

#ifdef HAVE_PCREPOSIX_H
    /* support UTF8 comparisons */
    cflags |= REG_UTF8;
#endif

    if (comparator == B_ASCIICASEMAP) {
        /* case-insensitive matches */
        cflags |= REG_ICASE;
    }
    if (!(requires & BFE_VARIABLES)) {
        /* do NOT need position of matches */
        cflags |= REG_NOSUB;
    }

    return cflags;
}

static int do_comparison(const char *needle, const char *hay,
                         comparator_t *comp, void *comprock, int ctag,
                         variable_list_t *variables, strarray_t *match_vars)
{
    int res;

    if (variables) {
        needle = parse_string(needle, variables);
    }

    if (ctag) {
        char errbuf[100]; /* Basically unused, as regex is tested at compile */
        regex_t *reg = bc_compile_regex(needle, ctag, errbuf, sizeof(errbuf));

        if (!reg) {
            /* Oops */
            res = SIEVE_NOMEM;
        }
        else {
            res = comp(hay, strlen(hay),
                       (const char *) reg, match_vars, comprock);
            regfree(reg);
            free(reg);
        }
    } else {
#if VERBOSE
        printf("%s compared to %s (from script)\n", hay, needle);
#endif
        res = comp(hay, strlen(hay), needle, match_vars, comprock);
    }

    return res;
}

static int do_comparisons(strarray_t *needles, const char *hay,
                          comparator_t *comp, void *comprock, int ctag,
                          variable_list_t *variables, strarray_t *match_vars)
{
    int n, res = 0, numneedles = strarray_size(needles);

    for (n = 0; n < numneedles && !res; n++) {
        const char *needle = strarray_nth(needles, n);

        int tmp = do_comparison(needle, hay,
                                comp, comprock, ctag, variables, match_vars);
        if (tmp < 0) res = tmp;
        else res |= tmp;
    }

    return res;
}

/* Evaluate a bytecode test */
static int eval_bc_test(sieve_interp_t *interp, void* m, void *sc,
                        bytecode_input_t * bc, int * ip,
			variable_list_t *variables,
                        duptrack_list_t *duptrack_list,
                        int version, int requires)
{
    test_t test;
    int res = 0;
    int i = *ip;
    int x, y, z;  /* loop variable */
    int list_len; /* for allof/anyof/exists */
    int list_end; /* for allof/anyof/exists */
    comparator_t *comp = NULL;
    void *comprock = NULL;
    strarray_t *match_vars = NULL;
    int op;
    #define SCOUNT_SIZE 20
    char scount[SCOUNT_SIZE];

    i = bc_test_parse(bc, i, version, &test);
    op = test.type;

    switch (op) {
    case BC_FALSE:
        res = 0;
        break;

    case BC_TRUE:
        res = 1;
        break;

    case BC_NOT:
        res = eval_bc_test(interp, m, sc, bc, &i, variables,
                           duptrack_list, version, requires);
        if (res >= 0) res = !res; /* Only invert in non-error case */
        break;

    case BC_EXISTS:
    {
        const char **val;

        res = 1;

        list_len = strarray_size(test.u.sl);

        for (x = 0; x < list_len && res; x++) {
            const char *str;

            str = strarray_nth(test.u.sl, x);

            if (requires & BFE_VARIABLES) {
                str = parse_string(str, variables);
            }

            if (interp->getheader(m, str, &val) != SIEVE_OK) res = 0;
        }

        free(strarray_takevf(test.u.sl));
        break;
    }

    case BC_SIZE:
    {
        int s;
        int sizevar = test.u.sz.t;
        int x = test.u.sz.n;

        if (interp->getsize(m, &s) != SIEVE_OK) break;

        if (sizevar == B_OVER) {
            /* over */
            res = s > x;
        } else {
            /* under */
            res = s < x;
        }
        break;
    }

    case BC_ANYOF:
        res = 0;
        list_len = test.u.aa.ntests;
        list_end = test.u.aa.endtests;

        /* return 0 unless you find one that is true, then return 1 */
        for (x = 0; x < list_len && !res; x++) {
            int tmp = eval_bc_test(interp, m, sc, bc, &i, variables,
                                   duptrack_list, version, requires);
            if (tmp < 0) {
                res = tmp;
                break;
            }
            res = res || tmp;
        }

        i = list_end; /* handle short-circuiting */

        break;

    case BC_ALLOF:
        res = 1;
        list_len = test.u.aa.ntests;
        list_end = test.u.aa.endtests;

        /* return 1 unless you find one that isn't true, then return 0 */
        for (x = 0; x < list_len && res; x++) {
            int tmp =  eval_bc_test(interp, m, sc, bc, &i, variables,
                                    duptrack_list, version, requires);
            if (tmp < 0) {
                res = tmp;
                break;
            }
            res = res && tmp;
        }

        i = list_end; /* handle short-circuiting */

        break;

    case BC_ADDRESS:
    case BC_ADDRESS_PRE_INDEX:
    case BC_ENVELOPE:
    {
        const char **val;
        struct address_itr ai;
        const struct address *a;
        char *addr;

        int numheaders = strarray_size(test.u.ae.sl);

        int header_count;
        int index = test.u.ae.comp.index; // used for address only
        int match = test.u.ae.comp.match;
        int relation = test.u.ae.comp.relation;
        int comparator = test.u.ae.comp.collation;
        int apart = test.u.ae.addrpart;
        int count = 0;
        int ctag = 0;

        /* set up variables needed for compiling regex */
        if (match == B_REGEX) {
            ctag = regcomp_flags(comparator, requires);
        }

        /* find the correct comparator fcn */
        comp = lookup_comp(interp, comparator, match, relation, &comprock);

        if (!comp) {
            res = SIEVE_RUN_ERROR;
            goto envelope_err;
        }
        match_vars = varlist_select(variables, VL_MATCH_VARS)->var;

        /* loop through all the headers */
#if VERBOSE
        printf("about to process %d headers\n", numheaders);
#endif
        for (x = 0; x < numheaders && !res; x++) {
            const char *this_header;
            int reverse_path = 0;

            this_header = strarray_nth(test.u.ae.sl, x);

            if (requires & BFE_VARIABLES) {
                this_header = parse_string(this_header, variables);
            }

            /* Try the next string if we don't have this one */
            if (op == BC_ENVELOPE) {
                /* Envelope */
                if (interp->getenvelope(m, this_header, &val) != SIEVE_OK)
                    continue;

                if (!strcmp(this_header, "from")) reverse_path = 1;
            }
            else {
                /* Address Header */
                if (interp->getheader(m, this_header, &val) != SIEVE_OK)
                    continue;
#if VERBOSE
                printf(" [%d] address header %s is %s\n", x, this_header, val[0]);
#endif
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

            /* header exists, now to test it */
            /* search through all the headers that match */

            for (y = index; y < header_count && !res; y++) {
#if VERBOSE
                printf("about to parse %s\n", val[y]);
#endif

                address_itr_init(&ai, val[y], reverse_path);

                while (!res && (a = address_itr_next(&ai)) != NULL) {
#if VERBOSE
                    printf("working addr %s\n", (addr ? addr : "[nil]"));
#endif
                    /* find the part of the address that we want */
                    switch(apart) {
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
                        /* search through all the data */
                        res = do_comparisons(test.u.ae.pl, addr,
                                             comp, comprock, ctag,
                                             (requires & BFE_VARIABLES) ?
                                             variables : NULL, match_vars);
                        if (res < 0) {
                            free(addr);
                            goto envelope_err;
                        }
                    }
                    free(addr);
                } /* For each address */

                address_itr_fini(&ai);
            }/* For each message header */

#if VERBOSE
            printf("end of loop, res is %d, x is %d (%d)\n", res, x, numheaders);
#endif
        } /* For each script header */

        if (match == B_COUNT) {
            snprintf(scount, SCOUNT_SIZE, "%u", count);
            /* search through all the data */
            res = do_comparisons(test.u.ae.pl, scount,
                                 comp, comprock, 0 /* regex */,
                                 (requires & BFE_VARIABLES) ? variables : NULL,
                                 match_vars);
        }

envelope_err:
        free(strarray_takevf(test.u.ae.sl));
        free(strarray_takevf(test.u.ae.pl));
        break;
    }

    case BC_HEADER:
    case BC_HEADER_PRE_INDEX:
    {
        const char **val;

        int numheaders = strarray_size(test.u.hhs.sl);

        int header_count;
        int index = test.u.hhs.comp.index;
        int match = test.u.hhs.comp.match;
        int relation = test.u.hhs.comp.relation;
        int comparator = test.u.hhs.comp.collation;
        int count = 0;
        int ctag = 0;
        char *decoded_header;

        /* set up variables needed for compiling regex */
        if (match == B_REGEX) {
            ctag = regcomp_flags(comparator, requires);
        }

        /* find the correct comparator fcn */
        comp = lookup_comp(interp, comparator, match, relation, &comprock);

        if (!comp) {
            res = SIEVE_RUN_ERROR;
            goto header_err;
        }
        match_vars = varlist_select(variables, VL_MATCH_VARS)->var;

        /* search through all the flags for the header */
        for (x = 0; x < numheaders && !res; x++) {
            const char *this_header;

            this_header = strarray_nth(test.u.hhs.sl, x);

            if (requires & BFE_VARIABLES) {
                this_header = parse_string(this_header, variables);
            }

            if (interp->getheader(m, this_header, &val) != SIEVE_OK) {
                continue; /* this header does not exist, search the next */
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

            for (y = index; y < header_count && !res; y++) {
                if (match == B_COUNT) {
                    count++;
                } else {
                    /* Per RFC 5228, Section 5.7,
                       leading and trailing whitespace are ignored */
                    decoded_header =
                        charset_parse_mimeheader(val[y],
                                                 CHARSET_MIME_UTF8 | CHARSET_TRIMWS);

                    res = do_comparisons(test.u.hhs.pl, decoded_header,
                                         comp, comprock, ctag,
                                         (requires & BFE_VARIABLES) ?
                                         variables : NULL, match_vars);
                    free(decoded_header);

                    if (res < 0) goto header_err;
                }
            }
        }

        if (match == B_COUNT) {
            snprintf(scount, SCOUNT_SIZE, "%u", count);
            /* search through all the data */
            res = do_comparisons(test.u.hhs.pl, scount,
                                 comp, comprock, 0 /* regex */,
                                 (requires & BFE_VARIABLES) ? variables : NULL,
                                 match_vars);
        }

      header_err:
        free(strarray_takevf(test.u.hhs.sl));
        free(strarray_takevf(test.u.hhs.pl));
        break;
    }

    case BC_STRING:
    case BC_HASFLAG:
    {
        int numhaystacks = strarray_size(test.u.hhs.sl); // number of vars to search
        int numneedles = strarray_size(test.u.hhs.pl); // number of search flags

        int match = test.u.hhs.comp.match;
        int relation = test.u.hhs.comp.relation;
        int comparator = test.u.hhs.comp.collation;
        int count = 0;
        int ctag = 0;

        /* set up variables needed for compiling regex */
        if (match == B_REGEX) {
            ctag = regcomp_flags(comparator, requires);
        }

        /* find the correct comparator fcn */
        comp = lookup_comp(interp, comparator, match, relation, &comprock);

        if (!comp) {
            res = SIEVE_RUN_ERROR;
            goto string_err;
        }
        match_vars = varlist_select(variables, VL_MATCH_VARS)->var;

        /* loop on each haystack */
        for (z = 0; z < (op == BC_STRING ? numhaystacks :
                         numhaystacks ? numhaystacks : 1); z++) {
            const char *this_haystack = NULL;
            strarray_t *this_var = NULL;

            if (numhaystacks) {
                this_haystack = strarray_nth(test.u.hhs.sl, z);
            }

            if (op == BC_STRING) {
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
                if (op == BC_STRING) {
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
		/* search through all the data */
                res = do_comparisons(test.u.hhs.pl, scount,
                                     comp, comprock, 0 /* regex */,
                                     (requires & BFE_VARIABLES) ?
                                     variables : NULL,
                                     match_vars);
                break;
            }

            /* search through the haystack for the needles */
            for (x = 0; x < numneedles && !res; x++) {
                const char *this_needle;
                int tmp;

                this_needle = strarray_nth(test.u.hhs.pl, x);

                if (requires & BFE_VARIABLES) {
                    this_needle = parse_string(this_needle, variables);
                }

#if VERBOSE
                printf ("val %s %s %s\n", val[0], val[1], val[2]);
#endif

                if (op == BC_STRING) {
                    tmp = do_comparison(this_needle, this_haystack,
                                        comp, comprock, ctag,
                                        NULL /* variables */, match_vars);
                    if (tmp < 0) {
                        res = -1;
                        goto string_err;
                    }

                    res |= tmp;
                } else {
                    /* search through all the flags */

                    for (y = 0; y < this_var->count && !res; y++) {
                        const char *active_flag;

                        active_flag = this_var->data[y];

                        tmp = do_comparison(this_needle, active_flag,
                                            comp, comprock, ctag,
                                            NULL /* variables */, match_vars);
                        if (tmp < 0) {
                            res = -1;
                            goto string_err;
                        }

                        res |= tmp;
                    }
                } // (op == BC_STRING) else

            } // loop on each item of the current haystack
#if VERBOSE
            {
                /* for debugging purposes only */
                char *temp;
                temp = strarray_join(varlist_select(variables, VL_MATCH_VARS)->var,
                                     ", ");
                printf((op == BC_STRING ? "BC_STRING" : "BC_HASFLAG"));
                printf(" %s\n\n", temp);
                free (temp);
            }
#endif
	} // loop on each variable or string

      string_err:
        free(strarray_takevf(test.u.hhs.sl));
        free(strarray_takevf(test.u.hhs.pl));
        break;
    }

    case BC_BODY:
    {
        sieve_bodypart_t **val;
        const char **content_types = NULL;

        int match = test.u.b.comp.match;
        int relation = test.u.b.comp.relation;
        int comparator = test.u.b.comp.collation;
        int transform = test.u.b.transform;
        /* test.u.b.offset is now unused */
        int count = 0;
        int ctag = 0;

        /* set up variables needed for compiling regex */
        if (match == B_REGEX) {
            ctag = regcomp_flags(comparator, requires);
        }

        /* find the correct comparator fcn */
        comp = lookup_comp(interp, comparator, match, relation, &comprock);

        if (!comp) {
            res = SIEVE_RUN_ERROR;
            goto body_err;
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

        /* find the part(s) of the body that we want */
        content_types = (const char **) strarray_safetakevf(test.u.b.content_types);
        res = interp->getbody(m, content_types, &val);
        free(content_types);

        if (res != SIEVE_OK) goto body_err;


        /* bodypart(s) exist, now to test them */

        for (y = 0; val && val[y]; y++) {

            if (!res) {
                if (match == B_COUNT) {
                    count++;
                } else if (val[y]->decoded_body) {
                    const char *content = val[y]->decoded_body;

                    /* search through all the data */
                    res = do_comparisons(test.u.b.pl, content,
                                        comp, comprock, ctag,
                                        (requires & BFE_VARIABLES) ?
                                        variables : NULL, match_vars);
                }
            }

            /* free the bodypart */
            free(val[y]);

        } /* For each body part */

        /* free the bodypart array */
        free(val);
        if (res < 0)
            goto body_err;

        if (match == B_COUNT) {
            snprintf(scount, SCOUNT_SIZE, "%u", count);
            /* search through all the data */
            res = do_comparisons(test.u.b.pl, scount,
                                 comp, comprock, 0 /* regex */,
                                 (requires & BFE_VARIABLES) ? variables : NULL,
                                 match_vars);
        }

      body_err:
        free(strarray_takevf(test.u.b.pl));
        break;
    }

    case BC_DATE:
    case BC_CURRENTDATE:
    {
        char buffer[64];
        const char **headers = NULL;
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
        int ctag = 0;

        /* index */
        index = test.u.dt.comp.index;

        /* zone tag */
        zone = test.u.dt.zone.tag;

        /* timezone offset */
        if (zone == B_TIMEZONE) {
            const char *offset = test.u.dt.zone.offset;

            if (offset) {
                char sign;
                int hours;
                int minutes;

                if (requires & BFE_VARIABLES) {
                    offset = parse_string(offset, variables);
                }

                if (3 != sscanf(offset, "%c%02d%02d",
                                &sign, &hours, &minutes)) {
                    res = 0;
                    goto date_err;
                }

                timezone_offset =
                    (sign == '-' ? -1 : 1) * ((hours * 60) + (minutes));
            }
            else {
                struct tm tm;
                time_t now = time(NULL);

                localtime_r(&now, &tm);
                timezone_offset = gmtoff_of(&tm, now) / 60;
            }
        }

        /* comparator */
        match = test.u.dt.comp.match;
        relation = test.u.dt.comp.relation;
        comparator = test.u.dt.comp.collation;

        /* set up variables needed for compiling regex */
        if (match == B_REGEX) {
            ctag = regcomp_flags(comparator, requires);
        }

        /* find comparator function */
        comp = lookup_comp(interp, comparator, match, relation, &comprock);
        if (!comp) {
            res = SIEVE_RUN_ERROR;
            goto date_err;
        }
        match_vars = varlist_select(variables, VL_MATCH_VARS)->var;

        /* date-part */
        date_part = test.u.dt.date_part;

        if (BC_DATE == op) {
            /* header name */
            header_name = test.u.dt.header_name;

            if (requires & BFE_VARIABLES) {
                header_name = parse_string(header_name, variables);
            }

            /*
             * Process header
             */

            if (interp->getheader(m, header_name, &headers) != SIEVE_OK) {
                res = 0;
                goto date_err;
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
                    break;
                }
                header_count = index + 1;
            }
            else if (index < 0) {
                index += header_count;
                if (index < 0) {
                    res = 0;
                    goto date_err;
                }
                header_count = index + 1;
            }

            /* check if index is out of bounds */
            if (index < 0 || index >= header_count) {
                res = 0;
                goto date_err;
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

            if (-1 == time_from_rfc5322(header_data, &t, DATETIME_FULL)) {
                res = 0;
                goto date_err;
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
                    goto date_err;
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
            goto date_err;
        }

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
            time_to_rfc5322(t, buffer, sizeof(buffer));
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

        res = do_comparisons(test.u.dt.kl, buffer, comp, comprock, ctag,
                             (requires & BFE_VARIABLES) ? variables : NULL,
                             match_vars);

    date_err:
        free(strarray_takevf(test.u.dt.kl));
        break;
    }

    case BC_IHAVE:
        res = 1;

        list_len = strarray_size(test.u.sl);

        for (x = 0; x < list_len && res; x++) {
            const char *str;

            str = strarray_nth(test.u.sl, x);

            if (!extension_isactive(interp, str)) res = 0;
        }

        free(strarray_takevf(test.u.sl));
        break;

    case BC_MAILBOXEXISTS:
        res = 0;

        list_len = strarray_size(test.u.mm.keylist);

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x = 0; x < list_len && !res; x++) {
            const char *extname;

            /* this is a mailbox name in external namespace */
            extname = strarray_nth(test.u.mm.keylist, x);

            if (requires & BFE_VARIABLES) {
                extname = parse_string(extname, variables);
            }

            res = interp->getmailboxexists(sc, extname);
            if (res) break;
        }

        free(strarray_takevf(test.u.mm.keylist));
        break;

    case BC_MAILBOXIDEXISTS:
        res = 0;

        list_len = strarray_size(test.u.mm.keylist);

        /* need to process all of them, to ensure our instruction pointer stays
         * in the right place */
        for (x = 0; x < list_len && !res; x++) {
            const char *extname;

            /* this is a mailbox name in external namespace */
            extname = strarray_nth(test.u.mm.keylist, x);

            if (requires & BFE_VARIABLES) {
                extname = parse_string(extname, variables);
            }

            res = interp->getmailboxidexists(sc, extname);
            if (res) break;
        }

        free(strarray_takevf(test.u.mm.keylist));
        break;

    case BC_METADATA:
    case BC_SERVERMETADATA:
    case BC_ENVIRONMENT:
    case BC_NOTIFYMETHODCAPABILITY:
    {
        res = 0;
        const char *extname = NULL;
        const char *keyname = NULL;
        char *val = NULL;
        i++;
        int match = test.u.mm.comp.match;
        int relation = test.u.mm.comp.relation;
        int comparator = test.u.mm.comp.collation;
        int ctag = 0;

        /* set up variables needed for compiling regex */
        if (match == B_REGEX) {
            ctag = regcomp_flags(comparator, requires);
        }

        /* find the correct comparator fcn */
        comp = lookup_comp(interp, comparator, match, relation, &comprock);

        if (!comp) {
            res = SIEVE_RUN_ERROR;
            goto meta_err;
        }

        if (op == BC_METADATA || op == BC_NOTIFYMETHODCAPABILITY) {
            extname = test.u.mm.extname;

            if (requires & BFE_VARIABLES) {
                extname = parse_string(extname, variables);
            }
        }

        keyname = test.u.mm.keyname;
        if (requires & BFE_VARIABLES) {
            keyname = parse_string(keyname, variables);
        }

        if (op == BC_ENVIRONMENT)
            interp->getenvironment(sc, keyname, &val);
        else if (op == BC_NOTIFYMETHODCAPABILITY) {
            if (!strcasecmp(keyname, "online")) val = xstrdup("maybe");
            else if (!strcasecmp(keyname, "fcc")) val = xstrdup("no");
        }
        else
            interp->getmetadata(sc, extname, keyname, &val);

        if (val) {
            res = do_comparisons(test.u.mm.keylist, val,
                                 comp, comprock, ctag,
                                 (requires & BFE_VARIABLES) ? variables : NULL,
                                 match_vars);
            free(val);
        }

      meta_err:
        free(strarray_takevf(test.u.mm.keylist));
        break;
    }

    case BC_METADATAEXISTS:
    case BC_SERVERMETADATAEXISTS:
    {
        res = 1;

        const char *extname = NULL;

        if (op == BC_METADATAEXISTS) {
            extname = test.u.mm.extname;

            if (requires & BFE_VARIABLES) {
                extname = parse_string(extname, variables);
            }
        }

        list_len = strarray_size(test.u.mm.keylist);

        for (x = 0; x < list_len; x++) {
            const char *keyname = NULL;
            char *val = NULL;

            /* this is an annotation name */
            keyname = strarray_nth(test.u.mm.keylist, x);

            if (requires & BFE_VARIABLES) {
                keyname = parse_string(keyname, variables);
            }

            interp->getmetadata(sc, extname, keyname, &val);
            if (!val) res = 0;
            free(val);
            if (!res) break;
        }

        free(strarray_takevf(test.u.mm.keylist));
        break;
    }

    case BC_VALIDEXTLIST:
        res = 1;

        list_len = strarray_size(test.u.sl);

        for (x = 0; x < list_len && res; x++) {
            const char *str;

            str = strarray_nth(test.u.sl, x);

            if (requires & BFE_VARIABLES) {
                str = parse_string(str, variables);
            }

            if (interp->isvalidlist(interp->interp_context, str) != SIEVE_OK)
                res = 0;
        }

        break;

    case BC_VALIDNOTIFYMETHOD:
        res = 1;

        list_len = strarray_size(test.u.sl);

        for (x = 0; x < list_len && res; x++) {
            const char *str;

            str = strarray_nth(test.u.sl, x);

            if (requires & BFE_VARIABLES) {
                str = parse_string(str, variables);
                char *p = strchr(str, ':');
                if (p) p[1] = '\0';
            }

            if (strarray_find_case(interp->notifymethods, str, 0) == -1)
                res = 0;
        }

        break;

    case BC_DUPLICATE:
    {
        int type = test.u.dup.idtype;
        const char *idval, *handle;
        int last;
        sieve_duplicate_context_t dc;

        idval = test.u.dup.idval;
        handle = test.u.dup.handle;

        dc.seconds = test.u.dup.seconds;
        last = test.u.dup.last;

        res = 1;
        if (!dc.seconds) res = 0;
        else if (type == B_HEADER) {
            /* fetch header body */
            const char **hdr;
            if (interp->getheader(m, idval, &hdr) != SIEVE_OK) res = 0;
            else idval = hdr[0];
        }
        else if (requires & BFE_VARIABLES) {
            /* substitute variables in uniqueid */
            idval = parse_string(idval, variables);
        }

        if (res) {
            struct buf id = BUF_INITIALIZER;
            const char *errmsg;

            /* prefix the ID with the handle */
            buf_printf(&id, "%s:%s", handle, idval);
            dc.id = buf_release(&id);

            res = interp->duplicate->check(&dc, interp->interp_context,
                                           sc, m, &errmsg);
            if (!res || last) {
                /* add tracking record to list
                   (to be processed iff script executes successfully) */
                do_duptrack(duptrack_list, &dc);
            }
            else free(dc.id);
        }
        break;
    }

    case BC_SPECIALUSEEXISTS:
    {
        res = 1;
        const char *extname = NULL;
        strarray_t uses = STRARRAY_INITIALIZER;

        extname = test.u.mm.extname;

        list_len = strarray_size(test.u.mm.keylist);

        if (extname && !(res = interp->getmailboxexists(sc, extname))) {
            goto exists_err;
        }

        for (x = 0; x < list_len; x++) {
            const char *use = NULL;

            /* this is a special-use flag */
            use = strarray_nth(test.u.mm.keylist, x);
            strarray_add_case(&uses, use);
        }

        res = interp->getspecialuseexists(sc, extname, &uses);
        strarray_fini(&uses);

      exists_err:
        free(strarray_takevf(test.u.mm.keylist));
        break;
    }

    case BC_JMAPQUERY:
        if (interp->jmapquery) {
            const char *json = test.u.jquery;

            if (requires & BFE_VARIABLES) {
                json = parse_string(json, variables);
            }

            res = interp->jmapquery(interp->interp_context, sc, m, json);
        }
        else res = 0;
        break;

    default:
#if VERBOSE
        printf("WERT, can't evaluate if statement. %d is not a valid command",
               op);
#endif
        return SIEVE_RUN_ERROR;
    }

    *ip = i;
    return res;
}

void unwrap_flaglist(strarray_t *strlist, strarray_t **flaglist,
                     variable_list_t *variables)
{
    if (!strlist) return;

    int len = strarray_size(strlist);

    if (len) {
        int i;

        if (!*flaglist) *flaglist = strarray_new();

        for (i = 0; i < len; i++) {
            const char *flag;

            flag = strarray_nth(strlist, i);

            if (variables) {
                flag = parse_string(flag, variables);
            }

            if (flag[0]) {
                strarray_add_case(*flaglist, flag);
            }
        }

        verify_flaglist(*flaglist);
    }

    free(strarray_takevf(strlist));
}

const char *priority_to_string(int priority)
{
    switch (priority) {
    case B_LOW:    return "low";
    case B_NORMAL: return "normal";
    case B_HIGH:   return "high";
    case B_ANY:    return "any";
    default:       return NULL;
    }
}


/* The entrypoint for bytecode evaluation */
int sieve_eval_bc(sieve_execute_t *exe, int is_incl, sieve_interp_t *i,
                  void *sc, void *m, variable_list_t *variables,
                  action_list_t *actions, notify_list_t *notify_list,
                  duptrack_list_t *duptrack_list, const char **errmsg)
{
    int res = 0;
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
    if (!bc) return SIEVE_FAIL;
    if (bc_cur->len < (BYTECODE_MAGIC_LEN + 2*sizeof(bytecode_input_t)))
       return SIEVE_FAIL;

    ip = bc_header_parse(bc, &version, &requires);
    if (ip < 0) {
        *errmsg = "Not a bytecode file";
        return SIEVE_FAIL;
    }

    /* this is because there was a time where integers were not network byte
       order.  all the scripts written then would have version 0x01 written
       in host byte order.*/

     if (version == (int) ntohl(1)) {
        if(errmsg) {
            *errmsg =
                "Incorrect Bytecode Version, please recompile (use sievec)";

        }
        return SIEVE_FAIL;
    }

    if ((version < BYTECODE_MIN_VERSION) || (version > BYTECODE_VERSION)) {
        if (errmsg) {
            *errmsg =
                "Incorrect Bytecode Version, please recompile (use sievec)";
        }
        return SIEVE_FAIL;
    }

#if VERBOSE
    printf("version number %d\n",version);
#endif

    while (ip < ip_max) {
        commandlist_t cmd;
        strarray_t *actionflags = NULL;
        variable_list_t *variable = NULL;

        ip = bc_action_parse(bc, ip, version, &cmd);
        op = cmd.type;

        switch (op) {
        case B_STOP:
            res = 1;
            break;


        case B_KEEP:
        case B_KEEP_COPY:
        case B_KEEP_ORIG:
        {
            struct buf *headers = NULL;

            unwrap_flaglist(cmd.u.k.flags, &actionflags,
                            (requires & BFE_VARIABLES) ? variables: NULL);

            /* if there's no :flags parameter, use the internal flags var */
            if (!actionflags) {
                actionflags = strarray_dup(variables->var);
            }

            if (i->edited_headers) i->getheadersection(m, &headers);

            res = do_keep(i, sc, actions, actionflags, headers);
            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Keep can not be used with Reject";

            actionflags = NULL;
            break;
        }


        case B_DISCARD:
            res = do_discard(actions);

            break;


        case B_REJECT:
        case B_EREJECT:
        {
            const char *reason = cmd.u.str;

            if (requires & BFE_VARIABLES) {
                reason = parse_string(reason, variables);
            }

            res = do_reject(actions,
                            (op == B_EREJECT) ? ACTION_EREJECT : ACTION_REJECT,
                            reason);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "[e]Reject can not be used with any other action";

            break;
        }


        case B_FILEINTO:
        case B_FILEINTO_SPECIALUSE:
        case B_FILEINTO_CREATE:
        case B_FILEINTO_FLAGS:
        case B_FILEINTO_COPY:
        case B_FILEINTO_ORIG:
        {
            const char *folder = cmd.u.f.folder;
            const char *mailboxid = cmd.u.f.mailboxid;
            const char *specialuse = cmd.u.f.specialuse;
            struct buf *headers = NULL;

            if (requires & BFE_VARIABLES) {
                folder = parse_string(folder, variables);
                mailboxid = parse_string(mailboxid, variables);
                specialuse = parse_string(specialuse, variables);
            }

            unwrap_flaglist(cmd.u.f.flags, &actionflags,
                            (requires & BFE_VARIABLES) ? variables: NULL);

            /* if there's no :flags parameter, use the internal flags var */
            if (!actionflags) {
                actionflags = strarray_dup(variables->var);
            }

            if (i->edited_headers) i->getheadersection(m, &headers);

            res = do_fileinto(i, sc, actions, folder, specialuse,
                              !cmd.u.f.copy, cmd.u.f.create, mailboxid,
                              actionflags, headers);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Fileinto can not be used with Reject";

            actionflags = NULL;
            break;
        }


        case B_SNOOZE:
        case B_SNOOZE_TZID:
        case B_SNOOZE_ORIG:
        {
            const char *awaken_mbox = cmd.u.sn.f.folder;
            const char *awaken_mboxid = cmd.u.sn.f.mailboxid;
            const char *awaken_spluse = cmd.u.sn.f.specialuse;
            const char *tzid = cmd.u.sn.tzid;
            strarray_t *addflags = NULL;
            strarray_t *removeflags = NULL;
            struct buf *headers = NULL;

            if (!awaken_mboxid && cmd.u.sn.is_mboxid) {
                awaken_mboxid = cmd.u.sn.f.folder;
                awaken_mbox = NULL;
            }

            if (requires & BFE_VARIABLES) {
                if (awaken_mbox)
                    awaken_mbox = parse_string(awaken_mbox, variables);
                if (awaken_mboxid)
                    awaken_mboxid = parse_string(awaken_mboxid, variables);
                if (awaken_spluse)
                    awaken_spluse = parse_string(awaken_spluse, variables);
                tzid = parse_string(tzid, variables);
            }

            unwrap_flaglist(cmd.u.sn.addflags, &addflags,
                            (requires & BFE_VARIABLES) ? variables: NULL);
            unwrap_flaglist(cmd.u.sn.removeflags, &removeflags,
                            (requires & BFE_VARIABLES) ? variables: NULL);

            actionflags = strarray_dup(variables->var);

            if (i->edited_headers) i->getheadersection(m, &headers);

            res = do_snooze(actions, awaken_mbox, awaken_mboxid,
                            awaken_spluse, cmd.u.sn.f.create,
                            addflags, removeflags, tzid,
                            cmd.u.sn.days, cmd.u.sn.times, actionflags, headers);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Snooze can not be used with Reject";

            actionflags = NULL;
            break;
        }


        case B_REDIRECT:
        case B_REDIRECT_LIST:
        case B_REDIRECT_COPY:
        case B_REDIRECT_ORIG:
        {
            const char *address = cmd.u.r.address;
            const char *bytime = cmd.u.r.bytime;
            const char *bymode = cmd.u.r.bymode;
            const char *dsn_notify = cmd.u.r.dsn_notify;
            const char *dsn_ret = cmd.u.r.dsn_ret;
            const char *deliverby = NULL;
            struct buf *headers = NULL;

            if (requires & BFE_VARIABLES) {
                address = parse_string(address, variables);
                bytime = parse_string(bytime, variables);
                bymode = parse_string(bymode, variables);
                dsn_notify = parse_string(dsn_notify, variables);
                dsn_ret = parse_string(dsn_ret, variables);
            }

            if (bytime) {
                long sec;

                if (bytime[0] == '+') {
                    /* Relative time ("+" 1*9DIGIT) */
                    sec = atol(cmd.u.r.bytime);
                }
                else {
                    /* Absolute time (RFC 3339 date-time) */
                    time_t t;

                    if (time_from_iso8601(bytime, &t) == -1) {
                        res = SIEVE_RUN_ERROR;
                        *errmsg = "Redirect bytimeabsolute value is invalid";
                    }
                    sec = t - time(NULL);
                }

                if (abs((int)sec) > 999999999 /* RFC 2852 */) {
                    res = SIEVE_RUN_ERROR;
                    *errmsg = "Redirect bytime value too large";
                    break;
                }

                /*
                  Construct RFC 2852 by-value:

                  by-value = by-time";"by-mode[by-trace]
                  by-time  = ["-" / "+"]1*9digit ; a <= zero value is not
                                                 ; allowed with a by-mode of "R"
                  by-mode  = "N" / "R"           ; "Notify" or "Return"
                  by-trace = "T"                 ; "Trace"
                */
                static char by_value[14];
                snprintf(by_value, sizeof(by_value), "%+ld;%c%s",
                         sec, toupper(bymode[0]), cmd.u.r.bytrace ? "T" : "");
                deliverby = by_value;
            }

            if (i->edited_headers) i->getheadersection(m, &headers);

            res = do_redirect(actions, address,
                              deliverby, dsn_notify, dsn_ret,
                              cmd.u.r.list, !cmd.u.r.copy, headers);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Redirect can not be used with Reject";

            break;
        }


        case B_IF:
        {
            int testend = cmd.u.i.testend;
            int result;

            result = eval_bc_test(i, m, sc, bc, &ip, variables,
                                duptrack_list, version, requires);

            if (result < 0) {
                *errmsg = "Invalid test";
                return SIEVE_FAIL;
            } else if (result) {
                /* skip over jump instruction */
                testend += 2;
            }

            ip = testend;
            break;
        }


        case B_MARK:
            strarray_add_case(variables->var, "\\Flagged");
            break;


        case B_UNMARK:
            strarray_remove_all_case(variables->var, "\\Flagged");
            break;


        case B_ADDFLAG:
        case B_SETFLAG:
        case B_REMOVEFLAG:
            /* RFC 5229, 3. Interpretation of Strings
               Strings where no variable substitutions take place are
               referred to as constant strings.  Future extensions may
               specify that passing non-constant strings as arguments
               to its actions or tests is an error.

               The name MUST be a constant string and conform to the
               syntax of variable-name.
               (this is done in the parser in sieve.y)
            */

            /* select or create the variable */
            variable = varlist_select(variables, cmd.u.fl.variable);
            if (variable) {
                actionflags = variable->var;
            } else if (op == B_REMOVEFLAG) {
                /* variable doesn't exist, so we're done */
                break;
            } else {
                actionflags = (variable = varlist_extend(variables))->var;
                variable->name = xstrdup(cmd.u.fl.variable);
            }

            GCC_FALLTHROUGH

        case B_ADDFLAG_ORIG:
        case B_SETFLAG_ORIG:
        case B_REMOVEFLAG_ORIG:
            if (!actionflags) {
                actionflags = variables->var;
            }

            switch (op) {
            case B_SETFLAG:
            case B_SETFLAG_ORIG:
                strarray_fini(actionflags);

                GCC_FALLTHROUGH

            case B_ADDFLAG:
            case B_ADDFLAG_ORIG:
                unwrap_flaglist(cmd.u.fl.flags, &actionflags,
                                (requires & BFE_VARIABLES) ? variables: NULL);
                break;

            case B_REMOVEFLAG:
            case B_REMOVEFLAG_ORIG:
            {
                strarray_t *temp = NULL;
                int x;

                unwrap_flaglist(cmd.u.fl.flags, &temp,
                                (requires & BFE_VARIABLES) ? variables: NULL);

                for (x = 0; x < strarray_size(temp); x++) {
                    strarray_remove_all(actionflags, strarray_nth(temp, x));
                }

                strarray_free(temp);

                break;
            }
            }
            break;

        case B_ENOTIFY:
        case B_NOTIFY:
        {
            const char *message = cmd.u.n.message;
            const char *priority = priority_to_string(cmd.u.n.priority);

            if (!priority) {
                res = SIEVE_RUN_ERROR;
                break;
            }

            /* RFC 5435 (Sieve Extension: Notifications)
             * Section 8. Security Considerations
             * implementations SHOULD NOT allow the use of variables containing
             * values extracted from the email message in the "method" parameter to
             * the "notify" action.
             */

            if (requires & BFE_VARIABLES) {
                message = parse_string(message, variables);
            }

            res = do_notify(notify_list, cmd.u.n.id, cmd.u.n.from, cmd.u.n.method,
                            cmd.u.n.options, priority, message);

            break;
        }


        case B_DENOTIFY:
        {
            /*
             * i really have no idea what the count matchtype should do here.
             * the sanest thing would be to use 1.
             * however that would require passing on the match type to do_notify.
             *  -jsmith2
             */

            comparator_t *comp = NULL;
            const char *pattern = cmd.u.d.pattern;
            const char *priority = priority_to_string(cmd.u.n.priority);
            void *comprock = NULL;
            strarray_t *match_vars = NULL;
            int comparator = cmd.u.d.comp.match;
            regex_t *reg = NULL;

            if (!priority) {
                res = SIEVE_RUN_ERROR;
                break;
            }

            if (comparator == B_ANY) {
                comp = NULL;
            } else {
                comp = lookup_comp(i, B_ASCIICASEMAP, comparator,
                                   cmd.u.d.comp.relation, &comprock);
                match_vars = varlist_select(variables, VL_MATCH_VARS)->var;
            }


	    /* draft-ietf-sieve-notify-12:
	     * Changes since draft-ietf-sieve-notify-00
	     * Removed denotify action. */
	  
            if (comparator == B_REGEX) {
                char errmsg[1024]; /* Basically unused */

                reg = bc_compile_regex(pattern,
                                       REG_EXTENDED | REG_NOSUB | REG_ICASE,
                                       errmsg, sizeof(errmsg));
                if (!reg) {
                    res = SIEVE_RUN_ERROR;
                    break;
                }
            }

            res = do_denotify(notify_list, comp, reg,
                              match_vars, comprock, priority);

            if (reg) {
                regfree(reg);
                free(reg);
            }
            break;
        }


        case B_VACATION_ORIG:
        case B_VACATION_SEC:
        case B_VACATION_FCC_ORIG:
        case B_VACATION_FCC_SPLUSE:
        case B_VACATION:
        {
            int respond;
            sieve_fileinto_context_t fcc = {
                cmd.u.v.fcc.folder,
                cmd.u.v.fcc.specialuse,
                NULL,
                cmd.u.v.fcc.create,
                cmd.u.v.fcc.mailboxid,
                /*headers*/NULL,
                /*resolved_mailbox*/NULL
            };
            char *fromaddr = NULL; /* relative to message we send */
            char *toaddr = NULL;   /* relative to message we send */
            const char *from = cmd.u.v.from;
            const char *handle = cmd.u.v.handle;
            const char *message = cmd.u.v.message;
            char *subject = cmd.u.v.subject;
            int seconds =
                cmd.u.v.seconds * ((op == B_VACATION_ORIG) ? DAY2SEC : 1);
            int mime = cmd.u.v.mime;

            respond = shouldRespond(m, i, cmd.u.v.addresses,
				    &fromaddr, &toaddr, variables, requires);

            if (respond != SIEVE_OK) {
                if (cmd.u.v.fcc.flags) free(strarray_takevf(cmd.u.v.fcc.flags));

                if (respond != SIEVE_DONE) {
                    res = SIEVE_RUN_ERROR; /* something is bad */
                }
                break;
            }

            if (requires & BFE_VARIABLES) {
                from = parse_string(from, variables);
                handle = parse_string(handle, variables);
                message = parse_string(message, variables);
                subject = parse_string(subject, variables);

                fcc.mailbox = parse_string(fcc.mailbox, variables);
                fcc.mailboxid = parse_string(fcc.mailboxid, variables);
                fcc.specialuse = parse_string(fcc.specialuse, variables);
            }

            unwrap_flaglist(cmd.u.v.fcc.flags, &fcc.imapflags,
                            (requires & BFE_VARIABLES) ? variables : NULL);

            subject = xstrdupnull(subject);
            if (!subject) {
                /* we have to generate a subject */
                struct buf buf = BUF_INITIALIZER;
                const char **s;

                if (i->getheader(m, "subject", &s) != SIEVE_OK || s[0] == NULL) {
                    buf_setcstr(&buf, "Automated reply");
                } else {
                    /* s[0] contains the original subject */
                    const char *origsubj = s[0];
                    char *decoded_subj =
                        charset_parse_mimeheader(origsubj, 0 /*flags*/);
                    buf_initm(&buf, decoded_subj, strlen(decoded_subj));
                    buf_insertcstr(&buf, 0, "Auto: ");
                }

                subject = buf_release(&buf);
            }

            if (from) {
                /* user specified from address */
                free(fromaddr);
                fromaddr = xstrdup(from);
            }

            res = do_vacation(actions, toaddr, fromaddr, subject,
                              message, seconds, mime, handle, &fcc);

            if (res == SIEVE_RUN_ERROR)
                *errmsg = "Vacation can not be used with Reject or Vacation";

            break;
        }


        case B_NULL:
            break;


        case B_JUMP:
            ip = cmd.u.jump;
            break;


        case B_INCLUDE:
        {
            const char *script = cmd.u.inc.script;
            int isglobal = cmd.u.inc.location == B_GLOBAL;
            int once = cmd.u.inc.once;
            int isoptional = cmd.u.inc.optional;
            char fpath[4096];

            if (requires & BFE_VARIABLES) {
                script = parse_string(script, variables);
            }

            res = i->getinclude(sc, script, isglobal, fpath, sizeof(fpath));
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

            res = sieve_eval_bc(exe, 1, i, sc, m, variables, actions,
				notify_list, duptrack_list, errmsg);
            break;
        }

        case B_RETURN:
            if (is_incl)
                goto done;
            else
                res = 1;
            break;


        case B_SET:
        {
            const char *name = cmd.u.s.variable;
            const char *value = cmd.u.s.value;

	    /* RFC 5229, 3. Interpretation of Strings
               Strings where no variable substitutions take place are referred to as
               constant strings.  Future extensions may specify that passing non-
               constant strings as arguments to its actions or tests is an error.

               The name MUST be a constant string and conform
               to the syntax of variable-name.
               (this is done in the parser in sieve.y)
            */

            /* select or create the variable */
            variable = varlist_select(variables, name);
            if (variable) {
                actionflags = variable->var;
            } else {
                actionflags = (variable = varlist_extend(variables))->var;
                variable->name = xstrdup(name);
            }

            value = parse_string(value, variables);
            strarray_fini(variable->var);
            strarray_appendm(variable->var,
                             variables_modify_string(value, cmd.u.s.modifiers));
#if VERBOSE
	    printf("\nB_SET:%s\n\n", strarray_nth(variable->var, -1));
#endif
            actionflags = NULL;
            break;
        }

        case B_ADDHEADER:
        {
            const char *name = cmd.u.ah.name;
            const char *value = cmd.u.ah.value;
            char *encoded_value;
            const char *h;
            int index = cmd.u.ah.index;

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
            
            if (requires & BFE_VARIABLES) {
                value = parse_string(value, variables);
            }

            encoded_value = charset_encode_mimeheader(value, strlen(value), 0);

            i->addheader(m, name, encoded_value, index);
            i->edited_headers = 1;

            free(encoded_value);
            break;
        }

        case B_DELETEHEADER:
        {
            const char *name = cmd.u.dh.name;
            int index = cmd.u.dh.comp.index;
            int match = cmd.u.dh.comp.match;
            int relation = cmd.u.dh.comp.relation;
            int comparator = cmd.u.dh.comp.collation;
            comparator_t *comp = NULL;
            void *comprock = NULL;
            int npat = strarray_size(cmd.u.dh.values);

            /* find comparator function */
            comp = lookup_comp(i, comparator, match, relation, &comprock);
            if (!comp) {
                res = SIEVE_RUN_ERROR;
                break;
            }

            if (requires & BFE_VARIABLES) {
                name = parse_string(name, variables);
            }
            if (!strcasecmp("Received", name) ||
                !strcasecmp("Auto-Submitted", name)) {
                /* MUST NOT delete -- ignore */
                name = NULL;
            }

            if (!npat) {
                if (name) {
                    i->deleteheader(m, name, index);
                    i->edited_headers = 1;
                }
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
                    pat = strarray_nth(cmd.u.dh.values, p);

                    for (v = first_val; v < nval; v++) {
                        if (!(delete_mask & (1 << v))) {
                            const char *val;

                            if (match == B_COUNT) {
                                val = scount;
                            }
                            else {
                                val = strarray_nth(&decoded_vals, v);
                            }
                            if (do_comparison(pat, val, comp, comprock,
                                              ctag, variables, NULL)) {
                                /* flag the header for deletion */
                                delete_mask |= (1 << v);
                            }
                        }
                    }
                }
                strarray_fini(&decoded_vals);

                /* delete flagged headers in reverse order
                   (so indexing is consistent) */
                for (v = nval - 1; v >= first_val; v--) {
                    if (delete_mask & (1<<v)) {
                        i->deleteheader(m, name, v+1 /* 1-based */);
                        i->edited_headers = 1;
                    }
                }
            }
            free(strarray_takevf(cmd.u.dh.values));
            break;
        }

        case B_LOG:
            if (i->log) {
                const char *text = cmd.u.l.text;

                if (requires & BFE_VARIABLES) {
                    text = parse_string(text, variables);
                }

                i->log(sc, m, text);
            }
            break;

        case B_PROCESSIMIP:
            if (i->imip) {
                sieve_imip_context_t imip_ctx = {
                    !!cmd.u.imip.invites_only,
                    !!cmd.u.imip.updates_only,
                    !!cmd.u.imip.delete_canceled,
                    cmd.u.imip.calendarid,
                    BUF_INITIALIZER,  // outcome
                    BUF_INITIALIZER   // errstr
                };
                variable_list_t *vl;

                res = i->imip(&imip_ctx, i->interp_context, sc, m, errmsg);

                if (cmd.u.imip.outcome_var) {
                    vl = varlist_select(variables, cmd.u.imip.outcome_var);

                    if (!vl) {
                        vl = varlist_extend(variables);
                        vl->name = xstrdup(cmd.u.imip.outcome_var);
                    }
                    strarray_fini(vl->var);
                    strarray_appendm(vl->var, buf_release(&imip_ctx.outcome));
                }

                if (cmd.u.imip.errstr_var) {
                    vl = varlist_select(variables, cmd.u.imip.errstr_var);

                    if (!vl) {
                        vl = varlist_extend(variables);
                        vl->name = xstrdup(cmd.u.imip.errstr_var);
                    }
                    strarray_fini(vl->var);
                    strarray_appendm(vl->var, buf_release(&imip_ctx.errstr));
                }

                buf_free(&imip_ctx.outcome);
                buf_free(&imip_ctx.errstr);
            }
            else {
                return SIEVE_RUN_ERROR;
            }
            break;

        case B_ERROR:
            res = SIEVE_RUN_ERROR;
            *errmsg = cmd.u.str;

            break;

        default:
            if(errmsg) *errmsg = "Invalid sieve bytecode";
            return SIEVE_FAIL;
        }

        if (res) break;  /* we've either encountered an error or a stop */
    }

  done:
    bc_cur->is_executing = 0;

    return res;
}
