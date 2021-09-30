/* glob.c -- fast globbing routine using '*', '%', and '?'
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
 *
 * Author: Chris Newman
 * Start Date: 4/5/93
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "glob.h"
#include "xmalloc.h"

/* initialize globbing structure
 *  This makes the following changes to the input string:
 *   1) '*' eats all '*'s and '%'s connected by any wildcard
 *   2) '%' eats all adjacent '%'s
 */
EXPORTED glob *glob_init(const char *str, char sep)
{
    struct buf buf = BUF_INITIALIZER;
    glob *g;

    buf_appendcstr(&buf, "(^");
    while (*str) {
        switch (*str) {
        case '*':
        case '%':
            /* remove duplicate hierarchy match (2) */
            while (*str == '%') ++str;
            /* If we found a '*', treat '%' as '*' (1) */
            if (*str == '*') {
                /* remove duplicate wildcards (1) */
                while (*str == '*' || (*str == '%' && str[1])) ++str;
                buf_appendcstr(&buf, ".*");
            }
            else {
                buf_appendcstr(&buf, "[^");
                if (sep == '\\') buf_putc(&buf, '\\');
                buf_putc(&buf, sep);
                buf_appendcstr(&buf, "]*");
            }
            break;
        /* http://stackoverflow.com/questions/399078/what-special-characters-must-be-escaped-in-regular-expressions
         * In POSIX basic regular expressions (BRE), these are metacharacters
         * that you need to escape to suppress their meaning:
         * .^$*
         * (and we're already handling * above)
         * also discovered that prceposix will segfault if we don't escape +, ?, and of course \
         */
        case '.':
        case '^':
        case '$':
        case '+':
        case '?':
        case '(':
        case ')':
        case '[':
        case ']':
        case '\\':
            buf_putc(&buf, '\\');
            /* fall through */
        default:
            buf_putc(&buf, *str++);
            break;
        }
    }
    buf_appendcstr(&buf, ")([");
    if (sep == '\\') buf_putc(&buf, '\\');
    buf_putc(&buf, sep);
    buf_appendcstr(&buf, "]|$)");

    g = xmalloc(sizeof(glob));
    regcomp(&g->regex, buf_cstring(&buf), REG_EXTENDED);
    buf_free(&buf);

    return g;
}

/* free a glob structure
 */
EXPORTED void glob_free(glob **gp)
{
    glob *g = *gp;
    if (g) {
        regfree(&g->regex);
        free(g);
    }
    *gp = NULL;
}

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string
 *  min       pointer to minimum length of a valid partial-match
 *            set to return value + 1 on partial match, otherwise -1
 *            if NULL, partial matches not allowed
 */
EXPORTED int glob_test(glob *g, const char *str)
{
    regmatch_t match[3];

    if (regexec(&g->regex, str, 2, match, 0))
        return -1;

    return match[1].rm_eo;
}
