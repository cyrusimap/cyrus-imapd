/* glob.c - fast globbing routine using '*', '%', and '?' */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include "assert.h"
#include "util.h"
#include "glob.h"
#include "xmalloc.h"

/* "compiled" glob structure: may change
 */
typedef struct glob {
    regex_t regex;
} glob;

/* initialize globbing structure
 *  This makes the following changes to the input string:
 *   1) '*' eats all '*'s and '%'s connected by any wildcard
 *   2) '%' eats all adjacent '%'s
 */
EXPORTED glob *glob_init(const char *str, char sep)
{
    struct buf buf = BUF_INITIALIZER;
    int r;

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

    glob *g = xmalloc(sizeof(glob));
    r = regcomp(&g->regex, buf_cstring(&buf), REG_EXTENDED);
    /* XXX handle regex compilation failure properly! */
    assert(r == 0);
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
