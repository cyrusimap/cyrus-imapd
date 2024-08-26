/* wildmat.h - NNTP wildmat processing functions
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

/*
**
**  Do shell-style pattern matching for ?, \, [], and * characters.
**  Might not be robust in face of malformed patterns; e.g., "foo[a-"
**  could cause a segmentation violation.  It is 8bit clean.
**
**  Written by Rich $alz, mirror!rs, Wed Nov 26 19:03:17 EST 1986.
**  Rich $alz is now <rsalz@osf.org>.
**  April, 1991:  Replaced mutually-recursive calls with in-line code
**  for the star character.
**
**  Special thanks to Lars Mathiesen <thorinn@diku.dk> for the ABORT code.
**  This can greatly speed up failing wildcard patterns.  For example:
**      pattern: -*-*-*-*-*-*-12-*-*-*-m-*-*-*
**      text 1:  -adobe-courier-bold-o-normal--12-120-75-75-m-70-iso8859-1
**      text 2:  -adobe-courier-bold-o-normal--12-120-75-75-X-70-iso8859-1
**  Text 1 matches with 51 calls, while text 2 fails with 54 calls.  Without
**  the ABORT code, it takes 22310 calls to fail.  Ugh.  The following
**  explanation is from Lars:
**  The precondition that must be fulfilled is that DoMatch will consume
**  at least one character in text.  This is true if *p is neither '*' nor
**  '\0'.)  The last return has ABORT instead of FALSE to avoid quadratic
**  behaviour in cases like pattern "*a*b*c*d" with text "abcxxxxx".  With
**  FALSE, each star-loop has to run to the end of the text; with ABORT
**  only the last one does.
**
**  Once the control of one instance of DoMatch enters the star-loop, that
**  instance will return either TRUE or ABORT, and any calling instance
**  will therefore return immediately after (without calling recursively
**  again).  In effect, only one star-loop is ever active.  It would be
**  possible to modify the code to maintain this context explicitly,
**  eliminating all recursive calls at the cost of some complication and
**  loss of clarity (and the ABORT stuff seems to be unclear enough by
**  itself).  I think it would be unwise to try to get this into a
**  released version unless you have a good test data base to try it out
**  on.
*/
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "wildmat.h"
#include "xmalloc.h"


#define TRUE                    1
#define FALSE                   0
#define ABORT                   -1


    /* What character marks an inverted character class? */
#define NEGATE_CLASS            '^'
    /* Is "*" a common pattern? */
#define OPTIMIZE_JUST_STAR
    /* Do tar(1) matching rules, which ignore a trailing slash? */
#undef MATCH_TAR_PATTERN


/*
**  Match text and p, return TRUE, FALSE, or ABORT.
*/
static int DoMatch(const char *text, const char *p)
{
    int                 last;
    int                 matched;
    int                 reverse;

    for ( ; *p; text++, p++) {
        if (*text == '\0' && *p != '*')
            return ABORT;
        switch (*p) {
        case '\\':
            /* Literal match with following character. */
            p++;
            /* FALLTHROUGH */
        default:
            if (*text != *p)
                return FALSE;
            continue;
        case '?':
            /* Match anything. */
            continue;
        case '*':
            while (*++p == '*')
                /* Consecutive stars act just like one. */
                continue;
            if (*p == '\0')
                /* Trailing star matches everything. */
                return TRUE;
            while (*text)
                if ((matched = DoMatch(text++, p)) != FALSE)
                    return matched;
            return ABORT;
        case '[':
            reverse = p[1] == NEGATE_CLASS ? TRUE : FALSE;
            if (reverse)
                /* Inverted character class. */
                p++;
            matched = FALSE;
            if (p[1] == ']' || p[1] == '-')
                if (*++p == *text)
                    matched = TRUE;
            for (last = *p; *++p && *p != ']'; last = *p)
                /* This next line requires a good C compiler. */
                if (*p == '-' && p[1] != ']'
                    ? *text <= *++p && *text >= last : *text == *p)
                    matched = TRUE;
            if (matched == reverse)
                return FALSE;
            continue;
        }
    }

#ifdef  MATCH_TAR_PATTERN
    if (*text == '/')
        return TRUE;
#endif  /* MATCH_TAR_ATTERN */
    return *text == '\0';
}


/*
**  User-level routine.  Returns TRUE or FALSE.
*/
EXPORTED int wildmat(const char *text, const char *p)
{
#ifdef  OPTIMIZE_JUST_STAR
    if (p[0] == '*' && p[1] == '\0')
        return TRUE;
#endif  /* OPTIMIZE_JUST_STAR */
    return DoMatch(text, p) == TRUE;
}



#if     defined(TEST)

/* Yes, we use gets not fgets.  Sue me. */
extern char     *gets();


int
main()
{
    char         p[80];
    char         text[80];

    printf("Wildmat tester.  Enter pattern, then strings to test.\n");
    printf("A blank line gets prompts for a new pattern; a blank pattern\n");
    printf("exits the program.\n");

    for ( ; ; ) {
        printf("\nEnter pattern:  ");
        (void)fflush(stdout);
        if (gets(p) == NULL || p[0] == '\0')
            break;
        for ( ; ; ) {
            printf("Enter text:  ");
            (void)fflush(stdout);
            if (gets(text) == NULL)
                exit(0);
            if (text[0] == '\0')
                /* Blank line; go back and get a new pattern. */
                break;
            printf("      %s\n", wildmat(text, p) ? "YES" : "NO");
        }
    }

    exit(0);
    /* NOTREACHED */
}
#endif  /* defined(TEST) */



EXPORTED struct wildmat *split_wildmats(char *str, const char *prefix)
{
    char pattern[1024] = "", *p, *c;
    struct wildmat *wild = NULL;
    int n = 0;

    if (prefix) snprintf(pattern, sizeof(pattern), "%s.", prefix);
    p = pattern + strlen(pattern);

    /*
     * split the list of wildmats
     *
     * we split them right to left because this is the order in which
     * we want to test them (per RFC 3977 section 4.2)
     */
    do {
        if ((c = strrchr(str, ',')))
            *c++ = '\0';
        else
            c = str;

        if (!(n % 10)) /* alloc some more */
            wild = xrealloc(wild, (n + 11) * sizeof(struct wildmat));

        if (*c == '!') wild[n].not = 1;         /* not */
        else if (*c == '@') wild[n].not = -1;   /* absolute not (feeding) */
        else wild[n].not = 0;

        strncpy(p, wild[n].not ? c + 1 : c, pattern+sizeof(pattern) - p);
        pattern[sizeof(pattern)-1] = '\0';

        wild[n++].pat = xstrdup(pattern);
    } while (c != str);
    wild[n].pat = NULL;

    return wild;
}

EXPORTED void free_wildmats(struct wildmat *wild)
{
    struct wildmat *w = wild;

    while (w->pat) {
        free(w->pat);
        w++;
    }
    free(wild);
}
