/* strcasecmp.c -- replacement strcasecmp() & strncasecmp() routines
 *
 *	(C) Copyright 1993 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * Author: Chris Newman
 * Start Date: 4/6/93
 */

#include "util.h"

/* case insensitive string compare
 */
int strcasecmp(str1, str2)
    char *str1, *str2;
{
    while (*str1 && TOLOWER(*str1) == TOLOWER(*str2)) ++str1, ++str2;

    return ((int) TOLOWER(*str1) - (int) TOLOWER(*str2));
}

/* case insensitive string compare with count
 */
int strncasecmp(str1, str2, n)
    char *str1, *str2;
    int n;
{
    while (n && *str1 && TOLOWER(*str1) == TOLOWER(*str2)) ++str1, ++str2, --n;

    return (n ? (int) TOLOWER(*str1) - (int) TOLOWER(*str2) : 0);
}

