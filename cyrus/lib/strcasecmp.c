/* strcasecmp.c -- replacement strcasecmp() & strncasecmp() routines
 *
 *	(C) Copyright 1993 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
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

