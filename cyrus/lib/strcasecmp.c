/* strcasecmp.c -- replacement strcasecmp() & strncasecmp() routines
 $Id: strcasecmp.c,v 1.5.16.1 2003/02/13 20:33:14 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

