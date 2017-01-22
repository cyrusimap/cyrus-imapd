/* comparator.h
 * Larry Greenfield
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

#ifndef COMPARATOR_H
#define COMPARATOR_H

#include <sys/types.h>

#ifdef ENABLE_REGEX
# ifdef HAVE_PCREPOSIX_H
#  include <pcre.h>
#  include <pcreposix.h>
# else /* !HAVE_PCREPOSIX_H */
#  ifdef HAVE_RXPOSIX_H
#   include <rxposix.h>
#  else /* !HAVE_RXPOSIX_H */
#   include <regex.h>
#  endif /* HAVE_RXPOSIX_H */
# endif /* HAVE_PCREPOSIX_H */
#endif /* ENABLE_REGEX */

#include "sieve_interface.h"
#include "strarray.h"

/* compares pat to text; returns 1 if it's true, 0 otherwise */
typedef int comparator_t(const char *text, size_t tlen, const char *pat,
                         strarray_t *match_vars, void *rock);

/* returns a pointer to a comparator function given it's name */
comparator_t *lookup_comp(sieve_interp_t *i, int comp, int mode,
                          int relation, void **rock);

#endif /* COMPARATOR_H */
