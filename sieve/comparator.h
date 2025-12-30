/* comparator.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef COMPARATOR_H
#define COMPARATOR_H

#include <sys/types.h>

#ifdef ENABLE_REGEX
# if defined HAVE_PCREPOSIX_H
#  include <pcre.h>
#  include <pcreposix.h>
# elif defined HAVE_PCRE2POSIX_H
#  ifndef PCRE2POSIX_H_INCLUDED
#   include <pcre2posix.h>
#   define PCRE2POSIX_H_INCLUDED
#  endif
# elif defined HAVE_RXPOSIX_H
#  include <rxposix.h>
# else
#  include <regex.h>
# endif
#endif

#include "sieve_interface.h"
#include "strarray.h"

#define MAX_MATCH_VARS 9  /* MUST support ${1} through ${9} per RFC 5229 */

/* compares pat to text; returns 1 if it's true, 0 otherwise */
typedef int comparator_t(const char *text, size_t tlen, const char *pat,
                         strarray_t *match_vars, void *rock);

/* returns a pointer to a comparator function given it's name */
comparator_t *lookup_comp(sieve_interp_t *i, int comp, int mode,
                          int relation, void **rock);

#endif /* COMPARATOR_H */
