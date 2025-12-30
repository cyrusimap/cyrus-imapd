/* glob.h -- fast globbing routine using '*', '%', and '?' */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_GLOB_H
#define INCLUDED_GLOB_H

typedef struct glob glob;

/* initialize globbing structure
 *  str      -- globbing string
 *  sep      -- hierarchy separator
 */
extern glob *glob_init(const char *str, char sep);

/* free a glob structure
 */
extern void glob_free(glob **gp);

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 */
extern int glob_test(glob *g, const char *str);

/* MACROS */
#define GLOB_MATCH(g, str) ((int)strlen(str) == glob_test((g), (str)))

#endif /* INCLUDED_GLOB_H */
