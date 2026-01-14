/* map.h - memory mapping functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_MAP_H
#define INCLUDED_MAP_H

#define MAP_UNKNOWN_LEN ((unsigned long)-1)

extern const char map_method_desc[];

/* Create a memory map
 *
 * fd is the file descriptor which is to be mapped
 * onceonly is set to be nonzero if you do not intend to ever refresh the map
 * base and len are output parameters that receive the address and length
 *      of the map once it is created.  NOTE: *len should be zero the first
 *      time map_refresh() is called to force the initial mapping
 * newlen is set to the size of the file, or MAP_UNKNOWN_LEN to have the
 *      mapping facility compute it for you.
 * name and mboxname are used for logging purposes, name is the name
 *      of the file, and shouldn't be NULL, while mboxname is the name
 *      of the applicable mailbox (if any), and may be NULL
 */
extern void map_refresh(int fd, int onceonly, const char **base,
                        size_t *len, size_t newlen,
                        const char *name, const char *mboxname);

/* map_free will free a memory map allocated by map_refresh
 *
 * base and len are the same values that were passed to map_refresh */
extern void map_free(const char **base, size_t *len);

#endif /* INCLUDED_MAP_H */
