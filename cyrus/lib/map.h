/* map.h -- memory mapping functions
 * $Id: map.h,v 1.9.2.4 2003/02/27 18:12:12 rjs3 Exp $
 *
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
 */

#ifndef INCLUDED_MAP_H
#define INCLUDED_MAP_H

#define MAP_UNKNOWN_LEN ((unsigned long)-1)

extern const char *map_method_desc;

/* Create a memory map
 *
 * fd is the file descriptor which is to be mapped
 * onceonly is set to be nonzero if you do not intend to ever refresh the map
 * base and len are output parameters that receive the address and length
 * 	of the map once it is created.  NOTE: *len should be zero the first
 * 	time map_refresh() is called to force the initial mapping
 * newlen is set to the size of the file, or MAP_UNKNOWN_LEN to have the
 * 	mapping facility compute it for you.
 * name and mboxname are used for logging purposes, name is the name
 * 	of the file, and shouldn't be NULL, while mboxname is the name
 * 	of the applicable mailbox (if any), and may be NULL
 */
extern void map_refresh(int fd, int onceonly, const char **base,
			unsigned long *len, unsigned long newlen,
			const char *name, const char *mboxname);

/* map_free will free a memory map allocated by map_refresh
 *
 * base and len are the same values that were passed to map_refresh */
extern void map_free(const char **base, unsigned long *len);

#endif /* INCLUDED_MAP_H */
