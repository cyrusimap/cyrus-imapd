/* 
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
 */

/* $Id: netnews.h,v 1.1.2.4 2003/02/13 20:32:59 rjs3 Exp $ */

#ifndef NETNEWS_H
#define NETNEWS_H

#define NETNEWS_RECOVER 0x01

/* name of the netnews database */
#define FNAME_NETNEWSDB "/netnews.db"

struct wildmat {
    char *pat;
    int not;
};

struct wildmat *split_wildmats(char *str);
void free_wildmats(struct wildmat *wild);
extern int wildmat(const char *text, const char *p);

int netnews_init(char*, int);

int netnews_lookup(char *msgid, char **mailbox, unsigned long *uid,
		   unsigned long *lines, time_t *tstamp);
void netnews_store(char *msgid, char *mailbox, unsigned long uid,
		   unsigned long lines, time_t tstamp);
void netnews_delete(char *msgid);

int netnews_findall(struct wildmat *wild, time_t mark, int since,
		    int (*proc)(), void *rock);

int netnews_done(void);

#endif /* NETNEWS_H */
