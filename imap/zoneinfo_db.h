/* zoneinfo_db.h -- zoneinfo DB routines
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#ifndef ZONEINFO_DB_H
#define ZONEINFO_DB_H

#include <time.h>

#include "annotate.h" /* for strlist functionality */

/* name of the zoneinfo directory */
#define FNAME_ZONEINFODIR "/zoneinfo"

/* name of the zoneinfo database */
#define FNAME_ZONEINFODB "/zoneinfo.db"
#define ZONEINFO_VERSION 1

#define INFO_TZID    ".info"
#define zoneinfo_lookup_info(zi) zoneinfo_lookup(INFO_TZID, zi)

struct zoneinfo {
    unsigned type;
    time_t dtstamp;
    struct strlist *data;
};

/* zoneinfo record types */
enum {
    ZI_ZONE = 0,
    ZI_LINK,
    ZI_INFO
};

/* open the zoneinfo db */
extern int zoneinfo_open(const char *name);

/* lookup a single zoneinfo entry and return result, or error if it
   doesn't exist or doesn't have the fields we need */
extern int zoneinfo_lookup(const char *tzid, struct zoneinfo *zi);

/* store a zoneinfo entry */
extern int zoneinfo_store(const char *tzid, struct zoneinfo *zi,
			  struct txn **tid);

/* process all zoneinfo entries (optionally matching 'find') */
extern int zoneinfo_find(const char *find, int tzid_only, time_t changedsince,
			 int (*proc)(const char *tzid, int tzidlen,
				     struct zoneinfo *zi, void *rock),
			 void *rock);

/* close the database (optionally committing txn) */
extern void zoneinfo_close(struct txn *tid);

/* done with database stuff */
extern void zoneinfo_done(void);

#endif /* ZONEINFO_DB_H */
