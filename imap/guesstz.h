/* guesstz.h -- routines to guess timezone ids from VTIMEZONEs
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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

#ifndef GUESSTZ_H
#define GUESSTZ_H

#include <jansson.h>

#include "ical_support.h"

struct guesstzdb;

/* Open a guesstz database.
 *
 * Optional alt_fname defines the file path of the database file.
 * The default database is located at <zoneinfo_dir>/guesstz.db
 *
 * Returns the database handle, or NULL on error.
 */
extern struct guesstzdb *guesstz_open(const char *alt_fname);

/* Close a database handle */
extern void guesstz_close(struct guesstzdb **gtzdbptr);

/* Create a guesstz database.
 *
 * Arguments start and end define the timerange in which
 * timezone observances are expanded.
 *
 * Optional zoneinfo_dir defines where the VTIMEZONEs to inspect
 * are located. The default zoneinfo_dir is read from imapd.conf.
 *
 * Optional fname defines the file path were to store the database
 * (also see guesstz_open).
 *
 * Returns a cyrusdb return code.
 */
extern int guesstz_create(const char *zoneinfo_dir, const char *fname,
                            icaltimetype start, icaltimetype end);

/* Encode a guesstz database as human-readable string.
 *
 * Optional argument fname defines the file path of the database
 * file (also see guesstz_open).
 */
extern char *guesstz_dump(const char *alt_fname);

/* Guess the IANA timezone id for a VTIMEZONE and a calendar object.
 *
 * Argument vtz contains the VTIMEZONE.
 *
 * Argument span defines the UTC time span covered of the calendar object.
 * A span must have a start time. It may have an infinite end time,
 * encoded as caldav_epoch.
 *
 * Argument is_recurring defines if the calendar object has multiple
 * occurrences.
 *
 * After completion, argument idbuf contains the guessed IANA
 * timezone identifier, or empty if none.
 */
extern void guesstz_toiana(struct guesstzdb *gtzdb,
                           struct buf *idbuf, icalcomponent *vtz,
                           struct icalperiodtype span,
                           unsigned is_recurring);

#endif /* GUESSTZ_H */
