/* guesstz.h - guess IANA timezone names from VTIMEZONE components */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef GUESSTZ_H
#define GUESSTZ_H

#include <stdio.h>

#include <libical/ical.h>

typedef struct guesstz guesstz_t;

/** @brief Create a guesstz database from a zoneinfo directory.
 *
 *  Reads every VTIMEZONE found below the zoneinfo directory and writes
 *  a database indexing their observances within the given time range.
 *  The IANA version is taken from the "version" file in that directory,
 *  or recorded as "unknown" if there is none.
 *
 *  @param zoneinfo_dir the directory holding the VTIMEZONEs
 *  @param trstart the UTC start time of the time range
 *  @param trend the UTC end time of the time range
 *  @param fp the file to write the database to
 *  @return zero on success, or a sysexits.h code
 */
extern int guesstz_create(const char *zoneinfo_dir,
                          icaltimetype trstart, icaltimetype trend,
                          FILE *fp);

/** @brief Open the guesstz database at the specified file path.
 *
 *  The file is kept open during the lifetime of the returned
 *  database handle. The return value always points to a database
 *  handle. Use guesstz_error() to assert if there was any error.
 *
 *  @param fpath the file path of the database
 *  @return the database handle
 */
extern guesstz_t *guesstz_open(const char *fpath);


/** @brief Close the guesstz database and free its resources.
 *
 *  @param gtzp the database handle to close. It is safe to
                pass a NULL value or a pointer to NULL.
 */
extern void guesstz_close(guesstz_t **gtzp);


/** @brief Check the error state of the database handle.
 *
 *  Indicates if the last operation on the database handle resulted
 *  in an error. Errors are unrecoverable and the result of
 *  operations executed on an erroneous handle is undefined.
 *
 *  @param gtz the database handle
 *  @return a null-terminated string indicating an error,
 *          or NULL if there is no error
 */
extern const char *guesstz_error(guesstz_t *gtz);

/** @brief Guess the IANA timezone name of a VTIMEZONE
 *
 *  Two timezones are considered equal if their observance
 *  onsets and UTC offsets match within the given time range.
 *  Observances are expanded until the minimum of the given
 *  time range end and the end of the database time range.
 *
 *  @param gtz the database handle
 *  @param vtz a VCALENDAR component containing a VTIMEZONE
 *  @param trstart the UTC start time of the time range
 *  @param trend the UTC end time of the time range
 *  @return a null-terminated string containing the IANA time
 *          timezone name, or NULL if no name is found.
 *          The return value must be free()d by the caller.
 */
extern char *guesstz_guess(guesstz_t *gtz, icalcomponent *vtz,
                           icaltimetype trstart, icaltimetype trend);

/** @brief Encode the database in JSON
 *
 *  @param gtz the database handle
 *  @return a null-terminated string containing the JSON format
 */
extern char *guesstz_encode(guesstz_t *gtz);

#endif // GUESSTZ_H
