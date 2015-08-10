/* lock_file.h -- module for use of dedicated lock files
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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
#ifndef LIB_LOCK_FILE_H
#define LIB_LOCK_FILE_H

struct lockf;

/*
 * Obtain a lock by exclusively creating named file.  If the named file
 * already exists, retries for up to 15 seconds before timing out.
 *
 * Warns to syslog upon timeout, and upon detection of existing stale lock
 * file.
 *
 * Returns a struct lockf handle, or NULL if the lock could not be obtained.
 */
struct lockf *lf_lock(const char *filename);

/*
 * Verify if the struct lockf handle is still valid (i.e. that the underlying
 * lock file has not been trampled on by some other process).
 *
 * Returns true (1) if so, false (0) otherwise.
 */
int lf_ismine(struct lockf *lf);

/*
 * Refresh the timestamp on the provided handle.  Call this periodically
 * during long operations.
 *
 * Calls fatal() if the handle is no longer valid.  To (mostly) avoid this,
 * check lf_ismine() before invocation.
 */
int lf_touch(struct lockf *lf);

/*
 * Release the provided handle and unlink its corresponding file.
 *
 * Calls fatal() if the handle is no longer valid.  To (mostly) avoid this,
 * check lf_ismine() before invocation.
 */
int lf_unlock(struct lockf **lf);

#endif
