/* sievedir.h -- functions for managing scripts in a sievedir
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_SIEVEDIR_H
#define INCLUDED_SIEVEDIR_H

#include "util.h"

/* error codes */
#define SIEVEDIR_DONE      1  /* for short-circuiting sievedir_foreach() */
#define SIEVEDIR_OK        0
#define SIEVEDIR_IOERROR  -1
#define SIEVEDIR_NOTFOUND -2
#define SIEVEDIR_INVALID  -3
#define SIEVEDIR_FAIL     -4

#define BYTECODE_SUFFIX        ".bc"
#define BYTECODE_SUFFIX_LEN    3
#define SCRIPT_SUFFIX          ".script"
#define SCRIPT_SUFFIX_LEN      7
#define DEFAULTBC_NAME         "defaultbc"

#define SIEVEDIR_MAX_NAME_LEN  1024 - SCRIPT_SUFFIX_LEN - 4 /* for ".NEW" */

#define SIEVEDIR_SCRIPTS_ONLY  (1<<0)
#define SIEVEDIR_IGNORE_JUNK   (1<<1)

int sievedir_foreach(const char *sievedir, unsigned flags,
                     int (*func)(const char *sievedir,
                                 const char *name, struct stat *sbuf,
                                 const char *link_target, void *rock),
                     void *rock);

int sievedir_valid_name(const struct buf *name);

int sievedir_script_isactive(const char *sievedir, const char *name);
const char *sievedir_get_active(const char *sievedir);

int sievedir_activate_script(const char *sievedir, const char *name);
int sievedir_deactivate_script(const char *sievedir);

struct buf *sievedir_get_script(const char *sievedir, const char *script);
int sievedir_put_script(const char *sievedir, const char *name,
                        const char *content, char **errors);
int sievedir_delete_script(const char *sievedir, const char *name);
int sievedir_rename_script(const char *sievedir,
                           const char *oldname, const char *newname);

#endif /* INCLUDED_SIEVEDIR_H */
