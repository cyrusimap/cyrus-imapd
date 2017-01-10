/* spool.h -- Routines for spooling/parsing messages from a prot stream
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_SPOOL_H
#define INCLUDED_SPOOL_H

#include <stdio.h>
#include "prot.h"

typedef struct hdrcache_t *hdrcache_t;

hdrcache_t spool_new_hdrcache(void);
void spool_prepend_header(char *name, char *body, hdrcache_t cache);
void spool_append_header(char *name, char *body, hdrcache_t cache);
#define spool_cache_header(n, b, c) spool_append_header(n, b, c)
void spool_replace_header(char *name, char *newvalue, hdrcache_t cache);
void spool_remove_header(char *name, hdrcache_t cache);
void spool_remove_header_instance(char *name, const char *body, hdrcache_t cache);
int spool_fill_hdrcache(struct protstream *fin, FILE *fout, hdrcache_t cache,
                        const char **skipheaders);
const char **spool_getheader(hdrcache_t cache, const char *phead);
void spool_free_hdrcache(hdrcache_t cache);
void spool_enum_hdrcache(hdrcache_t cache,
                         void (*proc)(const char *, const char *, void *),
                         void *rock);
int spool_copy_msg(struct protstream *fin, FILE *fout);

#endif
