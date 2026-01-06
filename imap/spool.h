/* spool.h -- Routines for spooling/parsing messages from a prot stream */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_SPOOL_H
#define INCLUDED_SPOOL_H

#include <stdio.h>
#include "prot.h"

typedef struct hdrcache_t *hdrcache_t;

hdrcache_t spool_new_hdrcache(void);
void spool_prepend_header(char *name, char *body, hdrcache_t cache);
void spool_prepend_header_raw(char *name, char *body, char *raw, hdrcache_t cache);
void spool_append_header(char *name, char *body, hdrcache_t cache);
void spool_append_header_raw(char *name, char *body, char *raw, hdrcache_t cache);
#define spool_cache_header(n, b, c) spool_append_header(n, b, c)
void spool_replace_header(char *name, char *newvalue, hdrcache_t cache);
/* remove all instances of header 'name' */
void spool_remove_header(const char *name, hdrcache_t cache);
/* remove nth instance of header 'name'.  1 = first, -1 = last */
void spool_remove_header_instance(const char *name, int n, hdrcache_t cache);
int spool_fill_hdrcache(struct protstream *fin, FILE *fout, hdrcache_t cache,
                        const char **skipheaders);
const char **spool_getheader(hdrcache_t cache, const char *phead);
void spool_free_hdrcache(hdrcache_t cache);
void spool_enum_hdrcache(hdrcache_t cache,
                         void (*proc)(const char *, const char *, const char *, void *),
                         void *rock);
int spool_copy_msg(struct protstream *fin, FILE *fout);

#endif
