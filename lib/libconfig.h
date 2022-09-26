/* libconfig.h -- Header for imapd.conf processing
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

#ifndef INCLUDED_LIBCONFIG_H
#define INCLUDED_LIBCONFIG_H

#include "imapopts.h"

/* these will assert() if they're called on the wrong type of
   option (imapopts.c) */
extern void config_reset(void);
extern void config_read(const char *alt_config, const int config_need_data);
extern const char *config_getstring(enum imapopt opt);
extern int config_getint(enum imapopt opt);
extern int config_getswitch(enum imapopt opt);
extern enum enum_value config_getenum(enum imapopt opt);
extern unsigned long config_getbitfield(enum imapopt opt);
extern int config_getduration(enum imapopt opt, int defunit);
extern int64_t config_getbytesize(enum imapopt opt, int defunit);

/* these work on additional strings that are not defined in the
 * imapoptions table */
extern const char *config_getoverflowstring(const char *key, const char *def);
extern void config_foreachoverflowstring(
    void (*func)(const char *, const char *, void *), void *rock);
extern const char *config_partitiondir(const char *partition);
extern const char *config_metapartitiondir(const char *partition);
extern const char *config_archivepartitiondir(const char *partition);

extern const char *config_backupstagingpath(void);

/* for parsing duration/bytesize-format strings obtained elsewhere,
 * such as from an overflow string */
extern int config_parseduration(const char *str,
                                int defunit,
                                int *out_duration);
extern int config_parsebytesize(const char *str,
                                int defunit,
                                int64_t *out_bytesize);

/* for parsing boolean switch values, returns -1 on error */
extern int config_parse_switch(const char *p);

/* cached configuration variables accessable to external world */
extern const char *config_filename;
extern const char *config_dir;
extern const char *config_defpartition;
extern const char *config_servername;
extern enum enum_value config_serverinfo;
extern const char *config_mupdate_server;
extern const char *config_defdomain;
extern const char *config_ident;
extern int config_hashimapspool;
extern int config_implicitrights;
extern enum enum_value config_virtdomains;
extern enum enum_value config_mupdate_config;
extern int config_auditlog;
extern int config_iolog;
extern unsigned config_maxquoted;
extern unsigned config_maxword;
extern int config_qosmarking;
extern int config_debug;

/* config requirement flags */
#define CONFIG_NEED_PARTITION_DATA (1<<0)

/* what it really means when a byte size option treats 0 as "unlimited" */
#define BYTESIZE_UNLIMITED (INT_MAX)

#endif /* INCLUDED_LIBCONFIG_H */
