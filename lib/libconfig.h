/* libconfig.h -- Header for imapd.conf processing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_LIBCONFIG_H
#define INCLUDED_LIBCONFIG_H

#include "imapopts.h"
#include "strarray.h"

#include <stdio.h>

/* these will assert() if they're called on the wrong type of
   option (imapopts.c) */
extern void config_reset(void);
extern void config_read(const char *alt_config, const int config_need_data);
extern const char *config_getstring(enum imapopt opt);
extern int config_getint(enum imapopt opt);
extern int config_getswitch(enum imapopt opt);
extern enum enum_value config_getenum(enum imapopt opt);
extern uint64_t config_getbitfield(enum imapopt opt);
extern int config_getduration(enum imapopt opt, int defunit);
extern int64_t config_getbytesize(enum imapopt opt, int defunit);

/* these work on additional strings that are not defined in the
 * imapoptions table */
extern const char *config_getoverflowstring(const char *key, const char *def);
extern void config_foreachoverflowstring(
    void (*func)(const char *, const char *, void *), void *rock);

/* partition utilities */
extern const char *config_partitiondir(const char *partition);
extern const char *config_metapartitiondir(const char *partition);
extern const char *config_archivepartitiondir(const char *partition);
extern int config_check_partitions(FILE *user_output);

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
extern strarray_t config_cua_domains;
extern int config_hashimapspool;
extern int config_implicitrights;
extern enum enum_value config_virtdomains;
extern enum enum_value config_mupdate_config;
extern int config_auditlog;
extern int config_iolog;
extern unsigned config_maxliteral;
extern unsigned config_maxquoted;
extern unsigned config_maxword;
extern int config_qosmarking;
extern int config_debug;
extern int config_debug_slowio;
extern int config_fatals_abort;
extern const char *config_zoneinfo_dir;

/* for toggling config_debug and its behaviours at runtime */
typedef void (*toggle_debug_cb)(void);
extern toggle_debug_cb config_toggle_debug_cb;
extern void config_toggle_debug(void);

/* config requirement flags */
#define CONFIG_NEED_PARTITION_DATA (1<<0)

/* what it really means when a byte size option treats 0 as "unlimited" */
#define BYTESIZE_UNLIMITED (INT_MAX)

/* Examine the name of a file, and return a single character
 * (as an int) that can be used as the name of a hash
 * directory.  Caller is responsible for skipping any prefix
 * of the name.
 */
extern int dir_hash_c(const char *name, int full);

/*
 * Like dir_hash_c() but builds the result as a single-byte
 * C string in the provided buffer, and returns the buffer,
 * which is sometimes more convenient.
 */
extern char *dir_hash_b(const char *name, int full, char buf[2]);

#endif /* INCLUDED_LIBCONFIG_H */
