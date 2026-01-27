/* sievedir.h - functions for managing scripts in a sievedir */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

int sievedir_valid_path(const char *sievedir);

#endif /* INCLUDED_SIEVEDIR_H */
