/* libcyr_cfg.h -- configuration interface to libcyrus
 * 
 * Copyright (c) 1998-2002 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * Author: Chris Newman
 * Start Date: 4/6/93
 */
/* $Id: libcyr_cfg.h,v 1.1.2.4 2002/11/15 21:47:01 rjs3 Exp $
 */

#ifndef INCLUDED_LIBCYR_CFG_H
#define INCLUDED_LIBCYR_CFG_H

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

/* This is basically a simplified version of the configuration system
 * that is used for the application level of Cyrus IMAPd */

enum cyrus_opttype {
    CYRUS_OPT_NOTOPT,
    CYRUS_OPT_STRING,
    CYRUS_OPT_INT,
    CYRUS_OPT_SWITCH
};

enum cyrus_opt {

    CYRUSOPT_ZERO = 0,

    /* Use unix groups with auth_unix? (ON) */
    CYRUSOPT_AUTH_UNIX_GROUP_ENABLE,
    /* Don't fsync() the skiplist backend (OFF) */
    CYRUSOPT_SKIPLIST_UNSAFE,
    /* Temporary Storage Directory ("/tmp") */
    CYRUSOPT_TEMP_PATH,
    /* PTS Cache Timeout */
    CYRUSOPT_PTS_CACHE_TIMEOUT,
    /* IMAPd config directory */
    CYRUSOPT_CONFIG_DIR,
    /* CyrusDB INIT flags */
    CYRUSOPT_DB_INIT_FLAGS,

    CYRUSOPT_LAST
    
};

union cyrus_config_value {
    const char *s; /* string */
    int i; /* int */
    int b; /* switch */
};

struct cyrusopt_s {
    const enum cyrus_opt opt;
    union cyrus_config_value val;
    const enum cyrus_opttype t;
};

/* these will assert() if they're called on the wrong type of
   option (imapopt.c) */
extern const char *libcyrus_config_getstring(enum cyrus_opt opt);
extern int libcyrus_config_getint(enum cyrus_opt opt);
extern int libcyrus_config_getswitch(enum cyrus_opt opt);

void libcyrus_config_setstring(enum cyrus_opt opt, const char *val);
void libcyrus_config_setint(enum cyrus_opt opt, int val);
void libcyrus_config_setswitch(enum cyrus_opt opt, int val);

/* Start/Stop the Library */
/* Should be done AFTER setting configuration options */
void libcyrus_init();
void libcyrus_done();

#endif
