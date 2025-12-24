/* libcyr_cfg.h -- configuration interface to libcyrus */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_LIBCYR_CFG_H
#define INCLUDED_LIBCYR_CFG_H

#include <stdio.h>
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
    /* Lowercase usernames? (OFF) */
    CYRUSOPT_USERNAME_TOLOWER,
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
    /* Full directory hashing (OFF) */
    CYRUSOPT_FULLDIRHASH,
    /* Database for use by AUTH_PTS */
    CYRUSOPT_PTSCACHE_DB,
    /* Path to database for use by AUTH_PTS */
    CYRUSOPT_PTSCACHE_DB_PATH,
    /* ptloader socket for use by AUTH_PTS */
    CYRUSOPT_PTLOADER_SOCK,
    /* Virtual Domains (OFF) */
    CYRUSOPT_VIRTDOMAINS,
    /* authorization mechanism (unix) */
    CYRUSOPT_AUTH_MECH,
    /* RFC 2086 right which allows DELETE ("c") */
    CYRUSOPT_DELETERIGHT,
    /* SQL database */
    CYRUSOPT_SQL_DATABASE,
    /* SQL engine */
    CYRUSOPT_SQL_ENGINE,
    /* SQL hostname(s) ("") */
    CYRUSOPT_SQL_HOSTNAMES,
    /* SQL username */
    CYRUSOPT_SQL_USER,
    /* SQL password */
    CYRUSOPT_SQL_PASSWD,
    /* Secure SQL connection (OFF) */
    CYRUSOPT_SQL_USESSL,
    /* Checkpoint after every recovery (OFF) */
    CYRUSOPT_SKIPLIST_ALWAYS_CHECKPOINT,
    /* ACL override */
    CYRUSOPT_ACL_ADMIN_IMPLIES_WRITE,
    /* cyrusdb autoconvert */
    CYRUSOPT_CYRUSDB_AUTOCONVERT,

    CYRUSOPT_LAST

};

union cyrus_config_value {
    const char *s; /* string */
    long i; /* int */
    long b; /* switch */
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

extern void libcyrus_delayed_action(const char *key, void (*cb)(void *), void (*free)(void *), void *rock);
extern void libcyrus_run_delayed(void);

/* Start/Stop the Library */
/* Should be done AFTER setting configuration options */
void libcyrus_init(void);
void libcyrus_done(void);

#endif
