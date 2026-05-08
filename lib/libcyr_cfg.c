/* libcyr_cfg.c - configuration interface to libcyrus */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "assert.h"
#include "libcyr_cfg.h"
#include "charset.h"
#include "cyrusdb.h"
#include "xmalloc.h"
#include "util.h"

struct delayed_action {
    struct delayed_action *next;
    char *key;
    void (*cb)(void *rock);
    void (*myfree)(void *rock);
    void *rock;
};

static struct delayed_action *delayed_actions;

/* XXX audit this struct for equivalence to imapopts, or
 * XXX generate it from lib/imapoptions properly!
 */
static struct cyrusopt_s cyrus_options[] =
{
    { .opt = CYRUSOPT_ZERO, .val.s = NULL, .t = CYRUS_OPT_NOTOPT },

    { .opt = CYRUSOPT_AUTH_UNIX_GROUP_ENABLE,
      .val.b = 1,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_USERNAME_TOLOWER,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_SKIPLIST_UNSAFE,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_TEMP_PATH,
      .val.s = "/tmp",
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_PTS_CACHE_TIMEOUT,
      .val.i = 3 * 60 * 60, /* 3 hours */
      .t = CYRUS_OPT_INT },

    { .opt = CYRUSOPT_CONFIG_DIR,
      .val.s = "/var/imap",
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_DB_INIT_FLAGS,
      .val.i = 0,
      .t = CYRUS_OPT_INT },

    { .opt = CYRUSOPT_FULLDIRHASH,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_PTSCACHE_DB,
      .val.s = "skiplist",
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_PTSCACHE_DB_PATH,
      .val.s = NULL,
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_PTLOADER_SOCK,
      .val.s = NULL,
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_VIRTDOMAINS,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_AUTH_MECH,
      .val.s = "unix",
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_DELETERIGHT,
      .val.s = "c",
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_SQL_DATABASE,
      .val.s = NULL,
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_SQL_ENGINE,
      .val.s = NULL,
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_SQL_HOSTNAMES,
      .val.s = "",
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_SQL_USER,
      .val.s = NULL,
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_SQL_PASSWD,
      .val.s = NULL,
      .t = CYRUS_OPT_STRING },

    { .opt = CYRUSOPT_SQL_USESSL,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_SKIPLIST_ALWAYS_CHECKPOINT,
      .val.b = 1,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_ACL_ADMIN_IMPLIES_WRITE,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_CYRUSDB_AUTOCONVERT,
      .val.b = 0,
      .t = CYRUS_OPT_SWITCH },

    { .opt = CYRUSOPT_LAST, .val.s = NULL, .t = CYRUS_OPT_NOTOPT }
};

HIDDEN const char *libcyrus_config_getstring(enum cyrus_opt opt)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_STRING);

    return cyrus_options[opt].val.s;
}

HIDDEN int libcyrus_config_getint(enum cyrus_opt opt)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_INT);
#if (SIZEOF_LONG != 4)
    if ((cyrus_options[opt].val.i > 0x7fffffff)||(cyrus_options[opt].val.i < -0x7fffffff)) {
        syslog(LOG_ERR, "libcyrus_config_getint: option %d: %ld too large for type", cyrus_options[opt].opt, cyrus_options[opt].val.i);
    }
#endif
    return cyrus_options[opt].val.i;
}

EXPORTED int libcyrus_config_getswitch(enum cyrus_opt opt)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_SWITCH);
#if (SIZEOF_LONG != 4)
    if ((cyrus_options[opt].val.b > 0x7fffffff)||(cyrus_options[opt].val.b < -0x7fffffff)) {
        syslog(LOG_ERR, "libcyrus_config_getswitch: option %d: %ld too large for type", cyrus_options[opt].opt, cyrus_options[opt].val.b);
    }
#endif
    return cyrus_options[opt].val.b;
}

EXPORTED void libcyrus_config_setstring(enum cyrus_opt  opt, const char *val)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_STRING);

    cyrus_options[opt].val.s = val;
}

EXPORTED void libcyrus_config_setint(enum cyrus_opt opt, int val)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_INT);

    cyrus_options[opt].val.i = val;
}

EXPORTED void libcyrus_config_setswitch(enum cyrus_opt opt, int val)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_SWITCH);

    cyrus_options[opt].val.b = val;
}

/* This keeps a list of functions to call at an opportune time when the
 * user is not waiting.
 * Arguments:
 *  dedup key: if provided, don't add this callback again if there's
 *             already one for this key.
 *  cb:        callback to call with rock passed
 *  free:      function to call with rock after the callback to free it,
               if NULL there is nothing to free.
 *  rock:      arguments for the callback
 */
EXPORTED void libcyrus_delayed_action(const char *key, void (*cb)(void *),
                                      void (*myfree)(void *), void *rock)
{
    struct delayed_action *action;
    if (key) {
        // check if we already have this event on our list
        for (action = delayed_actions; action; action = action->next) {
            if (!strcmpsafe(key, action->key)) {
                if (myfree) myfree(rock);
                return;
            }
        }
    }
    action = xzmalloc(sizeof(struct delayed_action));
    action->key = xstrdupnull(key);
    action->cb = cb;
    action->myfree = myfree;
    action->rock = rock;
    action->next = delayed_actions;
    delayed_actions = action;
}

EXPORTED void libcyrus_run_delayed(void)
{
    while (delayed_actions) {
        struct delayed_action *action = delayed_actions;
        delayed_actions = action->next;
        action->cb(action->rock);
        if (action->myfree) action->myfree(action->rock);
        free(action->key);
        free(action);
    }
}

EXPORTED void libcyrus_init(void)
{
    charset_lib_init();
    cyrusdb_init();
}

EXPORTED void libcyrus_done(void)
{
    libcyrus_run_delayed();
    cyrusdb_done();
    charset_lib_done();
}
