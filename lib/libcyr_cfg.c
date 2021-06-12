/* libcyr_cfg.c -- configuration interface to libcyrus
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "assert.h"
#include "libcyr_cfg.h"
#include "cyrusdb.h"

#if defined(__GNUC__) && __GNUC__ > 1
/* We can use the GCC union constructor extension */
#define CFGVAL(t,v)     (union cyrus_config_value)((t)(v))
#else
#define CFGVAL(t,v)     {(void *)(v)}
#endif

static struct cyrusopt_s cyrus_options[] = {
    { CYRUSOPT_ZERO, { NULL }, CYRUS_OPT_NOTOPT },

    { CYRUSOPT_AUTH_UNIX_GROUP_ENABLE,
      CFGVAL(long, 1),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_USERNAME_TOLOWER,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_SKIPLIST_UNSAFE,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_TEMP_PATH,
      CFGVAL(const char *, "/tmp"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_PTS_CACHE_TIMEOUT,
      CFGVAL(long, 3 * 60 * 60), /* 3 hours */
      CYRUS_OPT_INT },

    { CYRUSOPT_CONFIG_DIR,
      CFGVAL(const char *, "/var/imap"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_DB_INIT_FLAGS,
      CFGVAL(long, 0),
      CYRUS_OPT_INT },

    { CYRUSOPT_FULLDIRHASH,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_PTSCACHE_DB,
      CFGVAL(const char *, "skiplist"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_PTSCACHE_DB_PATH,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_PTLOADER_SOCK,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_VIRTDOMAINS,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_AUTH_MECH,
      CFGVAL(const char *, "unix"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_DELETERIGHT,
      CFGVAL(const char *, "c"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_SQL_DATABASE,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_SQL_ENGINE,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_SQL_HOSTNAMES,
      CFGVAL(const char *, ""),
      CYRUS_OPT_STRING },

    { CYRUSOPT_SQL_USER,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_SQL_PASSWD,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_SQL_USESSL,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_SKIPLIST_ALWAYS_CHECKPOINT,
      CFGVAL(long, 1),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_ACL_ADMIN_IMPLIES_WRITE,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_LAST, { NULL }, CYRUS_OPT_NOTOPT }
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

EXPORTED void libcyrus_init(void)
{
    cyrusdb_init();
}

EXPORTED void libcyrus_done(void)
{
    cyrusdb_done();
}
