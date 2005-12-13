/* libcyr_cfg.c -- configuration interface to libcyrus
 * 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 */
/*
 * $Id: libcyr_cfg.c,v 1.2.2.12 2005/12/13 19:36:12 murch Exp $
 */

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "libcyr_cfg.h"
#include "cyrusdb.h"

#if defined(__GNUC__) && __GNUC__ > 1
/* We can use the GCC union constructor extension */
#define CFGVAL(t,v)	(union cyrus_config_value)((t)(v))
#else
#define CFGVAL(t,v)	{(void *)(v)}
#endif

struct cyrusopt_s cyrus_options[] = {
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
      CFGVAL(const char *, "berkeley"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_PTLOADER_SOCK,
      CFGVAL(const char *, NULL),
      CYRUS_OPT_STRING },

    { CYRUSOPT_VIRTDOMAINS,
      CFGVAL(long, 0),
      CYRUS_OPT_SWITCH },

    { CYRUSOPT_BERKELEY_CACHESIZE,
      CFGVAL(long, 512 * 1024), /* 512KB */
      CYRUS_OPT_INT },

    { CYRUSOPT_AUTH_MECH,
      CFGVAL(const char *, "unix"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_BERKELEY_LOCKS_MAX,
      CFGVAL(long, 50000),
      CYRUS_OPT_INT },

    { CYRUSOPT_BERKELEY_TXNS_MAX,
      CFGVAL(long, 100),
      CYRUS_OPT_INT },

    { CYRUSOPT_DELETERIGHT,
      CFGVAL(const char *, "c"),
      CYRUS_OPT_STRING },

    { CYRUSOPT_LAST, { NULL }, CYRUS_OPT_NOTOPT }
};

const char *libcyrus_config_getstring(enum cyrus_opt opt)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_STRING);
    
    return cyrus_options[opt].val.s;
}

int libcyrus_config_getint(enum cyrus_opt opt)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_INT);
#if (SIZEOF_LONG != 4)
    if ((cyrus_options[opt].val.i > 0x7fffffff)||(cyrus_options[opt].val.i < -0x7fffffff)) {
	syslog(LOG_ERR, "libcyrus_config_getint: option %d: %lld too large for type", cyrus_options[opt].opt, cyrus_options[opt].val.i);
    }
#endif    
    return cyrus_options[opt].val.i;
}

int libcyrus_config_getswitch(enum cyrus_opt opt)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_SWITCH);
#if (SIZEOF_LONG != 4)
    if ((cyrus_options[opt].val.b > 0x7fffffff)||(cyrus_options[opt].val.b < -0x7fffffff)) {
	syslog(LOG_ERR, "libcyrus_config_getswitch: option %d: %lld too large for type", cyrus_options[opt].opt, cyrus_options[opt].val.b);
    }
#endif    
    return cyrus_options[opt].val.b;
}

void libcyrus_config_setstring(enum cyrus_opt  opt, const char *val) 
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_STRING);

    cyrus_options[opt].val.s = val;
}

void libcyrus_config_setint(enum cyrus_opt opt, int val)
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_INT);

    cyrus_options[opt].val.i = val;
}

void libcyrus_config_setswitch(enum cyrus_opt opt, int val) 
{
    assert(opt > CYRUSOPT_ZERO && opt < CYRUSOPT_LAST);
    assert(cyrus_options[opt].opt == opt);
    assert(cyrus_options[opt].t == CYRUS_OPT_SWITCH);

    cyrus_options[opt].val.b = val;
}

void libcyrus_init()
{
    cyrusdb_init();
}

void libcyrus_done()
{
    cyrusdb_done();
}
