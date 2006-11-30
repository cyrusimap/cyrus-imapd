/* 
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
 */

/* $Id: auth.c,v 1.2 2006/11/30 17:11:22 murch Exp $ */

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "exitcodes.h"
#include "libcyr_cfg.h"
#include "xmalloc.h"

struct auth_mech *auth_mechs[] = {
    &auth_unix,
    &auth_pts,
#ifdef HAVE_KRB
    &auth_krb,
#endif
#ifdef HAVE_GSSAPI_H
    &auth_krb5,
#endif
    NULL };

static struct auth_mech *auth_fromname()
{
    int i;
    const char *name = libcyrus_config_getstring(CYRUSOPT_AUTH_MECH);
    static struct auth_mech *auth = NULL;

    if (auth)
        return auth;

    for (i = 0; auth_mechs[i]; i++) {
	if (!strcmp(auth_mechs[i]->name, name)) {
	    auth = auth_mechs[i]; break;
	}
    }
    if (!auth) {
	char errbuf[1024];
	snprintf(errbuf, sizeof(errbuf),
		 "Authorization mechanism %s not supported", name);
	fatal(errbuf, EC_CONFIG);
    }

    return auth;
}

int auth_memberof(auth_state, identifier)
struct auth_state *auth_state;
const char *identifier;
{
    struct auth_mech *auth = auth_fromname();

    return auth->memberof(auth_state, identifier);
}

char *auth_canonifyid(identifier, len)
const char *identifier;
size_t len;
{
    struct auth_mech *auth = auth_fromname();

    return auth->canonifyid(identifier, len);
}

struct auth_state *auth_newstate(identifier)
const char *identifier;
{
    struct auth_mech *auth = auth_fromname();

    return auth->newstate(identifier);
}

void auth_freestate(auth_state)
struct auth_state *auth_state;
{
    struct auth_mech *auth = auth_fromname();

    auth->freestate(auth_state);
}
