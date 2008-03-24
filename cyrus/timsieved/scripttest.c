/* scripttest.c -- test wheather the sieve script is valid
 * Tim Martin
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
 *
 * $Id: scripttest.c,v 1.25 2008/03/24 20:20:57 murch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sieve_interface.h"
#include "scripttest.h"
#include <syslog.h>

#include "codes.h"

#include "mystring.h"

#include "xmalloc.h"
#include <string.h>
#include <stdlib.h>

/* to make larry's stupid functions happy :) */ 
void foo(void)
{
    fatal("stub function called", 0);
}


sieve_vacation_t vacation = {
    0,				/* min response */
    0,				/* max response */
    (sieve_callback *) &foo,	/* autorespond() */
    (sieve_callback *) &foo	/* send_response() */
};

static int sieve_notify(void *ac __attribute__((unused)), 
			void *interp_context __attribute__((unused)), 
			void *script_context __attribute__((unused)),
			void *message_context __attribute__((unused)),
			const char **errmsg __attribute__((unused)))
{
    fatal("stub function called", 0);
    return SIEVE_FAIL;
}

int mysieve_error(int lineno, const char *msg,
		  void *i __attribute__((unused)), void *s)
{
    char buf[1024];
    char **errstr = (char **) s;

    snprintf(buf, 80, "line %d: %s\r\n", lineno, msg);
    *errstr = xrealloc(*errstr, strlen(*errstr) + strlen(buf) + 30);
    syslog(LOG_DEBUG, "%s", buf);
    strcat(*errstr, buf);

    return SIEVE_OK;
}

/* returns TRUE or FALSE */
int build_sieve_interp(void)
{
    int res;
  
    res = sieve_interp_alloc(&interp, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_interp_alloc() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_redirect(interp, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_redirect() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_discard(interp, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_discard() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_reject(interp, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_reject() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_fileinto(interp, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_fileinto() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_keep(interp, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_keep() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_imapflags(interp, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_imapflags() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_size(interp, (sieve_get_size *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_size() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_header(interp, (sieve_get_header *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_header() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_envelope(interp, (sieve_get_envelope *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_envelope() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_body(interp, (sieve_get_body *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_body() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_include(interp, (sieve_get_include *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_include() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_vacation(interp, &vacation);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_vacation() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_notify(interp, &sieve_notify);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_notify() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_parse_error(interp, &mysieve_error);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_parse_error() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    return TIMSIEVE_OK;
}

/* returns TRUE or FALSE */
int is_script_parsable(FILE *stream, char **errstr, sieve_script_t **ret)
{
    sieve_script_t *s;
    int res;
  
    rewind(stream);

    *errstr = (char *) xmalloc(20 * sizeof(char));
    strcpy(*errstr, "script errors:\r\n");

    res = sieve_script_parse(interp, stream, errstr, &s);

    if (res == SIEVE_OK) {
	if(ret) {
	    *ret = s;
	} else {
	    sieve_script_free(&s);
	}
	free(*errstr);
	*errstr = NULL;
    }

    return (res == SIEVE_OK) ? TIMSIEVE_OK : TIMSIEVE_FAIL;
}
