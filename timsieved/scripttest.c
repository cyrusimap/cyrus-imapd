/* scripttest.c -- test wheather the sieve script is valid
 * Tim Martin
 * $Id: scripttest.c,v 1.17 2000/10/09 04:00:09 leg Exp $
 */
/*
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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


#include <sieve_interface.h>
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

static int sieve_notify(void *ac, 
			void *interp_context, 
			void *script_context,
			void *message_context,
			const char **errmsg)
{
    fatal("stub function called", 0);
    return SIEVE_FAIL;
}

int mysieve_error(int lineno, const char *msg,
		  void *i, void *s)
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
int is_script_parsable(FILE *stream, char **errstr)
{
    sieve_interp_t *i;
    sieve_script_t *s;
    int res;
  
    res = sieve_interp_alloc(&i, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_interp_alloc() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_redirect(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_redirect() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_discard(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_discard() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_reject(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_reject() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_fileinto(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_fileinto() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_keep(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_keep() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_imapflags(i, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_imapflags() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_size(i, (sieve_get_size *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_size() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_header(i, (sieve_get_header *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_header() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_envelope(i, (sieve_get_envelope *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_envelope() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
  
    res = sieve_register_vacation(i, &vacation);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_vacation() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_notify(i, &sieve_notify);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_notify() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    res = sieve_register_parse_error(i, &mysieve_error);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_parse_error() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }

    rewind(stream);

    *errstr = (char *) xmalloc(20 * sizeof(char));
    strcpy(*errstr, "script errors:\r\n");

    res = sieve_script_parse(i, stream, errstr, &s);

    if (res == SIEVE_OK) {
	sieve_script_free(&s);
	free(*errstr);
	*errstr = NULL;
    }

    /* free interpreter */
    sieve_interp_free(&i);

    return (res == SIEVE_OK) ? TIMSIEVE_OK : TIMSIEVE_FAIL;
}
