/* scripttest.c -- test wheather the sieve script is valid
 * Tim Martin
 * $Id: scripttest.c,v 1.8 2000/01/28 22:09:57 leg Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/


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
    (int (*)(unsigned char *, int, int, 
	     void *, void *, 
	     void *))    &foo,	/* autorespond() */
    (int (*)(char *, char *, char *, int, int,
	     void *, void *,
	     void *) )   &foo   /* send_response() */
};

int mysieve_error(int lineno, char *msg,
		  void *i, void *s)
{
    char buf[1024];
    char **errstr = (char **) s;

    snprintf(buf, 80, "line %d: %s\r\n", lineno, msg);
    *errstr = xrealloc(*errstr, strlen(*errstr) + strlen(buf));
    syslog(LOG_DEBUG, buf);
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

    res = sieve_register_setflag(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_setflag() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_addflag(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_addflag() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_removeflag(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_removeflag() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_mark(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_mark() returns %d\n", res);
	return TIMSIEVE_FAIL;
    }
    res = sieve_register_unmark(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_unmark() returns %d\n", res);
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
