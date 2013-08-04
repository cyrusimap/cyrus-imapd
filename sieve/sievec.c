/* sievec.c -- compile a sieve script to bytecode manually
 * Rob Siemborski
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sieve_interface.h"
#include <syslog.h>

#include "libconfig.h"
#include "xmalloc.h"

#include "script.h"
#include "util.h"
#include "assert.h"
#include <string.h> 
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int is_script_parsable(FILE *stream, char **errstr, sieve_script_t **ret);

#define TIMSIEVE_FAIL -1
#define TIMSIEVE_OK 0

int main(int argc, char **argv) 
{
    FILE *instream;
    char *err = NULL;
    sieve_script_t *s;
    bytecode_info_t *bc;
    int c, fd, usage_error = 0;
    char *alt_config = NULL;

    while ((c = getopt(argc, argv, "C:")) != EOF)
	switch (c) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	default:
	    usage_error = 1;
	    break;
	}

    if (usage_error || (argc - optind) < 2) {
	fprintf(stderr, "Syntax: %s [-C <altconfig>] <filename> <outputfile>\n",
	       argv[0]);
	exit(1);
    }

    instream = fopen(argv[optind++],"r");
    if(instream == NULL) {
	fprintf(stderr, "Unable to open %s for reading\n", argv[1]);
	exit(1);
    }
    
    /* Load configuration file. */
    config_read(alt_config, 0);

    if(is_script_parsable(instream, &err, &s) == TIMSIEVE_FAIL) {
	if(err) {
	    fprintf(stderr, "Unable to parse script: %s\n", err);
	} else {
	    fprintf(stderr, "Unable to parse script.\n");
	}
	 
	exit(1);
    }
    
    /* Now, generate the bytecode */
    if(sieve_generate_bytecode(&bc, s) == -1) {
	fprintf(stderr, "bytecode generate failed\n");
	exit(1);
    }

    /* Now, open the new file */
    fd = open(argv[optind], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
	fprintf(stderr, "couldn't open bytecode output file\n");
	exit(1);
    }  

    /* Now, emit the bytecode */
    if(sieve_emit_bytecode(fd, bc) == -1) {
	fprintf(stderr, "bytecode emit failed\n");
	exit(1);
    }

    close(fd);
    
    sieve_free_bytecode(&bc);
    sieve_script_free(&s);

    return 0;
}

/* to make larry's stupid functions happy :) */ 
static void foo(void)
{
    fatal("stub function called", 0);
}
static sieve_vacation_t vacation = {
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

static int mysieve_error(int lineno, const char *msg,
			 void *i __attribute__((unused)), void *s)
{
    struct buf *errors = (struct buf *)s;
    buf_printf(errors, "line %d: %s\r\n", lineno, msg);
    return SIEVE_OK;
}

EXPORTED void fatal(const char *s, int code)
{  
    fprintf(stderr, "Fatal error: %s (%d)\r\n", s, code);
                           
    exit(1);
}
/* end the boilerplate */

/* returns TRUE or FALSE */
static int is_script_parsable(FILE *stream, char **errstr, sieve_script_t **ret)
{
    sieve_interp_t *i;
    sieve_script_t *s;
    struct buf errors = BUF_INITIALIZER;
    int res;

    i = sieve_interp_alloc(NULL);
    assert(i != NULL);

    sieve_register_redirect(i, (sieve_callback *) &foo);
    sieve_register_discard(i, (sieve_callback *) &foo);
    sieve_register_reject(i, (sieve_callback *) &foo);
    sieve_register_fileinto(i, (sieve_callback *) &foo);
    sieve_register_keep(i, (sieve_callback *) &foo);
    sieve_register_imapflags(i, NULL);
    sieve_register_size(i, (sieve_get_size *) &foo);
    sieve_register_header(i, (sieve_get_header *) &foo);
    sieve_register_envelope(i, (sieve_get_envelope *) &foo);
    sieve_register_body(i, (sieve_get_body *) &foo);
    sieve_register_include(i, (sieve_get_include *) &foo);

    res = sieve_register_vacation(i, &vacation);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_vacation() returns %d\n", res);
	goto done;
    }

    sieve_register_notify(i, &sieve_notify);
    sieve_register_parse_error(i, &mysieve_error);

    rewind(stream);

    buf_appendcstr(&errors, "script errors:\r\n");
    *errstr = NULL;

    res = sieve_script_parse(i, stream, &errors, &s);

    if (res == SIEVE_OK) {
	if(ret) {
	    *ret = s;
	} else {
	    sieve_script_free(&s);
	}
    }
    else {
	sieve_script_free(&s);
	*errstr = buf_release(&errors);
    }
    buf_free(&errors);

done:
    /* free interpreter */
    sieve_interp_free(&i);

    return (res == SIEVE_OK) ? TIMSIEVE_OK : TIMSIEVE_FAIL;
}
