/* sieve_interface.h -- interface for deliver
 * $Id: sieve_interface.h,v 1.1.1.1 1999/07/02 18:55:35 leg Exp $
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

#ifndef SIEVE_H
#define SIEVE_H

#include <stdio.h>

extern const char *sieve_version;

typedef enum {
    SIEVE_OK = 0,
    SIEVE_FAIL = 1284593152,
    SIEVE_NOT_FINALIZED,
    SIEVE_PARSE_ERROR,
    SIEVE_RUN_ERROR,
    SIEVE_INTERNAL_ERROR,
    SIEVE_NOMEM,
    SIEVE_DONE
} sieve_error_t;

/* external sieve types */
typedef struct sieve_interp sieve_interp_t;
typedef struct sieve_script sieve_script_t;

typedef int sieve_callback(char *arg, void *interp_context, 
			   void *script_context,
			   void *message_context);
typedef int sieve_get_size(void *message_context, int *size);
typedef int sieve_get_header(void *message_context, char *header,
			     char ***contents);
typedef int sieve_get_envelope(void *message_context, char *field,
			       char ***contents);

typedef struct sieve_vacation {
    int min_response;		/* 0 -> defaults to 3 */
    int max_response;		/* 0 -> defaults to 90 */

    /* given a hash, say whether we've already responded to it in the last
       days days.  return SIEVE_OK if we SHOULD autorespond (have not already)
       or SIEVE_DONE if we SHOULD NOT. */
    int (*autorespond)(unsigned char *hash, int len, int days, 
		       void *interp_context, void *script_context, 
		       void *message_context); 

    /* mail the response */
    int (*send_response)(char *addr, char *subj, char *msg, int mime,
			 void *interp_context, void *script_context,
			 void *message_context);
} sieve_vacation_t;

/* build a sieve interpretor */
int sieve_interp_alloc(sieve_interp_t **interp, void *interp_context);
int sieve_interp_free(sieve_interp_t **interp);

/* add the callbacks for actions. undefined behavior results if these
   are called after sieve_script_parse is called! */
int sieve_register_redirect(sieve_interp_t *interp, sieve_callback *f);
int sieve_register_discard(sieve_interp_t *interp, sieve_callback *f);
int sieve_register_reject(sieve_interp_t *interp, sieve_callback *f);
int sieve_register_fileinto(sieve_interp_t *interp, sieve_callback *f);
int sieve_register_keep(sieve_interp_t *interp, sieve_callback *f);
int sieve_register_vacation(sieve_interp_t *interp, sieve_vacation_t *v);

/* add the callbacks for messages. again, undefined if used after
   sieve_script_parse */
int sieve_register_size(sieve_interp_t *interp, sieve_get_size *f);
int sieve_register_header(sieve_interp_t *interp, sieve_get_header *f);
int sieve_register_envelope(sieve_interp_t *interp, sieve_get_envelope *f);

/* given an interpretor and a script, produce an executable script */
int sieve_script_parse(sieve_interp_t *interp, FILE *script,
		       void *script_context, sieve_script_t **ret);
int sieve_script_free(sieve_script_t **s);

/* execute a script on a message, producing side effects via callbacks */
int sieve_execute_script(sieve_script_t *script, 
			 void *message_context);


#endif
