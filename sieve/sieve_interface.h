/* sieve_interface.h -- interface for deliver
 * $Id: sieve_interface.h,v 1.17.4.2 2003/03/05 18:15:10 rjs3 Exp $
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

#define SIEVE_VERSION "CMU Sieve 2.2"

/* error codes */
#define SIEVE_OK (0)

#include "sieve_err.h"

/* external sieve types */
typedef struct sieve_interp sieve_interp_t;
typedef struct sieve_script sieve_script_t;
typedef struct sieve_bytecode sieve_bytecode_t;
typedef struct bytecode_info bytecode_info_t;

typedef int sieve_callback(void *action_context, void *interp_context, 
			   void *script_context,
			   void *message_context, const char **errmsg);
typedef int sieve_get_size(void *message_context, int *size);
typedef int sieve_get_header(void *message_context, 
			     const char *header,
			     const char ***contents);
typedef int sieve_get_envelope(void *message_context, 
			       const char *field,
			       const char ***contents);

typedef struct sieve_vacation {
    int min_response;		/* 0 -> defaults to 3 */
    int max_response;		/* 0 -> defaults to 90 */

    /* given a hash, say whether we've already responded to it in the last
       days days.  return SIEVE_OK if we SHOULD autorespond (have not already)
       or SIEVE_DONE if we SHOULD NOT. */
    sieve_callback *autorespond;

    /* mail the response */
    sieve_callback *send_response;
} sieve_vacation_t;

typedef struct sieve_imapflags {
    char **flag;		/* NULL -> defaults to \flagged */
    int nflags;
} sieve_imapflags_t;

typedef struct sieve_redirect_context {
    const char *addr;
} sieve_redirect_context_t;

typedef struct sieve_reject_context {
    const char *msg;
} sieve_reject_context_t;

typedef struct sieve_fileinto_context {
    const char *mailbox;
    sieve_imapflags_t *imapflags;
} sieve_fileinto_context_t;

typedef struct sieve_keep_context {
    sieve_imapflags_t *imapflags;
} sieve_keep_context_t;

typedef struct sieve_notify_context {
    const char *method;
    const char **options;
    const char *priority;
    const char *message;
} sieve_notify_context_t;

typedef struct sieve_autorespond_context {
    unsigned char *hash;
    int len;
    int days;
} sieve_autorespond_context_t;

typedef struct sieve_send_response_context {
    char *addr;
    char *fromaddr;
    const char *msg;
    char *subj;
    int mime;
} sieve_send_response_context_t;

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
int sieve_register_imapflags(sieve_interp_t *interp, sieve_imapflags_t *mark);
int sieve_register_notify(sieve_interp_t *interp, sieve_callback *f);

/* add the callbacks for messages. again, undefined if used after
   sieve_script_parse */
int sieve_register_size(sieve_interp_t *interp, sieve_get_size *f);
int sieve_register_header(sieve_interp_t *interp, sieve_get_header *f);
int sieve_register_envelope(sieve_interp_t *interp, sieve_get_envelope *f);

typedef int sieve_parse_error(int lineno, const char *msg, 
			      void *interp_context,
			      void *script_context);
int sieve_register_parse_error(sieve_interp_t *interp, sieve_parse_error *f);

typedef int sieve_execute_error(const char *msg, void *interp_context,
				void *script_context, void *message_context);
int sieve_register_execute_error(sieve_interp_t *interp, 
				 sieve_execute_error *f);
 
/* given an interpretor and a script, produce an executable script */
int sieve_script_parse(sieve_interp_t *interp, FILE *script,
		       void *script_context, sieve_script_t **ret);

/* given a bytecode file descriptor, setup the sieve_bytecode_t */
int sieve_script_load(sieve_interp_t *interp, int fd, const char *name,
		      void *script_context, sieve_bytecode_t **ret);

/* Unload a sieve_bytecode_t */
int sieve_script_unload(sieve_bytecode_t **s);

/* Free a sieve_script_t */
int sieve_script_free(sieve_script_t **s);

/* execute bytecode on a message */
int sieve_execute_bytecode(sieve_bytecode_t *script, 
			   void *message_context);

/* execute a script on a message, producing side effects via callbacks */
int sieve_execute_script(sieve_script_t *script, 
			 void *message_context);

/* Get space separated list of extensions supported by the implementation */
const char *sieve_listextensions(void);

/* Create a bytecode structure given a parsed commandlist */
int sieve_generate_bytecode(bytecode_info_t **retval, sieve_script_t *s);

/* Emit bytecode to a file descriptor */
int sieve_emit_bytecode(int fd, bytecode_info_t *bc);

/* Free a bytecode_info_t */
void sieve_free_bytecode(bytecode_info_t **p);

#endif
