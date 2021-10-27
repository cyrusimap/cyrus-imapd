/* sieve_interface.h -- interface for deliver
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#ifndef SIEVE_H
#define SIEVE_H

#include <stdio.h>

#define SIEVE_VERSION "CMU Sieve 3.0"

/* error codes */
#define SIEVE_OK (0)

#include "arrayu64.h"
#include "strarray.h"
#include "util.h"
#include "sieve/sieve_err.h"

/* external sieve types */
typedef struct sieve_interp sieve_interp_t;
typedef struct sieve_script sieve_script_t;
typedef struct sieve_execute sieve_execute_t;
typedef struct bytecode_info bytecode_info_t;

typedef int sieve_callback(void *action_context, void *interp_context,
                           void *script_context,
                           void *message_context, const char **errmsg);
typedef int sieve_get_size(void *message_context, int *size);
typedef int sieve_get_mailboxexists(void *interp_context, const char *extname);
typedef int sieve_get_mailboxidexists(void *interp_context, const char *extname);
typedef int sieve_get_specialuseexists(void *interp_context, const char *extname,
                                       strarray_t *uses);
typedef int sieve_get_metadata(void *interp_context, const char *extname,
                               const char *keyname, char **res);
typedef int sieve_get_header(void *message_context,
                             const char *header,
                             const char ***contents);
typedef int sieve_get_headersection(void *message_context,
                                    struct buf **contents);
typedef int sieve_add_header(void *message_context,
                             const char *header, const char *contents, int index);
typedef int sieve_delete_header(void *message_context,
                                const char *header, int index);
typedef int sieve_get_fname(void *message_context, const char **fname);
typedef int sieve_get_envelope(void *message_context,
                               const char *field,
                               const char ***contents);
typedef int sieve_get_environment(void *script_context,
                                  const char *keyname, char **res);
typedef int sieve_get_include(void *script_context, const char *script,
                              int isglobal, char *fpath, size_t size);
typedef void sieve_logger(void *script_context, void *message_context,
                          const char *text);
typedef int sieve_list_validator(void *interp_context, const char *list);
typedef int sieve_list_comparator(const char *text, size_t tlen,
                                  const char *list, strarray_t *match_vars,
                                  void *rock);
typedef int sieve_jmapquery(void *interp_context, void *script_context,
                            void *message_context, const char *json);

typedef struct sieve_imip_context {
    unsigned updates_only    : 1;
    unsigned delete_canceled : 1;
    const char *calendarid;
    struct buf errstr;
} sieve_imip_context_t;

typedef int sieve_processimip(void *interp_context, void *script_context,
                              void *message_context,
                              sieve_imip_context_t *imip_context);
                              
/* MUST keep this struct sync'd with bodypart in imap/message.h */
typedef struct sieve_bodypart {
    char section[128];
    const char *decoded_body;
} sieve_bodypart_t;

typedef int sieve_get_body(void *message_context, const char **content_types,
                           sieve_bodypart_t ***parts);

typedef struct sieve_vacation {
    int min_response;           /* 0 -> defaults to 3 days */
    int max_response;           /* 0 -> defaults to 90 days */

    /* given a hash, say whether we've already responded to it in the last
       days days.  return SIEVE_OK if we SHOULD autorespond (have not already)
       or SIEVE_DONE if we SHOULD NOT. */
    sieve_callback *autorespond;

    /* mail the response */
    sieve_callback *send_response;
} sieve_vacation_t;

typedef struct sieve_duplicate {
    int max_expiration;           /* 0 -> defaults to 90 days */
    sieve_callback *check;
    sieve_callback *track;
} sieve_duplicate_t;


/* sieve_imapflags: NULL -> defaults to \flagged */

typedef struct sieve_redirect_context {
    const char *addr;
    int is_ext_list :1;
    const char *deliverby;
    const char *dsn_notify;
    const char *dsn_ret;
    struct buf *headers;
} sieve_redirect_context_t;

typedef struct sieve_reject_context {
    const char *msg;
    int is_extended :1;
} sieve_reject_context_t;

typedef struct sieve_snooze_context {
    const char *awaken_mbox;
    const char *awaken_mboxid;
    const char *awaken_spluse;
    int do_create : 1;
    strarray_t *imapflags;
    strarray_t *addflags;
    strarray_t *removeflags;
    unsigned char days;
    arrayu64_t *times;
    const char *tzid;
    struct buf *headers;
} sieve_snooze_context_t;

typedef struct sieve_fileinto_context {
    const char *mailbox;
    const char *specialuse;
    strarray_t *imapflags;
    int do_create :1;
    const char *mailboxid;
    struct buf *headers;
    char *resolved_mailbox;
} sieve_fileinto_context_t;

typedef struct sieve_keep_context {
    strarray_t *imapflags;
    struct buf *headers;
    char *resolved_mailbox;
} sieve_keep_context_t;

typedef struct sieve_notify_context {
    const char *method;
    const char *from;
    strarray_t *options;
    const char *priority;
    const char *message;
    const char *fname;
} sieve_notify_context_t;

#define SIEVE_HASHLEN 16

typedef struct sieve_autorespond_context {
    unsigned char hash[SIEVE_HASHLEN];
    int seconds;
} sieve_autorespond_context_t;

typedef struct sieve_send_response_context {
    char *addr;
    char *fromaddr;
    const char *msg;
    char *subj;
    int mime;
    sieve_fileinto_context_t fcc;
} sieve_send_response_context_t;

typedef struct sieve_duplicate_context {
    char *id;
    int seconds;
} sieve_duplicate_context_t;

/* build a sieve interpreter */
sieve_interp_t *sieve_interp_alloc(void *interp_context);
int sieve_interp_free(sieve_interp_t **interp);

sieve_interp_t *sieve_build_nonexec_interp();

/* add the callbacks for actions. undefined behavior results if these
   are called after sieve_script_parse is called! */
void sieve_register_redirect(sieve_interp_t *interp, sieve_callback *f);
void sieve_register_discard(sieve_interp_t *interp, sieve_callback *f);
void sieve_register_reject(sieve_interp_t *interp, sieve_callback *f);
void sieve_register_fileinto(sieve_interp_t *interp, sieve_callback *f);
void sieve_register_snooze(sieve_interp_t *interp, sieve_callback *f);
void sieve_register_keep(sieve_interp_t *interp, sieve_callback *f);
int sieve_register_vacation(sieve_interp_t *interp, sieve_vacation_t *v);
void sieve_register_notify(sieve_interp_t *interp,
                           sieve_callback *f, const strarray_t *methods);
void sieve_register_include(sieve_interp_t *interp, sieve_get_include *f);
void sieve_register_logger(sieve_interp_t *interp, sieve_logger *f);

/* add the callbacks for messages. again, undefined if used after
   sieve_script_parse */
void sieve_register_size(sieve_interp_t *interp, sieve_get_size *f);
void sieve_register_mailboxexists(sieve_interp_t *interp,
                                  sieve_get_mailboxexists *f);
void sieve_register_mailboxidexists(sieve_interp_t *interp,
                                    sieve_get_mailboxidexists *f);
void sieve_register_specialuseexists(sieve_interp_t *interp,
                                     sieve_get_specialuseexists *f);
void sieve_register_metadata(sieve_interp_t *interp, sieve_get_metadata *f);
void sieve_register_header(sieve_interp_t *interp, sieve_get_header *f);
void sieve_register_headersection(sieve_interp_t *interp,
                                  sieve_get_headersection *f);
int sieve_register_addheader(sieve_interp_t *interp, sieve_add_header *f);
int sieve_register_deleteheader(sieve_interp_t *interp, sieve_delete_header *f);
void sieve_register_fname(sieve_interp_t *interp, sieve_get_fname *f);
void sieve_register_envelope(sieve_interp_t *interp, sieve_get_envelope *f);
void sieve_register_environment(sieve_interp_t *interp, sieve_get_environment *f);
void sieve_register_body(sieve_interp_t *interp, sieve_get_body *f);

void sieve_register_extlists(sieve_interp_t *interp,
                             sieve_list_validator *v, sieve_list_comparator *c);
                                
int sieve_register_duplicate(sieve_interp_t *interp, sieve_duplicate_t *d);

void sieve_register_jmapquery(sieve_interp_t *interp, sieve_jmapquery *f);

void sieve_register_imip(sieve_interp_t *interp, sieve_processimip *f);

typedef int sieve_parse_error(int lineno, const char *msg,
                              void *interp_context,
                              void *script_context);
void sieve_register_parse_error(sieve_interp_t *interp, sieve_parse_error *f);

typedef int sieve_execute_error(const char *msg, void *interp_context,
                                void *script_context, void *message_context);
void sieve_register_execute_error(sieve_interp_t *interp,
                                 sieve_execute_error *f);

/* given an interpreter and a script, produce an executable script */
int sieve_script_parse(sieve_interp_t *interp, FILE *script,
                       void *script_context, sieve_script_t **ret);

/* Wrapper for sieve_script_parse using a disposable single-use interpreter.
 * Use when you only want to parse or compile, but not execute, a script. */
int sieve_script_parse_only(FILE *stream, char **out_errors,
                            sieve_script_t **ret);

/* Parse (but not compile or execute) a script in a string buffer.
 * If interp is NULL, a disposable single-use interpreter will be used. */
int sieve_script_parse_string(sieve_interp_t *interp, const char *s,
                              char **errors, sieve_script_t **script);

/* given a path to a bytecode file, load it into the sieve_execute_t */
int sieve_script_load(const char *fpath, sieve_execute_t **ret);

/* Unload a sieve_bytecode_t */
int sieve_script_unload(sieve_execute_t **s);

/* Free a sieve_script_t */
void sieve_script_free(sieve_script_t **s);

/* execute bytecode on a message */
int sieve_execute_bytecode(sieve_execute_t *script, sieve_interp_t *interp,
                           void *script_context, void *message_context);

/* Get space separated list of extensions supported by the implementation */
const strarray_t *sieve_listextensions(sieve_interp_t *i);

/* Create a bytecode structure given a parsed commandlist */
int sieve_generate_bytecode(bytecode_info_t **retval, sieve_script_t *s);

/* Emit bytecode to a file descriptor */
int sieve_emit_bytecode(int fd, bytecode_info_t *bc);

/* Free a bytecode_info_t */
void sieve_free_bytecode(bytecode_info_t **p);

/* Rebuild bc_fname from script_fname if needed or forced.
 * At least one of script_fname or bc_fname must be provided.
 */
int sieve_rebuild(const char *script_fname, const char *bc_fname,
                  int force, char **out_parse_errors);

#endif
