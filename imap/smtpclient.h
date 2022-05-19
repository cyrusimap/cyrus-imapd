/* smtpclient.h -- Routines for sending a message via SMTP
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

#ifndef INCLUDED_SMTPCLIENT_H
#define INCLUDED_SMTPCLIENT_H

#include "prot.h"
#include "ptrarray.h"
#include "strarray.h"
#include "util.h"

/* A parameter for SMTP envelope address, identified by key.
 * The value val may be NULL. */
typedef struct {
    char *key;
    char *val;
} smtp_param_t;

/* A SMTP envelope address with address addr. The params
 * array contains the optional address parameters for the
 * MAIL FROM and RCPT TO commands. */
typedef struct {
    char *addr;
    ptrarray_t params; /* Array of smtp_param_t */
    int completed;
} smtp_addr_t;

/* A SMTP envelope with the MAIL FROM address and one
 * or more RCPT TO recipient addresses. */
typedef struct {
    smtp_addr_t from;
    ptrarray_t rcpts; /* Array of smtp_addr_t */
} smtp_envelope_t;

/* The empty SMTP envelope */
#define SMTP_ENVELOPE_INITIALIZER { { NULL, PTRARRAY_INITIALIZER, 0 }, PTRARRAY_INITIALIZER }

/* Return non-zero if val is a valid esmtp-keyword
 * as defined in RFC 5321, section 4.1.2. */
extern int smtp_is_valid_esmtp_keyword(const char *val);

/* Return non-zero if val is a valid esmtp-value
 * as defined in RFC 5321, section 4.1.2. */
extern int smtp_is_valid_esmtp_value(const char *val);

/* Encode val as an esmtp-value
 * as defined in RFC 5321, section 4.1.2. */
extern void smtp_encode_esmtp_value(const char *val, struct buf *xtext);

/* Set the MAIL FROM address in env and return the new value.
 * Any existing address is deallocated. */
extern smtp_addr_t *smtp_envelope_set_from(smtp_envelope_t *env, const char *addr);

/* Add a RCPT TO address to the recipients of env and return the new value. */
extern smtp_addr_t *smtp_envelope_add_rcpt(smtp_envelope_t *env, const char *addr);

/* Free all memory of pointers and arrays in env */
extern void smtp_envelope_fini(smtp_envelope_t *env);

/* Opaque SMTP client type */
typedef struct smtpclient smtpclient_t;

/* Open a SMTP client to the default SMTP backend */
extern int smtpclient_open(smtpclient_t **smp);

/* Open a SMTP client to the sendmail process */
extern int smtpclient_open_sendmail(smtpclient_t **smp);

/* Open a SMTP client to the host at addr, formatted as host[:port] */
extern int smtpclient_open_host(const char *addr, smtpclient_t **smp);

/* Send message data with SMTP envelope env. Data is dot-escaped
 * before it is written to the SMTP backend. */
extern int smtpclient_send(smtpclient_t *sm, smtp_envelope_t *env, struct buf *data);
extern int smtpclient_sendprot(smtpclient_t *sm, smtp_envelope_t *env, struct protstream *data);

/* Check the SMTP envelope (and optionally size and/or From: header addresses)
   without sending data */
extern int smtpclient_sendcheck(smtpclient_t *sm, smtp_envelope_t *env,
                                size_t size, strarray_t *fromaddr);

/* Close the SMTP client and free its memory */
extern int smtpclient_close(smtpclient_t **smp);

/* Add the AUTH=userid parameter to MAIL FROM commands, if the
 * SMTP backend advertised support for the RFC 4954 AUTH extension.
 *
 * An AUTH parameter in the SMTP envelope of the smtpclient_send
 * function overrides this value, regardless of advertised extensions.
 *
 * Setting this to NULL resets userid. */
extern void smtpclient_set_auth(smtpclient_t *sm, const char *userid);

/* Add the NOTIFY=value parameter to RCPT TO commands, if the
 * SMTP backend advertised support for the RFC 3461 DSN extension.
 *
 * A NOTIFY parameter in the SMTP envelope of the smtpclient_send
 * function overrides this value, regardless of advertised extensions.
 *
 * Setting this to NULL resets the value. */
extern void smtpclient_set_notify(smtpclient_t *sm, const char *value);

/* Add the RET=value parameter to MAIL FROM commands, if the
 * SMTP backend advertised support for the RFC 3461 DSN extension.
 *
 * A RET parameter in the SMTP envelope of the smtpclient_from
 * function overrides this value, regardless of advertised extensions.
 *
 * Setting this to NULL resets the value. */
extern void smtpclient_set_ret(smtpclient_t *sm, const char *value);

/* Add the BY=value parameter to MAIL FROM commands, if the
 * SMTP backend advertised support for the RFC 2852 DELIVERYBY extension.
 *
 * A BY parameter in the SMTP envelope of the smtpclient_from
 * function overrides this value, regardless of advertised extensions.
 *
 * Setting this to NULL resets the value. */
extern void smtpclient_set_by(smtpclient_t *sm, const char *value);

/* Add the SIZE=value parameter to MAIL FROM commands, if the
 * SMTP backend advertised support for the RFC 1870 SIZE extension.
 *
 * A SIZE parameter in the SMTP envelope of the smtpclient_from
 * function overrides this value, regardless of advertised extensions.
 *
 * Setting this to 0 resets the value. */
extern void smtpclient_set_size(smtpclient_t *sm, unsigned long value);

/* Return the SIZE SMTP extension value.
 *
 * Return 0 if the extension has no value or is not supported. */
extern unsigned long smtpclient_get_maxsize(smtpclient_t *sm);

/* Return the argument string of SMTP extension 'name' as returned
 * in response to the EHLO command, excluding the extension name.
 * This may be the empty string.
 * Return NULL if the extension is not supported. */
extern const char *smtpclient_has_ext(smtpclient_t *sm, const char *name);

/* Return the code of the last SMTP response */
extern unsigned smtpclient_get_resp_code(smtpclient_t *sm);

/* Return the text of the last SMTP response, or NULL if empty */
extern const char *smtpclient_get_resp_text(smtpclient_t *sm);


#endif
