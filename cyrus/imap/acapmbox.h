/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: acapmbox.h,v 1.18 2002/05/25 19:57:43 leg Exp $ */

#ifndef ACAPMBOX_H_
#define ACAPMBOX_H_

#include "acap.h"
#include "mailbox.h"

/* all functions return IMAP error codes */

int acapmbox_init(void);

#define global_dataset "/mailbox/site"

typedef enum {
    ACAPMBOX_UNKNOWN,
    ACAPMBOX_RESERVED,
    ACAPMBOX_COMMITTED
} acapmbox_status;

typedef struct acapmbox_data_s {
    char name[MAX_MAILBOX_NAME]; /* name of the mailbox */
    unsigned int uidvalidity;

    acapmbox_status status;	 /* reserved | committed */
    int haschildren;		 /* yes | no */
    char post[MAX_MAILBOX_PATH]; /* where a post to this mailbox should go */
    char url[MAX_MAILBOX_PATH];	 /* where mailbox is located */
    char *acl;			 /* acl */

    unsigned int answered;       /* number of messages with attribute */
    unsigned int flagged;        /* etc */
    unsigned int deleted;
    unsigned int total;
} acapmbox_data_t;

typedef struct acapmbox_handle_s acapmbox_handle_t;

/*
 * get a handle.  all returns (including NULL) are valid!
 * may be a noop for non-acap-enabled installs.
 */
acapmbox_handle_t *acapmbox_get_handle(void);

void acapmbox_disconnect(acapmbox_handle_t *conn);

void acapmbox_release_handle(acapmbox_handle_t *handle);

/*
 * generate an entry
 *
 * 'mboxdata' need not be initialized but must be allocated
 * 'server' may be NULL
 */
acapmbox_data_t *acapmbox_new(acapmbox_data_t *mboxdata,
			      const char *server, const char *name);

/*
 * Create a new entry for mailbox_name
 * 
 * mboxdata is initial value for it (may be NULL)
 *
 * sets the status of the entry on success to reserved
 */
int acapmbox_create(acapmbox_handle_t *AC,
		    acapmbox_data_t *mboxdata);

/* likewise, but you can mark it active immediately; use with caution */
int acapmbox_store(acapmbox_handle_t *AC,
		   acapmbox_data_t *mboxdata,
		   int commit);

/*
 * Commit the entry 
 */
int acapmbox_markactive(acapmbox_handle_t *AC,
			acapmbox_data_t *mboxdata);

/*
 * Remove an entry
 */
int acapmbox_delete(acapmbox_handle_t *AC,
		    const char *mailbox_name);


/*
 * Delete all entries (the whole dataset)
 */
int acapmbox_deleteall(acapmbox_handle_t *AC);

/* 
 * does a mailbox exist? 
 * return ACAP_OK if it does; ACAP_FAIL if it doesn't
 */
int acapmbox_entryexists(acapmbox_handle_t *AC,
			 char *mailbox_name);

typedef enum {
    ACAPMBOX_ANSWERED,
    ACAPMBOX_FLAGGED,
    ACAPMBOX_DELETED,
    ACAPMBOX_TOTAL,
    ACAPMBOX_UIDVALIDITY
} acapmbox_property_t;

/*
 * properties are hints that the ACAP server stores about various mailboxes
 * used to provide a master update service
 */
int acapmbox_setproperty_acl(acapmbox_handle_t *AC,
			     char *mailbox_name,
			     char *newvalue);

int acapmbox_setproperty(acapmbox_handle_t *AC,
			 char *mailbox_name,
			 acapmbox_property_t prop,
			 int value);

int acapmbox_setsomeprops(acapmbox_handle_t *AC,
			  char *mailbox_name,
			  int uidvalidity,
			  int exists,
			  int deleted,
			  int flagged,
			  int answered);

acapmbox_status mboxdata_convert_status(acap_value_t *v);

acap_conn_t *acapmbox_get_acapconn(acapmbox_handle_t *AC);

/*
 * return the ACAP entry for 'mailbox'.  
 * 'ret' must be at least MAX_MAILBOX_PATH.
 */
int acapmbox_dataset_name(const char *mailbox, char *ret);

/* 
 * given an ACAP entry 'entryname', return 'mailbox'.
 * 'ret' must be at least MAX_MAILBOX_NAME
 */
int acapmbox_decode_entry(const char *entryname, char *ret);

/* helper function */
int add_attr(skiplist *sl, char *name, char *value);

/**************** proxy use *****************/
#define FNAME_TARGET_SOCK "/socket/target"
void acapmbox_kick_target(void);

#endif /* ACAP_MBOX_H_ */
