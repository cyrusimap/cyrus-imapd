/* actions.h -- executes the commands (creating, deleting scripts etc..) for timsieved
 * Tim Martin
 * 9/21/99
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


#ifndef _ACTIONS_H_
#define _ACTIONS_H_


#include "prot.h"
#include "mystring.h"

/*
 * Get the list of capabilities
 *
 */

int capabilities(struct protstream *conn, sasl_conn_t *saslconn);

/*
 * Get a sieve scripe with name "name" and output it's contents
 *
 */

int getscript(struct protstream *conn, mystring_t *name);

/*
 * Put a scripts in the server with 'name' whose contents should be 'data'
 *
 */

int putscript(struct protstream *conn, mystring_t *name, mystring_t *data);

/*
 * Delete the script with name 'name'
 *
 */

int deletescript(struct protstream *conn, mystring_t *name);

/*
 * ?
 *
 */

int verifyscriptname(mystring_t *name);

/*
 * Is there space for this script?
 *
 */

int cmd_havespace(struct protstream *sieved_out, mystring_t *sieve_name, unsigned long num);

/*
 * List all the scripts for the user. place a '*' next to the active one
 *   if there is one
 *
 */

int listscripts(struct protstream *conn);

/*
 * Set 'name' as the active sieve script
 *
 */

int setactive(struct protstream *conn, mystring_t *name);

/*
 * Initialize
 *
 */

int actions_init(void);

/*
 * Set user after sucessful authentication
 *
 */

int actions_setuser(char *userid);



#endif
