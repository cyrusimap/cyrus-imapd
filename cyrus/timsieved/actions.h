/* actions.h -- executes the commands (creating, deleting scripts etc..) for timsieved
 * Tim Martin
 * 9/21/99
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

int putscript(struct protstream *conn, mystring_t *name, mystring_t *data,
	      int verify_only);

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

int actions_setuser(const char *userid);



#endif
