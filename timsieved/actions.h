/* actions.h -- executes the commands (creating, deleting scripts etc..) for timsieved */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _ACTIONS_H_
#define _ACTIONS_H_


#include "prot.h"
#include "util.h"

extern int sieved_tls_required;

/*
 * Get the list of capabilities
 *
 */

int capabilities(struct protstream *conn, sasl_conn_t *saslconn,
                 int starttls_done, int authenticated, sasl_ssf_t sasl_ssf);

/*
 * Get a sieve script with name "name" and output it's contents
 *
 */

int getscript(struct protstream *conn, const struct buf *name);

/*
 * Put a scripts in the server with 'name' whose contents should be 'data'
 *
 */

int putscript(struct protstream *conn, const struct buf *name,
              const struct buf *data, int verify_only);

/*
 * Rename the script with name 'oldname' to 'newname'
 *
 */

int renamescript(struct protstream *conn,
                 const struct buf *oldname, const struct buf *newname);

/*
 * Delete the script with name 'name'
 *
 */

int deletescript(struct protstream *conn, const struct buf *name);

/*
 * Is there space for this script?
 *
 */

int cmd_havespace(struct protstream *sieved_out, const struct buf *sieve_name, unsigned long num);

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

int setactive(struct protstream *conn, const struct buf *name);

/*
 * Initialize
 *
 */

int actions_init(void);

/*
 * Set user after successful authentication
 *
 */

int actions_setuser(const char *userid);

/*
 * Unset user after unauthentication/logout
 *
 */

void actions_unsetuser(void);

#endif
