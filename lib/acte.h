/* acte.h -- Interface for IMAP AUTHENTICATE mechanisms 
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/* Client-side authentication mechanism */
struct acte_client {
    char *auth_type;		/* Name of authentication mechanism */
    int (*start)();		/* Start a client->server authentication */
    int (*auth)();		/* Do an authentication protocol exchange */
    void (*query_state)();	/* Query an authentication state */
    void (*free_state)();	/* Free an authentication state */
    char *(*new_cred)();	/* Acquire daemon's credentials */
    void (*free_cred)();	/* Free daemon's credentials */
};

/* Server-side authentication mechanism */
struct acte_server {
    char *auth_type;		/* Name of authentication mechanism */
    int (*start)();		/* Start an incoming authentication */
    int (*auth)();		/* Do an authentication protocol exchange */
    void (*query_state)();	/* Query an authentication state */
    void (*free_state)();	/* Free an authentication state */
    char *(*get_cacheid)();	/* Get a cacheid, if available */
};

/* Protection mechanisms */
#define ACTE_PROT_NONE 1
#define ACTE_PROT_INTEGRITY 2
#define ACTE_PROT_PRIVACY 4
#define ACTE_PROT_ANY (ACTE_PROT_NONE|ACTE_PROT_INTEGRITY|ACTE_PROT_PRIVACY)

#define ACTE_FAIL 1		/* Authentication failed */

#define ACTE_DONE 3		/* Server has authenticated user */

extern char *acte_prottostring();
