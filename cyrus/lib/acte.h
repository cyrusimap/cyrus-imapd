/* acte.h -- Interface for IMAP AUTHENTICATE mechanisms 
 *
 *	(C) Copyright 1994,1996 by Carnegie Mellon University
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

#ifndef INCLUDED_ACTE_H
#define INCLUDED_ACTE_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <time.h>

struct sockaddr;

typedef const char *acte_encodefunc_t P((void *state,
					  char *input, int inputlen,
					  char *output, int *outputlen));
typedef const char *acte_decodefunc_t P((void *state,
					  char *input, int inputlen,
					  char **output, int *outputlen));
typedef int acte_authproc_t P((const char *user, const char *auth_identity,
			       const char **reply));

/* Client-side authentication mechanism */
struct acte_client {
    /* Name of authentication mechanism */
    char *auth_type;

    /* Start a client->server authentication */
    int (*start) P((const char *service, const char *host, const char *user,
		    int protallowed, int maxbufsize,
		    struct sockaddr *localaddr, struct sockaddr *remoteaddr,
		    void **state));

    /* Do an authentication protocol exchange */
    int (*auth) P((void *state, int inputlen, char *input,
		   int *outputlen, char **output));
    
    /* Query an authentication state */
    void (*query_state) P((void *state, char **user, int *protlevel,
			   acte_encodefunc_t **encodefunc,
			   acte_decodefunc_t **decodefunc, int *maxplain));

    /* Free an authentication state */
    void (*free_state) P((void *state));
    
    /* Acquire daemon's credentials */
    const char *(*new_cred) P((const char *service, time_t *lifetime));	

    /* Free daemon's credentials */
    void (*free_cred) P((void));
};

/* Server-side authentication mechanism */
struct acte_server {
    /* Name of authentication mechanism */
    char *auth_type;		

    /* Start an incoming authentication */
    int (*start) P((const char *service, acte_authproc_t *authproc,
		    int protallowed, int maxbufsize,
		    struct sockaddr *localaddr, struct sockaddr *remoteaddr,
		    int *outputlen, char **output,
		    void **state, const char ** reply));
    
    /* Do an authentication protocol exchange */
    int (*auth) P((void *state, int inputlen, char *input,
		   int *outputlen, char **output, const char **reply));

    /* Query an authentication state */
    void (*query_state) P((void *state, char **user, int *protlevel,
			   acte_encodefunc_t **encodefunc,
			   acte_decodefunc_t **decodefunc, int *maxplain));

    /* Free an authentication state */
    void (*free_state) P((void *state));
    
    /* Get a cacheid, if available */
    char *(*get_cacheid) P((void *state));
};

/* Protection mechanisms */
#define ACTE_PROT_NONE 1
#define ACTE_PROT_INTEGRITY 2
#define ACTE_PROT_PRIVACY 4
#define ACTE_PROT_ANY (ACTE_PROT_NONE|ACTE_PROT_INTEGRITY|ACTE_PROT_PRIVACY)

#define ACTE_FAIL 1		/* Authentication failed */

#define ACTE_DONE 3		/* Server has authenticated user */

extern char *acte_prottostring P((int protlevel));

#endif /* INCLUDED_ACTE_H */
