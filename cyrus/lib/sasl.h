/* sasl.h -- Interface for SASL mechanisms 
 $Id: sasl.h,v 1.2 1998/05/15 21:53:05 neplokh Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */

#ifndef INCLUDED_SASL_H
#define INCLUDED_SASL_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <time.h>

struct sockaddr;

typedef const char *sasl_encodefunc_t P((void *state,
					  char *input, int inputlen,
					  char *output, int *outputlen));
typedef const char *sasl_decodefunc_t P((void *state,
					  char *input, int inputlen,
					  char **output, int *outputlen));
typedef int sasl_authproc_t P((const char *user, const char *auth_identity,
			       const char **reply));

/* Client-side authentication mechanism */
struct sasl_client {
    /* Name of authentication mechanism */
    char *auth_type;

    int can_send_initial_response;

    /* Start a client->server authentication */
    int (*start) P((void *rock,
		    const char *service, const char *host, const char *user,
		    int protallowed, int maxbufsize,
		    struct sockaddr *localaddr, struct sockaddr *remoteaddr,
		    void **state));

    /* Do an authentication protocol exchange */
    int (*auth) P((void *state, int inputlen, char *input,
		   int *outputlen, char **output));
    
    /* Query an authentication state */
    void (*query_state) P((void *state, char **user, int *protlevel,
			   sasl_encodefunc_t **encodefunc,
			   sasl_decodefunc_t **decodefunc, int *maxplain));

    /* Free an authentication state */
    void (*free_state) P((void *state));
    
    /* Acquire daemon's credentials */
    const char *(*new_cred) P((const char *service, time_t *lifetime));	

    /* Free daemon's credentials */
    void (*free_cred) P((void));

    /* Place to hide data useful for starting authentications
     * (such as function for prompting user for password)
     */
    void *rock;
};

/* Server-side authentication mechanism */
struct sasl_server {
    /* Name of authentication mechanism */
    char *auth_type;		

    /* Start an incoming authentication */
    int (*start) P((void *rock,
		    const char *service, sasl_authproc_t *authproc,
		    int protallowed, int maxbufsize,
		    struct sockaddr *localaddr, struct sockaddr *remoteaddr,
		    int *outputlen, char **output,
		    void **state, const char ** reply));
    
    /* Do an authentication protocol exchange */
    int (*auth) P((void *state, int inputlen, char *input,
		   int *outputlen, char **output, const char **reply));

    /* Query an authentication state */
    void (*query_state) P((void *state, char **user, int *protlevel,
			   sasl_encodefunc_t **encodefunc,
			   sasl_decodefunc_t **decodefunc, int *maxplain));

    /* Free an authentication state */
    void (*free_state) P((void *state));
    
    /* Get a cacheid, if available */
    char *(*get_cacheid) P((void *state));

    /* Place to hide data useful for starting authentications
     * (such as place to get credentials)
     */
    void *rock;
};

/* Protection mechanisms */
#define SASL_PROT_NONE 1
#define SASL_PROT_INTEGRITY 2
#define SASL_PROT_PRIVACY 4
#define SASL_PROT_ANY (SASL_PROT_NONE|SASL_PROT_INTEGRITY|SASL_PROT_PRIVACY)

#define SASL_FAIL 1		/* Authentication failed */

#define SASL_DONE 3		/* Server has authenticated user */

extern char *sasl_prottostring P((int protlevel));

#endif /* INCLUDED_SASL_H */
