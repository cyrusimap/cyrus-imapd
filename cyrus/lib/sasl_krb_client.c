/* sasl_krb.c -- KERBEROS_V4 authentication routines for IMAP.
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
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <krb.h>

#include "sasl.h"
#include "sasl_krb_internal.h"

extern char *malloc();

extern char *lcase P((char *str));
extern char *krb_get_phost P((char *)), *krb_realmofhost P((char *));

/*
 * Start the client side of an authentication exchange.
 */
static int krb_client_start(rock, service, host, user, protallowed,
			    maxbufsize, localaddr, remoteaddr, state)
void *rock;			/* Ignored */
const char *service;		/* Name of service */
const char *host;		/* Name of server host */
const char *user;		/* (optional) user to log in as */
int protallowed;		/* Protection mechanisms allowed */
int maxbufsize;			/* Maximum ciphertext input buffer size */
struct sockaddr *localaddr;	/* Network address of local side */
struct sockaddr *remoteaddr;	/* Network address of remote side */
void **state;			/* On success, filled in with state ptr */
{
    struct hostent *host_name;
    char userbuf[MAX_K_NAME_SZ+1];
    char instance[INST_SZ];
    char realm[REALM_SZ];
    char uinst[INST_SZ];
    char urealm[INST_SZ];
    KTEXT_ST authent;
    CREDENTIALS cr;
    struct krb_state *kstate;
    char *p;

    protallowed &= SASL_PROT_NONE|SASL_PROT_INTEGRITY
#ifndef NOPRIVACY
	|SASL_PROT_PRIVACY
#endif
	;
    if (!localaddr || !remoteaddr) {
	protallowed &= SASL_PROT_NONE;
    }
    if (!protallowed) {
	return SASL_FAIL;
    }
    if (maxbufsize > 0xffffff) maxbufsize = 0xffffff;

    /* Canonicalize hostname */
    host_name = gethostbyname(host);
    if (!host_name) {
	return SASL_FAIL;
    }

    strncpy(instance, host_name->h_name, sizeof(instance)-1);
    instance[sizeof(instance)-1] = '\0';
    /* downcase the instance */
    p = instance;
    do {
      if (isupper(*p)) *p=tolower(*p);
    } while (*p++);
    strcpy(realm, krb_realmofhost(instance));
    if (p = strchr(instance, '.')) *p = '\0';


    /* Fetch imap.hostname service key */
    (void) krb_mk_req(&authent, service, instance, realm, 0);
    memset(&authent, 0, sizeof(authent));

    if (krb_get_cred(service, instance, realm, &cr)) {
	return SASL_FAIL;
    }
    
    if (!user || !user[0]) {
	if (krb_get_tf_fullname(TKT_FILE, userbuf, uinst, urealm)) {
	    memset(&cr, 0, sizeof(cr));
	    return SASL_FAIL;
	}
	if (uinst[0]) {
	    strcat(userbuf, ".");
	    strcat(userbuf, uinst);
	}
	if (strcmp(urealm, realm) != 0) {
	    strcat(userbuf, "@");
	    strcat(userbuf, urealm);
	}
	user = userbuf;
    }
    else if (strlen(user) > MAX_K_NAME_SZ) {
	return SASL_FAIL;
    }

    kstate = (struct krb_state *)malloc(sizeof(struct krb_state));
    if (!kstate) return SASL_FAIL;
    memset((char *)kstate, 0, sizeof(*kstate));
    strcpy(kstate->service, service);
    kstate->authstepno = 0;
    memcpy(kstate->session, cr.session, sizeof(des_cblock));
    des_key_sched(kstate->session, kstate->schedule);
    strcpy(kstate->user, user);
    kstate->protallowed = protallowed;
    kstate->maxbufsize = maxbufsize;
    if (localaddr && remoteaddr) {
	kstate->localaddr = *(struct sockaddr_in *)localaddr;
	kstate->remoteaddr = *(struct sockaddr_in *)remoteaddr;
    }
    strcpy(kstate->instance, instance);
    strcpy(kstate->realm, realm);

    memset(&cr, 0, sizeof(cr));
    *state = (void *)kstate;
    return 0;
}

/*
 * Perform client-side authentication protocol exchange
 * Returns SASL_DONE if authentication can be complete after
 * sending our client reply.
 */
static int krb_client_auth(state, inputlen, input, outputlen, output)
void *state;			/* State of exchange */
int inputlen;			/* Length of server response */
char *input;			/* Server response data */
int *outputlen;			/* Set to length of client reply */
char **output;			/* Set to point to client reply data */
{
    static KTEXT_ST authent;
    struct krb_state *kstate = (struct krb_state *)state;
    char tmp[4];
    int code;
    int maxbufsize;

    switch (kstate->authstepno++) {
    case 0:
	/* Server gave us challenge, respond with ticket+authenticator */
	if (inputlen < 4) {
	    kstate->authstepno = -1;
	    return SASL_FAIL;
	}
	memcpy(tmp, input, 4);
	kstate->challenge = ntohl(*(int *)tmp);

	code = krb_mk_req(&authent, kstate->service, kstate->instance,
			  kstate->realm, kstate->challenge);
	if (code) {
	    kstate->authstepno = -1;
	    return SASL_FAIL;
	}
	*outputlen = authent.length;
	*output = authent.dat;
	return 0;

    case 1:
	/*
	 * Server gave us mutual auth reply+available protection mechanisms.
	 * Respond with challenge, desired protection mechanism, userid
	 */
	if (inputlen < 8) {
	    kstate->authstepno = -1;
	    return SASL_FAIL;
	}
	des_ecb_encrypt(input, input, kstate->schedule, 0);
	memcpy(tmp, input, 4);
	if (ntohl(*(int *)tmp) != kstate->challenge + 1) {
	    /* Server failed to mutually authenticte */
	    kstate->authstepno = -1;
	    return SASL_FAIL;
	}	    
	memcpy(tmp, input+4, 4);
	maxbufsize = ntohl(*(int *)tmp) & 0xfffff;
	kstate->protallowed &= input[4];
	if (maxbufsize <= PROTECTION_OVERHEAD) {
	    /* Protection buffer too small */
	    kstate->protallowed &= SASL_PROT_NONE;
	}
#ifndef NOPRIVACY
	if (kstate->protallowed & SASL_PROT_PRIVACY) {
	    kstate->protallowed = SASL_PROT_PRIVACY;
	}
	else
#endif
	if (kstate->protallowed & SASL_PROT_INTEGRITY) {
	    kstate->protallowed = SASL_PROT_INTEGRITY;
	}
	else if (kstate->protallowed & SASL_PROT_NONE) {
	    kstate->protallowed = SASL_PROT_NONE;
	}
	else {
	    /* No mutually agreeable protection mechanism */
	    kstate->authstepno = -1;
	    return SASL_FAIL;
	}

	*(int *)authent.dat = htonl(kstate->challenge);
	*(int *)(authent.dat+4) = htonl(kstate->maxbufsize);
	authent.dat[4] = kstate->protallowed;
	strcpy(&authent.dat[8], kstate->user);
	authent.length = 8+strlen(kstate->user);
	do {
	    authent.dat[authent.length++] = '\0';
	} while (authent.length & 7);
	des_pcbc_encrypt(authent.dat, authent.dat, authent.length,
			 kstate->schedule, kstate->session, 1);
	*output = authent.dat;
	*outputlen = authent.length;
	if (maxbufsize < kstate->maxbufsize) kstate->maxbufsize = maxbufsize;
	return SASL_DONE;

    default:
	kstate->authstepno = -1;
	return SASL_FAIL;
    }
}

/*
 * Acquire daemon client credentials for 'service'.  Places lifetime
 * of credentials in seconds in the buffer pointed to by 'lifetime'
 * Returns error message on failure, NULL on success.
 */
static const char *
krb_new_cred(service, lifetime)
const char *service;
time_t *lifetime;
{
    static int inited = 0;
    char hostname[MAXHOSTNAMELEN+1];
    char instance[MAXHOSTNAMELEN+1];
    char realm[REALM_SZ];
    char tktstring[256];
    int r;
    CREDENTIALS cr;

    if (!inited++) {
	sprintf(tktstring, "/tmp/tkt_pid_%d", getpid());
	krb_set_tkt_string(tktstring);
    }

    if (krb_get_lrealm(realm,1) != KSUCCESS) {
	return "cannot get local Kerberos realm";
    }

    gethostname(hostname, sizeof(hostname));
    strcpy(instance, krb_get_phost(hostname));

    r = krb_get_svc_in_tkt(service, instance, realm, "krbtgt", realm, 127,
			   krb_srvtab);

    if (!r) {
	r = krb_get_cred("krbtgt", realm, realm, &cr);
	if (!r) *lifetime = cr.lifetime*5*60;
	memset((char *)&cr, 0, sizeof(cr));
    }

    if (r) return krb_err_txt[r];
    return 0;
}
    
static void
krb_free_cred()
{
    dest_tkt();
}

/* Exported definition of client-side authentication mechanism */
struct sasl_client krb_sasl_client = {
    "KERBEROS_V4",
    0,
    krb_client_start,
    krb_client_auth,
    krb_query_state,
    krb_free_state,
    krb_new_cred,
    krb_free_cred,
    0,
};


