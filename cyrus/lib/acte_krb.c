/* acte_krb.c -- KERBEROS_V4 authentication routines for IMAP.
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

#include "acte.h"

extern char *malloc();

extern char *lcase P((char *str));
extern char *krb_get_phost P((char *)), *krb_realmofhost P((char *));

static char *srvtab = "";	/* Srvtab filename */

/* Maximum number of bytes of overhead the protection mechanisms use */
#define PROTECTION_OVERHEAD 31

/* Private state used by this mechanism */
struct krb_state {
    /* common */
    char service[MAX_K_NAME_SZ+1];
    int authstepno;
    des_cblock session;	/* Our session key */
    des_key_schedule schedule; /* Schedule for our session key */
    long challenge;
    char user[MAX_K_NAME_SZ+1];
    int protallowed;
    int maxbufsize;
    struct sockaddr_in localaddr, remoteaddr;
    long prot_time_sec;
    char prot_time_5ms;
    /* client */
    char instance[INST_SZ];
    char realm[REALM_SZ];
    /* server */
    int (*authproc)();
    AUTH_DAT kdata;
};

/*
 * Free the space used by an opaque state pointer
 */
static void
krb_free_state(state)
void *state;
{
    memset((char *)state, 0, sizeof(struct krb_state));
    free((char *) state);
}

static acte_encodefunc_t krb_en_integrity;
static acte_decodefunc_t krb_de_integrity;
#ifndef NOPRIVACY
static acte_encodefunc_t krb_en_privacy;
static acte_decodefunc_t krb_de_privacy;
#endif

/*
 * Query public values of the state pointer after authentiation
 * complete.  Fills in buffers pointed to by the following arguments:
 *
 * user       -- IMAP userid authenticated as
 * protlevel  -- bitmask for selected protection mechanism
 * encodefunc -- if nonzero, protection mechanism function to encode
 *               outgoing data with.
 * decodefunc -- if nonzero, protection mechanism function to decode
 *               incoming data with.
 * maxplain   -- The maximum number of bytes that may be encoded by
 *                the encodefunc at one time
 */
static void 
krb_query_state(state, user, protlevel, encodefunc, decodefunc, maxplain)
void *state;
char **user;
int *protlevel;
acte_encodefunc_t **encodefunc;
acte_decodefunc_t **decodefunc;
int *maxplain;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *user = kstate->user;
    *protlevel = kstate->protallowed;

    switch (kstate->protallowed) {
    case ACTE_PROT_NONE:
	*encodefunc = 0;
	*decodefunc = 0;
	*maxplain = 0;
	return;

    case ACTE_PROT_INTEGRITY:
	*encodefunc = krb_en_integrity;
	*decodefunc = krb_de_integrity;
	*maxplain = kstate->maxbufsize - PROTECTION_OVERHEAD;
	return;

#ifndef NOPRIVACY
    case ACTE_PROT_PRIVACY:
	*encodefunc = krb_en_privacy;
	*decodefunc = krb_de_privacy;
	*maxplain = kstate->maxbufsize - PROTECTION_OVERHEAD;
	return;
#endif

    default:
	abort();
    }
}

/*
 * Get the cacheid for 'state'
 */
static char *
krb_get_cacheid(state)
void *state;
{
    char *cacheid;

    struct krb_state *kstate = (struct krb_state *)state;

    cacheid = malloc(16);
    if (!cacheid) return 0;

    memset(cacheid, 0, sizeof(cacheid));
    memcpy(cacheid, kstate->session, sizeof(kstate->session));
    return cacheid;
}

/*
 * Start the client side of an authentication exchange.
 */
static int krb_client_start(service, host, user, protallowed, maxbufsize,
			    localaddr, remoteaddr, state)
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

    protallowed &= ACTE_PROT_NONE|ACTE_PROT_INTEGRITY
#ifndef NOPRIVACY
	|ACTE_PROT_PRIVACY
#endif
	;
    if (!localaddr || !remoteaddr) {
	protallowed &= ACTE_PROT_NONE;
    }
    if (!protallowed) {
	return ACTE_FAIL;
    }
    if (maxbufsize > 0xffffff) maxbufsize = 0xffffff;

    /* Canonicalize hostname */
    host_name = gethostbyname(host);
    if (!host_name) {
	return ACTE_FAIL;
    }

    strncpy(instance, host_name->h_name, sizeof(instance)-1);
    instance[sizeof(instance)-1] = '\0';
    if (p = strchr(instance, '.')) *p = '\0';

    strcpy(realm, krb_realmofhost(host_name->h_name));

    /* Fetch imap.hostname service key */
    (void) krb_mk_req(&authent, service, instance, realm, 0);
    memset(&authent, 0, sizeof(authent));

    if (krb_get_cred(service, instance, realm, &cr)) {
	return ACTE_FAIL;
    }
    
    if (!user || !user[0]) {
	if (krb_get_tf_fullname(TKT_FILE, userbuf, uinst, urealm)) {
	    memset(&cr, 0, sizeof(cr));
	    return ACTE_FAIL;
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
	return ACTE_FAIL;
    }

    kstate = (struct krb_state *)malloc(sizeof(struct krb_state));
    if (!kstate) return ACTE_FAIL;
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
 * Returns ACTE_DONE if authentication can be complete after
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
	    return ACTE_FAIL;
	}
	memcpy(tmp, input, 4);
	kstate->challenge = ntohl(*(int *)tmp);

	code = krb_mk_req(&authent, kstate->service, kstate->instance,
			  kstate->realm, kstate->challenge);
	if (code) {
	    kstate->authstepno = -1;
	    return ACTE_FAIL;
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
	    return ACTE_FAIL;
	}
	des_ecb_encrypt(input, input, kstate->schedule, 0);
	memcpy(tmp, input, 4);
	if (ntohl(*(int *)tmp) != kstate->challenge + 1) {
	    /* Server failed to mutually authenticte */
	    kstate->authstepno = -1;
	    return ACTE_FAIL;
	}	    
	memcpy(tmp, input+4, 4);
	maxbufsize = ntohl(*(int *)tmp) & 0xfffff;
	kstate->protallowed &= input[4];
	if (maxbufsize <= PROTECTION_OVERHEAD) {
	    /* Protection buffer too small */
	    kstate->protallowed &= ACTE_PROT_NONE;
	}
#ifndef NOPRIVACY
	if (kstate->protallowed & ACTE_PROT_PRIVACY) {
	    kstate->protallowed = ACTE_PROT_PRIVACY;
	}
	else
#endif
	if (kstate->protallowed & ACTE_PROT_INTEGRITY) {
	    kstate->protallowed = ACTE_PROT_INTEGRITY;
	}
	else if (kstate->protallowed & ACTE_PROT_NONE) {
	    kstate->protallowed = ACTE_PROT_NONE;
	}
	else {
	    /* No mutually agreeable protection mechanism */
	    kstate->authstepno = -1;
	    return ACTE_FAIL;
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
	return ACTE_DONE;

    default:
	kstate->authstepno = -1;
	return ACTE_FAIL;
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
		       srvtab);

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
struct acte_client krb_acte_client = {
    "KERBEROS_V4",
    krb_client_start,
    krb_client_auth,
    krb_query_state,
    krb_free_state,
    krb_new_cred,
    krb_free_cred,
};

/*
 * Start the server side of an authentication exchange
 */
static int
krb_server_start(service, authproc, protallowed, maxbufsize,
		 localaddr, remoteaddr, outputlen, output, state, reply)
const char *service;
acte_authproc_t *authproc;	/* (optional) function to decide
				 * authoriztion to log in as given user
				 */
int protallowed;		/* Protection mechanisms allowed */
int maxbufsize;			/* Maximum ciphertext input buffer size */
struct sockaddr *localaddr;	/* Network address of local side */
struct sockaddr *remoteaddr;	/* Network address of remote side */
int *outputlen;			/* Set to length of initial reply */
char **output;			/* Set to point to initial reply data */
void **state;			/* On success, filled in with state ptr */
const char **reply;		/* On failure, filled in with ptr to reason */
{
    static char outputbuf[4];
    struct krb_state *kstate;

    protallowed &= ACTE_PROT_NONE|ACTE_PROT_INTEGRITY
#ifndef NOPRIVACY
	|ACTE_PROT_PRIVACY
#endif
	;
    if (!localaddr || !remoteaddr) {
	protallowed &= ACTE_PROT_NONE;
    }
    if (!protallowed) {
	*reply = "No suitable protection mechanism";
	return ACTE_FAIL;
    }
    if (maxbufsize > 0xffffff) maxbufsize = 0xffffff;

    kstate = (struct krb_state *)malloc(sizeof(struct krb_state));
    if (!kstate) {
	*reply = "Out of memory";
	return ACTE_FAIL;
    }
    memset((char *)kstate, 0, sizeof(*kstate));
    strcpy(kstate->service, service);
    kstate->authstepno = 0;
    kstate->challenge = time(0) ^ getpid();
    kstate->protallowed = protallowed;
    kstate->maxbufsize = maxbufsize;
    if (localaddr && remoteaddr) {
	kstate->localaddr = *(struct sockaddr_in *)localaddr;
	kstate->remoteaddr = *(struct sockaddr_in *)remoteaddr;
    }
    kstate->authproc = authproc;

    *(int *)outputbuf = htonl(kstate->challenge);
    *output = outputbuf;
    *outputlen = 4;
    *state = (void *)kstate;
    
    return 0;
}

/*
 * Perform server-side authentication protocol exchange.
 * Returns 0 to continue exchange, ACTE_FAIL on failure, and ACTE_DONE
 * if user is now successfully authenticated
 */
static int krb_server_auth(state, inputlen, input, outputlen, output, reply)
void *state;			/* State of exchange */
int inputlen;			/* Length of client response */
char *input;			/* Client response data */
int *outputlen;			/* Set to length of server reply */
char **output;			/* Set to point to server reply data */
const char ** reply;		/* On failure, filled in with ptr to reason */
{
    struct krb_state *kstate = (struct krb_state *)state;
    static char outputbuf[8];
    KTEXT_ST authent;
    int code;
    char tmp[4];
    char instance[INST_SZ];
    char realm[REALM_SZ];
    int protallowed;
    int maxbufsize;
    char clientname[MAX_K_NAME_SZ+1];

    switch (kstate->authstepno++) {
    case 0:
	/*
	 * Client gave us ticket+authenticator
	 * reply with mutual auth + supported protection mechanisms
	 */
	if (inputlen > MAX_KTXT_LEN) {
	    kstate->authstepno = -1;
	    *reply = "Kerberos authenticator too long";
	    return ACTE_FAIL;
	}
	authent.length = inputlen;
	memcpy(authent.dat, input, inputlen);
	authent.mbz = 0;
	strcpy(instance, "*");
	code = krb_rd_req(&authent, kstate->service, instance, 0L,
			  &kstate->kdata, srvtab);
	if (code) {
	    kstate->authstepno = -1;
	    *reply = krb_err_txt[code];
	    return ACTE_FAIL;
	}
	if (kstate->kdata.checksum != kstate->challenge) {
	    kstate->authstepno = -1;
	    *reply = "Incorrect checksum in Kerberos authenticator";
	    return ACTE_FAIL;
	}
	memcpy(kstate->session, kstate->kdata.session, sizeof(des_cblock));
	des_key_sched(kstate->session, kstate->schedule);
	
	*(int *)outputbuf = htonl(kstate->challenge+1);
	*(int *)(outputbuf+4) = htonl(kstate->maxbufsize);
	outputbuf[4] = kstate->protallowed;
	des_ecb_encrypt(outputbuf, outputbuf, kstate->schedule, 1);
	*output = outputbuf;
	*outputlen = 8;

	return 0;

    case 1:
	/* Client gave us selected protection mechanism + userid, we're done */
	if (inputlen < 16 || inputlen & 7) {
	    kstate->authstepno = -1;
	    *reply = "Kerberos authenticator has incorrect length";
	    return ACTE_FAIL;
	}
	des_pcbc_encrypt(input, input, inputlen,
			 kstate->schedule, kstate->session, 0);
	memcpy(tmp, input, 4);
	if (ntohl(*(int *)tmp) != kstate->challenge) {
	    kstate->authstepno = -1;
	    *reply = "Incorrect checksum in Kerberos authenticator";
	    return ACTE_FAIL;
	}
	memcpy(tmp, input+4, 4);
	maxbufsize = ntohl(*(int *)tmp) & 0xfffff;
	if (maxbufsize < kstate->maxbufsize) kstate->maxbufsize = maxbufsize;
	protallowed = input[4];
	if (!(protallowed & kstate->protallowed)) {
	    kstate->authstepno = -1;
	    *reply = "No suitable protection mechanism selected";
	    return ACTE_FAIL;
	}
	if (
#ifndef NOPRIVACY
	    protallowed != ACTE_PROT_PRIVACY &&
#endif
	    protallowed != ACTE_PROT_INTEGRITY &&
	    protallowed != ACTE_PROT_NONE) {
	    kstate->authstepno = -1;
	    *reply = "Multiple protection mechanisms selected";
	    return ACTE_FAIL;
	}
	if (protallowed != ACTE_PROT_NONE &&
	    kstate->maxbufsize <= PROTECTION_OVERHEAD) {
	    /* Protection buffer too small */
	    kstate->authstepno = -1;
	    *reply = "Protection buffer size too small";
	    return ACTE_FAIL;
	}
	kstate->protallowed = protallowed;

	if (input[inputlen-1] != '\0') {
	    *reply = "User name not nul-terminated";
	    return ACTE_FAIL;
	}
	strcpy(kstate->user, input+8);

	/* Check kerberos identity can log in as user */
	if (krb_get_lrealm(realm,1)) {
	    *reply = "Can't find local Kerberos realm";
	    return ACTE_FAIL;
	}
	if (kstate->authproc) {
	    strcpy(clientname, kstate->kdata.pname);
	    if (kstate->kdata.pinst[0]) {
		strcat(clientname, ".");
		strcat(clientname, kstate->kdata.pinst);
	    }
	    if (kstate->kdata.prealm[0]) {
		strcat(clientname, "@");
		strcat(clientname, kstate->kdata.prealm);
	    }
	    if (kstate->authproc(kstate->user, clientname, reply) != 0) {
		return ACTE_FAIL;
	    }
	}
	else {
	    if (strcmp(kstate->kdata.pname, kstate->user) != 0 ||
		kstate->kdata.pinst[0] ||
		strcmp(kstate->kdata.prealm, realm) != 0) {
		*reply = "Kerberos ID does not match user name";
		return ACTE_FAIL;
	    }
	}

	return ACTE_DONE;

    default:
	*reply = "Internal error: invalid state in krb_server_auth";
	return ACTE_FAIL;
    }
}

/* Exported definition of server-side authentication mechanism */
struct acte_server krb_acte_server = {
    "KERBEROS_V4",
    krb_server_start,
    krb_server_auth,
    krb_query_state,
    krb_free_state,
    krb_get_cacheid,
};

/*
 * Apply integrity protection to the 'inputlen' bytes of data at 'input',
 * using the state in 'state', placing the output data and length in the
 * buffers pointed to by 'output' and 'outputlen' respectively.
 */
static const char *
krb_en_integrity(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char *output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *outputlen = krb_mk_safe(input, output, inputlen, kstate->session,
			     &kstate->localaddr, &kstate->remoteaddr);
    return 0;
}

/*
 * Decode integrity protection on the 'inputlen' bytes of data at
 * 'input', using the state in 'state', placing a pointer to the
 * output data and length in the buffers pointed to by 'output' and
 * 'outputlen' respectively.
 */
static const char *
krb_de_integrity(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char **output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;
    int code;
    MSG_DAT m_data;

    code = krb_rd_safe(input, inputlen, kstate->session,
		       &kstate->remoteaddr, &kstate->localaddr, &m_data);
    if (code) return krb_err_txt[code];
    if (m_data.time_sec < kstate->prot_time_sec ||
	(m_data.time_sec == kstate->prot_time_sec &&
	 m_data.time_5ms < kstate->prot_time_5ms)) {
	return krb_err_txt[RD_AP_TIME];
    }
    kstate->prot_time_sec = m_data.time_sec;
    kstate->prot_time_5ms = m_data.time_5ms;

    *output = m_data.app_data;
    *outputlen = m_data.app_length;
    return 0;
}

#ifndef NOPRIVACY
/*
 * Apply privacy protection to the 'inputlen' bytes of data at 'input',
 * using the state in 'state', placing the output data and length in the
 * buffers pointed to by 'output' and 'outputlen' respectively.
 */
static const char *
krb_en_privacy(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char *output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *outputlen = krb_mk_priv(input, output, inputlen, kstate->schedule,
			     kstate->session, &kstate->localaddr,
			     &kstate->remoteaddr);
    return 0;
}

/*
 * Decode privacy protection on the 'inputlen' bytes of data at
 * 'input', using the state in 'state', placing a pointer to the
 * output data and length in the buffers pointed to by 'output' and
 * 'outputlen' respectively.
 */
static const char *
krb_de_privacy(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char **output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;
    int code;
    MSG_DAT m_data;

    code = krb_rd_priv(input, inputlen, kstate->schedule, kstate->session,
		       &kstate->remoteaddr, &kstate->localaddr, &m_data);
    if (code) return krb_err_txt[code];
    if (m_data.time_sec < kstate->prot_time_sec ||
	(m_data.time_sec == kstate->prot_time_sec &&
	 m_data.time_5ms < kstate->prot_time_5ms)) {
	return krb_err_txt[RD_AP_TIME];
    }
    kstate->prot_time_sec = m_data.time_sec;
    kstate->prot_time_5ms = m_data.time_5ms;

    *output = m_data.app_data;
    *outputlen = m_data.app_length;
    return 0;
}
#endif /* !NOPRIVACY */

static afs_string_to_key P((char *str, des_cblock *key, char *cell));

/*
 * Kerberos set srvtab filename
 * Accepts: name of srvtab file to use in reading authenticators
 */
int kerberos_set_srvtab(fname)
char *fname;
{
    srvtab = fname;
    return 0;
}

/*
 * Kerberos get srvtab filename
 * Returns: name of srvtab file to use in reading authenticators
 */
char *kerberos_get_srvtab()
{
    return srvtab;
}

static use_key(user, instance, realm, key, returned_key)
char *user;
char *instance;
char *realm;
des_cblock key;
des_cblock returned_key;
{
    memcpy (returned_key, key, sizeof(des_cblock));
    return 0;
}

/*
 * Securely verify the plaintext password 'passwd' for user 'user'
 * against the Kerberos database.  "service" is the name of a service
 * we can verify the returned ticket against.  Returns 1 for success,
 * 0 for failure.  On failure, 'reply' is filled in with a pointer to
 * the reason.
 */
int kerberos_verify_password(user, passwd, service, reply)
char *user;
char *passwd;
char *service;
const char **reply;
{
    int result;
    des_cblock key;
    char tfname[40];
    char realm[REALM_SZ];
    char cell[REALM_SZ];
    char hostname[MAXHOSTNAMELEN+1];
    char phost[MAXHOSTNAMELEN+1];
    KTEXT_ST authent;
    char instance[INST_SZ];
    AUTH_DAT kdata;

    if (krb_get_lrealm(realm,1)) return 0;

    sprintf(tfname, "/tmp/tkt_imapd_%d", getpid());
    krb_set_tkt_string(tfname);

    /* First try Kerberos string-to-key */
    des_string_to_key(passwd, key);
    
    result = krb_get_in_tkt(user, "", realm,
			    "krbtgt", realm, 1, use_key, NULL, key);

    if (result == INTK_BADPW) {
	/* Now try andrew string-to-key */
	strcpy(cell, realm);
	lcase(cell);
	afs_string_to_key(passwd, &key, cell);
    
	result = krb_get_in_tkt(user, "", realm,
				"krbtgt", realm, 1, use_key, NULL, key);
    }

    memset(key, 0, sizeof(key));

    if (result != 0) {
	dest_tkt();
	*reply = krb_err_txt[result];
	return 0;
    }

    /* Check validity of returned ticket */
    gethostname(hostname, sizeof(hostname));
    strcpy(phost, krb_get_phost(hostname));
    result = krb_mk_req(&authent, service, phost, realm, 0);
    if (result != 0) {
	memset(&authent, 0, sizeof(authent));
	dest_tkt();
	*reply = krb_err_txt[result];
	return 0;
    }
    strcpy(instance, "*");
    result = krb_rd_req(&authent, service, instance, 0L, &kdata, srvtab);
    memset(&authent, 0, sizeof(authent));
    memset(kdata.session, 0, sizeof(kdata.session));
    if (result != 0 || strcmp(kdata.pname, user) != 0 || kdata.pinst[0] ||
	strcmp(kdata.prealm, realm) != 0) {
	if (result != 0) {
	    *reply = krb_err_txt[result];
	}
	else {
	    *reply = "Kerberos ID does not match user name";
	}
	result = 0;
    }
    else result = 1;

    dest_tkt();
    return result;
}

/* andrewstk.c -- afs string to key function
 *
 * Code taken from AuthMan from University of Michigan
 */

/* forward declarations */
static afs_transarc_StringToKey P((char *str, char *cell, des_cblock *key));
static afs_cmu_StringToKey P((char *str, char *cell, des_cblock *key));

extern char *crypt();

/* This defines the Andrew string_to_key function.  It accepts a password
 * string as input and converts its via a one-way encryption algorithm to a DES
 * encryption key.  It is compatible with the original Andrew authentication
 * service password database.
 */

static
afs_cmu_StringToKey (str, cell, key)
char *str;
char *cell;                  /* cell for password */
des_cblock *key;
{   char  password[8+1];                /* crypt is limited to 8 chars anyway */
    int   i;
    int   passlen;

    memset(key, 0, sizeof(des_cblock));
    memset((void *)password, 0, sizeof(password));

    strncpy (password, cell, 8);
    passlen = strlen (str);
    if (passlen > 8) passlen = 8;

    for (i=0; i<passlen; i++)
        password[i] = str[i] ^ cell[i];

    for (i=0;i<8;i++)
        if (password[i] == '\0') password[i] = 'X';

    /* crypt only considers the first 8 characters of password but for some
       reason returns eleven characters of result (plus the two salt chars). */
    strncpy((void *)key, crypt(password, "p1") + 2, sizeof(des_cblock));

    /* parity is inserted into the LSB so leftshift each byte up one bit.  This
       allows ascii characters with a zero MSB to retain as much significance
       as possible. */
    {   char *keybytes = (char *)key;
        unsigned int temp;

        for (i = 0; i < 8; i++) {
            temp = (unsigned int) keybytes[i];
            keybytes[i] = (unsigned char) (temp << 1);
        }
    }
    des_fixup_key_parity (key);
}

static
afs_transarc_StringToKey (str, cell, key)
char *str;
char *cell;                  /* cell for password */
des_cblock *key;
{   des_key_schedule schedule;
    char temp_key[8];
    char ivec[8];
    char password[BUFSIZ];
    int  passlen;

    strncpy (password, str, sizeof(password));
    if ((passlen = strlen (password)) < sizeof(password)-1)
        strncat (password, cell, sizeof(password)-passlen);
    if ((passlen = strlen(password)) > sizeof(password)) passlen = sizeof(password);

    memcpy (ivec, "kerberos", 8);
    memcpy (temp_key, "kerberos", 8);
    des_fixup_key_parity ((void *)temp_key);
    des_key_sched (temp_key, schedule);
    des_cbc_cksum (password, ivec, passlen, schedule, ivec);

    memcpy (temp_key, ivec, 8);
    des_fixup_key_parity ((void *)temp_key);
    des_key_sched (temp_key, schedule);
    des_cbc_cksum (password, (void *)key, passlen, schedule, ivec);

    des_fixup_key_parity (key);
}

static afs_string_to_key(str, key, cell)
char *str;
des_cblock *key;
char *cell;                  /* cell for password */
{
    if (strlen(str) > 8) {
	afs_transarc_StringToKey (str, cell, key);
    }
    else {
	afs_cmu_StringToKey (str, cell, key);
    }
}

