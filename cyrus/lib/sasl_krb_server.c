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
 * Start the server side of an authentication exchange
 */
static int
krb_server_start(rock, service, authproc, protallowed, maxbufsize,
		 localaddr, remoteaddr, outputlen, output, state, reply)
void *rock;			/* Ignored */
const char *service;
sasl_authproc_t *authproc;	/* (optional) function to decide
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
    static union { char buf[4]; int num; } outputbuf;
    /* static char outputbuf[4]; */
    struct krb_state *kstate;

    protallowed &= SASL_PROT_NONE|SASL_PROT_INTEGRITY
#ifndef NOPRIVACY
	|SASL_PROT_PRIVACY
#endif
	;
    if (!localaddr || !remoteaddr) {
	protallowed &= SASL_PROT_NONE;
    }
    if (!protallowed) {
	*reply = "No suitable protection mechanism";
	return SASL_FAIL;
    }
    if (maxbufsize > 0xffffff) maxbufsize = 0xffffff;

    kstate = (struct krb_state *)malloc(sizeof(struct krb_state));
    if (!kstate) {
	*reply = "Out of memory";
	return SASL_FAIL;
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

    /* this has a bug */
    /* *(int *)outputbuf.num = htonl(kstate->challenge); */
    /* *output = outputbuf.buf; */
    outputbuf.num = htonl(kstate->challenge);
    *output = outputbuf.buf;
    *outputlen = 4;
    *state = (void *)kstate;
    
    return 0;
}

/*
 * Perform server-side authentication protocol exchange.
 * Returns 0 to continue exchange, SASL_FAIL on failure, and SASL_DONE
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
	    return SASL_FAIL;
	}
	authent.length = inputlen;
	memcpy(authent.dat, input, inputlen);
	authent.mbz = 0;
	strcpy(instance, "*");
	code = krb_rd_req(&authent, kstate->service, instance, 0L,
			  &kstate->kdata, krb_srvtab);
	if (code) {
	    kstate->authstepno = -1;
	    *reply = krb_err_txt[code];
	    return SASL_FAIL;
	}
	if (kstate->kdata.checksum != kstate->challenge) {
	    kstate->authstepno = -1;
	    *reply = "Incorrect checksum in Kerberos authenticator";
	    return SASL_FAIL;
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
	    return SASL_FAIL;
	}
	des_pcbc_encrypt(input, input, inputlen,
			 kstate->schedule, kstate->session, 0);
	memcpy(tmp, input, 4);
	if (ntohl(*(int *)tmp) != kstate->challenge) {
	    kstate->authstepno = -1;
	    *reply = "Incorrect checksum in Kerberos authenticator";
	    return SASL_FAIL;
	}
	memcpy(tmp, input+4, 4);
	maxbufsize = ntohl(*(int *)tmp) & 0xfffff;
	if (maxbufsize < kstate->maxbufsize) kstate->maxbufsize = maxbufsize;
	protallowed = input[4];
	if (!(protallowed & kstate->protallowed)) {
	    kstate->authstepno = -1;
	    *reply = "No suitable protection mechanism selected";
	    return SASL_FAIL;
	}
	if (
#ifndef NOPRIVACY
	    protallowed != SASL_PROT_PRIVACY &&
#endif
	    protallowed != SASL_PROT_INTEGRITY &&
	    protallowed != SASL_PROT_NONE) {
	    kstate->authstepno = -1;
	    *reply = "Multiple protection mechanisms selected";
	    return SASL_FAIL;
	}
	if (protallowed != SASL_PROT_NONE &&
	    kstate->maxbufsize <= PROTECTION_OVERHEAD) {
	    /* Protection buffer too small */
	    kstate->authstepno = -1;
	    *reply = "Protection buffer size too small";
	    return SASL_FAIL;
	}
	kstate->protallowed = protallowed;

	if (input[inputlen-1] != '\0') {
	    *reply = "User name not nul-terminated";
	    return SASL_FAIL;
	}
	strcpy(kstate->user, input+8);

	/* Check kerberos identity can log in as user */
	if (krb_get_lrealm(realm,1)) {
	    *reply = "Can't find local Kerberos realm";
	    return SASL_FAIL;
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
		return SASL_FAIL;
	    }
	}
	else {
	    if (strcmp(kstate->kdata.pname, kstate->user) != 0 ||
		kstate->kdata.pinst[0] ||
		strcmp(kstate->kdata.prealm, realm) != 0) {
		*reply = "Kerberos ID does not match user name";
		return SASL_FAIL;
	    }
	}

	return SASL_DONE;

    default:
	*reply = "Internal error: invalid state in krb_server_auth";
	return SASL_FAIL;
    }
}

/* Exported definition of server-side authentication mechanism */
struct sasl_server krb_sasl_server = {
    "KERBEROS_V4",
    krb_server_start,
    krb_server_auth,
    krb_query_state,
    krb_free_state,
    krb_get_cacheid,
    0,
};

static krb_afs_string_to_key P((char *str, des_cblock key, char *cell));

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
	krb_afs_string_to_key(passwd, key, cell);
    
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
    result = krb_rd_req(&authent, service, instance, 0L, &kdata, krb_srvtab);
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
static afs_transarc_StringToKey P((char *str, char *cell, des_cblock key));
static afs_cmu_StringToKey P((char *str, char *cell, des_cblock key));

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
des_cblock key;
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
des_cblock key;
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

static krb_afs_string_to_key(str, key, cell)
char *str;
des_cblock key;
char *cell;                  /* cell for password */
{
    if (strlen(str) > 8) {
	afs_transarc_StringToKey (str, cell, key);
    }
    else {
	afs_cmu_StringToKey (str, cell, key);
    }
}

