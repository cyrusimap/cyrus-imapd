/* acte_krb.c -- KERBEROS_V4 authentication routines for IMAP.
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
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
extern char *lcase();
extern char *krb_get_phost(), *krb_realmofhost();

static char *srvtab = "";	/* Srvtab filename */

/* Maximum number of bytes of overhead the protection mechanisms use */
#define PROTECTION_OVERHEAD 31

/* XXX Left to do:
 * "hard" vs "soft" errors
 */ 

struct krb_state {
    /* common */
    int authstepno;
    des_cblock session;	/* Our session key */
    des_key_schedule schedule; /* Schedule for our session key */
    long challenge;
    int protallowed;
    int maxbufsize;
    struct sockaddr_in sender, receiver;
    long prot_time_sec;
    char prot_time_5ms
    /* client */
    char instance[INST_SZ];
    char ream[REALM_SZ];
    /* server */
    int (*authproc)();
    AUTH_DAT kdata;
};

static void krb_free_state(state)
void *state;
{
    memset((char *)state, 0, sizeof(struct krb_state));
    free((char *) state);
}

static int krb_en_integrity(), krb_de_integrity();
static int krb_en_privacy(), krb_de_privacy();

static void krb_query_state(state, completed, encodefunc, decodefunc, maxplain)
void *state;
int completed;
int (**encodefunc)();
int (**decodefunc)();
int *maxplain;
{
    struct krb_state *kstate = (struct krb_state *)state;

    if (kstate->authstepno != 2) {
	*completed = 0;
	return;
    }
    *completed = 1;

    switch (kstate->protallowed) {
    case PROT_NONE:
	*encodefunc = *decodefunc = 0;
	*maxplain = 0;
	return;

    case PROT_INTEGRITY:
	*encodefunc = krb_en_integrity;
	*decodefunc = krb_de_integrity;
	*maxplain = kstate->maxbufsize - PROTECTION_OVERHEAD;
	return;

    case PROT_PRIVACY:
	*encodefunc = krb_en_privacy;
	*decodefunc = krb_de_privacy;
	*maxplain = kstate->maxbufsize - PROTECTION_OVERHEAD;
	return;

    default:
	abort();
    }
}

static int krb_client_start(host, user, protallowed, maxbufsize,
			    sender, receiver, state)
char *host;
char *user;
void **state;
int protallowed;
int maxbufsize;
struct sockaddr *sender;
struct sockaddr *receiver;
{
    struct hostent *host_name;
    char instance[INST_SZ];
    char realm[REALM_SZ];
    char uinst[INST_SZ];
    char urealm[INST_SZ];
    int code;
    int i;
    CREDENTIALS cr;
    struct krb_state *kstate;

    protallowed &= ACTE_PROT_NONE|ACTE_PROT_INTEGRITY|ACTE_PROT_PRIVACY;
    if (!protallowed) {
	return ACTE_FAIL_SOFT;
    }
    if (maxbufsize > 0xffffff) maxbufsize = 0xffffff;

    /* Canonicalize hostname */
    host_name = gethostbyname(host);
    if (!host_name) {
	return ACTE_FAIL_SOFT;
    }

    strcpy(realm, krb_realmofhost(host_name->h_name));
    strcpy(instance, krb_get_phost(host_name->h_name));

    if (code = krb_get_cred("imap", instance, realm, &cr)) {
	return ACTE_FAIL_SOFT;
    }
    
    if (!user[0]) {
	if (krb_get_tf_fullname(TKT_FILE, user, uinst, urealm)) {
	    memset(&cr, 0, sizeof(cr));
	    return ACTE_FAIL_SOFT;
	}
	if (uinst[0]) {
	    strcat(user, ".");
	    strcat(user, uinst);
	}
	if (strcmp(urealm, realm) != 0) {
	    strcat(user, "@");
	    strcat(user, urealm);
	}
    }

    kstate = (struct krb_state *)malloc(sizeof(struct krb_state));
    if (!kstate) return ACTE_FAIL_SOFT
    memset((char *)kstate, 0, sizeof(*kstate));
    kstate->authstepno = 0;
    memcpy(kstate->session, cr.session, sizeof(des_cblock));
    des_key_sched(kstate->session, kstate->schedule);
    kstate->protallowed = protallowed;
    kstate->maxbufsize = maxbufsize;
    kstate->sender = *(struct sockaddr_in *)sender;
    kstate->receiver = *(struct sockaddr_in *)receiver;
    strcpy(kstate->instance, instance);
    strcpy(kstate->realm, realm);

    memset(&cr, 0, sizeof(cr));
    *state = (void *)kstate;
    return 0;
}

static int krb_client_auth(state, inputlen, input, outputlen, output)
void *state;
int inputlen;
char *input;
int *outputlen;
char **output;
{
    static KTEXT_ST authent;
    struct krb_state *kstate = (struct krb_state *)state;
    int maxbufsize;

    switch (kstate->authstepno++) {
    case 0:
	if (inputlen < 4) {
	    kstate->authstepno = -1;
	    return ACTE_FAIL_SOFT;
	}
	kstate->challenge = ntohl(*(int *)input);

	code = krb_mk_req(&authent, "imap", instance, realm,
			  kstate->challenge);
	if (code) {
	    kstate->authstepno = -1;
	    return ACTE_FAIL_SOFT;
	}
	*outputlen = authent.length;
	*output = authent.dat;
	return 0;

    case 1:
	if (inputlen < 8) {
	    kstate->authstepno = -1;
	    return ACTE_FAIL_SOFT;
	}
	des_ecb_encrypt(input, input, kstate->schedule, 0);
	if (ntohl(*(int *)input) + 1 != kstate->challenge) {
	    /* Server failed to mutually authenticte */
	    kstate->authstepno = -1;
	    return ACTE_FAIL_HARD;
	}	    
	maxbufsize = ntohl(*(int *)(input+4)) & 0xfffff;
	kstate->protallowed &= input[4];
	if (maxbufsize <= PROTECTION_OVERHEAD) {
	    /* Protection buffer too small */
	    kstate->protallowed &= ACTE_PROT_NONE;
	}
	if (kstate->protallowed & ACTE_PROT_PRIVACY) {
	    kstate->protallowed = ACTE_PROT_PRIVACY;
	}
	else if (kstate->protallowed & ACTE_PROT_INTEGRITY) {
	    kstate->protallowed = ACTE_PROT_INTEGRITY;
	}
	else if (kstate->protallowed & ACTE_PROT_NONE) {
	    kstate->protallowed = ACTE_PROT_NONE;
	}
	else {
	    /* No mutually agreeable protection mechanism */
	    kstate->authstepno = -1;
	    return ACTE_FAIL_HARD;
	}

	*(int *)authent.dat = htonl(kstate->challenge);
	*(int *)(authent.dat+4) = htonl(kstate->maxbufsize);
	authent.dat[4] = kstate->protallowed;
	des_ecb_encrypt(authent.dat, authent.dat, kstate->schedule, 1);
	*output = authent.dat
	*outputlen = 8;
	kstate->maxbufsize = maxbufsize;
	return 0;

    default:
	kstate->authstepno = -1;
	return ACTE_FAIL_HARD;
    }
}

struct acte_client {
    "KERBEROS_V4",
    krb_client_start,
    krb_client_auth,
    krb_query_state,
    krb_free_state
} krb_acte_client;

static int
krb_server_start(user, authproc, protallowed, maxbufsize,
		 sender, receiver, outputlen, output, state, reply)
char *user;
int (*authproc)();
int protallowed;
int maxbufsize;
struct sockaddr *sender;
struct sockaddr *receiver;
int *outputlen;
char **output;
void **state;
char **reply;
{
    static char outputbuf[4];
    struct krb_state *kstate;

    protallowed &= ACTE_PROT_NONE|ACTE_PROT_INTEGRITY|ACTE_PROT_PRIVACY;
    if (!protallowed) {
	*reply = "No suitable protection mechanism";
	return ACTE_FAIL_SOFT;
    }
    if (maxbufsize > 0xffffff) maxbufsize = 0xffffff;

    kstate = (struct krb_state *)malloc(sizeof(struct krb_state));
    if (!kstate) {
	*reply = "Out of memory";
	return ACT_FAIL_SOFT;
    }
    memset((char *)kstate, 0, sizeof(*kstate));
    kstate->authstepno = 0;
    kstate->challenge = time(0) ^ getpid();
    kstate->protallowed = protallowed;
    kstate->maxbufsize = maxbufsize;
    kstate->sender = *(struct sockaddr_in *)sender;
    kstate->receiver = *(struct sockaddr_in *)receiver;

    *(int *)outputbuf = htonl(kstate->challenge);
    *output = outbutbuf;
    *outputlen = 4;
    *state = (void *)kstate;
    
    return 0;
}

static int krb_server_auth(state, inputlen, input, outputlen, output, reply)
void *state;
int inputlen;
char *input;
int *outputlen;
char **output;
char **reply
{
    struct krb_state *kstate = (struct krb_state *)state;
    static char outbutbuf[8];
    KTEXT_ST authent;
    int code;
    char instance[INST_SZ];
    char realm[REALM_SZ];
    int protallowed;
    char clientname[MAX_K_NAME_SZ+1];

    switch (kstate->authstepno++) {
    case 0:
	if (inputlen > MAX_KTXT_LEN) {
	    kstate->authstepno = -1;
	    *reply = "Kerberos authenticator too long";
	    return ACTE_FAIL_SOFT;
	}
	authent.length = inputlen;
	memcpy(authent.dat, input, inputlen);
	authent.mbz = 0;
	strcpy(instance, "*");
	code = krb_rd_req(&authent, "imap", instance, 0L, &kstate->kdata,
			  srvtab);
	if (code) {
	    kstate->authstepno = -1;
	    *reply = error_message(code);
	    return ACTE_FAIL_HARD;
	}
	if (kdata->checksum != kstate->challenge) {
	    kstate->authstepno = -1;
	    *reply = "Incorrect checksum in Kerberos authenticator";
	    return ACTE_FAIL_HARD;
	}
	memcpy(kstate->session, cr.session, sizeof(des_cblock));
	des_key_sched(kstate->session, kstate->schedule);
	
	/* Check kerberos identity can log in as user */
	if (krb_get_lrealm(realm,1)) {
	    *reply = "Can't find local Kerberos realm";
	    return ACTE_FAIL_SOFT;
	}
	if (kstate->authproc) {
	    strcpy(clientname, kstate->kdata->pname);
	    if (kstate->kdata->pinst[0]) {
		strcat(clientname, ".");
		strcat(clientname, kstate->kdata->pinst);
	    }
	    if (strcmp(kstate->kdata->prealm, realm) != 0) {
		strcat(clientname, "@");
		strcat(clientname, kstate->kdata->prealm);
	    }
	    if (!kstate->authproc(user, clientname)) {
		*reply = "Not authorized";
		return ACTE_FAIL_SOFT;
	    }
	}
	else {
	    if (strcmp(kstate->kdata->pname, user) != 0 ||
		kstate->kdata->pinst[0] ||
		strcmp(kstate->kdata->prealm, realm) != 0) {
		*reply = "Not authorized";
		return ACTE_FAIL_SOFT;
	    }
	}

	*(int *)outputbuf = htonl(challenge+1);
	*(int *)(outputbuf+4) = htonl(kstate->maxbufsize);
	outputbuf[4] = kstate->protallowed;
	des_ecb_encrypt(outputbuf, outputbuf, kstate->schedule, 1);
	*output = outputbuf;
	*outputlen = 8;

	return 0;

    case 1:
	if (inputlen < 8) {
	    kstate->authstepno = -1;
	    *reply = "Kerberos authenticator too short";
	    return ACTE_FAIL_HARD;
	}
	des_ecb_encrypt(input, input, kstate->schedule, 0);
	if (ntohl(*(int *)input) != kstate->challenge) {
	    kstate->authstepno = -1;
	    *reply = "Incorrect checksum in Kerberos authenticator";
	    return ACTE_FAIL_HARD;
	}
	kstate->maxbufsize = ntohl(*(int *)(input+4)) & 0xfffff;
	protallowed = input[4];
	if (!(protallowed & kstate->protallowed)) {
	    kstate->authstepno = -1;
	    *reply = "No suitable protection mechanism selected";
	    return ACTE_FAIL_HARD;
	}
	if (protallowed != ACTE_PROT_PRIVACY &&
	    protallowed != ACTE_PROT_INTEGRITY &&
	    protallowed != ACTE_PROT_NONE) {
	    kstate->authstepno = -1;
	    *reply = "Multiple protection mechanisms selected";
	    return ACTE_FAIL_HARD;
	}
	if (protallowed != ACTE_PROT_NONE &&
	    kstate->maxbufsize <= PROTECTION_OVERHEAD) {
	    /* Protection buffer too small */
	    kstate->authstepno = -1;
	    *reply = "Protection buffer size too small";
	    return ACTE_FAIL_HARD;
	}
	kstate->protallowed = protallowed;
	
	return ACTE_DONE;

    default:
	*reply = "Internal error: invalid state in krb_server_auth";
	return ACTE_FAIL_HARD;
    }
}

/* Server side stuff */
struct acte_server {
    "KERBEROS_V4",
    krb_server_start,
    krb_server_auth,
    krb_query_state,
    krb_free_state
} krb_acte_server;

static int krb_en_integrity(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char *output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *output = krb_mk_safe(input, output, inputlen, kstate->session,
			  &kstate->sender, &kstate->receiver);
    return 0;
}

static int krb_de_integrity(state, input, inputlen, output, outputlen)
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
		       kstate->sender, kstate->receiver, &m_data);
    if (code) return code;
    if (m_data.time_sec < kstate->prot_time_sec ||
	(m_data.time_sec == kstate->prot_time_sec &&
	 m_data.time_5ms < kstate->prot_time_5ms)) {
	return RD_AP_TIME;
    }
    kstate->prot_time_sec = mdata.time_sec;
    kstate->prot_time_5ms = mdata.time_5ms;

    *output = m_data.app_data;
    *outputlen = m_data.app_length;
    return 0;
}


static int krb_en_privacy(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char *output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *output = krb_mk_safe(input, output, inputlen, kstate->schedule,
			  kstate->session, &kstate->sender, &kstate->receiver);
    return 0;
}

static int krb_de_privacy(state, input, inputlen, output, outputlen)
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
		       kstate->sender, kstate->receiver, &m_data);
    if (code) return code;
    if (m_data.time_sec < kstate->prot_time_sec ||
	(m_data.time_sec == kstate->prot_time_sec &&
	 m_data.time_5ms < kstate->prot_time_5ms)) {
	return RD_AP_TIME;
    }
    kstate->prot_time_sec = mdata.time_sec;
    kstate->prot_time_5ms = mdata.time_5ms;

    *output = m_data.app_data;
    *outputlen = m_data.app_length;
    return 0;
}

static afs_string_to_key();

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

int kerberos_verify_password(user, passwd)
char *user;
char *passwd;
{
    int result;
    des_cblock key;
    char realm[REALM_SZ];
    char cell[REALM_SZ];
    char hostname[MAXHOSTNAMELEN+1];
    KTEXT_ST authent
    char instance[INST_SZ];
    char userbuf[ANAME_SZ];
    AUTH_DAT kdata;
    char *reply;

    if (krb_get_lrealm(realm,1)) return NIL;

    sprintf(passbuf, "/tmp/tkt_imapd_%d", getpid());
    krb_set_tkt_string(passbuf);

    /* First try Kerberos string-to-key */
    des_string_to_key(passwd, key);
    
    result = krb_get_in_tkt(user, "", realm,
			    "krbtgt", realm, 1, use_key, NULL, key);

    if (result == INTK_BADPW) {
	/* Now try andrew string-to-key */
	strcpy(cell, realm);
	lcase(cell);
	afs_string_to_key(passwd, key, cell);
    
	result = krb_get_in_tkt(user, "", realm,
				"krbtgt", realm, 1, use_key, NULL, key);
    }

    memset(key, 0, sizeof(key));

    if (result != 0) {
	dest_tkt();
	return NIL;
    }

    /* Check validity of returned ticket */
    gethostname(hostname, sizeof(hostname));
    result = krb_mk_req(&authent, "imap", krb_get_phost(hostname), realm, 0);
    if (result != 0) {
	memset(&authent, 0, sizeof(authent));
	dest_tkt();
	return NIL;
    }
    strcpy(instance, "*");
    result = krb_rd_req(&authent, "imap", instance, 0L, &kdata, srvtab);
    memset(&authent, 0, sizeof(authent));
    memset(kdata.session, 0, sizeof(kdata.session));
    if (result != 0 || strcmp(kdata.pname, user) != 0 || kdata.pinst[0] ||
	strcmp(kdata.prealm, realm) != 0) {
	result = NIL;
    }
    else result = T;

    dest_tkt();
    return result;
}

/* andrewstk.c -- afs string to key function
 *
 * Code taken from AuthMan from University of Michigan
 */

/* forward declarations */
static afs_transarc_StringToKey();
static afs_cmu_StringToKey();

extern char *crypt();

/* This defines the Andrew string_to_key function.  It accepts a password
 * string as input and converts its via a one-way encryption algorithm to a DES
 * encryption key.  It is compatible with the original Andrew authentication
 * service password database.
 */

static
afs_cmu_StringToKey (str, cell, key)
  char          *str;
  char          *cell;                  /* cell for password */
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
  char          *str;
  char          *cell;                  /* cell for password */
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
  char          *str;
  des_cblock	*key;
  char          *cell;                  /* cell for password */
{
	if (strlen(str) > 8)
		afs_transarc_StringToKey (str, cell, key);
	else
		afs_cmu_StringToKey (str, cell, key);
}

