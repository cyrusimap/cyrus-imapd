/* pop3test.c -- pop3 test client
 * $Id: pop3test.c,v 1.7 2002/04/12 18:09:30 ken3 Exp $
 *
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <pwd.h>

#include "prot.h"
#include "iptostring.h"

#ifdef HAVE_SSL
#include <openssl/ssl.h>

static SSL_CTX *tls_ctx = NULL;
static SSL *tls_conn = NULL;

#else
#include <sasl/md5global.h>
#include <sasl/md5.h>

#define MD5_Init _sasl_MD5Init
#define MD5_Update _sasl_MD5Update
#define MD5_Final _sasl_MD5Final

#endif /* HAVE_SSL */

#define IMTEST_OK    0
#define IMTEST_FAIL -1

typedef enum {
    STAT_CONT = 0,
    STAT_NO = 1,
    STAT_OK = 2
} imt_stat;

/* global vars */
sasl_conn_t *conn;
int sock; /* socket descriptor */

int verbose=0;
int dochallenge=1;

struct protstream *pout, *pin;

static char *authname = NULL;
static char *username = NULL;
static char *realm = NULL;

extern int _sasl_debug;

extern char *optarg;

struct stringlist 
{
    char *str;
    struct stringlist *next;
};

struct stringlist *strlist_head = NULL;

/* callbacks we support */
static sasl_callback_t callbacks[] = {
  {
    SASL_CB_ECHOPROMPT, NULL, NULL    
  }, {
    SASL_CB_NOECHOPROMPT, NULL, NULL    
  }, {
#ifdef SASL_CB_GETREALM
    SASL_CB_GETREALM, NULL, NULL
  }, {
#endif
    SASL_CB_USER, NULL, NULL
  }, {
    SASL_CB_AUTHNAME, NULL, NULL
  }, {
    SASL_CB_PASS, NULL, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

void imtest_fatal(char *msg)
{
    if (msg != NULL) {
	printf("failure: %s\n",msg);
    }
    exit(1);
}

/* libcyrus makes us define this */
void fatal(void)
{
  exit(1);
}

#ifdef HAVE_SSL

static int verify_depth;
static int verify_error = X509_V_OK;
static int do_dump = 0;

#define CCERT_BUFSIZ 256
static char peer_subject[CCERT_BUFSIZ];
static char peer_issuer[CCERT_BUFSIZ];
static char peer_CN[CCERT_BUFSIZ];
static char issuer_CN[CCERT_BUFSIZ];
static unsigned char md[EVP_MAX_MD_SIZE];
static char fingerprint[EVP_MAX_MD_SIZE * 3];

char   *tls_peer_CN = NULL;
char   *tls_issuer_CN = NULL;

const char *tls_protocol = NULL;
const char *tls_cipher_name = NULL;
int	tls_cipher_usebits = 0;
int	tls_cipher_algbits = 0;

/*
  * Set up the cert things on the server side. We do need both the
  * private key (in key_file) and the cert (in cert_file).
  * Both files may be identical.
  *
  * This function is taken from OpenSSL apps/s_cb.c
  */

static int set_cert_stuff(SSL_CTX * ctx, char *cert_file, char *key_file)
{
    if (cert_file != NULL) {
	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) <= 0) {
	  printf("unable to get certificate from '%s'\n", cert_file);
	  return (0);
	}
	if (key_file == NULL)
	    key_file = cert_file;
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file,
					SSL_FILETYPE_PEM) <= 0) {
	  printf("unable to get private key from '%s'\n", key_file);
	  return (0);
	}
	/* Now we know that a key and cert have been set against
         * the SSL context */
	if (!SSL_CTX_check_private_key(ctx)) {
	  printf("Private key does not match the certificate public key\n");
	  return (0);
	}
    }
    return (1);
}

/* taken from OpenSSL apps/s_cb.c */

static int verify_callback(int ok, X509_STORE_CTX * ctx)
{
    char    buf[256];
    X509   *err_cert;
    int     err;
    int     depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    if (verbose==1)
      printf("Peer cert verify depth=%d %s\n", depth, buf);

    if (!ok) {
      printf("verify error:num=%d:%s\n", err,
	     X509_verify_cert_error_string(err));
	if (verify_depth >= depth) {
	    ok = 1;
	    verify_error = X509_V_OK;
	} else {
	    ok = 0;
	    verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	}
    }
    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	printf("issuer= %s\n", buf);
	break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
      printf("cert not yet valid\n");
      break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
      printf("cert has expired\n");
      break;
    }

    if (verbose==1)
      printf("verify return:%d\n", ok);

    return (ok);
}


/* taken from OpenSSL apps/s_cb.c */

static RSA *tmp_rsa_cb(SSL * s, int export, int keylength)
{
    static RSA *rsa_tmp = NULL;

    if (rsa_tmp == NULL) {
	rsa_tmp = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    }
    return (rsa_tmp);
}

/* taken from OpenSSL apps/s_cb.c 
 * tim - this seems to just be giving logging messages
 */

static void apps_ssl_info_callback(SSL * s, int where, int ret)
{
    char   *str;
    int     w;

    if (verbose==0) return;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
	str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
	str = "SSL_accept";
    else
	str = "undefined";

    if (where & SSL_CB_LOOP) {
      printf("%s:%s\n", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
	str = (where & SSL_CB_READ) ? "read" : "write";
	if ((ret & 0xff) != SSL3_AD_CLOSE_NOTIFY)
	  printf("SSL3 alert %s:%s:%s\n", str,
		   SSL_alert_type_string_long(ret),
		   SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
	if (ret == 0)
	    printf("%s:failed in %s\n",
		     str, SSL_state_string_long(s));
	else if (ret < 0) {
	    printf("%s:error in %s %i\n",
		     str, SSL_state_string_long(s),ret);
	}
    }
}


/*
 * Seed the random number generator.
 */
static int tls_rand_init(void)
{
#ifdef EGD_SOCKET
    return (RAND_egd(EGD_SOCKET));
#else
    /* otherwise let OpenSSL do it internally */
    return 0;
#endif
}


char *var_tls_CAfile="";
char *var_tls_CApath="";
 /*
  * This is the setup routine for the SSL client. 
  *
  * The skeleton of this function is taken from OpenSSL apps/s_client.c.
  */

static int tls_init_clientengine(int verifydepth, char *var_tls_cert_file, char *var_tls_key_file)
{
    int     off = 0;
    int     verify_flags = SSL_VERIFY_NONE;
    char   *CApath;
    char   *CAfile;
    char   *c_cert_file;
    char   *c_key_file;


    if (verbose==1)
      printf("starting TLS engine\n");

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    if (tls_rand_init() == -1) {
	printf("TLS engine: cannot seed PRNG\n");
	return IMTEST_FAIL;
    }

    tls_ctx = SSL_CTX_new(TLSv1_client_method());
    if (tls_ctx == NULL) {
	return IMTEST_FAIL;
    };

    off |= SSL_OP_ALL;		/* Work around all known bugs */
    SSL_CTX_set_options(tls_ctx, off);
    SSL_CTX_set_info_callback(tls_ctx, apps_ssl_info_callback);

    if (strlen(var_tls_CAfile) == 0)
	CAfile = NULL;
    else
	CAfile = var_tls_CAfile;
    if (strlen(var_tls_CApath) == 0)
	CApath = NULL;
    else
	CApath = var_tls_CApath;

    if (CAfile || CApath)
	if ((!SSL_CTX_load_verify_locations(tls_ctx, CAfile, CApath)) ||
	    (!SSL_CTX_set_default_verify_paths(tls_ctx))) {
	    printf("TLS engine: cannot load CA data\n");
	    return IMTEST_FAIL;
	}
    if (strlen(var_tls_cert_file) == 0)
	c_cert_file = NULL;
    else
	c_cert_file = var_tls_cert_file;
    if (strlen(var_tls_key_file) == 0)
	c_key_file = NULL;
    else
	c_key_file = var_tls_key_file;

    if (c_cert_file || c_key_file)
	if (!set_cert_stuff(tls_ctx, c_cert_file, c_key_file)) {
	    printf("TLS engine: cannot load cert/key data\n");
	    return IMTEST_FAIL;
	}
    SSL_CTX_set_tmp_rsa_callback(tls_ctx, tmp_rsa_cb);

    verify_depth = verifydepth;
    SSL_CTX_set_verify(tls_ctx, verify_flags, verify_callback);

    return IMTEST_OK;
}

/*
 * taken from OpenSSL crypto/bio/b_dump.c, modified to save a lot of strcpy
 * and strcat by Matti Aarnio.
 */

#define TRUNCATE
#define DUMP_WIDTH	16

static int tls_dump(const char *s, int len)
{
    int     ret = 0;
    char    buf[160 + 1];
    char    *ss;
    int     i;
    int     j;
    int     rows;
    int     trunc;
    unsigned char ch;

    trunc = 0;

#ifdef TRUNCATE
    for (; (len > 0) && ((s[len - 1] == ' ') || (s[len - 1] == '\0')); len--)
	trunc++;
#endif

    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
	rows++;

    for (i = 0; i < rows; i++) {
	buf[0] = '\0';				/* start with empty string */
	ss = buf;

	sprintf(ss, "%04x ", i * DUMP_WIDTH);
	ss += strlen(ss);
	for (j = 0; j < DUMP_WIDTH; j++) {
	    if (((i * DUMP_WIDTH) + j) >= len) {
		strcpy(ss, "   ");
	    } else {
		ch = ((unsigned char) *((char *) (s) + i * DUMP_WIDTH + j))
		    & 0xff;
		sprintf(ss, "%02x%c", ch, j == 7 ? '|' : ' ');
		ss += 3;
	    }
	}
	ss += strlen(ss);
	*ss+= ' ';
	for (j = 0; j < DUMP_WIDTH; j++) {
	    if (((i * DUMP_WIDTH) + j) >= len)
		break;
	    ch = ((unsigned char) *((char *) (s) + i * DUMP_WIDTH + j)) & 0xff;
	    *ss+= (((ch >= ' ') && (ch <= '~')) ? ch : '.');
	    if (j == 7) *ss+= ' ';
	}
	*ss = 0;
	/* 
	 * if this is the last call then update the ddt_dump thing so that
         * we will move the selection point in the debug window
         */
	printf("%s\n", buf);
	ret += strlen(buf);
    }
#ifdef TRUNCATE
    if (trunc > 0) {
	sprintf(buf, "%04x - <SPACES/NULS>\n", len+ trunc);
	printf("%s\n", buf);
	ret += strlen(buf);
    }
#endif
    return (ret);
}


/* taken from OpenSSL apps/s_cb.c */

static long bio_dump_cb(BIO * bio, int cmd, const char *argp, int argi,
			long argl, long ret)
{
    if (!do_dump)
	return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
	printf("read from %08X [%08lX] (%d bytes => %ld (0x%X))\n", bio, argp,
		 argi, ret, ret);
	tls_dump(argp, (int) ret);
	return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
	printf("write to %08X [%08lX] (%d bytes => %ld (0x%X))\n", bio, argp,
		 argi, ret, ret);
	tls_dump(argp, (int) ret);
    }
    return (ret);
}

int tls_start_clienttls(unsigned *layer, char **authid)
{
    int     sts;
    int     j;
    unsigned int n;
    SSL_SESSION *session;
    SSL_CIPHER *cipher;
    X509   *peer;

    if (verbose==1)
      printf("setting up TLS connection\n");

    if (tls_conn == NULL) {
	tls_conn = (SSL *) SSL_new(tls_ctx);
    }
    if (tls_conn == NULL) {
	printf("Could not allocate 'con' with SSL_new()\n");
	return IMTEST_FAIL;
    }
    SSL_clear(tls_conn);

    if (!SSL_set_fd(tls_conn, sock)) {
      printf("SSL_set_fd failed\n");
      return IMTEST_FAIL;
    }
    /*
     * This is the actual handshake routine. It will do all the negotiations
     * and will check the client cert etc.
     */
    SSL_set_connect_state(tls_conn);


    /*
     * We do have an SSL_set_fd() and now suddenly a BIO_ routine is called?
     * Well there is a BIO below the SSL routines that is automatically
     * created for us, so we can use it for debugging purposes.
     */
    if (verbose==1)
      BIO_set_callback(SSL_get_rbio(tls_conn), bio_dump_cb);

    /* Dump the negotiation for loglevels 3 and 4 */
    if (verbose==1)
	do_dump = 1;

    if ((sts = SSL_connect(tls_conn)) < 0) {
	printf("SSL_connect error %d\n", sts);
	session = SSL_get_session(tls_conn);
	if (session) {
	    SSL_CTX_remove_session(tls_ctx, session);
	    printf("SSL session removed\n");
	}
	if (tls_conn!=NULL)
	    SSL_free(tls_conn);
	tls_conn = NULL;
	return IMTEST_FAIL;
    }

    /*
     * Lets see, whether a peer certificate is available and what is
     * the actual information. We want to save it for later use.
     */
    peer = SSL_get_peer_certificate(tls_conn);
    if (peer != NULL) {
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
			  NID_commonName, peer_CN, CCERT_BUFSIZ);
	tls_peer_CN = peer_CN;
	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
			  NID_commonName, issuer_CN, CCERT_BUFSIZ);
	if (verbose==1)
	  printf("subject_CN=%s, issuer_CN=%s\n", peer_CN, issuer_CN);
	tls_issuer_CN = issuer_CN;

    }
    tls_protocol = SSL_get_version(tls_conn);
    cipher = SSL_get_current_cipher(tls_conn);
    tls_cipher_name = SSL_CIPHER_get_name(cipher);
    tls_cipher_usebits = SSL_CIPHER_get_bits(cipher,
						 &tls_cipher_algbits);

    if (layer!=NULL)
      *layer = tls_cipher_usebits;

    if (authid!=NULL)
      *authid = tls_peer_CN;

    printf("TLS connection established: %s with cipher %s (%d/%d bits)\n",
	   tls_protocol, tls_cipher_name,
	   tls_cipher_usebits, tls_cipher_algbits);
    return IMTEST_OK;
}


#endif /* HAVE_SSL */


static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=(sasl_security_properties_t *)
    malloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize=1024;
  ret->min_ssf=min;
  ret->max_ssf=max;

  ret->security_flags=0;
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}

/*
 * Initialize SASL and set necessary options
 */
static int init_sasl(char *serverFQDN, int port, int minssf, int maxssf)
{
  int saslresult;
  sasl_security_properties_t *secprops=NULL;
  socklen_t addrsize;
  char localip[60], remoteip[60];
  struct sockaddr_in saddr_l;
  struct sockaddr_in saddr_r;

  /* attempt to start sasl */
  saslresult=sasl_client_init(callbacks+(!dochallenge ? 2 : 0));

  if (saslresult!=SASL_OK) return IMTEST_FAIL;

  addrsize=sizeof(struct sockaddr_in);
  if (getpeername(sock,(struct sockaddr *)&saddr_r,&addrsize)!=0)
      return IMTEST_FAIL;

  addrsize=sizeof(struct sockaddr_in);
  if (getsockname(sock,(struct sockaddr *)&saddr_l,&addrsize)!=0)
      return IMTEST_FAIL;

  if(iptostring((struct sockaddr *)&saddr_l, sizeof(struct sockaddr_in),
		localip, 60))
      return IMTEST_FAIL;

  if(iptostring((struct sockaddr *)&saddr_r, sizeof(struct sockaddr_in),
		remoteip, 60))
      return IMTEST_FAIL;
  

  /* client new connection */
  saslresult=sasl_client_new("pop",
			     serverFQDN,
			     localip,
			     remoteip,
			     NULL,
			     0,
			     &conn);

  if (saslresult!=SASL_OK) return IMTEST_FAIL;

  /* create a security structure and give it to sasl */
  secprops = make_secprops(minssf, maxssf);
  if (secprops != NULL)
  {
    sasl_setprop(conn, SASL_SEC_PROPS, secprops);
    free(secprops);
  }
  
  return IMTEST_OK;
}

#define BUFSIZE 16384

imt_stat getauthline(char **line, int *linelen)
{
  char buf[BUFSIZE];
  int saslresult;
  unsigned len;
  char *str=(char *) buf;
  
  str = prot_fgets(str, BUFSIZE, pin);
  if (str == NULL) imtest_fatal("prot layer failure");
  printf("S: %s",str);

  if (!strncasecmp(str, "+OK ", 4)) { return STAT_OK; }
  if (!strncasecmp(str, "-ERR ", 5)) { return STAT_NO; }

  str += 2; /* jump past the "+ " */

  len = strlen(str) + 1;
  *line = malloc(len);
  if ((*line)==NULL) {
      return STAT_NO;
  }

  if (*str != '\r') {
      /* decode this line */
      saslresult = sasl_decode64(str, strlen(str), 
				 *line, len, (unsigned *) linelen);
      if (saslresult != SASL_OK) {
	  printf("base64 decoding error\n");
	  return STAT_NO;
      }
  } else {
      /* this is a blank */
      *line = NULL;
      *linelen = 0;
  }

  return STAT_CONT;
}

void interaction (int id, const char *challenge, const char *prompt,
		  char **tresult, unsigned int *tlen)
{
    char result[1024];

    struct stringlist *cur;

    cur = malloc(sizeof(struct stringlist));
    if(!cur) {
	*tlen=0;
	*tresult=NULL;
	return;
    }
  
    cur->str = NULL;
    cur->next = strlist_head;
    strlist_head = cur;
    
    if (id==SASL_CB_PASS) {
	printf("%s: ", prompt);
	cur->str=strdup(getpass(""));
	*tlen=strlen(cur->str);
	*tresult = cur->str;
	return;
    } else if (id==SASL_CB_USER) {
	if (username != NULL) {
	    strcpy(result, username);
	} else {
	    strcpy(result, getpwuid(getuid())->pw_name);
	}
    } else if (id==SASL_CB_AUTHNAME) {
	if (authname != NULL) {
	    strcpy(result, authname);
	} else {
	    strcpy(result, getpwuid(getuid())->pw_name);
	}
#ifdef SASL_CB_GETREALM
    } else if ((id==SASL_CB_GETREALM) && (realm != NULL)) {
      strcpy(result, realm);
#endif
    } else {
	int c;
	
	if (((id==SASL_CB_ECHOPROMPT) || (id=SASL_CB_NOECHOPROMPT)) &&
	    (challenge != NULL)) {
	    printf("Server challenge: %s\n", challenge);
	}
	printf("%s: ",prompt);
	if (id==SASL_CB_NOECHOPROMPT) {
	    strcpy(result, getpass(""));
	} else {
	    fgets(result, sizeof(result) - 1, stdin);
	    c = strlen(result);
	    result[c - 1] = '\0';
	}
    }

    *tlen = strlen(result);
    cur->str = (char *) malloc(*tlen+1);
    if(!cur->str) {
	*tresult = NULL;
	return;
    }
    memset(cur->str, 0, *tlen+1);
    memcpy(cur->str, result, *tlen);
    *tresult  = cur->str;
}

void fillin_interactions(sasl_interact_t *tlist)
{
  while (tlist->id!=SASL_CB_LIST_END)
  {
    interaction(tlist->id, tlist->challenge, tlist->prompt,
		(void *) &(tlist->result), 
		&(tlist->len));
    tlist++;
  }

}

static int waitfor(char *tag)
{
    char str[1024];

    do {
	if (prot_fgets(str,sizeof(str),pin) == NULL) {
	    imtest_fatal("prot layer failure");
	}
	printf("%s", str);
    } while (strncmp(str, tag, strlen(tag)));

    return 0;
}

static int auth_user(void)
{
  char str[1024];
  /* we need username and password to do USER/PASS */
  char *username;
  unsigned int userlen;
  char *pass;
  unsigned int passlen;

  interaction(SASL_CB_AUTHNAME,NULL,"Authname",&username,&userlen);
  interaction(SASL_CB_PASS,NULL,"Password",&pass,&passlen);

  printf("C: USER %s\r\n", username);
  prot_printf(pout,"USER %s\r\n", username);
  prot_flush(pout);

  if(prot_fgets(str, 1024, pin) == NULL) {
      imtest_fatal("prot layer failure");
  }

  printf("S: %s", str);

  if (strncasecmp(str, "+OK ", 4)) return IMTEST_FAIL;

  printf("C: PASS <omitted>\r\n");
  prot_printf(pout,"PASS %s\r\n",pass);
  prot_flush(pout);

  if(prot_fgets(str, 1024, pin) == NULL) {
      imtest_fatal("prot layer failure");
  }

  printf("S: %s", str);

  if (!strncasecmp(str, "+OK ", 4)) {
      return IMTEST_OK;
  } else {
      return IMTEST_FAIL;
  }
}

static int auth_apop(char *apop_chal)
{
  char str[1024];
  /* we need username and password to do "APOP" */
  char *username;
  unsigned int userlen;
  char *pass;
  unsigned int passlen;
  int i;
  MD5_CTX ctx;
  unsigned char digest[16];
  char digeststr[32];

  if(!apop_chal) {
      prot_printf(pout, "QUIT\r\n");
      printf("C: QUIT\r\n");
      imtest_fatal("[Server does not support APOP]\n");
  }

  interaction(SASL_CB_AUTHNAME,NULL,"Authname",&username,&userlen);
  interaction(SASL_CB_PASS,NULL,"Password",&pass,&passlen);

  MD5_Init(&ctx);
  MD5_Update(&ctx,apop_chal,strlen(apop_chal));
  MD5_Update(&ctx,pass,passlen);
  MD5_Final(digest, &ctx);

  /* convert digest from binary to ASCII hex */
  for (i = 0; i < 16; i++)
      sprintf(digeststr + (i*2), "%02x", digest[i]);

  printf("C: APOP %s %s\r\n", username,digeststr);
  prot_printf(pout,"APOP %s %s\r\n", username,digeststr);
  prot_flush(pout);

  if(prot_fgets(str, 1024, pin) == NULL) {
      imtest_fatal("prot layer failure");
  }

  printf("S: %s", str);

  if (!strncasecmp(str, "+OK ", 4)) {
      return IMTEST_OK;
  } else {
      return IMTEST_FAIL;
  }
}

int auth_sasl(char *mechlist)
{
  sasl_interact_t *client_interact=NULL;
  int saslresult=SASL_INTERACT;
  const char *out;
  unsigned int outlen;
  char *in;
  int inlen;
  const char *mechusing;
  char inbase64[4096];
  int inbase64len;

  imt_stat status = STAT_CONT;

  /* call sasl client start */
  while (saslresult==SASL_INTERACT)
  {
    saslresult = sasl_client_start(conn, mechlist,
				   &client_interact,
				   NULL, NULL,
				   &mechusing);

    if (saslresult==SASL_INTERACT)
      fillin_interactions(client_interact); /* fill in prompts */      
  }

  if ((saslresult != SASL_OK) && 
      (saslresult != SASL_CONTINUE)) {
      return saslresult;
  }

  prot_printf(pout,"AUTH %s\r\n",mechusing);
  prot_flush(pout);
  printf("C: AUTH %s\r\n", mechusing);

  inlen = 0;
  status = getauthline(&in, &inlen);

  while (status==STAT_CONT)
  {
    saslresult=SASL_INTERACT;
    while (saslresult==SASL_INTERACT)
    {
      saslresult=sasl_client_step(conn,
				  in,
				  inlen,
				  &client_interact,
				  &out,
				  &outlen);

      if (saslresult==SASL_INTERACT)
	fillin_interactions(client_interact); /* fill in prompts */
    }

    /* check if sasl suceeded */
    if (saslresult != SASL_OK && saslresult != SASL_CONTINUE) {
	/* cancel the exchange */
	prot_printf(pout,"*\r\n");
	prot_flush(pout);

	return saslresult;
    }

    /* convert to base64 */
    saslresult = sasl_encode64(out, outlen,
			       inbase64, 2048, (unsigned *) &inbase64len);
    if (saslresult != SASL_OK) return saslresult;

    free(in);

    /* send to server */
    printf("C: %s\n",inbase64);
    prot_write(pout, inbase64, inbase64len);
    prot_printf(pout,"\r\n");
    prot_flush(pout);

    /* get reply */
    status=getauthline(&in,&inlen);
  }
  
  return (status == STAT_OK) ? IMTEST_OK : IMTEST_FAIL;
}

/* initialize the network */
int init_net(char *serverFQDN, int port)
{
  struct sockaddr_in addr;
  struct hostent *hp;

  if ((hp = gethostbyname(serverFQDN)) == NULL) {
    perror("gethostbyname");
    return IMTEST_FAIL;
  }
  strncpy(serverFQDN, hp->h_name, 1023);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return IMTEST_FAIL;	
  }

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_port = htons(port);

  if (connect(sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    perror("connect");
    return IMTEST_FAIL;
  }

  return IMTEST_OK;
}

/***********************
 * Parse a mech list of the form: ... SASL foo bar ...
 *
 * Return: string with mechs seperated by spaces
 *
 ***********************/

static char *parsemechlist(char *str)
{
  char *tmp;
  int num=0;
  char *ret=malloc(strlen(str)+1);
  if (ret==NULL) return NULL;

  strcpy(ret,"");

  if ((tmp=strstr(str,"SASL "))!=NULL)
  {
    char *end=tmp+5;
    tmp+=5;

    while(((*end)!='\n') && ((*end)!='\0'))
      end++;

    (*end)='\0';

    strcpy(ret, tmp);
  }

  return ret;
}


static char *ask_capability(int *supports_starttls)
{
  char str[1024];
  char *ret = NULL;

  /* request capabilities of server */
  prot_printf(pout, "CAPA\r\n");
  prot_flush(pout);

  printf("C: %s", "CAPA\r\n");

  *supports_starttls=0;

  do { /* look for the * CAPABILITY response */
      if (prot_fgets(str,sizeof(str),pin) == NULL) {
	  imtest_fatal("prot layer failure");
      }
      printf("S: %s", str);
      if (!strncasecmp(str,"SASL ",5)) {
	  ret=parsemechlist(str);
      }
      if (!strncasecmp(str,"STLS",4)) {
	  *supports_starttls=1;
      }
  } while (strncasecmp(str, ".", 1));

  return ret;
}

#define LOGOUT "QUIT"

void interactive(char *filename)
{
  char buf[2048];
  fd_set read_set, rset;
  fd_set write_set, wset;
  int nfds;
  int nfound;
  int count;
  int fd = 0;
  int donewritingfile = 0;

  /* open the file if available */
  if (filename != NULL) {
    if ((fd = open(filename, O_RDONLY)) == -1) {
      fprintf(stderr,"Unable to open file: %s:", filename);
      perror("");
      exit(1);
    }
  }
  
  FD_ZERO(&read_set);
  FD_SET(fd, &read_set);  
  FD_SET(sock, &read_set);

  FD_ZERO(&write_set);
  FD_SET(sock, &write_set);

  nfds = getdtablesize();

  if (filename != NULL) {
      donewritingfile = 0;
  }

  /* loop reading from network and from stdin if applicable */
  while(1) {
      rset = read_set;
      wset = write_set;
      nfound = select(nfds, &rset, &wset, NULL, NULL);
      if (nfound < 0) {
	  perror("select");
	  imtest_fatal("select");
      }

      if ((FD_ISSET(0, &rset)) && (FD_ISSET(sock, &wset)))  {
	  if (fgets(buf, sizeof (buf) - 1, stdin) == NULL) {
	      printf(LOGOUT);
	      prot_write(pout, LOGOUT, sizeof (LOGOUT));
	      FD_CLR(0, &read_set);
	  } else {
	      count = strlen(buf);
	      buf[count - 1] = '\r';
	      buf[count] = '\n';
	      buf[count + 1] = '\0';
	      prot_write(pout, buf, count + 1);
	  }
	  prot_flush(pout);
      } else if (FD_ISSET(sock, &rset)) {
	  do {
	      count = prot_read(pin, buf, sizeof (buf) - 1);
	      if (count == 0) {
		  if (prot_error(pin)) {
		      printf("Protection error: %s\n", prot_error(pin));
		  }
		  close(sock);
		  printf("Connection closed.\n");
		  return;
	      }
	      if (count < 0) {
		  perror("read");
		  imtest_fatal("prot_read");
	      }
	      buf[count] = '\0';
	      printf("%s", buf); 
	  } while (pin->cnt > 0);
      } else if ((FD_ISSET(fd, &rset)) && (FD_ISSET(sock, &wset))
		 && (donewritingfile == 0)) {
	  /* read from disk */	
	  int numr = read(fd, buf, sizeof(buf));


	  /* and send out over wire */
	  if (numr < 0)
	  {
	      perror("read");
	      imtest_fatal("read");
	  } else if (numr==0) {
	      donewritingfile = 1;

	      FD_CLR(fd,&read_set);

	      /* send LOGOUT */
	      printf(LOGOUT);
	      prot_write(pout, LOGOUT, sizeof (LOGOUT));	      
	      prot_flush(pout);
	  } else {
	      /* echo for the user */
	      write(1, buf, numr);
	      prot_write(pout, buf, numr);
	      prot_flush(pout);
	  }
      } else {
	  /* if can't do anything else sleep */
	  usleep(1000);
      }


  }
}

/* didn't give correct parameters; let's exit */
void usage(void)
{
  printf("Usage: imtest [options] hostname\n");
  printf("  -p port  : port to use\n");
  printf("  -k #     : minimum protection layer required\n");
  printf("  -l #     : max protection layer (0=none; 1=integrity; etc)\n");
  printf("  -u user  : authorization name to use\n");
  printf("  -a user  : authentication name to use\n");
  printf("  -v       : verbose\n");
  printf("  -m mech  : SASL mechanism to use (\"user\" for USER/PASS, \"apop\" for APOP)\n");
  printf("  -f file  : pipe file into connection after authentication\n");
  printf("  -r realm : realm\n");
#ifdef HAVE_SSL
  printf("  -t file  : Enable TLS. file has the TLS public and private keys\n"
	 "             (specify \"\" to not use TLS for authentication)\n");
#endif /* HAVE_SSL */
  printf("  -c       : disable challenge prompt callbacks\n"
	 "             (enter secret pass-phrase instead of one-time password)\n");

  exit(1);
}


int main(int argc, char **argv)
{
  char *mechanism=NULL;
  char servername[1024];
  char *filename=NULL;

  char *mechlist;
  unsigned ext_ssf = 0;
  const int *ssfp;
  int maxssf = 128;
  int minssf = 0;
  int c;
  int result;
  int errflg = 0;

  char *tls_keyfile="";
  char *port = "pop3";
  struct servent *serv;
  int servport;
  int run_stress_test=0;
  int dotls=0;
  int server_supports_tls;
  char str[1024], *start, *cp;
  char *apop_chal=NULL;

  struct stringlist *cur, *cur_next;

  /* do not buffer */
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  /* look at all the extra args */
  while ((c = getopt(argc, argv, "cvk:l:p:u:a:m:f:r:t:")) != EOF)
    switch (c) {
    case 'c':
	dochallenge=0;
	break;
    case 'v':
	verbose=1;
	break;
    case 'k':
	minssf=atoi(optarg);      
	break;
    case 'l':
	maxssf=atoi(optarg);      
	break;
    case 'p':
	port = optarg;
	break;
    case 'u':
	username = optarg;
	break;
    case 'a':
	authname = optarg;
	break;
    case 'm':
	mechanism=optarg;
	break;
    case 'f':
        filename=optarg;
	break;
    case 'r':
        realm=optarg;
        break;
    case 't':
      dotls=1;
      tls_keyfile=optarg;
      break;
    case '?':
    default:
	errflg = 1;
	break;
    }

  if (optind != argc - 1) {
      errflg = 1;
  }

  if (errflg) {
      usage();
  }

  /* last arg is server name */
  strncpy(servername, argv[optind], 1023);

  /* map port -> num */
  serv = getservbyname(port, "tcp");
  if (serv == NULL) {
      servport = atoi(port);
  } else {
      servport = ntohs(serv->s_port);
  }

  if (init_net(servername, servport) != IMTEST_OK) {
      imtest_fatal("Network initialization");
  }
  
  if (init_sasl(servername, servport, minssf, maxssf) != IMTEST_OK) {
      imtest_fatal("SASL initialization");
  }

  /* set up the prot layer */
  pin = prot_new(sock, 0);
  pout = prot_new(sock, 1); 

  /* Get header line */
  if(prot_fgets(str,sizeof(str),pin) == NULL) {
      imtest_fatal("prot layer failure");
  }

  printf("S: %s",str);
  
  if(strncmp(str, "+OK", 3)) {
      imtest_fatal("bad POP3 header");
  }
  
  /* look for APOP challenge in header '<...@...>' */
  cp = str+4;
  while (cp && (start = strchr(cp, '<'))) {
      cp = start + 1;
      while (*cp && *cp != '@' && *cp != '<' && *cp != '>') cp++;
      if (*cp != '@') continue;
      while (*cp && *cp != '<' && *cp != '>') cp++;
      if (*cp == '>') {
	  *(++cp) = '\0';
	  apop_chal = strdup(start);
	  if (!apop_chal) imtest_fatal("memory error");
	  break;
      }	    
  }

  mechlist=ask_capability(&server_supports_tls);

#ifdef HAVE_SSL
  if ((dotls==1) && (server_supports_tls==1))
  {
    char *auth_id;
      
    prot_printf(pout,"STLS\r\n");
    prot_flush(pout);
    
    waitfor("+OK");

    result=tls_init_clientengine(10, tls_keyfile, tls_keyfile);
    if (result!=IMTEST_OK)
    {
      printf("Start TLS engine failed\n");
    } else {
      result=tls_start_clienttls(&ext_ssf, &auth_id);
      
      if (result!=IMTEST_OK)
	printf("TLS negotiation failed!\n");
    }

    /* TLS negotiation suceeded */

    /* tell SASL about the negotiated layer */
    result=sasl_setprop(conn,
			SASL_SSF_EXTERNAL,
			&ext_ssf);
    if (result!=SASL_OK)
	imtest_fatal("Error setting SASL property (external ssf)");

    result=sasl_setprop(conn,
			SASL_AUTH_EXTERNAL,
			auth_id);
    if (result!=SASL_OK)
	imtest_fatal("Error setting SASL property (external auth_id)");

    prot_settls (pin,  tls_conn);
    prot_settls (pout, tls_conn);

    /* ask for the capabilities again */
    if (verbose==1)
	printf("Asking for capabilities again since they might have changed\n");
    mechlist=ask_capability(&server_supports_tls);

  } else if ((dotls==1) && (server_supports_tls!=1)) {
    imtest_fatal("STARTTLS not supported by the server!\n");
  }
#endif /* HAVE_SSL */

  if (mechanism) {
      if (!strcasecmp(mechanism, "apop")) {
	  result = auth_apop(apop_chal);
      } else if (!strcasecmp(mechanism, "user")) {
	  result = auth_user();
      } else {
	  result = auth_sasl(mechanism);
      }
  } else {
      if (mechlist && *mechlist) {
	  result = auth_sasl(mechlist);
      } else if (apop_chal) {
	  result = auth_apop(apop_chal);
      } else {
	  result = auth_user();
      }
  }

  if (apop_chal) {
      free(apop_chal);
      apop_chal = NULL;
  }

  if (result == IMTEST_OK) {
      printf("Authenticated.\n");

      /* turn on layer if need be */
      prot_setsasl(pin,  conn);
      prot_setsasl(pout, conn);
  } else {
      const char *s = sasl_errstring(result, NULL, NULL);

      printf("Authentication failed. %s\n", s);
  }

  result = sasl_getprop(conn, SASL_SSF, (const void **)&ssfp);
  if (result != SASL_OK) {
      printf("SSF: unable to determine (SASL ERROR %d)\n", result);
  } else {
      printf("Security strength factor: %d\n", ext_ssf + *ssfp);
  }

  /* run in interactive mode or 
     pipe in a filename if applicable */
  interactive(filename);

  for(cur=strlist_head; cur; cur=cur_next) {
      cur_next = cur->next;
      free(cur->str);
      free(cur);
  }

  exit(0);
}
