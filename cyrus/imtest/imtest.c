/* imtest.c -- IMAP/POP3/LMTP/SMTP/MUPDATE/MANAGESIEVE test client
 * Ken Murchison (multi-protocol implementation)
 * Tim Martin (SASL implementation)
 * $Id: imtest.c,v 1.82.2.2 2002/08/16 20:03:38 ken3 Exp $
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

#include "config.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <pwd.h>

#include "prot.h"
#include "imparse.h"
#include "iptostring.h"
#include "xmalloc.h"

#ifdef HAVE_SSL
#include <openssl/ssl.h>

static SSL_CTX *tls_ctx = NULL;
static SSL *tls_conn = NULL;
static SSL_SESSION *tls_sess = NULL;

#else /* HAVE_SSL */
#include <sasl/md5global.h>
#include <sasl/md5.h>

#define MD5_Init _sasl_MD5Init
#define MD5_Update _sasl_MD5Update
#define MD5_Final _sasl_MD5Final

#endif /* HAVE_SSL */

#define IMTEST_OK    0
#define IMTEST_FAIL -1
#define IMTEST_CLOSEME -2

typedef enum {
    STAT_CONT = 0,
    STAT_NO = 1,
    STAT_OK = 2
} imt_stat;

/* global vars */
sasl_conn_t *conn;
int sock; /* socket descriptor */

int verbose=0;

struct protstream *pout, *pin;

static char *authname = NULL;
static char *username = NULL;
static char *realm = NULL;
static char *cmdline_password = NULL;

static char *output_socket = NULL;
static int output_socket_opened = 0;
static ino_t output_socket_ino = 0;

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

struct banner_t {
    int is_capa;	/* banner is capability response */
    char *resp;		/* end of banner response */
    void *(*parse_banner)(char *str);
			/* [OPTIONAL] parse banner, returns 'rock' */
};

struct capa_cmd_t {
    char *cmd;		/* capability command string (NULL = no capa cmd) */
    char *resp;		/* end of capability response */
    char *tls;		/* [OPTIONAL] TLS capability string */
    char *auth;		/* [OPTIONAL] AUTH capability string */
    char *(*parse_mechlist)(char *str);
			/* [OPTIONAL] parse capability string,
			   returns space-separated list of mechs */
};

struct tls_cmd_t {
    char *cmd;		/* tls command string */
    char *ok;		/* start tls prompt */
    char *fail;		/* failure response */
    int auto_capa;	/* capa response given automatically after TLS */
};

struct sasl_cmd_t {
    char *cmd;		/* auth command string */
    int quote;		/* quote arguments (literal for base64 data) */
    char *empty_init;	/* string to send as empty initial-response,
			   (NULL = initial response unsupported by protocol) */
    char *(*parse_success)(char *str);
			/* [OPTIONAL] parse response for success data */
    char *ok;		/* success response string */
    char *fail;		/* failure response string */
    char *cont;		/* continue response string
			   (NULL = send/receive literals) */
    char *cancel;	/* cancel auth string */
};

struct logout_cmd_t {
    char *cmd;		/* logout command string */
    char *resp;		/* logout response */
};

struct protocol_t {
    char *protocol;	/* protocol service name */
    char *sprotocol;	/* SSL-wrapped service name (NULL = unsupported) */
    char *service;	/* SASL service name */
    struct banner_t banner;
    struct capa_cmd_t capa_cmd;
    struct tls_cmd_t tls_cmd;
    struct sasl_cmd_t sasl_cmd;
    int (*do_auth)(struct sasl_cmd_t *sasl_cmd, void *rock,
		   char *mech, char *mechlist);
			/* [OPTIONAL] perform protocol-specific
			   authentication; based on rock, mech, mechlist */
    struct logout_cmd_t logout_cmd;

    /* these 3 are used for maintaining connection state */
    void *(*init_conn)(void); /* generate a context (if needed). This context
			       * must be malloc()ed and will be freed by
			       * interactive() as each connection is reused */
    int (*pipe)(char *buf, int len, void *rock); /* pipe a buffer to pout
						  * may be necessary to keep
						  * connection state */
    int (*reset)(void *rock); /* perform any protocol-specific reset when we
			       * lose connection on a unix domain socket
			       * during interactive mode.  If this is NULL we
			       * assume that we should not attempt to reuse
			       * connections (and just die at the end of one)
			       */
};


void imtest_fatal(const char *msg) __attribute__((noreturn));
void imtest_fatal(const char *msg)
{
    struct stat sbuf;
    if (output_socket && output_socket_opened &&
	stat(output_socket, &sbuf) != -1 &&
	sbuf.st_ino == output_socket_ino) {
	unlink(output_socket);
    }
    if (msg != NULL) {
	printf("failure: %s\n",msg);
    }
    exit(1);
}

/* libcyrus makes us define this */
void fatal(const char *msg, int code)
{
    imtest_fatal(msg);
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

    if (tls_sess)  /* Reuse a session if we have one */
	SSL_set_session(tls_conn, tls_sess);

    if ((sts = SSL_connect(tls_conn)) <= 0) {
	printf("SSL_connect error %d\n", sts);
	tls_sess = SSL_get_session(tls_conn);
	if (tls_sess) {
	    SSL_CTX_remove_session(tls_ctx, tls_sess);
	    tls_sess = NULL;
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

void do_starttls(int ssl, char *keyfile, unsigned *ssf)
{
    int result;
    char *auth_id;
    
    result=tls_init_clientengine(10, keyfile, keyfile);
    if (result!=IMTEST_OK)
	{
	    if (ssl) {
		imtest_fatal("Start TLS engine failed\n");
	    } else {
		printf("Start TLS engine failed\n");
		return;
	    }
	} else {
	    result=tls_start_clienttls(ssf, &auth_id);
	    
	    if (result!=IMTEST_OK)
		imtest_fatal("TLS negotiation failed!\n");
	}
    
    /* TLS negotiation suceeded */
    tls_sess = SSL_get_session(tls_conn); /* Save the session for reuse */
    
    /* tell SASL about the negotiated layer */
    result=sasl_setprop(conn,
			SASL_SSF_EXTERNAL,
			ssf);
    if (result!=SASL_OK)
	imtest_fatal("Error setting SASL property (external ssf)");
    
    result=sasl_setprop(conn,
			SASL_AUTH_EXTERNAL,
			auth_id);
    if (result!=SASL_OK)
	imtest_fatal("Error setting SASL property (external auth_id)");
    
    prot_settls (pin,  tls_conn);
    prot_settls (pout, tls_conn);
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
static int init_sasl(char *service, char *serverFQDN, int minssf, int maxssf,
		     unsigned flags)
{
    int saslresult;
    sasl_security_properties_t *secprops=NULL;
    socklen_t addrsize;
    char localip[60], remoteip[60];
    struct sockaddr_in saddr_l;
    struct sockaddr_in saddr_r;
    
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
    saslresult=sasl_client_new(service,
			       serverFQDN,
			       localip,
			       remoteip,
			       NULL,
			       flags,
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

imt_stat getauthline(struct sasl_cmd_t *sasl_cmd, char **line, int *linelen)
{
    char buf[BUFSIZE];
    int saslresult;
    unsigned len;
    char *str=(char *) buf;
    int ret = STAT_CONT;

    *line = NULL;
    *linelen = 0;
    
    do {
	str = prot_fgets(str, BUFSIZE, pin);
	if (str == NULL) imtest_fatal("prot layer failure");
	printf("S: %s",str);
    } while(str[0] == '*');      /* Ignore potential untagged responses */
    
    if (!strncasecmp(str, sasl_cmd->ok, strlen(sasl_cmd->ok))) {
	if (sasl_cmd->parse_success) {
	    str = sasl_cmd->parse_success(str);
	    if (!str) return STAT_OK;

	    ret = STAT_OK;
	}
	else {
	    return STAT_OK;
	}
    }
    else if (!strncasecmp(str, sasl_cmd->fail, strlen(sasl_cmd->fail))) {
	return STAT_NO;
    }
    else if (sasl_cmd->cont) {
	str += strlen(sasl_cmd->cont); /* jump past the continuation */
    }
    else {
	/* literal */
	len = atoi(str+1);

	str = prot_fgets(str, BUFSIZE, pin);
	if (str == NULL || strlen(str) < len)
	    imtest_fatal("prot layer failure");
	printf("S: %s", str);
    }
    
    if (*str != '\r') {
	len = strlen(str) + 1;
	*line = malloc(len);
	if ((*line) == NULL) {
	    return STAT_NO;
	}
    
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
    
    return ret;
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
    
    if (id==SASL_CB_PASS && !cmdline_password) {
	printf("%s: ", prompt);
	cur->str=strdup(getpass(""));
	*tlen=strlen(cur->str);
	*tresult = cur->str;
	return;
    } else if (id==SASL_CB_PASS && cmdline_password) {
	strcpy(result, cmdline_password);
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
    *tresult = cur->str;
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

static char *waitfor(char *tag, char *tag2, int echo)
{
    static char str[1024];
    
    do {
	if (prot_fgets(str, sizeof(str), pin) == NULL) {
	    imtest_fatal("prot layer failure");
	}
	if(echo) printf("S: %s", str);
    } while (strncmp(str, tag, strlen(tag)) &&
	     (tag2 ? strncmp(str, tag2, strlen(tag2)) : 1));
    
    return str;
}

int auth_sasl(struct sasl_cmd_t *sasl_cmd, char *mechlist)
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
    while (saslresult==SASL_INTERACT) {
	if (sasl_cmd->empty_init) {
	    /* we support initial client response */
	    saslresult = sasl_client_start(conn, mechlist,
					   &client_interact,
					   &out, &outlen,
					   &mechusing);
	} else {
	    saslresult = sasl_client_start(conn, mechlist,
					   &client_interact,
					   NULL, NULL,
					   &mechusing);
	    out = NULL;
	    outlen = 0;
	}
	    
	if (saslresult==SASL_INTERACT)
	    fillin_interactions(client_interact); /* fill in prompts */      
	}
    
    if ((saslresult != SASL_OK) && 
	(saslresult != SASL_CONTINUE)) {
	return saslresult;
    }
    
    if (sasl_cmd->quote) {
	printf("C: %s \"%s\"", sasl_cmd->cmd, mechusing);
	prot_printf(pout, "%s \"%s\"", sasl_cmd->cmd, mechusing);
    }
    else {
	printf("C: %s %s", sasl_cmd->cmd, mechusing);
	prot_printf(pout, "%s %s", sasl_cmd->cmd, mechusing);
    }

    if (!out) {
	/* no initial client response */
	printf("\r\n");
	prot_printf(pout, "\r\n");
    }
    else if (!outlen) {
	/* empty initial client response */
	printf(" %s\r\n", sasl_cmd->empty_init);
	prot_printf(pout," %s\r\n", sasl_cmd->empty_init);
    }
    else {
	/* initial client response - convert to base64 */
	saslresult = sasl_encode64(out, outlen,
				   inbase64, 2048, (unsigned *) &inbase64len);
	if (saslresult != SASL_OK) return saslresult;
	
	if (sasl_cmd->quote) {
	    /* send a literal */
	    printf(" {%d+}\r\n%s\r\n", inbase64len, inbase64);
	    prot_printf(pout, " {%d+}\r\n", inbase64len);
	    prot_flush(pout);
	}
	else {
	    printf(" %s\r\n", inbase64);
	    prot_printf(pout, " ");
	}

	prot_write(pout, inbase64, inbase64len);
	prot_printf(pout, "\r\n");
    }
    prot_flush(pout);

    status = getauthline(sasl_cmd, &in, &inlen);
    
    while (status==STAT_CONT) {
	saslresult=SASL_INTERACT;
	while (saslresult==SASL_INTERACT) {
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
	    printf("C: %s\r\n", sasl_cmd->cancel);
	    prot_printf(pout,"%s\r\n", sasl_cmd->cancel);
	    prot_flush(pout);
	    
	    return saslresult;
	}
	
	/* convert to base64 */
	saslresult = sasl_encode64(out, outlen,
				   inbase64, 2048, (unsigned *) &inbase64len);
	if (saslresult != SASL_OK) return saslresult;
	
	free(in);
	
	/* send to server */
	if (!sasl_cmd->cont) {
	    /* send a literal */
	    printf("C: {%d+}\r\n%s\n", inbase64len, inbase64);
	    prot_printf(pout, "{%d+}\r\n", inbase64len);
	    prot_flush(pout);
	}
	else {
	    printf("C: %s\n", inbase64);
	}

	prot_write(pout, inbase64, inbase64len);
	prot_printf(pout,"\r\n");
	prot_flush(pout);
   
	/* get reply */
	status = getauthline(sasl_cmd, &in, &inlen);
    }

    if (status == STAT_OK) {
	if (in) {
	    saslresult=sasl_client_step(conn,
					in,
					inlen,
					&client_interact,
					&out,
					&outlen);
	    if (saslresult != SASL_OK) return saslresult;
	}
	return IMTEST_OK;
    } else {
	return IMTEST_FAIL;
    }
}

/* initialize the network */
static int init_net(char *serverFQDN, int port)
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

static void logout(struct logout_cmd_t *logout_cmd, int wait)
{
    printf("C: %s\r\n", logout_cmd->cmd);
    prot_printf(pout, "%s\r\n", logout_cmd->cmd);
    prot_flush(pout);

    /* only wait if we are explicitly told to */
    if(wait) waitfor(logout_cmd->resp, NULL, 1);
}

static int gotsigint = 0;

static void sigint_handler(int sig __attribute__((unused)))
{
    gotsigint = 1;
}

/* This needs to support 3 modes:
 *
 * 1. Terminal Interface Only
 * 2. File input
 * 3. Redirect to a unix socket - This mode needs to be sure that the
 *    IMAP session is in an unselected state whenever the unix socket is
 *    disconnected.
 *
 */
static void interactive(struct protocol_t *protocol, char *filename)
{
    char buf[2048];
    fd_set read_set, rset;
    fd_set write_set, wset;
    fd_set accept_set, aset;
    int nfds;
    int nfound;
    int count;
    int r;
    int fd = 0, fd_out = 1, listen_sock = -1;
    void *rock = NULL;
    int donewritingfile = 0;

    struct sockaddr_un sunsock;
    int salen;

    /* open the file if available */
    if (filename != NULL) {
	if ((fd = open(filename, O_RDONLY)) == -1) {
	    fprintf(stderr,"Unable to open file: %s:", filename);
	    perror("");
	    exit(1);
	}
    } else if(output_socket) {
	struct timeval tv;
	struct stat sbuf;
	
	/* can't have this and a file for input */
	sunsock.sun_family = AF_UNIX;
	strcpy(sunsock.sun_path, output_socket);
	unlink(output_socket);

	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(listen_sock < 0) imtest_fatal("could not create output socket");

	salen = sizeof(sunsock.sun_family) + strlen(sunsock.sun_path) + 1;

	if((bind(listen_sock, (struct sockaddr *)&sunsock, salen)) < 0) {
	    imtest_fatal("could not bind output socket");
	}

	if((listen(listen_sock, 5)) < 0) {
	    imtest_fatal("could not listen to output socket");
	}

	if(stat(output_socket, &sbuf) == -1) {
	    imtest_fatal("could not stat output socket");
	}

	output_socket_opened = 1;
	output_socket_ino = sbuf.st_ino;

	FD_ZERO(&accept_set);
	FD_SET(listen_sock, &accept_set);

    accept_again:
	if(rock) {
	    free(rock);
	    rock = NULL;
	}

	tv.tv_sec = 600; /* 10 minute timeout - xxx protocol specific? */
	tv.tv_usec = 0;

	aset = accept_set;
	
	/* Have the separate select so that signals will wake us up
	 * and we get a timeout to use on our own imap connection */
	if(select(listen_sock + 1, &aset, NULL, NULL, &tv) <= 0) {
	    /* either we timed out or had an error */
	    goto cleanup;
	}

	fd = fd_out = accept(listen_sock, NULL, NULL);
	if(fd < 0) imtest_fatal("accept failure");
	    
	if(protocol->init_conn) rock = protocol->init_conn();
    }
    
    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);  /* In the terminal case fd == 0 */
    FD_SET(sock, &read_set);
    
    FD_ZERO(&write_set);
    FD_SET(fd_out, &write_set);
    FD_SET(sock, &write_set);
    
    nfds = getdtablesize();
    
    if (filename != NULL) {
	donewritingfile = 0;
    }

    /* add handler for SIGINT */
    signal(SIGINT, sigint_handler);

    /* loop reading from network and from stdin as applicable */
    while (1) {
	rset = read_set;
	wset = write_set;
	nfound = select(nfds, &rset, &wset, NULL, NULL);
	if (nfound < 0) {
	    perror("select");
	    imtest_fatal("select");
	}
	
	if (!output_socket &&
	    (FD_ISSET(0, &rset)) && (FD_ISSET(sock, &wset)))  {
	    /* There is explicit terminal input -- note this is only possible
	     * if fd is 0 (and we are in terminal mode!).
	     * We need to use stream API for this, which is why it
	     * is different */
	    if (fgets(buf, sizeof (buf) - 1, stdin) == NULL) {
		logout(&protocol->logout_cmd, 0);
		FD_CLR(0, &read_set);
	    } else {
		count = strlen(buf);
		/* If we read a full line, translate the newline */
		if (buf[count - 1] == '\n') {
		    buf[count - 1] = '\r';
		    buf[count] = '\n';
		    buf[count + 1] = '\0';
		    count++;
		}
		prot_write(pout, buf, count);
	    }
	    prot_flush(pout);
	} else if (FD_ISSET(sock, &rset) && (FD_ISSET(fd_out, &wset))) {
	    /* This does input from remote for all modes */
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
		if(output_socket)
		    write(fd_out, buf, count);
		else {
		    /* use the stream API */
		    buf[count] = '\0';
		    printf("%s", buf); 
		}
	    } while (pin->cnt > 0);
	} else if ((FD_ISSET(fd, &rset)) && (FD_ISSET(sock, &wset))
		   && (donewritingfile == 0)) {
	    /* This does input for both socket and file modes */
	    int numr = read(fd, buf, sizeof(buf));
	    
	    /* and send out over wire */
	    if (numr < 0)
	    {
		perror("read");
		imtest_fatal("read");
	    } else if (numr==0) {
		if(output_socket) {
		    if(protocol->reset) {
			if(protocol->reset(rock) != IMTEST_OK)
			    goto cleanup;
		    } else
			/* no protocol->reset, we're done */
			goto cleanup;
		    
		    close(fd);
		    fd = 0;
		    fd_out = 1;
		    goto accept_again;
		} else {
		    /* we're done, cleanup */
		    donewritingfile = 1;
		    
		    FD_CLR(fd,&read_set);
			
		    /* send LOGOUT */
		    logout(&protocol->logout_cmd, 0);
		}
	    } else {
		if (!output_socket) {
		    /* echo for the user - if not in socket mode */
		    write(1, buf, numr);
		} 

		if (output_socket && protocol->pipe) {
		    if(protocol->pipe(buf, numr, rock) == IMTEST_CLOSEME) {
			if(protocol->reset) {
			    if(protocol->reset(rock) != IMTEST_OK)
				goto cleanup;
			} else
			    /* no protocol->reset, we're done */
			    goto cleanup;
			
			close(fd);
			fd = 0;
			fd_out = 1;
			goto accept_again;
		    }
		} else {
		    /* echo to remote */
		    prot_write(pout, buf, numr);
		    prot_flush(pout);
		}
	    }
	} else {
	    /* if can't do anything else sleep */
	    usleep(1000);
	}
	
	/* received interrupt signal, logout */
	if (gotsigint) goto cleanup;
    }

 cleanup:
    if(rock) free(rock);

    if(output_socket && output_socket_opened) {
	struct stat sbuf;
	
	close(fd);
	close(listen_sock);

	if(stat(output_socket, &sbuf) != -1
	   && sbuf.st_ino == output_socket_ino) {
	    unlink(output_socket);
	}
    }
    
    logout(&protocol->logout_cmd, 0);
    close(sock);
    
    printf("Connection closed.\n");
    
    /* remove handler for SIGINT */
    signal(SIGINT, SIG_DFL);
    return;
}

static char *ask_capability(struct capa_cmd_t *capa_cmd,
			    int *supports_starttls, int automatic)
{
    char str[1024];
    char *ret = NULL, *tmp;
    
    *supports_starttls = 0;

    if (!automatic) {
	/* no capability command */
	if (!capa_cmd->cmd) return NULL;
	
	/* request capabilities of server */
	printf("C: %s\r\n", capa_cmd->cmd);
	prot_printf(pout, "%s\r\n", capa_cmd->cmd);
	prot_flush(pout);
    }

    do { /* look for the end of the capabilities */
	if (prot_fgets(str, sizeof(str), pin) == NULL) {
	    imtest_fatal("prot layer failure");
	}
	printf("S: %s", str);

	/* check for starttls */
	if (capa_cmd->tls &&
	    strstr(str, capa_cmd->tls) != NULL) {
	    *supports_starttls = 1;
	}
	
	/* check for auth */
	if (capa_cmd->auth &&
	    (tmp = strstr(str, capa_cmd->auth)) != NULL) {
	    if (capa_cmd->parse_mechlist)
		ret = capa_cmd->parse_mechlist(str);
	    else
		ret = strdup(tmp+strlen(capa_cmd->auth));
	}
    } while (strncasecmp(str, capa_cmd->resp, strlen(capa_cmd->resp)));
    
    return ret;
}

/* generic pipe functionality - break it into one line at a time, and
 * pass that into a per-protocol pipe function. */
struct generic_context_t 
{
    int (*pipe_oneline)(char *buf, int len, void *rock);
    void *rock;
    
    /* Deal with half-finished lines */
    char *midLine;
    size_t midLineLen;
};

static int generic_pipe(char *buf, int len, void *rock) 
{
    struct generic_context_t *text = (struct generic_context_t *)rock;
    char *toWrite = NULL, *toSend = NULL;
    int toWriteLen = 0;
    char *lineEnd = NULL;
    int ret = IMTEST_OK;

    /* do we have leftovers? -- if so, we append the new stuff */
    if(text->midLine) {
	text->midLine =
	    (char *)xrealloc(text->midLine, text->midLineLen+len+1);
	memcpy(text->midLine+text->midLineLen, buf, len);
	text->midLineLen += len;
	text->midLine[text->midLineLen] = '\0';
	
	toWrite = text->midLine;
	toWriteLen = text->midLineLen;
    } else {
	toWrite = buf;
	toWriteLen = len;
    }

    /* one line at a time now */
    while(toWrite && (lineEnd = memchr(toWrite, '\n', toWriteLen)) != NULL) {
	size_t len_todo;

	len_todo = lineEnd - toWrite + 1; /* +1 is to include the newline! */
	
	toSend = (char *)xrealloc(toSend, len_todo + 1);

	memcpy(toSend, toWrite, len_todo);
	toSend[len_todo] = '\0';

	ret = text->pipe_oneline(toSend, len_todo, text->rock);
	if(ret != IMTEST_OK) break;

	toWrite = lineEnd+1; /* +1 is to skip the newline! */
	toWriteLen -= len_todo; 

	if(toWriteLen <= 0) toWrite = NULL;

    }

    if(toWrite && ret == IMTEST_OK) {
	char *newMidLine;
	/* we need to save the leftover for next time */
	newMidLine = (char *)xmalloc(toWriteLen);
	memcpy(newMidLine, toWrite, toWriteLen);
	if(text->midLine) free(text->midLine);
	text->midLine = newMidLine;
	text->midLineLen = toWriteLen;
    } else if (text->midLine || ret != IMTEST_OK) {
	free(text->midLine);
	text->midLine = NULL;
	text->midLineLen = 0;
    }

    free(toSend);
    return ret;
}

/*********************************** IMAP ************************************/

/*
 * Parse a mech list of the form: ... AUTH=foo AUTH=bar ...
 *
 * Return: string with mechs separated by spaces
 *
 */

static char *imap_parse_mechlist(char *str)
{
    char *tmp;
    int num = 0;
    char *ret = malloc(strlen(str)+1);

    if (ret == NULL) return NULL;
    
    strcpy(ret, "");
    
    while ((tmp = strstr(str,"AUTH=")) != NULL) {
	char *end = tmp+5;
	tmp += 5;
	
	while(((*end) != ' ') && ((*end) != '\0'))
	    end++;
	
	(*end)='\0';
	
	/* add entry to list */
	if (num > 0)
	    strcat(ret, " ");
	strcat(ret, tmp);
	num++;
	
	/* reset the string */
	str = end+1;
    }
    
    return ret;
}

static int auth_login(void)
{
    char str[1024];
    /* we need username and password to do "login" */
    char *username;
    unsigned int userlen;
    char *pass;
    unsigned int passlen;
    char *tag = "L01 ";
    
    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &username, &userlen);
    interaction(SASL_CB_PASS, NULL, "Please enter your password",
		&pass, &passlen);
    
    printf("C: %sLOGIN %s {%d}\r\n", tag, username, passlen);
    prot_printf(pout,"%sLOGIN %s {%d}\r\n", tag, username, passlen);
    prot_flush(pout);
    
    if (!strncmp(waitfor("+", tag, 1), "+", 1)) {
	printf("C: <omitted>\r\n");
	prot_printf(pout,"%s\r\n", pass);
	prot_flush(pout);
	
	do {
	    if (prot_fgets(str, sizeof(str), pin) == NULL) {
		imtest_fatal("prot layer failure");
	    }
	    printf("S: %s", str);
	} while (strncmp(str, tag, strlen(tag)));
    }
    
    if (!strncasecmp(str+strlen(tag), "OK", 2)) {
	return IMTEST_OK;
    } else {
	return IMTEST_FAIL;
    }
}

static int imap_do_auth(struct sasl_cmd_t *sasl_cmd,
			void *rock __attribute__((unused)),
			char *mech, char *mechlist)
{
    int result = IMTEST_FAIL;

    if (mech) {
	if (!strcasecmp(mech, "login")) {
	    result = auth_login();
	} else {
	    result = auth_sasl(sasl_cmd, mech);
	}
    } else {
	if (mechlist) {
	    result = auth_sasl(sasl_cmd, mechlist);
	} else {
	    result = auth_login();
	}
    }

    return result;
}

struct imap_context_t 
{
    int inLiteral;
};

static int imap_pipe_oneline(char *buf, int len, void *rock) {
    struct imap_context_t *text = (struct imap_context_t *)rock;
    int add_crlf = 0; /* hack for terminals */

    if(text->inLiteral) {
	if(len <= text->inLiteral) {
	    text->inLiteral -= len;
	} else {
	    prot_write(pout, buf, text->inLiteral);
	    buf += text->inLiteral;
	    len -= text->inLiteral;
	    text->inLiteral = 0;
	}
    }

    if(!text->inLiteral) {
	char c, *tag, *cmd, *tmp, *sparebuf = (char *)xstrdup(buf);
	int i;
	tmp = sparebuf;

	if(len > 4 &&
	   buf[len-1] == '\n' && buf[len-1] == '\r' && buf[len-2] == '}') {
	    /* possible literal, with \r */
	    i = len-4;
	    while(i > 0 && buf[i] != '{' && isdigit((int)buf[i])) i--;
	    if(buf[i] == '{') text->inLiteral = atoi(buf + i + 1);
	} else if(len > 3 && buf[len-1] == '\n' && buf[len-2] == '}') {
	    /* possible literal, no \r -- hack for terminals*/
	    i = len-3;
	    while(i > 0 && buf[i] != '{' && isdigit((int)buf[i])) i--;
	    if(buf[i] == '{') text->inLiteral = atoi(buf + i + 1);
	}

	/* We could still have another special case! */
	c = imparse_word(&tmp, &tag);
	if(c == ' ') {
	    c = imparse_word(&tmp, &cmd);
	    if(c == '\n' || (c == '\r' && *tmp == '\n')){
		/* Are we logging out? */
		if(!strncasecmp(cmd, "LOGOUT", 6)) {
		    free(sparebuf);
		    return IMTEST_CLOSEME;
		}
	    }
	}

	free(sparebuf);

	/* If the remote is sending only \n, clean it up for them */
	if((len == 1 && buf[0] == '\n') ||
	   (len >= 2 && buf[len-2] != '\r')) {
	    len -= 1; /* truncate \n */
	    add_crlf = 1;
	}
    }

    prot_write(pout, buf, len);
    if(add_crlf) prot_write(pout, "\r\n", 2);
    prot_flush(pout);

    return IMTEST_OK;
}

static void * imap_init_conn(void) 
{
    struct generic_context_t *ret;
    
    ret =
	(void *)xmalloc(sizeof(struct generic_context_t));
    memset(ret, 0, sizeof(struct generic_context_t));

    ret->rock =
	(void *)xmalloc(sizeof(struct imap_context_t));
    memset(ret->rock, 0, sizeof(struct imap_context_t));

    ret->pipe_oneline = &imap_pipe_oneline;

    return ret;
}

static int imap_reset(void *rock) 
{
    struct generic_context_t *gentext = (struct generic_context_t *)rock;
    struct imap_context_t *text = (struct imap_context_t *)gentext->rock;
    char tag[64];
    static int i=0;

    if(text->inLiteral || gentext->midLine) return IMTEST_FAIL;

    snprintf(tag, sizeof(tag-1), "UN%d", i);
    prot_printf(pout, "%s UNSELECT\r\n", tag);
    prot_flush(pout);
    waitfor(tag, NULL, 0);

    return IMTEST_OK;
}
    
#define HEADERS "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n \
From: Fred Foobar <foobar@Blurdybloop.COM>\r\n \
Subject: afternoon meeting\r\n \
To: mooch@owatagu.siam.edu\r\n \
Message-Id: <B27397-0100000@Blurdybloop.COM>\r\n \
MIME-Version: 1.0\r\n \
Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n\r\n"

static int append_msg(char *mbox, int size)
{
    int lup;
    
    prot_printf(pout,"A003 APPEND %s (\\Seen) {%u}\r\n",mbox,size+strlen(HEADERS));
    /* do normal header foo */
    prot_printf(pout,HEADERS);
    
    for (lup=0;lup<size/10;lup++)
	prot_printf(pout,"0123456789");
    prot_printf(pout,"\r\n");
    
    prot_flush(pout);
    
    waitfor("A003", NULL, 1);
    
    return IMTEST_OK;
}

/**************
 *
 * This tests throughput of IMAP server
 *
 * Steps:
 *  Creat mailbox
 *  Append message of 200 bytes, 2000 bytes, 20k, 200k, 2M
 *  Delete mailbox
 *  
 *************/


static void send_recv_test(void)
{
    char *mboxname="inbox.imtest";
    time_t start, end;
    int lup;
    
    start=time(NULL);
    
    for (lup=0;lup<10;lup++)
	{
	    prot_printf(pout,"C01 CREATE %s\r\n",mboxname);
	    prot_flush(pout);  
	    waitfor("C01", NULL, 1);
	    
	    append_msg(mboxname,200);
	    append_msg(mboxname,2000);
	    append_msg(mboxname,20000);
	    append_msg(mboxname,200000);
	    append_msg(mboxname,2000000);
	    
	    prot_printf(pout,"D01 DELETE %s\r\n",mboxname);
	    prot_flush(pout);  
	    waitfor("D01", NULL, 1);
	}
    
    end=time(NULL);
    
    printf("took %ld seconds\n", end - start);
}

/*********************************** POP3 ************************************/

static void *pop3_parse_banner(char *str)
{
    char *cp, *start;
    char *chal = NULL;
    
    /* look for APOP challenge in banner '<...@...>' */
    cp = str+4;
    while (cp && (start = strchr(cp, '<'))) {
	cp = start + 1;
	while (*cp && *cp != '@' && *cp != '<' && *cp != '>') cp++;
	if (*cp != '@') continue;
	while (*cp && *cp != '<' && *cp != '>') cp++;
	if (*cp == '>') {
	    *(++cp) = '\0';
	    chal = strdup(start);
	    if (!chal) imtest_fatal("memory error");
	    break;
	}
    }

    return chal;
}

static int auth_user(void)
{
    char str[1024];
    /* we need username and password to do USER/PASS */
    char *username;
    unsigned int userlen;
    char *pass;
    unsigned int passlen;
    
    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &username, &userlen);
    interaction(SASL_CB_PASS, NULL, "Please enter your password",
		&pass, &passlen);
    
    printf("C: USER %s\r\n", username);
    prot_printf(pout,"USER %s\r\n", username);
    prot_flush(pout);
    
    if (prot_fgets(str, 1024, pin) == NULL) {
	imtest_fatal("prot layer failure");
    }
    
    printf("S: %s", str);
    
    if (strncasecmp(str, "+OK ", 4)) return IMTEST_FAIL;
    
    printf("C: PASS <omitted>\r\n");
    prot_printf(pout,"PASS %s\r\n",pass);
    prot_flush(pout);
    
    if (prot_fgets(str, 1024, pin) == NULL) {
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
    
    if (!apop_chal) {
	printf("[Server does not support APOP]\n");
	return IMTEST_FAIL;
    }

    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &username, &userlen);
    interaction(SASL_CB_PASS,NULL, "Please enter your password",
		&pass, &passlen);
    
    MD5_Init(&ctx);
    MD5_Update(&ctx,apop_chal,strlen(apop_chal));
    MD5_Update(&ctx,pass,passlen);
    MD5_Final(digest, &ctx);
    
    /* convert digest from binary to ASCII hex */
    for (i = 0; i < 16; i++)
	sprintf(digeststr + (i*2), "%02x", digest[i]);
    
    printf("C: APOP %s %s\r\n", username, digeststr);
    prot_printf(pout,"APOP %s %s\r\n", username, digeststr);
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

static int pop3_do_auth(struct sasl_cmd_t *sasl_cmd, void *rock,
			char *mech, char *mechlist)
{
    int result = IMTEST_FAIL;
    
    if (mech) {
	if (!strcasecmp(mech, "apop")) {
	    result = auth_apop((char *) rock);
	} else if (!strcasecmp(mech, "user")) {
	    result = auth_user();
	} else {
	    result = auth_sasl(sasl_cmd, mech);
	}
    } else {
	if (mechlist) {
	    result = auth_sasl(sasl_cmd, mechlist);
	} else if (rock) {
	    result = auth_apop((char *) rock);
	} else {
	    result = auth_user();
	}
    }

    return result;
}

/******************************** LMTP/SMTP **********************************/

static int xmtp_do_auth(struct sasl_cmd_t *sasl_cmd,
			void *rock __attribute__((unused)),
			char *mech, char *mechlist)
{
    int result = IMTEST_OK;

    if (mech) {
	result = auth_sasl(sasl_cmd, mech);
    } else if (mechlist) {
	result = auth_sasl(sasl_cmd, mechlist);
    }

    return result;
}

struct xmtp_context_t 
{
    int inData;
};

/* This takes a NUL-terminated full line (including any trailing \r\n) */
static int xmtp_pipe_oneline(char *buf, int len, void *rock) {
    struct xmtp_context_t *text = (struct xmtp_context_t *)rock;

    if(text->inData && len <= 3) {
	if(buf[0] == '.' &&
	   (buf[1] == '\n' || (buf[1] == '\r' && buf[2] == '\n'))) {
	    text->inData = 0;
	}
    } else if(!text->inData && len > 4 && len <= 6) {
	if(!strncasecmp(buf, "DATA", 4) &&
	   (buf[4] == '\n' || (buf[4] == '\r' && buf[5] == '\n'))) {
	    text->inData = 1;
	} else if(!strncasecmp(buf, "QUIT", 4) &&
	   (buf[4] == '\n' || (buf[4] == '\r' && buf[5] == '\n'))) {
	    return IMTEST_CLOSEME;
	}
    }
        
    prot_write(pout, buf, len);
    prot_flush(pout);

    return IMTEST_OK;
}

static void *xmtp_init_conn(void) 
{
    struct generic_context_t *ret;
    
    ret =
	(void *)xmalloc(sizeof(struct generic_context_t));
    memset(ret, 0, sizeof(struct generic_context_t));

    ret->rock =
	(void *)xmalloc(sizeof(struct xmtp_context_t));
    memset(ret->rock, 0, sizeof(struct xmtp_context_t));
    
    ret->pipe_oneline = &xmtp_pipe_oneline;

    return ret;
}

static int xmtp_reset(void *rock) 
{
    struct generic_context_t *gentext = (struct generic_context_t *)rock;
    struct xmtp_context_t *text = (struct xmtp_context_t *)gentext->rock;

    if(text->inData || gentext->midLine) return IMTEST_FAIL;

    prot_printf(pout, "RSET\r\n");
    prot_flush(pout);
    waitfor("250", NULL, 1);

    return IMTEST_OK;
}


/******************************** MUPDATE ************************************/


/********************************* SIEVE *************************************/

static char *sieve_parse_success(char *str)
{
    char *success = NULL, *tmp;

    if (!strncmp(str, "OK (", 4) &&
	(tmp = strstr(str+4, "SASL \"")) != NULL) {
	success = tmp+6; /* skip SASL " */
	tmp = strstr(success, "\"");
	*tmp = '\0'; /* clip " */
    }

    return success;
}

/*****************************************************************************/

/* didn't give correct parameters; let's exit */
void usage(char *prog, char *prot)
{
    printf("Usage: %s [options] hostname\n", prog);
    printf("  -p port  : port to use (default=standard port for protocol)\n");
    if (!strcasecmp(prot, "imap"))
	printf("  -z       : timing test\n");
    printf("  -k #     : minimum protection layer required\n");
    printf("  -l #     : max protection layer (0=none; 1=integrity; etc)\n");
    printf("  -u user  : authorization name to use\n");
    printf("  -a user  : authentication name to use\n");
    printf("  -w pass  : password to use (if not supplied, we will prompt)\n");
    printf("  -v       : verbose\n");
    printf("  -m mech  : SASL mechanism to use\n");
    if (!strcasecmp(prot, "imap"))
	printf("             (\"login\" for IMAP LOGIN)\n");
    if (!strcasecmp(prot, "pop3"))
	printf("             (\"user\" for USER/PASS, \"apop\" for APOP)\n");
    printf("  -f file  : pipe file into connection after authentication\n");
    printf("  -r realm : realm\n");
#ifdef HAVE_SSL
    if (!strcasecmp(prot, "imap") || !strcasecmp(prot, "pop3") ||
	!strcasecmp(prot, "smtp"))
	printf("  -s       : Enable %s over SSL (%ss)\n", prot, prot);
    if (strcasecmp(prot, "mupdate"))
	printf("  -t file  : Enable TLS. file has the TLS public and private keys\n"
	       "             (specify \"\" to not use TLS for authentication)\n");
#endif /* HAVE_SSL */
    printf("  -c       : enable challenge prompt callbacks\n"
	   "             (enter one-time password instead of secret pass-phrase)\n");
    printf("  -n       : number of auth attempts (default=1)\n");
    printf("  -I file  : output my PID to (file) (useful with -X)\n");
    printf("  -x file  : open the named socket for the interactive portion\n");
    printf("  -X file  : same as -X, except close all file descriptors & dameonize\n");
    
    exit(1);
}


static struct protocol_t protocols[] = {
    { "imap", "imaps", "imap",
      { 0, "* OK", NULL },
      { "C01 CAPABILITY", "C01 ", "STARTTLS", "AUTH=", &imap_parse_mechlist },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0, NULL, NULL, "A01 OK", "A01 NO", "+ ", "*" },
      &imap_do_auth, { "Q01 LOGOUT", "Q01 " },
      &imap_init_conn, &generic_pipe, &imap_reset
    },
    { "pop3", "pop3s", "pop",
      { 0, "+OK ", &pop3_parse_banner },
      { "CAPA", ".", "STLS", "SASL ", NULL },
      { "STLS", "+OK", "-ERR", 0 },
      { "AUTH", 0, "=", NULL, "+OK", "-ERR", "+ ", "*" },
      &pop3_do_auth, { "QUIT", "+OK" }, NULL, NULL, NULL
    },
    { "lmtp", NULL, "lmtp",
      { 0, "220 ", NULL },
      { "LHLO example.com", "250 ", "STARTTLS", "AUTH ", NULL },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 0, "=", NULL, "235", "5", "334 ", "*" },
      &xmtp_do_auth, { "QUIT", "221" },
      &xmtp_init_conn, &generic_pipe, &xmtp_reset
    },
    { "smtp", "smtps", "smtp",
      { 0, "220 ", NULL },
      { "EHLO example.com", "250 ", "STARTTLS", "AUTH ", NULL },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 0, "=", NULL, "235", "5", "334 ", "*" },
      &xmtp_do_auth, { "QUIT", "221" },
      &xmtp_init_conn, &generic_pipe, &xmtp_reset
    },
    { "mupdate", NULL, "mupdate",
      { 1, "* OK", NULL },
      { NULL , "* OK", NULL, "* AUTH ", NULL },
      { NULL },
      { "A01 AUTHENTICATE", 1, "=", NULL, "A01 OK", "A01 NO", "", "*" },
      NULL, { "Q01 LOGOUT", "Q01 " }, NULL, NULL, NULL
    },
    { "sieve", NULL, SIEVE_SERVICE_NAME,
      { 1, "OK", NULL },
      { "CAPABILITY", "OK", "\"STARTTLS\"", "\"SASL\" ", NULL },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", 1, "=", &sieve_parse_success, "OK", "NO", NULL, "*" },
      NULL, { "LOGOUT", "OK" }, NULL, NULL, NULL
    },
    { NULL }
};

int main(int argc, char **argv)
{
    struct protocol_t *protocol;
    char *mechanism = NULL;
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
    
    char *prog;
    char *tls_keyfile="";
    char *port = "", *prot = "";
    struct servent *serv;
    int servport;
    int run_stress_test=0;
    int dotls=0, dossl=0;
    int server_supports_tls;
    char str[1024];
    const char *pidfile = NULL;
    void *rock = NULL;
    int reauth = 1;
    int dochallenge = 0;
    
    struct stringlist *cur, *cur_next;
    
    /* do not buffer */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    prog = strrchr(argv[0], '/') ? strrchr(argv[0], '/')+1 : argv[0];

    /* look at all the extra args */
    while ((c = getopt(argc, argv, "P:sczvk:l:p:u:a:m:f:r:t:n:I:x:X:w:?")) != EOF)
	switch (c) {
	case 'P':
	    prot = optarg;
	    break;
	case 's':
#ifdef HAVE_SSL
	    dossl=1;
#else
	    imtest_fatal("imtest was not compiled with SSL/TLS support\n");
#endif
	    break;
	case 'c':
	    dochallenge=1;
	    break;
	case 'z':
	    run_stress_test=1;
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
	case 'w':
	    cmdline_password = optarg;
	    break;
	case 'm':
	    mechanism=optarg;
	    break;
	case 'f':
	    if(output_socket)
		imtest_fatal("cannot pipe a file when using unix domain socket output");
	    filename=optarg;
	    break;
	case 'r':
	    realm=optarg;
	    break;
	case 't':
#ifdef HAVE_SSL
	    dotls=1;
	    tls_keyfile=optarg;
#else
	    imtest_fatal("imtest was not compiled with SSL/TLS support\n");
#endif
	    break;
	case 'n':
	    reauth = atoi(optarg);
	    if (reauth <= 0)
		imtest_fatal("number of auth attempts must be > 0\n");
	    break;
	case 'I':
	    pidfile = optarg;
	    break;
	case 'X':
	case 'x':
	    if(filename)
		imtest_fatal("cannot pipe a file when using unix domain socket output");
	    if(output_socket)
		imtest_fatal("cannot specify both -X and -x");
	    
	    output_socket = optarg;

	    if(c == 'X'){
		/* close all already-open file descriptors that are
		 * not stdin/stdout/stderr */
		int i, dsize = getdtablesize();

		/* close all file descriptors */
		for(i=0; i<dsize; i++) close(i);

		/* background ourselves and lose the process group info */
		for(i=0;i<3;i++) if(fork()) exit(0);
	    }
	    
	    break;
	case '?':
	default:
	    errflg = 1;
	    break;
	}
    
    if (optind != argc - 1) {
	errflg = 1;
    }
    
    if (!*prot) {
	if (!strcasecmp(prog, "imtest"))
	    prot = "imap";
	else if (!strcasecmp(prog, "pop3test"))
	    prot = "pop3";
	else if (!strcasecmp(prog, "lmtptest"))
	    prot = "lmtp";
	else if (!strcasecmp(prog, "smtptest"))
	    prot = "smtp";
	else if (!strcasecmp(prog, "mupdatetest"))
	    prot = "mupdate";
	else if (!strcasecmp(prog, "sivtest"))
	    prot = "sieve";
    }

    protocol = protocols;
    while (protocol->protocol && strcasecmp(prot, protocol->protocol))
	protocol++;

    if (!protocol->protocol)
	imtest_fatal("unknown protocol\n");
    
    if (dossl && !protocol->sprotocol)
	imtest_fatal("protocol can not be SSL-wrapped\n");

    if (run_stress_test && strcmp(protocol->protocol, "imap"))
	imtest_fatal("stress test can only be run for IMAP\n");

    if (errflg) {
	usage(prog, protocol->protocol);
    }

    if (!*port) {
	if (dossl) {
	    port=protocol->sprotocol;
	} else {
	    port=protocol->protocol;
	}
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

    if(pidfile) {
	FILE *pf;
	pf = fopen(pidfile, "w");  
	if(!pf) {
	    fprintf(stderr, "could not open %s for writing\n",pidfile);
	    perror("error");
	    exit(1);
	}
	fprintf(pf, "%d", getpid());
	fclose(pf);
    } 
    
    /* attempt to start sasl */
    if (sasl_client_init(callbacks+(!dochallenge ? 2 : 0)) != IMTEST_OK) {
	imtest_fatal("SASL initialization");
    }

    conn = NULL;
    do {
	if (conn) {
	    /* send LOGOUT */
	    logout(&protocol->logout_cmd, 1);
	    printf("Connection closed.\n\n");
	    
	    prot_free(pin);
	    prot_free(pout);
	    
	    close(sock);
	    
	    sasl_dispose(&conn);
	}

	if (init_net(servername, servport) != IMTEST_OK) {
	    imtest_fatal("Network initialization");
	}
    
	if (init_sasl(protocol->service, servername, minssf, maxssf,
		      protocol->sasl_cmd.parse_success ?
		      SASL_SUCCESS_DATA : 0) != IMTEST_OK) {
	    imtest_fatal("SASL initialization");
	}
	
	/* set up the prot layer */
	pin = prot_new(sock, 0);
	pout = prot_new(sock, 1); 
	
#ifdef HAVE_SSL
	if (dossl==1) {
	    do_starttls(1, "", &ext_ssf);
	}
#endif /* HAVE_SSL */

	if (protocol->banner.is_capa) {
	    mechlist = ask_capability(&protocol->capa_cmd,
				      &server_supports_tls, 1);
	}
	else {
	    do { /* look for the banner response */
		if (prot_fgets(str, sizeof(str), pin) == NULL) {
		    imtest_fatal("prot layer failure");
		}
		printf("S: %s", str);
		
		/* parse it if need be */
		if (protocol->banner.parse_banner)
		    rock = protocol->banner.parse_banner(str);
	    } while (strncasecmp(str, protocol->banner.resp,
				 strlen(protocol->banner.resp)));
	
	    mechlist = ask_capability(&protocol->capa_cmd,
				      &server_supports_tls, 0);
	}
	
#ifdef HAVE_SSL
	if ((dossl==0) && (dotls==1) && (server_supports_tls==1)) {
	    char *resp;

	    printf("C: %s\r\n", protocol->tls_cmd.cmd);
	    prot_printf(pout, "%s\r\n", protocol->tls_cmd.cmd);
	    prot_flush(pout);
	    
	    resp = waitfor(protocol->tls_cmd.ok, protocol->tls_cmd.fail, 1);
	    
	    if (!strncasecmp(resp, protocol->tls_cmd.ok,
			     strlen(protocol->tls_cmd.ok))) {

		do_starttls(0, tls_keyfile, &ext_ssf);
		
		/* ask for the capabilities again */
		if (verbose==1)
		    printf("Asking for capabilities again "
			   "since they might have changed\n");
		if (mechlist) free(mechlist);
		mechlist = ask_capability(&protocol->capa_cmd,
					  &server_supports_tls,
					  protocol->tls_cmd.auto_capa);
	    }
	    
	} else if ((dotls==1) && (server_supports_tls!=1)) {
	    imtest_fatal("STARTTLS not supported by the server!\n");
	}
#endif /* HAVE_SSL */

	if (protocol->do_auth)
	    result = protocol->do_auth(&protocol->sasl_cmd, rock,
				       mechanism, mechlist);
	else {
	    if (mechanism) {
		result = auth_sasl(&protocol->sasl_cmd, mechanism);
	    } else if (mechlist) {
		result = auth_sasl(&protocol->sasl_cmd, mechlist);
	    } else {
		result = IMTEST_FAIL;
	    }
	}
	
	if (rock) free(rock);
	if (mechlist) free(mechlist);
	
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

    } while (--reauth);

    if (run_stress_test == 1) {
	send_recv_test();
    } else {
	/* else run in interactive mode or 
	   pipe in a filename if applicable */
	interactive(protocol, filename);
    }
    
    for (cur = strlist_head; cur; cur = cur_next) {
	cur_next = cur->next;
	free(cur->str);
	free(cur);
    }
    
    exit(0);
}
