/* imtest.c -- IMAP/POP3/NNTP/LMTP/SMTP/MUPDATE/MANAGESIEVE test client
 * Ken Murchison (multi-protocol implementation)
 * Tim Martin (SASL implementation)
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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

#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "hash.h"
#include "imparse.h"
#include "iptostring.h"
#include "md5.h"
#include "prot.h"
#include "retry.h"
#include "strarray.h"
#include "stristr.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#ifdef HAVE_SSL
#include <openssl/ssl.h>

static SSL_CTX *tls_ctx = NULL;
static SSL *tls_conn = NULL;
static SSL_SESSION *tls_sess = NULL;

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
static sasl_conn_t *conn;
static int sock; /* socket descriptor */

static int verbose=0;

static struct protstream *pout, *pin;

static char *authname = NULL;
static char *username = NULL;
static char *realm = NULL;
static char *cmdline_password = NULL;

static char *output_socket = NULL;
static int output_socket_opened = 0;
static ino_t output_socket_ino = 0;

#define CONFIGHASHSIZE 30 /* relatively small */

static struct hash_table confighash;
static int mysasl_config(void*, const char*, const char*, const char**, unsigned*);

extern int _sasl_debug;
extern char *optarg;

static strarray_t stashed_strings = STRARRAY_INITIALIZER;

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
#if GCC_VERSION >= 80000
        SASL_CB_GETOPT, (void*)&mysasl_config, NULL
#else
        SASL_CB_GETOPT, (int (*)(void))&mysasl_config, NULL
#endif
    }, {
        SASL_CB_LIST_END, NULL, NULL
    }
};

struct protocol_t;

struct banner_t {
    u_char is_capa;     /* banner is capability response */
    char *resp;         /* end of banner response */
    void *(*parse_banner)(char *str);
                        /* [OPTIONAL] parse banner, returns 'rock' */
};

struct capa_cmd_t {
    char *cmd;          /* capability command string (NULL = no capa cmd) */
    char *resp;         /* end of capability response */
    char *tls;          /* [OPTIONAL] TLS capability string */
    char *login;        /* [OPTIONAL] plaintext login cmd capability string */
    char *auth;         /* [OPTIONAL] AUTH (SASL) capability string */
    char *compress;     /* [OPTIONAL] COMPRESS capability string */
    void (*parse_mechlist)(struct buf *list, const char *str,
                           struct protocol_t *prot, unsigned long *capabilities);
                        /* [OPTIONAL] parse capability string,
                           returns space-separated list of mechs */
};

struct tls_cmd_t {
    char *cmd;          /* tls command string */
    char *ok;           /* start tls prompt */
    char *fail;         /* failure response */
    u_char auto_capa;   /* capability response sent automatically after TLS */
};

struct sasl_cmd_t {
    char *cmd;          /* auth command string */
    u_short maxlen;     /* maximum command line length,
                           (0 = initial response unsupported by protocol) */
    u_char quote;       /* quote arguments (literal for base64 data) */
    char *ok;           /* success response string */
    char *fail;         /* failure response string */
    char *cont;         /* continue response string
                           (NULL = send/receive literals) */
    char *cancel;       /* cancel auth string */
    char *(*parse_success)(char *str);
                        /* [OPTIONAL] parse response for success data */
    u_char auto_capa;   /* capability response sent automatically
                           after AUTH with SASL security layer */
};

struct compress_cmd_t {
    char *cmd;          /* compress command string */
    char *ok;           /* success response string */
    char *fail;         /* failure response string */
};

struct logout_cmd_t {
    char *cmd;          /* logout command string */
    char *resp;         /* logout response */
};

struct protocol_t {
    char *protocol;     /* protocol service name */
    char *sprotocol;    /* SSL-wrapped service name (NULL = unsupported) */
    char *service;      /* SASL service name */
    int login_enabled;  /* [OPTIONAL] login command on/off by default;
                           toggled by capability string */
    struct banner_t banner;
    struct capa_cmd_t capa_cmd;
    struct tls_cmd_t tls_cmd;
    struct sasl_cmd_t sasl_cmd;
    struct compress_cmd_t compress_cmd;
    int (*do_auth)(struct sasl_cmd_t *sasl_cmd, void *rock,
                   int login_enabled, char *mech, const char *mechlist);
                        /* [OPTIONAL] perform protocol-specific authentication;
                           based on rock, login_enabled, mech, mechlist */
    struct logout_cmd_t logout_cmd;
    char *unauth_cmd;

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


static void
__attribute__((noreturn, format(printf, 1, 2)))
imtest_fatal(const char *msg, ...)
{
    struct stat sbuf;
    if (output_socket && output_socket_opened &&
        stat(output_socket, &sbuf) != -1 &&
        sbuf.st_ino == output_socket_ino) {
        unlink(output_socket);
    }
    if (msg != NULL) {
        va_list ap;
        va_start(ap, msg);
        fprintf(stderr, "failure: ");
        vfprintf(stderr, msg, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }
    exit(1);
}

/* libcyrus makes us define this */
EXPORTED void fatal(const char *msg, int code __attribute__((unused)))
{
    imtest_fatal("%s", msg);
}

int mysasl_config(void *context __attribute__((unused)),
                  const char *plugin_name,
                  const char *option,
                  const char **result,
                  unsigned *len)
{
    *result = NULL;

    if (plugin_name) {
        /* first try it with the plugin name */
        char opt[1024];

        strlcpy(opt, plugin_name, sizeof(opt));
        strlcat(opt, "_", sizeof(opt));
        strlcat(opt, option, sizeof(opt));
        *result = hash_lookup(opt, &confighash);
    }

    if (*result == NULL) {
        /* try without the plugin name */
        *result = hash_lookup(option, &confighash);
    }

    if (*result != NULL) {
        if (len) { *len = strlen(*result); }
        return SASL_OK;
    }

    return SASL_FAIL;
}

#ifdef HAVE_SSL

static int verify_depth;
static int verify_error = X509_V_OK;
static int do_dump = 0;

#define CCERT_BUFSIZ 256
static char peer_CN[CCERT_BUFSIZ];
static char issuer_CN[CCERT_BUFSIZ];

static char   *tls_peer_CN = NULL;
static char   *tls_issuer_CN = NULL;

static const char *tls_protocol = NULL;
static const char *tls_cipher_name = NULL;
static int      tls_cipher_usebits = 0;
static int      tls_cipher_algbits = 0;

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
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
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
    switch (err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
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


#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* taken from OpenSSL apps/s_cb.c */
static RSA *tmp_rsa_cb(SSL * s __attribute__((unused)),
                       int export __attribute__((unused)), int keylength)
{
    static RSA *rsa_tmp = NULL;

    if (rsa_tmp == NULL) {
        rsa_tmp = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    }
    return (rsa_tmp);
}
#endif

/* taken from OpenSSL apps/s_cb.c
 * tim - this seems to just be giving logging messages
 */

static void apps_ssl_info_callback(const SSL * s, int where, int ret)
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


static char *var_tls_CAfile="";
static char *var_tls_CApath="";
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    tls_ctx = SSL_CTX_new(TLS_client_method());
#else
    tls_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
    if (tls_ctx == NULL) {
        return IMTEST_FAIL;
    };

    off |= SSL_OP_ALL;            /* Work around all known bugs */
    off |= SSL_OP_NO_SSLv2;       /* Disable insecure SSLv2 */
    off |= SSL_OP_NO_SSLv3;       /* Disable insecure SSLv3 */
    off |= SSL_OP_NO_COMPRESSION; /* Disable TLS compression */
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
            printf("TLS engine: cannot load cert/key data, may be a cert/key mismatch?\n");
            return IMTEST_FAIL;
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX_set_tmp_rsa_callback(tls_ctx, tmp_rsa_cb);
#endif

    verify_depth = verifydepth;
    SSL_CTX_set_verify(tls_ctx, verify_flags, verify_callback);

    return IMTEST_OK;
}

/*
 * taken from OpenSSL crypto/bio/b_dump.c, modified to save a lot of strcpy
 * and strcat by Matti Aarnio.
 */

#define TRUNCATE
#define DUMP_WIDTH      16

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
        buf[0] = '\0';                          /* start with empty string */
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
                        long argl __attribute__((unused)), long ret)
{
    if (!do_dump)
        return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
        printf("read from %08lX [%08lX] (%d bytes => %ld (0x%lX))\n",
               (unsigned long) bio, (unsigned long) argp,
               argi, ret, ret);
        tls_dump(argp, (int) ret);
        return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
        printf("write to %08lX [%08lX] (%d bytes => %ld (0x%lX))\n",
               (unsigned long) bio, (unsigned long) argp,
               argi, ret, ret);
        tls_dump(argp, (int) ret);
    }
    return (ret);
}

static int tls_start_clienttls(unsigned *layer, char **authid)
{
    int     sts;
    const SSL_CIPHER *cipher;
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
        SSL_SESSION *currsess;

        printf("SSL_connect error %d\n", sts);
        currsess = SSL_get_session(tls_conn);
        if (currsess) {
            SSL_CTX_remove_session(tls_ctx, currsess);
            printf("SSL session removed\n");
        }
        if (tls_sess) {
            SSL_SESSION_free(tls_sess);
            tls_sess = NULL;
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

static void do_starttls(int ssl, char *keyfile, unsigned *ssf)
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

    /* TLS negotiation succeeded */
    if (tls_sess)
        SSL_SESSION_free(tls_sess);
    tls_sess = SSL_get1_session(tls_conn); /* Save the session for reuse */

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

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    static unsigned char finished[EVP_MAX_MD_SIZE];
    static struct sasl_channel_binding cbinding;

    if (SSL_session_reused(tls_conn)) {
        cbinding.len = SSL_get_peer_finished(tls_conn,
                                             finished, sizeof(finished));
    }
    else {
        cbinding.len = SSL_get_finished(tls_conn, finished, sizeof(finished));
    }

    cbinding.name = "tls-unique";
    cbinding.critical = 0;
    cbinding.data = finished;

    result = sasl_setprop(conn, SASL_CHANNEL_BINDING, &cbinding);
    if (result!=SASL_OK)
        imtest_fatal("Error setting SASL property (channel binding)");
#endif /* (OPENSSL_VERSION_NUMBER >= 0x0090800fL) */

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
    struct sockaddr_storage saddr_l;
    struct sockaddr_storage saddr_r;

    addrsize=sizeof(struct sockaddr_storage);
    if (getpeername(sock,(struct sockaddr *)&saddr_r,&addrsize)!=0)
        return IMTEST_FAIL;

    addrsize=sizeof(struct sockaddr_storage);
    if (getsockname(sock,(struct sockaddr *)&saddr_l,&addrsize)!=0)
        return IMTEST_FAIL;

    if(iptostring((struct sockaddr *)&saddr_l, addrsize, localip, 60))
        return IMTEST_FAIL;

    if(iptostring((struct sockaddr *)&saddr_r, addrsize, remoteip, 60))
        return IMTEST_FAIL;


    /* client new connection */
#if defined(SASL_NEED_HTTP) && defined(SASL_HTTP_REQUEST)
    if (!strcasecmp(service, "HTTP")) flags |= SASL_NEED_HTTP;
#endif

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

static imt_stat getauthline(struct sasl_cmd_t *sasl_cmd, char **line, int *linelen)
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
        /* trim CRLF */
        char *p = str + strlen(str) - 1;
        if (p >= str && *p == '\n') *p-- = '\0';
        if (p >= str && *p == '\r') *p-- = '\0';

        /* alloc space for decoded response */
        len = strlen(str) + 1;
        *line = malloc(len);
        if ((*line) == NULL) {
            return STAT_NO;
        }

        /* decode this line */
        saslresult = sasl_decode64(str, strlen(str),
                                   *line, len, (unsigned *) linelen);
        if (saslresult != SASL_OK && saslresult != SASL_CONTINUE) {
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

static void interaction (int id, const char *challenge, const char *prompt,
                  char **tresult, unsigned int *tlen)
{
    char *s;
    char result[1024];

    if (id==SASL_CB_PASS && !cmdline_password) {
        printf("%s: ", prompt);
        s = xstrdup(cyrus_getpass(""));
        strarray_appendm(&stashed_strings, s);
        *tlen = strlen(s);
        *tresult = s;
        return;
    } else if (id==SASL_CB_PASS && cmdline_password) {
        strcpy(result, cmdline_password);
    } else if (id==SASL_CB_USER) {
        if (username != NULL) {
            strcpy(result, username);
        } else {
            strcpy(result, "");
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

        if (((id==SASL_CB_ECHOPROMPT) || (id==SASL_CB_NOECHOPROMPT)) &&
            (challenge != NULL)) {
            printf("Server challenge: %s\n", challenge);
        }
        printf("%s: ",prompt);
        if (id==SASL_CB_NOECHOPROMPT) {
            strcpy(result, cyrus_getpass(""));
        } else {
            result[0] = '\0';
            if (fgets(result, sizeof(result) - 1, stdin) != NULL) {
                c = strlen(result);
                result[c - 1] = '\0';
            }
        }
    }

    s = xstrdup(result);
    strarray_appendm(&stashed_strings, s);
    *tlen = strlen(s);
    *tresult = s;
}

static void fillin_interactions(sasl_interact_t *tlist)
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

    if (echo) {
        /* pipe any responses remaining after tagged response */
        char str2[1024] = "";

        prot_NONBLOCK(pin);
        while (prot_fgets(str2, sizeof(str2), pin)) {
            printf("S: %s", str2);
        }
        prot_BLOCK(pin);
    }

    return str;
}

static int auth_sasl(struct sasl_cmd_t *sasl_cmd, const char *mechlist)
{
    sasl_interact_t *client_interact = NULL;
    int saslresult;
    const char *out = NULL;
    unsigned int outlen = 0;
    char *in;
    int inlen;
    const char *mechusing;
    char inbase64[4096];
    int inbase64len;
    char cmdbuf[40];
    int sendliteral;
    int initial_response = 1;
    imt_stat status;

    if (!sasl_cmd || !sasl_cmd->cmd) return IMTEST_FAIL;
    sendliteral = sasl_cmd->quote;

    do { /* start authentication */
        saslresult = sasl_client_start(conn, mechlist, &client_interact,
                                       /* do we support initial response? */
                                       sasl_cmd->maxlen ? &out : NULL,
                                       &outlen, &mechusing);

        if (saslresult == SASL_INTERACT)
            fillin_interactions(client_interact); /* fill in prompts */
    } while (saslresult == SASL_INTERACT);

    if ((saslresult != SASL_OK) && (saslresult != SASL_CONTINUE)) {
        return saslresult;
    }

    /* build the auth command */
    if (sasl_cmd->quote) {
        sprintf(cmdbuf, "%s \"%s\"", sasl_cmd->cmd, mechusing);
    }
    else {
        sprintf(cmdbuf, "%s %s", sasl_cmd->cmd, mechusing);
    }
    printf("C: %s", cmdbuf);
    prot_printf(pout, "%s", cmdbuf);

    if (out) { /* initial response */
        if (!outlen) { /* empty initial response */
            printf(" =");
            prot_printf(pout, " =");

            out = NULL;
        }
        else if (!sendliteral &&
                 ((int) (strlen(cmdbuf) + outlen + 3) > sasl_cmd->maxlen)) {
            /* initial response is too long for auth command,
               so wait for a server challenge before sending it */
            goto noinitresp;
        }
        else { /* full response -- encoded below */
            printf(" ");
            prot_printf(pout, " ");
        }
    } else {
        goto noinitresp;
    }

    do {
        if (out) { /* response */
            /* convert to base64 */
            saslresult = sasl_encode64(out, outlen, inbase64, sizeof(inbase64),
                                       (unsigned *) &inbase64len);
            if (saslresult != SASL_OK) return saslresult;

            /* send to server */
            if (sendliteral) {
                printf("%s{%d+}\r\n",
                       initial_response ? "" : "C: ", inbase64len);
                prot_printf(pout, "{%d+}\r\n", inbase64len);
                prot_flush(pout);
            }
            printf("%s%s", initial_response ? "" : "C: ", inbase64);
            prot_write(pout, inbase64, inbase64len);

            out = NULL;
        } else if (sendliteral) {
            /* If we had no response, we still need to send the
               empty literal in this case */
            printf("{0+}\r\nC: ");
            prot_printf(pout, "{0+}\r\n");
        } else if (!initial_response) {
            printf("C: ");
        }
      noinitresp:
        initial_response = 0;

        printf("\r\n");
        prot_printf(pout, "\r\n");
        prot_flush(pout);

        /* get challenge/reply from the server */
        status = getauthline(sasl_cmd, &in, &inlen);

        if ((status == STAT_CONT || (status == STAT_OK && in)) &&
            (inlen || !out)) { /* no delayed initial response */
            do { /* do the next step */
                saslresult = sasl_client_step(conn, in, inlen,
                                              &client_interact,
                                              &out, &outlen);

                if (saslresult == SASL_INTERACT)
                    fillin_interactions(client_interact); /* fill in prompts */
            } while (saslresult == SASL_INTERACT);

            if (in) free(in);
        }

        if ((saslresult != SASL_OK) && (saslresult != SASL_CONTINUE)) {
            /* cancel the exchange */
            printf("C: %s\r\n", sasl_cmd->cancel);
            prot_printf(pout, "%s\r\n", sasl_cmd->cancel);
            prot_flush(pout);

            return saslresult;
        }

        sendliteral = !sasl_cmd->cont;

    } while (status == STAT_CONT);

    return (status == STAT_OK) ? IMTEST_OK : IMTEST_FAIL;
}

/* initialize the network */
static int init_net(char *serverFQDN, char *port)
{
    struct addrinfo hints, *res0 = NULL, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    if ((err = getaddrinfo(serverFQDN, port, &hints, &res0)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return IMTEST_FAIL;
    }

    if (res0->ai_canonname)
        strncpy(serverFQDN, res0->ai_canonname, 1023);
    for (res = res0; res; res = res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, res->ai_addr, res->ai_addrlen) >= 0)
            break;
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res0);
    if(sock < 0) {
        perror("connect");
        return IMTEST_FAIL;
    }

    return IMTEST_OK;
}

static void logout(struct logout_cmd_t *logout_cmd, int wait)
{
    if (!logout_cmd->cmd) return;

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

static int haveinput(struct protstream *s)
{
    /* Is something currently pending in our protstream's buffer? */
#ifdef HAVE_SSL
    if (s->cnt == 0 && s->tls_conn != NULL) {
        /* Maybe there's data pending in the SSL buffer? */
        int n = SSL_pending(s->tls_conn);
        if (verbose) printf("SSL_pending=%d\n", n);
        return n;
    }
#endif
    return s->cnt;
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
        strlcpy(sunsock.sun_path, output_socket, sizeof(sunsock.sun_path));
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

    nfds = fd;
    if (nfds < sock) nfds = sock;
    if (nfds < fd_out) nfds = fd_out;
    nfds++;

    if (filename != NULL) {
        donewritingfile = 0;
    }

    /* add handler for SIGINT */
    signal(SIGINT, sigint_handler);

    /* loop reading from network and from stdin as applicable */
    int unauth = 0;
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
                /* If we read a full line, translate the newline
                 * if necessary. */
                if (buf[count - 1] == '\n' && (count < 2 || buf[count - 2] != '\r')) {
                    buf[count - 1] = '\r';
                    buf[count] = '\n';
                    buf[count + 1] = '\0';
                    count++;
                }
                prot_write(pout, buf, count);

                if (protocol->unauth_cmd) {
                    /* Check if unauthenticate command was sent */
                    char *p = stristr(buf, protocol->unauth_cmd);

                    if (p && !strcmp("\r\n", p + strlen(protocol->unauth_cmd)))
                        unauth = 1;
                }
            }
            prot_flush(pout);
        } else if (FD_ISSET(sock, &rset) && (FD_ISSET(fd_out, &wset))) {
            /* This does input from remote for all modes */
            do {
                count = prot_read(pin, buf, sizeof (buf) - 1);
                if (count == 0) {
                    const char *str = prot_error(pin);
                    if (str && strcmp(str, PROT_EOF_STRING)) {
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
                    retry_write(fd_out, buf, count);
                else {
                    /* use the stream API */
                    buf[count] = '\0';
                    printf("%s", buf);
                }

                if (unauth) {
                    /* Reset auth and connection state (other than TLS) */
                    sasl_dispose(&conn);
                    if (init_sasl(protocol->service, NULL,
                                  0, 128, 0) != IMTEST_OK) {
                        imtest_fatal("SASL initialization");
                    }
                    unauth = 0;

#ifdef HAVE_ZLIB
                    prot_unsetcompress(pout);
                    prot_unsetcompress(pin);
#endif
                    prot_unsetsasl(pout);
                    prot_unsetsasl(pin);
                }
            } while (haveinput(pin) > 0);
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
                    retry_write(1, buf, numr);
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
        if (listen_sock != -1) close(listen_sock);

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

enum {
    AUTO_BANNER = -1,
    AUTO_NO = 0,
    AUTO_YES = 1
};

enum {
    CAPA_LOGIN          = (1 << 0),
    CAPA_STARTTLS       = (1 << 1),
    CAPA_COMPRESS       = (1 << 2)
};

static void print_command(const char *cmd, const char *arg)
{
    static struct buf buf = BUF_INITIALIZER;

    buf_reset(&buf);
    buf_printf(&buf, cmd, arg);
    buf_replace_all(&buf, "\r\n", "\r\nC: ");

    printf("C: %s", buf_cstring(&buf));
}

static struct buf *ask_capability(struct protocol_t *prot,
                                  const char *servername,
                                  unsigned long *capabilities, int automatic)
{
    char str[1024] = "";
    char *tmp, *resp;
    static struct buf ret = BUF_INITIALIZER;

    buf_reset(&ret);

    /* default state of login command unless toggled by capabilities */
    *capabilities = prot->login_enabled;

    resp = (automatic == AUTO_BANNER) ? prot->banner.resp : prot->capa_cmd.resp;

    if (!automatic) {
        /* no capability command */
        if (!prot->capa_cmd.cmd) return NULL;

        /* request capabilities of server */
        print_command(prot->capa_cmd.cmd, servername);
        printf("\r\n");

        prot_printf(pout, prot->capa_cmd.cmd, servername);
        prot_puts(pout, "\r\n");
        prot_flush(pout);
    }

    do { /* look for the end of the capabilities */
        if (prot_fgets(str, sizeof(str), pin) == NULL) {
            if (!*str) imtest_fatal("prot layer failure");
            else break;
        }
        printf("S: %s", str);

        /* check for login - toggles existing state */
        if (prot->capa_cmd.login &&
            strstr(str, prot->capa_cmd.login) != NULL) {
            *capabilities ^= CAPA_LOGIN;
        }

        /* check for starttls */
        if (prot->capa_cmd.tls &&
            strstr(str, prot->capa_cmd.tls) != NULL) {
            *capabilities |= CAPA_STARTTLS;
        }

        /* check for compress */
        if (prot->capa_cmd.compress &&
            strstr(str, prot->capa_cmd.compress) != NULL) {
            *capabilities |= CAPA_COMPRESS;
        }

        /* check for auth */
        if (prot->capa_cmd.auth &&
            (tmp = strstr(str, prot->capa_cmd.auth)) != NULL) {

            if (prot->capa_cmd.parse_mechlist)
                prot->capa_cmd.parse_mechlist(&ret, str, prot, capabilities);
            else
                buf_setcstr(&ret, tmp+strlen(prot->capa_cmd.auth));
        }

        if (!resp) {
            /* multiline response with no distinct end (IMAP banner) */
            prot_NONBLOCK(pin);
        }

        /* look for the end of the capabilities */
    } while (!resp || strncasecmp(str, resp, strlen(resp)));

    prot_BLOCK(pin);
    return &ret;
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

static void imap_parse_mechlist(struct buf *ret, const char *str,
                                struct protocol_t *prot,
                                unsigned long *capabilities __attribute__((unused)))
{
    char *tmp;
    int num = 0;

    if (strstr(str, " SASL-IR")) {
        /* server supports initial response in AUTHENTICATE command */
        prot->sasl_cmd.maxlen = USHRT_MAX;
    }

    while ((tmp = strstr(str, " AUTH="))) {
        char *end = (tmp += 6);

        while((*end != ' ') && (*end != '\0')) end++;

        /* add entry to list */
        if (num++ > 0) buf_putc(ret, ' ');
        buf_appendmap(ret, tmp, (end - tmp) + 1);

        /* reset the string */
        str = end;
    }
}

static int auth_imap(void)
{
    char str[1024];
    /* we need username and password to do "login" */
    char *username;
    unsigned int userlen;
    char *pass;
    unsigned int passlen;
    char *tag = "L01 ";

    str[0] = '\0';

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
                        int login_enabled,
                        char *mech, const char *mechlist)
{
    int result = IMTEST_FAIL;

    if (mech) {
        if (!strcasecmp(mech, "login")) {
            if (!login_enabled) {
                printf("[Server advertised LOGINDISABLED]\n");
            } else {
                result = auth_imap();
            }
        } else if (!mechlist || !stristr(mechlist, mech)) {
            printf("[Server did not advertise AUTH=%s]\n", ucase(mech));
        } else {
            result = auth_sasl(sasl_cmd, mech);
        }
    } else {
        if (mechlist) {
            result = auth_sasl(sasl_cmd, mechlist);
        } else if (login_enabled) {
            result = auth_imap();
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
        char *tag, *cmd, *tmp, *sparebuf = (char *)xstrdup(buf);
        int c, i;
        tmp = sparebuf;

        if(len > 4 &&
           buf[len-1] == '\n' && buf[len-1] == '\r' && buf[len-2] == '}') {
            /* possible literal, with \r */
            i = len-4;
            while(i > 0 && buf[i] != '{' && Uisdigit(buf[i])) i--;
            if(buf[i] == '{') text->inLiteral = atoi(buf + i + 1);
        } else if(len > 3 && buf[len-1] == '\n' && buf[len-2] == '}') {
            /* possible literal, no \r -- hack for terminals*/
            i = len-3;
            while(i > 0 && buf[i] != '{' && Uisdigit(buf[i])) i--;
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

    snprintf(tag, sizeof(tag) - 1, "UN%d", i);
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

    prot_printf(pout,"A003 APPEND %s (\\Seen) {" SIZE_T_FMT "}\r\n",
                mbox,size+strlen(HEADERS));
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

    printf("took " TIME_T_FMT " seconds\n", end - start);
}

/*********************************** POP3 ************************************/

static void *pop3_parse_banner(char *str)
{
    char *cp, *start;
    char *chal = NULL;

    /* look for APOP challenge in banner '<...@...>' */
    cp = str+3;
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

static int auth_pop(void)
{
    char str[1024];
    /* we need username and password to do USER/PASS */
    char *username;
    unsigned int userlen;
    char *pass;
    unsigned int passlen;

    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &username, &userlen);

    printf("C: USER %s\r\n", username);
    prot_printf(pout,"USER %s\r\n", username);
    prot_flush(pout);

    if (prot_fgets(str, 1024, pin) == NULL) {
        imtest_fatal("prot layer failure");
    }

    printf("S: %s", str);

    if (strncasecmp(str, "+OK", 3)) return IMTEST_FAIL;

    interaction(SASL_CB_PASS, NULL, "Please enter your password",
                &pass, &passlen);

    printf("C: PASS <omitted>\r\n");
    prot_printf(pout,"PASS %s\r\n",pass);
    prot_flush(pout);

    if (prot_fgets(str, 1024, pin) == NULL) {
        imtest_fatal("prot layer failure");
    }

    printf("S: %s", str);

    if (!strncasecmp(str, "+OK", 3)) {
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
    unsigned char digest[MD5_DIGEST_LENGTH];
    char digeststr[2*MD5_DIGEST_LENGTH+1];

    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &username, &userlen);
    interaction(SASL_CB_PASS,NULL, "Please enter your password",
                &pass, &passlen);

    MD5Init(&ctx);
    MD5Update(&ctx,apop_chal,strlen(apop_chal));
    MD5Update(&ctx,pass,passlen);
    MD5Final(digest, &ctx);

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

    if (!strncasecmp(str, "+OK", 3)) {
        return IMTEST_OK;
    } else {
        return IMTEST_FAIL;
    }
}

static int pop3_do_auth(struct sasl_cmd_t *sasl_cmd, void *apop_chal,
                        int user_enabled, char *mech, const char *mechlist)
{
    int result = IMTEST_FAIL;

    if (mech) {
        if (!strcasecmp(mech, "apop")) {
            if (!apop_chal) {
                printf("[Server did not advertise APOP challenge]\n");
            } else {
                result = auth_apop((char *) apop_chal);
            }
        } else if (!strcasecmp(mech, "user")) {
            if (!user_enabled) {
                printf("[Server did not advertise USER]\n");
            } else {
                result = auth_pop();
            }
        } else if (!mechlist || !stristr(mechlist, mech)) {
            printf("[Server did not advertise SASL %s]\n", ucase(mech));
        } else {
            result = auth_sasl(sasl_cmd, mech);
        }
    } else {
        if (mechlist) {
            result = auth_sasl(sasl_cmd, mechlist);
        } else if (apop_chal) {
            result = auth_apop((char *) apop_chal);
        } else if (user_enabled) {
            result = auth_pop();
        }
    }

    return result;
}

/********************************** NNTP *************************************/

static int auth_nntp()
{
    char str[1024];
    /* we need username and password to do AUTHINFO USER/PASS */
    char *username;
    unsigned int userlen;
    char *pass;
    unsigned int passlen;

    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &username, &userlen);

    printf("C: AUTHINFO USER %s\r\n", username);
    prot_printf(pout,"AUTHINFO USER %s\r\n", username);
    prot_flush(pout);

    if (prot_fgets(str, 1024, pin) == NULL) {
        imtest_fatal("prot layer failure");
    }

    printf("S: %s", str);

    if (!strncmp(str, "381", 3)) {
        interaction(SASL_CB_PASS, NULL, "Please enter your password",
                    &pass, &passlen);

        printf("C: AUTHINFO PASS <omitted>\r\n");
        prot_printf(pout,"AUTHINFO PASS %s\r\n",pass);
        prot_flush(pout);

        if (prot_fgets(str, 1024, pin) == NULL) {
            imtest_fatal("prot layer failure");
        }

        printf("S: %s", str);
    }

    if (!strncmp(str, "281", 3)) {
        return IMTEST_OK;
    } else {
        return IMTEST_FAIL;
    }
}

static int nntp_do_auth(struct sasl_cmd_t *sasl_cmd,
                        void *rock __attribute__((unused)),
                        int user_enabled, char *mech, const char *mechlist)
{
    int result = IMTEST_OK;

    if (mech) {
        if (!strcasecmp(mech, "user")) {
            if (!user_enabled) {
                printf("[Server did not advertise AUTHINFO USER]\n");
                result = IMTEST_FAIL;
            } else {
                result = auth_nntp();
            }
        } else if (!mechlist || !stristr(mechlist, mech)) {
            printf("[Server did not advertise SASL %s]\n", ucase(mech));
            result = IMTEST_FAIL;
        } else {
            result = auth_sasl(sasl_cmd, mech);
        }
    } else {
        if (mechlist) {
            result = auth_sasl(sasl_cmd, mechlist);
        } else if (user_enabled) {
            result = auth_nntp();
        }
    }

    return result;
}

static char *nntp_parse_success(char *str)
{
    char *success = NULL, *tmp;

    if (!strncmp(str, "283 ", 4)) {
        success = str+4;
        if ((tmp = strchr(success, ' ')))
            *tmp = '\0'; /* clip trailing comment */
    }

    return success;
}

/******************************** LMTP/SMTP **********************************/

static int xmtp_do_auth(struct sasl_cmd_t *sasl_cmd,
                        void *rock __attribute__((unused)),
                        int login_enabled __attribute__((unused)),
                        char *mech, const char *mechlist)
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
        if (tmp) *tmp = '\0'; /* clip " */
    }

    return success;
}

/********************************** HTTP *************************************/

#define HTTP_CAPA_TLS   "Upgrade: TLS/1.2"
#define HTTP_CAPA_AUTH  "WWW-Authenticate:"
#define HTTP_AUTH_INFO  "Authentication-Info:"

#define HTTP_OPTIONS           \
    "OPTIONS * HTTP/1.1\r\n"   \
    "Host: %s\r\n"             \
    "User-Agent: httptest\r\n"

#define HTTP_STARTTLS          \
    HTTP_OPTIONS               \
    "Connection: Upgrade\r\n"  \
    HTTP_CAPA_TLS "\r\n"

#define HTTP_101  "HTTP/1.1 101"
#define HTTP_200  "HTTP/1.1 200"
#define HTTP_401  "HTTP/1.1 401"
#define HTTP_5xx  "HTTP/1.1 5"

static void http_parse_mechlist(struct buf *ret, const char *str,
                                struct protocol_t *prot __attribute__((unused)),
                                unsigned long *capabilities)
{
    char *scheme;
    size_t len;

    scheme = strchr(str, ':');
    while (strchr(" \t", *++scheme)); /* trim options whitespace */
    len = strcspn(scheme, " \t\r\n"); /* end of scheme name */

    if (len == 5 && !strncmp(scheme, "Basic", len)) {
        *capabilities |= CAPA_LOGIN;
        return;
    }
    else if (len == 6 && !strncmp(scheme, "Digest", len)) {
        scheme = "DIGEST-MD5";
        len = strlen(scheme);
    }
    else if (len == 9 && !strncmp(scheme, "Negotiate", len)) {
        scheme = "GSS-SPNEGO";
        len = strlen(scheme);
    }

    /* add entry to list */
    if (buf_len(ret)) buf_putc(ret, ' ');
    buf_appendmap(ret, scheme, len);
}

static int auth_http_basic(const char *servername)
{
    char str[1024];
    /* we need username and password to do HTTP Basic */
    char *authname;
    unsigned int authlen;
    char *username;
    unsigned int userlen;
    char *pass;
    unsigned int passlen;
    char creds[4096];
    int credslen;
    char *resp;

    interaction(SASL_CB_AUTHNAME, NULL, "Authname", &authname, &authlen);
    interaction(SASL_CB_USER, NULL, "Username", &username, &userlen);
    interaction(SASL_CB_PASS, NULL, "Please enter your password",
                &pass, &passlen);

    snprintf(str, sizeof(str), "%s:%s", authname, pass);
    if (sasl_encode64(str, strlen(str), creds, sizeof(creds),
                      (unsigned *) &credslen) != SASL_OK) {
        return IMTEST_FAIL;
    }

    print_command(HTTP_OPTIONS, servername);
    if (username && *username) printf("Authorize-As: %s\r\nC: ", username);
    printf("Authorization: Basic %.*s\r\nC: \r\n", credslen, creds);

    prot_printf(pout, HTTP_OPTIONS, servername);
    if (username && *username)
        prot_printf(pout, "Authorize-As: %s\r\n", username);
    prot_printf(pout, "Authorization: Basic %.*s\r\n", credslen, creds);
    prot_puts(pout, "\r\n");
    prot_flush(pout);

    resp = waitfor("HTTP/1.1 ", NULL, 1);

    if (!strncmp(resp, HTTP_200, strlen(HTTP_200))) {
        return IMTEST_OK;
    } else {
        return IMTEST_FAIL;
    }
}

#define BASE64_BUF_SIZE 21848   /* per RFC 2222bis: ((16K / 3) + 1) * 4  */

static int auth_http_sasl(const char *servername, const char *mechlist)
{
    sasl_interact_t *client_interact = NULL;
    int saslresult;
    const char *out = NULL;
    unsigned int outlen = 0;
    char *in, *sid = NULL;
    int inlen;
    const char *mechusing;
    char buf[BASE64_BUF_SIZE+1], *base64 = buf;
    int initial_response = 1, do_base64 = 1, use_params = 0;
    imt_stat status;
    char *username;
    unsigned int userlen;

#ifdef SASL_HTTP_REQUEST
    /* Set HTTP request (REQUIRED) */
    sasl_http_request_t httpreq = { "OPTIONS",      /* Method */
                                    "*",            /* URI */
                                    (u_char *) "",  /* Empty body */
                                    0,              /* Zero-length body */
                                    1 };            /* Persistent cxn? */
    sasl_setprop(conn, SASL_HTTP_REQUEST, &httpreq);
#endif

    interaction(SASL_CB_USER, NULL, "Username", &username, &userlen);

    do { /* start authentication */
        saslresult = sasl_client_start(conn, mechlist, &client_interact,
                                       &out, &outlen, &mechusing);

        if (saslresult == SASL_INTERACT)
            fillin_interactions(client_interact); /* fill in prompts */
    } while (saslresult == SASL_INTERACT);

    if ((saslresult != SASL_OK) && (saslresult != SASL_CONTINUE)) {
        return saslresult;
    }

    if (!strcmp(mechusing, "DIGEST-MD5")) {
        mechusing = "Digest";
        do_base64 = 0;
    }
    else if (!strcmp(mechusing, "GSS-SPNEGO")) {
        mechusing = "Negotiate";
    }
    else if (!strncmp(mechusing, "SCRAM-", 6)) {
        use_params = 1;
    }

    do {
        /* build the auth command */
        print_command(HTTP_OPTIONS, servername);
        if (username && *username) printf("Authorize-As: %s\r\nC: ", username);
        printf("Authorization: %s", mechusing);

        prot_printf(pout, HTTP_OPTIONS, servername);
        if (username && *username)
            prot_printf(pout, "Authorize-As: %s\r\n", username);
        prot_printf(pout, "Authorization: %s", mechusing);

        if (out) { /* response */
            printf(" ");
            prot_putc(' ', pout);

            if (initial_response && !outlen) {
                /* empty initial response */
                printf("=");
                prot_putc('=', pout);
            }
            else {
                if (outlen && do_base64) {
                    /* convert to base64 */
                    saslresult = sasl_encode64(out, outlen,
                                               base64, BASE64_BUF_SIZE,
                                               (unsigned *) &outlen);
                    if (saslresult != SASL_OK) return saslresult;

                    out = base64;
                }

                /* send response to server */
                if (use_params) {
                    if (sid) {
                        printf("sid=%s,", sid);
                        prot_printf(pout, "sid=%s,", sid);
                    }
                    printf("data=");
                    prot_puts(pout, "data=");
                }
                printf("%.*s", outlen, out);
                prot_write(pout, out, outlen);
            }
        }

        out = NULL;
        initial_response = 0;

        printf("\r\nC: \r\n");
        prot_puts(pout, "\r\n\r\n");
        prot_flush(pout);

        /* get status line from the server */
        if (prot_fgets(buf, sizeof(buf), pin) == NULL) {
            imtest_fatal("prot layer failure");
        }
        printf("S: %s", buf);

        if (!strncmp(buf, HTTP_200, strlen(HTTP_200)))
            status = STAT_OK;
        else if (!strncmp(buf, HTTP_401, strlen(HTTP_401)))
            status = STAT_CONT;
        else status = STAT_NO;

        /* get challenge/reply from the server */
        in = NULL;
        inlen = 0;
        prot_NONBLOCK(pin);
        while (prot_fgets(buf, sizeof(buf), pin)) {
            printf("S: %s", buf);

            if ((status == STAT_OK &&
                 !strncmp(buf, HTTP_AUTH_INFO, strlen(HTTP_AUTH_INFO))) ||
                !strncmp(buf, HTTP_CAPA_AUTH, strlen(HTTP_CAPA_AUTH))) {
                char *scheme;
                size_t len;

                scheme = strchr(buf, ':');
                while (strchr(" \t", *++scheme)); /* trim optional whitespace */
                len = strcspn(scheme, " \t\r\n"); /* end of scheme name */

                if (len == strlen(mechusing) &&
                    !strncmp(scheme, mechusing, len)) {
                    in = scheme + len;
                    while (strchr(" \t", *++in)); /* trim optional whitespace */

                    if (use_params) {
                        /* Parse parameters */
                        const char *token = in;

                        in = NULL;
                        while (token && *token) {
                            size_t tok_len, val_len;
                            char *value;

                            /* Trim leading and trailing BWS */
                            while (strchr(", \t", *token)) token++;
                            tok_len = strcspn(token, "= \t");

                            /* Find value */
                            value = strchr(token + tok_len, '=');
                            if (!value) {
                                printf("Missing value for '%.*s'"
                                       " parameter in challenge\n",
                                       (int) tok_len, token);
                                return IMTEST_FAIL;
                            }

                            /* Trim leading and trailing BWS */
                            while (strchr(" \t", *++value));
                            val_len = strcspn(value, ", \t");

                            /* Check known parameters */
                            if (!strncmp("sid", token, tok_len)) {
                                if (!sid) sid = xstrndup(value, val_len);
                                else if (val_len != strlen(sid) ||
                                         strncmp(sid, value, val_len)) {
                                    printf("Incorrect session ID parameter\n");
                                    return IMTEST_FAIL;
                                }
                            }
                            else if (!strncmp("data", token, tok_len)) {
                                in = value;
                                inlen = val_len;
                            }

                            /* Find next token */
                            token = strchr(value + val_len, ',');
                        }
                        if (!in) {
                            printf("Missing 'data' parameter in challenge\n");
                            return IMTEST_FAIL;
                        }
                    }
                    else {
                        /* token68 */
                        inlen = strcspn(in, " \t\r\n");  /* end of challenge */
                    }

                    in = xstrndup(in, inlen);
                }
            }
        }
        prot_BLOCK(pin);

        if ((status == STAT_CONT || (status == STAT_OK && in))) {
            if (do_base64) {
                /* decode this line */
                saslresult = sasl_decode64(in, inlen,
                                           base64, BASE64_BUF_SIZE,
                                           (unsigned *) &inlen);

                free(in);

                if (saslresult != SASL_OK && saslresult != SASL_CONTINUE) {
                    printf("base64 decoding error: %d\n", saslresult);
                    return IMTEST_FAIL;
                }

                in = base64;
            }

            do { /* do the next step */
                saslresult = sasl_client_step(conn, in, inlen,
                                              &client_interact,
                                              &out, &outlen);

                if (saslresult == SASL_INTERACT)
                    fillin_interactions(client_interact); /* fill in prompts */
            } while (saslresult == SASL_INTERACT);
        }

        if ((saslresult != SASL_OK) && (saslresult != SASL_CONTINUE)) {
            /* cancel the exchange */
            return IMTEST_FAIL;
        }
    } while (out);

    free(sid);

    return (status == STAT_OK) ? IMTEST_OK : IMTEST_FAIL;
}

static int http_do_auth(struct sasl_cmd_t *sasl_cmd __attribute__((unused)),
                        void *servername, int basic_enabled,
                        char *mech, const char *mechlist)
{
    int result = IMTEST_OK;

    if (mech) {
        if (!strcasecmp(mech, "basic") || !strcasecmp(mech, "plain")) {
            if (!basic_enabled) {
                printf("[Server did not advertise HTTP Basic]\n");
                result = IMTEST_FAIL;
            } else {
                result = auth_http_basic(servername);
            }
        } else {
            if (!strcasecmp(mech, "digest")) mech = "DIGEST-MD5";
            else if (!strcasecmp(mech, "negotiate")) mech = "GSS-SPNEGO";

            if (!mechlist || !stristr(mechlist, mech)) {
                printf("[Server did not advertise HTTP %s]\n", ucase(mech));
                result = IMTEST_FAIL;
            } else {
                result = auth_http_sasl(servername, mech);
            }
        }
    } else {
        if (mechlist) {
            result = auth_http_sasl(servername, mechlist);
        } else if (basic_enabled) {
            result = auth_http_basic(servername);
        }
    }

    return result;
}

/*****************************************************************************/

/* didn't give correct parameters; let's exit */
static void usage(char *prog, char *prot)
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
    else if (!strcasecmp(prot, "pop3"))
        printf("             (\"user\" for USER/PASS, \"apop\" for APOP)\n");
    else if (!strcasecmp(prot, "nntp"))
        printf("             (\"user\" for AUTHINFO USER/PASS\n");
    else if (!strcasecmp(prot, "http"))
        printf("             (\"basic\", \"digest\", \"negotiate\", \"ntlm\")\n");
    printf("  -f file  : pipe file into connection after authentication\n");
    printf("  -r realm : realm\n");
#ifdef HAVE_SSL
    if (!strcasecmp(prot, "imap") || !strcasecmp(prot, "pop3") ||
        !strcasecmp(prot, "nntp") || !strcasecmp(prot, "smtp") || !strcasecmp(prot, "http"))
        printf("  -s       : Enable %s over SSL (%ss)\n", prot, prot);
    if (strcasecmp(prot, "mupdate"))
        printf("  -t file  : Enable TLS. file has the TLS public and private keys\n"
               "             (specify \"\" to not use TLS for authentication)\n");
#endif /* HAVE_SSL */
#ifdef HAVE_ZLIB
    if (!strcasecmp(prot, "imap") || !strcasecmp(prot, "nntp") ||
        !strcasecmp(prot, "mupdate") || !strcasecmp(prot, "csync")) {
        printf("  -q       : Enable %s COMPRESSion (after authentication)\n",
               prot);
    }
#endif /* HAVE_ZLIB */
    printf("  -c       : enable challenge prompt callbacks\n"
           "             (enter one-time password instead of secret pass-phrase)\n");
    printf("  -n       : number of auth attempts (default=1)\n");
    printf("  -I file  : output my PID to (file) (useful with -X)\n");
    printf("  -x file  : open the named socket for the interactive portion\n");
    printf("  -X file  : same as -X, except close all file descriptors & daemonize\n");

    exit(1);
}


static struct protocol_t protocols[] = {
    { "imap", "imaps", "imap", 1,  /* LOGIN available until LOGINDISABLED */
      { 1, NULL, NULL },
      { "C01 CAPABILITY", "C01 ", " STARTTLS", " LOGINDISABLED", " AUTH=",
        " COMPRESS=DEFLATE", &imap_parse_mechlist },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0,  /* no init resp until SASL-IR advertised */
        0, "A01 OK", "A01 NO", "+ ", "*", NULL, 0 },
      { "Z01 COMPRESS DEFLATE", "Z01 OK", "Z01 NO" },
      &imap_do_auth, { "Q01 LOGOUT", "Q01 " }, " UNAUTHENTICATE",
      &imap_init_conn, &generic_pipe, &imap_reset
    },
    { "pop3", "pop3s", "pop", 0,   /* USER unavailable until advertised */
      { 0, "+OK", &pop3_parse_banner },
      { "CAPA", ".", "STLS", "USER", "SASL ", NULL, NULL },
      { "STLS", "+OK", "-ERR", 0 },
      { "AUTH", 255, 0, "+OK", "-ERR", "+ ", "*", NULL, 0 },
      { NULL, NULL, NULL, },
      &pop3_do_auth, { "QUIT", "+OK" }, NULL, NULL, NULL, NULL
    },
    { "nntp", "nntps", "nntp", 0,  /* AUTHINFO USER unavail until advertised */
      { 0, "20", NULL },
      { "CAPABILITIES", ".", "STARTTLS", "AUTHINFO USER", "SASL ",
        "COMPRESS DEFLATE", NULL },
      { "STARTTLS", "382", "580", 0 },
      { "AUTHINFO SASL", 512, 0, "28", "48", "383 ", "*",
        &nntp_parse_success, 0 },
      { "COMPRESS DEFLATE", "206", "403", },
      &nntp_do_auth, { "QUIT", "205" }, NULL, NULL, NULL, NULL
    },
    { "lmtp", NULL, "lmtp", 0,
      { 0, "220 ", NULL },
      { "LHLO lmtptest", "250 ", "STARTTLS", NULL, "AUTH ", NULL, NULL },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL, },
      &xmtp_do_auth, { "QUIT", "221" }, NULL,
      &xmtp_init_conn, &generic_pipe, &xmtp_reset
    },
    { "smtp", "smtps", "smtp", 0,
      { 0, "220 ", NULL },
      { "EHLO smtptest", "250 ", "STARTTLS", NULL, "AUTH ", NULL, NULL },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL, },
      &xmtp_do_auth, { "QUIT", "221" }, NULL,
      &xmtp_init_conn, &generic_pipe, &xmtp_reset
    },
    { "mupdate", NULL, "mupdate", 0,
      { 1, "* OK", NULL },
      { NULL , "* OK", "* STARTTLS", NULL, "* AUTH ", "* COMPRESS \"DEFLATE\"", NULL },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 1 },
      { "A01 AUTHENTICATE", USHRT_MAX, 1, "A01 OK", "A01 NO", "", "*", NULL, 0 },
      { "Z01 COMPRESS \"DEFLATE\"", "Z01 OK", "Z01 NO" },
      NULL, { "Q01 LOGOUT", "Q01 " }, NULL, NULL, NULL, NULL
    },
    { "sieve", NULL, SIEVE_SERVICE_NAME, 0,
      { 1, "OK", NULL },
      { "CAPABILITY", "OK", "\"STARTTLS\"", NULL, "\"SASL\" ", NULL, NULL },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", USHRT_MAX, 1, "OK", "NO", NULL, "*",
        &sieve_parse_success, 1 },
      { NULL, NULL, NULL, },
      NULL, { "LOGOUT", "OK" }, "UNAUTHENTICATE", NULL, NULL, NULL
    },
    { "csync", NULL, "csync", 0,
      { 1, "* OK", NULL },
      { NULL , "* OK", "* STARTTLS", NULL, "* SASL ", "* COMPRESS DEFLATE", NULL },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", USHRT_MAX, 0, "OK", "NO", "+ ", "*", NULL, 0 },
      { "COMPRESS DEFLATE", "OK", "NO" },
      NULL, { "EXIT", "OK" }, NULL, NULL, NULL, NULL
    },
    { "http", "https", "HTTP", 0,  /* Basic unavail until advertised */
      { 0, NULL, NULL },
      { HTTP_OPTIONS, NULL, HTTP_CAPA_TLS, NULL,
        HTTP_CAPA_AUTH, NULL, &http_parse_mechlist },
      { HTTP_STARTTLS, HTTP_101, HTTP_5xx, 1 },
      { NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 0 },
      { NULL, NULL, NULL, },
      &http_do_auth, { NULL, NULL }, NULL, NULL, NULL, NULL
    },
    { NULL, NULL, NULL, 0,
      { 0, NULL, NULL },
      { NULL, NULL, NULL, NULL, NULL, NULL, NULL },
      { NULL, NULL, NULL, 0 },
      { NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 0 },
      { NULL, NULL, NULL, },
      NULL, { NULL, NULL }, NULL, NULL, NULL, NULL
    }
};

int main(int argc, char **argv)
{
    struct protocol_t *protocol;
    char *mechanism = NULL;
    char servername[1024];
    char *filename=NULL;

    struct buf *mechlist = NULL;
    unsigned ext_ssf = 0;
    const void *ssfp;
    sasl_ssf_t ssf;
    int maxssf = 128;
    int minssf = 0;
    int c;
    int result;
    int errflg = 0;

#ifdef HAVE_SSL
    #define WITH_SSL_ONLY /**/
#else
    #define WITH_SSL_ONLY __attribute__((unused))
#endif
#ifdef HAVE_ZLIB
    #define WITH_ZLIB_ONLY /**/
#else
    #define WITH_ZLIB_ONLY __attribute__((unused))
#endif

    char *prog;
    char *tls_keyfile WITH_SSL_ONLY = "";
    char *port = "", *prot = "";
    int run_stress_test=0;
    int dotls WITH_SSL_ONLY = 0, dossl = 0, docompress WITH_ZLIB_ONLY = 0;
    unsigned long capabilities = 0;
    char str[1024];
    const char *pidfile = NULL;
    void *rock = NULL;
    int reauth = 1;
    int dochallenge = 0, noinitresp = 0;
    char *val;

#undef WITH_SSL_ONLY

    if (!construct_hash_table(&confighash, CONFIGHASHSIZE, 1)) {
        imtest_fatal("could not construct config hash table");
    }

   /* do not buffer */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    prog = strrchr(argv[0], '/') ? strrchr(argv[0], '/')+1 : argv[0];

    /* look at all the extra args */
    while ((c = getopt(argc, argv, "P:qscizvk:l:p:u:a:m:f:r:t:n:I:x:X:w:o:?h")) != EOF)
        switch (c) {
        case 'P':
            prot = optarg;
            break;
        case 'q':
#ifdef HAVE_ZLIB
            docompress=1;
#else
            imtest_fatal("imtest was not compiled with zlib support\n");
#endif
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
        case 'i':
            noinitresp=1;
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

        case 'o':
            /* parse the opt=val string.  if no value is given, assume '1' */
            if ((val = strchr(optarg, '=')))
                *val++ = '\0';
            else
                val = "1";

            /* insert the opt/val pair into the hash table */
            hash_insert(optarg, xstrdup(val), &confighash);
            break;

        case 'h':
        case '?':
        default:
            errflg = 1;
            break;
        }

    if (!*prot) {
        if (!strcasecmp(prog, "imtest"))
            prot = "imap";
        else if (!strcasecmp(prog, "pop3test"))
            prot = "pop3";
        else if (!strcasecmp(prog, "nntptest"))
            prot = "nntp";
        else if (!strcasecmp(prog, "lmtptest"))
            prot = "lmtp";
        else if (!strcasecmp(prog, "smtptest"))
            prot = "smtp";
        else if (!strcasecmp(prog, "mupdatetest"))
            prot = "mupdate";
        else if (!strcasecmp(prog, "sivtest"))
            prot = "sieve";
        else if (!strcasecmp(prog, "synctest"))
            prot = "csync";
        else if (!strcasecmp(prog, "httptest"))
            prot = "http";
    }

    protocol = protocols;
    while (protocol->protocol && strcasecmp(prot, protocol->protocol))
        protocol++;

    if (!protocol->protocol)
        imtest_fatal("unknown protocol\n");

    if (dossl && !protocol->sprotocol)
        imtest_fatal("protocol cannot be SSL-wrapped\n");

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
    if (optind < argc)
        strncpy(servername, argv[optind], 1023);
    else {
        fprintf(stderr, "WARNING: no hostname supplied, assuming localhost\n\n");
        strncpy(servername, "localhost", 1023);
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
        unsigned flags = 0;

        if (conn) {
            /* send LOGOUT */
            logout(&protocol->logout_cmd, 1);
            printf("Connection closed.\n\n");

            prot_free(pin);
            prot_free(pout);

#ifdef HAVE_SSL
            /* Properly shutdown TLS so that session can be reused */
            if (tls_conn) {
                SSL_shutdown(tls_conn);
                SSL_set_shutdown(tls_conn, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
            }
#endif

            close(sock);

            sasl_dispose(&conn);
        }

        if (init_net(servername, port) != IMTEST_OK) {
            imtest_fatal("Network initialization - cannot connect to %s:%s",
                         servername, port);
        }

        if (username && strcmpnull(authname, username)) flags += SASL_NEED_PROXY;
        if (protocol->sasl_cmd.parse_success) flags += SASL_SUCCESS_DATA;

        if (init_sasl(protocol->service, servername,
                      minssf, maxssf, flags) != IMTEST_OK) {
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
            /* try to get the capabilities from the banner */
            mechlist = ask_capability(protocol, servername,
                                      &capabilities, AUTO_BANNER);
            if ((!mechlist || !buf_len(mechlist)) && !(capabilities & CAPA_STARTTLS)) {
                /* found no capabilities in banner -> get them explicitly */
                protocol->banner.is_capa = 0;
            }
        }
        else if (protocol->banner.resp) {
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
        }
        if (!protocol->banner.is_capa) {
            mechlist = ask_capability(protocol, servername,
                                      &capabilities, AUTO_NO);
        }

#ifdef HAVE_SSL
        if ((dossl==0) && (dotls==1) && (capabilities & CAPA_STARTTLS)) {
            char *resp;

            print_command(protocol->tls_cmd.cmd, servername);
            printf("\r\n");

            prot_printf(pout, protocol->tls_cmd.cmd, servername);
            prot_puts(pout, "\r\n");
            prot_flush(pout);

            resp = waitfor(protocol->tls_cmd.ok, protocol->tls_cmd.fail, 1);

            if (!strncasecmp(resp, protocol->tls_cmd.ok,
                             strlen(protocol->tls_cmd.ok))) {

                do_starttls(0, tls_keyfile, &ext_ssf);

                /* ask for the capabilities again */
                if (verbose==1)
                    printf("Asking for capabilities again "
                           "since they might have changed\n");
                mechlist = ask_capability(protocol, servername, &capabilities,
                                          protocol->tls_cmd.auto_capa);
            }

        } else if ((dotls==1) && !(capabilities & CAPA_STARTTLS)) {
            imtest_fatal("STARTTLS not supported by the server!\n");
        }
#endif /* HAVE_SSL */

        if (noinitresp) {
            /* don't use an initial response, even if its supported */
            protocol->sasl_cmd.maxlen = 0;
        }

        if (protocol->do_auth)
            result = protocol->do_auth(&protocol->sasl_cmd,
                                       rock ? rock : servername,
                                       capabilities & CAPA_LOGIN,
                                       mechanism, buf_cstring(mechlist));
        else {
            if (mechanism) {
                result = auth_sasl(&protocol->sasl_cmd, mechanism);
            } else if (mechlist) {
                result = auth_sasl(&protocol->sasl_cmd, buf_cstring(mechlist));
            } else {
                result = IMTEST_FAIL;
            }
        }

        if (rock) free(rock);

        if (result == IMTEST_OK) {
            printf("Authenticated.\n");

            /* turn on layer if need be */
            prot_setsasl(pin,  conn);
            prot_setsasl(pout, conn);
        } else {
            const char *s = sasl_errstring(result, NULL, NULL);

            printf("Authentication failed. %s\n", s);
        }

        result = sasl_getprop(conn, SASL_SSF, &ssfp);
        ssf = *((sasl_ssf_t *) ssfp);
        if (result != SASL_OK) {
            printf("SSF: unable to determine (SASL ERROR %d)\n", result);
        } else {
            printf("Security strength factor: %d\n", ext_ssf + ssf);

            if (ssf) {
                /* ask for the capabilities again */
                struct buf orig_mechlist = BUF_INITIALIZER;

                if (verbose==1)
                    printf("Asking for capabilities again "
                           "since they might have changed\n");
                if (!strcmp(protocol->protocol, "sieve")) {
                    /* XXX  Hack to handle ManageSieve servers.
                     * No way to tell from protocol if server will
                     * automatically send capabilities, so we treat it
                     * as optional.
                     */
                    int ch;

                    /* wait and probe for possible auto-capability response*/
                    usleep(250000);
                    prot_NONBLOCK(pin);
                    if ((ch = prot_getc(pin)) != EOF) {
                        prot_ungetc(ch, pin);
                    } else {
                        protocol->sasl_cmd.auto_capa = 0;
                    }
                    prot_BLOCK(pin);
                }

                buf_copy(&orig_mechlist, mechlist);

                mechlist = ask_capability(protocol, servername, &capabilities,
                                          protocol->sasl_cmd.auto_capa);
                if (mechlist &&
                    strcmp(buf_cstring(mechlist), buf_cstring(&orig_mechlist))) {
                    printf("WARNING: possible MITM attack: "
                           "list of available SASL mechanisms changed\n");
                }

                buf_free(&orig_mechlist);
            }

        }

    } while (--reauth);

#ifdef HAVE_ZLIB
    if ((docompress==1) && (capabilities & CAPA_COMPRESS)) {
        char *resp;

        printf("C: %s\r\n", protocol->compress_cmd.cmd);
        prot_printf(pout, "%s\r\n", protocol->compress_cmd.cmd);
        prot_flush(pout);

        resp = waitfor(protocol->compress_cmd.ok, protocol->compress_cmd.fail, 1);

        if (!strncasecmp(resp, protocol->compress_cmd.ok,
                         strlen(protocol->compress_cmd.ok))) {
            prot_setcompress(pin);
            prot_setcompress(pout);
        }
    }
#endif /* HAVE_ZLIB */

    if (run_stress_test == 1) {
        send_recv_test();
    } else {
        /* else run in interactive mode or
           pipe in a filename if applicable */
        interactive(protocol, filename);
    }

    while (stashed_strings.count)
        free(strarray_pop(&stashed_strings));
    free_hash_table(&confighash, free);

    exit(0);
}
