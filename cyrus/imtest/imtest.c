/* imtest.c -- IMAP/IMSP test client
 *
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 * Author: Chris Newman <chrisn+@cmu.edu>
 * Start Date: 2/16/93
 */

/* kludge: send a non-synchronizing literal with password instead of
   unquoted password; should not do this, as it is not compatible with
   base-line IMAP4rev1 servers.
   */

#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "sasl.h"
#include "prot.h"

/* from OS: */
extern char *getpass();
extern struct hostent *gethostbyname();

/* constant commands */
char logout[] = ". LOGOUT\r\n";

/* authstate which must be cleared before exit */
static void *authstate;

#ifdef HAVE_SASL_KRB
char auth_kv4[] = ". AUTHENTICATE KERBEROS_V4\r\n";

extern struct sasl_client krb_sasl_client;
#define client_start krb_sasl_client.start
#define client_auth  krb_sasl_client.auth
#define client_query krb_sasl_client.query_state
#define client_free  krb_sasl_client.free_state

/* base64 tables
 */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};
#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

void to64(out, in, inlen)
    unsigned char *out, *in;
    int inlen;
{
    unsigned char oval;
    
    while (inlen >= 3) {
	*out++ = basis_64[in[0] >> 2];
	*out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
	*out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
	*out++ = basis_64[in[2] & 0x3f];
	in += 3;
	inlen -= 3;
    }
    if (inlen > 0) {
	*out++ = basis_64[in[0] >> 2];
	oval = (in[0] << 4) & 0x30;
	if (inlen > 1) oval |= in[1] >> 4;
	*out++ = basis_64[oval];
	*out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
	*out++ = '=';
    }
    *out++ = '\r';
    *out++ = '\n';
    *out = '\0';
}

int from64(out, in)
    char *out, *in;
{
    int len = 0;
    int c1, c2, c3, c4;

    if (in[0] == '+' && in[1] == ' ') in += 2;
    if (*in == '\r') return (0);
    do {
	c1 = in[0];
	if (CHAR64(c1) == -1) return (-1);
	c2 = in[1];
	if (CHAR64(c2) == -1) return (-1);
	c3 = in[2];
	if (c3 != '=' && CHAR64(c3) == -1) return (-1); 
	c4 = in[3];
	if (c4 != '=' && CHAR64(c4) == -1) return (-1);
	in += 4;
	*out++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
	++len;
	if (c3 != '=') {
	    *out++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
	    ++len;
	    if (c4 != '=') {
		*out++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
		++len;
	    }
	}
    } while (*in != '\r' && c4 != '=');

    return (len);
}
#endif

void usage()
{
#ifdef HAVE_SASL_KRB
    fprintf(stderr, "usage: imtest [-k[p/i] / -p] <server> <port>\n");
#else
    fprintf(stderr, "usage: imtest [-p] <server> <port>\n");
#endif
    exit(1);
}

void fatal(str, level)
    char *str;
    int level;
{
    if (str) fprintf(stderr, "%s\n", str);
#ifdef HAVE_SASL_KRB
    if (authstate) client_free(authstate);
#endif
    exit(1);
}

main(argc, argv)
    int argc;
    char **argv;
{
    int sock, nfds, nfound, count, dologin, dopass;
    int len, done, maxplain;
    int prot_req, protlevel;
    
    sasl_encodefunc_t *encodefunc;
    sasl_decodefunc_t *decodefunc;
    char *host, *port, *pass, *outbuf, *user;
    fd_set read_set, rset;
    struct sockaddr_in addr, laddr;
    struct hostent *hp;
    struct servent *serv;
    struct protstream *pout, *pin;
    char buf[4096];
    
    if (argc < 2) usage();
    dologin = dopass = 0;
    encodefunc = 0;
    decodefunc = 0;
    authstate = 0;
    done = 0;
    host = argv[1];
    port = argv[2];
    if (*argv[1] == '-') {
	dologin = 1;
	prot_req = SASL_PROT_NONE;
	if (argv[1][1] == 'p') dopass = 1;
#ifdef HAVE_SASL_KRB
	else if (argv[1][1] == 'k') {
	    if (argv[1][2] == 'p') {
		prot_req |= SASL_PROT_ANY;
	    } else if (argv[1][2] == 'i') {
		prot_req |= SASL_PROT_INTEGRITY;
	    }
	}
#endif
	else usage();
	host = argv[2];
	port = argv[3];
    }
    if (!port) usage();
    if ((hp = gethostbyname(host)) == NULL) {
	herror("gethostbyname");
	exit(1);
    }
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket");
	exit(1);
    }
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(atoi(port));
    if (!isdigit(*port)) {
	if (!(serv = getservbyname(port, "tcp"))) {
	    fprintf(stderr, "%s not found in servtab\n", port);
	    exit(1);
	} else {
	    addr.sin_port = serv->s_port;
	}
    }
    if (connect(sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
	perror("connect");
	exit(1);
    }
    FD_ZERO(&read_set);
    FD_SET(0, &read_set);
    FD_SET(sock, &read_set);
    nfds = getdtablesize();
    pin = prot_new(sock, 0);
    pout = prot_new(sock, 1);
    for (;;) {
	rset = read_set;
	nfound = select(nfds, &rset, NULL, NULL, NULL);
	if (nfound < 0) {
	    perror("select");
	    fatal(NULL, 0);
	}
	if (FD_ISSET(0, &rset)) {
	    if (fgets(buf, sizeof (buf) - 1, stdin) == NULL) {
		printf(logout);
		prot_write(pout, logout, sizeof (logout));
		FD_CLR(0, &read_set);
	    } else {
		count = strlen(buf);
		buf[count - 1] = '\r';
		buf[count] = '\n';
		buf[count + 1] = '\0';
		prot_write(pout, buf, count + 1);
	    }
	    prot_flush(pout);
	}
	if (FD_ISSET(sock, &rset)) {
	    count = prot_read(pin, buf, sizeof (buf) - 1);
	    if (count == 0) {
		if (prot_error(pin)) {
		    printf("Protection error: %s\n", prot_error(pin));
		}
		close(sock);
		printf("Connection Closed.\n");
		break;
	    }
	    if (count < 0) {
		perror("read");
		fatal(NULL, 0);
	    }
	    buf[count] = '\0';
	    printf("%s", buf);
#ifdef HAVE_SASL_KRB
	    if (done == SASL_DONE && strchr(buf, ' ')
		&& !strncmp(" OK ", strchr(buf, ' '), 4)) {
		done = 0;
		client_query(authstate, &user, &protlevel,
			     &encodefunc, &decodefunc, &maxplain);
		switch (protlevel) {
		    case SASL_PROT_NONE:
			printf("__No integrity protection__\n");
			break;
		    case SASL_PROT_INTEGRITY:
			printf("__Integrity protection only__\n");
			break;
		    case SASL_PROT_PRIVACY:
			printf("__Full privacy protection__\n");
			break;
		}
		if (encodefunc || decodefunc) {
		    prot_setfunc(pin, decodefunc, authstate, 0);
		    prot_setfunc(pout, encodefunc, authstate, maxplain);
		}
	    }
#endif
	    if (dologin) {
		if (dopass) {
		    dologin = 0;
		    pass = getpass("Password: ");
		    /* XXX kludge!  we just send a non-synchronizing
		       literal instead of dealing with this
		       appropriately. */
		    printf(". LOGIN %s {L+}\r\nX\r\n",
			   getpwuid(getuid())->pw_name);
		    sprintf(buf, ". LOGIN %s {%d+}\r\n%s\r\n",
			    getpwuid(getuid())->pw_name, strlen(pass),
			    pass);
		    prot_write(pout, buf, strlen(buf));
		    memset(buf, 0, sizeof (buf));
		    memset(pass, 0, 8);
		} else if (dologin == 1) {
#ifdef HAVE_SASL_KRB
		    ++dologin;
		    len = sizeof (laddr);
		    if (getsockname(sock, (struct sockaddr *)&laddr,
				    &len) < 0 ||
			client_start(krb_sasl_client.rock,
				     "imap", host, NULL, prot_req,
				     sizeof (buf) - 4,
				     (struct sockaddr *)&laddr,
				     (struct sockaddr *)&addr,
				     &authstate) != 0) {
			printf("__Kerberos initialization failed__\n");
			dologin = 0;
		    } else {
			printf(auth_kv4);
			prot_write(pout, auth_kv4,
				   sizeof (auth_kv4) - 1);
		    }
		} else if ((len = from64(buf, buf)) < 0 ||
			   (done = client_auth(authstate, len, buf, &len,
					       &outbuf)) == SASL_FAIL) {
		    printf("__Authentication failed__\n");
		    prot_write(pout, "*\r\n", 3);
		    client_free(authstate);
		    authstate = 0;
		    dologin = 0;
		} else {
		    to64(buf, outbuf, len);
		    printf(buf);
		    prot_write(pout, buf, strlen(buf));
		    if (done)
#endif
			dologin = 0;
		}
		prot_flush(pout);
	    }
	}
    }
#ifdef HAVE_SASL_KRB
    if (authstate) client_free(authstate);
#endif

    exit(0);
}
