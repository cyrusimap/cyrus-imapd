/* mupdatetest.c -- cyrus murder database test client
 *
 * $Id: mupdatetest.c,v 1.3 2002/02/20 21:01:15 rjs3 Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "mupdate.h"
#include "prot.h"
#include "mupdate-client.h"
#include "iptostring.h"
#include "xmalloc.h"
#include "exitcodes.h"
#include "imparse.h"

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

static const char service_name[] = "mupdate";

#define LOGOUT "L01 LOGOUT\r\n"

extern sasl_callback_t *mysasl_callbacks(const char *username,
                                         const char *authname,
                                         const char *realm,
                                         const char *password);

static sasl_security_properties_t *make_secprops(int min, int max)
{
  sasl_security_properties_t *ret =
      (sasl_security_properties_t *) xzmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize = 4000; /* xxx */
  ret->min_ssf = config_getint("sasl_minimum_layer", min);	
  ret->max_ssf = config_getint("sasl_maximum_layer", max);

  return ret;
}

static int mupdate_authenticate_spew(mupdate_handle *h,
				     const char *mechlist)
{
    int saslresult;
    sasl_security_properties_t *secprops=NULL;
    socklen_t addrsize;
    struct sockaddr_in saddr_l;
    struct sockaddr_in saddr_r;
    char localip[60], remoteip[60];
    const char *out;
    unsigned int outlen;
    const char *mechusing;
    int ch;
    char buf[4096];

    /* Why do this again? */
    if (h->saslcompleted) {
	return 1;
    }

    secprops = make_secprops(0, 256);
    if(!secprops) return 1;
    
    saslresult=sasl_setprop(h->saslconn, SASL_SEC_PROPS, secprops);
    if(saslresult != SASL_OK) return 1;
    free(secprops);
    
    addrsize=sizeof(struct sockaddr_in);
    if (getpeername(h->sock,(struct sockaddr *)&saddr_r,&addrsize)!=0)
	return 1;

    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(h->sock,(struct sockaddr *)&saddr_l,&addrsize)!=0)
	return 1;

    if(iptostring((const struct sockaddr *)&saddr_l, sizeof(struct sockaddr_in),
		  localip, 60) != 0)
	return 1;
    
    if(iptostring((const struct sockaddr *)&saddr_r, sizeof(struct sockaddr_in),
		  remoteip, 60) != 0)
	return 1;

    saslresult=sasl_setprop(h->saslconn, SASL_IPREMOTEPORT, remoteip);
    if (saslresult!=SASL_OK) return 1;

    saslresult=sasl_setprop(h->saslconn, SASL_IPLOCALPORT, localip);
    if (saslresult!=SASL_OK) return 1;

    /* We shouldn't get sasl_interact's,
     * because we provide explicit callbacks */
    saslresult = sasl_client_start(h->saslconn, mechlist,
				   NULL, &out, &outlen, &mechusing);

    if(saslresult != SASL_OK && saslresult != SASL_CONTINUE) return 1;

    if(out) {
	int r = sasl_encode64(out, outlen,
			      buf, sizeof(buf), NULL);
	if(r != SASL_OK) return 1;
	
	printf("C: A01 AUTHENTICATE \"%s\" {%d+}\r\n%s\r\n",
	       mechusing, strlen(buf), buf);

	/* it's always ok to send the mechname quoted */
	prot_printf(h->pout, "A01 AUTHENTICATE \"%s\" {%d+}\r\n%s\r\n",
		    mechusing, strlen(buf), buf);
    } else {
	printf("C: A01 AUTHENTICATE \"%s\"\r\n",
	       mechusing);

        prot_printf(h->pout, "A01 AUTHENTICATE \"%s\"\r\n", mechusing);
    }

    while(saslresult == SASL_CONTINUE) {
	char *p, *in;
	unsigned int len, inlen;
	
	if(!prot_fgets(buf, sizeof(buf)-1, h->pin)) {
	    /* Connection Dropped */
	    return 1;
	}

	printf("S: %s", buf);

	p = buf + strlen(buf) - 1;
	if(p >= buf && *p == '\n') *p-- = '\0';
	if(p >= buf && *p == '\r') *p-- = '\0';

	len = strlen(buf);
	in = xmalloc(len);
	saslresult = sasl_decode64(buf, len, in, len, &inlen);
	if(saslresult != SASL_OK) {
	    free(in);

	    /* CANCEL */
	    fprintf(stderr, "couldn't base64 decode: aborted authentication\n");

	    /* If we haven't already canceled due to bad authentication,
	     * then we should */
	    if(strncmp(buf, "A01 NO ", 7)) prot_printf(h->pout, "*");
	    else {
		fprintf(stderr,
		       "Authentication to master failed (%s)\n", buf+7);
	    }
	    return 1;
	}

	saslresult = sasl_client_step(h->saslconn, in, inlen, NULL,
				      &out, &outlen);
	free(in);

	if((saslresult == SASL_OK || saslresult == SASL_CONTINUE) && out) {
	    int r = sasl_encode64(out, outlen,
				  buf, sizeof(buf), NULL);
	    if(r != SASL_OK) return 1;

	    printf("C: %s\n", buf);
	    
	    prot_printf(h->pout, "%s\r\n", buf);
	}
    }

    if(saslresult != SASL_OK) {
	fprintf(stderr, "bad authentication: %s\n",
	       sasl_errdetail(h->saslconn));
	
	prot_printf(h->pout, "*");
	return 1;
    }

    /* Check Result */
    ch = getword(h->pin, &(h->tag));
    if(ch != ' ') return 1; /* need an OK or NO */

    ch = getword(h->pin, &(h->cmd));
    if(!strncmp(h->cmd.s, "NO", 2)) {
	if(ch != ' ') return 1; /* no reason really necessary, but we failed */
	ch = getstring(h->pin, h->pout, &(h->arg1));
	fprintf(stderr, "authentication failed: %s\n", h->arg1.s);
	return 1;
    }

    prot_setsasl(h->pin, h->saslconn);
    prot_setsasl(h->pout, h->saslconn);

    h->saslcompleted = 1;

    return 0; /* SUCCESS */
}

int mupdate_connect_spew(const char *server, const char *port,
			 mupdate_handle **handle,
			 sasl_callback_t *cbs)
{
    mupdate_handle *h;
    struct hostent *hp;
    struct servent *sp;
    struct sockaddr_in addr;
    int s, saslresult;
    char buf[4096];
    char *mechlist = NULL;
    
    if(!handle)
	return MUPDATE_BADPARAM;

    /* open connection to 'server' */
    if(!server) {
	server = config_getstring("mupdate_server", NULL);
	if (server == NULL) {
	    fatal("couldn't get mupdate server name", EC_UNAVAILABLE);
	}
    }
    if(!port) {
	port = config_getstring("mupdate_port",NULL);
    }
    
    hp = gethostbyname(server);
    if (!hp) {
	fprintf(stderr, "mupdate-client: gethostbyname %s failed: %m\n", server);
	return MUPDATE_NOCONN;
    }
    
    printf("Connecting to %s...\n", server);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
	fprintf(stderr, "mupdate-client: socket(): %m\n");
	return MUPDATE_NOCONN;
    }
    
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, hp->h_addr, sizeof(addr.sin_addr));

    if (port && imparse_isnumber(port)) {
	addr.sin_port = htons(atoi(port));
    } else if (port) {
	sp = getservbyname(port, "tcp");
	if (!sp) {
	    fprintf(stderr, "mupdate-client: getservbyname(tcp, %s): %m\n",
		   port);
	}
	addr.sin_port = sp->s_port;
    } else if((sp = getservbyname("mupdate", "tcp")) != NULL) {
	addr.sin_port = sp->s_port;
    } else {
	addr.sin_port = htons(2004);
    }

    h = xzmalloc(sizeof(mupdate_handle));
    *handle = h;
    h->sock = s;

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	fprintf(stderr, "mupdate-client: connect(%s): %m\n", server);
	return MUPDATE_NOCONN;
    }

    if(!cbs) {
	cbs = mysasl_callbacks(config_getstring("mupdate_username",""),
			       config_getstring("mupdate_authname",NULL),
			       config_getstring("mupdate_realm",NULL),
			       config_getstring("mupdate_password",NULL));
    }

    saslresult = sasl_client_new(service_name,
				 server,
				 NULL, NULL,
				 cbs,
				 0,
				 &(h->saslconn));

    /* create protstream */
    h->pin = prot_new(h->sock, 0);
    h->pout = prot_new(h->sock, 1);

    prot_setflushonread(h->pin, h->pout);
    prot_settimeout(h->pin, 30*60);

    /* Read the mechlist & other capabilities */
    while(1) {
	if (!prot_fgets(buf, sizeof(buf)-1, h->pin)) {
	    goto noconn;
	}

	printf("S: %s", buf);

	if(!strncmp(buf, "* AUTH", 6)) {
	    mechlist = xstrdup(buf + 6);
	} else if(!strncmp(buf, "* OK MUPDATE", 12)) {
	    break;
	}
    }

    if(!mechlist) {
	fprintf(stderr, "no AUTH banner from remote\n");
	mupdate_disconnect(handle);
	return MUPDATE_NOAUTH;
    }
    
    if (mupdate_authenticate_spew(h, mechlist)) {
	free(mechlist);
	mupdate_disconnect(handle);
	return MUPDATE_NOAUTH;
    }

    free(mechlist);
    /* SUCCESS */
    return 0;

 noconn:
    if(mechlist) free(mechlist);
    fprintf(stderr, "mupdate-client: connection to server closed: %s\n",
	   prot_error(h->pin));
    mupdate_disconnect(handle);

    return MUPDATE_NOCONN;
}

void interactive(int sock, struct protstream *pin, struct protstream *pout)
{
  char buf[2048];
  fd_set read_set, rset;
  fd_set write_set, wset;
  int nfds;
  int nfound;
  int count;
  int fd = 0;
  int donewritingfile = 0;
  
  FD_ZERO(&read_set);
  FD_SET(fd, &read_set);  
  FD_SET(sock, &read_set);

  FD_ZERO(&write_set);
  FD_SET(sock, &write_set);

  nfds = getdtablesize();

  /* loop reading from network and from stdin if applicable */
  while(1) {
      rset = read_set;
      wset = write_set;
      nfound = select(nfds, &rset, &wset, NULL, NULL);
      if (nfound < 0) {
	  perror("select");
	  fatal("select", errno);
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
		  fatal("prot_read", errno);
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
	      fatal("read", errno);
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

int main(int argc, char **argv) 
{
    mupdate_handle *h;
    const char *server=NULL, *port=NULL;
    int c;
    int flag_fail = 0;

    sasl_client_init(NULL);

    while((c = getopt(argc, argv, "s:p:")) != EOF) {
	switch(c) {
	case 's':
	    /* backwards compatible */
	    server = optarg;
	    break;
	case 'p':
	    port = optarg;
	    break;
	default:
	    flag_fail = 1;
	    break;
	}
    }

    if(!server) {
	/* last arg is servername */
	server = argv[optind];
    }
    
    if(!server || flag_fail) {
	printf("Usage: %s [-p port] server\n", argv[0]);
	return 1;
    }
    
    if(mupdate_connect_spew(server, port, &h, NULL)) {
	printf("mupdate_connect failure\n");
	return 1;
    }

    printf("Connected to mupdate server: %s\r\n", server);

    interactive(h->sock, h->pin, h->pout);

    /* Perform Requested Operation */
    mupdate_disconnect(&h);

    return 0;
}


