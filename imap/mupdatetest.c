/* mupdatetest.c -- cyrus murder database test client
 *
 * $Id: mupdatetest.c,v 1.2 2002/01/30 01:29:24 rjs3 Exp $
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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "mupdate.h"
#include "prot.h"
#include "mupdate-client.h"

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

#define LOGOUT "L01 LOGOUT\r\n"

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
    
    if(mupdate_connect(server, port, &h, NULL)) {
	printf("mupdate_connect failure\n");
	return 1;
    }

    printf("Connected to mupdate server: %s\r\n", server);

    interactive(h->sock, h->pin, h->pout);

    /* Perform Requested Operation */
    mupdate_disconnect(&h);

    return 0;
}


