/* request.h -- request to execute functions on the timsieved server
 * Tim Martin
 * 9/21/99
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifndef _REQUEST_H_
#define _REQUEST_H_

#include "mystring.h"
#include "isieve.h"

/* old and new versions of the protocol */
#define OLD_VERSION  4
#define NEW_VERSION  5
#define ACAP_VERSION 6

int handle_response(int res,int version,struct protstream *pin, mystring_t **errstr);

int deleteascript(int version,struct protstream *pout, struct protstream *pin,
		  char *name);

int installafile(int version,struct protstream *pout, struct protstream *pin,
		 char *filename);

int installdata(int version,struct protstream *pout, struct protstream *pin,
		char *scriptname, char *data, int len);

int showlist(int version, struct protstream *pout, struct protstream *pin);

int list_wcb(int version, struct protstream *pout, struct protstream *pin,isieve_listcb_t *cb ,void *rock);

int setscriptactive(int version,struct protstream *pout, struct protstream *pin,
		    char *name);

/*
 * Getscript. Save {0,1} wheather to save to disk or display on screen
 */

int getscript(int version, struct protstream *pout, struct protstream *pin,
	      char *name, int save);

int getscriptvalue(int version,struct protstream *pout, struct protstream *pin,
		   char *name, mystring_t **data);

void parseerror(char *str);


#endif
