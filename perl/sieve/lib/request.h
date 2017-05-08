/* request.h -- request to execute functions on the timsieved server
 * Tim Martin
 * 9/21/99
 */
/*
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
#ifndef _REQUEST_H_
#define _REQUEST_H_

#include "util.h"
#include "perl/sieve/lib/isieve.h"

/* old and new versions of the protocol */
#define OLD_VERSION  4
#define NEW_VERSION  5
#define ACAP_VERSION 6

int handle_response(int res,int version,struct protstream *pin,
                    char **refer_to, char **errstr);

int deleteascript(int version,struct protstream *pout, struct protstream *pin,
                  const char *name, char **refer_to, char **errstr);

int installafile(int version,struct protstream *pout, struct protstream *pin,
                 char *filename, char *destname,
                 char **refer_to, char **errstr);

int installdata(int version,struct protstream *pout, struct protstream *pin,
                char *scriptname, char *data, int len,
                char **refer_to, char **errstr);

//int showlist(int version, struct protstream *pout, struct protstream *pin,
//           char **refer_to);

int list_wcb(int version, struct protstream *pout, struct protstream *pin,
             isieve_listcb_t *cb , void *rock, char **refer_to);

int setscriptactive(int version, struct protstream *pout,
                    struct protstream *pin,
                    char *name, char **refer_to, char **errstr);

/*
 * Getscript. Save {0,1} whether to save to disk or display on screen
 */

//int getscript(int version, struct protstream *pout, struct protstream *pin,
//            const char *name, int save, char **refer_to, char **errstr);

int getscriptvalue(int version,struct protstream *pout, struct protstream *pin,
                   char *name, char **data, char **refer_to,
                   char **errstr);

void parseerror(const char *str);


#endif
