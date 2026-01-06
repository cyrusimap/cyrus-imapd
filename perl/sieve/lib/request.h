/* request.h -- request to execute functions on the timsieved server */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
