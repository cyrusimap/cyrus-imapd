/* config.h -- Configuration routines
 $Id: config.h,v 1.15 2000/03/15 10:31:11 leg Exp $
 
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
 */

#ifndef INCLUDED_CONFIG_H
#define INCLUDED_CONFIG_H

#include <sasl.h>

extern int config_init(const char *ident);
extern const char *config_getstring(const char *key, const char *def);
extern int config_getint(const char *key, int def);
extern int config_getswitch(const char *key, int def);
extern const char *config_partitiondir(const char *partition);
extern int config_changeident(const char *ident);

/* sasl configuration */
extern int mysasl_config(void *context,
			 const char *plugin_name,
			 const char *option,
			 const char **result,
			 unsigned *len);
extern sasl_security_properties_t *mysasl_secprops(void);

/* Values of mandatory options */
extern const char *config_dir;
extern const char *config_defpartition;
extern const char *config_newsspool;

extern const char *config_servername;

extern int config_hashimapspool;

void config_scanpartition( void (*proc)() );

/* signal handling (signals.c) */

typedef void shutdownfn(int);

void signals_add_handlers(void);
void signals_set_shutdown(shutdownfn *s);
void signals_poll(void);

/* base64 authentication functions (base64.c) */
struct protstream;
struct buf {
    char *s;
    int alloc;
};

void printauthready(struct protstream *out, int len, unsigned char *data);
int getbase64string(struct protstream *in, struct buf *buf);
int parsebase64string(char **ptr, const char *s);

#endif /* INCLUDED_CONFIG_H */
