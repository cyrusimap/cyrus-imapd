/* config.h -- Configuration routines
 $Id: config.h,v 1.1 2000/02/15 22:21:53 leg Exp $
 
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

extern int config_init(const char *ident);
extern const char *config_getstring(const char *key, const char *def);
extern int config_getint(const char *key, int def);
extern int config_getswitch(const char *key, int def);
extern const char *config_partitiondir(const char *partition);
extern int config_changeident(const char *ident);

/* Values of mandatory options */
extern const char *config_dir;
extern const char *config_defpartition;
extern const char *config_newsspool;

extern const char *config_servername;

extern int config_hashimapspool;

void config_scanpartition( void (*proc)() );

#endif /* INCLUDED_CONFIG_H */
