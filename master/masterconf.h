/* config.h -- Configuration routines
 $Id: masterconf.h,v 1.2 2000/02/21 06:22:58 leg Exp $
 
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

#ifndef INCLUDED_MASTERCONF_H
#define INCLUDED_MASTERCONF_H

extern int masterconf_init(const char *ident);

struct entry;

extern const char *masterconf_getstring(struct entry *e,
					const char *key, const char *def);
extern int masterconf_getint(struct entry *e,
			     const char *key, int def);
extern int masterconf_getswitch(struct entry *e,
				const char *key, int def);

/* entry values are good until the next call */
typedef void masterconf_process(const char *name, struct entry *e, void *rock);

extern void masterconf_getsection(const char *section, 
				  masterconf_process *f, void *rock);

#endif /* INCLUDED_MASTERCONF_H */
