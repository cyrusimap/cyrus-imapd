/* config.h -- Configuration routines
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

#ifndef INCLUDED_CONFIG_H
#define INCLUDED_CONFIG_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

extern int config_init P((const char *ident));
extern const char *config_getstring P((const char *key, const char *def));
extern int config_getint P((const char *key, int def));
extern int config_getswitch P((const char *key, int def));
extern const char *config_partitiondir P((const char *partition));

/* Values of mandatory options */
extern const char *config_dir;
extern const char *config_defpartition;
extern const char *config_newsspool;

#endif /* INCLUDED_CONFIG_H */
