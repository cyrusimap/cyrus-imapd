/* auth.h -- Site authorization module
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

#ifndef INCLUDED_AUTH_H
#define INCLUDED_AUTH_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

struct auth_state;

extern int auth_memberof P((struct auth_state *auth_state, const char *identifier));
extern char *auth_canonifyid P((const char *identifier));
extern struct auth_state *auth_newstate P((const char *identifier,
					   const char *cacheid));
extern void auth_freestate P((struct auth_state *auth_state));

#endif /* INCLUDED_AUTH_H */
