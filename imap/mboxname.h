/* mboxname.h -- Mailbox list manipulation routines
 * $Id: mboxname.h,v 1.2 2000/01/28 22:09:49 leg Exp $
 *
 # Copyright 1999 Carnegie Mellon University
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

#ifndef INCLUDED_MBOXNAME_H
#define INCLUDED_MBOXNAME_H

int mboxname_tointernal(char *name, char *userid, char *result);
int mboxname_userownsmailbox(char *userid, char *name);
int mboxname_netnewscheck(char *name);
int mboxname_policycheck(char *name);

#endif
