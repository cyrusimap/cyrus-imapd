/* gun.h -- Mailbox database gun interface
 * Larry Greenfield
 * SysV IPC implementation
 * 
 * Copyright 1999 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 * $Id: gun.h,v 1.2 2000/01/28 22:09:44 leg Exp $
 */

#ifndef INCLUDED_GUN_H
#define INCLUDED_GUN_H

/* TCP port the gun listens on for targets */
#define PORT 2234

#include "mailbox.h"
#include "mboxlist.h"

#define COMMANDS 1234
#define RESPONSES 1235

enum operations {
    CREATEMAILBOX = 1,
    DELETEMAILBOX,
    RENAMEMAILBOX,
    SETACL
};

struct inmsg {
    long mtype;
    int pid;
    char name[MAX_MAILBOX_NAME];
    char userid[MAX_MAILBOX_NAME];
    int isadmin;
    union {
	struct { /* create */
	    char partition[MAX_PARTITION_LEN];
	    int mbtype;
	} cmb;
	struct { /* delete */
	    int checkacl;
	} dmb;
	struct { /* rename */
	    char newname[MAX_MAILBOX_NAME];
	    char partition[MAX_PARTITION_LEN];
	} rmb;
	struct { /* setacl */
	    char ident[MAX_MAILBOX_NAME];
	    char rights[30];
	} amb;
    } u;
};

struct outmsg {
    long mtype;
    int result;
};

struct mboxdata {
    char name[MAX_MAILBOX_NAME];
    char acl[1]; /* null terminated */
};

#endif /* INCLUDED_GUN_H */
