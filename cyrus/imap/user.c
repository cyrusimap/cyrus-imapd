/* user.c -- User manipulation routines
 * 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */
/*
 * $Id: user.c,v 1.2.2.1 2001/07/08 16:00:02 ken3 Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "imapconf.h"
#include "user.h"
#include "mboxlist.h"
#include "mailbox.h"


static int user_deleteacl(char *name, int matchlen, int maycreate, void* rock)
{
    char *ident = (char *) rock;
    int r;
    char *acl;
    char *rights, *nextid;

    r = mboxlist_lookup(name, (char **)0, &acl, NULL);

    while (!r && acl) {
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';

	nextid = strchr(rights, '\t');
	if (!nextid) break;
	*nextid++ = '\0';

	if (!strcmp(acl, ident)) {
	    /* delete ACL for ident */
	    if (!r) mboxlist_setacl(name, ident, (char *)0,
				    1, ident, NULL);
	}

	acl = nextid;
    }
    return 0;
}

int user_delete(char *user, char *userid, struct auth_state *authstate)
{
    char *fname;
    char pat[] = "*";

    /* delete seen state */
    seen_delete_user(user);

    /* delete subscriptions */
    fname = mboxlist_hash_usersubs(user);
    (void) unlink(fname);
    free(fname);

    /* delete quotas */
    user_deletequotas(user);

    /* delete ACLs */
    mboxlist_findall(pat, 1, userid, authstate, user_deleteacl, user);

    return 0;
}
#if 0
static int user_renameacl(char *name, int matchlen, int maycreate, void* rock)
{
    char **ident = (char **) rock;
    int r;
    char *acl;
    char *rights, *nextid;

    r = mboxlist_lookup(name, (char **)0, &acl, NULL);

    while (!r && acl) {
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';

	nextid = strchr(rights, '\t');
	if (!nextid) break;
	*nextid++ = '\0';

	if (!strcmp(acl, ident[0])) {
	    /* copy ACL for old ident to new ident */
	    r = mboxlist_setacl(name, ident[1], rights, 1, ident[1], NULL);
	    /* delete ACL for old ident */
	    if (!r) mboxlist_setacl(name, ident[0], (char *)0,
				    1, ident[1], NULL);
	}

	acl = nextid;
    }
    return 0;
}

static int user_renamesub(char *name, int matchlen, int maycreate, void* rock)
{
    char **ident = (char **) rock;
    char newname[MAX_MAILBOX_NAME+1];

    /* unsubscribe from old folder */
    mboxlist_changesub(name, ident[1], NULL, 0, 1);

    /* subscribe to new folder */
    sprintf(newname, "user.%s.%s", ident[1], name+6+strlen(ident[0]));
    mboxlist_changesub(newname, ident[1], NULL, 1, 1);

    return 0;
}

int user_rename(char *oldmailboxname, char *newmailboxname,
		char *userid, struct auth_state *authstate)
{
    char *ident[] = { oldmailboxname+5, newmailboxname+5 };
    char pat[MAX_MAILBOX_NAME];
    char *oldfname, *newfname;
    int r = 0;

    /* change ACLs */
    strcpy(pat, "*");
    mboxlist_findall(pat, 1, userid, authstate, user_renameacl, ident);

    /* rename/change subscriptions */
    oldfname = mboxlist_hash_usersubs(ident[0]);
    newfname = mboxlist_hash_usersubs(ident[1]);
    unlink(newfname);
    r = mailbox_copyfile(oldfname, newfname);
    if (!r) {
	unlink(oldfname);
	sprintf(pat, "%s.*", oldmailboxname);
	mboxlist_findsub(pat, 1, ident[1], authstate, user_renamesub,
			 ident, 1);
    }
    free(oldfname);
    free(newfname);

    /* rename seendb */
    seen_rename_user(ident[0], ident[1]);

    /* set quota on INBOX */
    user_copyquota(oldmailboxname, newmailboxname);
}

int user_copyquota(char *oldname, char *newname)
{
    int r;
    struct quota quota;
    char buf[MAX_MAILBOX_PATH];

    quota.root = oldname;
    quota.fd = -1;

    mailbox_hash_quota(buf, quota.root);
    quota.fd = open(buf, O_RDWR, 0);
    if (quota.fd > 0) {
	r = mailbox_read_quota(&quota);
	if (!r) mboxlist_setquota(newname, quota.limit);
    }
}
#endif
int user_deletequotas(const char *user)
{
    char c, qpath[MAX_MAILBOX_NAME], *tail;
    DIR *dirp;
    struct dirent *f;

    c = (char) tolower((int) *user);
    if (!islower((int) c)) c = 'q';
    sprintf(qpath, "%s%s%c/", config_dir, FNAME_QUOTADIR, c);
    tail = qpath + strlen(qpath);

    dirp = opendir(qpath);
    if (dirp) {
	while ((f = readdir(dirp)) != NULL) {
	    if (!strncmp(f->d_name, "user.", 5) &&
		!strncmp(f->d_name+5, user, strlen(user)) &&
		(f->d_name[5+strlen(user)] == '\0'||
		 f->d_name[5+strlen(user)] == '.')) {

		strcpy(tail, f->d_name);
		unlink(qpath);
	    }
	}
	closedir(dirp);
    }
}
