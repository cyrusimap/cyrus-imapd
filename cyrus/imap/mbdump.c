/* mbdump.c -- Mailbox dump routines
 * $Id: mbdump.c,v 1.18.6.4 2002/12/20 18:32:03 rjs3 Exp $
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <assert.h>
#include <com_err.h>

#include "exitcodes.h"
#include "imap_err.h"
#include "imapconf.h"
#include "imparse.h"
#include "mailbox.h"
#include "map.h"
#include "mbdump.h"
#include "mboxlist.h"
#include "prot.h"
#include "seen.h"
#include "xmalloc.h"
#include "util.h"

/* is this the active script? */
static int sieve_isactive(char *sievepath, char *name)
{
    char filename[1024];
    char linkname[1024];
    char activelink[1024];
    char *file, *link;

    snprintf(filename, 1023, "%s/%s", sievepath, name);
    snprintf(linkname, 1023, "%s/default", sievepath);

    memset(activelink, 0, sizeof(activelink));
    if ((readlink(linkname, activelink, sizeof(activelink)-1) < 0) && 
	(errno != ENOENT)) 
    {
	syslog(LOG_ERR, "readlink(default): %m");
	return 0;
    }

    /* Only compare the part of the file after the last /,
     * since that is what timsieved does */
    file = strrchr(filename, '/');
    link = strrchr(activelink, '/');
    if(!file) file = filename;
    else file++;
    if(!link) link = activelink;
    else link++;

    if (!strcmp(file, link)) {
	return 1;
    } else {
	return 0;
    }
}

int dump_mailbox(const char *tag, const char *mbname, const char *mbpath,
		 const char *mbacl, int uid_start,
		 struct protstream *pin, struct protstream *pout,
		 struct auth_state *auth_state)
{
    DIR *mbdir = NULL;
    int r = 0;
    struct dirent *next = NULL;
    char filename[MAX_MAILBOX_PATH + 1024];
    int filefd;
    const char *base;
    unsigned long len;
    int first = 1;
    struct mailbox mb;
    struct stat sbuf;
    char c;
    int i;
    const char *data_files[] = { "cyrus.header",
				 "cyrus.cache",
				 "cyrus.index",
				 NULL 
                               };
    /* non-null userid means we are moving the user */
    const char *userid = NULL;
    const int SEEN_DB = 0;
    const int SUBS_DB = 1;
    char *user_data_files[3];
    int domainlen = 0;
    char *p = NULL, userbuf[81];
    
    assert(mbpath);

    if (config_virtdomains && (p = strchr(mbname, '!')))
	domainlen = p - mbname + 1; /* include separator */

    if(!strncmp(mbname+domainlen, "user.", 5) &&
       !strchr(mbname+domainlen+5, '.')) {
	strcpy(userbuf, mbname+5);
	if (domainlen)
	    sprintf(userbuf+strlen(userbuf), "@%.*s", domainlen-1, mbname);
	userid = userbuf;
	memset(user_data_files, 0, sizeof(user_data_files));
	user_data_files[SEEN_DB] = seen_getpath(userid);
	user_data_files[SUBS_DB] = mboxlist_hash_usersubs(userid);
    }

    mbdir = opendir(mbpath);
    if(!mbdir && errno == EACCES) {
	syslog(LOG_ERR,
	       "could not dump mailbox in %s (permission denied)", mbpath);
	return IMAP_PERMISSION_DENIED;
    } else if (!mbdir) {
	syslog(LOG_ERR,
	       "could not dump mailbox in %s (unknown error)", mbpath);
	return IMAP_SYS_ERROR;
    }

    r = mailbox_open_locked(mbname, mbpath, mbacl, auth_state, &mb, 0);
    if(r) {
	closedir(mbdir);
	return r;
    }

    /* after this point we have to both close the directory and unlock
     * the mailbox */

    /* xxx check to ensure we have the cyrus.* files, but we send those last */

    if(tag) prot_printf(pout, "%s DUMP ", tag);
    prot_putc('(',pout);

    /* The first member is either a number (if it is a quota root), or NIL
     * (if it isn't) */
    {
	char buf[MAX_MAILBOX_PATH];
	struct quota quota;

	quota.fd = -1;
	quota.root = (char *)mbname; /* xxx */
	mailbox_hash_quota(buf,quota.root);
	quota.fd = open(buf, O_RDWR, 0);
	if(quota.fd == -1) {
	    prot_printf(pout, "NIL ");
	    goto dump_files;
	}

	r = mailbox_read_quota(&quota);
	close(quota.fd);

	if(r) {
	    prot_printf(pout, "NIL ");
	    goto dump_files; 
	}
	
	prot_printf(pout, "%d ", quota.limit);
    }

 dump_files:
    
    while((next = readdir(mbdir)) != NULL) {
	char *name = next->d_name;  /* Alias */
	char *p = name;

	/* special case for '.'
	   (well, it gets '..' too) */
	if(name[0] == '.') continue;

	/* skip non-message files */
	while(*p && isdigit((int)(*p))) p++;
	if(p[0] != '.' || p[1] != '\0') continue;

	/* ensure (number) is >= our target uid */
	if(atoi(name) < uid_start) continue;

	/* map file */
	snprintf(filename,sizeof(filename),"%s/%s",mbpath,name);

	filefd = open(filename, O_RDONLY, 0666);
	if (filefd == -1) {
	    syslog(LOG_ERR, "IOERROR: open on %s: %m", filename);
	    r = IMAP_SYS_ERROR;
	    goto done;
	}
    
	if (fstat(filefd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat on %s: %m", filename);
	    fatal("can't fstat message file", EC_OSFILE);
	}	

	base = NULL;
	len = 0;

	map_refresh(filefd, 1, &base, &len, sbuf.st_size, filename, NULL);

	close(filefd);

	/* send filename, size, and contents */
	if(first) {
	    prot_printf(pout, "{%d}\r\n",
			strlen(name));

	    if(!tag) {
		/* synchronize */
		c = prot_getc(pin);
		eatline(pin, c); /* We eat it no matter what */
		if(c != '+') {
		    /* Synchronization Failure, Abort! */
		    syslog(LOG_ERR, "Sync Error: expected '+' got '%c'",c);
		    r = IMAP_SERVER_UNAVAILABLE;
		    goto done;
		}
	    }

	    prot_printf(pout, "%s {%lu%s}\r\n",
			name, len,
			(!tag ? "+" : ""));

	    first = 0;
	} else {
	    prot_printf(pout, " {%d%s}\r\n%s {%lu%s}\r\n",
			strlen(name),
			(!tag ? "+" : ""),
			name, len,
			(!tag ? "+" : ""));
	}
	prot_write(pout, base, len);
	map_free(&base, &len);
    }

    for(i=0;data_files[i];i++) {
	/* map file */
	snprintf(filename,sizeof(filename),"%s/%s",mbpath,data_files[i]);

	filefd = open(filename, O_RDONLY, 0666);
	if (filefd == -1) {
	    syslog(LOG_ERR, "IOERROR: open on %s: %m", filename);
	    r = IMAP_SYS_ERROR;
	    goto done;
	}
    
	if (fstat(filefd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat on %s: %m", filename);
	    fatal("can't fstat message file", EC_OSFILE);
	}	

	base = NULL;
	len = 0;

	map_refresh(filefd, 1, &base, &len, sbuf.st_size, filename, NULL);

	close(filefd);

	/* send filename, size, and contents */
	if(first) {
	    prot_printf(pout, "{%d}\r\n",
			strlen(data_files[i]));
	    
	    if(!tag) {
		/* synchronize */
		c = prot_getc(pin);
		if(c != '+') {
		    /* Synchronization Failure, Abort! */
		    r = IMAP_SERVER_UNAVAILABLE;
		    goto done;
		} else {
		    eatline(pin, c);
		}
	    }

	    prot_printf(pout, "%s {%lu%s}\r\n",
			data_files[i], len,
			(!tag ? "+" : ""));
	    first = 0;
	} else {
	    prot_printf(pout, " {%d%s}\r\n%s {%lu%s}\r\n",
			strlen(data_files[i]),
			(!tag ? "+" : ""),
			data_files[i], len,
			(!tag ? "+" : ""));
	}
	prot_write(pout, base, len);
	map_free(&base, &len);
    }

    if(userid) {
	char sieve_path[MAX_MAILBOX_PATH];
	int sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);

	/* need to transfer seen, subs, and sieve files */
	for(i=0;i<3;i++) {
	    if(!user_data_files[i]) continue;
	    
	    /* map file */
	    filefd = open(user_data_files[i], O_RDONLY, 0666);
	    if (filefd == -1) {
		syslog(LOG_ERR, "IOERROR: open on %s: %m (continuing)",
		       user_data_files[i]);
		/* but it is allowed to not exist, so... */
		continue;
	    }
    
	    if (fstat(filefd, &sbuf) == -1) {
		syslog(LOG_ERR, "IOERROR: fstat on %s: %m",
		       user_data_files[i]);
		fatal("can't fstat message file", EC_OSFILE);
	    }	
	    
	    base = NULL;
	    len = 0;
	    
	    map_refresh(filefd, 1, &base, &len, sbuf.st_size,
			user_data_files[i], NULL);
	    
	    close(filefd);
	    
	    /* send user data file type, size, and contents */
	    /* No need to test synchronization, all mailboxes should have
	     * sent a file by this point! */
	    if(i == SEEN_DB) prot_printf(pout, " {4%s}\r\nSEEN",
					 (!tag ? "+" : ""));
	    else if(i == SUBS_DB) prot_printf(pout, " {4%s}\r\nSUBS",
					      (!tag ? "+" : ""));
	    else fatal("unknown user_data_file", EC_OSFILE);
	    prot_printf(pout, " {%lu%s}\r\n",
			len, (!tag ? "+" : ""));
	    prot_write(pout, base, len);
	    map_free(&base, &len);
	}

	/* xxx can't use home directories currently
	 * (it makes almost no sense in the conext of a murder) */
	/* xxx will need to be update for bytecode */
	if(!sieve_usehomedir) {
	    char ext_fname[2048];
	    
	    if(mbdir) closedir(mbdir);
	    mbdir = NULL;

	    if (domainlen) {
		*p = '\0'; /* separate domain!mboxname */
		snprintf(sieve_path, sizeof(sieve_path), "%s%s%c/%s/%c/%s",
			 config_getstring(IMAPOPT_SIEVEDIR),
			 FNAME_DOMAINDIR, (char) dir_hash_c(mbname), mbname, 
			 (char) dir_hash_c(p+6), p+6); /* unqualified userid */
		*p = '!'; /* reassemble domain!mboxname */
	    }
	    else {
		snprintf(sieve_path, sizeof(sieve_path), "%s/%c/%s",
			 config_getstring(IMAPOPT_SIEVEDIR),
			 (char) dir_hash_c(userid), userid);
	    }
	    mbdir=opendir(sieve_path);
	    
	    if(mbdir) {
		while((next = readdir(mbdir)) != NULL) {
		    int length=strlen(next->d_name);
		    if (length >= strlen(".script")) /* if ends in .script */
		    {
			if (strcmp(next->d_name + (length - 7), ".script")==0)
			{
			    /* map file */
			    snprintf(filename, sizeof(filename), "%s/%s",
				     sieve_path, next->d_name);
			    syslog(LOG_DEBUG, "wanting to dump %s", filename);
			    filefd = open(filename, O_RDONLY, 0666);
			    if (filefd == -1) {
				/* non-fatal */
				syslog(LOG_ERR,
				       "IOERROR: open on %s: %m", filename);
				continue;
			    }

			    if (fstat(filefd, &sbuf) == -1) {
				syslog(LOG_ERR,
				       "IOERROR: fstat on %s: %m", filename);
				fatal("can't fstat message file", EC_OSFILE);
			    }	
			    
			    base = NULL;
			    len = 0;
			    
			    map_refresh(filefd, 1, &base, &len, sbuf.st_size,
					filename, NULL);

			    close(filefd);

			    /* send filename w/tag + contents */
			    if(sieve_isactive(sieve_path, next->d_name)) {
				snprintf(ext_fname, sizeof(ext_fname),
					 "SIEVED-%s", next->d_name);
			    } else {
				snprintf(ext_fname, sizeof(ext_fname),
					 "SIEVE-%s", next->d_name);
			    }
			    prot_printf(pout, " {%d%s}\r\n%s {%lu%s}\r\n",
					strlen(ext_fname), 
					(!tag ? "+" : ""),
					ext_fname,
					len,
					(!tag ? "+" : ""));
			    prot_write(pout, base, len);
			    map_free(&base, &len);
			}
		    }
		}
	    }
	}
	    
	/* transmit sieve script(s) */
	/* free strings for user_data_files */
    } /* end if user */

    prot_printf(pout,")\r\n");
 done:
    prot_flush(pout);

    mailbox_close(&mb);
    if(mbdir) closedir(mbdir);

    return r;
}

int undump_mailbox(const char *mbname, const char *mbpath, const char *mbacl,
		   struct protstream *pin, struct protstream *pout,
		   struct auth_state *auth_state)
{
    struct buf file, data;
    char c;
    int quotaused = 0;
    int r = 0;
    int curfile = -1;
    const char *userid = NULL;
    struct mailbox mb;
    char sieve_path[2048];
    int sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);
    int domainlen = 0;
    char *p = NULL, userbuf[81];
    
    memset(&file, 0, sizeof(struct buf));
    memset(&data, 0, sizeof(struct buf));

    c = getword(pin, &data);

    if (config_virtdomains && (p = strchr(mbname, '!')))
	domainlen = p - mbname + 1; /* include separator */

    if(!strncmp(mbname+domainlen, "user.", 5) &&
       !strchr(mbname+domainlen+5, '.')) {
	strcpy(userbuf, mbname+5);
	if (domainlen)
	    sprintf(userbuf+strlen(userbuf), "@%.*s", domainlen-1, mbname);
	userid = userbuf;

	if(!sieve_usehomedir) {
	    if (domainlen) {
		*p = '\0'; /* separate domain!mboxname */
		snprintf(sieve_path, sizeof(sieve_path), "%s%s%c/%s/%c/%s",
			 config_getstring(IMAPOPT_SIEVEDIR),
			 FNAME_DOMAINDIR, (char) dir_hash_c(mbname), mbname, 
			 (char) dir_hash_c(p+6), p+6); /* unqualified userid */
		*p = '!'; /* reassemble domain!mboxname */
	    }
	    else {
		snprintf(sieve_path, sizeof(sieve_path), "%s/%c/%s",
			 config_getstring(IMAPOPT_SIEVEDIR),
			 (char) dir_hash_c(userid), userid);
	    }
	}
    }

    /* we better be in a list now */
    if(c != '(' || data.s[0]) {
	freebuf(&data);
	eatline(pin, c);
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    }
    
    /* We should now have a number or a NIL */
    c = getword(pin, &data);
    if(!strcmp(data.s, "NIL")) {
	/* Remove any existing quotaroot */
	mboxlist_unsetquota(mbname);
    } else if(imparse_isnumber(data.s)) {
	/* Set a Quota */ 
	mboxlist_setquota(mbname, atoi(data.s), 0);
    } else {
	/* Huh? */
	freebuf(&data);
	eatline(pin, c);
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    if(c != ' ' && c != ')') {
	freebuf(&data);
	eatline(pin, c);
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    } else if(c == ')') {
	goto done;
    }
    
    r = mailbox_open_locked(mbname, mbpath, mbacl, auth_state, &mb, 0);
    if(r) goto done;

    while(1) {
	char fnamebuf[MAX_MAILBOX_PATH + 1024];
	char *seen_file = NULL;
	
      	c = getastring(pin, pout, &file);

	if(c != ' ') {
	    r = IMAP_PROTOCOL_ERROR;
	    goto done;
	}
	c = getbastring(pin, pout, &data);
	if(c != ' ' && c != ')') {
	    r = IMAP_PROTOCOL_ERROR;
	    goto done;
	}

	if(userid && !strcmp(file.s, "SUBS")) {
	    /* overwriting this outright is absolutely what we want to do */
	    char *s = mboxlist_hash_usersubs(userid);
	    strcpy(fnamebuf, s);
	    free(s);
	} else if (userid && !strcmp(file.s, "SEEN")) {
	    seen_file = seen_getpath(userid);

	    snprintf(fnamebuf,sizeof(fnamebuf),"%s.%d",seen_file,getpid());
	} else if (userid && !strncmp(file.s, "SIEVE", 5)) {
	    int isdefault = !strncmp(file.s, "SIEVED", 6);
	    char *realname;
	    int ret;
	    DIR *d;
	    
	    /* skip prefixes */
	    if(isdefault) realname = file.s + 7;
	    else realname = file.s + 6;

	    if(sieve_usehomedir) {
		/* xxx! */
		syslog(LOG_ERR,
		       "dropping sieve file %s since this host is " \
		       "configured for sieve_usehomedir",
		       realname);
		continue;
	    } else {
		/* xxx! - should we be less silent? */
		if((d = opendir(sieve_path)) == NULL) {
		    ret = mkdir(sieve_path, 0755);
		    
		    if(ret) {
			syslog(LOG_ERR, "dropping sieve file %s because " \
			       "we could not create %s: %m",
			       realname, sieve_path);
			continue;
		    }
		} else {
		    closedir(d);
		}

		if(snprintf(fnamebuf, sizeof(fnamebuf),
			    "%s/%s", sieve_path, realname) == -1) {
		    r = IMAP_PROTOCOL_ERROR;
		    goto done;
		} else if(isdefault) {
		    char linkbuf[2048];
		    		    
		    snprintf(linkbuf, sizeof(linkbuf), "%s/default",
			     sieve_path);
		    ret = symlink(realname, linkbuf);
		    if(ret) {
			syslog(LOG_ERR, "symlink(%s, %s): %m", realname,
			       linkbuf);
			/* Non-fatal,
			   let's get the file transferred if we can */
		    }
		    
		}
	    }
	} else {
	    if(snprintf(fnamebuf, sizeof(fnamebuf),
			 "%s/%s", mbpath, file.s) == -1) {
		r = IMAP_PROTOCOL_ERROR;
		goto done;
	    }
	    if(strncmp(file.s, "cyrus.", 6)) {
		/* it doesn't match cyrus.*, so its a message file.
		 * charge it against the quota */
		quotaused += data.len;
	    }
	}	

	/* if we haven't opened it, do so */
	curfile = open(fnamebuf, O_WRONLY|O_TRUNC|O_CREAT, 0666);
	if(curfile == -1) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", fnamebuf);
	    r = IMAP_IOERROR;
	    goto done;
	}

	if(write(curfile,data.s,data.len) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
	    r = IMAP_IOERROR;
	    goto done;
	}

	close(curfile);

	/* we were operating on the seen state, so merge it and cleanup */
	if(seen_file) {
	    seen_merge(fnamebuf, seen_file);
	    free(seen_file);
	    seen_file = NULL;

	    unlink(fnamebuf);
	}
	
	if(c == ')') break;
    }
    
    if(!r && quotaused) {
	struct quota quota;
	char quota_root[MAX_MAILBOX_PATH];
	
	if(mailbox_findquota(quota_root, mbname)) {
	    /* update the quota file */
	    memset(&quota, 0, sizeof(quota));
	    quota.root = quota_root;
	    quota.fd = -1;
	    r = mailbox_lock_quota(&quota);
	    if(!r) {
		quota.used += quotaused;
		r = mailbox_write_quota(&quota);
		close(quota.fd);
	    } else {
		syslog(LOG_ERR, "could not lock quota file for %s (%s)",
		       quota_root, error_message(r));
	    }
	    if(r) {
		syslog(LOG_ERR, "failed writing quota file for %s (%s)",
		       quota_root, error_message(r));
	    }
	}
    }

 done:
    /* eat the rest of the line, we have atleast a \r\n coming */
    eatline(pin, c);
    freebuf(&file);
    freebuf(&data);

    if(curfile >= 0) close(curfile);
    mailbox_close(&mb);
    
    return r;
}
