/* mbdump.c -- Mailbox dump routines
 * $Id: mbdump.c,v 1.3 2002/03/13 23:18:08 rjs3 Exp $
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
#include <time.h>

#include "exitcodes.h"
#include "imap_err.h"
#include "imapconf.h"
#include "mailbox.h"
#include "map.h"
#include "mbdump.h"
#include "prot.h"
#include "xmalloc.h"

static int lock_mailbox_ctl_files(const char *mbname,
				  struct auth_state *auth_state,
				  struct mailbox *mb) 
{
    int r;
    
    r = mailbox_open_header(mbname, auth_state, mb);
    if(r) return r;

    /* now we have to close the mailbox if we fail */

    r = mailbox_lock_header(mb);
    if(!r)
	r = mailbox_open_index(mb);
    if(!r) 
	r = mailbox_lock_index(mb);

    if(r) mailbox_close(mb);

    return r;
}

int dump_mailbox(const char *tag, const char *mbpath, const char *mbname,
		 int uid_start,
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

    r = lock_mailbox_ctl_files(mbname, auth_state, &mb);
    if(r) {
	closedir(mbdir);
	return r;
    }

    /* after this point we have to both close the directory and unlock
     * the mailbox */

    /* xxx check to ensure we have the cyrus.* files, but we send those last */

    if(tag) prot_printf(pout, "%s DUMP ", tag);
    prot_putc('(',pout);

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
	    prot_printf(pout, "{%d}\n\r",
			strlen(name));

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

	    prot_printf(pout, "%s {%lu%s}\n\r",
			name, len,
			(!tag ? "+" : ""));

	    first = 0;
	} else {
	    prot_printf(pout, " {%d%s}\n\r%s {%lu%s}\n\r",
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
	    prot_printf(pout, "{%d}\n\r",
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

	    prot_printf(pout, "%s {%lu%s}\n\r",
			data_files[i], len,
			(!tag ? "+" : ""));
	    first = 0;
	} else {
	    prot_printf(pout, " {%d%s}\n\r%s {%lu%s}\n\r",
			strlen(data_files[i]),
			(!tag ? "+" : ""),
			data_files[i], len,
			(!tag ? "+" : ""));
	}
	prot_write(pout, base, len);
	map_free(&base, &len);
    }

 done:
    prot_printf(pout,")\n\r");
    prot_flush(pout);

    mailbox_close(&mb);
    if(mbdir) closedir(mbdir);

    return r;
}

int undump_mailbox(const char *mbpath, const char *mbname,
		   struct protstream *pin, struct protstream *pout,
		   struct auth_state *auth_state)
{
    struct buf file, data;
    char c;
    int r = 0;
    int curfile = -1;
    struct mailbox mb;
    
    memset(&file, 0, sizeof(struct buf));
    memset(&data, 0, sizeof(struct buf));

    c = getword(pin, &data);

    /* we better be in a list now */
    if(c != '(' || data.s[0]) {
	freebuf(&data);
	eatline(pin, c);
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    r = lock_mailbox_ctl_files(mbname, auth_state, &mb);
    if(r) goto done;

    while(1) {
	char fnamebuf[MAX_MAILBOX_PATH + 1024];
	
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

	if(snprintf(fnamebuf, sizeof(fnamebuf),
		    "%s/%s", mbpath, file.s) == -1) {
	    r = IMAP_PROTOCOL_ERROR;
	    goto done;
	}

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
	
	if(c == ')') break;
    }
    
 done:
    /* eat the rest of the line, we have atleast a \n\r coming */
    eatline(pin, c);
    freebuf(&file);
    freebuf(&data);
    if(curfile >= 0) close(curfile);
    mailbox_close(&mb);
    
    return r;
}
