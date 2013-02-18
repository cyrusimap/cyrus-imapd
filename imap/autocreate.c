/* autocreate.c -- Mailbox list manipulation routines
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <config.h>

#include "global.h"
#include "util.h"
#include "user.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "imap/imap_err.h"

#ifdef USE_SIEVE

#include "sieve/sieve_interface.h"
#include "sieve/script.h"

#define TIMSIEVE_FAIL 	-1
#define TIMSIEVE_OK 	0
#define MAX_FILENAME	1024

static void foo(void);
static int sieve_notify(void *ac __attribute__((unused)),
			void *interp_context __attribute__((unused)),
			void *script_context __attribute__((unused)),
			void *message_context __attribute__((unused)),
			const char **errmsg __attribute__((unused)));
static int mysieve_error(int lineno, const char *msg,
		  void *i __attribute__((unused)), void *s);
static int is_script_parsable(FILE *stream, char **errstr, sieve_script_t **ret);


static sieve_vacation_t vacation2 = {
    0,				/* min response */
    0,				/* max response */
    (sieve_callback *) &foo,	/* autorespond() */
    (sieve_callback *) &foo	/* send_response() */
};


/*
 * Find the name of the sieve script
 * given the source script and compiled script names
 */
static const char *get_script_name(const char *filename)
{
    const char *p;

    p = strrchr(filename, '/');
    if (p == NULL)
	return filename;
    else
	return p + 1;
}

static int autocreate_sieve(const char *userid, const char *source_script)
{
    /* XXX - this is really ugly, but too much work to tidy up right now -- Bron */
    const char *sieve_dir = NULL;
    sieve_script_t *s = NULL;
    bytecode_info_t *bc = NULL;
    char *err = NULL;
    FILE *in_stream, *out_fp;
    int out_fd, in_fd, r, k;
    int do_compile = 0;
    const char *compiled_source_script = NULL;
    const char *sievename = get_script_name(source_script);
    char sieve_script_name[MAX_FILENAME];
    char sieve_script_dir[MAX_FILENAME];
    char sieve_bcscript_name[MAX_FILENAME];
    char sieve_default[MAX_FILENAME];
    char sieve_tmpname[MAX_FILENAME];
    char sieve_bctmpname[MAX_FILENAME];
    char sieve_bclink_name[MAX_FILENAME];
    char buf[4096];
    mode_t oldmask;
    struct stat statbuf;

    /* We don't support using the homedirectory, like timsieved */
    if (config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) {
	syslog(LOG_WARNING,"autocreate_sieve: autocreate_sieve does not work with sieveusehomedir option in imapd.conf");
	return 1;
    }

    /* Check if sievedir is defined in imapd.conf */
    if(!(sieve_dir = config_getstring(IMAPOPT_SIEVEDIR))) {
	syslog(LOG_WARNING, "autocreate_sieve: sievedir option is not defined. Check imapd.conf");
	return 1;
    }

    /* Check if autocreate_sieve_compiledscript is defined in imapd.conf */
    if(!(compiled_source_script = config_getstring(IMAPOPT_AUTOCREATE_SIEVE_COMPILEDSCRIPT))) {
	syslog(LOG_WARNING, "autocreate_sieve: autocreate_sieve_compiledscript option is not defined. Compiling it");
	do_compile = 1;
    }

    if(snprintf(sieve_tmpname, MAX_FILENAME, "%s%s.script.NEW",sieve_script_dir, sievename) >= MAX_FILENAME) {
	syslog(LOG_WARNING, "autocreate_sieve: Invalid sieve path %s, %s, %s", sieve_dir, sievename, userid);
	return 1;
    }
    if(snprintf(sieve_bctmpname, MAX_FILENAME, "%s%s.bc.NEW",sieve_script_dir, sievename) >= MAX_FILENAME) {
	syslog(LOG_WARNING, "autocreate_sieve: Invalid sieve path %s, %s, %s", sieve_dir, sievename, userid);
	return 1;
    }
    if(snprintf(sieve_script_name, MAX_FILENAME, "%s%s.script",sieve_script_dir, sievename) >= MAX_FILENAME) {
	syslog(LOG_WARNING, "autocreate_sieve: Invalid sieve path %s, %s, %s", sieve_dir, sievename, userid);
	return 1;
    }
    if(snprintf(sieve_bcscript_name, MAX_FILENAME, "%s%s.bc",sieve_script_dir, sievename) >= MAX_FILENAME) {
	syslog(LOG_WARNING, "autocreate_sieve: Invalid sieve path %s, %s, %s", sieve_dir, sievename, userid);
	return 1;
    }
    if(snprintf(sieve_default, MAX_FILENAME, "%s%s",sieve_script_dir,"defaultbc") >= MAX_FILENAME) {
	syslog(LOG_WARNING, "autocreate_sieve: Invalid sieve path %s, %s, %s", sieve_dir, sievename, userid);
	return 1;
    }
    if(snprintf(sieve_bclink_name, MAX_FILENAME, "%s.bc", sievename) >= MAX_FILENAME) {
	syslog(LOG_WARNING, "autocreate_sieve: Invalid sieve path %s, %s, %s", sieve_dir, sievename, userid);
	return 1;
    }

    /* Check if a default sieve filter alrady exists */
    if(!stat(sieve_default,&statbuf)) {
	syslog(LOG_WARNING,"autocreate_sieve: Default sieve script already exists");
	return 1;
    }

    /* Open the source script. if there is a problem with that exit */
    in_stream = fopen(source_script, "r");
    if(!in_stream) {
	syslog(LOG_WARNING,"autocreate_sieve: Unable to open sieve script %s. Check permissions",source_script);
	return 1;
    }

    /*
     * At this point we start the modifications of the filesystem
     */

    /* Create the directory where the sieve scripts will reside */
    r = cyrus_mkdir(sieve_script_dir, 0755);
    if(r == -1) {
	/* If this fails we just leave */
	syslog(LOG_WARNING,"autocreate_sieve: Unable to create directory %s. Check permissions",sieve_script_name);
	fclose(in_stream);
	return 1;
    }

    /*
     * We open the file that will be used as the bc file. If this file exists, overwrite it 
     * since something bad has happened. We open the file here so that this error checking is
     * done before we try to open the rest of the files to start copying etc.
     */
    out_fd = open(sieve_bctmpname, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if(out_fd < 0) {
	if(errno == EEXIST) {
	    syslog(LOG_WARNING,"autocreate_sieve: File %s already exists. Probaly left over. Ignoring",sieve_bctmpname);
	} else if (errno == EACCES) {
	    syslog(LOG_WARNING,"autocreate_sieve: No access to create file %s. Check permissions",sieve_bctmpname);
	    fclose(in_stream);
	    return 1;
	} else {
	    syslog(LOG_WARNING,"autocreate_sieve: Unable to create %s. Unknown error",sieve_bctmpname);
	    fclose(in_stream);
	    return 1;
	}
    }

    if(!do_compile && compiled_source_script && (in_fd = open(compiled_source_script, O_RDONLY)) != -1) {
	while((r = read(in_fd, buf, sizeof(buf))) > 0) {
	    if((k=write(out_fd, buf,r)) < 0) {
		syslog(LOG_WARNING, "autocreate_sieve: Error writing to file: %s, error: %d", sieve_bctmpname, errno);
		close(out_fd);
		close(in_fd);
		fclose(in_stream);
		unlink(sieve_bctmpname);
		return 1;
	   }
	}

	if(r == 0) { /* EOF */
	    xclose(out_fd);
	    xclose(in_fd);
	} else if (r < 0) {
	    syslog(LOG_WARNING, "autocreate_sieve: Error reading compiled script file: %s. Will try to compile it", 
			   compiled_source_script);
	    xclose(in_fd);
	    do_compile = 1;
	    if(lseek(out_fd, 0, SEEK_SET)) {
		syslog(LOG_WARNING, "autocreate_sieve: Major IO problem. Aborting");
		return 1;
	    }
	}
	xclose(in_fd);
    } else {
	if(compiled_source_script)
	      syslog(LOG_WARNING,"autocreate_sieve: Problem opening compiled script file: %s. Compiling it", compiled_source_script);
	do_compile = 1;
    }


    /* Because we failed to open a precompiled bc sieve script, we compile one */
    if(do_compile) {
       if(is_script_parsable(in_stream,&err, &s) == TIMSIEVE_FAIL) {
	    if(err && *err) {
	       syslog(LOG_WARNING,"autocreate_sieve: Error while parsing script %s.",err);
	       free(err);
	    } else
		syslog(LOG_WARNING,"autocreate_sieve: Error while parsing script");

	    unlink(sieve_bctmpname);
	    fclose(in_stream);
	    close(out_fd);
	    return 1;
	}

	/* generate the bytecode */
	if(sieve_generate_bytecode(&bc, s) == TIMSIEVE_FAIL) {
	    syslog(LOG_WARNING,"autocreate_sieve: problem compiling sieve script");
	    /* removing the copied script and cleaning up memory */
	    unlink(sieve_bctmpname);
	    sieve_script_free(&s);
	    fclose(in_stream);
	    close(out_fd);
	    return 1;
	}

	if(sieve_emit_bytecode(out_fd, bc) == TIMSIEVE_FAIL) {
	    syslog(LOG_WARNING,"autocreate_sieve: problem emiting sieve script");
	    /* removing the copied script and cleaning up memory */
	    unlink(sieve_bctmpname);
	    sieve_free_bytecode(&bc);
	    sieve_script_free(&s);
	    fclose(in_stream);
	    close(out_fd);
	    return 1;
	}

	/* clean up the memory */
	sieve_free_bytecode(&bc);
	sieve_script_free(&s);
    }

    xclose(out_fd);
    rewind(in_stream);

    /* Copy the initial script */
    oldmask = umask(077);
    if((out_fp = fopen(sieve_tmpname, "w")) == NULL) {
	syslog(LOG_WARNING,"autocreate_sieve: Unable to open %s destination sieve script", sieve_tmpname);
	unlink(sieve_bctmpname);
	umask(oldmask);
	fclose(in_stream);
	return 1;
    }
    umask(oldmask);

    while((r = fread(buf,sizeof(char), sizeof(buf), in_stream)) > 0) {
	if( fwrite(buf,sizeof(char), r, out_fp) != (unsigned)r) {
	    syslog(LOG_WARNING,"autocreate_sieve: Problem writing to sieve script file: %s",sieve_tmpname);
	    fclose(out_fp);
	    unlink(sieve_tmpname);
	    unlink(sieve_bctmpname);
	    fclose(in_stream);
	    return 1;
	}
    }

    if(feof(in_stream)) {
	fclose(out_fp);
    } else { /* ferror */
	fclose(out_fp);
	unlink(sieve_tmpname);
	unlink(sieve_bctmpname);
	fclose(in_stream);
	return 1;
    }

    /* Renaming the necessary stuff */
    if(rename(sieve_tmpname, sieve_script_name)) {
	unlink(sieve_tmpname);
	unlink(sieve_bctmpname);
	return 1;
    }

    if(rename(sieve_bctmpname, sieve_bcscript_name)) {
	unlink(sieve_bctmpname);
	unlink(sieve_bcscript_name);
	return 1;
    }

    /* end now with the symlink */
    if(symlink(sieve_bclink_name, sieve_default)) {
	if(errno != EEXIST) {
	    syslog(LOG_WARNING, "autocreate_sieve: problem making the default link.");
	    /* Lets delete the files */
	    unlink(sieve_script_name);
	    unlink(sieve_bcscript_name);
	}
    }

    /*
     * If everything has succeeded AND we have compiled the script AND we have requested
     * to generate the global script so that it is not compiled each time then we create it.
     */
    if(do_compile &&
	  config_getswitch(IMAPOPT_GENERATE_COMPILED_SIEVE_SCRIPT)) {

	if(!compiled_source_script) {
	    syslog(LOG_WARNING, "autocreate_sieve: To save a compiled sieve script, autocreate_sieve_compiledscript must have been defined in imapd.conf");
	    return 0;
	}

	if(snprintf(sieve_tmpname, MAX_FILENAME, "%s.NEW", compiled_source_script) >= MAX_FILENAME)
	    return 0;

	/*
	 * Copy everything from the newly created bc sieve sieve script.
	 */
	if((in_fd = open(sieve_bcscript_name, O_RDONLY))<0) {
	    return 0;
	}

	if((out_fd = open(sieve_tmpname, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
	    if(errno == EEXIST) {
	       /* Someone is already doing this so just bail out. */
	       syslog(LOG_WARNING, "autocreate_sieve: %s already exists. Some other instance processing it, or it is left over", sieve_tmpname);
		close(in_fd);
		return 0;
	    } else if (errno == EACCES) {
		syslog(LOG_WARNING,"autocreate_sieve: No access to create file %s. Check permissions",sieve_tmpname);
		close(in_fd);
		return 0;
	    } else {
		syslog(LOG_WARNING,"autocreate_sieve: Unable to create %s",sieve_tmpname);
		close(in_fd);
		return 0;
	    }
	}

	while((r = read(in_fd, buf, sizeof(buf))) > 0) {
	    if((k = write(out_fd,buf,r)) < 0) {
		syslog(LOG_WARNING, "autocreate_sieve: Error writing to file: %s, error: %d", sieve_tmpname, errno);
		close(out_fd);
		close(in_fd);
		unlink(sieve_tmpname);
		return 0;
	   }
	}

	if(r == 0 ) { /*EOF */
	    xclose(out_fd);
	    xclose(in_fd);
	} else if (r < 0) {
		syslog(LOG_WARNING, "autocreate_sieve: Error writing to file: %s, error: %d", sieve_tmpname, errno);
		xclose(out_fd);
		xclose(in_fd);
		unlink(sieve_tmpname);
		return 0;
	}

	/* Rename the temporary created sieve script to its final name. */
	if(rename(sieve_tmpname, compiled_source_script)) {
	    if(errno != EEXIST) {
	       unlink(sieve_tmpname);
	       unlink(compiled_source_script);
	}
	    return 0;
	}

	syslog(LOG_NOTICE, "autocreate_sieve: Compiled sieve script was successfully saved in %s", compiled_source_script);
    }

    return 0;
}

/* to make larry's stupid functions happy :) */
static void foo(void)
{
    fatal("stub function called", 0);
}

static int sieve_notify(void *ac __attribute__((unused)),
			void *interp_context __attribute__((unused)),
			void *script_context __attribute__((unused)),
			void *message_context __attribute__((unused)),
			const char **errmsg __attribute__((unused)))
{
    fatal("stub function called", 0);
    return SIEVE_FAIL;
}

static int mysieve_error(int lineno, const char *msg,
		  void *i __attribute__((unused)), void *s)
{
    struct buf *errors = (struct buf *)s;
    buf_printf(errors, "line %d: %s\r\n", lineno, msg);
    return SIEVE_OK;
}

/* end the boilerplate */

static int is_script_parsable(FILE *stream, char **errstr, sieve_script_t **ret)
{
    sieve_interp_t *i;
    sieve_script_t *s;
    struct buf errors = BUF_INITIALIZER;
    int res;

    res = sieve_interp_alloc(&i, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_interp_alloc() returns %d\n", res);
	goto out;
    }

    res = sieve_register_redirect(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_redirect() returns %d\n", res);
	goto out;
    }
    res = sieve_register_discard(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_discard() returns %d\n", res);
	goto out;
    }
    res = sieve_register_reject(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_reject() returns %d\n", res);
	goto out;
    }
    res = sieve_register_fileinto(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_fileinto() returns %d\n", res);
	goto out;
    }
    res = sieve_register_keep(i, (sieve_callback *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_keep() returns %d\n", res);
	goto out;
    }

    res = sieve_register_imapflags(i, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_imapflags() returns %d\n", res);
	goto out;
    }

    res = sieve_register_size(i, (sieve_get_size *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_size() returns %d\n", res);
	goto out;
    }

    res = sieve_register_header(i, (sieve_get_header *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_header() returns %d\n", res);
	goto out;
    }

    res = sieve_register_envelope(i, (sieve_get_envelope *) &foo);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_envelope() returns %d\n", res);
	goto out;
    }

    res = sieve_register_vacation(i, &vacation2);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_vacation() returns %d\n", res);
	goto out;
    }

    res = sieve_register_notify(i, &sieve_notify);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_notify() returns %d\n", res);
	goto out;
    }

    res = sieve_register_parse_error(i, &mysieve_error);
    if (res != SIEVE_OK) {
	syslog(LOG_WARNING, "sieve_register_parse_error() returns %d\n", res);
	goto out;
    }

    rewind(stream);

    buf_appendcstr(&errors, "script errors:\r\n");
    *errstr = NULL;

    res = sieve_script_parse(i, stream, &errors, &s);

    if (res == SIEVE_OK) {
	if(ret) {
	    *ret = s;
	} else {
	    sieve_script_free(&s);
	}
    }
    else {
	sieve_script_free(&s);
	*errstr = buf_release(&errors);
    }
    buf_free(&errors);

out:
    /* free interpreter */
    sieve_interp_free(&i);

    return (res == SIEVE_OK) ? TIMSIEVE_OK : TIMSIEVE_FAIL;
}

#endif /* USE_SIEVE */

/*
 * Struct needed to be passed as void *rock to
 * mboxlist_autochangesub();
 */
struct changesub_rock_st {
    const char *userid;
    struct auth_state *auth_state;
    int was_explicit;
};

/*
 * Automatically subscribe user to *ALL* shared folders,
 * one has permissions to be subscribed to.
 * INBOX subfolders are excluded.
 */
static int autochangesub(const char *name,
			 int matchlen __attribute__((unused)),
			 int maycreate __attribute__((unused)),
			 void *rock)
{
    struct changesub_rock_st *crock = (struct changesub_rock_st *)rock;
    const char *userid = crock->userid;
    struct auth_state *auth_state = crock->auth_state;
    int was_explicit = crock->was_explicit;
    int r;

    /* ignore all user mailboxes, we only want shared */
    if (mboxname_isusermailbox(name, 0)) return 0;

    r = mboxlist_changesub(name, userid, auth_state, 1, 0, 1);

    /* unless this name was explicitly chosen, ignore the failure */
    if (!was_explicit) return 0;

    if (r) {
	syslog(LOG_WARNING,
	       "autosubscribe: User %s to folder %s, subscription failed: %s",
	       userid, name, error_message(r));
    } else {
	syslog(LOG_NOTICE,
	       "autosubscribe: User %s to folder %s, subscription succeeded",
	       userid, name);
    }

    return 0;
}

/* string for strarray_split */
#define SEP "|"

/*
 * Automatically subscribe user to a shared folder.
 * Subscription is done successfully, if the shared
 * folder exists and the user has the necessary
 * permissions.
 */
static void autosubscribe_sharedfolders(struct namespace *namespace,
					const char *userid,
					struct auth_state *auth_state)
{
    strarray_t *folders = NULL;
    const char *sub;
    int i;
    struct changesub_rock_st changesub_rock;

    changesub_rock.userid = userid;
    changesub_rock.auth_state = auth_state;
    changesub_rock.was_explicit = 0;

    /*
     * If subscribeallsharedfolders is set to yes in imapd.conf, then
     * subscribe user to every shared folder one has the apropriate
     * permissions.
     */
    if (config_getswitch(IMAPOPT_AUTOSUBSCRIBE_ALL_SHAREDFOLDERS)) {
	/* don't care about errors here, the sub will log them */
	mboxlist_findall(namespace, "*", 0, userid, auth_state,
			 autochangesub, &changesub_rock);
	return;
    }

    /* otherwise, check if there are particular folders to subscribe */

    sub = config_getstring(IMAPOPT_AUTOSUBSCRIBESHAREDFOLDERS);
    if (!sub) return;

    changesub_rock.was_explicit = 1;

    folders = strarray_split(sub, SEP, STRARRAY_TRIM);

    for (i = 0; i < folders->count; i++) {
	const char *mboxname = strarray_nth(folders, i);
	autochangesub(mboxname, 0, 0, &changesub_rock);
    }

    strarray_free(folders);

    return;
}

int autocreate_user(struct namespace *namespace,
		    const char *userid)
{
    int r = IMAP_MAILBOX_NONEXISTENT; /* default error if we break early */
    int autocreatequota = config_getint(IMAPOPT_AUTOCREATEQUOTA);
    int autocreatequotamessage = config_getint(IMAPOPT_AUTOCREATEQUOTAMSG);
    int n;
    char *inboxname = mboxname_user_mbox(userid, NULL);
    struct auth_state *auth_state = NULL;
    strarray_t *create = NULL;
    strarray_t *subscribe = NULL;
    int numcrt = 0;
    int numsub = 0;
#ifdef USE_SIEVE
    const char *source_script;
#endif

    /* check for anonymous */
    if (!strcmp(userid, "anonymous"))
	return IMAP_MAILBOX_NONEXISTENT;

    auth_state = auth_newstate(userid);

    /* Added this for debug information. */
    syslog(LOG_DEBUG, "autocreateinbox: autocreate inbox for user %s was called", userid);

    /*
     * While this is not needed for admins
     * and imap_admins accounts, it would be
     * better to separate *all* admins and
     * proxyservers from normal accounts
     * (accounts that have mailboxes).
     * UOA Specific note(1): Even if we do not
     * exclude these servers-classes here,
     * UOA specific code, will neither return
     * role, nor create INBOX, because none of these
     * administrative accounts belong to  the
     * mailRecipient objectclass, or have imapPartition.
     * UOA Specific note(2): Another good reason for doing
     * this, is to prevent the code, from getting into
     * cyrus_ldap.c because of the continues MSA logins to LMTPd.
     */

    /*
     * we need to exclude admins here
     */

    /*
     * Do we really need group membership
     * for admins or service_admins?
     */
    if (global_authisa(auth_state, IMAPOPT_ADMINS)) goto done;

    /*
     * Do we really need group membership
     * for proxyservers?
     */
    if (global_authisa(auth_state, IMAPOPT_PROXYSERVERS)) goto done;

    /*
     * Check if user belongs to the autocreate_users group. This option
     * controls for whom the mailbox may be automatically created. Default
     * value for this option is 'anyone'. So, if not declared, all mailboxes
     * will be created.
     */
    if (!global_authisa(auth_state, IMAPOPT_AUTOCREATE_USERS)) {
	syslog(LOG_DEBUG, "autocreateinbox: User %s does not belong to the autocreate_users. No mailbox is created",
	       userid);
	goto done;
    }

    r = mboxlist_createmailbox(inboxname, /*mbtype*/0, /*partition*/NULL,
			       /*isadmin*/1, userid, auth_state,
			       /*localonly*/0, /*forceuser*/0,
			       /*dbonly*/0, /*extargs*/NULL, 1);

    if (!r) r = mboxlist_changesub(inboxname, userid, auth_state, 1, 1, 1);
    if (r) {
	syslog(LOG_ERR, "autocreateinbox: User %s, INBOX failed. %s",
	       userid, error_message(r));
	goto done;
    }

    if (autocreatequota >= 0 || autocreatequotamessage >= 0) {
	int newquotas[QUOTA_NUMRESOURCES];
	int res;

	for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
	    newquotas[res] = QUOTA_UNLIMITED;

	newquotas[QUOTA_STORAGE] = autocreatequota;
	newquotas[QUOTA_MESSAGE] = autocreatequotamessage;

	r = mboxlist_setquotas(inboxname, newquotas, 0);
	if (r) {
	    syslog(LOG_ERR, "autocreateinbox: User %s, QUOTA failed. %s",
		   userid, error_message(r));
	    goto done;
	}
    }

    syslog(LOG_NOTICE, "autocreateinbox: User %s, INBOX was successfully created", 
	   userid);

    create = strarray_split(config_getstring(IMAPOPT_AUTOCREATEINBOXFOLDERS), SEP, STRARRAY_TRIM);
    subscribe = strarray_split(config_getstring(IMAPOPT_AUTOSUBSCRIBEINBOXFOLDERS), SEP, STRARRAY_TRIM);

    /* need to convert all names to internal namespace first */
    for (n = 0; n < create->count; n++)
	mboxname_hiersep_tointernal(namespace, create->data[n], 0);

    for (n = 0; n < subscribe->count; n++)
	mboxname_hiersep_tointernal(namespace, subscribe->data[n], 0);

    for (n = 0; n < create->count; n++) {
	const char *name = strarray_nth(create, n);
	char *foldername = mboxname_user_mbox(userid, name);

	r = mboxlist_createmailbox(foldername, /*mbtype*/0, /*partition*/NULL,
				   /*isadmin*/1, userid, auth_state,
				   /*localonly*/0, /*forceuser*/0,
				   /*dbonly*/0, /*extargs*/NULL, 1);

	if (!r) {
	    numcrt++;
	    syslog(LOG_NOTICE, "autocreateinbox: User %s, subfolder %s creation succeeded.", 
		   userid, name);
	} else {
	    syslog(LOG_WARNING, "autocreateinbox: User %s, subfolder %s creation failed. %s", 
		   userid, name, error_message(r));
	    r = 0;
	    continue;
	}

	/* skip to next if not subscribing */
	if (strarray_find(subscribe, name, 0) < 0)
	    continue;

	r = mboxlist_changesub(foldername, userid, auth_state, 1, 1, 1);
	if (!r) {
	    numsub++;
	    syslog(LOG_NOTICE,"autocreateinbox: User %s, subscription to %s succeeded",
		   userid, name);
	} else {
	    syslog(LOG_WARNING, "autocreateinbox: User %s, subscription to  %s failed. %s",
		   userid, name, error_message(r));
	    r = 0;
	}
    }

    if (numcrt)
	syslog(LOG_INFO, "User %s, Inbox subfolders, created %d, subscribed %d", 
	       userid, numcrt, numsub);

    /*
     * Check if shared folders are available for subscription.
     */
    autosubscribe_sharedfolders(namespace, userid, auth_state);

#ifdef USE_SIEVE
    /*
     * Here the autocreate sieve script feature is iniated from.
     */
    source_script = config_getstring(IMAPOPT_AUTOCREATE_SIEVE_SCRIPT);

    if (source_script) {
	if (!autocreate_sieve(userid, source_script))
	    syslog(LOG_NOTICE, "autocreate_sieve: User %s, default sieve script creation succeeded", userid);
	else
	    syslog(LOG_WARNING, "autocreate_sieve: User %s, default sieve script creation failed", userid);
    }
#endif

 done:
    free(inboxname);
    strarray_free(create);
    strarray_free(subscribe);
    auth_freestate(auth_state);

    return r;
}
