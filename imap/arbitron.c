/* arbitron.c -- program to report readership statistics
 *
 * Copyright (c) 1998, 2000 Carnegie Mellon University.  All rights reserved.
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
 */

/* $Id: arbitron.c,v 1.27 2003/07/31 03:07:39 rjs3 Exp $ */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <com_err.h>
#include <time.h>

#include "assert.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "hash.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mpool.h"
#include "mboxlist.h"
#include "convert_code.h"
#include "seen.h"
#include "xmalloc.h"

#define DB (CONFIG_DB_SEEN)

extern int optind;
extern char *optarg;

/* Maintain the mailbox list */
/* xxx it'd be nice to generate a subscriber list too */
struct arb_mailbox_data {
/*    const char *id; */
    char *name;
    int readers;
/*    int subscribers; */
};

struct mpool *arb_pool;
hash_table mailbox_table;

time_t report_time, prune_time = 0;
int code = 0;

/* current namespace */
static struct namespace arb_namespace;

/* forward declarations */
void usage(void);
void run_users(void);
void make_report(char *key, void *data, void *rock);
void process_seen(const char *path);
void process_subs(const char *user);
int do_mailbox(const char *name, int matchlen, int maycreate, void *rock);

int main(int argc,char **argv)
{
    int opt, r;
    int report_days = 30;
    int prune_months = 0;
    char pattern[MAX_MAILBOX_NAME+1];
    char *alt_config = NULL;

    strcpy(pattern, "*");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:d:p:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'd':
	    report_days = atoi(optarg);
	    if (report_days <= 0) usage();
	    break;

	case 'p':
	    prune_months = atoi(optarg);
	    if (prune_months <= 0) usage();
	    break;

	default:
	    usage();
	}
    }

    /* Init Cyrus Backend Foo */
    config_init(alt_config, "arbitron");

    mboxlist_init(0);
    mboxlist_open(NULL);
    
    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&arb_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    if (optind != argc) strlcpy(pattern, argv[optind], sizeof(pattern));

    report_time = time(0) - (report_days*60*60*24);
    if (prune_months) {
	prune_time = time(0) - (prune_months*60*60*24*31);
    }

    /* Allocate our shared memory pools */
    arb_pool = new_mpool(0);
    construct_hash_table(&mailbox_table, 1023, 1);

    /* Translate any separators in mailboxname */
    mboxname_hiersep_tointernal(&arb_namespace, pattern);
    
    /* Get the mailbox list */
    fprintf(stderr, "Loading Mailboxes...");
    (*arb_namespace.mboxlist_findall)(&arb_namespace, pattern, 1, 0, 0,
				      do_mailbox, NULL);

    fprintf(stderr, "Done\nLoading Users");
    
    /* Now do all the users */
    run_users();

    fprintf(stderr, "\n");    

    /* And print the report */
    hash_enumerate(&mailbox_table, make_report, NULL);    

    /* Free Resources */
    free_hash_table(&mailbox_table, NULL);    
    free_mpool(arb_pool);    
    mboxlist_close();
    mboxlist_done();    

    return code;
}

void usage(void)
{
    fprintf(stderr,
	    "usage: arbitron [-C alt_config] [-d days]"
	    " [-p months] [mboxpattern]\n");
    exit(EC_USAGE);
}    

int do_mailbox(const char *name, int matchlen, int maycreate, void *rock)
{
    int r;
    struct mailbox mbox;

    r = mailbox_open_header(name, NULL, &mbox);
    if(!r) {
	struct arb_mailbox_data *d = mpool_malloc(arb_pool,
						  sizeof(struct arb_mailbox_data));
    
	d->name = xstrdup(name);
	d->readers = 0;

/*	printf("inserting %s (key %s)\n", name, mbox.uniqueid); */

	hash_insert(mbox.uniqueid, d, &mailbox_table);

	mailbox_close(&mbox);
    }

    return 0;
}

void run_users(void) 
{
    char prefix[MAX_MAILBOX_PATH+1],path[MAX_MAILBOX_PATH+1],
	file[MAX_MAILBOX_PATH+1];    
    DIR *dirp, *dirq;
    struct dirent *dirent1, *dirent2;
    
    snprintf(prefix, sizeof(prefix), "%s%s", config_dir, FNAME_USERDIR);
    
    dirp = opendir(prefix);
    if(!dirp) {
	fatal("can't open user directory", EC_SOFTWARE);
    }

    while((dirent1 = readdir(dirp)) != NULL) {
	if(!strcmp(dirent1->d_name, ".") || !strcmp(dirent1->d_name,"..")) {
	    continue;	    
	}
	
	snprintf(path, sizeof(path), "%s%s", prefix, dirent1->d_name);
/*	printf("trying %s\n",path); */
	
	dirq = opendir(path);
	if(dirq) {	    
	    fprintf(stderr, ".");	    
	    while(dirq && ((dirent2 = readdir(dirq)) != NULL)) {
		size_t len;
		
		if(!strcmp(dirent2->d_name, ".") ||
		   !strcmp(dirent2->d_name,"..")) {
		    continue;	    
		}

		len = strlen(dirent2->d_name);

	        /* 5 is magic number for strlen(".seen") */
		if(len > 5 && !strcmp(dirent2->d_name + len - 5, ".seen")) {
		    snprintf(file, sizeof(file),
			     "%s/%s", path, dirent2->d_name);
/*		    printf("got file %s\n",file); */
		    process_seen(file);
		} else if (len > 5 &&
			   !strcmp(dirent2->d_name + len - 5, ".subs")) {
		    *(dirent2->d_name + len - 5) = '\0';		    
		    process_subs(dirent2->d_name);		    
		}		
	    }
	    closedir(dirq);
	}
	    
    }    
    closedir(dirp);

}

static int process_user_cb(void *rockp,
			   const char *key, int keylen,
			   const char *tmpdata __attribute__((unused)),
			   int tmpdatalen __attribute__((unused))) 
{
    /* Only called to do deletes */
/*    printf("pruning entry\n"); */
    
    DB->delete((struct db *)rockp, key, keylen, NULL, 0);    

    return 0;    
}

/* We can cheat and do all we need to in this function */
static int process_user_p(void *rockp __attribute__((unused)),
			  const char *key,
			  int keylen,
			  const char *data,
			  int datalen) 
{
    int ret = 0;    
    long version, lastread;
    char *p;    
    char buf[64];
    struct arb_mailbox_data *mbox;

    /* remember that 'data' may not be null terminated ! */
    version = strtol(data, &p, 10); data = p;
    /* xxx not checking version */
    lastread = strtol(data, &p, 10); data = p;
    
    memcpy(buf, key, keylen);
    buf[keylen] = '\0';

    mbox = hash_lookup(buf, &mailbox_table);
    if(mbox && lastread >= report_time) {
/*	printf("got %s\n", mbox->name);	     */
	mbox->readers++;
    }

    /* Check for pruning even if mailbox isn't valid */
    if(lastread < prune_time) {
	ret = 1;
    }	

    /* Only return true if we need to prune this guy */
    return ret;    
}

void process_seen(const char *path) 
{
    int r;    
    struct db *tmp = NULL;

    r = DB->open(path, &tmp);
    if(r) goto done;
    
    DB->foreach(tmp, "", 0, process_user_p, process_user_cb, tmp, NULL);

 done:
    if(tmp) DB->close(tmp);
}

void process_subs(const char *user) 
{
    /* xxx for this to be reasonable to do, we need to 
     * have a lookup-mailbox-by-name hash table as well
     *
     * can probably just use mboxlist_findsub() directly
     *
     * stubbing out for now
     */
}

void make_report(char *key, void *data, void *rock) 
{
    struct arb_mailbox_data *mbox = (struct arb_mailbox_data *)data;

    /* Skip underread user mailboxes */
    if(!strncasecmp(mbox->name, "user.", 5) && mbox->readers <= 1)
	return;    

    mboxname_hiersep_toexternal(&arb_namespace, mbox->name);

    printf("%s %d\n", mbox->name, mbox->readers);    
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "arbitron: %s\n", s);
    exit(code);
}

