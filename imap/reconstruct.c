/* reconstruct.c -- program to reconstruct a mailbox 
 *
 * Copyright 1998 Carnegie Mellon University
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
 */

/* $Id: reconstruct.c,v 1.43 2000/01/28 22:09:51 leg Exp $ */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <com_err.h>

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

#include "acl.h"
#include "assert.h"
#include "bsearch.h"
#include "imparse.h"
#include "config.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "xmalloc.h"

extern int errno;
extern int optind;
extern char *optarg;

extern char *mailbox_findquota P((const char *name));
extern acl_canonproc_t mboxlist_ensureOwnerRights;

int code = 0;

int do_reconstruct();

main(argc, argv)
int argc;
char **argv;
{
    int opt, i;
    int rflag = 0;
    int mflag = 0;
    char buf[MAX_MAILBOX_PATH];

    config_init("reconstruct");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_UIDVALIDITY+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_USER_FLAGS+MAX_USER_FLAGS/8));

    while ((opt = getopt(argc, argv, "rm")) != EOF) {
	switch (opt) {
	case 'r':
	    rflag = 1;
	    break;

	case 'm':
	    mflag = 1;
	    break;

	default:
	    usage();
	}
    }

    if (mflag) {
	if (rflag || optind != argc) usage();
	do_mboxlist();
    }

    mailbox_reconstructmode();

    if (optind == argc) {
	if (!rflag) usage();
	strcpy(buf, "*");
	mboxlist_findall(buf, 1, 0, 0, do_reconstruct, NULL);
    }

    for (i = optind; i < argc; i++) {
	if (rflag) {
	    strcpy(buf, argv[i]);
	    strcat(buf, ".*");
	    mboxlist_findall(argv[i], 1, 0, 0, do_reconstruct, NULL);
	    mboxlist_findall(buf, 1, 0, 0, do_reconstruct, NULL);
	}
	else {
	    do_reconstruct(argv[i], 0, 0);
	}
    }

    exit(code);
}

usage()
{
    fprintf(stderr, "usage: reconstruct [-r] mailbox...\n");
    fprintf(stderr, "       reconstruct -m\n");
    exit(EC_USAGE);
}    

int compare_uid(a, b)
char *a, *b;
{
    return *(unsigned long *)a - *(unsigned long *)b;
}

#define UIDGROW 300

/*
 * mboxlist_findall() callback function to reconstruct a mailbox
 */
int
do_reconstruct(name, matchlen, maycreate, rock)
char *name;
int matchlen;
int maycreate;
void* rock;
{
    int r;

    r = reconstruct(name);
    if (r) {
	com_err(name, r, (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	code = convert_code(r);
    }
    else {
	printf("%s\n", name);
    }

    return 0;
}

/*
 * Reconstruct the single mailbox named 'name'
 */
int 
reconstruct(name)
char *name;
{
    int r;
    struct mailbox mailbox;
    char *quota_root;
    int i, flag;
    char *p;
    const char *val;
    int format = MAILBOX_FORMAT_NORMAL;
    bit32 valid_user_flags[MAX_USER_FLAGS/32];
    char fnamebuf[MAX_MAILBOX_PATH];
    FILE *newindex;
    int newcache_fd;
    char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
	     INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
    unsigned long *uid;
    int uid_num, uid_alloc;
    DIR *dirp;
    struct dirent *dirent;
    int msg, old_msg = 0, new_exists = 0;
    unsigned long new_quota = 0;
    struct index_record message_index, old_index;
    static struct index_record zero_index;
    char newspath[4096], *end_newspath;
    const char *group;
    int newsprefixlen;
    FILE *msgfile;
    struct stat sbuf;
    int n;

    /* Open/lock header */
    r = mailbox_open_header(name, 0, &mailbox);
    if (r) {
	return r;
    }
    if (mailbox.header_fd != -1) {
	(void) mailbox_lock_header(&mailbox);
    }
    mailbox.header_lock_count = 1;

    if ((val = config_getstring("partition-news", 0)) &&
	!strncmp(val, mailbox.path, strlen(val)) &&
	mailbox.path[strlen(val)] == '/') {
	format = MAILBOX_FORMAT_NETNEWS;
    }

    if (chdir(mailbox.path) == -1) {
	return IMAP_IOERROR;
    }

    /* Fix quota root */
    quota_root = mailbox_findquota(mailbox.name);
    if (mailbox.quota.root) free(mailbox.quota.root);
    if (quota_root) {
	mailbox.quota.root = xstrdup(quota_root);
    }
    else {
	mailbox.quota.root = 0;
    }

    /* Validate user flags */
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	valid_user_flags[i] = 0;
    }
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox.flagname[flag]) continue;
	if ((flag && !mailbox.flagname[flag-1]) ||
	    !imparse_isatom(mailbox.flagname[flag])) {
	    free(mailbox.flagname[flag]);
	    mailbox.flagname[flag] = 0;
	}
	valid_user_flags[flag/32] |= 1<<(flag&31);
    }
    
    /* Write header */
    r = mailbox_write_header(&mailbox);
    if (r) {
	mailbox_close(&mailbox);
	return r;
    }

    /* Attempt to open/lock index */
    r = mailbox_open_index(&mailbox);
    if (r) {
	mailbox.exists = 0;
	mailbox.last_uid = 0;
	mailbox.last_appenddate = 0;
	mailbox.uidvalidity = time(0);
    }
    else {
	(void) mailbox_lock_index(&mailbox);
    }
    mailbox.index_lock_count = 1;
    mailbox.pop3_last_login = 0;

    /* Create new index/cache files */
    strcpy(fnamebuf, FNAME_INDEX+1);
    strcat(fnamebuf, ".NEW");
    newindex = fopen(fnamebuf, "w+");
    if (!newindex) {
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    strcpy(fnamebuf, FNAME_CACHE+1);
    strcat(fnamebuf, ".NEW");
    newcache_fd = open(fnamebuf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newcache_fd == -1) {
	fclose(newindex);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    
    memset(buf, 0, sizeof(buf));
    (*(bit32 *)buf) = mailbox.generation_no + 1;
    fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);
    retry_write(newcache_fd, buf, sizeof(bit32));

    /* Find all message files in directory */
    uid = (unsigned long *) xmalloc(UIDGROW * sizeof(unsigned long));
    uid_num = 0;
    uid_alloc = UIDGROW;
    if (format == MAILBOX_FORMAT_NETNEWS && config_newsspool) {
	/* Articles are over in the news spool directory, open it */
	strcpy(newspath, config_newsspool);
	end_newspath = newspath + strlen(newspath);
	if (end_newspath == newspath || end_newspath[-1] != '/') {
	    *end_newspath++ = '/';
	}

	group = mailbox.name;
	if (newsprefixlen = strlen(config_getstring("newsprefix", ""))) {
	    group += newsprefixlen;
	    if (*group == '.') group++;
	}
	strcpy(end_newspath, group);

	while (*end_newspath) {
	    if (*end_newspath == '.') *end_newspath = '/';
	    end_newspath++;
	}
	dirp = opendir(newspath);
	*end_newspath++ = '/';
    }
    else {
	dirp = opendir(".");
	end_newspath = newspath;
    }
    if (!dirp) {
	if (format == MAILBOX_FORMAT_NETNEWS)  {
	    /* If this is true, we might be looking at a newsgroup
	       with no entries, which INN is happy to just have a
	       nonexistant directory.  We don't want to give up,
	       because the index files that we're keeping in
	       partition-news might be invalid, and we need to check
	       them.  So we just find nothing.  */
	} else {
	    fclose(newindex);
	    close(newcache_fd);
	    mailbox_close(&mailbox);
	    free(uid);
	    return IMAP_IOERROR;
	}
    } else {
	while (dirent = readdir(dirp)) {
	    if (!isdigit(dirent->d_name[0]) || dirent->d_name[0] ==
		'0')
		continue;
	    if (uid_num == uid_alloc) {
		uid_alloc += UIDGROW;
		uid = (unsigned long *)
		    xrealloc((char *)uid, uid_alloc * sizeof(unsigned long));
	    }
	    uid[uid_num] = 0;
	    p = dirent->d_name;
	    while (isdigit(*p)) {
		uid[uid_num] = uid[uid_num] * 10 + *p++ - '0';
	    }
	    if (format != MAILBOX_FORMAT_NETNEWS) {
		if (*p++ != '.') continue;
	    }
	    if (*p) continue;
	    
	    uid_num++;
	}
	closedir(dirp);
	qsort((char *)uid, uid_num, sizeof(*uid), compare_uid);
    }

    /* Put each message file in the new index/cache */
    old_msg = 0;
    old_index.uid = 0;
    mailbox.format = format;
    if (mailbox.cache_fd) close(mailbox.cache_fd);
    mailbox.cache_fd = newcache_fd;

    for (msg = 0; msg < uid_num; msg++) {
	message_index = zero_index;
	message_index.uid = uid[msg];
	
	if (format == MAILBOX_FORMAT_NETNEWS) {
	    sprintf(end_newspath, "%u", uid[msg]);
	    msgfile = fopen(newspath, "r");
	}
	else {
	    msgfile = fopen(mailbox_message_fname(&mailbox, uid[msg]), "r");
	}
	if (!msgfile) continue;
	if (fstat(fileno(msgfile), &sbuf)) {
	    fclose(msgfile);
	    continue;
	}
	if (((sbuf.st_mode & S_IFMT) == S_IFDIR) && 
	    (format == MAILBOX_FORMAT_NETNEWS)) {
	  /* This is in theory a subnewsgroup and should be left alone. */
	  fclose(msgfile);
	  continue;
	}
	if (sbuf.st_size == 0) {
	    /* Zero-length message file--blow it away */
	    fclose(msgfile);
	    if (format != MAILBOX_FORMAT_NETNEWS) {
		unlink(mailbox_message_fname(&mailbox, uid[msg]));
	    }
	    continue;
	}

	/* Find old index record, if it exists */
	while (old_msg < mailbox.exists && old_index.uid < uid[msg]) {
	    if (mailbox_read_index_record(&mailbox, ++old_msg, &old_index)) {
		old_index.uid = 0;
	    }
	}

	if (old_index.uid == uid[msg]) {
	    /* Use data in old index file, subject to validity checks */
	    message_index.internaldate = old_index.internaldate;
	    message_index.system_flags = old_index.system_flags &
	      (FLAG_ANSWERED|FLAG_FLAGGED|FLAG_DELETED|FLAG_DRAFT);
	    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
		message_index.user_flags[i] =
		  old_index.user_flags[i] & valid_user_flags[i];
	    }
	}
	else {
	    /* Message file write time is good estimate of internaldate */
	    message_index.internaldate = sbuf.st_mtime;
	}
	message_index.last_updated = time(0);
	
	if (r = message_parse_file(msgfile, &mailbox, &message_index)) {
	    fclose(msgfile);
	    fclose(newindex);
	    mailbox_close(&mailbox);
	    free(uid);
	    return r;
	}
	fclose(msgfile);
	
	/* Write out new entry in index file */
	*((bit32 *)(buf+OFFSET_UID)) = htonl(message_index.uid);
	*((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(message_index.internaldate);
	*((bit32 *)(buf+OFFSET_SENTDATE)) = htonl(message_index.sentdate);
	*((bit32 *)(buf+OFFSET_SIZE)) = htonl(message_index.size);
	*((bit32 *)(buf+OFFSET_HEADER_SIZE)) = htonl(message_index.header_size);
	*((bit32 *)(buf+OFFSET_CONTENT_OFFSET)) = htonl(message_index.content_offset);
	*((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(message_index.cache_offset);
	*((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(message_index.last_updated);
	*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)) = htonl(message_index.system_flags);
	for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	    *((bit32 *)(buf+OFFSET_USER_FLAGS+4*i)) = htonl(message_index.user_flags[i]);
	}
	n = fwrite(buf, 1, INDEX_RECORD_SIZE, newindex);
	if (n != INDEX_RECORD_SIZE) {
	    fclose(newindex);
	    mailbox_close(&mailbox);
	    free(uid);
	    return IMAP_IOERROR;
	}

	new_exists++;
	new_quota += message_index.size;
    }
    
    /* Write out new index file header */
    rewind(newindex);
    if (uid_num && mailbox.last_uid < uid[uid_num-1]) {
	mailbox.last_uid = uid[uid_num-1] +
	    ((format == MAILBOX_FORMAT_NETNEWS) ? 0 : 100);
    }
    if (mailbox.last_appenddate == 0 || mailbox.last_appenddate > time(0)) {
	mailbox.last_appenddate = time(0);
    }
    if (mailbox.uidvalidity == 0 || mailbox.uidvalidity > time(0)) {
	mailbox.uidvalidity = time(0);
    }
    free(uid);
    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = mailbox.generation_no + 1;
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(mailbox.format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(MAILBOX_MINOR_VERSION);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(INDEX_HEADER_SIZE);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(INDEX_RECORD_SIZE);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(new_exists);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(mailbox.last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(mailbox.last_uid);
    *((bit32 *)(buf+OFFSET_QUOTA_MAILBOX_USED)) = htonl(new_quota);
    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(mailbox.pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox.uidvalidity);

    n = fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);
    fflush(newindex);
    if (n != INDEX_HEADER_SIZE || ferror(newindex) 
	|| fsync(fileno(newindex)) || fsync(newcache_fd)) {
	fclose(newindex);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }

    /* Rename new index/cache file in place */
    strcpy(fnamebuf, FNAME_INDEX+1);
    strcat(fnamebuf, ".NEW");
    if (rename(fnamebuf, FNAME_INDEX+1)) {
	fclose(newindex);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    strcpy(fnamebuf, FNAME_CACHE+1);
    strcat(fnamebuf, ".NEW");
    if (rename(fnamebuf, FNAME_CACHE+1)) {
	fclose(newindex);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    
    toimsp(mailbox.name, mailbox.uidvalidity,
	   "UIDNnn", mailbox.last_uid, new_exists, 0);

    fclose(newindex);
    r = seen_reconstruct(&mailbox, (time_t)0, (time_t)0, (int (*)())0, (void *)0);
    mailbox_close(&mailbox);
    return r;
}

/*
 * List of mailboxes in reconstructed mailbox list
 */
#define NEWMBOX_GROW 1000
char **newmbox_name = 0;
char **newmbox_partition = 0;
char **newmbox_acl = 0;
int newmbox_num = 0;
int newmbox_alloc = 0;

/*
 * Insert a mailbox 'name' with 'partition' and 'acl' into
 * the being-reconstructed mailbox list
 */
void
newmbox_insert(name, partition, acl)
char *name;
char *partition;
char *acl;
{
    int low=0;
    int high=newmbox_num-1;
    int mid, cmp, i;

    printf("%s %s\n", name, partition);

    if (newmbox_num == newmbox_alloc) {
	newmbox_alloc += NEWMBOX_GROW;
	newmbox_name = (char **)xrealloc((char *)newmbox_name,
					 newmbox_alloc * sizeof (char *));
	newmbox_partition = (char **)xrealloc((char *)newmbox_partition,
					      newmbox_alloc * sizeof (char *));
	newmbox_acl = (char **)xrealloc((char *)newmbox_acl,
					newmbox_alloc * sizeof (char *));
    }

    /* special-case -- appending to end */
    if (newmbox_num == 0 || bsearch_compare(name, newmbox_name[newmbox_num-1]) > 0) {
	newmbox_name[newmbox_num] = name;
	newmbox_partition[newmbox_num] = partition;
	newmbox_acl[newmbox_num] = acl;
	newmbox_num++;
	return;
    }
    
    /* Binary-search for location */
    while (low <= high) {
	mid = (high - low)/2 + low;
	cmp = bsearch_compare(name, newmbox_name[mid]);

	if (cmp == 0) return;

	if (cmp < 0) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    
    /* Open a slot for the new entry and insert entry into the list */
    for (i = newmbox_num-1; i > high; i--) {
	newmbox_name[i+1] = newmbox_name[i];
	newmbox_partition[i+1] = newmbox_partition[i];
	newmbox_acl[i+1] = newmbox_acl[i];
    }
    newmbox_num++;
    newmbox_name[low] = name;
    newmbox_partition[low] = partition;
    newmbox_acl[low] = acl;
}

int
newmbox_lookup(name)
char *name;
{
    int low=0;
    int high=newmbox_num-1;
    int mid, cmp;

    /* Binary-search for location */
    while (low <= high) {
	mid = (high - low)/2 + low;
	cmp = bsearch_compare(name, newmbox_name[mid]);

	if (cmp == 0) return 1;

	if (cmp < 0) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    return 0;
}

/* List of directories to scan for mailboxes */
struct todo {
    char *name;
    char *path;
    char *partition;
    struct todo *next;
} *todo_head = 0, **todo_tail = &todo_head;

void
todo_append(name, path, partition)
char *name;
char *path;
char *partition;
{
    struct todo *newentry;

    newentry = (struct todo *)xmalloc(sizeof(struct todo));
    newentry->name = name;
    newentry->path = path;
    newentry->partition = partition;
    newentry->next = 0;
    *todo_tail = newentry;
    todo_tail = &newentry->next;
}

void
todo_append_hashed(char *name, char *path, char *partition)
{
    DIR *dirp;
    struct dirent *dirent;

    dirp = opendir(path);
    if (!dirp) {
	fprintf(stderr, "reconstruct: couldn't open partition %s\n", name);
    } else while (dirent = readdir(dirp)) {
	struct todo *newentry;

	if (strchr(dirent->d_name, '.')) {
	    continue;
	}

	newentry = (struct todo *)xmalloc(sizeof(struct todo));
	newentry->name = xstrdup(name);
	newentry->path = xmalloc(strlen(path) +
				 strlen(dirent->d_name) + 2);
	sprintf(newentry->path, "%s/%s", path, dirent->d_name);
	newentry->partition = partition;
	newentry->next = 0;
	*todo_tail = newentry;
	todo_tail = &newentry->next;
    }
}

char *cleanacl(acl, mboxname)
char *acl;
char *mboxname;
{
    char owner[MAX_MAILBOX_NAME+1];
    acl_canonproc_t *aclcanonproc = 0;
    char *p;
    char *newacl;
    char *identifier;
    char *rights;

    /* Rebuild ACL */
    if (!strncmp(mboxname, "user.", 5)) {
	strcpy(owner, mboxname+5);
	p = strchr(owner, '.');
	if (p) *p = '\0';
	aclcanonproc = mboxlist_ensureOwnerRights;
    }
    newacl = xstrdup("");
    if (aclcanonproc) {
	acl_set(&newacl, owner, ACL_MODE_SET, ACL_ALL,
		(acl_canonproc_t *)0, (void *)0);
    }
    for (;;) {
	identifier = acl;
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';
	acl = strchr(rights, '\t');
	if (!acl) break;
	*acl++ = '\0';

	acl_set(&newacl, identifier, ACL_MODE_SET, acl_strtomask(rights),
		aclcanonproc, (void *)owner);
    }

    return newacl;
}

/*
 * Reconstruct the mailboxes list.
 */
do_mboxlist()
{
    int r;
    const char *listfname, *newlistfname;
    const char *startline;
    unsigned long left;
    const char *endline;
    char *p;
    char *mboxname;
    char *partition;
    char *acl;
    char optionbuf[MAX_MAILBOX_NAME+1];
    const char *root;
    static char pathresult[MAX_MAILBOX_PATH];
    struct mailbox mailbox;
    char *newacl;
    int isnewspartition;
    DIR *dirp;
    struct dirent *dirent;
    struct todo *todo_next;
    char *path;
    FILE *newlistfile;
    int i;

    /* Lock mailbox list */
    r = mboxlist_open();
    if (r) {
	fprintf(stderr, "reconstruct: cannot open/lock mailboxes file\n");
	exit(1);
    }

    mboxlist_getinternalstuff(&listfname, &newlistfname,
			      &startline, &left);

    /* For each line in old mailboxes file */
    while (endline = memchr(startline, '\n', left)) {
	/* Copy line into malloc'ed memory; skip over line */
	mboxname = xmalloc(endline - startline + 1);
	strncpy(mboxname, startline, endline - startline);
	mboxname[endline - startline] = '\0';
	left -= endline - startline + 1;
	startline = endline + 1;

	/* Parse line */
	partition = strchr(mboxname, '\t');
	if (!partition) continue;
	*partition++ = '\0';
	acl = strchr(partition, '\t');
	if (!acl) continue;
	*acl++ = '\0';
	
	/* Check syntax of name */
	if (mboxname_policycheck(mboxname)) continue;

	/* Check partition existence */
	if (strlen(partition) > sizeof(optionbuf)-11) {
	    continue;
	}
	strcpy(optionbuf, "partition-");
	strcat(optionbuf, partition);
	root = config_getstring(optionbuf, (char *)0);
	if (!root) {
	    continue;
	}
	
	/* Check mailbox exists */
	mailbox_hash_mbox(pathresult, root, mboxname);
	r = mailbox_open_header_path(mboxname, pathresult, "", 0,
				     &mailbox, 1);
	if (r) {
	    /* Try lowercasing mailbox name */
	    lcase(mboxname);
	    mailbox_hash_mbox(pathresult, root, mboxname);

	    r = mailbox_open_header_path(mboxname, pathresult, "", 0,
					 &mailbox, 1);
	}

	if (r) continue;

	newacl = cleanacl(acl, mboxname);

	/* Store new ACL in mailbox header */
	r = mailbox_lock_header(&mailbox);
	if (!r) {
	    free(mailbox.acl);
	    mailbox.acl = xstrdup(newacl);
	    (void) mailbox_write_header(&mailbox);
	}

	mailbox_close(&mailbox);
	newmbox_insert(mboxname, partition, newacl);
    }
    
    /* Enqueue each partition directory for scanning */
    if (config_hashimapspool) {
	config_scanpartition(todo_append_hashed);
    } else {
	config_scanpartition(todo_append);
    }

    /* Process each directory in queue */
    while (todo_head) {
	isnewspartition = (strcmp(todo_head->partition, "news") == 0);
	dirp = opendir(todo_head->path);
	if (!dirp) {
	    free(todo_head->name);
	    free(todo_head->path);
	    todo_next = todo_head->next;
	    free((char *)todo_head);
	    todo_head = todo_next;
	    continue;
	}

	while (dirent = readdir(dirp)) {
	    if (!strchr(dirent->d_name, '.')) {
		/* Ignore all-numeric files in news partitons */
		if (isnewspartition) {
		    p = dirent->d_name;
		    while (*p) {
			if (!isdigit(*p)) break;
			p++;
		    }
		    if (!*p) continue;
		}

		/* Probably a directory, enqueue it */
		mboxname = xmalloc(strlen(todo_head->name) +
				   strlen(dirent->d_name) + 2);
		path = xmalloc(strlen(todo_head->path) +
			       strlen(dirent->d_name) + 2);
		strcpy(mboxname, todo_head->name);
		if (mboxname[0]) strcat(mboxname, ".");
		strcat(mboxname, dirent->d_name);
		strcpy(path, todo_head->path);
		strcat(path, "/");
		strcat(path, dirent->d_name);
		todo_append(mboxname, path, todo_head->partition);
	    }
	    else if (!strcmp(dirent->d_name, FNAME_HEADER+1) &&
		     !newmbox_lookup(todo_head->name) &&
		     !mailbox_open_header_path(todo_head->name,
					       todo_head->path, "", 0,
					       &mailbox, 1)) {
		r = mailbox_open_index(&mailbox);
		if (!r) {
		    r = mailbox_read_header_acl(&mailbox);
		}
		if (!r) {
		    newmbox_insert(todo_head->name, todo_head->partition,
				   cleanacl(mailbox.acl, todo_head->name));
		}
		mailbox_close(&mailbox);
	    }
	}
	closedir(dirp);

	todo_next = todo_head->next;
	free(todo_head->path);
	free((char *)todo_head);
	todo_head = todo_next;
    }
	
    newlistfile = fopen(newlistfname, "w");
    for (i = 0; i < newmbox_num; i++) {
	fprintf(newlistfile, "%s\t%s\t%s\n",
		newmbox_name[i], newmbox_partition[i], newmbox_acl[i]);
    }
    fflush(newlistfile);

    if (ferror(newlistfile) || fsync(fileno(newlistfile))) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	perror("writing new mailboxes list");
	exit(1);
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	perror("renaming new mailboxes list");
	exit(1);
    }
    
    exit(0);
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "reconstruct: %s\n", s);
    exit(code);
}

