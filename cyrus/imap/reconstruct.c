/* reconstruct.c -- program to reconstruct a mailbox 
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
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

#include "assert.h"
#include "config.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

extern int errno;
extern int optind;
extern char *optarg;

extern char *mailbox_findquota();

int code = 0;

int do_reconstruct();

main(argc, argv)
int argc;
char **argv;
{
    int opt, i;
    int rflag = 0;
    char buf[MAX_MAILBOX_PATH];

    config_init("reconstruct");

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_UIDVALIDITY+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_USER_FLAGS+MAX_USER_FLAGS/8));

    while ((opt = getopt(argc, argv, "r")) != EOF) {
	switch (opt) {
	case 'r':
	    rflag = 1;
	    break;

	default:
	    usage();
	}
    }

    mailbox_reconstructmode();

    for (i = optind; i < argc; i++) {
	if (rflag) {
	    strcpy(buf, argv[i]);
	    strcat(buf, ".*");
	    mboxlist_findall(argv[i], 1, 0, do_reconstruct);
	    mboxlist_findall(buf, 1, 0, do_reconstruct);
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
    exit(EX_USAGE);
}    

int compare_uid(a, b)
char *a, *b;
{
    return *(unsigned long *)a - *(unsigned long *)b;
}

#define UIDGROW 300

int
do_reconstruct(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
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

int 
reconstruct(name)
char *name;
{
    int r;
    struct mailbox mailbox;
    char *quota_root;
    int i, flag;
    char *p;
    int format = MAILBOX_FORMAT_NORMAL;
    bit32 valid_user_flags[MAX_USER_FLAGS/32];
    char fnamebuf[MAX_MAILBOX_PATH];
    FILE *newindex, *newcache;
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
    FILE *msgfile;
    struct stat sbuf;
    int n;

    /* Open/lock header */
    r = mailbox_open_header(name, &mailbox);
    if (r) {
	return r;
    }
    if (mailbox.header) {
	(void) mailbox_lock_header(&mailbox);
    }
    mailbox.header_lock_count = 1;

    if ((p = config_getstring("partition-news", 0)) &&
	!strncmp(p, mailbox.path, strlen(p)) &&
	mailbox.path[strlen(p)] == '/') {
	format = MAILBOX_FORMAT_NETNEWS;
    }

    if (chdir(mailbox.path) == -1) {
	return IMAP_IOERROR;
    }

    /* Fix quota root */
    quota_root = mailbox_findquota(mailbox.name);
    if (mailbox.quota.root) free(mailbox.quota.root);
    if (quota_root) {
	mailbox.quota.root = strsave(quota_root);
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
	    !is_atom(mailbox.flagname[flag])) {
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
	mailbox.pop3_last_uid = 0;
	mailbox.uidvalidity = time(0);
    }
    else {
	(void) mailbox_lock_index(&mailbox);
    }
    mailbox.index_lock_count = 1;

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
    newcache = fopen(fnamebuf, "w+");
    if (!newcache) {
	fclose(newindex);
	mailbox_close(&mailbox);
	return IMAP_IOERROR;
    }
    
    memset(buf, 0, sizeof(buf));
    (*(bit32 *)buf) = mailbox.generation_no + 1;
    fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);
    fwrite(buf, 1, sizeof(bit32), newcache);

    /* Find all message files in directory */
    uid = (unsigned long *) xmalloc(UIDGROW * sizeof(unsigned long));
    uid_num = 0;
    uid_alloc = UIDGROW;
    dirp = opendir(".");
    if (!dirp) {
	fclose(newindex);
	fclose(newcache);
	mailbox_close(&mailbox);
	free(uid);
	return IMAP_IOERROR;
    }
    while (dirent = readdir(dirp)) {
	if (!isdigit(dirent->d_name[0]) || dirent->d_name[0] == '0') continue;
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

    /* Put each message file in the new index/cache */
    old_msg = 0;
    old_index.uid = 0;
    mailbox.format = format;
    if (mailbox.cache) fclose(mailbox.cache);
    mailbox.cache = newcache;
    for (msg = 0; msg < uid_num; msg++) {
	message_index = zero_index;
	message_index.uid = uid[msg];
	
	msgfile = fopen(mailbox_message_fname(&mailbox, uid[msg]), "r");
	if (!msgfile) continue;
	if (fstat(fileno(msgfile), &sbuf)) {
	    fclose(msgfile);
	    continue;
	}
	if (sbuf.st_size == 0) {
	    /* Zero-length message file--blow it away */
	    fclose(msgfile);
	    unlink(mailbox_message_fname(&mailbox, uid[msg]));
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
	
	if (r = message_parse(msgfile, &mailbox, &message_index)) {
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
    if (mailbox.last_uid < uid[uid_num-1]) {
	mailbox.last_uid = uid[uid_num-1] +
	    ((format == MAILBOX_FORMAT_NETNEWS) ? 0 : 100);
    }
    if (mailbox.last_appenddate == 0 || mailbox.last_appenddate > time(0)) {
	mailbox.last_appenddate = time(0);
    }
    if (mailbox.pop3_last_uid > uid[uid_num-1]) {
	mailbox.pop3_last_uid = uid[uid_num-1];
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
    *((bit32 *)(buf+OFFSET_POP3_LAST_UID)) = htonl(mailbox.pop3_last_uid);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(mailbox.uidvalidity);

    n = fwrite(buf, 1, INDEX_HEADER_SIZE, newindex);
    fflush(newindex);
    fflush(newcache);
    if (n != INDEX_HEADER_SIZE || ferror(newindex) || ferror(newcache)
	|| fsync(fileno(newindex)) || fsync(fileno(newcache))) {
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
    
    drop_last(mailbox.name, mailbox.last_uid, new_exists);

    fclose(newindex);
    r = seen_reconstruct(&mailbox);
    mailbox_close(&mailbox);
    return r;
}

int convert_code(r)
int r;
{
    switch (r) {
    case 0:
	return 0;
	
    case IMAP_IOERROR:
	return EX_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EX_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
	return EX_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
	return EX_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	return EX_UNAVAILABLE;
    }
	
    /* Some error we're not expecting. */
    return EX_SOFTWARE;
}	

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "reconstruct: %s\n", s);
    exit(code);
}

