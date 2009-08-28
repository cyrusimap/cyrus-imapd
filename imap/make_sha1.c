/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *
 * $Id: make_sha1.c,v 1.6 2009/08/28 13:48:46 brong Exp $
 */

#include <config.h>

#include <stdio.h>

#ifdef HAVE_SSL

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "util.h"

#include <openssl/sha.h>

/* global state */
const int config_need_data = 0;

extern char *optarg;
extern int optind;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;

void printastring(const char *s __attribute__((unused)))
{
    fatal("not implemented", EC_SOFTWARE);
}

void printstring(const char *s __attribute__((unused)))
{
    fatal("not implemented", EC_SOFTWARE);
}

/* end stuff to make index.c link */

static int verbose = 0;

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    seen_done();
    quotadb_close();
    quotadb_done();
    mboxlist_close();
    mboxlist_done();
    cyrus_done();
    exit(code);
}

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [-C <alt_config>] [-d] [-k <count>] [-v]"
            " [-m <offset>] [-M <modulo>] user...\n",
            name);
 
    exit(EC_USAGE);
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "make_sha1: %s\n", s);
    exit(code);
}

/* ====================================================================== */

struct sha1_node {
    struct sha1_node *next;
    int           active;
    unsigned long uid;
    unsigned char sha1_msg[20];
    unsigned char sha1_cache[20];
};

struct sha1_mailbox {
    struct sha1_mailbox *next;
    char *name;
    char *uniqueid;
    struct sha1_node *head;
    struct sha1_node *tail;
    unsigned long count;
    int active;
};

struct sha1_mailbox_list {
    struct sha1_mailbox *head;
    struct sha1_mailbox *tail;
    unsigned long count;
    int dirty;
};

static void
sha1_mailbox_free(struct sha1_mailbox *list)
{
    struct sha1_node *current, *next;

    for (current = list->head; current ; current = next) {
        next = current->next;
        free(current);
    }
    free(list->name);
    free(list->uniqueid);
    free(list);
}

static void
sha1_mailbox_rename(struct sha1_mailbox *mailbox, char *name)
{
    free(mailbox->name);
    mailbox->name = xstrdup(name);
}

static struct sha1_node *
sha1_mailbox_add(struct sha1_mailbox *list,
                unsigned long uid,
                unsigned char sha1_msg[20],
                unsigned char sha1_cache[20],
                int active)
{
    struct sha1_node *new = xmalloc(sizeof(struct sha1_node));
    struct sha1_node *current, *last;

    new->next = NULL;
    new->uid  = uid;
    new->active = active;
    memcpy(&new->sha1_msg, sha1_msg, 20);
    memcpy(&new->sha1_cache, sha1_cache, 20);

    list->count++;

    if (list->head == NULL) {
        /* Add to empty list */
        list->head = list->tail = new;
        return(new);
    }

    assert(list->tail != NULL);
    if (list->tail->uid < uid) {
        /* Add to end of list */
        /* This is the common case as UIDs assigned in ascending order */
        list->tail = list->tail->next = new;
        return(new);
    }

    assert(list->head != NULL);
    if (uid < list->head->uid) {
        new->next = list->head;  /* Add to start of list */
        list->head = new;
        return(new);
    }

    current = list->head;
    do {
        last    = current;
        current = current->next;
    } while (current && (uid > current->uid));

    if (current && (uid < current->uid)) {
        new->next  = current;  /* Insert between last and current */
        last->next = new;
        return(new);
    }
    return(current);
}

static struct sha1_mailbox_list *
sha1_mailbox_list_create(void)
{
    struct sha1_mailbox_list *list = xmalloc(sizeof(struct sha1_mailbox_list));

    list->head  = NULL;
    list->tail  = NULL;
    list->count = 0;
    list->dirty = 0;

    return(list);
}

static void
sha1_mailbox_list_free(struct sha1_mailbox_list *list)
{
    struct sha1_mailbox *current, *next;

    for (current = list->head; current ; current = next) {
        next = current->next;
        sha1_mailbox_free(current);
    }
    free(list);
}

static struct sha1_mailbox *
sha1_mailbox_list_add(struct sha1_mailbox_list *list, char *name, char *uniqueid)
{
    struct sha1_mailbox *new = xzmalloc(sizeof(struct sha1_mailbox));
    struct sha1_mailbox *current, *last;

    list->count++;
    new->next = NULL;
    new->name = xstrdup(name);
    new->uniqueid = xstrdup(uniqueid);
    new->head = NULL;
    new->tail = NULL;
    new->count = 0;
    new->active = 0;

    if (list->head == NULL) {
        /* Add to empty list */
        list->head = list->tail = new;
        return(new);
    }

    assert(list->tail != NULL);
    if (strcmp(list->tail->uniqueid, uniqueid) < 0) {
        /* Add to end of list */
        /* This is the common case as folders sorted in ascending order */
        list->tail = list->tail->next = new;
        return(new);
    }
    
    assert(list->head != NULL);
    if (strcmp(list->head->uniqueid, uniqueid) > 0) {
        new->next = list->head;  /* Add to start of list */
        list->head = new;
        return(new);
    }

    current = list->head;
    do {
        last    = current;
        current = current->next;
    } while (current && (strcmp(uniqueid, current->uniqueid) > 0));

    if (!current)
        return(NULL);

    if (!strcmp(uniqueid, current->uniqueid)) {
        if (strcmp(current->name, name) != 0) {
            free(current->name);
            current->name = xstrdup(name);
        }
        return(current);
    }

    /* Insert between last and current */
    new->next  = current;  
    last->next = new;
    return(new);
}

static struct sha1_mailbox *
sha1_mailbox_list_find(struct sha1_mailbox_list *list, char *uniqueid)
{
    struct sha1_mailbox *mailbox;

    for (mailbox = list->head ; mailbox ; mailbox = mailbox->next) {
        if (!strcmp(mailbox->uniqueid, uniqueid))
            return(mailbox);
    }
    return(NULL);
}

static int
sha1_mailbox_list_check_deleted(struct sha1_mailbox_list *list)
{
    struct sha1_mailbox *mailbox;

    for (mailbox = list->head ; mailbox ; mailbox = mailbox->next) {
        if (!mailbox->active) {
            list->dirty = 1;
            return(1);
        }
    }
    return(0);
}

static int
sha1_parse(unsigned char sha1[20], char *s)
{
    int i;
    char c;

    if (strlen(s) != 40)
        return(0);

    for (i = 0 ; i < 20 ; i++) {
        c = *s++;

        if ((c >= '0') && (c <= '9'))
            sha1[i] = (c - '0') * 16;
        else if ((c >= 'a') && (c <= 'z'))
            sha1[i] = (c - 'a' + 10) * 16;
        else if ((c >= 'A') && (c <= 'Z'))
            sha1[i] = (c - 'A' + 10) * 16;
        else
            return(0);

        c = *s++;

        if ((c >= '0') && (c <= '9'))
            sha1[i] += (c - '0');
        else if ((c >= 'a') && (c <= 'z'))
            sha1[i] += (c - 'a' + 10);
        else if ((c >= 'A') && (c <= 'Z'))
            sha1[i] += (c - 'A' + 10);
        else
            return(0);
    }
    return(1);
}

static int
sha1_mailbox_list_read(struct sha1_mailbox_list *list, char *name)
{
    struct sha1_mailbox *current = NULL;
    FILE *file;
    char buf[MAX_MAILBOX_BUFFER]; /* mboxname + uniqueid(16) + SP + CR */
    unsigned char sha1_msg[20];
    unsigned char sha1_cache[20];
    int len;
    int lineno = 0;
    unsigned long uid;
    char *mboxname, *uniqueid, *s;

    if ((file=fopen(name, "r")) == NULL)
        return(0);

    while (fgets(buf, sizeof(buf), file)) {
        ++lineno;

        if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
            buf[--len] = '\0';

        if ((buf[0] == '#') || (buf[0] == '\0'))
            continue;

        if (buf[0] != ' ') {
            /* "%s %s", mboxname, uniqueid. mboxname may contain spaces */
            mboxname = buf;
            uniqueid = strrchr(buf, ' ');

            if ((uniqueid == NULL) || ((uniqueid - mboxname) < 6))
                goto parse_err;
            *uniqueid++ = '\0';

            current = sha1_mailbox_list_add(list, mboxname, uniqueid);
        } else {
            if (!(current && (s = strtok(buf, "\t ")) && (uid = atoi(s)) &&
                  (s = strtok(NULL, "\t ")) && sha1_parse(sha1_msg, s) &&
                  (s = strtok(NULL, "\t ")) && sha1_parse(sha1_cache, s)))
                goto parse_err;

            sha1_mailbox_add(current, uid, sha1_msg, sha1_cache, 0);
        }
    }
    fclose(file);
    return(0);

 parse_err:
    syslog(LOG_ERR, "Invalid format input file %s at line %d",
           name, lineno);
    fclose(file);
    return(IMAP_IOERROR);
}

static int
sha1_mailbox_list_write(struct sha1_mailbox_list *list, char *name)
{
    struct sha1_mailbox *mailbox;
    struct sha1_node    *node;
    FILE *file;
    int i;

    file = fopen(name, "w");
    if (file == NULL && errno == ENOENT) {
	if (cyrus_mkdir(name, 0750) == 0) {
	    file = fopen(name, "w");
	}
    }
    if (file == NULL)
        return(IMAP_IOERROR);

    for (mailbox = list->head ; mailbox ; mailbox = mailbox->next) {
        if (!mailbox->active)
            continue;

        fprintf(file, "%s %s\n", mailbox->name, mailbox->uniqueid);

        for (node = mailbox->head ; node ; node = node->next) {
            if (!node->active)
                continue;

            fprintf(file, " %lu: ", node->uid);
            for (i = 0 ; i < 20 ; i++)
                fprintf(file, "%-2.2x", node->sha1_msg[i]);
            fprintf(file, " ");
            for (i = 0 ; i < 20 ; i++)
                fprintf(file, "%-2.2x", node->sha1_cache[i]);
            fprintf(file, "\n");
        }
    }
    fclose(file);
    return(0);
}

/* ====================================================================== */

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   resulting message digest number will be written into the 20 bytes
   beginning at RESBLOCK.  */
static void *
sha1_buffer (const char *buffer, size_t len, void *resblock)
{
    SHA1((const unsigned char *) buffer, len, resblock);

    return resblock;
}

/* Compute SHA1 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 20 bytes
   beginning at RESBLOCK.  */
static int
sha1_stream (FILE *stream, void *resblock)
{
    const char *base = NULL;
    unsigned long len = 0;

    map_refresh(fileno(stream), 1, &base, &len, MAP_UNKNOWN_LEN, "msg", NULL);

    sha1_buffer(base, len, resblock);

    map_free(&base, &len);

    return 0;
}

static int
sha1_single(char *name, int matchlen __attribute__((unused)),
	    int maycreate __attribute__((unused)),
	    void *rock)
{
    struct mailbox m;
    int    r = 0;
    unsigned long msgno;
    struct index_record record;
    unsigned char sha1_msg[20], sha1_cache[20];
    char buf[MAX_MAILBOX_PATH+1];
    FILE *file;
    struct sha1_mailbox_list *sha1_mailbox_list;
    struct sha1_mailbox *sha1_mailbox;
    struct sha1_node *sha1_node;
    unsigned long cache_offset;
    unsigned long cache_size;

    if (verbose > 1)
        printf("   %s\n", name);

    sha1_mailbox_list = (struct sha1_mailbox_list *)rock;

    /* First we have to jump through hoops to open the mailbox and its
       Cyrus index. */
    memset(&m, 0, sizeof(struct mailbox));

    /* Garbage collect live cache file */
    if (!r) r = mailbox_open_header(name, 0, &m);
    if (r) {
        syslog(LOG_NOTICE, "error opening %s: %s\n", name, error_message(r));
        return(r);
    }

    if (!r) r = mailbox_open_index(&m);

    if (r) {
        syslog(LOG_NOTICE, "error opening %s: %s\n", name, error_message(r));
        goto bail;
    }

    if (!(sha1_mailbox=sha1_mailbox_list_find(sha1_mailbox_list,m.uniqueid))) {
        /* New mailbox */
        sha1_mailbox = sha1_mailbox_list_add(sha1_mailbox_list,
                                             name, m.uniqueid);
        sha1_mailbox_list->dirty = 1;
    }

    if (!sha1_mailbox) {
        syslog(LOG_NOTICE, "Failed to create sha1_mailbox_list for %s", name);
        goto bail;
    }

    if (strcmp(sha1_mailbox->name, m.name) != 0) {
        /* Renamed mailbox */
        sha1_mailbox_rename(sha1_mailbox, m.name);
        sha1_mailbox_list->dirty = 1;
    }

    sha1_mailbox->active = 1;
    sha1_node = sha1_mailbox->head;

    for (msgno = 1 ; msgno <= m.exists ; msgno++) {
        if ((r=mailbox_read_index_record(&m, msgno, &record))) {
            syslog(LOG_ERR, "IOERROR: %s failed to read index record %lu/%lu",
                   m.name, msgno, m.exists);
            r = IMAP_IOERROR;
            goto bail;
        }

        if (record.uid == 0) {
            syslog(LOG_ERR, "IOERROR: %s zero index record %lu/%lu",
                   m.name, msgno, m.exists);
            r = IMAP_IOERROR;
            goto bail;
        }

        /* Skip over UIDs in sha1_mailbox which have now been deleted
         * (but record fact that sha1 list should be updated for this user) */
        while (sha1_node && (sha1_node->uid < record.uid)) {
            sha1_mailbox_list->dirty = 1; /* Need to write out new SHA1 list */
            sha1_node->active = 0;
            sha1_node = sha1_node->next;
        }

        /* Check whether SHA1 value already exists for this UID */
        if (sha1_node && (sha1_node->uid == record.uid)) {
            sha1_node->active = 1;
            sha1_node = sha1_node->next;
            continue;
        }

        snprintf(buf, sizeof(buf), "%s/%lu.", m.path, record.uid);

        if (!(file=fopen(buf, "r"))) {
            syslog(LOG_ERR, "IOERROR: %s failed to open msg UID %lu",
                   m.name, record.uid);
            r = IMAP_IOERROR;
            goto bail;
        }

        if (sha1_stream(file, sha1_msg) != 0) {
            syslog(LOG_ERR, "IOERROR: %s failed to sha1 msg UID %lu",
                   m.name, record.uid);
            r = IMAP_IOERROR;
            fclose(file);
            goto bail;
        }

        cache_offset = record.cache_offset;
        cache_size = mailbox_cacherecord_index(&m, msgno, 0);

        if (!sha1_buffer(m.cache_base+cache_offset, cache_size, sha1_cache)) {
            syslog(LOG_ERR, "IOERROR: %s failed to sha1 msg cache UID %lu",
                   m.name, record.uid);
            r = IMAP_IOERROR;
            goto bail;
        }

        sha1_mailbox_add(sha1_mailbox, record.uid, sha1_msg, sha1_cache, 1);
        sha1_mailbox_list->dirty = 1; /* Need to write out new SHA1 list */
        fclose(file);
    }
    /* Check for deletions at end of the folder */
    if (sha1_node)
        sha1_mailbox_list->dirty = 1; /* Need to write out new SHA1 list */

 bail:
#if 0
    mailbox_unlock_expire(&m);
#endif
    mailbox_close(&m);
    return(r);
}

/* ====================================================================== */

/* If uid_set and uid_modulo non-zero, use existing database entry for all
 * but given tranche of users. That tranche gets regenerated from scratch */

static int use_existing_data(char *s, unsigned uid_set, int uid_modulo)
{
    unsigned long total;

    if (uid_modulo == 0)
        return(1);

    total = 0;
    while (*s) {
        total += (unsigned long)*s;
        s++;
    }
    
    return ((uid_set == (total % uid_modulo)) ? 0 : 1);
}

static int
do_user(const char *sha1_dir, char *user, struct namespace *namespacep,
        int uid_set, int uid_modulo)
{
    char  buf[MAX_MAILBOX_PATH+1];
    char  buf2[MAX_MAILBOX_PATH+1];
    int   r = 0;
    int   regenerate = 0;
    struct sha1_mailbox_list *sha1_mailbox_list = sha1_mailbox_list_create();

    imapd_userid    = user;
    imapd_authstate = auth_newstate(imapd_userid);

    if (use_existing_data(user, uid_set, uid_modulo)) {
        snprintf(buf, sizeof(buf)-1, "%s/%c/%s", sha1_dir, user[0], user);
        r = sha1_mailbox_list_read(sha1_mailbox_list, buf);

        if (r) {
            syslog(LOG_NOTICE, "Failed to read mailbox list for %s", user);
            sha1_mailbox_list_free(sha1_mailbox_list);
            return(r);
        }

        if (verbose > 0)
            printf("Make_SHA1: %s\n", user);

    } else {
        regenerate = 1;
        if (verbose > 0)
            printf("Make_SHA1: %s (regenerating)\n", user);
    }

    /* Index inbox */
    snprintf(buf, sizeof(buf)-1, "user.%s", user);
    sha1_single(buf, 0, 0, sha1_mailbox_list);
    
    /* And then all folders */
    snprintf(buf, sizeof(buf)-1, "user.%s.*", user);
    r = (namespacep->mboxlist_findall)(namespacep, buf, 0,
                                       imapd_userid, imapd_authstate,
                                       sha1_single, sha1_mailbox_list);
    if (r) {
        syslog(LOG_NOTICE, "Failed to enumerate mailboxes for %s", user);
        sha1_mailbox_list_free(sha1_mailbox_list);
        return(r);
    }

    auth_freestate(imapd_authstate);

    /* If mailbox have been deleted, we need to rewrite */
    if (sha1_mailbox_list->dirty ||
        sha1_mailbox_list_check_deleted(sha1_mailbox_list)) {
        snprintf(buf, sizeof(buf)-1, "%s/%c/%s-NEW", sha1_dir, user[0], user);
        sha1_mailbox_list_write(sha1_mailbox_list, buf);

        snprintf(buf, sizeof(buf)-1, "%s/%c/%s-NEW", sha1_dir, user[0], user);
        snprintf(buf2, sizeof(buf2)-1, "%s/%c/%s", sha1_dir, user[0], user);

        if (rename(buf, buf2) < 0) {
            syslog(LOG_NOTICE, "Failed to rename %s -> %s", buf, buf2);
            sha1_mailbox_list_free(sha1_mailbox_list);
            return(IMAP_IOERROR);
        }
    }

    if (regenerate)
        syslog(LOG_NOTICE, "Done make_sha1 for %s (regenerated)", user);
    else
        syslog(LOG_NOTICE, "Done make_sha1 for %s", user);

    sha1_mailbox_list_free(sha1_mailbox_list);
    return(0);
}

/* ====================================================================== */

static unsigned long sha1_children = 0;

static void
sha1_child_reaper()
{
    int              status;
    pid_t            child;

    do {
        child = waitpid(0, &status, WNOHANG);
        if ((child > 0) && (sha1_children > 0))
            sha1_children--;
    } while (child > 0);
}

static int
sha1_signal_child_init(void (*fn)())
{
    struct sigaction act, oact;

    sigemptyset(&act.sa_mask);
    act.sa_handler = fn;
    act.sa_flags   = 0;
  
    if (sigaction(SIGCHLD, &act, &oact) == 0)
        return(1);
  
    fprintf(stderr, "[os_signal_child_init()] sigaction() failed: %s",
            strerror(errno));
    return(0);
}

/* ====================================================================== */

int main(int argc, char **argv)
{
    int   opt;
    char *alt_config = NULL;
    char *input_file = NULL;
    const char *sha1_dir  = NULL;
    unsigned   uid_set    = 0;
    int   uid_modulo = 0;
    int   r = 0;
    int   i;
    unsigned   max_children = 0;
    pid_t pid;
    struct namespace sha1_namespace;
    char buf[512];
    FILE *file;
    int len;

    if(geteuid() == 0)
        fatal("must run as the Cyrus user", EC_USAGE);

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:D:k:f:m:M:v")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'D': /* SHA1 directory */
            sha1_dir = optarg;
            break;

        case 'f': /* Input file */
            input_file = optarg;
            break;

        case 'k': /* Concurrent threads */
            max_children = atoi(optarg);
            break;

        case 'm': /* Together with -M process fraction of users */
            uid_set = atoi(optarg);
            break;

        case 'M': /* Together with -m process fraction of users */
            uid_modulo = atoi(optarg);
            break;

        case 'v': /* verbose */
            verbose++;
            break;

        default:
            usage("make_sha1");
        }
    }

    /* Set up default bounds if no command line options provided */

    cyrus_init(alt_config, "make_sha1", 0);

    syslog(LOG_NOTICE, "Generating SHA1 checksums for mailboxes");

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&sha1_namespace, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);
    mailbox_initialize();

    /* open the quota db, we'll need it for real work */
    quotadb_init(0);
    quotadb_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (!input_file && (optind == argc)) {
        fprintf(stderr, "please specify user to SHA1\n");
        shut_down(1);
    }

    if (!sha1_dir) sha1_dir = config_getstring(IMAPOPT_SHA1_DIR);

    if (!sha1_dir)
        sha1_dir = xstrdup("/var/imap/sha1");

    if (max_children == 0) {
        /* Simple case */

        if (input_file) {
            if ((file=fopen(input_file, "r")) == NULL) {
                syslog(LOG_NOTICE, "Unable to open %s: %m", input_file);
                shut_down(1);
            }
            while (fgets(buf, sizeof(buf), file)) {
                /* Chomp, then ignore empty/comment lines. */
                if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                    buf[--len] = '\0';

                if ((len == 0) || (buf[0] == '#'))
                    continue;

                if (do_user(sha1_dir, buf, &sha1_namespace,
                            uid_set, uid_modulo)) {
                    syslog(LOG_NOTICE, "Error make_sha1 %s: %m", buf);
                    shut_down(1);
                }
            }
            fclose(file);
        } else for (i = optind; i < argc; i++) {
            if (do_user(sha1_dir, argv[i], &sha1_namespace,
                        uid_set, uid_modulo)) {
                syslog(LOG_NOTICE, "Error make_sha1 %s: %m", argv[i]);
                shut_down(1);
            }
        }

        syslog(LOG_NOTICE, "Done SHA1 checksums for mailboxes");
        shut_down(0);
    }

    /* Enable child handler */
    if (!sha1_signal_child_init(sha1_child_reaper)) {
        fprintf(stderr, "Couldn't initialise child reaper\n");
        exit(1);
    }

    if (input_file) {
        if ((file=fopen(input_file, "r")) == NULL) {
            syslog(LOG_NOTICE, "Unable to open %s: %m", input_file);
            shut_down(1);
        }
        while (fgets(buf, sizeof(buf), file)) {
            /* Chomp, then ignore empty/comment lines. */
            if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                buf[--len] = '\0';
            
            if ((len == 0) || (buf[0] == '#'))
                continue;


            while (sha1_children == max_children)   /* Concurrency limit */
                pause();
    
            if ((pid = fork()) < 0) {
                fprintf(stderr, "Fork failed.\n");
                shut_down(1);
            }
            if (pid == 0) {
                /* Child process */
                do_user(sha1_dir, buf, &sha1_namespace,
                        uid_set, uid_modulo);
                _exit(0);
            }
            sha1_children++;   /* Parent process */
        }
        fclose(file);
    } else for (i = optind; i < argc; i++) {
        while (sha1_children == max_children)   /* Concurrency limit */
            pause();
    
        if ((pid = fork()) < 0) {
            fprintf(stderr, "Fork failed.\n");
            shut_down(1);
        }
        if (pid == 0) {
            /* Child process */
            do_user(sha1_dir, argv[i], &sha1_namespace,
                    uid_set, uid_modulo);
            _exit(0);
        }
        sha1_children++;   /* Parent process */
    }
  
    /* Wait forall children to finish */
    while (sha1_children > 0)
        pause();

    syslog(LOG_NOTICE, "Finished generating SHA1 checksums for mailboxes");
    shut_down(0);
}
#else
int main(int argc, char **argv)
{
    fprintf(stderr, "make_sha1: not implemented due to missing OpenSSL\n");
    exit(code);
}
#endif /* !HAVE_SSL */
