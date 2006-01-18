#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
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
#include "md5global.h"
#include "md5.h"
/*#include "cdb.h"*/

/* global state */
const int config_need_data = 0;

extern char *optarg;
extern int optind;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;

void printastring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}

void printstring(const char *s)
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
    fprintf(stderr, "make_md5: %s\n", s);
    exit(code);
}

/* ====================================================================== */

struct md5_node {
    struct md5_node *next;
    int           active;
    unsigned long uid;
    unsigned char md5_msg[16];
    unsigned char md5_cache[16];
};

struct md5_mailbox {
    struct md5_mailbox *next;
    char *name;
    char *uniqueid;
    struct md5_node *head;
    struct md5_node *tail;
    unsigned long count;
    int active;
};

struct md5_mailbox_list {
    struct md5_mailbox *head;
    struct md5_mailbox *tail;
    unsigned long count;
    int dirty;
};

static void
md5_mailbox_free(struct md5_mailbox *list)
{
    struct md5_node *current, *next;

    for (current = list->head; current ; current = next) {
        next = current->next;
        free(current);
    }
    free(list->name);
    free(list->uniqueid);
    free(list);
}

static void
md5_mailbox_rename(struct md5_mailbox *mailbox, char *name)
{
    free(mailbox->name);
    mailbox->name = xstrdup(name);
}

static struct md5_node *
md5_mailbox_add(struct md5_mailbox *list,
                unsigned long uid,
                unsigned char md5_msg[16],
                unsigned char md5_cache[16],
                int active)
{
    struct md5_node *new = xmalloc(sizeof(struct md5_node));
    struct md5_node *current, *last;

    new->next = NULL;
    new->uid  = uid;
    new->active = active;
    memcpy(&new->md5_msg, md5_msg, 16);
    memcpy(&new->md5_cache, md5_cache, 16);

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

static struct md5_mailbox_list *
md5_mailbox_list_create(void)
{
    struct md5_mailbox_list *list = xmalloc(sizeof(struct md5_mailbox_list));

    list->head  = NULL;
    list->tail  = NULL;
    list->count = 0;
    list->dirty = 0;

    return(list);
}

static void
md5_mailbox_list_free(struct md5_mailbox_list *list)
{
    struct md5_mailbox *current, *next;

    for (current = list->head; current ; current = next) {
        next = current->next;
        md5_mailbox_free(current);
    }
    free(list);
}

static struct md5_mailbox *
md5_mailbox_list_add(struct md5_mailbox_list *list, char *name, char *uniqueid)
{
    struct md5_mailbox *new = xzmalloc(sizeof(struct md5_mailbox));
    struct md5_mailbox *current, *last;

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

static struct md5_mailbox *
md5_mailbox_list_find(struct md5_mailbox_list *list, char *uniqueid)
{
    struct md5_mailbox *mailbox;

    for (mailbox = list->head ; mailbox ; mailbox = mailbox->next) {
        if (!strcmp(mailbox->uniqueid, uniqueid))
            return(mailbox);
    }
    return(NULL);
}

static int
md5_mailbox_list_check_deleted(struct md5_mailbox_list *list)
{
    struct md5_mailbox *mailbox;

    for (mailbox = list->head ; mailbox ; mailbox = mailbox->next) {
        if (!mailbox->active) {
            list->dirty = 1;
            return(1);
        }
    }
    return(0);
}

static int
md5_parse(unsigned char md5[16], char *s)
{
    int i;
    char c;

    if (strlen(s) != 32)
        return(0);

    for (i = 0 ; i < 16 ; i++) {
        c = *s++;

        if ((c >= '0') && (c <= '9'))
            md5[i] = (c - '0') * 16;
        else if ((c >= 'a') && (c <= 'z'))
            md5[i] = (c - 'a' + 10) * 16;
        else if ((c >= 'A') && (c <= 'Z'))
            md5[i] = (c - 'A' + 10) * 16;
        else
            return(0);

        c = *s++;

        if ((c >= '0') && (c <= '9'))
            md5[i] += (c - '0');
        else if ((c >= 'a') && (c <= 'z'))
            md5[i] += (c - 'a' + 10);
        else if ((c >= 'A') && (c <= 'Z'))
            md5[i] += (c - 'A' + 10);
        else
            return(0);
    }
    return(1);
}

static int
md5_mailbox_list_read(struct md5_mailbox_list *list, char *name)
{
    struct md5_mailbox *current = NULL;
    FILE *file;
    char buf[MAX_MAILBOX_NAME+2];
    unsigned char md5_msg[16];
    unsigned char md5_cache[16];
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

            current = md5_mailbox_list_add(list, mboxname, uniqueid);
        } else {
            if (!(current && (s = strtok(buf, "\t ")) && (uid = atoi(s)) &&
                  (s = strtok(NULL, "\t ")) && md5_parse(md5_msg, s) &&
                  (s = strtok(NULL, "\t ")) && md5_parse(md5_cache, s)))
                goto parse_err;

            md5_mailbox_add(current, uid, md5_msg, md5_cache, 0);
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
md5_mailbox_list_write(struct md5_mailbox_list *list, char *name)
{
    struct md5_mailbox *mailbox;
    struct md5_node    *node;
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
            for (i = 0 ; i < 16 ; i++)
                fprintf(file, "%-2.2x", node->md5_msg[i]);
            fprintf(file, " ");
            for (i = 0 ; i < 16 ; i++)
                fprintf(file, "%-2.2x", node->md5_cache[i]);
            fprintf(file, "\n");
        }
    }
    fclose(file);
    return(0);
}

/* ====================================================================== */

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
static void *
md5_buffer (const char *buffer, size_t len, void *resblock)
{
    MD5_CTX ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, buffer, len);
    MD5Final(resblock, &ctx);

    return resblock;
}

/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
static int
md5_stream (FILE *stream, void *resblock)
{
    const char *base = NULL;
    unsigned long len = 0;

    map_refresh(fileno(stream), 1, &base, &len, MAP_UNKNOWN_LEN, "msg", NULL);

    md5_buffer(base, len, resblock);

    map_free(&base, &len);

    return 0;
}

static int
md5_single(char *name, int matchlen, int maycreate, void *rock)
{
    struct mailbox m;
    int    r = 0;
    unsigned long msgno;
    struct index_record record;
    unsigned char md5_msg[16], md5_cache[16];
    char buf[MAX_MAILBOX_PATH+1];
    FILE *file;
    struct md5_mailbox_list *md5_mailbox_list;
    struct md5_mailbox *md5_mailbox;
    struct md5_node *md5_node;
    unsigned long cache_offset;
    unsigned long cache_size;

    if (verbose > 1)
        printf("   %s\n", name);

    md5_mailbox_list = (struct md5_mailbox_list *)rock;

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

    if (!(md5_mailbox=md5_mailbox_list_find(md5_mailbox_list, m.uniqueid))) {
        /* New mailbox */
        md5_mailbox = md5_mailbox_list_add(md5_mailbox_list, name, m.uniqueid);
        md5_mailbox_list->dirty = 1;
    }

    if (!md5_mailbox) {
        syslog(LOG_NOTICE, "Failed to create md5_mailbox_list for %s", name);
        goto bail;
    }

    if (strcmp(md5_mailbox->name, m.name) != 0) {
        /* Renamed mailbox */
        md5_mailbox_rename(md5_mailbox, m.name);
        md5_mailbox_list->dirty = 1;
    }

    md5_mailbox->active = 1;
    md5_node = md5_mailbox->head;

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

        /* Skip over UIDs in md5_mailbox which have now been deleted
         * (but record fact that md5 list should be updated for this user) */
        while (md5_node && (md5_node->uid < record.uid)) {
            md5_mailbox_list->dirty = 1; /* Need to write out new MD5 list */
            md5_node->active = 0;
            md5_node = md5_node->next;
        }

        /* Check whether MD5 value already exists for this UID */
        if (md5_node && (md5_node->uid == record.uid)) {
            md5_node->active = 1;
            md5_node = md5_node->next;
            continue;
        }

        snprintf(buf, sizeof(buf), "%s/%lu.", m.path, record.uid);

        if (!(file=fopen(buf, "r"))) {
            syslog(LOG_ERR, "IOERROR: %s failed to open msg UID %lu",
                   m.name, record.uid);
            r = IMAP_IOERROR;
            goto bail;
        }

        if (md5_stream(file, md5_msg) != 0) {
            syslog(LOG_ERR, "IOERROR: %s failed to md5 msg UID %lu",
                   m.name, record.uid);
            r = IMAP_IOERROR;
            fclose(file);
            goto bail;
        }

        cache_offset = record.cache_offset;
        cache_size = mailbox_cache_size(&m, msgno);

        if (!md5_buffer(m.cache_base+cache_offset, cache_size, md5_cache)) {
            syslog(LOG_ERR, "IOERROR: %s failed to md5 msg cache UID %lu",
                   m.name, record.uid);
            r = IMAP_IOERROR;
            goto bail;
        }

        md5_mailbox_add(md5_mailbox, record.uid, md5_msg, md5_cache, 1);
        md5_mailbox_list->dirty = 1; /* Need to write out new MD5 list */
        fclose(file);
    }
    /* Check for deletions at end of the folder */
    if (md5_node)
        md5_mailbox_list->dirty = 1; /* Need to write out new MD5 list */

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

static int
use_existing_data(char *user, int uid_set, int uid_modulo, int uid_fd)
{
    char buf[64];
    unsigned long len;
    int  uid;

    if ((uid_modulo == 0) || (uid_fd < 0))
        return(1);
#if 0 /* XXX  make sure we're not the replica */
    if (cdb_seek(uid_fd, (unsigned char *)user, strlen(user), &len) != 1)
        return(1);
#endif
    if ((len >= sizeof(buf)) || (read(uid_fd, buf, len) != len))
        return(1);

    if ((uid = atoi(buf)) == 0)
        return(1);

    return ((uid_set == (uid % uid_modulo)) ? 0 : 1);
}

static int
do_user(const char *md5_dir, char *user, struct namespace *namespacep,
        int uid_set, int uid_modulo, int uid_fd)
{
    char  buf[MAX_MAILBOX_PATH+1];
    char  buf2[MAX_MAILBOX_PATH+1];
    int   r = 0;
    int   regenerate = 0;
    struct md5_mailbox_list *md5_mailbox_list = md5_mailbox_list_create();

    imapd_userid    = user;
    imapd_authstate = auth_newstate(imapd_userid);

    if (use_existing_data(user, uid_set, uid_modulo, uid_fd)) {
        snprintf(buf, sizeof(buf)-1, "%s/%c/%s", md5_dir, user[0], user);
        r = md5_mailbox_list_read(md5_mailbox_list, buf);

        if (r) {
            syslog(LOG_NOTICE, "Failed to read mailbox list for %s", user);
            md5_mailbox_list_free(md5_mailbox_list);
            return(r);
        }

        if (verbose > 0)
            printf("Make_MD5: %s\n", user);

    } else {
        regenerate = 1;
        if (verbose > 0)
            printf("Make_MD5: %s (regenerating)\n", user);
    }

    /* Index inbox */
    snprintf(buf, sizeof(buf)-1, "user.%s", user);
    md5_single(buf, 0, 0, md5_mailbox_list);
    
    /* And then all folders */
    snprintf(buf, sizeof(buf)-1, "user.%s.*", user);
    r = (namespacep->mboxlist_findall)(namespacep, buf, 0,
                                       imapd_userid, imapd_authstate,
                                       md5_single, md5_mailbox_list);
    if (r) {
        syslog(LOG_NOTICE, "Failed to enumerate mailboxes for %s", user);
        md5_mailbox_list_free(md5_mailbox_list);
        return(r);
    }

    auth_freestate(imapd_authstate);

    /* If mailbox have been deleted, we need to rewrite */
    if (md5_mailbox_list->dirty ||
        md5_mailbox_list_check_deleted(md5_mailbox_list)) {
        snprintf(buf, sizeof(buf)-1, "%s/%c/%s-NEW", md5_dir, user[0], user);
        md5_mailbox_list_write(md5_mailbox_list, buf);

        snprintf(buf, sizeof(buf)-1, "%s/%c/%s-NEW", md5_dir, user[0], user);
        snprintf(buf2, sizeof(buf2)-1, "%s/%c/%s", md5_dir, user[0], user);

        if (rename(buf, buf2) < 0) {
            syslog(LOG_NOTICE, "Failed to rename %s -> %s", buf, buf2);
            md5_mailbox_list_free(md5_mailbox_list);
            return(IMAP_IOERROR);
        }
    }

    if (regenerate)
        syslog(LOG_NOTICE, "Done make_md5 for %s (regenerated)", user);
    else
        syslog(LOG_NOTICE, "Done make_md5 for %s", user);

    md5_mailbox_list_free(md5_mailbox_list);
    return(0);
}

/* ====================================================================== */

static unsigned long md5_children = 0;

static void
md5_child_reaper()
{
    int              status;
    pid_t            child;

    do {
        child = waitpid(0, &status, WNOHANG);
        if ((child > 0) && (md5_children > 0))
            md5_children--;
    } while (child > 0);
}

static int
md5_signal_child_init(void (*fn)())
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

int
main(int argc, char **argv)
{
    int   opt;
    char *alt_config = NULL;
    char *input_file = NULL;
    const char *md5_dir  = NULL;
    const char *uid_file = NULL;
    int   uid_fd     = (-1);
    int   uid_set    = 0;
    int   uid_modulo = 0;
    int   r = 0;
    int   i;
    int   max_children = 0;
    pid_t pid;
    struct namespace md5_namespace;
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

        case 'D': /* MD5 directory */
            md5_dir = optarg;
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
            usage("make_md5");
        }
    }

    /* Set up default bounds if no command line options provided */

    cyrus_init(alt_config, "make_md5", 0);

    syslog(LOG_NOTICE, "Generating MD5 checksums for mailboxes");

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&md5_namespace, 1)) != 0) {
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
        fprintf(stderr, "please specify user to MD5\n");
        shut_down(1);
    }

    if (!md5_dir) md5_dir = config_getstring(IMAPOPT_MD5_DIR);

    if (!md5_dir)
        md5_dir = xstrdup("/var/imap/md5");

    if (((uid_file = config_getstring(IMAPOPT_MD5_USER_MAP)) != NULL) &&
        ((uid_fd=open(uid_file, O_RDONLY)) < 0)) {
        syslog(LOG_NOTICE, "Failed to open uid file %s: %m\n", uid_file);
        shut_down(1);
    }

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

                if (do_user(md5_dir, buf, &md5_namespace,
                            uid_set, uid_modulo, uid_fd)) {
                    syslog(LOG_NOTICE, "Error make_md5 %s: %m", buf);
                    shut_down(1);
                }
            }
            fclose(file);
        } else for (i = optind; i < argc; i++) {
            if (do_user(md5_dir, argv[i], &md5_namespace,
                        uid_set, uid_modulo, uid_fd)) {
                syslog(LOG_NOTICE, "Error make_md5 %s: %m", argv[i]);
                shut_down(1);
            }
        }

        syslog(LOG_NOTICE, "Done MD5 checksums for mailboxes");
        shut_down(0);
    }

    /* Enable child handler */
    if (!md5_signal_child_init(md5_child_reaper)) {
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


            while (md5_children == max_children)   /* Concurrency limit */
                pause();
    
            if ((pid = fork()) < 0) {
                fprintf(stderr, "Fork failed.\n");
                shut_down(1);
            }
            if (pid == 0) {
                /* Child process */
                do_user(md5_dir, buf, &md5_namespace,
                        uid_set, uid_modulo, uid_fd);
                _exit(0);
            }
            md5_children++;   /* Parent process */
        }
        fclose(file);
    } else for (i = optind; i < argc; i++) {
        while (md5_children == max_children)   /* Concurrency limit */
            pause();
    
        if ((pid = fork()) < 0) {
            fprintf(stderr, "Fork failed.\n");
            shut_down(1);
        }
        if (pid == 0) {
            /* Child process */
            do_user(md5_dir, argv[i], &md5_namespace,
                    uid_set, uid_modulo, uid_fd);
            _exit(0);
        }
        md5_children++;   /* Parent process */
    }
  
    /* Wait forall children to finish */
    while (md5_children > 0)
        pause();

    syslog(LOG_NOTICE, "Finished generating MD5 checksums for mailboxes");
    shut_down(0);
}

