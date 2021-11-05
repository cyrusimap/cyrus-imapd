/* cyr_virusscan.c - scan mailboxes for infected messages and remove them
 *
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

/* cyrus includes */
#include "assert.h"
#include "global.h"
#include "append.h"
#include "index.h"
#include "mailbox.h"
#include "map.h"
#include "message.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "parseaddr.h"
#include "prot.h"
#include "util.h"
#include "times.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

struct infected_msg {
    char *mboxname;
    char *virname;
    char *msgid;
    char *date;
    char *from;
    char *subj;
    unsigned long uid;
    struct infected_msg *next;
};

struct infected_mbox {
    char *owner;
    struct infected_msg *msgs;
    struct infected_mbox *next;
};

struct scan_rock {
    struct infected_mbox *i_mbox;
    struct searchargs *searchargs;
    struct index_state *idx_state;
    struct namespace *namespace;
    uint32_t msgno;
    char userid[MAX_MAILBOX_NAME];
    int user_infected;
    int total_infected;
    int mailboxes_scanned;
};

/* globals for getopt routines */
extern char *optarg;
extern int  optind;
extern int  opterr;
extern int  optopt;

/* globals for callback functions */
int disinfect = 0;
int email_notification = 0;
struct infected_mbox *public = NULL;
struct infected_mbox *user = NULL;

static int verbose = 0;

/* abstract definition of a virus scan engine */
struct scan_engine {
    const char *name;
    void *state;
    void *(*init)(void);  /* initialize state */
    int (*scanfile)(void *state,  /* scan fname & return non-zero if infected */
                    const char *fname, const char **virname);
    void (*destroy)(void *state);  /* destroy state */
};


#ifdef HAVE_CLAMAV
/* ClamAV implementation */
#include <clamav.h>

struct clamav_state {
    struct cl_engine *av_engine;
};

void *clamav_init()
{
    unsigned int sigs = 0;
    int64_t starttime;
    int r;

    /* initialise ClamAV library */
    if ((r = cl_init(0)) != CL_SUCCESS) {
        syslog(LOG_ERR, "cl_init: %s", cl_strerror(r));
        fatal("Failed to initialise ClamAV library", EX_SOFTWARE);
    }

    struct clamav_state *st = xzmalloc(sizeof(struct clamav_state));
    if (st == NULL) {
        fatal("memory allocation failed", EX_SOFTWARE);
    }

    st->av_engine = cl_engine_new();
    if ( ! st->av_engine ) {
        fatal("Failed to initialize AV engine", EX_SOFTWARE);
    }

    /* load all available databases from default directory */
    if (verbose) puts("Loading virus signatures...");
    starttime = now_ms();
    if ((r = cl_load(cl_retdbdir(), st->av_engine, &sigs, CL_DB_STDOPT))) {
        syslog(LOG_ERR, "cl_load: %s", cl_strerror(r));
        fatal(cl_strerror(r), EX_SOFTWARE);
    }

    printf("Loaded %d virus signatures (%.3f seconds).\n",
           sigs, (now_ms() - starttime)/1000.0);

    /* build av_engine */
    if ((r = cl_engine_compile(st->av_engine))) {
        syslog(LOG_ERR,
               "Database initialization error: %s", cl_strerror(r));
        cl_engine_free(st->av_engine);
        fatal(cl_strerror(r), EX_SOFTWARE);
    }

    /* set up archive av_limits */
    /* max files */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_FILES, 10000);
    /* during the scanning of archives, this size (100 MB) will
     * never be exceeded
     */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_SCANSIZE, 100 * 1048576);
    /* compressed files will only be decompressed and scanned up to
     * this size (10 MB)
     */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_FILESIZE, 10 * 1048576);
    /* maximum recursion level for archives */
    cl_engine_set_num(st->av_engine, CL_ENGINE_MAX_RECURSION, 16);

    return (void *) st;
}


int clamav_scanfile(void *state, const char *fname,
                    const char **virname)
{
    struct clamav_state *st = (struct clamav_state *) state;
    int r;

    /* scan file */
#ifdef CL_SCAN_STDOPT
    r = cl_scanfile(fname, virname, NULL, st->av_engine,
                    CL_SCAN_STDOPT);
#else
    static struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0; /* enable all parsers */

    r = cl_scanfile(fname, virname, NULL, st->av_engine, &options);
#endif

    switch (r) {
    case CL_CLEAN:
        /* do nothing */
        break;
    case CL_VIRUS:
        return 1;
        break;

    default:
        printf("cl_scanfile error: %s\n", cl_strerror(r));
        syslog(LOG_ERR, "cl_scanfile error: %s", cl_strerror(r));
        break;
    }

    return 0;
}

void clamav_destroy(void *state)
{
    struct clamav_state *st = (struct clamav_state *) state;

    if (st->av_engine) {
        /* free memory */
        cl_engine_free(st->av_engine);
    }
    free(st);
}

struct scan_engine engine =
{ "ClamAV", NULL, &clamav_init, &clamav_scanfile, &clamav_destroy };

#elif defined(HAVE_SOME_UNKNOWN_VIRUS_SCANNER)
/* XXX  Add other implementations here */

#else
/* NO configured virus scanner */
struct scan_engine engine = { "<None Configured>", NULL, NULL, NULL, NULL };
#endif


/* forward declarations */
int usage(char *name);
int scan_me(struct findall_data *, void *);
unsigned virus_check(struct mailbox *mailbox,
                     const struct index_record *record,
                     void *rock);
static int load_notification_template(struct buf *dst);
static int check_notification_template(const struct buf *template);
static void put_notification_headers(FILE *f, int counter, time_t t,
                                     const mbname_t *mbname);
static void append_notifications(const struct buf *template);

static const char *default_notification_template =
	"The following message was deleted from mailbox '%MAILBOX%'\n"
	"because it was infected with virus '%VIRUS%'\n"
	"\n"
	"\tMessage-ID: %MSG_ID%\n"
	"\tDate: %MSG_DATE%\n"
	"\tFrom: %MSG_FROM%\n"
	"\tSubject: %MSG_SUBJECT%\n"
	"\tIMAP UID: %MSG_UID%\n";

int main (int argc, char *argv[])
{
    int option;         /* getopt() returns an int */
    char *alt_config = NULL;
    char *search_str = NULL;
    struct scan_rock srock;
    struct buf notification_template = BUF_INITIALIZER;
    struct namespace scan_namespace;
    int r;

    while ((option = getopt(argc, argv, "C:s:rnv")) != EOF) {
        switch (option) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 's': /* IMAP SEARCH string */
            search_str = optarg;
            break;

        case 'r':
            disinfect = 1;
            break;

        case 'n':
            email_notification = 1;
            break;

        case 'v':
            verbose ++;
            break;

        case 'h':
        default: usage(argv[0]);
        }
    }

    cyrus_init(alt_config, "cyr_virusscan", 0, CONFIG_NEED_PARTITION_DATA);

    memset(&srock, 0, sizeof(struct scan_rock));

    if (email_notification) {
        /* load notification template early, so if it fails we haven't wasted
         * time initialising the av engine */
        if (load_notification_template(&notification_template)) {
            syslog(LOG_ERR, "Couldn't load notification template");
            fatal("Couldn't load notification template", EX_CONFIG);
        }
    }

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&scan_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }
    srock.namespace = &scan_namespace;

    if (search_str) {
        int c;
        struct protstream *scan_in = NULL;
        struct protstream *scan_out = NULL;

        scan_in = prot_readmap(search_str, strlen(search_str)+1); /* inc NUL */
        scan_out = prot_new(2, 1);

        srock.searchargs = new_searchargs("*", GETSEARCH_CHARSET_KEYWORD,
                                          &scan_namespace, NULL, NULL, 1);
        c = get_search_program(scan_in, scan_out, srock.searchargs);
        prot_free(scan_in);
        prot_flush(scan_out);
        prot_free(scan_out);

        if (c == EOF) {
            syslog(LOG_ERR, "Invalid search string");
            fatal("Invalid search string", EX_USAGE);
        }
    }
    else {
        printf("Using %s virus scanner\n", engine.name);

        if (engine.init) engine.state = engine.init();
    }

    if (optind == argc) { /* do the whole partition */
        mboxlist_findall(NULL, "*", 1, 0, 0, scan_me, &srock);
    } else {
        strarray_t *array = strarray_new();
        for (; optind < argc; optind++) {
            strarray_append(array, argv[optind]);
        }
        mboxlist_findallmulti(NULL, array, 1, 0, 0, scan_me, &srock);
        strarray_free(array);
    }

    if (email_notification) append_notifications(&notification_template);

    buf_free(&notification_template);

    printf("\n%d mailboxes scanned, %d infected messages %s\n",
           srock.mailboxes_scanned,
           srock.total_infected,
           disinfect ? "removed" : "found");

    if (srock.searchargs) freesearchargs(srock.searchargs);
    else if (engine.destroy) engine.destroy(engine.state);

    cyrus_done();

    return 0;
}

int usage(char *name)
{
    printf("usage: %s [-C <alt_config>] [-s <imap-search-string>] [ -r [-n] ] [-v]\n"
           "\t[mboxpattern1 ... [mboxpatternN]]\n", name);
    printf("\tif no mboxpattern is given %s works on all mailboxes\n", name);
    printf("\t -s imap-search-string  Rather than scanning for viruses,\n"
           "\t    messages matching the search criteria will be treated as infected.\n"
           "\t    Useful for removing messages without a distinct signature, such as Phish.\n");
    printf("\t -r remove infected messages\n");
    printf("\t -n notify mailbox owner of deleted messages via email\n");
    printf("\t -v verbose output\n");
    exit(0);
}

static void print_header(void)
{
    printf("\n%-40s\t%10s\t%6s\t%s\n",
           "Mailbox Name", "Msg UID", "Status", "Virus Name");
    printf("----------------------------------------\t"
           "----------\t------\t"
           "--------------------------------------------------\n");
}

int scan_me(struct findall_data *data, void *rock)
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    struct mailbox *mailbox = NULL;
    int r;
    struct infected_mbox *i_mbox = NULL;
    const char *name = mbname_intname(data->mbname);
    const char *userid = mbname_userid(data->mbname);
    struct scan_rock *srock = (struct scan_rock *) rock;

    /* reset infected count when user changes, without choking
     * on shared mailboxes, which don't have a user. */
    if (userid != NULL && strcmp(srock->userid, userid) != 0) {
        strlcpy(srock->userid, userid, sizeof(srock->userid));
        srock->user_infected = 0;
    }
    else if (userid == NULL && *srock->userid != '\0') {
        memset(srock->userid, 0, sizeof(srock->userid));
        srock->user_infected = 0;
    }

    r = mailbox_open_iwl(name, &mailbox);
    if (r) {
        printf("failed to open %s (%s)\n", name, error_message(r));
        return 0;
    }

    if (srock->searchargs) {
        r = index_open_mailbox(mailbox, NULL, &srock->idx_state);
        if (!r) r = mailbox_lock_index(mailbox, LOCK_EXCLUSIVE);
        if (r) {
            printf("failed to open index %s (%s)\n", name, error_message(r));
            return 0;
        }

        search_expr_internalise(srock->idx_state, srock->searchargs->root);

        srock->msgno = 1;
    }

    if (email_notification) {
        char *owner = mboxname_to_userid(name);
        if (owner) {
            if (user && !strcmp(owner, user->owner)) {
                i_mbox = user;
                free(owner);
            } else {
                /* new owner (Inbox) */
                struct infected_mbox *new = xzmalloc(sizeof(struct infected_mbox));
                new->owner = owner;
                new->next = user;
                i_mbox = user = new;
            }
        }
#if 0  /* XXX what to do with public mailboxes (bboards)? */
        else {
            if (!public) {
                public = xzmalloc(sizeof(struct infected_mbox));
                public->owner = xstrdup("");
            }

            i_mbox = public;
        }
#endif
    }

    srock->i_mbox = i_mbox;

    if (verbose) printf("Scanning %s...\n", name);
    mailbox_expunge(mailbox, virus_check, srock, NULL, EVENT_MESSAGE_EXPUNGE);
    if (srock->idx_state) index_close(&srock->idx_state);  /* closes mailbox */
    else mailbox_close(&mailbox);

    srock->mailboxes_scanned++;

    return 0;
}

void create_digest(struct infected_mbox *i_mbox, struct mailbox *mailbox,
                   const struct index_record *record, const char *virname)
{
    struct infected_msg *i_msg = xzmalloc(sizeof(struct infected_msg));
    char *tmp;
    struct address addr;
    struct buf from = BUF_INITIALIZER;

    i_msg->mboxname = xstrdup(mailbox_name(mailbox));
    i_msg->virname = xstrdup(virname);
    i_msg->uid = record->uid;

    i_msg->msgid = mailbox_cache_get_env(mailbox, record, ENV_MSGID);
    i_msg->date = mailbox_cache_get_env(mailbox, record, ENV_DATE);
    i_msg->subj = mailbox_cache_get_env(mailbox, record, ENV_SUBJECT);

    /* decode the FROM header */
    tmp = mailbox_cache_get_env(mailbox, record, ENV_FROM);
    message_parse_env_address(tmp, &addr);
    if (addr.name)
        buf_printf(&from, "\"%s\" ", addr.name);
    buf_printf(&from, "<%s@%s>", addr.mailbox, addr.domain);
    free(tmp);
    i_msg->from = buf_release(&from);

    i_msg->next = i_mbox->msgs;
    i_mbox->msgs = i_msg;
}

/* thumbs up routine, checks for virus and returns yes or no for deletion */
/* 0 = no, 1 = yes */
unsigned virus_check(struct mailbox *mailbox,
                     const struct index_record *record,
                     void *deciderock)
{
    struct scan_rock *srock = (struct scan_rock *) deciderock;
    struct infected_mbox *i_mbox = srock->i_mbox;
    const char *virname =
        "Cyrus Administrator Targeted Removal (Phish, etc.)";
    int r = 0;

    if (srock->searchargs) {
        /* run the search program against this message */
        r = index_search_evaluate(srock->idx_state,
                                  srock->searchargs->root, srock->msgno++);
    }
    else if (engine.scanfile) {
        const char *fname = mailbox_record_fname(mailbox, record);

        /* run the virus scanner against this message */
        r = engine.scanfile(engine.state, fname, &virname);
    }

    if (r) {
        /* print header if this is the first infection seen for this user */
        if (verbose || !srock->user_infected) print_header();

        char *extname = mboxname_to_external(mailbox_name(mailbox),
                                             srock->namespace,
                                             NULL);

        printf("%-40s\t%10u\t%6s\t%s\n", extname, record->uid,
               (record->system_flags & FLAG_SEEN) ? "READ" : "UNREAD",
               virname);

        free(extname);

        srock->user_infected ++;
        srock->total_infected ++;

        if (disinfect) {
            if (email_notification && i_mbox) {
                create_digest(i_mbox, mailbox, record, virname);
            }
        }
        else r = 0;
    }

    return r;
}

static int load_notification_template(struct buf *dst)
{
    const char *template_fname =
        config_getstring(IMAPOPT_VIRUSSCAN_NOTIFICATION_TEMPLATE);
    int r;

    if (!template_fname) {
        buf_setcstr(dst, default_notification_template);
        return 0;
    }

    int fd = open(template_fname, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_WARNING, "unable to read notification template file %s (%m), "
                            "using default instead",
                            template_fname);
        buf_setcstr(dst, default_notification_template);
        return 0;
    }

    buf_refresh_mmap(dst, 1, fd, template_fname, MAP_UNKNOWN_LEN, NULL);
    close(fd);

    /* using a custom template, validate it! */
    r = check_notification_template(dst);
    if (r) buf_reset(dst);

    return r;
}

static int check_notification_template(const struct buf *template)
{
    struct buf chunk = BUF_INITIALIZER;
    int fd;
    FILE *f;
    mbname_t *mbname;
    struct protstream *pout;
    size_t msgsize;
    size_t i;
    int r;

    const char *subs[] = {
        "%MAILBOX%",
        "%VIRUS%",
        "%MSG_ID%",
        "%MSG_DATE%",
        "%MSG_FROM%",
        "%MSG_SUBJECT%",
        "%MSG_UID%",
    };

    /* warn about missing fields, but they're not catastrophic */
    for (i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        if (!memmem(buf_base(template), buf_len(template),
                    subs[i], strlen(subs[i])))
            syslog(LOG_WARNING, "notification template is missing %s substitution",
                                subs[i]);
    }

    /* stub a message, and do minimal checking for RFC 822 compliance */
    fd = create_tempfile(config_getstring(IMAPOPT_TEMP_PATH));
    f = fdopen(fd, "w+");
    mbname = mbname_from_intname("user.nobody");
    put_notification_headers(f, 0, time(NULL), mbname);
    mbname_free(&mbname);

    buf_copy(&chunk, template);
    buf_tocrlf(&chunk);
    /* not bothering to perform substitutions */
    char *encoded_chunk = charset_qpencode_mimebody(buf_base(&chunk),
                                                    buf_len(&chunk),
                                                    /* force_quote */ 0, NULL);
    fputs(encoded_chunk, f);
    fputs("\r\n", f);
    free(encoded_chunk);
    buf_free(&chunk);

    fflush(f);
    msgsize = ftell(f);

    pout = prot_new(fd, 0);
    prot_rewind(pout);
    r = message_copy_strict(pout, NULL, msgsize, /* allow_null */ 0);
    prot_free(pout);

    fclose(f);
    return r;
}

static void put_notification_headers(FILE *f, int counter, time_t t,
                                     const mbname_t *mbname)
{
    pid_t p = getpid();
    char datestr[RFC5322_DATETIME_MAX+1];
    char *encoded_subject;

    time_to_rfc5322(t, datestr, sizeof(datestr));
    encoded_subject = charset_encode_mimeheader(
        config_getstring(IMAPOPT_VIRUSSCAN_NOTIFICATION_SUBJECT), 0, 0);

    fprintf(f, "Return-Path: <>\r\n");
    fprintf(f, "Message-ID: <cmu-cyrus-%d-%d-%d@%s>\r\n",
               (int) p, (int) t, counter, config_servername);
    fprintf(f, "Date: %s\r\n", datestr);
    fprintf(f, "From: Mail System Administrator <%s>\r\n",
               config_getstring(IMAPOPT_POSTMASTER));
    fprintf(f, "To: <%s>\r\n", mbname_userid(mbname));
    fprintf(f, "Subject: %s\r\n", encoded_subject);
    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "Content-Type: text/plain; charset=UTF-8\r\n");
    fprintf(f, "Content-Transfer-Encoding: quoted-printable\r\n");
    fputs("\r\n", f);

    free(encoded_subject);
}

static void append_notifications(const struct buf *template)
{
    struct infected_mbox *i_mbox;
    int outgoing_count = 0;
    int fd = create_tempfile(config_getstring(IMAPOPT_TEMP_PATH));
    struct namespace notification_namespace;

    mboxname_init_namespace(&notification_namespace, 0);

    while ((i_mbox = user)) {
        if (i_mbox->msgs) {
            FILE *f = fdopen(fd, "w+");
            struct infected_msg *msg;
            time_t t;
            struct protstream *pout;
            struct appendstate as;
            struct body *body = NULL;
            long msgsize;
            mbname_t *owner = mbname_from_userid(i_mbox->owner);
            struct buf message = BUF_INITIALIZER;
            int first;
            int r;

            t = time(NULL);
            put_notification_headers(f, outgoing_count++, t, owner);

            first = 1;
            while ((msg = i_mbox->msgs)) {
                struct buf chunk = BUF_INITIALIZER;
                char uidbuf[16]; /* UINT32_MAX is 4294967295 */
                int n;

                /* stringify the uid */
                n = snprintf(uidbuf, sizeof(uidbuf), "%lu", msg->uid);
                assert(n > 0 && (unsigned) n < sizeof(uidbuf));

                buf_copy(&chunk, template);
                buf_tocrlf(&chunk);

                mbname_t *mailbox = mbname_from_intname(msg->mboxname);
                const char *extname = mbname_extname(mailbox,
                                                     &notification_namespace,
                                                     mbname_userid(owner));
                buf_replace_all(&chunk, "%MAILBOX%", extname);
                buf_replace_all(&chunk, "%VIRUS%", msg->virname);
                buf_replace_all(&chunk, "%MSG_ID%", msg->msgid);
                buf_replace_all(&chunk, "%MSG_DATE%", msg->date);
                buf_replace_all(&chunk, "%MSG_FROM%", msg->from);
                buf_replace_all(&chunk, "%MSG_SUBJECT%", msg->subj);
                buf_replace_all(&chunk, "%MSG_UID%", uidbuf);
                mbname_free(&mailbox);

                if (!first)
                    buf_appendcstr(&message, "\r\n");
                else
                    first = 0;
                buf_append(&message, &chunk);
                buf_free(&chunk);

                i_mbox->msgs = msg->next;

                /* free msg digest */
                free(msg->mboxname);
                free(msg->msgid);
                free(msg->date);
                free(msg->from);
                free(msg->subj);
                free(msg->virname);
                free(msg);
            }

            char *encoded_message = charset_qpencode_mimebody(
                                        buf_base(&message), buf_len(&message),
                                        /* force_quote */ 0, NULL);
            fputs(encoded_message, f);
            fflush(f);
            msgsize = ftell(f);

            free(encoded_message);
            buf_free(&message);

            /* send MessageAppend event notification */
            r = append_setup(&as, mbname_intname(owner), NULL, NULL, 0, NULL, NULL, 0,
                             EVENT_MESSAGE_APPEND);

            if (!r) {
                pout = prot_new(fd, 0);
                prot_rewind(pout);
                r = append_fromstream(&as, &body, pout, msgsize, t, NULL);
                /* n.b. append_fromstream calls append_abort itself if it fails */
                if (!r) r = append_commit(&as);

                if (body) {
                    message_free_body(body);
                    free(body);
                }
                prot_free(pout);
            }

            if (r) {
                syslog(LOG_ERR, "couldn't send notification to user %s: %s",
                                mbname_userid(owner),
                                error_message(r));
            }

            mbname_free(&owner);
            /* XXX funny smell here, fdopen() promises to close the underlying
             *     file descriptor at fclose(), but we're about to loop around
             *     and re-fdopen() it?
             */
            fclose(f);
        }

        user = i_mbox->next;

        /* free owner info */
        free(i_mbox->owner);
        free(i_mbox);
    }
}
