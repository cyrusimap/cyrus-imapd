/*
 * test_mailbox.c -- tester for libcyrus_sieve
 * Ken Murchison
 *
 * usage: "test_mailbox mailbox script"
 */
/*
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sysexits.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "libconfig.h"
#include "assert.h"
#include "sieve_interface.h"
#include "bytecode.h"
#include "comparator.h"
#include "tree.h"
#include "sieve/sieve.h"
#include "imap/global.h"
#include "imap/mailbox.h"
#include "imap/mboxname.h"
#include "imap/message.h"
#include "imap/spool.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "hash.h"
#include "times.h"

static char vacation_answer;

/* current namespace */
static struct namespace test_namespace;

typedef struct {
    char *name;
    FILE *data;
    int size;
    struct message_content content;

    int cache_full;
    hdrcache_t cache;
    strarray_t *env_from;
    strarray_t *env_to;
} message_data_t;

typedef struct {
    const char *host;
    const char *remotehost;
    const char *remoteip;
    int edited_header;
} script_data_t;

static void fill_cache(message_data_t *m)
{
    struct protstream *pin = prot_new(fileno(m->data), 0);

    prot_rewind(pin);
    spool_fill_hdrcache(pin, NULL, m->cache, NULL);
    prot_free(pin);

    m->cache_full = 1;
}

/* we use the temp field in message_data to avoid having to malloc memory
   to return, and we also can't expose our the recipients to the message */
static int getenvelope(void *mc, const char *field, const char ***contents)
{
    message_data_t *m = (message_data_t *)mc;

    if (!strcasecmp(field, "from")) {
        *contents = (const char **)m->env_from->data;
        return SIEVE_OK;
    } else if (!strcasecmp(field, "to")) {
        *contents = (const char **)m->env_to->data;
        return SIEVE_OK;
    } else {
        *contents = NULL;
        return SIEVE_FAIL;
    }
}

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = (message_data_t *) v;

    if (!m->cache_full) {
        fill_cache(m);
    }

    *body = spool_getheader(m->cache, phead);

    if (*body) {
        return SIEVE_OK;
    } else {
        return SIEVE_FAIL;
    }
}

static void getheaders_cb(const char *name, const char *value,
                          const char *raw, void *rock)
{
    struct buf *contents = (struct buf *) rock;

    if (raw) buf_appendcstr(contents, raw);
    else buf_printf(contents, "%s: %s\r\n", name, value);
}

static int getheadersection(void *mc, struct buf **contents)
{
    message_data_t *m = (message_data_t *) mc;

    *contents = buf_new();

    spool_enum_hdrcache(m->cache, &getheaders_cb, *contents);

    return SIEVE_OK;
}

/* adds the header "head" with body "body" to msg */
static int addheader(void *mc, const char *head, const char *body, int index)
{
    message_data_t *m = (message_data_t *) mc;

    if (head == NULL || body == NULL) return SIEVE_FAIL;

    if (index < 0) {
        printf("appending header '%s: %s'\n", head, body);
        spool_append_header(xstrdup(head), xstrdup(body), m->cache);
    }
    else {
        printf("prepending header '%s: %s'\n", head, body);
        spool_prepend_header(xstrdup(head), xstrdup(body), m->cache);
    }

    return SIEVE_OK;
}

/* deletes (instance "index" of) the header "head" from msg */
static int deleteheader(void *mc, const char *head, int index)
{
    message_data_t *m = (message_data_t *) mc;

    if (head == NULL) return SIEVE_FAIL;

    if (!index) {
        printf("removing all headers '%s'\n", head);
        spool_remove_header(xstrdup(head), m->cache);
    }
    else {
        printf("removing header '%s[%d]'\n", head, index);
        spool_remove_header_instance(xstrdup(head), index, m->cache);
    }

    return SIEVE_OK;
}

static int getenvironment(void *sc, const char *keyname, char **res)
{
    script_data_t *sd = (script_data_t *) sc;
    *res = NULL;

    switch (*keyname) {
    case 'd':
        if (!strcmp(keyname, "domain")) {
            const char *domain = strchr(sd->host, '.');

            if (domain) domain++;
            else domain = "";

            *res = xstrdup(domain);
        }
        break;

    case 'h':
        if (!strcmp(keyname, "host")) *res = xstrdup(sd->host);
        break;

    case 'l':
        if (!strcmp(keyname, "location")) *res = xstrdup("MDA");
        break;

    case 'n':
        if (!strcmp(keyname, "name")) *res = xstrdup("Cyrus LMTP");
        break;

    case 'p':
        if (!strcmp(keyname, "phase")) *res = xstrdup("during");
        break;

    case 'r':
        if (!strncmp(keyname, "remote-", 7)) {
            if (!strcmp(keyname+7, "host"))
                *res = xstrdup(sd->remotehost);
            else if (sd->remoteip && !strcmp(keyname+7, "ip"))
                *res = xstrdup(sd->remoteip);
        }
        break;

    case 'v':
        if (!strcmp(keyname, "version")) *res = xstrdup(CYRUS_VERSION);
        break;
    }

    return (*res ? SIEVE_OK : SIEVE_FAIL);
}

static message_data_t *new_msg(FILE *msg, int size, const char *name)
{
    message_data_t *m;

    m = xzmalloc(sizeof(message_data_t));
    m->data = msg;
    m->size = size;
    m->name = xstrdup(name);
    m->cache = spool_new_hdrcache();

    return m;
}

static void free_msg(message_data_t *m)
{
    spool_free_hdrcache(m->cache);
    free(m->name);
    free(m);
}

static int getsize(void *mc, int *size)
{
    message_data_t *m = (message_data_t *) mc;

    *size = m->size;
    return SIEVE_OK;
}

static int getbody(void *mc, const char **content_types, sieve_bodypart_t ***parts)
{
    message_data_t *m = (message_data_t *) mc;
    int r = 0;

    if (!m->content.body) {
        /* parse the message body if we haven't already */
        r = message_parse_file_buf(m->data, &m->content.map,
                                   &m->content.body, NULL);
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    if (!r) message_fetch_part(&m->content, content_types,
                               (struct bodypart ***) parts);
    return (!r ? SIEVE_OK : SIEVE_FAIL);
}

static int getinclude(void *sc __attribute__((unused)),
                      const char *script,
                      int isglobal __attribute__((unused)),
                      char *fpath, size_t size)
{
    strlcpy(fpath, script, size);
    strlcat(fpath, ".bc", size);

    return SIEVE_OK;
}

static int redirect(void *ac, void *ic, void *sc __attribute__((unused)),
                    void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("redirecting message '%s' to '%s'\n", m->name, rc->addr);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int discard(void *ac __attribute__((unused)),
                   void *ic, void *sc __attribute__((unused)),
                   void *mc, const char **errmsg __attribute__((unused)))
{
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("discarding message '%s'\n", m->name);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int reject(void *ac, void *ic, void *sc __attribute__((unused)),
                  void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    if (rc->is_extended)
        printf("LMTP rejecting message '%s' with '%s'\n", m->name, rc->msg);
    else
        printf("rejecting message '%s' with '%s'\n", m->name, rc->msg);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int fileinto(void *ac, void *ic, void *sc __attribute__((unused)),
                    void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("filing message '%s' into '%s'\n", m->name, fc->mailbox);

    if (fc->imapflags->count) {
        char *s = strarray_join(fc->imapflags, "' '");
        if (s) {
            printf("\twith flags '%s'\n", s);
            free(s);
        }
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int keep(void *ac, void *ic, void *sc __attribute__((unused)),
                void *mc, const char **errmsg __attribute__((unused)))
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("keeping message '%s'\n", m->name);
    if (kc->imapflags->count) {
        char *s = strarray_join(kc->imapflags, "' '");
        if (s) {
            printf("\twith flags '%s'\n", s);
            free(s);
        }
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static int notify(void *ac, void *ic, void *sc __attribute__((unused)),
                  void *mc __attribute__((unused)),
                  const char **errmsg __attribute__((unused)))
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
    int *force_fail = (int*) ic;

    printf("notify ");
    if (nc->method) {
        printf("%s(", nc->method);
        if (nc->options) {
            int i;
            for (i = 0; i < strarray_size(nc->options); i++) {
                if (i) printf(", ");
                printf("%s", strarray_nth(nc->options, i));
            }
        }
        printf("), ");
    }
    printf("msg = '%s' with priority = %s\n",nc->message, nc->priority);

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

void sieve_log(void *sc __attribute__((unused)), void *mc __attribute__((unused)), const char *text)
{
    printf("sieve log: text=%s\n", text);
}

static int mysieve_error(int lineno, const char *msg,
                         void *i __attribute__((unused)),
                         void *s __attribute__((unused)))
{
    fprintf(stderr, "line %d: %s\r\n", lineno, msg);

    return SIEVE_OK;
}

static int mysieve_execute_error(const char *msg,
                                 void *i __attribute__((unused)),
                                 void *s __attribute__((unused)),
                                 void *m __attribute__((unused)))
{
    fprintf(stderr, "%s\r\n", msg);

    return SIEVE_OK;
}


static int autorespond(void *ac, void *ic __attribute__((unused)),
                       void *sc __attribute__((unused)),
                       void *mc __attribute__((unused)),
                       const char **errmsg __attribute__((unused)))
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    char yn;
    int i;

    if (vacation_answer) {
        yn = vacation_answer;
    }
    else {
        printf("Have I already responded to '");
        for (i = 0; i < SIEVE_HASHLEN; i++) {
            printf("%x", arc->hash[i]);
        }
        if (arc->seconds % DAY2SEC) {
            printf("' in %d seconds? ", arc->seconds);
        }
        else {
            printf("' in %d days? ", arc->seconds / DAY2SEC);
        }
        if (!scanf(" %c", &yn))
            return SIEVE_FAIL;
    }

    if (TOLOWER(yn) == 'y') return SIEVE_DONE;
    if (TOLOWER(yn) == 'n') return SIEVE_OK;

    return SIEVE_FAIL;
}

static int send_response(void *ac, void *ic, void *sc,
                         void *mc, const char **errmsg)
{
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    int *force_fail = (int*) ic;

    printf("echo '%s' | mail -s '%s' '%s' for message '%s' (from: %s)\n",
           src->msg, src->subj, src->addr, m->name, src->fromaddr);

    if (src->fcc.mailbox) {
        message_data_t vmc = { .name = "vacation-autoresponse" };

        (void) fileinto(&src->fcc, ic, sc, &vmc, errmsg);
    }

    return (*force_fail ? SIEVE_FAIL : SIEVE_OK);
}

static sieve_vacation_t vacation = {
    0,                          /* min response */
    0,                          /* max response */
    &autorespond,               /* autorespond() */
    &send_response              /* send_response() */
};

static int usage(const char *argv0) __attribute__((noreturn));
static int usage(const char *argv0)
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "%s -v script\n", argv0);
    fprintf(stderr, "%s [opts] mailbox script\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "   -e envelope_from\n");
    fprintf(stderr, "   -t envelope_to\n");
    fprintf(stderr, "   -r y|n - have sent vacation response already? (if required)\n");
    fprintf(stderr, "   -h local_hostname\n");
    fprintf(stderr, "   -H remote_hostname\n");
    fprintf(stderr, "   -I remote_ipaddr\n");
    exit(1);
}

static strarray_t e_from = STRARRAY_INITIALIZER;
static strarray_t e_to = STRARRAY_INITIALIZER;

int process_message(const char *path, sieve_execute_t *exe,
                    sieve_interp_t *i, script_data_t *sd)
{
    message_data_t *m = NULL;
    struct stat sbuf;
    int fd, res;
    FILE *f;

    fd = open(path, O_RDONLY);
    res = fstat(fd, &sbuf);
    if (res != 0) {
        perror("fstat");
    }

    f = fdopen(fd, "r");
    if (f) m = new_msg(f, sbuf.st_size, path);
    if (!f || !m) {
        printf("can not open message '%s'\n", path);
        return 1;
    }

    m->env_from = &e_from;
    m->env_to = &e_to;

    res = sieve_execute_bytecode(exe, i, sd, m);
    free_msg(m);
    fclose(f);
    close(fd);
    if (res != SIEVE_OK) {
        printf("sieve_execute_bytecode() returns %d\n", res);
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    sieve_interp_t *i;
    sieve_execute_t *exe = NULL;
    char *tmpscript = NULL, *script = NULL, *extname = NULL;
    int c, force_fail = 0;
    int fd, res, r;
    char *alt_config = NULL;
    script_data_t sd = { NULL, "", NULL, 0 };
    FILE *f;
    unsigned uid = 0;

    /* prevent crashes if -e or -t aren't specified */
    strarray_append(&e_from, "");
    strarray_append(&e_to, "");

    while ((c = getopt(argc, argv, "C:v:fu:e:t:r:h:H:I:")) != EOF)
        switch (c) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'v':
            script = optarg;
            break;
        case 'f':
            force_fail = 1;
            break;
        case 'u':
            uid = strtoul(optarg, NULL, 10);
            break;
        case 'e':
            strarray_fini(&e_from);
            strarray_append(&e_from, optarg);
            break;
        case 't':
            strarray_fini(&e_to);
            strarray_append(&e_to, optarg);
            break;
        case 'r':
            vacation_answer = optarg[0];
            break;
        case 'h':
            sd.host = optarg;
            break;
        case 'H':
            sd.remotehost = optarg;
            break;
        case 'I':
            sd.remoteip = optarg;
            break;
        default:
            usage(argv[0]);
            break;
        }

    if (!script) {
        if ((argc - optind) < 2)
            usage(argv[0]);
        else {
            extname = argv[optind];
            script = argv[optind+1];
        }
    }

    cyrus_init(alt_config, "test_mailbox", 0, CONFIG_NEED_PARTITION_DATA);
    global_sasl_init(1,0,NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&test_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    if (!sd.host) sd.host = config_servername;

    /* Check if script is bytecode or text */
    f = fopen(script, "r");
    if (f == NULL) {
        fprintf(stderr, "Unable to open %s for reading\n", script);
        exit(1);
    }
    else {
        char magic[BYTECODE_MAGIC_LEN];
        char tempname[] = "/tmp/sieve-test-bytecode-XXXXXX";
        sieve_script_t *s = NULL;
        bytecode_info_t *bc = NULL;
        char *err = NULL;

        if (fread(magic, BYTECODE_MAGIC_LEN, 1, f) <= 0 ||
            memcmp(magic, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN) != 0) {
            /* Not Sieve bytecode - try to parse as text */

            if (sieve_script_parse_only(f, &err, &s) != SIEVE_OK) {
                if(err) {
                    fprintf(stderr, "Unable to parse script: %s\n", err);
                } else {
                    fprintf(stderr, "Unable to parse script\n");
                }
                sieve_script_free(&s);

                exit(1);
            }

            /* Now, generate the bytecode */
            if (sieve_generate_bytecode(&bc, s) == -1) {
                fprintf(stderr, "bytecode generate failed\n");
                sieve_free_bytecode(&bc);
                sieve_script_free(&s);
                exit(1);
            }

            /* Now, open a temp bytecode file */
            script = tmpscript = tempname;
            fd = mkstemp(script);
            if (fd < 0) {
                fprintf(stderr, "couldn't open bytecode output file %s\n", script);
                sieve_free_bytecode(&bc);
                sieve_script_free(&s);
                exit(1);
            }

            /* Now, emit the bytecode */
            if (sieve_emit_bytecode(fd, bc) == -1) {
                fprintf(stderr, "bytecode emit failed\n");
                sieve_free_bytecode(&bc);
                sieve_script_free(&s);
                exit(1);
            }

            close(fd);

            sieve_free_bytecode(&bc);
            sieve_script_free(&s);
        }

        fclose(f);
    }

    i = sieve_interp_alloc(&force_fail);
    assert(i != NULL);

    sieve_register_redirect(i, redirect);
    sieve_register_discard(i, discard);
    sieve_register_reject(i, reject);
    sieve_register_fileinto(i, fileinto);
    sieve_register_keep(i, keep);
    sieve_register_size(i, getsize);
    sieve_register_header(i, getheader);
    sieve_register_headersection(i, getheadersection);
    sieve_register_addheader(i, addheader);
    sieve_register_deleteheader(i, deleteheader);
    sieve_register_envelope(i, getenvelope);
    sieve_register_environment(i, getenvironment);
    sieve_register_body(i, getbody);
    sieve_register_include(i, getinclude);
    sieve_register_logger(i, sieve_log);

    res = sieve_register_vacation(i, &vacation);
    if (res != SIEVE_OK) {
        printf("sieve_register_vacation() returns %d\n", res);
        exit(1);
    }

    sieve_register_notify(i, notify, NULL);
    sieve_register_parse_error(i, mysieve_error);
    sieve_register_execute_error(i, mysieve_execute_error);

    res = sieve_script_load(script, &exe);
    if (res != SIEVE_OK) {
        printf("sieve_script_load() returns %d\n", res);
        exit(1);
    }

    if (tmpscript) {
        /* Remove temp bytecode file */
        unlink(tmpscript);
    }

    if (extname) {
        char *intname = mboxname_from_external(extname, &test_namespace, NULL);
        struct mailbox *mailbox = NULL;

        /* Open/lock header */
        r = mailbox_open_irl(intname, &mailbox);
        free(intname);
        if (r) {
            printf("can not open mailbox '%s': %s\n", extname, error_message(r));
            exit(1);
        }

        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            if (uid && record->uid != uid) continue;
            printf("\n\nProcessing UID %u:\n", record->uid);
            const char *path = mailbox_record_fname(mailbox, record);
            r = process_message(path, exe, i, &sd);
        }
        mailbox_iter_done(&iter);

        mailbox_close(&mailbox);
    }

    /*used to be sieve_script_free*/
    res = sieve_script_unload(&exe);
    if (res != SIEVE_OK) {
        printf("sieve_script_unload() returns %d\n", res);
        exit(1);
    }
    res = sieve_interp_free(&i);
    if (res != SIEVE_OK) {
        printf("sieve_interp_free() returns %d\n", res);
        exit(1);
    }

    strarray_fini(&e_from);
    strarray_fini(&e_to);

    cyrus_done();

    return 0;
}

EXPORTED void fatal(const char* message, int rc)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(rc);
}
