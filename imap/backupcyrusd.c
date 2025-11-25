/* backupcyrusd.c -- server to speak Fastmail Internal backup protocol
 *
 * Copyright (c) 2025 Fastmail Pty Ltd
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
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "prot.h"

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "acl.h"
#ifdef USE_AUTOCREATE
#include "autocreate.h"
#endif
#include "util.h"
#include "auth.h"
#include "global.h"
#include "slowio.h"

#include "auditlog.h"
#include "loginlog.h"
#include "mailbox.h"
#include "map.h"
#include "user.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "mboxlist.h"
#include "proc.h"

/* generated headers are not necessarily in current directory */
#include "master/service.h"
#include "iostat.h"

extern int optind;
extern char *optarg;
extern int opterr;

static const char *bcd_clienthost = "[local]";
static struct protstream *bcd_out = NULL;
static struct protstream *bcd_in = NULL;
static int bcd_logfd = -1;

static struct proc_handle *proc_handle = NULL;

/* signal to config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* current namespace */
static struct namespace bcd_namespace;

/* Functions */
static int do_fdata();
static int do_fmeta();
static int do_fmultistatus();
static int do_meta();

static void cmdloop(void);
void shut_down(int code) __attribute__ ((noreturn));

static void bcd_reset(int in_shutdown)
{
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    proc_cleanup(&proc_handle);

    if (bcd_in) {
        prot_NONBLOCK(bcd_in);
        prot_fill(bcd_in);
        bytes_in = prot_bytes_in(bcd_in);
        prot_free(bcd_in);
    }

    if (bcd_out) {
        prot_flush(bcd_out);
        bytes_out = prot_bytes_out(bcd_out);
        prot_free(bcd_out);
    }

    auditlog_traffic(bytes_in, bytes_out);

    bcd_in = bcd_out = NULL;

    if (in_shutdown) return;

    cyrus_reset_stdio();

    bcd_clienthost = "[local]";
    if (bcd_logfd != -1) {
        close(bcd_logfd);
        bcd_logfd = -1;
    }

    slowio_reset();
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv,
                 char **envp __attribute__((unused)))
{
    int r;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    proc_settitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* Set namespace */
    if ((r = mboxname_init_namespace(&bcd_namespace, 0))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    const char *localip, *remoteip;

    signals_poll();

    bcd_in = prot_new(0, 0);
    bcd_out = prot_new(1, 1);

    /* Find out name of client host */
    bcd_clienthost = get_clienthost(0, &localip, &remoteip);

    /* Set inactivity timer */
    prot_settimeout(bcd_in, 600);
    prot_setflushonread(bcd_in, bcd_out);

    cmdloop();

    /* QUIT executed */

    /* cleanup */
    bcd_reset(0);

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    in_shutdown = 1;

    libcyrus_run_delayed();

    bcd_reset(1);

    cyrus_done();

    exit(code);
}

EXPORTED void fatal(const char* s __attribute__((unused)), int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        proc_cleanup(&proc_handle);
        exit(recurse_code);
    }
    recurse_code = code;
    shut_down(code);
}

static int geturistring(struct protstream *in, struct protstream *out, struct buf *buf)
{
    int c = getastring(in, out, buf);
    buf_cstring(buf);

    size_t i = 0, j = 0;
    while (i < buf->len) {
        char v = buf->s[i++];
        if (v == '%' && i < buf->len - 1) {
            hex_to_bin(buf->s+i, 2, &v);
            i += 2;
        }
        buf->s[j++] = v;
    }
    buf->len = j;
    buf->s[j] = '\0';

    return c;
}

// should this be somewhere more general?
static const char URISAFECHAR[256] = {
  /* control chars are unsafe */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* https://en.wikipedia.org/wiki/Percent-encoding */
/* RFC 3986 section 2.3 Unreserved Characters (January 2005) */
/* [A-Za-z0-9_~.-] */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
/* all high bits are unsafe */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void puturistring(struct protstream *out, const char *string)
{
    for (const char *p = string; *p; p++) {
        if (URISAFECHAR[(int)*p]) {
            prot_putc(*p, out);
        }
        else {
            prot_printf(out, "%%%02X", *p);
        }
    }
}

struct file_item {
   char *name;
   char *fname;
};

static int _readone(const char *mailbox __attribute__((unused)),
                    uint32_t uid __attribute__((unused)),
                    const char *entry,
                    const char *userid,
                    const struct buf *value,
                    const struct annotate_metadata *mdata __attribute__((unused)),
                    void *rock)
{
    json_array_append_new((json_t *)rock, json_pack("[sss]", entry, userid, buf_cstring(value)));
    return 0;
}


static char *read_annot(const mbentry_t *mbentry)
{
    json_t *jres = json_array();
    annotatemore_findall_mbentry(mbentry, 0, "*", 0, _readone, jres, 0);
    char *res = json_array_size(jres) ? json_dumps(jres, JSON_INDENT(2)) : NULL;
    json_decref(jres);
    return res;
}

static void send_annot(const mbentry_t *mbentry, const char *mboxname, int do_data)
{
    const char *name = "mailbox_annotations";
    char *base = read_annot(mbentry);
    if (!base) {
        if (do_data) prot_puts(bcd_out, "NO empty mailbox_annotations\n");
        return;
    }
    size_t len = strlen(base);
    struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    message_guid_generate(&guid, base, strlen(base));
    // synthetic inode
    char guidbuf[MESSAGE_GUID_SIZE];
    message_guid_export(&guid, guidbuf);
    long unsigned ino = *((uint16_t *)(guidbuf));
    long unsigned mtime = 0;

    if (do_data) {
        prot_puts(bcd_out, "DATA ");
        puturistring(bcd_out, name);
        prot_printf(bcd_out, " %lu %lu %lu\n", len, mtime, ino);
        prot_write(bcd_out, base, len);
        prot_puts(bcd_out, "DONE ");
        puturistring(bcd_out, name);
        prot_printf(bcd_out, " %s\n", message_guid_encode(&guid));
    }
    else {
        prot_puts(bcd_out, "STAT ");
        if (mboxname) {
            puturistring(bcd_out, mboxname);
            prot_putc(' ', bcd_out);
        }
        puturistring(bcd_out, name);
        prot_printf(bcd_out, " %lu %lu %lu\n", len, mtime, ino);
    }
    free(base);
}

/*
 *  All "DATA $file / bytes / DONE $sha1" sets can be replaced with
 *  "NO $file errormsg" if there is an error reading the file.
 */
static void send_file(const char *name, const char *mboxname, const char *fname, int do_data)
{
    struct stat sbuf;

    if (!fname || stat(fname, &sbuf)) {
        if (!do_data) return; // quiet if no file
        prot_printf(bcd_out, "NO no such file ");
        puturistring(bcd_out, name);
        prot_putc('\n', bcd_out);
        return;
    }

    if (do_data) {
        int fd = open(fname, O_RDONLY);
        if (fd < 0) {
            prot_puts(bcd_out, "NO failed to open file ");
            puturistring(bcd_out, name);
            prot_putc('\n', bcd_out);
            return;
        }
        const char *base = NULL;
        size_t len = 0;
        map_refresh(fd, 1, &base, &len, sbuf.st_size, fname, 0);
        prot_puts(bcd_out, "DATA ");
        puturistring(bcd_out, name);
        prot_printf(bcd_out, " %lu %lu %lu\n", len, sbuf.st_mtim.tv_sec, sbuf.st_ino);
        prot_write(bcd_out, base, len);
        struct message_guid guid = MESSAGE_GUID_INITIALIZER;
        message_guid_generate(&guid, base, len);
        prot_puts(bcd_out, "DONE ");
        puturistring(bcd_out, name);
        prot_printf(bcd_out, " %s\n", message_guid_encode(&guid));
        map_free(&base, &len);
        close(fd);
    }
    else {
        prot_puts(bcd_out, "STAT ");
        if (mboxname) {
            puturistring(bcd_out, mboxname);
            prot_putc(' ', bcd_out);
        }
        puturistring(bcd_out, name);
        prot_printf(bcd_out, " %lu %lu %lu\n", sbuf.st_size, sbuf.st_mtim.tv_sec, sbuf.st_ino);
    }
}

/*
 *  FDATA $slot $user $folder @files      # @files are UID numbers, no trailing dots
 *  => OK or NO message
 *  (
 *    => DATA $file $size $mtime $inode
 *    => $size bytes
 *    => DONE $file $sha1
 *  )
 *  => DONE FDATA $uniqueid $jmapid
 */
static int do_fdata()
{
    static struct buf user;
    static struct buf folder;
    static struct buf item;

    int c = geturistring(bcd_in, bcd_out, &user);
    if (c != ' ') {
        prot_printf(bcd_out, "NO missing user\n");
        return c;
    }

    const char *userid = buf_cstring(&user);

    c = geturistring(bcd_in, bcd_out, &folder);

    mbname_t *mbname = mbname_from_extname(buf_cstring(&folder), &bcd_namespace, userid);

    struct mailbox *mailbox = NULL;
    int r = mailbox_open_irl(mbname_intname(mbname), &mailbox);
    if (r) {
         prot_printf(bcd_out, "NO no such folder ");
         puturistring(bcd_out, buf_cstring(&folder));
         prot_putc('\n', bcd_out);
         mbname_free(&mbname);
         return c;
    }

    prot_puts(bcd_out, "OK\n");

    // we hold the read lock while we return the files
    ptrarray_t records = PTRARRAY_INITIALIZER;
    while (c == ' ') {
        c = getword(bcd_in, &item);
        uint32_t uid = atoi(buf_cstring(&item));
        struct index_record record;
        struct file_item *file = xzmalloc(sizeof(struct file_item));
        file->name = xstrdup(buf_cstring(&item));
        if (!mailbox_find_index_record(mailbox, uid, &record)) {
             const char *fname = mailbox_record_fname(mailbox, &record);
             file->fname = xstrdup(fname);
        }
        ptrarray_append(&records, file);
    }

    // ignore errors here
    mailbox_unlock_index(mailbox, NULL);

    int i;
    for (i = 0; i < ptrarray_size(&records); i++) {
        struct file_item *item = ptrarray_nth(&records, i);
        send_file(item->name, NULL, item->fname, 1);
        free(item->name);
        free(item->fname);
        free(item);
    }
    ptrarray_fini(&records);

    prot_printf(bcd_out, "DONE FDATA ");
    puturistring(bcd_out, mailbox_uniqueid(mailbox));
    prot_putc(' ', bcd_out);
    puturistring(bcd_out, mailbox_jmapid(mailbox));
    prot_putc('\n', bcd_out);

    mailbox_close(&mailbox);
    mbname_free(&mbname);

    return c;
}

/*
 * FMETA $slot $user $folder
 *  => OK or NO message
 *  => STAT header $size $mtime $inode
 *  => STAT index $size $mtime $inode
 *  => STAT annotations $size $mtime $inode
 *  => DONE FMETA $uniqueid $jmapid
 *
 * FMETA $slot $user $folder @files
 *  => OK or NO message
 *  (
 *    => DATA $fname $size $mtime $inode
 *    => $size bytes
 *    => DONE $file $sha1
 *  )
 *  => DONE FMETA $uniqueid $jmapid
 */
static int do_fmeta()
{
    static struct buf user;
    static struct buf folder;
    static struct buf item;

    int c = geturistring(bcd_in, bcd_out, &user);
    if (c == EOF) return c;
    if (c != ' ') {
        prot_printf(bcd_out, "NO missing user\n");
        return c;
    }

    c = geturistring(bcd_in, bcd_out, &folder);
    if (c == EOF) return c;

    mbname_t *mbname = mbname_from_extname(buf_cstring(&folder), &bcd_namespace, buf_cstring(&user));

    struct mailbox *mailbox = NULL;
    int r = mailbox_open_irl(mbname_intname(mbname), &mailbox);
    if (r) {
         prot_printf(bcd_out, "NO no such folder ");
         puturistring(bcd_out, mbname_intname(mbname));
         prot_putc('\n', bcd_out);
         mbname_free(&mbname);
         return c;
    }

    prot_puts(bcd_out, "OK\n");

    // case: want meta info
    if (c != ' ') {
        send_file("header", NULL, mailbox_meta_fname(mailbox, META_HEADER), 0);
        send_file("index", NULL, mailbox_meta_fname(mailbox, META_INDEX), 0);
        send_file("annotations", NULL, mailbox_meta_fname(mailbox, META_ANNOTATIONS), 0);
        send_annot(mailbox_mbentry(mailbox), NULL, 0);
    }

    // otherwise, list of files to send
    while (c == ' ') {
        c = getword(bcd_in, &item);
        if (!strcmp(buf_cstring(&item), "header")) {
            send_file("header", NULL, mailbox_meta_fname(mailbox, META_HEADER), 1);
        }
        else if (!strcmp(buf_cstring(&item), "index")) {
            send_file("index", NULL, mailbox_meta_fname(mailbox, META_INDEX), 1);
        }
        else if (!strcmp(buf_cstring(&item), "annotations")) {
            send_file("annotations", NULL, mailbox_meta_fname(mailbox, META_ANNOTATIONS), 1);
        }
        else if (!strcmp(buf_cstring(&item), "mailbox_annotations")) {
            send_annot(mailbox_mbentry(mailbox), NULL, 1);
        }
    }

    prot_printf(bcd_out, "DONE FMETA ");
    puturistring(bcd_out, mailbox_uniqueid(mailbox));
    prot_putc(' ', bcd_out);
    puturistring(bcd_out, mailbox_jmapid(mailbox));
    prot_putc('\n', bcd_out);

    mailbox_close(&mailbox);
    mbname_free(&mbname);

    return c;
}

static int one_status(const mbentry_t *mbentry, void *rock)
{
    const char *userid = (const char *)rock;
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    const char *extname = mbname_extname(mbname, &bcd_namespace, userid);
    prot_puts(bcd_out, "FOLDER ");
    puturistring(bcd_out, extname);
    prot_putc(' ', bcd_out);
    puturistring(bcd_out, mbentry->uniqueid);
    prot_putc(' ', bcd_out);
    puturistring(bcd_out, mbentry->jmapid);
    prot_putc('\n', bcd_out);
    send_file("header", extname, mbentry_metapath(mbentry, META_HEADER, 0), 0);
    send_file("index", extname, mbentry_metapath(mbentry, META_INDEX, 0), 0);
    send_file("annotations", extname, mbentry_metapath(mbentry, META_ANNOTATIONS, 0), 0);
    send_annot(mbentry, extname, 0);
    mbname_free(&mbname);
    return 0;
}

/*
 *  FMULTISTATUS $slot $user
 *    => OK or NO message
 *    (
 *      => FOLDER $name $uniqueid $jmapid
 *      => STAT $name header $size $mtime $inode
 *      => STAT $name index $size $mtime $inode
 *      => STAT $name annotations $size $mtime $inode
 *      => STAT $name mailbox_annotations $size $mtime $inode
 *    )
 *    => DONE FMULTISTATUS
 */
static int do_fmultistatus()
{
    static struct buf user;

    int c = geturistring(bcd_in, bcd_out, &user);
    if (c == EOF) return c;

    const char *userid = buf_cstring(&user);

    prot_puts(bcd_out, "OK\n");
    mboxlist_usermboxtree(userid, NULL, one_status, (void *)userid, MBOXTREE_DELETED);
    prot_printf(bcd_out, "DONE FMULTISTATUS\n");

    return c;
}

/*
 *  META $slot $user
 *    => OK or NO message
 *    => STAT seen $size $mtime $inode
 *    => STAT sub $size $mtime $inode
 *    => DONE META
 *
 *  META $slot $user @files
 *    => OK or NO message
 *    (
 *      => DATA $file $size $mtime $inode
 *      => $size bytes
 *      => DONE $file $sha1
 *    )
 *    => DONE META
 */
static int do_meta()
{
    static struct buf user;
    static struct buf item;
    char *fname;

    int c = geturistring(bcd_in, bcd_out, &user);
    if (c == EOF) return c;

    const char *userid = buf_cstring(&user);

    prot_puts(bcd_out, "OK\n");

    // case: want meta info
    if (c != ' ') {
        fname = user_hash_meta(userid, "seen");
        send_file("seen", NULL, fname, 0);
        free(fname);
        fname = user_hash_meta(userid, "sub");
        send_file("sub", NULL, fname, 0);
        free(fname);
    }

    // otherwise, list of files to send
    while (c == ' ') {
        c = getword(bcd_in, &item);
        if (!strcmp(buf_cstring(&item), "seen")) {
            fname = user_hash_meta(userid, "seen");
            send_file("seen", NULL, fname, 1);
            free(fname);
        }
        else if (!strcmp(buf_cstring(&item), "sub")) {
            fname = user_hash_meta(userid, "sub");
            send_file("sub", NULL, fname, 1);
            free(fname);
        }
    }

    prot_printf(bcd_out, "DONE META\n");

    return c;
}

static int users_cb(const char *userid, void *rock __attribute__((unused)))
{
    prot_puts(bcd_out, "USER ");
    puturistring(bcd_out, userid);
    prot_putc('\n', bcd_out);
    return 0;
}

/*
 *  USERS $slot
 *    => OK or NO message
 *    => USER $username
 *    => USER $username
 *    => DONE USERS
 */
static void do_users()
{
    prot_puts(bcd_out, "OK\n");
    mboxlist_alluser(users_cb, NULL);
    prot_printf(bcd_out, "DONE USERS\n");
}

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    static struct buf cmd, slot;
    int r;

    for (;;) {
        signals_poll();

        /* register process */
        r = proc_register(&proc_handle, 0,
                          config_ident, bcd_clienthost, NULL, NULL, NULL);
        if (r) fatal("unable to register process", EX_IOERR);
        proc_settitle(config_ident, bcd_clienthost, NULL, NULL, NULL);

        libcyrus_run_delayed();

        /* check for shutdown file */
        if (shutdown_file(NULL, 0)) {
            shut_down(0);
        }

        int c = getword(bcd_in, &cmd);
        if (c == EOF) break;
        const char *cstr = buf_cstring(&cmd);

        if (!strcasecmp(cstr, "QUIT")) {
            prot_printf(bcd_out, "OK\n");
            prot_flush(bcd_out);
            break;
        }

        if (!strcasecmp(cstr, "PING")) {
            prot_printf(bcd_out, "OK\n");
            prot_printf(bcd_out, "DONE PING\n");
            goto done;
        }

        c = getword(bcd_in, &slot);

        if (strcmp(buf_cstring(&slot), config_servername)) {
            prot_printf(bcd_out, "NO iam %s\n", config_servername);
            goto done;
        }

        if (!strcasecmp(cstr, "USERS")) {
            do_users();
            goto done;
        }

        if (c != ' ') {
            prot_printf(bcd_out, "NO bad command\n");
            eatline(bcd_in, c);
            prot_flush(bcd_out);
            continue;
        }

        if (!strcasecmp(cstr, "FDATA")) {
            c = do_fdata();
        }
        else if (!strcasecmp(cstr, "FMETA")) {
            c = do_fmeta();
        }
        else if (!strcasecmp(cstr, "FMULTISTATUS")) {
            c = do_fmultistatus();
        }
        else if (!strcasecmp(cstr, "META")) {
            c = do_meta();
        }
        else {
            prot_printf(bcd_out, "NO unknown command %s\n", cstr);
        }

done:
        eatline(bcd_in, c);
        prot_flush(bcd_out);
    }
}
