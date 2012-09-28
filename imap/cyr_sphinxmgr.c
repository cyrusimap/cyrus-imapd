/* cyr_sphinxmgr.c - daemon for managing Sphinx index daemons
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <fcntl.h>
#include <sys/poll.h>

#include "mboxname.h"
#include "mboxlist.h"
#include "imap/imap_err.h"
#include "global.h"
#include "retry.h"
#include "command.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xmalloc.h"
#include "hash.h"
#include "exitcodes.h"

/* Various locations, relative to the Sphinx base directory */
#define SOCKET_PATH	    "/searchd.sock"
#define SPHINX_CONFIG	    "/sphinx.conf"
#define SEARCHD		    "/usr/bin/searchd"

extern int optind;
extern char *optarg;

static int verbose = 0;
static int server_sock;
static int sphinx_timeout;
static const char *syslog_prefix;

typedef struct indexd indexd_t;
struct indexd {
    char *basedir;	/* also used as the key */
    char *socketpath;
    time_t started;
    time_t used;
};
static struct hash_table itable;


static void shut_down(int code) __attribute__((noreturn));

void fatal(const char *msg, int err)
{
    syslog(LOG_ERR, "Fatal error %s, exiting", msg);
    shut_down(err);
}

static void indexd_free(indexd_t *id)
{
    free(id->basedir);
    free(id->socketpath);
    free(id);
}

static int indexd_setup_tree(indexd_t *id)
{
    static const char * const tobuild[] = {
	"",
	"/binlog",
	NULL
    };
    const char * const *dp;
    char *path = NULL;
    int r;

    if (verbose > 1)
	syslog(LOG_INFO, "setting up tree");
    for (dp = tobuild ; *dp ; dp++) {
	free(path);
	path = strconcat(id->basedir, *dp, "/filename",  (char *)NULL);
	r = cyrus_mkdir(path, 0700);
	if (r < 0 && errno != EEXIST) {
	    syslog(LOG_ERR, "IOERROR: unable to mkdir %s: %m", path);
	    r = IMAP_IOERROR;
	    goto out;
	}
    }
    r = 0;

out:
    free(path);
    return r;
}

static int indexd_setup_config(indexd_t *id)
{
    static const char config[] =
	"index rt\n"
	"{\n"
	"    type = rt\n"
	"    path = $sphinxdir/rt\n"
	"    morphology = stem_en\n"
	"    charset_type = utf-8\n"
	"\n"
	"    rt_attr_string = cyrusid\n"
	"    rt_field = header_from\n"
	"    rt_field = header_to\n"
	"    rt_field = header_cc\n"
	"    rt_field = header_bcc\n"
	"    rt_field = header_subject\n"
	"    rt_field = headers\n"
	"    rt_field = body\n"
	"}\n"
	"\n"
	"index latest\n"
	"{\n"
	"    type = rt\n"
	"    path = $sphinxdir/latest\n"
	"    rt_attr_string = mboxname\n"
	"    rt_attr_uint = uidvalidity\n"
	"    rt_attr_uint = uid\n"
	"    rt_field = dummy\n"
	"}\n"
	"\n"
	"searchd\n"
	"{\n"
	"    listen = $sphinxsock:mysql41\n"
	"    log = syslog\n"
	"    pid_file = $sphinxdir/searchd.pid\n"
	"    binlog_path = $sphinxdir/binlog\n"
	"    compat_sphinxql_magics = 0\n"
	"    workers = threads\n"
	"    max_matches = " SPHINX_MAX_MATCHES "\n"
	"}\n";
    char *sphinx_config = NULL;
    int fd = -1;
    struct buf buf = BUF_INITIALIZER;
    int r;

    sphinx_config = strconcat(id->basedir, SPHINX_CONFIG, (char *)NULL);
    if (verbose > 1)
	syslog(LOG_INFO, "setting up config \"%s\"", sphinx_config);

/* the searchd.log entry changed, so force a rewrite of the config file */
#if 0
    struct stat sb;
    if (stat(sphinx_config, &sb) == 0 &&
	S_ISREG(sb.st_mode) &&
	sb.st_size > 0) {
	r = 0;
	goto out;	/* a non-zero file already exists */
    }
#endif

    if (verbose)
	syslog(LOG_NOTICE, "Sphinx writing config file %s", sphinx_config);

    fd = open(sphinx_config, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
	syslog(LOG_ERR, "IOERROR: unable to open %s for writing: %m",
	       sphinx_config);
	r = IMAP_IOERROR;
	goto out;
    }

    buf_init_ro_cstr(&buf, config);
    buf_replace_all(&buf, "$sphinxsock", id->socketpath);
    buf_replace_all(&buf, "$sphinxdir", id->basedir);

    r = retry_write(fd, buf.s, buf.len);
    if (r < 0) {
	syslog(LOG_ERR, "IOERROR: error writing %s: %m", sphinx_config);
	r = IMAP_IOERROR;
	goto out;
    }
    r = 0;

out:
    if (fd >= 0) close(fd);
    free(sphinx_config);
    buf_free(&buf);
    return r;
}

static int indexd_start(indexd_t *id)
{
    char *config_file = NULL;
    int r;

    r = indexd_setup_tree(id);
    if (r) goto out;

    r = indexd_setup_config(id);
    if (r) goto out;

    if (verbose)
	syslog(LOG_NOTICE, "Sphinx starting searchd");

    config_file = strconcat(id->basedir, SPHINX_CONFIG, (char *)NULL);
    r = run_command(SEARCHD, "--config", config_file,
		    "--syslog-prefix", syslog_prefix, (char *)NULL);
    if (r) goto out;

    id->started = time(NULL);
    r = 0;

out:
    free(config_file);
    return r;
}

static int indexd_stop(indexd_t *id)
{
    char *config_file = NULL;
    int r;

    if (verbose)
	syslog(LOG_NOTICE, "Sphinx stopping searchd, "
			   "base directory %s socket %s",
			   id->basedir, id->socketpath);

    config_file = strconcat(id->basedir, SPHINX_CONFIG, (char *)NULL);
    r = run_command(SEARCHD, "--config", config_file,
		    "--syslog-prefix", syslog_prefix,
		    "--stop", (char *)NULL);
    if (r) goto out;

    unlink(id->socketpath);

    r = 0;

out:
    free(config_file);
    return r;
}

/* Returns in *basedir and *sockname, two new strings which must be free()d */
static int sphinx_paths_from_mboxname(const char *mboxname,
				      char **basedirp,
				      char **socknamep)
{
    char *confkey = NULL;
    const char *root;
    struct mboxlist_entry *mbentry = NULL;
    char *basedir = NULL;
    struct mboxname_parts parts;
    char *sockname = NULL;
    char c[2], d[2];
    int r;

    mboxname_init_parts(&parts);

    r = mboxlist_lookup(mboxname, &mbentry, /*tid*/NULL);
    if (r) goto out;
    if (mbentry->mbtype & MBTYPE_REMOTE) {
	r = IMAP_PARTITION_UNKNOWN;
	goto out;
    }

    confkey = strconcat("sphinxpartition-", mbentry->partition, NULL);
    root = config_getoverflowstring(confkey, NULL);
    if (!root) {
	r = IMAP_PARTITION_UNKNOWN;
	goto out;
    }

    r = mboxname_to_parts(mboxname, &parts);
    if (r) goto out;
    if (!parts.userid) {
	r = IMAP_PARTITION_UNKNOWN;
	goto out;
    }

    if (parts.domain)
	basedir = strconcat(root,
			    FNAME_DOMAINDIR,
			    dir_hash_b(parts.domain, config_fulldirhash, d),
			    "/", parts.domain,
			    FNAME_USERDIR,
			    dir_hash_b(parts.userid, config_fulldirhash, c),
			    "/", parts.userid,
			    (char *)NULL);
    else
	basedir = strconcat(root,
			    FNAME_USERDIR,
			    dir_hash_b(parts.userid, config_fulldirhash, c),
			    "/", parts.userid,
			    (char *)NULL);

    if (parts.domain)
	sockname = strconcat(config_dir,
			     "/socket/sphinx.",
			     parts.userid,
			     "@",
			     parts.domain,
			     (char *)NULL);
    else
	sockname = strconcat(config_dir,
			     "/socket/sphinx.",
			     parts.userid,
			     (char *)NULL);
    r = 0;

out:
    if (r) {
	free(basedir);
	free(sockname);
    }
    else {
	*basedirp = basedir;
	*socknamep = sockname;
    }
    free(confkey);
    mboxname_free_parts(&parts);
    mboxlist_entry_free(&mbentry);
    return r;
}

static int indexd_get(const char *mboxname, indexd_t **idp, int create)
{
    indexd_t *id;
    char *basedir = NULL;
    char *socketpath = NULL;
    int r;

    r = sphinx_paths_from_mboxname(mboxname, &basedir, &socketpath);
    if (r) return r;

    id = (indexd_t *)hash_lookup(basedir, &itable);
    if (!id) {
	if (!create) {
	    r = IMAP_NOTFOUND;
	    goto out;
	}
	id = xzmalloc(sizeof(*id));
	id->basedir = basedir;
	basedir = NULL;
	id->socketpath = socketpath;
	socketpath = NULL;
	r = indexd_start(id);
	if (r) {
	    indexd_free(id);
	    return r;
	}
	hash_insert(id->basedir, id, &itable);
    }
    id->used = time(NULL);
    *idp = id;
    r = 0;
out:
    free(basedir);
    free(socketpath);
    return r;
}

static void expire_indexd(const char *key __attribute__((unused)),
			  void *data,
			  void *rock __attribute__((unused)))
{
    indexd_t *id = (indexd_t *)data;

    if (time(NULL) > id->used + sphinx_timeout) {
	indexd_stop(id);
	hash_del(id->basedir, &itable);
	indexd_free(id);
    }
}

static int create_server_socket(void)
{
    const char *sockname = config_getstring(IMAPOPT_SPHINXMGR_SOCKET);
    struct sockaddr_un asun;
    int r;
    int s;

    s = socket(PF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
	perror("socket(PF_UNIX)");
	shut_down(1);
    }

    r = unlink(sockname);
    if (r < 0 && errno != ENOENT) {
	perror(sockname);
	shut_down(1);
    }

    memset(&asun, 0, sizeof(asun));
    asun.sun_family = AF_UNIX;
    strlcpy(asun.sun_path, sockname, sizeof(asun.sun_path));

    r = bind(s, (struct sockaddr *)&asun, sizeof(asun));
    if (r < 0) {
	perror(sockname);
	shut_down(1);
    }

    r = listen(s, 100);
    if (r < 0) {
	perror("listen");
	shut_down(1);
    }

    return s;
}

/*
 * Command is: GETSOCK <internal-mboxname>
 */
static int handle_getsock(char *mboxname, char *reply, size_t maxreply)
{
    indexd_t *id = NULL;
    int r;

    if (!mboxname || !*mboxname) return IMAP_PROTOCOL_BAD_PARAMETERS;

    r = indexd_get(mboxname, &id, /*create*/1);
    if (!r)
	snprintf(reply, maxreply, "%s", id->socketpath);
    return r;
}

/*
 * Command is: STOP <internal-mboxname>
 */
static int handle_stop(char *mboxname,
		       char *reply __attribute__((unused)),
		       size_t maxreply __attribute__((unused)))
{
    indexd_t *id = NULL;
    int r;

    if (!mboxname || !*mboxname) return IMAP_PROTOCOL_BAD_PARAMETERS;

    r = indexd_get(mboxname, &id, /*create*/0);
    if (!r)
	indexd_stop(id);
    return r;
}

static void process_command(int ss)
{
    int s;
    int r;
    int i;
    char *cmd;
    char *arg;
    int (*handler)(char *arg, char *reply, size_t maxreply) = NULL;
    char buf[1024];
    static const char sep[] = " \t\r\n";

    s = accept(ss, NULL, NULL);
    if (s < 0) {
	syslog(LOG_ERR, "accept(): %m");
	return;
    }

    r = read(s, buf, sizeof(buf)-1);
    if (r < 0) {
	syslog(LOG_ERR, "read(): %m");
	goto out;
    }
    if (r == 0) {
	/* what, eof already?  whatever */
	goto out;
    }
    buf[r] = '\0';

    /* trim trailing CR or LF from the line */
    while (r > 0 && (buf[r-1] == '\r' || buf[r-1] == '\n'))
	buf[--r] = '\0';

    /* split into command and argument, preserving whitespace
     * inside the argument */
    cmd = buf;
    i = strcspn(buf, sep);
    if (i <= 0 || i >= r) {
	syslog(LOG_ERR, "Malformed command received, ignoring");
	goto out;
    }
    while (i < r && isspace(buf[i]))
	buf[i++] = '\0';

    ucase(cmd);
    arg = buf+i;

    if (verbose > 1)
	syslog(LOG_INFO, "parsed command, cmd=\"%s\" arg=\"%s\"", cmd, arg);

    if (!strcmp(cmd, "GETSOCK"))
	handler = handle_getsock;
    else if (!strcmp(cmd, "STOP"))
	handler = handle_stop;

    if (handler) {
	snprintf(buf, sizeof(buf), "OK ");
	r = handler(arg, buf+strlen(buf), sizeof(buf)-strlen(buf)-2);
	if (!r)
	    strlcat(buf, "\r\n", sizeof(buf));
	else
	    snprintf(buf, sizeof(buf), "NO %s\r\n", error_message(r));
    }
    else
	snprintf(buf, sizeof(buf), "BAD Unrecognized command\r\n");

    if (verbose > 1)
	syslog(LOG_INFO, "sending reply \"%s\"", buf);

    retry_write(s, buf, strlen(buf));

    /* we always shut down the connection after one command */
out:
    close(s);
}

static void kill_indexd(const char *key __attribute__((unused)),
			void *data,
			void *rock __attribute__((unused)))
{
    indexd_t *id = (indexd_t *)data;

    indexd_stop(id);
}

static void shut_down(int code)
{
    if (server_sock >= 0) close(server_sock);
    hash_enumerate(&itable, kill_indexd, NULL);

    /* mboxlist might not have been opened yet, but that's harmless */
    mboxlist_close();
    mboxlist_done();

    cyrus_done();

    exit(code);
}

int main(int argc, char **argv)
{
    char *p = NULL;
    int opt;
    struct pollfd pfd;
    char *alt_config = NULL;
    int background = 1;
    int init_flags = CYRUSINIT_PERROR;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;

    while ((opt = getopt(argc, argv, "C:fv")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	case 'f': /* run in foreground for debugging */
	    background = 0;
	    break;
	case 'v':   /* be more verbose */
	    verbose++;
	    break;
	default:
	    fprintf(stderr, "invalid argument\n");
	    exit(EC_USAGE);
	    break;
	}
    }

    cyrus_init(alt_config, "cyr_sphinxmgr", 0, 0);

    syslog_prefix = config_getstring(IMAPOPT_SYSLOG_PREFIX);
    if (!syslog_prefix)
	syslog_prefix = "cyrus";

    /* Set inactivity timer (convert from minutes to seconds) */
    sphinx_timeout = config_getint(IMAPOPT_SPHINXMGR_TIMEOUT);

    signals_add_handlers(0);
    signals_set_shutdown(shut_down);

    /* create idle table */
    construct_hash_table(&itable, 1024, 1);

    server_sock = create_server_socket();

    /* fork unless we were given the -f option */
    if (background) {
	pid_t pid;
	int nullfd;

	nullfd = open("/dev/null", O_RDWR, 0);
	if (nullfd < 0) {
	    perror("/dev/null");
	    exit(1);
	}
	dup2(nullfd, 0);
	dup2(nullfd, 1);
	dup2(nullfd, 2);
	close(nullfd);
	init_flags &= ~CYRUSINIT_PERROR;

	pid = fork();
	if (pid == -1) {
	    perror("fork");
	    exit(1);
	}

	if (pid)
	    exit(0);/* parent */
	/* child */
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    syslog(LOG_INFO, "cyr_sphinxmgr running");

    for (;;) {
	int n;

	signals_poll();

	/* check for shutdown file */
	if (shutdown_file(NULL, 0))
	    shut_down(0);

	hash_enumerate(&itable, expire_indexd, NULL);

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = server_sock;
	pfd.events = POLLIN;

	n = poll(&pfd, 1, /*1 second timeout*/1000);
	if (n < 0) {
	    if (errno == EAGAIN || errno == EINTR) continue;
	    syslog(LOG_ERR, "poll(): %m");
	    fatal("poll failed", EC_TEMPFAIL);
	}

	if (n > 0 && (pfd.revents & POLLIN))
	    process_command(server_sock);
    }

    shut_down(0);
}

