/* sievedir.c -- functions for managing scripts in a sievedir
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "assert.h"
#include "map.h"
#include "sievedir.h"
#include "sieve/bc_parse.h"
#include "sieve/sieve_interface.h"
#include "util.h"

EXPORTED struct buf *sievedir_get_script(const char *sievedir, const char *script)
{
    struct buf buf = BUF_INITIALIZER;

    buf_printf(&buf, "%s/%s", sievedir, script);

    int fd = open(buf_cstring(&buf), 0);
    if (fd < 0) return NULL;

    buf_free(&buf);
    buf_refresh_mmap(&buf, 1, fd, script, MAP_UNKNOWN_LEN, "sieve");

    close(fd);

    struct buf *ret = buf_new();

    buf_move(ret, &buf);

    return ret;
}
 
/* Everything but '/' and '\0' are valid. */
EXPORTED int sievedir_valid_name(const struct buf *name)
{
    size_t lup, len = buf_len(name);
    const char *ptr;

    /* must be at least one character long */
    if (len < 1) return 0;

    ptr = buf_base(name);

    for (lup = 0; lup < len; lup++) {
        if ((ptr[lup] == '/') || (ptr[lup] == '\0')) return 0;
    }

    return (lup < 1013);
}

EXPORTED int sievedir_script_exists(const char *sievedir, const char *name)
{
    char path[PATH_MAX];
    struct stat sbuf;

    snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, SCRIPT_SUFFIX);

    return (stat(path, &sbuf) == 0);
}

EXPORTED int sievedir_script_isactive(const char *sievedir, const char *name)
{
    char link[PATH_MAX];
    char target[PATH_MAX];
    ssize_t tgt_len;

    if (!name) return 0;

    snprintf(link, sizeof(link), "%s/%s", sievedir, DEFAULTBC_NAME);

    tgt_len = readlink(link, target, sizeof(target) - 1);

    if (tgt_len > BYTECODE_SUFFIX_LEN) {
        target[tgt_len - BYTECODE_SUFFIX_LEN] = '\0';
        return !strcmp(name, target);
    }
    else if (tgt_len == -1 && errno != ENOENT) {
        syslog(LOG_ERR, "IOERROR: readlink(%s): %m", link);
    }

    return 0;
}

EXPORTED int sievedir_activate_script(const char *sievedir, const char *name)
{
    char target[PATH_MAX];
    char active[PATH_MAX];
    char tmp[PATH_MAX+4];  /* +4 for ".NEW" */

    snprintf(target, sizeof(target), "%s%s", name, BYTECODE_SUFFIX);
    snprintf(active, sizeof(active), "%s/%s", sievedir, DEFAULTBC_NAME);
    snprintf(tmp, sizeof(tmp), "%s.NEW", active);

    /* N.B symlink() does NOT verify target for anything but string validity,
     * so activation of a nonexistent script will report success.
     */
    if (symlink(target, tmp) < 0) {
        syslog(LOG_ERR, "IOERROR: unable to symlink %s as %s: %m", target, tmp);
        return SIEVEDIR_IOERROR;
    }

    if (rename(tmp, active) < 0) {
        syslog(LOG_ERR, "IOERROR: unable to rename %s to %s: %m", tmp, active);
        unlink(tmp);
        return SIEVEDIR_IOERROR;
    }

    return SIEVEDIR_OK;
}

EXPORTED int sievedir_deactivate_script(const char *sievedir)
{
    char active[PATH_MAX];

    snprintf(active, sizeof(active), "%s/defaultbc", sievedir);
    if (unlink(active) != 0 && errno != ENOENT) {
        syslog(LOG_ERR, "IOERROR: unable to unlink %s: %m", active);
        return SIEVEDIR_IOERROR;
    }

    return SIEVEDIR_OK;
}

EXPORTED int sievedir_delete_script(const char *sievedir, const char *name)
{
    char path[PATH_MAX];
    int r;

    snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, SCRIPT_SUFFIX);
    r = unlink(path);
    if (r) {
        if (errno == ENOENT) return SIEVEDIR_NOTFOUND;

        syslog(LOG_ERR, "IOERROR: unlink(%s): %m", path);
        return SIEVEDIR_IOERROR;
    }

    snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, BYTECODE_SUFFIX);
    r = unlink(path);
    if (r && errno != ENOENT) {
        syslog(LOG_NOTICE, "IOERROR: unlink(%s): %m", path);
    }

    return SIEVEDIR_OK;
}

#ifdef USE_SIEVE
EXPORTED int sievedir_put_script(const char *sievedir, const char *name,
                                 const char *content, char **errors)
{
    char new_path[PATH_MAX];
    FILE *f;

    /* parse the script */
    sieve_script_t *s = NULL;
    (void) sieve_script_parse_string(NULL, content, errors, &s);
    if (!s) return SIEVEDIR_INVALID;

    /* open a new file for the script */
    snprintf(new_path, sizeof(new_path),
             "%s/%s%s.NEW", sievedir, name, SCRIPT_SUFFIX);

    f = fopen(new_path, "w+");

    if (f == NULL) {
        syslog(LOG_ERR, "IOERROR: fopen(%s): %m", new_path);
        sieve_script_free(&s);
        return SIEVEDIR_IOERROR;
    }

    size_t i, content_len = strlen(content);
    int saw_cr = 0;

    /* copy data to file - replacing any lone CR or LF with the
     * CRLF pair so notify messages are SMTP compatible */
    for (i = 0; i < content_len; i++) {
        if (saw_cr) {
            if (content[i] != '\n') putc('\n', f);
        }
        else if (content[i] == '\n')
            putc('\r', f);

        putc(content[i], f);
        saw_cr = (content[i] == '\r');
    }
    if (saw_cr) putc('\n', f);

    fflush(f);
    fclose(f);

    /* generate the bytecode */
    bytecode_info_t *bc = NULL;
    if (sieve_generate_bytecode(&bc, s) == -1) {
        unlink(new_path);
        sieve_script_free(&s);
        return SIEVEDIR_FAIL;
    }

    /* open the new bytecode file */
    char new_bcpath[PATH_MAX];
    snprintf(new_bcpath, sizeof(new_bcpath),
             "%s/%s%s.NEW", sievedir, name, BYTECODE_SUFFIX);
    int fd = open(new_bcpath, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        syslog(LOG_ERR, "IOERROR: open(%s): %m", new_bcpath);
        unlink(new_path);
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        return SIEVEDIR_IOERROR;
    }

    /* emit the bytecode */
    if (sieve_emit_bytecode(fd, bc) == -1) {
        close(fd);
        unlink(new_path);
        unlink(new_bcpath);
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        return SIEVEDIR_FAIL;
    }

    sieve_free_bytecode(&bc);
    sieve_script_free(&s);

    close(fd);

    /* rename */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, SCRIPT_SUFFIX);
    int r = rename(new_path, path);
    if (r) syslog(LOG_ERR, "IOERROR: rename(%s, %s): %m", new_path, path);
    else {
        snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, BYTECODE_SUFFIX);
        r = rename(new_bcpath, path);
        if (r) syslog(LOG_ERR, "IOERROR: rename(%s, %s): %m", new_bcpath, path);
    }

    return (r ? SIEVEDIR_IOERROR : SIEVEDIR_OK);
}
#endif /* USE_SIEVE */
