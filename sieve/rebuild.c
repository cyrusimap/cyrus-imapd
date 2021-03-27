/* rebuild.c -- wrapper functions for rebuilding sieve bytecode
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "lib/cyr_lock.h"
#include "lib/util.h"
#include "lib/xmalloc.h"
#include "lib/xstrlcat.h"
#include "lib/xstrlcpy.h"

#include "imap/imap_err.h"
#include "imap/mailbox.h"

#include "sieve/bytecode.h"
#include "sieve/bc_parse.h"
#include "sieve/script.h"
#include "sieve/sieve_interface.h"

static char *sieve_getbcfname(const char *script_fname)
{
    char tmp[MAX_MAILBOX_PATH + 1];
    char *ext;
    size_t len;

    len = strlcpy(tmp, script_fname, sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    ext = strrchr(tmp, '.');
    if (!ext || strcmp(ext, ".script"))
        return NULL;

    *ext = '\0';
    len = strlcat(tmp, ".bc", sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    return xstrdup(tmp);
}

static char *sieve_getscriptfname(const char *bc_name)
{
    char tmp[MAX_MAILBOX_PATH + 1];
    char *ext;
    size_t len;

    len = strlcpy(tmp, bc_name, sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    ext = strrchr(tmp, '.');
    if (!ext || strcmp(ext, ".bc"))
        return NULL;

    *ext = '\0';
    len = strlcat(tmp, ".script", sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    return xstrdup(tmp);
}

EXPORTED char *sieve_getdefaultbcfname(const char *defaultbc)
{
    char tmp[MAX_MAILBOX_PATH + 1];
    char target[MAX_MAILBOX_PATH + 1];
    char *tail;
    size_t len;
    ssize_t llen;

    len = strlcpy(tmp, defaultbc, sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    tail = strrchr(tmp, '/');
    if (!tail || strcmp(tail, "/defaultbc"))
        return NULL;

    llen = readlink(defaultbc, target, sizeof(target) - 1);
    if (llen == -1)
        return NULL;

    target[llen] = '\0';
    *(tail + 1) = '\0';

    len = strlcat(tmp, target, sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    return xstrdup(tmp);
}

extern int sieve_bytecode_version(const sieve_bytecode_t *bc);

EXPORTED int sieve_rebuild(const char *script_fname, const char *bc_fname,
                           int force, char **out_parse_errors)
{
    char new_bc_fname[MAX_MAILBOX_PATH + 1] = {0};
    char *freeme = NULL;
    FILE *script_file = NULL;
    char *parse_errors = NULL;
    sieve_script_t *script = NULL;
    bytecode_info_t *bc = NULL;
    int script_fd = -1, bc_fd = -1;
    int r;
    size_t len;

    if (!script_fname && !bc_fname)
        return SIEVE_FAIL; /* XXX assert? */

    if (!script_fname)
        script_fname = freeme = sieve_getscriptfname(bc_fname);

    if (!bc_fname)
        bc_fname = freeme = sieve_getbcfname(script_fname);

    if (!script_fname || !bc_fname)
        return SIEVE_FAIL;

    /* open and lock the script file */
    script_fd = open(script_fname, O_RDWR);
    if (script_fd == -1) {
        syslog(LOG_ERR, "IOERROR: unable to open %s for reading: %m",
                        script_fname);
        r = IMAP_IOERROR;
        goto done;
    }

    r = lock_setlock(script_fd, /* exclusive */ 1, /* nonblocking */ 0,
                     script_fname);
    if (r) {
        syslog(LOG_ERR, "IOERROR: unable to obtain lock on %s: %m",
                        script_fname);
        r = IMAP_IOERROR;
        goto done;
    }

    /* exit early if bc is up to date */
    if (!force) {
        struct stat script_stat, bc_stat;

        r = fstat(script_fd, &script_stat);
        if (r) {
            syslog(LOG_ERR, "IOERROR: fstat %s: %m", script_fname);
            r = IMAP_IOERROR;
            goto done;
        }

        r = stat(bc_fname, &bc_stat);
        if (r && errno != ENOENT) {
            syslog(LOG_ERR, "IOERROR: stat %s: %m", bc_fname);
            r = IMAP_IOERROR;
            goto done;
        }

        if (!r && bc_stat.st_mtime >= script_stat.st_mtime) {
            sieve_execute_t *exe = NULL;
            r = sieve_script_load(bc_fname, &exe);

            if (!r) {
                int version;

                bc_header_parse((bytecode_input_t *) exe->bc_cur->data,
                                &version, NULL);
                if (version == BYTECODE_VERSION) {
                    syslog(LOG_DEBUG,
                           "%s: %s is up to date", __func__, bc_fname);
                    r = SIEVE_OK;
                    sieve_script_unload(&exe);
                    goto done;
                }
            }

            sieve_script_unload(&exe);
        }
    }

    len = strlcpy(new_bc_fname, bc_fname, sizeof(new_bc_fname));
    if (len >= sizeof(new_bc_fname)) {
        syslog(LOG_ERR, "IOERROR: filename too long: %s", bc_fname);
        r = IMAP_IOERROR;
        goto done;
    }
    len = strlcat(new_bc_fname, ".NEW", sizeof(new_bc_fname));
    if (len >= sizeof(new_bc_fname)) {
        syslog(LOG_ERR, "IOERROR: filename too long: %s", bc_fname);
        r = IMAP_IOERROR;
        goto done;
    }

    /* make sure no stray hardlink is lying around */
    unlink(new_bc_fname);

    bc_fd = open(new_bc_fname, O_CREAT|O_TRUNC|O_WRONLY,
                               S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (bc_fd < 0) {
        syslog(LOG_ERR, "IOERROR: unable to open %s for writing: %m",
                        new_bc_fname);
        r = IMAP_IOERROR;
        goto done;
    }

    /* if an error occurs after this point, we need to unlink new_bc_fname */

    script_file = fdopen(script_fd, "r");
    if (!script_file) {
        syslog(LOG_ERR, "IOERROR: unable to fdopen %s for reading: %m",
                        script_fname);
        r = IMAP_IOERROR;
        goto done;
    }

    r = sieve_script_parse_only(script_file, &parse_errors, &script);
    if (r != SIEVE_OK) {
        syslog(LOG_ERR, "%s: %s parse failed: %s",
                        __func__, script_fname, parse_errors);
        goto done;
    }

    if (sieve_generate_bytecode(&bc, script) == -1) {
        syslog(LOG_ERR, "%s: %s bytecode generation failed: %s",
                        __func__, script_fname, "unknown error");
        r = SIEVE_FAIL;
        goto done;
    }

    if (sieve_emit_bytecode(bc_fd, bc) == -1) {
        syslog(LOG_ERR, "%s: unable to emit bytecode to %s: %s",
                        __func__, bc_fname, "unknown error");
        r = SIEVE_FAIL;
        goto done;
    }

    if (fsync(bc_fd) < 0) {
        r = errno;
        syslog(LOG_ERR, "IOERROR: fsync %s: %m", new_bc_fname);
        goto done;
    }

    if (rename(new_bc_fname, bc_fname) < 0) {
        r = errno;
        syslog(LOG_ERR, "IOERROR: rename %s -> %s: %m",
                        new_bc_fname, bc_fname);
        goto done;
    }

    syslog(LOG_DEBUG, "%s: %s rebuilt from %s",
                      __func__, bc_fname, script_fname);

done:
    if (r && new_bc_fname[0] != '\0') unlink(new_bc_fname);

    if (bc_fd >= 0) close(bc_fd);

    lock_unlock(script_fd, script_fname);
    if (script_file) {
        fclose(script_file); /* also closes underlying fd */
    }
    else if (script_fd >= 0) {
        close(script_fd);
    }

    if (parse_errors) {
        if (out_parse_errors)
            *out_parse_errors = parse_errors;
        else
            free(parse_errors);
    }

    if (bc) sieve_free_bytecode(&bc);
    if (script) sieve_script_free(&script);

    if (freeme) free(freeme);

    return r;
}
