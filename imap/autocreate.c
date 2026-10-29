/* autocreate.c - Mailbox list manipulation routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>

#include "global.h"
#include "acl.h"
#include "annotate.h"
#include "util.h"
#include "user.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "xunlink.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#ifdef USE_SIEVE

#include "sieve/sieve_interface.h"
#include "sieve/script.h"

#define TIMSIEVE_FAIL   -1
#define TIMSIEVE_OK     0
#define MAX_FILENAME    1024

/*
 * Find the name of the sieve script
 * given the source script and compiled script names
 */
static const char *get_script_name(const char *filename)
{
    const char *p;

    p = strrchr(filename, '/');
    if (p == NULL)
        return filename;
    else
        return p + 1;
}

enum SieveFileType {
    SIEVE_TMP_1 = 0,
    SIEVE_TMP_2,
    SIEVE_BC_TMP,
    SIEVE_SCRIPT,
    SIEVE_BC_SCRIPT,
    SIEVE_DEFAULT,
    SIEVE_BC_LINK,
    SIEVE_NUM_FILE_TYPES
};
static struct sieve_scripts_info {
    enum SieveFileType stype;
    const char *ext;
} sieve_names[] = {
    {SIEVE_TMP_1, ".script.NEW"},
    {SIEVE_TMP_2, ".NEW"},
    {SIEVE_BC_TMP, ".bc.NEW"},
    {SIEVE_SCRIPT, ".script"},
    {SIEVE_BC_SCRIPT, ".bc"},
    {SIEVE_DEFAULT, ""},
    {SIEVE_BC_LINK, ".bc"}
};

struct sieve_scripts {
    char tmpname1[MAX_FILENAME];
    char tmpname2[MAX_FILENAME];
    char bctmpname[MAX_FILENAME];
    char scriptname[MAX_FILENAME];
    char bcscriptname[MAX_FILENAME];
    char defaultname[MAX_FILENAME];
    char bclinkname[MAX_FILENAME];
};

/*
 * Given the path to the sieve script directory `script_dir` and the sievename,
 * generate filenames and return it in the `fnames` structure.
 *
 * On Success, returns 0, else returns 1
 */
static int setup_sieve_filenames(const char *script_dir, const char *sievename,
                                 struct sieve_scripts *fnames)
{
    int r = 0, i;

    for (i = 0; i < SIEVE_NUM_FILE_TYPES; i++) {
        struct sieve_scripts_info *info = &sieve_names[i];
        int ret = 0;
        switch(info->stype) {
            case SIEVE_TMP_1:
                ret = snprintf(fnames->tmpname1, MAX_FILENAME, "%s/%s%s",
                               script_dir, sievename, info->ext);
                break;
            case SIEVE_TMP_2:
                ret = snprintf(fnames->tmpname2, MAX_FILENAME, "%s/%s%s",
                               script_dir, sievename, info->ext);
                break;
            case SIEVE_BC_TMP:
                ret = snprintf(fnames->bctmpname, MAX_FILENAME, "%s/%s%s",
                               script_dir, sievename, info->ext);
                break;
            case SIEVE_SCRIPT:
                ret = snprintf(fnames->scriptname, MAX_FILENAME, "%s/%s%s",
                               script_dir, sievename, info->ext);
                break;
            case SIEVE_BC_SCRIPT:
                ret = snprintf(fnames->bcscriptname, MAX_FILENAME, "%s/%s%s",
                               script_dir, sievename, info->ext);
                break;
            case SIEVE_DEFAULT:
                ret = snprintf(fnames->defaultname, MAX_FILENAME, "%s/%s%s",
                               script_dir, "defaultbc", info->ext);
                break;
            case SIEVE_BC_LINK:
                /*
                  Note from ellie timoney:
                  This is because a relative symlink target is relative to the
                  location of the symlink, and since the defaultname symlink is
                  being created in the appropriate directory, its target can't
                  also specify the directory [otherwise you'd get like
                  "user/f/foo/default" pointing to
                  "[user/f/foo/]user/f/foo/somescript.bc" and things would fall
                  apart :)]
                 */
                ret = snprintf(fnames->bclinkname, MAX_FILENAME, "%s%s",
                               sievename, info->ext);
                break;
            default:
                break;
        }

        if (ret < 0) {
            r = 1;
            break;
        }
    }

    return r;
}

static int autocreate_sieve(const char *userid, const char *source_script)
{
    sieve_script_t *s = NULL;
    bytecode_info_t *bc = NULL;
    char *err = NULL;
    FILE *in_stream = NULL, *out_fp;
    int out_fd = -1, in_fd = -1, r;
    int do_compile = 0;
    const char *compiled_source_script = NULL;
    const char *sievename = get_script_name(source_script);
    const char *sieve_script_dir = NULL;
    struct sieve_scripts script_names;
    char buf[4096];
    mode_t oldmask;
    struct stat statbuf;

    memset(&script_names, 0, sizeof(struct sieve_scripts));
    /* We don't support using the home directory, like timsieved */
    if (config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.config.invalid",
                   lf_s("config.option", "sieveusehomedir"));
        goto failed_start;
    }

    /* check if sievedir is defined in imapd.conf */
    if (!config_getstring(IMAPOPT_SIEVEDIR)) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.config.invalid",
                   lf_s("config.option", "sievedir"));
        goto failed_start;
    }

    /* Check if autocreate_sieve_compiledscript is defined in imapd.conf */
    compiled_source_script = config_getstring(IMAPOPT_AUTOCREATE_SIEVE_SCRIPT_COMPILED);
    if (!compiled_source_script) {
        xsyslog_ev(LOG_WARNING, "autocreate.sieve.compiling",
                   lf_s("autocreate.reason", "no_compiled_script"));
        do_compile = 1;
    }

    sieve_script_dir = user_sieve_path(userid);
    if (!sieve_script_dir) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "sieve_dir"));
        goto failed_start;
    }

    if (setup_sieve_filenames(sieve_script_dir, sievename, &script_names) != 0) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "filenames"),
                   lf_s("sys.path", sieve_script_dir),
                   lf_s("sieve.script", sievename));
        goto failed_start;
    }

    /* Check if a default sieve filter already exists */
    if (!stat(script_names.defaultname, &statbuf)) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.reason", "exists"));
        goto failed_start;
    }

    if (access(source_script, R_OK)) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "access"),
                   lf_s("sys.path", source_script));
        goto failed_start;
    }

    /*
     * At this point we start the modifications of the filesystem
     */

    /* Create the directory where the sieve scripts will reside */
    r = cyrus_mkdir(script_names.bctmpname, 0755);
    if (r == -1)
        goto failed_start;

    /*
     * We open the file that will be used as the bc file. If this file exists,
     * overwrite it since something bad has happened. We open the file here so
     * that this error checking is done before we try to open the rest of the
     * files to start copying etc.
     */
    out_fd = open(script_names.bctmpname,
                  O_CREAT|O_TRUNC|O_WRONLY,
                  S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (out_fd < 0 && errno != EEXIST) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "open_bytecode"),
                   lf_s("sys.path", script_names.bctmpname));
        goto failed_start;
    }

    /* Read the compiled script file */
    if (!do_compile && compiled_source_script) {
        if ((in_fd = open(compiled_source_script, O_RDONLY)) != -1) {
            do {
                r = read(in_fd, buf, sizeof(buf));
                int w = write(out_fd, buf, r);
                if ( w < 0 || w != r) {
                    xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                               lf_s("u.username", userid),
                               lf_s("autocreate.step", "write_bytecode"),
                               lf_s("sys.path", script_names.bctmpname));
                    goto failed2;
                }
            } while (r > 0);

            if (r == 0) {       /* EOF */
                xclose(out_fd);
                xclose(in_fd);
            } else if (r < 0) {
                xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                           lf_s("u.username", userid),
                           lf_s("autocreate.step", "read_compiled"),
                           lf_s("sys.path", compiled_source_script));
                xclose(in_fd);
                do_compile = 1;
                if (lseek(out_fd, 0, SEEK_SET)) {
                    xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                               lf_s("u.username", userid),
                               lf_s("autocreate.step", "lseek"),
                               lf_s("sys.path", compiled_source_script));
                    goto failed1;
                } /* if (lseek()) */
            } /* if (r < 0) */

            xclose(in_fd);
        } else
            xsyslog_ev(LOG_WARNING, "autocreate.sieve.compiled.unreadable",
                       lf_s("u.username", userid),
                       lf_s("sys.path", compiled_source_script));
    } else {
        do_compile = 1;
    } /* if (!do_compile && compiled_source_script) */

    /*
      We either failed to open a precompiled bc sieve script or
      we need to compile on
    */
    if (do_compile) {
        in_stream = fopen(source_script, "r");
        if (!in_stream) {
            xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "open_source"),
                       lf_s("sys.path", source_script));
            goto failed1;
        }

        if (sieve_script_parse_only(in_stream, &err, &s) != SIEVE_OK) {
            xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "parse"),
                       lf_s("sys.path", source_script));
            if (err && *err) {
                xsyslog_ev(LOG_ERR, "autocreate.sieve.parse.error",
                           lf_s("u.username", userid),
                           lf_s("error", err));
                free(err);
            }
            goto failed2;
        } /* if (sieve_script_parse_only()) */

        /* Generate Bytecode */
        if (sieve_generate_bytecode(&bc, s) == TIMSIEVE_FAIL) {
            xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "compile"));
            fclose(in_stream);
            goto failed2;
        } /* if (sieve_generate_bytecode()) */

        if (sieve_emit_bytecode(out_fd, bc) == TIMSIEVE_FAIL) {
            xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "emit"));
            fclose(in_stream);
            sieve_free_bytecode(&bc);
            sieve_script_free(&s);
            goto failed2;
        } /* if (sieve_emit_bytecode()) */

        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
    } /* if (do_compile) */

    xclose(out_fd);
    rewind(in_stream);

    /* Copy the source script */
    oldmask = umask(077);

    if ((out_fp = fopen(script_names.tmpname1, "w")) == NULL) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "open_destination"),
                   lf_s("sys.path", script_names.tmpname1));
        fclose(in_stream);
        umask(oldmask);
        goto failed2;
    }
    umask(oldmask);

    while ((r = fread(buf, sizeof(char), sizeof(buf), in_stream)) > 0) {
        if (fwrite(buf, sizeof(char), r, out_fp) != (unsigned)r) {
            xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "write_script"),
                       lf_s("sys.path", script_names.tmpname1));
            fclose(out_fp);
            fclose(in_stream);
            goto failed3;
        }
    }

    r = feof(in_stream);
    fclose(in_stream);
    fclose(out_fp);

    if (!r)                     /* error */
        goto failed3;


    /* Renaming the necessary stuff */
    if (cyrus_rename(script_names.tmpname1, script_names.scriptname)) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "rename"),
                   lf_s("old.sys.path", script_names.tmpname1),
                   lf_s("sys.path", script_names.scriptname));
        goto failed3;
    }

    if (cyrus_rename(script_names.bctmpname, script_names.bcscriptname)) {
        xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "rename"),
                   lf_s("old.sys.path", script_names.bctmpname),
                   lf_s("sys.path", script_names.bcscriptname));
        xunlink(script_names.bcscriptname);
        goto failed2;
    }

    /* end now with the symlink */
    if (symlink(script_names.bclinkname, script_names.defaultname)) {
        if (errno != EEXIST) {
            xsyslog_ev(LOG_WARNING, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "symlink"));
            xunlink(script_names.scriptname);
            xunlink(script_names.bcscriptname);
        }
    }

    /*
     * If everything has succeeded AND we have compiled the script AND we have
     * requested to generate the global script so that it is not compiled each
     * time then we create it.
     */
    if (do_compile &&
        config_getswitch(IMAPOPT_AUTOCREATE_SIEVE_SCRIPT_COMPILE)) {

        if (!compiled_source_script) {
            xsyslog_ev(LOG_WARNING, "autocreate.sieve.compiled.skipped",
                       lf_s("config.option", "autocreate_sieve_compiledscript"));
            goto success;
        } /* if (!compiled_source_script) */

        /*
         * Copy everything from the newly created bc sieve sieve script.
         */
        if ((in_fd = open(script_names.bcscriptname, O_RDONLY)) < 0) {
            xsyslog_ev(LOG_WARNING, "autocreate.sieve.compiled.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "open"),
                       lf_s("sys.path", script_names.bcscriptname));
            goto success;
        } /* if (open()) */

        out_fd = open(script_names.tmpname2,
                      O_CREAT|O_EXCL|O_WRONLY,
                      S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if (out_fd < 0 && errno != EEXIST) {
            xsyslog_ev(LOG_ERR, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "open_bytecode"),
                       lf_s("sys.path", script_names.tmpname2));
            xclose(in_fd);
            goto success;
        }

        while ((r = read(in_fd, buf, sizeof(buf))) > 0) {
            if (write(out_fd, buf, r) < 0) {
                xsyslog_ev(LOG_WARNING, "autocreate.sieve.compiled.failed",
                           lf_s("u.username", userid),
                           lf_s("autocreate.step", "write"),
                           lf_s("sys.path", script_names.tmpname2));
                xclose(out_fd);
                xclose(in_fd);
                xunlink(script_names.tmpname2);
                goto success;
           }
        } /* while */

        if (r == 0) { /*EOF */
            xclose(out_fd);
            xclose(in_fd);
        } else if (r < 0) {
                xsyslog_ev(LOG_WARNING, "autocreate.sieve.compiled.failed",
                           lf_s("u.username", userid),
                           lf_s("autocreate.step", "read"),
                           lf_s("sys.path", script_names.bcscriptname));
                xclose(out_fd);
                xclose(in_fd);
                xunlink(script_names.tmpname2);
                goto success;
        } /* if else if */

        /* rename the temporary created sieve script to its final name. */
        if (cyrus_rename(script_names.tmpname2, compiled_source_script)) {
            if (errno != EEXIST) {
                xunlink(script_names.tmpname2);
                xunlink(compiled_source_script);
            } /* if (errno) */
            goto success;
        }

        xsyslog_ev(LOG_NOTICE, "autocreate.sieve.compiled.saved",
                   lf_s("sys.path", compiled_source_script));
    }

 success:
    return 0;

 failed3:
    xunlink(script_names.tmpname1);
 failed2:
    xunlink(script_names.bctmpname);
    xclose(in_fd);
 failed1:
    xclose(out_fd);
 failed_start:
    return 1;
}
#endif /* USE_SIEVE */

/*
 * Struct needed to be passed as void *rock to
 * mboxlist_autochangesub();
 */
struct changesub_rock_st {
    const char *userid;
    struct auth_state *auth_state;
    int was_explicit;
};

/*
 * Automatically subscribe user to *ALL* shared folders,
 * one has permissions to be subscribed to.
 * INBOX subfolders are excluded.
 */
static int autochangesub(struct findall_data *data, void *rock)
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;
    struct changesub_rock_st *crock = (struct changesub_rock_st *)rock;
    const char *userid = crock->userid;
    struct auth_state *auth_state = crock->auth_state;
    int was_explicit = crock->was_explicit;
    const char *name = mbname_intname(data->mbname);
    int r;

    /* ignore all user mailboxes, we only want shared */
    if (mboxname_isusermailbox(name, 0)) return 0;

    r = mboxlist_changesub(name, userid, auth_state, 1, 0, 1, 1);

    /* unless this name was explicitly chosen, ignore the failure */
    if (!was_explicit) return 0;

    if (r) {
        xsyslog_ev(LOG_WARNING, "autocreate.subscribe.failed",
                   lf_s("u.username", userid),
                   lf_mbname("mbox.name", data->mbname),
                   lf_err("error", r));
    } else {
        xsyslog_ev(LOG_NOTICE, "autocreate.subscribe.succeeded",
                   lf_s("u.username", userid),
                   lf_mbname("mbox.name", data->mbname));
    }

    return 0;
}

/* string for strarray_split */
#define SEP "|"

/*
 * Automatically subscribe user to a shared folder.
 * Subscription is done successfully, if the shared
 * folder exists and the user has the necessary
 * permissions.
 */
static void autosubscribe_sharedfolders(struct namespace *namespace,
                                        const char *userid,
                                        struct auth_state *auth_state)
{
    strarray_t *folders = NULL;
    const char *sub;
    int i;
    struct changesub_rock_st changesub_rock;

    changesub_rock.userid = userid;
    changesub_rock.auth_state = auth_state;
    changesub_rock.was_explicit = 0;

    /*
     * If subscribeallsharedfolders is set to yes in imapd.conf, then
     * subscribe user to every shared folder one has the appropriate
     * permissions.
     */
    if (config_getswitch(IMAPOPT_AUTOCREATE_SUBSCRIBE_SHAREDFOLDERS_ALL)) {
        /* don't care about errors here, the sub will log them */
        mboxlist_findall(namespace, "*", 0, userid, auth_state,
                         autochangesub, &changesub_rock);
        return;
    }

    /* otherwise, check if there are particular folders to subscribe */

    sub = config_getstring(IMAPOPT_AUTOCREATE_SUBSCRIBE_SHAREDFOLDERS);
    if (!sub) return;

    changesub_rock.was_explicit = 1;

    folders = strarray_split(sub, SEP, STRARRAY_TRIM);

    for (i = 0; i < folders->count; i++) {
        const char *mboxname = strarray_nth(folders, i);
        mboxlist_findone(namespace, mboxname, 0, userid, auth_state,
                         autochangesub, &changesub_rock);
    }

    strarray_free(folders);

    return;
}

struct autocreate_specialuse_rock {
    const char *userid;
    const char *intname;
    const char *name;
};

static void autocreate_specialuse_cb(const char *key, const char *val, void *rock)
{
    struct autocreate_specialuse_rock *ar = (struct autocreate_specialuse_rock *)rock;
    if (strncmp(key, "xlist-", 6)) return;
    if (strcmp(val, ar->name)) return;

    struct buf usebuf = BUF_INITIALIZER;
    buf_putc(&usebuf, '\\');
    buf_appendcstr(&usebuf, key + 6);

    /* we've got an XLIST key that matches the autocreated name */
    char *existing = mboxlist_find_specialuse(buf_cstring(&usebuf), ar->userid);
    if (existing) {
        xsyslog_ev(LOG_NOTICE, "autocreate.specialuse.skipped",
                   lf_intname("mbox.name", ar->intname),
                   lf_buf("autocreate.specialuse", &usebuf),
                   lf_intname("other.mbox.name", existing));
        free(existing);
        goto done;
    }

    int r = annotatemore_write(ar->intname, "/specialuse", ar->userid, &usebuf);
    if (r) {
        xsyslog_ev(LOG_WARNING, "autocreate.specialuse.failed",
                   lf_intname("mbox.name", ar->intname),
                   lf_buf("autocreate.specialuse", &usebuf),
                   lf_err("error", r));
    }
    else {
        xsyslog_ev(LOG_INFO, "autocreate.specialuse.set",
                   lf_intname("mbox.name", ar->intname),
                   lf_buf("autocreate.specialuse", &usebuf));
    }

 done:
    buf_free(&usebuf);
}

struct autocreate_acl_rock {
    struct namespace *namespace;
    const char *intname;
    const char *shortname;
    struct auth_state *auth_state;
    const char *userid;
};

static void autocreate_acl_cb(const char *key, const char *val, void *rock)
{
    char *freeme = NULL, *folder, *identifier, *rights, *junk;
    char *err = NULL;
    struct autocreate_acl_rock *acl_rock = (struct autocreate_acl_rock *) rock;
    int r;

    if (strcmp(key, "autocreate_acl")) return;

    freeme = xstrdup(val);
    folder = strtok(freeme, " ");
    identifier = strtok(NULL, " ");
    rights = strtok(NULL, " ");
    junk = strtok(NULL, " ");

    if (strcmpnull(folder, acl_rock->shortname)) goto done;

    if (!folder || !identifier || !rights || junk) {
        xsyslog_ev(LOG_WARNING, "autocreate.acl.invalid",
                   lf_s("config.option", "autocreate_acl"),
                   lf_s("autocreate.value", val));
        goto done;
    }

    r = cyrus_acl_checkstr(rights, &err);
    if (r) {
        xsyslog_ev(LOG_WARNING, "autocreate.acl.invalid",
                   lf_intname("mbox.name", acl_rock->intname),
                   lf_s("acl.rights", rights),
                   lf_s("error", err));
        goto done;
    }

    r = mboxlist_setacl(acl_rock->namespace,
                        acl_rock->intname,
                        identifier, rights,
                        /* isadmin */ 1, acl_rock->userid,
                        acl_rock->auth_state);

    if (r) {
        xsyslog_ev(LOG_ERR, "autocreate.acl.failed",
                   lf_intname("mbox.name", acl_rock->intname),
                   lf_s("autocreate.identifier", identifier),
                   lf_s("acl.rights", rights),
                   lf_err("error", r));
        goto done;
    }

done:
    free(freeme);
    free(err);
    return;
}

int autocreate_user(struct namespace *namespace, const char *userid)
{
    int r = IMAP_MAILBOX_NONEXISTENT; /* default error if we break early */
    int64_t autocreatequota = config_getbytesize(IMAPOPT_AUTOCREATE_QUOTA);
    int autocreatequotamessage = config_getint(IMAPOPT_AUTOCREATE_QUOTA_MESSAGES);
    int n;
    struct auth_state *auth_state = NULL;
    strarray_t *create = NULL;
    strarray_t *subscribe = NULL;
    int numcrt = 0;
    int numsub = 0;

    user_nslock_t *user_nslock = user_nslock_lock_w(userid);
#ifdef USE_SIEVE
    const char *source_script;
#endif

    /* check for anonymous */
    if (!strcmp(userid, "anonymous"))
        return IMAP_MAILBOX_NONEXISTENT;

    char *inboxname = mboxname_user_mbox(userid, NULL);

    auth_state = auth_newstate(userid);

    /* Added this for debug information. */
    xsyslog_ev(LOG_DEBUG, "autocreate.inbox.started",
               lf_s("u.username", userid));

    /*
     * While this is not needed for admins
     * and imap_admins accounts, it would be
     * better to separate *all* admins and
     * proxyservers from normal accounts
     * (accounts that have mailboxes).
     * UOA Specific note(1): Even if we do not
     * exclude these servers-classes here,
     * UOA specific code, will neither return
     * role, nor create INBOX, because none of these
     * administrative accounts belong to  the
     * mailRecipient objectclass, or have imapPartition.
     * UOA Specific note(2): Another good reason for doing
     * this, is to prevent the code, from getting into
     * cyrus_ldap.c because of the continues MSA logins to LMTPd.
     */

    /*
     * we need to exclude admins here
     */

    /*
     * Do we really need group membership
     * for admins or service_admins?
     */
    if (global_authisa(auth_state, IMAPOPT_ADMINS)) goto done;

    /*
     * Do we really need group membership
     * for proxyservers?
     */
    if (global_authisa(auth_state, IMAPOPT_PROXYSERVERS)) goto done;

    /*
     * Check if user belongs to the autocreate_users group. This option
     * controls for whom the mailbox may be automatically created. Default
     * value for this option is 'anyone'. So, if not declared, all mailboxes
     * will be created.
     */
    if (!global_authisa(auth_state, IMAPOPT_AUTOCREATE_USERS)) {
        xsyslog_ev(LOG_DEBUG, "autocreate.inbox.skipped",
                   lf_s("u.username", userid),
                   lf_s("autocreate.reason", "not_autocreate_user"));
        goto done;
    }

    mbentry_t mbentry = MBENTRY_INITIALIZER;
    mbentry.name = inboxname;
    mbentry.mbtype = MBTYPE_EMAIL;

    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                               1/*isadmin*/, userid, auth_state,
                               MBOXLIST_CREATE_NOTIFY, NULL/*mailboxptr*/);

    if (!r) r = mboxlist_changesub(inboxname, userid, auth_state, 1, 1, 1, 1);
    if (r) {
        xsyslog_ev(LOG_ERR, "autocreate.inbox.failed",
                   lf_s("u.username", userid),
                   lf_s("autocreate.step", "create"),
                   lf_err("error", r));
        goto done;
    }

    if (autocreatequota >= 0 || autocreatequotamessage >= 0) {
        quota_t newquotas[QUOTA_NUMRESOURCES];
        int res;

        for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
            newquotas[res] = QUOTA_UNLIMITED;

        if (autocreatequota > 0)
            newquotas[QUOTA_STORAGE] = autocreatequota / 1024;

        if (autocreatequotamessage)
            newquotas[QUOTA_MESSAGE] = autocreatequotamessage;

        r = mboxlist_setquotas(inboxname, newquotas, 0, 0);
        if (r) {
            xsyslog_ev(LOG_ERR, "autocreate.inbox.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "quota"),
                       lf_err("error", r));
            goto done;
        }
    }

    xsyslog_ev(LOG_NOTICE, "autocreate.inbox.created",
               lf_s("u.username", userid));

    create = strarray_split(config_getstring(IMAPOPT_AUTOCREATE_INBOX_FOLDERS), SEP, STRARRAY_TRIM);
    subscribe = strarray_split(config_getstring(IMAPOPT_AUTOCREATE_SUBSCRIBE_FOLDERS), SEP, STRARRAY_TRIM);

    for (n = 0; n < create->count; n++) {
        const char *name = strarray_nth(create, n);
        char *foldername = mboxname_user_mbox(userid, name);
        struct autocreate_specialuse_rock specialrock = { userid, foldername, name };
        struct autocreate_acl_rock aclrock = { namespace, foldername, name,
                                               auth_state, userid };

        mbentry.name = foldername;
        mbentry.mbtype = MBTYPE_EMAIL;

        r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, auth_state,
                                   MBOXLIST_CREATE_NOTIFY, NULL/*mailboxptr*/);

        if (!r) {
            numcrt++;
            xsyslog_ev(LOG_NOTICE, "autocreate.folder.created",
                       lf_s("u.username", userid),
                       lf_intname("mbox.name", foldername));
        } else {
            xsyslog_ev(LOG_WARNING, "autocreate.folder.failed",
                       lf_s("u.username", userid),
                       lf_intname("mbox.name", foldername),
                       lf_err("error", r));
            r = 0;
            free(foldername);
            continue;
        }

        /* subscribe if requested */
        if (strarray_contains(subscribe, name)) {
            r = mboxlist_changesub(foldername, userid, auth_state, 1, 1, 1, 1);
            if (!r) {
                numsub++;
                xsyslog_ev(LOG_NOTICE, "autocreate.subscribe.succeeded",
                           lf_s("u.username", userid),
                           lf_intname("mbox.name", foldername));
            } else {
                xsyslog_ev(LOG_WARNING, "autocreate.subscribe.failed",
                           lf_s("u.username", userid),
                           lf_intname("mbox.name", foldername),
                           lf_err("error", r));
                r = 0;
            }
        }

        /* set specialuse if requested */
        config_foreachoverflowstring(autocreate_specialuse_cb, &specialrock);

        /* add additional acl's if requested */
        config_foreachoverflowstring(autocreate_acl_cb, &aclrock);

        free(foldername);
    }

    if (numcrt)
        xsyslog_ev(LOG_INFO, "autocreate.folders.created",
                   lf_s("u.username", userid),
                   lf_d("autocreate.created", numcrt),
                   lf_d("autocreate.subscribed", numsub));

    /*
     * Check if shared folders are available for subscription.
     */
    autosubscribe_sharedfolders(namespace, userid, auth_state);

#ifdef USE_SIEVE
    /*
     * Here the autocreate sieve script feature is initiated from.
     */
    source_script = config_getstring(IMAPOPT_AUTOCREATE_SIEVE_SCRIPT);

    if (source_script) {
        if (!autocreate_sieve(userid, source_script))
            xsyslog_ev(LOG_NOTICE, "autocreate.sieve.created",
                       lf_s("u.username", userid));
        else
            xsyslog_ev(LOG_WARNING, "autocreate.sieve.failed",
                       lf_s("u.username", userid),
                       lf_s("autocreate.step", "script"));
    }
#endif

 done:
    user_nslock_release(&user_nslock);
    free(inboxname);
    strarray_free(create);
    strarray_free(subscribe);
    auth_freestate(auth_state);

    return r;
}
