/* actions.c -- executes the commands for timsieved
 * Tim Martin
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "libconfig.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "imap/global.h"
#include "imap/sievedir.h"
#include "imap/sieve_db.h"
#include "imap/tls.h"
#include "imap/version.h"
#include "sieve/sieve_interface.h"
#include "timsieved/actions.h"
#include "timsieved/codes.h"

extern int sieved_userisadmin;
extern sieve_interp_t *interp;

static char *sieve_dir_config = NULL;
static char *sieved_userid = NULL;

static char *sieve_dir = NULL;

static struct mailbox *sieve_mailbox = NULL;
static struct sieve_db *sievedb = NULL;

int actions_init(void)
{
    int sieve_usehomedir = 0;

    sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);

    if (!sieve_usehomedir) {
        sieve_dir_config = (char *) config_getstring(IMAPOPT_SIEVEDIR);
    } else {
        /* can't use home directories with timsieved */
        syslog(LOG_ERR, "can't use home directories");

        return TIMSIEVE_FAIL;
    }

    return TIMSIEVE_OK;
}

int actions_setuser(const char *userid)
{
    char *domain = NULL;
    struct buf buf = BUF_INITIALIZER;
    int result;

    sieved_userid = xstrdup(userid);
    if (config_virtdomains) {
        /* split the user and domain */
        if ((domain = strrchr(sieved_userid, '@'))) *domain++ = '\0';
    }

    buf_setcstr(&buf, sieve_dir_config);

    if (domain) {
        char dhash = (char) dir_hash_c(domain, config_fulldirhash);
        buf_printf(&buf, "%s%c/%s", FNAME_DOMAINDIR, dhash, domain);
    }

    if (sieved_userisadmin) {
        buf_appendcstr(&buf, "/global");
    }
    else {
        char hash = (char) dir_hash_c(sieved_userid, config_fulldirhash);
        buf_printf(&buf, "/%c/%s", hash, sieved_userid);
    }

    /* rejoin user and domain */
    if (domain) domain[-1] = '@';

    if (sieve_dir) free(sieve_dir);
    sieve_dir = buf_release(&buf);

    struct stat sbuf;
    result = stat(sieve_dir, &sbuf);
    if (result && errno == ENOENT) {
        result = cyrus_mkdir(sieve_dir, 0755);
        if (!result) {
            result = mkdir(sieve_dir, 0755);
            if (!result) result = stat(sieve_dir, &sbuf);
        }
    }
    if (result) return TIMSIEVE_FAIL;

    sievedb = sievedb_open_userid(sieved_userid);
    if (!sievedb) return TIMSIEVE_FAIL;

    result = sieve_ensure_folder(sieved_userid, &sieve_mailbox);
    if (result) return TIMSIEVE_FAIL;

    mailbox_unlock_index(sieve_mailbox, NULL);

    return TIMSIEVE_OK;
}

void actions_unsetuser(void)
{
    free(sieved_userid);
    sieved_userid = NULL;

    mailbox_close(&sieve_mailbox);
    sieve_mailbox = NULL;

    sievedb_close(sievedb);
    sievedb = NULL;
}

int capabilities(struct protstream *conn, sasl_conn_t *saslconn,
                 int starttls_done, int authenticated, sasl_ssf_t sasl_ssf)
{
    const char *sasllist;
    int mechcount, i;

    /* implementation */
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        prot_printf(conn,
                    "\"IMPLEMENTATION\" \"Cyrus timsieved%s %s\"\r\n",
                    config_mupdate_server ? " (Murder)" : "", CYRUS_VERSION);
    } else if (config_serverinfo == IMAP_ENUM_SERVERINFO_MIN) {
        prot_printf(conn,
                    "\"IMPLEMENTATION\" \"Cyrus timsieved%s\"\r\n",
                    config_mupdate_server ? " (Murder)" : "");
    } else {
        /* IMAP_ENUM_SERVERINFO_OFF */
        prot_puts(conn, "\"IMPLEMENTATION\" \"ManageSieve\"\r\n");
    }
    prot_puts(conn, "\"VERSION\" \"1.0\"\r\n");

    /* SASL */
    if (!sieved_tls_required && (!authenticated || sasl_ssf) &&
        sasl_listmech(saslconn, NULL,
                      "\"SASL\" \"", " ", "\"\r\n",
                      &sasllist,
                      NULL, &mechcount) == SASL_OK/* && mechcount > 0*/)
    {
        prot_printf(conn,"%s",sasllist);
    }

    /* Sieve capabilities */
    const strarray_t *extensions = sieve_listextensions(interp);
    for (i = 0; i < strarray_size(extensions); i += 2) {
        /* capability/value pairs */
        prot_printf(conn,"\"%s\" \"%s\"\r\n",
                    strarray_nth(extensions, i), strarray_nth(extensions, i+1));
    }

    if (tls_enabled() && !starttls_done && !authenticated) {
        prot_puts(conn, "\"STARTTLS\"\r\n");
    }

    if (authenticated) prot_printf(conn, "\"OWNER\" \"%s\"\r\n", sieved_userid);
    prot_puts(conn, "\"UNAUTHENTICATE\"\r\n");

    prot_puts(conn,"OK\r\n");

    return TIMSIEVE_OK;
}

int getscript(struct protstream *conn, const struct buf *name)
{
    struct sieve_data *sdata = NULL;
    int result;

    if (!sievedir_valid_name(name)) {
        prot_printf(conn,"NO \"Invalid script name\"\r\n");
        return TIMSIEVE_FAIL;
    }

    result = sievedb_lookup_name(sievedb, sieve_mailbox->name,
                                 buf_cstring(name), &sdata, 0);
    if (result == CYRUSDB_NOTFOUND) {
        prot_printf(conn, "NO (NONEXISTENT) \"Script does not exist\"\r\n");
        return TIMSIEVE_NOEXIST;
    }
    else if (result) {
        prot_printf(conn, "NO \"Error getting script\"\r\n");
        return TIMSIEVE_FAIL;
    }

    prot_printf(conn, "{%lu}\r\n%s\r\n", strlen(sdata->content), sdata->content);

    prot_printf(conn, "OK\r\n");
    return TIMSIEVE_OK;
}

/* save name as a sieve script */
int putscript(struct protstream *conn, const struct buf *name,
              const struct buf *data, int verify_only)
{
    int result;
    char *err = NULL;
    int numscripts, maxscripts;

    if (!verify_only) {
        if (!sievedir_valid_name(name)) {
            prot_printf(conn,"NO \"Invalid script name\"\r\n");
            return TIMSIEVE_FAIL;
        }

        /* see if this would put the user over quota */
        maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

        sievedb_count(sievedb, &numscripts);
        if (numscripts == maxscripts) {
            prot_printf(conn, "NO (QUOTA/MAXSCRIPTS)"
                        " \"You are only allowed %d scripts on this server\"\r\n",
                        maxscripts);
            return TIMSIEVE_FAIL;
        }
    }

    result = sieve_script_parse_string(interp, buf_cstring(data), &err, NULL);

    if (result != SIEVE_OK) {
        if (err) {
            prot_printf(conn, "NO ");
            prot_printstring(conn, err);
            prot_printf(conn, "\r\n");
            free(err);
        } else {
            prot_printf(conn, "NO \"parse failed\"\r\n");
        }
        return TIMSIEVE_FAIL;
    }

    if (!verify_only) {
        struct sieve_data *sdata = NULL;

        result = sievedb_lookup_name(sievedb, sieve_mailbox->name,
                                     buf_cstring(name), &sdata, 0);
        if (!result || result == CYRUSDB_NOTFOUND) {
            sdata->name = buf_cstring(name);
            sdata->content = buf_cstring(data);

            result = sieve_script_store(sieve_mailbox, sdata);
        }

        if (result) {
            prot_printf(conn, "NO \"Error putting script\"\r\n");
            return TIMSIEVE_FAIL;
        }
    }

    prot_printf(conn, "OK\r\n");
    return TIMSIEVE_OK;
}

/* delete a sieve script */
int deletescript(struct protstream *conn, const struct buf *name)
{
    struct sieve_data *sdata = NULL;
    int result;

    if (!sievedir_valid_name(name)) {
        prot_printf(conn,"NO \"Invalid script name\"\r\n");
        return TIMSIEVE_FAIL;
    }

    result = sievedb_lookup_name(sievedb, sieve_mailbox->name,
                                 buf_cstring(name), &sdata, 0);
    if (result == CYRUSDB_NOTFOUND) {
        prot_printf(conn, "NO (NONEXISTENT) \"Script does not exist\"\r\n");
        return TIMSIEVE_NOEXIST;
    }
    else if (sdata->isactive) {
        prot_printf(conn, "NO (ACTIVE) \"Active script cannot be deleted\"\r\n");
        return TIMSIEVE_FAIL;
    }
    else if (!result) {
        result = sieve_script_remove(sieve_mailbox, sdata);
    }

    if (result) {
        prot_printf(conn, "NO \"Error deleting script\"\r\n");
        return TIMSIEVE_FAIL;
    }

    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}

static int list_cb(void *rock, struct sieve_data *sdata)
{
    struct protstream *conn = (struct protstream *) rock;

    prot_printf(conn, "\"%s\"", sdata->name);
    if (sdata->isactive) prot_puts(conn, " ACTIVE");
    prot_puts(conn, "\r\n");

    return 0;
}

/* list the scripts user has available */
int listscripts(struct protstream *conn)
{
    sievedb_foreach(sievedb, &list_cb, conn);

    prot_printf(conn, "OK\r\n");
    return TIMSIEVE_OK;
}

/* set the sieve script 'name' to be the active script */

int setactive(struct protstream *conn, const struct buf *name)
{
    const char *action = "deactivating";
    struct sieve_data *sdata = NULL;
    int result = 0;

    /* if string name is empty, disable active script */
    if (buf_len(name)) {
        action = "activating";

        if (!sievedir_valid_name(name)) {
            prot_printf(conn,"NO \"Invalid script name\"\r\n");
            return TIMSIEVE_FAIL;
        }

        result = sievedb_lookup_name(sievedb, sieve_mailbox->name,
                                     buf_cstring(name), &sdata, 0);
        if (result == CYRUSDB_NOTFOUND) {
            prot_printf(conn,"NO (NONEXISTENT) \"Script does not exist\"\r\n");
            return TIMSIEVE_NOEXIST;
        }
    }

    result = sieve_script_activate(sieve_mailbox, sdata);

    if (result) {
        prot_printf(conn, "NO \"Error %s script\"\r\n", action);
        return TIMSIEVE_FAIL;
    }

    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}

/* rename a sieve script */
int renamescript(struct protstream *conn,
                 const struct buf *oldname, const struct buf *newname)
{
    struct sieve_data *sdata = NULL;
    int result;

    if (!sievedir_valid_name(oldname)) {
            prot_printf(conn,"NO \"Invalid old script name\"\r\n");
            return TIMSIEVE_FAIL;
    }
    if (!sievedir_valid_name(newname)) {
            prot_printf(conn,"NO \"Invalid new script name\"\r\n");
            return TIMSIEVE_FAIL;
    }

    result = sievedb_lookup_name(sievedb, sieve_mailbox->name,
                                 buf_cstring(newname), &sdata, 0);
    if (!result) {
        prot_printf(conn, "NO (ALREADYEXISTS) \"Script %s already exists.\"\r\n",
                    buf_cstring(newname));
        return TIMSIEVE_EXISTS;
    }

    if (result == CYRUSDB_NOTFOUND) {
        result = sievedb_lookup_name(sievedb, sieve_mailbox->name,
                                     buf_cstring(oldname), &sdata, 0);
        if (result == CYRUSDB_NOTFOUND) {
            prot_printf(conn,"NO (NONEXISTENT) \"Script %s does not exist\"\r\n",
                        buf_cstring(oldname));
            return TIMSIEVE_NOEXIST;
        }

        if (!result) {
            result = sieve_script_rename(sieve_mailbox,
                                         sdata, buf_cstring(newname));
        }
    }

    if (result) {
        prot_printf(conn,"NO \"Error renaming script\"\r\n");
        return TIMSIEVE_FAIL;
    }

    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}

int cmd_havespace(struct protstream *conn,
                  const struct buf *sieve_name, unsigned long num)
{
    int numscripts, maxscripts;
    extern unsigned long maxscriptsize;

    if (!sievedir_valid_name(sieve_name)) {
        prot_printf(conn,"NO \"Invalid script name\"\r\n");
        return TIMSIEVE_FAIL;
    }

    /* see if the size of the script is too big */
    if (num > maxscriptsize) {
        prot_printf(conn,
                    "NO (QUOTA/MAXSIZE) \"Script size is too large. "
                    "Max script size is %ld bytes\"\r\n",
                    maxscriptsize);
        return TIMSIEVE_FAIL;
    }

    /* see if this would put the user over quota */
    maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

    sievedb_count(sievedb, &numscripts);
    if (numscripts == maxscripts) {
        prot_printf(conn, "NO (QUOTA/MAXSCRIPTS)"
                    " \"You are only allowed %d scripts on this server\"\r\n",
                    maxscripts);
        return TIMSIEVE_FAIL;
    }


    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}
