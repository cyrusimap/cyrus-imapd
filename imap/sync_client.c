/* sync_client.c -- Cyrus synchonization client
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
 *
 * $Id: sync_client.c,v 1.51 2010/06/28 12:04:20 brong Exp $
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

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
#include <ctype.h>
#include <signal.h>
#include <utime.h>

#include <netinet/tcp.h>

#include "global.h"
#include "assert.h"
#include "append.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "util.h"
#include "prot.h"
#include "message_guid.h"
#include "sync_support.h"
#include "lock.h"
#include "backend.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "signals.h"
#include "cyrusdb.h"

/* signal to config.c */
const int config_need_data = 0;  /* YYY */

/* ====================================================================== */

/* Static global variables and support routines for sync_client */

extern char *optarg;
extern int optind;

static const char *servername = NULL;
static struct protstream *sync_out = NULL;
static struct protstream *sync_in = NULL;

static struct namespace   sync_namespace;

static int verbose         = 0;
static int verbose_logging = 0;
static int connect_once    = 0;
static int foreground      = 0;
static int do_compress     = 0;

static struct protocol_t csync_protocol =
{ "csync", "csync",
  { 1, "* OK" },
  { NULL, NULL, "* OK", NULL,
    { { "* SASL ", CAPA_AUTH },
      { "* STARTTLS", CAPA_STARTTLS },
      { NULL, 0 } } },
  { "STARTTLS", "OK", "NO", 0 },
  { "AUTHENTICATE", INT_MAX, 0, "OK", "NO", "+ ", "*", NULL, 0 },
  { NULL, NULL, NULL },
  { "NOOP", NULL, "OK" },
  { "EXIT", NULL, "OK" }
};

static int do_meta(char *user);

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    seen_done();
    annotatemore_close();
    annotatemore_done();
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
            "usage: %s -S <servername> [-C <alt_config>] [-r] [-v] mailbox...\n", name);
 
    exit(EC_USAGE);
}

void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    exit(code);
}

/* ====================================================================== */

/* Routines relevant to reserve operation */

/* Find the messages that we will want to upload from this mailbox,
 * flag messages that are already available at the server end */

static int find_reserve_messages(struct mailbox *mailbox,
				 unsigned last_uid,
				 struct sync_msgid_list *part_list)
{
    struct index_record record;
    unsigned long recno;
    int r;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);

	if (r) {
	    syslog(LOG_ERR,
		   "IOERROR: reading index entry for recno %lu of %s: %m",
		   recno, mailbox->name);
	    return IMAP_IOERROR;
	}

	if (record.system_flags & FLAG_UNLINKED)
	    continue;

	/* skip over records already on replica */
	if (record.uid <= last_uid)
	    continue;

	sync_msgid_add(part_list, &record.guid);
    }
    
    return(0);
}

static int find_reserve_all(struct sync_name_list *mboxname_list,
			    struct sync_folder_list *master_folders,
			    struct sync_folder_list *replica_folders,
			    struct sync_reserve_list *reserve_guids)
{
    struct sync_name *mbox;
    struct sync_folder *rfolder;
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox;
    int r;

    /* Find messages we want to upload that are available on server */
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
	r = mailbox_open_irl(mbox->name, &mailbox);

	/* Quietly skip over folders which have been deleted since we
	   started working (but record fact in case caller cares) */
	if (r == IMAP_MAILBOX_NONEXISTENT) {  
	    r = 0;     
	    continue;
	}

	/* Quietly ignore objects that we don't have access to.
	 * Includes directory stubs, which have not underlying cyrus.*
	 * files in the filesystem */
	if (r == IMAP_PERMISSION_DENIED) {
	    r = 0;
	    continue;
	}

	if (r) {
	    syslog(LOG_ERR, "IOERROR: Failed to open %s: %s",
		   mbox->name, error_message(r));
	    goto bail;
	}

	part_list = sync_reserve_partlist(reserve_guids, mailbox->part);

	sync_folder_list_add(master_folders, mailbox->uniqueid, mailbox->name, 
			     mailbox->part, mailbox->acl, mailbox->i.options,
			     mailbox->i.uidvalidity, mailbox->i.last_uid,
			     mailbox->i.highestmodseq, mailbox->i.sync_crc,
			     mailbox->i.recentuid, mailbox->i.recenttime,
			     mailbox->i.pop3_last_login);

	rfolder = sync_folder_lookup(replica_folders, mailbox->uniqueid);
	if (rfolder)
	    find_reserve_messages(mailbox, rfolder->last_uid, part_list);
	else
	    find_reserve_messages(mailbox, 0, part_list);

	mailbox_close(&mailbox);
    }

bail:
    return r;
}

static int mark_missing (struct dlist *kin,
			 struct sync_msgid_list *part_list)
{
    struct dlist *kl = kin->head;
    struct dlist *ki;
    struct message_guid tmp_guid;
    struct sync_msgid *msgid;

    /* no missing at all, good */
    if (!kl) return 0;

    if (strcmp(kl->name, "MISSING")) {
	syslog(LOG_ERR, "Illegal response to RESERVE: %s", kl->name);
	return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    /* unmark each missing item */
    for (ki = kl->head; ki; ki = ki->next) {
	if (!message_guid_decode(&tmp_guid, ki->sval)) {
	    syslog(LOG_ERR, "RESERVE: failed to parse GUID %s", ki->sval);
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
        }

	msgid = sync_msgid_lookup(part_list, &tmp_guid);
	if (!msgid) {
	    syslog(LOG_ERR, "RESERVE: Got unexpected GUID %s", ki->sval);
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	}

	msgid->mark = 0;
	part_list->marked--;
    }

    return 0;
}

static int reserve_partition(char *partition,
			     struct sync_folder_list *replica_folders,
			     struct sync_msgid_list *part_list)
{
    const char *cmd = "RESERVE";
    struct sync_msgid *msgid;
    struct sync_folder *folder;
    struct dlist *kl;
    struct dlist *kin = NULL;
    struct dlist *ki;
    int r;

    if (!part_list->count)
	return 0; /* nothing to reserve */

    if (!replica_folders->head)
	return 0; /* nowhere to reserve */

    kl = dlist_new(cmd);
    dlist_atom(kl, "PARTITION", partition);

    ki = dlist_list(kl, "MBOXNAME");
    for (folder = replica_folders->head; folder; folder = folder->next)
	dlist_atom(ki, "MBOXNAME", folder->name);

    ki = dlist_list(kl, "GUID");
    for (msgid = part_list->head; msgid; msgid = msgid->next) {
	dlist_atom(ki, "GUID", message_guid_encode(&msgid->guid));
	msgid->mark = 1;
	part_list->marked++;
    }

    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_in, &kin);
    if (r) return r;

    r = mark_missing(kin, part_list);
    dlist_free(&kin);

    return r;
}

static int reserve_messages(struct sync_name_list *mboxname_list,
			    struct sync_folder_list *master_folders,
			    struct sync_folder_list *replica_folders,
			    struct sync_reserve_list *reserve_guids)
{
    struct sync_reserve *reserve;
    int r;

    r = find_reserve_all(mboxname_list, master_folders, 
			 replica_folders, reserve_guids);
    if (r) return r;

    for (reserve = reserve_guids->head; reserve; reserve = reserve->next) {
	r = reserve_partition(reserve->part, replica_folders, reserve->list);
	if (r) return r;
    }

    return 0;
}

/* ====================================================================== */

static int response_parse(const char *cmd,
			  struct sync_folder_list *folder_list,
			  struct sync_name_list *sub_list,
			  struct sync_sieve_list *sieve_list,
			  struct sync_seen_list *seen_list,
			  struct sync_quota_list *quota_list)
{
    struct dlist *kin = NULL;
    struct dlist *kl;
    int r;

    r = sync_parse_response(cmd, sync_in, &kin);

    /* Unpleasant: translate remote access error into "please reset me" */
    if (r == IMAP_MAILBOX_NONEXISTENT)
        return 0;

    for (kl = kin->head; kl; kl = kl->next) {
	if (!strcmp(kl->name, "SIEVE")) {
	    const char *filename = NULL;
	    time_t modtime = 0;
	    unsigned long active = 0;
	    if (!sieve_list) goto parse_err;
	    if (!dlist_getatom(kl, "FILENAME", &filename)) goto parse_err;
	    if (!dlist_getdate(kl, "LAST_UPDATE", &modtime)) goto parse_err;
	    dlist_getnum(kl, "ISACTIVE", &active); /* optional */
	    sync_sieve_list_add(sieve_list, filename, modtime, active);
	}

	else if (!strcmp(kl->name, "QUOTA")) {
	    const char *root = NULL;
	    unsigned long limit = 0;
	    if (!quota_list) goto parse_err;
	    if (!dlist_getatom(kl, "ROOT", &root)) goto parse_err;
	    if (!dlist_getnum(kl, "LIMIT", &limit)) goto parse_err;
	    sync_quota_list_add(quota_list, root, limit);
	}

	else if (!strcmp(kl->name, "LSUB")) {
	    struct dlist *i;
	    if (!sub_list) goto parse_err;
	    for (i = kl->head; i; i = i->next) {
		sync_name_list_add(sub_list, i->sval);
	    }
	}

	else if (!strcmp(kl->name, "SEEN")) {
	    const char *uniqueid = NULL;
	    time_t lastread = 0;
	    unsigned long lastuid = 0;
	    time_t lastchange = 0;
	    const char *seenuids = NULL;
	    if (!seen_list) goto parse_err;
	    if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) goto parse_err;
	    if (!dlist_getdate(kl, "LASTREAD", &lastread)) goto parse_err;
	    if (!dlist_getnum(kl, "LASTUID", &lastuid)) goto parse_err;
	    if (!dlist_getdate(kl, "LASTCHANGE", &lastchange)) goto parse_err;
	    if (!dlist_getatom(kl, "SEENUIDS", &seenuids)) goto parse_err;
	    sync_seen_list_add(seen_list, uniqueid, lastread,
			       lastuid, lastchange, seenuids);
	}

	else if (!strcmp(kl->name, "MAILBOX")) {
	    const char *uniqueid = NULL;
	    const char *mboxname = NULL;
	    const char *part = NULL;
	    const char *acl = NULL;
	    const char *options = NULL;
	    modseq_t highestmodseq = 0;
	    unsigned long uidvalidity = 0;
	    unsigned long last_uid = 0;
	    unsigned long sync_crc = 0;
	    unsigned long recentuid = 0;
	    time_t recenttime = 0;
	    time_t pop3_last_login = 0;
	    if (!folder_list) goto parse_err;
	    if (!dlist_getatom(kl, "UNIQUEID", &uniqueid)) goto parse_err;
	    if (!dlist_getatom(kl, "MBOXNAME", &mboxname)) goto parse_err;
	    if (!dlist_getatom(kl, "PARTITION", &part)) goto parse_err;
	    if (!dlist_getatom(kl, "ACL", &acl)) goto parse_err;
	    if (!dlist_getatom(kl, "OPTIONS", &options)) goto parse_err;
	    if (!dlist_getmodseq(kl, "HIGHESTMODSEQ", &highestmodseq)) goto parse_err;
	    if (!dlist_getnum(kl, "UIDVALIDITY", &uidvalidity)) goto parse_err;
	    if (!dlist_getnum(kl, "LAST_UID", &last_uid)) goto parse_err;
	    if (!dlist_getnum(kl, "SYNC_CRC", &sync_crc)) goto parse_err;
	    if (!dlist_getnum(kl, "RECENTUID", &recentuid)) goto parse_err;
	    if (!dlist_getdate(kl, "RECENTTIME", &recenttime)) goto parse_err;
	    if (!dlist_getdate(kl, "POP3_LAST_LOGIN", &pop3_last_login)) goto parse_err;

	    sync_folder_list_add(folder_list, uniqueid,
				 mboxname, part, acl,
				 sync_parse_options(options),
				 uidvalidity, last_uid, 
				 highestmodseq, sync_crc,
				 recentuid, recenttime,
				 pop3_last_login);
	}
	else
	    goto parse_err;
    }
    dlist_free(&kin);

    return r;

 parse_err:
    dlist_free(&kin);
    syslog(LOG_ERR, "%s: Invalid response %s", cmd, dlist_lastkey());
    return IMAP_PROTOCOL_BAD_PARAMETERS;
}

static int user_reset(char *userid)
{
    const char *cmd = "UNUSER";
    struct dlist *kl;

    kl = dlist_atom(NULL, cmd, userid);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int folder_rename(char *oldname, char *newname, char *partition)
{
    const char *cmd = "RENAME";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "OLDMBOXNAME", oldname);
    dlist_atom(kl, "NEWMBOXNAME", newname);
    dlist_atom(kl, "PARTITION", partition);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int folder_delete(char *mboxname)
{
    const char *cmd = "UNMAILBOX";
    struct dlist *kl;

    kl = dlist_atom(NULL, cmd, mboxname);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int set_sub(const char *userid, const char *mboxname, int add)
{
    const char *cmd = add ? "SUB" : "UNSUB";
    struct dlist *kl;

    if (verbose) 
        printf("%s %s %s\n", cmd, userid, mboxname);

    if (verbose_logging)
        syslog(LOG_INFO, "%s %s %s", cmd, userid, mboxname);

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "MBOXNAME", mboxname);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int folder_setannotation(const char *mboxname, const char *entry,
				const char *userid, const char *value)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "MBOXNAME", mboxname);
    dlist_atom(kl, "ENTRY", entry);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "VALUE", value);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int folder_unannotation(const char *mboxname, const char *entry,
			       const char *userid)
{
    const char *cmd = "UNANNOTATION";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "MBOXNAME", mboxname);
    dlist_atom(kl, "ENTRY", entry);
    dlist_atom(kl, "USERID", userid);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

/* ====================================================================== */

static int sieve_upload(const char *userid, const char *filename,
			unsigned long last_update)
{
    const char *cmd = "SIEVE";
    struct dlist *kl;
    char *sieve;
    unsigned long size;

    sieve = sync_sieve_read(userid, filename, &size);
    if (!sieve) return IMAP_IOERROR;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    dlist_date(kl, "LAST_UPDATE", last_update);
    dlist_buf(kl, "CONTENT", sieve, size);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);
    free(sieve);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int sieve_delete(const char *userid, const char *filename)
{
    const char *cmd = "UNSIEVE";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int sieve_activate(const char *userid, const char *filename)
{
    const char *cmd = "ACTIVATE_SIEVE";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    dlist_atom(kl, "FILENAME", filename);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int sieve_deactivate(const char *userid)
{
    const char *cmd = "UNACTIVATE_SIEVE";
    struct dlist *kl;

    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", userid);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

/* ====================================================================== */

static int delete_quota(const char *root)
{
    const char *cmd = "UNQUOTA";
    struct dlist *kl;

    kl = dlist_atom(NULL, cmd, root);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int update_quota_work(struct quota *client,
			     struct sync_quota *server)
{
    const char *cmd = "QUOTA";
    struct dlist *kl;
    int r;

    r = quota_read(client, NULL, 0);

    /* disappeared?  Delete it*/
    if (r == IMAP_QUOTAROOT_NONEXISTENT)
        return delete_quota(client->root);

    if (r) {
        syslog(LOG_INFO, "Warning: failed to read quotaroot %s: %s",
               client->root, error_message(r));
        return r;
    }

    if (server && (client->limit == server->limit))
        return(0);

    kl = dlist_new(cmd);
    dlist_atom(kl, "ROOT", client->root);
    dlist_num(kl, "LIMIT", client->limit);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int user_sub(const char *userid, const char *mboxname)
{
    int r;

    r = mboxlist_checksub(mboxname, userid);

    switch (r) {
    case CYRUSDB_OK:
	return set_sub(userid, mboxname, 1);
    case CYRUSDB_NOTFOUND:
	return set_sub(userid, mboxname, 0);
    default:
	return r;
    }
}

static int copy_local(struct mailbox *mailbox, unsigned long uid)
{
    int recno;
    struct index_record record;
    char *oldfname, *newfname;
    int r;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);
	if (r) return r;
	if (record.uid == uid) {
	    /* store the old record, expunged */
	    record.system_flags |= FLAG_EXPUNGED;
	    r = mailbox_rewrite_index_record(mailbox, &record);
	    if (r) return r;

	    /* create the new record */
	    record.system_flags &= ~FLAG_EXPUNGED;
	    record.uid = mailbox->i.last_uid + 1;

	    /* copy the file in to place */
	    oldfname = xstrdup(mailbox_message_fname(mailbox, uid));
	    newfname = xstrdup(mailbox_message_fname(mailbox, record.uid));
	    r = mailbox_copyfile(oldfname, newfname, 0);
	    free(oldfname);
	    free(newfname);
	    if (r) return r;

	    /* and append the new record (a clone apart from the EXPUNGED flag) */
	    r = mailbox_append_index_record(mailbox, &record);

	    /* done - return */
	    return r;
	}
    }

    /* not finding the record is an error! (should never happen) */
    return IMAP_MAILBOX_NONEXISTENT;
}

static int fetch_file(struct mailbox *mailbox, unsigned long uid,
		      struct index_record *rp)
{
    const char *cmd = "FETCH";
    struct dlist *kin = NULL;
    struct dlist *kl;
    int r;

    kl = dlist_new(cmd);
    dlist_atom(kl, "MBOXNAME", mailbox->name);
    dlist_atom(kl, "PARTITION", mailbox->part);
    dlist_atom(kl, "GUID", message_guid_encode(&rp->guid));
    dlist_num(kl, "UID", uid);
    sync_send_lookup(kl, sync_out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_in, &kin);
    if (r) return r;

    kl = kin->head;
    if (!kl) {
	r = IMAP_MAILBOX_NONEXISTENT;
	goto done;
    }

    if (!message_guid_compare(&kl->gval, &rp->guid))
	r = IMAP_MAILBOX_CRC;

done:
    dlist_free(&kin);
    return r;
}

static int copy_remote(struct mailbox *mailbox, unsigned long uid,
		       struct dlist *kr)
{
    struct index_record record;
    struct dlist *ki;
    int r;

    for (ki = kr->head; ki; ki = ki->next) {
	r = parse_upload(ki, mailbox, &record);
	if (r) return r;
	if (record.uid == uid) {
	    /* find the destination UID */
	    record.uid = mailbox->i.last_uid + 1;

	    /* upload the file */
	    r = fetch_file(mailbox, uid, &record);
	    if (r) return r;

	    /* append the file */
	    r = sync_append_copyfile(mailbox, &record);

	    return r;
	}
    }
    /* not finding the record is an error! (should never happen) */
    return IMAP_MAILBOX_NONEXISTENT;
}

static int copyback_one_record(struct mailbox *mailbox,
			       struct index_record *rp,
			       struct dlist *kaction)
{
    int r;

    /* don't want to copy back expunged records! */
    if (rp->system_flags & FLAG_EXPUNGED)
	return 0;

    /* if the UID is lower than master's last_uid,
     * we'll need to renumber */
    if (rp->uid <= mailbox->i.last_uid) {
	/* Ok, now we need to check if it's just really stale
	 * (has been cleaned out locally) or an error.
	 * In the error case we copy back, stale
	 * we remove from the replica */
	if (rp->modseq < mailbox->i.deletedmodseq)
	    dlist_num(kaction, "EXPUNGE", rp->uid);
	else
	    dlist_num(kaction, "COPYBACK", rp->uid);
    }

    /* otherwise we can pull it in with the same UID,
     * which saves causing renumbering on the replica
     * end, so is preferable */
    else {
	/* grab the file */
	r = fetch_file(mailbox, rp->uid, rp);
	if (r) return r;
	/* append the file */
	r = sync_append_copyfile(mailbox, rp);
	if (r) return r;
    }

    return 0;
}

static int renumber_one_record(struct mailbox *mailbox,
			       struct index_record *mp,
			       struct dlist *kaction)
{
    /* don't want to renumber expunged records */
    if (mp->system_flags & FLAG_EXPUNGED)
	return 0;

    dlist_num(kaction, "RENUMBER", mp->uid);

    return 0;
}

static const char *make_flags(struct mailbox *mailbox, struct index_record *record)
{
    static char buf[4096];
    const char *sep = "";
    int flag;

    if (record->system_flags & FLAG_DELETED) {
	snprintf(buf, 4096, "%s\\Deleted", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_ANSWERED) {
	snprintf(buf, 4096, "%s\\Answered", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_FLAGGED) {
	snprintf(buf, 4096, "%s\\Flagged", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_DRAFT) {
	snprintf(buf, 4096, "%s\\Draft", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_EXPUNGED) {
	snprintf(buf, 4096, "%s\\Expunged", sep);
        sep = " ";
    }
    if (record->system_flags & FLAG_SEEN) {
	snprintf(buf, 4096, "%s\\Seen", sep);
        sep = " ";
    }
        
    /* print user flags in mailbox order */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(record->user_flags[flag/32] & (1<<(flag&31))))
	    continue;
	snprintf(buf, 4096, "%s%s", sep, mailbox->flagname[flag]);
        sep = " ";
    }

    return buf;
}

static void log_record(const char *name, struct mailbox *mailbox,
		       struct index_record *record)
{
    syslog(LOG_ERR, "uid:%lu modseq:" MODSEQ_FMT " last_updated:%lu internaldate:%lu flags:(%s)",
	   record->uid, record->modseq, record->last_updated, record->internaldate, make_flags(mailbox, record));
}

static void log_mismatch(const char *reason, struct mailbox *mailbox,
			 struct index_record *mp,
			 struct index_record *rp)
{
    syslog(LOG_ERR, "RECORD MISMATCH WITH REPLICA: %s", reason);
    log_record("master", mailbox, mp);
    log_record("replica", mailbox, rp);
}

static int compare_one_record(struct mailbox *mailbox,
			      unsigned long recno,
			      struct index_record *mp,
			      struct index_record *rp,
			      struct dlist *kaction)
{
    int diff = 0;
    int i;
    int r;

    /* if the GUIDs don't match, then treat as two 
     * un-matched records :) */
    if (!message_guid_compare(&mp->guid, &rp->guid)) {
    	if (!(rp->system_flags & FLAG_EXPUNGED))
	    dlist_num(kaction, "COPYBACK", rp->uid);
    	if (!(mp->system_flags & FLAG_EXPUNGED))
	    dlist_num(kaction, "RENUMBER", mp->uid);
	return 0;
    }

    /* UIDs match, GUIDs match: look for differences in 
     * everything else that's part of sync_crc! */

    if (mp->modseq != rp->modseq)
	diff = 1;
    if (mp->last_updated != rp->last_updated)
	diff = 1;
    if (mp->internaldate != rp->internaldate)
	diff = 1;
    if (mp->system_flags != rp->system_flags)
	diff = 1;
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
	if (mp->user_flags[i] != rp->user_flags[i])
	    diff = 1;
    }

    /* if differences we'll have to rewrite to bump the modseq
     * so that regular replication will cause an update */
    if (diff) {
	/* interesting case - expunged locally */
	if (mp->system_flags & FLAG_EXPUNGED) {
	    /* if the remote record is MORE recent, we
	     * probably want to keep it */
	    if (rp->modseq > mp->modseq ||
		rp->last_updated > mp->last_updated)
		return copyback_one_record(mailbox, rp, kaction);
	    /* otherwise fall through - the modseq update
	     * will cause it to expunge */
	}
	/* evil - expunged remotely, NOT locally */
	else if (rp->system_flags & FLAG_EXPUNGED) {
	    /* is the replica "newer"? */
	    if (rp->modseq > mp->modseq ||
		rp->last_updated > mp->last_updated) {
		syslog(LOG_ERR, "recent expunged on replica %s:%lu, expunging locally",
		       mailbox->name, mp->uid);
		mp->system_flags |= FLAG_EXPUNGED;
	    }
	    else {
		/* will have to move the local record */
		return renumber_one_record(mailbox, mp, kaction);
	    }
	}

	/* general case */
	else {
	    /* is the replica "newer"? */
	    if (rp->modseq > mp->modseq ||
		rp->last_updated > mp->last_updated) {
		log_mismatch("more recent on replica", mailbox, mp, rp);
		mp->system_flags = rp->system_flags;
		for (i = 0; i < MAX_USER_FLAGS/32; i++) 
		    mp->user_flags[i] = rp->user_flags[i];
		mp->internaldate = rp->internaldate;
		/* no point copying modseq, it will be updated regardless */
	    }
	    else {
		log_mismatch("more recent on master", mailbox, mp, rp);
	    }
	}

	/* this will bump the modseq and force a resync either way :) */
	r = mailbox_rewrite_index_record(mailbox, mp);
	if (r) return r;
    }

    return 0;
}

static int mailbox_full_update(struct sync_folder *local,
			       struct sync_folder *remote,
			       struct sync_reserve_list *reserve_guids)
{
    const char *cmd = "FULLMAILBOX";
    unsigned long recno;
    unsigned old_num_records;
    struct index_record mrecord, rrecord;
    struct mailbox *mailbox;
    int r;
    struct dlist *kin;
    struct dlist *ki;
    struct dlist *kr;
    struct dlist *ka;
    struct dlist *kuids;
    struct dlist *kl = NULL;
    struct dlist *kaction = NULL;
    struct dlist *kexpunge = NULL;
    modseq_t highestmodseq;
    unsigned long last_uid;
    int mboxopen = 0;

    kl = dlist_atom(NULL, cmd, local->name);
    sync_send_lookup(kl, sync_out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_in, &kin);
    if (r) return r;

    kl = kin->head;

    if (!kl) {
	dlist_free(&kin);
	return IMAP_MAILBOX_NONEXISTENT;
    }

    /* we'll probably be updating it! */
    r = mailbox_open_iwl(local->name, &mailbox);
    if (r) goto done;
    mboxopen = 1;

    /* re-calculate our local CRC just in case it's out of sync */
    r = mailbox_index_recalc(mailbox);
    if (r) goto done;

    old_num_records = mailbox->i.num_records;

    /* XXX - handle the header.  I want to do some ordering on timestamps
     * in particular here - if there's more recent data on the replica then
     * it should be copied back.  This depends on having a nice way to
     * parse the mailbox structure back in to a struct index_header rather
     * than the by hand stuff though, because that sucks.  NOTE - this
     * doesn't really matter too much, because we'll blat the replica's
     * values anyway! */

    if (!dlist_getmodseq(kl, "HIGHESTMODSEQ", &highestmodseq))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    if (!dlist_getnum(kl, "LAST_UID", &last_uid))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    if (!dlist_getlist(kl, "RECORD", &kr))
	return IMAP_PROTOCOL_BAD_PARAMETERS;

    if (mailbox->i.highestmodseq < highestmodseq) {
	/* highestmodseq on replica is dirty - we must go to at least one higher! */
	mailbox->i.highestmodseq = highestmodseq;
	mailbox_modseq_dirty(mailbox);
    }

    /* initialise the two loops */
    kaction = dlist_list(NULL, "ACTION");
    recno = 1;
    ki = kr->head;

    /* while there are more records on either master OR replica,
     * work out what to do with them */
    while (ki || recno <= old_num_records) {
	/* most common case - both a master AND a replica record exist */
	if (ki && recno <= old_num_records) {
	    r = mailbox_read_index_record(mailbox, recno, &mrecord);
	    if (r) goto done;
	    r = parse_upload(ki, mailbox, &rrecord);
	    if (r) goto done;

	    /* same UID - compare the records */
	    if (rrecord.uid == mrecord.uid) {
		/* hasn't been changed already, check it */
		if (mrecord.modseq <= highestmodseq) {
		    r = compare_one_record(mailbox, recno,
					   &mrecord, &rrecord,
					   kaction);
		    if (r) goto done;
		}
		/* increment both */
		recno++;
		ki = ki->next;
	    }
	    else if (rrecord.uid > mrecord.uid) {
		/* record only exists on the master */
		r = renumber_one_record(mailbox, &mrecord, kaction);
		if (r) goto done;
		/* only increment master */
		recno++;
	    }
	    else {
		/* record only exists on the replica */
		r = copyback_one_record(mailbox, &rrecord, kaction);
		if (r) goto done;
		/* only increment replica */
		ki = ki->next;
	    }
	}

	/* no more replica records, but still master records */
	else if (recno <= old_num_records) {
	    r = mailbox_read_index_record(mailbox, recno, &mrecord);
	    if (r) goto done;
	    /* if the replica has seen this UID, we need to renumber.
	     * Otherwise it will replicate fine as-is */
	    if (mrecord.uid <= last_uid) {
		r = renumber_one_record(mailbox, &mrecord, kaction);
		if (r) goto done;
	    }
	    recno++;
	}

	/* record only exists on the replica */
	else {
	    r = parse_upload(ki, mailbox, &rrecord);
	    if (r) goto done;
	    
	    /* going to need this one */
	    r = copyback_one_record(mailbox, &rrecord, kaction);
	    if (r) goto done;

	    ki = ki->next;
	}
    }

    /* if replica still has a higher last_uid, bump our local
     * number to match so future records don't clash */
    if (mailbox->i.last_uid < last_uid)
        mailbox->i.last_uid = last_uid;

    /* blatant reuse 'r' us */
    kexpunge = dlist_new("EXPUNGE");
    dlist_atom(kexpunge, "MBOXNAME", mailbox->name);
    dlist_atom(kexpunge, "UNIQUEID", mailbox->uniqueid); /* just for safety */
    kuids = dlist_list(kexpunge, "UID");
    for (ka = kaction->head; ka; ka = ka->next) {
	if (!strcmp(ka->name, "EXPUNGE")) {
	    dlist_num(kuids, "UID", ka->nval);
	}
	else if (!strcmp(ka->name, "COPYBACK")) {
	    r = copy_remote(mailbox, ka->nval, kr);
	    if (r) goto done;
	    dlist_num(kuids, "UID", ka->nval);
	}
	else if (!strcmp(ka->name, "RENUMBER")) {
	    r = copy_local(mailbox, ka->nval);
	    if (r) goto done;
	}
    }

    /* close the mailbox before sending any expunges to avoid deadlocks */
    r = mailbox_commit(mailbox);
    mailbox_close(&mailbox);
    mboxopen = 0;
    if (r) goto done;

    /* only send expunge if we have some UIDs to expunge */
    if (kuids->head) {
	sync_send_apply(kexpunge, sync_out);
	r = sync_parse_response("EXPUNGE", sync_in, NULL);
    }

done:
    if (mboxopen) mailbox_close(&mailbox);
    dlist_free(&kaction);
    dlist_free(&kexpunge);
    return r;
}

static int is_unchanged(struct mailbox *mailbox, struct sync_folder *remote)
{
    /* look for any mismatches */
    if (!remote) return 0;
    if (remote->last_uid != mailbox->i.last_uid) return 0;
    if (remote->highestmodseq != mailbox->i.highestmodseq) return 0;
    if (remote->sync_crc != mailbox->i.sync_crc) return 0;
    if (remote->recentuid != mailbox->i.recentuid) return 0;
    if (remote->recenttime != mailbox->i.recenttime) return 0;
    if (remote->pop3_last_login != mailbox->i.pop3_last_login) return 0;
    if (remote->options != mailbox->i.options) return 0;
    if (strcmp(remote->acl, mailbox->acl)) return 0;

    /* otherwise it's unchanged! */
    return 1;
}

static int update_mailbox(struct sync_folder *local,
			  struct sync_folder *remote,
			  struct sync_reserve_list *reserve_guids)
{
    struct sync_msgid_list *part_list;
    struct mailbox *mailbox;
    int r = 0;
    struct dlist *kl = dlist_new("MAILBOX");
    struct dlist *kupload = dlist_list(NULL, "MESSAGE");

    r = mailbox_open_irl(local->name, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* been deleted in the meanwhile... */
	r = folder_delete(remote->name);
	goto done;
    }
    else if (r)
	goto done;

    /* definitely bad if these don't match! */
    if (strcmp(mailbox->uniqueid, local->uniqueid) ||
	strcmp(mailbox->part, local->part)) {
	r = IMAP_MAILBOX_MOVED;
	goto done;
    }

    /* nothing changed - nothing to send */
    if (is_unchanged(mailbox, remote))
	goto done;

    part_list = sync_reserve_partlist(reserve_guids, mailbox->part);
    r = sync_mailbox(mailbox, remote, part_list, kl, kupload, 1);
    if (r) goto done;

    /* upload any messages required */
    if (kupload->head) {
	/* keep the mailbox locked for shorter time! Unlock the index now */
	/* but don't close it until after the apply, because we need to
	 * guarantee that message files don't get deleted first */
	mailbox_unlock_index(mailbox, NULL);
	sync_send_apply(kupload, sync_out);
	mailbox_close(&mailbox);
	r = sync_parse_response("MESSAGE", sync_in, NULL);
	if (!r) {
	    /* update our list of reserved messages on the replica */
	    struct dlist *ki;
	    struct sync_msgid *msgid;
	    for (ki = kupload->head; ki; ki = ki->next) {
		msgid = sync_msgid_lookup(part_list, &ki->gval);
		if (!msgid)
		    msgid = sync_msgid_add(part_list, &ki->gval);
		msgid->mark = 1;
		part_list->marked++; 
	    }
	}
    }
    else {
	/* just close the mailbox now, we have all the data */
	mailbox_close(&mailbox);
    }

    /* update the mailbox */
    sync_send_apply(kl, sync_out);
    r = sync_parse_response("MAILBOX", sync_in, NULL);
    if (r == IMAP_MAILBOX_CRC) {
	syslog(LOG_ERR, "CRC failure on sync update for %s", local->name);
	r = mailbox_full_update(local, remote, reserve_guids);
	if (!r) r = update_mailbox(local, remote, reserve_guids);
    }
    return r;

done:
    dlist_free(&kupload);
    dlist_free(&kl);
    mailbox_close(&mailbox);
    return r;
}

/* ====================================================================== */


static int update_seen_work(const char *user, const char *uniqueid,
			    struct seendata *sd)
{
    const char *cmd = "SEEN";
    struct dlist *kl;

    /* Update seen list */
    kl = dlist_new(cmd);
    dlist_atom(kl, "USERID", user);
    dlist_atom(kl, "UNIQUEID", uniqueid);
    dlist_date(kl, "LASTREAD", sd->lastread);
    dlist_num(kl, "LASTUID", sd->lastuid);
    dlist_date(kl, "LASTCHANGE", sd->lastchange);
    dlist_atom(kl, "SEENUIDS", sd->seenuids);
    sync_send_apply(kl, sync_out);
    dlist_free(&kl);

    return sync_parse_response(cmd, sync_in, NULL);
}

static int do_seen(char *user, char *uniqueid)
{
    int r = 0;
    struct seen *seendb;
    struct seendata sd;

    if (verbose) 
        printf("SEEN %s %s\n", user, uniqueid);

    if (verbose_logging)
        syslog(LOG_INFO, "SEEN %s %s", user, uniqueid);

    /* ignore read failures */
    r = seen_open(user, SEEN_SILENT, &seendb);
    if (r) return 0;

    r = seen_read(seendb, uniqueid, &sd);
    if (r) {
	seen_close(seendb);
	return 0;
    }

    r = update_seen_work(user, uniqueid, &sd);

    seen_close(seendb);
    seen_freedata(&sd);

    return r;
}

/* ====================================================================== */

static int do_quota(const char *root)
{
    int r = 0;
    struct quota q;

    if (verbose) 
        printf("SETQUOTA %s\n", root);

    if (verbose_logging)
        syslog(LOG_INFO, "SETQUOTA: %s", root);

    q.root = root;
    r = update_quota_work(&q, NULL);

    return r;
}

static int getannotation_cb(const char *mailbox __attribute__((unused)),
			    const char *entry, const char *userid,
			    struct annotation_data *attrib, void *rock)
{
    struct sync_annot_list *l = (struct sync_annot_list *) rock;

    sync_annot_list_add(l, entry, userid, attrib->value);

    return 0;
}

static int parse_annotation(struct dlist *kin,
			    struct sync_annot_list *replica_annot)
{
    struct dlist *kl;
    const char *entry;
    const char *userid;
    const char *value;

    for (kl = kin->head; kl; kl = kl->next) {
	if (!dlist_getatom(kl, "ENTRY", &entry))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getatom(kl, "USERID", &userid))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	if (!dlist_getatom(kl, "VALUE", &value))
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
	sync_annot_list_add(replica_annot, entry, userid, value);
    }

    return 0;
}

static int do_getannotation(char *mboxname,
			    struct sync_annot_list *replica_annot)
{
    const char *cmd = "ANNOTATION";
    struct dlist *kl;
    struct dlist *kin = NULL;
    int r;

    /* Update seen list */
    kl = dlist_atom(NULL, cmd, mboxname);
    sync_send_lookup(kl, sync_out);
    dlist_free(&kl);

    r = sync_parse_response(cmd, sync_in, &kin);
    if (r) return r;

    r = parse_annotation(kin, replica_annot);
    dlist_free(&kin);

    return r;
}

static int do_annotation(char *mboxname)
{
    int r;
    struct sync_annot_list *replica_annot = sync_annot_list_create();
    struct sync_annot_list *master_annot = sync_annot_list_create();
    struct sync_annot *ma, *ra;
    int n;

    r = do_getannotation(mboxname, replica_annot);
    if (r) goto bail;

    r = annotatemore_findall(mboxname, "*", &getannotation_cb, master_annot, NULL);
    if (r) goto bail;

    /* both lists are sorted, so we work our way through the lists
       top-to-bottom and determine what we need to do based on order */
    ma = master_annot->head;
    ra = replica_annot->head;
    while (ma || ra) {
	if (!ra) n = -1;		/* add all master annotations */
	else if (!ma) n = 1;		/* remove all replica annotations */
	else if ((n = strcmp(ma->entry, ra->entry)) == 0)
	    n = strcmp(ma->userid, ra->userid);

	if (n > 0) {
	    /* remove replica annotation */
	    r = folder_unannotation(mboxname, ra->entry, ra->userid);
	    if (r) goto bail;
	    ra = ra->next;
	    continue;
	}

	if (n == 0) {
	    /* already have the annotation, but is the value different? */
	    if (!strcmp(ra->value, ma->value)) {
		ra = ra->next;
		ma = ma->next;
		continue;
	    }
	    ra = ra->next;
	}

	/* add the current client annotation */
	r = folder_setannotation(mboxname, ma->entry, ma->userid, ma->value);
	if (r) goto bail;

	ma = ma->next;
    }

bail:
    sync_annot_list_free(&master_annot);
    sync_annot_list_free(&replica_annot);
    return r;
}

/* ====================================================================== */

int do_folders(struct sync_name_list *mboxname_list,
	       struct sync_folder_list *replica_folders)
{
    int r;
    struct sync_folder_list *master_folders;
    struct sync_rename_list *rename_folders;
    struct sync_reserve_list *reserve_guids;
    struct sync_folder *mfolder, *rfolder;

    master_folders = sync_folder_list_create();
    rename_folders = sync_rename_list_create();
    reserve_guids = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    r = reserve_messages(mboxname_list, master_folders,
			 replica_folders, reserve_guids);
    if (r) goto bail;

    /* Tag folders on server which still exist on the client. Anything
     * on the server which remains untagged can be deleted immediately */
    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
	rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
	if (!rfolder) continue;
	rfolder->mark = 1;

	/* does it need a rename? */
	if (strcmp(mfolder->name, rfolder->name) || strcmp(mfolder->part, rfolder->part))
	    sync_rename_list_add(rename_folders, mfolder->uniqueid, rfolder->name, 
				 mfolder->name, mfolder->part);
    }

    /* Delete folders on server which no longer exist on client */
    for (rfolder = replica_folders->head; rfolder; rfolder = rfolder->next) {
	if (rfolder->mark) continue;
	r = folder_delete(rfolder->name);
	if (r) goto bail;
    }

    /* Need to rename folders in an order which avoids dependancy conflicts
     * following isn't wildly efficient, but rename_folders will typically be
     * short and contain few dependancies.  Algorithm is to simply pick a
     * rename operation which has no dependancy and repeat until done */

    while (rename_folders->done < rename_folders->count) {
	int rename_success = 0;
	struct sync_rename *item, *item2;

	for (item = rename_folders->head; item; item = item->next) {
	    if (item->done) continue;

	    item2 = sync_rename_lookup(rename_folders, item->newname);
	    if (item2 && !item2->done) continue;

	    /* Found unprocessed item which should rename cleanly */
	    r = folder_rename(item->oldname, item->newname, item->part);
	    if (r) {
		syslog(LOG_ERR, "do_folders(): failed to rename: %s -> %s ",
		       item->oldname, item->newname);
		goto bail;
	    }

	    rename_folders->done++;
	    item->done = 1;
	    rename_success = 1;
	}

	if (!rename_success) {
	    /* Scanned entire list without a match */
	    syslog(LOG_ERR,
		   "do_folders(): failed to order folders correctly");
	    r = IMAP_AGAIN;
	    goto bail;
	}
    }

    for (mfolder = master_folders->head; mfolder; mfolder = mfolder->next) {
	/* NOTE: rfolder->name may now be wrong, but we're guaranteed that
	 * it was successfully renamed above, so just use mfolder->name for
	 * all commands */
	rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
	r = update_mailbox(mfolder, rfolder, reserve_guids);
	if (r) {
	    syslog(LOG_ERR, "do_folders(): update failed: %s '%s'", 
		   mfolder->name, error_message(r));
	    goto bail;
	}
    }

 bail:
    sync_folder_list_free(&master_folders);
    sync_rename_list_free(&rename_folders);
    sync_reserve_list_free(&reserve_guids);
    return r;
}

static int do_mailboxes(struct sync_name_list *mboxname_list)
{
    struct sync_name *mbox;
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct dlist *kl = NULL;
    int r;

    if (verbose) {
	printf("MAILBOXES");
	for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
	    printf(" %s", mbox->name);
	}
	printf("\n");
    }

    if (verbose_logging) {
	for (mbox = mboxname_list->head; mbox; mbox = mbox->next)
	    syslog(LOG_INFO, "MAILBOX %s", mbox->name);
    }

    kl = dlist_list(NULL, "MAILBOXES");
    for (mbox = mboxname_list->head; mbox; mbox = mbox->next)
	dlist_atom(kl, "MBOXNAME", mbox->name);
    sync_send_lookup(kl, sync_out);
    dlist_free(&kl);

    r = response_parse("MAILBOXES", replica_folders, NULL, NULL, NULL, NULL);

    if (!r)
	r = do_folders(mboxname_list, replica_folders);

    sync_folder_list_free(&replica_folders);

    return r;
}

/* ====================================================================== */

struct mboxinfo {
    struct sync_name_list *mboxlist;
    struct sync_name_list *quotalist;
};

static int do_mailbox_info(char *name,
			   int matchlen __attribute__((unused)),
			   int maycreate __attribute__((unused)),
			   void *rock)
{
    int r;
    struct mailbox *mailbox;
    struct mboxinfo *info = (struct mboxinfo *)rock;

    r = mailbox_open_irl(name, &mailbox);
    /* doesn't exist?  Probably not finished creating or removing yet */
    if (r == IMAP_MAILBOX_NONEXISTENT) return 0;
    if (r == IMAP_MAILBOX_RESERVED) return 0;
    if (r) return r;

    if (info->quotalist && mailbox->quotaroot) {
	if (!sync_name_lookup(info->quotalist, mailbox->quotaroot))
	    sync_name_list_add(info->quotalist, mailbox->quotaroot);
    }

    mailbox_close(&mailbox);

    addmbox(name, 0, 0, info->mboxlist);

    return 0;
}

static int do_user_quota(char *user, struct sync_name_list *master_quotaroots,
			 struct sync_quota_list *replica_quota)
{
    int r;
    struct sync_name *mitem;
    struct sync_quota *rquota;
    struct quota q;

    /* set any new or changed quotas */
    for (mitem = master_quotaroots->head; mitem; mitem = mitem->next) {
	rquota = sync_quota_lookup(replica_quota, mitem->name);
	q.root = mitem->name;
	if (rquota)
	    rquota->done = 1;
	r = update_quota_work(&q, rquota);
	if (r) return r;
    }

    /* delete any quotas no longer on the master */
    for (rquota = replica_quota->head; rquota; rquota = rquota->next) {
	if (rquota->done) continue;
	r = delete_quota(rquota->root);
	if (r) return r;
    }

    return 0;
}

int do_user_main(char *user, struct sync_folder_list *replica_folders,
		 struct sync_quota_list *replica_quota)
{
    char buf[MAX_MAILBOX_BUFFER];
    int r = 0;
    struct sync_name_list *mboxname_list = sync_name_list_create();
    struct sync_name_list *master_quotaroots = sync_name_list_create();
    struct mboxinfo info;

    info.mboxlist = mboxname_list;
    info.quotalist = master_quotaroots;

    /* Generate full list of folders on client side */
    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					  user, buf);
    do_mailbox_info(buf, 0, 0, &info);

    strlcat(buf, ".*", sizeof(buf));
    r = (sync_namespace.mboxlist_findall)(&sync_namespace, buf, 1,
					  user, NULL, do_mailbox_info,
					  &info);

    if (r) {
	syslog(LOG_ERR, "IOERROR: %s", error_message(r));
	return(r);
    }

    r = do_folders(mboxname_list, replica_folders);
    if (!r) r = do_user_quota(user, master_quotaroots, replica_quota);

    sync_name_list_free(&mboxname_list);
    sync_name_list_free(&master_quotaroots);

    return r;
}

int do_user_sub(const char *userid, struct sync_name_list *replica_subs)
{
    char buf[MAX_MAILBOX_BUFFER];
    struct sync_name_list *master_subs = sync_name_list_create();
    struct sync_name *msubs, *rsubs;
    int r;

    /* Includes subsiduary nodes automatically */
    r = (sync_namespace.mboxlist_findsub)(&sync_namespace, "*", 1,
                                          userid, NULL, addmbox_sub,
                                          master_subs, 1);
    if (r) {
	syslog(LOG_ERR, "IOERROR: %s", error_message(r));
	goto bail;
    }

    /* add any folders that need adding, and mark any which
     * still exist */
    for (msubs = master_subs->head; msubs; msubs = msubs->next) {
	r = (sync_namespace.mboxname_tointernal)(&sync_namespace, msubs->name,
						 userid, buf);
	if (r) continue;
	rsubs = sync_name_lookup(replica_subs, buf);
	if (rsubs) {
	    rsubs->mark = 1;
	    continue;
	}
	r = set_sub(userid, buf, 1);
	if (r) goto bail;
    }

    /* remove any no-longer-subscribed folders */
    for (rsubs = replica_subs->head; rsubs; rsubs = rsubs->next) {
	if (rsubs->mark)
	    continue;
	r = set_sub(userid, rsubs->name, 0);
	if (r) goto bail;
    }

 bail:
    sync_name_list_free(&master_subs);
    return(r);
}

static int get_seen(const char *uniqueid, struct seendata *sd, void *rock)
{
    struct sync_seen_list *list = (struct sync_seen_list *)rock;

    sync_seen_list_add(list, uniqueid, sd->lastread, sd->lastuid,
		       sd->lastchange, sd->seenuids);

    return 0;
}

static int do_user_seen(char *user, struct sync_seen_list *replica_seen)
{
    int r;
    struct sync_seen *mseen, *rseen;
    struct seen *seendb;
    struct sync_seen_list *list;

    /* silently ignore errors */
    r = seen_open(user, SEEN_SILENT, &seendb);
    if (r) return 0;

    list = sync_seen_list_create();

    seen_foreach(seendb, get_seen, list);
    seen_close(seendb);

    for (mseen = list->head; mseen; mseen = mseen->next) {
	rseen = sync_seen_list_lookup(replica_seen, mseen->uniqueid);
	if (rseen) {
	    rseen->mark = 1;
	    if (seen_compare(&rseen->sd, &mseen->sd))
		continue; /* nothing changed */
	}
	r = update_seen_work(user, mseen->uniqueid, &mseen->sd);
    }

    /* XXX - delete seen on the replica for records that don't exist? */

    sync_seen_list_free(&list);

    return 0;
}

int do_user_sieve(char *userid, struct sync_sieve_list *replica_sieve)
{
    int r = 0;
    struct sync_sieve_list *master_sieve;
    struct sync_sieve *mitem, *ritem;
    int master_active = 0;
    int replica_active = 0;

    master_sieve = sync_sieve_list_generate(userid);
    if (!master_sieve) {
        syslog(LOG_ERR, "Unable to list sieve scripts for %s", userid);
        return IMAP_IOERROR;
    }

    /* Upload missing and out of date scripts */
    for (mitem = master_sieve->head; mitem; mitem = mitem->next) {
        ritem = sync_sieve_lookup(replica_sieve, mitem->name);
	if (ritem) {
	    ritem->mark = 1;
	    if (ritem->last_update >= mitem->last_update)
		continue; /* doesn't need updating */
	}
	r = sieve_upload(userid, mitem->name, mitem->last_update);
	if (r) goto bail;
    }

    /* Delete scripts which no longer exist on the master */
    replica_active = 0;
    for (ritem = replica_sieve->head; ritem; ritem = ritem->next) {
	if (ritem->mark) {
	    if (ritem->active)
		replica_active = 1;
	} else {
	    r = sieve_delete(userid, ritem->name);
	    if (r) goto bail;
	}
    }

    /* Change active script if necessary */
    master_active = 0;
    for (mitem = master_sieve->head; mitem; mitem = mitem->next) {
	if (!mitem->active)
	    continue;

	master_active = 1;
	ritem = sync_sieve_lookup(replica_sieve, mitem->name);
	if (ritem && ritem->active)
	    break;

	r = sieve_activate(userid, mitem->name);
	if (r) goto bail;

	replica_active = 1;
	break;
    }

    if (!master_active && replica_active)
	r = sieve_deactivate(userid);

 bail:
    sync_sieve_list_free(&master_sieve);
    return(r);
}

int do_user(char *userid)
{
    char buf[MAX_MAILBOX_BUFFER];
    int r = 0;
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct sync_name_list *replica_subs = sync_name_list_create();
    struct sync_sieve_list *replica_sieve = sync_sieve_list_create();
    struct sync_seen_list *replica_seen = sync_seen_list_create();
    struct sync_quota_list *replica_quota = sync_quota_list_create();
    struct dlist *kl = NULL;
    struct mailbox *mailbox;

    if (verbose) 
        printf("USER %s\n", userid);

    if (verbose_logging)
        syslog(LOG_INFO, "USER %s", userid);

    kl = dlist_atom(NULL, "USER", userid);
    sync_send_lookup(kl, sync_out);
    dlist_free(&kl);

    r = response_parse("USER",
		       replica_folders, replica_subs,
		       replica_sieve, replica_seen, replica_quota);
    /* can happen! */
    if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    if (r) goto done;

    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					  userid, buf);
    r = mailbox_open_irl(buf, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* user has been removed, RESET server */
	syslog(LOG_ERR, "Inbox missing on master for %s", userid);
	r = user_reset(userid);
	goto done;
    }
    if (r) goto done;

    /* we don't hold locks while sending commands */
    mailbox_close(&mailbox);
    r = do_user_main(userid, replica_folders, replica_quota);
    if (r) goto done;
    r = do_user_sub(userid, replica_subs);
    if (r) goto done;
    r = do_user_sieve(userid, replica_sieve);
    if (r) goto done;
    r = do_user_seen(userid, replica_seen);

done:
    sync_folder_list_free(&replica_folders);
    sync_name_list_free(&replica_subs);
    sync_sieve_list_free(&replica_sieve);
    sync_seen_list_free(&replica_seen);
    sync_quota_list_free(&replica_quota);

    return r;
}

/* ====================================================================== */

static int do_meta(char *userid)
{
    struct sync_name_list *replica_subs = sync_name_list_create();
    struct sync_sieve_list *replica_sieve = sync_sieve_list_create();
    struct sync_seen_list *replica_seen = sync_seen_list_create();
    struct dlist *kl = NULL;
    int r = 0;

    if (verbose)
	printf("META %s\n", userid);

    if (verbose_logging)
	syslog(LOG_INFO, "META %s", userid);

    kl = dlist_atom(NULL, "META", userid);
    sync_send_lookup(kl, sync_out);
    dlist_free(&kl);

    r = response_parse("META", NULL, replica_subs, replica_sieve, replica_seen, NULL);
    if (!r) r = do_user_seen(userid, replica_seen);
    if (!r) r = do_user_sub(userid, replica_subs);
    if (!r) r = do_user_sieve(userid, replica_sieve);
    sync_seen_list_free(&replica_seen);
    sync_name_list_free(&replica_subs);
    sync_sieve_list_free(&replica_sieve);

    return r;
}

/* ====================================================================== */

static void remove_meta(char *user, struct sync_action_list *list)
{
    struct sync_action *action;

    for (action = list->head ; action ; action = action->next) {
	if (!strcmp(user, action->user)) {
	    action->active = 0;
	}
    }
}

static void remove_folder(char *name, struct sync_action_list *list,
			  int chk_child)
{
    struct sync_action *action;
    size_t len = strlen(name);

    for (action = list->head ; action ; action = action->next) {
	if (!strncmp(name, action->name, len) &&
	    ((action->name[len] == '\0') ||
	     (chk_child && (action->name[len] == '.')))) {
            action->active = 0;
        }
    }
}

/* ====================================================================== */

static int do_sync(const char *filename)
{
    struct sync_action_list *user_list = sync_action_list_create();
    struct sync_action_list *meta_list = sync_action_list_create();
    struct sync_action_list *mailbox_list = sync_action_list_create();
    struct sync_action_list *quota_list = sync_action_list_create();
    struct sync_action_list *annot_list = sync_action_list_create();
    struct sync_action_list *seen_list = sync_action_list_create();
    struct sync_action_list *sub_list = sync_action_list_create();
    struct sync_name_list *mboxname_list = sync_name_list_create();
    static struct buf type, arg1, arg2;
    char *arg1s, *arg2s;
    struct sync_action *action;
    int c;
    int fd = -1;
    int doclose = 0;
    struct protstream *input;
    int r = 0;

    if ((filename == NULL) || !strcmp(filename, "-"))
	fd = 0; /* STDIN */
    else {
	fd = open(filename, O_RDWR);
	if (fd < 0) {
	    syslog(LOG_ERR, "Failed to open %s: %m", filename);
	    r = IMAP_IOERROR;
	    goto cleanup;
	}

	doclose = 1;

	if (lock_blocking(fd) < 0) {
	    syslog(LOG_ERR, "Failed to lock %s: %m", filename);
	    r = IMAP_IOERROR;
	    goto cleanup;
	}
    }

    input = prot_new(fd, 0);

    while (1) {
	if ((c = getword(input, &type)) == EOF)
	    break;

	/* Ignore blank lines */
	if (c == '\r') c = prot_getc(input);
	if (c == '\n')
	    continue;

	if (c != ' ') {
	    syslog(LOG_ERR, "Invalid input");
	    eatline(input, c);
	    continue;
	}

	if ((c = getastring(input, 0, &arg1)) == EOF) break;
	arg1s = arg1.s;

	if (c == ' ') {
	    if ((c = getastring(input, 0, &arg2)) == EOF) break;
	    arg2s = arg2.s;

	} else 
	    arg2s = NULL;
	
	if (c == '\r') c = prot_getc(input);
	if (c != '\n') {
	    syslog(LOG_ERR, "Garbage at end of input line");
	    eatline(input, c);
	    continue;
	}

	ucase(type.s);

	if (!strcmp(type.s, "USER"))
	    sync_action_list_add(user_list, NULL, arg1s);
	else if (!strcmp(type.s, "META"))
	    sync_action_list_add(meta_list, NULL, arg1s);
	else if (!strcmp(type.s, "SIEVE"))
	    sync_action_list_add(meta_list, NULL, arg1s);
	else if (!strcmp(type.s, "MAILBOX"))
	    sync_action_list_add(mailbox_list, arg1s, NULL);
	else if (!strcmp(type.s, "QUOTA"))
	    sync_action_list_add(quota_list, arg1s, NULL);
	else if (!strcmp(type.s, "ANNOTATION"))
	    sync_action_list_add(annot_list, arg1s, NULL);
	else if (!strcmp(type.s, "SEEN"))
	    sync_action_list_add(seen_list, arg2s, arg1s);
	else if (!strcmp(type.s, "SUB"))
	    sync_action_list_add(sub_list, arg2s, arg1s);
	else if (!strcmp(type.s, "UNSUB"))
	    sync_action_list_add(sub_list, arg2s, arg1s);
	else
	    syslog(LOG_ERR, "Unknown action type: %s", type.s);
    }

    prot_free(input);
    if (doclose) {
	close(fd);
	doclose = 0;
    }

    /* Optimise out redundant clauses */

    for (action = user_list->head; action; action = action->next) {
	char inboxname[MAX_MAILBOX_BUFFER];
	char deletedname[MAX_MAILBOX_BUFFER];

	/* USER action overrides any MAILBOX action on any of the 
	 * user's mailboxes or any META, SEEN or SUB/UNSUB
	 * action for same user */
	(sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					      action->user, inboxname);
	remove_folder(inboxname, mailbox_list, 1);

	/* remove deleted namespace items as well */
	if (mboxlist_delayed_delete_isenabled()) {
	    mboxname_todeleted(inboxname, deletedname, 0);
	    remove_folder(deletedname, mailbox_list, 1);
	}

	/* remove per-user items */
	remove_meta(action->user, meta_list);
	remove_meta(action->user, seen_list);
	remove_meta(action->user, sub_list);
    }
    
    for (action = meta_list->head; action; action = action->next) {
	/* META action overrides any user SEEN or SUB/UNSUB action
	   for same user */
	remove_meta(action->user, seen_list);
	remove_meta(action->user, sub_list);
    }

    /* And then run tasks. */
    for (action = quota_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	if (do_quota(action->name)) {
	    /* XXX - bogus handling, should be user */
	    sync_action_list_add(mailbox_list, action->name, NULL);
	    if (verbose) {
		printf("  Promoting: QUOTA %s -> MAILBOX %s\n",
		       action->name, action->name);
	    }
	    if (verbose_logging) {
		syslog(LOG_INFO, "  Promoting: QUOTA %s -> MAILBOX %s",
		       action->name, action->name);
	    }
	}
    }

    for (action = annot_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	/* NOTE: ANNOTATION "" is a special case - it's a server
	 * annotation, hence the check for a character at the
	 * start of the name */
	if (do_annotation(action->name) && *action->name) {
	    /* XXX - bogus handling, should be ... er, something */
	    sync_action_list_add(mailbox_list, action->name, NULL);
	    if (verbose) {
		printf("  Promoting: ANNOTATION %s -> MAILBOX %s\n",
		       action->name, action->name);
	    }
	    if (verbose_logging) {
		syslog(LOG_INFO, "  Promoting: ANNOTATION %s -> MAILBOX %s",
		       action->name, action->name);
	    }
	}
    }

    for (action = seen_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

        if (do_seen(action->user, action->name)) {
	    char *userid = mboxname_isusermailbox(action->name, 1);
	    if (userid && !strcmp(userid, action->user)) {
		sync_action_list_add(user_list, NULL, action->user);
		if (verbose) {
		    printf("  Promoting: SEEN %s %s -> USER %s\n",
			   action->user, action->name, action->user);
		}
		if (verbose_logging) {
		    syslog(LOG_INFO, "  Promoting: SEEN %s %s -> USER %s",
			   action->user, action->name, action->user);
		}
	    } else {
		sync_action_list_add(meta_list, NULL, action->user);
		if (verbose) {
		    printf("  Promoting: SEEN %s %s -> META %s\n",
			   action->user, action->name, action->user);
		}
		if (verbose_logging) {
		    syslog(LOG_INFO, "  Promoting: SEEN %s %s -> META %s",
			   action->user, action->name, action->user);
		}
	    }
	}
    }

    for (action = sub_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

        if (user_sub(action->user, action->name)) {
            sync_action_list_add(meta_list, NULL, action->user);
            if (verbose) {
                printf("  Promoting: SUB %s %s -> META %s\n",
                       action->user, action->name, action->user);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: SUB %s %s -> META %s",
                       action->user, action->name, action->name);
            }
        }
    }

    for (action = mailbox_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	sync_name_list_add(mboxname_list, action->name);
    }

    if (mboxname_list->count) {
	int nonuser = 0;
	r = do_mailboxes(mboxname_list);
	if (r) {
	    /* promote failed personal mailboxes to USER */
	    struct sync_name *mbox;
	    char *userid, *p, *useridp;

	    for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
		/* done OK?  Good :) */
		if (mbox->mark)
		    continue;

		useridp = mboxname_isusermailbox(mbox->name, 0);
		if (useridp) {
		    userid = xstrdup(useridp);
		    if ((p = strchr(userid, '.'))) *p = '\0';
		    mbox->mark = 1;

		    sync_action_list_add(user_list, NULL, userid);
		    if (verbose) {
			printf("  Promoting: MAILBOX %s -> USER %s\n",
			       mbox->name, userid);
		    }
		    if (verbose_logging) {
			syslog(LOG_INFO, "  Promoting: MAILBOX %s -> USER %s",
			       mbox->name, userid);
		    }
		    free(userid);
		}
		else
		    nonuser = 1;
	    }
	}

	if (r && nonuser) goto cleanup;
    }

    for (action = meta_list->head; action; action = action->next) {
	if (!action->active)
	    continue;

	r = do_meta(action->user);
	if (r) {
	    if (r == IMAP_INVALID_USER) goto cleanup;

	    sync_action_list_add(user_list, NULL, action->user);
	    if (verbose) {
		printf("  Promoting: META %s -> USER %s\n",
		       action->user, action->user);
	    }
	    if (verbose_logging) {
		syslog(LOG_INFO, "  Promoting: META %s -> USER %s",
		       action->user, action->user);
	    }
	}
    }

    for (action = user_list->head; action; action = action->next) {
	r = do_user(action->user);
	if (r) goto cleanup;
    }

  cleanup:
    if (doclose) close(fd);

    if (r) {
	if (verbose)
	    fprintf(stderr, "Error in do_sync(): bailing out! %s\n", error_message(r));

	syslog(LOG_ERR, "Error in do_sync(): bailing out! %s", error_message(r));
    }

    sync_action_list_free(&user_list);
    sync_action_list_free(&meta_list);
    sync_action_list_free(&mailbox_list);
    sync_action_list_free(&quota_list);
    sync_action_list_free(&annot_list);
    sync_action_list_free(&seen_list);
    sync_action_list_free(&sub_list);
    sync_name_list_free(&mboxname_list);

    return r;
}

/* ====================================================================== */

enum {
    RESTART_NONE = 0,
    RESTART_NORMAL,
    RESTART_RECONNECT
};

int do_daemon_work(const char *sync_log_file, const char *sync_shutdown_file,
		   unsigned long timeout, unsigned long min_delta,
		   int *restartp)
{
    int r = 0;
    char *work_file_name;
    time_t session_start;
    time_t single_start;
    int    delta;
    struct stat sbuf;

    *restartp = RESTART_NONE;

    /* Create a work log filename.  Use the parent PID so we can
     * try to reprocess it if the child fails.
     */
    work_file_name = xmalloc(strlen(sync_log_file)+20);
    snprintf(work_file_name, strlen(sync_log_file)+20,
             "%s-%d", sync_log_file, getppid());

    session_start = time(NULL);

    while (1) {
        single_start = time(NULL);

        signals_poll();

	/* Check for shutdown file */
        if (sync_shutdown_file && !stat(sync_shutdown_file, &sbuf)) {
            unlink(sync_shutdown_file);
            break;
        }

	/* See if its time to RESTART */
        if ((timeout > 0) &&
	    ((single_start - session_start) > (time_t) timeout)) {
            *restartp = RESTART_NORMAL;
            break;
        }

        if ((stat(work_file_name, &sbuf) == 0) &&
	    (sbuf.st_mtime - single_start < 3600)) {
	    /* Existing work log file from our parent < 1 hour old */
	    /* XXX  Is 60 minutes a resonable timeframe? */
	    syslog(LOG_NOTICE,
		   "Reprocessing sync log file %s", work_file_name);
	}
	else {
	    /* Check for sync_log file */
	    if (stat(sync_log_file, &sbuf) < 0) {
		if (min_delta > 0) {
		    sleep(min_delta);
		} else {
		    usleep(100000);    /* 1/10th second */
		}
		continue;
	    }

	    /* Move sync_log to our work file */
	    if (rename(sync_log_file, work_file_name) < 0) {
		syslog(LOG_ERR, "Rename %s -> %s failed: %m",
		       sync_log_file, work_file_name);
		r = IMAP_IOERROR;
		break;
	    }
	}

	/* Process the work log */
        if ((r=do_sync(work_file_name))) {
	    syslog(LOG_ERR,
		   "Processing sync log file %s failed: %s",
		   work_file_name, error_message(r));
	    break;
	}

	/* Remove the work log */
        if (unlink(work_file_name) < 0) {
            syslog(LOG_ERR, "Unlink %s failed: %m", work_file_name);
	    r = IMAP_IOERROR;
	    break;
        }
        delta = time(NULL) - single_start;

        if (((unsigned) delta < min_delta) && ((min_delta-delta) > 0))
            sleep(min_delta-delta);
    }
    free(work_file_name);

    if (*restartp == RESTART_NORMAL) {
	prot_printf(sync_out, "RESTART\r\n"); 
	prot_flush(sync_out);

	r = sync_parse_response("RESTART", sync_in, NULL);

	if (r) {
	    syslog(LOG_ERR, "sync_client RESTART failed: %s",
		   error_message(r));
	} else {
	    syslog(LOG_INFO, "sync_client RESTART succeeded");
	}
	r = 0;
    }

    return(r);
}

struct backend *replica_connect(struct backend *be, const char *servername,
				sasl_callback_t *cb)
{
    int wait;
    struct protoent *proto;

    /* get the right port */
    csync_protocol.service = config_getstring(IMAPOPT_SYNC_PORT);

    for (wait = 15;; wait *= 2) {
	be = backend_connect(be, servername, &csync_protocol,
			     "", cb, NULL);

	if (be || connect_once || wait > 1000) break;

	fprintf(stderr,
		"Can not connect to server '%s', retrying in %d seconds\n",
		servername, wait);
	sleep(wait);
    }

    if (!be) {
	fprintf(stderr, "Can not connect to server '%s'\n",
		servername);
	syslog(LOG_ERR, "Can not connect to server '%s'", servername);
	_exit(1);
    }

    /* Disable Nagle's Algorithm => increase throughput
     *
     * http://en.wikipedia.org/wiki/Nagle's_algorithm
     */ 
    if (servername[0] != '/') {
	if (be->sock >= 0 && (proto = getprotobyname("tcp")) != NULL) {
	    int on = 1;

	    if (setsockopt(be->sock, proto->p_proto, TCP_NODELAY,
			   (void *) &on, sizeof(on)) != 0) {
		syslog(LOG_ERR, "unable to setsocketopt(TCP_NODELAY): %m");
	    }

            /* turn on TCP keepalive if set */
            if (config_getswitch(IMAPOPT_TCP_KEEPALIVE)) {
		int r;
                int optval = 1;
                socklen_t optlen = sizeof(optval);

                r = setsockopt(be->sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
                if (r < 0) {
                    syslog(LOG_ERR, "unable to setsocketopt(SO_KEEPALIVE): %m");
                }
#ifdef TCP_KEEPCNT
                if (config_getint(IMAPOPT_TCP_KEEPALIVE_CNT)) {
                    r = setsockopt(be->sock, SOL_TCP, TCP_KEEPCNT, &optval, optlen);
                    if (r < 0) {
                        syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPCNT): %m");
                    }
                }
#endif
#ifdef TCP_KEEPIDLE
                if (config_getint(IMAPOPT_TCP_KEEPALIVE_IDLE)) {
                    r = setsockopt(be->sock, SOL_TCP, TCP_KEEPIDLE, &optval, optlen);
                    if (r < 0) {
                        syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPIDLE): %m");
                    }
                }
#endif
#ifdef TCP_KEEPINTVL
                if (config_getint(IMAPOPT_TCP_KEEPALIVE_INTVL)) {
                    r = setsockopt(be->sock, SOL_TCP, TCP_KEEPINTVL, &optval, optlen);
                    if (r < 0) {
                        syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPINTVL): %m");
                    }
                }
#endif
	    }
	} else {
	    syslog(LOG_ERR, "unable to getprotobyname(\"tcp\"): %m");
	}
    }

#ifdef HAVE_ZLIB
    /* check if we should compress */
    if (do_compress || config_getswitch(IMAPOPT_SYNC_COMPRESS)) {
        prot_printf(be->out, "COMPRESS DEFLATE\r\n");
        prot_flush(be->out);

        if (sync_parse_response("COMPRESS", be->in, NULL)) {
	    syslog(LOG_ERR, "Failed to enable compression, continuing uncompressed");
	}
	else {
	    prot_setcompress(be->in);
	    prot_setcompress(be->out);
        }
    }
#endif

    return be;
}

void do_daemon(const char *sync_log_file, const char *sync_shutdown_file,
	       unsigned long timeout, unsigned long min_delta,
	       struct backend *be, sasl_callback_t *cb)
{
    int r = 0;
    pid_t pid;
    int status;
    int restart;

    if (!foreground) {
	/* fork a child so we can release from master */
	if ((pid=fork()) < 0) fatal("fork failed", EC_SOFTWARE);

	if (pid != 0) { /* parent */
	    cyrus_done();
	    exit(0);
	}
	/* child */
    }

    if (foreground || timeout == 0) {
        do_daemon_work(sync_log_file, sync_shutdown_file,
                       timeout, min_delta, &restart);
        return;
    }

    signal(SIGPIPE, SIG_IGN); /* don't fail on server disconnects */

    do {
	/* fork a child so we can RESTART (flush memory) */
        if ((pid=fork()) < 0) fatal("fork failed", EC_SOFTWARE);

        if (pid == 0) { /* child */

	    if (be->sock == -1) {
		/* Reopen up connection to server */
		be = replica_connect(be, servername, cb);

		if (!be) {
		    fprintf(stderr, "Can not connect to server '%s'\n",
			    be->hostname);
		    syslog(LOG_ERR, "Can not connect to server '%s'",
			   be->hostname);
		    _exit(1);
		}

		sync_in = be->in;
		sync_out = be->out;
	    }

            r = do_daemon_work(sync_log_file, sync_shutdown_file,
                               timeout, min_delta, &restart);

            if (r) {
		/* See if we're still connected to the server.
		 * If we are, we had some type of error, so we exit.
		 * Otherwise, try reconnecting.
		 */
		if (!backend_ping(be)) _exit(1);

		syslog(LOG_WARNING, "Lost connection to server. Reconnecting");
		restart = 1;
	    }

            if (restart) _exit(EX_TEMPFAIL);
            _exit(0);
        }

	/* parent */
        if (waitpid(pid, &status, 0) < 0) fatal("waitpid failed", EC_SOFTWARE);

	backend_disconnect(be);
    } while (WIFEXITED(status) && (WEXITSTATUS(status) == EX_TEMPFAIL));

    if (WIFEXITED(status)) {
	syslog(LOG_ERR, "process %d exited, status %d\n", pid, 
	       WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
	syslog(LOG_ERR, 
	       "process %d exited, signaled to death by %d\n",
	       pid, WTERMSIG(status));
    }
}

/* ====================================================================== */

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_CANON_USER, &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

enum {
    MODE_UNKNOWN = -1,
    MODE_REPEAT,
    MODE_USER,
    MODE_MAILBOX,
    MODE_META
};

int main(int argc, char **argv)
{
    int   opt, i = 0;
    char *alt_config     = NULL;
    char *input_filename = NULL;
    int   r = 0;
    int   exit_rc = 0;
    int   mode = MODE_UNKNOWN;
    int   wait     = 0;
    int   timeout  = 600;
    int   min_delta = 0;
    char sync_log_file[MAX_MAILBOX_PATH+1];
    char *sync_log_name = NULL;
    const char *sync_shutdown_file = NULL;
    char buf[512];
    FILE *file;
    int len;
    struct backend *be = NULL;
    sasl_callback_t *cb;
    int config_virtdomains;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vlS:F:f:w:t:d:n:rRumsoz")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'o': /* only try to connect once */
            connect_once = 1;
            break;

        case 'v': /* verbose */
            verbose++;
            break;

        case 'l': /* verbose Logging */
            verbose_logging++;
            break;

	case 'S': /* Socket descriptor for server */
	    servername = optarg;
	    break;

        case 'F': /* Shutdown file */
            sync_shutdown_file = optarg;
            break;

        case 'f': /* input_filename used by user and mailbox modes; OR
		     alternate sync_log_file used by single-run repeat mode */
            input_filename = optarg;
            break;

        case 'n':
	    sync_log_name = optarg;
	    break;

        case 'w':
            wait = atoi(optarg);
            break;

        case 't':
            timeout = atoi(optarg);
            break;

        case 'd':
            min_delta = atoi(optarg);
            break;

        case 'R':
	    foreground = 1;
        case 'r':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_REPEAT;
            break;

        case 'u':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_USER;
            break;

        case 'm':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_MAILBOX;
            break;

        case 's':
	    if (mode != MODE_UNKNOWN)
		fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_META;
            break;

	case 'z':
#ifdef HAVE_ZLIB
	    do_compress = 1;
#else
	    fatal("Compress not available without zlib compiled in", EC_SOFTWARE);
#endif
	    break;

        default:
            usage("sync_client");
        }
    }

    if (mode == MODE_UNKNOWN)
        fatal("No replication mode specified", EC_USAGE);

    cyrus_init(alt_config, "sync_client", 0);

    if (!servername &&
	!(servername = config_getstring(IMAPOPT_SYNC_HOST))) {
        fatal("sync_host not defined", EC_SOFTWARE);
    }

    /* Just to help with debugging, so we have time to attach debugger */
    if (wait > 0) {
        fprintf(stderr, "Waiting for %d seconds for gdb attach...\n", wait);
        sleep(wait);
    }

    /* Set namespace -- force standard (internal) */
    config_virtdomains = config_getenum(IMAPOPT_VIRTDOMAINS);
    if ((r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for real work */
    quotadb_init(0);
    quotadb_open(NULL);

    /* open the annotation db */
    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    /* load the SASL plugins */
    global_sasl_init(1, 0, mysasl_cb);

    cb = mysasl_callbacks(NULL,
			  config_getstring(IMAPOPT_SYNC_AUTHNAME),
			  config_getstring(IMAPOPT_SYNC_REALM),
			  config_getstring(IMAPOPT_SYNC_PASSWORD));

    /* Open up connection to server */
    be = replica_connect(NULL, servername, cb);

    if (!be) {
        fprintf(stderr, "Can not connect to server '%s'\n", servername);
        exit(1);
    }

    sync_in = be->in;
    sync_out = be->out;

    switch (mode) {
    case MODE_USER:
	if (input_filename) {
	    if ((file=fopen(input_filename, "r")) == NULL) {
		syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
		shut_down(1);
	    }
	    while (fgets(buf, sizeof(buf), file)) {
		/* Chomp, then ignore empty/comment lines. */
		if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
		    buf[--len] = '\0';

		if ((len == 0) || (buf[0] == '#'))
		    continue;

		mboxname_hiersep_tointernal(&sync_namespace, buf,
					    config_virtdomains ?
					    strcspn(buf, "@") : 0);
		if (do_user(buf)) {
		    if (verbose)
			fprintf(stderr,
				"Error from do_user(%s): bailing out!\n",
				buf);
		    syslog(LOG_ERR, "Error in do_user(%s): bailing out!",
			   buf);
		    exit_rc = 1;
		}
	    }
	    fclose(file);
	} else for (i = optind; !r && i < argc; i++) {
	    mboxname_hiersep_tointernal(&sync_namespace, argv[i],
					config_virtdomains ?
					strcspn(argv[i], "@") : 0);
	    if (do_user(argv[i])) {
		if (verbose)
		    fprintf(stderr, "Error from do_user(%s): bailing out!\n",
			    argv[i]);
		syslog(LOG_ERR, "Error in do_user(%s): bailing out!", argv[i]);
		exit_rc = 1;
	    }
	}
	break;

    case MODE_MAILBOX:
    {
	struct sync_name_list *mboxname_list = sync_name_list_create();
	char mailboxname[MAX_MAILBOX_BUFFER];

	if (input_filename) {
	    if ((file=fopen(input_filename, "r")) == NULL) {
		syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
		shut_down(1);
	    }
	    while (fgets(buf, sizeof(buf), file)) {
		/* Chomp, then ignore empty/comment lines. */
		if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
		    buf[--len] = '\0';

		if ((len == 0) || (buf[0] == '#'))
		    continue;

		(*sync_namespace.mboxname_tointernal)(&sync_namespace, buf,
						      NULL, mailboxname);
		if (!sync_name_lookup(mboxname_list, mailboxname))
		    sync_name_list_add(mboxname_list, mailboxname);
	    }
	    fclose(file);
	} else for (i = optind; i < argc; i++) {
	    (*sync_namespace.mboxname_tointernal)(&sync_namespace, argv[i],
						   NULL, mailboxname);
	    if (!sync_name_lookup(mboxname_list, mailboxname))
		sync_name_list_add(mboxname_list, mailboxname);
	}

	if (do_mailboxes(mboxname_list)) {
	    if (verbose) {
		fprintf(stderr,
			"Error from do_mailboxes(): bailing out!\n");
	    }
	    syslog(LOG_ERR, "Error in do_mailboxes(): bailing out!");
	    exit_rc = 1;
	}

	sync_name_list_free(&mboxname_list);
    }
    break;

    case MODE_META:
        for (i = optind; i < argc; i++) {
	    mboxname_hiersep_tointernal(&sync_namespace, argv[i],
					config_virtdomains ?
					strcspn(argv[i], "@") : 0);
	    if (do_meta(argv[i])) {
		if (verbose) {
		    fprintf(stderr,
			    "Error from do_meta(%s): bailing out!\n",
			    argv[i]);
		}
		syslog(LOG_ERR, "Error in do_meta(%s): bailing out!",
		       argv[i]);
		exit_rc = 1;
	    }
        }
	break;

    case MODE_REPEAT:
	if (input_filename) {
	    exit_rc = do_sync(input_filename);
	}
	else {
	    if (sync_log_name) {
		strlcpy(sync_log_file, config_dir, sizeof(sync_log_file));
		strlcat(sync_log_file, "/sync/", sizeof(sync_log_file));
		strlcat(sync_log_file, sync_log_name, sizeof(sync_log_file));
		strlcat(sync_log_file, "/log", sizeof(sync_log_file));
	    } else {
		strlcpy(sync_log_file, config_dir, sizeof(sync_log_file));
		strlcat(sync_log_file, "/sync/log", sizeof(sync_log_file));
	    }

	    if (!sync_shutdown_file)
		sync_shutdown_file = config_getstring(IMAPOPT_SYNC_SHUTDOWN_FILE);

	    if (!min_delta)
		min_delta = config_getint(IMAPOPT_SYNC_REPEAT_INTERVAL);

	    do_daemon(sync_log_file, sync_shutdown_file, timeout, min_delta,
		      be, cb);
	}
	break;

    default:
	if (verbose) fprintf(stderr, "Nothing to do!\n");
	break;
    }

    backend_disconnect(be);

    shut_down(exit_rc);
}
