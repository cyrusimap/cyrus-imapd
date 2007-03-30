/* sync_client.c -- Cyrus synchonization client
 *
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 *
 * $Id: sync_client.c,v 1.8 2007/03/30 18:40:20 murch Exp $
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

#include "global.h"
#include "assert.h"
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
#include "sync_support.h"
#include "sync_commit.h"
#include "lock.h"
#include "backend.h"

/* signal to config.c */
const int config_need_data = 0;  /* YYY */

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

/* ====================================================================== */

/* Static global variables and support routines for sync_client */

extern char *optarg;
extern int optind;

static struct protstream *toserver   = NULL;
static struct protstream *fromserver = NULL;

/* List/Hash of messageIDs that are available on server */
static struct sync_msgid_list *msgid_onserver = NULL;

static struct namespace   sync_namespace;
static struct auth_state *sync_authstate = NULL;

static int verbose         = 0;
static int verbose_logging = 0;
static int connect_once    = 0;

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
    fprintf(stderr, "sync_client: %s\n", s);
    exit(code);
}

/* ====================================================================== */

static int send_lock()
{
    prot_printf(toserver, "LOCK\r\n"); 
    prot_flush(toserver);

    return(sync_parse_code("LOCK", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int send_unlock()
{
    int r = 0;
    int c = ' ';
    static struct buf token;   /* BSS */

    prot_printf(toserver, "UNLOCK\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("UNLOCK", fromserver, SYNC_PARSE_NOEAT_OKLINE, NULL);
    if (r) return(r);

    if ((c = getword(fromserver, &token)) != ' ') {
        eatline(fromserver, c);
        syslog(LOG_ERR, "Garbage on Unlock response");
        return(IMAP_PROTOCOL_ERROR);
    }
    eatline(fromserver, c);

    /* Clear out msgid_on_server list if server restarted */
    if (!strcmp(token.s, "[RESTART]")) {
        int hash_size = msgid_onserver->hash_size;

        sync_msgid_list_free(&msgid_onserver);
        msgid_onserver = sync_msgid_list_create(hash_size);

	syslog(LOG_INFO, "UNLOCK: received RESTART");
    }

    return(0);
}

/* ====================================================================== */

/* Routines relevant to reserve operation */

/* Find the messages that we will want to upload from this mailbox,
 * flag messages that are already available at the server end */

static int find_reserve_messages(struct mailbox *mailbox,
				 struct sync_msg_list   *msg_list,
				 struct sync_msgid_list *server_msgid_list,
				 struct sync_msgid_list *reserve_msgid_list)
{
    struct sync_msg *msg;
    struct index_record record;
    unsigned long msgno;
    int r;

    if (mailbox->exists == 0)
        return(0);

    msg = msg_list->head;
    for (msgno = 1 ; msgno <= mailbox->exists ; msgno++) {
        r = mailbox_read_index_record(mailbox, msgno, &record);

        if (r) {
            syslog(LOG_ERR,
                   "IOERROR: reading index entry for nsgno %lu of %s: %m",
                   record.uid, mailbox->name);
            return(IMAP_IOERROR);
        }

        if (msg && ((msg->uid < record.uid) ||
                    ((msg->uid == record.uid) &&
                     message_uuid_compare(&msg->uuid, &record.uuid)))) {
            msg = msg->next;
            continue;
        }

        /* Want to upload this message; does the server have a copy? */
        if (sync_msgid_lookup(server_msgid_list, &record.uuid))
            sync_msgid_add(reserve_msgid_list, &record.uuid);
    }
    
    return(0);
}

static int reserve_all_messages(struct mailbox *mailbox,
				struct sync_msgid_list *server_msgid_list,
				struct sync_msgid_list *reserve_msgid_list)
{
    struct index_record record;
    unsigned long msgno;
    int r;

    if (mailbox->exists == 0)
        return(0);

    for (msgno = 1 ; msgno <= mailbox->exists ; msgno++) {
        r = mailbox_read_index_record(mailbox, msgno, &record);

        if (r) {
            syslog(LOG_ERR,
                   "IOERROR: reading index entry for nsgno %lu of %s: %m",
                   record.uid, mailbox->name);
            return(IMAP_IOERROR);
        }

        /* Want to upload this message; does the server have a copy? */
        if (sync_msgid_lookup(server_msgid_list, &record.uuid))
            sync_msgid_add(reserve_msgid_list, &record.uuid);
    }
    
    return(0);
}

/* Count numbers of instances on server of each MessageID that we will
 * want to copy */

static int count_reserve_messages(struct sync_folder *server_folder,
				  struct sync_msgid_list *reserve_msgid_list)
{
    struct sync_msg_list *msglist = server_folder->msglist;
    struct sync_msg      *msg;
    struct sync_msgid    *msgid;

    for (msg = msglist->head ; msg ; msg = msg->next) {
        if ((msgid=sync_msgid_lookup(reserve_msgid_list, &msg->uuid)))
            msgid->count++;
    }
    
    return(0);
}

static int reserve_check_folder(struct sync_msgid_list *reserve_msgid_list,
				struct sync_folder *folder)
{
    struct sync_msg   *msg;
    struct sync_msgid *msgid;

    for (msg = folder->msglist->head ; msg ; msg = msg->next) {
        msgid = sync_msgid_lookup(reserve_msgid_list, &msg->uuid);

        if (msgid && !msgid->reserved)
            return(1);
    }
    return(0);
}

static int reserve_folder(struct sync_msgid_list *reserve_msgid_list,
			  struct sync_folder *folder)
{
    struct sync_msg   *msg;
    struct sync_msgid *msgid;
    static struct buf arg;
    int r = 0, unsolicited, c;

    prot_printf(toserver, "RESERVE "); 
    sync_printastring(toserver, folder->name);

    for (msg = folder->msglist->head ; msg ; msg = msg->next) {
        msgid = sync_msgid_lookup(reserve_msgid_list, &msg->uuid);

        if (msgid && !msgid->reserved) {
            /* Attempt to Reserve message in this folder */
            prot_printf(toserver, " "); 
            sync_printastring(toserver, message_uuid_text(&msgid->uuid));
        }
    }
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("RESERVE", fromserver,
                        SYNC_PARSE_EAT_OKLINE, &unsolicited);

    /* Parse response to record successfully reserved messages */
    while (!r && unsolicited) {
        struct message_uuid tmp_uuid;

        c = getword(fromserver, &arg);

        if (c == '\r')
            c = prot_getc(fromserver);

        if (c != '\n') {
            syslog(LOG_ERR, "Illegal response to RESERVE: %s", arg.s);
            sync_eatlines_unsolicited(fromserver, c);
            return(IMAP_PROTOCOL_ERROR);
        }
 
        if (!message_uuid_from_text(&tmp_uuid, arg.s)) {
            syslog(LOG_ERR, "Illegal response to RESERVE: %s", arg.s);
            sync_eatlines_unsolicited(fromserver, c);
            return(IMAP_PROTOCOL_ERROR);
        }

        if ((msgid = sync_msgid_lookup(reserve_msgid_list, &tmp_uuid))) {
            msgid->reserved = 1;
            reserve_msgid_list->reserved++;
            sync_msgid_add(msgid_onserver, &tmp_uuid);
        } else
            syslog(LOG_ERR, "RESERVE: Unexpected response MessageID %s in %s",
                   arg.s, folder->name);

        r = sync_parse_code("RESERVE", fromserver,
                            SYNC_PARSE_EAT_OKLINE, &unsolicited);
    }
    return(r);
}

struct reserve_sort_item {
    struct sync_folder *folder;
    unsigned long count;
};

static int reserve_folder_compare(const void *v1, const void *v2)
{
    struct reserve_sort_item *s1 = (struct reserve_sort_item *)v1;
    struct reserve_sort_item *s2 = (struct reserve_sort_item *)v2;

    return(s1->count - s2->count);
}

static int reserve_messages(struct sync_folder_list *client_list,
			    struct sync_folder_list *server_list,
			    int *vanishedp)
{
    struct sync_msgid_list *server_msgid_list  = NULL;
    struct sync_msgid_list *reserve_msgid_list = NULL;
    struct sync_folder     *folder, *folder2;
    struct sync_msg   *msg;
    struct sync_msgid *msgid;
    struct reserve_sort_item *reserve_sort_list = 0;
    int reserve_sort_count;
    int r = 0;
    int mailbox_open = 0;
    int count;
    int i;
    struct mailbox m;

    server_msgid_list  = sync_msgid_list_create(SYNC_MSGID_LIST_HASH_SIZE);
    reserve_msgid_list = sync_msgid_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    /* Generate fast lookup hash of all MessageIDs available on server */
    for (folder = server_list->head ; folder ; folder = folder->next) {
        for (msg = folder->msglist->head ; msg ; msg = msg->next) {
            if (!sync_msgid_lookup(server_msgid_list, &msg->uuid))
                sync_msgid_add(server_msgid_list, &msg->uuid);
        }
    }

    /* Find messages we want to upload that are available on server */
    for (folder = client_list->head ; folder ; folder = folder->next) {
	/* Quietly skip over folders that have already been processed */
	if (folder->mark) continue;

        folder->id  = NULL;
        folder->acl = NULL;

        r = mailbox_open_header(folder->name, 0, &m);

        /* Quietly skip over folders which have been deleted since we
           started working (but record fact in case caller cares) */
        if (r == IMAP_MAILBOX_NONEXISTENT) {  
            (*vanishedp)++;
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

        if (!r) mailbox_open = 1;
        if (!r) r = mailbox_open_index(&m);

        if (r) {
            if (mailbox_open) mailbox_close(&m);

            syslog(LOG_ERR, "IOERROR: %s", error_message(r));
            goto bail;
        }

        folder->id  = xstrdup(m.uniqueid);
        folder->acl = xstrdup(m.acl);

        if ((folder2=sync_folder_lookup(server_list, m.uniqueid)))
            find_reserve_messages(&m, folder2->msglist, 
                                  server_msgid_list,
                                  reserve_msgid_list);
        else
            reserve_all_messages(&m, 
                                 server_msgid_list,
                                 reserve_msgid_list);

        mailbox_close(&m);
    }

    if (reserve_msgid_list->count == 0) {
        r = 0;      /* Nothing to do */
        goto bail;
    }

    /* Generate instance count for messages available on server */
    for (folder = server_list->head ; folder ; folder = folder->next)
        count_reserve_messages(folder, reserve_msgid_list);

    /* Add all folders which have unique copies of messages to reserve list
     * (as they will definitely be needed) */
    for (folder = server_list->head ; folder ; folder = folder->next) {
        for (msg = folder->msglist->head ; msg ; msg = msg->next) {
            msgid = sync_msgid_lookup(reserve_msgid_list, &msg->uuid);

            if (msgid && (msgid->count == 1)) {
                reserve_folder(reserve_msgid_list, folder);
                folder->reserve = 1;
                break;
            }
        }
    }

    /* Record all folders with unreserved messages and sort them so the
     * folder with most unreserved messages in first */
    reserve_sort_list
        = xmalloc(server_list->count*sizeof(struct reserve_sort_item));

    /* Count messages we will be able to reserve from each folder on server */
    reserve_sort_count = 0;
    for (folder = server_list->head; folder ; folder=folder->next) {
        if (folder->reserve) continue;

        for (count = 0, msg = folder->msglist->head ; msg ; msg = msg->next) {
            msgid = sync_msgid_lookup(reserve_msgid_list, &msg->uuid);

            if (msgid && !msgid->reserved)
                count++;
        }

        if (count > 0) {
            reserve_sort_list[reserve_sort_count].folder = folder;
            reserve_sort_list[reserve_sort_count].count  = count;
            reserve_sort_count++;
        }
    }

    /* Sort folders (folder with most reservable messages first) */
    if (reserve_sort_count > 0)
        qsort(reserve_sort_list, reserve_sort_count,
              sizeof(struct reserve_sort_item), reserve_folder_compare);

    /* Work through folders until all messages reserved or no more */
    for (i=0; i < reserve_sort_count ; i++) {
        folder = reserve_sort_list[i].folder;

        if (reserve_check_folder(reserve_msgid_list, folder))
            reserve_folder(reserve_msgid_list, folder);

        if (reserve_msgid_list->reserved == reserve_msgid_list->count)
            break;
    }

 bail:
    sync_msgid_list_free(&server_msgid_list);
    sync_msgid_list_free(&reserve_msgid_list);
    if (reserve_sort_list) free(reserve_sort_list);
    return(r);
}

static int folders_get_uniqueid(struct sync_folder_list *client_list,
				int *vanishedp)
{
    struct sync_folder *folder;
    int r = 0;
    int mailbox_open = 0;
    struct mailbox m;

    /* Find messages we want to upload that are available on server */
    for (folder = client_list->head ; folder ; folder = folder->next) {
	/* Quietly skip over folders that have already been processed */
	if (folder->mark) continue;

        folder->id  = NULL;
        folder->acl = NULL;

        r = mailbox_open_header(folder->name, 0, &m);

        /* Quietly skip over folders which have been deleted since we
           started working (but record fact in case caller cares) */
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            (*vanishedp)++;
            r = 0;
            continue;
        }

        /* Quietly ignore objects that we don't have access to.
         * Includes directory stubs, which have not underlying cyrus.*
         * files in the filesystem */
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            r = 0;
            continue;
        }


        if (!r) mailbox_open = 1;
        if (!r) r = mailbox_open_index(&m);

       if (r) {
            if (mailbox_open) mailbox_close(&m);
            syslog(LOG_ERR, "IOERROR: %s", error_message(r));
            return(r);
        }

        folder->id  = xstrdup(m.uniqueid);
        folder->acl = xstrdup(m.acl);

        mailbox_close(&m);
    }

    return(0);
}

/* ====================================================================== */

static int user_reset(char *user)
{
    prot_printf(toserver, "RESET "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    return(sync_parse_code("RESET", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

/* ====================================================================== */

static int folder_select(char *name, char *myuniqueid,
			 unsigned long *lastuidp)
{
    int r, c;
    static struct buf uniqueid;
    static struct buf lastuid;

    prot_printf(toserver, "SELECT "); 
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("SELECT", fromserver, SYNC_PARSE_NOEAT_OKLINE, NULL);
    if (r) return(r);
    
    if ((c = getword(fromserver, &uniqueid)) != ' ') {
        eatline(fromserver, c);
        syslog(LOG_ERR, "Garbage on Select response");
        return(IMAP_PROTOCOL_ERROR);
    }

    c = getword(fromserver, &lastuid);
    if (c == '\r') c = prot_getc(fromserver);
    if (c != '\n') {
        eatline(fromserver, c);
        syslog(LOG_ERR, "Garbage on Select response");
        return(IMAP_PROTOCOL_ERROR);
    }

    if (strcmp(uniqueid.s, myuniqueid) != 0)
        return(IMAP_MAILBOX_MOVED);

    if (lastuidp)  *lastuidp  = sync_atoul(lastuid.s);

    return(0);
}

static int folder_create(char *name, char *part, char *uniqueid, char *acl,
			 unsigned long options, unsigned long uidvalidity)
{
    prot_printf(toserver, "CREATE ");
    sync_printastring(toserver, name);
    prot_printf(toserver, " ");
    sync_printastring(toserver, part);
    prot_printf(toserver, " ");
    sync_printastring(toserver, uniqueid);
    prot_printf(toserver, " ");
    sync_printastring(toserver, acl);
    prot_printf(toserver, " %d %lu %lu\r\n", 0, options, uidvalidity);
    prot_flush(toserver);

    return(sync_parse_code("CREATE", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int folder_rename(char *oldname, char *newname)
{
    prot_printf(toserver, "RENAME ");
    sync_printastring(toserver, oldname);
    prot_printf(toserver, " ");
    sync_printastring(toserver, newname);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("RENAME", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int folder_delete(char *name)
{
    prot_printf(toserver, "DELETE "); 
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    return(sync_parse_code("DELETE", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int user_addsub(char *user, char *name)
{
    if (verbose) 
        printf("ADDSUB %s %s\n", user, name);

    if (verbose_logging)
        syslog(LOG_INFO, "ADDSUB %s %s", user, name);

    prot_printf(toserver, "ADDSUB ");
    sync_printastring(toserver, user);
    prot_printf(toserver, " ");
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("ADDSUB", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int user_delsub(char *user, char *name)
{
    if (verbose) 
        printf("DELSUB %s %s\n", user, name);

    if (verbose_logging)
        syslog(LOG_INFO, "DELSUB %s %s", user, name);

    prot_printf(toserver, "DELSUB ");
    sync_printastring(toserver, user);
    prot_printf(toserver, " ");
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("DELSUB", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int folder_setacl(char *name, char *acl)
{
    prot_printf(toserver, "SETACL "); 
    sync_printastring(toserver, name);
    prot_printf(toserver, " "); 
    sync_printastring(toserver, acl);
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    return(sync_parse_code("SETACL", fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int folder_setannotation(char *name, char *entry, char *userid,
				char *value)
{
    prot_printf(toserver, "SETANNOTATION "); 
    sync_printastring(toserver, name);
    prot_printf(toserver, " ");
    sync_printastring(toserver, entry);
    prot_printf(toserver, " ");
    sync_printastring(toserver, userid);
    prot_printf(toserver, " ");
    if (value) sync_printastring(toserver, value);
    else prot_printf(toserver, "NIL");
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    return(sync_parse_code("SETANNOTATION", fromserver,
			   SYNC_PARSE_EAT_OKLINE, NULL));
}

/* ====================================================================== */

static int sieve_upload(char *user, char *name, unsigned long last_update)
{
    char *s, *sieve;
    unsigned long size;

    if (!(sieve = sync_sieve_read(user, name, &size))) {
        return(IMAP_IOERROR);
    }

    prot_printf(toserver, "UPLOAD_SIEVE "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, " ");
    sync_printastring(toserver, name);
    prot_printf(toserver, " %lu {%lu+}\r\n", last_update, size);

    s = sieve;
    while (size) {
        prot_putc(*s, toserver);
        s++;
        size--;
    }
    prot_printf(toserver,"\r\n");
    free(sieve);
    prot_flush(toserver);

    return(sync_parse_code("UPLOAD_SIEVE",
                           fromserver, SYNC_PARSE_EAT_OKLINE, NULL));

    return(1);
}

static int sieve_delete(char *user, char *name)
{
    prot_printf(toserver, "DELETE_SIEVE "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, " ");
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    return(sync_parse_code("DELETE_SIEVE",
                           fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int sieve_activate(char *user, char *name)
{
    prot_printf(toserver, "ACTIVATE_SIEVE "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, " ");
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("ACTIVATE_SIEVE",
                           fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

static int sieve_deactivate(char *user)
{
    prot_printf(toserver, "DEACTIVATE_SIEVE "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("DEACTIVATE_SIEVE",
                           fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}

/* ====================================================================== */

static int update_quota_work(struct quota *client, struct quota *server)
{
    int  r;

    if ((r = quota_read(client, NULL, 0))) {
        syslog(LOG_INFO, "Warning: failed to read quotaroot %s: %s",
               client->root, error_message(r));
        return(0);
    }

    if (server && (client->limit == server->limit))
        return(0);

    prot_printf(toserver, "SETQUOTA ");
    sync_printastring(toserver, client->root);

    prot_printf(toserver, " %d\r\n", client->limit);
    prot_flush(toserver);
    
    return(sync_parse_code("SETQUOTA",fromserver,SYNC_PARSE_EAT_OKLINE,NULL));
}

/* ====================================================================== */

static void create_flags_lookup(int table[], char *client[], char *server[])
{
    int i, j;

    /* Rather unfortunate O(n^2) loop, where 0 <= n <= 128
     * However n (number of active user defined flags is typically small:
     * (client[i] == NULL) test should make this much closer to O(n).
     */
    for (i = 0 ; i < MAX_USER_FLAGS ; i++) {
        table[i] = (-1);

        if (client[i] == NULL)
            continue;

        for (j = 0 ; j < MAX_USER_FLAGS ; j++) {
            if (server[j] && !strcmp(client[i], server[j])) {
                table[i] = j;
                break;
            }
        }
    }
}

static int check_flags(struct mailbox *mailbox, struct sync_msg_list *list,
		       int flag_lookup_table[])
{
    struct sync_msg *msg;
    unsigned long msgno;
    struct index_record record;
    int cflag, sflag, cvalue, svalue;

    msg = list->head;
    for (msgno = 1; msg && (msgno <= mailbox->exists) ; msgno++) {
        mailbox_read_index_record(mailbox, msgno, &record);

        /* Skip msgs on client missing on server (will upload later) */
        if (record.uid < msg->uid)
            continue;

        /* Skip over messages recorded on server which are missing on client
         * (either will be expunged or have been expunged already) */
        while (msg && (record.uid > msg->uid))
            msg = msg->next;

        if (!(msg && (record.uid == msg->uid)))
            continue;

        /* Got a message on client which has same UID as message on server
         * Work out if system and user flags match */
        if (record.system_flags != msg->flags.system_flags)
            return(1);

        for (cflag = 0; cflag < MAX_USER_FLAGS; cflag++) {
            if (mailbox->flagname[cflag] == NULL)
                continue;

            cvalue = svalue = 0;

            if (record.user_flags[cflag/32] & (1<<(cflag&31)))
                cvalue = 1;

            if (((sflag = flag_lookup_table[cflag]) >= 0) &&
                (msg->flags.user_flags[sflag/32] & 1<<(sflag&31)))
                svalue = 1;

            if (cvalue != svalue)
                return(1);
        }
    }
    return(0);
}

static int update_flags(struct mailbox *mailbox, struct sync_msg_list *list,
			int flag_lookup_table[])
{
    struct sync_msg *msg;
    unsigned long msgno;
    struct index_record record;
    int flags_printed, flag;
    int cflag, sflag, cvalue, svalue;
    int update;
    int have_update = 0;

    msg = list->head;
    for (msgno = 1; msg && (msgno <= mailbox->exists) ; msgno++) {
        mailbox_read_index_record(mailbox, msgno, &record);

        /* Skip msgs on client missing on server (will upload later) */
        if (record.uid < msg->uid)
            continue;
        
        /* Skip over messages recorded on server which are missing on client
         * (either will be expunged or have been expunged already) */
        while (msg && (record.uid > msg->uid))
            msg = msg->next;

        if (!(msg && (record.uid == msg->uid)))
            continue;

        /* Got a message on client which has same UID as message on server
         * Work out if system and user flags match */
        update = 0;
        if (record.system_flags != msg->flags.system_flags) {
            update = 1;
        } else for (cflag = 0; cflag < MAX_USER_FLAGS; cflag++) {
            if (mailbox->flagname[cflag] == NULL)
                continue;

            cvalue = svalue = 0;
            
            if (record.user_flags[cflag/32] & (1<<(cflag&31)))
                cvalue = 1;
                    
            if (((sflag = flag_lookup_table[cflag]) >= 0) &&
                (msg->flags.user_flags[sflag/32] & 1<<(sflag&31)))
                svalue = 1;
                    
            if (cvalue != svalue) {
                update = 1;
                break;
            }
        }
        if (!update)
            continue;

        if (!have_update) {
            prot_printf(toserver, "SETFLAGS");
            have_update = 1;
        }

        prot_printf(toserver, " %lu (", record.uid);
        flags_printed = 0;

        if (record.system_flags & FLAG_DELETED)
            sync_flag_print(toserver, &flags_printed,"\\deleted");
        if (record.system_flags & FLAG_ANSWERED)
            sync_flag_print(toserver, &flags_printed,"\\answered");
        if (record.system_flags & FLAG_FLAGGED)
            sync_flag_print(toserver,&flags_printed, "\\flagged");
        if (record.system_flags & FLAG_DRAFT)
            sync_flag_print(toserver,&flags_printed, "\\draft");
        
        for (flag = 0 ; flag < MAX_USER_FLAGS ; flag++) {
            if (mailbox->flagname[flag] &&
                (record.user_flags[flag/32] & (1<<(flag&31)) ))
                sync_flag_print(toserver, &flags_printed,
                                mailbox->flagname[flag]);
        }
        prot_printf(toserver, ")");
    }

    if (!have_update)
        return(0);

    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("SETFLAGS",fromserver,SYNC_PARSE_EAT_OKLINE,NULL));
}

/* ====================================================================== */

static int check_expunged(struct mailbox *mailbox, struct sync_msg_list *list)
{
    struct sync_msg *msg = list->head;
    unsigned long msgno = 1;
    struct index_record record;

    for (msgno = 1; msg && (msgno <= mailbox->exists) ; msgno++) {
        mailbox_read_index_record(mailbox, msgno, &record);

        /* Skip msgs on client missing on server (will upload later) */
        if (record.uid < msg->uid)
            continue;

        /* Message on server doesn't exist on client: need expunge */
        if (record.uid > msg->uid)
            return(1);

        /* UIDs match => exist on client and server */
        msg = msg->next;
    }
    return((msg) ? 1 : 0);  /* Remaining messages on server: expunge needed */
}

static int expunge(struct mailbox *mailbox, struct sync_msg_list *list)
{
    struct sync_msg *msg = list->head;
    unsigned long msgno = 1;
    struct index_record record;
    int count = 0;

    for (msgno = 1; msg && (msgno <= mailbox->exists) ; msgno++) {
        mailbox_read_index_record(mailbox, msgno, &record);

        /* Skip msgs on client missing on server (will upload later) */
        if (record.uid < msg->uid)
            continue;

        /* Expunge messages on server which do not exist on client */
        while (msg && (record.uid > msg->uid)) {
            if (count++ == 0)
                prot_printf(toserver, "EXPUNGE");

            prot_printf(toserver, " %lu", msg->uid);
            msg = msg->next;
        }

        /* Skip messages which exist on both client and server */
        if (msg && (record.uid == msg->uid))
            msg = msg->next;
    }

    /* Expunge messages on server which do not exist on client */
    while (msg) {
        if (count++ == 0)
            prot_printf(toserver, "EXPUNGE");

        prot_printf(toserver, " %lu", msg->uid);

        msg = msg->next;
    }

    if (count == 0)
        return(0);

    prot_printf(toserver, "\r\n");
    prot_flush(toserver);
    return(sync_parse_code("EXPUNGE",fromserver,SYNC_PARSE_EAT_OKLINE,NULL));
}

/* ====================================================================== */

/* Check whether there are any messages to upload in this folder */

static int check_upload_messages(struct mailbox *mailbox,
				 struct sync_msg_list *list)
{
    struct sync_msg *msg;
    struct index_record record;
    unsigned long msgno;

    if (mailbox->exists == 0)
        return(0);

    /* Find out whether server is missing any messages */
    if ((msg = list->head) == NULL)
        return(1);

    for (msgno = 1 ; msgno <= mailbox->exists ; msgno++) {
        if (mailbox_read_index_record(mailbox, msgno, &record))
            return(1);     /* Attempt upload, report error then */
        
        /* Skip over messages recorded on server which are missing on client
         * (either will be expunged or have been expunged already) */
        while (msg && (record.uid > msg->uid))
            msg = msg->next;

        if (msg && (record.uid == msg->uid) &&
            message_uuid_compare(&record.uuid, &msg->uuid)) {
            msg = msg->next;  /* Ignore exact match */
            continue;
        }

        /* Found a message on the client which doesn't exist on the server */
        return(1);
    }

    return (msgno <= mailbox->exists);
}

/* Upload missing messages from folders (uses UPLOAD COPY where possible) */

static int upload_message_work(struct mailbox *mailbox,
			       unsigned long msgno,
			       struct index_record *record)
{
    unsigned long cache_size;
    int flags_printed = 0;
    int r = 0, flag, need_body;
    static unsigned long sequence = 1;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;

    /* Protocol for PARSED items:
     * C:  PARSED  <msgid> <uid>
     *             <internaldate> <sent-date> <last-updated> <modseq> <flags>
     *             <hdr size> <content_lines>
     *             <cache literal (includes cache size!)>
     * <msg literal (includes msg size!)>
     */

    /* Protocol for COPY items:
     * C:  COPY <msgid> <uid>
     *           <internaldate> <sent-date> <last-updated> <modseq> <flags>
     */

    if (sync_msgid_lookup(msgid_onserver, &record->uuid)) {
        prot_printf(toserver, " COPY");
        need_body = 0;
    } else {
        sync_msgid_add(msgid_onserver, &record->uuid);
        prot_printf(toserver, " PARSED");
        need_body = 1;
    }

    prot_printf(toserver, " %s %lu %lu %lu %lu " MODSEQ_FMT " (",
             message_uuid_text(&record->uuid),
             record->uid, record->internaldate,
             record->sentdate, record->last_updated, record->modseq);

    flags_printed = 0;

    if (record->system_flags & FLAG_DELETED)
        sync_flag_print(toserver, &flags_printed, "\\deleted");
    if (record->system_flags & FLAG_ANSWERED)
        sync_flag_print(toserver, &flags_printed, "\\answered");
    if (record->system_flags & FLAG_FLAGGED)
        sync_flag_print(toserver, &flags_printed, "\\flagged");
    if (record->system_flags & FLAG_DRAFT)
        sync_flag_print(toserver, &flags_printed, "\\draft");

    for (flag = 0 ; flag < MAX_USER_FLAGS ; flag++) {
        if (mailbox->flagname[flag] &&
            (record->user_flags[flag/32] & (1<<(flag&31)) ))
            sync_flag_print(toserver, 
                            &flags_printed, mailbox->flagname[flag]);
    }
    prot_printf(toserver, ")");

    if (need_body) {
        /* Server doesn't have this message yet */
        cache_size = mailbox_cache_size(mailbox, msgno);

        if (cache_size == 0) {
            syslog(LOG_ERR,
                   "upload_messages(): Empty cache entry for msgno %lu",
                   msgno);
            return(IMAP_INTERNAL);
        }
        
        r = mailbox_map_message(mailbox, record->uid, &msg_base, &msg_size);
        
        if (r) {
            syslog(LOG_ERR, "IOERROR: opening message file %lu of %s: %m",
                   record->uid, mailbox->name);
            return(IMAP_IOERROR);
        }

        prot_printf(toserver, " %lu %lu %lu {%lu+}\r\n",
		    record->header_size, record->content_lines,
		    record->cache_version, cache_size);

        prot_write(toserver,
		   (char *)(mailbox->cache_base + record->cache_offset),
		   cache_size);
                    
        prot_printf(toserver, "{%lu+}\r\n", msg_size);
        prot_write(toserver, (char *)msg_base, msg_size);
        mailbox_unmap_message(mailbox, record->uid, &msg_base, &msg_size);
        sequence++;
    }
    return(r);
}

static int upload_messages_list(struct mailbox *mailbox,
				struct sync_msg_list *list)
{
    unsigned long msgno = 1;
    int r = 0;
    struct index_record record;
    struct sync_msg *msg;
    int count;
    int c = ' ';
    static struct buf token;   /* BSS */
    int max_count = config_getint(IMAPOPT_SYNC_BATCH_SIZE);

    if (max_count <= 0) max_count = INT_MAX;

    if (chdir(mailbox->path)) {
        syslog(LOG_ERR, "Couldn't chdir to %s: %s",
               mailbox->path, strerror(errno));
        return(IMAP_IOERROR);
    }

repeatupload:

    msg = list->head;
    for (count = 0; count < max_count && msgno <= mailbox->exists ; msgno++) {
        r = mailbox_read_index_record(mailbox, msgno, &record);

        if (r) {
            syslog(LOG_ERR,
                   "IOERROR: reading index entry for nsgno %lu of %s: %m",
                   record.uid, mailbox->name);
            return(IMAP_IOERROR);
        }

        /* Skip over messages recorded on server which are missing on client
         * (either will be expunged or have been expunged already) */
        while (msg && (record.uid > msg->uid))
            msg = msg->next;

        if (msg && (record.uid == msg->uid) &&
            message_uuid_compare(&record.uuid, &msg->uuid)) {
            msg = msg->next;  /* Ignore exact match */
            continue;
        }

        if (count++ == 0)
            prot_printf(toserver, "UPLOAD %lu %lu",
                     mailbox->last_uid, mailbox->last_appenddate); 

        /* Message with this UUID exists on client but not server */
        if ((r=upload_message_work(mailbox, msgno, &record)))
            return(r);

        if (msg && (msg->uid == record.uid))  /* Overwritten on server */
            msg = msg->next;
    }

    if (count == 0)
        return(r);

    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("UPLOAD", fromserver, SYNC_PARSE_NOEAT_OKLINE, NULL);
    if (r) return(r);

    if ((c = getword(fromserver, &token)) != ' ') {
        eatline(fromserver, c);
        syslog(LOG_ERR, "Garbage on Upload response");
        return(IMAP_PROTOCOL_ERROR);
    }
    eatline(fromserver, c);

    /* Clear out msgid_on_server list if server restarted */
    if (!strcmp(token.s, "[RESTART]")) {
        int hash_size = msgid_onserver->hash_size;

        sync_msgid_list_free(&msgid_onserver);
        msgid_onserver = sync_msgid_list_create(hash_size);

	syslog(LOG_INFO, "UPLOAD: received RESTART");
    }

    /* don't overload the server with too many uploads at once! */
    if (count >= max_count) {
	syslog(LOG_INFO, "UPLOAD: hit %d uploads at msgno %d", count, msgno);
	goto repeatupload;
    }

    return(0);
}

static int upload_messages_from(struct mailbox *mailbox,
				unsigned long old_last_uid)
{
    unsigned long msgno;
    int r = 0;
    struct index_record record;
    int count = 0;
    int c = ' ';
    static struct buf token;   /* BSS */

    if (chdir(mailbox->path)) {
        syslog(LOG_ERR, "Couldn't chdir to %s: %s",
               mailbox->path, strerror(errno));
        return(IMAP_IOERROR);
    }

    for (msgno = 1 ; msgno <= mailbox->exists ; msgno++) {
        r =  mailbox_read_index_record(mailbox, msgno, &record);

        if (r) {
            syslog(LOG_ERR,
                   "IOERROR: reading index entry for nsgno %lu of %s: %m",
                   record.uid, mailbox->name);
            return(IMAP_IOERROR);
        }

        if (record.uid <= old_last_uid)
            continue;

        if (count++ == 0)
            prot_printf(toserver, "UPLOAD %lu %lu",
                     mailbox->last_uid, mailbox->last_appenddate); 

        if ((r=upload_message_work(mailbox, msgno, &record)))
            return(r);
    }

    if (count == 0)
        return(r);

    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("UPLOAD", fromserver, SYNC_PARSE_NOEAT_OKLINE, NULL);
    if (r) return(r);

    if ((c = getword(fromserver, &token)) != ' ') {
        eatline(fromserver, c);
        syslog(LOG_ERR, "Garbage on Upload response");
        return(IMAP_PROTOCOL_ERROR);
    }
    eatline(fromserver, c);

    /* Clear out msgid_on_server list if server restarted */
    if (!strcmp(token.s, "[RESTART]")) {
        int hash_size = msgid_onserver->hash_size;

        sync_msgid_list_free(&msgid_onserver);
        msgid_onserver = sync_msgid_list_create(hash_size);

	syslog(LOG_INFO, "UPLOAD: received RESTART");
    }

    return(0);
}

/* upload_messages() null operations still requires UIDLAST update */

static int update_uidlast(struct mailbox *mailbox)
{
    prot_printf(toserver, "UIDLAST %lu %lu\r\n",
             mailbox->last_uid, mailbox->last_appenddate);
    prot_flush(toserver);
    return(sync_parse_code("UIDLAST",fromserver, SYNC_PARSE_EAT_OKLINE, NULL));
}


/* ====================================================================== */

static int do_seen(char *user, char *name)
{
    int r = 0;
    struct mailbox m;
    struct seen *seendb;
    time_t lastread, lastchange;
    unsigned int last_recent_uid;
    char *seenuid = NULL;

    if (verbose) 
        printf("SEEN %s %s\n", user, name);

    if (verbose_logging)
        syslog(LOG_INFO, "SEEN %s %s", user, name);

    r = mailbox_open_header(name, 0, &m);
    if (r) return(r);

    r = seen_open(&m, user, 0, &seendb);
    if (!r) {
        r = seen_read(seendb, &lastread, &last_recent_uid,
                      &lastchange, &seenuid);
        seen_close(seendb);
    }

    if (r) {
        syslog(LOG_ERR, "Failed to read seendb (%s, %s): %s",
               user, m.name, error_message(r));
	goto bail;
    }

    /* Update seen list */
    prot_printf(toserver, "SETSEEN ");
    sync_printastring(toserver, user);
    prot_printf(toserver, " ");
    sync_printastring(toserver, m.name);
    prot_printf(toserver, " %lu %lu %lu ",
		lastread, last_recent_uid, lastchange);
    sync_printastring(toserver, seenuid);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);
    r = sync_parse_code("SETSEEN",fromserver,SYNC_PARSE_EAT_OKLINE,NULL);

  bail:
    mailbox_close(&m);
    if (seenuid) free(seenuid);

    return r;
}

/* ====================================================================== */

static int do_append(char *name)
{
    struct mailbox m;
    int r = 0;
    int mailbox_open = 0;
    int selected = 0;
    unsigned long last_uid  = 0;
    struct index_record record;

    if (verbose) 
        printf("APPEND %s\n", name);

    if (verbose_logging)
        syslog(LOG_INFO, "APPEND %s", name);

    if ((r = mailbox_open_header(name, 0, &m)))
        goto bail;

    mailbox_open = 1;
    
    if ((r = mailbox_open_index(&m)))
        goto bail;

    if ((r = folder_select(name, m.uniqueid, &last_uid)))
        goto bail;

    selected = 1;

    if ((r = mailbox_read_index_record(&m, m.exists, &record)))
        goto bail;

    if ((record.uid > last_uid) && (r=upload_messages_from(&m, last_uid)))
        goto bail;

 bail:
    if (mailbox_open) mailbox_close(&m);

    return(r);
}

/* ====================================================================== */

static int do_acl(char *name)
{
    int r = 0;
    struct mailbox m;

    if (verbose) 
        printf("SETACL %s\n", name);

    if (verbose_logging)
        syslog(LOG_INFO, "SETACL: %s", name);

    r = mailbox_open_header(name, 0, &m);
    if (r) return r;

    r = folder_setacl(m.name, m.acl);
    mailbox_close(&m);

    return(r);
}

static int do_quota(char *name)
{
    int r = 0;
    struct quota quota;

    if (verbose) 
        printf("SETQUOTA %s\n", name);

    if (verbose_logging)
        syslog(LOG_INFO, "SETQUOTA: %s", name);

    quota.root = name;
    r = update_quota_work(&quota, NULL);

    return(r);
}

static int add_annot(const char *mailbox __attribute__((unused)),
		     const char *entry, const char *userid,
		     struct annotation_data *attrib, void *rock)
{
    struct sync_annot_list *l = (struct sync_annot_list *) rock;

    sync_annot_list_add(l, entry, userid, attrib->value);

    return 0;
}

static int do_annotation(char *name)
{
    int unsolicited, c, r = 0;
    static struct buf entry, userid, value;
    struct sync_annot_list *server_list = sync_annot_list_create();

    prot_printf(toserver, "LIST_ANNOTATIONS ");
    sync_printastring(toserver, name);
    prot_printf(toserver, "\r\n", name);
    prot_flush(toserver);
    r=sync_parse_code("LIST_ANNOTATIONS", fromserver,
		      SYNC_PARSE_EAT_OKLINE, &unsolicited);

    while (!r && unsolicited) {
	if ((c = getastring(fromserver, toserver, &entry)) != ' ') {
            syslog(LOG_ERR,
		   "LIST_ANNOTATIONS: Invalid type %d response from server: %s",
                   unsolicited, entry.s);
            sync_eatlines_unsolicited(fromserver, c);
            r = IMAP_PROTOCOL_ERROR;
            break;
        }

	if ((c = getastring(fromserver, toserver, &userid)) != ' ') {
            syslog(LOG_ERR,
		   "LIST_ANNOTATIONS: Invalid type %d response from server: %s",
                   unsolicited, userid.s);
            sync_eatlines_unsolicited(fromserver, c);
            r = IMAP_PROTOCOL_ERROR;
            break;
        }

        c = getastring(fromserver, toserver, &value);
        if (c == '\r') c = prot_getc(fromserver);
        if (c != '\n') {
            syslog(LOG_ERR,
		   "LIST_ANNOTATIONS: Invalid type %d response from server: %s",
                   unsolicited, value.s);
            sync_eatlines_unsolicited(fromserver, c);
            r = IMAP_PROTOCOL_ERROR;
            break;
        }
        sync_annot_list_add(server_list, entry.s, userid.s, value.s);

        r = sync_parse_code("LIST_ANNOTATIONS", fromserver,
                            SYNC_PARSE_EAT_OKLINE, &unsolicited);
    }

    if (!r) {
	struct sync_annot_list *client_list = sync_annot_list_create();
	struct sync_annot_item *c, *s;
	int n;

	annotatemore_findall(name, "*", &add_annot, client_list, NULL);

	/* both lists are sorted, so we work our way through the lists
	   top-to-bottom and determine what we need to do based on order */
	for (c = client_list->head,
		 s = server_list->head; c || s;  c = c ? c->next : NULL) {
	    if (!s) n = -1;		/* add all client annotations */
	    else if (!c) n = 1;		/* remove all server annotations */
	    else if ((n = strcmp(c->entry, s->entry)) == 0)
		n = strcmp(c->userid, s->userid);

	    if (n > 0) {
		/* remove server annotations until we reach or pass the
		   current client annotation, or we reach the end of the
		   server list */
		do {
		    if ((r = folder_setannotation(name, s->entry, s->userid,
						  NULL))) {
			goto bail;
		    }
		    s = s->next;
		    if (!s) n = -1;	/* end of server list, we're done */
		    else if (!c) n = 1;	/* remove all server annotations */
		    else if ((n = strcmp(c->entry, s->entry)) == 0)
			n = strcmp(c->userid, s->userid);
		} while (n > 0);
	    }

	    if (n == 0) {
		/* already have the annotation, but is the value different? */
		if (strcmp(c->value, s->value) != 0) n = -1;
		s = s->next;
	    }
	    if (c && n < 0) {
		/* add the current client annotation */
		if ((r = folder_setannotation(name, c->entry, c->userid,
					      c->value))) {
		    goto bail;
		}
	    }
	}
      bail:
	sync_annot_list_free(&client_list);
    }

    sync_annot_list_free(&server_list);

    return(r);
}

/* ====================================================================== */

/* Caller should acquire expire lock before opening mailbox index:
 * gives us readonly snapshot of mailbox for duration of upload
 */

static int do_mailbox_work(struct mailbox *mailbox, 
			   struct sync_msg_list *list, int just_created,
			   char *uniqueid)
{
    unsigned int last_recent_uid;
    time_t lastread, lastchange;
    struct seen *seendb;
    char *seenuid;
    int r = 0;
    int selected = 0;
    int flag_lookup_table[MAX_USER_FLAGS];

    create_flags_lookup(flag_lookup_table,
                        mailbox->flagname, list->meta.flagname);

    if (check_flags(mailbox, list, flag_lookup_table)) {
        if (!selected &&
            (r=folder_select(mailbox->name, mailbox->uniqueid, NULL)))
            return(r);

        selected = 1;
        if ((r=update_flags(mailbox, list, flag_lookup_table)))
            goto bail;
    }
    
    if (check_expunged(mailbox, list)) {
        if (!selected &&
            (r=folder_select(mailbox->name, mailbox->uniqueid, NULL)))
            goto bail;

        selected = 1;

        if ((r=expunge(mailbox, list)))
            goto bail;
    }

    if (check_upload_messages(mailbox, list)) {
        if (!selected &&
            (r=folder_select(mailbox->name, mailbox->uniqueid, NULL)))
            goto bail;
        selected = 1;

        if ((r=upload_messages_list(mailbox, list)))
            goto bail;
    } else if (just_created || (list->last_uid != mailbox->last_uid)) {
        if (!selected &&
            (r=folder_select(mailbox->name, mailbox->uniqueid, NULL)))
            goto bail;
        selected = 1;

        if ((r=update_uidlast(mailbox)))
            goto bail;
    }

 bail:
    return(r);
}

/* ====================================================================== */

int do_folders(struct sync_folder_list *client_list,
	       struct sync_folder_list *server_list,
	       int *vanishedp,
	       int do_contents,
	       int doing_user)
{
    struct mailbox m;
    int r = 0, mailbox_open = 0;
    struct sync_rename_list *rename_list = sync_rename_list_create();
    struct sync_folder   *folder, *folder2;

    *vanishedp = 0;

    if (do_contents) {
        /* Attempt to reserve messages on server that we would overwise have
         * to upload from client */
        if ((r = reserve_messages(client_list, server_list, vanishedp)))
            goto bail;
    } else {
        /* Just need to check whether folders exist, get uniqueid */
        if ((r = folders_get_uniqueid(client_list, vanishedp)))
            goto bail;
    }

    /* Tag folders on server which still exist on the client. Anything
     * on the server which remains untagged can be deleted immediately */
    for (folder = client_list->head ; folder ; folder = folder->next) {
	/* Quietly skip over folders that have already been processed */
	if (folder->mark) continue;

        if (folder->id &&
            (folder2 = sync_folder_lookup(server_list, folder->id))) {
            folder2->mark = 1;
            if (strcmp(folder->name , folder2->name) != 0)
                sync_rename_list_add(rename_list,
                                     folder->id, folder2->name, folder->name);
        }
    }

    /* Delete folders on server which no longer exist on client */
    for (folder = server_list->head ; folder ; folder = folder->next) {
        if (!folder->mark && ((r=folder_delete(folder->name)) != 0))
            goto bail;
    }

    /* Need to rename folders in an order which avoids dependancy conflicts
     * following isn't wildly efficient, but rename_list will typically be
     * short and contain few dependancies.  Algorithm is to simply pick a
     * rename operation which has no dependancy and repeat until done */

    while (rename_list->done < rename_list->count) {
        int rename_success = 0;
        struct sync_rename_item *item, *item2;

        for (item = rename_list->head; item; item = item->next) {
            if (item->done) continue;

            item2 = sync_rename_lookup(rename_list, item->newname);
            if (item2 && !item2->done) continue;

            /* Found unprocessed item which should rename cleanly */
            if ((r = folder_rename(item->oldname, item->newname))) {
                syslog(LOG_ERR, "do_folders(): failed to rename: %s -> %s ",
                       item->oldname, item->newname);
                goto bail;
            }

            rename_list->done++;
            item->done = 1;
            rename_success = 1;
        }

        if (!rename_success) {
            /* Scanned entire list without a match */
            syslog(LOG_ERR,
                   "do_folders(): failed to order folders correctly");
            r = IMAP_PROTOCOL_ERROR;
            goto bail;
        }
    }

    for (folder = client_list->head ; folder ; folder = folder->next) {
	/* Quietly skip over folders that have already been processed */
        if (folder->mark || !folder->id) continue;

        r = mailbox_open_header(folder->name, 0, &m);

        /* Deal with folders deleted since start of function call. Likely
         * cause concurrent rename/delete: caller may need countermeaures
         * (e.g: lock out imapds for a few seconds and then retry)
         */
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            (*vanishedp)++;

            folder2 = sync_folder_lookup(server_list, folder->id);

            if (folder2 && folder2->mark) {
                if ((r=folder_delete(folder2->name))) goto bail;
                folder2->mark = 0;
            }
            continue;
        }

        /* Quietly ignore objects that we don't have access to.
         * Includes directory stubs, which have not underlying cyrus.*
         * files in the filesystem */
        if (r == IMAP_PERMISSION_DENIED) {
            r = 0;
            continue;
        }

        if (!r) mailbox_open = 1;

        if (!r) r = mailbox_open_index(&m);

        if (r) {
            if (mailbox_open) mailbox_close(&m);
            syslog(LOG_ERR, "IOERROR: Failed to open %s: %s",
                   folder->name, error_message(r));
            r = IMAP_IOERROR;
            goto bail;
        }

        if ((folder2=sync_folder_lookup(server_list, folder->id))) {
            if (strcmp(folder2->id, m.uniqueid) != 0) {
                /* Folder UniqueID has changed under our feet: force resync */
		char *part;

                if ((r=folder_delete(folder2->name)))
                    goto bail;

                if ((r=mboxlist_detail(m.name,NULL,NULL,NULL,&part,NULL,NULL))
		    || (r=folder_create(m.name,part,m.uniqueid,m.acl,m.options,
					m.uidvalidity)))
                    goto bail;

		if (!r && m.quota.root && !strcmp(m.name, m.quota.root))
		    r = update_quota_work(&m.quota, &folder2->quota);

		if (!r) r = do_annotation(m.name);

                if (!r && do_contents) {
                    struct sync_msg_list *folder_msglist;

                    /* 0L, 0L Forces last_uid and seendb push as well */
                    folder_msglist = sync_msg_list_create(m.flagname, 0);
                    r = do_mailbox_work(&m, folder_msglist, 1, m.uniqueid);
                    sync_msg_list_free(&folder_msglist);
                }
            } else {
                /* Deal with existing folder */
                if (!(folder2->acl && !strcmp(m.acl, folder2->acl)))
                    r = folder_setacl(folder->name, m.acl);

                if ((folder2->options ^ m.options) & OPT_IMAP_CONDSTORE) {
                    r = folder_setannotation(m.name,
					     "/vendor/cmu/cyrus-imapd/condstore",
					     "",
					     (m.options & OPT_IMAP_CONDSTORE) ?
					     "true" : "false");
		}

		if (!r && m.quota.root && !strcmp(m.name, m.quota.root))
		    r = update_quota_work(&m.quota, &folder2->quota);

		if (!r) r = do_annotation(m.name);

                if (!r && do_contents)
                    r = do_mailbox_work(&m, folder2->msglist, 0, m.uniqueid);
            }
        } else {
	    char *userid, *part;

            /* Need to create fresh folder on server */
            if ((r=mboxlist_detail(m.name,NULL,NULL,NULL,&part,NULL,NULL)) ||
		(r=folder_create(m.name,part,m.uniqueid,m.acl,m.options,
				 m.uidvalidity)))
                goto bail;

	    if (!r && m.quota.root && !strcmp(m.name, m.quota.root))
		r = update_quota_work(&m.quota, NULL);

	    if (!r) r = do_annotation(m.name);

            if (!r && do_contents) {
                struct sync_msg_list *folder_msglist;

                /* 0L, 0L Forces last_uid and seendb push as well */
                folder_msglist = sync_msg_list_create(m.flagname, 0);
                r = do_mailbox_work(&m, folder_msglist, 1, m.uniqueid);
                sync_msg_list_free(&folder_msglist);
            }

	    if (!r && !doing_user && (userid = mboxname_isusermailbox(m.name, 1)))
		r = do_meta(userid);

        }
        if (r) goto bail;

	/* Mark folder as processed */
	folder->mark = 1;
	client_list->count--;

        mailbox_close(&m);
        mailbox_open = 0;
    }

 bail:
    if (mailbox_open) mailbox_close(&m);
    sync_rename_list_free(&rename_list);
    return(r);
}

/* ====================================================================== */

/* Generate sync_folder_list including all msg information from
   list of client folders */

int do_mailboxes_work(struct sync_folder_list *client_list,
		      struct sync_folder_list *server_list)
{
    struct sync_folder *folder = NULL;
    int               c = ' ', r = 0;
    int               unsolicited_type;
    struct sync_msg  *msg = NULL;
    static struct buf id;
    static struct buf acl;
    static struct buf name;
    static struct buf lastuid;
    static struct buf options;
    static struct buf arg;
    struct quota quota, *quotap;

    prot_printf(toserver, "MAILBOXES"); 

    for (folder = client_list->head ; folder; folder = folder->next) {
	/* Quietly skip over folders that have already been processed */
	if (folder->mark) continue;

        prot_printf(toserver, " "); 
        sync_printastring(toserver, folder->name);
    }
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("MAILBOXES", fromserver,
                        SYNC_PARSE_EAT_OKLINE, &unsolicited_type);

    while (!r && (unsolicited_type > 0)) {
        switch (unsolicited_type) {
        case 2:
            /* New folder */
            if ((c = getword(fromserver, &id)) != ' ')
                goto parse_err;

            if ((c = getastring(fromserver, toserver, &name)) != ' ')
                goto parse_err;

            if ((c = getastring(fromserver, toserver, &acl)) != ' ')
                goto parse_err;

            if ((c = getastring(fromserver, toserver, &lastuid)) != ' ')
                goto parse_err;

            c = getastring(fromserver, toserver, &options);

	    quotap = NULL;
	    if (c == ' ') {
		c = getword(fromserver, &arg);
		quota.limit = atoi(arg.s);
		quotap = &quota;
	    }

            if (c == '\r') c = prot_getc(fromserver);
            if (c != '\n') goto parse_err;
            if (!imparse_isnumber(lastuid.s))  goto parse_err;

            folder = sync_folder_list_add(server_list, id.s, name.s, acl.s,
					  sync_atoul(options.s), quotap);
            folder->msglist = sync_msg_list_create(NULL, sync_atoul(lastuid.s));
            break;
        case 1:
            /* New message in current folder */
            if (folder == NULL) goto parse_err;       /* No current folder */
            msg = sync_msg_list_add(folder->msglist);
        
            if (((c = getword(fromserver, &arg)) != ' ') ||
                ((msg->uid = sync_atoul(arg.s)) == 0)) goto parse_err;
            
            if (((c = getword(fromserver, &arg)) != ' ')) goto parse_err;

            if (!message_uuid_from_text(&msg->uuid, arg.s))
                goto parse_err;

            c = sync_getflags(fromserver, &msg->flags, &folder->msglist->meta);
            if (c == '\r') c = prot_getc(fromserver);
            if (c != '\n') goto parse_err;
            break;
        default:
            goto parse_err;
        }
        r = sync_parse_code("MAILBOXES", fromserver,
                            SYNC_PARSE_EAT_OKLINE, &unsolicited_type);
    }
    return(r);

 parse_err:
    syslog(LOG_ERR,
           "MAILBOXES: Invalid unsolicited response type %d from server: %s",
           unsolicited_type, arg.s);
    sync_eatlines_unsolicited(fromserver, c);
    return(IMAP_PROTOCOL_ERROR);
}

/* ====================================================================== */

static int do_mailboxes(struct sync_folder_list *client_folder_list)
{
    struct sync_folder_list *server_folder_list = sync_folder_list_create();
    int r = 0;
    int vanished = 0;
    struct sync_folder *folder;

    if (verbose) {
        printf("MAILBOXES");

        for (folder = client_folder_list->head; folder ; folder = folder->next) {
	    /* Quietly skip over folders that have already been processed */
	    if (folder->mark) continue;

            printf(" %s", folder->name);
	}
        printf("\n");
    }

    if (verbose_logging) {
        for (folder = client_folder_list->head; folder ; folder = folder->next) {
	    /* Quietly skip over folders that have already been processed */
	    if (folder->mark) continue;

            syslog(LOG_INFO, "MAILBOX %s", folder->name);
	}
    }

    /* Worthwhile doing mailboxes even in case of single mailbox:
     * catches duplicate messages in single folder. Only cost is that
     * mailbox at server end is opened twice: once for do_mailboxes_work(),
     * once for do_folders() */

    if (!r) r = do_mailboxes_work(client_folder_list,
				  server_folder_list);
    if (!r) r = do_folders(client_folder_list, server_folder_list,
                           &vanished, 1, 0);

    sync_folder_list_free(&server_folder_list);
    return(r);
}

/* ====================================================================== */

static int addmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock)
{
    struct sync_folder_list *list = (struct sync_folder_list *) rock;
    int mbtype;

    mboxlist_detail(name, &mbtype, NULL, NULL, NULL, NULL, NULL);
    if (!(mbtype & (MBTYPE_RESERVE | MBTYPE_MOVING | MBTYPE_REMOTE))) {
	sync_folder_list_add(list, NULL, name, NULL, 0, NULL);
    }
    return(0);
}

static int addmbox_sub(char *name,
		       int matchlen __attribute__((unused)),
		       int maycreate __attribute__((unused)),
		       void *rock)
{
    struct sync_folder_list *list = (struct sync_folder_list *) rock;

    sync_folder_list_add(list, name, name, NULL, 0, NULL);
    return(0);
}

/* ====================================================================== */

int do_mailbox_preload(struct sync_folder *folder)
{
    struct mailbox m;
    int r = 0;
    unsigned long msgno;
    struct index_record record;
    int lastuid = 0;

    if ((r=mailbox_open_header(folder->name, 0, &m)))
        return(r);

    if (!r) r = mailbox_open_index(&m);

    /* Quietly preload data from index */
    for (msgno = 1 ; msgno <= m.exists; msgno++) {
        mailbox_read_index_record(&m, msgno, &record);

        /* Fairly pointless, just to ensure that compiler doesn't
           optimise loop away somehow */
        if (record.uid <= lastuid)
            syslog(LOG_ERR, "cmd_status_work_sub(): UIDs out of order!");
    }

    mailbox_close(&m);
    return r;
}

int do_user_preload(char *user)
{
    char buf[MAX_MAILBOX_NAME+1];
    int r = 0;
    struct sync_folder_list *client_list = sync_folder_list_create();
    struct sync_folder *folder;

    /* Generate full list of folders on client side */
    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					  user, buf);
    addmbox(buf, 0, 0, (void *)client_list);

    strlcat(buf, ".*", sizeof(buf));
    r = (sync_namespace.mboxlist_findall)(&sync_namespace, buf, 1,
                                          user, NULL, addmbox,
                                          (void *)client_list);

    if (r) {
        syslog(LOG_ERR, "IOERROR: %s", error_message(r));
        sync_folder_list_free(&client_list);
        return(r);
    }

    for (folder = client_list->head ; folder ; folder = folder->next) {
        r = do_mailbox_preload(folder);

        if (r) break;
    }

    sync_folder_list_free(&client_list);
    return(r);
}

int do_user_main(char *user, struct sync_folder_list *server_list,
		 int *vanishedp)
{
    char buf[MAX_MAILBOX_NAME+1];
    int r = 0;
    struct sync_folder_list *client_list = sync_folder_list_create();

    /* Generate full list of folders on client side */
    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					  user, buf);
    addmbox(buf, 0, 0, (void *)client_list);

    strlcat(buf, ".*", sizeof(buf));
    r = (sync_namespace.mboxlist_findall)(&sync_namespace, buf, 1,
                                          user, NULL, addmbox,
                                          (void *)client_list);

    if (r) {
        syslog(LOG_ERR, "IOERROR: %s", error_message(r));
        return(r);
    }

    return(do_folders(client_list, server_list, vanishedp, 1, 1));
}

int do_user_sub(char *user, struct sync_folder_list *server_list)
{
    int r = 0;
    struct sync_folder_list *client_list = sync_folder_list_create();
    struct sync_folder *c, *s;
    int n;
    char buf[MAX_MAILBOX_NAME+1];

    /* Includes subsiduary nodes automatically */
    r = (sync_namespace.mboxlist_findsub)(&sync_namespace, "*", 1,
                                          user, NULL, addmbox_sub,
                                          (void *)client_list, 1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: %s", error_message(r));
        goto bail;
    }

    /* both lists are sorted, so we work our way through the lists
       top-to-bottom and determine what we need to do based on order */
    for (c = client_list->head,
	     s = server_list->head; c || s; c = c ? c->next : NULL) {
	if (!s) n = -1;		/* add all client subscriptions */
	else if (!c) n = 1;	/* remove all server subscriptions */
	else n = strcmp(c->name, s->name);

	if (n > 0) {
	    /* remove server subscriptions until we reach or pass the
	       current client subscription, or we reach the end of the
	       server list */
	    do {
		(sync_namespace.mboxname_tointernal)(&sync_namespace, s->name,
						     user, buf);
		if ((r = user_delsub(user, buf))) goto bail;
		s = s->next;
		if (!s) n = -1;		/* end of server list, we're done */
		else if (!c) n = 1;	/* remove all server subscriptions */
		else n = strcmp(c->name, s->name);
	    } while (n > 0);
	}

	if (n == 0) {
	    /* already subscribed, skip it */
	    s = s->next;
	}
	else if (c && n < 0) {
	    /* add the current client subscription */
	    if ((r = user_addsub(user, c->name))) goto bail;
	}
    }

 bail:
    sync_folder_list_free(&client_list);
    return(r);
}

static int do_user_seen(char *user)
{
    char *seen_file = seen_getpath(user);
    int filefd;
    const char *base;
    unsigned long len;
    struct stat sbuf;

    /* map file */
    filefd = open(seen_file, O_RDONLY, 0666);
    if (filefd == -1) {
	if (errno == ENOENT) {
	    /* its ok if it doesn't exist */
	    free(seen_file);
	    return 0;
	}
	syslog(LOG_ERR, "IOERROR: open on %s: %m", seen_file);
	return IMAP_SYS_ERROR;
    }
    
    if (fstat(filefd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", seen_file);
	fatal("can't fstat seen db", EC_OSFILE);
    }	

    base = NULL;
    len = 0;

    map_refresh(filefd, 1, &base, &len, sbuf.st_size, seen_file, NULL);

    close(filefd);
    free(seen_file);

    /* Update seen db */
    prot_printf(toserver, "SETSEEN_ALL ");
    sync_printastring(toserver, user);
    prot_printf(toserver, " {%lu+}\r\n", len);

    prot_write(toserver, base, len);
    map_free(&base, &len);

    prot_printf(toserver, "\r\n");
    prot_flush(toserver);

    return(sync_parse_code("SETSEEN_ALL",fromserver,SYNC_PARSE_EAT_OKLINE,NULL));
}

int do_user_sieve(char *user, struct sync_sieve_list *server_list)
{
    int r = 0;
    struct sync_sieve_list *client_list;
    struct sync_sieve_item *item, *item2;
    int client_active = 0;
    int server_active = 0;

    if ((client_list = sync_sieve_list_generate(user)) == NULL) {
        syslog(LOG_ERR, "Unable to list sieve scripts for %s", user);
        return(IMAP_IOERROR);
    }

    /* Upload missing and out of date scripts */
    for (item = client_list->head ; item ; item = item->next) {
        if ((item2 = sync_sieve_lookup(server_list, item->name))) {
            item2->mark = 1;
            if ((item2->last_update < item->last_update) &&
                (r=sieve_upload(user, item->name, item->last_update)))
                goto bail;
        } else if ((r=sieve_upload(user, item->name, item->last_update)))
            goto bail;
    }

    /* Delete scripts which no longer exist on the client */
    server_active = 0;
    for (item = server_list->head ; item ; item = item->next) {
        if (item->mark) {
            if (item->active) server_active = 1;
        } else if ((r=sieve_delete(user, item->name)))
            goto bail;
    }

    /* Change active script if necessary */
    client_active = 0;
    for (item = client_list->head ; item ; item = item->next) {
        if (!item->active)
            continue;

        client_active = 1;
        if (!((item2 = sync_sieve_lookup(server_list, item->name)) &&
              (item2->active))) {
            if ((r = sieve_activate(user, item->name)))
                goto bail;

            server_active = 1;
        }
        break;
    }

    if (!r && !client_active && server_active)
        r = sieve_deactivate(user);

 bail:
    sync_sieve_list_free(&client_list);
    return(r);
}

/* do_user() separated into two parts so that we can start process
 * asynchronously, come back and parse result when local list generated */

int do_user_start(char *user)
{
    prot_printf(toserver, "USER "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, "\r\n"); 
    prot_flush(toserver);
    return(0);
}

int do_user_parse(char *user,
		      struct sync_folder_list *server_list,
		      struct sync_folder_list *server_sub_list,
		      struct sync_sieve_list  *server_sieve_list)
{
    int r = 0;
    int c = ' ';
    int active = 0;
    int unsolicited_type;
    static struct buf id;
    static struct buf name;
    static struct buf time;
    static struct buf flag;
    static struct buf acl;
    static struct buf lastuid;
    static struct buf options;
    static struct buf arg;
    struct sync_folder *folder = NULL;
    struct sync_msg    *msg    = NULL;
    struct quota quota, *quotap;

    r = sync_parse_code("USER", fromserver,
                        SYNC_PARSE_NOEAT_OKLINE, &unsolicited_type);

    /* Unpleasant: translate remote access error into "please reset me" */
    if (r == IMAP_MAILBOX_NONEXISTENT)
        return(0);

    while (!r && (unsolicited_type > 0)) {
        switch (unsolicited_type) {
        case 4:
            /* New Sieve script */
            c = getastring(fromserver, toserver, &name);
            if (c != ' ') goto parse_err;
            c = getastring(fromserver, toserver, &time);
            if (c == ' ') {
                c = getastring(fromserver, toserver, &flag);
                if (!strcmp(flag.s, "*"))
                    active = 1;
            } else
                active = 0;

            if (c == '\r') c = prot_getc(fromserver);
            if (c != '\n') goto parse_err;
            sync_sieve_list_add(server_sieve_list,
                                name.s, atoi(time.s), active);
            break;
        case 3:
            /* New subscription */
            c = getastring(fromserver, toserver, &name);
            if (c == '\r') c = prot_getc(fromserver);
            if (c != '\n') goto parse_err;
            sync_folder_list_add(server_sub_list, name.s, name.s, NULL, 0, NULL);
            break;
        case 2:
            /* New folder */
            if ((c = getword(fromserver, &id)) != ' ')
                goto parse_err;
        
            if ((c = getastring(fromserver, toserver, &name)) != ' ')
                goto parse_err;

            if ((c = getastring(fromserver, toserver, &acl)) != ' ')
                goto parse_err;

            if ((c = getastring(fromserver, toserver, &lastuid)) != ' ')
                goto parse_err;

            c = getastring(fromserver, toserver, &options);

	    quotap = NULL;
	    if (c == ' ') {
		c = getword(fromserver, &arg);
		quota.limit = atoi(arg.s);
		quotap = &quota;
	    }

            if (c == '\r') c = prot_getc(fromserver);
            if (c != '\n') goto parse_err;
            if (!imparse_isnumber(lastuid.s)) goto parse_err;

            folder = sync_folder_list_add(server_list, id.s, name.s, acl.s,
					  sync_atoul(options.s), quotap);
            folder->msglist = sync_msg_list_create(NULL, sync_atoul(lastuid.s));
            break;
        case 1:
            /* New message in current folder */
            if (folder == NULL) goto parse_err;       /* No current folder */
            msg = sync_msg_list_add(folder->msglist);

            if (((c = getword(fromserver, &arg)) != ' ') ||
                ((msg->uid = sync_atoul(arg.s)) == 0)) goto parse_err;
            
            if (((c = getword(fromserver, &arg)) != ' ')) goto parse_err;

            if (!message_uuid_from_text(&msg->uuid, arg.s))
                goto parse_err;

            c = sync_getflags(fromserver, &msg->flags, &folder->msglist->meta);
            if (c == '\r') c = prot_getc(fromserver);
            if (c != '\n') goto parse_err;
            break;
        default:
            goto parse_err;
        }

        r = sync_parse_code("USER", fromserver,
                            SYNC_PARSE_EAT_OKLINE, &unsolicited_type);
    }

    return(r);

 parse_err:
    syslog(LOG_ERR, "USER: Invalid type %d response from server",
           unsolicited_type);
    sync_eatlines_unsolicited(fromserver, c);
    return(IMAP_PROTOCOL_ERROR);
}

int do_user_work(char *user, int *vanishedp)
{
    char buf[MAX_MAILBOX_NAME+1];
    int r = 0, mailbox_open = 0;
    struct sync_folder_list *server_list      = sync_folder_list_create();
    struct sync_folder_list *server_sub_list  = sync_folder_list_create();
    struct sync_sieve_list *server_sieve_list = sync_sieve_list_create();
    struct mailbox m;
    struct sync_folder *folder2;

    if (verbose) 
        printf("USER %s\n", user);

    if (verbose_logging)
        syslog(LOG_INFO, "USER %s", user);

    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					  user, buf);
    r = mailbox_open_header(buf, 0, &m);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* user has been removed, RESET server */
	r = user_reset(user);
	goto bail;
    }
    if (!r) mailbox_open = 1;
    if (!r) r = mailbox_open_index(&m);

    if (r) {
        if (mailbox_open) mailbox_close(&m);
        syslog(LOG_ERR, "IOERROR: Failed to open %s: %s",
               buf, error_message(r));
        r = IMAP_IOERROR;
        goto bail;
    }

    /* Get server started */
    do_user_start(user);

    /* Preload data at client end while server is working */
    do_user_preload(user);

    r = do_user_parse(user, server_list, server_sub_list, server_sieve_list);

    if (r) {
        sync_folder_list_free(&server_list);
        sync_folder_list_free(&server_sub_list);
        return(r);
    }

    /* Reset target account entirely if uniqueid of inbox doesn't match
     * (Most likely reason is that source account has been replaced)
     * Also if mailbox doesn't exist at all on target.
     */
    if (((folder2 = sync_folder_lookup_byname(server_list, m.name)) == NULL) ||
        (strcmp(m.uniqueid, folder2->id) != 0)) {
        r = user_reset(user);

        /* Reset local copies */
        sync_folder_list_free(&server_list);
        sync_folder_list_free(&server_sub_list);
        server_list     = sync_folder_list_create();
        server_sub_list = sync_folder_list_create();
    }

    mailbox_close(&m);

    if (!r) r = do_user_main(user, server_list, vanishedp);
    if (!r) r = do_user_sub(user, server_sub_list);
    if (!r) r = do_user_seen(user);
    if (!r) r = do_user_sieve(user, server_sieve_list);

 bail:
    sync_folder_list_free(&server_list);
    sync_folder_list_free(&server_sub_list);
    sync_sieve_list_free(&server_sieve_list);
    return(r);
}

static int do_user(char *user)
{
    struct sync_lock lock;
    int r = 0;
    int vanished = 0;

    /* Most of the time we don't need locking here: rename (the only
     * complicated case) is pretty rare, especially in the middle of the
     * night, which is when most of this will be going on */
    r = do_user_work(user, &vanished);

    /* Complication: monthly folder rotation causes rapid rename+create.
     *
     * mailbox_open_header() and mailbox_open_index() bail out with
     * IMAP_MAILBOX_BADFORMAT if they try to open a mailbox which is
     * currently in the process of being created. This is a nasty race
     * condition which imapd just ignores (presumably on the principle that
     * rapid rename+create+select would be very rare in normal use).
     *
     * We could solve this problem by putting a sync_lock() around
     * _every_ single replication operation, but this is tedious and would
     * probably involve quite a lot of overhead. As an experiment
     * catch IMAP_MAILBOX_BADFORMAT and have another go while locking out
     * user access to the mboxlist.
     */

    if (r == IMAP_MAILBOX_BADFORMAT)
        syslog(LOG_ERR,
               "do_user() IMAP_MAILBOX_BADFORMAT: retrying with snapshot");

    if ((r == IMAP_MAILBOX_BADFORMAT) || (vanished > 0)) {
        /* (vanished > 0): If we lost a folder in transit, lock the user
         * out of mboxlist for a few seconds while we retry. Will be a NOOP
         * if folder actually was deleted during do_user_work run.
         * Following just protects us against folder rename smack in the
         * middle of night or manual sys. admin inspired sync run */

        r = do_user_work(user, &vanished);
    }
    return(r);
}

/* ====================================================================== */

static int do_meta_sub(char *user)
{
    int unsolicited, c, r = 0;
    static struct buf name;
    struct sync_folder_list *server_list = sync_folder_list_create();

    prot_printf(toserver, "LSUB ");
    sync_printastring(toserver, user);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);
    r=sync_parse_code("LSUB",fromserver, SYNC_PARSE_EAT_OKLINE, &unsolicited);

    while (!r && unsolicited) {
        c = getastring(fromserver, toserver, &name);

        if (c == '\r') c = prot_getc(fromserver);
        if (c != '\n') {
            syslog(LOG_ERR, "LSUB: Invalid type %d response from server: %s",
                   unsolicited, name.s);
            sync_eatlines_unsolicited(fromserver, c);
            r = IMAP_PROTOCOL_ERROR;
            break;
        }
        sync_folder_list_add(server_list, name.s, name.s, NULL, 0, NULL);

        r = sync_parse_code("LSUB", fromserver,
                            SYNC_PARSE_EAT_OKLINE, &unsolicited);
    }

    if (!r) r = do_user_sub(user, server_list);

    sync_folder_list_free(&server_list);
    return(r);
}

static int do_meta_sieve(char *user)
{
    int unsolicited, c, r = 0;
    static struct buf name;
    static struct buf time;
    static struct buf flag;
    struct sync_sieve_list *server_list = sync_sieve_list_create();
    int active = 0;

    prot_printf(toserver, "LIST_SIEVE "); 
    sync_printastring(toserver, user);
    prot_printf(toserver, "\r\n");
    prot_flush(toserver);
    r=sync_parse_code("LIST_SIEVE", 
                      fromserver, SYNC_PARSE_EAT_OKLINE, &unsolicited);

    while (!r && unsolicited) {
        c = getastring(fromserver, toserver, &name);

        if (c != ' ') {
            syslog(LOG_ERR,
                   "LIST_SIEVE: Invalid name response from server: %s",
                   name.s);
            sync_eatlines_unsolicited(fromserver, c);
            r = IMAP_PROTOCOL_ERROR;
            break;
        }
        c = getastring(fromserver, toserver, &time);

        if (c == ' ') {
            c = getastring(fromserver, toserver, &flag);
            if (!strcmp(flag.s, "*"))
                active = 1;
        } else
            active = 0;

        if (c == '\r') c = prot_getc(fromserver);
        if (c != '\n') {
            syslog(LOG_ERR,
                   "LIST_SIEVE: Invalid flag response from server: %s",
                   flag.s);
            sync_eatlines_unsolicited(fromserver, c);
            r = IMAP_PROTOCOL_ERROR;
            break;
        }
        sync_sieve_list_add(server_list, name.s, atoi(time.s), active);

        r = sync_parse_code("LIST_SIEVE", fromserver,
                            SYNC_PARSE_EAT_OKLINE, &unsolicited);
    }
    if (r) {
        sync_sieve_list_free(&server_list);
        return(IMAP_IOERROR);
    }

    r = do_user_sieve(user, server_list);

    sync_sieve_list_free(&server_list);
    return(r);
}

static int do_sieve(char *user)   
{
    int r = 0;

    r = do_meta_sieve(user);

    return(r);
}

static int do_meta(char *user)   
{
    int r = 0;

    if (verbose)
        printf("META %s\n", user);

    if (verbose_logging)
        syslog(LOG_INFO, "META %s", user);

    if (!r) r = do_meta_sub(user);
    if (!r) r = do_user_seen(user);
    if (!r) r = do_meta_sieve(user);

    return(r);
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

#define SYNC_MAILBOX_RETRIES 3

static int do_sync(const char *filename)
{
    struct sync_user_list   *user_folder_list = sync_user_list_create();
    struct sync_user        *user;
    struct sync_action_list *user_list   = sync_action_list_create();
    struct sync_action_list *meta_list   = sync_action_list_create();
    struct sync_action_list *sieve_list  = sync_action_list_create();
    struct sync_action_list *mailbox_list= sync_action_list_create();
    struct sync_action_list *append_list = sync_action_list_create();
    struct sync_action_list *acl_list    = sync_action_list_create();
    struct sync_action_list *quota_list  = sync_action_list_create();
    struct sync_action_list *annot_list  = sync_action_list_create();
    struct sync_action_list *seen_list   = sync_action_list_create();
    struct sync_action_list *sub_list    = sync_action_list_create();
    struct sync_action_list *unsub_list  = sync_action_list_create();
    struct sync_folder_list *folder_list = sync_folder_list_create();
    static struct buf type, arg1, arg2;
    char *arg1s, *arg2s;
    char *userid;
    struct sync_action *action;
    int c;
    int fd;
    struct protstream *input;
    int r = 0;

    if ((filename == NULL) || !strcmp(filename, "-"))
        fd = 0;
    else {
        if ((fd = open(filename, O_RDWR)) < 0) {
            syslog(LOG_ERR, "Failed to open %s: %m", filename);
            return(IMAP_IOERROR);
        }

        if (lock_blocking(fd) < 0) {
            syslog(LOG_ERR, "Failed to lock %s: %m", filename);
            return(IMAP_IOERROR);
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

	if ((c = getastring(input, 0, &arg1)) == EOF)
            break;
        arg1s = arg1.s;

        if (c == ' ') {
            if ((c = getastring(input, 0, &arg2)) == EOF)
                break;
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
        else if (!strcmp(type.s, "APPEND"))
            sync_action_list_add(append_list, arg1s, NULL);
        else if (!strcmp(type.s, "ACL"))
            sync_action_list_add(acl_list, arg1s, NULL);
        else if (!strcmp(type.s, "QUOTA"))
            sync_action_list_add(quota_list, arg1s, NULL);
        else if (!strcmp(type.s, "ANNOTATION"))
            sync_action_list_add(annot_list, arg1s, NULL);
        else if (!strcmp(type.s, "SEEN"))
            sync_action_list_add(seen_list, arg2s, arg1s);
        else if (!strcmp(type.s, "SUB"))
            sync_action_list_add(sub_list, arg2s, arg1s);
        else if (!strcmp(type.s, "UNSUB"))
            sync_action_list_add(unsub_list, arg2s, arg1s);
        else
            syslog(LOG_ERR, "Unknown action type: %s", type.s);
    }

    /* Optimise out redundant clauses */

    for (action = user_list->head ; action ; action = action->next) {
	char inboxname[MAX_MAILBOX_NAME+1];

	/* USER action overrides any MAILBOX, APPEND, ACL, QUOTA, ANNOTATION action on
	   any of the user's mailboxes or any META, SIEVE, SEEN, SUB, UNSUB
	   action for same user */
	(sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
					      action->user, inboxname);
        remove_folder(inboxname, mailbox_list, 1);
        remove_folder(inboxname, append_list, 1);
        remove_folder(inboxname, acl_list, 1);
        remove_folder(inboxname, quota_list, 1);
        remove_folder(inboxname, annot_list, 1);
        remove_meta(action->user, meta_list);
        remove_meta(action->user, sieve_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
        remove_meta(action->user, unsub_list);
    }
    
    for (action = meta_list->head ; action ; action = action->next) {
	/* META action overrides any user SIEVE, SEEN, SUB, UNSUB action
	   for same user */
        remove_meta(action->user, sieve_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
        remove_meta(action->user, unsub_list);
    }

    for (action = mailbox_list->head ; action ; action = action->next) {
	/* MAILBOX action overrides any APPEND, ACL, QUOTA, ANNOTATION action
	   on same mailbox */
        remove_folder(action->name, append_list, 0);
        remove_folder(action->name, acl_list, 0);
        remove_folder(action->name, quota_list, 0);
        remove_folder(action->name, annot_list, 0);
    }

    /* Create a lock for our transaction */
    if ((r = send_lock())) goto cleanup;

    /* And then run tasks. */
    for (action = append_list->head ; action ; action = action->next) {
        if (!action->active)
            continue;

        if (do_append(action->name)) {
            sync_action_list_add(mailbox_list, action->name, NULL);
            if (verbose) {
                printf("  Promoting: APPEND %s -> MAILBOX %s\n",
                       action->name, action->name);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: APPEND %s -> MAILBOX %s",
                       action->name, action->name);
            }
        }
    }

    for (action = acl_list->head ; action ; action = action->next) {
        if (action->active && do_acl(action->name)) {
            sync_action_list_add(mailbox_list, action->name, NULL);
            if (verbose) {
                printf("  Promoting: ACL %s -> MAILBOX %s\n",
                       action->name, action->name);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: ACL %s -> MAILBOX %s",
                       action->name, action->name);
            }
        }
    }

    for (action = quota_list->head ; action ; action = action->next) {
        if (action->active && do_quota(action->name)) {
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

    for (action = annot_list->head ; action ; action = action->next) {
        if (action->active && do_annotation(action->name) && *action->name) {
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

    for (action = sieve_list->head ; action ; action = action->next) {
        if (action->active && do_sieve(action->user)) {
            sync_action_list_add(meta_list, NULL, action->user);
            if (verbose) {
                printf("  Promoting: SIEVE %s -> META %s\n",
                       action->user, action->user);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: SIEVE %s -> META %s",
                       action->user, action->user);
            }
        }
    }

    for (action = seen_list->head ; action ; action = action->next) {
        if (action->active && do_seen(action->user, action->name)) {
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

    for (action = sub_list->head ; action ; action = action->next) {
        if (action->active && user_addsub(action->user, action->name)) {
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

    for (action = unsub_list->head ; action ; action = action->next) {
        if (action->active && user_delsub(action->user, action->name)) {
            sync_action_list_add(meta_list, NULL, action->user);
            if (verbose) {
                printf("  Promoting: UNSUB %s %s -> META %s\n",
                       action->user, action->name, action->user);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: UNSUB %s %s -> META %s",
                       action->user, action->name, action->name);
            }
        }
    }
    for (action = mailbox_list->head ; action ; action = action->next) {
        if (!action->active)
            continue;

	sync_folder_list_add(folder_list, NULL, action->name, NULL, 0, NULL);
    }

    if (folder_list->count) {
	int n = 0;
	do {
	    sleep(n*2);  /* XXX  should this be longer? */
	    r = do_mailboxes(folder_list);
	    if (r) {
		/* promote failed personal mailboxes to USER */
		struct sync_folder *folder;
		char *userid, *p;

		for (folder = folder_list->head; folder && folder->mark;
		     folder = folder->next);
		if (folder &&
		    (userid = xstrdup(mboxname_isusermailbox(folder->name, 0)))) {
		    if ((p = strchr(userid, '.'))) *p = '\0';
		    folder->mark = 1;
		    if (--folder_list->count == 0) r = 0;

		    sync_action_list_add(user_list, NULL, userid);
		    if (verbose) {
			printf("  Promoting: MAILBOX %s -> USER %s\n",
			       folder->name, userid);
		    }
		    if (verbose_logging) {
			syslog(LOG_INFO, "  Promoting: MAILBOX %s -> USER %s",
			       folder->name, userid);
		    }
		    free(userid);
		}
	    }
	} while (r && (++n < SYNC_MAILBOX_RETRIES));

	if (r) goto bail;
    }

    for (action = meta_list->head ; action ; action = action->next) {
        if (action->active && (r=do_meta(action->user))) {
            if (r == IMAP_INVALID_USER) goto bail;

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

    for (action = user_list->head ; action ; action = action->next) {
	int n = 0;
	do {
	    sleep(n*2);  /* XXX  should this be longer? */
	    r = do_user(action->user);
	} while (r && (++n < SYNC_MAILBOX_RETRIES));

	if (r) goto bail;
    }

  bail:
    send_unlock();

  cleanup:
    if (r) {
	if (verbose)
	    fprintf(stderr, "Error in do_sync(): bailing out!\n");

	syslog(LOG_ERR, "Error in do_sync(): bailing out!");
    }

    sync_user_list_free(&user_folder_list);
    sync_action_list_free(&user_list);
    sync_action_list_free(&meta_list);
    sync_action_list_free(&sieve_list);
    sync_action_list_free(&mailbox_list);
    sync_action_list_free(&append_list);
    sync_action_list_free(&acl_list);
    sync_action_list_free(&quota_list);
    sync_action_list_free(&annot_list);
    sync_action_list_free(&seen_list);
    sync_action_list_free(&sub_list);
    sync_action_list_free(&unsub_list);
    sync_folder_list_free(&folder_list);

    prot_free(input);
    close(fd);

    return(r);
}

/* ====================================================================== */

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

    *restartp = 0;

    work_file_name = xmalloc(strlen(sync_log_file)+20);
    snprintf(work_file_name, strlen(sync_log_file)+20,
             "%s-%d", sync_log_file, getpid());

    session_start = time(NULL);

    while (1) {
        single_start = time(NULL);

        if (sync_shutdown_file && !stat(sync_shutdown_file, &sbuf)) {
            unlink(sync_shutdown_file);
            break;
        }

        if ((timeout > 0) && ((single_start - session_start) > timeout)) {
            *restartp = 1;
            break;
        }

        if (stat(sync_log_file, &sbuf) < 0) {
            if (min_delta > 0) {
                sleep(min_delta);
            } else {
                usleep(100000);    /* 1/10th second */
            }
            continue;
        }

        if (rename(sync_log_file, work_file_name) < 0) {
            syslog(LOG_ERR, "Rename %s -> %s failed: %m",
                   sync_log_file, work_file_name);
            exit(1);
        }

        if ((r=do_sync(work_file_name)))
            return(r);
        
        if (unlink(work_file_name) < 0) {
            syslog(LOG_ERR, "Unlink %s failed: %m", work_file_name);
            exit(1);
        }
        delta = time(NULL) - single_start;

        if ((delta < min_delta) && ((min_delta-delta) > 0))
            sleep(min_delta-delta);
    }
    free(work_file_name);

    if (*restartp == 0)
        return(0);

    prot_printf(toserver, "RESTART\r\n"); 
    prot_flush(toserver);

    r = sync_parse_code("RESTART", fromserver, SYNC_PARSE_EAT_OKLINE, NULL);

    if (r)
        syslog(LOG_ERR, "sync_client RESTART failed");
    else
        syslog(LOG_INFO, "sync_client RESTART succeeded");

    return(r);
}

struct backend *replica_connect(struct backend *be, const char *servername,
				sasl_callback_t *cb)
{
    int wait;

    for (wait = 15;; wait *= 2) {
	be = backend_connect(be, servername, &protocol[PROTOCOL_CSYNC],
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
	_exit(1);
    }

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

    /* for a child so we can release from master */
    if ((pid=fork()) < 0)
	fatal("fork failed", EC_SOFTWARE);

    if (pid != 0) { /* parent */
	cyrus_done();
	exit(0);
    }
    /* child */

    if (timeout == 0) {
        do_daemon_work(sync_log_file, sync_shutdown_file,
                       timeout, min_delta, &restart);
        return;
    }

    do {
        if ((pid=fork()) < 0)
            fatal("fork failed", EC_SOFTWARE);

        if (pid == 0) {
	    if (be->sock == -1) {
		/* Reopen up connection to server */
		be = replica_connect(be, be->hostname, cb);

		if (!be) {
		    fprintf(stderr, "Can not connect to server '%s'\n",
			    be->hostname);
		    _exit(1);
		}

		/* XXX  hack.  should just pass 'be' around */
		fromserver = be->in;
		toserver = be->out;
	    }

            r = do_daemon_work(sync_log_file, sync_shutdown_file,
                               timeout, min_delta, &restart);

            if (r)       _exit(1);
            if (restart) _exit(EX_TEMPFAIL);
            _exit(0);
        }
        if (waitpid(pid, &status, 0) < 0)
            fatal("waitpid failed", EC_SOFTWARE);
	backend_disconnect(be);
    } while (WIFEXITED(status) && (WEXITSTATUS(status) == EX_TEMPFAIL));
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
    MODE_SIEVE
};

int main(int argc, char **argv)
{
    int   opt, i = 0;
    char *alt_config     = NULL;
    char *input_filename = NULL;
    const char *servername = NULL;
    int   r = 0;
    int   exit_rc = 0;
    int   mode = MODE_UNKNOWN;
    int   wait     = 0;
    int   timeout  = 600;
    int   min_delta = 0;
    const char *sync_host = NULL;
    char sync_log_file[MAX_MAILBOX_PATH+1];
    const char *sync_shutdown_file = NULL;
    char buf[512];
    FILE *file;
    int len;
    struct backend *be = NULL;
    sasl_callback_t *cb;

    /* Global list */
    msgid_onserver = sync_msgid_list_create(SYNC_MSGID_LIST_HASH_SIZE);

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vlS:F:f:w:t:d:rumso")) != EOF) {
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

        case 'w':
            wait = atoi(optarg);
            break;

        case 't':
            timeout = atoi(optarg);
            break;

        case 'd':
            min_delta = atoi(optarg);
            break;

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
            mode = MODE_SIEVE;
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
    if ((r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);
    mailbox_initialize();

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

    /* XXX  hack.  should just pass 'be' around */
    fromserver = be->in;
    toserver = be->out;

    switch (mode) {
    case MODE_USER:
	if (input_filename) {
            if ((file=fopen(input_filename, "r")) == NULL) {
                syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
                shut_down(1);
            }
            while (!r && fgets(buf, sizeof(buf), file)) {
                /* Chomp, then ignore empty/comment lines. */
                if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                    buf[--len] = '\0';

                if ((len == 0) || (buf[0] == '#'))
                    continue;

		if ((r = send_lock())) {
		    if (verbose) {
			fprintf(stderr,
				"Error from send_lock(): bailing out!\n");
		    }
		    exit_rc = 1;
		}
		else {
		    if (do_user(buf)) {
			if (verbose)
			    fprintf(stderr,
				    "Error from do_user(%s): bailing out!\n",
				    buf);
			syslog(LOG_ERR, "Error in do_user(%s): bailing out!",
			       buf);
			exit_rc = 1;
		    }
		    send_unlock();
		}
	    }
            fclose(file);
        } else for (i = optind; !r && i < argc; i++) {
	    if ((r = send_lock())) {
		if (verbose) {
		    fprintf(stderr,
			    "Error from send_lock(): bailing out!\n");
		}
		exit_rc = 1;
	    }
	    else {
		if (do_user(argv[i])) {
		    if (verbose)
			fprintf(stderr, "Error from do_user(%s): bailing out!\n",
				argv[1]);
		    syslog(LOG_ERR, "Error in do_user(%s): bailing out!", argv[i]);
		    exit_rc = 1;
		}
		send_unlock();
	    }
	}
	break;

    case MODE_MAILBOX:
    {
	struct sync_folder_list *folder_list = sync_folder_list_create();
	struct sync_user   *user;
	char   *s, *t;

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

		if (!sync_folder_lookup_byname(folder_list, argv[i]))
		    sync_folder_list_add(folder_list,
					 NULL, argv[i], NULL, 0, NULL);
	    }
	    fclose(file);
	} else for (i = optind; i < argc; i++) {
	    if (!sync_folder_lookup_byname(folder_list, argv[i]))
		sync_folder_list_add(folder_list, NULL, argv[i], NULL, 0, NULL);
	}

	if ((r = send_lock())) {
	    if (verbose) {
		fprintf(stderr,
			"Error from send_lock(): bailing out!\n");
	    }
	    syslog(LOG_ERR, "Error in send_lock(): bailing out!");
	    exit_rc = 1;
	} else {
	    if (do_mailboxes(folder_list)) {
		if (verbose) {
		    fprintf(stderr,
			    "Error from do_mailboxes(): bailing out!\n");
		}
		syslog(LOG_ERR, "Error in do_mailboxes(): bailing out!");
		exit_rc = 1;
	    }
	    send_unlock();
	}

	sync_folder_list_free(&folder_list);
    }
    break;

    case MODE_SIEVE:
        for (i = optind; !r && i < argc; i++) {
	    if ((r = send_lock())) {
		if (verbose) {
		    fprintf(stderr,
			    "Error from send_lock(): bailing out!\n");
		}
		syslog(LOG_ERR, "Error in send_lock(): bailing out!");
		exit_rc = 1;
	    }
	    else {
		if (do_sieve(argv[i])) {
		    if (verbose) {
			fprintf(stderr,
				"Error from do_sieve(%s): bailing out!\n",
				argv[i]);
		    }
		    syslog(LOG_ERR, "Error in do_sieve(%s): bailing out!",
			   argv[i]);
		    exit_rc = 1;
		}
		send_unlock();
	    }
        }
	break;

    case MODE_REPEAT:
	if (input_filename) {
	    exit_rc = do_sync(input_filename);
	}
	else {
	    strlcpy(sync_log_file, config_dir, sizeof(sync_log_file));
	    strlcat(sync_log_file, "/sync/log", sizeof(sync_log_file));

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

    sync_msgid_list_free(&msgid_onserver);
    backend_disconnect(be);

  quit:
    shut_down(exit_rc);
}
