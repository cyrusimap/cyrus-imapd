/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 */


#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <com_err.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <acap.h>
#include "acapmbox.h"
#include "mailbox.h"
#include "assert.h"
#include "imapurl.h"
#include "exitcodes.h"

#include "imapconf.h"
#include "imap_err.h"
#include "xmalloc.h"

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);
extern void free_callbacks(sasl_callback_t *in);

struct acapmbox_handle_s {
    acap_conn_t *conn;
};

/* server may be NULL.
   dst should be MAX_MAILBOX_PATH */
static char *acapmbox_get_url(char *dst, const char *server, const char *name)
{
    if (!server) server = config_servername;
    imapurl_toURL(dst, server, name);

    return dst;
}

/* this varies depending on whether it's a private
   mailbox or a bboard, and it should default to 
   "bb+bboard.name@server.name". */
/* postaddr should be MAX_MAILBOX_PATH */
char *acapmbox_get_postaddr(char *postaddr, 
			    const char *server, const char *name)
{
    if (!server) server = config_servername;
    if (!strncmp(name, "user.", 5)) {
	char *p;

	/* user+detail */
	strcpy(postaddr, name + 5);
	p = strchr(postaddr, '.');
	if (p) *p = '+';
	strcat(postaddr, "@");
	strcat(postaddr, server);
    } else {
	const char *postspec = config_getstring("postspec", NULL);
	const char *BB = config_getstring("postuser", "bb");

	if (postspec) {
	    snprintf(postaddr, sizeof(postaddr), postspec, name);
	} else {
	    snprintf(postaddr, sizeof(postaddr), "%s+%s@%s", BB,
		     name, server);
	}
    }

    return postaddr;
}

/*
 * generate an entry
 *
 * 'mboxdata' need not be initialized but must be allocated
 * 'server' may be NULL
 */
acapmbox_data_t *acapmbox_new(acapmbox_data_t *mboxdata, 
			      const char *server, 
			      const char *name)
{
    assert(mboxdata != NULL);
    assert(name != NULL);

    memset(mboxdata, 0, sizeof(acapmbox_data_t));
    strcpy(mboxdata->name, name);
    acapmbox_get_postaddr(mboxdata->post, server, name);
    acapmbox_get_url(mboxdata->url, server, name);

    return mboxdata;
}


/*
 * Get the acapconn. This should only be used if you need to get the
 * acapconn file descriptor
 */

acap_conn_t *acapmbox_get_acapconn(acapmbox_handle_t *AC)
{
    return AC->conn;
}

static acapmbox_handle_t *cached_conn = NULL;
#ifdef DELAY_SASL_CLIENT_INIT
static int did_sasl_client_init = 0;
#endif

void acapmbox_disconnect(acapmbox_handle_t *conn)
{
    if (conn == cached_conn) {
	acap_conn_close(conn->conn);
	free(conn);
	/* xxx free memory */
	cached_conn = NULL;
    }
}

acapmbox_handle_t *acapmbox_get_handle(void)
{
    int r;
    char str[2048];
    const char *acapserver;

    const char *user;
    const char *authprog;
    sasl_callback_t *cb;
    
    acapserver = config_getstring("acap_server", NULL);
    if (!acapserver) return NULL;

    if (cached_conn) {
	/* xxx verify cached_conn is still a valid connection */
	return cached_conn;
    }
#ifdef DELAY_SASL_CLIENT_INIT
    if (!did_sasl_client_init) {
	if ((r = sasl_client_init(NULL)) != SASL_OK) {
	    syslog(LOG_ERR, "failed initializing: sasl_client_init(): %s", 
		   sasl_errstring(r, NULL, NULL));
	    return NULL;
	}
	did_sasl_client_init = 1;
    }
#endif

    cached_conn = (acapmbox_handle_t *) xmalloc(sizeof(acapmbox_handle_t));
    cached_conn->conn = NULL;
    
    user = config_getstring("acap_username", NULL);
    if (user == NULL) {
	syslog(LOG_ERR, "unable to find option acap_username");
	return cached_conn;
    }

    authprog = config_getstring("acap_getauth", NULL);
    if (authprog) {
	system(authprog);
    }

    cb = mysasl_callbacks(user,
			  config_getstring("acap_authname", user),
			  config_getstring("acap_realm", NULL),
			  config_getstring("acap_password", NULL));
    snprintf(str, sizeof(str), "acap://%s@%s/", user, acapserver);
    r = acap_conn_connect(str, cb, &(cached_conn->conn));
    free_callbacks(cb);

    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_conn_connect() failed: %s",
	       error_message(r));
	acap_conn_close(cached_conn->conn);
	cached_conn->conn = NULL;
	return cached_conn;
    }
    syslog(LOG_INFO, "ACAP: opened connection to %s", acapserver);

    return cached_conn;
}

void acapmbox_release_handle(acapmbox_handle_t *handle)
{
    /* NOOP */
}

/*
 * Create the full dataset with entry name
 * 'ret' must be at least MAX_MAILBOX_PATH
 *
 */

int acapmbox_dataset_name(const char *mailbox_name, char *ret)
{
    int j;

    /* needs to convert from mUTF7 to UTF-8 */
    snprintf(ret, MAX_MAILBOX_PATH, "%s/%s",  global_dataset, mailbox_name);
    for (j = strlen(global_dataset); ret[j] != '\0'; j++) {
	if (ret[j] == '.') ret[j] = '/';
    }

    return 0;
}

/* do the reverse of above */
int acapmbox_decode_entry(const char *entryname, char *ret)
{
    int j;
    int gdlen = strlen(global_dataset);

    *ret = '\0';
    if (strncmp(entryname, global_dataset, gdlen)) {
	return IMAP_MAILBOX_BADNAME;
    }

    if (strlen(entryname + gdlen) > MAX_MAILBOX_NAME) {
	return IMAP_MAILBOX_BADNAME;
    }

    strcpy(ret, entryname + gdlen + 1);
    for (j = 0; ret[j] != '\0'; j++) {
	if (ret[j] == '/') ret[j] = '.';
    }

    return 0;
}

int add_attr(skiplist *sl, char *name, char *value)
{
    acap_attribute_t *tmpattr;

    tmpattr = acap_attribute_new_simple (name, value);
    if (tmpattr) sinsert(sl, tmpattr);

    return 0;
}

static void nab_entrycb(acap_entry_t *entry, void *rock)
{
    acap_entry_t **ret = (acap_entry_t **) rock;

    *ret = acap_entry_copy(entry);
}

static struct acap_search_callback nab_search_cb = {
    &nab_entrycb, NULL
};

static struct acap_requested nab_request = {
    1, {{"*" , 0 }}
};

/* returns the entry associated with 'entryname'.  returns NULL
   if it doesn't exist or other ACAP error occurs. */
static acap_entry_t *nab_entry(acap_conn_t *conn, const char *entryname)
{
    int r = 0;
    char dset[MAX_MAILBOX_PATH];
    char ent[50 + MAX_MAILBOX_PATH];
    char *p;
    acap_entry_t *ret = NULL;
    acap_cmd_t *cmd;

    strcpy(dset, entryname);
    p = strrchr(dset, '/');
    assert(p != NULL);

    p++;
    sprintf(ent, "EQUAL \"entry\" \"i;octet\" \"%s\"", p);
    *p = '\0';

    r = acap_search_dataset(conn, dset, ent, 1,
			    &nab_request, NULL,
			    NULL,
			    &nab_search_cb,
			    NULL, NULL,
			    &ret,
			    &cmd);
    if (r == ACAP_OK) {
	r = acap_process_on_command(conn, cmd, NULL);
    }

    if (r == ACAP_OK) {
	return ret;
    } else {
	return NULL;
    }
}

int acapmbox_store(acapmbox_handle_t *AC,
		   acapmbox_data_t *mboxdata,
		   int commit)
{
    int result;
    int retry = 0;
    acap_entry_t *newentry;
    acap_result_t acapres;

    acap_cmd_t *cmd;
    char fullname[MAX_MAILBOX_PATH];
    char tmpstr[30];

    if (AC == NULL) return 0;
    assert(mboxdata);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* create the new entry */
    result = acapmbox_dataset_name(mboxdata->name, fullname);
    if (result) return result;

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) fatal("out of memory", EC_TEMPFAIL);

 retry:
    /* make and insert all our initial attributes */
    snprintf(tmpstr, sizeof(tmpstr), "%d", mboxdata->uidvalidity);
    add_attr(newentry->attrs, "mailbox.uidvalidity", tmpstr);

    add_attr(newentry->attrs, "mailbox.status", 
	     commit ? "committed" : "reserved");

    add_attr(newentry->attrs, "mailbox.post", mboxdata->post);

    add_attr(newentry->attrs, "mailbox.haschildren", 
	     mboxdata->haschildren ? "yes" : "no");

    add_attr(newentry->attrs, "mailbox.url", mboxdata->url);

    add_attr(newentry->attrs, "mailbox.acl", mboxdata->acl);

    snprintf(tmpstr, sizeof(tmpstr), "%d", mboxdata->answered);
    add_attr(newentry->attrs, "mailbox.answered", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", mboxdata->flagged);
    add_attr(newentry->attrs, "mailbox.flagged", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", mboxdata->deleted);
    add_attr(newentry->attrs, "mailbox.deleted", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", mboxdata->total);
    add_attr(newentry->attrs, "mailbox.total", tmpstr);

    /* create the cmd; if it's the first time through, we ACAP_STORE_INITIAL */
    result = acap_store_entry(AC->conn,
			      newentry,
			      NULL,
			      NULL,
			      (commit || retry) ? 0 : ACAP_STORE_INITIAL,
			      &cmd);
    if (result == ACAP_OK) {
	result = acap_process_on_command(AC->conn, cmd, &acapres);
	switch (result) {
	case ACAP_OK:
	    switch (acapres) {
	    case ACAP_RESULT_OK:
		/* good */
		break;

	    case ACAP_RESULT_NO:
	    case ACAP_RESULT_BAD:
		/* we'll treat these the same */
		if (commit) {
		    /* this shouldn't have happened */
		    result = IMAP_IOERROR;
		} else {
		    /* unfortunately, we could be in the situation where a
		       child mailbox exists but we don't. */
		    acap_entry_free(newentry);
		    newentry = NULL;

		    /* search against the ACAP server to find current entry
		     and it's modtime */
		    newentry = nab_entry(AC->conn, fullname);

		    /* does the mailbox exist? check 'mailbox.status' */
		    if (newentry && 
			!acap_entry_getattr_simple(newentry, "mailbox.status"))
		    {
		        /* retry store */
			syslog(LOG_DEBUG, "ACAP: retrying reservation of '%s'",
			       mboxdata->name);

			retry = 1;
			goto retry;
		    } else {
			result = IMAP_MAILBOX_EXISTS;
		    }
		}
		break;

	    case ACAP_RESULT_NOTDONE:
		fatal("acap command finished but not done?", EC_SOFTWARE);
		break;
	    }
	    break;
	    
	case ACAP_NO_CONNECTION:
	    result = IMAP_SERVER_UNAVAILABLE;
	    break;

	default:
	    /* yikes, we didn't expect anything else; we'll leave the
	     error as is */
	    break;
	}
    }

    if (newentry) acap_entry_free(newentry);
    return result;
}

int acapmbox_create(acapmbox_handle_t *AC,
		    acapmbox_data_t *mboxdata)
{
    return acapmbox_store(AC, mboxdata, 0);
}
		
int acapmbox_markactive(acapmbox_handle_t *AC,
			acapmbox_data_t *mboxdata)
{
    return acapmbox_store(AC, mboxdata, 1);
}

static void myacap_entry(acap_entry_t *entry, void *rock)
{
    int *num = (int *) rock;
    skipnode *node;
    acap_attribute_t *attr;

    printf("\tentry = %s\n", entry->name);
    attr = sfirst(entry->attrs, &node);
    while (attr) {
	printf("\t\t%s = %s\n", attr->name, attr->v->data);

	attr = snext(&node);
    }

    /* indicate we saw something */
    *num = 1;
}

static void myacap_modtime(char *modtime, void *rock)
{
    printf("\tmodtime = %s\n", modtime);
}

static const struct acap_search_callback myacap_search_cb = {
    &myacap_entry, &myacap_modtime
};

static const struct acap_requested myacap_request = {
    1, {{"entry" , 0x00}}
};

/*
 * Returns:
 *   ACAP_OK -> does exist
 *   ACAP_FAIL -> doesn't exist
 *   other   -> error
 *   
 */

int acapmbox_entryexists(acapmbox_handle_t *AC,
			 char *mailbox_name)
{
    acap_cmd_t *cmd;
    int r;
    char *search_crit;
    int exists = 0;

    if (AC == NULL) return 0;
    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* create search criteria */
    search_crit = (char *) malloc(strlen(mailbox_name)+30);
    if (search_crit==NULL) fatal("out of memory", EC_TEMPFAIL);

    sprintf(search_crit,"EQUAL \"entry\" \"i;octet\" \"%s\"",mailbox_name);

    r = acap_search_dataset(AC->conn, global_dataset,
			    search_crit, 1,
			    &myacap_request, NULL,
			    NULL,
			    &myacap_search_cb,
			    NULL, NULL, 
			    &exists, 
			    &cmd);
    if (r != ACAP_OK) {
	return r;
    }

    r = acap_process_on_command(AC->conn, cmd, NULL);
    if (r != ACAP_OK) {
	return r;
    }
    
    return (exists == 0) ? ACAP_FAIL : ACAP_OK;
}

int acapmbox_setsomeprops(acapmbox_handle_t *AC,
			  char *mailbox_name,
			  int uidvalidity,
			  int exists,
			  int deleted,
			  int flagged,
			  int answered)
{
    int result;
    char fullname[MAX_MAILBOX_PATH];
    acap_cmd_t *cmd;
    acap_entry_t *newentry;
    acap_result_t acapres;
    char tmpstr[30];

    if (AC == NULL) return 0;

    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* get the entry path */
    result = acapmbox_dataset_name(mailbox_name, fullname);
    if (result) return result;

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) fatal("out of memory", EC_TEMPFAIL);

    /* make and insert all our attributes */
    snprintf(tmpstr, sizeof(tmpstr), "%d", uidvalidity);
    add_attr(newentry->attrs, "mailbox.uidvalidity", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", answered);
    add_attr(newentry->attrs, "mailbox.answered", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", flagged);
    add_attr(newentry->attrs, "mailbox.flagged", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", deleted);
    add_attr(newentry->attrs, "mailbox.deleted", tmpstr);

    snprintf(tmpstr, sizeof(tmpstr), "%d", exists);
    add_attr(newentry->attrs, "mailbox.total", tmpstr);

    result = acap_store_entry(AC->conn,
			      newentry,
			      NULL,
			      NULL,
			      0,
			      &cmd);
    if (result == ACAP_OK) {
	result = acap_process_on_command(AC->conn, cmd, &acapres);
	if (result == ACAP_NO_CONNECTION) {
	    result = IMAP_SERVER_UNAVAILABLE;
	} else if (acapres != ACAP_RESULT_OK) {
	    result = IMAP_IOERROR;
	}
    }

    acap_entry_free(newentry);

    return result;    
}

int acapmbox_setproperty(acapmbox_handle_t *AC,
			 char *mailbox_name,
			 acapmbox_property_t prop,
			 int value)
{
    int result;
    char fullname[MAX_MAILBOX_PATH];
    acap_cmd_t *cmd;
    acap_attribute_t *tmpattr;
    char *attrname;
    char attrvalue[30];

    if (AC == NULL) return 0;
    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* get the entry path */
    result = acapmbox_dataset_name(mailbox_name, fullname);
    if (result) return result;

    /* create the attribute */
    switch (prop) {
    case ACAPMBOX_ANSWERED: 
	attrname = "mailbox.answered";
	break;
    case ACAPMBOX_FLAGGED:
	attrname = "mailbox.flagged";
	break;
    case ACAPMBOX_DELETED:
	attrname = "mailbox.deleted";
	break;
    case ACAPMBOX_TOTAL:
	attrname = "mailbox.total";
	break;
    default:
	return ACAP_BAD_PARAM;
	break;
    }

    snprintf(attrvalue, sizeof(attrvalue), "%d", value);
    
    tmpattr = acap_attribute_new_simple (attrname,attrvalue);
    if (tmpattr==NULL) fatal("out of memory", EC_TEMPFAIL);

    /* issue store command */
    result = acap_store_attribute(AC->conn,
				  fullname,
				  tmpattr,
				  NULL, /* don't care about unchangedsince */
				  NULL,
				  NULL,
				  &cmd);
    
    if (result == ACAP_OK) {
	result = acap_process_on_command(AC->conn, cmd, NULL);
    }
    if (result != ACAP_OK) {
	syslog(LOG_ERR, "couldn't update ACAP attribute: %s",
	       error_message(result));
    }

    acap_attribute_free(tmpattr);

    return result;
}


int acapmbox_setproperty_acl(acapmbox_handle_t *AC,
			     char *mailbox_name,
			     char *newvalue)
{
    int result;
    char fullname[MAX_MAILBOX_PATH];
    acap_cmd_t *cmd;
    acap_attribute_t *tmpattr;
    char *attrname;

    if (AC == NULL) return 0;
    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* get the entry path */
    result = acapmbox_dataset_name(mailbox_name, fullname);
    if (result) return result;

    /* create the attribute */
    attrname = "mailbox.acl";

    tmpattr = acap_attribute_new_simple (attrname,newvalue);

    if (tmpattr==NULL) fatal("out of memory", EC_TEMPFAIL);

    /* issue store command */
    result = acap_store_attribute(AC->conn,
				  fullname,
				  tmpattr,
				  NULL, /* don't care about unchangedsince */
				  NULL,
				  NULL,
				  &cmd);

    if (result == ACAP_OK) {
	result = acap_process_on_command(AC->conn, cmd, NULL);
    }
    if (result != ACAP_OK) {
	syslog(LOG_ERR, "couldn't update ACAP attribute: %s",
	       error_message(result));
    }

    acap_attribute_free(tmpattr);

    return result;
}


acapmbox_status mboxdata_convert_status(acap_value_t *v)
{
    char *s = v->data;

    if (!s || v->next) return ACAPMBOX_UNKNOWN;

    if (s && (*s == 'c' || *s == 'C')) return ACAPMBOX_COMMITTED;
    else if (s && (*s == 'r' || *s == 'R')) return ACAPMBOX_RESERVED;
    else return ACAPMBOX_UNKNOWN;
}

int acapmbox_delete(acapmbox_handle_t *AC,
		    char *mailbox_name)
{
    acap_cmd_t *cmd;
    int r;
    char fullname[MAX_MAILBOX_PATH];
    acap_entry_t *entry;

    if (AC == NULL) return 0;
    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* create the new entry */
    r = acapmbox_dataset_name(mailbox_name, fullname);
    if (r) return r;

    /* we can't just delete the entry, since that will delete subdatasets
       of the entry, as well.  instead, we just delete "mailbox.status"
       and "mailbox.url". */
    entry = acap_entry_new(fullname);
    if (entry == NULL) fatal("out of memory", EC_TEMPFAIL);

    add_attr(entry->attrs, "mailbox.status", NULL);
    add_attr(entry->attrs, "mailbox.url", NULL);

    r = acap_store_entry(AC->conn, entry, NULL, NULL, 0, &cmd);
    if (!r) r = acap_process_on_command(AC->conn, cmd, NULL);
    
    acap_entry_free(entry);

    return r;
}

int acapmbox_deleteall(acapmbox_handle_t *AC)
{
    acap_cmd_t *cmd;
    int r;

    if (AC==NULL) return ACAP_OK;

    r = acap_delete_entry_name(AC->conn,
			       global_dataset,
			       NULL,
			       NULL,
			       &cmd);
    if (!r) r = acap_process_on_command(AC->conn, cmd, NULL);

    return r;
}

void acapmbox_kick_target(void)
{
    char buf[1024];
    struct sockaddr_un srvaddr;
    int s, r;
    int len;
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	return;
    }

    strcpy(buf, config_dir);
    strcat(buf, FNAME_TARGET_SOCK);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, buf);
    len = sizeof(srvaddr.sun_family) + strlen(srvaddr.sun_path) + 1;

    r = connect(s, (struct sockaddr *)&srvaddr, len);
    if (r == -1) {
	syslog(LOG_ERR, "acapmbox_kick_target: can't connect to target: %m");
	close(s);
	return;
    }

    r = read(s, &buf, sizeof(buf));
    if (r <= 0) {
	syslog(LOG_ERR, "acapmbox_kick_target: can't read from target: %m");
	close(s);
	return;
    }

    /* if we got here, it's been kicked */
    close(s);
    return;
}
