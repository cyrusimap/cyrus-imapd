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

#include "imapconf.h"
#include "imap_err.h"
#include "xmalloc.h"

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);

struct acapmbox_handle_s {
    acap_conn_t *conn;
};

char *acapmbox_get_url(char *name)
{
    static char url[4 * MAX_MAILBOX_PATH];

    imapurl_toURL(url, config_servername, name);

    return url;
}

/*
 * Get the acapconn. This should only be used if you need to get the
 * acapconn file descriptor
 */

acap_conn_t *acapmbox_get_acapconn(acapmbox_handle_t *AC)
{
    return AC->conn;
}

/* this should probably vary depending on whether it's a private
   mailbox or a bboard, and it should default to 
   "bb+bboard.name@server.name".
   currently, we don't set this for personal mailboxes */
char *acapmbox_get_postaddr(char *name)
{
    static char postaddr[MAX_MAILBOX_PATH + 30];

    if (!strncmp(name, "user.", 5)) {
	char *p;

	/* user+detail */
	strcpy(postaddr, name + 5);
	p = strchr(postaddr, '.');
	if (p) *p = '+';
	strcat(postaddr, "@");
	strcat(postaddr, config_servername);
    } else {
	const char *postspec = config_getstring("postspec", NULL);
	const char *BB = config_getstring("postuser", "bb");

	if (postspec) {
	    snprintf(postaddr, sizeof(postaddr), postspec, name);
	} else {
	    snprintf(postaddr, sizeof(postaddr), "%s+%s@%s", BB,
		     name, config_servername);
	}
    }

    return postaddr;
}

static acapmbox_handle_t *cached_conn = NULL;

void acapmbox_disconnect(acapmbox_handle_t *conn)
{

    if (conn == cached_conn) {

	acap_conn_close(conn);
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

    cached_conn = (acapmbox_handle_t *) xmalloc(sizeof(acapmbox_handle_t));
    cached_conn->conn = NULL;
    
    user = config_getstring("acap_username", NULL);
    if (user == NULL) {
	syslog(LOG_ERR, "unable to find option acap_username");
	return cached_conn;
    }

    cb = mysasl_callbacks(user,
			  config_getstring("acap_authname", user),
			  config_getstring("acap_realm", NULL),
			  config_getstring("acap_password", NULL));

    authprog = config_getstring("acap_getauth", NULL);
    if (authprog) {
	system(authprog);
    }

    r = sasl_client_init(cb);
    if (r != SASL_OK) {
	syslog(LOG_ERR, "sasl_client_init() failed: %s",
	       sasl_errstring(r, NULL, NULL));
	return cached_conn;
    }

    snprintf(str, sizeof(str), "acap://%s@%s/", user, acapserver);

    r = acap_conn_connect(str, &(cached_conn->conn));
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

void acapmbox_cb(acap_result_t res, void *rock)
{
    printf("in callback\n");
}

/*
 * Create the full dataset with entry name
 *
 */

static char *create_full_dataset_name(char *mailbox_name)
{
    static char fullname[MAX_MAILBOX_PATH];

    /* needs to convert from mUTF7 to UTF-8 */
    snprintf(fullname, sizeof(fullname), "%s/%s", 
	     global_dataset, mailbox_name);

    return fullname;
}

int add_attr(skiplist *sl, char *name, char *value)
{
    acap_attribute_t *tmpattr;

    tmpattr = acap_attribute_new_simple (name, value);
    if (tmpattr) sinsert(sl, tmpattr);

    return 0;
}

int acapmbox_store(acapmbox_handle_t *AC,
		   acapmbox_data_t *mboxdata,
		   int commit)
{
    int result;
    acap_entry_t *newentry;
    acap_result_t acapres;

    acap_cmd_t *cmd;
    char *fullname;
    char tmpstr[30];

    if (AC == NULL) return 0;
    assert(mboxdata);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* create the new entry */
    fullname = create_full_dataset_name(mboxdata->name);
    if (fullname == NULL) return ACAP_NOMEM;

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) return ACAP_NOMEM;

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
			      commit ? 0 : ACAP_STORE_INITIAL,
			      &cmd);
    if (result == ACAP_OK) {
	result = acap_process_on_command(AC->conn, cmd, &acapres);
	if (result == ACAP_NO_CONNECTION) {
	    result = IMAP_SERVER_UNAVAILABLE;
	} else if (acapres != ACAP_RESULT_OK) {
	    /* this is a likely but not certain error */
	    result = IMAP_MAILBOX_EXISTS;
	}
    }

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

static struct acap_search_callback myacap_search_cb = {
    &myacap_entry, &myacap_modtime
};

static struct acap_requested myacap_request = {
    1, { "entry" }
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
    if (search_crit==NULL) return ACAP_NOMEM;

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
    char *fullname;
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
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) return ACAP_NOMEM;

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

    /* create the cmd; if it's the first time through, we ACAP_STORE_INITIAL */
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
	    /* this is a likely but not certain error */
	    result = IMAP_MAILBOX_EXISTS;
	}
    }

    return result;    

}

int acapmbox_setproperty(acapmbox_handle_t *AC,
			 char *mailbox_name,
			 acapmbox_property_t prop,
			 int value)
{
    int result;
    char *fullname;
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
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

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
    if (tmpattr==NULL) return ACAP_NOMEM;

    /* issue store command */
    result = acap_store_attribute(AC->conn,
				  fullname,
				  tmpattr,
				  NULL, /* don't care about unchangedsince */
				  NULL,
				  NULL,
				  &cmd);

    /* get result of command */
    result = acap_process_on_command(AC->conn, cmd, NULL);
    if (result != ACAP_OK) {
	printf("failure on command\n");
    }

    /* xxx free memory */

    return result;
}


int acapmbox_setproperty_acl(acapmbox_handle_t *AC,
			     char *mailbox_name,
			     char *newvalue)
{
    int result;
    char *fullname;
    acap_cmd_t *cmd;
    acap_attribute_t *tmpattr;
    char *attrname;

    if (AC == NULL) return 0;
    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* get the entry path */
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

    /* create the attribute */
    attrname = "mailbox.acl";

    tmpattr = acap_attribute_new_simple (attrname,newvalue);

    if (tmpattr==NULL) return ACAP_NOMEM;

    /* issue store command */
    result = acap_store_attribute(AC->conn,
				  fullname,
				  tmpattr,
				  NULL, /* don't care about unchangedsince */
				  NULL,
				  NULL,
				  &cmd);

    /* get result of command */
    result = acap_process_on_command(AC->conn, cmd, NULL);
    if (result != ACAP_OK) {
	printf("failure on command\n");
    }

    /* xxx free memory */

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

static void myacap_copy_modtime(char *modtime, void *rock)
{
    printf("\tmodtime = %s\n", modtime);
}

int acapmbox_delete(acapmbox_handle_t *AC,
		    char *mailbox_name)
{
    acap_cmd_t *cmd;
    int r;
    char *fullname;

    if (AC == NULL) return 0;
    assert(mailbox_name != NULL);
    if (AC->conn == NULL) {
	return IMAP_SERVER_UNAVAILABLE;
    }

    /* create the new entry */
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

    r = acap_delete_entry_name(AC->conn,
			       fullname,
			       NULL,
			       NULL,
			       &cmd);
    if (!r) r = acap_process_on_command(AC->conn, cmd, NULL);

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
    len = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family);

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
