#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "acap.h"
#include "acapmbox.h"

#include "config.h"
#include "imap_err.h"

char *global_dataset = "/mb";

struct acapmbox_handle_s {

    acap_conn_t *conn;

};

acapmbox_handle_t *acapmbox_get_handle(void)
{
    int r;
    char str[2048];
    const char *acapserver;
    static acapmbox_handle_t *cached_conn = NULL;
    const char *user;
    sasl_callback_t *cb;

    acapserver = config_getstring("acap_server", NULL);
    if (!acapserver) return NULL;

    if (cached_conn) {
	/* verify cached_conn is still a valid connection */
	return cached_conn;
    }

    user = config_getstring("acap_username", NULL);
    if (user == NULL) {
	syslog(LOG_ERR, "unable to find option acap_authname");
	return NULL;
    }

    /* these aren't required */
    /*    acap_password = config_getstring("acap_password", NULL);
	  acap_realm = config_getstring("acap_realm", NULL);*/
    
    cb = mysasl_callbacks(user,
			  config_getstring("acap_authname", user),
			  config_getstring("acap_realm", NULL),
			  config_getstring("acap_password", NULL));

    r = sasl_client_init(cb);
    if (r != SASL_OK) {
	syslog(LOG_ERR, "sasl_client_init() failed");
	return NULL;
    }

    snprintf(str, sizeof(str), "acap://%s@%s/",config_getstring("acap_authname",NULL),acapserver);

    cached_conn = malloc(sizeof(acapmbox_handle_t));
    
    r = acap_conn_connect(str, &(cached_conn->conn));
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_conn_connect() failed");
	return NULL;
    }

    return cached_conn;
}

void acapmbox_cb(acap_result_t res, void *rock)
{
    printf("in callback\n");
}

/*
 * Create the full dataset with entry name
 *
 */

char *create_full_dataset_name(char *mailbox_name)
{
    char * fullname = (char *) malloc( strlen(global_dataset) + strlen(mailbox_name) + 1);
    if (fullname == NULL) return NULL;

    strcpy(fullname, global_dataset);
    strcat(fullname, "/");
    strcat(fullname, mailbox_name);

    return fullname;
}

int add_attr(skiplist *sl, char *name, char *value)
{
    acap_attribute_t *tmpattr;

    tmpattr = acap_attribute_new_simple (name, value);
    if (tmpattr==NULL) return ACAP_NOMEM;
    sinsert( sl, tmpattr);

    return ACAP_OK;
}

int acapmbox_create(acapmbox_handle_t *AC,
		    char *mailbox_name,
		    acapmbox_data_t *mboxdata_p)
{
    int result;
    acap_entry_t *newentry;

    acap_cmd_t *cmd;
    char *fullname;
    char tmpstr[30];
    acapmbox_data_t mboxdata;

    if (AC==NULL) return ACAP_OK;

    
    if (mboxdata_p==NULL) {
	memset(&mboxdata,'\0',sizeof(acapmbox_data_t));
    } else {
	memcpy(&mboxdata,mboxdata_p, sizeof(acapmbox_data_t));
    }

    /* verify arguements */
    if ((AC->conn==NULL) || (mailbox_name==NULL))
    {
	return ACAP_FAIL;
    }

    /* create the new entry */
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

    newentry = acap_entry_new(fullname);    
    if (newentry==NULL) return ACAP_NOMEM;

    /* make and insert all our initial attributes */
    snprintf(tmpstr,sizeof(tmpstr),"%d",mboxdata.uidvalidity);
    add_attr(newentry->attrs, "mailbox.uidvalidity", tmpstr);

    add_attr(newentry->attrs, "mailbox.status", "reserved");

    add_attr(newentry->attrs, "mailbox.post", mboxdata.post);

    if (mboxdata.haschildren==1)
	add_attr(newentry->attrs, "mailbox.haschildren", "yes");
    else
	add_attr(newentry->attrs, "mailbox.haschildren", "no");

    add_attr(newentry->attrs, "mailbox.url", mboxdata.url);

    snprintf(tmpstr,sizeof(tmpstr),"%d",mboxdata.answered);
    add_attr(newentry->attrs, "mailbox.answered", tmpstr);

    snprintf(tmpstr,sizeof(tmpstr),"%d",mboxdata.flagged);
    add_attr(newentry->attrs, "mailbox.flagged", tmpstr);

    snprintf(tmpstr,sizeof(tmpstr),"%d",mboxdata.deleted);
    add_attr(newentry->attrs, "mailbox.deleted", tmpstr);

    snprintf(tmpstr,sizeof(tmpstr),"%d",mboxdata.total);
    add_attr(newentry->attrs, "mailbox.total", tmpstr);


    /* create the cmd */
    result = acap_store_entry(AC->conn,
			      newentry,
			      &acapmbox_cb,
			      NULL,
			      ACAP_STORE_INITIAL,
			      &cmd);

    if (result != ACAP_OK) {
	printf("result = %d\n",result);
    }

    
    result = acap_process_on_command(AC->conn, cmd, NULL);
    if (result != ACAP_OK) {
	printf("failure on command\n");
    }


    /* xxx free memory */

    return result;
}

int set_commit(acap_conn_t *conn,
	       char *mailbox_name,
	       int commit) /* 0 or 1 */
{
    int result;
    char *fullname;
    acap_cmd_t *cmd;
    acap_attribute_t *tmpattr;

    /* get the entry path */
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

    /* create the attribute */
    if (commit == 1) {
	tmpattr = acap_attribute_new_simple ("mailbox.status", "commited");
    } else {
	tmpattr = acap_attribute_new_simple ("mailbox.status", "reserved");
    }

    if (tmpattr==NULL) return ACAP_NOMEM;

    /* issue store command */
    result = acap_store_attribute(conn,
				  fullname,
				  tmpattr,
				  NULL, /* don't care about unchangedsince */
				  &acapmbox_cb,
				  NULL,
				  &cmd);

    /* get result of command */
    result = acap_process_on_command(conn, cmd, NULL);
    if (result != ACAP_OK) {
	printf("failure on command\n");
    }

    /* xxx free memory */

    return result;
}

int acapmbox_markactive(acapmbox_handle_t *AC,
			char *mailbox_name)
{
    if (AC==NULL) return ACAP_OK;

    return set_commit(AC->conn, mailbox_name, 1);
}

int acapmbox_markreserved(acapmbox_handle_t *AC,
			  char *mailbox_name)
{
    if (AC==NULL) return ACAP_OK;

    return set_commit(AC->conn, mailbox_name, 0);
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

    if (AC==NULL) return ACAP_OK;

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
    
    if (exists == 0)
	return ACAP_FAIL;
    else
	return ACAP_OK;
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

    if (AC==NULL) return ACAP_OK;

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
				  &acapmbox_cb,
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
    char attrvalue[30];

    if (AC==NULL) return ACAP_OK;

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
				  &acapmbox_cb,
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

static void myacap_copy_entry(acap_entry_t *entry, void *rock)
{
    acapmbox_data_t *mboxdata = (acapmbox_data_t *) rock;
    skipnode *node;
    acap_attribute_t *attr;

    printf("\tentry = %s\n", entry->name);
    attr = sfirst(entry->attrs, &node);
    while (attr) {
	printf("\t\t%s = %s\n", attr->name, attr->v->data);

	if (strcmp(attr->name,"mailbox.status")==0) {
	    mboxdata->status = mboxdata_convert_status(attr->v);
	} else if (strcmp(attr->name,"mailbox.total")==0) {
	    mboxdata->total = atoi(attr->v->data);
	}

	attr = snext(&node);
    }
}

static void myacap_copy_modtime(char *modtime, void *rock)
{
    printf("\tmodtime = %s\n", modtime);
}

static struct acap_search_callback myacap_search_copy_cb = {
    &myacap_copy_entry, &myacap_copy_modtime
};

static struct acap_requested myacap_copy_request = {
    1, { "*" }
};

int acapmbox_copy(acapmbox_handle_t *AC,
		  char *old_mailbox,
		  char *new_mailbox)
{
    acap_cmd_t *cmd;
    int r;
    char *search_crit;
    acapmbox_data_t mboxdata;

    if (AC==NULL) return ACAP_OK;

    /* create search criteria */
    search_crit = (char *) malloc(strlen(old_mailbox)+30);
    if (search_crit==NULL) return ACAP_NOMEM;

    sprintf(search_crit,"EQUAL \"entry\" \"i;octet\" \"%s\"",old_mailbox);

    r = acap_search_dataset(AC->conn, global_dataset,
			    search_crit, 1,
			    &myacap_copy_request, NULL,
			    NULL,
			    &myacap_search_copy_cb,
			    NULL, NULL, 
			    &mboxdata, 
			    &cmd);
    if (r != ACAP_OK) {
	return r;
    }

    r = acap_process_on_command(AC->conn, cmd, NULL);
    if (r != ACAP_OK) {
	return r;
    }

    /* ok now we hopefully have all the data from the old entry.
       let's create the new entry now */

    r = acapmbox_create(AC,new_mailbox,&mboxdata);

    return r;
}

int acapmbox_delete(acapmbox_handle_t *AC,
		    char *mailbox_name)
{
    acap_cmd_t *cmd;
    int r;
    char *fullname;

    if (AC==NULL) return ACAP_OK;

    /* create the new entry */
    fullname = create_full_dataset_name(mailbox_name);
    if (fullname == NULL) return ACAP_NOMEM;

    r = acap_delete_entry_name(AC->conn,
			       fullname,
			       &acapmbox_cb,
			       NULL,
			       &cmd);

    if (r != ACAP_OK) {
	return r;
    }

    r = acap_process_on_command(AC->conn, cmd, NULL);
    if (r != ACAP_OK) {
	return r;
    }

    return r;
}

int acapmbox_deleteall(acapmbox_handle_t *AC)
{
    acap_cmd_t *cmd;
    int r;

    if (AC==NULL) return ACAP_OK;

    r = acap_delete_entry_name(AC->conn,
			       global_dataset,
			       &acapmbox_cb,
			       NULL,
			       &cmd);

    if (r != ACAP_OK) {
	return r;
    }

    r = acap_process_on_command(AC->conn, cmd, NULL);
    if (r != ACAP_OK) {
	return r;
    }

    return r;
}


static unsigned int getintattr(acap_entry_t *e, char *attrname)
{
    char *s = acap_entry_getattr_simple(e, attrname);
    if (s) return atoi(s);
    else return 0;
}

static char *getstrattr(acap_entry_t *e, char *attrname)
{
    return acap_entry_getattr_simple(e, attrname);
}

int acapmbox_dissect(acap_entry_t *e, acapmbox_data_t *data)
{
    acap_value_t *v;

    if (!e || !data) return ACAP_BAD_PARAM;

    data->name = acap_entry_getname(e);
    data->uidvalidity = getintattr(e, "mailbox.uidvalidity");

    v = acap_entry_getattr(e, "mailbox.status");
    data->status = mboxdata_convert_status(v);

    data->post = getstrattr(e, "mailbox.post");
    data->haschildren = getintattr(e, "mailbox.haschildren");
    data->url = getstrattr(e, "mailbox.url");
    data->acl = getstrattr(e, "mailbox.acl");

    data->answered = getintattr(e, "mailbox.answered");
    data->flagged = getintattr(e, "mailbox.flagged");
    data->deleted = getintattr(e, "mailbox.deleted");
    data->total = getintattr(e, "mailbox.total");

    return ACAP_OK;
}
