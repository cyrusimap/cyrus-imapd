
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <acap.h>
#include "acapsieve.h"
#include "xmalloc.h"


struct acapsieve_handle_s {
    acap_conn_t *conn;
};

/*
 * Get the acapconn. This should only be used if you need to get the
 * acapconn file descriptor
 */

acap_conn_t *acapsieve_get_acapconn(acapsieve_handle_t *AC)
{
    return AC->conn;
}


static acapsieve_handle_t *cached_conn = NULL;

void acapsieve_disconnect(acapsieve_handle_t *conn)
{

    if (conn == cached_conn) {

	acap_conn_close(conn->conn);
	free(conn);
	/* xxx free memory */
	cached_conn = NULL;
    }
}

acapsieve_handle_t *acapsieve_get_handle(char *acapserver, sasl_callback_t *cb)
{
    int r;
    char str[2048];
    char *user = NULL;
    sasl_callback_t *tmpcb;
    
    if (!acapserver) return NULL;
    if (!cb) return NULL;

    if (cached_conn) {
	/* xxx verify cached_conn is still a valid connection */
	return cached_conn;
    }

    cached_conn = (acapsieve_handle_t *) xmalloc(sizeof(acapsieve_handle_t));
    cached_conn->conn = NULL;
    
    r = sasl_client_init(cb);
    if (r != SASL_OK) {
	return cached_conn;
    }

    /* xxx get user */
    tmpcb = cb;

    while (tmpcb->id != SASL_CB_LIST_END) {

	if (tmpcb->id == SASL_CB_USER) {
	    r = ((sasl_getsimple_t *)(tmpcb->proc))(tmpcb->context,SASL_CB_USER,
						  (const char **) &user, NULL);
	    if (r!=SASL_OK) return NULL;
	}

	tmpcb++;
    }

    if (user == NULL) {
	printf("no user specified\n");
	return NULL;
    }

    snprintf(str, sizeof(str), "acap://%s@%s/", user, acapserver);

    r = acap_conn_connect(str, &(cached_conn->conn));
    if (r != ACAP_OK) {
	acap_conn_close(cached_conn->conn);
	cached_conn->conn = NULL;
	return cached_conn;
    }

    return cached_conn;
}

void acapsieve_release_handle(acapsieve_handle_t *handle)
{
    /* NOOP */
}

static void myacap_entry(acap_entry_t *entry, void *rock)
{
    acapsieve_list_cb_t *cb = (acapsieve_list_cb_t *) rock;
    skipnode *node;
    acap_attribute_t *attr;

    attr = sfirst(entry->attrs, &node);
    while (attr) {
	cb(attr->name, 0);

	attr = snext(&node);
    }
}

static void myacap_modtime(char *modtime, void *rock)
{

}

static struct acap_search_callback myacap_search_cb = {
    &myacap_entry, &myacap_modtime
};

static struct acap_requested myacap_request = {
    2, {{ "email.account.sieve.*", 0x01 }, { "email.sieve.script", 0x01}}
};

int acapsieve_list(acapsieve_handle_t *AC,
		   acapsieve_list_cb_t *cb)
{
    acap_cmd_t *cmd;
    int r;
    char *search_crit;
    int exists = 0;

    if (AC == NULL) return 0;

    if (AC->conn == NULL) {
	return -1;
    }

    /* create search criteria */
    search_crit = (char *) malloc(30);
    if (search_crit==NULL) return ACAP_NOMEM;

    sprintf(search_crit,"ALL");

    r = acap_search_dataset(AC->conn, 
			    "/sieve/tmartin/", /* xxx */
			    search_crit, 1,
			    &myacap_request, NULL,
			    NULL,
			    &myacap_search_cb,
			    NULL, NULL, 
			    cb,
			    &cmd);

    if (r != ACAP_OK) {
	return r;
    }

    r = acap_process_on_command(AC->conn, cmd, NULL);    
    if (r != ACAP_OK) {
	printf("r = %d\n",r);
	return r;
    }
    
    return ACAP_OK;
}


int acapsieve_put(acapsieve_handle_t *AC,
		  acapsieve_data_t *data)
{
    return acapsieve_put_simple(AC, data->name, data->data, data->datalen);
}

static int add_attr(skiplist *sl, char *name, char *value)
{
    acap_attribute_t *tmpattr;

    tmpattr = acap_attribute_new_simple (name, value);
    if (tmpattr) sinsert(sl, tmpattr);

    return 0;
}

int acapsieve_put_simple(acapsieve_handle_t *AC,
			 char *name,
			 char *data, 
			 int datalen)
{
    int result;
    acap_entry_t *newentry;
    acap_result_t acapres;

    acap_cmd_t *cmd;
    char *fullname;
    char attrname[1024];

    if (AC == NULL) return 0;

    if (AC->conn == NULL) {
	return -1;
    }

    /* create the new entry */
    fullname = xmalloc(strlen(name)+40);

    sprintf(fullname, "/sieve/tmartin/default");

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) return ACAP_NOMEM;

    /* make and insert all our initial attributes */
    snprintf(attrname,sizeof(attrname)-1,"email.account.sieve.%s",name);
    add_attr(newentry->attrs, attrname, data);

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
	    result = -1;
	} else if (acapres != ACAP_RESULT_OK) {
	    /* this is a likely but not certain error */
	    result = -1;
	}
    }

    return result;
}

char *getsievename(char *filename)
{
  char *ret, *ptr;

  ret=(char *) xmalloc( strlen(filename) + 2);

  /* just take the basename of the file */
  ptr = strrchr(filename, '/');
  if (ptr == NULL) {
      ptr = filename;
  } else {
      ptr++;
  }

  strcpy(ret, ptr);

  if ( strcmp( ret + strlen(ret) - 7,".script")==0)
  {
    ret[ strlen(ret) - 7] = '\0';
  }

  return ret;
}

int acapsieve_put_file(acapsieve_handle_t *AC,
		       char *filename)
{
    FILE *stream;
    struct stat filestats;  /* returned by stat */
    int size;     /* size of the file */
    int result;
    char *sievename;
    char *sievedata;

    sievename=getsievename(filename);

    result=stat(filename,&filestats);

    if (result!=0)
    {
	perror("stat");
	return -1;
    }

    size=filestats.st_size;

    stream=fopen(filename, "r");

    if (stream==NULL)
    {
	printf("Couldn't open file\n");
	return -1;
    }

    sievedata = xmalloc(size+1);

    fread(sievedata, 1, size, stream);

    return acapsieve_put_simple(AC,
				sievename,
				sievedata, 
				size);
}

int acapsieve_activate(acapsieve_handle_t *AC,
		       char *name)
{
    int result;
    acap_entry_t *newentry;
    acap_result_t acapres;

    acap_cmd_t *cmd;
    char *fullname;
    char attrvalue[1024];

    if (AC == NULL) return 0;

    if (AC->conn == NULL) {
	return -1;
    }

    /* create the new entry */
    fullname = xmalloc(strlen(name)+40);

    sprintf(fullname, "/sieve/tmartin/default");

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) return ACAP_NOMEM;

    /* make and insert all our initial attributes */
    snprintf(attrvalue,sizeof(attrvalue)-1,"email.account.sieve.%s",name);
    add_attr(newentry->attrs, "email.sieve.script", attrvalue);

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
	    result = -1;
	} else if (acapres != ACAP_RESULT_OK) {
	    /* this is a likely but not certain error */
	    result = -1;
	}
    }

    return result;
}

int acapsieve_delete(acapsieve_handle_t *AC,
		     char *name)
{
    int result;
    acap_entry_t *newentry;
    acap_result_t acapres;

    acap_cmd_t *cmd;
    char *fullname;
    char attrname[1024];

    if (AC == NULL) return 0;

    if (AC->conn == NULL) {
	return -1;
    }

    /* create the new entry */
    fullname = xmalloc(strlen(name)+40);

    sprintf(fullname, "/sieve/tmartin/default");

    newentry = acap_entry_new(fullname);
    if (newentry == NULL) return ACAP_NOMEM;

    snprintf(attrname,sizeof(attrname)-1,"email.account.sieve.%s",name);

    /* create the cmd; if it's the first time through, we ACAP_STORE_INITIAL */
    result = acap_delete_attribute(AC->conn,
				   fullname,
				   attrname,
				   NULL,
				   NULL,
				   &cmd);

    /* xxx what about active script??? */

    if (result == ACAP_OK) {
	result = acap_process_on_command(AC->conn, cmd, &acapres);
	if (result == ACAP_NO_CONNECTION) {
	    result = -1;
	} else if (acapres != ACAP_RESULT_OK) {
	    /* this is a likely but not certain error */
	    result = -1;
	}
    }

    return result;   
}

static void myacap_entry_get(acap_entry_t *entry, void *rock)
{
    FILE *stream = (FILE *) rock;
    skipnode *node;
    acap_attribute_t *attr;

    attr = sfirst(entry->attrs, &node);
    while (attr) {
	
	fwrite(attr->v->data, attr->v->len, 1, stream);

	attr = snext(&node);
    }
}

static struct acap_search_callback myacap_search_get_cb = {
    &myacap_entry_get, NULL
};


int acapsieve_get(acapsieve_handle_t *AC,
		  char *name,
		  FILE *stream)
{
    struct acap_requested myacap_req;
    char *search_crit;
    int r;
    acap_cmd_t *cmd;

    myacap_req.n_attrs = 1;
    myacap_req.attrs[0].attrname = xmalloc(strlen(name)+30);

    sprintf(myacap_req.attrs[0].attrname, "email.account.sieve.%s",name);
    myacap_req.attrs[0].ret = 0;

    /* create search criteria */
    search_crit = (char *) malloc(30);
    if (search_crit==NULL) return ACAP_NOMEM;

    sprintf(search_crit,"ALL");

    r = acap_search_dataset(AC->conn, 
			    "/sieve/tmartin/", /* xxx */
			    search_crit, 1,
			    &myacap_req, NULL,
			    NULL,
			    &myacap_search_get_cb,
			    NULL, NULL, 
			    stream,
			    &cmd);

    if (r != ACAP_OK) {
	return r;
    }

    r = acap_process_on_command(AC->conn, cmd, NULL);    
    if (r != ACAP_OK) {
	printf("r = %d\n",r);
	return r;
    }
    
    return ACAP_OK;
    
}
