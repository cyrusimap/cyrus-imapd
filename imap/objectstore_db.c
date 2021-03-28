/* objectstore_db.c
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
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>

#include "mailbox.h"
#include "mboxname.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "util.h"
#include "sqldb.h"
#include "sqlite3.h"
#include "objectstore_db.h"

#define TOKEN_UID  "\"uid\":"
#define TOKEN_MBOX "\"mboxs\":"
#define SQL_SELECT_CMD "SELECT list_info FROM user_msg WHERE msg_guid = "
#define SQL_SELECT_ALL "SELECT * FROM user_msg"
#define SQL_DELETE_CMD "DELETE FROM user_msg WHERE msg_guid = "

static int      bkeep_db_open        = 0 ;
static sqldb_t *opened_db            = NULL ;
static char    *opened_mailboxname   = NULL ;

static struct message_info message_info = { 0,0 } ;
static struct message_list message_list = { 0,0 } ;

static void free_message_info () {
    int i;
    for (i=0; i < message_info.mailboxes; i++){
        free (message_info.mailbox [i]) ;
    }
    free (message_info.mailbox) ;
    message_info.mailboxes = 0 ;
    message_info.mailbox = NULL ;
}

static void free_message_list () {
    if (message_list.message)
        free (message_list.message) ;
    message_list.count = 0 ;
    message_list.message = NULL ;
}

static char** append_to_array(char** src, int *size, char *newData) {
       char **tmp = malloc(  sizeof (char*) * (*size + 1) );
       int i ;
       for (i = 0; i < *size; i++){
           tmp [i] = src[i];
       }

       tmp [*size] = newData;

       free (src) ;
       *size += 1;
       return tmp ;
}

static struct message *append_to_list_array(struct message *src, int *size, struct message_guid guid, uint32_t uid )
{
    struct message *tmp = malloc(  sizeof (struct message) * (*size + 1) );
    int i ;
    for (i = 0; i < *size; i++){
        tmp [i].message_guid = src[i].message_guid;
        tmp [i].message_uid = src[i].message_uid;
    }

    tmp [*size].message_guid = guid;
    tmp [*size].message_uid = uid;
    free (src) ;
    *size += 1;
    return tmp ;
}

static char *new_str (char *newData, int size) {
    char *ret = malloc( size + 1 ) ;
    strncpy (ret, newData , size ) ;
    ret [size] = '\0';
    return ret ;
}

static char** delete_element_in_array(char** src, int *size, char *newData, int *bfound ) {
    int b_first_element = (*size == 1 && strstr(src[0], newData) );
    char **tmp = b_first_element ? NULL : malloc(  sizeof (char*) * (*size - 1) ) ;

    int i ;
    char *ret ;
    int ifound = 0 ;
    for (i = 0; i < *size; i++){
        ret = strstr(src[i], newData) ;
// !bfound  == > restriction to one element; same message can be more than once in mailbox; adding and removing one instance at the time)
// remove bfound test and all instance will be remove at once.
        if (!ifound && ret){
            ifound++ ;
            free (src[i]) ;
        }
        else
           tmp [i-ifound] = src[i];
    }
    free (src) ;
    *bfound = ifound ;
    *size -= ifound ;
    return tmp ;
}

static int callback(void *data __attribute__((unused)),
                    int argc __attribute__((unused)),
                    char **argv __attribute__((unused)),
                    char **azColName __attribute__((unused)))
{
    return 0;
}

static int get_mailboxes_callback(void *data __attribute__((unused)),
                                  int argc, char **argv,
                                  char **azColName __attribute__((unused)))
{
    if (argc == 1) // one column return
    {
        char *str = argv[0] ;
        char *ret = NULL ;
        int  blast = 0 ;
        ret = strstr(str, TOKEN_UID) ;
        while (ret && !blast) {
            char *p;
            ret += (strlen (TOKEN_UID)) ;
            p = strstr(ret, TOKEN_UID) ;
            if ( !p ) {
                p = strstr(ret, "}") ;
                blast = 1 ;
            }
            if ( p ){
                char *newstr = new_str ( ret, (p - ret) ) ;

                message_info.mailbox = append_to_array(message_info.mailbox, &message_info.mailboxes, newstr);
            }
            ret = p ;
        }
    }
    return 0;
}

static int get_guid_callback(void *data __attribute__((unused)),
                             int argc, char **argv,
                             char **azColName __attribute__((unused)))
{
    char *mailboxname = (char*) data ;
    int imailboxname = strlen (mailboxname);
    uint32_t uid;
    struct message_guid guid ;

    if (argc == 2)  // two columns return
    {
        char *str = argv[1] ;
        char *ret = NULL ;
        int  blast = 0 ;
        ret = strstr(str, TOKEN_UID) ;
        while (ret && !blast) {
            char *p;
            ret += (strlen (TOKEN_UID)) ;
            p = strstr(ret, TOKEN_UID) ;
            if ( !p ) {
                p = strstr(ret, "}") ;
                blast = 1 ;
            }
            if ( p ){
                char *fname = new_str ( ret, (p - ret) ) ;

                char *ret = strstr(fname, mailboxname) ;
                if (ret)
                {
                    const char *pstart = ret + imailboxname  + 1 ;
                    const char *pend   = ret + strlen (fname);
                    if (!parseuint32(pstart, &pend, &uid) && message_guid_decode(&guid, argv[0]))
                        message_list.message = append_to_list_array(message_list.message, &message_list.count, guid, uid );
                }
            }
            ret = p ;
        }
    }
    return 0;
}



static char *pack_update_message (const char *msg_guid){
    // SQL statement: UPDATE user_msg SET list_info = '{"mboxs":{"uid":mailbox1 "uid":mailbox2}}' WHERE msg_guid = 'message_guid';
    char *sql = "UPDATE user_msg SET list_info = " ;
    char *sql_where = "WHERE msg_guid = " ;
    int final_length = strlen (sql) +
            2 + strlen(TOKEN_MBOX) + 1 + 4 + //  "'{" + TOKEN_MBOX + "{" ... + "}}' "
                strlen(sql_where)  +         //
            1 + 40 + 1 +                     //  "'" + msg_guid (40) + "'"
            1 ;                              //   EOS

    int i;
    for (i=0; i < message_info.mailboxes; i++){
        final_length += strlen ( message_info.mailbox [i]) + strlen (TOKEN_UID) + 1;
    }
    char *list_info = malloc ( final_length ) ;
    sprintf ( list_info, "%s'{%s{", sql, TOKEN_MBOX) ;
    int j = strlen (list_info) ;
    for (i=0; i < message_info.mailboxes; i++){
        sprintf ( &list_info [j], "%s%s", TOKEN_UID, message_info.mailbox [i] ) ;
        j = strlen (list_info) ;
    }
    sprintf ( &list_info [j], "}}' %s'%s'", sql_where, msg_guid ) ;
    return list_info ;
}

static char *pack_insert_message (const char *msg_guid, char *mailbox_name){
    // SQL statement: INSERT INTO user_msg (msg_guid,list_info) values ('message_guid', '{"mboxs":{"uid":mailbox}}' )
    char *sql = "INSERT INTO user_msg (msg_guid,list_info) values " ;
    int final_length = strlen (sql) +
            2 + 40 + strlen(TOKEN_MBOX) + 5 + 1 + strlen(TOKEN_UID) + //  "('" + msg_guid (40) + "', '{" + TOKEN_MBOX  + "{" + TOKEN_UID
            strlen (mailbox_name) +  5 + 1 ;                          //  "}}' )" +  1
    char *list_info = malloc ( final_length ) ;
    sprintf ( list_info, "%s('%s', '{%s{%s%s}}' )", sql, msg_guid , TOKEN_MBOX, TOKEN_UID, mailbox_name) ;
    return list_info ;
}

static char *pack_other_message (char *sql_cmd, const char *msg_guid){   // used with: SQL_SELECT_CMD SQL_DELETE_CMD

    int final_length = strlen (sql_cmd) +
            1 + 40 + 1 + 1 ;           //  "('" + msg_guid (40) + "'" + EOS

    char *list_info = malloc ( final_length ) ;
    sprintf ( list_info, "%s'%s'", sql_cmd, msg_guid) ;
    return list_info ;
}

void sql_error (int rc, char *zErrMsg)
{
    if( rc != SQLITE_OK ){
        syslog(LOG_ERR, "SQL error: %s", zErrMsg);
        sqlite3_free(zErrMsg);
    }
}

static sqldb_t *open_db_userid (struct mailbox *mailbox) {
    sqldb_t *db = NULL;
    static char filename[MAX_MAILBOX_PATH+1];
    static char user_path[MAX_MAILBOX_PATH+1];
    char *path = NULL ;

    const char *root = config_partitiondir(mailbox->part);
    const char *user = (char*) mboxname_to_userid(mailbox->name);

    mboxname_hash(user_path, MAX_MAILBOX_PATH, root, mailbox->name);

// remove domain from user string ;
    path = strstr(user, "@");
    if (path)
        *path = '\0' ;

// now remove tail part part after user/<username>/
    path = strstr(user_path, user);
    if (path){
        path [strlen (user)] = '\0' ;
    }

    // remove // DELETEDPREFIX if there...
     const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
     path = strstr(user_path, dp);
     if (path)
     {
         int len = strlen (dp) + 1 ;
         char *p ;
         for (p = path; *p; p++, path++) {
             *p = path [len];
         }
     }

    snprintf(filename, sizeof(filename), "%s/message.db", user_path );
    path = filename ;

    /* Create table SQL statement */
    char *sql_table = "CREATE TABLE user_msg("  \
                      "msg_guid    CHAR (40)   PRIMARY KEY     NOT NULL," \
                      "list_info   TEXT                        NOT NULL);";

    db = sqldb_open(path , sql_table , 1.0, NULL, SQLDB_DEFAULT_TIMEOUT) ;

    if (db && bkeep_db_open)
    {
        char *zErrMsg = 0;
        int rc = sqlite3_exec(db->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
        sql_error (rc, zErrMsg) ;
    }
    return db ;
}

static const char *objectstore_get_mailbox_name(struct mailbox *mailbox, const struct index_record *record){
    static char filename[MAX_MAILBOX_PATH+1];
    char *ret = NULL ;

    snprintf(filename, sizeof(filename), "%s.%u", mailbox->name, record->uid);

    ret = filename ;
    return ret;
}

EXPORTED int keep_user_message_db_open (int bopen) {
    if (bkeep_db_open != bopen) {
        bkeep_db_open = bopen ;
        if (!bopen && opened_db) {  // time to commit all changes into db file and close
            char *zErrMsg = 0;
            int rc ;
            rc = sqlite3_exec(opened_db->db, "COMMIT;", NULL, NULL, NULL);
            sql_error (rc, zErrMsg) ;
            sqldb_close(&opened_db);
            opened_db = NULL ;
            opened_mailboxname = NULL ;
        }
    }
    return 0 ;
}

static sqldb_t *manage_db_open (struct mailbox *mailbox) {
    sqldb_t *db = NULL ;
    if (opened_mailboxname && bkeep_db_open && opened_db) {
        char *ret = strstr(opened_mailboxname, mailbox->name);
        if  ( ret)  // same mailbox ?
           db = opened_db ;  // use this
        else {
            keep_user_message_db_open (0) ;  // commit all changes and close this database
            keep_user_message_db_open (1) ;  // prepare to keep open the next one
            db = open_db_userid (mailbox) ;  // open new database for new mailbox
        }
    }
    else
        db = open_db_userid (mailbox) ;
    return db ;
}


EXPORTED int add_message_guid (struct mailbox *mailbox, const struct index_record *record)
{
    char *zErrMsg = 0;
    int rc ;
    sqldb_t *db = NULL ;

    db = manage_db_open (mailbox) ;

    if (db){
        char *sql = pack_other_message (SQL_SELECT_CMD, message_guid_encode(&record->guid)) ;
        rc = sqlite3_exec(db->db, sql, get_mailboxes_callback, NULL, &zErrMsg);
        sql_error (rc, zErrMsg) ;
        free (sql) ;

        char *mailbox_name = xstrdup (objectstore_get_mailbox_name (mailbox, record)) ;
        if (rc == SQLITE_OK )
        {
            if (message_info.mailboxes)
            {
            //  add mailbox for this message in database (message already exist in other mailbox(es))
                message_info.mailbox = append_to_array(message_info.mailbox, &message_info.mailboxes, mailbox_name);
                sql = pack_update_message (message_guid_encode(&record->guid));
                rc = sqlite3_exec(db->db, sql, get_mailboxes_callback, NULL, &zErrMsg);
                sql_error (rc, zErrMsg) ;
                free (sql) ;
            }
            else
            {
            //  Insert (message_guid, mailbox) in database
                sql = pack_insert_message (message_guid_encode(&record->guid), mailbox_name ) ;
                rc = sqlite3_exec(db->db, sql, callback, 0, &zErrMsg);
                sql_error (rc, zErrMsg) ;
                free (mailbox_name) ;
                free (sql) ;
            }
        }

        free_message_info () ;

        if (bkeep_db_open) {
            opened_db  = db ;
            opened_mailboxname = mailbox->name ;
        }
        else
            sqldb_close(&db);
    }
    return rc == SQLITE_OK;
}


EXPORTED int delete_message_guid (struct mailbox *mailbox, const struct index_record *record, int *count)
{
    char *zErrMsg = 0;
    int rc ;
    sqldb_t *db = NULL ;

    db = manage_db_open (mailbox) ;

    if (db){
        char *sql = pack_other_message (SQL_SELECT_CMD, message_guid_encode(&record->guid)) ;
        rc = sqlite3_exec(db->db, sql, get_mailboxes_callback, NULL, &zErrMsg);
        sql_error (rc, zErrMsg) ;
        free (sql) ;

        int bfound = 0 ;
        if (rc == SQLITE_OK )
        {
            if (message_info.mailboxes >= 1)
            {
                char *mailbox_name = (char *) objectstore_get_mailbox_name (mailbox, record) ;
                message_info.mailbox = delete_element_in_array(message_info.mailbox, &message_info.mailboxes, mailbox_name, &bfound );
                if (bfound)
                {
                    *count = message_info.mailboxes ;
                    if (message_info.mailboxes)
                    {
                        //  remove mailbox for this message in database (message still exist in other mailbox(es))
                        sql = pack_update_message (message_guid_encode(&record->guid));
                        rc = sqlite3_exec(db->db, sql, get_mailboxes_callback, NULL, &zErrMsg);
                        sql_error (rc, zErrMsg) ;
                        free (sql) ;
                    }
                    else
                    {
                    //  delete (message_guid, mailbox) in database;  email file can be deleted
                    sql = pack_other_message (SQL_DELETE_CMD, message_guid_encode(&record->guid) ) ;
                    rc = sqlite3_exec(db->db, sql, callback, 0, &zErrMsg);
                    sql_error (rc, zErrMsg) ;
                    free (sql) ;
                    }
                }
            }
        }

        free_message_info () ;

        if (bkeep_db_open) {
            opened_db  = db ;
            opened_mailboxname = mailbox->name ;
        }
        else
            sqldb_close(&db);
    }
    return (rc == SQLITE_OK) ;
}

/* return a list of pair GUID - UID */
EXPORTED struct message *get_list_of_message (struct mailbox *mailbox, uint32_t *count)
{
    /* SQL_SELECT_ALL */
    char *zErrMsg = 0;
    int rc ;
    sqldb_t *db = NULL ;

    db = manage_db_open (mailbox) ;

    if (db){
        rc = sqlite3_exec(db->db, SQL_SELECT_ALL, get_guid_callback, mailbox->name, &zErrMsg);
        sql_error (rc, zErrMsg) ;

        if (bkeep_db_open) {
            opened_db  = db ;
            opened_mailboxname = mailbox->name ;
        }
        else
            sqldb_close(&db);
    }

    if (rc == SQLITE_OK)
    {
        *count = message_list.count ;
        return message_list.message ;
    }
    else return NULL ;
}


EXPORTED int discard_list ()
{
    free_message_list () ;
    return 0 ;
}

