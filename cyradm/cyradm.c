/* cyradm.c -- Cyrus administrative client
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>

extern int errno;

#include "acte.h"
#include "imclient.h"
#include "imparse.h"
#include "tcl.h"
#include "xmalloc.h"

#ifdef HAVE_ACTE_KRB
extern struct acte_client krb_acte_client;
#endif

struct acte_client *login_acte_client[] = {
#ifdef HAVE_ACTE_KRB
    &krb_acte_client,
#endif
    NULL
};

struct admconn {
    struct imclient *imclient;
    int cmd_done;
    int cmd_result;
    Tcl_Interp *interp;
};

/* Forward decls */
int Cyradm_CyradmCmd(), Cyradm_ConnCmd();
static void Cyradm_DeleteConn();
static int cmd_authenticate(), cmd_listmailbox();
static int cmd_deleteaclmailbox(), cmd_listaclmailbox(), cmd_setaclmailbox();
static int cmd_setquota(), cmd_listquota(), cmd_listquotaroot();

/*
 * Initialize the cyradm package
 */
int Cyradm_Init(interp)
Tcl_Interp *interp;
{
    Tcl_CreateCommand(interp, "cyradm", Cyradm_CyradmCmd,
		      (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);

    return TCL_OK;
}


/*
 * The cyradm class command
 */
int Cyradm_CyradmCmd(clientData, interp, argc, argv)
ClientData clientData;
Tcl_Interp *interp;
int argc;
char **argv;
{
    char *connection, *hostname, *port = 0;
    struct admconn *newconn;
    static struct admconn zeroconn;
    int r;

    if (argc < 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " option [arg...]\"", (char *) NULL);
	return TCL_ERROR;
    }
    if (strcmp(argv[1], "connect")) {
	Tcl_AppendResult(interp, "bad option \"",
			 argv[1], "\", must be connect", (char *) NULL);
	return TCL_ERROR;
    }
    if (argc < 3 || argc > 5) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " connect connection [hostname port]\"",
			 (char *) NULL);
	return TCL_ERROR;
    }
    connection = argv[2];
    if (argc < 4) {
	hostname = connection;
    }
    else {
	hostname = argv[3];
	if (argc == 5) {
	    port = argv[4];
	}
    }
    
    newconn = (struct admconn *)xmalloc(sizeof(struct admconn));
    *newconn = zeroconn;

    r = imclient_connect(&newconn->imclient, hostname, port);
    if (r) {
	if (r == -1) {
	    interp->result = "unknown host";
	    return TCL_ERROR;
	}
	if (r == -2) {
	    interp->result = "unknown service";
	    return TCL_ERROR;
	}

	errno = r;
	Tcl_AppendResult(interp, "couldn't connect to ",
			 hostname, ": ", Tcl_PosixError(interp),
			 (char *) NULL);
	return TCL_ERROR;
    }

    /* XXX register callbacks, esp. OK/NO/BAD/BYE */
    imclient_addcallback(newconn->imclient,
			 "OK", CALLBACK_NOLITERAL, (void (*)()) 0, (void *)0,
			 "NO", CALLBACK_NOLITERAL, (void (*)()) 0, (void *)0,
			 "BAD", CALLBACK_NOLITERAL, (void (*)()) 0, (void *)0,
			 "BYE", CALLBACK_NOLITERAL, (void (*)()) 0, (void *)0,
			 "LIST", 0, (void (*)()) 0, (void *)0,
			 "LSUB", 0, (void (*)()) 0, (void *)0,
			 "ACL", 0, (void (*)()) 0, (void *)0,
			 "QUOTA", 0, (void (*)()) 0, (void *)0,
			 "QUOTAROOT", 0, (void (*)()) 0, (void *)0,
			 (char *)0);

    Tcl_CreateCommand(interp, connection, Cyradm_ConnCmd,
		      (ClientData) newconn,
		      (Tcl_CmdDeleteProc *) Cyradm_DeleteConn);

    return TCL_OK;
}

/*
 * Connection deletion callback
 */
static void
Cyradm_DeleteConn(clientData)
ClientData clientData;
{
    struct admconn *conn = (struct admconn *)clientData;

    imclient_close(conn->imclient);
    free((char *) conn);
}

/*
 * IMAP command completion callback
 */
static void
callback_finish(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct admconn *conn = (struct admconn *)rock;

    conn->cmd_done++;
    
    if (!strcmp(reply->keyword, "OK")) {
	return;
    }
	    
    conn->cmd_result = TCL_ERROR;
    if (!strcmp(reply->keyword, "NO")) {
	Tcl_ResetResult(conn->interp);
	Tcl_AppendResult(conn->interp, "command failed: ",
			 reply->text, (char *) NULL);
    }
    else if (!strcmp(reply->keyword, "BAD")) {
	Tcl_ResetResult(conn->interp);
	Tcl_AppendResult(conn->interp, "server does not support operation: ",
			 reply->text, (char *) NULL);
    }
    else if (!strcmp(reply->keyword, "EOF")) {
	Tcl_SetResult(conn->interp, "server connection closed",
		      TCL_STATIC);
    }
    else {
	Tcl_SetResult(conn->interp, "unknown result error type",
		      TCL_STATIC);
    }
}


/*
 * Connection object command
 */
int Cyradm_ConnCmd(clientData, interp, argc, argv)
ClientData clientData;
Tcl_Interp *interp;
int argc;
char **argv;
{
    struct admconn *conn = (struct admconn *)clientData;
    int numcmd = 1, r;

    conn->cmd_done = 0;
    conn->cmd_result = TCL_OK;
    conn->interp = interp;

    if (argc < 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " option [arg...]\"", (char *) NULL);
	return TCL_ERROR;
    }

    switch (argv[1][0]) {
    case 'a':
	if (!strcmp(argv[1], "authenticate")) {
	    return cmd_authenticate(conn, interp, argc, argv);
	}
	goto badoption;
	
    case 'c':
	if (!strcmp(argv[1], "createmailbox")) {
	    if (argc < 3 || argc > 4) {
		Tcl_AppendResult(interp, "wrong # args: should be \"",
				 argv[0],
				 " createmailbox mailbox [partition]\"",
				 (char *) NULL);
		return TCL_ERROR;
	    }
	    imclient_send(conn->imclient, callback_finish, (void *)conn,
			  "CREATE %s%a%a", argv[2], argv[3] ? " " : "",
			  argv[3] ? argv[3] : "");
	    break;
	}
	goto badoption;

    case 'd':
	if (!strcmp(argv[1], "deletemailbox")) {
	    if (argc < 3 || argc > 4) {
		Tcl_AppendResult(interp, "wrong # args: should be \"",
				 argv[0],
				 " deletemailbox mailbox [host]\"",
				 (char *) NULL);
		return TCL_ERROR;
	    }
	    if (argc == 4) {
		interp->result = "host argument only supported in IMSP";
		return TCL_ERROR;
	    }

	    imclient_send(conn->imclient, callback_finish, (void *)conn,
			  "DELETE %s%a%a", argv[2], argv[3] ? " " : "",
			  argv[3] ? argv[3] : "");
	    break;
	}
	if (!strcmp(argv[1], "deleteaclmailbox")) {
	    numcmd = cmd_deleteaclmailbox(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	goto badoption;

    case 'l':
	if (!strcmp(argv[1], "listaclmailbox")) {
	    numcmd = cmd_listaclmailbox(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	if (!strcmp(argv[1], "listmailbox")) {
	    numcmd = cmd_listmailbox(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	if (!strcmp(argv[1], "listquota")) {
	    numcmd = cmd_listquota(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	if (!strcmp(argv[1], "listquotaroot")) {
	    numcmd = cmd_listquotaroot(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	goto badoption;

    case 'r':
	if (!strcmp(argv[1], "renamemailbox")) {
	    if (argc < 4 || argc > 5) {
		Tcl_AppendResult(interp, "wrong # args: should be \"",
				 argv[0],
				 " renamemailbox old new [partition]\"",
				 (char *) NULL);
		return TCL_ERROR;
	    }
	    imclient_send(conn->imclient, callback_finish, (void *)conn,
			  "RENAME %s %s%a%a", argv[2], argv[3],
			  argv[4] ? " " : "", argv[4] ? argv[4] : "");
	    break;
	}
	goto badoption;

    case 's':
	if (!strcmp(argv[1], "servername")) {
	    if (argc != 2) {
		Tcl_AppendResult(interp, "wrong # args: should be \"",
				 argv[0], " servername\"",
				 (char *) NULL);
		return TCL_ERROR;
	    }
	    Tcl_SetResult(conn->interp, imclient_servername(conn->imclient),
			  TCL_STATIC);
	    return TCL_OK;
	}
	if (!strcmp(argv[1], "setaclmailbox")) {
	    numcmd = cmd_setaclmailbox(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	if (!strcmp(argv[1], "setquota")) {
	    numcmd = cmd_setquota(conn, interp, argc, argv);
	    if (numcmd < 0) return TCL_ERROR;
	    break;
	}
	goto badoption;

    badoption:
    default:
	Tcl_AppendResult(interp, "bad option \"", argv[1],
			 "\", must be authenticate, createmailbox, ",
			 "deletemailbox, deleteaclmailbox, ",
			 "listaclmailbox, listmailbox, listquota, listquotaroot, ",
			 "renamemailbox, ",
			 "setaclmailbox, or setquota",
			 (char *) NULL);
	return TCL_ERROR;
	
    }

    while (conn->cmd_done < numcmd) {
	imclient_processoneevent(conn->imclient);
    }
    return conn->cmd_result;
}

/*
 * Perform the authenticate subcommand
 */
static int
cmd_authenticate(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    char *pwcommand = 0;
    char *user = 0;
    int prot = ACTE_PROT_ANY;
    char *p;
    int r;
    
    /* skip over command & subcommand */
    argv += 2;

    /* parse switches */
    while (argv[0]) {
	if (!strcmp(argv[0], "-pwcommand")) {
	    if (!argv[1]) break;
	    pwcommand = *++argv;
	}
	else if (!strcmp(argv[0], "-user")) {
	    if (!argv[1]) break;
	    user = *++argv;
	}
	else if (!strcmp(argv[0], "-protection")) {
	    if (!argv[1]) break;
	    prot = 0;
	    for (p = *++argv; *p; p++) {
		switch (*p) {
		case 'n':
		    prot |= ACTE_PROT_NONE;
		    break;

		case 'i':
		    prot |= ACTE_PROT_INTEGRITY;
		    break;

		case 'p':
		    prot |= ACTE_PROT_PRIVACY;
		    break;

		default:
		    Tcl_AppendResult(interp, "incorrect protection mode: ",
				     "should be one or more of n, i, p",
				     (char *) NULL);
		    return TCL_ERROR;
		}
	    }
	}
	argv++;
    }
    if (*argv) {
	Tcl_AppendResult(interp, "incorrect args: should be \"",
			 argv[0], " authenticate ",
			 "[-pwcommand string] [-user user] ",
			 "[-protection (n|i|p)+\"",
			 (char *) NULL);
	return TCL_ERROR;
    }

    r = imclient_authenticate(conn->imclient, login_acte_client, user, prot);
    
    if (r == 1 && (prot & ACTE_PROT_NONE) && pwcommand) {
	Tcl_DString command;
	int comc;
	char **comv;

	/* Expand the %-escapes in pwcommand */
	Tcl_DStringInit(&command);
	while (p = strchr(pwcommand, '%')) {
	    Tcl_DStringAppend(&command, pwcommand, p - pwcommand);
	    switch (*++p) {
	    case '%':
		Tcl_DStringAppend(&command, p, 1);
		break;

	    case 'h':
		Tcl_DStringAppendElement(&command,
					 imclient_servername(conn->imclient));
		break;

	    case 'u':
		if (!user) user = "";
		Tcl_DStringAppendElement(&command, user);
		break;

	    default:
		Tcl_DStringFree(&command);
		Tcl_AppendResult(interp, "invalid %-sequence in pwcommand",
				 (char *) NULL);
		return TCL_ERROR;
	    }
	    pwcommand = p+1;
	}
	Tcl_DStringAppend(&command, pwcommand, -1);

	r = Tcl_GlobalEval(interp, Tcl_DStringValue(&command));
	Tcl_DStringFree(&command);
	if (r) return r;
	
	if (Tcl_SplitList(interp, interp->result, &comc, &comv)) {
	    return TCL_ERROR;
	}
	Tcl_ResetResult(interp);
	if (comc != 2) {
	    Tcl_SetResult(interp,
		  "pwcommand script did not return a list with two elements",
			  TCL_STATIC);
	    return TCL_ERROR;
	}

	imclient_send(conn->imclient, callback_finish, (void *)conn,
		      "LOGIN %s %s", comv[0], comv[1]);
	free((char *)comv);

	while (!conn->cmd_done) {
	    imclient_processoneevent(conn->imclient);
	}
	r = conn->cmd_result;
    }

    if (r) {
	interp->result = "authentication failed";
	return TCL_ERROR;
    }
    return TCL_OK;
}


struct mailboxdata {
    Tcl_DString data;
};

/*
 * Callback to deal with untagged LIST/LSUB data
 */
static void
callback_list(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct mailboxdata *mailboxdata = (struct mailboxdata *)rock;
    char *s, *end;
    char *mailbox, *attributes, *separator;
    int c;

    s = reply->text;
    
    if (*s++ != '(') return;
    end = strchr(s, ')');
    if (!end) return;
    attributes = s;
    s = end;
    *s++ = '\0';

    if (*s++ != ' ') return;
    if (*s == 'N') {
	if (s[1] != 'I' || s[2] != 'L') return;
	separator = "";
    	s += 3;
    }
    else if (*s == '\"') {
	s++;
	if (*s == '\\') s++;
	separator = s++;
	if (*s != '\"') return;
	*s++ = '\0';
    }

    if (*s++ != ' ') return;
    c = imparse_astring(&s, &mailbox);
    if (c != '\0') return;
    Tcl_DStringStartSublist(&mailboxdata->data);
    Tcl_DStringAppendElement(&mailboxdata->data, mailbox);
    Tcl_DStringStartSublist(&mailboxdata->data);
    for (s = attributes; end = strchr(s, ' '); s = end+1) {
	*s = '\0';
	Tcl_DStringAppendElement(&mailboxdata->data, s);
    }
    Tcl_DStringAppendElement(&mailboxdata->data, s);
    Tcl_DStringEndSublist(&mailboxdata->data);
    Tcl_DStringAppendElement(&mailboxdata->data, separator);
    Tcl_DStringEndSublist(&mailboxdata->data);
}    

/*
 * Perform the listmailbox subcommand
 */
static int
cmd_listmailbox(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    char *command = argv[0];
    int i;
    struct mailboxdata mailboxdata;
    int subscribed = 0;
    char *reference = "";

    argc -= 2;
    argv += 2;
    while (argc > 0 && argv[0][0] == '-') {
	argc--;
	argv++;
	if (!strcmp(argv[-1], "--")) break;
	if (!strcmp(argv[-1], "-subscribed")) subscribed = 1;
	else {
	    Tcl_AppendResult(interp, "unrecognized switch: should be \"",
			     command,
		     " listmailbox [-subscribed|--] pattern [reference]\"",
			     (char *) NULL);
	    return -1;
	}
    }

    if (argc < 1 || argc > 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 command,
			 " listmailbox [-subscribed|--] pattern [reference]\"",
			 (char *) NULL);
	return -1;
    }
    if (argc == 2) reference = argv[1];

    Tcl_DStringInit(&mailboxdata.data);


    imclient_addcallback(conn->imclient,
			 subscribed ? "LSUB" : "LIST", 0, callback_list,
			 (void *)&mailboxdata, (char *)0);
    imclient_send(conn->imclient, callback_finish, (void *)conn,
		  "%a %s %s", subscribed ? "LSUB" : "LIST", reference,
		  argv[0]);

    while (!conn->cmd_done) {
	imclient_processoneevent(conn->imclient);
    }
    
    if (!conn->cmd_result) {
	Tcl_DStringResult(interp, &mailboxdata.data);
    }

    imclient_addcallback(conn->imclient,
			 subscribed ? "LSUB" : "LIST", 0, (void (*)()) 0,
			 (void *)0, (char *)0);

    return 0;
}

/*
 * Perform the deleteaclmailbox subcommand
 */
static int
cmd_deleteaclmailbox(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    int i, num;
    char *mailbox;
    char *rights;

    if (argc < 4) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0],
			 " deleteaclmailbox mailbox id [id]...\"",
			 (char *) NULL);
	return -1;
    }

    mailbox = argv[2];
    argv += 3;
    num = argc - 3;
    for (i = 0; i < num; i++) {
	imclient_send(conn->imclient, callback_finish, (void *)conn,
		      "DELETEACL MAILBOX %s %s", mailbox, argv[i]);
    }

    return num;
}

/*
 * Perform the setaclmailbox subcommand
 */
static int
cmd_setaclmailbox(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    int i, num;
    char *mailbox;
    char *rights;

    /* XXX doesn't do -clear */

    if (argc < 5 || !(argc & 1)) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0],
			 " setaclmailbox mailbox id rights [id rights]...\"",
			 (char *) NULL);
	return -1;
    }

    mailbox = argv[2];
    argv += 3;
    num = (argc - 3)/2;
    for (i = 0; i < num; i++) {
	rights = argv[1];
	if (!strcasecmp(rights, "none")) rights = "";
	else if (!strcasecmp(rights, "read")) rights = "lrs";
	else if (!strcasecmp(rights, "post")) rights = "lrsp";
	else if (!strcasecmp(rights, "append")) rights = "lrsip";
	else if (!strcasecmp(rights, "write")) rights = "lrswipcd";
	else if (!strcasecmp(rights, "all")) rights = "lrswipcda";

	imclient_send(conn->imclient, callback_finish, (void *)conn,
		      "SETACL %s %s %s", mailbox, argv[0], rights);
	argv += 2;
    }

    return num;
}

struct acldata {
    char *option;
    char *object;
    Tcl_DString data;
};

/*
 * Callback to deal with untagged ACL data
 */
static void
callback_acl(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct acldata *acldata = (struct acldata *)rock;
    char *s;
    char *val, *identifier, *rights;
    int c;

    s = reply->text;
    
    c = imparse_astring(&s, &val);
    if (strcasecmp(val, acldata->object) != 0) return;
    if (c != '\0' && c != ' ') return;

    while (c == ' ') {
	c = imparse_astring(&s, &identifier);
	if (c != ' ') return;

	c = imparse_astring(&s, &rights);
	if (c != '\0' && c != ' ') return;

	Tcl_DStringAppendElement(&acldata->data, identifier);
	Tcl_DStringAppendElement(&acldata->data, rights);
    }
}    

/*
 * Perform the listaclmailbox subcommand
 */
static int
cmd_listaclmailbox(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    int i;
    struct acldata acldata;

    if (argc != 3) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " listaclmailbox mailbox\"", (char *) NULL);
	return -1;
    }

    acldata.option = "MAILBOX";
    acldata.object = argv[2];
    Tcl_DStringInit(&acldata.data);

    imclient_addcallback(conn->imclient,
			 "ACL", 0, callback_acl, (void *)&acldata,
			 (char *)0);
    imclient_send(conn->imclient, callback_finish, (void *)conn,
		  "GETACL %s", argv[2]);

    while (!conn->cmd_done) {
	imclient_processoneevent(conn->imclient);
    }
    
    if (!conn->cmd_result) {
	Tcl_DStringResult(interp, &acldata.data);
    }

    imclient_addcallback(conn->imclient,
			 "ACL", 0, (void (*)()) 0, (void *)0,
			 (char *)0);

    return 0;
}

/*
 * Perform the setquota subcommand
 */
static int
cmd_setquota(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    int i, num;
    char *mailbox;

    if (argc < 3 || !(argc & 1)) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0],
			 " setquota mailbox [limit num]...\"",
			 (char *) NULL);
	return -1;
    }

    mailbox = argv[2];
    argv += 3;
    num = (argc - 3)/2;
    for (i = 0; i < num; i++) {
	if (!imparse_isatom(argv[2*i])) {
	    Tcl_AppendResult(interp, "invalid quota resource '",
			     argv[2*i], "'", (char *) NULL);
	    return -1;
	}
	if (!imparse_isnumber(argv[2*i+1])) {
	    Tcl_AppendResult(interp, "non-numeric quota value '",
			     argv[2*i+1], "'", (char *) NULL);
	    return -1;
	}
    }

    imclient_send(conn->imclient, callback_finish, (void *)conn,
		  "SETQUOTA %s (%v)", mailbox, argv);
    return 1;
}

struct quotadata {
    char *mailbox;
    Tcl_DString quotaroots;
    Tcl_DString data;
};

/*
 * Callback to deal with untagged QUOTAROOT data
 */
static void
callback_quotaroot(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct quotadata *quotadata = (struct quotadata *)rock;
    char *s;
    char *val;
    int c;

    s = reply->text;
    
    c = imparse_astring(&s, &val);
    if (c != ' ' || strcasecmp(val, quotadata->mailbox) != 0) return;

    Tcl_DStringFree(&quotadata->quotaroots);
    Tcl_DStringAppend(&quotadata->quotaroots, s, -1);
}    

static void
callback_quota(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct quotadata *quotadata = (struct quotadata *)rock;
    char *s, *end;
    char *root;
    int c;

    s = reply->text;
    
    c = imparse_astring(&s, &root);
    if (c != ' ') return;

    if (*s++ != '(') return;
    end = strchr(s, ')');
    if (!end || end[1]) return;
    *end = '\0';

    Tcl_DStringAppendElement(&quotadata->data, root);
    Tcl_DStringAppendElement(&quotadata->data, s);
}    

/*
 * Perform the listquota subcommand
 */
static int
cmd_listquota(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    int i;
    struct quotadata quotadata;
    int quotac;
    char **quotav;

    if (argc != 3) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " listquota root\"", (char *) NULL);
	return -1;
    }

    Tcl_DStringInit(&quotadata.data);

    imclient_addcallback(conn->imclient,
			 "QUOTA", 0, callback_quota, (void *)&quotadata,
			 (char *)0);
    imclient_send(conn->imclient, callback_finish, (void *)conn,
		  "GETQUOTA %s", argv[2]);

    while (!conn->cmd_done) {
	imclient_processoneevent(conn->imclient);
    }
    
    imclient_addcallback(conn->imclient,
			 "QUOTA", 0, (void (*)()) 0, (void *)0,
			 (char *)0);

    if (!conn->cmd_result) {
	if (Tcl_SplitList(interp, Tcl_DStringValue(&quotadata.data),
			  &quotac, &quotav)) {
	    Tcl_DStringFree(&quotadata.data);
	    return -1;
	}
	for (i = 0; i < quotac; i += 2) {
	    if (!strcasecmp(argv[2], quotav[i])) {
		Tcl_SetResult(interp, quotav[i+1], TCL_VOLATILE);
	    }
	}
	free((char *)quotav);
	Tcl_DStringFree(&quotadata.data);
    }

    return 0;
}

/*
 * Perform the listquotaroot subcommand
 */
static int
cmd_listquotaroot(conn, interp, argc, argv)
struct admconn *conn;
Tcl_Interp *interp;
int argc;
char **argv;
{
    int i, j;
    struct quotadata quotadata;
    int quotac, rootc;
    char **quotav, **rootv;
    Tcl_DString result;
    char *quotaforroot;

    if (argc != 3) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " listquotaroot mailbox\"", (char *) NULL);
	return -1;
    }

    quotadata.mailbox = argv[2];
    Tcl_DStringInit(&quotadata.quotaroots);
    Tcl_DStringInit(&quotadata.data);

    imclient_addcallback(conn->imclient,
			 "QUOTA", 0, callback_quota, (void *)&quotadata,
		 "QUOTAROOT", 0, callback_quotaroot, (void *)&quotadata,
			 (char *)0);
    imclient_send(conn->imclient, callback_finish, (void *)conn,
		  "GETQUOTAROOT %s", argv[2]);

    while (!conn->cmd_done) {
	imclient_processoneevent(conn->imclient);
    }
    
    imclient_addcallback(conn->imclient,
			 "QUOTA", 0, (void (*)()) 0, (void *)0,
			 "QUOTAROOT", 0, (void (*)()) 0, (void *)0,
			 (char *)0);

    if (!conn->cmd_result) {
	if (Tcl_SplitList(interp, Tcl_DStringValue(&quotadata.data),
			  &quotac, &quotav) ||
	    Tcl_SplitList(interp, Tcl_DStringValue(&quotadata.quotaroots),
			  &rootc, &rootv)) {
	    Tcl_DStringFree(&quotadata.data);
	    Tcl_DStringFree(&quotadata.quotaroots);
	    return -1;
	}
	Tcl_DStringInit(&result);
	for (i = 0; i < rootc; i++) {
	    Tcl_DStringStartSublist(&result);
	    Tcl_DStringAppendElement(&result, rootv[i]);
	    
	    quotaforroot = 0;
	    for (j = 0; j < quotac; j += 2) {
		if (!strcasecmp(rootv[i], quotav[j])) {
		    quotaforroot = quotav[j+1];
		}
	    }

	    if (*quotaforroot) {
		Tcl_DStringAppend(&result, " ", 1);
		Tcl_DStringAppend(&result, quotaforroot, -1);
	    }
	    Tcl_DStringEndSublist(&result);
	}
	Tcl_DStringFree(&quotadata.data);
	Tcl_DStringFree(&quotadata.quotaroots);
	free((char *)quotav);
	free((char *)rootv);

	Tcl_DStringResult(interp, &result);
    }

    return 0;
}
