#include <stdio.h>
#include <errno.h>

extern int errno;

#include "imclient.h"
#include "acte.h"
#include "tcl.h"
#include "xmalloc.h"

extern struct acte_client krb_acte_client;
struct acte_client *login_acte_client[] = {
    &krb_acte_client,
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
void Cyradm_DeleteConn();


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
	    /* XXX */
	    interp->result = "port argument not implemented yet";
	    return TCL_ERROR;
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

	errno = r;
	Tcl_AppendResult(interp, "couldn't connect to ",
			 hostname, ": ", Tcl_PosixError(interp),
			 (char *) NULL);
	return TCL_ERROR;
    }

    /* XXX register callbacks, esp. OK/NO/BAD/BYE */

    Tcl_CreateCommand(interp, connection, Cyradm_ConnCmd,
		      (ClientData) newconn,
		      (Tcl_CmdDeleteProc *) Cyradm_DeleteConn);

    return TCL_OK;
}

/*
 * Connection deletion callback
 */
void Cyradm_DeleteConn(clientData)
ClientData clientData;
{
    struct admconn *conn = (struct admconn *)clientData;

    imclient_close(conn->imclient);
    free((char *) conn);
}

/*
 * IMAP command completion callback
 */
void Cyradm_Finish(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    struct admconn *conn = (struct admconn *)rock;

    conn->cmd_done = 1;
    
    if (!strcmp(reply->keyword, "OK")) {
	conn->cmd_result = TCL_OK;
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
    int r;

    conn->cmd_done = 0;
    conn->interp = interp;

    if (argc < 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"",
			 argv[0], " option [arg...]\"", (char *) NULL);
	return TCL_ERROR;
    }

    switch (argv[1][0]) {
    case 'a':
	if (!strcmp(argv[1], "authenticate")) {
	    /* XXX switches to specify protection mechanism */
	    if (argc > 3) {
		Tcl_AppendResult(interp, "wrong # args: should be \"",
				 argv[0], " authenticate [user]\"",
				 (char *) NULL);
		return TCL_ERROR;
	    }
	    r = imclient_authenticate(conn->imclient, login_acte_client,
				      argv[2], ACTE_PROT_ANY);
	    
	    if (r) {
		interp->result = "authentication failed";
		/* XXX deal with error codes -- 2==perm screwup */
		/* XXX deal with LOGIN command */
		return TCL_ERROR;
	    }
	    return TCL_OK;
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
	    imclient_send(conn->imclient, Cyradm_Finish, (void *)conn,
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

	    imclient_send(conn->imclient, Cyradm_Finish, (void *)conn,
			  "DELETE %s%a%a", argv[2], argv[3] ? " " : "",
			  argv[3] ? argv[3] : "");
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
	    imclient_send(conn->imclient, Cyradm_Finish, (void *)conn,
			  "RENAME %s %s%a%a", argv[2], argv[3],
			  argv[4] ? " " : "", argv[4] ? argv[4] : "");
	    break;
	}
	goto badoption;

    badoption:
    default:
	Tcl_AppendResult(interp, "bad option \"", argv[1],
			 "\", must be authenticate or createmailbox",
			 (char *) NULL);
	return TCL_ERROR;
	
    }

    while (!conn->cmd_done) {
	imclient_processoneevent(conn->imclient);
    }
    return conn->cmd_result;
}
