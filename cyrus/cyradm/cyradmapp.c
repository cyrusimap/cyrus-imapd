/* cyradmapp.c -- Cyrus administrative client application startup
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */
#include "tcl.h"

extern int main();
int *tclDummyMainPtry = (int *) main;

extern char cyrinit[];

int Tcl_AppInit(interp)
Tcl_Interp *interp;
{
    char *value;
    int code;
    
    if (Tcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    if (Cyradm_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    value = Tcl_GetVar(interp, "tcl_interactive", 0);
    if (value && *value == '1') {
	code = Tcl_Eval(interp, cyrinit);
	if (code != TCL_OK) return code;
    }

    Tcl_SetVar(interp, "tcl_rcFileName", "~/.cyradmrc", TCL_GLOBAL_ONLY);
    return TCL_OK;
}

fatal(msg)
char *msg;
{
    fprintf(stderr, "cyradm: %s\n", msg);
    exit(1);
}
