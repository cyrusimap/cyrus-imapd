/* cyradmapp.c -- Cyrus administrative client application startup
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
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
