#include "tcl.h"

extern int main();
int *tclDummyMainPtry = (int *) main;

int Tcl_AppInit(interp)
Tcl_Interp *interp;
{
    if (Tcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    if (Cyradm_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    tcl_RcFileName = "~/.cyradmrc";
    return TCL_OK;
}

fatal(msg)
char *msg;
{
    fprintf(stderr, "cyradm: %s\n", msg);
    exit(1);
}
