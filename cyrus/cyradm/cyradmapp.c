/* cyradmapp.c -- Cyrus administrative client application startup
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
