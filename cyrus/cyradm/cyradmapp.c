/* cyradmapp.c -- Cyrus administrative client application startup

 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */

/* $Id: cyradmapp.c,v 1.9 2002/05/25 19:57:43 leg Exp $ */

#include "tcl.h"

extern int main();
int *tclDummyMainPtry = (int *) main;

extern int Cyradm_Init(Tcl_Interp *interp);

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

int fatal(char *msg)
{
    fprintf(stderr, "cyradm: %s\n", msg);
    exit(1);
}
