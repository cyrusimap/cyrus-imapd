/* 
 * cyrmain.c -- Main program for Cyradm
 
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
 * Copyright (c) 1988-1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Permission is hereby granted, without written agreement and without
 * license or royalty fees, to use, copy, modify, and distribute this
 * software and its documentation for any purpose, provided that the
 * above copyright notice and the following two paragraphs appear in
 * all copies of this software.
 * 
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF
 * CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

/* $Id: cyrmain.c,v 1.12 2002/11/06 20:43:17 rjs3 Exp $ */

#include <stdio.h>
#include <tcl.h>
#include <errno.h>

/*
 * Declarations for various library procedures and variables (don't want
 * to include tclUnix.h here, because people might copy this file out of
 * the Tcl source directory to make their own modified versions).
 */

extern void		exit _ANSI_ARGS_((int status));
extern int		isatty _ANSI_ARGS_((int fd));
extern char *		strcpy _ANSI_ARGS_((char *dst, CONST char *src));

static Tcl_Interp *interp;	/* Interpreter for application. */
static Tcl_DString command;	/* Used to buffer incomplete commands being
				 * read from stdin. */
#ifdef TCL_MEM_DEBUG
static char dumpFile[100];	/* Records where to dump memory allocation
				 * information. */
static int quitFlag = 0;	/* 1 means the "checkmem" command was
				 * invoked, so the application should quit
				 * and dump memory allocation information. */
#endif

/*
 * Forward references for procedures defined later in this file:
 */
#ifdef TCL_MEM_DEBUG
static int		CheckmemCmd _ANSI_ARGS_((ClientData clientData,
			    Tcl_Interp *interp, int argc, char *argv[]));
#endif /* TCL_MEM_DEBUG */

/*
 *----------------------------------------------------------------------
 *
 * main --
 *
 *	This is the main program for cyradm, a Tcl-based shell that reads
 *	Tcl commands from standard input.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Can be almost arbitrary, depending on what the Tcl commands do.
 *
 *----------------------------------------------------------------------
 */

int
main(argc, argv)
    int argc;				/* Number of arguments. */
    char **argv;			/* Array of argument strings. */
{
    char buffer[1000], *cmd, *args, *fileName;
    int code, gotPartial, tty, length;
    int exitCode = 0;
    Tcl_Channel inChannel, outChannel, errChannel;
    Tcl_DString temp;

    Tcl_FindExecutable(argv[0]);
    interp = Tcl_CreateInterp();
#ifdef TCL_MEM_DEBUG
    Tcl_InitMemory(interp);
    Tcl_CreateCommand(interp, "checkmem", CheckmemCmd, (ClientData) 0,
	    (Tcl_CmdDeleteProc *) NULL);
#endif

    /*
     * Make command-line arguments available in the Tcl variables "argc"
     * and "argv". If the first two arguments are "-file filename"
     * strip them off and use them as the name of a script file to process.
     */

    fileName = NULL;
    if ((argc > 2) && !strcmp(argv[1], "-file")) {
	fileName = argv[2];
	argc-=2;
	argv+=2;
    }
    args = Tcl_Merge(argc-1, argv+1);
    Tcl_SetVar(interp, "argv", args, TCL_GLOBAL_ONLY);
    ckfree(args);
    sprintf(buffer, "%d", argc-1);
    Tcl_SetVar(interp, "argc", buffer, TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "argv0", (fileName != NULL) ? fileName : argv[0],
	    TCL_GLOBAL_ONLY);

    /*
     * Set the "tcl_interactive" variable.
     */

    tty = isatty(0);
    Tcl_SetVar(interp, "tcl_interactive",
	    ((fileName == NULL) && tty) ? "1" : "0", TCL_GLOBAL_ONLY);

    /*
     * Invoke application-specific initialization.
     */

    if (Tcl_AppInit(interp) != TCL_OK) {
        errChannel = Tcl_GetStdChannel(TCL_STDERR);
        if (errChannel) {
            Tcl_Write(errChannel,
                    "application-specific initialization failed: ", -1);
            Tcl_Write(errChannel, interp->result, -1);
            Tcl_Write(errChannel, "\n", 1);
	    exit(1);
        }
    }

    /*
     * If a script file was specified then just source that file
     * and quit.
     */

    if (fileName != NULL) {
        char *msg;
	code = Tcl_EvalFile(interp, fileName);
        if (code != TCL_OK) {
            errChannel = Tcl_GetStdChannel(TCL_STDERR);
            if (errChannel) {
                msg = Tcl_GetVar(interp, "errorInfo", TCL_GLOBAL_ONLY);
                if (msg == NULL) {
                    msg = interp->result;
                }
                Tcl_Write(errChannel, msg, -1);
                Tcl_Write(errChannel, "\n", 1);
            }
            exitCode = 1;
        }
        goto done;
    }

    /*
     * We're running interactively.  Source a user-specific startup
     * file if Tcl_AppInit specified one and if the file exists.
     */

    fileName = Tcl_GetVar(interp, "tcl_rcFileName", TCL_GLOBAL_ONLY);

    if (fileName != NULL) {
        Tcl_Channel c;
        char *fullName;

        Tcl_DStringInit(&temp);
        fullName = Tcl_TranslateFileName(interp, fileName, &temp);
        if (fullName == NULL) {
            errChannel = Tcl_GetStdChannel(TCL_STDERR);
            if (errChannel) {
                Tcl_Write(errChannel, interp->result, -1);
                Tcl_Write(errChannel, "\n", 1);
            }
        } else {

            /*
             * Test for the existence of the rc file before trying to read it.
             */

            c = Tcl_OpenFileChannel(NULL, fullName, "r", 0);
            if (c != (Tcl_Channel) NULL) {
                Tcl_Close(NULL, c);
                if (Tcl_EvalFile(interp, fullName) != TCL_OK) {
                    errChannel = Tcl_GetStdChannel(TCL_STDERR);
                    if (errChannel) {
                        Tcl_Write(errChannel, interp->result, -1);
                        Tcl_Write(errChannel, "\n", 1);
                    }
                }
            }
        }
        Tcl_DStringFree(&temp);
      }

    /*
     * Process commands from stdin until there's an end-of-file.
     */

    gotPartial = 0;
    Tcl_DStringInit(&command);
    inChannel = Tcl_GetStdChannel(TCL_STDIN);
    outChannel = Tcl_GetStdChannel(TCL_STDOUT);
    while (1) {
        if (tty) {
            char *promptCmd;

            promptCmd = Tcl_GetVar(interp,
                gotPartial ? "tcl_prompt2" : "tcl_prompt1", TCL_GLOBAL_ONLY);
            if (promptCmd == NULL) {
defaultPrompt:
                if (!gotPartial && outChannel) {
                    Tcl_Write(outChannel, "% ", 2);
                }
            } else {
                code = Tcl_Eval(interp, promptCmd);
                inChannel = Tcl_GetStdChannel(TCL_STDIN);
                outChannel = Tcl_GetStdChannel(TCL_STDOUT);
                errChannel = Tcl_GetStdChannel(TCL_STDERR);
                if (code != TCL_OK) {
                    if (errChannel) {
                        Tcl_Write(errChannel, interp->result, -1);
                        Tcl_Write(errChannel, "\n", 1);
                    }
                    Tcl_AddErrorInfo(interp,
                            "\n    (script that generates prompt)");
                    goto defaultPrompt;
                }
            }
            if (outChannel) {
                Tcl_Flush(outChannel);
            }
        }
        if (!inChannel) {
            goto done;
        }
        length = Tcl_Gets(inChannel, &command);
        if (length < 0) {
            goto done;
        }
        if ((length == 0) && Tcl_Eof(inChannel) && (!gotPartial)) {
            goto done;
        }

        /*
         * Add the newline removed by Tcl_Gets back to the string.
         */
        
        (void) Tcl_DStringAppend(&command, "\n", -1);

        cmd = Tcl_DStringValue(&command);
        if (!Tcl_CommandComplete(cmd)) {
            gotPartial = 1;
            continue;
	  }

        gotPartial = 0;
        code = Tcl_RecordAndEval(interp, cmd, 0);
        inChannel = Tcl_GetStdChannel(TCL_STDIN);
        outChannel = Tcl_GetStdChannel(TCL_STDOUT);
        errChannel = Tcl_GetStdChannel(TCL_STDERR);
        Tcl_DStringFree(&command);
        if (code != TCL_OK) {
            if (errChannel) {
                Tcl_Write(errChannel, interp->result, -1);
                Tcl_Write(errChannel, "\n", 1);
	      }
	  } else if (tty && (*interp->result != 0)) {
            if (outChannel) {
                Tcl_Write(outChannel, interp->result, -1);
                Tcl_Write(outChannel, "\n", 1);
	      }
	  }
#ifdef TCL_MEM_DEBUG
	if (quitFlag) {
	    Tcl_DeleteInterp(interp);
	    exit(0);
	}
#endif
    }

    /*
     * Rather than calling exit, invoke the "exit" command so that
     * users can replace "exit" with some other command to do additional
     * cleanup on exit.  The Tcl_Eval call should never return.
     */

    done:
    sprintf(buffer, "exit %d", exitCode);
    Tcl_Eval(interp, buffer);
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * CheckmemCmd --
 *
 *	This is the command procedure for the "checkmem" command, which
 *	causes the application to exit after printing information about
 *	memory usage to the file passed to this command as its first
 *	argument.
 *
 * Results:
 *	Returns a standard Tcl completion code.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */
#ifdef TCL_MEM_DEBUG

	/* ARGSUSED */
static int
CheckmemCmd(clientData, interp, argc, argv)
    ClientData clientData;		/* Not used. */
    Tcl_Interp *interp;			/* Interpreter for evaluation. */
    int argc;				/* Number of arguments. */
    char *argv[];			/* String values of arguments. */
{
    if (argc != 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
		" fileName\"", (char *) NULL);
	return TCL_ERROR;
    }
    strcpy(dumpFile, argv[1]);
    quitFlag = 1;
    return TCL_OK;
}
#endif
