/*
 * Copyright (c) 1983 Eric P. Allman
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include "xmalloc.h"

/*
**  Arrange to use either varargs or stdargs
*/

# ifdef __STDC__

# include <stdarg.h>

# define VA_LOCAL_DECL	va_list ap;
# define VA_START(f)	va_start(ap, f)
# define VA_END		va_end(ap)

# else

# include <varargs.h>

# define VA_LOCAL_DECL	va_list ap;
# define VA_START(f)	va_start(ap)
# define VA_END		va_end(ap)

# endif

# define MAXLINE 2048            /* max line length */

# ifdef SETPROCTITLE
extern char **environ;

static char		**Argv = NULL;		/* pointer to argument vector */
static char		*LastArgv = NULL;	/* end of argv */
#define MAXUSERENVIRON 100
static char *UserEnviron[MAXUSERENVIRON + 2]; /* saved user environment */
# endif /* SETPROCTITLE */

/*
 * Sets up a process to be able to use setproctitle()
 */
setproctitle_init(argc, argv, envp)
int argc;
char **argv, **envp;
{
# ifdef SETPROCTITLE
    int i, j;
    char *p;

    /*
     * Move the environment so setproctitle can use the space at
     * the top of memory.
     */
    for (i = j = 0; j < MAXUSERENVIRON && (p = envp[i]) != NULL; i++) {
	UserEnviron[j++] = strsave(p);
    }
    UserEnviron[j] = NULL;
    environ = UserEnviron;

    /*
     * Save start and extent of argv for setproctitle.
     */

    Argv = argv;
    if (i > 0)
      LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    else
      LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
# endif /* SETPROCTITLE */
}

/*
**  SETPROCTITLE -- set process title for ps
**
**	Parameters:
**		fmt -- a printf style format string.
**		a, b, c -- possible parameters to fmt.
**
**	Returns:
**		none.
**
**	Side Effects:
**		Clobbers argv of our main procedure so ps(1) will
**		display the title.
*/

#ifdef SETPROCTITLE
# ifdef __hpux
#  include <sys/pstat.h>
# endif
# ifdef BSD4_4
#  include <machine/vmparam.h>
#  include <sys/exec.h>
#  ifdef __bsdi__
#   undef PS_STRINGS	/* BSDI 1.0 doesn't do PS_STRINGS as we expect */
#  endif
#  ifdef PS_STRINGS
#   define SETPROC_STATIC static
#  endif
# endif
# ifndef SETPROC_STATIC
#  define SETPROC_STATIC
# endif
#endif

/*VARARGS1*/
#ifdef __STDC__
setproctitle(char *fmt, ...)
#else
setproctitle(fmt, va_alist)
	char *fmt;
	va_dcl
#endif
{
# ifdef SETPROCTITLE
	register char *p;
	register int i;
	SETPROC_STATIC char buf[MAXLINE];
	VA_LOCAL_DECL
#  ifdef __hpux
	union pstun pst;
#  endif
	extern char **Argv;
	extern char *LastArgv;

	p = buf;

	/* print the argument string */
	VA_START(fmt);
	(void) vsprintf(p, fmt, ap);
	VA_END;

	i = strlen(buf);

#  ifdef __hpux
	pst.pst_command = buf;
	pstat(PSTAT_SETCMD, pst, i, 0, 0);
#  else
#   ifdef PS_STRINGS
	PS_STRINGS->ps_nargvstr = 1;
	PS_STRINGS->ps_argvstr = buf;
#   else
	if (i > LastArgv - Argv[0] - 2)
	{
		i = LastArgv - Argv[0] - 2;
		buf[i] = '\0';
	}
	(void) strcpy(Argv[0], buf);
	p = &Argv[0][i];
	while (p < LastArgv)
		*p++ = ' ';
#   endif
#  endif
# endif /* SETPROCTITLE */
}
