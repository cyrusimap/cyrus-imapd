/* setproctitle -- set process title shown by ps(1)
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
/*
 * Copyright (c) 1983, 1995 Eric P. Allman
 * Copyright (c) 1988, 1993
 *      The Regents of the University of California.  All rights reserved.
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"

# define VA_LOCAL_DECL  va_list ap;
# define VA_START(f)    va_start(ap, f)
# define VA_END         va_end(ap)

# define MAXLINE 2048            /* max line length */

extern char **environ;
#ifdef USE_SETPROCTITLE
static int setproctitle_enable = 1;
#else
static int setproctitle_enable = 0;
#endif

static char             **Argv = NULL;          /* pointer to argument vector */
static char             *LastArgv = NULL;       /* end of argv */

extern void setproctitle_init(int argc, char **argv, char **envp); /* XXX WTF!?!?!? no header? */

/*
 * Sets up a process to be able to use setproctitle()
 */
EXPORTED void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;

    if (!setproctitle_enable) return;

    /*
     * Move the environment so setproctitle can use the space at
     * the top of memory.
     */
    for (i = 0; envp[i] != NULL; i++)
        continue;
    environ = (char **) xmalloc(sizeof (char *) * (i + 1));
    for (i = 0; envp[i] != NULL; i++)
        environ[i] = xstrdup(envp[i]);
    environ[i] = NULL;

    /*
     * Save start and extent of argv for setproctitle.
     */

    Argv = argv;
    if (i > 0)
      LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    else
      LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
}

/*
**  SETPROCTITLE -- set process title for ps
**
**      Parameters:
**              fmt -- a printf style format string.
**              a, b, c -- possible parameters to fmt.
**
**      Returns:
**              none.
**
**      Side Effects:
**              Clobbers argv of our main procedure so ps(1) will
**              display the title.
*/

#define SPT_NONE        0       /* don't use it at all */
#define SPT_REUSEARGV   1       /* cover argv with title information */
#define SPT_BUILTIN     2       /* use libc builtin */
#define SPT_PSTAT       3       /* use pstat(PSTAT_SETCMD, ...) */
#define SPT_PSSTRINGS   4       /* use PS_STRINGS->... */
#define SPT_SYSMIPS     5       /* use sysmips() supported by NEWS-OS 6 */
#define SPT_SCO         6       /* write kernel u. area */

#ifndef SPT_TYPE
# define SPT_TYPE       SPT_REUSEARGV
#endif

#if SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN

# if SPT_TYPE == SPT_PSTAT
#  include <sys/pstat.h>
# endif
# if SPT_TYPE == SPT_PSSTRINGS
#  include <machine/vmparam.h>
#  include <sys/exec.h>
#  ifndef PS_STRINGS    /* hmmmm....  apparently not available after all */
#   undef SPT_TYPE
#   define SPT_TYPE     SPT_REUSEARGV
#  else
#   ifndef NKPDE                        /* FreeBSD 2.0 */
#    define NKPDE 63
typedef unsigned int    *pt_entry_t;
#   endif
#  endif
# endif

# if SPT_TYPE == SPT_PSSTRINGS
#  define SETPROC_STATIC        static
# else
#  define SETPROC_STATIC
# endif

# if SPT_TYPE == SPT_SYSMIPS
#  include <sys/sysmips.h>
#  include <sys/sysnews.h>
# endif

# if SPT_TYPE == SPT_SCO
#  include <sys/immu.h>
#  include <sys/dir.h>
#  include <sys/user.h>
#  include <sys/fs/s5param.h>
#  if PSARGSZ > MAXLINE
#   define SPT_BUFSIZE  PSARGSZ
#  endif
# endif

# ifndef SPT_PADCHAR
#  define SPT_PADCHAR   ' '
# endif

# ifndef SPT_BUFSIZE
#  define SPT_BUFSIZE   MAXLINE
# endif

#endif /* SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN */

#if SPT_TYPE != SPT_BUILTIN

/*VARARGS1*/
HIDDEN void
__attribute__((format(printf, 1, 2)))
#if SPT_TYPE != SPT_NONE
setproctitle(const char *fmt, ...)
#else
setproctitle(const char *fmt __attribute__((__unused__)), ...)
#endif
{
# if SPT_TYPE != SPT_NONE
        register char *p;
        register int i;
        SETPROC_STATIC char buf[SPT_BUFSIZE];
        VA_LOCAL_DECL
#  if SPT_TYPE == SPT_PSTAT
        union pstun pst;
#  endif
#  if SPT_TYPE == SPT_SCO
        off_t seek_off;
        static int kmem = -1;
        static int kmempid = -1;
        struct user u;
#  endif
#  if SPT_TYPE == SPT_REUSEARGV
        extern char **Argv;
        extern char *LastArgv;
#  endif

        if (!setproctitle_enable) return;

        p = buf;

        /* print the argument string */
        VA_START(fmt);
        (void) vsprintf(p, fmt, ap);
        VA_END;

        i = strlen(buf);

#  if SPT_TYPE == SPT_PSTAT
        pst.pst_command = buf;
        pstat(PSTAT_SETCMD, pst, i, 0, 0);
#  endif
#  if SPT_TYPE == SPT_PSSTRINGS
        PS_STRINGS->ps_nargvstr = 1;
        PS_STRINGS->ps_argvstr = buf;
#  endif
#  if SPT_TYPE == SPT_SYSMIPS
        sysmips(SONY_SYSNEWS, NEWS_SETPSARGS, buf);
#  endif
#  if SPT_TYPE == SPT_SCO
        if (kmem < 0 || kmempid != getpid())
        {
                if (kmem >= 0)
                        close(kmem);
                kmem = open(_PATH_KMEM, O_RDWR, 0);
                if (kmem < 0)
                        return;
                (void) fcntl(kmem, F_SETFD, 1);
                kmempid = getpid();
        }
        buf[PSARGSZ - 1] = '\0';
        seek_off = UVUBLK + (off_t) u.u_psargs - (off_t) &u;
        if (lseek(kmem, (char *) seek_off, SEEK_SET) == seek_off)
                (void) write(kmem, buf, PSARGSZ);
#  endif
#  if SPT_TYPE == SPT_REUSEARGV
        if (i > LastArgv - Argv[0] - 2)
        {
                i = LastArgv - Argv[0] - 2;
                buf[i] = '\0';
        }
        (void) strcpy(Argv[0], buf);
        p = &Argv[0][i];
        while (p < LastArgv)
                *p++ = SPT_PADCHAR;
        Argv[1] = NULL;
#  endif
# endif /* SPT_TYPE != SPT_NONE */
}

#endif /* SPT_TYPE != SPT_BUILTIN */
