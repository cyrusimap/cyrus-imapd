/* nonblock_fcntl.c -- Set nonblocking mode using fcntl()
 $Id: nonblock_fcntl.c,v 1.12.2.1 2003/02/13 20:33:13 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *
 */
#include <config.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>

#include "xmalloc.h"
#include "exitcodes.h"
#include "nonblock.h"

#ifndef	FNDELAY
#define FNDELAY		O_NDELAY
#endif

#ifdef O_NONBLOCK
#define NON_BLOCKING_MODE O_NONBLOCK
#else
#define NON_BLOCKING_MODE FNDELAY
#endif

const char *nonblock_method_desc = "fcntl";

/*
 * Modifies the non-blocking mode on the file descriptor 'fd'.  If
 * 'mode' is nonzero, sets non-blocking mode, if 'mode' is zero
 * clears non-blocking mode.
 */
void
nonblock(fd, mode)
int fd;
int mode;
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) fatal("Internal error: fcntl F_GETFL failed", EC_IOERR);
    if (mode) {
	flags |= NON_BLOCKING_MODE;
    }
    else {
	flags &= ~NON_BLOCKING_MODE;
    }
    fcntl(fd, F_SETFL, flags);
}
