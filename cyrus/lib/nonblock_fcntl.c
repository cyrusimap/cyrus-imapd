/* nonblock_fcntl.c -- Set nonblocking mode using fcntl()
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
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>

#include "nonblock.h"

#ifndef	FNDELAY
#define FNDELAY		O_NDELAY
#endif

#ifdef O_NONBLOCK
#define NON_BLOCKING_MODE O_NONBLOCK
#else
#define NON_BLOCKING_MODE FNDELAY
#endif

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
    if (flags < 0) fatal("Internal error: fcntl F_GETFL failed");
    if (mode) {
	flags |= NON_BLOCKING_MODE;
    }
    else {
	flags &= ~NON_BLOCKING_MODE;
    }
    fcntl(fd, F_SETFL, flags);
}
