/* nonblock_fcntl.c -- Set nonblocking mode using ioctl()
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
#include <sys/ioctl.h>

#include "nonblock.h"

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
    mode = mode ? 1 : 0;

    if (ioctl(fd, FIONBIO, (char *)&mode) < 0) {
	fatal("Internal error: ioctl FIONBIO failed");
    }
}
