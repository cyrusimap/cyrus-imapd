/* ftruncate -- Replacement ftruncate() function
 * Does nothing
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
 */

#include <errno.h>
extern int errno;

int
ftruncate(fd, length)
int fd;
int length;
{
    errno = EINVAL;
    return -1;
}

