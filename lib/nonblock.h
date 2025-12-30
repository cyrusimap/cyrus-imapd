/* nonblock.h -- Set nonbolocking mode on file descriptor */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_NONBLOCK_H
#define INCLUDED_NONBLOCK_H

extern const char nonblock_method_desc[];

extern void nonblock(int fd, int mode);

#endif /* INCLUDED_NONBLOCK_H */
