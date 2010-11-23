# maintainer.m4 - maintainer mode
#
# Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# CMU_MAINTAINER_MODE
# ---------------
dnl This is a re-implementation of Automake's AM_MAINTAINER_MODE
AC_DEFUN([CMU_MAINTAINER_MODE],[
AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
AC_ARG_ENABLE([maintainer-mode],
              [AC_HELP_STRING([--enable-maintainer-mode],
                              [enable make rules and dependencies not useful
			      (and sometimes confusing) to the casual installer])],
              [USE_MAINTAINER_MODE=$enableval],
              [USE_MAINTAINER_MODE=no])
AC_MSG_RESULT($USE_MAINTAINER_MODE)
if test $USE_MAINTAINER_MODE = yes; then
    MAINTAINER_MODE_TRUE=
    MAINTAINER_MODE_FALSE='#'
else
    MAINTAINER_MODE_TRUE='#'
    MAINTAINER_MODE_FALSE=
fi
MAINT=$MAINTAINER_MODE_TRUE
AC_SUBST(MAINT)
AC_SUBST(MAINTAINER_MODE_TRUE)
AC_SUBST(MAINTAINER_MODE_FALSE)
])#CMU_MAINTAINER_MODE
