# perlmake.m4 - Perl MakeMaker support
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# CMU_PERL_MAKEMAKER
# ------------------
AC_DEFUN([CMU_PERL_MAKEMAKER],[
AC_CONFIG_FILES([$1/build.cfg:perl/build.cfg.in])
AC_CONFIG_COMMANDS($1/Makefile,[
    ( cd $1 \
      && $PERL ${ac_top_srcdir}/$1/Makefile.PL $MAKE_MAKER_ARGS
    ) || as_fn_error $? "failed to generate Makefile for $1"

],[
    PERL="${PERL}"
    MAKE_MAKER_ARGS="PREFIX=${prefix}"
])
])#CMU_PERL_MAKEMAKER
