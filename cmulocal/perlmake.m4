# perlmake.m4 - Perl MakeMaker support
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# CMU_PERL_MAKEMAKER
# ------------------
#
# 1) run the module's Makefile.PL to generate a Makefile
# 2) run it through fix-makefile.pl to massage some details
#
# while taking pains to not leave behind temporary files on success,
# nor a bogus 'Makefile' on failure
AC_DEFUN([CMU_PERL_MAKEMAKER],[
AC_CONFIG_FILES([$1/build.cfg:perl/build.cfg.in])
AC_CONFIG_COMMANDS($1/Makefile,[
    (cd $1 \
        && $PERL ${ac_top_srcdir}/$1/Makefile.PL $MAKE_MAKER_ARGS \
        && mv Makefile Makefile.ORIG \
        && $PERL ${ac_top_srcdir}/perl/fix-makefile.pl Makefile.ORIG > Makefile.NEW \
        && mv Makefile.NEW Makefile \
        && rm Makefile.ORIG
    ) || as_fn_error $? "failed to generate Makefile for $1"
],[
    PERL="${PERL}"
    MAKE_MAKER_ARGS="PREFIX=${prefix}"
])
])#CMU_PERL_MAKEMAKER
