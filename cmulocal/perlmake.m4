# perlmake.m4 - Perl MakeMaker support
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# CMU_PERL_MAKEMAKER
# ------------------
AC_DEFUN([CMU_PERL_MAKEMAKER],[
AC_CONFIG_FILES([$1/Makefile.PL])
AC_CONFIG_COMMANDS($1/Makefile,[
    ( cd $1;
      $PERL Makefile.PL $MAKE_MAKER_ARGS;
      $PERL -i -pe'next unless /^uninstall_from_sitedirs ::/;
		print $_;
		$_ = <>;
		s/\$\(SITEARCHEXP\)/\$\(DESTINSTALLSITEARCH\)/;
		$_ .= <<'END';
	\$(RM_F) \"\$(DESTINSTALLSITEARCH)/auto/\$(FULLEXT)/.packlist\"
	\$(RM_F) \"\$(DESTINSTALLSITEARCH)/perllocal.pod\"
END
	  ' Makefile
    )
],[
    PERL="${PERL}"
    MAKE_MAKER_ARGS="PREFIX=${prefix}"
])
])#CMU_PERL_MAKEMAKER
