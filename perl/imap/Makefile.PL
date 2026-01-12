# SPDX-License-Identifier: BSD-3-Clause-CMU */
# See COPYING file at the root of the distribution for more details. */

use ExtUtils::MakeMaker;
use Config;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
$libs = "-lcyrus";

my $build = do './build.cfg' || die "build.cfg $!";

my $LIB_SASL = $build->{LIB_SASL} || '-lsasl2';

# override default xs.c rule with a VPATH-aware version
sub MY::xs_c
{
    return <<'EOT';

.xs.c: .xs
	$(XSUBPPRUN) $(XSPROTOARG) $(XSUBPPARGS) $(XSUBPP_EXTRA_ARGS) $< > $*.xsc && $(MV) $*.xsc $@

EOT
}

# xs_c above is adequate, override this to get it out of the way
sub MY::xs_o
{
    ;
}

sub MY::postamble
{
    return <<"EOT";

VPATH=$build->{top_srcdir}/perl/imap

cyradm: cyradm.sh
	$build->{PERL_PREINSTALL} < \$< > \$\@

check:

dvi:

installcheck:

EOT
}

WriteMakefile(
    'NAME'	=> 'Cyrus::IMAP',
    'ABSTRACT'  => 'Cyrus administrative interface',
    'VERSION_FROM' => "$build->{top_srcdir}/perl/imap/IMAP.pm", # finds $VERSION
    'macro'	=> {
		    'IMCLIENT_LIBS' => '',	# hack
		},
    'clean'	=> {'FILES' => 'libcyrperl.a cyradm'},
    'LD'       => $Config{ld} . " $build->{GCOV_LDFLAGS}",
    'OBJECT'    => 'IMAP.o',
    'MYEXTLIB'  => "$build->{top_builddir}/perl/.libs/libcyrus.a $build->{top_builddir}/perl/.libs/libcyrus_min.a",
    'LIBS'	=> [ "$LIB_SASL $build->{SSL_LIBS} $build->{LIB_UUID} $build->{LIB_REGEX} $build->{ZLIB} $build->{GCOV_LIBS}"],
    'DEFINE'	=> '-DPERL_POLLUTE',    # e.g., '-DHAVE_SOMETHING'
    'INC'	=> "-I$build->{top_srcdir} -I$build->{top_srcdir}/com_err/et $build->{SASLFLAGS} $build->{SSL_CFLAGS} $build->{GCOV_CFLAGS} -I$build->{top_srcdir}/perl/imap",
    'EXE_FILES' => [cyradm],
    # This is a disgusting hack to effectively disable the stupid
    # behaviour of the generated Makefile which moves itself aside
    # on a 'make clean' instead of on 'make distclean'.
    'MAKEFILE_OLD' => 'Makefile',
);
