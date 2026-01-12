# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
use ExtUtils::MakeMaker;
use Config;

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

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Cyrus::SIEVE::managesieve',
    'ABSTRACT'  => 'Cyrus Sieve management interface',
    'VERSION_FROM' => "$build->{top_srcdir}/perl/sieve/managesieve/managesieve.pm", # finds $VERSION
    'MYEXTLIB'  => "../lib/.libs/libisieve.a $build->{top_builddir}/perl/.libs/libcyrus.a $build->{top_builddir}/perl/.libs/libcyrus_min.a",
    'LIBS'	=> ["$LIB_SASL $build->{SSL_LIBS} $build->{LIB_UUID} $build->{LIB_REGEX} $build->{ZLIB} $build->{SQLITE_LIBADD} $build->{MYSQL_LIBADD} $build->{PGSQL_LIBADD} $build->{ICU_LIBS}"],
    'CCFLAGS'	=> "$build->{GCOV_CFLAGS}",
    'DEFINE'	=> '-DPERL_POLLUTE',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> "-I$build->{top_srcdir}/lib -I$build->{top_srcdir}/perl/sieve -I$build->{top_srcdir}/perl/sieve/lib $build->{SASLFLAGS} $build->{SSL_CFLAGS}",
    'OBJECT'    => 'managesieve.o',
    'LD'	=> $Config{ld} . " $build->{GCOV_LDFLAGS}",
    # This is a disgusting hack to effectively disable the stupid
    # behaviour of the generated Makefile which moves itself aside
    # on a 'make clean' instead of on 'make distclean'.
    'MAKEFILE_OLD' => 'Makefile',
);

sub MY::postamble {
    return <<"EOT";

VPATH=$build->{top_srcdir}/perl/sieve/managesieve

check:

dvi:

installcheck:

EOT
}
