# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
use ExtUtils::MakeMaker;
use Config;

$libs = "-lcyrus";

my $build = do './build.cfg' || die "build.cfg $!";

my $LIB_SASL = $build->{LIB_SASL} || '-lsasl2';

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'      => 'Cyrus::SIEVE::managesieve',
    'ABSTRACT'  => 'Cyrus Sieve management interface',
    'VERSION_FROM' => "$build->{top_srcdir}/perl/sieve/managesieve/managesieve.pm", # finds $VERSION
    'MYEXTLIB'  => "../lib/.libs/libisieve.a $build->{top_builddir}/perl/.libs/libcyrus.a $build->{top_builddir}/perl/.libs/libcyrus_min.a",
    'LIBS'      => ["$LIB_SASL $build->{SSL_LIBS} $build->{LIB_UUID} $build->{LIB_REGEX} $build->{ZLIB} $build->{SQLITE_LIBADD} $build->{MYSQL_LIBADD} $build->{PGSQL_LIBADD} $build->{ICU_LIBS}"],
    'CCFLAGS'   => "$build->{GCOV_CFLAGS}",
    'DEFINE'    => '-DPERL_POLLUTE',     # e.g., '-DHAVE_SOMETHING'
    'INC'       => "-I$build->{top_srcdir}/lib -I$build->{top_srcdir}/perl/sieve -I$build->{top_srcdir}/perl/sieve/lib $build->{SASLFLAGS} $build->{SSL_CFLAGS}",
    'OBJECT'    => 'managesieve.o',
    'LD'        => $Config{ld} . " $build->{GCOV_LDFLAGS}",
);

package MY; # so that "SUPER" works right

# prevent 'clean' target from renaming the Makefile
sub clean
{
    my @clean = split "\n", shift->SUPER::clean(@_);

    # suppresses these actions:
    #   $(NOECHO) $(RM_F) $(MAKEFILE_OLD)
    #   - $(MV) $(FIRST_MAKEFILE) $(MAKEFILE_OLD) $(DEV_NULL)
    @clean = grep { $_ !~ m/\Q$(MAKEFILE_OLD)\E/ } @clean;

    return join "\n", @clean;
}

# massage uninstall_from_sitedirs rule so that top level 'make distcheck'
# can succeed.
# there is no 'sub uninstall_from_sitedirs' to override, all the install
# and uninstall rules are generated in one go by 'sub install'.  so
# override and manipulate that
sub install
{
    my @orig = split "\n", shift->SUPER::install(@_);
    my @modified;

    my @inject = (
        '$(RM_F) "$(DESTINSTALLSITEARCH)/auto/$(FULLEXT)/.packlist"',
        '$(RM_F) "$(DESTINSTALLSITEARCH)/perllocal.pod"',
    );

    my $got_uninstall_from_sitedirs = 0;
    foreach my $line (@orig) {
        if ($line =~ m/^uninstall_from_sitedirs ::/) {
            $got_uninstall_from_sitedirs = 1;
            push @modified, $line;
        }
        elsif ($got_uninstall_from_sitedirs) {
            $line =~ s{\Q$(SITEARCHEXP)\E}{\$(DESTINSTALLSITEARCH)};
            push @modified, $line;

            push @modified, "\t$_" for @inject;
            $got_uninstall_from_sitedirs = 0;
        }
        else {
            push @modified, $line;
        }
    }

    return join "\n", @modified;
}

# override default xs.c rule with a VPATH-aware version
sub xs_c
{
    return <<"EOT";

.xs.c: .xs
\t\$(XSUBPPRUN) \$(XSPROTOARG) \$(XSUBPPARGS) \$(XSUBPP_EXTRA_ARGS) \$< > \$*.xsc && \$(MV) \$*.xsc \$@

EOT
}

# xs_c above is adequate, override this to get it out of the way
sub xs_o
{
    ;
}

sub postamble
{
    return <<"EOT";

VPATH=$build->{top_srcdir}/perl/sieve/managesieve

check:

dvi:

installcheck:

EOT
}
