# SPDX-License-Identifier: BSD-3-Clause-CMU */
# See COPYING file at the root of the distribution for more details. */

use ExtUtils::MakeMaker;
use Config;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
$libs = "-lcyrus";

my $build = do './build.cfg' || die "build.cfg $!";

my $LIB_SASL = $build->{LIB_SASL} || '-lsasl2';

WriteMakefile(
    'NAME'      => 'Cyrus::IMAP',
    'ABSTRACT'  => 'Cyrus administrative interface',
    'VERSION_FROM' => "$build->{top_srcdir}/perl/imap/IMAP.pm", # finds $VERSION
    'macro'     => {
        'IMCLIENT_LIBS' => '',  # hack
    },
    'clean'     => {'FILES' => 'libcyrperl.a cyradm'},
    'LD'        => $Config{ld} . " $build->{GCOV_LDFLAGS}",
    'OBJECT'    => 'IMAP.o',
    'MYEXTLIB'  => "$build->{top_builddir}/perl/.libs/libcyrus.a $build->{top_builddir}/perl/.libs/libcyrus_min.a",
    'LIBS'      => [ "$LIB_SASL $build->{SSL_LIBS} $build->{LIB_UUID} $build->{LIB_REGEX} $build->{ZLIB} $build->{GCOV_LIBS}"],
    'DEFINE'    => '-DPERL_POLLUTE',    # e.g., '-DHAVE_SOMETHING'
    'INC'       => "-I$build->{top_srcdir} -I$build->{top_srcdir}/com_err/et $build->{SASLFLAGS} $build->{SSL_CFLAGS} $build->{GCOV_CFLAGS} -I$build->{top_srcdir}/perl/imap",
    'EXE_FILES' => [cyradm],
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

VPATH=$build->{top_srcdir}/perl/imap

cyradm: cyradm.sh
\t$build->{PERL_PREINSTALL} < \$< > \$\@

check:

dvi:

installcheck:

EOT
}
