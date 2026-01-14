# SPDX-License-Identifier: BSD-3-Clause-CMU */
# See COPYING file at the root of the distribution for more details. */

use ExtUtils::MakeMaker;
use Config;

my $build = do './build.cfg' || die "build.cfg: $!";

WriteMakefile(
    'NAME'      => 'Cyrus::Annotator::Daemon',
    'ABSTRACT'  => 'Cyrus annotator daemon framework',
    'VERSION_FROM' => "$build->{top_srcdir}/perl/annotator/Daemon.pm", # finds $VERSION
);

package MY; # so that "SUPER" works

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

sub postamble {
    return <<"EOT";

VPATH=$build->{top_srcdir}/perl/annotator

check:

dvi:

installcheck:

EOT
}
