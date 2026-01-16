# SPDX-License-Identifier: BSD-3-Clause-CMU */
# See COPYING file at the root of the distribution for more details. */

use ExtUtils::MakeMaker;
use Config;

my $build = do './build.cfg' || die "build.cfg: $!";

WriteMakefile(
    'NAME'      => 'Cyrus::Annotator::Daemon',
    'ABSTRACT'  => 'Cyrus annotator daemon framework',
    'VERSION_FROM' => "$build->{top_srcdir}/perl/annotator/Daemon.pm", # finds $VERSION
    # This is a disgusting hack to effectively disable the stupid
    # behaviour of the generated Makefile which moves itself aside
    # on a 'make clean' instead of on 'make distclean'.
    'MAKEFILE_OLD' => 'Makefile',
);

sub MY::postamble {
    return <<"EOT";

VPATH=$build->{top_srcdir}/perl/annotator

check:

dvi:

installcheck:

EOT
}
