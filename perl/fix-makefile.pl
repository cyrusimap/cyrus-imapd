#!/usr/bin/env perl
# fix-makefile.pl - massage details in generated perl Makefiles
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use warnings;
use strict;
use v5.10; # say

while (<>) {
    if (m/^uninstall_from_sitedirs ::/) {
        print $_;

        # read ahead to massage next line
        my $uninstall = <>;
        die 'unexpected Makefile content'
            if $uninstall !~ m/^\t\$\(NOECHO\) \$\(UNINSTALL\) /;
        $uninstall =~ s/\$\(SITEARCHEXP\)/\$\(DESTINSTALLSITEARCH\)/;
        print $uninstall;

        # and then add some others
        say "\t", '$(RM_F) "$(DESTINSTALLSITEARCH)/auto/$(FULLEXT)/.packlist"';
        say "\t", '$(RM_F) "$(DESTINSTALLSITEARCH)/perllocal.pod"';
    }
    else {
        print $_;
    }
}
