# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Slurp;
use strict;
use warnings;
use base qw(Exporter);


our @EXPORT = qw(&slurp_file);

sub slurp_file
{
    my ($filename) = @_;

    local $/;
    open my $f, '<', $filename
        or die "Cannot open $filename for reading: $!\n";
    my $str = <$f>;
    close $f;

    return $str;
}

1;
