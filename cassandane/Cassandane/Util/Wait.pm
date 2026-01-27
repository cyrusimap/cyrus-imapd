# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Wait;
use strict;
use warnings;
use base qw(Exporter);
use Time::HiRes qw(sleep gettimeofday tv_interval);

use Cassandane::Util::Log;

our @EXPORT = qw(&timed_wait);

sub timed_wait
{
    my ($condition, %p) = @_;
    $p{delay} = 0.010           # 10 millisec
        unless defined $p{delay};
    $p{maxwait} = 20.0
        unless defined $p{maxwait};
    $p{description} = 'unknown condition'
        unless defined $p{description};

    my $start = [gettimeofday()];
    my $delayed = 0;
    while ( ! $condition->() )
    {
        die "Timed out waiting for " . $p{description}
            if (tv_interval($start, [gettimeofday()]) > $p{maxwait});
        sleep($p{delay});
        $delayed = 1;
        $p{delay} *= 1.5;       # backoff
    }

    if ($delayed)
    {
        my $t = tv_interval($start, [gettimeofday()]);
        xlog "Waited $t sec for " . $p{description};
        return $t;
    }
    return 0.0;
}


1;
