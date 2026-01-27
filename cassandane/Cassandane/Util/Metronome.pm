# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Metronome;
use strict;
use warnings;
use Time::HiRes qw(clock_gettime clock_nanosleep CLOCK_MONOTONIC);

use Cassandane::Util::Log;

sub new
{
    my ($class, %params) = @_;

    my $self = {
        # These are floating point numbers in seconds
        # with presumed nanosecond resolution
        interval => 0.0,
        error => 0.0,
        last_tick => undef,
        first_tick => undef,
        nticks => 0,
    };

    $self->{interval} = $params{interval}
        if defined $params{interval};
    $self->{interval} = 1.0/$params{rate}
        if defined $params{rate};

    return bless $self, $class;
}

sub tick
{
    my ($self) = @_;

    my $now = clock_gettime(CLOCK_MONOTONIC);
    $self->{first_tick} ||= $now;
    $self->{nticks}++;
    my $next_tick = ($self->{last_tick} || $now)
                    + $self->{interval};
    my $delay = ($next_tick + $self->{error} - $now);
    clock_nanosleep(CLOCK_MONOTONIC, 1e9 * $delay)
        if ($delay > 0.0);
    $now = clock_gettime(CLOCK_MONOTONIC);
    $self->{error} = $next_tick - $now;
    $self->{last_tick} = $next_tick;
}

sub actual_rate
{
    my ($self) = @_;

    return undef if !$self->{nticks};
    return $self->{nticks} /
            (clock_gettime(CLOCK_MONOTONIC) - $self->{first_tick});
}

1;
