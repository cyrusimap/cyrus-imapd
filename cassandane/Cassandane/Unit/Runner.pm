# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Runner;
use strict;
use warnings;
use Benchmark;

use Cassandane::Unit::FailedTests;
use Cassandane::Unit::Result;

sub new
{
    my ($class) = @_;

    return bless {
        listeners => [ Cassandane::Unit::FailedTests->new() ],
    }, $class;
}

# A formatter is a listener that reports what it hears, and there is only the
# one list of listeners for it to go on.
sub add_formatter
{
    my ($self, $formatter) = @_;

    push @{$self->{listeners}}, $formatter;
}

sub do_run
{
    my ($self, $plan) = @_;

    my $result = Cassandane::Unit::Result->new();
    $result->add_listener($_) for @{$self->{listeners}};

    my $start_time = new Benchmark();
    $plan->run($result);
    my $end_time = new Benchmark();

    $result->tell_listeners(finished => $result, $start_time, $end_time);

    return $result->was_successful;
}

1;
