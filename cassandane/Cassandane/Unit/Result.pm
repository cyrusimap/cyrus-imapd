# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Result;
use strict;
use warnings;
use experimental 'signatures';

use Error qw(:try);

use Cassandane::Error;
use Cassandane::Failure;

sub new ($class)
{
    return bless {
        failures  => [],
        errors    => [],
        listeners => [],
        run_count => 0,
    }, $class;
}

sub listeners ($self)
{
    return $self->{listeners}->@*;
}

sub add_listener ($self, $listener)
{
    push $self->{listeners}->@*, $listener;
    return;
}

sub set_listeners ($self, @listeners)
{
    $self->{listeners} = \@listeners;
    return;
}

sub tell_listeners ($self, $event, @args)
{
    $_->$event(@args) for $self->{listeners}->@*;
    return;
}

# Run one test and record how it went.  A Cassandane::Failure means the test
# ran and came out wrong; anything else thrown means it never got to say.
sub run ($self, $test)
{
    $self->start_test($test);

    try {
        $test->run_bare();
        $self->add_pass($test);
    }
    catch Cassandane::Failure with {
        $self->add_failure($test, shift->stringify);
    }
    catch Error with {
        my $thrown = shift;
        $thrown = Cassandane::Error->from_thrown($thrown)
            if not $thrown->isa('Cassandane::Error');
        $self->add_error($test, $thrown->stringify);
    }
    otherwise {
        $self->add_error($test, Cassandane::Error->from_thrown(shift)->stringify);
    };

    $self->end_test($test);
    return;
}

sub start_test ($self, $test)
{
    $self->{run_count}++;
    $self->tell_listeners(start_test => $test);
    return;
}

sub end_test ($self, $test)
{
    $self->tell_listeners(end_test => $test);
    return;
}

sub add_pass ($self, $test)
{
    $self->tell_listeners(add_pass => $test);
    return;
}

sub add_failure ($self, $test, $report)
{
    push $self->{failures}->@*, { test => $test, report => $report };
    $self->tell_listeners(add_failure => $test, $report);
    return;
}

sub add_error ($self, $test, $report)
{
    push $self->{errors}->@*, { test => $test, report => $report };
    $self->tell_listeners(add_error => $test, $report);
    return;
}

sub run_count ($self)
{
    return $self->{run_count};
}

# Each is an arrayref of { test, report }: the test that went wrong, and what
# a report should say about it.
sub failures ($self)
{
    return $self->{failures};
}

sub errors ($self)
{
    return $self->{errors};
}

sub failure_count ($self)
{
    return scalar $self->{failures}->@*;
}

sub error_count ($self)
{
    return scalar $self->{errors}->@*;
}

sub was_successful ($self)
{
    return !$self->failure_count && !$self->error_count;
}

1;
