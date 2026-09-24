# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Runner;
use strict;
use warnings;
use experimental 'signatures';

use Benchmark;

use Cassandane::Unit::FailedTests;

sub new
{
    my ($class) = @_;

    return bless {
        listeners  => [ Cassandane::Unit::FailedTests->new() ],
        failures   => [],
        errors     => [],
        run_count  => 0,
        skips      => [],
    }, $class;
}

sub add_listener ($self, $listener)
{
    push $self->{listeners}->@*, $listener;
    return;
}

sub tell_listeners ($self, $event, @args)
{
    $_->$event(@args) for $self->{listeners}->@*;
    return;
}

sub start_test ($self, $witem)
{
    $self->{run_count}++;
    $self->tell_listeners(start_test => $witem);
    return;
}

sub end_test ($self, $witem)
{
    $self->tell_listeners(end_test => $witem);
    return;
}

sub add_pass ($self, $witem)
{
    $self->tell_listeners(add_pass => $witem);
    return;
}

sub add_failure ($self, $witem)
{
    push $self->{failures}->@*, $witem;
    $self->tell_listeners(add_failure => $witem);
    return;
}

sub add_error ($self, $witem)
{
    push $self->{errors}->@*, $witem;
    $self->tell_listeners(add_error => $witem);
    return;
}

sub add_skip ($self, $witem)
{
    push $self->{skips}->@*, $witem;
    $self->tell_listeners(add_skip => $witem);
    return;
}

sub was_successful ($self)
{
    return !$self->{failures}->@* && !$self->{errors}->@*;
}

# How the run went, as plain data, for a listener to report at the end.
sub result_summary ($self)
{
    return {
        was_successful => ($self->was_successful ? 1 : 0),
        run_count      => $self->{run_count},
        failures       => [ $self->{failures}->@* ],
        errors         => [ $self->{errors}->@* ],
        skips          => [ $self->{skips}->@* ],
    };
}

sub do_run
{
    my ($self, $plan) = @_;

    my $start_time = new Benchmark();
    $plan->run($self);
    my $end_time = new Benchmark();

    $self->tell_listeners(finished => $self->result_summary,
                          $start_time, $end_time);

    return $self->was_successful;
}

1;
