# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::OutcomeListener;
use strict;
use warnings;

sub new
{
    my ($class) = shift;
    my $self = {
        outcome => undef,
    };
    return bless $self, $class;
}

sub reset
{
    my ($self) = @_;
    $self->{outcome} = undef;
}

sub outcome
{
    my ($self) = @_;
    return $self->{outcome};
}

sub start_suite
{
    my ($self, $suite) = @_;
    # nothing to see here
}

sub start_test
{
    my ($self, $test) = @_;
    # nothing to see here
}

sub end_test
{
    my ($self, $test) = @_;
    # nothing to see here
}

sub end_suite
{
    my ($self, $suite) = @_;
    # nothing to see here
}

sub _failure
{
    my ($exception) = @_;
    return {
        text       => $exception->text(),
        stacktrace => $exception->{'-stacktrace'},
        file       => $exception->file(),
        line       => $exception->line(),
    };
}

sub add_error
{
    my ($self, $test, $exception) = @_;
    $self->{outcome} = { outcome => 'error', failure => _failure($exception) };
}

sub add_failure
{
    my ($self, $test, $exception) = @_;
    $self->{outcome} = { outcome => 'fail', failure => _failure($exception) };
}

sub add_pass
{
    my ($self, $test) = @_;
    $self->{outcome} = { outcome => 'pass' };
}

1;
