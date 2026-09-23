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
        filter => [],
        formatters => [],
        failed_tests => Cassandane::Unit::FailedTests->new(),
    }, $class;
}

# The filter tokens that decide whether a test runs at all: testrunner.pl sets
# them from the command line, the plan asks each test about them in turn.  See
# Cassandane::Unit::TestCase::filter for what a token means.
sub filter
{
    my ($self, @tokens) = @_;

    $self->{filter} = \@tokens if @tokens;

    return @{ $self->{filter} };
}

sub create_test_result
{
    my ($self) = @_;
    $self->{_result} = Cassandane::Unit::Result->new();
    return $self->{_result};
}

sub add_formatter
{
    my ($self, $formatter) = @_;

    push @{$self->{formatters}}, $formatter;
}

# this is very similar to Cassandane::Unit::Result's tell_listeners(), except
# without the annoying crash when the listener doesn't care about the event
sub tell_formatters
{
    my ($self, $method, @args) = @_;

    foreach my $formatter (@{$self->{formatters}}) {
        if ($formatter->can($method)) {
            $formatter->$method(@args);
        }
    }
}

sub do_run
{
    my ($self, $suite) = @_;
    my $result = $self->create_test_result();

    $result->add_listener($self->{failed_tests});
    foreach my $f (@{$self->{formatters}}) {
        $result->add_listener($f);
    }

    my $start_time = new Benchmark();
    $suite->run($result, $self);
    my $end_time = new Benchmark();

    foreach my $f (@{$self->{formatters}}) {
        $f->finished($result, $start_time, $end_time);
    }

    return $result->was_successful;
}

1;
