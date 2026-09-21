# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::WorkerListener;
use strict;
use warnings;

use base qw(Test::Unit::Listener);
use Cassandane::Util::Log;

sub new
{
    my ($class) = shift;
    my $self = {
        witem => undef,
    };
    return bless $self, $class;
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

sub add_error
{
    my ($self, $test, $exception) = @_;
    my $witem = $self->{witem};
    $witem->{result} = 'error';

    # Remove '-object' which points at the TestCase, which will have all
    # sorts of stuff we can't thaw.  We have enough information to
    # discover the right TestCase in the parent process.
    $exception->{'-object'} = undef;
    $witem->{exception} = $exception;
}

sub add_failure
{
    my ($self, $test, $exception) = @_;
    my $witem = $self->{witem};
    $witem->{result} = 'fail';

    # Remove '-object' which points at the TestCase, which will have all
    # sorts of stuff we can't thaw.  We have enough information to
    # discover the right TestCase in the parent process.
    $exception->{'-object'} = undef;
    $witem->{exception} = $exception;
}

sub add_pass
{
    my ($self, $test) = @_;
    my $witem = $self->{witem};
    $witem->{result} = 'pass';
}

1;
