# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::OutcomeListener;
use strict;
use warnings;
use base qw(Cassandane::Unit::Listener);

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

sub add_error
{
    my ($self, $test, $report) = @_;
    $self->{outcome} = { outcome => 'error', report => $report };
}

sub add_failure
{
    my ($self, $test, $report) = @_;
    $self->{outcome} = { outcome => 'fail', report => $report };
}

sub add_pass
{
    my ($self, $test) = @_;
    $self->{outcome} = { outcome => 'pass' };
}

1;
