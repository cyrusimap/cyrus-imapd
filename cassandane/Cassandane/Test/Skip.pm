# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Skip;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_skip_old_version
    :min_version_3_0
{
    my ($self) = @_;

    my ($maj, $min) = Cassandane::Instance->get_version();

    $self->assert($maj >= 3);
    $self->assert($min >= 0);
}

sub test_skip_new_version
    :max_version_2_5
{
    my ($self) = @_;

    my ($maj, $min) = Cassandane::Instance->get_version();

    $self->assert($maj <= 2);
    $self->assert($min <= 5);
}

sub test_skip_outside_range
    :min_version_2_5_0 :max_version_2_5_9
{
    my ($self) = @_;

    my ($maj, $min, $rev) = Cassandane::Instance->get_version();

    $self->assert_equals($maj, 2);
    $self->assert_equals($min, 5);
    $self->assert($rev >= 0);
    $self->assert($rev <= 9);
}

# Don't actually use this device in real tests.  This is meant to exercise the
# skip mechanism, not as an example of its proper use :)
sub test_skip_everything
    :min_version_3_0 :max_version_2_5
{
    my ($self) = @_;

    my ($maj, $min, $rev) = Cassandane::Instance->get_version();

    # should never get here -- if we do, we've failed
    $self->assert(0);
}

1;
