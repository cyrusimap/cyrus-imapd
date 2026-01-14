# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Mbpath;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

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

sub test_mbpath_8bit
{
    my ($self) = @_;

    xlog $self, "Test mbpath 8 bit name parsing";

    # create and prepare the user
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create('A & B');

    xlog "check with 8bit name";
    my $mbpath = $self->{instance}->run_mbpath('user.cassandane.A & B');
    $self->assert_str_equals($mbpath->{mbname}{intname}, 'user.cassandane.A &- B');

    xlog "check with 7bit name";
    $mbpath = $self->{instance}->run_mbpath("-7", 'user.cassandane.A &- B');
    $self->assert_str_equals($mbpath->{mbname}{intname}, 'user.cassandane.A &- B');
}

1;
