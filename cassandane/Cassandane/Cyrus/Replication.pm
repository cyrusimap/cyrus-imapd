# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Replication;
use strict;
use warnings;
use Data::Dumper;
use DateTime;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Service;
use Cassandane::Config;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new({ replica => 1, adminstore => 1 }, @_);

    $self->needs('component', 'replication');
    return $self;
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

# XXX need a test for version 10 mailbox without guids in it!

#* create mailbox on master with no messages
#* sync_client to get it copied to replica
#* create a message in the mailbox on replica (imaptalk on replica_store)
#* delete the message from the replica (with expunge_mode default or expunge_mode immediate... try both)
#* run sync_client on the master again and make sure it successfully syncs up

sub assert_user_sub_exists
{
    my ($self, $instance, $user) = @_;

    my $subs = $instance->get_conf_user_file($user, 'sub');
    $self->assert_not_null($subs);

    xlog $self, "Looking for subscriptions file $subs";

    $self->assert_file_test($subs, '-f');
}

sub assert_user_sub_not_exists
{
    my ($self, $instance, $user) = @_;

    my $subs = $instance->get_conf_user_file($user, 'sub');
    return unless $subs;  # user might not exist

    xlog $self, "Looking for subscriptions file $subs";

    $self->assert_not_file_test($subs, '-f');
}

use Cassandane::Tiny::Loader 'tiny-tests/Replication';

1;
