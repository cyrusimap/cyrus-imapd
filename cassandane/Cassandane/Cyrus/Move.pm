# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Move;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config::default()->clone();
    $config->set("conversations", "yes");
    $config->set("reverseacls", "yes");
    $config->set("annotation_allow_undefined", "yes");
    return $class->SUPER::new({ config => $config, adminstore => 1 }, @_);
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

sub test_move_new_user
    :NoAltNameSpace
{
    # test whether the imap_admins setting works correctly
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $admintalk->create("user.user2");
    $admintalk->create("user.user2.sub");
    $admintalk->setacl("user.user2.sub", "cassandane", "lrswited");

    $talk->enable("QRESYNC");
    $talk->select("INBOX");

    xlog $self, "create a message and mark it \\Seen";
    $self->make_message("Message foo");
    $talk->store("1", "+flags", "\\Seen");

    xlog $self, "moving to second user works";
    $talk->move("1", "user.user2.sub");
    $talk->select("user.user2.sub");
    my $res = $talk->fetch("1", "(flags)");
    my $flags = $res->{1}->{flags};
    $self->assert_contains("\\Seen", $flags);

    xlog $self, "moving back works";
    $talk->move("1", "INBOX");
    $talk->select("INBOX");
    $res = $talk->fetch("1", "(flags)");
    $flags = $res->{1}->{flags};
    $self->assert_contains("\\Seen", $flags);
}

1;
