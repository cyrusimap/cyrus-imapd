# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::QResync;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::NetString;


sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1, services => ['smmap', 'imap'] }, @_);
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

sub test_qresync_simple
{
    my ($self) = @_;

    xlog $self, "Make some messages";
    my $uid = 1;
    my %msgs;
    for (1..50)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }

    my $talk = $self->{store}->get_client();
    $talk->select("INBOX");
    my $uidvalidity = $talk->get_response_code('uidvalidity');

    xlog $self, "Mark some messages \\Deleted";
    $talk->enable("qresync");
    $talk->store('5:10,25:45', '+flags', '(\\Deleted)');

    xlog $self, "Expunge messages";
    $talk->expunge();
    my @vanished = $talk->get_response_code('vanished');
    $self->assert_equals("5:10,25:45", $vanished[0][0]);

    xlog "QResync mailbox";
    $talk->unselect();
    $talk->select("INBOX", "(QRESYNC ($uidvalidity 0))" => 1);
    @vanished = $talk->get_response_code('vanished');
    $self->assert_num_equals(23, $talk->get_response_code('exists'));
    $self->assert_equals("5:10,25:45", $vanished[0][1]);
}

sub test_qresync_saved_search
{
    my ($self) = @_;

    xlog $self, "Make some messages";
    my $uid = 1;
    my %msgs;
    for (1..3)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }

    my $talk = $self->{store}->get_client();
    $talk->uid(1);
    $talk->enable("qresync");
    $talk->select("INBOX");
    my $since = $talk->get_response_code('highestmodseq');
    for (4..6)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }
    $talk->store('5', '+flags', '(\\Deleted)');
    $talk->expunge();
    $talk->search('RETURN', ['SAVE'], 'SINCE', '1-Feb-1994');
    my $res = $talk->fetch('$', ['FLAGS'], ['CHANGEDSINCE', $since, 'VANISHED']);
    $self->assert_str_equals("4,6", join(',', sort keys %$res));
}

1;
