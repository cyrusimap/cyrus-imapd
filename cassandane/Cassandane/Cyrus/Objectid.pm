# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Objectid;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return  $class->SUPER::new({adminstore => 1}, @_);
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

#
# Test uniqueid and rename
#
sub test_uniqueid
    :AltNamespace :Conversations :min_version_3_1
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create('foo');
    $talk->create('bar');
    $talk->create('foo');
    my $status1 = $talk->status('foo', "(mailboxid)");
    my $status2 = $talk->status('bar', "(mailboxid)");

    $talk->rename('foo', 'renamed');
    my $status3 = $talk->status('renamed', "(mailboxid)");
    my $status4 = $talk->status('bar', "(mailboxid)");

    $self->assert_str_equals($status1->{mailboxid}[0], $status3->{mailboxid}[0]);
    $self->assert_str_equals($status2->{mailboxid}[0], $status4->{mailboxid}[0]);

    $talk->list('', '*', 'return', [ "status", [ "mailboxid" ] ]);
}

#
# Test uniqueid and rename
#
sub test_emailid_threadid
    :AltNamespace :Conversations :min_version_3_1
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create('foo');

    my %exp;

    $self->{store}->set_fetch_attributes('uid', 'cid');

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{B}->set_attributes(uid => 2, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message C";
    $exp{C} = $self->make_message("Message C");
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    $self->check_messages(\%exp);

    $talk->select('INBOX');
    my $data = $talk->fetch('1:*', "(emailid threadid)");

    $talk->search('emailid', $data->{1}{emailid});
    $talk->search('threadid', $data->{1}{threadid});

    $talk->move("2", "foo");

    $talk->fetch('1:*', "(emailid threadid)");

    $talk->select('foo');
    $talk->fetch('1:*', "(emailid threadid)");

    $talk->select('INBOX');

    my $email = <<EOF;
Subject: foo
Date: bar
From: <foobar\@example.com>

Body
EOF

    my $email2 = <<EOF;
Subject: foo
Date: bar
From: <foobar\@example.com>

Body2
EOF

    $email =~ s/\r?\n/\r\n/gs;
    $email2 =~ s/\r?\n/\r\n/gs;

    $talk->append("INBOX", "()", " 7-Feb-1994 22:43:04 -0800", { Literal => "$email" },
                           "()", " 7-Feb-1994 22:43:04 -0800", { Literal => "$email2" });

    # XXX and then what???  is this test incomplete?
}

1;
