#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Cyrus::ACL;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
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

    my $admintalk = $self->{adminstore}->get_client();

    # let's create ourselves an archive user
    # sub folders of another user - one is subscribable
    $self->{instance}->create_user("archive",
                                   subdirs => [ 'cassandane', ['cassandane', 'sent'] ]);
    $admintalk->setacl("user.archive.cassandane.sent", "cassandane", "lrswp");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test regular delete
#
sub test_delete
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $self->{adminstore}->set_folder('user.archive.cassandane.sent');
    $self->make_message("Message A", store => $self->{adminstore});

    $self->{store}->set_folder('user.archive.cassandane.sent');
    $self->{store}->_select();

    my $res = $talk->store('1', '+flags', '(\\deleted)');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

sub test_many_users
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();
    $self->make_message("Message A");

    $talk->create("INBOX.multi");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    for (1..100) {
        $admintalk->setacl("user.cassandane.multi", "test$_", "lrswipcd");
        $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    }

    my $res = $talk->select("INBOX.multi");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub test_move
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $self->{adminstore}->set_folder('user.archive.cassandane.sent');
    $self->make_message("Message A", store => $self->{adminstore});

    $self->{store}->set_folder('user.archive.cassandane.sent');
    $self->{store}->_select();

    my $res = $talk->move('1', "INBOX");
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

sub test_setacl_badacl
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.badacl");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.badacl", "foo", "ylrswipcd");
    $self->assert_str_equals('bad', $admintalk->get_last_completion_response());
}

sub test_setacl_addacl
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.addacl");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.addacl", "foo", "lrswipkxtecdn");
    $admintalk->setacl("user.cassandane.addacl", "foo", "+a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_setacl_rmacl
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.rmacl");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.rmacl", "foo", "lrswipkxtecdan");
    $admintalk->setacl("user.cassandane.rmacl", "foo", "-a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_setacl_addacl_exists
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.exists");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.exists", "foo", "lrswipkxtecdan");
    $admintalk->setacl("user.cassandane.exists", "foo", "+a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_setacl_rmacl_unexists
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.rmunexists");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.rmunexists", "foo", "lrswipkxtecdn");
    $admintalk->setacl("user.cassandane.rmunexists", "foo", "-a");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_reconstruct
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    my $oldacl = $admintalk->getacl("user.archive.cassandane.sent");

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct');

    my $newacl = $admintalk->getacl("user.archive.cassandane.sent");
    $self->assert_deep_equals($oldacl, $newacl);
}

sub test_setacl_emptyid
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.emptyid");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    # send an empty identifier for SETACL
    $admintalk->setacl("user.cassandane.emptyid", "", "lrswipcd");
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
}

sub test_setacl_badrights
    :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.badrights");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $origacl = $admintalk->getacl("user.cassandane.badrights");

    $admintalk->setacl("user.cassandane.badrights", "cassandane", "b");
    $self->assert_str_equals('bad', $admintalk->get_last_completion_response());

    my $newacl = $admintalk->getacl("user.cassandane.badrights");
    $self->assert_deep_equals($origacl, $newacl);
}

# see also LDAP.pm for groupid tests

1;
