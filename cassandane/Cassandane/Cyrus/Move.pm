#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty. Ltd.  All rights reserved.
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
#  3. The name "FastMail" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#         FastMail Pty. Ltd.
#         Level 1, 91 William St
#         Melbourne 3000
#         Victoria
#         Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by FastMail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Move;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
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
    $self->assert(grep { $_ eq "\\Seen" } @$flags);

    xlog $self, "moving back works";
    $talk->move("1", "INBOX");
    $talk->select("INBOX");
    $res = $talk->fetch("1", "(flags)");
    $flags = $res->{1}->{flags};
    $self->assert(grep { $_ eq "\\Seen" } @$flags);
}

1;
