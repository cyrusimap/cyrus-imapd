#!/usr/bin/perl
#
#  Copyright (c) 2011-2020 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::QResync;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use lib '.';
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

1;
