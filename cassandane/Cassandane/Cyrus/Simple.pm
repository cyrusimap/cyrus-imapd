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

package Cassandane::Cyrus::Simple;
use strict;
use warnings;
use DateTime;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

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

#
# Test APPEND of messages to IMAP
#
sub test_append
{
    my ($self) = @_;

    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Message B");
    $self->check_messages(\%exp);

    xlog $self, "generating message C";
    $exp{C} = $self->make_message("Message C");
    $self->check_messages(\%exp);

    xlog $self, "generating message D";
    $exp{D} = $self->make_message("Message D");
    $self->check_messages(\%exp);
}

sub test_select
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "SELECTing INBOX";
    $imaptalk->select("INBOX");
    $self->assert(!$imaptalk->get_last_error());

    xlog $self, "SELECTing inbox";
    $imaptalk->select("inbox");
    $self->assert(!$imaptalk->get_last_error());

    xlog $self, "CREATEing sub folders";
    $imaptalk->create("INBOX.sub");
    $self->assert(!$imaptalk->get_last_error());
    $imaptalk->create("inbox.blub");
    $self->assert(!$imaptalk->get_last_error());

    xlog $self, "SELECTing subfolders";
    $imaptalk->select("inbox.sub");
    $self->assert(!$imaptalk->get_last_error());
    $imaptalk->select("INbOX.blub");
    $self->assert(!$imaptalk->get_last_error());
}

sub test_cmdtimer_sessionid
    :min_version_3_5 :NoStartInstances
{
    my ($self) = @_;

    # log the timing for anything that takes longer than zero seconds
    $self->{instance}->{config}->set('commandmintimer', '0');
    $self->_start_instances();

    my $imaptalk = $self->{store}->get_client();

    # put a bunch of messages in inbox to make sure fetch isn't instantaneous
    my %msgs;
    foreach my $n (1..5) {
        $msgs{$n} = $self->make_message("message $n");
    }

    $imaptalk->select("INBOX");
    $self->assert_str_equals("ok", $imaptalk->get_last_completion_response());

    # discard buffered syslog output from setup
    $self->{instance}->getsyslog();

    # fetch some things that will take a little while
    $imaptalk->fetch('1:*', '(uid flags body[])');
    $self->assert_str_equals("ok", $imaptalk->get_last_completion_response());

    # should have logged some timer output, which should include the sess id
    if ($self->{instance}->{have_syslog_replacement}) {
        my @lines = grep { m/\bcmdtimer:/ } $self->{instance}->getsyslog();
        $self->assert_num_gte(1, scalar @lines);
        foreach my $line (@lines) {
            $self->assert_matches(qr/sessionid=<[^ >]+>/, $line);
        }
    }
}

1;
