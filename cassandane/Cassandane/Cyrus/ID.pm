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

package Cassandane::Cyrus::ID;
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
    return $class->SUPER::new({ }, @_);
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

sub test_cmd_id
{
    my ($self) = @_;

    # Purge any syslog lines before this test runs.
    $self->{instance}->getsyslog();

    my $imaptalk = $self->{store}->get_client();

    return if not $imaptalk->capability()->{id};

    my $res = $imaptalk->id(name => "cassandane");
    xlog $self, Dumper $res;

    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # should have logged some timer output, which should include the sess id,
    # and since we sent a client id via IMAP ID, we should get that, too!
    if ($self->{instance}->{have_syslog_replacement}) {
        # make sure that the connection is ended so that imapd reset happens
        $imaptalk->logout();
        undef $imaptalk;

        my @behavior_lines = $self->{instance}->getsyslog(qr/session ended/);

        $self->assert_num_gte(1, scalar @behavior_lines);

        $self->assert_matches(qr/\bid\.name=<cassandane>/, $_) for @behavior_lines;
    }
}

sub test_cmd_id_nil_cant_unget
{
    my ($self) = @_;

    # Purge any syslog lines before this test runs.
    $self->{instance}->getsyslog();

    my $imaptalk = $self->{store}->get_client();

    # Construct an ID command where the 'N' in NULL is the 4096'th character
    # in the prot buffer.
    # This will require a new read to get the rest of the command,
    # but will also prohibit calling prot_ungetc('N').
    # Successful execution of the command will verify that we have fixed the
    # parsing issue.
    # If the previous bug returns, imapd will fatal() attempting to prot_unget()
    my $x = 'x' x 1014;
    $imaptalk->{CmdId} = 'XX';
    $imaptalk->_imap_cmd('ID', 0, {},
                         qq{("a" "$x" "b" "$x" "c" "$x" "d" "$x" "e" NIL)});
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
}

1;
