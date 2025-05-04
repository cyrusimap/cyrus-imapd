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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::UIDbatches;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    $config->set(uidbatches_min_batch => '10');
    return $class->SUPER::new({adminstore => 1, config => $config}, @_);
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

sub test_uidbatches
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my @results;
    my %handlers =
    (
        uidbatches => sub
        {
            my (undef, $uidbatches) = @_;
            push(@results, $uidbatches);
        },
    );

    $imaptalk->examine('INBOX');

    # batch size of 10 on empty mailbox
    @results = ();
    my $tag = $imaptalk->{CmdId};
    my $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('TAG', $results[0][0][0]);
    $self->assert_str_equals($tag, $results[0][0][1]);
    $self->assert_null($results[0][1]);

    xlog $self, "append some messages";
    my %exp;
    my $N = 50;
    for (1..$N)
    {
        my $msg = $self->make_message("Message $_");
        $exp{$_} = $msg;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp);

    # expunge some messages
    $imaptalk->store('1,14:17,41,43,45', '+FLAGS', '(\\Deleted)');
    $imaptalk->expunge();

    # for manual debugging
    $imaptalk->fetch('1:*', 'UID');

    # batch size of 1 (below the minimum)
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '1');
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert_matches(qr/[TOOSMALL]/i, $imaptalk->get_last_error());

    # eleven batches of size of 10000
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10000', '1:11');
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert_matches(qr/[LIMIT]/i, $imaptalk->get_last_error());

    # batch size of 50 with less than 50 messages
    @results = ();
    $tag = $imaptalk->{CmdId};
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '50');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('TAG', $results[0][0][0]);
    $self->assert_str_equals($tag, $results[0][0][1]);
    $self->assert_str_equals('50:1', $results[0][1]);
    $self->assert_null($results[0][2]);

    # batch size of 25
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '25');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('50:23,22:1', $results[0][1]);
    $self->assert_null($results[0][2]);

    # batch size of 10
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('50:38,37:28,27:18,13:4,3:1', $results[0][1]);
    $self->assert_null($results[0][2]);

    # batch size of 10, first batch only
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '1:1');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('50:38', $results[0][1]);
    $self->assert_null($results[0][2]);

    # batch size of 10, second & third batches
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '2:3');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('37:28,27:18', $results[0][1]);
    $self->assert_null($results[0][2]);

    # batch size of 10, fifth & sixth batches
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '5:6');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('3:1', $results[0][1]);
    $self->assert_null($results[0][2]);

    # batch size of 10, nonexistent batch
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '7:7');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_null($results[0][1]);

    # bad syntax
    @results = ();
    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers);
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, 'X');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '6:');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '6:5');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    $res = $imaptalk->_imap_cmd('UIDBATCHES', 0, \%handlers, '10', '5:6', 'X');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());
}

1;
