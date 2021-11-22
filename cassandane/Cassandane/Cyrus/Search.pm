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

package Cassandane::Cyrus::Search;
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

sub _fgrep_msgs
{
    my ($msgs, $attr, $s) = @_;
    my @res;

    foreach my $msg (values %$msgs)
    {
        push(@res, $msg->uid())
            if (index($msg->$attr(), $s) >= 0);
    }
    @res = sort { $a <=> $b } @res;
    return \@res;
}

sub test_from
{
    my ($self) = @_;

    xlog $self, "test SEARCH with the FROM predicate";
    my $talk = $self->{store}->get_client();

    xlog $self, "append some messages";
    my %exp;
    my %from_domains;
    my $N = 20;
    for (1..$N)
    {
        my $msg = $self->make_message("Message $_");
        $exp{$_} = $msg;
        my ($dom) = ($msg->from() =~ m/(@[^>]*)>/);
        $from_domains{$dom} = 1;
        xlog $self, "Message uid " . $msg->uid() . " from domain " . $dom;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp);

    my @found;
    foreach my $dom (keys %from_domains)
    {
        xlog $self, "searching for: FROM $dom";
        my $uids = $talk->search('from', { Quote => $dom })
            or die "Cannot search: $@";
        my $expected_uids = _fgrep_msgs(\%exp, 'from', $dom);
        $self->assert_deep_equals($expected_uids, $uids);
        map { $found[$_] = 1 } @$uids;
    }

    xlog $self, "checking all the message were found";
    for (1..$N)
    {
        $self->assert($found[$_],
                      "UID $_ was not returned from a SEARCH");
    }

    xlog $self, "Double-check the messages are still there";
    $self->check_messages(\%exp);
}

sub test_header_multiple
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $extra_headers = [
        ['x-nice-day-for', 'start again (come on)' ],
        ['x-nice-day-for', 'white wedding' ],
        ['x-nice-day-for', 'start agaaain' ],
    ];

    my %exp;
    $exp{1} = $self->make_message('message 1',
                                  'extra_headers' => $extra_headers);
    $exp{2} = $self->make_message('nice day');
    $self->check_messages(\%exp);

    # make sure a search that doesn't match anything doesn't find anything!
    my $uids = $talk->search('header', 'x-nice-day-for', 'cease and desist');
    $self->assert_num_equals(0, scalar @{$uids});

    # we must be able to find a message by the first header value
    $uids = $talk->search('header', 'x-nice-day-for', 'come on');
    $self->assert_num_equals(1, scalar @{$uids});
    $self->assert_deep_equals( [ 1 ], $uids);

    # we must be able to find a message by the last header value
    $uids = $talk->search('header', 'x-nice-day-for', 'start agaaain');
    $self->assert_num_equals(1, scalar @{$uids});
    $self->assert_deep_equals( [ 1 ], $uids);

    # we must be able to find a message by some other header value
    $uids = $talk->search('header', 'x-nice-day-for', 'white wedding');
    $self->assert_num_equals(1, scalar @{$uids});
    $self->assert_deep_equals( [ 1 ], $uids);

    # we must be able to ever find some other message!
    $uids = $talk->search('header', 'subject', 'nice day');
    $self->assert_num_equals(1, scalar @{$uids});
    $self->assert_deep_equals( [ 2 ], $uids);
}

1;
