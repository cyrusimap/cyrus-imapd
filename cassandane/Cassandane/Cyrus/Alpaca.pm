#!/usr/bin/perl
#
#  Copyright (c) 2011-2024 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::Alpaca;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Socket;

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

sub imap_cmd_with_tag
{
    my ($talk, $tag, @args) = @_;

    die "not a Mail::IMAPTalk object" if ref $talk ne 'Mail::IMAPTalk';

    # save some internal state
    my $saved_CmdId = $talk->{CmdId};

    # override next tag with the tag we want to use
    $talk->{CmdId} = $tag;

    my $ret;
    {
        # suppress an expected warning from _imap_cmd because CmdId
        # (probably) isn't numeric
        local $SIG{__WARN__} = sub {
            if ($_[0] !~ m/^Argument "\Q$tag\E" isn't numeric /) {
                warn @_;
            }
        };
        $ret = $talk->_imap_cmd(@args);
    }

    # restore internal state
    $talk->{CmdId} = $saved_CmdId;

    return $ret;
}

sub test_consecutive_syntax_errors_drop_connection
{
    my ($self) = @_;

    $self->{store}->disconnect();
    my $sock = create_client_socket($self->{store}->{address_family},
                                    $self->{store}->{host},
                                    $self->{store}->{port});

    # 50 lines of just "bogus \r\n", that is the tag 'bogus' and a space
    # but no command, which cyrus will reject with "bogus BAD Null command"
    my @request = ('bogus ') x 50;
    foreach my $line (@request) {
        $sock->send("$line\015\012") or die "send: $!";
        last if not $sock->connected();
    }

    # if the connection hasn't been dropped already, send a logout so the
    # test doesn't hang
    $sock->send(". logout\015\012") if $sock->connected();

    my @response;
    while (defined(my $line = $sock->getline())) {
        $line =~ s/\015?\012//;
        push @response, $line;
    }

    # double check that our request contained more lines than cyrus'
    # syntax error limit of 10
    $self->assert_num_gt(10, scalar @request);

    # cyrus should have dropped the connection before we sent all the lines
    $self->assert_num_lt(scalar @request, scalar @response);

    # should have gotten as many BAD responses as cyrus's limit
    $self->assert_num_equals(10, scalar grep { m/BAD/ } @response);

    # snarky last response back from the server
    $self->assert_matches(qr{This is an IMAP server}, $response[-1]);
}

sub test_html_tag_dont_reflect1
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    # mimic a HTTP connection sending request content that contains a line
    # that parses such that the tag is a chunk of javacript and the command
    # is something that will provoke a tagged response, causing us to reflect
    # the script back to the client.
    # we'll say "BAD Invalid tag" for trivial forms of this such as
    # <script>attack()</script> just because () are not valid characters in
    # tags, but it's possible to invoke a javascript function without
    # parentheses, and it's probably possible to do so without any whitespace
    # or atom-specials at all
    #
    # https://portswigger.net/research/xss-without-parentheses-and-semi-colons
    my $saw_untagged_bad = 0;
    imap_cmd_with_tag($talk, '<script>do_attack</script>',
                             { IdleResponse => 1 },
                             'noop', 0,
                             { 'bad' => sub { $saw_untagged_bad++ } });

    # the only acceptable response to this is an untagged BAD or BYE!
    # any tagged response will reflect an attacker-supplied payload to
    # the victim
    $self->assert_num_equals(1, $saw_untagged_bad);
}

sub test_html_tag_dont_reflect2
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    # as above, but with no command!
    my $saw_untagged_bad = 0;
    imap_cmd_with_tag($talk, '<script>do_attack</script>',
                             { IdleResponse => 1 },
                             '', 0,
                             { 'bad' => sub { $saw_untagged_bad++ } });

    # the only acceptable response to this is an untagged BAD or BYE!
    # any tagged response will reflect an attacker-supplied payload to
    # the victim
    $self->assert_num_equals(1, $saw_untagged_bad);
}

1;
