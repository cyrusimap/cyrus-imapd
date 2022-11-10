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
    return $class->SUPER::new({adminstore => 1}, @_);
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

sub test_esearch
    :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Create shared folder, writeable by cassandane user";
    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("shared");
    $admintalk->setacl("shared", "cassandane", "lrsip");

    xlog $self, "Create some personal folders";
    my $imaptalk = $self->{store}->get_client();

    $self->setup_mailbox_structure($imaptalk, [
        [ 'subscribe' => 'INBOX' ],
        [ 'create' => [qw( INBOX.a INBOX.a.b.c INBOX.d INBOX.d.e INBOX.f )] ],
        [ 'subscribe' => [qw( INBOX.a.b INBOX.d )] ],
        [ 'subscribe' => [qw( shared )] ],
    ]);

    xlog $self, "Remove 'p' right from most  personal folders";
    $imaptalk->setacl("INBOX.a", "anyone", "-p");
    $imaptalk->setacl("INBOX.a.b", "anyone", "-p");
    $imaptalk->setacl("INBOX.a.b.c", "anyone", "-p");
    $imaptalk->setacl("INBOX.d", "anyone", "-p");
    $imaptalk->setacl("INBOX.d.e", "anyone", "-p");

    my $alldata = $imaptalk->list("", "*");

    $self->assert_mailbox_structure($alldata, '.', {
        'INBOX'                 => [qw( \\HasChildren )],
        'INBOX.a'               => [qw( \\HasChildren )],
        'INBOX.a.b'             => [qw( \\HasChildren )],
        'INBOX.a.b.c'           => [qw( \\HasNoChildren )],
        'INBOX.d'               => [qw( \\HasChildren )],
        'INBOX.d.e'             => [qw( \\HasNoChildren )],
        'INBOX.f'               => [qw( \\HasNoChildren )],
        'shared'                => [qw( \\HasNoChildren )],
    });

    xlog $self, "Append some emails into the folders";
    my %raw = (
        A => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test A\r
EOF
        B => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test B\r
EOF
        C => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Message-Id: <messageid1\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
Message-Id: <reply2\@foo>\r
In-Reply-To: <messageid1\@foo>\r
\r
test C\r
EOF
        D => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid2\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test D\r
EOF
        E => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test3\r
Message-Id: <messageid3\@foo>\r
In-Reply-To: <messageid2\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test E\r
EOF
        F => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid4\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test F\r
EOF
        G => <<"EOF",
From: <from\@local>\r
To: to\@local\r
Subject: test2\r
Message-Id: <messageid5\@foo>\r
In-Reply-To: <messageid4\@foo>\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test D\r
EOF
    );

    $imaptalk->append('INBOX',       "()", $raw{A}) || die $@;
    $imaptalk->append('INBOX',       "()", $raw{B}) || die $@;
    $imaptalk->append('INBOX',       "()", $raw{C}) || die $@;
    $imaptalk->append('INBOX.a',     "()", $raw{B}) || die $@;
    $imaptalk->append('INBOX.a.b',   "()", $raw{C}) || die $@;
    $imaptalk->append('INBOX.a.b.c', "()", $raw{D}) || die $@;
    $imaptalk->append('INBOX.d',     "()", $raw{E}) || die $@;
    $imaptalk->append('INBOX.f',     "()", $raw{F}) || die $@;
    $imaptalk->append('shared',      "()", $raw{G}) || die $@;

    my @results;
    my %handlers =
    (
        esearch => sub
        {
            my (undef, $esearch) = @_;
            push(@results, $esearch);
        },
    );

    xlog $self, "Search the (un)selected mailbox (should fail)";
    my $res = $imaptalk->_imap_cmd('ESEARCH', 0, 'esearch',
                                   'IN', '(SELECTED)',
                                   'subject', 'test');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    xlog $self, "Now select a mailbox";
    $res = $imaptalk->select("INBOX");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Search the newly selected mailbox";
    @results = ();
    $res = $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                                'IN', '(SELECTED)', 'RETURN', '(MIN MAX ALL)',
                                'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(1, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);
    $self->assert_num_equals(1, $results[0][3]);
    $self->assert_num_equals(3, $results[0][5]);
    $self->assert_str_equals('1:3', $results[0][7]);

    xlog $self, "Search the personal namespace, returning just counts";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(PERSONAL)', 'RETURN', '(COUNT)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(6, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);
    $self->assert_num_equals(3, $results[0][3]);
    $self->assert_str_equals('INBOX.a', $results[1][0][3]);
    $self->assert_num_equals(1, $results[1][3]);
    $self->assert_str_equals('INBOX.a.b', $results[2][0][3]);
    $self->assert_num_equals(1, $results[2][3]);
    $self->assert_str_equals('INBOX.a.b.c', $results[3][0][3]);
    $self->assert_num_equals(1, $results[3][3]);
    $self->assert_str_equals('INBOX.d', $results[4][0][3]);
    $self->assert_num_equals(1, $results[4][3]);
    $self->assert_str_equals('INBOX.f', $results[5][0][3]);
    $self->assert_num_equals(1, $results[5][3]);

    xlog $self, "Search the subscribed folders";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(SUBSCRIBED)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(4, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);
    $self->assert_str_equals('INBOX.a.b', $results[1][0][3]);
    $self->assert_str_equals('INBOX.d', $results[2][0][3]);
    $self->assert_str_equals('shared', $results[3][0][3]);

    xlog $self, "Search the Inboxes (deliverable)";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(INBOXES)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(2, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);
    $self->assert_str_equals('INBOX.f', $results[1][0][3]);

    xlog $self, "Search a subtree";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(SUBTREE INBOX.a)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @results);
    $self->assert_str_equals('INBOX.a', $results[0][0][3]);
    $self->assert_str_equals('INBOX.a.b', $results[1][0][3]);
    $self->assert_str_equals('INBOX.a.b.c', $results[2][0][3]);

    xlog $self, "Search a limited subtree";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(SUBTREE-ONE INBOX.a)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(2, scalar @results);
    $self->assert_str_equals('INBOX.a', $results[0][0][3]);
    $self->assert_str_equals('INBOX.a.b', $results[1][0][3]);

    xlog $self, "Search a single folder without a match";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(MAILBOXES INBOX.e)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(0, scalar @results);

    xlog $self, "Search a single folder with a match";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(MAILBOXES INBOX.f)',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(1, scalar @results);
    $self->assert_str_equals('INBOX.f', $results[0][0][3]);

    xlog $self, "Search a multiple folders with only one match)";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(MAILBOXES (INBOX.e INBOX.f))',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(1, scalar @results);
    $self->assert_str_equals('INBOX.f', $results[0][0][3]);

    xlog $self, "Search multiple sourcesand make sure there are no duplicates";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(SUBSCRIBED SELECTED SUBTREE-ONE INBOX.a MAILBOXES (INBOX.e shared))',
                         'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(5, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);
    $self->assert_str_equals('INBOX.a.b', $results[1][0][3]);
    $self->assert_str_equals('INBOX.d', $results[2][0][3]);
    $self->assert_str_equals('shared', $results[3][0][3]);
    $self->assert_str_equals('INBOX.a', $results[4][0][3]);
}

1;
