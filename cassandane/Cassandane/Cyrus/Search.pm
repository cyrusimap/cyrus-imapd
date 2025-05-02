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
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
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
    :NoAltNameSpace :needs_search_xapian :Conversations :min_version_3_7
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

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @results;
    my %handlers =
    (
        esearch => sub
        {
            my (undef, $esearch) = @_;
            push(@results, $esearch);
        },
    );

    xlog $self, "Unselected Esearch with empty source opts (should fail)";
    my $res = $imaptalk->_imap_cmd('ESEARCH', 0, 'esearch',
                                   'IN', '()',
                                   'subject', 'test');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    xlog $self, "Search the (un)selected mailbox (should fail)";
    $res = $imaptalk->_imap_cmd('ESEARCH', 0, 'esearch',
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

    xlog $self, "Fuzzy search the personal namespace";
    @results = ();
    $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                         'IN', '(PERSONAL)', 'FUZZY', 'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @results);
    $self->assert_str_equals('INBOX', $results[0][0][3]);
    $self->assert_str_equals('INBOX.a', $results[1][0][3]);
    $self->assert_str_equals('INBOX.a.b', $results[2][0][3]);
}

sub test_searchres
    :NoAltNameSpace :min_version_3_7
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();


    $self->setup_mailbox_structure($imaptalk, [
        [ 'create' => [qw( INBOX.target )] ],
    ]);

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
Subject: foo\r
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
From: <foo\@local>\r
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

    $imaptalk->append('INBOX', "()", $raw{A}) || die $@;
    $imaptalk->append('INBOX', "()", $raw{B}) || die $@;
    $imaptalk->append('INBOX', "()", $raw{C}) || die $@;
    $imaptalk->append('INBOX', "()", $raw{D}) || die $@;
    $imaptalk->append('INBOX', "()", $raw{E}) || die $@;
    $imaptalk->append('INBOX', "()", $raw{F}) || die $@;
    $imaptalk->append('INBOX', "()", $raw{G}) || die $@;

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
    my $res = $imaptalk->_imap_cmd('SEARCH', 0, 'esearch',
                                   'RETURN', '(SAVE)',
                                   'subject', 'test');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    xlog $self, "Now select a mailbox";
    $res = $imaptalk->select("INBOX");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Search results should be empty";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(0, scalar keys %{$res});

    xlog $self, "Attempt to Search the newly selected mailbox and others";
    @results = ();
    $res = $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                                'IN', '(SELECTED PERSONAL)', 'RETURN', '(SAVE)',
                                'subject', 'test');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    xlog $self, "Search the selected mailbox for minimum and save";
    @results = ();
    $res = $imaptalk->_imap_cmd('ESEARCH', 0, \%handlers,
                                'RETURN', '(SAVE MIN)',
                                'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(1, scalar keys %{$res});
    $self->assert_str_equals('1', $res->{'1'}->{uid});

    xlog $self, "Search the mailbox for maximum and save";
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(MAX SAVE)',
                                'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(1, scalar keys %{$res});
    $self->assert_str_equals('7', $res->{'7'}->{uid});

    xlog $self, "Search the mailbox for minimum & maximum and save";
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(MAX SAVE MIN)',
                                'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(2, scalar keys %{$res});
    $self->assert_str_equals('1', $res->{'1'}->{uid});
    $self->assert_str_equals('7', $res->{'7'}->{uid});

    xlog $self, "Search the mailbox for all and save";
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(SAVE)',
                                'subject', 'test');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(6, scalar keys %{$res});
    $self->assert_str_equals('1', $res->{'1'}->{uid});
    $self->assert_str_equals('3', $res->{'3'}->{uid});
    $self->assert_str_equals('4', $res->{'4'}->{uid});
    $self->assert_str_equals('5', $res->{'5'}->{uid});
    $self->assert_str_equals('6', $res->{'6'}->{uid});
    $self->assert_str_equals('7', $res->{'7'}->{uid});

    xlog $self, "Store using the search results";
    $res = $imaptalk->store('$', '+flags', '(\\Flagged)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(6, scalar keys %{$res});
    $self->assert_str_equals('1', $res->{'1'}->{uid});
    $self->assert_str_equals('3', $res->{'3'}->{uid});
    $self->assert_str_equals('4', $res->{'4'}->{uid});
    $self->assert_str_equals('5', $res->{'5'}->{uid});
    $self->assert_str_equals('6', $res->{'6'}->{uid});
    $self->assert_str_equals('7', $res->{'7'}->{uid});

    xlog $self, "Copy using the search results";
    $res = $imaptalk->copy('$', 'INBOX.target');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->get_response_code('copyuid');
    $self->assert_str_equals('1,3:7', $res->[1]);
    $self->assert_str_equals('1:6', $res->[2]);

    xlog $self, "Expunge the first message";
    $res = $imaptalk->store('1', '+flags', '(\\Deleted)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->expunge();
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(5, scalar keys %{$res});
    $self->assert_str_equals('3', $res->{'2'}->{uid});
    $self->assert_str_equals('4', $res->{'3'}->{uid});
    $self->assert_str_equals('5', $res->{'4'}->{uid});
    $self->assert_str_equals('6', $res->{'5'}->{uid});
    $self->assert_str_equals('7', $res->{'6'}->{uid});

    xlog $self, "Expunge the middle message in the search results range";
    $res = $imaptalk->store('4', '+flags', '(\\Deleted)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->expunge();
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(4, scalar keys %{$res});
    $self->assert_str_equals('3', $res->{'2'}->{uid});
    $self->assert_str_equals('4', $res->{'3'}->{uid});
    $self->assert_str_equals('6', $res->{'4'}->{uid});
    $self->assert_str_equals('7', $res->{'5'}->{uid});

    xlog $self, "Expunge the 1st message in the 1st range and the last in the 2nd";
    $res = $imaptalk->store('2,5', '+flags', '(\\Deleted)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->expunge();
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(2, scalar keys %{$res});
    $self->assert_str_equals('4', $res->{'2'}->{uid});
    $self->assert_str_equals('6', $res->{'3'}->{uid});

    xlog $self, "Search the mailbox for a from address in the saved results";
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(SAVE ALL)',
                                'uid', '$', 'from', 'foo');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Fetch using the search results";
    $res = $imaptalk->fetch('$', 'UID');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_num_equals(1, scalar keys %{$res});
    $self->assert_str_equals('6', $res->{'3'}->{uid});
}

sub test_uidsearch_empty
    :min_version_3_9
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $imap->create('INBOX.test');
    $self->assert_str_equals('ok', $imap->get_last_completion_response());

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @results;
    my %handlers =
    (
        esearch => sub
        {
            my (undef, $esearch) = @_;
            push(@results, $esearch);
        },
    );

    $imap->select('INBOX.test');
    $imap->_imap_cmd('UID', 0, \%handlers,
        'SEARCH', 'RETURN', '(ALL SAVE COUNT) UID 1:*');
    $self->assert_num_equals(1, scalar @results);
    $self->assert_str_equals('UID', $results[0][1]);
    $self->assert_str_equals('COUNT', $results[0][2]);
    $self->assert_str_equals('0', $results[0][3]);
}

sub test_partial
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "append some messages";
    my %exp;
    my $N = 10;
    for (1..$N)
    {
        my $msg = $self->make_message("Message $_");
        $exp{$_} = $msg;
    }
    xlog $self, "check the messages got there";
    $self->check_messages(\%exp);

    # delete the 1st and 6th
    $imaptalk->store('1,6', '+FLAGS', '(\\Deleted)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    my @results;
    my %handlers =
    (
        esearch => sub
        {
            my (undef, $esearch) = @_;
            push(@results, $esearch);
        },
    );

    # search and return non-existent messages
    @results = ();
    my $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                   'RETURN', '(PARTIAL -100:-1)', '100:300');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('-1:-100', $results[0][2][0]);
    $self->assert_null($results[0][2][1]);

    # search and return all messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '()', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('2:5,7:10', $results[0][2]);

    # attempt search with all and partial
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(ALL PARTIAL 1:2)', 'UNDELETED');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    # search and return first 2 messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL 1:2)', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('1:2', $results[0][2][0]);
    $self->assert_str_equals('2:3', $results[0][2][1]);

    # search and return next 2 messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL 3:4)', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('3:4', $results[0][2][0]);
    $self->assert_str_equals('4:5', $results[0][2][1]);

    # flag the last message
    $imaptalk->store('10', '+FLAGS', '(\\flagged)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # search and return next 2 messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL 5:6)', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('5:6', $results[0][2][0]);
    $self->assert_str_equals('7:8', $results[0][2][1]);

    # search and return last 2 messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL -1:-2)', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('-1:-2', $results[0][2][0]);
    $self->assert_str_equals('9:10', $results[0][2][1]);

    # search and return the previous 2 messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL -3:-4)', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('-3:-4', $results[0][2][0]);
    $self->assert_str_equals('7:8', $results[0][2][1]);

    # search and return middle 2 messages by UID
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL 2:3)',
                                'UID', '4:8', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('2:3', $results[0][2][0]);
    $self->assert_str_equals('5,7', $results[0][2][1]);

    # search and return non-existent messages
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(PARTIAL 9:10)', 'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('PARTIAL', $results[0][1]);
    $self->assert_str_equals('9:10', $results[0][2][0]);
    $self->assert_null($results[0][2][1]);

    # search and return count, min, max, and partial
    @results = ();
    $res = $imaptalk->_imap_cmd('SEARCH', 0, \%handlers,
                                'RETURN', '(MIN MAX COUNT PARTIAL 3:4)',
                                'UNDELETED');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_str_equals('COUNT', $results[0][1]);
    $self->assert_str_equals('8', $results[0][2]);
    $self->assert_str_equals('MIN', $results[0][3]);
    $self->assert_str_equals('2', $results[0][4]);
    $self->assert_str_equals('MAX', $results[0][5]);
    $self->assert_str_equals('10', $results[0][6]);
    $self->assert_str_equals('PARTIAL', $results[0][7]);
    $self->assert_str_equals('3:4', $results[0][8][0]);
    $self->assert_str_equals('4:5', $results[0][8][1]);
}

sub test_threadid
    :Conversations
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    $self->{store}->set_fetch_attributes('uid', 'cid');

    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating replies";
    for (1..99) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }
    $exp{"B"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{"B"}->set_attributes(uid => 101, cid => $exp{B}->make_cid(), basecid => $exp{A}->make_cid());
    for (1..99) {
      $exp{"B$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"B$_"}->set_attributes(uid => 101+$_, cid => $exp{B}->make_cid(), basecid => $exp{A}->make_cid());
    }
    $exp{"C"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{"C"}->set_attributes(uid => 201, cid => $exp{C}->make_cid(), basecid => $exp{A}->make_cid());

    $imaptalk->select("INBOX");
    my $res = $imaptalk->fetch('200', '(cid threadid)');
    my $cid = $res->{200}{cid};
    my $thrid = $res->{200}{threadid}[0];

    my $uids1 = $imaptalk->search('cid', $cid);
    $self->assert_num_equals(100, scalar @{$uids1});
    $self->assert_num_equals(101, $uids1->[0]);
    $self->assert_num_equals(200, $uids1->[99]);

    my $uids2 = $imaptalk->search('threadid', $thrid);
    $self->assert_deep_equals($uids1, $uids2);
}

1;
