#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::SearchFuzzy;
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

    if (not $self->{instance}->{buildinfo}->{search}->{xapian}) {
        xlog "No xapian support enabled. Skipping tests.";
        return;
    }
    $self->{test_fuzzy_search} = 1;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub create_testmessages
{
    my ($self) = @_;

    xlog "Generate test messages.";
    # Some subjects with the same verb word stem
    $self->make_message("I am running") || die;
    $self->make_message("I run") || die;
    $self->make_message("He runs") || die;
 
    # Some bodies with the same word stems but different senders. We use 
    # the "connect" word stem since it it the first example on Xapian's
    # Stemming documentation (https://xapian.org/docs/stemming.html).
    # Mails from foo@example.com...
    my %params;
    %params = (
        from => Cassandane::Address->new(
            localpart => "foo",
            domain => "example.com"
        ),
    );
    $params{'body'} ="He has connections.",
    $self->make_message("1", %params) || die;
    $params{'body'} = "Gonna get myself connected.";
    $self->make_message("2", %params) || die;
    # ...as well as from bar@example.com.
    %params = (
        from => Cassandane::Address->new(
            localpart => "bar",
            domain => "example.com"
        ),
        body => "Einstein's gravitational theory resulted in beautiful relations connecting gravitational phenomena with the geometry of space; this was an exciting idea."
    );
    $self->make_message("3", %params) || die;

    # Create the search database.
    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
}

sub test_stem_verbs
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};
    $self->create_testmessages();

    my $talk = $self->{store}->get_client();

    xlog "Select INBOX";
    $talk->select("INBOX") || die;

    my $r;
    xlog 'SEARCH for subject "runs"';
    $r = $talk->search('subject', { Quote => "runs" }) || die;
    $self->assert_num_equals(1, scalar @$r);

    xlog 'SEARCH for FUZZY subject "runs"';
    $r = $talk->search('fuzzy', ['subject', { Quote => "runs" }]) || die;
    $self->assert_num_equals(3, scalar @$r);
}

sub test_stem_any
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};
    $self->create_testmessages();

    my $talk = $self->{store}->get_client();

    xlog "Select INBOX";
    $talk->select("INBOX") || die;

    my $r;
    xlog 'SEARCH for body "connection"';
    $r = $talk->search('body', { Quote => "connection" }) || die;
    $self->assert_num_equals(1, scalar @$r);

    xlog "SEARCH for FUZZY body \"connection\"";
    $r = $talk->search(
        "fuzzy", ["body", { Quote => "connection" }],
    ) || die;
    $self->assert_num_equals(3, scalar @$r);
}

sub test_mix_fuzzy_and_nonfuzzy
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};
    $self->create_testmessages();
    my $talk = $self->{store}->get_client();

    xlog "Select INBOX";
    $talk->select("INBOX") || die;

    xlog "SEARCH for from \"foo\@example.com\" with FUZZY body \"connection\"";
    my $r = $talk->search(
        "fuzzy", ["body", { Quote => "connection" }],
        "from", { Quote => "foo\@example.com" }
    ) || die;
    $self->assert_num_equals(2, scalar @$r);
}

sub test_weird_crasher
    :Conversations
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};
    $self->create_testmessages();

    my $talk = $self->{store}->get_client();

    xlog "Select INBOX";
    $talk->select("INBOX") || die;

    xlog "SEARCH for 'A 李 A'";
    my $r = $talk->xconvmultisort( [ qw(reverse arrival) ], [ 'conversations', position => [1,10] ], 'utf-8', 'fuzzy', 'text', { Quote => "A 李 A" });
    $self->assert_not_null($r);
}

sub test_stopwords
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    # This test assumes that "the" is a stopword and is configured with
    # the search_stopword_path in cassandane.ini. If the option is not
    # set it tests legacy behaviour.

    my $talk = $self->{store}->get_client();

    # Set up Xapian database
    xlog "Generate and index test messages.";
    my %params = (
        mime_charset => "utf-8",
    );
    my $subject;
    my $body;

    $subject = "1";
    $body = "In my opinion the soup smells tasty";
    $params{body} = $body;
    $self->make_message($subject, %params) || die;

    $subject = "2";
    $body = "The funny thing is that this isn't funny";
    $params{body} = $body;
    $self->make_message($subject, %params) || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    # Connect via IMAP
    xlog "Select INBOX";
    $talk->select("INBOX") || die;
    my $uidvalidity = $talk->get_response_code('uidvalidity');
    my $uids = $talk->search('1:*', 'NOT', 'DELETED');

    my $term;
    my $r;

    # Search for stopword only
    $term = "the";
    xlog "SEARCH for FUZZY body \"$term\"";
    $r = $talk->search(
        "charset", "utf-8", "fuzzy", ["text", { Quote => $term }],
    ) || die;

    my $expected_matches;
    if ($self->{instance}->{config}->get('search_stopword_path')) {
        $expected_matches = 0;
    } else {
        $expected_matches = 2;
    }
    $self->assert_num_equals($expected_matches, scalar @$r);

    # Search for stopword plus significant term
    $term = "the soup";
    xlog "SEARCH for FUZZY body \"$term\"";
    $r = $talk->search(
        "charset", "utf-8", "fuzzy", ["text", { Quote => $term }],
    ) || die;
    $self->assert_num_equals(1, scalar @$r);
}

sub test_normalize_snippets
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    # Set up test message with funny characters
    my $body = "foo gären советской diĝir naïve léger";
    my @terms = split / /, $body;

    xlog "Generate and index test messages.";
    my %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message("1", %params) || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $talk = $self->{store}->get_client();

    # Connect to IMAP
    xlog "Select INBOX";
    my $r = $talk->select("INBOX") || die;
    my $uidvalidity = $talk->get_response_code('uidvalidity');
    my $uids = $talk->search('1:*', 'NOT', 'DELETED');

    # Assert that diacritics are matched and returned
    foreach my $term (@terms) {
        xlog "XSNIPPETS for FUZZY text \"$term\"";
        $r = $talk->xsnippets(
            [['INBOX', $uidvalidity, $uids]], 'utf-8',
            ['fuzzy', 'text', { Quote => $term }]
        ) || die;
        $self->assert_num_not_equals(index($r->{snippets}[0][3], "<b>$term</b>"), -1);
    }

    # Assert that search without diacritics matches
    my $skipdiacrit = $self->{instance}->{config}->get('search_skipdiacrit');
    if ($skipdiacrit && !($skipdiacrit eq "false")) {
        my $term = "naive";
        xlog "XSNIPPETS for FUZZY text \"$term\"";
        $r = $talk->xsnippets(
            [['INBOX', $uidvalidity, $uids]], 'utf-8',
            ['fuzzy', 'text', { Quote => $term }]
        ) || die;
        $self->assert_num_not_equals(index($r->{snippets}[0][3], "<b>naïve</b>"), -1);
    }
}

sub test_cjk_words
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    my $body = "明末時已經有香港地方的概念";

    xlog "Generate and index test messages.";
    my %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message("1", %params) || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $talk = $self->{store}->get_client();

    # Connect to IMAP
    xlog "Select INBOX";
    my $r = $talk->select("INBOX") || die;
    my $uidvalidity = $talk->get_response_code('uidvalidity');
    my $uids = $talk->search('1:*', 'NOT', 'DELETED');

    my $term;
    # Search for a two-character CJK word
    $term = "已經";
    xlog "XSNIPPETS for FUZZY text \"$term\"";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'text', { Quote => $term }]
    ) || die;
    $self->assert_num_not_equals(index($r->{snippets}[0][3], "<b>$term</b>"), -1);

    # Search for the CJK words 明末 and 時.
    # IMAP search requires them to be ANDed and so they won't be found.
    $term = "明末時";
    xlog "XSNIPPETS for FUZZY text \"$term\"";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'text', { Quote => $term }]
    ) || die;
    $self->assert_num_equals(scalar @{$r->{snippets}}, 0);
}

sub test_subject_isutf8
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    xlog "Generate and index test messages.";
    # that's: "nuff réunion critères duff"
    my $subject = "=?utf-8?q?nuff_r=C3=A9union_crit=C3=A8res_duff?=";
    my $body = "empty";
    my %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message($subject, %params) || die;
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $talk = $self->{store}->get_client();

    # Connect to IMAP
    xlog "Select INBOX";
    my $r = $talk->select("INBOX") || die;

    # Search subject without accents
    # my $term = "réunion critères";
    my %searches = (
        "reunion criteres" => 1,
        "réunion critères" => 1,
        "reunion critères" => 1,
        "réunion criter" => 1,
        "réunion crit" => 0,
        "union critères" => 0,
    );
    while (my($term, $expectedCnt) = each %searches) {
        xlog "SEARCH for FUZZY body \"$term\"";
        $r = $talk->search(
            "charset", "utf-8", "fuzzy", ["text", { Quote => $term }],
        ) || die;
        $self->assert_num_equals($expectedCnt, scalar @$r);
    }
}


1;
