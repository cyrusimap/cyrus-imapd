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
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    return $class->SUPER::new({ config => $config }, @args);
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

sub test_copy_messages
{
    my ($self) = @_;

    $self->create_testmessages();

    my $talk = $self->{store}->get_client();
    $talk->create("INBOX.foo");
    $talk->select("INBOX");
    $talk->copy("1:*", "INBOX.foo");

    xlog "Run squatter again";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-i');
}

sub test_stem_verbs
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};
    $self->create_testmessages();

    my $talk = $self->{store}->get_client();

    xlog "Select INBOX";
    my $r = $talk->select("INBOX") || die;
    my $uidvalidity = $talk->get_response_code('uidvalidity');
    my $uids = $talk->search('1:*', 'NOT', 'DELETED');

    xlog 'SEARCH for subject "runs"';
    $r = $talk->search('subject', { Quote => "runs" }) || die;
    $self->assert_num_equals(1, scalar @$r);

    xlog 'SEARCH for FUZZY subject "runs"';
    $r = $talk->search('fuzzy', ['subject', { Quote => "runs" }]) || die;
    $self->assert_num_equals(3, scalar @$r);

    xlog 'XSNIPPETS for FUZZY subject "runs"';
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'subject', { Quote => 'runs' }]
    ) || die;
    $self->assert_num_equals(3, scalar @{$r->{snippets}});
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

sub test_snippets_termcover
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    my $body =
    "The 'charset' portion of an 'encoded-word' specifies the character ".
    "set associated with the unencoded text.  A 'charset' can be any of ".
    "the character set names allowed in an MIME \"charset\" parameter of a ".
    "\"text/plain\" body part, or any character set name registered with ".
    "IANA for use with the MIME text/plain content-type. ".
    "".
    # Attempt to trick the snippet generator into picking the next two lines
    "Here is a line with favourite but not without that other search word ".
    "Here is another line with a favourite word but not the other one ".
    "".
    "Some character sets use code-switching techniques to switch between ".
    "\"ASCII mode\" and other modes.  If unencoded text in an 'encoded-word' ".
    "contains a sequence which causes the charset interpreter to switch ".
    "out of ASCII mode, it MUST contain additional control codes such that ".
    "ASCII mode is again selected at the end of the 'encoded-word'.  (This ".
    "rule applies separately to each 'encoded-word', including adjacent ".
    "encoded-word's within a single header field.) ".
    "When there is a possibility of using more than one character set to ".
    "represent the text in an 'encoded-word', and in the absence of ".
    "private agreements between sender and recipients of a message, it is ".
    "recommended that members of the ISO-8859-* series be used in ".
    "preference to other character sets.".
    "".
    # This is the line we want to get as a snippet
    "I don't have a favourite cereal. My favourite breakfast is oat meal.";

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
    my $want = "<b>favourite</b> <b>cereal</b>";

    $r = $talk->xsnippets( [ [ 'inbox', $uidvalidity, $uids ] ],
       'utf-8', [
           'fuzzy', 'text', 'favourite',
           'fuzzy', 'text', 'cereal',
           'fuzzy', 'text', { Quote => 'bogus gnarly' }
        ]
    ) || die;
    $self->assert_num_not_equals(-1, index($r->{snippets}[0][3], $want));

    $r = $talk->xsnippets( [ [ 'inbox', $uidvalidity, $uids ] ],
       'utf-8', [
           'fuzzy', 'text', 'favourite cereal'
        ]
    ) || die;
    $self->assert_num_not_equals(-1, index($r->{snippets}[0][3], $want));

    # Regression - a phrase is treated as a loose term
    $r = $talk->xsnippets( [ [ 'INBOX', $uidvalidity, $uids ] ],
       'utf-8', [
           'fuzzy', 'text', { Quote => 'favourite nope cereal' },
           'fuzzy', 'text', { Quote => 'bogus gnarly' }
        ]
    ) || die;
    $self->assert_num_not_equals(-1, index($r->{snippets}[0][3], $want));

    $r = $talk->xsnippets( [ [ 'inbox', $uidvalidity, $uids ] ],
       'utf-8', [
           'fuzzy', 'text', { Quote => 'favourite cereal' }
        ]
    ) || die;
    $self->assert_num_not_equals(-1, index($r->{snippets}[0][3], $want));
}

sub test_cjk_words
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    xlog "Generate and index test messages.";

    my $body = "明末時已經有香港地方的概念";
    my %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message("1", %params) || die;

    # Splits into the words: "み, 円, 月額, 申込
    $body = "申込み！月額円";
    %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message("2", %params) || die;

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

    # Search for the CJK words 明末 and 時, note that the
    # word order is reversed to the original message
    $term = "時明末";
    xlog "XSNIPPETS for FUZZY text \"$term\"";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'text', { Quote => $term }]
    ) || die;
    $self->assert_num_equals(scalar @{$r->{snippets}}, 1);

    # Search for the partial CJK word 月
    $term = "月";
    xlog "XSNIPPETS for FUZZY text \"$term\"";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'text', { Quote => $term }]
    ) || die;
    $self->assert_num_equals(scalar @{$r->{snippets}}, 0);

    # Search for the interleaved, partial CJK word 額申
    $term = "額申";
    xlog "XSNIPPETS for FUZZY text \"$term\"";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'text', { Quote => $term }]
    ) || die;
    $self->assert_num_equals(scalar @{$r->{snippets}}, 0);

    # Search for three of four words: "み, 月額, 申込",
    # in different order than the original.
    $term = "月額み申込";
    xlog "XSNIPPETS for FUZZY text \"$term\"";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'text', { Quote => $term }]
    ) || die;
    $self->assert_num_equals(scalar @{$r->{snippets}}, 1);
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
    my %searches;

    my $skipdiacrit = $self->{instance}->{config}->get('search_skipdiacrit');
    if (!($skipdiacrit eq "false")) {
        # Diacritics are stripped before indexing and search. That's a sane
        # choice as long as there is no language-specific stemming applied
        # during indexing and search.
        %searches = (
            "reunion criteres" => 1,
            "réunion critères" => 1,
            "reunion critères" => 1,
            "réunion criter" => 1,
            "réunion crit" => 0,
            "union critères" => 0,
        );
        my $term = "naive";
    } else {
        # Diacritics are not stripped from search. This currently is very
        # restrictive: until Cyrus can stem by language, this is basically
        # a whole-word match.
        %searches = (
            "reunion criteres" => 0,
            "réunion critères" => 1,
            "reunion critères" => 0,
            "réunion criter" => 0,
            "réunion crit" => 0,
            "union critères" => 0,
        );
    }

    while (my($term, $expectedCnt) = each %searches) {
        xlog "SEARCH for FUZZY text \"$term\"";
        $r = $talk->search(
            "charset", "utf-8", "fuzzy", ["text", { Quote => $term }],
        ) || die;
        $self->assert_num_equals($expectedCnt, scalar @$r);
    }

}

sub test_noindex_multipartheaders
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $body = ""
    . "--boundary\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body"
    . "\r\n"
    . "--boundary\r\n"
    . "Content-Type: application/octet-stream\r\n"
    . "Content-Transfer-Encoding: base64\r\n"
    . "\r\n"
    . "SGVsbG8sIFdvcmxkIQ=="
    . "\r\n"
    . "--boundary\r\n"
    . "Content-Type: message/rfc822\r\n"
    . "\r\n"
    . "Return-Path: <bla\@local>\r\n"
    . "Mime-Version: 1.0\r\n"
    . "Content-Type: text/plain"
    . "Content-Transfer-Encoding: 7bit\r\n"
    . "Subject: baz\r\n"
    . "From: blu\@local\r\n"
    . "Message-ID: <fake.12123239947.6507\@local>\r\n"
    . "Date: Wed, 06 Oct 2016 14:59:07 +1100\r\n"
    . "To: Test User <test\@local>\r\n"
    . "\r\n"
    . "embedded"
    . "\r\n"
    . "--boundary--\r\n";

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "boundary",
        body => $body
    );

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $r;

    $r = $talk->search(
        "header", "Content-Type", { Quote => "multipart/mixed" }
    ) || die;
    $self->assert_num_equals(1, scalar @$r);

    # Don't index the headers of multiparts or embedded RFC822s
    $r = $talk->search(
        "header", "Content-Type", { Quote => "text/plain" }
    ) || die;
    $self->assert_num_equals(0, scalar @$r);
    $r = $talk->search(
        "fuzzy", "body", { Quote => "text/plain" }
    ) || die;
    $self->assert_num_equals(0, scalar @$r);
    $r = $talk->search(
        "fuzzy", "text", { Quote => "content" }
    ) || die;
    $self->assert_num_equals(0, scalar @$r);

    # But index the body of an embedded RFC822
    $r = $talk->search(
        "fuzzy", "body", { Quote => "embedded" }
    ) || die;
    $self->assert_num_equals(1, scalar @$r);
}

sub test_xapianv2
{
    my ($self) = @_;
    my $talk = $self->{store}->get_client();

    # This is a smallish regression test to check if we break something
    # obvious by moving Xapian indexing from folder:uid to message guids.
    #
    # Apart from the tests in this module, at least also the following
    # imodules are relevant: Metadata for SORT, Thread for THREAD.

    xlog "Generate message";
    my $r = $self->make_message("I run", body => "Run, Forrest! Run!" ) || die;
    my $uid = $r->{attrs}->{uid};

    xlog "Copy message into INBOX";
    $talk->copy($uid, "INBOX");

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $r = $talk->xconvmultisort(
        [ qw(reverse arrival) ],
        [ 'conversations', position => [1,10] ],
        'utf-8', 'fuzzy', 'text', "run",
    );
    $self->assert_num_equals(2, scalar @{$r->{sort}[0]} - 1);
    $self->assert_num_equals(1, scalar @{$r->{sort}});

    xlog "Create target mailbox";
    $talk->create("INBOX.target");

    xlog "Copy message into INBOX.target";
    $talk->copy($uid, "INBOX.target");

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $r = $talk->xconvmultisort(
        [ qw(reverse arrival) ],
        [ 'conversations', position => [1,10] ],
        'utf-8', 'fuzzy', 'text', "run",
    );
    $self->assert_num_equals(3, scalar @{$r->{sort}[0]} - 1);
    $self->assert_num_equals(1, scalar @{$r->{sort}});

    xlog "Generate message";
    $self->make_message("You run", body => "A running joke" ) || die;

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $r = $talk->xconvmultisort(
        [ qw(reverse arrival) ],
        [ 'conversations', position => [1,10] ],
        'utf-8', 'fuzzy', 'text', "run",
    );
    $self->assert_num_equals(2, scalar @{$r->{sort}});

    xlog "SEARCH FUZZY";
    $r = $talk->search(
        "charset", "utf-8", "fuzzy", "text", "run",
    ) || die;
    $self->assert_num_equals(3, scalar @$r);

    xlog "Select INBOX";
    $r = $talk->select("INBOX") || die;
    my $uidvalidity = $talk->get_response_code('uidvalidity');
    my $uids = $talk->search('1:*', 'NOT', 'DELETED');

    xlog "XSNIPPETS";
    $r = $talk->xsnippets(
        [['INBOX', $uidvalidity, $uids]], 'utf-8',
        ['fuzzy', 'body', 'run'],
    ) || die;
    $self->assert_num_equals(3, scalar @{$r->{snippets}});
}

sub test_snippets_escapehtml
{
    my ($self) = @_;
    return if not $self->{test_fuzzy_search};

    xlog "Generate and index test messages.";
    $self->make_message("Test1 subject with an unescaped & in it",
        mime_charset => "utf-8",
        mime_type => "text/html",
        body => "Test1 body with the same <b>tag</b> as snippets"
    ) || die;

    $self->make_message("Test2 subject with a <tag> in it",
        mime_charset => "utf-8",
        mime_type => "text/plain",
        body => "Test2 body with a <tag/>, although it's plain text",
    ) || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $talk = $self->{store}->get_client();

    # Connect to IMAP
    xlog "Select INBOX";
    my $r = $talk->select("INBOX") || die;
    my $uidvalidity = $talk->get_response_code('uidvalidity');
    my $uids = $talk->search('1:*', 'NOT', 'DELETED');
    my %m;

    $r = $talk->xsnippets( [ [ 'inbox', $uidvalidity, $uids ] ],
       'utf-8', [ 'fuzzy', 'text', 'test1' ]
    ) || die;

    %m = map { lc($_->[2]) => $_->[3] } @{ $r->{snippets} };
    $self->assert_str_equals("<b>Test1</b> body with the same tag as snippets", $m{body});
    $self->assert_str_equals("<b>Test1</b> subject with an unescaped &amp; in it", $m{subject});

    $r = $talk->xsnippets( [ [ 'inbox', $uidvalidity, $uids ] ],
       'utf-8', [ 'fuzzy', 'text', 'test2' ]
    ) || die;

    %m = map { lc($_->[2]) => $_->[3] } @{ $r->{snippets} };
    $self->assert_str_equals("<b>Test2</b> body with a &lt;tag/&gt;, although it's plain text", $m{body});
    $self->assert_str_equals("<b>Test2</b> subject with a &lt;tag&gt; in it", $m{subject});
}

1;
