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

package Cassandane::Cyrus::Fetch;
use strict;
use warnings;
use Data::Dumper;
use DateTime;
use IO::Scalar;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Address;
use Cassandane::Util::DateTime qw(to_rfc822);
use Cassandane::Util::Log;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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
# Test COPY behaviour with a very long sequence set
#
sub test_fetch_header
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.dest");
    $self->make_message("Test Message");

    # unfortunately, you can't see the data that went over the wire very easily
    # in IMAPTalk - but we know the headers will be in a literal, so..
    my $body = "";
    $imaptalk->literal_handle_control(new IO::Scalar \$body);
    my $res = $imaptalk->fetch('1', '(UID FLAGS BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])');
    $imaptalk->literal_handle_control(0);

    $self->assert(defined $res, "Fetch feturned a response");
    $self->assert_matches(qr/^Message-ID: <[^>]+>\s+$/, $body);
}

# https://github.com/cyrusimap/cyrus-imapd/issues/21
sub test_duplicate_headers
    :min_version_3_0
{
    my ($self) = @_;

    my $from1 = Cassandane::Address->new(localpart => 'firstsender',
                                         domain    => 'example.com');
    my $from2 = Cassandane::Address->new(localpart => 'secondsender',
                                         domain    => 'example.com');

    my $rcpt1 = Cassandane::Address->new(localpart => 'firstrecipient',
                                         domain    => 'example.com');
    my $rcpt2 = Cassandane::Address->new(localpart => 'secondrecipient',
                                         domain    => 'example.com');

    my $cc1   = Cassandane::Address->new(localpart => 'firstcc',
                                         domain    => 'example.com');
    my $cc2   = Cassandane::Address->new(localpart => 'secondcc',
                                         domain    => 'example.com');

    my $bcc1  = Cassandane::Address->new(localpart => 'firstbcc',
                                         domain    => 'example.com');
    my $bcc2  = Cassandane::Address->new(localpart => 'secondbcc',
                                         domain    => 'example.com');

    my $date1 = DateTime->from_epoch(epoch => time());
    my $date2 = DateTime->from_epoch(epoch => time() - 2);

    my $msg = $self->make_message(
        'subject1',
        from => $from1,
        to => $rcpt1,
        cc => $cc1,
        bcc => $bcc1,
        messageid => 'messageid1@example.com',
        date => $date1,
        extra_headers => [
            [subject => 'subject2'],
            [from => $from2->as_string() ],
            [to => $rcpt2->as_string() ],
            [cc => $cc2->as_string() ],
            [bcc => $bcc2->as_string() ],
            ['message-id' => '<messageid2@example.com>' ],
            [date => to_rfc822($date2) ],
        ],
    );

    # Verify that it created duplicate headers, and didn't collate the values.
    # If it collated the values, this test proves nothing.
    $self->assert_equals(scalar(grep { $_->{name} eq 'subject' } @{$msg->{headers}}), 2);
    $self->assert_equals(scalar(grep { $_->{name} eq 'from' } @{$msg->{headers}}), 2);
    $self->assert_equals(scalar(grep { $_->{name} eq 'to' } @{$msg->{headers}}), 2);
    $self->assert_equals(scalar(grep { $_->{name} eq 'cc' } @{$msg->{headers}}), 2);
    $self->assert_equals(scalar(grep { $_->{name} eq 'bcc' } @{$msg->{headers}}), 2);

    # XXX Cassandane::Message's add_header() appends rather than prepends.
    # So we currently expect all the "second" values, when we would prefer
    # to expect the "first" ones.
    my %exp = (
        Subject => 'subject2',
        From => $from2->address(),
        To => $rcpt2->address(),
        Cc => $cc2->address(),
        Bcc => $bcc2->address(),
        Date => to_rfc822($date2),
        'Message-ID' => '<messageid2@example.com>',
        'In-Reply-To' => undef,
    );

    my $imaptalk = $self->{store}->get_client();
    my $res = $imaptalk->fetch('1', 'ENVELOPE');

    # XXX what behaviour do we expect from Sender and Reply-To headers?
    delete $res->{1}->{envelope}->{Sender};
    delete $res->{1}->{envelope}->{'Reply-To'};

    $self->assert_deep_equals(\%exp, $res->{1}->{envelope});
}

sub test_header_multiple
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $extra_headers = [
        ['x-nice-day-for', 'start again (come on)' ],
        ['x-awkward', 'interjection' ],
        ['x-nice-day-for', 'white wedding' ],
        ['x-nice-day-for', 'start agaaain' ],
    ];

    my %exp;
    $exp{1} = $self->make_message('message 1',
                                  'extra_headers' => $extra_headers);
    $exp{2} = $self->make_message('nice day');
    $self->check_messages(\%exp);

    my $res = $talk->fetch('1:*',
                           '(BODY.PEEK[HEADER.FIELDS (x-nice-day-for)])');
    $self->assert_num_equals(2, scalar keys %{$res});

    my $expected = {
        'x-nice-day-for' => [
            'start again (come on)',
            'white wedding',
            'start agaaain',
        ],
    };
    $self->assert_deep_equals($expected, $res->{1}->{headers});
    $self->assert_deep_equals({}, $res->{2}->{headers});
}

sub test_fetch_section
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    # Start body
    my $body = "--047d7b33dd729737fe04d3bde348\r\n";

    # Subpart 1
    $body .= ""
    . "Content-Type: text/plain; charset=UTF-8\r\n"
    . "\r\n"
    . "body1"
    . "\r\n";

    # Subpart 2
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: text/html;charset=\"ISO-8859-1\"\r\n"
    . "\r\n"
    . "<html><body><p>body2</p></body></html>"
    . "\r\n";

    # Subpart 3
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: multipart/mixed;boundary=frontier\r\n"
    . "\r\n";

    # Subpart 3.1
    $body .= "--frontier\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body31"
    . "\r\n";

    # Subpart 3.2
    $body .= "--frontier\r\n"
    . "Content-Type: multipart/mixed;boundary=border\r\n"
    . "\r\n"
    . "body32"
    . "\r\n";

    # Subpart 3.2.1
    $body .= "--border\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body321"
    . "\r\n";

    # Subpart 3.2.2
    $body .= "--border\r\n"
    . "Content-Type: application/octet-stream\r\n"
    . "Content-Transfer-Encoding: base64\r\n"
    . "\r\n"
    . "PGh0bWw+CiAgPGhlYWQ+CiAg=="
    . "\r\n";

    # End subpart 3.2
    $body .= "--border--\r\n";

    # End subpart 3
    $body .= "--frontier--\r\n";

    # Subpart 4
    my $msg4 = ""
    . "Return-Path: <Ava.Nguyen\@local>\r\n"
    . "Mime-Version: 1.0\r\n"
    . "Content-Type: text/plain\r\n"
    . "Content-Transfer-Encoding: 7bit\r\n"
    . "Subject: bar\r\n"
    . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
    . "Message-ID: <fake.1475639947.6507\@local>\r\n"
    . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
    . "To: Test User <test\@local>\r\n"
    . "\r\n"
    . "body4";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: message/rfc822\r\n"
    . "\r\n"
    . $msg4
    . "\r\n";

    # Subpart 5
    my $msg5 = ""
    . "Return-Path: <bla\@local>\r\n"
    . "Mime-Version: 1.0\r\n"
    . "Content-Type: multipart/mixed;boundary=subpart5\r\n"
    . "Content-Transfer-Encoding: 7bit\r\n"
    . "Subject: baz\r\n"
    . "From: blu\@local\r\n"
    . "Message-ID: <fake.12123239947.6507\@local>\r\n"
    . "Date: Wed, 06 Oct 2016 14:59:07 +1100\r\n"
    . "To: Test User <test\@local>\r\n"
    . "\r\n"
    . "--subpart5\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body51"
    . "\r\n"
    . "--subpart5\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body52"
    . "\r\n"
    . "--subpart5--\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: message/rfc822\r\n"
    . "\r\n"
    . $msg5
    . "\r\n";

    # End body
    $body .= "--047d7b33dd729737fe04d3bde348--";

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    my $res;

    $res = $imaptalk->fetch('1', '(BODY[1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body1");

    $res = $imaptalk->fetch('1', '(BODY[2])');
    $self->assert_str_equals($res->{'1'}->{body}, "<html><body><p>body2</p></body></html>");

    $res = $imaptalk->fetch('1', '(BODY[3.1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body31");

    $res = $imaptalk->fetch('1', '(BODY[3.2.1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body321");

    $res = $imaptalk->fetch('1', '(BODY[3.2.1.MIME])');
    $self->assert($res->{'1'}->{body} =~ m/Content-Type/);
    $self->assert(not $res->{'1'}->{body} =~ m/body321/);

    $res = $imaptalk->fetch('1', '(BODY[3.2.2])');
    $self->assert_str_equals($res->{'1'}->{body}, "PGh0bWw+CiAgPGhlYWQ+CiAg==");

    $res = $imaptalk->fetch('1', '(BODY[3.2.2]<4.3>)');
    $self->assert_str_equals($res->{'1'}->{body}, substr("PGh0bWw+CiAgPGhlYWQ+CiAg==", 4, 3));

    $res = $imaptalk->fetch('1', '(BODY.PEEK[4.HEADER.FIELDS (CONTENT-TYPE)])');
    $self->assert_str_equals($res->{'1'}->{headers}->{"content-type"}[0], "text/plain");

    $res = $imaptalk->fetch('1', '(BODY[4.1.MIME])');
    $self->assert($res->{'1'}->{body} =~ m/Content-Type/);

    $res = $imaptalk->fetch('1', '(BODY[4])');
    $self->assert_str_equals($res->{'1'}->{body}, $msg4);

    $res = $imaptalk->fetch('1', '(BODY[5.2])');
    $self->assert_str_equals($res->{'1'}->{body}, "body52");

    # Check for some bogus subparts
    $res = $imaptalk->fetch('1', '(BODY[3.2.3])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[3.2.1.2])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[4.2])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[-1])');
    $self->assert_null($res->{'1'}->{body});
}

sub test_fetch_section_multipart
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    # Start body
    my $body = "--047d7b33dd729737fe04d3bde348\r\n";

    # Subpart 1
    $body .= ""
    . "Content-Type: text/plain; charset=UTF-8\r\n"
    . "\r\n"
    . "body1"
    . "\r\n";

    # Subpart 2
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: text/html;charset=\"ISO-8859-1\"\r\n"
    . "\r\n"
    . "<html><body><p>body2</p></body></html>"
    . "\r\n";

    # Subpart 3
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: multipart/mixed;boundary=frontier\r\n"
    . "\r\n";

    # Subpart 3.1
    $body .= "--frontier\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body31"
    . "\r\n";

    # Subpart 3.2
    $body .= "--frontier\r\n"
    . "Content-Type: multipart/mixed;boundary=border\r\n"
    . "\r\n"
    . "body32"
    . "\r\n";

    # Subpart 3.2.1
    $body .= "--border\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body321"
    . "\r\n";

    # Subpart 3.2.2
    $body .= "--border\r\n"
    . "Content-Type: application/octet-stream\r\n"
    . "Content-Transfer-Encoding: base64\r\n"
    . "\r\n"
    . "PGh0bWw+CiAgPGhlYWQ+CiAg=="
    . "\r\n";

    # End subpart 3.2
    $body .= "--border--\r\n";

    # End subpart 3
    $body .= "--frontier--\r\n";

    # End body
    $body .= "--047d7b33dd729737fe04d3bde348--";

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    my $res;

    $res = $imaptalk->fetch('1', '(BODY[1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body1");

    $res = $imaptalk->fetch('1', '(BODY[2])');
    $self->assert_str_equals($res->{'1'}->{body}, "<html><body><p>body2</p></body></html>");

    $res = $imaptalk->fetch('1', '(BODY[3.1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body31");

    $res = $imaptalk->fetch('1', '(BODY[3.2.1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body321");

    $res = $imaptalk->fetch('1', '(BODY[3.2.1.MIME])');
    $self->assert($res->{'1'}->{body} =~ m/Content-Type/);
    $self->assert(not $res->{'1'}->{body} =~ m/body321/);

    $res = $imaptalk->fetch('1', '(BODY[3.2.2])');
    $self->assert_str_equals($res->{'1'}->{body}, "PGh0bWw+CiAgPGhlYWQ+CiAg==");

    $res = $imaptalk->fetch('1', '(BODY[3.2.2]<4.3>)');
    $self->assert_str_equals($res->{'1'}->{body}, substr("PGh0bWw+CiAgPGhlYWQ+CiAg==", 4, 3));

    # Check for some bogus subparts
    $res = $imaptalk->fetch('1', '(BODY[3.2.3])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[3.2.1.2])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[4.2])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[-1])');
    $self->assert_null($res->{'1'}->{body});
}

sub test_fetch_section_rfc822digest
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $ct = "multipart/digest; boundary=\"foo\"";
    my $from = "sub\@domain.org";
    my $date = "Sun, 12 Aug 2012 12:34:56 +0300";
    my $subj = "submsg";

    my $body = ""
    . "From: $from\r\n"
    . "Date: $date\r\n"
    . "Subject: $subj\r\n"
    . "Content-Type: $ct\r\n"
    . "\r\n"
    . "prologue\r\n"
    . "\r\n"
    . "--foo\r\n"
    . "\r\n"
    . "From: m1\@example.com\r\n"
    . "Subject: m1\r\n"
    . "\r\n"
    . "m1 body\r\n"
    . "\r\n"
    . "--foo\r\n"
    . "X-Mime: m2 header\r\n"
    . "\r\n"
    . "From: m2\@example.com\r\n"
    . "Subject: m2\r\n"
    . "\r\n"
    . "m2 body\r\n"
    . "\r\n"
    . "--foo--\r\n"
    . "\r\n"
    . "epilogue\r\n"
    . "\r\n";

    $self->make_message("foo",
        mime_type => "message/rfc822",
        body => $body,
    );

    my $res;

    $res = $imaptalk->fetch('1', '(BODY.PEEK[TEXT])');
    $self->assert_str_equals($res->{'1'}->{body}, $body);

    $res = $imaptalk->fetch('1', '(BODY.PEEK[1])');
    $self->assert_str_equals($res->{'1'}->{body}, $body);

    $res = $imaptalk->fetch('1', '(BODY.PEEK[1.HEADER])');
    $self->assert_str_equals($res->{'1'}->{headers}->{"content-type"}[0], $ct);
    $self->assert_str_equals($res->{'1'}->{headers}->{"date"}[0], $date);
    $self->assert_str_equals($res->{'1'}->{headers}->{"from"}[0], $from);
    $self->assert_str_equals($res->{'1'}->{headers}->{"subject"}[0], $subj);
}

sub test_fetch_section_rfc822
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $body = ""
    . "From: sub\@domain.org\r\n"
    . "Date: Sun, 12 Aug 2012 12:34:56 +0300\r\n"
    . "Subject: submsg\r\n"
    . "\r\n"
    . "foo";

    $self->make_message("foo",
        mime_type => "message/rfc822",
        body => $body,
    );

    my $res;

    $res = $imaptalk->fetch('1', '(BODY.PEEK[TEXT])');
    $self->assert_str_equals($res->{'1'}->{body}, $body);

    $res = $imaptalk->fetch('1', '(BODY.PEEK[1])');
    $self->assert_str_equals($res->{'1'}->{body}, $body);

    $res = $imaptalk->fetch('1', '(BODY.PEEK[1.TEXT])');
    $self->assert_str_equals($res->{'1'}->{body}, "foo");

    $res = $imaptalk->fetch('1', '(BODY.PEEK[1.1])');
    $self->assert_str_equals($res->{'1'}->{body}, "foo");
}


sub test_fetch_section_nomultipart
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $self->make_message(
        "foo",
        from =>  Cassandane::Address->new(
            localpart => 'foo',
            domain    => 'example.com',
        ),
        mime_type => "text/plain",
        body => "body1",
    );

    my $res;

    $res = $imaptalk->fetch('1', '(BODY[1])');
    $self->assert_str_equals($res->{'1'}->{body}, "body1");

    # RFC 3501: "Every message has at least one part number."
    $res = $imaptalk->fetch('1', '(BODY[1.MIME])');
    $self->assert($res->{'1'}->{body} =~ m/Content-Type/);
    $self->assert(not $res->{'1'}->{body} =~ m/body1/);

    $res = $imaptalk->fetch('1', '(BODY[HEADER])');
    $self->assert($res->{'1'}->{body} =~ m/Content-Type/);

    $res = $imaptalk->fetch('1', '(BODY.PEEK[HEADER.FIELDS (FROM)])');
    $self->assert_str_equals($res->{'1'}->{headers}->{from}[0], "<foo\@example.com>");

    $res = $imaptalk->fetch('1', '(BODY[1.HEADER])');
    $self->assert_null($res->{'1'}->{body});

    # invalid
    $res = $imaptalk->fetch('1', '(BODY[0])');
    $self->assert_null($res->{'1'}->{body});

    # invalid
    $res = $imaptalk->fetch('1', '(BODY[1.1])');
    $self->assert_null($res->{'1'}->{body});

    # invalid
    $res = $imaptalk->fetch('1', '(BODY[0.1])');
    $self->assert_null($res->{'1'}->{body});

    # invalid
    $res = $imaptalk->fetch('1', '(BODY[1.0])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BINARY[1]<0.2>)');
    $self->assert_str_equals($res->{'1'}->{binary}, "bo");

    $res = $imaptalk->fetch('1', '(BINARY[1]<2.10>)');
    $self->assert_str_equals($res->{'1'}->{binary}, "dy1");

    $res = $imaptalk->fetch('1', '(BINARY[1]<10.12>)');
    $self->assert_str_equals($res->{'1'}->{binary}, "");
}

sub test_fetch_urlfetch
{
    my ($self) = @_;

    my %exp_sub;
    my $store = $self->{store};
    my $talk = $store->get_client();

    $store->set_folder("INBOX");
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body;

    # Subpart 1
    $body = "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: text/plain; charset=UTF-8\r\n"
    . "\r\n"
    . "body1"
    . "\r\n";

    # Subpart 2
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: multipart/mixed;boundary=frontier\r\n"
    . "\r\n";

    # Subpart 2.1
    $body .= "--frontier\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body21"
    . "\r\n";

    # End subpart 2
    $body .= "--frontier--\r\n";

    # Subpart 3
    my $msg3 = ""
    . "Return-Path: <Ava.Nguyen\@local>\r\n"
    . "Mime-Version: 1.0\r\n"
    . "Content-Type: text/plain\r\n"
    . "Content-Transfer-Encoding: 7bit\r\n"
    . "Subject: bar\r\n"
    . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
    . "Message-ID: <fake.1475639947.6507\@local>\r\n"
    . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
    . "To: Test User <test\@local>\r\n"
    . "\r\n"
    . "body3";

    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: message/rfc822\r\n"
    . "\r\n"
    . $msg3
    . "\r\n";

    # End body
    $body .= "--047d7b33dd729737fe04d3bde348--";

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    my $uid;
    my %handlers =
    (
        appenduid => sub
        {
            my ($cmd, $ids) = @_;
            $uid = ${$ids}[1];
        },
    );

    my $res;

    # Copy the whole message
    $res = $talk->_imap_cmd('append', 0, \%handlers,
        'INBOX', [], "14-Jul-2013 17:01:02 +0000",
        "CATENATE", [
            "URL", "/INBOX/;uid=1/;section=HEADER",
            "URL", "/INBOX/;uid=1/;section=TEXT",
        ],
    );
    $self->assert_not_null($uid);
    $res = $talk->fetch($uid, '(BODY.PEEK[TEXT])');
    $self->assert_str_equals($res->{$uid}->{body}, $body);

    # Merge the headers of an embedded RFC822 message with a plaintext subpart
    $res = $talk->_imap_cmd('append', 0, \%handlers,
        'INBOX', [], "14-Jul-2013 17:01:02 +0000",
        "CATENATE", [
            "URL", "/INBOX/;uid=1/;section=3.HEADER",
            "URL", "/INBOX/;uid=1/;section=2.1",
        ],
    );
    $self->assert_not_null($uid);
    $res = $talk->fetch($uid, '(BODY.PEEK[TEXT] BODY.PEEK[HEADER.FIELDS (CONTENT-TYPE)])');
    $self->assert_str_equals($res->{$uid}->{headers}->{'content-type'}[0], "text/plain");
    $self->assert_str_equals($res->{$uid}->{body}, "body21");

    # Extract an embedded RFC822 message into a new standalone message
    $res = $talk->_imap_cmd('append', 0, \%handlers,
        'INBOX', [], "14-Jul-2013 17:01:02 +0000",
        "CATENATE", [
            "URL", "/INBOX/;uid=1/;section=3",
        ],
    );
    $self->assert_not_null($uid);
    $res = $talk->fetch($uid, '(BODY.PEEK[TEXT] BODY.PEEK[HEADER.FIELDS (CONTENT-TYPE)])');
    $self->assert_str_equals($res->{$uid}->{headers}->{'content-type'}[0], "text/plain");
    $self->assert_str_equals($res->{$uid}->{body}, "body3");
}

sub test_fetch_flags_before_exists
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->select('user.cassandane');
    $self->make_message("Test Message");
    # this sets the state with EXISTS = 1
    $admintalk->fetch('1:*', '(flags)');

    $self->make_message("Test Message");
#    $res = $admintalk->fetch('1:*', '(flags)');

    # need to make our own handlers
    my %handlers;
    {
        my $sawfetch = -1;
        use Data::Dumper;
        $handlers{fetch} = sub { $sawfetch = $_[2] if $sawfetch < $_[2] };
        $handlers{exists} = sub { die "Got exists count too late for $_[2]" if $_[2] <= $sawfetch };
    }

    # expecting to see EXISTS 2 before FETCH 2
    $admintalk->_imap_cmd("fetch", 1, \%handlers, \'1:*', '(flags)');
}

sub test_tell_exists_count_earlier
    :min_version_3_0
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->select('user.cassandane');

    $self->make_message("Test Message 1");
    $admintalk->fetch('1:*', '(flags)');

    $self->make_message("Test Message 2");
    $admintalk->fetch('2:*', '(flags)');

    $self->make_message("Test Message 3");
    $admintalk->fetch('3:*', '(uid flags)');

    $admintalk->unselect();
    $admintalk->select('user.cassandane');

    $imaptalk->store('2', '+flags', '(\\Flagged)');
    $self->make_message("Test Message 4");

    my %handlers;
    {
        my $sawfetch = -1;
        my $sawmsg2fetch = -1;
        my $sawmsg3fetch = -1;
        my $sawmsg4fetch = -1;
        use Data::Dumper;
        $handlers{fetch} = sub {
            $sawfetch = 1 if $sawfetch < 0;

            if ($_[2] == 2) { $sawmsg2fetch = $_[2] }
            elsif ($_[2] == 3) {
                $sawmsg3fetch = $_[2];
                die "Got FETCH for 3 before 2" if $sawmsg2fetch < 0;
            }
            elsif ($_[2] == 3) {
                $sawmsg4fetch = $_[2];
                die "Got FETCH for 4 before 2" if $sawmsg2fetch < 0;
                die "Got FETCH for 4 before 3" if $sawmsg3fetch < 0;
            }
            else { }
        };
        $handlers{exists} = sub { die "Got EXISTS after FETCH for $_[2]" if $sawfetch > 0; };
    }

    $admintalk->_imap_cmd("fetch", 1, \%handlers, \'3:*', '(uid flags)');
}

sub test_mailboxids
    :min_version_3_1 :Conversations
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $res = $imaptalk->status('INBOX', ['mailboxid']);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    my $inbox_id = $res->{'mailboxid'}->[0];
    $self->assert_not_null($inbox_id);

    $imaptalk->create("INBOX.target");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->status('INBOX.target', ['mailboxid']);
    my $target_id = $res->{'mailboxid'}->[0];
    $self->assert_not_null($target_id);

    # make a message
    my $msg = $self->make_message("test message");
    my $uid = $msg->{attrs}->{uid};

    # expect to find it in INBOX only
    $res = $imaptalk->fetch('1', '(MAILBOXES MAILBOXIDS)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals([$inbox_id], $res->{1}->{'mailboxids'});
    $self->assert_deep_equals(['INBOX'], $res->{1}->{'mailboxes'});

    # copy it to INBOX.target
    $imaptalk->copy($uid, "INBOX.target");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect to find it in INBOX and INBOX.target
    $res = $imaptalk->fetch('1', '(MAILBOXES MAILBOXIDS)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals([$inbox_id, $target_id],
                              $res->{1}->{'mailboxids'});
    $self->assert_deep_equals(['INBOX', 'INBOX.target'],
                              $res->{1}->{'mailboxes'});

    # delete it from INBOX
    $imaptalk->store('1', '+FLAGS', '(\\Deleted)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect to find it in INBOX.target only
    $res = $imaptalk->fetch('1', '(MAILBOXES MAILBOXIDS)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals([$target_id],
                              $res->{1}->{'mailboxids'});
    $self->assert_deep_equals(['INBOX.target'],
                              $res->{1}->{'mailboxes'});

    # expunge INBOX
    $imaptalk->expunge();

    # expect to find it in INBOX.target only
    $res = $imaptalk->fetch('1', '(MAILBOXES MAILBOXIDS)');
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $imaptalk->select('INBOX.target');
    $res = $imaptalk->fetch('1', '(MAILBOXES MAILBOXIDS)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals([$target_id],
                              $res->{1}->{'mailboxids'});
    $self->assert_deep_equals(['INBOX.target'],
                              $res->{1}->{'mailboxes'});
}

sub test_mailboxids_noconversations
    :min_version_3_1
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    # make a message
    my $msg = $self->make_message("test message");
    my $uid = $msg->{attrs}->{uid};

    # expect FETCH MAILBOXES to be rejected
    my $res = $imaptalk->fetch('1', '(MAILBOXES)');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    # expect FETCH MAILBOXIDS to be rejected
    $res = $imaptalk->fetch('1', '(MAILBOXIDS)');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());
}

# test for older draft preview behaviour, obsoleted by publication of
# RFC 8970
sub test_preview_args_legacy
    :min_version_3_1 :max_version_3_4 :Conversations
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    # make a message
    my $msg = $self->make_message("test message");
    my $uid = $msg->{attrs}->{uid};

    my $res;

    # expect no name to be accepted
    $res = $imaptalk->fetch('1', '(PREVIEW)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect no name to be accepted
    $res = $imaptalk->fetch('1', '(PREVIEW ())');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect bad name to be rejected
    $res = $imaptalk->fetch('1', '(PREVIEW (FUZZY=BUZZY))');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    # expect fuzzy name to be accepted
    $res = $imaptalk->fetch('1', '(PREVIEW (FUZZY))');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect lazy fuzzy name to be accepted
    $res = $imaptalk->fetch('1', '(PREVIEW (LAZY=FUZZY))');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
}

sub test_preview_args
    :min_version_3_5 :Conversations
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    # make a message
    my $msg = $self->make_message("test message");
    my $uid = $msg->{attrs}->{uid};

    my $res;

    # expect no modifier to be accepted
    $res = $imaptalk->fetch('1', '(PREVIEW)');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect empty modifier list to be rejected
    $res = $imaptalk->fetch('1', '(PREVIEW ())');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    # expect bad modifier name to be rejected
    $res = $imaptalk->fetch('1', '(PREVIEW (FOO))');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());

    # expect lazy modifier to be accepted
    $res = $imaptalk->fetch('1', '(PREVIEW (LAZY))');
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # expect lazy + bad modifier to be rejected
    $res = $imaptalk->fetch('1', '(PREVIEW (LAZY FOO))');
    $self->assert_str_equals('bad', $imaptalk->get_last_completion_response());
}

1;
