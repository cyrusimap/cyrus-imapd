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

    $res = $imaptalk->fetch('1', '(BODY[3.2.2])');
    $self->assert_str_equals($res->{'1'}->{body}, "PGh0bWw+CiAgPGhlYWQ+CiAg==");

    $res = $imaptalk->fetch('1', '(BODY[3.2.2]<4.3>)');
    $self->assert_str_equals($res->{'1'}->{body}, substr("PGh0bWw+CiAgPGhlYWQ+CiAg==", 4, 3));

    $res = $imaptalk->fetch('1', '(BODY.PEEK[4.HEADER.FIELDS (CONTENT-TYPE)])');
    $self->assert_str_equals($res->{'1'}->{headers}->{"content-type"}[0], "text/plain");

    $res = $imaptalk->fetch('1', '(BODY[4.TEXT])');
    $self->assert_str_equals($res->{'1'}->{body}, "body4");

    $res = $imaptalk->fetch('1', '(BODY[4])');
    $self->assert_str_equals($res->{'1'}->{body}, $msg4);

    $res = $imaptalk->fetch('1', '(BODY[5.2])');
    $self->assert_str_equals($res->{'1'}->{body}, "body52");

    # Check for some bogus subparts
    $res = $imaptalk->fetch('1', '(BODY[3.2.3])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[4.2])');
    $self->assert_null($res->{'1'}->{body});

    $res = $imaptalk->fetch('1', '(BODY[-1])');
    $self->assert_null($res->{'1'}->{body});
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


1;
