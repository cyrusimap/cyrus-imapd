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
use DateTime;
use IO::Scalar;

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

    $Data::Dumper::Sortkeys = 1;

    my $msg = $self->make_message(
	'subject1',
	from => $from1,
	to => $rcpt1,
	cc => $cc1,
	bcc => $bcc1,
	extra_headers => [
	    [subject => 'subject2'],
	    [from => $from2->as_string() ],
	    [to => $rcpt2->as_string() ],
	    [cc => $cc2->as_string() ],
	    [bcc => $bcc2->as_string() ],
	],
    );

    # XXX Cassandane::Message's add_header() appends rather than prepends.
    # So we currently expect all the "second" values, when we would prefer
    # to expect the "first" ones.
    my %exp = (
	Subject => 'subject2',
	From => $from2->address(),
	To => $rcpt2->address(),
	Cc => $cc2->address(),
	Bcc => $bcc2->address(),
	Date => $msg->get_header('date'),
	'Message-ID' => $msg->get_header('message-id'),
	'In-Reply-To' => undef,
    );

    my $imaptalk = $self->{store}->get_client();
    my $res = $imaptalk->fetch('1', 'ENVELOPE');

    # XXX what behaviour do we expect from Sender and Reply-To headers?
    delete $res->{1}->{envelope}->{Sender};
    delete $res->{1}->{envelope}->{'Reply-To'};

    $self->assert_deep_equals(\%exp, $res->{1}->{envelope});
}

1;
