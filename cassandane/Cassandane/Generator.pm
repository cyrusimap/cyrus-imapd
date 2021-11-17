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

package Cassandane::Generator;
use strict;
use warnings;
use Digest::MD5 qw(md5_hex);

use lib '.';
use Cassandane::Util::DateTime qw(to_rfc822 from_iso8601);
use Cassandane::Address;
use Cassandane::Message;
use Cassandane::Util::SHA;

our $admin = 'qa@cyrus.works';

our @girls_forenames = (
    # Top 10 girl baby names in 2006 according to
    # http://www.babyhold.com/babynames/Popular/Popular_girl_names_in_the_US_for_2006/
    'Emily',
    'Emma',
    'Madison',
    'Abigail',
    'Olivia',
    'Isabella',
    'Hannah',
    'Samantha',
    'Ava',
    'Ashley'
);
our @surnames = (
    # Top 10 common surnames in Australia according to
    # http://genealogy.about.com/od/australia/tp/common_surnames.htm
    'Smith',
    'Jones',
    'Williams',
    'Brown',
    'Wilson',
    'Taylor',
    'Nguyen',
    'Johnson',
    'Martin',
    'White'
);
our @domains = (
    # Pulled out of my hat.
    'fastmail.fm',
    'gmail.com',
    'hotmail.com',
    'yahoo.com'
);
our @localpart_styles = (
    sub($$$)
    {
        my ($forename, $initial, $surname) = @_;
        return "$forename.$surname";
    },
    sub($$$)
    {
        my ($forename, $initial, $surname) = @_;
        return lc(substr($forename,0,1) . $initial . $surname);
    },
    sub($$$)
    {
        my ($forename, $initial, $surname) = @_;
        return lc(substr($forename,0,1) .  $initial .  substr($surname,0,1));
    }
);

sub new
{
    my ($class, %params) = @_;

    my $self = {
        next_uid => 1,
        min_extra_lines => $params{min_extra_lines} || 0,
        max_extra_lines => $params{max_extra_lines} || 0,
    };

    bless $self, $class;
    return $self;
}

sub _generate_uid
{
    my ($self) = @_;
    my $uid = $self->{next_uid}++;
    return $uid;
}

sub set_next_uid
{
    my ($self, $uid) = @_;
    $self->{next_uid} = 0+$uid;
}

sub make_random_address
{
    my (%params) = @_;

    my $i = int(rand(scalar(@girls_forenames)));
    my $forename = delete $params{forename};
    $forename = $girls_forenames[$i] if !defined $forename;

    $i = int(rand(scalar(@surnames)));
    my $surname = delete $params{surname};
    $surname = $surnames[$i] if !defined $surname;

    my $digest = md5_hex("$forename $surname");

    $i = oct("0x" . substr($digest,0,4)) % scalar(@domains);
    my $domain = delete $params{domain};
    $domain = $domains[$i] if !defined $domain;

    $i = oct("0x" . substr($digest,4,4)) % 26;
    my $initial = delete $params{initial};
    $initial = substr("ABCDEFGHIJKLMNOPQRSTUVWXYZ", $i, 1)
        if !defined $initial;

    $i = oct("0x" . substr($digest,8,4)) % scalar(@localpart_styles);
    my $localpart = delete $params{localpart};
    $localpart = $localpart_styles[$i]->($forename, $initial, $surname)
        if !defined $localpart;

    my $extra = delete $params{extra};
    $extra = '' if !defined $extra;

    return Cassandane::Address->new(
        name => "$forename $initial. $surname$extra",
        localpart => $localpart,
        domain => $domain
    );
}

sub _generate_from
{
    my ($self, $params) = @_;
    return make_random_address();
}

sub _generate_to
{
    my ($self, $params) = @_;
    return Cassandane::Address->new(
        name => "Test User",
        localpart => 'test',
        domain => 'vmtom.com'
    );
}

sub _generate_messageid
{
    my ($self, $params) = @_;
    my $idsalt = int(rand(65536));
    return "fake." . $params->{date}->epoch() . ".$idsalt\@" .  $params->{from}->domain();
}

sub _params_defaults
{
    my $self = shift;
    my $params = { @_ };

    # Note: no error checking, e.g. for unknown parameters.  Sorry.
    #
    $params->{date} = DateTime->now()
        unless defined $params->{date};
    $params->{date} = from_iso8601($params->{date})
        if ref $params->{date} eq '';
    die "Bad date: " . ref $params->{date}
        unless ref $params->{date} eq 'DateTime';

    $params->{from} = $self->_generate_from($params)
        unless defined $params->{from};
    die "Bad from: " . ref $params->{from}
        unless ref $params->{from} eq 'Cassandane::Address';

    $params->{subject} = "Generated test email"
        unless defined $params->{subject};

    $params->{to} = $self->_generate_to($params)
        unless defined $params->{to};
    die "Bad to: " . ref $params->{to}
        unless ref $params->{to} eq 'Cassandane::Address';

    $params->{messageid} = $self->_generate_messageid($params)
        unless defined $params->{messageid};

    # Allow 'references' to be an array of Message objects
    # which is really handy for generating conversation data
    if (defined $params->{references} &&
        ref $params->{references} eq 'ARRAY')
    {
        my @refs;
        map {
            if (ref($_) eq 'Cassandane::Message')
            {
                push(@refs, $_->messageid())
            }
            else
            {
                push(@refs, "" . $_);
            }
        } @{$params->{references}};
        $params->{references} = join(', ', @refs);
    }

    $params->{uid} = $self->_generate_uid()
        unless defined $params->{uid};

    $params->{body} = "This is a generated test email.  " .
                      "If received, please notify $admin\r\n"
        unless defined $params->{body};

    $params->{extra_lines} = int($self->{min_extra_lines} +
                                 rand($self->{max_extra_lines} -
                                      $self->{min_extra_lines}))
        unless defined $params->{extra_lines};

    $params->{mime_encoding} = '7bit'
        unless defined $params->{mime_encoding};
    $params->{mime_type} = 'text/plain'
        unless defined $params->{mime_type};
    $params->{mime_charset} = 'us-ascii'
        unless defined $params->{mime_charset};
    $params->{mime_boundary} = 'Apple-Mail-1-798269008'
        unless defined $params->{mime_boundary};

    return $params;
}

sub _generate_unique
{
    return sha1_hex("" . int(rand(65536)));
}

#
# Generate a single email.
# Args: Generator, (param-key => param-value ... )
# Returns: Message ref
#
sub generate
{
    my ($self, @aparams) = @_;
    my $params = $self->_params_defaults(@aparams);
    my $datestr = to_rfc822($params->{date});
    my $from = $params->{from};
    my $to = $params->{to};
    my $extra_lines = $params->{extra_lines};
    my $extra = '';
    if ($extra_lines) {
        $extra .= "This is an extra line\r\n" x $extra_lines;
    }
    my $size = $params->{size};
    my $msg = Cassandane::Message->new();

    $msg->add_header("Return-Path", "<" . $from->address() . ">");
    # TODO: two minutes ago
    $msg->add_header("Received",
                     "from gateway (gateway." . $to->domain() . " [10.0.0.1])\r\n" .
                     "\tby ahost (ahost." . $to->domain() . "[10.0.0.2]); $datestr");
    $msg->add_header("Received",
                     "from mail." . $from->domain() . " (mail." . $from->domain() . " [192.168.0.1])\r\n" .
                     "\tby gateway." . $to->domain() . " (gateway." . $to->domain() . " [10.0.0.1]); $datestr");
    $msg->add_header("MIME-Version", "1.0");
    my $mimetype = $params->{mime_type};
    if ($mimetype =~ m/multipart\//i)
    {
        $mimetype .= "; boundary=\"$params->{mime_boundary}\""
    }
    else
    {
        $mimetype .= "; charset=\"$params->{mime_charset}\""
            if $params->{mime_charset} ne '';
    }
    $msg->add_header("Content-Type", $mimetype);
    $msg->add_header("Content-Transfer-Encoding", $params->{mime_encoding});
    $msg->add_header("Subject", $params->{subject});
    $msg->add_header("From", $from);
    $msg->add_header("Message-ID", "<" . $params->{messageid} . ">");
    $msg->add_header("References", $params->{references})
        if defined $params->{references};
    $msg->add_header("Date", $datestr);
    $msg->add_header("To", $to);
    $msg->add_header("Cc", $params->{cc}) if defined $params->{cc};
    $msg->add_header("Bcc", $params->{bcc}) if defined $params->{bcc};
    if (defined($params->{extra_headers})) {
        foreach my $extra_header (@{$params->{extra_headers}}) {
            $msg->add_header(@{$extra_header});
        }
    }
    $msg->add_header('X-Cassandane-Unique', _generate_unique());
    if (defined $size)
    {
        my $padding = "ton bear\r\n";
        my $msg_size = $msg->size() + length($params->{body}) + length($extra);
        my $needs = $size - $msg_size;
        die "size $size cannot be achieved, message is already $msg_size bytes long"
            if $needs < 0;
        my $npad = int($needs / length($padding)) - 1;
        if ($npad > 0)
        {
            $extra .= $padding x $npad;
            $needs -= length($padding) * $npad;
        }
        $extra .= 'X' x ($needs - 2) if ($needs >= 2);
        $extra .= "\r\n";
    }
    $msg->set_body($params->{body} . $extra);
    $msg->set_attributes(uid => $params->{uid});
    $msg->set_internaldate($params->{date});

    return $msg;
}


1;
