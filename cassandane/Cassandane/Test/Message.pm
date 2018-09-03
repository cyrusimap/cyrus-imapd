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

package Cassandane::Test::Message;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Message;
use Cassandane::Address;
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(to_rfc3501);

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

# Test default ctor
sub test_empty
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $self->assert_null($m->get_headers('from'));
    $self->assert_null($m->get_headers('to'));
    $self->assert_null($m->get_body());

    my $exp = <<'EOF';

EOF
    $exp =~ s/\n/\r\n/g;

    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test case sensitivity of header names
sub test_header_case
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('SUBJECT', 'Hello World');
    $self->assert_null($m->get_headers('from'));
    $self->assert_null($m->get_headers('to'));
    $self->assert_null($m->get_body);
    $self->assert_str_equals('Hello World', $m->get_headers('SUBJECT')->[0]);
    $self->assert_str_equals('Hello World', $m->get_headers('Subject')->[0]);
    $self->assert_str_equals('Hello World', $m->get_headers('subject')->[0]);
    $self->assert_str_equals('Hello World', $m->get_headers('sUbJeCt')->[0]);

    my $exp = <<'EOF';
Subject: Hello World

EOF
    $exp =~ s/\n/\r\n/g;

    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test implicit stringification of Addresses when passing to headers
sub test_address_stringification
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $m->add_header('From', Cassandane::Address->new(
            name => 'Fred J. Bloggs',
            localpart => 'fbloggs',
            domain => 'fastmail.fm'));
    $self->assert_null($m->get_headers('to'));
    $self->assert_null($m->get_body);
    $self->assert_str_equals('Fred J. Bloggs <fbloggs@fastmail.fm>',
                             $m->get_headers('from')->[0]);
    my $exp = <<'EOF';
Subject: Hello World
From: Fred J. Bloggs <fbloggs@fastmail.fm>

EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test stringification of a list of Addresses when passing to headers
sub test_address_list_stringification
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    my @tos = (
        Cassandane::Address->new(
            name => 'Sarah Jane Smith',
            localpart => 'sjsmith',
            domain => 'tard.is'),
        Cassandane::Address->new(
            name => 'Genghis Khan',
            localpart => 'gkhan',
            domain => 'horde.mo'),
        );
    $m->add_header('To', join(', ', @tos));
    $self->assert_null($m->get_body());
    $self->assert_null($m->get_headers('from'));
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    my $exp = <<'EOF';
Subject: Hello World
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>

EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test multiple headers with the same name
sub test_multiple_headers
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $m->add_header("received", "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100");
    $m->add_header("received", "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100");
    $m->add_header("received", "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100");
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers("received"));
    my $exp = <<'EOF';
Subject: Hello World
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}


# Test replacing headers
sub test_replacing_headers
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $self->assert_str_equals(
        'Hello World',
        $m->get_header('subject'));
    $m->set_headers('subject', 'No, scratch that');
    $self->assert_str_equals(
        'No, scratch that',
        $m->get_header('subject'));
    my $exp = <<'EOF';
Subject: No, scratch that

EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test deleting headers
sub test_deleting_headers
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $m->add_header("received", "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100");
    $m->add_header("received", "from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100");
    $m->add_header("received", "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100");
    $self->assert_str_equals('Hello World', $m->get_header('subject'));
    $m->remove_headers('subject');
    $self->assert_null($m->get_header('subject'));
    my $exp = <<'EOF';
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software); Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1]) by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test adding a body -- only plain text for now, no MIME
sub test_add_body
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $m->set_body("This is a message to let you know\r\nthat I'm alive and well\r\n");
    my $exp = <<'EOF';
Subject: Hello World

This is a message to let you know
that I'm alive and well
EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test setting lines.
sub test_setting_lines
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();

    my $txt = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: Hello World
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);
	Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1])
	by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by
	mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

This is a message to let you know
that I'm alive and well
EOF
    my @lines = split(/\n/, $txt);
    map { $_ .= "\r\n" } @lines;

    my $exp = $txt;
    $exp =~ s/\n/\r\n/g;

    $m->set_lines(@lines);
    $self->assert_str_equals(
        'Fred J. Bloggs <fbloggs@fastmail.fm>',
         $m->get_headers('from')->[0]);
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    $self->assert_str_equals(
        'Hello World',
        $m->get_headers('Subject')->[0]);
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);\r\n\tFri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1])\r\n\tby mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by\r\n\tmail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers('received'));
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);

    $m = Cassandane::Message->new(lines => \@lines);
    $self->assert_str_equals(
        'Fred J. Bloggs <fbloggs@fastmail.fm>',
         $m->get_headers('from')->[0]);
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    $self->assert_str_equals(
        'Hello World',
        $m->get_headers('Subject')->[0]);
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);\r\n\tFri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1])\r\n\tby mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by\r\n\tmail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers('received'));
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test setting raw text
sub test_setting_raw
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();

    my $txt = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: Hello World
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);
	Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1])
	by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by
	mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

This is a message to let you know
that I'm alive and well
EOF
    $txt =~ s/\n/\r\n/g;

    my $exp = $txt;

    $m->set_raw($txt);
    $self->assert_str_equals(
        'Fred J. Bloggs <fbloggs@fastmail.fm>',
         $m->get_headers('from')->[0]);
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    $self->assert_str_equals(
        'Hello World',
        $m->get_headers('Subject')->[0]);
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);\r\n\tFri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1])\r\n\tby mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by\r\n\tmail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers('received'));
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);

    $m = Cassandane::Message->new(raw => $txt);
    $self->assert_str_equals(
        'Fred J. Bloggs <fbloggs@fastmail.fm>',
         $m->get_headers('from')->[0]);
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    $self->assert_str_equals(
        'Hello World',
        $m->get_headers('Subject')->[0]);
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);\r\n\tFri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1])\r\n\tby mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by\r\n\tmail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers('received'));
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test message attributes
sub test_attributes
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();

    $self->assert(!$m->has_attribute('uid'));
    $self->assert_null($m->get_attribute('uid'));
    $self->assert_null($m->get_attribute('UID'));
    $self->assert_null($m->get_attribute('uId'));
    $self->assert(!$m->has_attribute('internaldate'));
    $self->assert_null($m->get_attribute('internaldate'));

    $m->set_attribute('uid', 123);
    $self->assert($m->has_attribute('uid'));
    $self->assert($m->get_attribute('uid') == 123);
    $self->assert($m->get_attribute('UID') == 123);
    $self->assert($m->get_attribute('uId') == 123);
    $self->assert(!$m->has_attribute('internaldate'));
    $self->assert_null($m->get_attribute('internaldate'));

    $m->set_attribute('uid');
    $self->assert($m->has_attribute('uid'));
    $self->assert_null($m->get_attribute('uid'));
    $self->assert_null($m->get_attribute('UID'));
    $self->assert_null($m->get_attribute('uId'));
    $self->assert(!$m->has_attribute('internaldate'));
    $self->assert_null($m->get_attribute('internaldate'));

    $m->set_internaldate('15-Oct-2010 03:19:52 +1100');
    $self->assert($m->has_attribute('internaldate'));
    $self->assert_str_equals('15-Oct-2010 03:19:52 +1100',
                             $m->get_attribute('internaldate'));
    $m->set_internaldate(undef);
    $self->assert($m->has_attribute('internaldate'));
    $self->assert_null($m->get_attribute('internaldate'));
    my $dt = DateTime->new(
                          year => 2010,
                          month => 10,
                          day => 15,
                          hour => 3,
                          minute => 19,
                          second => 47,
                          time_zone => 'Australia/Melbourne');
    $m->set_internaldate($dt);
    $self->assert($m->has_attribute('internaldate'));
    $self->assert_str_equals(to_rfc3501($dt),
                             $m->get_attribute('internaldate'));

    $m = Cassandane::Message->new(attrs => { UID => 456 });
    $self->assert($m->has_attribute('uid'));
    $self->assert($m->get_attribute('uid') == 456);
    $self->assert($m->get_attribute('UID') == 456);
    $self->assert($m->get_attribute('uId') == 456);
    $self->assert(!$m->has_attribute('internaldate'));
    $self->assert_null($m->get_attribute('internaldate'));
}

# Test parsing lines with unusually but validly named headers
sub test_strange_headers
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();

    my $txt = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
X-Foo_Bar.Baz&Quux: Foonly
Subject: Hello World
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);
	Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1])
	by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by
	mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100

This is a message to let you know
that I'm alive and well
EOF
    my @lines = split(/\n/, $txt);
    map { $_ .= "\r\n" } @lines;

    my $exp = $txt;
    $exp =~ s/\n/\r\n/g;

    $m->set_lines(@lines);
    $self->assert_str_equals(
        'Fred J. Bloggs <fbloggs@fastmail.fm>',
         $m->get_headers('from')->[0]);
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    $self->assert_str_equals(
        'Foonly',
        $m->get_headers('X-Foo_Bar.Baz&Quux')->[0]);
    $self->assert_str_equals(
        'Hello World',
        $m->get_headers('Subject')->[0]);
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);\r\n\tFri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1])\r\n\tby mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by\r\n\tmail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers('received'));
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);

    $m = Cassandane::Message->new(lines => \@lines);
    $self->assert_str_equals(
        'Fred J. Bloggs <fbloggs@fastmail.fm>',
         $m->get_headers('from')->[0]);
    $self->assert_str_equals(
        'Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>',
        $m->get_headers('to')->[0]);
    $self->assert_str_equals(
        'Foonly',
        $m->get_headers('X-Foo_Bar.Baz&Quux')->[0]);
    $self->assert_str_equals(
        'Hello World',
        $m->get_headers('Subject')->[0]);
    $self->assert_deep_equals([
        "from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);\r\n\tFri, 29 Oct 2010 13:05:01 +1100",
        "from mail.bar.com (mail.bar.com [10.0.0.1])\r\n\tby mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100",
        "from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by\r\n\tmail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100",
    ], $m->get_headers('received'));
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test parsing lines with unusually but validly named headers
sub test_clone
{
    my ($self) = @_;

    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $m->set_body("This is a message to let you know\r\nthat I'm alive and well\r\n");
    $m->set_attribute('uid', 42);

    my $exp = <<'EOF';
Subject: Hello World

This is a message to let you know
that I'm alive and well
EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_num_equals(42, $m->get_attribute('uid'));
    $self->assert_str_equals('Hello World', $m->get_header('subject'));

    my $m2 = $m->clone();
    $self->assert_str_equals($exp, $m2->as_string);
    $self->assert_num_equals(42, $m2->get_attribute('uid'));
    $self->assert_str_equals('Hello World', $m2->get_header('subject'));

    my $addr = Cassandane::Address->new(
            name => 'Fred J. Bloggs',
            localpart => 'fbloggs',
            domain => 'fastmail.fm');
    $m->add_header('From', $addr);
    $self->assert_str_equals($addr->as_string, $m->get_header('from'));
    $self->assert_null($m2->get_header('from'));
    my $exp2 = <<'EOF';
Subject: Hello World
From: Fred J. Bloggs <fbloggs@fastmail.fm>

This is a message to let you know
that I'm alive and well
EOF
    $exp2 =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp2, $m->as_string);
    $self->assert_str_equals($exp, $m2->as_string);
}

# Test base_subject()
sub test_base_subject
{
    my ($self) = @_;

    my @testcases = (
        'Hello World' => 'Hello World',
        '  Hello World' => 'Hello World',
        'Hello World   ' => 'Hello World',
        '    Hello World   ' => 'Hello World',
        '    Hello   World   ' => 'Hello World',
        " \t\t  Hello \t\t World \t\t " => 'Hello World',
        're: Hello World' => 'Hello World',
        'Re: Hello World' => 'Hello World',
        'RE: Hello World' => 'Hello World',
        're : Hello World' => 'Hello World',
        'Re : Hello World' => 'Hello World',
        'RE : Hello World' => 'Hello World',
        "re \t : Hello World" => 'Hello World',
        "Re \t : Hello World" => 'Hello World',
        "RE \t : Hello World" => 'Hello World',
        'fw: Hello World' => 'Hello World',
        'Fw: Hello World' => 'Hello World',
        'FW: Hello World' => 'Hello World',
        'fw : Hello World' => 'Hello World',
        'Fw : Hello World' => 'Hello World',
        'FW : Hello World' => 'Hello World',
        "fw \t : Hello World" => 'Hello World',
        "Fw \t : Hello World" => 'Hello World',
        "FW \t : Hello World" => 'Hello World',
        'fwd: Hello World' => 'Hello World',
        'Fwd: Hello World' => 'Hello World',
        'FWD: Hello World' => 'Hello World',
        'fwd : Hello World' => 'Hello World',
        'Fwd : Hello World' => 'Hello World',
        'FWD : Hello World' => 'Hello World',
        "fwd \t : Hello World" => 'Hello World',
        "Fwd \t : Hello World" => 'Hello World',
        "FWD \t : Hello World" => 'Hello World',
        "Hello World (fwd)" => 'Hello World',
        "Hello World (fwd) \t " => 'Hello World',
        "Hello World \t  \t (fwd)" => 'Hello World',
        "Hello World (FWD) \t" => 'Hello World',
        "Hello World \t\t  (FWD)" => 'Hello World',
        "Hello World (FWD)   " => 'Hello World',
        " \t\t     Hello World" => "Hello World",
        "[PATCH]Hello World" => "Hello World",
        "[PATCH] Hello World" => "Hello World",
        "\t [PATCH] \t Hello World" => "Hello World",
        "[RFC][PATCH][WTF]Hello World" => "Hello World",
        "  [RFC] [PATCH]   [WTF]    Hello World" => "Hello World",
    );

    while (@testcases)
    {
        my $in = shift @testcases;
        my $exp = shift @testcases;
        my $out = base_subject($in);
        xlog "base_subject(\"$in\") = \"$out\"";
        $self->assert_str_equals($exp, $out);
    }

}

sub test_attributes2
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();

    $self->assert(!$m->has_attribute('foo'));
    $self->assert(!$m->has_attribute('bar'));
    $self->assert(!$m->has_attribute('baz'));

    # set_attribute() sets an attribute to the given value
    $m->set_attribute(foo => 'cosby');
    $self->assert($m->has_attribute('foo'));
    $self->assert($m->has_attribute('Foo'));
    $self->assert($m->has_attribute('FOO'));
    # attribute names are case-insensitive
    $self->assert_str_equals('cosby', $m->get_attribute('foo'));
    $self->assert_str_equals('cosby', $m->get_attribute('Foo'));
    $self->assert_str_equals('cosby', $m->get_attribute('FOO'));
    # other attributes unchanged
    $self->assert(!$m->has_attribute('bar'));
    $self->assert(!$m->has_attribute('baz'));

    # set_attributes() sets a list of attributes from the
    # given list of attribute,value pairs
    $m->set_attributes(bar => 'sweater', foo => 'etsy');
    $self->assert($m->has_attribute('foo'));
    $self->assert_str_equals('etsy', $m->get_attribute('foo'));
    $self->assert($m->has_attribute('bar'));
    $self->assert_str_equals('sweater', $m->get_attribute('bar'));
    $self->assert(!$m->has_attribute('baz'));

    # set_attribute to an undef value doesn't remove the attribute
    # but remembers the undef - this is necessary for strict checking
    # of IMAP server responses in a number of cases.
    $m->set_attribute(foo => undef);
    $self->assert($m->has_attribute('foo'));
    $self->assert_null($m->get_attribute('foo'));
    $self->assert($m->has_attribute('bar'));
    $self->assert_str_equals('sweater', $m->get_attribute('bar'));
    $self->assert(!$m->has_attribute('baz'));
}

sub test_attributes_from_fetch
{
    my ($self) = @_;
    my $m = Cassandane::Message->new(attrs => {
                                foo => 'ethical',
                                bar => 'pitchfork',
                                });

    $self->assert($m->has_attribute('foo'));
    $self->assert_str_equals('ethical', $m->get_attribute('foo'));
    $self->assert($m->has_attribute('bar'));
    $self->assert_str_equals('pitchfork', $m->get_attribute('bar'));
    $self->assert(!$m->has_attribute('baz'));
}

sub test_annotations
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();

    my $e1 = '/comment';
    my $a1 = 'value.shared';
    my $e2 = '/vendor/hipsteripsum.me/buzzword';
    my $a2 = 'value.priv';

    # no annotations on empty message
    $self->assert(!$m->has_annotation($e1, $a1));
    $self->assert(!$m->has_annotation($e2, $a2));
    # alternate syntax for has_annotation
    $self->assert(!$m->has_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert(!$m->has_annotation({ entry => $e2, attrib => $a2 }));
    # get_annotation returns no annotations
    $self->assert_null($m->get_annotation($e1, $a1));
    $self->assert_null($m->get_annotation($e2, $a2));
    # alternate syntax for get_annotation
    $self->assert_null($m->get_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert_null($m->get_annotation({ entry => $e2, attrib => $a2 }));
    # list_annotations returns no annotations
    my @aa = $m->list_annotations();
    $self->assert_deep_equals([], \@aa);

    # set_annotation() sets an annotation to the given value
    $m->set_annotation($e1, $a1, 'wayfarers');
    $self->assert($m->has_annotation($e1, $a1));
    $self->assert(!$m->has_annotation($e2, $a2));
    $self->assert($m->has_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert(!$m->has_annotation({ entry => $e2, attrib => $a2 }));
    $self->assert_str_equals('wayfarers', $m->get_annotation($e1, $a1));
    $self->assert_null($m->get_annotation($e2, $a2));
    $self->assert_str_equals('wayfarers', $m->get_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert_null($m->get_annotation({ entry => $e2, attrib => $a2 }));
    @aa = $m->list_annotations();
    $self->assert_deep_equals([{entry => $e1, attrib => $a1}], \@aa);

    # set_annotation to an undef value doesn't remove the annotation
    # but remembers the undef - this is necessary for strict checking
    # of IMAP server responses in a number of cases.
    $m->set_annotation($e1, $a1, undef);
    $self->assert($m->has_annotation($e1, $a1));
    $self->assert(!$m->has_annotation($e2, $a2));
    $self->assert($m->has_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert(!$m->has_annotation({ entry => $e2, attrib => $a2 }));
    $self->assert_null($m->get_annotation($e1, $a1));
    $self->assert_null($m->get_annotation($e2, $a2));
    $self->assert_null($m->get_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert_null($m->get_annotation({ entry => $e2, attrib => $a2 }));
    @aa = $m->list_annotations();
    $self->assert_deep_equals([{entry => $e1, attrib => $a1}], \@aa);

    # Can set two annotations
    $m->set_annotation($e1, $a1, 'brooklyn');
    $m->set_annotation($e2, $a2, 'sustainable');
    $self->assert($m->has_annotation($e1, $a1));
    $self->assert($m->has_annotation($e2, $a2));
    $self->assert($m->has_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert($m->has_annotation({ entry => $e2, attrib => $a2 }));
    $self->assert_str_equals('brooklyn', $m->get_annotation($e1, $a1));
    $self->assert_str_equals('sustainable', $m->get_annotation($e2, $a2));
    $self->assert_str_equals('brooklyn', $m->get_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert_str_equals('sustainable', $m->get_annotation({ entry => $e2, attrib => $a2 }));
    @aa = $m->list_annotations();
    @aa = sort { $a->{entry} cmp $b->{entry} } @aa;
    $self->assert_deep_equals([
            {entry => $e1, attrib => $a1},
            {entry => $e2, attrib => $a2},
        ], \@aa);
}

sub test_annotations_from_fetch
{
    my ($self) = @_;

    my $e1 = '/comment';
    my $a1 = 'value.shared';
    my $e2 = '/vendor/hipsteripsum.me/buzzword';
    my $a2 = 'value.priv';

    my $m = Cassandane::Message->new(attrs => {
                        annotation => {
                            $e1 => { $a1 => 'whatever' },
                            $e2 => { $a2 => 'sartorial' }
                        }});

    $self->assert($m->has_annotation($e1, $a1));
    $self->assert($m->has_annotation($e2, $a2));
    $self->assert($m->has_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert($m->has_annotation({ entry => $e2, attrib => $a2 }));
    $self->assert_str_equals('whatever', $m->get_annotation($e1, $a1));
    $self->assert_str_equals('sartorial', $m->get_annotation($e2, $a2));
    $self->assert_str_equals('whatever', $m->get_annotation({ entry => $e1, attrib => $a1 }));
    $self->assert_str_equals('sartorial', $m->get_annotation({ entry => $e2, attrib => $a2 }));
    my @aa = $m->list_annotations();
    @aa = sort { $a->{entry} cmp $b->{entry} } @aa;
    $self->assert_deep_equals([
            {entry => $e1, attrib => $a1},
            {entry => $e2, attrib => $a2},
        ], \@aa);

}

sub test_accessors
{
    my ($self) = @_;

    my $txt = <<'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>
Subject: Hello World
Date: Tue, 06 Dec 2011 13:57:57 +1100
Received: from mail.quux.com (mail.quux.com [10.0.0.1]) by mail.gmail.com (Software);
	Fri, 29 Oct 2010 13:05:01 +1100
Received: from mail.bar.com (mail.bar.com [10.0.0.1])
	by mail.quux.com (Software); Fri, 29 Oct 2010 13:03:03 +1100
Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1]) by
	mail.bar.com (Software); Fri, 29 Oct 2010 13:01:01 +1100
Message-ID: <fake.1323140278.56086@fastmail.fm>

This is a message to let you know
that I'm alive and well
EOF
    my @lines = split(/\n/, $txt);
    map { $_ .= "\r\n" } @lines;

    my $m = Cassandane::Message->new(
                lines => \@lines,
                attrs => {
                    uid => 42
                });

    $self->assert_str_equals('Fred J. Bloggs <fbloggs@fastmail.fm>', $m->from());
    $self->assert_str_equals('Sarah Jane Smith <sjsmith@tard.is>, Genghis Khan <gkhan@horde.mo>', $m->to());
    $self->assert_str_equals('Hello World', $m->subject());
    $self->assert_str_equals('Tue, 06 Dec 2011 13:57:57 +1100', $m->date());
    $self->assert_str_equals('<fake.1323140278.56086@fastmail.fm>', $m->messageid());
    $self->assert_num_equals(42, $m->uid());
    $self->assert_num_equals(651, $m->size());
    $self->assert_str_equals('e2f2c19a8097587d54745801621d4bde4fa664b3', $m->guid());
    $self->assert_null($m->cid());

    # make_cid() returns a new CID but doesn't set the attribute
    $self->assert_str_equals('7301187b8bfe536f', $m->make_cid());
    $self->assert_null($m->cid());
    $m->set_attribute(cid => $m->make_cid());
    $self->assert_str_equals('7301187b8bfe536f', $m->cid());
}

sub test_header_normalisation
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');

    # data thanks to hipsteripsum.me
    $m->add_header('x-cliche', "sartorial");
    $m->add_header('x-cliche', "mixtape\nfreegan");
    $m->add_header('x-cliche', "leggings\r\nreadymade quinoa");
    $m->add_header('x-cliche', "chambray\rdenim");

    $m->set_headers('x-vegan',
        "helvetica\rwayfarers keytar\nshoreditch\r\n \t portland");

    $m->set_body("This is a message to let you know\r\nthat I'm alive and well\r\n");
    my $exp = <<'EOF';
Subject: Hello World
X-Cliche: sartorial
X-Cliche: mixtape
	freegan
X-Cliche: leggings
	readymade quinoa
X-Cliche: chambray
	denim
X-Vegan: helvetica
	wayfarers keytar
	shoreditch
 	 portland

This is a message to let you know
that I'm alive and well
EOF

    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}

# Test a header field which is present but with an empty value
sub test_add_empty
{
    my ($self) = @_;
    my $m = Cassandane::Message->new();
    $m->add_header('subject', 'Hello World');
    $m->add_header('X-Justin-Beiber', "");
    $m->add_header('From', Cassandane::Address->new(
            name => 'Fred J. Bloggs',
            localpart => 'fbloggs',
            domain => 'fastmail.fm'));
    $m->set_body("This is a message to let you know\r\nthat I'm alive and well\r\n");
    my $exp = <<'EOF';
Subject: Hello World
X-Justin-Beiber: 
From: Fred J. Bloggs <fbloggs@fastmail.fm>

This is a message to let you know
that I'm alive and well
EOF
    $exp =~ s/\n/\r\n/g;
    $self->assert_str_equals($exp, $m->as_string);
    $self->assert_str_equals($exp, "" . $m);
}


1;
