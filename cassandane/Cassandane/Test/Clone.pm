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

package Cassandane::Test::Clone;
use strict;
use warnings;
use Clone qw(clone);

use lib '.';
use base qw(Cassandane::Unit::TestCase);

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_undef
{
    my ($self) = @_;
    my $a = undef;
    my $b = clone($a);
    $self->assert_null($a);
    $self->assert_null($b);
}

sub test_string
{
    my ($self) = @_;
    my $a = "Hello World";
    my $b = clone($a);
    $self->assert_str_equals("Hello World", $a);
    $self->assert_str_equals("Hello World", $b);
    $b = "Jeepers";
    $self->assert_str_equals("Hello World", $a);
    $self->assert_str_equals("Jeepers", $b);
}

sub test_hash
{
    my ($self) = @_;
    my $a = { foo => 42 };
    my $b = clone($a);
    $self->assert_deep_equals({ foo => 42 }, $a);
    $self->assert_deep_equals({ foo => 42 }, $b);
    $b->{bar} = 123;
    $self->assert_deep_equals({ foo => 42 }, $a);
    $self->assert_deep_equals({ foo => 42, bar => 123 }, $b);
    delete $b->{foo};
    $self->assert_deep_equals({ foo => 42 }, $a);
    $self->assert_deep_equals({ bar => 123 }, $b);
}

sub test_array
{
    my ($self) = @_;
    my $a = [ 42 ];
    my $b = clone($a);
    $self->assert_deep_equals([ 42 ], $a);
    $self->assert_deep_equals([ 42 ], $b);
    push(@$b, 123);
    $self->assert_deep_equals([ 42 ], $a);
    $self->assert_deep_equals([ 42, 123 ], $b);
    shift @$b;
    $self->assert_deep_equals([ 42 ], $a);
    $self->assert_deep_equals([ 123 ], $b);
}

sub test_complex
{
    my ($self) = @_;
    my $a = { foo => [ { x => 42, y => 123 } ],
              bar => { quux => 37, foonly => 475 } };
    my $b = clone($a);
    $self->assert_deep_equals($a, $b);
}

1;
