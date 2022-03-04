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

package Cassandane::Test::Address;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Address;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_default_ctor
{
    my ($self) = @_;
    my $a = Cassandane::Address->new();
    $self->assert(!defined $a->name);
    $self->assert($a->localpart eq 'unknown-user');
    $self->assert($a->domain eq 'unspecified-domain');
    $self->assert($a->address eq 'unknown-user@unspecified-domain');
    $self->assert($a->as_string eq '<unknown-user@unspecified-domain>');
    $self->assert("" . $a eq '<unknown-user@unspecified-domain>');
}

sub test_full_ctor
{
    my ($self) = @_;
    my $a = Cassandane::Address->new(
        name => 'Fred J. Bloggs',
        localpart => 'fbloggs',
        domain => 'fastmail.fm',
        );
    $self->assert($a->name eq 'Fred J. Bloggs');
    $self->assert($a->localpart eq 'fbloggs');
    $self->assert($a->domain eq 'fastmail.fm');
    $self->assert($a->address eq 'fbloggs@fastmail.fm');
    $self->assert($a->as_string eq 'Fred J. Bloggs <fbloggs@fastmail.fm>');
    $self->assert("" . $a eq 'Fred J. Bloggs <fbloggs@fastmail.fm>');
}

1;
