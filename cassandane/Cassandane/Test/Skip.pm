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

package Cassandane::Test::Skip;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);

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

sub test_skip_old_version
    :min_version_3_0
{
    my ($self) = @_;

    my ($maj, $min) = Cassandane::Instance->get_version();

    $self->assert($maj >= 3);
    $self->assert($min >= 0);
}

sub test_skip_new_version
    :max_version_2_5
{
    my ($self) = @_;

    my ($maj, $min) = Cassandane::Instance->get_version();

    $self->assert($maj <= 2);
    $self->assert($min <= 5);
}

sub test_skip_outside_range
    :min_version_2_5_0 :max_version_2_5_9
{
    my ($self) = @_;

    my ($maj, $min, $rev) = Cassandane::Instance->get_version();

    $self->assert_equals($maj, 2);
    $self->assert_equals($min, 5);
    $self->assert($rev >= 0);
    $self->assert($rev <= 9);
}

# Don't actually use this device in real tests.  This is meant to exercise the
# skip mechanism, not as an example of its proper use :)
sub test_skip_everything
    :min_version_3_0 :max_version_2_5
{
    my ($self) = @_;

    my ($maj, $min, $rev) = Cassandane::Instance->get_version();

    # should never get here -- if we do, we've failed
    $self->assert(0);
}

1;
