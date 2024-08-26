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

package Cassandane::Test::Sample;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Sample;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new(@_);
}

sub check_expected
{
    my ($self, $ss, $ecount, $eavg, $emin, $emax, $estd) = @_;

    my $epsilon = 0.01;

    $self->assert_equals($ss->nsamples(), $ecount);

    my $avg = $ss->average();
    $self->assert(abs($eavg - $avg) < $epsilon,
                  "Average: expecting $eavg got $avg");

    my $min = $ss->minimum();
    $self->assert(abs($emin - $min) < $epsilon,
                  "Minimum: expecting $emin got $min");

    my $max = $ss->maximum();
    $self->assert(abs($emax - $max) < $epsilon,
                  "Maximum: expecting $emax got $max");

    my $std = $ss->sample_deviation();
    $self->assert(abs($estd - $std) < $epsilon,
                  "Sample Deviation: expecting $estd got $std");
}

sub test_uniform
{
    my ($self) = @_;

    xlog "Sample with 4 x 10.0";
    my $ss = new Cassandane::Util::Sample;
    $ss->add(10.0);
    $ss->add(10.0);
    $ss->add(10.0);
    $ss->add(10.0);
    xlog "Sample: $ss";
    $self->check_expected($ss, 4, 10.0, 10.0, 10.0, 0.0);
}

sub test_ramp
{
    my ($self) = @_;

    xlog "Sample with ramp from 1 to 5";
    my $ss = new Cassandane::Util::Sample;
    $ss->add(1.0);
    $ss->add(2.0);
    $ss->add(3.0);
    $ss->add(4.0);
    $ss->add(5.0);
    xlog "Sample: $ss";
    $self->check_expected($ss, 5, 3.0, 1.0, 5.0, 1.5811);
}

1;
