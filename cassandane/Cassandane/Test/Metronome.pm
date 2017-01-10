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

package Cassandane::Test::Metronome;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Metronome;
use Cassandane::Util::Sample;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_basic
{
    my ($self) = @_;

    my $rate = 100.0;
    my $epsilon = 0.05;
    my $m = Cassandane::Util::Metronome->new(rate => $rate);

    my $ss = new Cassandane::Util::Sample;

    for (1..$rate)
    {
	$m->tick();
	my $r = $m->actual_rate();
	xlog "Actual rate $r";
	# Be forgiving of early samples to let the
	# metronome stabilise.
	$ss->add($r) if ($_ >= 20)
    }

    xlog "Rates: $ss";
    my $avg = $ss->average();
    my $std = $ss->sample_deviation();
    $self->assert($avg >= (1.0-$epsilon)*$rate && $avg <= (1.0+$epsilon)*$rate,
		  "Average $avg is outside expected range");
    $self->assert($std/$rate < $epsilon,
		  "Standard deviation $std is too high");
}

1;
