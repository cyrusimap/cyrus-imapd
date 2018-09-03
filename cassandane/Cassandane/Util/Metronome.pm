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

package Cassandane::Util::Metronome;
use strict;
use warnings;
use Time::HiRes qw(clock_gettime clock_nanosleep CLOCK_MONOTONIC);

use lib '.';
use Cassandane::Util::Log;

sub new
{
    my ($class, %params) = @_;

    my $self = {
        # These are floating point numbers in seconds
        # with presumed nanosecond resolution
        interval => 0.0,
        error => 0.0,
        last_tick => undef,
        first_tick => undef,
        nticks => 0,
    };

    $self->{interval} = $params{interval}
        if defined $params{interval};
    $self->{interval} = 1.0/$params{rate}
        if defined $params{rate};

    return bless $self, $class;
}

sub tick
{
    my ($self) = @_;

    my $now = clock_gettime(CLOCK_MONOTONIC);
    $self->{first_tick} ||= $now;
    $self->{nticks}++;
    my $next_tick = ($self->{last_tick} || $now)
                    + $self->{interval};
    my $delay = ($next_tick + $self->{error} - $now);
    clock_nanosleep(CLOCK_MONOTONIC, 1e9 * $delay)
        if ($delay > 0.0);
    $now = clock_gettime(CLOCK_MONOTONIC);
    $self->{error} = $next_tick - $now;
    $self->{last_tick} = $next_tick;
}

sub actual_rate
{
    my ($self) = @_;

    return undef if !$self->{nticks};
    return $self->{nticks} /
            (clock_gettime(CLOCK_MONOTONIC) - $self->{first_tick});
}

1;
