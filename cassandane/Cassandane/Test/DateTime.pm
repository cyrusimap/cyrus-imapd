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

package Cassandane::Test::DateTime;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::DateTime;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_basic
{
    my ($self) = @_;
    $self->assert_num_equals(1287073192, from_iso8601('20101014T161952Z')->epoch);
    $self->assert_num_equals(1287073192, from_rfc822('Fri, 15 Oct 2010 03:19:52 +1100')->epoch);
    $self->assert_num_equals(1287073192, from_rfc3501('15-Oct-2010 03:19:52 +1100')->epoch);
    $self->assert_str_equals('20101014T161952Z', to_iso8601(DateTime->from_epoch(epoch => 1287073192)));
    local $ENV{TZ} = "Australia/Melbourne";
    $self->assert_str_equals('Fri, 15 Oct 2010 03:19:52 +1100', to_rfc822(DateTime->from_epoch(epoch => 1287073192)));
    $self->assert_str_equals('15-Oct-2010 03:19:52 +1100', to_rfc3501(DateTime->from_epoch(epoch => 1287073192)));
}

sub test_localtime_month_ahead_of_utc
{
    my ($self) = @_;

    # early morning 2023-09-01 UTC+10
    #  late evening 2023-08-31 UTC
    my $dt = DateTime->new(
        year => 2023,
        month => 9,
        day => 1,
        hour => 9,
        minute => 30,
        second => 0,
        time_zone => 'Australia/Sydney',
    );
    $dt->set_time_zone('Etc/UTC');

    local $ENV{TZ} = 'Australia/Sydney';
    $self->assert_str_equals('Fri, 01 Sep 2023 09:30:00 +1000',
                             to_rfc822($dt));
    $self->assert_str_equals(' 1-Sep-2023 09:30:00 +1000',
                             to_rfc3501($dt));
}

sub test_localtime_month_behind_utc
{
    my ($self) = @_;

    #  late evening 2023-08-31 UTC-4
    # early morning 2023-09-01 UTC
    my $dt = DateTime->new(
        year => 2023,
        month => 8,
        day => 31,
        hour => 22,
        minute => 30,
        second => 0,
        time_zone => 'America/New_York',
    );
    $dt->set_time_zone('Etc/UTC');

    local $ENV{TZ} = 'America/New_York';
    $self->assert_str_equals('Thu, 31 Aug 2023 22:30:00 -0400',
                             to_rfc822($dt));
    $self->assert_str_equals('31-Aug-2023 22:30:00 -0400',
                             to_rfc3501($dt));
}

1;
