# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

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
