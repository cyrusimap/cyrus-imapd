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

package Cassandane::Util::DateTime;
use strict;
use warnings;
use DateTime;
use POSIX qw(strftime);

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &from_iso8601 &to_iso8601
    &from_rfc822 &to_rfc822
    &from_rfc3501 &to_rfc3501
    );

#
# Construct and return a DateTime object using a string in the
# "combined basic" format defined in ISO8601, specifically
#
# <year><month><day>T<hour24><minute><second>[Z].
#
# Each field is fixed width zero-padded decimal numeric,
# 4 digits for year and 2 digits for all the others.
# The optional Z suffix indicates Zulu (UTC aka GMT)
# time, otherwise localtime is assumed.
#
sub from_iso8601($)
{
    my ($s) = @_;
    my ($year, $mon, $day, $hour, $min, $sec, $zulu) =
        ($s =~ m/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$/);
    return unless defined $sec;
    return if ($year < 1970 || $year > 2037);
    return if ($mon < 1 || $mon > 12);
    return if ($day < 1 || $day > 31);
    return if ($hour < 0 || $hour > 23);
    return if ($min < 0 || $min > 59);
    return if ($sec < 0 || $sec > 60);  # allow for leap second

#     printf STDERR "%s -> year=%u mon=%u day=%u hour=%u min=%u sec=%u\n",
#       $s, $year, $mon, $day, $hour, $min, $sec;

    my $tz = ($zulu ? 'GMT' : 'local');
    return DateTime->new(
                year => $year,
                month => $mon,
                day => $day,
                hour => $hour,
                minute => $min,
                second => $sec,
                time_zone => $tz
            );
}

#
# Given a DateTime, generate and return a string in ISO8601
# combined basic format.
#
sub to_iso8601($)
{
    my ($dt) = @_;
    return strftime("%Y%m%dT%H%M%SZ", gmtime($dt->epoch));
}

# Brief sanity test for parse_iso8601_datetime
# gnb@enki 566> date +%s -u -d '14 Oct 2010 16:19:52'
# 1287073192
# die "Woops, from_iso8601 is broken"
#     unless (from_iso8601('20101014T161952Z') == 1287073192);

our %rfc822_months = (
    Jan => 1,
    Feb => 2,
    Mar => 3,
    Apr => 4,
    May => 5,
    Jun => 6,
    Jul => 7,
    Aug => 8,
    Sep => 9,
    Oct => 10,
    Nov => 11,
    Dec => 12
    );
our @rfc822_months = (
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec'
    );

our @rfc822_days = (
    'Sun',
    'Mon',
    'Tue',
    'Wed',
    'Thu',
    'Fri',
    'Sat',
    'Sun'
    );

#
# Construct and return a DateTime object using a string in the
# format defined in RFC822 and its successors, which define
# the internet email message format.
# Example: Tue, 05 Oct 2010 11:19:52 +1100
#
sub from_rfc822($)
{
    my ($s) = @_;
    my ($wdayn, $day, $mon, $year, $hour, $min, $sec, $tzsign, $tzhour, $tzmin) =
        ($s =~ m/^([A-Z][a-z][a-z]), (\d+) ([A-Z][a-z][a-z]) (\d{4}) (\d{2}):(\d{2}):(\d{2}) ([-+])(\d{2})(\d{2})$/);
    return unless defined $tzmin;
    return if ($year < 1970 || $year > 2037);
    $mon = $rfc822_months{$mon};
    return unless defined $mon;
    return if ($day < 1 || $day > 31);
    return if ($hour < 0 || $hour > 23);
    return if ($min < 0 || $min > 59);
    return if ($sec < 0 || $sec > 60);  # allow for leap second
    return if ($tzhour < 0 || $tzhour > 23);
    return if ($tzmin < 0 || $tzmin > 59);

#     printf STDERR "%s -> year=%u mon=%u day=%u hour=%u min=%u sec=%u tzsign=%s tzhour=%u tzmin=%u\n",
#       $s, $year, $mon, $day, $hour, $min, $sec, $tzsign, $tzhour, $tzmin;

    return DateTime->new(
                year => $year,
                month => $mon,
                day => $day,
                hour => $hour,
                minute => $min,
                second => $sec,
                time_zone => "$tzsign$tzhour$tzmin"
            );
}

#
# Given a DateTime, generate and return a string in RFC822 format.
#
sub to_rfc822($)
{
    my ($dt) = @_;

    # We can't mix DateTime methods and strftime, because other parts of
    # Cassandane foolishly construct DateTime using the 'from_epoch' but
    # not the 'time_zone' parameters, resulting in a DT object in the
    # UTC timezone instead of local.  But conversely strftime() doesn't
    # have a portable way to emit the fixed (non-local-specific) strings
    # that the RFC expects.
    my @lt = localtime($dt->epoch);
    return strftime($rfc822_days[$lt[6]] .
                    ", %d " .
                    $rfc822_months[$lt[4]] .
                    " %Y %T %z", @lt);
}


# die "Woops, from_rfc822 is broken"
#     unless (from_rfc822('Fri, 15 Oct 2010 03:19:52 +1100') == 1287073192);

#
# Construct and return a DateTime object using a string in the
# format defined in RFC3501 which defines the IMAP protocol.
# Example: " 5-Oct-2010 09:19:52 +1100" (note leading space)
#
sub from_rfc3501($)
{
    my ($s) = @_;
    my ($day, $mon, $year, $hour, $min, $sec, $tzsign, $tzhour, $tzmin) =
        ($s =~ m/^\s*(\d+)-([A-Z][a-z][a-z])-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([-+])(\d{2})(\d{2})$/);
    return unless defined $tzmin;
    return if ($year < 1970 || $year > 2037);
    $mon = $rfc822_months{$mon};
    return unless defined $mon;
    return if ($day < 1 || $day > 31);
    return if ($hour < 0 || $hour > 23);
    return if ($min < 0 || $min > 59);
    return if ($sec < 0 || $sec > 60);  # allow for leap second
    return if ($tzhour < 0 || $tzhour > 23);
    return if ($tzmin < 0 || $tzmin > 59);

#     printf STDERR "%s -> year=%u mon=%u day=%u hour=%u min=%u sec=%u tzsign=%s tzhour=%u tzmin=%u\n",
#       $s, $year, $mon, $day, $hour, $min, $sec, $tzsign, $tzhour, $tzmin;

    return DateTime->new(
                year => $year,
                month => $mon,
                day => $day,
                hour => $hour,
                minute => $min,
                second => $sec,
                time_zone => "$tzsign$tzhour$tzmin"
            );
}

# die "Woops, from_rfc3501 is broken"
#     unless (from_rfc3501('15-Oct-2010 03:19:52 +1100') == 1287073192);

#
# Given a DateTime, generate and return a string in RFC3501 format.
#
sub to_rfc3501($)
{
    my ($dt) = @_;
    return strftime("%e-" . $rfc822_months[$dt->month -1] . "-%Y %T %z", localtime($dt->epoch));
}

1;
