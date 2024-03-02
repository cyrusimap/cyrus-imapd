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

package Cassandane::Cyrus::Caldav;
use v5.26.0; # strict + indented here-docs
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.12;
use Net::DAVTalk::XMLParser;
use File::Basename;
use Data::Dumper;
use Text::VCardFast;
use Cwd qw(abs_path);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use utf8;

sub MELBOURNE {
  return <<~'EOF';
    BEGIN:VCALENDAR
    BEGIN:VTIMEZONE
    TZID:Australia/Melbourne
    BEGIN:STANDARD
    TZOFFSETFROM:+1100
    RRULE:FREQ=YEARLY;BYMONTH=4;BYDAY=1SU
    DTSTART:20080406T030000
    TZNAME:AEST
    TZOFFSETTO:+1000
    END:STANDARD
    BEGIN:DAYLIGHT
    TZOFFSETFROM:+1000
    RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=1SU
    DTSTART:20081005T020000
    TZNAME:AEDT
    TZOFFSETTO:+1100
    END:DAYLIGHT
    END:VTIMEZONE
    END:VCALENDAR
    EOF
}

sub NEW_YORK {
  return <<~'EOF';
    BEGIN:VCALENDAR
    BEGIN:VTIMEZONE
    TZID:America/New_York
    BEGIN:DAYLIGHT
    TZNAME:EDT
    TZOFFSETFROM:-0500
    TZOFFSETTO:-0400
    DTSTART:20070311T020000
    RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
    END:DAYLIGHT
    BEGIN:STANDARD
    TZNAME:EST
    TZOFFSETFROM:-0400
    TZOFFSETTO:-0500
    DTSTART:20071104T020000
    RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
    END:STANDARD
    END:VTIMEZONE
    END:VCALENDAR
    EOF
}

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'caldav');
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(httpallowcompress => 'no');
    $config->set(caldav_historical_age => -1);
    $config->set(icalendar_max_size => 100000);
    $config->set(event_extra_params => 'vnd.cmu.davFilename vnd.cmu.davUid');
    $config->set(event_groups => 'calendar');
    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $ENV{DEBUGDAV} = 1;
    $ENV{JMAP_ALWAYS_FULL} = 1;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub _all_keys_match
{
    my $a = shift;
    my $b = shift;
    my $errors = shift;

    my $ref = ref($a);
    unless ($ref eq ref($b)) {
        push @$errors, "mismatched refs $ref / " . ref($b);
        return 0;
    }

    unless ($ref) {
        unless (defined $a) {
            return 1 unless defined $b;
            return 0;
        }
        return 0 unless defined $b;
        if (lc $a ne lc $b) {
            push @$errors, "not equal $a / $b";
            return 0;
        }
        return 1;
    }

    if ($ref eq 'ARRAY') {
        my @payloads = @$b;
        my @nomatch;
        foreach my $item (@$a) {
            my $match;
            my @rest;
            foreach my $payload (@payloads) {
                if (not $match and _all_keys_match($item, $payload, [])) {
                    $match = $payload;
                }
                else {
                    push @rest, $payload;
                }
            }
            push @nomatch, $item unless $match;
            @payloads = @rest;
        }
        if (@payloads or @nomatch) {
            push @$errors, "failed to match\n" . Dumper(\@nomatch, \@payloads);
            return 0;
        }
        return 1;
    }

    if ($ref eq 'HASH') {
        foreach my $key (keys %$a) {
            unless (exists $b->{$key}) {
                push @$errors, "no key $key";
                return 0;
            }
            my @err;
            unless (_all_keys_match($a->{$key}, $b->{$key}, \@err)) {
                push @$errors, "mismatch for $key: @err";
                return 0;
            }
        }
        return 1;
    }

    if ($ref eq 'JSON::PP::Boolean' or $ref eq 'JSON::XS::Boolean') {
        if ($a != $b) {
            push @$errors, "mismatched boolean " .  (!!$a) . " / " . (!!$b);
            return 0;
        }
        return 1;
    }

    die "WEIRD REF $ref for $a";
}

sub assert_caldav_notified
{
    my $self = shift;
    my @expected = @_;

    my $newdata = $self->{instance}->getnotify();
    my @imip = grep { $_->{METHOD} eq 'imip' } @$newdata;
    my @payloads = map { decode_json($_->{MESSAGE}) } @imip;
    foreach my $payload (@payloads) {
        ($payload->{event}) = $self->{caldav}->vcalendarToEvents($payload->{ical});
        $payload->{method} = delete $payload->{event}{method};
    }

    my @err;
    unless (_all_keys_match(\@expected, \@payloads, \@err)) {
        $self->fail("@err");
    }
}

sub _put_event {
    my $self = shift;
    my $CalendarId = shift;
    my %props = @_;
    my $uuid = delete $props{uuid} || $self->{caldav}->genuuid();
    my $href = "$CalendarId/$uuid.ics";

    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Melbourne
BEGIN:STANDARD
TZOFFSETFROM:+1100
RRULE:FREQ=YEARLY;BYMONTH=4;BYDAY=1SU
DTSTART:20080406T030000
TZNAME:AEST
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
TZOFFSETFROM:+1000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=1SU
DTSTART:20081005T020000
TZNAME:AEDT
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
CREATED:20150701T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160601T183000
TRANSP:OPAQUE
SUMMARY:{summary}
DTSTART;TZID=Australia/Melbourne:20160601T153000
DTSTAMP:20150806T234327Z
SEQUENCE:{sequence}
{lines}END:VEVENT
{overrides}END:VCALENDAR
EOF

    $props{lines} ||= '';
    $props{overrides} ||= '';
    $props{sequence} ||= 0;
    $props{summary} ||= "An Event";
    foreach my $key (keys %props) {
        $card =~ s/\{$key\}/$props{$key}/;
    }

    $self->{caldav}->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');
}

sub bogus_test_rfc6638_3_2_1_setpartstat_agentserver
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "attempt to set the partstat to something other than NEEDS-ACTION";
    # XXX - the server should reject this
    $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified(
        { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
    );
}

############ REPLIES #############

sub slurp {
    my $testdir = shift;
    my $name = shift;
    my $ext = shift;

    return slurp_file("$testdir/$name.$ext");
}

sub _safeeq {
    my ($a, $b) = @_;
    my $json = JSON::XS->new->canonical;
    return $json->encode([$a]) eq $json->encode([$b]);
}

use Cassandane::Tiny::Loader 'tiny-tests/Caldav';

1;
