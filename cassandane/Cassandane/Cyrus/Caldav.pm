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
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.12;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'caldav');
    $config->set(httpallowcompress => 'no');
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
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    $ENV{JMAP_ALWAYS_FULL} = 1;
    $self->{caldav} = Net::CalDAVTalk->new(
	user => 'cassandane',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    eval {
	# this fails on older Cyruses -- but don't crash during set_up!
	$self->{caldav}->UpdateAddressSet("Test User", "cassandane\@example.com");
    };
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

sub test_caldavcreate
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);
}

sub test_rename
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    xlog "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check name matches";
    $self->assert_str_equals('foo', $Calendar->{name});

    xlog "change name";
    my $NewId = $CalDAV->UpdateCalendar({ id => $CalendarId, name => 'bar'});
    $self->assert_str_equals($CalendarId, $NewId);

    xlog "fetch again";
    my $NewCalendar = $CalDAV->GetCalendar($NewId);
    $self->assert_not_null($NewCalendar);

    xlog "check new name stuck";
    $self->assert_str_equals('bar', $NewCalendar->{name});
}

sub test_url_nodomains
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    xlog "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check that the href has no domain";
    $self->assert_str_equals("/dav/calendars/user/cassandane/$CalendarId/", $Calendar->{href});
}

sub test_url_virtdom_nodomain
    :VirtDomains
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    xlog "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check that the href has no domain";
    $self->assert_str_equals("/dav/calendars/user/cassandane/$CalendarId/", $Calendar->{href});
}

sub test_url_virtdom_extradomain
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");
    my $caltalk = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "create calendar";
    my $CalendarId = $caltalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $caltalk->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check that the href has domain";
    $self->assert_str_equals("/dav/calendars/user/cassandane\@example.com/$CalendarId/", $Calendar->{href});
}

sub test_url_virtdom_domain
    :VirtDomains
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.test\@example.com");
    $admintalk->setacl("user.test\@example.com", "test\@example.com" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $caltalk = Net::CalDAVTalk->new(
	user => "test\@example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "create calendar";
    my $CalendarId = $caltalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $caltalk->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check that the href has domain";
    $self->assert_str_equals("/dav/calendars/user/test\@example.com/$CalendarId/", $Calendar->{href});
}

sub test_user_rename
    :AllowMoves
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    xlog "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check name matches";
    $self->assert_str_equals('foo', $Calendar->{name});

    xlog "rename user";
    $admintalk->rename("user.cassandane", "user.newuser");

    my $service = $self->{instance}->get_service("http");
    my $newtalk = Net::CalDAVTalk->new(
	user => 'newuser',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "fetch as new user $CalendarId";
    my $NewCalendar = $newtalk->GetCalendar($CalendarId);
    $self->assert_not_null($NewCalendar);

    xlog "check new name stuck";
    $self->assert_str_equals($NewCalendar->{name}, 'foo');
}

sub test_user_rename_dom
    :AllowMoves :VirtDomains
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.test\@example.com");
    $admintalk->setacl("user.test\@example.com", "test\@example.com" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $oldtalk = Net::CalDAVTalk->new(
	user => "test\@example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "create calendar";
    my $CalendarId = $oldtalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog "fetch again";
    my $Calendar = $oldtalk->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog "check name matches";
    $self->assert_str_equals($Calendar->{name}, 'foo');

    xlog "rename user";
    $admintalk->rename("user.test\@example.com", "user.test2\@example2.com");

    my $newtalk = Net::CalDAVTalk->new(
	user => "test2\@example2.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "fetch as new user $CalendarId";
    my $NewCalendar = $newtalk->GetCalendar($CalendarId);
    $self->assert_not_null($NewCalendar);

    xlog "check new name stuck";
    $self->assert_str_equals($NewCalendar->{name}, 'foo');
}

sub test_put_nouid
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $href = "$CalendarId/nouid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
DTEND:20160831T183000Z
TRANSP:OPAQUE
SUMMARY:NoUID
DTSTART:20160831T153000Z
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  eval { $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar') };
  my $Err = $@;
  $self->assert_matches(qr/valid-calendar-object-resource/, $Err);
}

sub test_apple_location_notz
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND:20160831T183000Z
TRANSP:OPAQUE
SUMMARY:Map
DTSTART:20160831T153000Z
DTSTAMP:20150806T234327Z
LOCATION:Melbourne Central Shopping Centre\\nSwanston Street & Latrobe St
 reet\\nBulleen VIC 3105
X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=Swanston Street & Latrob
 e Street\\\\nBulleen VIC 3105;X-APPLE-RADIUS=157.1122975611501;X-TITLE=Mel
 bourne Central Shopping Centre:geo:-37.810551,144.962840
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $response = $CalDAV->Request('GET', $href);

  my $newcard = $response->{content};

  $self->assert_matches(qr/geo:-37.810551,144.962840/, $newcard);
}

sub test_apple_location_tz
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
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
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:Map
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
LOCATION:Melbourne Central Shopping Centre\\nSwanston Street & Latrobe St
 reet\\nBulleen VIC 3105
X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=Swanston Street & Latrob
 e Street\\\\nBulleen VIC 3105;X-APPLE-RADIUS=157.1122975611501;X-TITLE=Mel
 bourne Central Shopping Centre:geo:-37.810551,144.962840
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $response = $CalDAV->Request('GET', $href);

  my $newcard = $response->{content};

  $self->assert_matches(qr/geo:-37.810551,144.962840/, $newcard);
}

sub test_empty_summary
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => ''});
    $self->assert_not_null($CalendarId);

    my $uuid = "2b82ea51-50b0-4c6b-a9b4-e8ff0f931ba2";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');
}

sub test_invite
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );
}

sub test_invite_add_another
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  $card =~ s/ORGANIZER/ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend2\@example.com\nORGANIZER/;
  $card =~ s/SEQUENCE:0/SEQUENCE:1/;
  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "friend2\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );
}

sub test_invite_from_nonsched
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $data = $self->{instance}->getnotify();

  my $extra = <<EOF;
SEQUENCE:1
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $card =~ s/SEQUENCE:0/$extra/;
  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );
}

sub test_invite_withheader
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.net
END:VEVENT
END:VCALENDAR
EOF

  my $data = $self->{instance}->getnotify();

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar', 'Schedule-Address' => 'cassandane@example.net');

  my $newdata = $self->{instance}->getnotify();
  my ($imip) = grep { $_->{METHOD} eq 'imip' } @$newdata;
  my $payload = decode_json($imip->{MESSAGE});

  $self->assert_str_equals($payload->{recipient}, "friend\@example.com");
}

sub test_invite_fullvirtual
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.domuser@example.com');

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "domuser\@example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:domuser\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:domuser\@example.com
END:VEVENT
END:VCALENDAR
EOF

  my $data = $self->{instance}->getnotify();

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $newdata = $self->{instance}->getnotify();
  my ($imip) = grep { $_->{METHOD} eq 'imip' } @$newdata;
  $self->assert_not_null($imip);
  my $payload = decode_json($imip->{MESSAGE});

  $self->assert_str_equals($payload->{recipient}, "friend\@example.com");
}

sub test_changes_add
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $Cal = $CalDAV->GetCalendar($CalendarId);

    my $uuid = "d4643cf9-4552-4a3e-8d6c-5f318bcc5b79";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:Test Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my ($adds, $removes, $errors) = $CalDAV->SyncEvents($CalendarId, syncToken => $Cal->{syncToken});

  $self->assert_equals(scalar @$adds, 1);
  $self->assert_str_equals($adds->[0]{uid}, $uuid);
  $self->assert_deep_equals($removes, []);
  $self->assert_deep_equals($errors, []);
}

sub test_changes_remove
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid = "d4643cf9-4552-4a3e-8d6c-5f318bcc5b79";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:Test Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $Cal = $CalDAV->GetCalendar($CalendarId);

  $CalDAV->DeleteEvent($href);

  my ($adds, $removes, $errors) = $CalDAV->SyncEvents($CalendarId, syncToken => $Cal->{syncToken});

  $self->assert_deep_equals([], $adds);
  $self->assert_equals(1, scalar @$removes);
  $self->assert_str_equals("/dav/calendars/user/cassandane/" . $href, $removes->[0]);
  $self->assert_deep_equals([], $errors);
}

sub test_propfind_principal
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.reallyprivateuser");
    $admintalk->setacl("user.reallyprivateuser", "reallyprivateuser" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $caltalk = Net::CalDAVTalk->new(
	user => "reallyprivateuser",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "create calendar";
    my $CalendarId = $caltalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $CalDAV = $self->{caldav};

    xlog "principal property search";

    my $xml = <<EOF;
<B:principal-property-search xmlns:B="DAV:">
  <B:property-search>
    <B:prop>
      <E:calendar-user-type xmlns:E="urn:ietf:params:xml:ns:caldav"/>
    </B:prop>
    <B:match>INDIVIDUAL</B:match>
  </B:property-search>
  <B:prop>
    <E:calendar-user-address-set xmlns:E="urn:ietf:params:xml:ns:caldav"/>
    <B:principal-URL/>
  </B:prop>
</B:principal-property-search>
EOF

    my $res = $CalDAV->Request('REPORT', '/dav/principals', $xml, Depth => 0, 'Content-Type' => 'text/xml');
    my $text = Dumper($res);
    # in an ideal world we would have assert_not_matches
    $self->assert($text !~ m/reallyprivateuser/);
}

sub test_freebusy
    :min_version_3_0
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    $CalDAV->NewEvent($CalendarId, {
        start => '2015-01-01T12:00:00',
        duration => 'PT1H',
        summary => 'waterfall',
    });

    $CalDAV->NewEvent($CalendarId, {
        start => '2015-02-01T12:00:00',
        duration => 'PT1H',
        summary => 'waterfall2',
    });

    my ($data, $errors) = $CalDAV->GetFreeBusy($CalendarId);

    $self->assert_equals('2015-01-01T12:00:00', $data->[0]{start});
    $self->assert_equals('2015-02-01T12:00:00', $data->[1]{start});
    $self->assert_num_equals(2, scalar @$data);
}

sub test_imap_plusdav_novirt
    :MagicPlus :min_version_3_0
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'magicplus'});
    $self->assert_not_null($CalendarId);

    my $plusstore = $self->{instance}->get_service('imap')->create_store(username => 'cassandane+dav');
    my $talk = $plusstore->get_client();

    my $list = $talk->list('', '*');
    my ($this) = grep { $_->[2] eq "INBOX.#calendars.$CalendarId" } @$list;
    $self->assert_not_null($this);
}

sub test_imap_plusdav
    :MagicPlus :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'magicplus'});
    $self->assert_not_null($CalendarId);

    my $plusstore = $self->{instance}->get_service('imap')->create_store(username => 'cassandane+dav');
    my $talk = $plusstore->get_client();

    my $list = $talk->list('', '*');
    my ($this) = grep { $_->[2] eq "INBOX.#calendars.$CalendarId" } @$list;
    $self->assert_not_null($this);
}

sub test_imap_magicplus_withdomain
    :MagicPlus :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.domuser@example.com');

    my $service = $self->{instance}->get_service("http");
    my $domdav = Net::CalDAVTalk->new(
	user => 'domuser@example.com',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $domdav->NewCalendar({name => 'magicplus'});
    $self->assert_not_null($CalendarId);

    my $plusstore = $self->{instance}->get_service('imap')->create_store(username => 'domuser+dav@example.com');
    my $talk = $plusstore->get_client();

    my $list = $talk->list('', '*');
    my ($this) = grep { $_->[2] eq "INBOX.#calendars.$CalendarId" } @$list;
    $self->assert_not_null($this);
}

sub test_bad_event_hex01
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid = "9f4f1212-222f-4182-850a-8f894818593c";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
PRODID:-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:America/Los_Angeles
BEGIN:DAYLIGHT
TZOFFSETFROM:-0800
TZOFFSETTO:-0700
TZNAME:PDT
DTSTART:19700308T020000
RRULE:FREQ=YEARLY;BYDAY=2SU;BYMONTH=3
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:-0700
TZOFFSETTO:-0800
TZNAME:PST
DTSTART:19701101T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=11
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
CREATED:20160106T200252Z
LAST-MODIFIED:20160106T200327Z
DTSTAMP:20160106T200327Z
UID:$uuid
SUMMARY:Social Media Event
DTSTART;TZID=America/Los_Angeles:20160119T110000
DTEND;TZID=America/Los_Angeles:20160119T120000
DESCRIPTION:Hi\,
 a weird character 
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $Cal = $CalDAV->GetCalendar($CalendarId);

  my $Events = $CalDAV->GetEvents($Cal->{id});

  $self->assert_str_equals("Hi,a weird character ", $Events->[0]{description});
}

sub test_fastmailsharing
    :FastmailSharing :ReverseACLs :min_version_3_0
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.manifold");
    $admintalk->setacl("user.manifold", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", manifold => 'lrswipkxtecdn');

    my $service = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
	user => "manifold",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    xlog "create calendar";
    my $CalendarId = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId);

    xlog "share to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lrswipcdn');

    xlog "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    my $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog "get calendars as manifold";
    my $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog "Update calendar name as cassandane";
    my ($CasId) = map { $_->{id} } grep { $_->{name} eq 'Manifold Calendar' } @$CasCal;
    $CalDAV->UpdateCalendar({id => $CasId, name => "Cassandane Name"});

    xlog "changed as cassandane";
    $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Cassandane Name/personal");

    xlog "unchanged as manifold";
    $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog "delete calendar as cassandane";
    $CalDAV->DeleteCalendar($CasId);

    xlog "changed as cassandane";
    $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(1, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "personal");

    xlog "unchanged as manifold";
    $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");
}

sub test_multiinvite_add_person_changes
{
  my ($self) = @_;

  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'invite2'});
  $self->assert_not_null($CalendarId);

  my $uuid = "a684f618-da72-4254-9274-d11f4180696b";
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
SUMMARY:An Event
RRULE:FREQ=WEEKLY;COUNT=3
DTSTART;TZID=Australia/Melbourne:20160601T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "test1\@example.com", is_update => JSON::false, method => 'REQUEST' },
   { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  # add an override instance
  $card =~ s/An Event/An Event just us/;
  $card =~ s/SEQUENCE:0/SEQUENCE:1/;
  my $override = <<EOF;
BEGIN:VEVENT
CREATED:20150701T234328Z
UID:$uuid
RECURRENCE-ID:20160608T053000Z
DTEND;TZID=Australia/Melbourne:20160608T183000
TRANSP:OPAQUE
SUMMARY:An Event with a different friend
DTSTART;TZID=Australia/Melbourne:20160608T153000
DTSTAMP:20150806T234327Z
SEQUENCE:1
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
EOF

  $card =~ s/END:VCALENDAR/${override}END:VCALENDAR/;

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "test1\@example.com", is_update => JSON::true, method => 'REQUEST',
        event => {
            uid => $uuid,
            replyTo => { imip => "mailto:cassandane\@example.com" },
            recurrenceOverrides => {
                '2016-06-08T15:30:00' => {
                    title => "An Event with a different friend",
                    participants => {
                        "cassandane\@example.com" => { email => "cassandane\@example.com" },
                        "test1\@example.com" => { email => "test1\@example.com" },
                        "test3\@example.com" => { email => "test3\@example.com" },
                    },
                },
            },
            start => '2016-06-01T15:30:00',
            title => "An Event just us",
            participants => {
                "cassandane\@example.com" => { email => "cassandane\@example.com" },
                "test1\@example.com" => { email => "test1\@example.com" },
                "test2\@example.com" => { email => "test2\@example.com" },
            },
        },
   },
   { recipient => "test2\@example.com", is_update => JSON::true, method => 'REQUEST',
        event => {
            uid => $uuid,
            replyTo => { imip => "mailto:cassandane\@example.com" },
            recurrenceOverrides => {
                '2016-06-08T15:30:00' => undef,
            },
            start => '2016-06-01T15:30:00',
            title => "An Event just us",
            participants => {
                "cassandane\@example.com" => { email => "cassandane\@example.com" },
                "test1\@example.com" => { email => "test1\@example.com" },
                "test2\@example.com" => { email => "test2\@example.com" },
            },
        },
   },
   { recipient => "test3\@example.com", is_update => JSON::false, method => 'REQUEST',
        event => {
            uid => $uuid,
            replyTo => { imip => "mailto:cassandane\@example.com" },
            recurrenceOverrides => {
                '2016-06-08T15:30:00' => {
                    title => "An Event with a different friend",
                    participants => {
                        "cassandane\@example.com" => { email => "cassandane\@example.com" },
                        "test1\@example.com" => { email => "test1\@example.com" },
                        "test3\@example.com" => { email => "test3\@example.com" },
                    },
                },
            },
        },
   },
  );
}

sub test_multiinvite_add_person_only
{
  my ($self) = @_;

  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'invite3'});
  $self->assert_not_null($CalendarId);

  my $uuid = "db5c26fd-238f-41e4-a679-54cc9d9c8efc";
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
SUMMARY:An Event
RRULE:FREQ=WEEKLY;COUNT=3
DTSTART;TZID=Australia/Melbourne:20160601T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "test1\@example.com", is_update => JSON::false, method => 'REQUEST' },
   { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  # add an override instance
  my $override = <<EOF;
BEGIN:VEVENT
CREATED:20150701T234328Z
UID:$uuid
RECURRENCE-ID:20160608T053000Z
DTEND;TZID=Australia/Melbourne:20160608T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160608T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
EOF

  $card =~ s/END:VCALENDAR/${override}END:VCALENDAR/;

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  # only test3 is notified
  $self->assert_caldav_notified(
   { recipient => "test3\@example.com", is_update => JSON::false, method => 'REQUEST',
        event => {
            uid => $uuid,
            replyTo => { imip => "mailto:cassandane\@example.com" },
            recurrenceOverrides => {
                '2016-06-08T15:30:00' => {
                    title => "An Event",
                    participants => {
                        "cassandane\@example.com" => { email => "cassandane\@example.com" },
                        "test1\@example.com" => { email => "test1\@example.com" },
                        "test3\@example.com" => { email => "test3\@example.com" },
                    },
                },
            },
        },
   },
  );
}

sub test_multiinvite_remove_person_only
{
  my ($self) = @_;

  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'invite3'});
  $self->assert_not_null($CalendarId);

  my $uuid = "db5c26fd-238f-41e4-a679-54cc9d9c8efc";
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
SUMMARY:An Event
RRULE:FREQ=WEEKLY;COUNT=3
DTSTART;TZID=Australia/Melbourne:20160601T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "test1\@example.com", is_update => JSON::false, method => 'REQUEST' },
   { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
   { recipient => "test3\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  # add an override instance
  my $override = <<EOF;
BEGIN:VEVENT
CREATED:20150701T234328Z
UID:$uuid
RECURRENCE-ID:20160608T053000Z
DTEND;TZID=Australia/Melbourne:20160608T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160608T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
EOF

  $card =~ s/END:VCALENDAR/${override}END:VCALENDAR/;

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  # only test3 is notified with an RDATE
  $self->assert_caldav_notified(
   { recipient => "test3\@example.com", is_update => JSON::true, method => 'REQUEST',
        event => {
            uid => $uuid,
            replyTo => { imip => "mailto:cassandane\@example.com" },
            recurrenceOverrides => {
                '2016-06-08T15:30:00' => undef,
            },
        },
   },
  );
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

sub test_rfc6638_3_2_1_setpartstat_agentclient
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "attempt to set the partstat to something other than NEEDS-ACTION, agent was client";
  $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $self->assert_caldav_notified(
   { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );
}

sub bogus_test_rfc6638_3_2_1_setpartstat_agentserver
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "attempt to set the partstat to something other than NEEDS-ACTION";
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

sub test_rfc6638_3_2_1_1_create
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "default schedule agent -> REQUEST";
  $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $self->assert_caldav_notified(
   { recipient => "test1\@example.com", is_update => JSON::false, method => 'REQUEST' },
   { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  xlog "schedule agent SERVER -> REQUEST";
  $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=SERVER:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=SERVER:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $self->assert_caldav_notified(
   { recipient => "test1\@example.com", is_update => JSON::false, method => 'REQUEST' },
   { recipient => "test2\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  xlog "schedule agent CLIENT -> nothing";
  $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $self->assert_caldav_notified();

  xlog "schedule agent NONE -> nothing";
  $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $self->assert_caldav_notified();
}

sub test_rfc6638_3_2_1_2_modify
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  # 4 x 4 matrix:
  #   +---------------+-----------------------------------------------+
  #   |               |                   Modified                    |
  #   |               +-----------+-----------+-----------+-----------+
  #   |               | <Removed> | SERVER    | CLIENT    | NONE      |
  #   |               |           | (default) |           |           |
  #   +===+===========+===========+===========+===========+===========+
  #   |   | <Absent>  |  --       | REQUEST / | --        | --        |
  #   | O |           |           | ADD       |           |           |
  #   | r +-----------+-----------+-----------+-----------+-----------+
  #   | i | SERVER    |  CANCEL   | REQUEST   | CANCEL    | CANCEL    |
  #   | g | (default) |           |           |           |           |
  #   | i +-----------+-----------+-----------+-----------+-----------+
  #   | n | CLIENT    |  --       | REQUEST / | --        | --        |
  #   | a |           |           | ADD       |           |           |
  #   | l +-----------+-----------+-----------+-----------+-----------+
  #   |   | NONE      |  --       | REQUEST / | --        | --        |
  #   |   |           |           | ADD       |           |           |
  #   +---+-----------+-----------+-----------+-----------+-----------+

  xlog "<Absent> / <Removed>";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "<Absent> / SERVER";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified(
     { recipient => "test1\@example.com", is_update => JSON::false, method => 'REQUEST' },
    );
  }

  xlog "<Absent> / CLIENT";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "<Absent> / NONE";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "SERVER / <Removed>";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified(
     { recipient => "test1\@example.com", method => 'CANCEL' },
    );
  }

  xlog "SERVER / SERVER";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified(
     { recipient => "test1\@example.com", is_update => JSON::true },
    );
  }

  xlog "SERVER / CLIENT";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified(
     { recipient => "test1\@example.com", method => 'CANCEL' },
    );
  }

  xlog "SERVER / NONE";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified(
     { recipient => "test1\@example.com", method => 'CANCEL' },
    );
  }

  xlog "CLIENT / <Removed>";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "CLIENT / SERVER";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    # XXX - should be a new request is_update => true
    $self->assert_caldav_notified(
     #{ recipient => "test1\@example.com", is_update => JSON::true, method => 'REQUEST' },
     { recipient => "test1\@example.com", method => 'REQUEST' },
    );
  }

  xlog "CLIENT / CLIENT";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "CLIENT / NONE";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "NONE / <Removed>";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "NONE / SERVER";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    # XXX - should be a new request is_update => true
    $self->assert_caldav_notified(
     #{ recipient => "test1\@example.com", is_update => JSON::true, method => 'REQUEST' },
     { recipient => "test1\@example.com", method => 'REQUEST' },
    );
  }

  xlog "NONE / CLIENT";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "NONE / NONE";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update");
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
  }

  # XXX - check that the SCHEDULE-STATUS property is set correctly...

  xlog "Forbidden organizer change";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    eval { $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "update"); };
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    my $err = $@;
    $self->assert_matches(qr/allowed-attendee-scheduling-object-change/, $err);
  }
}

sub test_rfc6638_3_2_1_3_remove
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "default => CANCEL";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $CalDAV->Request('DELETE', "$CalendarId/$uuid.ics");
    $self->assert_caldav_notified(
      { recipient => "test1\@example.com", method => 'CANCEL' },
    );
  }

  xlog "SERVER => CANCEL";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=SERVER:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $CalDAV->Request('DELETE', "$CalendarId/$uuid.ics");
    $self->assert_caldav_notified(
      { recipient => "test1\@example.com", method => 'CANCEL' },
    );
  }

  xlog "CLIENT => nothing";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $CalDAV->Request('DELETE', "$CalendarId/$uuid.ics");
    $self->assert_caldav_notified();
  }

  xlog "NONE => nothing";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    $CalDAV->Request('DELETE', "$CalendarId/$uuid.ics");
    $self->assert_caldav_notified();
  }
}

sub test_rfc6638_3_2_2_1_attendee_allowed_changes
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "change summary";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->{instance}->getnotify();
    eval { $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, summary => "updated event"); };
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    my $err = $@;
    # XXX - changing summary isn't rejected yet, should be
    #$self->assert_matches(qr/allowed-attendee-scheduling-object-change/, $err);
  }

  xlog "change organizer";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->{instance}->getnotify();
    eval { $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF); };
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test2\@example.com
EOF
    my $err = $@;
    $self->assert_matches(qr/allowed-attendee-scheduling-object-change/, $err);
  }

}

sub test_rfc6638_3_2_2_2_attendee_create
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "agent <default>";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified(
      { recipient => "test1\@example.com", method => 'REPLY' },
    );
  }

  xlog "agent SERVER";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER;SCHEDULE-AGENT=SERVER:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified(
      { recipient => "test1\@example.com", method => 'REPLY' },
    );
  }

  xlog "agent CLIENT";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "agent NONE";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified();
  }
}

sub test_rfc6638_3_2_2_3_attendee_modify
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "attendee-modify";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=YES:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified(
      { recipient => "test1\@example.com", method => 'REPLY' },
    );
  }

  xlog "attendee-modify CLIENT";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=YES:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified();
  }

  xlog "attendee-modify NONE";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=NEEDS-ACTION;RSVP=YES:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
EOF
    $self->assert_caldav_notified();
  }
}

sub test_attendee_exdate
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "recurring event";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
RRULE:FREQ=WEEKLY
ORGANIZER:MAILTO:test1\@example.com
EOF
    $self->{instance}->getnotify();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER:MAILTO:test1\@example.com
RRULE:FREQ=WEEKLY
EXDATE;TZID=Australia/Melbourne:20160608T153000
EOF

    # should this send a PARTSTAT=DECLINED instead? 
    $self->assert_caldav_notified(
      {
        recipient => "test1\@example.com",
        method => 'REPLY',
        event => {
            uid => $uuid,
            replyTo => { imip => "mailto:test1\@example.com" },
            recurrenceOverrides => { '2016-06-08T15:30:00' => undef },
        },
      },
    );
  }
}

sub test_remove_oneattendee_recurring
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "recurring event";
  {
    my $uuid = $CalDAV->genuuid();
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->{instance}->getnotify();
    my $overrides = <<EOF;
BEGIN:VEVENT
CREATED:20150701T234327Z
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
UID:$uuid
RECURRENCE-ID:20160608T153000
DTEND;TZID=Australia/Melbourne:20160608T190000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160608T160000
DTSTAMP:20150806T234327Z
SEQUENCE:1
END:VEVENT
EOF
    $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, overrides => $overrides);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF

    $self->assert_caldav_notified(
       {
         method => 'REQUEST',
         recipient => "test1\@example.com",
         is_update => JSON::true,
         event => {
           recurrenceOverrides => {
             '2016-06-08T15:30:00' => {
               participants => {
                 "cassandane\@example.com" => { email => "cassandane\@example.com" },
                 "test1\@example.com" => { email => "test1\@example.com" },
                 "test3\@example.com" => { email => "test3\@example.com" },
               },
               start => '2016-06-08T16:00:00',
             },
           },
         },
       },
       {
         method => 'REQUEST',
         recipient => "test2\@example.com",
         is_update => JSON::true,
         event => {
           start => '2016-06-01T15:30:00',
           recurrenceOverrides => { '2016-06-08T15:30:00' => undef },
           participants => {
             "cassandane\@example.com" => { email => "cassandane\@example.com" },
             "test1\@example.com" => { email => "test1\@example.com" },
             "test2\@example.com" => { email => "test2\@example.com" },
             "test3\@example.com" => { email => "test3\@example.com" },
           },
         },
       },
       {
         method => 'REQUEST',
         recipient => "test3\@example.com",
         is_update => JSON::true,
         event => {
           recurrenceOverrides => {
             '2016-06-08T15:30:00' => {
               participants => {
                 "cassandane\@example.com" => { email => "cassandane\@example.com" },
                 "test1\@example.com" => { email => "test1\@example.com" },
                 "test3\@example.com" => { email => "test3\@example.com" },
               },
               start => '2016-06-08T16:00:00',
             },
           },
         },
       },
    );
  }
}

sub test_delete_recur_extraattendee
{
  my ($self) = @_;
  my $CalDAV = $self->{caldav};

  my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
  $self->assert_not_null($CalendarId);

  xlog "set up event";
  my $uuid = $CalDAV->genuuid();
  my $overrides = <<EOF;
BEGIN:VEVENT
CREATED:20150701T234327Z
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
UID:$uuid
RECURRENCE-ID:20160608T153000
DTEND;TZID=Australia/Melbourne:20160608T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160608T153000
DTSTAMP:20150806T234327Z
SEQUENCE:1
END:VEVENT
BEGIN:VEVENT
CREATED:20150701T234327Z
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
UID:$uuid
RECURRENCE-ID:20160615T153000
DTEND;TZID=Australia/Melbourne:20160615T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160615T153000
DTSTAMP:20150806T234327Z
SEQUENCE:1
END:VEVENT
EOF
  $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF, overrides => $overrides);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test3\@example.com
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
  $self->{instance}->getnotify();
  my $href = "$CalendarId/$uuid.ics";
  $self->{caldav}->Request('DELETE', $href);

  my $except = {
    participants => {
      "cassandane\@example.com" => { email => "cassandane\@example.com" },
      "test1\@example.com" => { email => "test1\@example.com" },
      "test2\@example.com" => { email => "test2\@example.com" },
      "test3\@example.com" => { email => "test3\@example.com" },
    },
  };

  my $regular = {
    participants => {
      "cassandane\@example.com" => { email => "cassandane\@example.com" },
      "test1\@example.com" => { email => "test1\@example.com" },
      "test3\@example.com" => { email => "test3\@example.com" },
    },
    recurrenceOverrides => {
      '2016-06-08T15:30:00' => $except,
      '2016-06-15T15:30:00' => $except,
    },
  };

  $self->assert_caldav_notified(
     {
       method => 'CANCEL',
       recipient => "test1\@example.com",
       event => $regular,
     },
     {
       method => 'CANCEL',
       recipient => "test2\@example.com",
       event => {
         recurrenceOverrides => {
           '2016-06-08T15:30:00' => $except,
           '2016-06-15T15:30:00' => $except,
         },
       },
     },
     {
       method => 'CANCEL',
       recipient => "test3\@example.com",
       event => $regular,
     },
  );
}


############ REPLIES #############

sub test_reply
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:friend\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:friend\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  # we don't say anything when we add a NEEDS-ACTION item
  $self->assert_caldav_notified();

  $card =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;
  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  # we sent a reply
  $self->assert_caldav_notified(
    {
      method => 'REPLY',
      recipient => 'friend@example.com',
      event => {
        participants => {
          'cassandane@example.com' => {
            'scheduleStatus' => 'accepted',
            'email' => 'cassandane@example.com'
          },
        },
      },
    },
  );
}

sub test_reply_withothers
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:friend\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend2\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend3\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ORGANIZER;CN=Test User:MAILTO:friend\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  # we don't say anything when we add a NEEDS-ACTION item
  $self->assert_caldav_notified();

  $card =~ s/PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane/PARTSTAT=ACCEPTED:MAILTO:cassandane/;
  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  # we sent a reply
  $self->assert_caldav_notified(
    {
      method => 'REPLY',
      recipient => 'friend@example.com',
      event => {
        participants => {
          'cassandane@example.com' => {
            'scheduleStatus' => 'accepted',
            'email' => 'cassandane@example.com'
          },
        },
      },
    },
  );
}

sub test_supports_event
    :min_version_3_0
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $Calendar = $CalDAV->GetCalendar($CalendarId);

    $self->assert($Calendar->{_can_event});
}

sub slurp {
    my $testdir = shift;
    my $name = shift;
    my $ext = shift;
    open(FH, "<$testdir/$name.$ext") || return;
    local $/ = undef;
    my $data = <FH>;
    close(FH);
    return $data;
}

sub _safeeq {
  my ($a, $b) = @_;
  my $json = JSON::XS->new->canonical;
  return $json->encode([$a]) eq $json->encode([$b]);
}



sub test_netcaldavtalktests_fromical
    :min_version_3_1
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $cassini = Cassandane::Cassini->instance();
    my $basedir = $cassini->val('caldavtalk', 'basedir');

    unless ($basedir) {
        xlog "Not running test, no caldavtalk";
        return;
    }

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $Calendar = $CalDAV->GetCalendar($CalendarId);

    my $testdir = "$basedir/testdata";
    opendir(DH, $testdir);
    my @list;
    while (my $item = readdir(DH)) {
        next unless $item =~ m/(.*).ics/;
        push @list, $1;
    }
    closedir(DH);

    foreach my $name (sort @list) {
        my $ical = slurp($testdir, $name, 'ics');
        my $api = slurp($testdir, $name, 'je');
        my $data = decode_json($api);
        my $uid = $data->[0]{uid};

        xlog "put $name as text/calendar and fetch back as JSON";
        $CalDAV->Request("PUT", "$CalendarId/$uid.ics", $ical, 'Content-Type' => 'text/calendar');
        my $serverapi = $CalDAV->Request("GET", "$CalendarId/$uid.ics", '', 'Accept' => 'application/event+json');
        my $serverdata = decode_json($serverapi->{content});
        $self->assert_deep_equals($CalDAV->NormaliseEvent($data->[0]), $CalDAV->NormaliseEvent($serverdata));
    }
}

sub test_netcaldavtalktests_fromje
    :min_version_3_1
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $cassini = Cassandane::Cassini->instance();
    my $basedir = $cassini->val('caldavtalk', 'basedir');

    unless ($basedir) {
        xlog "Not running test, no caldavtalk";
        return;
    }

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $Calendar = $CalDAV->GetCalendar($CalendarId);

    my $testdir = "$basedir/testdata";
    opendir(DH, $testdir);
    my @list;
    while (my $item = readdir(DH)) {
        next unless $item =~ m/(.*).ics/;
        push @list, $1;
    }
    closedir(DH);

    foreach my $name (sort @list) {
        my $api = slurp($testdir, $name, 'je');
        my $data = decode_json($api);
        my $uid = $data->[0]{uid};

        xlog "put $name as application/event+json and fetch back as JSON";
        $CalDAV->Request("PUT", "$CalendarId/$uid.ics", $api, 'Content-Type' => 'application/event+json');
        my $serverapi = $CalDAV->Request("GET", "$CalendarId/$uid.ics", '', 'Accept' => 'application/event+json');
        my $serverdata = decode_json($serverapi->{content});
        $self->assert_deep_equals($CalDAV->NormaliseEvent($data->[0]), $CalDAV->NormaliseEvent($serverdata));
    }
}

sub test_invite_change_organizer
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
  );

  # change organizer and move the event 1 hour later
  $card = <<EOF;
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T193000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T163000
DTSTAMP:20150806T234327Z
SEQUENCE:1
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:otherme\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:otherme\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card,
                   'Content-Type' => 'text/calendar',
                   'Schedule-Address' => 'otherme@example.com',
                   'Allow-Organizer-Change' => 'yes',
  );

  $self->assert_caldav_notified(
   {
     recipient => "friend\@example.com",
     is_update => JSON::true,
     method => 'REQUEST',
     event => {
       replyTo => {
         imip => 'mailto:otherme@example.com',
       },
     },
   },
  );
}

sub test_reply_scheduleaddress
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:friend\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:othercas\@example.com
ORGANIZER;CN=Test User:MAILTO:friend\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar', 'Schedule-Address' => 'othercas@example.com');

  # we don't say anything when we add a NEEDS-ACTION item
  $self->assert_caldav_notified();

  $card =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;
  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar', 'Schedule-Address' => 'othercas@example.com');

  # we sent a reply from the correct address
  $self->assert_caldav_notified(
    {
      method => 'REPLY',
      recipient => 'friend@example.com',
      event => {
        participants => {
          'othercas@example.com' => {
            'scheduleStatus' => 'accepted',
            'email' => 'othercas@example.com',
          },
        },
      },
    },
  );
}

sub test_recurring_freebusy
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4319-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event Every Week
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
RRULE:FREQ=WEEKLY
EXDATE;TZID=Australia/Melbourne:20160907T153000
END:VEVENT
BEGIN:VEVENT
RECURRENCE-ID;TZID=Australia/Melbourne:20160914T153000
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160914T183000
TRANSP:OPAQUE
SUMMARY:An Event Every Week once
DTSTART;TZID=Australia/Melbourne:20160914T163000
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my ($Data) = $CalDAV->GetFreeBusy($CalendarId);

  $self->assert(@$Data > 50);
  $self->assert_str_equals("Etc/UTC", $Data->[0]{timeZone});
  $self->assert_str_equals("Etc/UTC", $Data->[1]{timeZone});
  $self->assert_str_equals("Etc/UTC", $Data->[2]{timeZone});
  # etc
  $self->assert_str_equals("2016-08-31T05:30:00", $Data->[0]{start});
  $self->assert_str_equals("2016-09-14T06:30:00", $Data->[1]{start});
  $self->assert_str_equals("2016-09-21T05:30:00", $Data->[2]{start});
  # and so on
  $self->assert_str_equals("PT3H", $Data->[0]{duration});
  $self->assert_str_equals("PT2H", $Data->[1]{duration});
  $self->assert_str_equals("PT3H", $Data->[2]{duration});
}

sub test_invite_samelocalpart
    :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $CalDAV = Net::CalDAVTalk->new(
	user => "cassandane%example.com",
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    my $CalendarId = $CalDAV->NewCalendar({name => 'hello'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
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
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@othersite.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  $self->assert_caldav_notified(
   { recipient => "cassandane\@othersite.com", is_update => JSON::false, method => 'REQUEST' },
  );
}

1;
