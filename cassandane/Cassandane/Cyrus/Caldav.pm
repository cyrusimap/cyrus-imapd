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

my $MELBOURNE = <<EOF;
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

my $NEW_YORK = <<EOF;
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
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);
}

sub test_rename
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    xlog $self, "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check name matches";
    $self->assert_str_equals('foo', $Calendar->{name});

    xlog $self, "change name";
    my $NewId = $CalDAV->UpdateCalendar({ id => $CalendarId, name => 'bar'});
    $self->assert_str_equals($CalendarId, $NewId);

    xlog $self, "fetch again";
    my $NewCalendar = $CalDAV->GetCalendar($NewId);
    $self->assert_not_null($NewCalendar);

    xlog $self, "check new name stuck";
    $self->assert_str_equals('bar', $NewCalendar->{name});
}

sub test_url_nodomains
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check that the href has no domain";
    $self->assert_str_equals("/dav/calendars/user/cassandane/$CalendarId/", $Calendar->{href});
}

sub test_url_virtdom_nodomain
    :VirtDomains :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check that the href has no domain";
    $self->assert_str_equals("/dav/calendars/user/cassandane/$CalendarId/", $Calendar->{href});
}

sub test_url_virtdom_extradomain
    :VirtDomains :min_version_3_0 :needs_component_httpd
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

    xlog $self, "create calendar";
    my $CalendarId = $caltalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $caltalk->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check that the href has domain";
    $self->assert_str_equals("/dav/calendars/user/cassandane\@example.com/$CalendarId/", $Calendar->{href});
}

sub test_url_virtdom_domain
    :VirtDomains :needs_component_httpd
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

    xlog $self, "create calendar";
    my $CalendarId = $caltalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $caltalk->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check that the href has domain";
    $self->assert_str_equals("/dav/calendars/user/test\@example.com/$CalendarId/", $Calendar->{href});
}

sub test_user_rename
    :AllowMoves :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create calendar";
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $CalDAV->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check name matches";
    $self->assert_str_equals('foo', $Calendar->{name});

    xlog $self, "rename user";
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

    xlog $self, "fetch as new user $CalendarId";
    my $NewCalendar = $newtalk->GetCalendar($CalendarId);
    $self->assert_not_null($NewCalendar);

    xlog $self, "check new name stuck";
    $self->assert_str_equals($NewCalendar->{name}, 'foo');
}

sub test_user_rename_dom
    :AllowMoves :VirtDomains :needs_component_httpd
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

    xlog $self, "create calendar";
    my $CalendarId = $oldtalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    xlog $self, "fetch again";
    my $Calendar = $oldtalk->GetCalendar($CalendarId);
    $self->assert_not_null($Calendar);

    xlog $self, "check name matches";
    $self->assert_str_equals($Calendar->{name}, 'foo');

    xlog $self, "rename user";
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

    xlog $self, "fetch as new user $CalendarId";
    my $NewCalendar = $newtalk->GetCalendar($CalendarId);
    $self->assert_not_null($NewCalendar);

    xlog $self, "check new name stuck";
    $self->assert_str_equals($NewCalendar->{name}, 'foo');
}

sub test_put_nouid
    :needs_component_httpd
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

sub test_put_changes_etag
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $href = "$CalendarId/uid1.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
DTEND:20160831T183000Z
TRANSP:OPAQUE
UID:uid1
SUMMARY:HasUID1
DTSTART:20160831T153000Z
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

    # annoyingly there's no "Request" that tells you the headers, so:
  my %Headers = (
    'Content-Type' => 'text/calendar',
    'Authorization' => $CalDAV->auth_header(),
  );

  my $Response = $CalDAV->{ua}->request('PUT', $CalDAV->request_url($href), {
    content => $card,
    headers => \%Headers,
  });

  $self->assert_num_equals(201, $Response->{status});
  my $etag = $Response->{headers}{etag};
  $self->assert_not_null($etag);

  $Response = $CalDAV->{ua}->request('HEAD', $CalDAV->request_url($href), {
    headers => \%Headers,
  });

  # the etag shouldn't have changed
  $self->assert_num_equals(200, $Response->{status});
  my $etag2 = $Response->{headers}{etag};
  $self->assert_not_null($etag2);
  $self->assert_str_equals($etag2, $etag);

  $card =~ s/HasUID1/HasUID2/s;

  $Response = $CalDAV->{ua}->request('PUT', $CalDAV->request_url($href), {
    content => $card,
    headers => \%Headers,
  });

  # no content, we're replacing a thing
  $self->assert_num_equals(204, $Response->{status});
  my $etag3 = $Response->{headers}{etag};
  $self->assert_not_null($etag2);

  # the content has changed, so the etag MUST change
  $self->assert_str_not_equals($etag, $etag3);

  $Response = $CalDAV->{ua}->request('HEAD', $CalDAV->request_url($href), {
    headers => \%Headers,
  });

  # the etag shouldn't have changed again
  $self->assert_num_equals(200, $Response->{status});
  my $etag4 = $Response->{headers}{etag};
  $self->assert_not_null($etag4);
  $self->assert_str_equals($etag4, $etag3);
}

sub test_apple_location_notz
    :needs_component_httpd
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
    :needs_component_httpd
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
    :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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

sub test_shared_invite_as_secretary
    :VirtDomains :min_version_3_1 :needs_component_httpd :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.test");
    $admintalk->setacl("user.test", "test" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $testtalk = Net::CalDAVTalk->new(
        user => "test",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-user-address-set>
        <D:href>mailto:test\@example.com</D:href>
      </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    $testtalk->Request('PROPPATCH', "/dav/principals/user/test", $xml,
                       'Content-Type' => 'text/xml');

    xlog $self, "create calendar";
    my $CalendarId = $testtalk->NewCalendar({name => 'Team Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "set calendar-user-address-set for all sharees";
    $testtalk->Request('PROPPATCH', "/dav/calendars/user/test/$CalendarId", $xml,
                       'Content-Type' => 'text/xml');

    xlog $self, "share to user";
    $admintalk->setacl("user.test.#calendars.$CalendarId",
                       "cassandane" => 'lrswipcdn');

    my $CalDAV = Net::CalDAVTalk->new(
        user => "cassandane",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog $self, "subscribe to shared calendar";
    my $imapstore = $self->{instance}->get_service('imap')->create_store(
                        username => "cassandane");
    my $imaptalk = $imapstore->get_client();
    $imaptalk->subscribe("user.test.#calendars.$CalendarId");

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    my $sharedCalendarId = $CasCal->[1]{href};

    $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-user-address-set>
        <D:href>mailto:test\@example.com</D:href>
      </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$sharedCalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
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
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test\@example.com
ORGANIZER;CN=Test User:MAILTO:friend\@example.com
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $self->assert_caldav_notified(
        { recipient => "friend\@example.com", is_update => JSON::false, method => 'REPLY' },
    );
}

sub test_shared_reply_as_secretary
    :VirtDomains :min_version_3_1 :needs_component_httpd :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.test");
    $admintalk->setacl("user.test", "test" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $testtalk = Net::CalDAVTalk->new(
        user => "test",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-user-address-set>
        <D:href>mailto:test\@example.com</D:href>
      </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    $testtalk->Request('PROPPATCH', "/dav/principals/user/test", $xml,
                       'Content-Type' => 'text/xml');

    xlog $self, "create calendar";
    my $CalendarId = $testtalk->NewCalendar({name => 'Team Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "set calendar-user-address-set for all sharees";
    $testtalk->Request('PROPPATCH', "/dav/calendars/user/test/$CalendarId", $xml,
                       'Content-Type' => 'text/xml');

    xlog $self, "share to user";
    $admintalk->setacl("user.test.#calendars.$CalendarId",
                       "cassandane" => 'lrswipcdn');

    my $CalDAV = Net::CalDAVTalk->new(
        user => "cassandane",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog $self, "subscribe to shared calendar";
    my $imapstore = $self->{instance}->get_service('imap')->create_store(
                        username => "cassandane");
    my $imaptalk = $imapstore->get_client();
    $imaptalk->subscribe("user.test.#calendars.$CalendarId");

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    my $sharedCalendarId = $CasCal->[1]{href};

    $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-user-address-set>
        <D:href>mailto:test\@example.com</D:href>
      </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$sharedCalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:test\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER:MAILTO:test\@example.com
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $self->assert_caldav_notified(
        { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
    );
}

sub test_shared_team_invite_sharee
    :VirtDomains :min_version_3_1 :needs_component_httpd :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.test");
    $admintalk->setacl("user.test", "test" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $testtalk = Net::CalDAVTalk->new(
        user => "test",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-user-address-set>
        <D:href>mailto:test\@example.com</D:href>
      </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    $testtalk->Request('PROPPATCH', "/dav/principals/user/test", $xml,
                       'Content-Type' => 'text/xml');

    xlog $self, "create calendar";
    my $CalendarId = $testtalk->NewCalendar({name => 'Team Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user";
    $admintalk->setacl("user.test.#calendars.$CalendarId",
                       "cassandane" => 'lrswipcdn');

    my $CalDAV = Net::CalDAVTalk->new(
        user => "cassandane",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog $self, "subscribe to shared calendar";
    my $imapstore = $self->{instance}->get_service('imap')->create_store(
                        username => "cassandane");
    my $imaptalk = $imapstore->get_client();
    $imaptalk->subscribe("user.test.#calendars.$CalendarId");

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    my $sharedCalendarId = $CasCal->[1]{href};

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "/dav/calendars/user/test/$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event from cassandane
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:test\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:test\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "add event as sharer, inviting sharee";
    $testtalk->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $self->assert_caldav_notified(
        { recipient => "cassandane\@example.com", is_update => JSON::false, method => 'REQUEST' },
        { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
    );

    xlog $self, "update PARTSTAT as sharee";
    $href = "$sharedCalendarId/$uuid.ics";
    $card =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $self->assert_caldav_notified(
        { recipient => "test\@example.com", is_update => JSON::false, method => 'REPLY' },
    );
}

sub test_shared_team_invite_sharer
    :VirtDomains :min_version_3_1 :needs_component_httpd :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.test");
    $admintalk->setacl("user.test", "test" => "lrswipkxtecda");

    my $service = $self->{instance}->get_service("http");
    my $testtalk = Net::CalDAVTalk->new(
        user => "test",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-user-address-set>
        <D:href>mailto:test\@example.com</D:href>
      </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    $testtalk->Request('PROPPATCH', "/dav/principals/user/test", $xml,
                       'Content-Type' => 'text/xml');

    xlog $self, "create calendar";
    my $CalendarId = $testtalk->NewCalendar({name => 'Team Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user";
    $admintalk->setacl("user.test.#calendars.$CalendarId",
                       "cassandane" => 'lrswipcdn');

    my $CalDAV = Net::CalDAVTalk->new(
        user => "cassandane",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog $self, "subscribe to shared calendar";
    my $imapstore = $self->{instance}->get_service('imap')->create_store(
                        username => "cassandane");
    my $imaptalk = $imapstore->get_client();
    $imaptalk->subscribe("user.test.#calendars.$CalendarId");

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    my $sharedCalendarId = $CasCal->[1]{href};

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$sharedCalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:$uuid
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:An Event from cassandane
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:test\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "add event as sharee, inviting sharer";
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $self->assert_caldav_notified(
        { recipient => "test\@example.com", is_update => JSON::false, method => 'REQUEST' },
        { recipient => "friend\@example.com", is_update => JSON::false, method => 'REQUEST' },
    );

    xlog $self, "update PARTSTAT as sharer";
    $href = "/dav/calendars/user/test/$CalendarId/$uuid.ics";
    $card =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;

    $testtalk->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $self->assert_caldav_notified(
        { recipient => "cassandane\@example.com", is_update => JSON::false, method => 'REPLY' },
    );
}

sub test_invite_add_another
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :needs_component_httpd
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
    :needs_component_httpd
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
    :needs_component_httpd
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

    xlog $self, "create calendar";
    my $CalendarId = $caltalk->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $CalDAV = $self->{caldav};

    xlog $self, "principal property search";

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
    $self->assert_does_not_match(qr/reallyprivateuser/, $text);
}

sub test_freebusy
    :min_version_3_0 :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    $CalDAV->NewEvent($CalendarId, {
        timeZone => 'Etc/UTC',
        start => '2015-01-01T12:00:00',
        duration => 'PT1H',
        summary => 'waterfall',
    });

    $CalDAV->NewEvent($CalendarId, {
        timeZone => 'America/New_York',
        start => '2015-02-01T12:00:00',
        duration => 'PT1H',
        summary => 'waterfall2',
    });

    my ($data, $errors) = $CalDAV->GetFreeBusy($CalendarId);

    $self->assert_str_equals('2015-01-01T12:00:00', $data->[0]{start});
    $self->assert_str_equals('2015-02-01T17:00:00', $data->[1]{start});
    $self->assert_num_equals(2, scalar @$data);
}

sub test_freebusy_floating
    :min_version_3_1 :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo', timeZone => $MELBOURNE});
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

    $self->assert_str_equals('2015-01-01T01:00:00', $data->[0]{start});
    $self->assert_str_equals('2015-02-01T01:00:00', $data->[1]{start});
    $self->assert_num_equals(2, scalar @$data);

    # Change floating time zone on the calendar
    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <C:calendar-timezone>$NEW_YORK</C:calendar-timezone>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    my $res = $CalDAV->Request('PROPPATCH',
                               "/dav/calendars/user/cassandane/". $CalendarId,
                               $xml, 'Content-Type' => 'text/xml');

    ($data, $errors) = $CalDAV->GetFreeBusy($CalendarId);

    $self->assert_str_equals('2015-01-01T17:00:00', $data->[0]{start});
    $self->assert_str_equals('2015-02-01T17:00:00', $data->[1]{start});
    $self->assert_num_equals(2, scalar @$data);
}

sub test_imap_plusdav_novirt
    :MagicPlus :min_version_3_0 :needs_component_httpd :NoAltNameSpace
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
    :MagicPlus :VirtDomains :min_version_3_0 :needs_component_httpd :NoAltNameSpace
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
    :MagicPlus :VirtDomains :min_version_3_0 :needs_component_httpd :NoAltNameSpace
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
    :needs_component_httpd
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
    :FastmailSharing :ReverseACLs :min_version_3_0 :needs_component_httpd
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

    xlog $self, "create calendar";
    my $CalendarId = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lrswipcdn');

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    my $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "get calendars as manifold";
    my $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "Update calendar name as cassandane";
    my ($CasId) = map { $_->{id} } grep { $_->{name} eq 'Manifold Calendar' } @$CasCal;
    $CalDAV->UpdateCalendar({id => $CasId, name => "Cassandane Name"});

    xlog $self, "changed as cassandane";
    $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Cassandane Name/personal");

    xlog $self, "unchanged as manifold";
    $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "delete calendar as cassandane";
    $CalDAV->DeleteCalendar($CasId);

    xlog $self, "changed as cassandane";
    $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(1, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "personal");

    xlog $self, "unchanged as manifold";
    $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");
}

sub test_davsharing
    :min_version_3_0 :needs_component_httpd :NoVirtDomains
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

    my $invite = <<EOF;
<?xml version="1.0" encoding="utf-8" ?>
<D:share-resource xmlns:D="DAV:">
  <D:sharee>
    <D:href>mailto:cassandane\@example.com</D:href>
    <D:prop>
      <D:displayname>Cassandane</D:displayname>
    </D:prop>
    <D:comment>Shared calendar</D:comment>
    <D:share-access>
      <D:read-write />
    </D:share-access>
  </D:sharee>
</D:share-resource>
EOF

    my $reply = <<EOF;
<?xml version="1.0" encoding="utf-8" ?>
<D:invite-reply xmlns:D="DAV:">
  <D:invite-accepted />
  <D:create-in>
    <D:href>/dav/calendars/user/cassandane/</D:href>
  </D:create-in>
  <D:comment>Thanks for the share!</D:comment>
</D:invite-reply>
EOF

    xlog $self, "create calendar";
    my $CalendarId = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user";
    $mantalk->Request('POST', $CalendarId, $invite,
                      'Content-Type' => 'application/davsharing+xml');

    xlog $self, "fetch invite";
    my ($adds) = $CalDAV->SyncEventLinks("/dav/notifications/user/cassandane");
    $self->assert_equals(scalar %$adds, 1);
    my $notification = (keys %$adds)[0];

    xlog $self, "accept invite";
    $CalDAV->Request('POST', $notification, $reply,
                     'Content-Type' => 'application/davsharing+xml');

    xlog $self, "get calendars as manifold";
    my $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    my $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "Update calendar name as cassandane";
    my ($CasId) = map { $_->{id} } grep { $_->{name} eq 'Manifold Calendar' } @$CasCal;
    $CalDAV->UpdateCalendar({id => $CasId, name => "Cassandane Name"});

    xlog $self, "changed as cassandane";
    $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Cassandane Name/personal");

    xlog $self, "unchanged as manifold";
    $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "delete calendar as cassandane";
    $CalDAV->DeleteCalendar($CasId);

    xlog $self, "changed as cassandane";
    $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(1, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "personal");

    xlog $self, "unchanged as manifold";
    $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");
}

sub test_alarm_peruser
    :MagicPlus :min_version_3_0 :needs_component_httpd :NoAltNameSpace :NoVirtDomains
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

    my $invite = <<EOF;
<?xml version="1.0" encoding="utf-8" ?>
<D:share-resource xmlns:D="DAV:">
  <D:sharee>
    <D:href>mailto:cassandane\@example.com</D:href>
    <D:prop>
      <D:displayname>Cassandane</D:displayname>
    </D:prop>
    <D:comment>Shared calendar</D:comment>
    <D:share-access>
      <D:read-write />
    </D:share-access>
  </D:sharee>
</D:share-resource>
EOF

    my $reply = <<EOF;
<?xml version="1.0" encoding="utf-8" ?>
<D:invite-reply xmlns:D="DAV:">
  <D:invite-accepted />
  <D:create-in>
    <D:href>/dav/calendars/user/cassandane/</D:href>
  </D:create-in>
  <D:comment>Thanks for the share!</D:comment>
</D:invite-reply>
EOF

    xlog $self, "create calendar";
    my $CalendarId = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user";
    $mantalk->Request('POST', $CalendarId, $invite,
                      'Content-Type' => 'application/davsharing+xml');

    xlog $self, "fetch invite";
    my ($adds) = $CalDAV->SyncEventLinks("/dav/notifications/user/cassandane");
    $self->assert_equals(scalar %$adds, 1);
    my $notification = (keys %$adds)[0];

    xlog $self, "accept invite";
    $CalDAV->Request('POST', $notification, $reply,
                     'Content-Type' => 'application/davsharing+xml');

    xlog $self, "get calendars as manifold";
    my $ManCal = $mantalk->GetCalendars();
    $self->assert_num_equals(2, scalar @$ManCal);
    my $names = join "/", sort map { $_->{name} } @$ManCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    xlog $self, "get calendars as cassandane";
    my $CasCal = $CalDAV->GetCalendars();
    $self->assert_num_equals(2, scalar @$CasCal);
    $names = join "/", sort map { $_->{name} } @$CasCal;
    $self->assert_str_equals($names, "Manifold Calendar/personal");

    my $uuid = 'fb7b57d1-8a49-4af8-8597-2c17bab1f987';
    my $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Europe/Vienna
X-LIC-LOCATION:Europe/Vienna
BEGIN:DAYLIGHT
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
TZNAME:CEST
DTSTART:19700329T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
TZNAME:CET
DTSTART:19701025T030000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:TRANSPARENT
XXDATESXX
UID:$uuid
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:Yep
DESCRIPTION:
LAST-MODIFIED:20150928T132434Z
BEGIN:VALARM
UID:$uuid-alarm
ACTION:DISPLAY
DESCRIPTION:Your event 'Yep' already started.
TRIGGER:PT10M
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    my $nonallday = <<EOF;
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
EOF

    my $allday = <<EOF;
DTSTART;TYPE=DATE:20160928
DURATION:P1D
EOF
    my $nonallevent = $event;
    $nonallevent =~ s/XXDATESXX/$nonallday/;
    my $allevent = $event;
    $allevent =~ s/XXDATESXX/$allday/;

    xlog $self, "Create an event as cassandane with an alarm";
    my ($cal) = grep { $_->{name} eq 'Manifold Calendar' } @$CasCal;
    $CalDAV->Request('PUT', "$cal->{id}/$uuid.ics", $nonallevent, 'Content-Type' => 'text/calendar');

    my $plusstore = $self->{instance}->get_service('imap')->create_store(username => 'cassandane+dav');
    my $plustalk = $plusstore->get_client();

    my @list = $plustalk->list("", "*");

    my @bits = split /\./, $cal->{id};
    $plustalk->select("user.manifold.#calendars.$bits[1]");
    my $res = $plustalk->fetch('1', '(rfc822.peek annotation (/* value.priv))');

    $self->assert_does_not_match(qr/VALARM/, $res->{1}{'rfc822'});
    $self->assert_matches(qr/VALARM/, $res->{1}{'annotation'}{'/vendor/cmu/cyrus-httpd/<http://cyrusimap.org/ns/>per-user-calendar-data'}{'value.priv'});

    $CalDAV->Request('PUT', "$cal->{id}/$uuid.ics", $allevent, 'Content-Type' => 'text/calendar');

    $res = $plustalk->fetch('2', '(rfc822.peek annotation (/* value.priv))');
    $self->assert_does_not_match(qr/VALARM/, $res->{2}{'rfc822'});
    $self->assert_matches(qr/VALARM/, $res->{2}{'annotation'}{'/vendor/cmu/cyrus-httpd/<http://cyrusimap.org/ns/>per-user-calendar-data'}{'value.priv'});
}

sub test_multiinvite_add_person_changes
    :needs_component_httpd
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
ORGANIZER;CN=Test User:mailto:cassandane\@example.com
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
        { recipient => "test1\@example.com",
          is_update => JSON::true,
          method => 'REQUEST',
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
        { recipient => "test2\@example.com",
          is_update => JSON::true,
          method => 'REQUEST',
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
        { recipient => "test3\@example.com",
          is_update => JSON::false,
          method => 'REQUEST',
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
    :needs_component_httpd
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
        { recipient => "test3\@example.com",
          is_update => JSON::false,
          method => 'REQUEST',
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
    :needs_component_httpd
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
        { recipient => "test3\@example.com",
          is_update => JSON::true,
          method => 'REQUEST',
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "attempt to set the partstat to something other than NEEDS-ACTION, agent was client";
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

sub test_rfc6638_3_2_1_1_create
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "default schedule agent -> REQUEST";
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

    xlog $self, "schedule agent SERVER -> REQUEST";
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

    xlog $self, "schedule agent CLIENT -> nothing";
    $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=CLIENT:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();

    xlog $self, "schedule agent NONE -> nothing";
    $self->_put_event($CalendarId, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test1\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=NONE:MAILTO:test2\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
EOF
    $self->assert_caldav_notified();
}

sub test_rfc6638_3_2_1_2_modify
    :needs_component_httpd
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

    xlog $self, "<Absent> / <Removed>";
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

    xlog $self, "<Absent> / SERVER";
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

    xlog $self, "<Absent> / CLIENT";
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

    xlog $self, "<Absent> / NONE";
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

    xlog $self, "SERVER / <Removed>";
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

    xlog $self, "SERVER / SERVER";
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

    xlog $self, "SERVER / CLIENT";
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

    xlog $self, "SERVER / NONE";
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

    xlog $self, "CLIENT / <Removed>";
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

    xlog $self, "CLIENT / SERVER";
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

    xlog $self, "CLIENT / CLIENT";
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

    xlog $self, "CLIENT / NONE";
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

    xlog $self, "NONE / <Removed>";
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

    xlog $self, "NONE / SERVER";
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

    xlog $self, "NONE / CLIENT";
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

    xlog $self, "NONE / NONE";
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

    xlog $self, "Forbidden organizer change";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "default => CANCEL";
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

    xlog $self, "SERVER => CANCEL";
    {
        my $uuid = $CalDAV->genuuid();
        $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-AGENT=SERVER:MAILTO:test1\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
STATUS:CONFIRMED
EOF
        $self->{instance}->getnotify();
        $CalDAV->Request('DELETE', "$CalendarId/$uuid.ics");
        $self->assert_caldav_notified(
            { recipient => "test1\@example.com", method => 'CANCEL' },
        );
    }

    xlog $self, "CLIENT => nothing";
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

    xlog $self, "NONE => nothing";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "change summary";
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

    xlog $self, "change organizer";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "agent <default>";
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

    xlog $self, "agent SERVER";
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

    xlog $self, "agent CLIENT";
    {
        my $uuid = $CalDAV->genuuid();
        $self->_put_event($CalendarId, uuid => $uuid, lines => <<EOF);
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:test1\@example.com
ORGANIZER;SCHEDULE-AGENT=CLIENT:MAILTO:test1\@example.com
EOF
        $self->assert_caldav_notified();
    }

    xlog $self, "agent NONE";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "attendee-modify";
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

    xlog $self, "attendee-modify CLIENT";
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

    xlog $self, "attendee-modify NONE";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "recurring event";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "recurring event";
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
    :needs_component_httpd
{
    my ($self) = @_;
    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'test'});
    $self->assert_not_null($CalendarId);

    xlog $self, "set up event";
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :min_version_3_1 :needs_component_httpd :needs_component_jmap
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
    :min_version_3_1 :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $cassini = Cassandane::Cassini->instance();
    my $basedir = $cassini->val('caldavtalk', 'basedir');

    unless ($basedir) {
        xlog $self, "Not running test, no caldavtalk";
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

        xlog $self, "put $name as text/calendar and fetch back as JSON";
        $CalDAV->Request("PUT", "$CalendarId/$uid.ics", $ical, 'Content-Type' => 'text/calendar');
        my $serverapi = $CalDAV->Request("GET", "$CalendarId/$uid.ics", '', 'Accept' => 'application/event+json');
        my $serverdata = decode_json($serverapi->{content});
        $self->assert_deep_equals($CalDAV->NormaliseEvent($data->[0]), $CalDAV->NormaliseEvent($serverdata));
    }
}

sub test_netcaldavtalktests_fromje
    :min_version_3_1 :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $cassini = Cassandane::Cassini->instance();
    my $basedir = $cassini->val('caldavtalk', 'basedir');

    unless ($basedir) {
        xlog $self, "Not running test, no caldavtalk";
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

        xlog $self, "put $name as application/event+json and fetch back as JSON";
        $CalDAV->Request("PUT", "$CalendarId/$uid.ics", $api, 'Content-Type' => 'application/event+json');
        my $serverapi = $CalDAV->Request("GET", "$CalendarId/$uid.ics", '', 'Accept' => 'application/event+json');
        my $serverdata = decode_json($serverapi->{content});
        $self->assert_deep_equals($CalDAV->NormaliseEvent($data->[0]), $CalDAV->NormaliseEvent($serverdata));
    }
}

sub test_invite_change_organizer
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
        { recipient => "cassandane\@example.com", is_update => JSON::false, method => 'CANCEL' },
    );
}

sub test_reply_scheduleaddress
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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
    :VirtDomains :min_version_3_0 :needs_component_httpd
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

sub test_put_date_with_tzid
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $href = "$CalendarId/datewith.ics";
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
UID:datewith
DTSTART;TZID=Australia/Melbourne;VALUE=DATE:20160901
DTEND;TZID=Australia/Melbourne;VALUE=DATE:20160902
RRULE:FREQ=WEEKLY;COUNT=3
EXDATE;TZID=Australia/Melbourne;VALUE=DATE:20160908
TRANSP:OPAQUE
SUMMARY:An Event
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');
}

sub test_replication_delete
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    $self->run_replication();
    $self->check_replication('cassandane');

    my $href = "$CalendarId/event1.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
DTEND:20160831T183000Z
TRANSP:OPAQUE
SUMMARY:An Event
UID:event1
DTSTART:20160831T153000Z
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');
    my $response = $CalDAV->Request('GET', $href);
    my $value = $response->{content};
    $self->assert_matches(qr/An Event/, $value);

    $self->run_replication();
    $self->check_replication('cassandane');

    $CalDAV->DeleteCalendar($CalendarId);

    $self->run_replication();
    $self->check_replication('cassandane');
}

sub test_calendar_setcolor
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($CalendarId);

    my $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/">
  <D:set>
    <D:prop>
      <A:calendar-color>#2952A3</A:calendar-color>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF

    my $propfindXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/">
  <D:prop>
    <A:calendar-color/>
  </D:prop>
</D:propfind>
EOF

    # Assert that color isn't set.
    my $response = $CalDAV->Request('PROPFIND', "/dav/calendars/user/cassandane/". $CalendarId,
                                 $propfindXml, 'Content-Type' => 'text/xml');
    my $propstat = $response->{'{DAV:}response'}[0]{'{DAV:}propstat'}[0];
    $self->assert_str_equals('HTTP/1.1 404 Not Found', $propstat->{'{DAV:}status'}{content});
    $self->assert(exists $propstat->{'{DAV:}prop'}{'{http://apple.com/ns/ical/}calendar-color'});

    # Set color.
    $response = $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane/". $CalendarId,
                                    $proppatchXml, 'Content-Type' => 'text/xml');

    # Assert color ist set.
    $response = $CalDAV->Request('PROPFIND', "/dav/calendars/user/cassandane/". $CalendarId,
                                 $propfindXml, 'Content-Type' => 'text/xml');
    $propstat = $response->{'{DAV:}response'}[0]{'{DAV:}propstat'}[0];
    $self->assert_str_equals('HTTP/1.1 200 OK', $propstat->{'{DAV:}status'}{content});
    $self->assert_str_equals('#2952A3', $propstat->{'{DAV:}prop'}{'{http://apple.com/ns/ical/}calendar-color'}{content});

}

sub test_header_cache_control
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    # Create an event
    my $href = "$CalendarId/event1.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
DTEND:20160831T183000Z
TRANSP:OPAQUE
SUMMARY:An Event
UID:event1
DTSTART:20160831T153000Z
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # Check that we can get the event via the CalDAV module
    my $response = $CalDAV->Request('GET', $href);
    $self->assert_matches(qr{An Event}, $response->{content});

    my %Headers = (
        'Authorization' => $CalDAV->auth_header(),
    );
    my $URI = $CalDAV->request_url($href);

    # Request the event without an authorization header
    $response = $CalDAV->{ua}->get($URI, { headers => {} });

    # Should be rejected
    $self->assert_num_equals(401, $response->{status});
    $self->assert_str_equals('Unauthorized', $response->{reason});

    # Request the event with an authorization header
    $response = $CalDAV->{ua}->get($URI, { headers => \%Headers });

    # Should have Cache-Control: private set
    $self->assert_matches(qr{An Event}, $response->{content});
    $self->assert_matches(qr{\bprivate\b},
                          $response->{headers}->{'cache-control'});
}

sub test_event_move
    :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid1 = "d4643cf9-4552-4a3e-8d6c-5f318bcc5b79";
    my $href = "$CalendarId/$uuid1.ics";
    my $card1 = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:$uuid1
DTEND;TZID=Australia/Melbourne:20160831T183000
TRANSP:OPAQUE
SUMMARY:Test Event 1
DTSTART;TZID=Australia/Melbourne:20160831T153000
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card1, 'Content-Type' => 'text/calendar');

    my $DestCal = $CalDAV->GetCalendar($CalendarId);

    my $uuid2 = "event2\@example.com";
    my $card2 = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20160913T100000
DURATION:PT1H
SUMMARY:Event #2
UID:$uuid2
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:friend\@example.com
ORGANIZER;CN=Test User:MAILTO:cassandane\@example.com
BEGIN:VALARM
UID:uuid-alarm
ACTION:DISPLAY
DESCRIPTION:Your event 'Yep' already started.
TRIGGER:PT10M
END:VALARM
END:VEVENT
END:VCALENDAR
EOF
    $href = "Default/$uuid2.ics";

    $CalDAV->Request('PUT', $href, $card2, 'Content-Type' => 'text/calendar');

    my $SrcCal = $CalDAV->GetCalendar('Default');

    $CalDAV->MoveEvent($href, $CalendarId);

    my ($adds, $removes, $errors) = $CalDAV->SyncEvents('Default', syncToken => $SrcCal->{syncToken});
    $self->assert_deep_equals([], $adds);
    $self->assert_equals(1, scalar @$removes);
    $self->assert_str_equals("/dav/calendars/user/cassandane/" . $href, $removes->[0]);
    $self->assert_deep_equals([], $errors);

    ($adds, $removes, $errors) = $CalDAV->SyncEvents($CalendarId, syncToken => $DestCal->{syncToken});

    $self->assert_equals(1, scalar @$adds);
    $self->assert_str_equals($adds->[0]{uid}, $uuid2);
    $self->assert_deep_equals([], $removes);
    $self->assert_deep_equals([], $errors);
}

sub test_put_toolarge
    :min_version_3_5 :needs_component_httpd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid = "d4643cf9-4552-4a3e-8d6c-5f318bcc5b79";
    my $href = "$CalendarId/$uuid.ics";
    my $desc = ('x') x 100000;
    my $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
DTEND:20160831T183000Z
TRANSP:OPAQUE
SUMMARY:Event
DESCRIPTION:$desc
UID:$uuid
DTSTART:20160831T153000Z
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF

    eval { $CalDAV->Request('PUT', $href, $event, 'Content-Type' => 'text/calendar') };
    my $Err = $@;
    $self->assert_matches(qr/max-resource-size/, $Err);
}

sub test_managed_attachment_itip
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my $rawIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
ORGANIZER:cassandane@example.com
ATTENDEE:attendee@local
UID:123456789
TRANSP:OPAQUE
SUMMARY:test
DTSTART;TZID=Australia/Melbourne:20160831T153000
DURATION:PT1H
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $rawIcal,
        'Content-Type' => 'text/calendar');
    my $eventHref = '/dav/calendars/user/cassandane/Default/test.ics';

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "Add attachment via CalDAV";
    my $url = $caldav->request_url($eventHref) . '?action=attachment-add';
    my $res = $caldav->ua->post($url, {
        headers => {
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => 'attachment;filename=test',
            'Prefer' => 'return=representation',
            'Authorization' => $caldav->auth_header(),
        },
        content => 'davattach',
    });
    $self->assert_str_equals('201', $res->{status});

    $self->assert_caldav_notified(
        { recipient => 'attendee@local', is_update => JSON::true, method => 'REQUEST' },
    );
}

sub test_sched_busytime_query
    :min_version_3_0 :needs_component_httpd :NoVirtDomains
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.friend");
    $admintalk->setacl("user.friend", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.friend", friend => 'lrswipkxtecdn');

    my $service = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "friend",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $query = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VFREEBUSY
UID:66687286-1EBF-48B4-B0D5-43144F801E2F
DTSTAMP:20210802T131858Z
DTEND:20210903T000000Z
DTSTART:20210902T210000Z
ATTENDEE:MAILTO:cassandane\@example.com
ATTENDEE:MAILTO:friend\@example.com
ORGANIZER:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "freebusy query";
    my $res = $CalDAV->Request('POST', 'Outbox',
                               $query, 'Content-Type' => 'text/calendar');
    my $text = Dumper($res);
    $self->assert_matches(qr/schedule-response/, $text);
}

1;
