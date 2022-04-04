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

package Cassandane::Cyrus::CaldavAlarm;
use strict;
use warnings;
use DateTime;
use DateTime::Format::ISO8601;
use JSON::XS;
use Net::CalDAVTalk 0.05;
use Data::Dumper;
use POSIX;
use Carp;

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
    $config->set(caldav_historical_age => -1);
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
    $self->{caldav} = Net::CalDAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
}

sub _can_match {
    my $event = shift;
    my $want = shift;

    # I wrote a really good one of these for Caldav, but this will do for now
    foreach my $key (keys %$want) {
        return 0 if not exists $event->{$key};
        return 0 if $event->{$key} ne $want->{$key};
    }

    return 1;
}

sub assert_alarms {
    my $self = shift;
    my @want = @_;
    # pick first calendar alarm from notifications
    my $data = $self->{instance}->getnotify();
    if ($self->{replica}) {
        my $more = $self->{replica}->getnotify();
        push @$data, @$more;
    }
    my @events;
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                push @events, $e;
            }
        }
    }

    my @left;
    while (my $event = shift @events) {
        my $found = 0;
        my @newwant;
        foreach my $data (@want) {
            if (not $found and _can_match($event, $data)) {
                $found = 1;
            }
            else {
                push @newwant, $data;
            }
        }
        if (not $found) {
            push @left, $event;
        }
        @want = @newwant;
    }

    if (@want or @left) {
        my $dump = Data::Dumper->Dump([\@want, \@left], [qw(want left)]);
        $self->assert_equals(0, scalar @want,
                             "expected events were not received:\n$dump");
        $self->assert_equals(0, scalar @left,
                             "unexpected extra events were received:\n$dump");
    }
}

sub tear_down
{
    my ($self) = @_;

    $self->SUPER::tear_down();
}

sub test_simple
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', start => $start, timezone => 'Australia/Sydney'});
}

sub test_recurring_absolute_trigger
    :min_version_3_7 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%SZ');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%SZ');

    # set the trigger to notify us at the start of the event
    my $triggerdt = $startdt->clone();
    $triggerdt->add(DateTime::Duration->new(seconds => 0 - $now->offset()));
    my $trigger = $triggerdt->strftime('%Y%m%dT%H%M%SZ');

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
DTEND:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
RRULE:FREQ=DAILY
BEGIN:VALARM
TRIGGER;VALUE=DATE-TIME:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', start => $start});
}

sub test_simple_reconstruct
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->{instance}->run_command({ cyrus => 1 }, 'dav_reconstruct', 'cassandane');

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', start => $start});

    $self->{instance}->run_command({ cyrus => 1 }, 'dav_reconstruct', 'cassandane');

    $self->assert_alarms();
}

sub test_simple_defaultalerts
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    # Set defaultalerts to trigger at start of event
    my $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:default-alarm-vevent-datetime>
BEGIN:VALARM
TRIGGER:PT0S
ACTION:DISPLAY
DESCRIPTION:alarm
END:VALARM
</C:default-alarm-vevent-datetime>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane/" . $CalendarId,
        $proppatchXml, 'Content-Type' => 'text/xml');

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
X-JMAP-USEDEFAULTALERTS;VALUE=BOOLEAN:TRUE
X-APPLE-DEFAULT-ALARM;VALUE=BOOLEAN:TRUE
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', start => $start});
}

sub test_update_defaultalerts
    :min_version_3_4 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    # Set defaultalerts to trigger at start of event
    my $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:default-alarm-vevent-datetime>
BEGIN:VALARM
TRIGGER:PT0S
ACTION:DISPLAY
DESCRIPTION:alarm
END:VALARM
</C:default-alarm-vevent-datetime>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane/" . $CalendarId,
        $proppatchXml, 'Content-Type' => 'text/xml');

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
X-JMAP-USEDEFAULTALERTS;VALUE=BOOLEAN:TRUE
X-APPLE-DEFAULT-ALARM;VALUE=BOOLEAN:TRUE
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "No alarm triggered before the event";
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );
    $self->assert_alarms();

    xlog "Alarm triggered in the first minute after the event";
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );
    $self->assert_alarms({summary => 'Simple', start => $start});

    xlog "No further alarm triggered for the event";
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 120 );
    $self->assert_alarms();

    xlog "Change default alarms to trigger one minute after event";
    $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:default-alarm-vevent-datetime>
BEGIN:VALARM
TRIGGER:PT1M
ACTION:DISPLAY
DESCRIPTION:alarm
END:VALARM
</C:default-alarm-vevent-datetime>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane/" . $CalendarId,
        $proppatchXml, 'Content-Type' => 'text/xml');

    xlog "Assert alarm gets triggered two minutes after the event";
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 120 );
    $self->assert_alarms({summary => 'Simple', start => $start});
}

sub test_reschedule_later
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', start => $start});

    # define the event to start in a few seconds
    my $newstartdt = $startdt->clone();
    $newstartdt->add(DateTime::Duration->new(seconds => 86400));
    my $newstart = $newstartdt->strftime('%Y%m%dT%H%M%S');

    my $newenddt = $enddt->clone();
    $newenddt->add(DateTime::Duration->new(seconds => 86400));
    my $newend = $newenddt->strftime('%Y%m%dT%H%M%S');

    $card =~ s/$start/$newstart/;
    $card =~ s/$end/$newend/;

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # nothing happens 1 second later
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 61 );

    $self->assert_alarms();

    # alarm happens one day later
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 + 86400 );

    $self->assert_alarms({summary => 'Simple', start => $newstart});
}

sub test_override
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define an event that started almost an hour ago and repeats hourly
    my $startdt = $now->clone();
    $startdt->subtract(DateTime::Duration->new(minutes => 59, seconds => 55));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # the next event will start in a few seconds
    my $recuriddt = $now->clone();
    $recuriddt->add(DateTime::Duration->new(seconds => 5));
    my $recurid = $recuriddt->strftime('%Y%m%dT%H%M%S');

    my $rstartdt = $recuriddt->clone();
    my $recurstart = $recuriddt->strftime('%Y%m%dT%H%M%S');

    my $renddt = $rstartdt->clone();
    $renddt->add(DateTime::Duration->new(seconds => 15));
    my $recurend = $renddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.11.1//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Australia/Sydney:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=Australia/Sydney:$start
CREATED:20160420T141217Z
RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=3
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alert
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
BEGIN:VEVENT
CREATED:20160420T141217Z
UID:12A08570-CF92-4418-986C-6173001AB557
DTEND;TZID=Australia/Sydney:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=Australia/Sydney:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=Australia/Sydney:$recurid
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm exception
DESCRIPTION:My alarm exception has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    # trigger processing of alarms
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'exception', start => $recurstart});
}

sub test_override_exception
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define an event that started almost an hour ago and repeats hourly
    my $startdt = $now->clone();
    $startdt->subtract(DateTime::Duration->new(minutes => 59, seconds => 55));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # the next event will start in a few seconds
    my $recuriddt = $now->clone();
    $recuriddt->add(DateTime::Duration->new(seconds => 5));
    my $recurid = $recuriddt->strftime('%Y%m%dT%H%M%S');

    # but it starts a few seconds after the regular start
    my $rstartdt = $now->clone();
    $rstartdt->add(DateTime::Duration->new(seconds => 15));
    my $recurstart = $rstartdt->strftime('%Y%m%dT%H%M%S');

    my $renddt = $rstartdt->clone();
    $renddt->add(DateTime::Duration->new(seconds => 15));
    my $recurend = $renddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.11.1//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Australia/Sydney:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=Australia/Sydney:$start
CREATED:20160420T141217Z
RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=3
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alert
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
BEGIN:VEVENT
CREATED:20160420T141217Z
UID:12A08570-CF92-4418-986C-6173001AB557
DTEND;TZID=Australia/Sydney:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=Australia/Sydney:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=Australia/Sydney:$recurid
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm exception
DESCRIPTION:My alarm exception has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    # trigger processing of alarms
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'exception', start => $recurstart});
}

sub test_floating_notz
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $utc = DateTime::Format::ISO8601->new->parse_datetime($start . 'Z');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "95989f3d-575f-4828-9610-6f16b9d54d04";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND:$end
TRANSP:OPAQUE
SUMMARY:Floating
DTSTART:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $utc->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $utc->epoch() + 60 );

    $self->assert_alarms({summary => 'Floating', start => $start, timezone => '[floating]'});
}

sub test_floating_sametz
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $tz = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
EOF

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo', timeZone => $tz});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "95989f3d-575f-4828-9610-6f16b9d54d04";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND:$end
TRANSP:OPAQUE
SUMMARY:Floating
DTSTART:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Floating'});
}

sub test_floating_differenttz
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;
    return if not $self->{test_calalarmd};

    my $CalDAV = $self->{caldav};

    my $tz = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:America/New_York
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=11
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=2SU;BYMONTH=3
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
EOF

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo', timeZone => $tz});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    my $syd = DateTime::TimeZone->new( name => 'Australia/Sydney' );
    my $ny = DateTime::TimeZone->new( name => 'America/New_York' );
    my $offset = $syd->offset_for_datetime($now) - $ny->offset_for_datetime($now);

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "95989f3d-575f-4828-9610-6f16b9d54d04";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND:$end
TRANSP:OPAQUE
SUMMARY:Floating
DTSTART:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    # no alarms
    $self->assert_alarms();

    # trigger processing in New York
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 + $offset );

    # alarm fires
    $self->assert_alarms({summary => 'Floating', timezone => 'America/New_York', start => $start});
}

sub test_replication_at1
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    $self->assert_not_null($self->{replica});

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define an event that starts now and repeats hourly
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 60));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 60));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # the next event will start in a few seconds
    my $recuriddt = $startdt->clone();
    $recuriddt->add(DateTime::Duration->new(minutes => 60));
    my $recurid = $recuriddt->strftime('%Y%m%dT%H%M%S');

    # but it starts a few seconds after the regular start
    my $rstartdt = $recuriddt->clone();
    $rstartdt->add(DateTime::Duration->new(seconds => 15));
    my $recurstart = $recuriddt->strftime('%Y%m%dT%H%M%S');

    my $renddt = $rstartdt->clone();
    $renddt->add(DateTime::Duration->new(seconds => 60));
    my $recurend = $renddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.11.1//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Australia/Sydney:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=Australia/Sydney:$start
CREATED:20160420T141217Z
RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=3
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alert
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
BEGIN:VEVENT
CREATED:20160420T141217Z
UID:12A08570-CF92-4418-986C-6173001AB557
DTEND;TZID=Australia/Sydney:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=Australia/Sydney:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=Australia/Sydney:$recurid
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm exception
DESCRIPTION:My alarm exception has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # replicate to the other end
    $self->run_replication();

    # clean notification cache
    $self->{instance}->getnotify();

    # trigger processing of alarms
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 500 );
    $self->assert_alarms({summary => 'main'});

    # no alarm when you run the second time
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 500 );
    $self->assert_alarms();

    # replicate to the other end
    $self->run_replication();

    # running on the replica gets the exception, not the first instance
    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5000 );
    $self->assert_alarms({summary => 'exception'});

    # no alarm when you run the second time
    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5000 );
    $self->assert_alarms();

    # running on the master still gets the exception, because it doesn't know about the change
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5000 );
    $self->assert_alarms({summary => 'exception'});
}

sub test_override_double
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define an event that started almost an hour ago and repeats hourly
    my $startdt = $now->clone();
    $startdt->subtract(DateTime::Duration->new(minutes => 59, seconds => 55));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # the next event will start in a few seconds
    my $recuriddt = $now->clone();
    $recuriddt->add(DateTime::Duration->new(seconds => 5));
    my $recurid = $recuriddt->strftime('%Y%m%dT%H%M%S');

    my $rstartdt = $recuriddt->clone();
    my $recurstart = $recuriddt->strftime('%Y%m%dT%H%M%S');

    my $renddt = $rstartdt->clone();
    $renddt->add(DateTime::Duration->new(seconds => 15));
    my $recurend = $renddt->strftime('%Y%m%dT%H%M%S');

    my $lastrepl = $recuriddt->clone();
    $lastrepl->add(DateTime::Duration->new(minutes => 60));
    my $lastalarm = $lastrepl->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.11.1//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Australia/Sydney:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=Australia/Sydney:$start
CREATED:20160420T141217Z
RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=3
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alert
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
BEGIN:VEVENT
CREATED:20160420T141217Z
UID:12A08570-CF92-4418-986C-6173001AB557
DTEND;TZID=Australia/Sydney:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=Australia/Sydney:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=Australia/Sydney:$recurid
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm exception
DESCRIPTION:My alarm exception has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    # trigger processing of alarms
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 6000 );

    $self->assert_alarms({summary => 'exception', start => $recurstart}, {summary => 'main', start => $lastalarm});
}

sub test_allday_notz
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start today
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(days => 1));
    $startdt->truncate(to => 'day');
    my $start = $startdt->strftime('%Y%m%d');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(days => 1));
    my $end = $enddt->strftime('%Y%m%d');

    my $utc = DateTime::Format::ISO8601->new->parse_datetime($start . 'T000000Z');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "95989f3d-575f-4828-9610-6f16b9d54d04";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:$uuid
DTEND;TYPE=DATE:$end
TRANSP:OPAQUE
SUMMARY:allday
DTSTART;TYPE=DATE:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $utc->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $utc->epoch() + 60 );

    $self->assert_alarms({summary => 'allday', start => $start, timezone => '[floating]'});
}

sub test_allday_sametz
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $tz = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Brisbane
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
EOF

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo', timeZone => $tz});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Brisbane');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in 2 days
    # (need to go 2 days out to account for the timezone of the testing location,
    #  otherwise we may store the event locally AFTER the adjusted alarm trigger)
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(days => 2));
    $startdt->truncate(to => 'day');
    my $start = $startdt->strftime('%Y%m%d');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(days => 1));
    my $end = $enddt->strftime('%Y%m%d');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "95989f3d-575f-4828-9610-6f16b9d54d04";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:$uuid
DTEND;TYPE=DATE:$end
TRANSP:OPAQUE
SUMMARY:allday
DTSTART;TYPE=DATE:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $startdt->epoch() + 60 );

    $self->assert_alarms({summary => 'allday', start => $start, timezone => 'Australia/Brisbane'});
}

sub test_replication_withalarms_in_tz_with_dst
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event which recurs weekly
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-/c/Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
RRULE:FREQ=WEEKLY
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');


    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5 );

    # clean notification cache
    $self->{instance}->getnotify();

    $self->run_replication(nosyncback => 1);

    $self->assert_alarms();

    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5 );

    $self->assert_alarms();

    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5 );

    $self->assert_alarms();

    $self->run_replication(nosyncback => 1);

    $self->assert_alarms();

    # Check if DST is applicable
    my $tdt = $now->clone();
    $tdt->add(DateTime::Duration->new(seconds => ((86400 * 7) + 5)));
    if (!$tdt->is_dst()) {
        # Not in DST, add an hour
        $tdt = $tdt->add(DateTime::Duration->new(seconds => (60 * 60)));
    }

    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $tdt->epoch());

    # should be a new alarm here
    $self->assert_alarms({summary => 'Simple'});
}

sub test_replication_withalarms_in_tz_without_dst
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Asia/Singapore');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event which recurs weekly
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-/c/Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Asia/Singapore
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+0800
TZOFFSETTO:+0800
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+0800
TZOFFSETTO:+0800
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Asia/Singapore:$end
RRULE:FREQ=WEEKLY
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Asia/Singapore:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');


    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5 );

    # clean notification cache
    $self->{instance}->getnotify();

    $self->run_replication(nosyncback => 1);

    $self->assert_alarms();

    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5 );

    $self->assert_alarms();

    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 5 );

    $self->assert_alarms();

    $self->run_replication(nosyncback => 1);

    $self->assert_alarms();

    $self->{replica}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + (86400*7) + 5);

    # should be a new alarm here
    $self->assert_alarms({summary => 'Simple'});
}

sub test_reschedule_exception
    :min_version_3_0 :needs_component_calalarmd
{
    my ($self) = @_;

    # FIXME disable this test until calalarmd is fixed
    return;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Europe/Vienna');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define an event that started yesterday and repeats daily
    my $startdt = $now->clone();
    $startdt->subtract(DateTime::Duration->new(hours => 23));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(minutes => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # the next event will start in one hour
    my $recuriddt = $now->clone();
    $recuriddt->add(DateTime::Duration->new(hours => 1));
    my $recurid = $recuriddt->strftime('%Y%m%dT%H%M%S');

    # but it exceptionally starts in two hours
    my $rstartdt = $now->clone();
    $rstartdt->add(DateTime::Duration->new(hours => 2));
    my $recurstart = $rstartdt->strftime('%Y%m%dT%H%M%S');
    my $renddt = $rstartdt->clone();
    $renddt->add(DateTime::Duration->new(minutes => 15));
    my $recurend = $renddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.11.1//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Europe/Vienna
X-LIC-LOCATION:Europe/Vienna
TZUNTIL:20170523T130000Z
BEGIN:DAYLIGHT
TZNAME:CEST
DTSTART:20170522T140000
TZOFFSETFROM:+0200
TZOFFSETTO:+0200
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Europe/Vienna:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=Europe/Vienna:$start
CREATED:20160420T141217Z
RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=3
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alert
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
BEGIN:VEVENT
CREATED:20160420T141217Z
UID:12A08570-CF92-4418-986C-6173001AB557
DTEND;TZID=Europe/Vienna:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=Europe/Vienna:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=Europe/Vienna:$recurid
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm exception
DESCRIPTION:My alarm exception has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "PUT VEVENT";
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    # trigger processing of alarms: wall clock for calalarmd is 10 seconds *after*
    # the occurrence of the exception. This will trigger it to fire its alarm.
    xlog $self, "run calalarmd";
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $rstartdt->epoch() + 10 );

    $self->assert_alarms({summary => 'exception', start => $recurstart});

    # reschedule the exception event to start one hour later than the original
    # exceptional start time.
    $rstartdt->add(DateTime::Duration->new(hours => 1));
    $recurstart = $rstartdt->strftime('%Y%m%dT%H%M%S');
    $renddt = $rstartdt->clone();
    $renddt->add(DateTime::Duration->new(minutes => 15));
    $recurend = $renddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.11.1//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Europe/Vienna
X-LIC-LOCATION:Europe/Vienna
TZUNTIL:20170523T130000Z
BEGIN:DAYLIGHT
TZNAME:CEST
DTSTART:20170522T140000
TZOFFSETFROM:+0200
TZOFFSETTO:+0200
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Europe/Vienna:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=Europe/Vienna:$start
CREATED:20160420T141217Z
RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=3
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alert
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
BEGIN:VEVENT
CREATED:20160420T141217Z
UID:12A08570-CF92-4418-986C-6173001AB557
DTEND;TZID=Europe/Vienna:$recurend
TRANSP:OPAQUE
SUMMARY:rescheduled
DTSTART;TZID=Europe/Vienna:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=Europe/Vienna:$recurid
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm exception
DESCRIPTION:My alarm exception has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "PUT rescheduled VEVENT";
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    xlog $self, "Re-run calalarmd";
    # trigger processing of alarms: wall clock now is 10 seconds after the
    # newly scheduled exception time
    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $rstartdt->epoch() + 10 );

    $self->assert_alarms({summary => 'rescheduled', start => $recurstart});
}

sub test_simple_multiuser
    :min_version_3_1 :needs_component_calalarmd :NoAltNameSpace
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $AdminTalk = $self->{adminstore}->get_client();
    $AdminTalk->create("user.foo");
    $AdminTalk->setacl("user.cassandane.#calendars.$CalendarId", "foo", "lrswipkxtecdn789");

    my $foostore = $self->{instance}->get_service('imap')->create_store(
                        username => "foo");
    my $footalk = $foostore->get_client();
    $footalk->subscribe("user.cassandane.#calendars.$CalendarId");

    my $service = $self->{instance}->get_service("http");
    my $FooDAV = Net::CalDAVTalk->new(
        user => 'foo',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $cal = $FooDAV->GetCalendar("cassandane.$CalendarId");
    $self->assert_not_null($cal);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    my $latedt = $startdt->clone();
    $latedt->add(DateTime::Duration->new(seconds => 300));
    my $late = $latedt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $cardtmpl = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
XXALARMDATAXX
END:VEVENT

END:VCALENDAR
EOF

    my $alarm = <<EOF;
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm cassandane
DESCRIPTION:My alarm has triggered
END:VALARM
EOF

    my $latealarm = <<EOF;
BEGIN:VALARM
TRIGGER:PT5M
ACTION:DISPLAY
SUMMARY: My alarm foo
DESCRIPTION:My latealarm has triggered
END:VALARM
EOF

    my $card = $cardtmpl;
    $card =~ s/XXALARMDATAXX/$alarm/;
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    my $Events = $CalDAV->GetEvents("$CalendarId");
    my $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    $self->assert_not_null($Events->[0]{alerts});
    # foo event does not yet have alarms
    $self->assert_null($FooEvents->[0]{alerts});

    my $foocard = $cardtmpl;
    $foocard =~ s/XXALARMDATAXX/$latealarm/;
    $FooDAV->Request('PUT', $FooEvents->[0]{href}, $foocard, 'Content-Type' => 'text/calendar');

    $Events = $CalDAV->GetEvents("$CalendarId");
    $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    $self->assert_not_null($Events->[0]{alerts});
    # foo event has alarms
    $self->assert_not_null($FooEvents->[0]{alerts});

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', userId => 'cassandane', alarmTime => $start, start => $start});

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 600 );

    $self->assert_alarms({summary => 'Simple', userId => 'foo', alarmTime => $late, start => $start});

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 900 );

    $self->assert_alarms();
}

sub test_override_multiuser
    :min_version_3_1 :needs_component_calalarmd :NoAltNameSpace
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $AdminTalk = $self->{adminstore}->get_client();
    $AdminTalk->create("user.foo");
    $AdminTalk->setacl("user.cassandane.#calendars.$CalendarId", "foo", "lrswipkxtecdn789");

    my $foostore = $self->{instance}->get_service('imap')->create_store(
                        username => "foo");
    my $footalk = $foostore->get_client();
    $footalk->subscribe("user.cassandane.#calendars.$CalendarId");

    my $service = $self->{instance}->get_service("http");
    my $FooDAV = Net::CalDAVTalk->new(
        user => 'foo',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $cal = $FooDAV->GetCalendar("cassandane.$CalendarId");
    $self->assert_not_null($cal);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $nextweekdt = $now->clone();
    $nextweekdt->add(DateTime::Duration->new(days => 7));
    my $nextweek = $nextweekdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    my $nwenddt = $nextweekdt->clone();
    $nwenddt->add(DateTime::Duration->new(seconds => 15));
    my $nwend = $nwenddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $cardtmpl = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
RRULE:FREQ=WEEKLY
SEQUENCE:0
END:VEVENT

BEGIN:VEVENT
RECURRENCE-ID;TZID=Australia/Sydney:$start
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
SUMMARY:EV1
END:VEVENT

BEGIN:VEVENT
RECURRENCE-ID;TZID=Australia/Sydney:$nextweek
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$nwend
TRANSP:OPAQUE
DTSTART;TZID=Australia/Sydney:$nextweek
DTSTAMP:20150806T234327Z
SEQUENCE:0
SUMMARY:EV2
END:VEVENT

END:VCALENDAR
EOF

    my $alarm = <<EOF;
BEGIN:VALARM
TRIGGER:$trigger
ACTION:EMAIL
SUMMARY: My alarm cassandane
DESCRIPTION:My alarm has triggered
ATTENDEE:MAILTO:cassandane\@example.com
END:VALARM
EOF

    my $latealarm = <<EOF;
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm foo
DESCRIPTION:My alarm has triggered
END:VALARM
EOF

    my $card = $cardtmpl;
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    my $Events = $CalDAV->GetEvents("$CalendarId");
    my $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    $self->assert_null($Events->[0]{alerts});
    $self->assert_null($FooEvents->[0]{alerts});

    my $foocard = $cardtmpl;
    $foocard =~ s/SUMMARY:EV2/SUMMARY:EV2\n$latealarm/;
    $FooDAV->Request('PUT', $FooEvents->[0]{href}, $foocard, 'Content-Type' => 'text/calendar');

    my $cascard = $cardtmpl;
    $cascard =~ s/SUMMARY:EV1/SUMMARY:EV1\n$alarm/;
    $CalDAV->Request('PUT', $Events->[0]{href}, $cascard, 'Content-Type' => 'text/calendar');

    $Events = $CalDAV->GetEvents("$CalendarId");
    $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    $self->assert_null($Events->[0]{alerts});
    $self->assert_null($FooEvents->[0]{alerts});

    # XXX - assert the recurrences

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'EV1', userId => 'cassandane', alarmTime => $start, action => 'email', start => $start});

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $nextweekdt->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $nextweekdt->epoch() + 60 );

    $self->assert_alarms({summary => 'EV2', userId => 'foo', alarmTime => $nextweek, action => 'display', start => $nextweek});
}

sub test_simple_multiuser_sametime
    :min_version_3_1 :needs_component_calalarmd :NoAltNameSpace
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $AdminTalk = $self->{adminstore}->get_client();
    $AdminTalk->create("user.foo");
    $AdminTalk->setacl("user.cassandane.#calendars.$CalendarId", "foo", "lrswipkxtecdn789");

    my $foostore = $self->{instance}->get_service('imap')->create_store(
                        username => "foo");
    my $footalk = $foostore->get_client();
    $footalk->subscribe("user.cassandane.#calendars.$CalendarId");

    my $service = $self->{instance}->get_service("http");
    my $FooDAV = Net::CalDAVTalk->new(
        user => 'foo',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $cal = $FooDAV->GetCalendar("cassandane.$CalendarId");
    $self->assert_not_null($cal);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "c10bea47-f280-4fba-b627-d1bc263c7666";
    my $href = "$CalendarId/$uuid.ics";
    my $cardtmpl = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm cassandane
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT

END:VCALENDAR
EOF

    my $foocard = $cardtmpl;
    $FooDAV->Request('PUT', "cassandane.$href", $foocard, 'Content-Type' => 'text/calendar');

    my $Events = $CalDAV->GetEvents("$CalendarId");
    my $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    # cassandane event does not yet have alarms
    $self->assert_null($Events->[0]{alerts});
    $self->assert_not_null($FooEvents->[0]{alerts});

    my $card = $cardtmpl;
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    $Events = $CalDAV->GetEvents("$CalendarId");
    $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    # now both have alarms
    $self->assert_not_null($Events->[0]{alerts});
    $self->assert_not_null($FooEvents->[0]{alerts});

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() - 60 );

    $self->assert_alarms();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', userId => 'foo', alarmTime => $start, start => $start},
                         {summary => 'Simple', userId => 'cassandane', alarmTime => $start, start => $start});
}

sub test_simple_multiuser_secretary
    :min_version_3_3 :needs_component_calalarmd :NoAltNameSpace :needs_component_jmap
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $AdminTalk = $self->{adminstore}->get_client();
    $AdminTalk->create("user.foo");
    $AdminTalk->setacl("user.cassandane.#calendars.$CalendarId", "foo", "lrswipkxtecdn789");

    my $foostore = $self->{instance}->get_service('imap')->create_store(
                        username => "foo");
    my $footalk = $foostore->get_client();
    $footalk->subscribe("user.cassandane.#calendars.$CalendarId");

    my $service = $self->{instance}->get_service("http");
    my $FooDAV = Net::CalDAVTalk->new(
        user => 'foo',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $cal = $FooDAV->GetCalendar("cassandane.$CalendarId");
    $self->assert_not_null($cal);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $enddt = $startdt->clone();
    $enddt->add(DateTime::Duration->new(seconds => 15));
    my $end = $enddt->strftime('%Y%m%dT%H%M%S');

    my $latedt = $startdt->clone();
    $latedt->add(DateTime::Duration->new(seconds => 300));
    my $late = $latedt->strftime('%Y%m%dT%H%M%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$CalendarId/$uuid.ics";
    my $cardtmpl = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=Australia/Sydney:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DTSTAMP:20150806T234327Z
SEQUENCE:0
XXALARMDATAXX
END:VEVENT

END:VCALENDAR
EOF

    my $alarm = <<EOF;
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm cassandane
DESCRIPTION:My alarm has triggered
END:VALARM
EOF

    my $latealarm = <<EOF;
BEGIN:VALARM
TRIGGER:PT5M
ACTION:DISPLAY
SUMMARY: My alarm foo
DESCRIPTION:My latealarm has triggered
END:VALARM
EOF

    my $card = $cardtmpl;
    $card =~ s/XXALARMDATAXX/$alarm/;
    $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    my $Events = $CalDAV->GetEvents("$CalendarId");
    my $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    $self->assert_not_null($Events->[0]{alerts});
    # foo event does not yet have alarms
    $self->assert_null($FooEvents->[0]{alerts});

    my $foocard = $cardtmpl;
    $foocard =~ s/XXALARMDATAXX/$latealarm/;
    $FooDAV->Request('PUT', $FooEvents->[0]{href}, $foocard, 'Content-Type' => 'text/calendar');

    $Events = $CalDAV->GetEvents("$CalendarId");
    $FooEvents = $FooDAV->GetEvents("cassandane.$CalendarId");
    $self->assert_num_equals(1, scalar @$Events);
    $self->assert_num_equals(1, scalar @$FooEvents);
    $self->assert_not_null($Events->[0]{alerts});
    # foo event has alarms
    $self->assert_not_null($FooEvents->[0]{alerts});

    # set secretary mode
    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:JMAP="urn:ietf:params:jmap:calendars">
  <D:set>
    <D:prop>
      <JMAP:sharees-act-as>secretary</JMAP:sharees-act-as>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane", $xml,
        'Content-Type' => 'text/xml');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    $self->assert_alarms({summary => 'Simple', userId => 'cassandane', alarmTime => $start, start => $start});

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 600 );

    $self->assert_alarms();
}

1;
