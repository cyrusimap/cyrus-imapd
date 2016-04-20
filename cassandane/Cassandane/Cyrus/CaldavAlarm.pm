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

use strict;
use warnings;

package Cassandane::Cyrus::CaldavAlarm;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use JSON::XS;
use Net::CalDAVTalk;
use Data::Dumper;
use POSIX;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'caldav');
    $config->set(httpallowcompress => 'no');
    $config->set(sasl_mech_list => 'PLAIN LOGIN');
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

    if (not $self->{instance}->{buildinfo}->{component}->{calalarmd}) {
        xlog "calalarmd not enabled. Skipping tests.";
        return;
    }
    $self->{test_calalarmd} = 1;

}

sub tear_down
{
    my ($self) = @_;

    if ($self->{calalarmd_pid}) {
        $self->stop_calalarmd();
    }

    $self->SUPER::tear_down();
}

sub start_calalarmd
{
    my ($self) = @_;

    my $pid = $self->{instance}->run_command(
        { cyrus => 1, background => 1 }, 'calalarmd', '-d'
    );
    $self->{calalarmd_pid} = $pid;
    xlog "Started calalarmd with PID $pid";
}

sub stop_calalarmd
{
    my ($self) = @_;

    xlog "Kill calarmd with PID $self->{calalarmd_pid}";
    kill(SIGTERM, $self->{calalarmd_pid});
    delete $self->{calalarmd_pid};
}

sub test_simple
{
    my ($self) = @_;
    return if not $self->{test_calalarmd};

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $tzid = strftime("%Z", localtime());
    my $now = DateTime->now();

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
BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
DTEND;TZID=$tzid:$end
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=$tzid:$start
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

    # trigger processing of alarms
    $self->start_calalarmd();
    sleep 3;
    $self->stop_calalarmd();

    # pick first calendar alarm from notifications
    my $event = undef;
    my $data = $self->{instance}->getnotify();
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                $event = $e;
                last;
            }
        }
    }

    $self->assert_str_equals($event->{summary}, 'Simple');
}

sub test_override
{
    my ($self) = @_;
    return if not $self->{test_calalarmd};

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $tzid = strftime("%Z", localtime());
    my $now = DateTime->now();

  
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
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=$tzid:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=$tzid:$start
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
DTEND;TZID=$tzid:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=$tzid:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=$tzid:$recurid
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
    $self->start_calalarmd();
    sleep 3;
    $self->stop_calalarmd();

    # pick first calendar alarm from notifications
    my $event = undef;
    my $data = $self->{instance}->getnotify();
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                $event = $e;
                last;
            }
        }
    }

    $self->assert_str_equals($event->{summary}, 'exception');
}

sub test_override_exception
{
    my ($self) = @_;
    return if not $self->{test_calalarmd};

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $tzid = strftime("%Z", localtime());
    my $now = DateTime->now();

  
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
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=$tzid:$end
UID:12A08570-CF92-4418-986C-6173001AB557
DTSTAMP:20160420T141259Z
SEQUENCE:0
SUMMARY:main
DTSTART;TZID=$tzid:$start
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
DTEND;TZID=$tzid:$recurend
TRANSP:OPAQUE
SUMMARY:exception
DTSTART;TZID=$tzid:$recurstart
DTSTAMP:20160420T141312Z
SEQUENCE:0
RECURRENCE-ID;TZID=$tzid:$recurid
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
    $self->start_calalarmd();
    sleep 15;
    $self->stop_calalarmd();

    # pick first calendar alarm from notifications
    my $event = undef;
    my $data = $self->{instance}->getnotify();
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                $event = $e;
                last;
            }
        }
    }

    $self->assert_str_equals($event->{summary}, 'exception');
}


1;
