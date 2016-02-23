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

package Cassandane::Cyrus::Caldav;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use JSON::XS;
use Net::CalDAVTalk;
use Data::Dumper;

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
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
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
    :VirtDomains
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
    :VirtDomains
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

  my $data = $self->{instance}->getnotify();

  $CalDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

  my $newdata = $self->{instance}->getnotify();
  my ($imip) = grep { $_->{METHOD} eq 'imip' } @$newdata;
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
  $self->assert_str_equals($href, $removes->[0]);
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
{
    my ($self) = @_;

    my $CalDAV = $self->{caldav};

    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    $CalDAV->NewEvent($CalendarId, {
        start => '2015-01-01T12:00:00',
        end => '2015-01-01T13:00:00',
        summary => 'waterfall',
    });

    $CalDAV->NewEvent($CalendarId, {
        start => '2015-02-01T12:00:00',
        end => '2015-02-01T13:00:00',
        summary => 'waterfall2',
    });

    my ($data, $errors) = $CalDAV->GetFreeBusy($CalendarId);

    $self->assert_equals('2015-01-01T12:00:00', $data->[0]{start});
    $self->assert_equals('2015-02-01T12:00:00', $data->[1]{start});
    $self->assert_num_equals(2, scalar @$data);
}

sub test_imap_plusdav_novirt
    :MagicPlus
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
    :MagicPlus :VirtDomains
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
    :MagicPlus :VirtDomains
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

1;
