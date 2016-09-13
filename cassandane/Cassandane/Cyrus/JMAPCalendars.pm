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

package Cassandane::Cyrus::JMAPCalendars;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk;
use Net::CardDAVTalk;
use Mail::JMAPTalk;
use Data::Dumper;
use Storable 'dclone';

use lib '.';
use base qw(Cassandane::Cyrus::JMAP);
use Cassandane::Util::Log;

use charnames ':full';

sub test_getcalendars
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $id = $caldav->NewCalendar({ name => "calname", color => "aqua"});
    my $unknownId = "foo";

    xlog "get existing calendar";
    my $res = $jmap->Request([['getCalendars', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendars');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, $id);
    $self->assert_str_equals($res->[0][1]{list}[0]{color}, 'aqua');

    xlog "get existing calendar with select properties";
    $res = $jmap->Request([['getCalendars', { ids => [$id], properties => ["name"] }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendars');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, $id);
    $self->assert_str_equals($res->[0][1]{list}[0]{name}, "calname");
    $self->assert_null($res->[0][1]{list}[0]{color});

    xlog "get unknown calendar";
    $res = $jmap->Request([['getCalendars', {ids => [$unknownId]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendars');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 0);
    $self->assert_num_equals(scalar(@{$res->[0][1]{notFound}}), 1);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $unknownId);

    # XXX - test for shared calendars
}

sub test_getcalendars_default
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # XXX - A previous CalDAV test might have created the default
    # calendar already. To make this test self-sufficient, we need
    # to create a test user just for this test. How?
    xlog "get default calendar";
    my $res = $jmap->Request([['getCalendars', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, "Default");
}

sub test_setcalendars
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendars', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, $id);
    $self->assert_str_equals($res->[0][1]{list}[0]{name}, 'foo');
    $self->assert_equals($res->[0][1]{list}[0]{isVisible}, JSON::true);

    xlog "update calendar $id";
    $res = $jmap->Request([
            ['setCalendars', {update => {"$id" => {
                            name => "bar",
                            isVisible => \0
            }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarsSet');
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);
    
    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendars', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]{name}, 'bar');
    $self->assert_equals($res->[0][1]{list}[0]{isVisible}, JSON::false);

    xlog "destroy calendar $id";
    $res = $jmap->Request([['setCalendars', {destroy => ["$id"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarsSet');
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{destroyed});
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendars', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);
}

sub test_setcalendars_state
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with invalid state token";
    my $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => "badstate",
                    create => { "#1" => { name => "foo" }}
                }, "R1"]
        ]);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][1]{type}, 'stateMismatch');

    xlog "create with wrong state token";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => "987654321",
                    create => { "#1" => { name => "foo" }}
                }, "R1"]
        ]);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][1]{type}, 'stateMismatch');

    xlog "create calendar";
    $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res);

    my $id = $res->[0][1]{created}{"#1"}{id};
    my $state = $res->[0][1]{newState};

    xlog "update calendar $id with current state";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => $state,
                    update => {"$id" => {name => "bar"}}
            }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "setCalendar noops must keep state";
    $res = $jmap->Request([
            ['setCalendars', {}, "R1"],
            ['setCalendars', {}, "R2"],
            ['setCalendars', {}, "R3"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_equals($res->[0][1]{newState}, $state);

    xlog "update calendar $id with expired state";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => $oldState,
                    update => {"$id" => {name => "baz"}}
            }, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][1]{type}, "stateMismatch");
    $self->assert_str_equals($res->[0][2], 'R1');

    xlog "get calendar $id to make sure state didn't change";
    $res = $jmap->Request([['getCalendars', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{state}, $state);
    $self->assert_str_equals($res->[0][1]{list}[0]{name}, 'bar');

    xlog "destroy calendar $id with expired state";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => $oldState,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][1]{type}, "stateMismatch");
    $self->assert_str_equals($res->[0][2], 'R1');

    xlog "destroy calendar $id with current state";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => $state,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);
}


sub test_getcalendarupdates
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->Request([
            ['setCalendars', { create => {
                        "#1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
                        },
                        "#2" => {
                            name => "bar",
                            color => "aqua",
                            sortOrder => 3,
                            isVisible => \1
                        }
                    }}, "R1"]
    ]);
    $self->assert_not_null($res);

    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};
    my $state = $res->[0][1]{newState};

    xlog "get calendar updates without changes";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals(scalar @{$res->[0][1]{changed}}, 0);
    $self->assert_str_equals(scalar @{$res->[0][1]{removed}}, 0);

    xlog "update name of calendar $id1, destroy calendar $id2";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => $state,
                    update => {"$id1" => {name => "foo (upd)"}},
                    destroy => [$id2]
            }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);

    xlog "get calendar updates";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals($res->[0][0], "calendarUpdates");
    $self->assert_str_equals($res->[0][2], "R1");
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 1);
    $self->assert_str_equals($res->[0][1]{removed}[0], $id2);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    $state = $res->[0][1]{newState};

    xlog "update color of calendar $id1";
    $res = $jmap->Request([
            ['setCalendars', { update => { $id1 => { color => "aqua" }}}, "R1" ]
        ]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id1);

    xlog "get calendar updates";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    $state = $res->[0][1]{newState};

    xlog "update sortOrder of calendar $id1";
    $res = $jmap->Request([
            ['setCalendars', { update => { $id1 => { sortOrder => 5 }}}, "R1" ]
        ]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id1);

    xlog "get calendar updates";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state,
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    $state = $res->[0][1]{newState};

    xlog "get empty calendar updates";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 0);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
}

sub test_setcalendars_error
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar with missing mandatory attributes";
    my $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {}}}, "R1"]
    ]);
    $self->assert_not_null($res);
    my $errType = $res->[0][1]{notCreated}{"#1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [
            "name", "color", "sortOrder", "isVisible"
    ]);

    xlog "create calendar with invalid optional attributes";
    $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo", color => "coral",
                            sortOrder => 2, isVisible => \1,
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [
            "mayReadFreeBusy", "mayReadItems", "mayAddItems",
            "mayModifyItems", "mayRemoveItems", "mayRename",
            "mayDelete"
    ]);

    xlog "update unknown calendar";
    $res = $jmap->Request([
            ['setCalendars', { update => { "unknown" => {
                            name => "foo"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{"unknown"}{type};
    $self->assert_str_equals($errType, "notFound");

    xlog "create calendar";
    $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "update calendar with immutable optional attributes";
    $res = $jmap->Request([
            ['setCalendars', { update => { $id => {
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{$id}{type};
    $errProp = $res->[0][1]{notUpdated}{$id}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [
            "mayReadFreeBusy", "mayReadItems", "mayAddItems",
            "mayModifyItems", "mayRemoveItems", "mayRename",
            "mayDelete"
    ]);

    xlog "destroy unknown calendar";
    $res = $jmap->Request([
            ['setCalendars', {destroy => ["unknown"]}, "R1"]
    ]);
    $errType = $res->[0][1]{notDestroyed}{"unknown"}{type};
    $self->assert_str_equals($errType, "notFound");

    xlog "destroy calendar $id";
    $res = $jmap->Request([['setCalendars', {destroy => ["$id"]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);
}

sub test_setcalendars_badname
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar with excessively long name";
    # Exceed the maximum allowed 256 byte length by 1.
    my $badname = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum tincidunt risus quis urna aliquam sollicitudin. Pellentesque aliquet nisl ut neque viverra pellentesque. Donec tincidunt eros at ante malesuada porta. Nam sapien arcu, vehicula non posuere.";

    my $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => $badname, color => "aqua",
                            sortOrder => 1, isVisible => \1
            }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    my $errType = $res->[0][1]{notCreated}{"#1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, ["name"]);
}

sub test_setcalendars_destroydefault
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my @specialIds = ["Inbox", "Outbox", "Default", "Attachments"];

    xlog "destroy special calendars";
    my $res = $jmap->Request([
            ['setCalendars', { destroy => @specialIds }, "R1"]
    ]);
    $self->assert_not_null($res);

    my $errType = $res->[0][1]{notDestroyed}{"Default"}{type};
    $self->assert_str_equals($errType, "isDefault");
    $errType = $res->[0][1]{notDestroyed}{"Inbox"}{type};
    $self->assert_str_equals($errType, "notFound");
    $errType = $res->[0][1]{notDestroyed}{"Outbox"}{type};
    $self->assert_str_equals($errType, "notFound");
    $errType = $res->[0][1]{notDestroyed}{"Attachments"}{type};
    $self->assert_str_equals($errType, "notFound");
}

sub normalize_event
{
    my ($event) = @_;

    if (not exists $event->{locations}) {
        $event->{locations} = undef;
    }
    if (not exists $event->{translations}) {
        $event->{translations} = undef;
    }
    if (not exists $event->{language}) {
        $event->{language} = undef;
    }
    if (not exists $event->{links}) {
        $event->{links} = undef;
    }
    if (not exists $event->{relatedTo}) {
        $event->{relatedTo} = undef;
    }
    if (not exists $event->{participants}) {
        $event->{participants} = undef;
    }
    if (not exists $event->{replyTo}) {
        $event->{replyTo} = undef;
    }
    if (not exists $event->{recurrenceRule}) {
        $event->{recurrenceRule} = undef;
    }
    if (not exists $event->{recurrenceOverrides}) {
        $event->{recurrenceOverrides} = undef;
    }
    if (not exists $event->{alerts}) {
        $event->{alerts} = undef;
    }
    if (not exists $event->{prodId}) {
        $event->{prodId} = undef;
    }
    if (not exists $event->{attachments}) {
        $event->{attachments} = undef;
    }
    if (not exists $event->{status}) {
        $event->{status} = "confirmed";
    }

    # undefine dynamically generated values
    $event->{created} = undef;
    $event->{updated} = undef;
    $event->{uid} = undef;
    $event->{id} = undef;
    $event->{"x-href"} = undef;
    $event->{sequence} = 0;
    $event->{prodId} = undef;
}

sub assert_normalized_event_equals
{
    my ($self, $a, $b) = @_;
    my $copyA = dclone($a);
    my $copyB = dclone($b);
    normalize_event($copyA);
    normalize_event($copyB);
    return $self->assert_deep_equals($copyA, $copyB);
}

sub putandget_vevent
{
    my ($self, $id, $ical) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "get default calendar id";
    my $res = $jmap->Request([['getCalendars', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, "Default");
    my $calid = $res->[0][1]{list}[0]{id};
    my $xhref = $res->[0][1]{list}[0]{"x-href"};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog "create event (via CalDAV)";
    my $href = "$xhref/$id.ics";

    $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    xlog "get event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);

    my $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);
    return $event;
}

sub test_getcalendarevents_simple
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART:20160928T160000Z
DTEND:20160928T170000Z
UID:$id
RELATED-TO:58ADE31-broken-UID
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:double yo
SEQUENCE:9
SUMMARY;LANGUAGE=en:yo
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals($event->{uid}, $id);
    $self->assert_deep_equals($event->{relatedTo}, ["58ADE31-broken-UID"]);
    $self->assert_str_equals($event->{title}, "yo");
    $self->assert_str_equals($event->{prodId}, "-//Apple Inc.//Mac OS X 10.9.5//EN");
    $self->assert_str_equals($event->{language}, "en");
    $self->assert_str_equals($event->{description}, "double yo");
    $self->assert_equals($event->{showAsFree}, JSON::true);
    $self->assert_equals($event->{isAllDay}, JSON::false);
    $self->assert_str_equals($event->{start}, "2016-09-28T16:00:00");
    $self->assert_str_equals($event->{timeZone}, "UTC");
    $self->assert_str_equals($event->{duration}, "PT1H");
    $self->assert_str_equals($event->{created}, "2015-09-28T12:52:12Z");
    $self->assert_str_equals($event->{updated}, "2015-09-28T13:24:34Z");
    $self->assert_num_equals($event->{sequence}, 9);
}

sub test_getcalendarevents_links
    :min_version_3_0
{
    my ($self) = @_;

    my $uri1 = "http://jmap.io/spec.html#calendar-events";
    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:yo
ATTACH;FMTTYPE=text/html;SIZE=4480:$uri1
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $links = {
        $uri1 => {
            href => $uri1,
            type => "text/html",
            size => 4480,
        }
    };

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_deep_equals($event->{links}, $links);
}


sub test_getcalendarevents_rscale
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;VALUE=DATE:20140208
DURATION:PT1H
RRULE:RSCALE=HEBREW;FREQ=YEARLY;BYMONTH=5L;BYMONTHDAY=8;SKIP=FORWARD
SUMMARY:Adar I
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals($event->{title}, "Adar I");
    $self->assert_str_equals($event->{recurrenceRule}{frequency}, "yearly");
    $self->assert_str_equals($event->{recurrenceRule}{rscale}, "hebrew");
    $self->assert_str_equals($event->{recurrenceRule}{skip}, "forward");
    $self->assert_num_equals($event->{recurrenceRule}{byDate}[0], 8);
    $self->assert_str_equals($event->{recurrenceRule}{byMonth}[0], "5L");
}

sub test_getcalendarevents_endtimezone
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/London:20160928T130000
DTEND;TZID=Europe/Vienna:20160928T150000
SUMMARY:Foo
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals($event->{start}, "2016-09-28T13:00:00");
    $self->assert_str_equals($event->{timeZone}, "Europe/London");
    $self->assert_str_equals($event->{duration}, "PT1H");

    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(scalar @locations, 1);
    $self->assert_str_equals($locations[0]{timeZone}, "Europe/Vienna");
    $self->assert_str_equals($locations[0]{rel}, "end");
}

sub test_getcalendarevents_participants
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:Yep
LAST-MODIFIED:20150928T132434Z
ATTENDEE;ROLE=OPT-PARTICIPANT;CN=Homer Simpson;PARTSTAT=ACCEPTED:mailto:homer\@example.com
ATTENDEE;PARTSTAT=TENTATIVE;DELEGATED-FROM="mailto:lenny\@example.com";CN=Carl Carlson:mailto:carl\@example.com
ATTENDEE;PARTSTAT=DELEGATED;DELEGATED-TO="mailto:carl\@example.com";CN=Lenny Leonard:mailto:lenny\@example.com
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;X-DTSTAMP=20150929T144423Z;CN=Larry Burns:mailto:larry\@example.com
ORGANIZER;CN="Monty Burns":mailto:smithers\@example.com
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;X-DTSTAMP=20150929T144423Z;CN=Monty Burns:mailto:smithers\@example.com
STATUS:TENTATIVE
END:VEVENT
END:VCALENDAR
EOF
    my $event = $self->putandget_vevent($id, $ical);

    $self->assert_not_null($event->{participants});
    $self->assert_num_equals(scalar values %{$event->{participants}}, 5);
    $self->assert_str_equals($event->{participants}{"smithers\@example.com"}{name}, "Monty Burns");
    $self->assert_str_equals($event->{participants}{"smithers\@example.com"}{email}, "smithers\@example.com");
    $self->assert_str_equals($event->{participants}{"smithers\@example.com"}{roles}[0], "owner");
    $self->assert_str_equals($event->{participants}{"homer\@example.com"}{name}, "Homer Simpson");
    $self->assert_str_equals($event->{participants}{"homer\@example.com"}{scheduleStatus}, "accepted");
    $self->assert_str_equals($event->{participants}{"homer\@example.com"}{schedulePriority}, "optional");
    $self->assert_str_equals($event->{participants}{"homer\@example.com"}{email}, "homer\@example.com");
    $self->assert_str_equals($event->{participants}{"homer\@example.com"}{roles}[0], "attendee");
    $self->assert_str_equals($event->{participants}{"carl\@example.com"}{name}, "Carl Carlson");
    $self->assert_str_equals($event->{participants}{"carl\@example.com"}{scheduleStatus}, "tentative");
    $self->assert_str_equals($event->{participants}{"carl\@example.com"}{email}, "carl\@example.com");
    $self->assert_str_equals($event->{participants}{"carl\@example.com"}{roles}[0], "attendee");
    $self->assert_str_equals($event->{participants}{"lenny\@example.com"}{name}, "Lenny Leonard");
    $self->assert_str_equals($event->{participants}{"lenny\@example.com"}{scheduleStatus}, "tentative");
    $self->assert_str_equals($event->{participants}{"lenny\@example.com"}{email}, "lenny\@example.com");
    $self->assert_str_equals($event->{participants}{"lenny\@example.com"}{roles}[0], "attendee");
    $self->assert_str_equals($event->{participants}{"larry\@example.com"}{name}, "Larry Burns");
    $self->assert_str_equals($event->{participants}{"larry\@example.com"}{scheduleStatus}, "declined");
    $self->assert_str_equals($event->{participants}{"larry\@example.com"}{email}, "larry\@example.com");
    $self->assert_str_equals($event->{participants}{"larry\@example.com"}{roles}[0], "attendee");
    $self->assert_str_equals($event->{status}, "tentative");
}

sub test_getcalendarevents_recurrence
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
RRULE:RSCALE=GREGORIAN;SKIP=OMIT;FREQ=MONTHLY;BYDAY=+2MO,TU,-3SU,+1MO,-2TH,-1SA
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event->{recurrenceRule});
    $self->assert_str_equals($event->{recurrenceRule}{frequency}, "monthly");
    $self->assert_str_equals($event->{recurrenceRule}{rscale}, "gregorian");
    $self->assert_str_equals($event->{recurrenceRule}{skip}, "omit");
    $self->assert_str_equals($event->{recurrenceRule}{firstDayOfWeek}, "monday");
    # This assertion is a bit brittle. It depends on the libical-internal
    # sort order for BYDAY
    $self->assert_deep_equals($event->{recurrenceRule}{byDay}, [{
                "day" => "monday",
                "nthOfPeriod" => 2,
            }, {
                "day" => "monday",
                "nthOfPeriod" => 1,
            }, {
                "day" => "tuesday",
            }, {
                "day" => "thursday",
                "nthOfPeriod" => -2,
            }, {
                "day" => "saturday",
                "nthOfPeriod" => -1,
            }, {
                "day" => "sunday",
                "nthOfPeriod" => -3,
            }]);
}

sub test_getcalendarevents_recurrenceoverrides
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $aid = $id . "-alarmid";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160101T130000
DURATION:PT1H
RRULE:RSCALE=GREGORIAN;SKIP=OMIT;FREQ=MONTHLY
RDATE;TZID=Europe/Vienna:20161224T200000
RDATE;TZID=Europe/London:20160203T130000
RDATE:20160204T130000Z
RDATE;VALUE=PERIOD:20160304T150000Z/20160304T160000Z
EXDATE:20160201T130000
EXDATE;TZID=Europe/London:20160701T120000
EXDATE;TZID=Europe/London:20161101T120000Z
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:description
SUMMARY:foo
X-JMAP-TRANSLATION;LANGUAGE=de;X-JMAP-PROP=title:Titel
LAST-MODIFIED:20150928T132434Z
END:VEVENT
BEGIN:VEVENT
TRANSP:OPAQUE
UID:$id
SEQUENCE:0
RECURRENCE-ID;TZID=Europe/Vienna:20160501T130000
SUMMARY:foobarbazbla
X-JMAP-TRANSLATION;LANGUAGE=de;X-JMAP-PROP=title:reinerbloedsinn
DESCRIPTION:description
DTSTART;TZID=Europe/Vienna:20160501T170000
DURATION:PT2H
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
BEGIN:VALARM
UID:$aid
ACTION:DISPLAY
DESCRIPTION:yo
TRIGGER:-PT5M
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    my $o;

    $o = $event->{recurrenceOverrides}->{"2016-12-24T20:00:00"};
    $self->assert_not_null($o);

    $o = $event->{recurrenceOverrides}->{"2016-02-03T14:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals($o->{start}, "2016-02-03T13:00:00");
    $self->assert_str_equals($o->{timeZone}, "Europe/London");

    $o = $event->{recurrenceOverrides}->{"2016-02-04T14:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals($o->{start}, "2016-02-04T13:00:00");
    $self->assert_str_equals($o->{timeZone}, "UTC");

    $o = $event->{recurrenceOverrides}->{"2016-03-04T16:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals($o->{duration}, "PT1H");

    $self->assert(exists $event->{recurrenceOverrides}->{"2016-02-01T13:00:00"});
    $self->assert_null($event->{recurrenceOverrides}->{"2016-02-01T13:00:00"});
    $self->assert(exists $event->{recurrenceOverrides}->{"2016-11-01T13:00:00"});
    $self->assert_null($event->{recurrenceOverrides}->{"2016-11-01T13:00:00"});

    $o = $event->{recurrenceOverrides}->{"2016-05-01T13:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals($o->{"title"}, "foobarbazbla");
    $self->assert_str_equals($o->{"start"}, "2016-05-01T17:00:00");
    $self->assert_str_equals($o->{"duration"}, "PT2H");
    $self->assert_str_equals($o->{"translations/de/title"}, "reinerbloedsinn");
    $self->assert_not_null($o->{alerts}{$aid});



    # diff={"translations/de/title": "reinerbloedsinn", "created": "2016-09-12T16:22:50Z", "duration": "PT1H", "updated": "2016-09-12T16:23:24Z", "showAsFree": false, "title": "foobarbazbla", "start": "2016-09-13T15:00:00"}
}

sub test_getcalendarevents_alerts
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $aid1 = "0CF835D0-CFEB-44AE-904A-C26AB62B73BB-1";
    my $aid2 = "0CF835D0-CFEB-44AE-904A-C26AB62B73BB-2";

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:Yep
DESCRIPTION:
LAST-MODIFIED:20150928T132434Z
BEGIN:VALARM
X-WR-ALARMUID:$aid1
UID:$aid1
TRIGGER:-PT5M
ACTION:EMAIL
ATTENDEE:mailto:foo\@example.com
SUMMARY:Event alert: 'Yep' starts soon.
DESCRIPTION:Your event 'Yep' starts soon.
END:VALARM
BEGIN:VALARM
UID:$aid2
ACTION:DISPLAY
DESCRIPTION:Your event 'Yep' starts soon.
TRIGGER;VALUE=DATE-TIME:20160928T150000Z
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    my $alert1 = {
        relativeTo => "before-start",
        offset => "PT5M",
        action => {
            type => "email",
            to => [{
                    name => "",
                    email => "foo\@example.com"
                }],
            subject => "Event alert: 'Yep' starts soon.",
            textBody => "Your event 'Yep' starts soon.",
        },
    };
    my $alert2 = {
        relativeTo => "after-start",
        offset => "PT1H",
        action => { type => "display", },
    };

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_deep_equals($event->{alerts}{$aid1}, $alert1);
    $self->assert_deep_equals($event->{alerts}{$aid2}, $alert2);
}

sub test_getcalendarevents_locations
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $aid = "0CF835D0-CFEB-44AE-904A-C26AB62B73BB";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:Remember the yep.
LOCATION:On planet Earth
SEQUENCE:9
SUMMARY;LANGUAGE=en:Yep
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(scalar @locations, 1);
    $self->assert_str_equals($locations[0]{name}, "On planet Earth");
}

sub test_getcalendarevents_locations_uri
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:Remember the yep.
LOCATION;ALTREP="skype:foo":On planet Earth
SEQUENCE:9
SUMMARY;LANGUAGE=en:Yep
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(scalar @locations, 1);
    $self->assert_str_equals($locations[0]{name}, "On planet Earth");
    $self->assert_str_equals($locations[0]{uri}, "skype:foo");
}

sub test_getcalendarevents_locations_geo
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:Remember the yep.
GEO:37.386013;-122.08293
SEQUENCE:9
SUMMARY;LANGUAGE=en:Yep
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(scalar @locations, 1);
    $self->assert_str_equals($locations[0]{coordinates}, "geo:37.386013,-122.082930");
}

sub test_getcalendarevents_locations_apple
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $lid1 = "loc1";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:Remember the yep.
X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-APPLE-RADIUS=14140.1607181516;X-TITLE="a place in Vienna":geo:48.208304,16.371602
SEQUENCE:9
SUMMARY;LANGUAGE=en:Yep
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(scalar @locations, 1);
    $self->assert_str_equals($locations[0]{name}, "a place in Vienna");
    $self->assert_str_equals($locations[0]{coordinates}, "geo:48.208304,16.371602");
}

sub test_getcalendarevents_translations
    :min_version_3_0
{
    my ($self) = @_;

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $lid = "loc1";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:description.
SUMMARY;LANGUAGE=en:title
LOCATION;X-JMAP-ID=$lid:On planet Earth
X-JMAP-TRANSLATION;LANGUAGE=de;X-JMAP-PROP=title:Titel
X-JMAP-TRANSLATION;LANGUAGE=de;X-JMAP-PROP=description:Beschreibung
X-JMAP-TRANSLATION;LANGUAGE=de;X-JMAP-PROP=locations.name;X-JMAP-ID=$lid:Am Planet Erde
X-JMAP-TRANSLATION;LANGUAGE=de;X-JMAP-PROP=links.title;X-JMAP-ID=$lid:No such link
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_str_equals($event->{translations}{de}{title}, "Titel");
    $self->assert_str_equals($event->{translations}{de}{description}, "Beschreibung");
    $self->assert_str_equals($event->{translations}{de}{locations}{$lid}{name}, "Am Planet Erde");
    $self->assert_str_equals($event->{translations}{de}{links}{$lid}{title}, "No such link");
}

sub test_getcalendarevents_infinite_delegates
    :min_version_3_0
{
    my ($self) = @_;

    # makes sure that delegated partstats may not cause an endless loop

    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
SEQUENCE:9
SUMMARY:Moebian Delegates
LAST-MODIFIED:20150928T132434Z
ATTENDEE;PARTSTAT=DELEGATED;DELEGATED-FROM="mailto:lenny\@example.com";DELEGATED-TO="mailto:lenny\@example.com";CN=Carl Carlson:mailto:carl\@example.com
ATTENDEE;PARTSTAT=DELEGATED;DELEGATED-TO="mailto:carl\@example.com";CN=Lenny Leonard:mailto:lenny\@example.com
ORGANIZER;CN="Monty Burns":mailto:smithers\@example.com
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($id, $ical);
    my $scheduleStatus = $event->{participants}{"lenny\@example.com"}{scheduleStatus};
    $self->assert_str_equals($scheduleStatus, "needs-action");
}

sub createandget_event
{
    my ($self, $event) = @_;

    my $jmap = $self->{jmap};

    xlog "create event";
    my $res = $jmap->Request([['setCalendarEvents', {create => {"#1" => $event}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub updateandget_event
{
    my ($self, $event) = @_;

    my $jmap = $self->{jmap};
    my $id = $event->{id};

    xlog "update event $id";
    my $res = $jmap->Request([['setCalendarEvents', {update => {$id => $event}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub createcalendar
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    return $res->[0][1]{created}{"#1"}{id};
}


sub test_setcalendarevents_simple
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "relatedTo" => ["58ADE31-someother-UID"],
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "UTC",
        "isAllDay"=> JSON::false,
        "language" => "en",
        "status" => "tentative",
        "description"=> "",
        "showAsFree"=> JSON::false,
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    $self->assert_num_equals($event->{sequence}, 42);
}

sub test_setcalendarevents_prodid
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/Amsterdam",
        "isAllDay"=> JSON::false,
        "description"=> "",
        "showAsFree"=> JSON::false,
    };

    my $ret;

    # assert default prodId
    $ret = $self->createandget_event($event);
    $self->assert_not_null($ret->{prodId});

    # assert custom prodId
    my $prodId = "my prodId";
    $event->{prodId} = $prodId;
    $ret = $self->createandget_event($event);
    $self->assert_str_equals($prodId, $ret->{prodId});
}

sub test_setcalendarevents_endtimezone
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "description"=> "",
        "showAsFree"=> JSON::false,
        "prodId" => "foo",
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);

    $event->{locations} = {
        "loc1" => {
            "timeZone" => "Europe/Berlin",
            "rel" => "end",
        },
    };
    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarId => $event->{calendarId},
            locations => $event->{locations},

    });

    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_links
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/Vienna",
        "isAllDay"=> JSON::false,
        "description"=> "",
        "showAsFree"=> JSON::false,
        "links" => {
            "http://jmap.io/spec.html#calendar-events" => {
                href => "http://jmap.io/spec.html#calendar-events",
            },
            "https://tools.ietf.org/html/rfc5545" => {
               href => "https://tools.ietf.org/html/rfc5545",
            },
        },
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_translations
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $translations = {
        de => {
            title => "Titel",
            description => "Beschreibung",
            "locations" => {
                "loc1" => {
                    name => "Am Planet Erde",
                },
            },
            "links" => {
                "http://foo.local/" => {
                    title => "A fooish site",
                },
            },
        },
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "showAsFree"=> JSON::false,
        "translations" => $translations,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);

    $event->{translations} = undef;
    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarId => $event->{calendarId},
            translations => undef,
    });
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_locations
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $locations = {
        locA => {
            "name" => "location A",
            "address" => {
                "street" => "107 a street",
                "locality" => "a town",
                "region" => "",
                "postcode" => "4321",
                "country" => "republic of a",
            },
        },
        locB => {
            "name" => "location B",
            "rel" => "start",
            "uri" => "skype:username",
        },
        locC => {
            "coordinates" => "geo:48.208304,16.371602",
            "name" => "a place in Vienna",
        },
        locD => {
            "coordinates" => "geo:48.208304,16.371602",
        },
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "showAsFree"=> JSON::false,
        "locations" => $locations,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_recurrence
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $recurrence = {
        frequency => "monthly",
        interval => 2,
        firstDayOfWeek => "sunday",
        count => 1024,
        byDay => [{
                day => "monday",
                nthOfPeriod => -2,
            }, {
                day => "saturday",
        }],
    };


    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "showAsFree"=> JSON::false,
        "recurrenceRule" => $recurrence,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $recurrence->{skip} = "omit";
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_participants
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $participants = {
        "foo\@local" => {
            name => "",
            email => "foo\@local",
            roles => ["owner"],
        },
        "monty\@local" => {
            name => "Monty Burns",
            email => "monty\@local",
            roles => ["attendee"],
        },
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "showAsFree"=> JSON::false,
        "status" => "confirmed",
        "replyTo" => "foo\@local",
        "participants" => $participants,
    };

    my $ret = $self->createandget_event($event);

    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};

    $participants->{"monty\@local"}{scheduleStatus} = "needs-action";
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_alerts
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $alerts = {
        alert1 => {
            relativeTo => "before-start",
            offset => "PT5M",
            action => {
                type => "email",
                to => [{
                        name => "",
                        email => "foo\@example.com"
                    }],
                subject => "foo",
                textBody => "bar",
            },
        },
        alert2 => {
            relativeTo => "after-start",
            offset => "PT1H",
            action => { type => "display", },
        },
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "showAsFree"=> JSON::false,
        "status" => "confirmed",
        "alerts" => $alerts,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_setcalendarevents_isallday
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $event = {
        "calendarId" => "Default",
        "title" => "foo",
        "description" => "foo's description",
        "showAsFree" => JSON::false,
        "isAllDay" => JSON::true,
    };

    my $res;

    xlog "create event (with erroneous start)";
    $event->{start} = "2015-10-06T16:45:00",
    $res = $jmap->Request([['setCalendarEvents', { create => {
        "#1" => $event,
    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notCreated}{"#1"}{type}, "invalidProperties");

    xlog "create event (with erroneous timeZone)";
    $event->{start} = "2015-10-06T00:00:00";
    $event->{timeZone} = "Europe/Vienna";
    $res = $jmap->Request([['setCalendarEvents', { create => {
        "#1" => $event,
    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notCreated}{"#1"}{type}, "invalidProperties");

    xlog "create event (with erroneous duration)";
    $event->{start} = "2015-10-06T00:00:00";
    $event->{timeZone} = undef;
    $event->{duration} = "PT15M";
    $res = $jmap->Request([['setCalendarEvents', { create => {
        "#1" => $event,
    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notCreated}{"#1"}{type}, "invalidProperties");

    xlog "create event";
    $event->{start} = "2015-10-06T00:00:00";
    $event->{timeZone} = undef;
    $event->{duration} = "P1D";
    $res = $jmap->Request([['setCalendarEvents', { create => {
        "#1" => $event,
    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"#1"});
}

sub test_setcalendarevents_move
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendars A and B";
    my $res = $jmap->Request([
            ['setCalendars', { create => {
                        "#1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                        },
                        "#2" => {
                            name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]
    ]);
    my $calidA = $res->[0][1]{created}{"#1"}{id};
    my $calidB = $res->[0][1]{created}{"#2"}{id};

    xlog "create event in calendar $calidA";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "foo's description",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        }
                    }}, "R1"]]);
    my $state = $res->[0][1]{newState};
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{calendarId}, $calidA);
    $self->assert_str_equals($res->[0][1]{state}, $state);

    xlog "move event to unknown calendar";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "calendarId" => "nope",
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "calendarNotFound");
    $self->assert_str_equals($res->[0][1]{newState}, $state);

    xlog "get calendar $id from untouched calendar $calidA";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{calendarId}, $calidA);

    xlog "move event to calendar $calidB";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "calendarId" => $calidB,
                        }
                    }}, "R1"]]);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $state = $res->[0][1]{newState};

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{calendarId}, $calidB);
}

sub test_getcalendareventupdates
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendars A and B";
    my $res = $jmap->Request([
            ['setCalendars', { create => {
                        "#1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                        },
                        "#2" => {
                            name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]
    ]);
    my $calidA = $res->[0][1]{created}{"#1"}{id};
    my $calidB = $res->[0][1]{created}{"#2"}{id};
    my $state = $res->[0][1]{newState};

    xlog "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calidA,
                            "title" => "1",
                            "description" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        },
                        "#2" => {
                            "calendarId" => $calidB,
                            "title" => "2",
                            "description" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};

    xlog "get calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 2);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "get zero calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', {sinceState => $state}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 0);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "update event #1 and #2";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id1 => {
                            "calendarId" => $calidA,
                            "title" => "1(updated)",
                        },
                        $id2 => {
                            "calendarId" => $calidB,
                            "title" => "2(updated)",
                        }
                    }}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{updated}}, 2);

    xlog "get exactly one update";
    $res = $jmap->Request([['getCalendarEventUpdates', {
                    sinceState => $state,
                    maxChanges => 1
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::true);
    $state = $res->[0][1]{newState};

    xlog "get the final update";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "update event #1 and destroy #2";
    $res = $jmap->Request([['setCalendarEvents', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidA,
                            "title" => "1(updated)",
                            "description" => "",
                        },
                    },
                    destroy => [ $id2 ]
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{updated}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{destroyed}}, 1);

    xlog "get calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 1);
    $self->assert_str_equals($res->[0][1]{removed}[0], $id2);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "get zero calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', {sinceState => $state}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 0);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "move event #1 from calendar $calidA to $calidB";
    $res = $jmap->Request([['setCalendarEvents', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidB,
                        },
                    }
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{updated}}, 1);

    xlog "get calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "update and remove event #1";
    $res = $jmap->Request([['setCalendarEvents', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidB,
                            "title" => "1(goodbye)",
                        },
                    },
                    destroy => [ $id1 ]
                }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{destroyed}}, 1);

    xlog "get calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 0);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 1);
    $self->assert_str_equals($res->[0][1]{removed}[0], $id1);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};
}

sub test_getcalendareventlist
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendars A and B";
    my $res = $jmap->Request([
            ['setCalendars', { create => {
                        "#1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                        },
                        "#2" => {
                            name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]
    ]);
    my $calidA = $res->[0][1]{created}{"#1"}{id};
    my $calidB = $res->[0][1]{created}{"#2"}{id};
    my $state = $res->[0][1]{newState};

    xlog "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "bar",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "timeZone" => undef,
                        },
                        "#2" => {
                            "calendarId" => $calidB,
                            "title" => "foo",
                            "description" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};

    xlog "get unfiltered calendar event list";
    $res = $jmap->Request([ ['getCalendarEventList', { }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{calendarEventIds}}, 2);

    xlog "get filtered calendar event list with flat filter";
    $res = $jmap->Request([ ['getCalendarEventList', {
                    "filter" => {
                        "after" => "2015-01-01T00:00:00Z",
                        "before" => "2015-12-31T23:59:59Z",
                        "text" => "foo",
                        "description" => "bar"
                    }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{calendarEventIds}}, 1);
    $self->assert_str_equals($res->[0][1]{calendarEventIds}[0], $id1);

    xlog "get filtered calendar event list";
    $res = $jmap->Request([ ['getCalendarEventList', {
                    "filter" => {
                        "operator" => "AND",
                        "conditions" => [
                            {
                                "after" => "2015-01-01T00:00:00Z",
                                "before" => "2015-12-31T23:59:59Z"
                            },
                            {
                                "text" => "foo",
                                "description" => "bar"
                            }
                        ]
                    }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{calendarEventIds}}, 1);
    $self->assert_str_equals($res->[0][1]{calendarEventIds}[0], $id1);
}

sub test_setcalendarevents_caldav
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendar";
    my $res = $jmap->Request([
            ['setCalendars', { create => {
                        "#1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]]);
    my $calid = $res->[0][1]{created}{"#1"}{id};

    xlog "create event in calendar";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "title" => "foo",
                            "description" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get x-href of event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $xhref = $res->[0][1]{list}[0]{"x-href"};
    my $state = $res->[0][1]{state};

    xlog "GET event $id in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    my $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:foo/, $ical);

    xlog "DELETE event $id via CalDAV";
    $res = $caldav->Request('DELETE', $xhref);

    xlog "get (non-existent) event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);

    xlog "get calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 1);
    $self->assert_str_equals($res->[0][1]{removed}[0], $id);
    $state = $res->[0][1]{newState};

    $id = '97c46ea4-4182-493c-87ef-aee4edc2d38b';
    $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:$id
SUMMARY:bar
DESCRIPTION:
TRANSP:OPAQUE
DTSTART;VALUE=DATE:20151008
DTEND;VALUE=DATE:20151009
END:VEVENT
END:VCALENDAR
EOF

    xlog "PUT event with UID $id";
    $res = $caldav->Request('PUT', "$calid/$id.ics", $ical, 'Content-Type' => 'text/calendar');

    xlog "get calendar event updates";
    $res = $jmap->Request([['getCalendarEventUpdates', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_equals($res->[0][1]{changed}[0], $id);
    $state = $res->[0][1]{newState};

    xlog "get x-href of event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $xhref = $res->[0][1]{list}[0]{"x-href"};
    $state = $res->[0][1]{state};

    xlog "update event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "calendarId" => $calid,
                            "title" => "bam",
                            "description" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-10T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-11T00:00:00",
                            "endTimeZone" => undef
                        }
                    }}, "R1"]]);

    xlog "GET event $id in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:bam/, $ical);

    xlog "destroy event $id";
    $res = $jmap->Request([['setCalendarEvents', { destroy => [$id] }, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{destroyed}}, 1);
    $self->assert_equals($res->[0][1]{destroyed}[0], $id);

    xlog "PROPFIND calendar $calid for non-existent event $id in CalDAV";
    # We'd like to GET the just destroyed event, to make sure that it also
    # vanished on the CalDAV layer. Unfortunately, that GET would cause
    # Net-DAVTalk to burst into flames with a 404 error. Instead, issue a
    # PROPFIND and make sure that the event id doesn't show  in the returned
    # DAV resources.
    my $xml = <<EOF;
<?xml version="1.0"?>
<a:propfind xmlns:a="DAV:">
 <a:prop><a:resourcetype/></a:prop>
</a:propfind>
EOF
    $res = $caldav->Request('PROPFIND', "$calid", $xml,
        'Content-Type' => 'application/xml',
        'Depth' => '1'
    );
    $self->assert($res !~ "$id");
}

sub test_setcalendarevents_schedule_request
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $participants = {
        "org" => {
            "name" => "Cassandane",
            "email" => "cassandane\@example.com",
            "roles" => ["owner"],
        },
        "att" => {
            "name" => "Bugs Bunny",
            "email" => "bugs\@example.com",
            "roles" => ["attendee"],
        },
    };

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "send invitation as organizer to attendee";
    my $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => "Default",
                            "title" => "foo",
                            "description" => "foo's description",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "timeZone" => "Australia/Melbourne",
                            "duration" => "PT1H",
                            "replyTo" => "cassandane\@example.com",
                            "participants" => $participants,
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals($payload->{recipient}, "bugs\@example.com");
    $self->assert($ical =~ "METHOD:REQUEST");

    my $attendee;
    # Line breaks are a bit brittle due to iCalendar line folding
    my @lines = split /\r\n/, $ical;
    foreach my $line (@lines) {
        xlog "$line";
        if ($line =~ /ATTENDEE/) {
            $attendee = $line;
            last;
        }
    }
    $self->assert_not_null($attendee);
    $self->assert($attendee =~ /PARTSTAT=NEEDS-ACTION/);
}

sub test_setcalendarevents_schedule_reply
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $participants = {
        "org" => {
            "name" => "Bugs Bunny",
            "email" => "bugs\@example.com",
            "roles" => ["owner"],
        },
        "att" => {
            "name" => "Cassandane",
            "email" => "cassandane\@example.com",
            "roles" => ["attendee"],
        },
    };

    xlog "create event";
    my $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => "Default",
                            "title" => "foo",
                            "description" => "foo's description",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "timeZone" => "Australia/Melbourne",
                            "duration" => "PT1H",
                            "replyTo" => "bugs\@example.com",
                            "participants" => $participants,
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "send reply as attendee to organizer";
    $participants->{att}->{scheduleStatus} = "tentative";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            replyTo => "bugs\@example.com",
                            participants => $participants,
                        }
                    }}, "R1"]]);


    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals($payload->{recipient}, "bugs\@example.com");
    $self->assert($ical =~ "METHOD:REPLY");

    my $attendee;
    # Line breaks are a bit brittle due to iCalendar line folding
    my @lines = split /\r\n/, $ical;
    foreach my $line (@lines) {
        xlog "$line";
        if ($line =~ /ATTENDEE/) {
            $attendee = $line;
            last;
        }
    }
    $self->assert_not_null($attendee);
    $self->assert($attendee =~ /PARTSTAT=TENTATIVE/);
}

sub test_setcalendarevents_schedule_cancel
    :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendar";
    my $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    my $calid = $res->[0][1]{created}{"#1"}{id};

    xlog "send invitation as organizer";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "title" => "foo",
                            "description" => "foo's description",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "timeZone" => "Australia/Melbourne",
                            "duration" => "PT15M",
                            "replyTo" => "cassandane\@example.com",
                            "participants" => {
                                "org" => {
                                    "name" => "Cassandane",
                                    "email" => "cassandane\@example.com",
                                    "roles" => ["owner"],
                                },
                                "att" => {
                                    "name" => "Bugs Bunny",
                                    "email" => "bugs\@example.com",
                                    "roles" => ["attendee"],
                                },
                            },
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};
    $self->assert_not_null($id);

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "cancel event as organizer";
    $res = $jmap->Request([['setCalendarEvents', { destroy => [$id]}, "R1"]]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals($payload->{recipient}, "bugs\@example.com");
    $self->assert($ical =~ "METHOD:CANCEL");
}

1;
