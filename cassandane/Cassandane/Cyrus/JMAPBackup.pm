#!/usr/bin/perl
#
#  Copyright (c) 2011-2019 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::JMAPBackup;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use XML::Spice;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 caldav_historical_age => -1,
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no',
                 jmap_nonstandard_extensions => 'yes');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/backup',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);
}

sub test_restore_contacts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "a" => {firstName => "a", lastName => "a"},
                        "b" => {firstName => "b", lastName => "b"},
                        "c" => {firstName => "c", lastName => "c"},
                        "d" => {firstName => "d", lastName => "d"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $contactA = $res->[0][1]{created}{"a"}{id};
    my $contactB = $res->[0][1]{created}{"b"}{id};
    my $contactC = $res->[0][1]{created}{"c"}{id};
    my $contactD = $res->[0][1]{created}{"d"}{id};

    xlog "destroy contact A, update contact B";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactA],
                    update => {$contactB => {firstName => "B"}}
                }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);

    xlog "get contacts";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['firstName', 'lastName'],
         }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);

    my @expect = sort { $a->{firstName} cmp $b->{firstName} } @{$res->[0][1]{list}};

    sleep 1;
    xlog "destroy contact C, update contacts B and D, create contact E";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactC],
                    update => {
                        $contactB => {lastName => "B"},
                        $contactD => {lastName => "D"},
                    },
                    create => {
                        "e" => {firstName => "e", lastName => "e"}
                    }
                }, "R4"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R4', $res->[0][2]);
    my $contactE = $res->[0][1]{created}{"e"}{id};
    my $state = $res->[0][1]{newState};

    xlog "restore contacts prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreContacts', {
                    undoPeriod => "PT1S",
                    undoCreate => JSON::true,
                    undoUpdate => JSON::true,
                    undoDestroy => JSON::true
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

    xlog "get restored contacts";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['firstName', 'lastName'],
         }, "R6"],
        ['ContactGroup/get', {}, "R6.1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R6', $res->[0][2]);

    my @got = sort { $a->{firstName} cmp $b->{firstName} } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar @expect, scalar @got);
    $self->assert_deep_equals(\@expect, \@got);

    $self->assert_str_equals('ContactGroup/get', $res->[1][0]);
    $self->assert_str_equals('R6.1', $res->[1][2]);
    $self->assert_str_equals($contactC, $res->[1][1]{list}[0]{contactIds}[0]);

    xlog "get contact updates";
    $res = $jmap->CallMethods([
        ['Contact/changes', {
            sinceState => $state
         }, "R6.5"],
        ['ContactGroup/changes', {
            sinceState => $state
         }, "R6.6"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/changes', $res->[0][0]);
    $self->assert_str_equals('R6.5', $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($contactC, $res->[0][1]{created}[0]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($contactE, $res->[0][1]{destroyed}[0]);

    $self->assert_str_equals('ContactGroup/changes', $res->[1][0]);
    $self->assert_str_equals('R6.6', $res->[1][2]);
    $self->assert_str_equals($state, $res->[1][1]{oldState});
    $self->assert_str_not_equals($state, $res->[1][1]{newState});
    $self->assert_equals(JSON::false, $res->[1][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{destroyed}});
    $state = $res->[1][1]{newState};

    xlog "restore contacts to before initial creation";
    $res = $jmap->CallMethods([['Backup/restoreContacts', {
                    undoPeriod => "P1D",
                    undoCreate => JSON::true,
                    undoUpdate => JSON::true,
                    undoDestroy => JSON::true
                }, "R7"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(4, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numDestroysUndone});

    xlog "get restored contacts";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['firstName', 'lastName'],
         }, "R8"],
        ['ContactGroup/get', {}, "R8.1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R8', $res->[0][2]);
    $self->assert_deep_equals([], $res->[0][1]{list});

    $self->assert_str_equals('ContactGroup/get', $res->[1][0]);
    $self->assert_str_equals('R8.1', $res->[1][2]);
    $self->assert_deep_equals([], $res->[1][1]{list});

    xlog "get contact updates";
    $res = $jmap->CallMethods([
        ['Contact/changes', {
            sinceState => $state
         }, "R8.5"],
        ['ContactGroup/changes', {
            sinceState => $state
         }, "R8.6"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/changes', $res->[0][0]);
    $self->assert_str_equals('R8.5', $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(3, scalar @{$res->[0][1]{destroyed}});

    $self->assert_str_equals('ContactGroup/changes', $res->[1][0]);
    $self->assert_str_equals('R8.6', $res->[1][2]);
    $self->assert_str_equals($state, $res->[1][1]{oldState});
    $self->assert_str_not_equals($state, $res->[1][1]{newState});
    $self->assert_equals(JSON::false, $res->[1][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{updated}});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{destroyed}});
    $state = $res->[1][1]{newState};
}

sub test_restore_calendars
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                "1" => {
                    name => "foo",
                    color => "coral",
                    sortOrder => 1,
                    isVisible => \1
                },
                "2" => {
                    name => "bar",
                    color => "aqua",
                    sortOrder => 2,
                    isVisible => \1
                }
            }
         }, "R1"]
    ]);
    my $calid = $res->[0][1]{created}{"1"}{id};
    my $calid2 = $res->[0][1]{created}{"2"}{id};

    xlog "send invitation as organizer";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    "calendarId" => $calid,
                    "title" => "foo",
                    "description" => "foo's description",
                    "freeBusyStatus" => "busy",
                    "showWithoutTime" => JSON::false,
                    "start" => "2015-10-06T16:45:00",
                    "timeZone" => "Australia/Melbourne",
                    "duration" => "PT15M",
                    "replyTo" => {
                        imip => "mailto:cassandane\@example.com",
                    },
                    "participants" => {
                        "org" => {
                            "name" => "Cassandane",
                            "email" => "cassandane\@example.com",
                            roles => {
                                'owner' => JSON::true,
                            },
                        },
                        "att" => {
                            "name" => "Bugs Bunny",
                            "email" => "bugs\@example.com",
                            roles => {
                                'attendee' => JSON::true,
                            },
                        },
                    },
                },
                "2" => {
                    "calendarId" => $calid2,
                    "title" => "bar",
                    "description" => "bar's description",
                    "freeBusyStatus" => "busy",
                    "showWithoutTime" => JSON::false,
                    "start" => "2019-10-06T16:45:00",
                    "timeZone" => "Australia/Melbourne",
                    "duration" => "PT15M",
                    "replyTo" => {
                        imip => "mailto:cassandane\@example.com",
                    },
                    "participants" => {
                        "org" => {
                            "name" => "Cassandane",
                            "email" => "cassandane\@example.com",
                            roles => {
                                'owner' => JSON::true,
                            },
                        },
                        "att" => {
                        "name" => "Bugs Bunny",
                        "email" => "bugs\@example.com",
                        roles => {
                            'attendee' => JSON::true,
                        },
                    },
                },
            }
        }}, "R1"]
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);
    $self->assert(exists $res->[0][1]{created}{'2'});

    sleep 1;
    xlog "update event title";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $id => { 'title' => "foo2", 'sequence' => 1 },
            },
         }, 'R2'],
        ['Calendar/set', {
            destroy => ["$calid2"]
         }, "R2.5"],
        ['CalendarEvent/get', {
            properties => ['title', 'sequence'],
         }, 'R3'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});
    $self->assert_str_equals($calid2, $res->[1][1]{destroyed}[0]);
    $self->assert_num_equals(1, scalar(@{$res->[2][1]{list}}));
    $self->assert_str_equals('foo2', $res->[2][1]{list}[0]{title});

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "restore calendar prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreCalendars', {
            undoPeriod => "PT1S",
            undoCreate => JSON::true,
            undoUpdate => JSON::true,
            undoDestroy => JSON::true
         }, "R4"],
        ['CalendarEvent/get', {
            properties => ['title', 'sequence'],
         }, "R5"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreCalendars', $res->[0][0]);
    $self->assert_str_equals('R4', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

    $self->assert_str_equals('CalendarEvent/get', $res->[1][0]);
    $self->assert_str_equals('R5', $res->[1][2]);
    $self->assert_num_equals(2, scalar(@{$res->[1][1]{list}}));

    my @got = sort { $a->{title} cmp $b->{title} } @{$res->[1][1]{list}};
    $self->assert_str_equals('bar', $got[0]{title});
    $self->assert_str_equals('foo', $got[1]{title});
    $self->assert_num_equals(2, $got[1]{sequence});

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:REQUEST");

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "restore calendar to before initial creation";
    $res = $jmap->CallMethods([
        ['Backup/restoreCalendars', {
            undoPeriod => "P1D",
            undoCreate => JSON::true,
            undoUpdate => JSON::true,
            undoDestroy => JSON::true
         }, "R6"],
        ['CalendarEvent/get', {
            properties => ['title'],
         }, "R7"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreCalendars', $res->[0][0]);
    $self->assert_str_equals('R6', $res->[0][2]);
    $self->assert_num_equals(2, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numDestroysUndone});

    $self->assert_str_equals('CalendarEvent/get', $res->[1][0]);
    $self->assert_str_equals('R7', $res->[1][2]);
    $self->assert_deep_equals([], $res->[1][1]{list});

    $data = $self->{instance}->getnotify();
    ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    $payload = decode_json($imip->{MESSAGE});
    $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:CANCEL");
}

1;
