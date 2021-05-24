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
                 notesmailbox => 'Notes',
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
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/backup',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/notes',
    ]);
}

sub test_restore_contacts
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "a" => {firstName => "a", lastName => "a"},
                        "b" => {firstName => "b", lastName => "b"},
                        "c" => {firstName => "c", lastName => "c"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $contactA = $res->[0][1]{created}{"a"}{id};
    my $contactB = $res->[0][1]{created}{"b"}{id};
    my $contactC = $res->[0][1]{created}{"c"}{id};

    xlog "destroy contact C";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactC]
                }, "R1.5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1.5', $res->[0][2]);

    xlog "dry-run restore contacts prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreContacts', {
                    undoPeriod => "P1D",
                    performDryRun => JSON::true,
                    undoAll => JSON::false
                }, "R1.7"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R1.7', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

    sleep 2;
    xlog "destroy contact A, update contact B, create contact D";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactA],
                    update => {$contactB => {firstName => "B"}},
                    create => {"d" => {firstName => "d", lastName => "d"}}
                }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    my $contactD = $res->[0][1]{created}{"d"}{id};

    xlog "destroy contact D, create contact E";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$contactD],
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
                    undoPeriod => "PT2S",
                    undoAll => JSON::false
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numDestroysUndone});

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
    $self->assert_num_equals(4, scalar @got);
    $self->assert_str_equals('B', $got[0]{firstName});
    $self->assert_str_equals('a', $got[1]{firstName});
    $self->assert_str_equals('d', $got[2]{firstName});
    $self->assert_str_equals('e', $got[3]{firstName});

    $self->assert_str_equals('ContactGroup/get', $res->[1][0]);
    $self->assert_str_equals('R6.1', $res->[1][2]);
    $self->assert_num_equals(2, scalar @{$res->[1][1]{list}[0]{contactIds}});

    my %contactIds = map { $_ => 1 } @{$res->[1][1]{list}[0]{contactIds}};
    $self->assert_not_null($contactIds{$contactA});
    $self->assert_not_null($contactIds{$contactD});

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
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    %contactIds = map { $_ => 1 } @{$res->[0][1]{created}};
    $self->assert_not_null($contactIds{$contactA});
    $self->assert_not_null($contactIds{$contactD});

    $self->assert_str_equals('ContactGroup/changes', $res->[1][0]);
    $self->assert_str_equals('R6.6', $res->[1][2]);
    $self->assert_str_equals($state, $res->[1][1]{oldState});
    $self->assert_str_not_equals($state, $res->[1][1]{newState});
    $self->assert_equals(JSON::false, $res->[1][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{destroyed}});
    $state = $res->[1][1]{newState};

    xlog "try to re-restore contacts prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreContacts', {
                    undoPeriod => "PT2S",
                    performDryRun => JSON::true,
                    undoAll => JSON::false
                }, "R7"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numDestroysUndone});
}

sub test_restore_contacts_all
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    sleep 2;
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
                    undoAll => JSON::true
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
                    undoPeriod => "PT3S",
                    undoAll => JSON::true
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

sub test_restore_contacts_all_dryrun
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    sleep 2;
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
                    performDryRun => JSON::true,
                    undoPeriod => "PT1S",
                    undoAll => JSON::true
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreContacts', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

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
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    $self->assert_str_equals('ContactGroup/changes', $res->[1][0]);
    $self->assert_str_equals('R6.6', $res->[1][2]);
    $self->assert_str_equals($state, $res->[1][1]{oldState});
    $self->assert_str_equals($state, $res->[1][1]{newState});
    $self->assert_equals(JSON::false, $res->[1][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{destroyed}});
}

sub test_restore_calendars_all
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendars";
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
                            roles => {
                                'owner' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        "att" => {
                            "name" => "Bugs Bunny",
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:bugs@example.com',
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
                            roles => {
                                'owner' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        "att" => {
                            "name" => "Bugs Bunny",
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:bugs@example.com',
                            },
                    },
                },
            }
        }}, "R1"]
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);
    $self->assert(exists $res->[0][1]{created}{'2'});

    sleep 2;
    xlog "update an event title and delete a calendar";
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

    xlog "restore calendars prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreCalendars', {
            undoPeriod => "PT2S",
            undoAll => JSON::true
         }, "R4"],
        ['CalendarEvent/get', {
            properties => ['title', 'sequence', 'calendarId'],
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

    xlog "check that the restored calendar has correct name and color";
    $res = $jmap->CallMethods([
        ['Calendar/get', {
            ids => [$got[0]{calendarId}],
            properties => ['name', 'color'],
         }, "R5.5"]
    ]);
    $self->assert_str_equals('bar', $res->[0][1]{list}[0]{name});
    $self->assert_str_equals('aqua', $res->[0][1]{list}[0]{color});

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:REQUEST");

    xlog "try to restore calendar to before initial creation";
    $res = $jmap->CallMethods([
        ['Backup/restoreCalendars', {
            undoPeriod => "P1D",
            undoAll => JSON::true
         }, "R6"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
    $self->assert_str_equals('R6', $res->[0][2]);
}

sub test_restore_calendars_all_dryrun
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendars";
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
                            roles => {
                                'owner' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        "att" => {
                            "name" => "Bugs Bunny",
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:bugs@example.com',
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
                            roles => {
                                'owner' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        "att" => {
                            "name" => "Bugs Bunny",
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:bugs@example.com',
                            },
                    },
                },
            }
        }}, "R1"]
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);
    $self->assert(exists $res->[0][1]{created}{'2'});

    sleep 2;
    xlog "update an event title and delete a calendar";
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

    xlog "restore calendars prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreCalendars', {
            performDryRun => JSON::true,
            undoPeriod => "PT2S",
            undoAll => JSON::true
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
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals('foo2', $res->[1][1]{list}[0]{title});

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($imip);
}

sub test_restore_mail_simple
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create email in Inbox";
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
         }, "R1"]
    ]);

    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    my $inboxId = $res->[0][1]{list}[0]{id};

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        $inboxId => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1"
                }
            },
        }, 'R2'],
        ['Email/get', {
            ids => [ '#email1' ],
            properties => ['receivedAt']
         }, "R3"]
    ]);
    my $emailId1 = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId1);
    my $emailAt1 = $res->[1][1]{list}[0]{receivedAt};

    xlog "create new mailbox";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "1" => {
                    name => "foo"
                }
            }
         }, "R4"],
    ]);
    $self->assert_not_null($res);
    my $fooId = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($fooId);

    xlog "move email from Inbox to foo";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId1 => {
                "mailboxIds/$inboxId" => undef,
                "mailboxIds/$fooId" => JSON::true
                } }
         }, "R5"]
    ]);

    sleep 1;
    xlog "destroy 'foo' mailbox";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => ["$fooId"],
            onDestroyRemoveEmails => JSON::true
         }, "R6"],
    ]);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{destroyed}}));
    $self->assert_str_equals($fooId, $res->[0][1]{destroyed}[0]);

    xlog "perform a dry-run restoration of mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            performDryRun => JSON::true,
            restoreDrafts => JSON::false,
            restoreNonDrafts => JSON::true,
            undoPeriod => "PT1H"
         }, "R7.1"],
        ['Mailbox/get', {
         }, "R8.1"],
        ['Email/get', {
            ids => ["$emailId1"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R9.1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R7.1', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(1, $res->[0][1]{numNonDraftsRestored});

    $self->assert_str_equals('Mailbox/get', $res->[1][0]);
    $self->assert_str_equals('R8.1', $res->[1][2]);
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("Inbox", $res->[1][1]{list}[0]{name});

    $self->assert_str_equals('Email/get', $res->[2][0]);
    $self->assert_str_equals('R9.1', $res->[2][2]);
    $self->assert_num_equals(0, scalar(@{$res->[2][1]{list}}));
    $self->assert_str_equals("$emailId1", $res->[2][1]{notFound}[0]);

    xlog "actually restore mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            restoreDrafts => JSON::false,
            restoreNonDrafts => JSON::true,
            undoPeriod => "PT1H"
         }, "R7"],
        ['Mailbox/get', {
         }, "R8"],
        ['Email/get', {
            ids => ["$emailId1"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R9"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(1, $res->[0][1]{numNonDraftsRestored});

    $self->assert_str_equals('Mailbox/get', $res->[1][0]);
    $self->assert_str_equals('R8', $res->[1][2]);
    $self->assert_num_equals(2, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("foo", $res->[1][1]{list}[1]{name});
    my $newFooId = $res->[1][1]{list}[1]{id};

    $self->assert_str_equals('Email/get', $res->[2][0]);
    $self->assert_str_equals('R9', $res->[2][2]);
    $self->assert_num_equals(1, scalar(@{$res->[2][1]{list}}));
    $self->assert_str_equals("$emailId1", $res->[2][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt1", $res->[2][1]{list}[0]{receivedAt});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{mailboxIds}{$newFooId});
    $self->assert_null($res->[2][1]{list}[0]{mailboxIds}->{$inboxId});

    xlog "attempt to re-restore mailbox back to same point in time";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            restoreDrafts => JSON::false,
            restoreNonDrafts => JSON::true,
            undoPeriod => "PT1H"
         }, "R10"],
        ['Email/get', {
            ids => ["$emailId1"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R11"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R10', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(0, $res->[0][1]{numNonDraftsRestored});

    $self->assert_str_equals('Email/get', $res->[1][0]);
    $self->assert_str_equals('R11', $res->[1][2]);
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("$emailId1", $res->[1][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt1", $res->[1][1]{list}[0]{receivedAt});
    $self->assert_null($res->[1][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$newFooId});
    $self->assert_null($res->[1][1]{list}[0]{mailboxIds}->{$inboxId});
}

sub test_restore_mail_draft_sent
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                '1' => { name => 'Drafts', parentId => undef },
                '2' => { name => 'Sent', parentId => undef  }
            }
         }, "R1"]
    ]);

    my $draftsId = $res->[0][1]{created}{1}{id};
    my $sentId = $res->[0][1]{created}{2}{id};

    xlog "create draft email";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        $draftsId => JSON::true
                    },
                    keywords => {
                        '$draft' => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1"
                }
            },
        }, 'R2']
    ]);

    my $emailId = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId);

    xlog "move email from Drafts to Sent";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$draftsId" => undef,
                "mailboxIds/$sentId" => JSON::true,
                'keywords/$draft' => undef
                } }
         }, "R5"]
    ]);

    sleep 1;
    xlog "destroy 'Sent' email";
    $res = $jmap->CallMethods([
        ['Email/set', {
            destroy => ["$emailId"]
         }, "R6"],
    ]);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{destroyed}}));
    $self->assert_str_equals($emailId, $res->[0][1]{destroyed}[0]);

    xlog "restore mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            restoreDrafts => JSON::true,
            restoreNonDrafts => JSON::true,
            undoPeriod => "PT1H"
         }, "R7"],
        ['Email/get', {
            ids => ["$emailId"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R8"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(1, $res->[0][1]{numNonDraftsRestored});

    $self->assert_str_equals('Email/get', $res->[1][0]);
    $self->assert_str_equals('R8', $res->[1][2]);
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("$emailId", $res->[1][1]{list}[0]{id});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_null($res->[1][1]{list}[0]{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$sentId});
    $self->assert_null($res->[1][1]{list}[0]{mailboxIds}->{$draftsId});
}

sub test_restore_mail_submailbox
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create mailbox tree";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                'A' => { name => 'A', parentId => undef },
                'B' => { name => 'B', parentId => '#A'  },
                'C' => { name => 'C', parentId => '#B'  }
            }
         }, "R1"]
    ]);

    my $aId = $res->[0][1]{created}{A}{id};
    my $bId = $res->[0][1]{created}{B}{id};
    my $cId = $res->[0][1]{created}{C}{id};

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        $cId => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1"
                }
            },
        }, 'R2'],
        ['Email/get', {
            ids => [ '#email1' ],
            properties => ['receivedAt']
         }, "R3"]
    ]);
    my $emailId1 = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId1);
    my $emailAt1 = $res->[1][1]{list}[0]{receivedAt};

    xlog "destroy 'C' mailbox and its ancestors";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            destroy => ["$cId", "$bId", "$aId"],
            onDestroyRemoveEmails => JSON::true
         }, "R6"],
    ]);
    $self->assert_num_equals(3, scalar(@{$res->[0][1]{destroyed}}));
    $self->assert_str_equals($cId, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($bId, $res->[0][1]{destroyed}[1]);
    $self->assert_str_equals($aId, $res->[0][1]{destroyed}[2]);

    xlog "restore mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            undoPeriod => "PT1H"
         }, "R7"],
        ['Mailbox/get', {
         }, "R8"],
        ['Email/get', {
            ids => ["$emailId1"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R9"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(1, $res->[0][1]{numNonDraftsRestored});

    # Make sure that the proper mailbox tree was reconstructed
    $self->assert_str_equals('Mailbox/get', $res->[1][0]);
    $self->assert_str_equals('R8', $res->[1][2]);
    $self->assert_num_equals(4, scalar(@{$res->[1][1]{list}}));

    $self->assert_str_equals("A", $res->[1][1]{list}[1]{name});
    my $newAId = $res->[1][1]{list}[1]{id};

    $self->assert_str_equals("B", $res->[1][1]{list}[2]{name});
    my $newBId = $res->[1][1]{list}[2]{id};
    $self->assert_str_equals("$newAId", $res->[1][1]{list}[2]{parentId});

    $self->assert_str_equals("C", $res->[1][1]{list}[3]{name});
    my $newCId = $res->[1][1]{list}[3]{id};
    $self->assert_str_equals("$newBId", $res->[1][1]{list}[3]{parentId});

    $self->assert_str_equals('Email/get', $res->[2][0]);
    $self->assert_str_equals('R9', $res->[2][2]);
    $self->assert_num_equals(1, scalar(@{$res->[2][1]{list}}));
    $self->assert_str_equals("$emailId1", $res->[2][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt1", $res->[2][1]{list}[0]{receivedAt});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{mailboxIds}{$newCId});
}

sub test_restore_mail_exists
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create email in Inbox";
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
         }, "R1"]
    ]);

    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    my $inboxId = $res->[0][1]{list}[0]{id};

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        $inboxId => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1"
                }
            },
        }, 'R2'],
        ['Email/get', {
            ids => [ '#email1' ],
            properties => ['receivedAt']
         }, "R3"]
    ]);
    my $emailId1 = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId1);
    my $emailAt1 = $res->[1][1]{list}[0]{receivedAt};

    xlog "create new mailbox";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "1" => {
                    name => "foo"
                }
            }
         }, "R4"],
    ]);
    $self->assert_not_null($res);
    my $fooId = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($fooId);

    xlog "move email from Inbox to foo";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId1 => {
                "mailboxIds/$inboxId" => undef,
                "mailboxIds/$fooId" => JSON::true
                } }
         }, "R5"]
    ]);

    sleep 1;
    xlog "actually restore mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            undoPeriod => "PT1H"
         }, "R7"],
        ['Email/get', {
            ids => ["$emailId1"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R9"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(0, $res->[0][1]{numNonDraftsRestored});

    $self->assert_str_equals('Email/get', $res->[1][0]);
    $self->assert_str_equals('R9', $res->[1][2]);
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("$emailId1", $res->[1][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt1", $res->[1][1]{list}[0]{receivedAt});
    $self->assert_null($res->[1][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$fooId});
    $self->assert_null($res->[1][1]{list}[0]{mailboxIds}->{$inboxId});
}

sub test_restore_mail_full
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "1" => {
                    name => "foo"
                },
                "3" => {
                    name => "bar"
                },
                "2" => {
                    name => "Drafts",
                    role => "Drafts"
                }
            }
         }, "R1"],
        ['Mailbox/get', {
         }, "R2"]
    ]);
    $self->assert_not_null($res);
    my $fooId = $res->[0][1]{created}{"1"}{id};
    my $barId = $res->[0][1]{created}{"3"}{id};
    my $draftsId = $res->[0][1]{created}{"2"}{id};
    $self->assert_not_null($fooId);
    $self->assert_not_null($barId);
    $self->assert_not_null($draftsId);

    $self->assert_num_equals(4, scalar(@{$res->[1][1]{list}}));
    my %m = map { $_->{name} => $_ } @{$res->[1][1]{list}};
    my $inboxId = $m{"Inbox"}->{id};
    $self->assert_not_null($inboxId);

    xlog "create emails in Inbox";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        $inboxId => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1"
                },
                email2 => {
                    mailboxIds => {
                        $inboxId => JSON::true,
                        $fooId => JSON::true
                    },
                    from => [{ email => q{foo2@bar} }],
                    to => [{ email => q{bar2@foo} }],
                    subject => "email2"
                },
                email3 => {
                    mailboxIds => {
                        $inboxId => JSON::true
                    },
                    # explicity set this keyword to make sure it gets removed
                    keywords => { '$restored' => JSON::true },
                    from => [{ email => q{foo3@bar} }],
                    to => [{ email => q{bar3@foo} }],
                    subject => "email3"
                },
                email4 => {
                    mailboxIds => {
                        $fooId => JSON::true
                    },
                    from => [{ email => q{foo4@bar} }],
                    to => [{ email => q{bar4@foo} }],
                    subject => "email4"
                },
                email5 => {
                    mailboxIds => {
                        $fooId => JSON::true
                    },
                    from => [{ email => q{foo5@bar} }],
                    to => [{ email => q{bar5@foo} }],
                    subject => "email5"
                },
                email6 => {
                    mailboxIds => {
                        $inboxId => JSON::true
                    },
                    from => [{ email => q{foo6@bar} }],
                    to => [{ email => q{bar6@foo} }],
                    subject => "email6"
                }
            },
        }, 'R3'],
        ['Email/get', {
            ids => [ '#email1', '#email2', '#email3', '#email4', '#email5', '#email6' ],
            properties => ['receivedAt']
         }, "R3.2"]
    ]);
    my $emailId1 = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId1);
    my $emailId2 = $res->[0][1]{created}{email2}{id};
    $self->assert_not_null($emailId2);
    my $emailId3 = $res->[0][1]{created}{email3}{id};
    $self->assert_not_null($emailId3);
    my $emailId4 = $res->[0][1]{created}{email4}{id};
    $self->assert_not_null($emailId4);
    my $emailId5 = $res->[0][1]{created}{email5}{id};
    $self->assert_not_null($emailId5);
    my $emailId6 = $res->[0][1]{created}{email6}{id};
    $self->assert_not_null($emailId6);

    my $emailAt1 = $res->[1][1]{list}[0]{receivedAt};
    my $emailAt2 = $res->[1][1]{list}[1]{receivedAt};
    my $emailAt3 = $res->[1][1]{list}[2]{receivedAt};
    my $emailAt4 = $res->[1][1]{list}[3]{receivedAt};
    my $emailAt5 = $res->[1][1]{list}[4]{receivedAt};
    my $emailAt6 = $res->[1][1]{list}[5]{receivedAt};

    xlog "create emails in Drafts";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                draft1 => {
                    mailboxIds => {
                        $draftsId => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "draft1",
                    keywords => { '$draft' => JSON::true },
                    messageId => ['fake.123456789@local'],
                },
                draft2 => {
                    mailboxIds => {
                        $draftsId => JSON::true
                    },
                    from => [{ email => q{foo2@bar} }],
                    to => [{ email => q{bar2@foo} }],
                    subject => "draft2 (biggest)",
                    keywords => { '$draft' => JSON::true },
                    messageId => ['fake.123456789@local'],
                },
                draft3 => {
                    mailboxIds => {
                        $draftsId => JSON::true
                    },
                    from => [{ email => q{foo3@bar} }],
                    to => [{ email => q{bar3@foo} }],
                    subject => "draft3 (bigger)",
                    keywords => { '$draft' => JSON::true },
                    messageId => ['fake.123456789@local'],
                },
            },
        }, 'R3.5'],
        ['Email/get', {
            ids => [ '#draft1', '#draft2', '#draft3' ],
            properties => ['receivedAt']
         }, "R3.7"]
    ]);
    my $draftId1 = $res->[0][1]{created}{draft1}{id};
    $self->assert_not_null($emailId1);
    my $draftId2 = $res->[0][1]{created}{draft2}{id};
    $self->assert_not_null($emailId2);
    my $draftId3 = $res->[0][1]{created}{draft3}{id};
    $self->assert_not_null($emailId3);

    my $draftAt1 = $res->[1][1]{list}[0]{receivedAt};
    my $draftAt2 = $res->[1][1]{list}[1]{receivedAt};
    my $draftAt3 = $res->[1][1]{list}[2]{receivedAt};

    xlog "move email6 from Inbox to bar, delete email1 and email5";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId6 => {
                "mailboxIds/$inboxId" => undef,
                "mailboxIds/$barId" => JSON::true
                } },
            destroy => ["$emailId1", "$emailId5"]
         }, "R4"]
    ]);
    $self->assert_str_equals($emailId1, $res->[0][1]{destroyed}[0]);

    sleep 1;
    xlog "remove email2 from Inbox";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId2 => { "mailboxIds/$inboxId" => undef }}
         }, "R4.5"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId2});

    sleep 2;
    xlog "destroy email2, all drafts, 'foo' and 'bar' mailboxes";
    $res = $jmap->CallMethods([
        ['Email/set', {
            destroy => ["$emailId2", "$draftId1", "$draftId2", "$draftId3"]
         }, "R5"],
        ['Mailbox/set', {
            destroy => ["$fooId", "$barId"],
            onDestroyRemoveEmails => JSON::true
         }, "R5.5"],
    ]);
    $self->assert_num_equals(4, scalar(@{$res->[0][1]{destroyed}}));
    $self->assert_str_equals($emailId2, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($draftId1, $res->[0][1]{destroyed}[1]);
    $self->assert_str_equals($draftId2, $res->[0][1]{destroyed}[2]);
    $self->assert_str_equals($draftId3, $res->[0][1]{destroyed}[3]);
    $self->assert_num_equals(2, scalar @{$res->[1][1]{destroyed}});
    my @expect = sort ($fooId, $barId);
    my @got = sort @{$res->[1][1]{destroyed}};
    $self->assert_deep_equals(\@expect, \@got);

    xlog "create a new 'bar' mailbox";
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "1" => {
                    name => "bar"
                }
            }
         }, "R5.7"],
        ['Mailbox/get', {
         }, "R5.8"],
        ['Email/get', {
            ids => ["$emailId1", "$emailId2", "$emailId3", "$emailId4", "$emailId5", "$emailId6",
                    "$draftId1", "$draftId2", "$draftId3"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R5.9"]
    ]);
    $self->assert_not_null($res);
    my $newBarId = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($newBarId);

    @expect = sort ($emailId1, $emailId2, $emailId4, $emailId5, $emailId6, $draftId1, $draftId2, $draftId3);
    @got = sort @{$res->[2][1]{notFound}};
    $self->assert_deep_equals(\@expect, \@got);

    xlog "perform a dry-run restoration of mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            performDryRun => JSON::true,
            undoPeriod => "PT2S"
         }, "R5.9.4"],
        ['Email/get', {
            ids => ["$emailId1", "$emailId2", "$emailId3", "$emailId4", "$emailId5", "$emailId6",
                    "$draftId1", "$draftId2", "$draftId3"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R5.9.5"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R5.9.4', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(3, $res->[0][1]{numNonDraftsRestored});

    $self->assert_num_equals(1, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("$emailId3", $res->[1][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt3", $res->[1][1]{list}[0]{receivedAt});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$inboxId});

    @expect = sort ($emailId1, $emailId2, $emailId4, $emailId5, $emailId6, $draftId1, $draftId2, $draftId3);
    @got = sort @{$res->[1][1]{notFound}};
    $self->assert_deep_equals(\@expect, \@got);

    xlog "restore mail prior to most recent changes";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            restoreNonDrafts => JSON::false,
            undoPeriod => "PT2S"
         }, "R6"],
        ['Email/get', {
            ids => ["$emailId1", "$emailId2", "$emailId3", "$emailId4", "$emailId5", "$emailId6",
                    "$draftId1", "$draftId2", "$draftId3"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R6.2"],
        ['Backup/restoreMail', {
            restoreDrafts => JSON::false,
            undoPeriod => "PT2S"
         }, "R6.5"],
        ['Mailbox/get', {
         }, "R7"],
        ['Email/get', {
            ids => ["$emailId1", "$emailId2", "$emailId3", "$emailId4", "$emailId5", "$emailId6",
                    "$draftId1", "$draftId2", "$draftId3"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R8"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R6', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(0, $res->[0][1]{numNonDraftsRestored});

    # - email3 should have $restored flag removed
    # - draft1 should NOT be restored (smaller than draft2)
    # - draft2 should be the only draft restored to mailbox 'Drafts'
    #   because it was the largest of those having the same Message-ID
    # - draft3 should NOT be restored (smaller than draft2)
    $self->assert_str_equals('Email/get', $res->[1][0]);
    $self->assert_str_equals('R6.2', $res->[1][2]);
    $self->assert_num_equals(2, scalar(@{$res->[1][1]{list}}));
    $self->assert_str_equals("$emailId3", $res->[1][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt3", $res->[1][1]{list}[0]{receivedAt});
    $self->assert_null($res->[1][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$inboxId});

    $self->assert_str_equals("$draftId2", $res->[1][1]{list}[1]{id});
    $self->assert_str_equals("$draftAt2", $res->[1][1]{list}[1]{receivedAt});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[1]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[1]{mailboxIds}{$draftsId});

    $self->assert_num_equals(7, scalar(@{$res->[1][1]{notFound}}));
    @expect = sort ($emailId1, $emailId2, $emailId4, $emailId5, $emailId6, $draftId1, $draftId3);
    @got = sort @{$res->[1][1]{notFound}};
    $self->assert_deep_equals(\@expect, \@got);

    $self->assert_str_equals('R6.5', $res->[2][2]);
    $self->assert_num_equals(0, $res->[2][1]{numDraftsRestored});
    $self->assert_num_equals(3, $res->[2][1]{numNonDraftsRestored});

    # - mailbox 'foo' should be recreated (will have a new id)
    # - email1 should NOT be restored (destroyed prior to cutoff)
    # - email2 should be restored to the server-recreated 'foo' mailbox ONLY
    #   (it was destroyed most recently)
    # - email4 should be restored to the server-recreated 'foo' mailbox
    # - email5 should NOT be restored (destroyed prior to cutoff)
    # - email6 should be restored to the user-recreated 'bar' mailbox ONLY
    #   (it was destroyed most recently)
    # - draft2 should have $restored flag removed
    $self->assert_str_equals('Mailbox/get', $res->[3][0]);
    $self->assert_str_equals('R7', $res->[3][2]);
    $self->assert_num_equals(4, scalar(@{$res->[3][1]{list}}));
    $self->assert_str_equals("bar", $res->[3][1]{list}[2]{name});
    $self->assert_str_equals($newBarId, $res->[3][1]{list}[2]{id});
    $self->assert_str_equals("foo", $res->[3][1]{list}[3]{name});
    my $newFooId = $res->[3][1]{list}[3]{id};

    $self->assert_str_equals('Email/get', $res->[4][0]);
    $self->assert_str_equals('R8', $res->[4][2]);
    $self->assert_num_equals(5, scalar(@{$res->[4][1]{list}}));
    $self->assert_str_equals("$emailId2", $res->[4][1]{list}[0]{id});
    $self->assert_str_equals("$emailAt2", $res->[4][1]{list}[0]{receivedAt});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[0]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[0]{mailboxIds}{$newFooId});
    $self->assert_null($res->[4][1]{list}[0]{mailboxIds}->{$inboxId});

    $self->assert_str_equals("$emailId3", $res->[4][1]{list}[1]{id});
    $self->assert_str_equals("$emailAt3", $res->[4][1]{list}[1]{receivedAt});
    $self->assert_null($res->[4][1]{list}[1]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[1]{mailboxIds}{$inboxId});

    $self->assert_str_equals("$emailId4", $res->[4][1]{list}[2]{id});
    $self->assert_str_equals("$emailAt4", $res->[4][1]{list}[2]{receivedAt});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[2]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[2]{mailboxIds}{$newFooId});

    $self->assert_str_equals("$emailId6", $res->[4][1]{list}[3]{id});
    $self->assert_str_equals("$emailAt6", $res->[4][1]{list}[3]{receivedAt});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[3]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[3]{mailboxIds}{$newBarId});
    $self->assert_null($res->[4][1]{list}[3]{mailboxIds}->{$inboxId});

    $self->assert_str_equals("$draftId2", $res->[4][1]{list}[4]{id});
    $self->assert_str_equals("$draftAt2", $res->[4][1]{list}[4]{receivedAt});
    $self->assert_null($res->[4][1]{list}[4]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[4][1]{list}[4]{mailboxIds}{$draftsId});

    $self->assert_num_equals(4, scalar(@{$res->[4][1]{notFound}}));
    @expect = sort ($emailId1, $emailId5, $draftId1, $draftId3);
    @got = sort @{$res->[4][1]{notFound}};
    $self->assert_deep_equals(\@expect, \@got);

    xlog "re-restore mailbox back to same point in time";
    $res = $jmap->CallMethods([
        ['Backup/restoreMail', {
            undoPeriod => "PT2S"
         }, "R9"],
        ['Email/get', {
            ids => ["$emailId1", "$emailId2", "$emailId3", "$emailId4", "$emailId5", "$emailId6",
                    "$draftId1", "$draftId2", "$draftId3"],
            properties => ['subject', 'keywords', 'mailboxIds', 'receivedAt']
         }, "R10"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreMail', $res->[0][0]);
    $self->assert_str_equals('R9', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numDraftsRestored});
    $self->assert_num_equals(0, $res->[0][1]{numNonDraftsRestored});

    $self->assert_str_equals('Email/get', $res->[1][0]);
    $self->assert_str_equals('R10', $res->[1][2]);
    $self->assert_num_equals(5, scalar(@{$res->[1][1]{list}}));

    $self->assert_str_equals("$draftId2", $res->[1][1]{list}[4]{id});
    $self->assert_str_equals("$draftAt2", $res->[1][1]{list}[4]{receivedAt});
    $self->assert_null($res->[4][1]{list}[4]{keywords}->{'$restored'});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[4]{mailboxIds}{$draftsId});
}

sub test_restore_notes
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # force creation of notes mailbox prior to creating notes
    my $res = $jmap->CallMethods([
        ['Note/set', {
         }, "R0"]
    ]);

    xlog "create notes";
    $res = $jmap->CallMethods([['Note/set', {create => {
                        "a" => {title => "a"},
                        "b" => {title => "b"},
                        "c" => {title => "c"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $noteA = $res->[0][1]{created}{"a"}{id};
    my $noteB = $res->[0][1]{created}{"b"}{id};
    my $noteC = $res->[0][1]{created}{"c"}{id};

    xlog "destroy note C";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteC]
                }, "R1.5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R1.5', $res->[0][2]);

    sleep 2;
    xlog "destroy note A, update note B, create note D";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteA],
                    update => {$noteB => {title => "B"}},
                    create => {"d" => {title => "d"}}
                }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    my $noteD = $res->[0][1]{created}{"d"}{id};

    xlog "destroy note D, create note E";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteD],
                    create => {
                        "e" => {title => "e"}
                    }
                }, "R4"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R4', $res->[0][2]);
    my $noteE = $res->[0][1]{created}{"e"}{id};
    my $state = $res->[0][1]{newState};

    xlog "restore notes prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreNotes', {
                    undoPeriod => "PT2S",
                    undoAll => JSON::false
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreNotes', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(0, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numDestroysUndone});

    xlog "get restored notes";
    $res = $jmap->CallMethods([
        ['Note/get', {
            properties => ['title', 'isFlagged'],
         }, "R6"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/get', $res->[0][0]);
    $self->assert_str_equals('R6', $res->[0][2]);

    my @got = sort { $a->{title} cmp $b->{title} } @{$res->[0][1]{list}};
    $self->assert_num_equals(4, scalar @got);
    $self->assert_str_equals('B', $got[0]{title});
    $self->assert_str_equals('a', $got[1]{title});
    $self->assert_str_equals('d', $got[2]{title});
    $self->assert_str_equals('e', $got[3]{title});

    xlog "get note updates";
    $res = $jmap->CallMethods([
        ['Note/changes', {
            sinceState => $state
         }, "R8.5"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/changes', $res->[0][0]);
    $self->assert_str_equals('R8.5', $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    my %noteIds = map { $_ => 1 } @{$res->[0][1]{created}};
    $self->assert_not_null($noteIds{$noteA});
    $self->assert_not_null($noteIds{$noteD});
}

sub test_restore_notes_all
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # force creation of notes mailbox prior to creating notes
    my $res = $jmap->CallMethods([
        ['Note/set', {
         }, "R0"]
    ]);

    sleep 2;
    xlog "create notes";
    $res = $jmap->CallMethods([['Note/set', {create => {
                        "a" => {title => "a"},
                        "b" => {title => "b"},
                        "c" => {title => "c"},
                        "d" => {title => "d"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $noteA = $res->[0][1]{created}{"a"}{id};
    my $noteB = $res->[0][1]{created}{"b"}{id};
    my $noteC = $res->[0][1]{created}{"c"}{id};
    my $noteD = $res->[0][1]{created}{"d"}{id};

    xlog "destroy note A, update note B";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteA],
                    update => {$noteB => {title => "B"}}
                }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);

    xlog "get notes";
    $res = $jmap->CallMethods([
        ['Note/get', {
            properties => ['title', 'isFlagged'],
         }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/get', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);

    my @expect = sort { $a->{title} cmp $b->{title} } @{$res->[0][1]{list}};

    sleep 1;
    xlog "destroy note C, update notes B and D, create note E";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteC],
                    update => {
                        $noteB => {isFlagged => JSON::true},
                        $noteD => {isFlagged => JSON::true},
                    },
                    create => {
                        "e" => {title => "e"}
                    }
                }, "R4"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R4', $res->[0][2]);
    my $noteE = $res->[0][1]{created}{"e"}{id};
    my $state = $res->[0][1]{newState};

    xlog "restore notes prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreNotes', {
                    undoPeriod => "PT1S",
                    undoAll => JSON::true
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreNotes', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

    xlog "get restored notes";
    $res = $jmap->CallMethods([
        ['Note/get', {
            properties => ['title', 'isFlagged'],
         }, "R6"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/get', $res->[0][0]);
    $self->assert_str_equals('R6', $res->[0][2]);

    my @got = sort { $a->{title} cmp $b->{title} } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar @expect, scalar @got);
    $self->assert_deep_equals(\@expect, \@got);

    xlog "get note updates";
    $res = $jmap->CallMethods([
        ['Note/changes', {
            sinceState => $state
         }, "R6.5"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/changes', $res->[0][0]);
    $self->assert_str_equals('R6.5', $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($noteC, $res->[0][1]{created}[0]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($noteE, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]{newState};

    xlog "restore notes to before initial creation";
    $res = $jmap->CallMethods([['Backup/restoreNotes', {
                    undoPeriod => "PT3S",
                    undoAll => JSON::true
                }, "R7"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreNotes', $res->[0][0]);
    $self->assert_str_equals('R7', $res->[0][2]);
    $self->assert_num_equals(3, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(0, $res->[0][1]{numDestroysUndone});

    xlog "get restored notes";
    $res = $jmap->CallMethods([
        ['Note/get', {
            properties => ['title', 'isFlagged'],
         }, "R8"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/get', $res->[0][0]);
    $self->assert_str_equals('R8', $res->[0][2]);
    $self->assert_deep_equals([], $res->[0][1]{list});

    xlog "get note updates";
    $res = $jmap->CallMethods([
        ['Note/changes', {
            sinceState => $state
         }, "R8.5"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/changes', $res->[0][0]);
    $self->assert_str_equals('R8.5', $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(3, scalar @{$res->[0][1]{destroyed}});
    $state = $res->[0][1]{newState};
}

sub test_restore_notes_all_dryrun
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # force creation of notes mailbox prior to creating notes
    my $res = $jmap->CallMethods([
        ['Note/set', {
         }, "R0"]
    ]);

    sleep 2;
    xlog "create notes";
    $res = $jmap->CallMethods([['Note/set', {create => {
                        "a" => {title => "a"},
                        "b" => {title => "b"},
                        "c" => {title => "c"},
                        "d" => {title => "d"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $noteA = $res->[0][1]{created}{"a"}{id};
    my $noteB = $res->[0][1]{created}{"b"}{id};
    my $noteC = $res->[0][1]{created}{"c"}{id};
    my $noteD = $res->[0][1]{created}{"d"}{id};

    xlog "destroy note A, update note B";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteA],
                    update => {$noteB => {title => "B"}}
                }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);

    xlog "get notes";
    $res = $jmap->CallMethods([
        ['Note/get', {
            properties => ['title', 'isFlagged'],
         }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/get', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);

    my @expect = sort { $a->{title} cmp $b->{title} } @{$res->[0][1]{list}};

    sleep 1;
    xlog "destroy note C, update notes B and D, create note E";
    $res = $jmap->CallMethods([['Note/set', {
                    destroy => [$noteC],
                    update => {
                        $noteB => {isFlagged => JSON::true},
                        $noteD => {isFlagged => JSON::true},
                    },
                    create => {
                        "e" => {title => "e"}
                    }
                }, "R4"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/set', $res->[0][0]);
    $self->assert_str_equals('R4', $res->[0][2]);
    my $noteE = $res->[0][1]{created}{"e"}{id};
    my $state = $res->[0][1]{newState};

    xlog "restore notes prior to most recent changes";
    $res = $jmap->CallMethods([['Backup/restoreNotes', {
                    performDryRun => JSON::true,
                    undoPeriod => "PT1S",
                    undoAll => JSON::true
                }, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Backup/restoreNotes', $res->[0][0]);
    $self->assert_str_equals('R5', $res->[0][2]);
    $self->assert_num_equals(1, $res->[0][1]{numCreatesUndone});
    $self->assert_num_equals(2, $res->[0][1]{numUpdatesUndone});
    $self->assert_num_equals(1, $res->[0][1]{numDestroysUndone});

    xlog "get note updates";
    $res = $jmap->CallMethods([
        ['Note/changes', {
            sinceState => $state
         }, "R6.5"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Note/changes', $res->[0][0]);
    $self->assert_str_equals('R6.5', $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
}

1;
