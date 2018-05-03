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

package Cassandane::Cyrus::JMAPCalendars;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.10;
use Data::Dumper;
use Storable 'dclone';
use Cwd qw(abs_path);
use File::Basename;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_historical_age => -1);
    return $class->SUPER::new({
        config => $config,
                              }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub test_calendar_get
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $id = $caldav->NewCalendar({ name => "calname", color => "aqua"});
    my $unknownId = "foo";

    xlog "get existing calendar";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Calendar/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    $self->assert_str_equals($id, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('aqua', $res->[0][1]{list}[0]{color});

    xlog "get existing calendar with select properties";
    $res = $jmap->CallMethods([['Calendar/get', { ids => [$id], properties => ["name"] }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    $self->assert_str_equals($id, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals("calname", $res->[0][1]{list}[0]{name});
    $self->assert_null($res->[0][1]{list}[0]{color});

    xlog "get unknown calendar";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$unknownId]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(0, scalar(@{$res->[0][1]{list}}));
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{notFound}}));
    $self->assert_str_equals($unknownId, $res->[0][1]{notFound}[0]);
}

sub test_calendar_get_shared
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");

    xlog "create shared account";
    $admintalk->create("user.manifold");

    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    $admintalk->setacl("user.manifold", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", manifold => 'lrswipkxtecdn');

    xlog "create calendar";
    my $CalendarId = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId);

    xlog "share to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lr') or die;

    xlog "get calendar";
    my $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold'}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{accountId}, 'manifold');
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "Manifold Calendar");
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]->{mayReadItems});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]->{mayAddItems});
    my $id = $res->[0][1]{list}[0]->{id};

    xlog "refetch calendar";
    $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold', ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);

    xlog "create another shared calendar";
    my $CalendarId2 = $mantalk->NewCalendar({name => 'Manifold Calendar 2'});
    $self->assert_not_null($CalendarId2);
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lr') or die;

    xlog "remove access rights to calendar";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => '') or die;

    xlog "refetch calendar (should fail)";
    $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold', ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);

    xlog "remove access rights to all shared calendars";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => '') or die;

    xlog "refetch calendar (should fail)";
    $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold', ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][0], "error");
    $self->assert_str_equals($res->[0][1]{type}, "accountNotFound");
}


sub test_calendar_get_default
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # XXX - A previous CalDAV test might have created the default
    # calendar already. To make this test self-sufficient, we need
    # to create a test user just for this test. How?
    xlog "get default calendar";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals("Default", $res->[0][1]{list}[0]{id});
}

sub test_calendar_set
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Calendar/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get calendar $id";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    $self->assert_str_equals($id, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{name});
    $self->assert_equals($res->[0][1]{list}[0]{isVisible}, JSON::true);

    xlog "update calendar $id";
    $res = $jmap->CallMethods([
            ['Calendar/set', {update => {"$id" => {
                            name => "bar",
                            isVisible => \0
            }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert(exists $res->[0][1]{updated}{$id});
    
    xlog "get calendar $id";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals('bar', $res->[0][1]{list}[0]{name});
    $self->assert_equals($res->[0][1]{list}[0]{isVisible}, JSON::false);

    xlog "destroy calendar $id";
    $res = $jmap->CallMethods([['Calendar/set', {destroy => ["$id"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{destroyed});
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);

    xlog "get calendar $id";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);
}

sub test_calendar_set_state
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with invalid state token";
    my $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => "badstate",
                    create => { "1" => { name => "foo" }}
                }, "R1"]
        ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog "create with wrong state token";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => "987654321",
                    create => { "1" => { name => "foo" }}
                }, "R1"]
        ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog "create calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res);

    my $id = $res->[0][1]{created}{"1"}{id};
    my $state = $res->[0][1]{newState};

    xlog "update calendar $id with current state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $state,
                    update => {"$id" => {name => "bar"}}
            }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "setCalendar noops must keep state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {}, "R1"],
            ['Calendar/set', {}, "R2"],
            ['Calendar/set', {}, "R3"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_equals($state, $res->[0][1]{newState});

    xlog "update calendar $id with expired state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $oldState,
                    update => {"$id" => {name => "baz"}}
            }, "R1"]
    ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals("stateMismatch", $res->[0][1]{type});
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "get calendar $id to make sure state didn't change";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{state});
    $self->assert_str_equals('bar', $res->[0][1]{list}[0]{name});

    xlog "destroy calendar $id with expired state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $oldState,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals("stateMismatch", $res->[0][1]{type});
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "destroy calendar $id with current state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $state,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}

sub test_calendar_set_shared
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");
    xlog "create shared account";
    $admintalk->create("user.manifold");

    $admintalk->setacl("user.manifold", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", manifold => 'lrswipkxtecdn');

    # Call CalDAV once to create manifold's calendar home #calendars
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog "share calendar home read-only to user";
    $admintalk->setacl("user.manifold.#calendars", cassandane => 'lr') or die;

    xlog "create calendar (should fail)";
    my $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'manifold',
                    create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][1]{accountId}, 'manifold');
    $self->assert_str_equals($res->[0][1]{notCreated}{1}{type}, "accountReadOnly");

    xlog "share calendar home read-writable to user";
    $admintalk->setacl("user.manifold.#calendars", cassandane => 'lrswipkxtecdn') or die;

    xlog "create calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'manifold',
                    create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][1]{accountId}, 'manifold');
    my $CalendarId = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($CalendarId);

    xlog "share calendar read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lr') or die;

    xlog "update calendar (should fail)";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'manifold',
                    update => {$CalendarId => {
                            name => "bar",
                            isVisible => \0
            }}}, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{notUpdated}{$CalendarId});
    $self->assert_str_equals($res->[0][1]{notUpdated}{$CalendarId}{type}, "accountReadOnly");

    xlog "share read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "update calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'manifold',
                    update => {$CalendarId => {
                            name => "bar",
                            isVisible => \0
            }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][1]{accountId}, 'manifold');
    $self->assert(exists $res->[0][1]{updated}{$CalendarId});

    xlog "share read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lr') or die;

    xlog "destroy calendar $CalendarId (should fail)";
    $res = $jmap->CallMethods([['Calendar/set', {accountId => 'manifold', destroy => [$CalendarId]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{accountId}, 'manifold');
    $self->assert_str_equals($res->[0][1]{notDestroyed}{$CalendarId}{type}, "accountReadOnly");

    xlog "share read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "destroy calendar $CalendarId";
    $res = $jmap->CallMethods([['Calendar/set', {accountId => 'manifold', destroy => [$CalendarId]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{accountId}, 'manifold');
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $CalendarId);
}


sub test_calendar_changes
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                        "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
                        },
                        "2" => {
                            name => "bar",
                            color => "aqua",
                            sortOrder => 3,
                            isVisible => \1
                        }
                    }}, "R1"]
    ]);
    $self->assert_not_null($res);

    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $state = $res->[0][1]{newState};

    xlog "get calendar updates without changes";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_str_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog "update name of calendar $id1, destroy calendar $id2";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $state,
                    update => {"$id1" => {name => "foo (upd)"}},
                    destroy => [$id2]
            }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});

    xlog "get calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals("Calendar/changes", $res->[0][0]);
    $self->assert_str_equals("R1", $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{destroyed}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($id1, $res->[0][1]{changed}[0]);
    $state = $res->[0][1]{newState};

    xlog "update color of calendar $id1";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { $id1 => { color => "aqua" }}}, "R1" ]
        ]);
    $self->assert(exists $res->[0][1]{updated}{$id1});

    xlog "get calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($id1, $res->[0][1]{changed}[0]);
    $state = $res->[0][1]{newState};

    xlog "update sortOrder of calendar $id1";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { $id1 => { sortOrder => 5 }}}, "R1" ]
        ]);
    $self->assert(exists $res->[0][1]{updated}{$id1});

    xlog "get calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state,
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($id1, $res->[0][1]{changed}[0]);
    $state = $res->[0][1]{newState};

    xlog "get empty calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
}

sub test_calendar_set_error
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar with missing mandatory attributes";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {}}}, "R1"]
    ]);
    $self->assert_not_null($res);
    my $errType = $res->[0][1]{notCreated}{"1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals($errProp, [
            "name", "color", "sortOrder", "isVisible"
    ]);

    xlog "create calendar with invalid optional attributes";
    $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral",
                            sortOrder => 2, isVisible => \1,
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"1"}{type};
    $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals($errProp, [
            "mayReadFreeBusy", "mayReadItems", "mayAddItems",
            "mayModifyItems", "mayRemoveItems", "mayRename",
            "mayDelete"
    ]);

    xlog "update unknown calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { "unknown" => {
                            name => "foo"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{"unknown"}{type};
    $self->assert_str_equals("notFound", $errType);

    xlog "create calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "update calendar with immutable optional attributes";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { $id => {
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{$id}{type};
    $errProp = $res->[0][1]{notUpdated}{$id}{properties};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals($errProp, [
            "mayReadFreeBusy", "mayReadItems", "mayAddItems",
            "mayModifyItems", "mayRemoveItems", "mayRename",
            "mayDelete"
    ]);

    xlog "destroy unknown calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', {destroy => ["unknown"]}, "R1"]
    ]);
    $errType = $res->[0][1]{notDestroyed}{"unknown"}{type};
    $self->assert_str_equals("notFound", $errType);

    xlog "destroy calendar $id";
    $res = $jmap->CallMethods([['Calendar/set', {destroy => ["$id"]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}

sub test_calendar_set_badname
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar with excessively long name";
    # Exceed the maximum allowed 256 byte length by 1.
    my $badname = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum tincidunt risus quis urna aliquam sollicitudin. Pellentesque aliquet nisl ut neque viverra pellentesque. Donec tincidunt eros at ante malesuada porta. Nam sapien arcu, vehicula non posuere.";

    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => $badname, color => "aqua",
                            sortOrder => 1, isVisible => \1
            }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    my $errType = $res->[0][1]{notCreated}{"1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals(["name"], $errProp);
}

sub test_calendar_set_destroydefault
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my @specialIds = ["Inbox", "Outbox", "Default", "Attachments"];

    xlog "destroy special calendars";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { destroy => @specialIds }, "R1"]
    ]);
    $self->assert_not_null($res);

    my $errType = $res->[0][1]{notDestroyed}{"Default"}{type};
    $self->assert_str_equals("isDefault", $errType);
    $errType = $res->[0][1]{notDestroyed}{"Inbox"}{type};
    $self->assert_str_equals("notFound", $errType);
    $errType = $res->[0][1]{notDestroyed}{"Outbox"}{type};
    $self->assert_str_equals("notFound", $errType);
    $errType = $res->[0][1]{notDestroyed}{"Attachments"}{type};
    $self->assert_str_equals("notFound", $errType);
}

sub normalize_event
{
    my ($event) = @_;

    if (not exists $event->{q{@type}}) {
        $event->{q{@type}} = 'jsevent';
    }
    if (not exists $event->{freeBusyStatus}) {
        $event->{freeBusyStatus} = 'busy';
    }
    if (not exists $event->{priority}) {
        $event->{priority} = 0;
    }
    if (not exists $event->{description}) {
        $event->{description} = '';
    }
    if (not exists $event->{htmlDescription}) {
        $event->{htmlDescription} = undef;
    }
    if (not exists $event->{locations}) {
        $event->{locations} = undef;
    } elsif (defined $event->{locations}) {
        foreach my $loc (values %{$event->{locations}}) {
            if (not exists $loc->{rel}) {
                $loc->{rel} = "unknown";
            }
            if (not exists $loc->{name}) {
                $loc->{name} = ''
            }
            if (not exists $loc->{description}) {
                $loc->{description} = undef;
            }
            if (not exists $loc->{coordinates}) {
                $loc->{coordinates} = undef;
            }
            if (not exists $loc->{features}) {
                $loc->{features} = undef;
            }
            if (not exists $loc->{linkIds}) {
                $loc->{linkIds} = undef;
            }
            if (not exists $loc->{timeZone}) {
                $loc->{timeZone} = undef;
            }
            if (not exists $loc->{uri}) {
                $loc->{uri} = undef;
            }
        }
    }
    if (not exists $event->{localizations}) {
        $event->{localizations} = undef;
    }
    if (not exists $event->{keywords}) {
        $event->{keywords} = undef;
    }
    if (not exists $event->{locale}) {
        $event->{locale} = undef;
    }
    if (not exists $event->{links}) {
        $event->{links} = undef;
    }
    if (not exists $event->{relatedTo}) {
        $event->{relatedTo} = undef;
    }
    if (not exists $event->{participants}) {
        $event->{participants} = undef;
    } elsif (defined $event->{participants}) {
        foreach my $p (values %{$event->{participants}}) {
            if (not exists $p->{linkIds}) {
                $p->{linkIds} = undef;
            }
            if (not exists $p->{participation}) {
                $p->{participation} = 'required';
            }
            if (not exists $p->{rsvpResponse}) {
                $p->{rsvpResponse} = 'needs-action';
            }
            if (exists $p->{roles}) {
                my @roles = sort @{$p->{roles}};
                $p->{roles} = \@roles;
            }
        }
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
    } elsif (defined $event->{attachments}) {
        foreach my $att (values %{$event->{attachments}}) {
            if (not exists $att->{cid}) {
                $att->{cid} = undef;
            }
            if (not exists $att->{type}) {
                $att->{type} = undef;
            }
            if (not exists $att->{size}) {
                $att->{size} = undef;
            }
            if (not exists $att->{rel}) {
                $att->{rel} = 'related';
            }
            if (not exists $att->{title}) {
                $att->{title} = undef;
            }
            if (not exists $att->{properties}) {
                $att->{properties} = undef;
            }
        }
    }
    if (not exists $event->{status}) {
        $event->{status} = "confirmed";
    }
    if (not exists $event->{privacy}) {
        $event->{privacy} = "public";
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
    my ($self, $id, $ical, $props) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "get default calendar id";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals("Default", $res->[0][1]{list}[0]{id});
    my $calid = $res->[0][1]{list}[0]{id};
    my $xhref = $res->[0][1]{list}[0]{"x-href"};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog "create event (via CalDAV)";
    my $href = "$xhref/$id.ics";

    $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    xlog "get event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id], properties => $props}, "R1"]]);

    my $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);
    return $event;
}

sub icalfile
{
    my ($self, $name) = @_;

    my $path = abs_path("data/icalendar/$name.ics");
    $self->assert(-f $path);
    open(FH, "<$path");
    local $/ = undef;
    my $data = <FH>;
    close(FH);
    my ($id) = ($data =~ m/^UID:(\S+)\r?$/m);
    $self->assert($id);
    return ($id, $data);
}

sub test_calendarevent_get_simple
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('simple');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals('jsevent', $event->{q{@type}});
    $self->assert_str_equals($id, $event->{uid});
    $self->assert_null($event->{relatedTo});
    $self->assert_str_equals("yo", $event->{title});
    $self->assert_str_equals("-//Apple Inc.//Mac OS X 10.9.5//EN", $event->{prodId});
    $self->assert_str_equals("en", $event->{locale});
    $self->assert_str_equals("turquoise", $event->{color});
    $self->assert_str_equals("double yo", $event->{description});
    $self->assert_equals($event->{freeBusyStatus}, "free");
    $self->assert_equals($event->{isAllDay}, JSON::false);
    $self->assert_str_equals("2016-09-28T16:00:00", $event->{start});
    $self->assert_str_equals("Etc/UTC", $event->{timeZone});
    $self->assert_str_equals("PT1H", $event->{duration});
    $self->assert_str_equals("2015-09-28T12:52:12Z", $event->{created});
    $self->assert_str_equals("2015-09-28T13:24:34Z", $event->{updated});
    $self->assert_num_equals(9, $event->{sequence});
    $self->assert_num_equals(3, $event->{priority});
    $self->assert_str_equals("public", $event->{privacy});
}

sub test_calendarevent_get_privacy
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('privacy');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals( $event->{privacy}, "private");
}

sub test_calendarevent_get_properties
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('simple');

    my $event = $self->putandget_vevent($id, $ical, ["x-href", "calendarId"]);
    $self->assert_not_null($event);
    $self->assert_not_null($event->{id});
    $self->assert_not_null($event->{uid});
    $self->assert_not_null($event->{"x-href"});
    $self->assert_not_null($event->{calendarId});
    $self->assert_num_equals(scalar keys %$event, 5);
}

sub test_calendarevent_get_relatedto
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('relatedto');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals($id, $event->{uid});
    $self->assert_deep_equals($event->{relatedTo}, {
            "first"     => "58ADE31-001",
            "next"      => "58ADE31-003",
            "x-unknown" => "foo",
    });
}

sub test_calendarevent_get_links
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('links');
    my $uri = "http://jmap.io/spec.html#calendar-events";

    my $links = {
        'link1' => {
            href => $uri,
            type => "text/html",
            size => 4480,
            title => "the spec",
            rel => "enclosure",
            cid => '123456789asd',
        }
    };

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_deep_equals($links, $event->{links});
}


sub test_calendarevent_get_rscale
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('rscale');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("Some day in Adar I", $event->{title});
    $self->assert_str_equals("yearly", $event->{recurrenceRule}{frequency});
    $self->assert_str_equals("hebrew", $event->{recurrenceRule}{rscale});
    $self->assert_str_equals("forward", $event->{recurrenceRule}{skip});
    $self->assert_num_equals(8, $event->{recurrenceRule}{byDate}[0]);
    $self->assert_str_equals("5L", $event->{recurrenceRule}{byMonth}[0]);
}

sub test_calendarevent_get_endtimezone
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('endtimezone');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("2016-09-28T13:00:00", $event->{start});
    $self->assert_str_equals("Europe/London", $event->{timeZone});
    $self->assert_str_equals("PT1H", $event->{duration});

    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("Europe/Vienna", $locations[0]{timeZone});
    $self->assert_str_equals("end", $locations[0]{rel});
}

sub test_calendarevent_get_keywords
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('keywords');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_num_equals(3, scalar @{$event->{keywords}});
    $self->assert_str_equals('foo', $event->{keywords}[0]);
    $self->assert_str_equals('bar', $event->{keywords}[1]);
    $self->assert_str_equals('baz', $event->{keywords}[2]);
}

sub test_calendarevent_get_description
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('description');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("Hello, from plain text.", $event->{description});
    $self->assert_str_equals("<html><body>Hello, from HTML!</body></html>", $event->{htmlDescription});
}

sub test_calendarevent_get_participants
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('participants');

    my $event = $self->putandget_vevent($id, $ical);

    $self->assert_not_null($event->{replyTo});
    $self->assert_str_equals("mailto:smithers\@example.com", $event->{replyTo}{imip});

    $self->assert_not_null($event->{participants});
    $self->assert_num_equals(5, scalar values %{$event->{participants}});
    $self->assert_str_equals("Monty Burns", $event->{participants}{"smithers\@example.com"}{name});
    $self->assert_str_equals("smithers\@example.com", $event->{participants}{"smithers\@example.com"}{email});
    $self->assert_str_equals("owner", $event->{participants}{"smithers\@example.com"}{roles}[0]);
    $self->assert_str_equals("Homer Simpson", $event->{participants}{"homer\@example.com"}{name});
    $self->assert_str_equals("accepted", $event->{participants}{"homer\@example.com"}{rsvpResponse});
    $self->assert_str_equals("optional", $event->{participants}{"homer\@example.com"}{participation});
    $self->assert_str_equals("homer\@example.com", $event->{participants}{"homer\@example.com"}{email});
    $self->assert_str_equals("attendee", $event->{participants}{"homer\@example.com"}{roles}[0]);
    $self->assert_str_equals("loc1", $event->{participants}{"homer\@example.com"}{locationId});
    $self->assert_str_equals("Carl Carlson", $event->{participants}{"carl"}{name});
    $self->assert_str_equals("tentative", $event->{participants}{"carl"}{rsvpResponse});
    $self->assert_str_equals("carl\@example.com", $event->{participants}{"carl"}{email});
    $self->assert_str_equals("attendee", $event->{participants}{"carl"}{roles}[0]);
    $self->assert_num_equals(3, $event->{participants}{"carl"}{scheduleSequence});
    $self->assert_str_equals("2017-01-02T03:04:05Z", $event->{participants}{"carl"}{scheduleUpdated});
    $self->assert_str_equals("Lenny Leonard", $event->{participants}{"lenny\@example.com"}{name});
    $self->assert_str_equals("tentative", $event->{participants}{"lenny\@example.com"}{rsvpResponse});
    $self->assert_str_equals("lenny\@example.com", $event->{participants}{"lenny\@example.com"}{email});
    $self->assert_str_equals("attendee", $event->{participants}{"lenny\@example.com"}{roles}[0]);
    $self->assert_str_equals("Larry Burns", $event->{participants}{"larry\@example.com"}{name});
    $self->assert_str_equals("declined", $event->{participants}{"larry\@example.com"}{rsvpResponse});
    $self->assert_str_equals("larry\@example.com", $event->{participants}{"larry\@example.com"}{email});
    $self->assert_str_equals("attendee", $event->{participants}{"larry\@example.com"}{roles}[0]);
    $self->assert_str_equals("projectA\@example.com", $event->{participants}{"larry\@example.com"}{memberOf}[0]);
    $self->assert_str_equals("tentative", $event->{status});
}

sub test_calendarevent_get_recurrence
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('recurrence');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event->{recurrenceRule});
    $self->assert_str_equals("monthly", $event->{recurrenceRule}{frequency});
    $self->assert_str_equals("gregorian", $event->{recurrenceRule}{rscale});
    # This assertion is a bit brittle. It depends on the libical-internal
    # sort order for BYDAY
    $self->assert_deep_equals($event->{recurrenceRule}{byDay}, [{
                "day" => "mo",
                "nthOfPeriod" => 2,
            }, {
                "day" => "mo",
                "nthOfPeriod" => 1,
            }, {
                "day" => "tu",
            }, {
                "day" => "th",
                "nthOfPeriod" => -2,
            }, {
                "day" => "sa",
                "nthOfPeriod" => -1,
            }, {
                "day" => "su",
                "nthOfPeriod" => -3,
            }]);
}

sub test_calendarevent_get_rdate_period
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('rdate_period');

    my $event = $self->putandget_vevent($id, $ical);
    my $o;

   $o = $event->{recurrenceOverrides}->{"2016-03-04T15:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals("PT1H", $o->{duration});
}


sub test_calendarevent_get_recurrenceoverrides
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('recurrenceoverrides');
    my $aid = $id . "-alarmuid";

    my $event = $self->putandget_vevent($id, $ical);
    my $o;

    $o = $event->{recurrenceOverrides}->{"2016-12-24T20:00:00"};
    $self->assert_not_null($o);

    $self->assert(exists $event->{recurrenceOverrides}->{"2016-02-01T13:00:00"});
    $self->assert_null($event->{recurrenceOverrides}->{"2016-02-01T13:00:00"});

    $o = $event->{recurrenceOverrides}->{"2016-05-01T13:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals("foobarbazbla", $o->{"title"});
    $self->assert_str_equals("2016-05-01T17:00:00", $o->{"start"});
    $self->assert_str_equals("PT2H", $o->{"duration"});
    $self->assert_not_null($o->{alerts}{$aid});

    $o = $event->{recurrenceOverrides}->{"2016-09-01T13:00:00"};
    $self->assert_not_null($o);
    $self->assert_str_equals("foobarbazblabam", $o->{"title"});
    $self->assert(not exists $o->{"start"});
}

sub test_calendarevent_get_alerts
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('alerts');

    my $aid1 = "0CF835D0-CFEB-44AE-904A-C26AB62B73BB-1";
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

    my $aid2 = "0CF835D0-CFEB-44AE-904A-C26AB62B73BB-2";
    my $alert2 = {
        relativeTo => "after-start",
        offset => "PT1H",
        action => {
            type => "display",
            acknowledged => "2016-09-28T15:00:05Z",
        },
    };

    my $aid3 = "0CF835D0-CFEB-44AE-904A-C26AB62B73BB-3";
    my $alert3 = {
        relativeTo => "after-start",
        offset => "PT1H",
        action => {
            type => "display",
            snoozed => "2016-09-28T15:00:05Z",

        },
    };

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_str_equals(JSON::true, $event->{useDefaultAlerts});
    $self->assert_deep_equals($alert1, $event->{alerts}{$aid1});
    $self->assert_deep_equals($alert2, $event->{alerts}{$aid2});
    $self->assert_deep_equals($alert3, $event->{alerts}{$aid3});

    # Check AUDIO VALARM
    my $alert4 = $event->{alerts}{"0CF835D0-CFEB-44AE-904A-C26AB62B73BB-4"};
    $self->assert_str_equals('display', $alert4->{action}{type});
    my $mediaLinks = {
        'alertMediaLink1' => {
            href => 'https://local/foo.ogg',
            type => 'audio/ogg',
        }
    };
    $self->assert_deep_equals($mediaLinks, $alert4->{action}{mediaLinks});
}

sub test_calendarevent_get_locations
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("On planet Earth", $locations[0]{name});
}

sub test_calendarevent_get_locations_uri
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-uri');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("On planet Earth", $locations[0]{name});
    $self->assert_str_equals("skype:foo", $locations[0]{uri});
}

sub test_calendarevent_get_locations_geo
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-geo');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("geo:37.386013,-122.082930", $locations[0]{coordinates});
}

sub test_calendarevent_get_locations_apple
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-apple');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("a place in Vienna", $locations[0]{name});
    $self->assert_str_equals("geo:48.208304,16.371602", $locations[0]{coordinates});
}

sub test_calendarevent_get_locations_conference
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-conference');

    my $event = $self->putandget_vevent($id, $ical);
    my $locations = $event->{locations};
    $self->assert_num_equals(2, scalar (values %{$locations}));

    my $loc1 = $locations->{loc1};
    $self->assert_str_equals('Moderator dial-in', $loc1->{name});
    $self->assert_str_equals('tel:+123451', $loc1->{uri});
    $self->assert_str_equals('virtual', $loc1->{rel});
    $self->assert_str_equals('phone', $loc1->{features}[0]);
    $self->assert_num_equals(2, scalar @{$loc1->{features}});
    $self->assert_str_equals('moderator', $loc1->{features}[1]);

    my $loc2 = $locations->{loc2};
    $self->assert_str_equals('Chat room', $loc2->{name});
    $self->assert_str_equals('xmpp:chat123@conference.example.com', $loc2->{uri});
    $self->assert_str_equals('virtual', $loc2->{rel});
    $self->assert_num_equals(1, scalar @{$loc2->{features}});
    $self->assert_str_equals('chat', $loc2->{features}[0]);
}

sub test_calendarevent_get_localizations
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('localizations');

    my $event = $self->putandget_vevent($id, $ical);

    my $locs = $event->{localizations};
    $self->assert_not_null($locs);

    $self->assert_str_equals("Titel", $locs->{de}{title});
    $self->assert_str_equals("Beschreibung", $locs->{de}{description});
    $self->assert_str_equals("legende", $locs->{fr}{description});
    $self->assert_str_equals("Am Planet Erde", $locs->{de}{"locations/loc1/name"});
    $self->assert_str_equals("die Spezifikation", $locs->{de}{"links/link1/title"});
    $self->assert_str_equals("Ihr Alarm", $locs->{de}{"alerts/43910EF2-F4D9-43F9-AEDD-1CADC38B05FB/action/subject"});

    my $o = $event->{recurrenceOverrides};
    $self->assert_str_equals("eine Ausnahme", $o->{"2016-09-15T11:15:00"}{"localizations/de/title"});
}

sub test_calendarevent_get_infinite_delegates
    :JMAP :min_version_3_1
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
    my $p = $event->{participants}{"lenny\@example.com"};
    $self->assert_str_equals("needs-action", $p->{rsvpResponse});
    $self->assert_deep_equals(["carl\@example.com"], $p->{delegatedTo});
    $p = $event->{participants}{"carl\@example.com"};
    $self->assert_str_equals("needs-action", $p->{rsvpResponse});
    $self->assert_deep_equals(["lenny\@example.com"], $p->{delegatedTo});
    $self->assert_deep_equals(["lenny\@example.com"], $p->{delegatedFrom});
}

sub createandget_event
{
    my ($self, $event, %params) = @_;

    my $jmap = $self->{jmap};
    my $accountId = $params{accountId} || 'cassandane';

    xlog "create event";
    my $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => $accountId,
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub updateandget_event
{
    my ($self, $event) = @_;

    my $jmap = $self->{jmap};
    my $id = $event->{id};

    xlog "update event $id";
    my $res = $jmap->CallMethods([['CalendarEvent/set', {update => {$id => $event}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub createcalendar
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    return $res->[0][1]{created}{"1"}{id};
}

sub test_calendarevent_set_type
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
    };

    # Setting no type is OK, we'll just assume jsevent
    my $res = $jmap->CallMethods([['CalendarEvent/set', {
        create => {
            "1" => $event,
        }
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"});

    # Setting any type other jsevent type is NOT OK
    $event->{q{@type}} = 'jstask';
    $event->{uid} = '58ADE31-custom-UID-2';
    $res = $jmap->CallMethods([['CalendarEvent/set', {
        create => {
            "1" => $event,
        }
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]{notCreated}{"1"});
}


sub test_calendarevent_set_simple
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "priority" => 9,
        "locale" => "en",
        "color" => "turquoise",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    $self->assert_num_equals(42, $event->{sequence});
}

sub test_calendarevent_set_relatedto
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "relatedTo" => {
            "first" => "uid1",
            "next"  => "uid2",
            "x-unknown" => "uid3",
        },
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    $self->assert_num_equals(42, $event->{sequence});
}

sub test_calendarevent_set_prodid
    :JMAP :min_version_3_1
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
        "freeBusyStatus"=> "busy",
    };

    my $ret;

    # assert default prodId
    $ret = $self->createandget_event($event);
    $self->assert_not_null($ret->{prodId});

    # assert custom prodId
    my $prodId = "my prodId";
    $event->{prodId} = $prodId;
    $ret = $self->createandget_event($event);
    $self->assert_str_equals($ret->{prodId}, $prodId);
}

sub test_calendarevent_set_endtimezone
    :JMAP :min_version_3_1
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
        "freeBusyStatus"=> "busy",
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

sub test_calendarevent_set_keywords
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "locale" => "en",
        "keywords" => [ 'foo', 'bar', 'baz' ],
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_endtimezone_recurrence
    :JMAP :min_version_3_1
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
        "locations" => {
            "loc1" => {
                "timeZone" => "Europe/Berlin",
                "rel" => "end",
            },
        },
        "isAllDay"=> JSON::false,
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "prodId" => "foo",
        "recurrenceRule" => {
            "frequency" => "monthly",
            count => 12,
        },
        "recurrenceOverrides" => {
            "2015-12-07T09:00:00" => {
                "locations/loc1/timeZone" => "America/New_York",
            },
        },
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_description
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "description"=> "A text description",
        "htmlDescription"=> "<html><body>Some HTML</body></html>",
        "privacy" => "secret",
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);

    delete $event->{description};
    $ret = $self->createandget_event($event);
    $event->{description} = "Some HTML";
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_links
    :JMAP :min_version_3_1
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
        "freeBusyStatus"=> "busy",
        "links" => {
            "http://jmap.io/spec.html#calendar-events" => {
                href => "http://jmap.io/spec.html#calendar-events",
                title => "the spec",
            },
            "rfc5545" => {
               href => "https://tools.ietf.org/html/rfc5545",
               rel => "describedby",
               properties => {
                   "https://tools.ietf.org/html/rfc4791/" => "the related CalDAV spec",
                   "https://tools.ietf.org/html/rfc2445/" => undef,
               },
            },
            "image" => {
               href => "https://foo.local/favicon.png",
               rel => "icon",
               cid => '123456789asd',
               properties => {
                   display => 'badge',
               },
            },
        },
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_localizations
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "alerts" => {
            "alert1" => {
                relativeTo => "before-start",
                offset => "PT5M",
                "action" => {
                    type => "email",
                    to => [{
                            email => "foo\@local",
                            name => "",
                    }],
                    subject => "A subject",
                },
            },
        },
        "locations" => {
            loc1 => { name => "on planet earth" },
        },
        "links" => {
            "http://info.cern.ch/" => {
                href => "http://info.cern.ch/",
                title => "the mother of all websites",
            },
        },
        "localizations" => {
            de => {
                title => "Titel",
                description => "Beschreibung",
                "alerts/alert1/action/subject" => "Betreff",
                "links/http:~1~1info.cern.ch~1/title" =>
                    "die Mutter aller Websites",
            },
            fr => {
                description => "la description",
                "locations/loc1/name" => "sur la planète terre",
            }
        },
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);

    $event->{localizations} = undef;
    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarId => $event->{calendarId},
            localizations => undef,
    });
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_locations
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $locations = {
        # A couple of sparse locations
        locA => {
            "name" => "location A",
            "description" => "my great description",
        },
        locB => {
            "name" => "location B",
            "uri" => "skype:username",
        },
        locC => {
            "coordinates" => "geo:48.208304,16.371602",
            "name" => "a place in Vienna",
        },
        locD => {
            "coordinates" => "geo:48.208304,16.371602",
            name => "",
        },
        locE => {
            name => "location E",
            linkIds => [ 'link1', 'link2' ],
        },
        # A full-blown location that will become a CONFERENCE,
        # if the JSON parser isn't unfortunate to pick this
        # as the first location to generate.
        locF => {
            name => "location F",
            description => "a description",
            rel => "virtual",
            features => [ "screen", "video" ],
            timeZone => "Europe/Vienna",
            coordinates => "geo:48.2010,16.3695,183",
            uri => "https://somewhere.local",
            linkIds =>  [ 'link1', 'link2' ],
        },
        # A full-blown location that will become a LOCATION
        locG => {
            name => "location G",
            description => "a description",
            features => [ "screen", "video" ],
            timeZone => "Europe/Vienna",
            coordinates => "geo:48.2010,16.3695,183",
            uri => "https://somewhere.local",
            linkIds =>  [ 'link1', 'link2' ],
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
        "freeBusyStatus"=> "free",
        "locations" => $locations,
        "links" => {
            link1 => { href => 'https://foo.local' },
            link2 => { href => 'https://bar.local' },
        },
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_locations_single
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $locations = {
        # A full-blown location that will become a LOCATION
        locF => {
            name => "location F",
            rel => "unknown",
            description => "a description",
            features => [ "screen", "video" ],
            timeZone => "Europe/Vienna",
            coordinates => "geo:48.2010,16.3695,183",
            uri => "https://somewhere.local",
            linkIds =>  [ 'link1', 'link2' ],
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
        "freeBusyStatus"=> "free",
        "locations" => $locations,
        "links" => {
            link1 => { href => 'https://foo.local' },
            link2 => { href => 'https://bar.local' },
        },
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_recurrence
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $recurrence = {
        frequency => "monthly",
        interval => 2,
        firstDayOfWeek => "su",
        count => 1024,
        byDay => [{
                day => "mo",
                nthOfPeriod => -2,
            }, {
                day => "sa",
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
        "freeBusyStatus"=> "busy",
        "recurrenceRule" => $recurrence,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_recurrenceoverrides
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $recurrence = {
        frequency => "monthly",
        count => 12,
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2016-01-01T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "locations" => {
            locA => {
                "name" => "location A",
                "uri" => "skype:username",
            },
            locB => {
                "coordinates" => "geo:48.208304,16.371602",
            },
        },
        "links" => {
            "http://jmap.io/spec.html#calendar-events" => {
                href => "http://jmap.io/spec.html#calendar-events",
                title => "the spec",
            },
            "https://tools.ietf.org/html/rfc5545" => {
                href => "https://tools.ietf.org/html/rfc5545",
            },
        },
        "recurrenceRule" => $recurrence,
        "recurrenceOverrides" => {
            "2016-02-01T09:00:00" => undef,
            "2016-02-03T09:00:00" => {},
            "2016-04-01T10:00:00" => {
                "description" => "don't come in without an April's joke!",
                "locations/locA/name" => "location A exception",
                "links/https:~1~1tools.ietf.org~1html~1rfc5545/title" => "RFC 5545",
            },
            "2016-05-01T10:00:00" => {
                "title" => "Labour Day",
            },
            "2016-06-01T10:00:00" => {
                freeBusyStatus => "free",
            },
            "2016-07-01T09:00:00" => {
                "uid" => "foo",
            },
        },
    };


    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    delete $event->{recurrenceOverrides}{"2016-07-01T09:00:00"}; # ignore patch with 'uid'
    $self->assert_normalized_event_equals($ret, $event);

    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarId => $event->{calendarId},
            title => "updated title",
    });
    $event->{title} = "updated title";
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_participants
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

=pod
=cut

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => {
            "imip" => "mailto:foo\@local",
            "web" => "http://local/rsvp",

        },
        "participants" => {
            'foo@local' => {
                name => 'Foo',
                email => 'foo@local',
                kind => 'individual',
                roles => [ 'owner', 'chair' ],
                locationId => 'loc1',
                rsvpResponse => 'accepted',
                participation => 'required',
                rsvpWanted => JSON::false,
                linkIds => [ 'loc1' ],
            },
            'bar@local' => {
                name => 'Bar',
                email => 'bar@local',
                kind => 'individual',
                roles => [ 'attendee' ],
                locationId => 'loc2',
                rsvpResponse => 'needs-action',
                participation => 'required',
                rsvpWanted => JSON::true,
                delegatedTo => [ 'bam@local' ],
                memberOf => [ 'group@local' ],
                linkIds => [ 'link1' ],
            },
            'bam@local' => {
                name => 'Bam',
                email => 'bam@local',
                roles => [ 'attendee' ],
                delegatedFrom => [ 'bar@local' ],
                scheduleSequence => 7,
                scheduleUpdated => '2018-07-06T05:03:02Z',
            },
            'group@local' => {
                name => 'Group',
                kind => 'group',
                roles => [ 'attendee' ],
                email => 'group@local',
            },
            'resource@local' => {
                name => 'Some resource',
                kind => 'resource',
                roles => [ 'attendee' ],
                email => 'resource@local',
            },
            'location@local' => {
                name => 'Some location',
                kind => 'location',
                roles => [ 'attendee' ],
                email => 'location@local',
                locationId => 'loc1',
            },
        },
        locations => {
            loc1 => {
                name => 'location1',
                rel => 'virtual',
                features => [ 'video', 'moderator' ],
                uri => 'https://somewhere.local/moderator',
            },
            loc2 => {
                name => 'location2',
                rel => 'virtual',
                features => [ 'video' ],
                uri => 'https://somewhere.local',
            },
        },
        links => {
            link1 => {
                href => 'https://somelink.local',
            },
        },
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_alerts
    :JMAP :min_version_3_1
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
                htmlBody => "<html><body>baz</body></html>",
                acknowledged => "2015-11-07T08:57:00Z",
                attachments => {
                    att1 => {
                        href => "https://local/some.jpg",
                        type => "image/jpeg",
                    }
                },
            },
        },
        alert2 => {
            relativeTo => "after-start",
            offset => "PT1H",
            action => {
                type => "display",
                snoozed => "2015-11-07T10:05:00Z",
                mediaLinks => {
                    alertLink1 => {
                        type => 'video/ogg',
                        href => 'https://local/bar.ogg'
                    }
                },
            },
        },
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT2H",
        "timeZone" => "Europe/London",
        "isAllDay"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "alerts" => $alerts,
        "useDefaultAlerts" => JSON::true,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($ret, $event);
}

sub test_calendarevent_set_participantid
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $participants = {
        "foo\@local" => {
            name => "",
            email => "foo\@local",
            roles => ["attendee"],
            locationId => "locX",
        },
        "you" => {
            name => "Cassandane",
            email => "cassandane\@example.com",
            roles => ["owner"],
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
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => { imip => "mailto:cassandane\@example.com" },
        "participants" => $participants,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $event->{participantId} = 'you';

    $self->assert_normalized_event_equals($ret, $event);
}


sub test_calendarevent_set_isallday
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $event = {
        "calendarId" => "Default",
        "title" => "foo",
        "description" => "foo's description",
        "freeBusyStatus" => "busy",
        "isAllDay" => JSON::true,
    };

    my $res;

    foreach (undef, 'Europe/Vienna') {

        $event->{timeZone} = $_;

        xlog "create all-day event (with erroneous start)";
        $event->{start} = "2015-10-06T16:45:00";
        $res = $jmap->CallMethods([['CalendarEvent/set', {
            create => { "1" => $event, }
        }, "R1"]]);
        $self->assert_str_equals("invalidProperties", $res->[0][1]{notCreated}{"1"}{type});
        $self->assert_str_equals("start", $res->[0][1]{notCreated}{"1"}{properties}[0]);

        xlog "create all-day event (with erroneous duration)";
        $event->{start} = "2015-10-06T00:00:00";
        $event->{duration} = "PT15M";
        $res = $jmap->CallMethods([['CalendarEvent/set', {
            create => { "1" => $event, }
        }, "R1"]]);
        $self->assert_str_equals("invalidProperties", $res->[0][1]{notCreated}{"1"}{type});
        $self->assert_str_equals("duration", $res->[0][1]{notCreated}{"1"}{properties}[0]);

        xlog "create all-day event";
        $event->{start} = "2015-10-06T00:00:00";
        $event->{duration} = "P1D";
        $res = $jmap->CallMethods([['CalendarEvent/set', {
            create => { "1" => $event, }
        }, "R1"]]);
        $self->assert_not_null($res->[0][1]{created}{"1"});
    }
}

sub test_calendarevent_set_move
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendars A and B";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                        "1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                        },
                        "2" => {
                            name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]
    ]);
    my $calidA = $res->[0][1]{created}{"1"}{id};
    my $calidB = $res->[0][1]{created}{"2"}{id};

    xlog "create event in calendar $calidA";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "foo's description",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        }
                    }}, "R1"]]);
    my $state = $res->[0][1]{newState};
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get calendar $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_str_equals($calidA, $event->{calendarId});
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog "move event to unknown calendar";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id => {
                            "calendarId" => "nope",
                        }
                    }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals($state, $res->[0][1]{newState});

    xlog "get calendar $id from untouched calendar $calidA";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_str_equals($calidA, $event->{calendarId});

    xlog "move event to calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id => {
                            "calendarId" => $calidB,
                        }
                    }}, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $state = $res->[0][1]{newState};

    xlog "get calendar $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_str_equals($calidB, $event->{calendarId});
}

sub test_calendarevent_set_shared
    :JMAP :min_version_3_1
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog "create shared account";
    $admintalk->create("user.manifold");

    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    $admintalk->setacl("user.manifold", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", manifold => 'lrswipkxtecdn');

    xlog "create calendar";
    my $CalendarId1 = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId1);

    xlog "share $CalendarId1 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lr') or die;

    my $event =  {
        "calendarId" => $CalendarId1,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
    };

    xlog "create event (should fail)";
    my $res = $jmap->CallMethods([['CalendarEvent/set',{
                    accountId => 'manifold',
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{notCreated}{1});

    xlog "share $CalendarId1 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "create event";
    $res = $jmap->CallMethods([['CalendarEvent/set',{
                    accountId => 'manifold',
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {
                    accountId => 'manifold',
                    ids => [$id]},
    "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    $self->assert_normalized_event_equals($event, $ret);

    xlog "share $CalendarId1 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lr') or die;

    xlog "update event (should fail)";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId1,
                            "title" => "1(updated)",
                        },
    }}, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});

    xlog "share calendar home read-writable to user";
    $admintalk->setacl("user.manifold.#calendars", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "create another calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'manifold',
                    create => { "2" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    my $CalendarId2 = $res->[0][1]{created}{"2"}{id};
    $self->assert_not_null($CalendarId2);

    xlog "share $CalendarId1 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "share $CalendarId2 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lr') or die;

    xlog "move event (should fail)";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId2,
                            "title" => "1(updated)",
                        },
    }}, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});

    xlog "share $CalendarId2 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "move event";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId2,
                            "title" => "1(updated)",
                        },
    }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "share $CalendarId2 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lr') or die;

    xlog "destroy event (should fail)";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    destroy => [ $id ],
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notDestroyed}{$id});

    xlog "share $CalendarId2 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "destroy event";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    destroy => [ $id ],
    }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);
}


sub test_calendarevent_changes
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendars A and B";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                        "1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                        },
                        "2" => {
                            name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]
    ]);
    my $calidA = $res->[0][1]{created}{"1"}{id};
    my $calidB = $res->[0][1]{created}{"2"}{id};
    my $state = $res->[0][1]{newState};

    xlog "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        },
                        "2" => {
                            "calendarId" => $calidB,
                            "title" => "2",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "get zero calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', {sinceState => $state}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "update event #1 and #2";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id1 => {
                            "calendarId" => $calidA,
                            "title" => "1(updated)",
                        },
                        $id2 => {
                            "calendarId" => $calidB,
                            "title" => "2(updated)",
                        }
                    }}, "R1"]]);
    $self->assert_num_equals(2, scalar keys %{$res->[0][1]{updated}});

    xlog "get exactly one update";
    $res = $jmap->CallMethods([['CalendarEvent/changes', {
                    sinceState => $state,
                    maxChanges => 1
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::true);
    $state = $res->[0][1]{newState};

    xlog "get the final update";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "update event #1 and destroy #2";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidA,
                            "title" => "1(updated)",
                            "description" => "",
                        },
                    },
                    destroy => [ $id2 ]
                }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});

    xlog "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($id1, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "get zero calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', {sinceState => $state}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "move event #1 from calendar $calidA to $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidB,
                        },
                    }
                }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_str_equals($id1, $res->[0][1]{changed}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};

    xlog "update and remove event #1";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidB,
                            "title" => "1(goodbye)",
                        },
                    },
                    destroy => [ $id1 ]
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});

    xlog "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{changed}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $state = $res->[0][1]{newState};
}

sub test_calendarevent_query
:JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendars A and B";
    my $res = $jmap->CallMethods([
            ['Calendar/set', {
                    create => {
                        "1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                        },
                        "2" => {
                            name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                        }
                    }}, "R1"]
        ]);
    my $calidA = $res->[0][1]{created}{"1"}{id};
    my $calidB = $res->[0][1]{created}{"2"}{id};
    my $state = $res->[0][1]{newState};

    xlog "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "bar",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::false,
                            "start" => "2016-07-01T10:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                        "2" => {
                            "calendarId" => $calidB,
                            "title" => "foo",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2016-01-01T00:00:00",
                            "duration" => "P2D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "get unfiltered calendar event list";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "get filtered calendar event list with flat filter";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "after" => "2015-12-31T00:00:00Z",
                        "before" => "2016-12-31T23:59:59Z",
                        "text" => "foo",
                        "description" => "bar"
                    }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog "get filtered calendar event list";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "operator" => "AND",
                        "conditions" => [
                            {
                                "after" => "2015-12-31T00:00:00Z",
                                "before" => "2016-12-31T23:59:59Z"
                            },
                            {
                                "text" => "foo",
                                "description" => "bar"
                            }
                        ]
                    }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog "filter by calendar $calidA";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "inCalendars" => [ $calidA ],
                    }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog "filter by calendar $calidA or $calidB";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "inCalendars" => [ $calidA, $calidB ],
                    }
                }, "R1"] ]);
    $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 2);

    xlog "filter by calendar NOT in $calidA and $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "operator" => "NOT",
                        "conditions" => [{
                                "inCalendars" => [ $calidA, $calidB ],
                            }],
                    }}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 0);

    xlog "limit results";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { limit => 1 }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 1);

    xlog "skip result a position 1";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { position => 1 }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 1);
}

sub test_calendarevent_query_shared
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");

    xlog "create shared account";
    $admintalk->create("user.manifold");

    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog "share calendar home to user";
    $admintalk->setacl("user.manifold.#calendars", cassandane => 'lrswipkxtecdn');

    # run tests for both the main and shared account
    foreach ("cassandane", "manifold") {
        my $account = $_;

        xlog "create calendars A and B";
        my $res = $jmap->CallMethods([
                ['Calendar/set', {
                        accountId => $account,
                        create => {
                            "1" => {
                                name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true,
                            },
                            "2" => {
                                name => "B", color => "blue", sortOrder => 1, isVisible => JSON::true
                            }
                        }}, "R1"]
            ]);
        my $calidA = $res->[0][1]{created}{"1"}{id};
        my $calidB = $res->[0][1]{created}{"2"}{id};
        my $state = $res->[0][1]{newState};

        xlog "create event #1 in calendar $calidA and event #2 in calendar $calidB";
        $res = $jmap->CallMethods([['CalendarEvent/set', {
                        accountId => $account,
                        create => {
                            "1" => {
                                "calendarId" => $calidA,
                                "title" => "foo",
                                "description" => "bar",
                                "freeBusyStatus" => "busy",
                                "isAllDay" => JSON::false,
                                "start" => "2016-07-01T10:00:00",
                                "timeZone" => "Europe/Vienna",
                                "duration" => "PT1H",
                            },
                            "2" => {
                                "calendarId" => $calidB,
                                "title" => "foo",
                                "description" => "",
                                "freeBusyStatus" => "busy",
                                "isAllDay" => JSON::true,
                                "start" => "2016-01-01T00:00:00",
                                "duration" => "P2D",
                            }
                        }}, "R1"]]);
        my $id1 = $res->[0][1]{created}{"1"}{id};
        my $id2 = $res->[0][1]{created}{"2"}{id};

        xlog "Run squatter";
        $self->{instance}->run_command({cyrus => 1}, 'squatter');

        xlog "get unfiltered calendar event list";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', { accountId => $account }, "R1"] ]);
        $self->assert_num_equals(2, $res->[0][1]{total});
        $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($account, $res->[0][1]{accountId});

        xlog "get filtered calendar event list with flat filter";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "after" => "2015-12-31T00:00:00Z",
                            "before" => "2016-12-31T23:59:59Z",
                            "text" => "foo",
                            "description" => "bar"
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(1, $res->[0][1]{total});
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

        xlog "get filtered calendar event list";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "operator" => "AND",
                            "conditions" => [
                                {
                                    "after" => "2015-12-31T00:00:00Z",
                                    "before" => "2016-12-31T23:59:59Z"
                                },
                                {
                                    "text" => "foo",
                                    "description" => "bar"
                                }
                            ]
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(1, $res->[0][1]{total});
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

        xlog "filter by calendar $calidA";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "inCalendars" => [ $calidA ],
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

        xlog "filter by calendar $calidA or $calidB";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "inCalendars" => [ $calidA, $calidB ],
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 2);

        xlog "filter by calendar NOT in $calidA and $calidB";
        $res = $jmap->CallMethods([['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "operator" => "NOT",
                            "conditions" => [{
                                    "inCalendars" => [ $calidA, $calidB ],
                                }],
                        }}, "R1"]]);
        $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 0);

        xlog "limit results";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', { accountId => $account, limit => 1 }, "R1"] ]);
        $self->assert_num_equals($res->[0][1]{total}, 2);
        $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 1);

        xlog "skip result a position 1";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', { accountId => $account, position => 1 }, "R1"] ]);
        $self->assert_num_equals($res->[0][1]{total}, 2);
        $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 1);
    }
}

sub test_calendarevent_query_datetime
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog "create events";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2016-01-01T08:00:00Z End: 2016-01-01T09:00:00Z
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::false,
                            "start" => "2016-01-01T09:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                    }}, "R1"]]);

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    # Exact start and end match
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T08:00:00Z",
                        "before" => "2016-01-01T09:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Check that boundaries are exclusive
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T09:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "before" =>  "2016-01-01T08:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});

    # Embedded subrange matches
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T08:15:00Z",
                        "before" => "2016-01-01T08:45:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Overlapping subrange matches
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T08:15:00Z",
                        "before" => "2016-01-01T09:15:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T07:45:00Z",
                        "before" => "2016-01-01T08:15:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Create an infinite recurring datetime event
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2017-01-01T08:00:00Z End: eternity
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "e",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::false,
                            "start" => "2017-01-01T09:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                            "recurrenceRule" => {
                                "frequency" => "yearly",
                            },
                        },
                    }}, "R1"]]);
    # Assert both events are found
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    # Search close to eternity
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2038-01-01T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
}

sub test_calendarevent_query_date
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog "create events";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2016-01-01 End: 2016-01-03
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2016-01-01T00:00:00",
                            "duration" => "P3D",
                        },
                    }}, "R1"]]);

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    # Match on start and end day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00Z",
                        "before" => "2016-01-03T23:59:59Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match after on the first second of the start day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00Z",
                        "before" => "2016-01-03T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match before on the last second of the end day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-03T23:59:59Z",
                        "before" => "2016-01-03T23:59:59Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match on interim day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-02T00:00:00Z",
                        "before" => "2016-01-03T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match on partially overlapping timerange
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2015-12-31T12:00:00Z",
                        "before" => "2016-01-01T12:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2015-01-03T12:00:00Z",
                        "before" => "2016-01-04T12:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Difference from the spec: 'before' is defined to be exclusive, but
    # a full-day event starting on that day still matches.
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2015-12-31T00:00:00Z",
                        "before" => "2016-01-01T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # In DAV db the event ends at 20160104. Test that it isn't returned.
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-04T00:00:00Z",
                        "before" => "2016-01-04T23:59:59Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});

    # Create an infinite recurring datetime event
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2017-01-01T08:00:00Z End: eternity
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "2",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2017-01-01T00:00:00",
                            "duration" => "P1D",
                            "recurrenceRule" => {
                                "frequency" => "yearly",
                            },
                        },
                    }}, "R1"]]);
    # Assert both events are found
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    # Search close to eternity
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2038-01-01T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
}

sub test_calendarevent_query_text
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => 'Default',
                            "title" => "foo",
                            "description" => "bar",
                            "locations" => {
                                "loc1" => {
                                    name => "baz",
                                },
                            },
                            "freeBusyStatus" => "busy",
                            "start"=> "2016-01-01T09:00:00",
                            "duration"=> "PT1H",
                            "timeZone" => "Europe/London",
                            "isAllDay"=> JSON::false,
                            "replyTo" => { imip => "mailto:tux\@local" },
                            "participants" => {
                                "tux\@local" => {
                                    name => "",
                                    email => "tux\@local",
                                    roles => ["owner"],
                                    locationId => "loc1",
                                },
                                "qux\@local" => {
                                    name => "Quuks",
                                    email => "qux\@local",
                                    roles => ["attendee"],
                                },
                            },
                            recurrenceRule => {
                                frequency => "monthly",
                                count => 12,
                            },
                            "recurrenceOverrides" => {
                                "2016-04-01T10:00:00" => {
                                    "description" => "blah",
                                    "locations/loc1/name" => "blep",
                                },
                                "2016-05-01T10:00:00" => {
                                    "title" => "boop",
                                },
                            },
                        },
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my %textqueries = (
        title => "foo",
        title => "boop",
        description => "bar",
        description => "blah",
        location => "baz",
        location => "blep",
        owner => "tux",
        owner => "tux\@local",
        attendee => "qux",
        attendee => "qux\@local",
        attendee => "Quuks",
    );

    while (my ($propname, $propval) = each %textqueries) {

        # Assert that catch-all text search matches
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        "filter" => {
                            "text" => $propval,
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(1, $res->[0][1]{total});
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

        # Sanity check catch-all text search
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        "filter" => {
                            "text" => "nope",
                        }
                    }, "R1"] ]);
        $self->assert_num_equals($res->[0][1]{total}, 0);

        # Assert that search by property name matches
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        "filter" => {
                            $propname => $propval,
                        }
                    }, "R1"] ]);
        $self->assert_num_equals($res->[0][1]{total}, 1);
        $self->assert_num_equals(scalar @{$res->[0][1]{ids}}, 1);
        $self->assert_str_equals($res->[0][1]{ids}[0], $id1);

        # Sanity check property name search
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        "filter" => {
                            $propname => "nope",
                        }
                    }, "R1"] ]);
        $self->assert_num_equals($res->[0][1]{total}, 0);
    }
}


sub test_calendarevent_set_caldav
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                        "1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]]);
    my $calid = $res->[0][1]{created}{"1"}{id};

    xlog "create event in calendar";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "foo",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get x-href of event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $xhref = $res->[0][1]{list}[0]{"x-href"};
    my $state = $res->[0][1]{state};

    xlog "GET event $id in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    my $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:foo/, $ical);

    xlog "DELETE event $id via CalDAV";
    $res = $caldav->Request('DELETE', $xhref);

    xlog "get (non-existent) event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);

    xlog "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
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
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{changed}});
    $self->assert_equals($res->[0][1]{changed}[0], $id);
    $state = $res->[0][1]{newState};

    xlog "get x-href of event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $xhref = $res->[0][1]{list}[0]{"x-href"};
    $state = $res->[0][1]{state};

    xlog "update event $id";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        "$id" => {
                            "calendarId" => $calid,
                            "title" => "bam",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-10T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);

    xlog "GET event $id in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:bam/, $ical);

    xlog "destroy event $id";
    $res = $jmap->CallMethods([['CalendarEvent/set', { destroy => [$id] }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
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

sub test_calendarevent_set_schedule_request
    :JMAP :min_version_3_1
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
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => "Default",
                            "title" => "foo",
                            "description" => "foo's description",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "timeZone" => "Australia/Melbourne",
                            "duration" => "PT1H",
                            "replyTo" => { imip => "mailto:cassandane\@example.com"},
                            "participants" => $participants,
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:REQUEST");
}

sub test_calendarevent_set_schedule_reply
    :JMAP :min_version_3_1
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
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
        "1" => {
            "calendarId" => "Default",
            "title" => "foo",
            "description" => "foo's description",
            "freeBusyStatus" => "busy",
            "isAllDay" => JSON::false,
            "start" => "2015-10-06T16:45:00",
            "timeZone" => "Australia/Melbourne",
            "duration" => "PT1H",
            "replyTo" => { imip => "mailto:bugs\@example.com" },
            "participants" => $participants,
        }
    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "send reply as attendee to organizer";
    $participants->{att}->{rsvpResponse} = "tentative";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
        $id => {
            replyTo => { imip => "mailto:bugs\@example.com" },
            participants => $participants,
         }
    }}, "R1"]]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:REPLY");
}

sub test_calendarevent_set_schedule_cancel
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    my $calid = $res->[0][1]{created}{"1"}{id};

    xlog "send invitation as organizer";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "foo",
                            "description" => "foo's description",
                            "freeBusyStatus" => "busy",
                            "isAllDay" => JSON::false,
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
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "cancel event as organizer";
    $res = $jmap->CallMethods([['CalendarEvent/set', { destroy => [$id]}, "R1"]]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:CANCEL");
}

sub test_misc_creationids
:JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create and get calendar and event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', { create => { "c1" => {
            name => "foo",
            color => "coral",
            sortOrder => 2,
            isVisible => \1,
        }}}, 'R1'],
        ['CalendarEvent/set', { create => { "e1" => {
            "calendarId" => "#c1",
            "title" => "bar",
            "description" => "description",
            "freeBusyStatus" => "busy",
            "isAllDay" => JSON::true,
            "start" => "2015-10-06T00:00:00",
        }}}, "R2"],
        ['CalendarEvent/get', {ids => ["#e1"]}, "R3"],
        ['Calendar/get', {ids => ["#c1"]}, "R4"],
    ]);
    my $event = $res->[2][1]{list}[0];
    $self->assert_str_equals($event->{title}, "bar");

    my $calendar = $res->[3][1]{list}[0];
    $self->assert_str_equals($calendar->{name}, "foo");

    $self->assert_str_equals($event->{calendarId}, $calendar->{id});
}

sub test_misc_timezone_expansion
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Europe/Vienna",
        "isAllDay"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
        "recurrenceRule" => {
            frequency => "weekly",
        },
    };

    my $ret = $self->createandget_event($event);

    my $CalDAV = $self->{caldav};
    $ret = $CalDAV->Request('GET', $ret->{"x-href"}, undef, 'CalDAV-Timezones' => 'T');

    # Assert that we get two RRULEs, one for DST and one for leaving DST
    $ret->{content} =~ /.*(BEGIN:VTIMEZONE\r\n.*END:VTIMEZONE).*/s;
    my $rrulecount = () = $1 =~ /RRULE/gi;
    $self->assert_num_equals(2, $rrulecount);
}

sub test_calendarevent_set_uid
    :JMAP :min_version_3_1
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "isAllDay"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "attachments"=> undef,
        "participants" => undef,
        "alerts"=> undef,
    };

    # An empty UID generates a random uid.
    my $ret = $self->createandget_event($event);
    my($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_not_null($ret->{id});
    $self->assert_str_equals($ret->{id}, $ret->{uid});
    $self->assert_str_equals($ret->{id}, $filename);

    # A sane UID maps to both the JMAP id and the DAV resource.
    $event->{uid} = "458912982-some_UID";
    delete $event->{id};
    $ret = $self->createandget_event($event);
    ($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_str_equals($event->{uid}, $filename);
    $self->assert_str_equals($event->{uid}, $ret->{id});

    # A non-pathsafe UID maps to the JMAP id but not the DAV resource.
    $event->{uid} = "a/bogus/path#uid";
    delete $event->{id};
    $ret = $self->createandget_event($event);
    ($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_not_null($filename);
    $self->assert_str_not_equals($event->{uid}, $filename);
    $self->assert_str_equals($event->{uid}, $ret->{id});
}


1;
