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

package Cassandane::Cyrus::JMAP;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use JSON::XS;
use Net::CalDAVTalk;
use Net::CardDAVTalk;
use Mail::JMAPTalk;
use Data::Dumper;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(conversations => 'yes');
    $config->set(httpmodules => 'carddav caldav jmap');
    $config->set(httpallowcompress => 'no');
    $config->set(sasl_mech_list => 'PLAIN LOGIN');
    return $class->SUPER::new({
	config => $config,
	services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my $service = $self->{instance}->get_service("http");
    $self->{carddav} = Net::CardDAVTalk->new(
	user => 'cassandane',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );
    $self->{caldav} = Net::CalDAVTalk->new(
	user => 'cassandane',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );
    $self->{jmap} = Mail::JMAPTalk->new(
	user => 'cassandane',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/jmap',
    );
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_jmap_multicontact
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->Request([['setContacts', {
        create => {
            "#1" => {firstName => "first", lastName => "last"},
            "#2" => {firstName => "second", lastName => "last"},
        }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id1, 'notacontact']}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_not_null($fetch->[0][1]{notFound});
    $self->assert_str_equals($fetch->[0][1]{notFound}[0], 'notacontact');

    $fetch = $jmap->Request([['getContacts', {ids => [$id2]}, "R3"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R3');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_null($fetch->[0][1]{notFound});

    $fetch = $jmap->Request([['getContacts', {ids => [$id1, $id2]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_num_equals(scalar @{$fetch->[0][1]{list}}, 2);
    $self->assert_null($fetch->[0][1]{notFound});

    $fetch = $jmap->Request([['getContacts', {}, "R5"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R5');
    $self->assert_num_equals(scalar @{$fetch->[0][1]{list}}, 2);
    $self->assert_null($fetch->[0][1]{notFound});
}


sub test_jmap_create
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
}

sub test_setcontacts_state
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contact";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};
    my $state = $res->[0][1]{newState};

    xlog "get contact $id";
    $res = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contacts');
    $self->assert_str_equals($res->[0][2], 'R2');
    $self->assert_str_equals($res->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_str_equals($res->[0][1]{state}, $state);

    xlog "update $id with state token $state";
    $res = $jmap->Request([['setContacts', {
                    ifInState => $state,
                    update => {$id =>
                        {firstName => "first", lastName => "last"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "update $id with expired state token $oldState";
    $res = $jmap->Request([['setContacts', {
                    ifInState => $oldState,
                    update => {$id =>
                        {firstName => "first", lastName => "last"}
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][1]{type}, 'stateMismatch');

    xlog "get contact $id to make sure state didn't change";
    $res = $jmap->Request([['getContacts', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{state}, $state);

    xlog "destroy $id with expired state token $oldState";
    $res = $jmap->Request([['setContacts', {
                    ifInState => $oldState,
                    destroy => [$id]
                }, "R1"]]);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][1]{type}, 'stateMismatch');

    xlog "destroy contact $id with current state";
    $res = $jmap->Request([
            ['setContacts', {
                    ifInState => $state,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);
}

sub test_getcalendars
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

    my $id = $res->[0][1]{created}{"#1"}{id};
    my $state = $res->[0][1]{newState};

    xlog "get calendar updates without changes";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_str_equals(scalar @{$res->[0][1]{changed}}, 0);
    $self->assert_str_equals(scalar @{$res->[0][1]{removed}}, 0);

    xlog "update calendar $id";
    $res = $jmap->Request([
            ['setCalendars', {
                    ifInState => $state,
                    update => {"$id" => {name => "bar"}}
            }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);

    xlog "get calendar updates with cannotCalculateChanges error";
    $res = $jmap->Request([['getCalendarUpdates', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals($res->[0][0], "error");
    $self->assert_str_equals($res->[0][1]{type}, "cannotCalculateChanges");
}


sub test_setcalendars_error
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

sub test_importance_later
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0.0);

    $res = $jmap->Request([['setContacts', {update => {$id => {"x-importance" => -0.1}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -0.1);
}

sub test_importance_upfront
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with importance in initial create";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"firstName" => "second"}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);
}

sub test_importance_multiedit
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"firstName" => "second", "x-importance" => -0.2}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -0.2);
}

sub test_importance_zero_multi
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"firstName" => "second", "x-importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0);
}

sub test_importance_zero_byself
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);

    $res = $jmap->Request([['setContacts', {update => {$id => {"x-importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0);
}

sub test_getcalendarevents
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

    xlog "get x-href of calendar $calid";
    $res = $jmap->Request([['getCalendars', {ids => [$calid]}, "R1"]]);
    my $xhref = $res->[0][1]{list}[0]{"x-href"};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog "create event (via CalDAV)";
    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $href = "$xhref/$id.ics";

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Vienna:20160928T160000
RRULE:FREQ=MONTHLY;BYDAY=+2MO,TU,-3SU,+1MO,-2TH,-1SA
DTEND;TZID=Europe/Vienna:20160928T170000
UID:$id
DTSTAMP:20150928T132434Z
RDATE;TZID=Europe/Vienna:20161107T160000
RDATE;TZID=Europe/Vienna:20161106T160000
EXDATE;TZID=Europe/Vienna:20161004T160000
DESCRIPTION:Remember the yep.
SEQUENCE:9
SUMMARY:Yep
LAST-MODIFIED:20150928T132434Z
ATTENDEE;CN=Homer Simpson;PARTSTAT=ACCEPTED:mailto:homer\@example.com
ATTENDEE;PARTSTAT=TENTATIVE;DELEGATED-FROM="mailto:lenny\@example.com";CN=Carl Carlson:mailto:carl\@example.com
ATTENDEE;PARTSTAT=DELEGATED;DELEGATED-TO="mailto:carl\@example.com";CN=Lenny Leonard:mailto:lenny\@example.com
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED;CN=Larry Burns:mailto:larry\@example.com
ORGANIZER;CN="Monty Burns":mailto:smithers\@example.com
ATTACH;FMTTYPE=application/octet-stream;SIZE=4480:https://www.user.fm/files/v1-123456789abcde
ATTACH:https://www.user.fm/files/v1-edcba987654321
BEGIN:VALARM
X-WR-ALARMUID:0CF835D0-CFEB-44AE-904A-C26AB62B73BB
UID:0CF835D0-CFEB-44AE-904A-C26AB62B73BB
TRIGGER:-PT5M
ACTION:EMAIL
ATTENDEE:mailto:foo\@example.com
SUMMARY:Event alert: 'Yep' starts in 5 minutes
DESCRIPTION:Your event 'Yep' starts in 5 minutes
END:VALARM
END:VEVENT
BEGIN:VEVENT
TRANSP:OPAQUE
DTEND;TZID=Europe/Vienna:20160930T180000
UID:$id
DTSTAMP:20150928T135221Z
DESCRIPTION:Remember an exceptional yep.
SEQUENCE:10
X-APPLE-EWS-BUSYSTATUS:FREE
RECURRENCE-ID;TZID=Europe/Vienna:20160930T160000
SUMMARY:Exceptional Yep
LAST-MODIFIED:20150928T132434Z
DTSTART;TZID=Europe/Vienna:20160930T170000
CREATED:20150928T135212Z
ORGANIZER;CN="Monty Burns":mailto:smithers\@example.com
END:VEVENT
END:VCALENDAR
EOF

  $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

  xlog "get event $id";
  $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);

  my $event = $res->[0][1]{list}[0];
  $self->assert_not_null($event);
  $self->assert_str_equals($event->{calendarId}, $calid);
  $self->assert_str_equals($event->{summary}, "Yep");
  $self->assert_str_equals($event->{description}, "Remember the yep.");
  $self->assert_equals($event->{showAsFree}, JSON::true);
  $self->assert_equals($event->{isAllDay}, JSON::false);
  $self->assert_str_equals($event->{start}, "2016-09-28T16:00:00");
  $self->assert_str_equals($event->{end}, "2016-09-28T17:00:00");
  $self->assert_str_equals($event->{startTimeZone}, "Europe/Vienna");
  $self->assert_str_equals($event->{endTimeZone}, "Europe/Vienna");
  $self->assert_not_null($event->{recurrence});
  $self->assert_str_equals($event->{recurrence}{frequency}, "monthly");
  $self->assert_deep_equals($event->{recurrence}{byDay}, [-21, -10, -1, 2, 8, 15]);
  $self->assert_not_null($event->{inclusions});
  $self->assert_num_equals(scalar @{$event->{inclusions}}, 2);
  $self->assert_str_equals($event->{inclusions}[0], "2016-11-06T16:00:00");
  $self->assert_str_equals($event->{inclusions}[1], "2016-11-07T16:00:00");
  $self->assert_not_null($event->{exceptions});
  $self->assert(exists $event->{exceptions}{"2016-10-04T16:00:00"});
  $self->assert_not_null($event->{exceptions}{"2016-09-30T16:00:00"});
  $self->assert_str_equals($event->{exceptions}{"2016-09-30T16:00:00"}{"summary"}, "Exceptional Yep");
  $self->assert_str_equals($event->{exceptions}{"2016-09-30T16:00:00"}{"showAsFree"}, JSON::false);
  $self->assert_not_null($event->{alerts});
  $self->assert_num_equals(scalar @{$event->{alerts}}, 1);
  $self->assert_num_equals($event->{alerts}[0]{minutesBefore}, 5);
  $self->assert_str_equals($event->{alerts}[0]{type}, "email");
  $self->assert_not_null($event->{attendees});
  $self->assert_num_equals(scalar @{$event->{attendees}}, 4);
  $self->assert_not_null($event->{organizer});
  $self->assert_str_equals($event->{organizer}{name}, "Monty Burns");
  $self->assert_str_equals($event->{organizer}{email}, "smithers\@example.com");
  $self->assert_equals($event->{organizer}{isYou}, JSON::false);
  $self->assert_num_equals(scalar @{$event->{attachments}}, 2);
  $self->assert_str_equals($event->{attachments}[0]{blobId}, "https://www.user.fm/files/v1-123456789abcde");
  $self->assert_str_equals($event->{attachments}[0]{type}, "application/octet-stream");
  $self->assert_null($event->{attachments}[0]{name});
  $self->assert_num_equals($event->{attachments}[0]{size}, 4480);
  $self->assert_str_equals($event->{attachments}[1]{blobId}, "https://www.user.fm/files/v1-edcba987654321");
  $self->assert_null($event->{attachments}[1]{type});
  $self->assert_null($event->{attachments}[1]{name});
  $self->assert_null($event->{attachments}[1]{size});
}

sub test_getcalendarevents_infinite_delegates
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

    xlog "get x-href of calendar $calid";
    $res = $jmap->Request([['getCalendars', {ids => [$calid]}, "R1"]]);
    my $xhref = $res->[0][1]{list}[0]{"x-href"};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog "create event (via CalDAV)";
    my $id = "642FDC66-B1C9-45D7-8441-B57BE3ADF3C6";
    my $href = "$xhref/$id.ics";

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

  $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

  xlog "get event $id";
  $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);

  my $attendees = $res->[0][1]{list}[0]{attendees};
  $self->assert_num_equals(scalar @{$attendees}, 2);
  $self->assert_str_equals($attendees->[0]{rsvp}, "");
  $self->assert_str_equals($attendees->[1]{rsvp}, "");
}

sub test_setcalendarevents {
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
    my $state = $res->[0][1]{newState};

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Australia/Melbourne",
                            "alerts" => [
                                { "type" => "alert", "minutesBefore" => 15 },
                                { "type" => "email", "minutesBefore" => -15 }
                            ],
                            "organizer" => {
                                "name" => "Daffy Duck",
                                "email" => "daffy\@example.com"
                            },
                            "attendees" => [{
                                    "name" => "Bugs Bunny",
                                    "email" => "bugs\@example.com",
                                    "rsvp" => "maybe"
                            }],
                            "recurrence" => {
                                "frequency" => "daily",
                                "byDay" => [-21, -10, -1, 2, 8, 15],
                                "byMonth" => [2, 8],
                                "until" => "2015-10-08T16:45:00"
                            },
                            "inclusions" => [ "2015-10-07T15:15:00" ],
                            "exceptions" => {
                                "2015-10-11T11:30:15" => {
                                    "summary" => "bar",
                                    "showAsFree" => JSON::false,
                                    "isAllDay" => JSON::false,
                                    "start" => "2015-10-11T11:30:15",
                                    "startTimeZone" => "Australia/Melbourne",
                                    "end" => "2015-10-11T12:15:00",
                                    "endTimeZone" => "Australia/Melbourne"
                                },
                                "2015-10-12T11:30:15" => undef,
                            },
                            "attachments" => [{
                                    "blobId" => "https://www.user.fm/files/v1-123456789abcde",
                                    "type" => "application/octet-stream",
                                    "name" => "", # XXX Currently ignored
                                    "size" => 4480
                            }]
                        }
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarEventsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $state = $res->[0][1]{newState};

    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);
    my $event = $res->[0][1]{list}[0];
    #basic properties
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{summary}, 'foo');
    $self->assert_str_equals($event->{description}, "foo's description");
    $self->assert_str_equals($event->{location}, "foo's location");
    $self->assert_equals($event->{showAsFree}, JSON::false);
    $self->assert_equals($event->{isAllDay}, JSON::false);
    $self->assert_str_equals($event->{start}, '2015-10-06T16:45:00');
    $self->assert_str_equals($event->{startTimeZone}, 'Australia/Melbourne');
    $self->assert_str_equals($event->{end}, '2015-10-06T17:15:00');
    $self->assert_str_equals($event->{endTimeZone}, 'Australia/Melbourne');
    # alerts
    $self->assert_str_equals($event->{alerts}[0]{type}, "alert");
    $self->assert_num_equals($event->{alerts}[0]{minutesBefore}, 15);
    $self->assert_str_equals($event->{alerts}[1]{type}, "email");
    $self->assert_num_equals($event->{alerts}[1]{minutesBefore}, -15);
    # organizer and attendees
    $self->assert_str_equals($event->{organizer}{email}, "daffy\@example.com");
    $self->assert_str_equals($event->{organizer}{name}, "Daffy Duck");
    $self->assert_str_equals($event->{attendees}[0]{email}, "bugs\@example.com");
    $self->assert_str_equals($event->{attendees}[0]{name}, "Bugs Bunny");
    $self->assert_str_equals($event->{attendees}[0]{rsvp}, "maybe");
    # recurrence
    $self->assert_str_equals($event->{recurrence}{frequency}, "daily");
    $self->assert_deep_equals($event->{recurrence}{byDay}, [-21, -10, -1, 2, 8, 15]);
    $self->assert_deep_equals($event->{recurrence}{byMonth}, [2, 8]);
    $self->assert_str_equals($event->{recurrence}{until}, "2015-10-08T16:45:00");
    # inclusions
    $self->assert_str_equals($event->{inclusions}[0], "2015-10-07T15:15:00");
    # exceptions
    my $exc = $event->{exceptions}{"2015-10-11T11:30:15"};
    $self->assert_str_equals($exc->{summary}, "bar");
    $self->assert_equals($event->{showAsFree}, JSON::false);
    $self->assert_equals($event->{isAllDay}, JSON::false);
    $self->assert_str_equals($exc->{start}, "2015-10-11T11:30:15");
    $self->assert_str_equals($exc->{startTimeZone}, "Australia/Melbourne");
    $self->assert_str_equals($exc->{end}, "2015-10-11T12:15:00");
    $self->assert_str_equals($exc->{endTimeZone}, "Australia/Melbourne");
    $self->assert(exists $event->{exceptions}{"2015-10-11T11:30:15"});
    #attachments
    my $att = $event->{attachments}[0];
    $self->assert_str_equals($att->{blobId}, "https://www.user.fm/files/v1-123456789abcde");
    $self->assert_str_equals($att->{type}, "application/octet-stream");
    $self->assert_null($att->{name});
    $self->assert_num_equals($att->{size}, 4480);

    xlog "update event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "calendarId" => $calid,
                            "summary" => "baz",
                            "description" => "baz's description",
                            "location" => "baz's location",
                            "showAsFree" => JSON::true,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T18:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T19:15:00",
                            "endTimeZone" => "America/New_York"
                        }
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarEventsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $state = $res->[0][1]{newState};

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    #basic properties
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{summary}, 'baz');
    $self->assert_str_equals($event->{description}, "baz's description");
    $self->assert_str_equals($event->{location}, "baz's location");
    $self->assert_equals($event->{showAsFree}, JSON::true);
    $self->assert_equals($event->{isAllDay}, JSON::false);
    $self->assert_str_equals($event->{start}, '2015-10-06T18:45:00');
    $self->assert_str_equals($event->{startTimeZone}, 'Australia/Melbourne');
    $self->assert_str_equals($event->{end}, '2015-10-06T19:15:00');
    $self->assert_str_equals($event->{endTimeZone}, 'America/New_York');

    xlog "destroy event $id";
    $res = $jmap->Request([['setCalendarEvents', { destroy => [ $id ]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarEventsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $state = $res->[0][1]{newState};

    xlog "get destroyed $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id, "foo"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar(@{$res->[0][1]{notFound}}), 2);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);
    $self->assert_str_equals($res->[0][1]{notFound}[1], "foo");
}

sub test_setcalendarevents_update_recurrence {
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

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Australia/Melbourne",
                            "recurrence" => {
                                "frequency" => "daily",
                                "byDay" => [-21, -10, -1, 2, 8, 15],
                                "byMonth" => [2, 8],
                                "until" => "2015-10-08T16:45:00"
                            }
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{recurrence}{frequency}, "daily");
    $self->assert_deep_equals($event->{recurrence}{byDay}, [-21, -10, -1, 2, 8, 15]);
    $self->assert_deep_equals($event->{recurrence}{byMonth}, [2, 8]);
    $self->assert_str_equals($event->{recurrence}{until}, "2015-10-08T16:45:00");

    xlog "update recurrence of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "recurrence" => {
                                "frequency" => "weekly",
                                "until" => "2016-10-08T16:45:00"
                            }
                        }
                    }}, "R1"]]);

    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);

    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{recurrence}{frequency}, "weekly");
    $self->assert_null($event->{recurrence}{byDay});
    $self->assert_null($event->{recurrence}{byMonth});
    $self->assert_str_equals($event->{recurrence}{until}, "2016-10-08T16:45:00");

    xlog "do not touch recurrence of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "summary" => "baz",
                        }
                    }}, "R1"]]);

    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{recurrence}{frequency}, "weekly");
    $self->assert_null($event->{recurrence}{byDay});
    $self->assert_null($event->{recurrence}{byMonth});
    $self->assert_str_equals($event->{recurrence}{until}, "2016-10-08T16:45:00");

    xlog "update startTimeZone of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Asia/Bangkok",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Europe/Vienna"
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{recurrence}{until}, "2016-10-08T16:45:00");

    xlog "remove recurrence of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "calendarId" => $calid,
                            "summary" => "baz",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Asia/Bangkok",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Europe/Vienna",
                            "recurrence" => undef
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_null($event->{recurrence});
}

sub test_setcalendarevents_update_inclusions {
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

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Australia/Melbourne",
                            "recurrence" => {
                                "frequency" => "daily",
                                "count" => 5
                            },
                            "inclusions" => [ "2015-10-20T15:15:00" ]
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{inclusions}[0], "2015-10-20T15:15:00");

    xlog "update inclusions of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "inclusions" => [
                                "2015-11-21T13:00:00", "2016-01-01T14:00:00"
                            ]
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);

    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{inclusions}[0], "2015-11-21T13:00:00");
    $self->assert_str_equals($event->{inclusions}[1], "2016-01-01T14:00:00");

    xlog "do not touch inclusions of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "summary" => "baz",
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{inclusions}[1], "2016-01-01T14:00:00");

    xlog "update startTimeZone of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "start" => "2015-10-06T16:45:00",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Europe/Vienna",
                            "startTimeZone" => "Asia/Bangkok"
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);
    $self->assert_str_equals($event->{inclusions}[1], "2016-01-01T14:00:00");

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);

    xlog "remove inclusions of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "inclusions" => undef
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_null($event->{inclusions});
}

sub test_setcalendarevents_update_alerts {
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

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Australia/Melbourne",
                            "alerts" => [
                                { "type" => "alert", "minutesBefore" => 15 },
                                { "type" => "email", "minutesBefore" => -15 }
                            ],
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_num_equals(scalar @{$event->{alerts}}, 2);
    $self->assert_str_equals($event->{alerts}[0]{type}, "alert");
    $self->assert_num_equals($event->{alerts}[0]{minutesBefore}, 15);
    $self->assert_str_equals($event->{alerts}[1]{type}, "email");
    $self->assert_num_equals($event->{alerts}[1]{minutesBefore}, -15);

    xlog "update alerts of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "alerts" => [{ "type" => "alert", "minutesBefore" => 30 }]
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_num_equals(scalar @{$event->{alerts}}, 1);
    $self->assert_str_equals($event->{alerts}[0]{type}, "alert");
    $self->assert_num_equals($event->{alerts}[0]{minutesBefore}, 30);

    xlog "do not touch alerts of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "location" => "foo's location",
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_num_equals(scalar @{$event->{alerts}}, 1);
    $self->assert_str_equals($event->{alerts}[0]{type}, "alert");
    $self->assert_num_equals($event->{alerts}[0]{minutesBefore}, 30);

    xlog "remove alerts of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => { 
                            "alerts" => undef
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_null($event->{alerts});
}

sub test_setcalendarevents_update_exceptions_basic {
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
    my $state = $res->[0][1]{newState};

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo",
                            "location" => "foo",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Europe/Vienna",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Europe/Vienna",
                            "recurrence" => {
                                "frequency" => "daily",
                                "count" => 3
                            },
                            "exceptions" => {
                                "2015-10-07T16:45:00" => {
                                    "summary" => "one hour later",
                                    "start" => "2015-10-07T17:45:00",
                                    "end" => "2015-10-07T18:15:00"
                                },
                                "2015-10-08T16:45:00" => undef
                            }
                        }
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";

    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    my $exc = $event->{exceptions}{"2015-10-07T16:45:00"};
    $self->assert_str_equals($exc->{summary}, "one hour later");
    $self->assert_null($exc->{description});
    $self->assert_null($exc->{location});
    $self->assert_null($exc->{showAsFree});
    $self->assert_null($exc->{isAllDay});
    $self->assert_str_equals($exc->{start}, "2015-10-07T17:45:00");
    $self->assert_str_equals($exc->{end}, "2015-10-07T18:15:00");
    $self->assert(exists $event->{exceptions}{"2015-10-08T16:45:00"});

    xlog "update exception startTimeZone of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "exceptions" => {
                                "2015-10-07T16:45:00" => {
                                    "start" => "2015-10-07T17:45:00",
                                    "end" => "2015-10-07T18:15:00",
                                    "startTimeZone" => "Australia/Melbourne",
                                    "endTimeZone" => "Australia/Melbourne",
                                    "showAsFree" => JSON::true,
                                    "summary" => "one hour later"
                                },
                            }
                        }
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{startTimeZone}, "Europe/Vienna");
    $exc = $event->{exceptions}{"2015-10-07T16:45:00"};
    $self->assert_str_equals($exc->{summary}, "one hour later");
    $self->assert_null($exc->{description});
    $self->assert_equals($exc->{showAsFree}, JSON::true);
    $self->assert_null($exc->{isAllDay});
    $self->assert_str_equals($exc->{start}, "2015-10-07T17:45:00");
    $self->assert_str_equals($exc->{startTimeZone}, "Australia/Melbourne");
    $self->assert_str_equals($exc->{end}, "2015-10-07T18:15:00");
    $self->assert_str_equals($exc->{endTimeZone}, "Australia/Melbourne");
    $self->assert(not exists $event->{exceptions}{"2015-10-08T16:45:00"});

    xlog "update start time of exception event $id with error";
    # This is an illegal event! start occurs after end. 
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => 
                        {
                            "exceptions" => {
                                "2015-10-07T16:45:00" => {
                                    "start" => "2015-10-07T17:45:00",
                                    "startTimeZone" => "America/NewYork",
                                },
                            }
                        }
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$id});

    xlog "update start time of exception event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => 
                        {
                            "exceptions" => {
                                "2015-10-07T16:45:00" => {
                                    "start" => "2015-10-07T17:45:00",
                                    "startTimeZone" => "Australia/Melbourne",
                                    "end" => "2015-10-07T18:45:00",
                                    "endTimeZone" => "Australia/Melbourne",
                                },
                            }
                        }
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $exc = $event->{exceptions}{"2015-10-07T16:45:00"};
    $self->assert_str_equals($exc->{start}, "2015-10-07T17:45:00");
    $self->assert_str_equals($exc->{startTimeZone}, "Australia/Melbourne");
    $self->assert_str_equals($exc->{end}, "2015-10-07T18:45:00");
    $self->assert_str_equals($exc->{endTimeZone}, "Australia/Melbourne");
}

sub test_setcalendarevents_update_exceptions_edge {
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
    my $state = $res->[0][1]{newState};

    my $event =  {
        "calendarId" => $calid,
        "start"=> "2015-11-07T09:00:00",
        "end"=> "2015-11-07T10:00:00",
        "startTimeZone"=> undef,
        "endTimeZone"=> undef,
        "isAllDay"=> JSON::false,
        "alerts"=> undef,
        "summary"=> "foo",
        "description"=> "",
        "location"=> "",
        "showAsFree"=> JSON::false,
        "recurrence"=> {
            "frequency"=> "weekly",
            "count"=> 4
        },
        "attachments"=> undef,
        "attendees" => undef,
        "organizer"=> undef,
        "inclusions" => undef,
        "exceptions" => undef
    };

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"#1"}{id};
    $event->{id} = $id;

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, $event->{id});
    my $xhref = $res->[0][1]{list}[0]{"x-href"};
    $event->{"x-href"} = $xhref;
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);

    xlog "update event $id";
    $event->{exceptions} = {
            "2015-11-14T09:00:00" => {
                "startTimeZone" => "Asia/Bangkok",
                "endTimeZone"=> "Asia/Bangkok"
          }
    };
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event->{exceptions}{"2015-11-14T09:00:00"}{start} = "2015-11-14T09:00:00";
    $event->{exceptions}{"2015-11-14T09:00:00"}{end} = "2015-11-14T10:00:00";
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, $event->{id});
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);

    xlog "update event $id";
    $event->{exceptions}{"2015-11-14T09:00:00"}{start} = "2015-11-14T11:00:00";
    $event->{exceptions}{"2015-11-14T09:00:00"}{end} = "2015-11-14T13:00:00";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);

    xlog "update event $id";
    $event->{exceptions}{"2015-11-21T09:00:00"} = {
        "start" => "2015-11-21T21:00:00",
        "end"=> "2015-11-21T22:00:00"
    };
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event->{exceptions}{"2015-11-21T09:00:00"}{"startTimeZone"} = undef;
    $event->{exceptions}{"2015-11-21T09:00:00"}{"endTimeZone"} = undef;
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);

    xlog "update event $id";
    $event->{"startTimeZone"} = "Europe/Vienna";
    $event->{"endTimeZone"} = "Europe/Berlin";
    # Keep exceptions, so we can null out the exceptions property for update.
    my $excs = $event->{exceptions};
    delete $event->{exceptions};
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $event->{exceptions} = $excs;
    $event->{exceptions}{"2015-11-21T09:00:00"} = {
        "start" => "2015-11-21T21:00:00",
        "end"=> "2015-11-21T22:00:00",
        "startTimeZone" => "Europe/Vienna",
        "endTimeZone" => "Europe/Berlin"
    };
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);

    xlog "update event $id";
    $event->{exceptions} = undef;
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);
}


sub test_setcalendarevents_update_exceptions_dtstartend {
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
    my $state = $res->[0][1]{newState};

    my $event =  {
        "calendarId" => $calid,
        "start"=> "2015-11-07T09:00:00",
        "end"=> "2015-11-07T10:00:00",
        "startTimeZone"=> undef,
        "endTimeZone"=> undef,
        "isAllDay"=> JSON::false,
        "alerts"=> undef,
        "summary"=> "foo",
        "description"=> "",
        "location"=> "",
        "showAsFree"=> JSON::false,
        "recurrence"=> {
            "frequency"=> "weekly",
            "count"=> 4
        },
        "attachments"=> undef,
        "attendees" => undef,
        "organizer"=> undef,
        "inclusions" => undef,
        "exceptions" => {
            "2015-11-14T09:00:00" => {
                "summary" => "foo (exc)"
            }
        }
    };

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => $event
                    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"#1"}{id};
    $event->{id} = $id;

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event->{exceptions}{"2015-11-14T09:00:00"}{start} = "2015-11-14T09:00:00";
    $event->{exceptions}{"2015-11-14T09:00:00"}{end} = "2015-11-14T10:00:00";
    $event->{exceptions}{"2015-11-14T09:00:00"}{startTimeZone} = undef;
    $event->{exceptions}{"2015-11-14T09:00:00"}{endTimeZone} = undef;
    $event->{"x-href"} = $res->[0][1]{list}[0]{"x-href"};
    $self->assert_str_equals($res->[0][1]{list}[0]{id}, $event->{id});
    $self->assert_deep_equals($res->[0][1]{list}[0], $event);
}


sub test_setcalendarevents_update_participants {
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

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Australia/Melbourne",
                            "organizer" => {
                                "name" => "Cassandane",
                                "email" => "cassandane\@localhost",
                            },
                            "attendees" => [{
                                "name" => "Bugs Bunny",
                                "email" => "bugs\@example.com",
                                "rsvp" => "maybe"
                            }, {
                                "name" => "Yosemite Sam",
                                "email" => "sam\@example.com",
                                "rsvp" => "no"
                            }]
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{organizer}{name}, "Cassandane");
    $self->assert_str_equals($event->{organizer}{email}, "cassandane\@localhost");
    $self->assert_str_equals($event->{organizer}{isYou}, JSON::false);
    $self->assert_num_equals(scalar @{$event->{attendees}}, 2);
    $self->assert_str_equals($event->{attendees}[0]{name}, "Bugs Bunny");
    $self->assert_str_equals($event->{attendees}[0]{email}, "bugs\@example.com");
    $self->assert_str_equals($event->{attendees}[0]{isYou}, JSON::false);
    $self->assert_str_equals($event->{attendees}[0]{rsvp}, "maybe");
    $self->assert_str_equals($event->{attendees}[1]{name}, "Yosemite Sam");
    $self->assert_str_equals($event->{attendees}[1]{email}, "sam\@example.com");
    $self->assert_str_equals($event->{attendees}[1]{isYou}, JSON::false);
    $self->assert_str_equals($event->{attendees}[1]{rsvp}, "no");

    xlog "update attendees of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "organizer" => {
                                "name" => "Cassandane",
                                "email" => "cassandane\@localhost",
                            },
                            "attendees" => [{
                                "name" => "Bugs Bunny",
                                "email" => "bugs\@example.com",
                                "rsvp" => "maybe"
                            }, {
                                "name" => "Yosemite Sam",
                                "email" => "sam\@example.com",
                                "rsvp" => "yes"
                            }]
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_num_equals(scalar @{$event->{attendees}}, 2);
    $self->assert_str_equals($event->{attendees}[0]{name}, "Bugs Bunny");
    $self->assert_str_equals($event->{attendees}[0]{email}, "bugs\@example.com");
    $self->assert_str_equals($event->{attendees}[0]{isYou}, JSON::false);
    $self->assert_str_equals($event->{attendees}[0]{rsvp}, "maybe");
    $self->assert_str_equals($event->{attendees}[1]{name}, "Yosemite Sam");
    $self->assert_str_equals($event->{attendees}[1]{email}, "sam\@example.com");
    $self->assert_str_equals($event->{attendees}[1]{isYou}, JSON::false);
    $self->assert_str_equals($event->{attendees}[1]{rsvp}, "yes");

    xlog "update attendees of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "organizer" => {
                                "name" => "Cassandane",
                                "email" => "cassandane\@localhost",
                            },
                            "attendees" => [{
                                "name" => "Bugs Bunny",
                                "email" => "bugs\@example.com",
                                "rsvp" => "yes"
                            }]
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event->{organizer});
    $self->assert_num_equals(scalar @{$event->{attendees}}, 1);
    $self->assert_str_equals($event->{attendees}[0]{name}, "Bugs Bunny");
    $self->assert_str_equals($event->{attendees}[0]{email}, "bugs\@example.com");
    $self->assert_str_equals($event->{attendees}[0]{isYou}, JSON::false);
    $self->assert_str_equals($event->{attendees}[0]{rsvp}, "yes");

    xlog "do not touch participants of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "showAsFree" => JSON::false,
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event->{organizer});
    $self->assert_num_equals(scalar @{$event->{attendees}}, 1);

    xlog "remove participants of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        $id => {
                            "organizer" => undef,
                            "attendees" => undef
                        }
                    }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_null($event->{organizer});
    $self->assert_null($event->{attendees});
}

sub test_setcalendarevents_isallday {
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
    my $state = $res->[0][1]{newState};

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
                        }
                    }}, "R1"]]);

    $state = $res->[0][1]{newState};
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_equals($event->{isAllDay}, JSON::true);
    $self->assert_str_equals($event->{start}, '2015-10-06T00:00:00');
    $self->assert_str_equals($event->{end}, '2015-10-07T00:00:00');
}

sub test_setcalendarevents_update_attachments {
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

    xlog "create event";
    $res = $jmap->Request([['setCalendarEvents', { create => {
                        "#1" => {
                            "calendarId" => $calid,
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::false,
                            "start" => "2015-10-06T16:45:00",
                            "startTimeZone" => "Australia/Melbourne",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Australia/Melbourne",
                            "attachments" => [{
                                    "blobId" => "https://www.user.fm/files/v1-123456789abcde",
                                    "type" => "application/octet-stream",
                                    "name" => undef,
                                    "size" => 4480
                            }]
                        }
                    }}, "R1"]]);

    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get calendar event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($event->{id}, $id);
    $self->assert_num_equals(scalar @{$event->{attachments}}, 1);
    my $att = $event->{attachments}[0];
    $self->assert_str_equals($att->{blobId}, "https://www.user.fm/files/v1-123456789abcde");
    $self->assert_str_equals($att->{type}, "application/octet-stream");
    $self->assert_null($att->{name});
    $self->assert_num_equals($att->{size}, 4480);

    xlog "update attachments of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "attachments" => [{
                                    "blobId" => "https://www.user.fm/files/v1-123456789abcde",
                                    "type" => undef,
                                    "name" => undef,
                                    "size" => undef
                            }, {
                                    "blobId" => "https://www.user.fm/files/v1-edcba987654321",
                                    "type" => "text/html",
                                    "name" => undef,
                                    "size" => 8
                            }]
                        }
                    }}, "R1"]]);
    xlog "get event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_num_equals(scalar @{$event->{attachments}}, 2);
    $att = $event->{attachments}[0];
    $self->assert_str_equals($att->{blobId}, "https://www.user.fm/files/v1-123456789abcde");
    $self->assert_null($att->{type});
    $self->assert_null($att->{name});
    $self->assert_null($att->{size});
    $att = $event->{attachments}[1];
    $self->assert_str_equals($att->{blobId}, "https://www.user.fm/files/v1-edcba987654321");
    $self->assert_str_equals($att->{type}, "text/html");
    $self->assert_null($att->{name});
    $self->assert_num_equals($att->{size}, 8);

    xlog "update attachments of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "attachments" => [{
                                    "blobId" => "https://www.user.fm/files/v1-123456789abcde",
                                    "type" => "application/octet-stream",
                                    "name" => undef,
                                    "size" => undef
                            }]
                        }
                    }}, "R1"]]);
    xlog "get event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_num_equals(scalar @{$event->{attachments}}, 1);
    $att = $event->{attachments}[0];
    $self->assert_str_equals($att->{blobId}, "https://www.user.fm/files/v1-123456789abcde");
    $self->assert_str_equals($att->{type}, "application/octet-stream");
    $self->assert_null($att->{name});
    $self->assert_null($att->{size});

    xlog "do not touch attachments of event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "isAllDay" => JSON::false,
                        }
                    }}, "R1"]]);
    xlog "get event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_num_equals(scalar @{$event->{attachments}}, 1);

    xlog "remove attachments from event $id";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "attachments" => undef
                        }
                    }}, "R1"]]);
    xlog "get event $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_null($event->{attachments});
}

sub test_setcalendarevents_move {
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
                            "summary" => "foo",
                            "description" => "foo's description",
                            "location" => "foo's location",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
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

sub test_getcalendareventupdates {
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
                            "summary" => "1",
                            "description" => "",
                            "location" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
                        },
                        "#2" => {
                            "calendarId" => $calidB,
                            "summary" => "2",
                            "description" => "",
                            "location" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
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
                            "summary" => "1(updated)",
                        },
                        $id2 => {
                            "calendarId" => $calidB,
                            "summary" => "2(updated)",
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
                            "summary" => "1(updated)",
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
                            "summary" => "1(goodbye)",
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

sub test_getcalendareventlist {
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
                            "summary" => "foo",
                            "description" => "",
                            "location" => "bar",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
                        },
                        "#2" => {
                            "calendarId" => $calidB,
                            "summary" => "foo",
                            "description" => "",
                            "location" => "",
                            "showAsFree" => JSON::false,
                            "isAllDay" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "startTimeZone" => undef,
                            "end" => "2015-10-07T00:00:00",
                            "endTimeZone" => undef
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
                        "location" => "bar"
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
                                "location" => "bar"
                            }
                        ]
                    }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{calendarEventIds}}, 1);
    $self->assert_str_equals($res->[0][1]{calendarEventIds}[0], $id1);
}

sub test_setcalendarevents_caldav {
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
                            "summary" => "foo",
                            "description" => "",
                            "location" => "bar",
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
LOCATION:bar
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
                            "summary" => "bam",
                            "description" => "",
                            "location" => "bam",
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

1;
