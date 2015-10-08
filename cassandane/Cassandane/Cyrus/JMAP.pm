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
  $self->assert_not_null($event->{exceptions}{"2016-09-30T17:00:00"});
  $self->assert_str_equals($event->{exceptions}{"2016-09-30T17:00:00"}{"summary"}, "Exceptional Yep");
  $self->assert_str_equals($event->{exceptions}{"2016-09-30T17:00:00"}{"showAsFree"}, JSON::false);
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
                            "startTimeZone" => "Europe/Vienna",
                            "end" => "2015-10-06T17:15:00",
                            "endTimeZone" => "Europe/Vienna",
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
                            }]
                        }
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'calendarsEventsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"#1"}{id};
    xlog "get calendar $id";
    $res = $jmap->Request([['getCalendarEvents', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar(@{$res->[0][1]{list}}), 1);

    my $event = $res->[0][1]{list}[0];

    $self->assert_str_equals($event->{id}, $id);
    $self->assert_str_equals($event->{summary}, 'foo');
    $self->assert_str_equals($event->{description}, "foo's description");
    $self->assert_str_equals($event->{location}, "foo's location");
    $self->assert_equals($event->{showAsFree}, JSON::false);
    $self->assert_equals($event->{isAllDay}, JSON::false);
    $self->assert_str_equals($event->{start}, '2015-10-06T16:45:00');
    $self->assert_str_equals($event->{startTimeZone}, 'Europe/Vienna');
    $self->assert_str_equals($event->{end}, '2015-10-06T17:15:00');
    $self->assert_str_equals($event->{endTimeZone}, 'Europe/Vienna');

    $self->assert_str_equals($event->{alerts}[0]{type}, "alert");
    $self->assert_num_equals($event->{alerts}[0]{minutesBefore}, 15);
    $self->assert_str_equals($event->{alerts}[1]{type}, "email");
    $self->assert_num_equals($event->{alerts}[1]{minutesBefore}, -15);

    $self->assert_str_equals($event->{organizer}{email}, "daffy\@example.com");
    $self->assert_str_equals($event->{organizer}{name}, "Daffy Duck");
    $self->assert_str_equals($event->{attendees}[0]{email}, "bugs\@example.com");
    $self->assert_str_equals($event->{attendees}[0]{name}, "Bugs Bunny");
    $self->assert_str_equals($event->{attendees}[0]{rsvp}, "maybe");

=pod
    my $xhref = $event->{"x-href"};
    my $caldavres = $caldav->Request('GET', $xhref);
    my $icalevent = $caldavres->{content};

    my $x = Dumper($icalevent);
    xlog "$x";

    # make it fail
    $self->assert_null($res);
=cut

}
1;
