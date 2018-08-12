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

package Cassandane::Cyrus::JMAPContacts;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.12;
use Data::Dumper;
use Storable 'dclone';

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
		 conversations => 'yes',
		 httpmodules => 'carddav caldav jmap',
		 httpallowcompress => 'no');

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
}

sub test_contact_set_multicontact
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([['Contact/set', {
        create => {
            "1" => {firstName => "first", lastName => "last"},
            "2" => {firstName => "second", lastName => "last"},
        }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id1, 'notacontact']}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_not_null($fetch->[0][1]{notFound});
    $self->assert_str_equals('notacontact', $fetch->[0][1]{notFound}[0]);

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id2]}, "R3"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R3', $fetch->[0][2]);
    $self->assert_str_equals('second', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_deep_equals([], $fetch->[0][1]{notFound});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id1, $id2]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_num_equals(2, scalar @{$fetch->[0][1]{list}});
    $self->assert_deep_equals([], $fetch->[0][1]{notFound});

    $fetch = $jmap->CallMethods([['Contact/get', {}, "R5"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R5', $fetch->[0][2]);
    $self->assert_num_equals(2, scalar @{$fetch->[0][1]{list}});
    $self->assert_deep_equals([], $fetch->[0][1]{notFound});
}

sub test_contact_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get contacts";
    my $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);

    xlog "create contact 1";
    $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "create contact 2";
    $res = $jmap->CallMethods([['Contact/set', {create => {"2" => {firstName => "second", lastName => "prev"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "get contact updates (since last change)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "get contact updates (in bulk)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog "get contact updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::true);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog "get contact updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "destroy contact 1, update contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$id1],
                    update => {$id2 => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog "destroy contact 2";
    $res = $jmap->CallMethods([['Contact/set', {destroy => [$id2]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_contact_changes_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog "create shared account";
    $admintalk->create("user.manifold");

    my $mantalk = Net::CardDAVTalk->new(
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
    xlog "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "get contacts";
    my $res = $jmap->CallMethods([['Contact/get', { accountId => 'manifold' }, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);

    xlog "create contact 1";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {"1" => {firstName => "first", lastName => "last"}}
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "create contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {"2" => {firstName => "second", lastName => "prev"}}
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "get contact updates (since last change)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "get contact updates (in bulk)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog "get contact updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::true);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog "get contact updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "destroy contact 1, update contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    destroy => [$id1],
                    update => {$id2 => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog "destroy contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    destroy => [$id2]
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_contact_set_nickname
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" => { firstName => "foo", lastName => "last1", nickname => "" },
                        "2" => { firstName => "bar", lastName => "last2", nickname => "string" },
                        "3" => { firstName => "bar", lastName => "last3", nickname => "string,list" },
                    }}, "R1"]]);
    $self->assert_not_null($res);
    my $contact1 = $res->[0][1]{created}{"1"}{id};
    my $contact2 = $res->[0][1]{created}{"2"}{id};
    my $contact3 = $res->[0][1]{created}{"3"}{id};
    $self->assert_not_null($contact1);
    $self->assert_not_null($contact2);
    $self->assert_not_null($contact3);

    $res = $jmap->CallMethods([['Contact/set', {update => {
                        $contact2 => { nickname => "" },
                    }}, "R2"]]);
    $self->assert_not_null($res);
}

sub test_contact_set_invalid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contact with invalid properties";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" => { id => "xyz", firstName => "foo", lastName => "last1", foo => "", "x-hasPhoto" => JSON::true },
                    }}, "R1"]]);
    $self->assert_not_null($res);
    my $notCreated = $res->[0][1]{notCreated}{"1"};
    $self->assert_not_null($notCreated);
    $self->assert_num_equals(3, scalar @{$notCreated->{properties}});

    xlog "create contacts";
    $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" => { firstName => "foo", lastName => "last1" },
                    }}, "R2"]]);
    $self->assert_not_null($res);
    my $contact = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($contact);

    xlog "get contact x-href";
    $res = $jmap->CallMethods([['Contact/get', {}, "R3"]]);
    my $href = $res->[0][1]{list}[0]{"x-href"};

    xlog "update contact with invalid properties";
    $res = $jmap->CallMethods([['Contact/set', {update => {
                        $contact => { id => "xyz", foo => "", "x-hasPhoto" => "yes", "x-ref" => "abc" },
                    }}, "R4"]]);
    $self->assert_not_null($res);
    my $notUpdated = $res->[0][1]{notUpdated}{$contact};
    $self->assert_not_null($notUpdated);
    $self->assert_num_equals(4, scalar @{$notUpdated->{properties}});

    xlog "update contact with server-set properties";
    $res = $jmap->CallMethods([['Contact/set', {update => {
                        $contact => { id => $contact, "x-hasPhoto" => JSON::false, "x-href" => $href },
                    }}, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{updated});
}

sub test_contactgroup_set
    :min_version_3_1 :needs_component_jmap
{

    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" => { firstName => "foo", lastName => "last1" },
                        "2" => { firstName => "bar", lastName => "last2" }
                    }}, "R1"]]);
    my $contact1 = $res->[0][1]{created}{"1"}{id};
    my $contact2 = $res->[0][1]{created}{"2"}{id};

    xlog "create contact group with no contact ids";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "1" => {name => "group1"}
                    }}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "get contact group $id";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [$id] }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/get', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert_str_equals('group1', $res->[0][1]{list}[0]{name});
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}[0]{contactIds}});

    xlog "update contact group with invalid contact ids";
    $res = $jmap->CallMethods([['ContactGroup/set', {update => {
                        $id => {name => "group1", contactIds => [$contact1, $contact2, 255]}
                    }}, "R4"]]);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals('contactIds[2]', $res->[0][1]{notUpdated}{$id}{properties}[0]);
    $self->assert_str_equals('R4', $res->[0][2]);

    xlog "get contact group $id";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [$id] }, "R3"]]);
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}[0]{contactIds}});


    xlog "update contact group with valid contact ids";
    $res = $jmap->CallMethods([['ContactGroup/set', {update => {
                        $id => {name => "group1", contactIds => [$contact1, $contact2]}
                    }}, "R4"]]);

    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact group $id";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [$id] }, "R3"]]);
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}[0]{contactIds}});
    $self->assert_str_equals($contact1, $res->[0][1]{list}[0]{contactIds}[0]);
    $self->assert_str_equals($contact2, $res->[0][1]{list}[0]{contactIds}[1]);
}

sub test_contact_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" =>
                        {
                            firstName => "foo", lastName => "last1",
                            emails => [{
                                    type => "personal",
                                    value => "foo\@example.com"
                                }]
                        },
                        "2" =>
                        {
                            firstName => "bar", lastName => "last2",
                            emails => [{
                                    type => "work",
                                    value => "bar\@bar.org"
                                }, {
                                    type => "other",
                                    value => "me\@example.com"
                                }],
                            addresses => [{
                                    type => "home",
                                   label => undef,
                                    street => "Some Lane 24",
                                    locality => "SomeWhere City",
                                    region => "",
                                    postcode => "1234",
                                    country => "Someinistan",
                                    isDefault => JSON::false
                                }],
                            isFlagged => JSON::true
                        },
                        "3" =>
                        {
                            firstName => "baz", lastName => "last3",
                            addresses => [{
                                    type => "home",
                                    label => undef,
                                    street => "Some Lane 12",
                                    locality => "SomeWhere City",
                                    region => "",
                                    postcode => "1234",
                                    country => "Someinistan",
                                    isDefault => JSON::false
                                }]
                        },
                        "4" => {firstName => "bam", lastName => "last4",
                                 isFlagged => JSON::false }
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};
    my $id4 = $res->[0][1]{created}{"4"}{id};

    xlog "create contact groups";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "1" => {name => "group1", contactIds => [$id1, $id2]},
                        "2" => {name => "group2", contactIds => [$id3]},
                        "3" => {name => "group3", contactIds => [$id4]}
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $group1 = $res->[0][1]{created}{"1"}{id};
    my $group2 = $res->[0][1]{created}{"2"}{id};
    my $group3 = $res->[0][1]{created}{"3"}{id};

    xlog "get unfiltered contact list";
    $res = $jmap->CallMethods([ ['Contact/query', { }, "R1"] ]);

    $self->assert_num_equals(4, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog "filter by firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog "filter by lastName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(4, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog "filter by firstName and lastName (one filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { firstName => "bam", lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id4, $res->[0][1]{ids}[0]);

    xlog "filter by firstName and lastName (AND filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { operator => "AND", conditions => [{
                                lastName => "last"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id3, $res->[0][1]{ids}[0]);

    xlog "filter by firstName (OR filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { operator => "OR", conditions => [{
                                firstName => "bar"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "filter by text";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { text => "some" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "filter by email";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { email => "example.com" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "filter by isFlagged (true)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { isFlagged => JSON::true }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id2, $res->[0][1]{ids}[0]);

    xlog "filter by isFlagged (false)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { isFlagged => JSON::false }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog "filter by inContactGroup";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { inContactGroup => [$group1, $group3] }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog "filter by inContactGroup and firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { inContactGroup => [$group1, $group3], firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);
}


sub test_contact_query_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog "create shared account";
    $admintalk->create("user.manifold");

    my $mantalk = Net::CardDAVTalk->new(
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
    xlog "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {
                        "1" =>
                        {
                            firstName => "foo", lastName => "last1",
                            emails => [{
                                    type => "personal",
                                    value => "foo\@example.com"
                                }]
                        },
                        "2" =>
                        {
                            firstName => "bar", lastName => "last2",
                            emails => [{
                                    type => "work",
                                    value => "bar\@bar.org"
                                }, {
                                    type => "other",
                                    value => "me\@example.com"
                                }],
                            addresses => [{
                                    type => "home",
                                   label => undef,
                                    street => "Some Lane 24",
                                    locality => "SomeWhere City",
                                    region => "",
                                    postcode => "1234",
                                    country => "Someinistan",
                                    isDefault => JSON::false
                                }],
                            isFlagged => JSON::true
                        },
                        "3" =>
                        {
                            firstName => "baz", lastName => "last3",
                            addresses => [{
                                    type => "home",
                                    label => undef,
                                    street => "Some Lane 12",
                                    locality => "SomeWhere City",
                                    region => "",
                                    postcode => "1234",
                                    country => "Someinistan",
                                    isDefault => JSON::false
                                }]
                        },
                        "4" => {firstName => "bam", lastName => "last4",
                                 isFlagged => JSON::false }
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};
    my $id4 = $res->[0][1]{created}{"4"}{id};

    xlog "create contact groups";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    create => {
                        "1" => {name => "group1", contactIds => [$id1, $id2]},
                        "2" => {name => "group2", contactIds => [$id3]},
                        "3" => {name => "group3", contactIds => [$id4]}
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $group1 = $res->[0][1]{created}{"1"}{id};
    my $group2 = $res->[0][1]{created}{"2"}{id};
    my $group3 = $res->[0][1]{created}{"3"}{id};

    xlog "get unfiltered contact list";
    $res = $jmap->CallMethods([ ['Contact/query', { accountId => 'manifold' }, "R1"] ]);

xlog "check total";
    $self->assert_num_equals(4, $res->[0][1]{total});
xlog "check ids";
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog "filter by firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog "filter by lastName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(4, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog "filter by firstName and lastName (one filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { firstName => "bam", lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id4, $res->[0][1]{ids}[0]);

    xlog "filter by firstName and lastName (AND filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { operator => "AND", conditions => [{
                                lastName => "last"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id3, $res->[0][1]{ids}[0]);

    xlog "filter by firstName (OR filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { operator => "OR", conditions => [{
                                firstName => "bar"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "filter by text";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { text => "some" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "filter by email";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { email => "example.com" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog "filter by isFlagged (true)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { isFlagged => JSON::true }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id2, $res->[0][1]{ids}[0]);

    xlog "filter by isFlagged (false)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { isFlagged => JSON::false }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog "filter by inContactGroup";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { inContactGroup => [$group1, $group3] }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog "filter by inContactGroup and firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { inContactGroup => [$group1, $group3], firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);
}

sub test_contactgroup_changes
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

    xlog "get contact groups state";
    $res = $jmap->CallMethods([['ContactGroup/get', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "create contact group 1";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "1" => {name => "first", contactIds => [$contactA, $contactB]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};


    xlog "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "create contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "2" => {name => "second", contactIds => [$contactC, $contactD]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "get contact group updates (since last change)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "get contact group updates (in bulk)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog "get contact group updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::true);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog "get contact group updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "destroy contact group 1, update contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    destroy => [$id1],
                    update => {$id2 => {name => "second (updated)"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog "destroy contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {destroy => [$id2]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_contactgroup_changes_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog "create shared account";
    $admintalk->create("user.manifold");

    my $mantalk = Net::CardDAVTalk->new(
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
    xlog "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {
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

    xlog "get contact groups state";
    $res = $jmap->CallMethods([['ContactGroup/get', { accountId => 'manifold', }, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "create contact group 1";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    create => {
                        "1" => {name => "first", contactIds => [$contactA, $contactB]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};


    xlog "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "create contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    create => {
                        "2" => {name => "second", contactIds => [$contactC, $contactD]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog "get contact group updates (since last change)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "get contact group updates (in bulk)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog "get contact group updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::true);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog "get contact group updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog "destroy contact group 1, update contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    destroy => [$id1],
                    update => {$id2 => {name => "second (updated)"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals($res->[0][1]{hasMoreChanges}, JSON::false);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog "destroy contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    destroy => [$id2]
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_contact_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $contact = {
        firstName => "first",
        lastName => "last",
        avatar => JSON::null
    };

    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => $contact }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    # get expands default values, so do the same manually
    $contact->{id} = $id;
    $contact->{isFlagged} = JSON::false;
    $contact->{prefix} = '';
    $contact->{suffix} = '';
    $contact->{nickname} = '';
    $contact->{birthday} = '0000-00-00';
    $contact->{anniversary} = '0000-00-00';
    $contact->{company} = '';
    $contact->{department} = '';
    $contact->{jobTitle} = '';
    $contact->{online} = [];
    $contact->{phones} = [];
    $contact->{addresses} = [];
    $contact->{emails} = [];
    $contact->{notes} = '';
    $contact->{avatar} = JSON::null;

    # Non-JMAP properties.
    $contact->{"x-importance"} = 0;
    $contact->{"x-hasPhoto"} = JSON::false;
    $contact->{"addressbookId"} = 'Default';

    xlog "get contact $id";
    my $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);

    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $contact->{"x-href"} = $fetch->[0][1]{list}[0]{"x-href"};
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # isFlagged
    xlog "update isFlagged (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {isFlagged => 'nope'} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("isFlagged", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update isFlagged";
    $contact->{isFlagged} = JSON::true;
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {isFlagged => JSON::true} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # prefix
    xlog "update prefix (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {prefix => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("prefix", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update prefix";
    $contact->{prefix} = 'foo';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {prefix => 'foo'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # suffix
    xlog "update suffix (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {suffix => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("suffix", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update suffix";
    $contact->{suffix} = 'bar';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {suffix => 'bar'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # nickname
    xlog "update nickname (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {nickname => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("nickname", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update nickname";
    $contact->{nickname} = 'nick';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {nickname => 'nick'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # birthday
    xlog "update birthday (with null error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {birthday => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("birthday", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update birthday (with JMAP datetime error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {birthday => '1979-04-01T00:00:00Z'} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("birthday", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update birthday";
    $contact->{birthday} = '1979-04-01'; # Happy birthday, El Barto!
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {birthday => '1979-04-01'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # anniversary
    xlog "update anniversary (with null error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {anniversary => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("anniversary", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update anniversary (with JMAP datetime error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {anniversary => '1989-12-17T00:00:00Z'} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("anniversary", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update anniversary";
    $contact->{anniversary} = '1989-12-17'; # Happy anniversary, Simpsons!
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {anniversary => '1989-12-17'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # company
    xlog "update company (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {company => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("company", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update company";
    $contact->{company} = 'acme';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {company => 'acme'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # department
    xlog "update department (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {department => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("department", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update department";
    $contact->{department} = 'looney tunes';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {department => 'looney tunes'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # jobTitle
    xlog "update jobTitle (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {jobTitle => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("jobTitle", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update jobTitle";
    $contact->{jobTitle} = 'director of everything';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {jobTitle => 'director of everything'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # emails
    xlog "update emails (with missing type error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            emails => [{ value => "acme\@example.com" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("emails[0].type", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update emails (with missing value error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            emails => [{ type => "other" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("emails[0].value", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update emails";
    $contact->{emails} = [{ type => "work", value => "acme\@example.com", isDefault => JSON::true }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            emails => [{ type => "work", value => "acme\@example.com" }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # phones
    xlog "update phones (with missing type error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            phones => [{ value => "12345678" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("phones[0].type", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update phones (with missing value error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            phones => [{ type => "home" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("phones[0].value", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update phones";
    $contact->{phones} = [{ type => "home", value => "12345678" }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            phones => [{ type => "home", value => "12345678" }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # online
    xlog "update online (with missing type error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            online => [{ value => "http://example.com/me" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("online[0].type", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update online (with missing value error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            online => [{ type => "uri" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("online[0].value", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update online";
    $contact->{online} = [{ type => "uri", value => "http://example.com/me" }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            online => [{ type => "uri", value => "http://example.com/me" }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # addresses
    xlog "update addresses";
    $contact->{addresses} = [{
            type => "home",
            street => "acme lane 1",
            locality => "acme city",
            region => "",
            postcode => "1234",
            country => "acme land"
        }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            addresses => [{
                                    type => "home",
                                    street => "acme lane 1",
                                    locality => "acme city",
                                    region => "",
                                    postcode => "1234",
                                    country => "acme land"
                                }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # notes
    xlog "update notes (with error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {notes => undef} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("notes", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog "update notes";
    $contact->{notes} = 'baz';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {notes => 'baz'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # avatar
    xlog "upload avatar";
    $res = $jmap->Upload("some photo", "image/jpeg");
    $contact->{"x-hasPhoto"} = JSON::true;
    $contact->{avatar} = {
        blobId => "$res->{blobId}",
        size => 10,
        type => "image/jpeg",
        name => JSON::null
    };

    xlog "update avatar";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id =>
                            {avatar => {
                                blobId => "$res->{blobId}",
                                size => 10,
                                type => "image/jpeg",
                                name => JSON::null
                             }
                     } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get avatar $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);
}

sub test_contact_set_emaillabel
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # See https://github.com/cyrusimap/cyrus-imapd/issues/2273

    my $contact = {
        firstName => "first",
        lastName => "last",
        emails => [{
            type => "other",
            label => "foo",
            value => "foo\@local",
            isDefault => JSON::true
        }]
    };

    xlog "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => $contact }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    xlog "get contact $id";
    $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{emails}[0]{label});

    xlog "update contact";
    $res = $jmap->CallMethods([['Contact/set', {
        update => {
            $id => {
                emails => [{
                    type => "personal",
                    label => undef,
                    value => "bar\@local",
                    isDefault => JSON::true
                }]
            }
        }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_str_equals('personal', $res->[0][1]{list}[0]{emails}[0]{type});
    $self->assert_null($res->[0][1]{list}[0]{emails}[0]{label});
}


sub test_contact_set_state
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};
    my $state = $res->[0][1]{newState};

    xlog "get contact $id";
    $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    $self->assert_str_equals('first', $res->[0][1]{list}[0]{firstName});
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog "update $id with state token $state";
    $res = $jmap->CallMethods([['Contact/set', {
                    ifInState => $state,
                    update => {$id =>
                        {firstName => "first", lastName => "last"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert(exists $res->[0][1]{updated}{$id});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "update $id with expired state token $oldState";
    $res = $jmap->CallMethods([['Contact/set', {
                    ifInState => $oldState,
                    update => {$id =>
                        {firstName => "first", lastName => "last"}
                    }}, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog "get contact $id to make sure state didn't change";
    $res = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog "destroy $id with expired state token $oldState";
    $res = $jmap->CallMethods([['Contact/set', {
                    ifInState => $oldState,
                    destroy => [$id]
                }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog "destroy contact $id with current state";
    $res = $jmap->CallMethods([
            ['Contact/set', {
                    ifInState => $state,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}

sub test_contact_set_importance_later
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(0.0, $fetch->[0][1]{list}[0]{"x-importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"x-importance" => -0.1}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-0.1, $fetch->[0][1]{list}[0]{"x-importance"});
}

sub test_contact_set_importance_upfront
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with importance in initial create";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"x-importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"firstName" => "second"}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('second', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"x-importance"});
}

sub test_contact_set_importance_multiedit
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"x-importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"firstName" => "second", "x-importance" => -0.2}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('second', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-0.2, $fetch->[0][1]{list}[0]{"x-importance"});
}

sub test_contact_set_importance_zero_multi
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"x-importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"firstName" => "second", "x-importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('second', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(0, $fetch->[0][1]{list}[0]{"x-importance"});
}

sub test_contact_set_importance_zero_byself
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"x-importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"x-importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(0, $fetch->[0][1]{list}[0]{"x-importance"});
}

sub test_misc_creationids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create and get contact group and contact";
    my $res = $jmap->CallMethods([
        ['Contact/set', {create => { "c1" => { firstName => "foo", lastName => "last1" }, }}, "R2"],
        ['ContactGroup/set', {create => { "g1" => {name => "group1", contactIds => ["#c1"]} }}, "R2"],
        ['Contact/get', {ids => ["#c1"]}, "R3"],
        ['ContactGroup/get', {ids => ["#g1"]}, "R4"],
    ]);
    my $contact = $res->[2][1]{list}[0];
    $self->assert_str_equals($contact->{firstName}, "foo");

    my $group = $res->[3][1]{list}[0];
    $self->assert_str_equals($group->{name}, "group1");

    $self->assert_str_equals($group->{contactIds}[0], $contact->{id});
}

sub test_misc_categories
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    my $carddav = Net::CardDAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );


    xlog "create a contact with two categories";
    my $id = 'ae2640cc-234a-4dd9-95cc-3106258445b9';
    my $href = "Default/$id.vcf";
    my $card = <<EOF;
BEGIN:VCARD
VERSION:3.0
UID:$id
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
REV:2008-04-24T19:52:43Z
CATEGORIES:cat1,cat2
END:VCARD
EOF

    $carddav->Request('PUT', $href, $card, 'Content-Type' => 'text/vcard');

    my $data = $carddav->Request('GET', $href);
    $self->assert_matches(qr/cat1,cat2/, $data->{content});

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('Forrest', $fetch->[0][1]{list}[0]{firstName});

    my $res = $jmap->CallMethods([['Contact/set', {
                    update => {$id => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    $data = $carddav->Request('GET', $href);
    $self->assert_matches(qr/cat1,cat2/, $data->{content});

}

sub test_contact_get_issue2292
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
        "1" => { firstName => "foo", lastName => "last1" },
    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"});

    xlog "get contact with no ids";
    $res = $jmap->CallMethods([['Contact/get', { }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    xlog "get contact with empty ids";
    $res = $jmap->CallMethods([['Contact/get', { ids => [] }, "R3"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    xlog "get contact with null ids";
    $res = $jmap->CallMethods([['Contact/get', { ids => undef }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
}

sub test_contactgroup_get_issue2292
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contact group";
    my $res = $jmap->CallMethods([['ContactGroup/set', {create => {
        "1" => {name => "group1"}
    }}, "R2"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"});

    xlog "get contact group with no ids";
    $res = $jmap->CallMethods([['ContactGroup/get', { }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    xlog "get contact group with empty ids";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [] }, "R3"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    xlog "get contact group with null ids";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => undef }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
}



1;
