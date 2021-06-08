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
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use File::Copy;

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
                 httpallowcompress => 'no',
                 vcard_max_size => 100000,
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
        'https://cyrusimap.org/ns/jmap/contacts',
    ]);
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

    xlog $self, "get contacts";
    my $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog $self, "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state,
                    addressbookId => "Default",
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});

    xlog $self, "create contact 1";
    $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog $self, "create contact 2";
    $res = $jmap->CallMethods([['Contact/set', {create => {"2" => {firstName => "second", lastName => "prev"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "get contact updates (since last change)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "get contact updates (in bulk)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "get contact updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::true, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog $self, "get contact updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "destroy contact 1, update contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    destroy => [$id1],
                    update => {$id2 => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog $self, "destroy contact 2";
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

    xlog $self, "create shared account";
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
    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "get contacts";
    my $res = $jmap->CallMethods([['Contact/get', { accountId => 'manifold' }, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog $self, "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});

    xlog $self, "create contact 1";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {"1" => {firstName => "first", lastName => "last"}}
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog $self, "create contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {"2" => {firstName => "second", lastName => "prev"}}
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "get contact updates (since last change)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "get contact updates (in bulk)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "get contact updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::true, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog $self, "get contact updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "destroy contact 1, update contact 2";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    destroy => [$id1],
                    update => {$id2 => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "get contact updates";
    $res = $jmap->CallMethods([['Contact/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog $self, "destroy contact 2";
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

    xlog $self, "create contacts";
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

    xlog $self, "create contact with invalid properties";
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                "1" => {
                    id => "xyz",
                    firstName => "foo",
                    lastName => "last1",
                    foo => "",
                    "x-hasPhoto" => JSON::true
                },
        }}, "R1"]]);
    $self->assert_not_null($res);
    my $notCreated = $res->[0][1]{notCreated}{"1"};
    $self->assert_not_null($notCreated);
    $self->assert_num_equals(3, scalar @{$notCreated->{properties}});

    xlog $self, "create contacts";
    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                "1" => {
                    firstName => "foo",
                    lastName => "last1"
                },
            }}, "R2"]]);
    $self->assert_not_null($res);
    my $contact = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($contact);

    xlog $self, "get contact x-href";
    $res = $jmap->CallMethods([['Contact/get', {}, "R3"]]);
    my $href = $res->[0][1]{list}[0]{"x-href"};

    xlog $self, "update contact with invalid properties";
    $res = $jmap->CallMethods([['Contact/set', {
        update => {
            $contact => {
                id => "xyz",
                foo => "",
                "x-hasPhoto" => "yes",
                "x-ref" => "abc"
            },
        }}, "R4"]]);
    $self->assert_not_null($res);
    my $notUpdated = $res->[0][1]{notUpdated}{$contact};
    $self->assert_not_null($notUpdated);
    $self->assert_num_equals(3, scalar @{$notUpdated->{properties}});

    xlog $self, "update contact with server-set properties";
    $res = $jmap->CallMethods([['Contact/set', {
        update => {
            $contact => {
                id => $contact,
                "x-hasPhoto" => JSON::false,
                "x-href" => $href
            },
        }}, "R5"]]);
    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{updated});
}

sub test_contactgroup_set
    :min_version_3_1 :needs_component_jmap
{

    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" => { firstName => "foo", lastName => "last1" },
                        "2" => { firstName => "bar", lastName => "last2" }
                    }}, "R1"]]);
    my $contact1 = $res->[0][1]{created}{"1"}{id};
    my $contact2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "create contact group with no contact ids";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "1" => {name => "group1"}
                    }}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get contact group $id";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [$id] }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/get', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert_str_equals('group1', $res->[0][1]{list}[0]{name});
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}[0]{contactIds}});

    xlog $self, "update contact group with invalid contact ids";
    $res = $jmap->CallMethods([['ContactGroup/set', {update => {
                        $id => {name => "group1", contactIds => [$contact1, $contact2, 255]}
                    }}, "R4"]]);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals('contactIds[2]', $res->[0][1]{notUpdated}{$id}{properties}[0]);
    $self->assert_str_equals('R4', $res->[0][2]);

    xlog $self, "get contact group $id";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [$id] }, "R3"]]);
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}[0]{contactIds}});


    xlog $self, "update contact group with valid contact ids";
    $res = $jmap->CallMethods([['ContactGroup/set', {update => {
                        $id => {name => "group1", contactIds => [$contact1, $contact2]}
                    }}, "R4"]]);

    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog $self, "get contact group $id";
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

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
                        "1" =>
                        {
                            firstName => "foo", lastName => "last",
                            emails => [{
                                    type => "personal",
                                    value => "foo\@example.com"
                                }]
                        },
                        "2" =>
                        {
                            firstName => "bar", lastName => "last",
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
                            firstName => "baz", lastName => "last",
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
                        "4" => {firstName => "bam", lastName => "last",
                                 isFlagged => JSON::false }
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};
    my $id4 = $res->[0][1]{created}{"4"}{id};

    xlog $self, "create contact groups";
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

    xlog $self, "get unfiltered contact list";
    $res = $jmap->CallMethods([ ['Contact/query', { }, "R1"] ]);

    $self->assert_num_equals(4, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog $self, "filter by lastName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(4, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by firstName and lastName (one filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { firstName => "bam", lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id4, $res->[0][1]{ids}[0]);

    xlog $self, "filter by firstName and lastName (AND filter)";
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

    xlog $self, "filter by firstName (OR filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { operator => "OR", conditions => [{
                                firstName => "bar"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by text";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { text => "some" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by email";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { email => "example.com" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by isFlagged (true)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { isFlagged => JSON::true }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id2, $res->[0][1]{ids}[0]);

    xlog $self, "filter by isFlagged (false)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { isFlagged => JSON::false }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by inContactGroup";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    filter => { inContactGroup => [$group1, $group3] }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by inContactGroup and firstName";
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

    xlog $self, "create shared account";
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
    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {
                        "1" =>
                        {
                            firstName => "foo", lastName => "last",
                            emails => [{
                                    type => "personal",
                                    value => "foo\@example.com"
                                }]
                        },
                        "2" =>
                        {
                            firstName => "bar", lastName => "last",
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
                            firstName => "baz", lastName => "last",
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
                        "4" => {firstName => "bam", lastName => "last",
                                 isFlagged => JSON::false }
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};
    my $id4 = $res->[0][1]{created}{"4"}{id};

    xlog $self, "create contact groups";
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

    xlog $self, "get unfiltered contact list";
    $res = $jmap->CallMethods([ ['Contact/query', { accountId => 'manifold' }, "R1"] ]);

    xlog $self, "check total";
    $self->assert_num_equals(4, $res->[0][1]{total});
    xlog $self, "check ids";
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog $self, "filter by lastName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(4, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by firstName and lastName (one filter)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { firstName => "bam", lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id4, $res->[0][1]{ids}[0]);

    xlog $self, "filter by firstName and lastName (AND filter)";
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

    xlog $self, "filter by firstName (OR filter)";
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

    xlog $self, "filter by text";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { text => "some" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by email";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { email => "example.com" }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by isFlagged (true)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { isFlagged => JSON::true }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id2, $res->[0][1]{ids}[0]);

    xlog $self, "filter by isFlagged (false)";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { isFlagged => JSON::false }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by inContactGroup";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { inContactGroup => [$group1, $group3] }
                }, "R1"] ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by inContactGroup and firstName";
    $res = $jmap->CallMethods([ ['Contact/query', {
                    accountId => 'manifold',
                    filter => { inContactGroup => [$group1, $group3], firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);
}

sub test_contact_query_uid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    firstName => 'contact1',
                },
                contact2 => {
                    firstName => 'contact2',
                },
                contact3 => {
                    firstName => 'contact3',
                },
            },
        }, 'R1'],
    ]);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);
    my $contactUid1 = $res->[0][1]{created}{contact1}{uid};
    $self->assert_not_null($contactUid1);

    my $contactId2 = $res->[0][1]{created}{contact2}{id};
    $self->assert_not_null($contactId2);
    my $contactUid2 = $res->[0][1]{created}{contact2}{uid};
    $self->assert_not_null($contactUid2);

    my $contactId3 = $res->[0][1]{created}{contact3}{id};
    $self->assert_not_null($contactId3);
    my $contactUid3 = $res->[0][1]{created}{contact3}{uid};
    $self->assert_not_null($contactUid3);

    xlog $self, "query by single uid";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                uid => $contactUid2,
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("Contact/query", $res->[0][0]);
    $self->assert_deep_equals([$contactId2], $res->[0][1]{ids});

    xlog $self, "query by invalid uid";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                uid => "notarealuid",
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("Contact/query", $res->[0][0]);
    $self->assert_deep_equals([], $res->[0][1]{ids});

    xlog $self, "query by multiple uids";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                operator => 'OR',
                conditions => [{
                        uid => $contactUid1,
                }, {
                        uid => $contactUid3,
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("Contact/query", $res->[0][0]);
    my %gotIds =  map { $_ => 1 } @{$res->[0][1]{ids}};
    $self->assert_deep_equals({ $contactUid1 => 1, $contactUid3 => 1, }, \%gotIds);
}

sub test_contact_query_sort
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    uid => 'XXX-UID-1',
                    company => 'companyB',
                    isFlagged => JSON::true,
                },
                contact2 => {
                    uid => 'XXX-UID-2',
                    company => 'companyA',
                    isFlagged => JSON::true,
                },
                contact3 => {
                    uid => 'XXX-UID-3',
                    company => 'companyB',
                    isFlagged => JSON::false,
                },
                contact4 => {
                    uid => 'XXX-UID-4',
                    company => 'companyC',
                    isFlagged => JSON::true,
                },
            },
        }, 'R1'],
    ]);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);

    my $contactId2 = $res->[0][1]{created}{contact2}{id};
    $self->assert_not_null($contactId2);

    my $contactId3 = $res->[0][1]{created}{contact3}{id};
    $self->assert_not_null($contactId3);

    my $contactId4 = $res->[0][1]{created}{contact4}{id};
    $self->assert_not_null($contactId4);

    xlog $self, "sort by multi-dimensional comparator";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            sort => [{
                property => 'company',
            }, {
                property => 'uid',
                isAscending => JSON::false,
            }],
        }, 'R2'],
    ]);
    $self->assert_deep_equals([
            $contactId2,
            $contactId3,
            $contactId1,
            $contactId4,
        ], $res->[0][1]{ids}
    );
}

sub test_contact_query_windowing
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    uid => 'XXX-UID-1',
                    company => 'companyB',
                    isFlagged => JSON::true,
                },
                contact2 => {
                    uid => 'XXX-UID-2',
                    company => 'companyA',
                    isFlagged => JSON::true,
                },
                contact3 => {
                    uid => 'XXX-UID-3',
                    company => 'companyB',
                    isFlagged => JSON::false,
                },
                contact4 => {
                    uid => 'XXX-UID-4',
                    company => 'companyC',
                    isFlagged => JSON::true,
                },
            },
        }, 'R1'],
    ]);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);

    my $contactId2 = $res->[0][1]{created}{contact2}{id};
    $self->assert_not_null($contactId2);

    my $contactId3 = $res->[0][1]{created}{contact3}{id};
    $self->assert_not_null($contactId3);

    my $contactId4 = $res->[0][1]{created}{contact4}{id};
    $self->assert_not_null($contactId4);

    xlog $self, "run query with windowing";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            sort => [{
                property => 'uid',
            }],
            limit => 2,
        }, 'R1'],
        ['Contact/query', {
            sort => [{
                property => 'uid',
            }],
            limit => 2,
            position => 2,
        }, 'R2'],
        ['Contact/query', {
            sort => [{
                property => 'uid',
            }],
            anchor => $contactId3,
            anchorOffset => -1,
            limit => 2,
        }, 'R3'],
        ['Contact/query', {
            sort => [{
                property => 'uid',
            }],
            limit => 2,
            position => -2,
        }, 'R4'],
    ]);
    # Request 1
    $self->assert_deep_equals([
            $contactId1,
            $contactId2,
        ], $res->[0][1]{ids}
    );
    $self->assert_num_equals(0, $res->[0][1]{position});
    $self->assert_num_equals(4, $res->[0][1]{total});
    # Request 2
    $self->assert_deep_equals([
            $contactId3,
            $contactId4,
        ], $res->[1][1]{ids}
    );
    $self->assert_num_equals(2, $res->[1][1]{position});
    $self->assert_num_equals(4, $res->[1][1]{total});
    # Request 3
    $self->assert_deep_equals([
            $contactId2,
            $contactId3,
        ], $res->[2][1]{ids}
    );
    $self->assert_num_equals(1, $res->[2][1]{position});
    $self->assert_num_equals(4, $res->[2][1]{total});
    # Request 4
    $self->assert_deep_equals([
            $contactId3,
            $contactId4,
        ], $res->[3][1]{ids}
    );
    $self->assert_num_equals(2, $res->[3][1]{position});
    $self->assert_num_equals(4, $res->[3][1]{total});
}

sub test_contact_query_text
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    notes => 'cats and dogs',
                },
                contact2 => {
                    notes => 'hats and bats',
                },
            },
        }, 'R1'],
    ]);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);
    my $contactId2 = $res->[0][1]{created}{contact2}{id};
    $self->assert_not_null($contactId2);

    xlog "Query with loose terms";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                notes => "cats dogs",
            },
        }, 'R1'],
        ['Contact/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    notes => 'cats dogs',
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$contactId1], $res->[0][1]{ids});
    $self->assert_deep_equals([$contactId2], $res->[1][1]{ids});

    xlog "Query with phrase";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                notes => "'cats and dogs'",
            },
        }, 'R1'],
        ['Contact/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    notes => "'cats and dogs'",
                }],
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals([$contactId1], $res->[0][1]{ids});
    $self->assert_deep_equals([$contactId2], $res->[1][1]{ids});

    xlog "Query with both phrase and loose terms";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                notes => "cats 'cats and dogs' dogs",
            },
        }, 'R1'],
        ['Contact/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    notes => "cats 'cats and dogs' dogs",
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$contactId1], $res->[0][1]{ids});
    $self->assert_deep_equals([$contactId2], $res->[1][1]{ids});

    xlog "Query text";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                text => "cats dogs",
            },
        }, 'R1'],
        ['Contact/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    text => "cats dogs",
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$contactId1], $res->[0][1]{ids});
    $self->assert_deep_equals([$contactId2], $res->[1][1]{ids});

    xlog "Query text and notes";
    $res = $jmap->CallMethods([
        ['Contact/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    text => "cats",
                }, {
                    notes => "dogs",
                }],
            },
        }, 'R1'],
        ['Contact/query', {

            filter => {
                operator => 'NOT',
                conditions => [{
                    operator => 'AND',
                    conditions => [{
                        text => "cats",
                    }, {
                        notes => "dogs",
                    }],
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$contactId1], $res->[0][1]{ids});
    $self->assert_deep_equals([$contactId2], $res->[1][1]{ids});
}

sub test_contactgroup_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
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

    xlog $self, "get contact groups state";
    $res = $jmap->CallMethods([['ContactGroup/get', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog $self, "create contact group 1";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "1" => {name => "first", contactIds => [$contactA, $contactB]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};


    xlog $self, "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog $self, "create contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {create => {
                        "2" => {name => "second", contactIds => [$contactC, $contactD]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "get contact group updates (since last change)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "get contact group updates (in bulk)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "get contact group updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::true, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog $self, "get contact group updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "destroy contact group 1, update contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    destroy => [$id1],
                    update => {$id2 => {name => "second (updated)"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog $self, "destroy contact group 2";
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

    xlog $self, "create shared account";
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
    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "create contacts";
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

    xlog $self, "get contact groups state";
    $res = $jmap->CallMethods([['ContactGroup/get', { accountId => 'manifold', }, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog $self, "create contact group 1";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    create => {
                        "1" => {name => "first", contactIds => [$contactA, $contactB]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id1 = $res->[0][1]{created}{"1"}{id};


    xlog $self, "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog $self, "create contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    create => {
                        "2" => {name => "second", contactIds => [$contactC, $contactD]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "get contact group updates (since last change)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "get contact group updates (in bulk)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "get contact group updates from initial state (maxChanges=1)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::true, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{created}[0]);
    my $interimState = $res->[0][1]{newState};

    xlog $self, "get contact group updates from interim state (maxChanges=10)";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($interimState, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "destroy contact group 1, update contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    destroy => [$id1],
                    update => {$id2 => {name => "second (updated)"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "get contact group updates";
    $res = $jmap->CallMethods([['ContactGroup/changes', {
                    accountId => 'manifold',
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id2, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog $self, "destroy contact group 2";
    $res = $jmap->CallMethods([['ContactGroup/set', {
                    accountId => 'manifold',
                    destroy => [$id2]
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('ContactGroup/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_contactgroup_query_uid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contact groups";
    my $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            create => {
                contactGroup1 => {
                    name => 'contactGroup1',
                },
                contactGroup2 => {
                    name => 'contactGroup2',
                },
                contactGroup3 => {
                    name => 'contactGroup3',
                },
            },
        }, 'R1'],
    ]);
    my $contactGroupId1 = $res->[0][1]{created}{contactGroup1}{id};
    $self->assert_not_null($contactGroupId1);
    my $contactGroupUid1 = $res->[0][1]{created}{contactGroup1}{uid};
    $self->assert_not_null($contactGroupUid1);

    my $contactGroupId2 = $res->[0][1]{created}{contactGroup2}{id};
    $self->assert_not_null($contactGroupId2);
    my $contactGroupUid2 = $res->[0][1]{created}{contactGroup2}{uid};
    $self->assert_not_null($contactGroupUid2);

    my $contactGroupId3 = $res->[0][1]{created}{contactGroup3}{id};
    $self->assert_not_null($contactGroupId3);
    my $contactGroupUid3 = $res->[0][1]{created}{contactGroup3}{uid};
    $self->assert_not_null($contactGroupUid3);

    xlog $self, "query by single uid";
    $res = $jmap->CallMethods([
        ['ContactGroup/query', {
            filter => {
                uid => $contactGroupUid2,
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("ContactGroup/query", $res->[0][0]);
    $self->assert_deep_equals([$contactGroupId2], $res->[0][1]{ids});

    xlog $self, "query by invalid uid";
    $res = $jmap->CallMethods([
        ['ContactGroup/query', {
            filter => {
                uid => "notarealuid",
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("ContactGroup/query", $res->[0][0]);
    $self->assert_deep_equals([], $res->[0][1]{ids});

    xlog $self, "query by multiple uids";
    $res = $jmap->CallMethods([
        ['ContactGroup/query', {
            filter => {
                operator => 'OR',
                conditions => [{
                        uid => $contactGroupUid1,
                }, {
                        uid => $contactGroupUid3,
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("ContactGroup/query", $res->[0][0]);
    my %gotIds =  map { $_ => 1 } @{$res->[0][1]{ids}};
    $self->assert_deep_equals({ $contactGroupUid1 => 1, $contactGroupUid3 => 1, }, \%gotIds);
}

sub test_contactgroup_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contact groups";
    my $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            create => {
                contactGroup1 => {
                    name => 'dogs and cats',
                },
                contactGroup2 => {
                    name => 'cats and bats',
                },
                contactGroup3 => {
                    name => 'bats and hats',
                },
            },
        }, 'R1'],
    ]);
    my $contactGroupId1 = $res->[0][1]{created}{contactGroup1}{id};
    $self->assert_not_null($contactGroupId1);
    my $contactGroupUid1 = $res->[0][1]{created}{contactGroup1}{uid};
    $self->assert_not_null($contactGroupUid1);

    my $contactGroupId2 = $res->[0][1]{created}{contactGroup2}{id};
    $self->assert_not_null($contactGroupId2);
    my $contactGroupUid2 = $res->[0][1]{created}{contactGroup2}{uid};
    $self->assert_not_null($contactGroupUid2);

    my $contactGroupId3 = $res->[0][1]{created}{contactGroup3}{id};
    $self->assert_not_null($contactGroupId3);
    my $contactGroupUid3 = $res->[0][1]{created}{contactGroup3}{uid};
    $self->assert_not_null($contactGroupUid3);

    xlog $self, "query by exact name";
    $res = $jmap->CallMethods([
        ['ContactGroup/query', {
            filter => {
                name => 'dogs and cats',
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("ContactGroup/query", $res->[0][0]);
    $self->assert_deep_equals([$contactGroupId1], $res->[0][1]{ids});

    xlog $self, "query by unknown name";
    $res = $jmap->CallMethods([
        ['ContactGroup/query', {
            filter => {
                name => 'nope',
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("ContactGroup/query", $res->[0][0]);
    $self->assert_deep_equals([], $res->[0][1]{ids});

    xlog $self, "query substring of name";
    $res = $jmap->CallMethods([
        ['ContactGroup/query', {
            filter => {
                operator => 'OR',
                conditions => [{
                    name => 'bats',
                }, {
                    text => 'hats',
                }],
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals("ContactGroup/query", $res->[0][0]);
    my %gotIds =  map { $_ => 1 } @{$res->[0][1]{ids}};
    $self->assert_deep_equals({ $contactGroupUid2 => 1, $contactGroupUid3 => 1, }, \%gotIds);
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
    $contact->{uid} = $id;
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
    $contact->{avatar} = undef;

    # Non-JMAP properties.
    $contact->{"importance"} = 0;
    $contact->{"x-hasPhoto"} = JSON::false;
    $contact->{"addressbookId"} = 'Default';

    if ($res->[0][1]{created}{"1"}{blobId}) {
        $contact->{blobId} = $res->[0][1]{created}{"1"}{blobId};
        $contact->{size} = $res->[0][1]{created}{"1"}{size};
    }

    xlog $self, "get contact $id";
    my $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);

    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $contact->{"x-href"} = $fetch->[0][1]{list}[0]{"x-href"};
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update isFlagged";
    $contact->{isFlagged} = JSON::true;
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {isFlagged => JSON::true} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update prefix";
    $contact->{prefix} = 'foo';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {prefix => 'foo'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update suffix";
    $contact->{suffix} = 'bar';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {suffix => 'bar'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update nickname";
    $contact->{nickname} = 'nick';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {nickname => 'nick'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update birthday (with JMAP datetime error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {birthday => '1979-04-01T00:00:00Z'} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("birthday", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update birthday";
    $contact->{birthday} = '1979-04-01'; # Happy birthday, El Barto!
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {birthday => '1979-04-01'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update anniversary (with JMAP datetime error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {anniversary => '1989-12-17T00:00:00Z'} }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("anniversary", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update anniversary";
    $contact->{anniversary} = '1989-12-17'; # Happy anniversary, Simpsons!
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {anniversary => '1989-12-17'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update company";
    $contact->{company} = 'acme';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {company => 'acme'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update department";
    $contact->{department} = 'looney tunes';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {department => 'looney tunes'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update jobTitle";
    $contact->{jobTitle} = 'director of everything';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {jobTitle => 'director of everything'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    # emails
    xlog $self, "update emails (with missing type error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            emails => [{ value => "acme\@example.com" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("emails[0].type", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update emails (with missing value error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            emails => [{ type => "other" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("emails[0].value", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update emails";
    $contact->{emails} = [{ type => "work", value => "acme\@example.com", isDefault => JSON::true }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            emails => [{ type => "work", value => "acme\@example.com" }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    # phones
    xlog $self, "update phones (with missing type error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            phones => [{ value => "12345678" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("phones[0].type", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update phones (with missing value error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            phones => [{ type => "home" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("phones[0].value", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update phones";
    $contact->{phones} = [{ type => "home", value => "12345678" }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            phones => [{ type => "home", value => "12345678" }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    # online
    xlog $self, "update online (with missing type error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            online => [{ value => "http://example.com/me" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("online[0].type", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update online (with missing value error)";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            online => [{ type => "uri" }]
                        } }}, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals("online[0].value", $res->[0][1]{notUpdated}{$id}{properties}[0]);

    xlog $self, "update online";
    $contact->{online} = [{ type => "uri", value => "http://example.com/me" }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            online => [{ type => "uri", value => "http://example.com/me" }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    # addresses
    xlog $self, "update addresses";
    $contact->{addresses} = [{
            type => "home",
            street => "acme lane 1",
            locality => "acme city",
            region => "",
            postcode => "1234",
            country => "acme land",
            label => undef,
        }];
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {
                            addresses => [{
                                    type => "home",
                                    street => "acme lane 1",
                                    locality => "acme city",
                                    region => "",
                                    postcode => "1234",
                                    country => "acme land",
                                    label => undef,
                                }]
                        } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    xlog $self, "update notes";
    $contact->{notes} = 'baz';
    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {notes => 'baz'} }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    xlog $self, "get contact $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);

    # avatar
    xlog $self, "upload avatar";
    $res = $jmap->Upload("some photo", "image/jpeg");
    my $blobId = $res->{blobId};
    $contact->{"x-hasPhoto"} = JSON::true;
    $contact->{avatar} = {
        blobId => $blobId,
        size => 10,
        type => "image/jpeg",
        name => JSON::null
    };

    xlog $self, "attempt to update avatar with invalid type";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id =>
                            {avatar => {
                                blobId => $blobId,
                                size => 10,
                                type => "JPEG",
                                name => JSON::null
                             }
                     } }}, "R1"]]);
    $self->assert_null($res->[0][1]{updated});
    $self->assert_not_null($res->[0][1]{notUpdated}{$id});

    xlog $self, "update avatar";
    $res = $jmap->CallMethods([['Contact/set', {update => {$id =>
                            {avatar => {
                                blobId => $blobId,
                                size => 10,
                                type => "image/jpeg",
                                name => JSON::null
                             }
                     } }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    if ($res->[0][1]{updated}{$id}{blobId}) {
        $contact->{blobId} = $res->[0][1]{updated}{$id}{blobId};
        $contact->{size} = $res->[0][1]{updated}{$id}{size};
    }

    if ($res->[0][1]{updated}{$id}{avatar}{blobId}) {
        $contact->{avatar}{blobId} = $res->[0][1]{updated}{$id}{avatar}{blobId};
    }

    xlog $self, "get avatar $id";
    $fetch = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_deep_equals($contact, $fetch->[0][1]{list}[0]);
}

sub test_contact_set_avatar_singlecommand
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $contact = {
        firstName => "first",
        lastName => "last",
        avatar => {
            blobId => "#img",
            size => 10,
            type => "image/jpeg",
            name => JSON::null
        }
    };

    my $using = [
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/blob',
    ];

    my $res = $jmap->CallMethods([
        ['Blob/set', { create => {
            "img" => { content => 'some photo',
                       type => 'image/jpeg' } } }, 'R0'],
        ['Contact/set', {create => {"1" => $contact }}, "R1"],
        ['Contact/get', {}, "R2"]],
        $using);
    $self->assert_not_null($res);
    $self->assert_str_equals('Blob/set', $res->[0][0]);
    $self->assert_str_equals('R0', $res->[0][2]);

    $contact->{avatar}{blobId} = $res->[0][1]{created}{"img"}{blobId};

    $self->assert_str_equals('Contact/set', $res->[1][0]);
    $self->assert_str_equals('R1', $res->[1][2]);
    my $id = $res->[1][1]{created}{"1"}{id};

    if ($res->[1][1]{created}{"1"}{avatar}{blobId}) {
        $contact->{avatar}{blobId} = $res->[1][1]{created}{"1"}{avatar}{blobId};
    }

    $self->assert_str_equals('Contact/get', $res->[2][0]);
    $self->assert_str_equals('R2', $res->[2][2]);
    $self->assert_str_equals($id, $res->[2][1]{list}[0]{id});
    $self->assert_deep_equals($contact->{avatar}, $res->[2][1]{list}[0]{avatar});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{"x-hasPhoto"});

    xlog $self, "remove avatar";
    $res = $jmap->CallMethods([
        ['Contact/set', {update => {$id => {avatar => JSON::null} }}, "R1"],
        ['Contact/get', {}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $self->assert_str_equals('Contact/get', $res->[1][0]);
    $self->assert_str_equals('R2', $res->[1][2]);
    $self->assert_str_equals($id, $res->[1][1]{list}[0]{id});
    $self->assert_null($res->[1][1]{list}[0]{avatar});
    $self->assert_equals(JSON::false, $res->[1][1]{list}[0]{"x-hasPhoto"});
}

sub test_contact_set_avatar_from_deleted_contact
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $contact = {
        firstName => "first",
        lastName => "last",
        avatar => {
            blobId => "#img",
            size => 10,
            type => "image/jpeg",
            name => JSON::null
        }
    };

    my $using = [
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/blob',
    ];

    xlog $self, "create initial card";
    my $res = $jmap->CallMethods([
        ['Blob/set', { create => {
            "img" => { content => 'some photo',
                       type => 'image/jpeg' } } }, 'R0'],
        ['Contact/set', {create => {"1" => $contact }}, "R1"],
        ['Contact/get', {}, "R2"]],
        $using);
    $self->assert_not_null($res);
    $self->assert_str_equals('Blob/set', $res->[0][0]);
    $self->assert_str_equals('R0', $res->[0][2]);

    $contact->{avatar}{blobId} = $res->[0][1]{created}{"img"}{blobId};

    $self->assert_str_equals('Contact/set', $res->[1][0]);
    $self->assert_str_equals('R1', $res->[1][2]);
    my $id = $res->[1][1]{created}{"1"}{id};

    $contact->{avatar}{blobId} = $res->[1][1]{created}{"1"}{avatar}{blobId};

    $self->assert_str_equals('Contact/get', $res->[2][0]);
    $self->assert_str_equals('R2', $res->[2][2]);
    $self->assert_str_equals($id, $res->[2][1]{list}[0]{id});
    $self->assert_str_equals('first', $res->[2][1]{list}[0]{firstName});
    $self->assert_deep_equals($contact->{avatar}, $res->[2][1]{list}[0]{avatar});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{"x-hasPhoto"});

    my $newcontact = {
        firstName => "first2",
        lastName => "last2",
        avatar => {
            blobId => "$contact->{avatar}{blobId}",
            size => 10,
            type => "image/jpeg",
            name => JSON::null
        }
    };

    xlog $self, "delete initial card";
    $res = $jmap->CallMethods([
        ['Contact/set', { destroy => [ "$id"] }, 'R0']],
        $using);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R0', $res->[0][2]);

    xlog $self, "create new card using avatar from deleted card";
    $res = $jmap->CallMethods([
        ['Contact/set', {create => {"1" => $newcontact }}, "R1"],
        ['Contact/get', {}, "R2"]],
        $using);

    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $id = $res->[0][1]{created}{"1"}{id};

    $contact->{avatar}{blobId} = $res->[0][1]{created}{"1"}{avatar}{blobId};

    $self->assert_str_equals('Contact/get', $res->[1][0]);
    $self->assert_str_equals('R2', $res->[1][2]);
    $self->assert_str_equals($id, $res->[1][1]{list}[0]{id});
    $self->assert_str_equals('first2', $res->[1][1]{list}[0]{firstName});
    $self->assert_deep_equals($contact->{avatar}, $res->[1][1]{list}[0]{avatar});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{"x-hasPhoto"});

    xlog $self, "download and check avatar content";
    my $blob = $jmap->Download({ accept => 'image/jpeg' },
                               'cassandane', $res->[1][1]{list}[0]{avatar}{blobId});
    $self->assert_str_equals('image/jpeg',
                             $blob->{headers}->{'content-type'});
    $self->assert_num_equals(10, $blob->{headers}->{'content-length'});
    $self->assert_equals('some photo', $blob->{content});
}

sub test_contact_set_uid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # An empty UID generates a random uid.
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                "1" => {
                    firstName => "first1",
                    lastName => "last1",
                }
            }
        }, "R1"],
        ['Contact/get', { ids => ['#1'] }, 'R2'],
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{uid});
    $jmap->{CreatedIds} = {};

    # A sane UID maps to both the JMAP id and the DAV resource.
    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                "2" => {
                    firstName => "first2",
                    lastName => "last2",
                    uid => '1234-56789-01234-56789',
                }
            }
        }, "R1"],
        ['Contact/get', { ids => ['#2'] }, 'R2'],
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{uid});
    my($filename, $dirs, $suffix) = fileparse($res->[1][1]{list}[0]{"x-href"}, ".vcf");
    $self->assert_not_null($res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($res->[1][1]{list}[0]->{uid}, $res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($filename, $res->[1][1]{list}[0]->{id});
    $jmap->{CreatedIds} = {};

    # A non-pathsafe UID maps to uid but not the DAV resource.
    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                "3" => {
                    firstName => "first3",
                    lastName => "last3",
                    uid => 'a/bogus/path#uid',
                }
            }
        }, "R1"],
        ['Contact/get', { ids => ['#3'] }, 'R2'],
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{uid});
    ($filename, $dirs, $suffix) = fileparse($res->[1][1]{list}[0]{"x-href"}, ".vcf");
    $self->assert_not_null($res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($res->[1][1]{list}[0]->{id}, $res->[1][1]{list}[0]->{uid});
    $self->assert_str_not_equals('path#uid', $filename);
    $jmap->{CreatedIds} = {};

    # Can't change an UID
    my $contactId = $res->[0][1]{created}{3}{id};
    $self->assert_not_null($contactId);
    $res = $jmap->CallMethods([
        ['Contact/set', {
            update => {
                $contactId => {
                    uid => '0000-1234-56789-01234-56789-000'
                }
            }
        }, "R1"],
    ]);
    $self->assert_str_equals('uid', $res->[0][1]{notUpdated}{$contactId}{properties}[0]);
    $jmap->{CreatedIds} = {};

}

sub test_contactgroup_set_uid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # An empty UID generates a random uid.
    my $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            create => {
                "1" => {
                    name => "name1",
                }
            }
        }, "R1"],
        ['ContactGroup/get', { ids => ['#1'] }, 'R2'],
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{uid});
    $jmap->{CreatedIds} = {};

    # A sane UID maps to both the JMAP id and the DAV resource.
    $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            create => {
                "2" => {
                    name => "name2",
                    uid => '1234-56789-01234-56789',
                }
            }
        }, "R1"],
        ['ContactGroup/get', { ids => ['#2'] }, 'R2'],
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{uid});
    my($filename, $dirs, $suffix) = fileparse($res->[1][1]{list}[0]{"x-href"}, ".vcf");
    $self->assert_not_null($res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($res->[1][1]{list}[0]->{uid}, $res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($filename, $res->[1][1]{list}[0]->{id});
    $jmap->{CreatedIds} = {};

    # A non-pathsafe UID maps to uid but not the DAV resource.
    $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            create => {
                "3" => {
                    name => "name3",
                    uid => 'a/bogus/path#uid',
                }
            }
        }, "R1"],
        ['ContactGroup/get', { ids => ['#3'] }, 'R2'],
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{uid});
    ($filename, $dirs, $suffix) = fileparse($res->[1][1]{list}[0]{"x-href"}, ".vcf");
    $self->assert_not_null($res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($res->[1][1]{list}[0]->{id}, $res->[1][1]{list}[0]->{uid});
    $self->assert_str_not_equals('path#uid', $filename);
    $jmap->{CreatedIds} = {};

    # Can't change an UID
    my $contactId = $res->[0][1]{created}{3}{id};
    $self->assert_not_null($contactId);
    $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            update => {
                $contactId => {
                    uid => '0000-1234-56789-01234-56789-000'
                }
            }
        }, "R1"],
    ]);
    $self->assert_str_equals('uid', $res->[0][1]{notUpdated}{$contactId}{properties}[0]);
    $jmap->{CreatedIds} = {};

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

    xlog $self, "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => $contact }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    xlog $self, "get contact $id";
    $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{emails}[0]{label});

    xlog $self, "update contact";
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

    xlog $self, "get contact $id";
    $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_str_equals('personal', $res->[0][1]{list}[0]{emails}[0]{type});
    $self->assert_null($res->[0][1]{list}[0]{emails}[0]{label});
}


sub test_contact_set_state
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};
    my $state = $res->[0][1]{newState};

    xlog $self, "get contact $id";
    $res = $jmap->CallMethods([['Contact/get', {}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/get', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    $self->assert_str_equals('first', $res->[0][1]{list}[0]{firstName});
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog $self, "update $id with state token $state";
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

    xlog $self, "update $id with expired state token $oldState";
    $res = $jmap->CallMethods([['Contact/set', {
                    ifInState => $oldState,
                    update => {$id =>
                        {firstName => "first", lastName => "last"}
                    }}, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog $self, "get contact $id to make sure state didn't change";
    $res = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog $self, "destroy $id with expired state token $oldState";
    $res = $jmap->CallMethods([['Contact/set', {
                    ifInState => $oldState,
                    destroy => [$id]
                }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog $self, "destroy contact $id with current state";
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

    xlog $self, "create with no importance";
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
    $self->assert_num_equals(0.0, $fetch->[0][1]{list}[0]{"importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"importance" => -0.1}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-0.1, $fetch->[0][1]{list}[0]{"importance"});
}

sub test_contact_set_avatar_shared
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
    $admintalk->create("user.manifold");

    xlog $self, "create #jmap folder";
    $admintalk->create("user.manifold.#jmap", ['TYPE', 'COLLECTION']);

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
    $admintalk->setacl("user.manifold.#jmap", admin => 'lrswipkxtecdn');

    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    # avatar
    xlog $self, "upload avatar - setacl on shared #jmap folder";
    my $res = $jmap->Upload("some photo", "image/jpeg", "manifold");
    my $blobId = $res->{blobId};

    xlog $self, "create contact";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {"1" => {firstName => "first", lastName => "last",
                     avatar => {
                         blobId => $blobId,
                         size => 10,
                         type => "image/jpeg",
                         name => JSON::null
                      }
                               }}
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "delete #jmap folder";
    $admintalk->delete("user.manifold.#jmap") || die;

    # avatar
    xlog $self, "upload new avatar - create new shared #jmap folder";
    $res = $jmap->Upload("some other photo", "image/jpeg", "manifold");
    $blobId = $res->{blobId};

    xlog $self, "update avatar";
    $res = $jmap->CallMethods([['Contact/set', {
        accountId => 'manifold',
        update => {$id =>
                     {avatar => {
                         blobId => $blobId,
                         size => 10,
                         type => "image/jpeg",
                         name => JSON::null
                      }
                  }
        }
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});
}

sub test_contact_set_importance_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
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
    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    create => {"1" => {firstName => "first", lastName => "last"}}
    }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    $admintalk->setacl("user.manifold.#addressbooks.Default", "cassandane" => 'lrsn') or die;

    xlog $self, "update importance";
    $res = $jmap->CallMethods([['Contact/set', {
                    accountId => 'manifold',
                    update => {$id => {"importance" => -0.1}}
    }, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R2', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});
}

sub test_contact_set_importance_upfront
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create with importance in initial create";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"importance"});

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
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"importance"});
}

sub test_contact_set_importance_multiedit
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"firstName" => "second", "importance" => -0.2}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('second', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-0.2, $fetch->[0][1]{list}[0]{"importance"});
}

sub test_contact_set_importance_zero_multi
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"firstName" => "second", "importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('second', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(0, $fetch->[0][1]{list}[0]{"importance"});
}

sub test_contact_set_importance_zero_byself
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create with no importance";
    my $res = $jmap->CallMethods([['Contact/set', {create => {"1" => {firstName => "first", lastName => "last", "importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my $id = $res->[0][1]{created}{"1"}{id};

    my $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R2', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(-5.2, $fetch->[0][1]{list}[0]{"importance"});

    $res = $jmap->CallMethods([['Contact/set', {update => {$id => {"importance" => 0}}}, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R3', $res->[0][2]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->CallMethods([['Contact/get', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals('Contact/get', $fetch->[0][0]);
    $self->assert_str_equals('R4', $fetch->[0][2]);
    $self->assert_str_equals('first', $fetch->[0][1]{list}[0]{firstName});
    $self->assert_num_equals(0, $fetch->[0][1]{list}[0]{"importance"});
}

sub test_misc_creationids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create and get contact group and contact";
    my $res = $jmap->CallMethods([
        ['Contact/set', {create => { "c1" => { firstName => "foo", lastName => "last1" }, }}, "R2"],
        ['ContactGroup/set', {create => { "g1" => {name => "group1", contactIds => ["#c1"]} }}, "R2"],
        ['Contact/get', {ids => ["#c1"]}, "R3"],
        ['ContactGroup/get', {ids => ["#g1"]}, "R4"],
    ]);
    my $contact = $res->[2][1]{list}[0];
    $self->assert_str_equals("foo", $contact->{firstName});

    my $group = $res->[3][1]{list}[0];
    $self->assert_str_equals("group1", $group->{name});

    $self->assert_str_equals($contact->{id}, $group->{contactIds}[0]);
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


    xlog $self, "create a contact with two categories";
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

sub test_contact_get_with_addressbookid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get contact with addressbookid";
    my $res = $jmap->CallMethods([['Contact/get',
                                   { addressbookId => "Default" }, "R3"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
}

sub test_contact_get_issue2292
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
        "1" => { firstName => "foo", lastName => "last1" },
    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"});

    xlog $self, "get contact with no ids";
    $res = $jmap->CallMethods([['Contact/get', { }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    xlog $self, "get contact with empty ids";
    $res = $jmap->CallMethods([['Contact/get', { ids => [] }, "R3"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    xlog $self, "get contact with null ids";
    $res = $jmap->CallMethods([['Contact/get', { ids => undef }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
}

sub test_contactgroup_get_issue2292
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contact group";
    my $res = $jmap->CallMethods([['ContactGroup/set', {create => {
        "1" => {name => "group1"}
    }}, "R2"]]);
    $self->assert_not_null($res->[0][1]{created}{"1"});

    xlog $self, "get contact group with no ids";
    $res = $jmap->CallMethods([['ContactGroup/get', { }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    xlog $self, "get contact group with empty ids";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => [] }, "R3"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    xlog $self, "get contact group with null ids";
    $res = $jmap->CallMethods([['ContactGroup/get', { ids => undef }, "R3"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
}

sub test_contact_copy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared accounts";
    $admintalk->create("user.other");
    $admintalk->create("user.other2");
    $admintalk->create("user.other3");

    my $othercarddav = Net::CardDAVTalk->new(
        user => "other",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $other2carddav = Net::CardDAVTalk->new(
        user => "other2",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $other3carddav = Net::CardDAVTalk->new(
        user => "other3",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog $self, "share addressbooks";
    $admintalk->setacl("user.other.#addressbooks.Default",
                       "cassandane" => 'lrswipkxtecdn') or die;
    $admintalk->setacl("user.other2.#addressbooks.Default",
                       "cassandane" => 'lrswipkxtecdn') or die;
    $admintalk->setacl("user.other3.#addressbooks.Default",
                       "cassandane" => 'lrswipkxtecdn') or die;

    # avatar
    xlog $self, "upload avatar";
    my $data = "some photo";
    my $res = $jmap->Upload($data, "image/jpeg");
    my $blobid = $res->{blobId};

    my $card =  {
        "addressbookId" => "Default",
        "firstName"=> "foo",
        "lastName"=> "bar",
        "avatar" => {
            "blobId" => $blobid,
            "size" => 10,
            "type" => "image/jpeg",
            "name" => JSON::null
         }
    };

    xlog $self, "create card";
    $res = $jmap->CallMethods([['Contact/set',{
        create => {"1" => $card}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $cardId = $res->[0][1]{created}{"1"}{id};

    xlog $self, "copy card $cardId w/o changes";
    $res = $jmap->CallMethods([['Contact/copy', {
        fromAccountId => 'cassandane',
        accountId => 'other',
        create => {
            1 => {
                id => $cardId,
                addressbookId => "Default",
            },
        },
    },
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $copiedCardId = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
        ['Contact/get', {
            accountId => 'other',
            ids => [$copiedCardId],
        }, 'R1'],
        ['Contact/get', {
            accountId => undef,
            ids => [$cardId],
        }, 'R2'],
    ]);
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{firstName});
    my $blob = $jmap->Download({ accept => 'image/jpeg' },
                               'other', $res->[0][1]{list}[0]{avatar}{blobId});
    $self->assert_str_equals('image/jpeg',
                             $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($data, $blob->{content});

    $self->assert_str_equals('foo', $res->[1][1]{list}[0]{firstName});
    $blob = $jmap->Download({ accept => 'image/jpeg' },
                            'cassandane', $res->[1][1]{list}[0]{avatar}{blobId});
    $self->assert_str_equals('image/jpeg',
                             $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($data, $blob->{content});

    xlog $self, "move card $cardId with changes";
    $res = $jmap->CallMethods([['Contact/copy', {
        fromAccountId => 'cassandane',
        accountId => 'other2',
        create => {
            1 => {
                id => $cardId,
                addressbookId => "Default",
                avatar => JSON::null,
                nickname => "xxxxx"
            },
        }
    },
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    $copiedCardId = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
        ['Contact/get', {
            accountId => 'other2',
            ids => [$copiedCardId],
        }, 'R1'],
        ['Contact/get', {
            accountId => undef,
            ids => [$cardId],
        }, 'R2'],
    ]);
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{firstName});
    $self->assert_str_equals('xxxxx', $res->[0][1]{list}[0]{nickname});
    $self->assert_null($res->[0][1]{list}[0]{avatar});
    $self->assert_str_equals('foo', $res->[1][1]{list}[0]{firstName});

    my $other3Jmap = Mail::JMAPTalk->new(
        user => 'other3',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $other3Jmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    # avatar
    xlog $self, "upload avatar for other3";
    $data = "some other photo";
    $res = $other3Jmap->Upload($data, "image/jpeg");
    $blobid = $res->{blobId};

    $admintalk->setacl("user.other3.#jmap",
                       "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "move card $cardId with different avatar";
    $res = $jmap->CallMethods([['Contact/copy', {
        fromAccountId => 'cassandane',
        accountId => 'other3',
        create => {
            1 => {
                id => $cardId,
                addressbookId => "Default",
                avatar => {
                    blobId => "$blobid",
                    size => 16,
                    type => "image/jpeg",
                    name => JSON::null
                }
            },
        },
        onSuccessDestroyOriginal => JSON::true,
    },
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    $copiedCardId = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
        ['Contact/get', {
            accountId => 'other3',
            ids => [$copiedCardId],
        }, 'R1'],
        ['Contact/get', {
            accountId => undef,
            ids => [$cardId],
        }, 'R2'],
    ]);
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{firstName});
    $blob = $jmap->Download({ accept => 'image/jpeg' },
                               'other3', $res->[0][1]{list}[0]{avatar}{blobId});
    $self->assert_str_equals('image/jpeg',
                             $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($data, $blob->{content});

    $self->assert_str_equals($cardId, $res->[1][1]{notFound}[0]);
}

sub test_contactgroup_set_patch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            create => {
                1 => {
                    name => 'name1',
                    otherAccountContactIds => {
                        other1 => ['contact1'],
                        other2 => ['contact2']
                    }
                }
            }
        }, "R1"],
        ['ContactGroup/get', { ids => ['#1'] }, 'R2'],
    ]);
    $self->assert_str_equals('name1', $res->[1][1]{list}[0]{name});
    $self->assert_deep_equals({
        other1 => ['contact1'],
        other2 => ['contact2']
    }, $res->[1][1]{list}[0]{otherAccountContactIds});
    my $groupId1 = $res->[1][1]{list}[0]{id};

    $res = $jmap->CallMethods([
        ['ContactGroup/set', {
            update => {
                $groupId1 => {
                    name => 'updatedname1',
                    'otherAccountContactIds/other2' => undef,
                }
            }
        }, "R1"],
        ['ContactGroup/get', { ids => [$groupId1] }, 'R2'],
    ]);
    $self->assert_str_equals('updatedname1', $res->[1][1]{list}[0]{name});
    $self->assert_deep_equals({
        other1 => ['contact1'],
    }, $res->[1][1]{list}[0]{otherAccountContactIds});
}

sub test_contact_blobid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contact";
    my $res = $jmap->CallMethods([['Contact/set', {create => {
        "1" => { firstName => "foo", lastName => "last1" },
    }}, "R1"]]);
    my $contactId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($contactId);

    xlog $self, "get contact blobId";
    $res = $jmap->CallMethods([
        ['Contact/get', {
            ids => [$contactId],
            properties => ['blobId'],
        }, 'R2']
    ]);

    # fetch a second time to make sure this works with a cached response
    $res = $jmap->CallMethods([
        ['Contact/get', {
            ids => [$contactId],
            properties => ['blobId'],
        }, 'R2']
    ]);
    my $blobId = $res->[0][1]{list}[0]{blobId};
    $self->assert_not_null($blobId);

    xlog $self, "download blob";

    $res = $jmap->Download('cassandane', $blobId);
    $self->assert_str_equals("BEGIN:VCARD", substr($res->{content}, 0, 11));
    $self->assert_num_not_equals(-1, index($res->{content}, 'FN:foo last1'));
}

sub test_contact_set_issue2953
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create contacts";
    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                1 => {
                    online => [{
                        type => 'username',
                        value => 'foo,bar',
                        label => 'Github',
                    }],
                },
            },
        }, 'R1'],
        ['Contact/get', {
            ids => ['#1'], properties => ['online'],
        }, 'R2'],
    ]);
    $self->assert_not_null($res->[0][1]{created}{1});
    $self->assert_str_equals('foo,bar', $res->[1][1]{list}[0]{online}[0]{value});
}

sub _set_quotaroot
{
    my ($self, $quotaroot) = @_;
    $self->{quotaroot} = $quotaroot;
}

sub _set_quotalimits
{
    my ($self, %resources) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my $quotaroot = delete $resources{quotaroot} || $self->{quotaroot};
    my @quotalist;
    foreach my $resource (keys %resources)
    {
        my $limit = $resources{$resource}
            or die "No limit specified for $resource";
        push(@quotalist, uc($resource), $limit);
    }
    $self->{limits}->{$quotaroot} = { @quotalist };
    $admintalk->setquota($quotaroot, \@quotalist);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_contact_copy_overquota
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared accounts";
    $admintalk->create("user.other");

    my $othercarddav = Net::CardDAVTalk->new(
        user => "other",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    $admintalk->setacl('user.other.#addressbooks.Default',
                       'cassandane' => 'lrswipkxtecdn') or die;

    $self->_set_quotaroot('user.other.#addressbooks');
    $self->_set_quotalimits(storage => 1);

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                1 => {
                    lastName => 'name',
                    notes => ('x' x 1024),
                },
            },
        }, 'R1'],
    ]);
    my $contactId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($contactId);

    $res = $jmap->CallMethods([
        ['Contact/copy', {
            fromAccountId => 'cassandane',
            accountId => 'other',
            create => {
                2 => {
                    id => $contactId,
                },
            },
        }, 'R1']
    ]);
    $self->assert_str_equals('overQuota', $res->[0][1]{notCreated}{2}{type});

}

sub test_contact_get_invalid_utf8
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['emails'],
        }, 'R1']
    ]);

    my $datadir = $self->{instance}->folder_to_directory("user.cassandane.#addressbooks.Default");
    copy('data/vcard/invalid-utf8.eml', "$datadir/1.") or die;
    $self->{instance}->run_command({ cyrus => 1 },
        'reconstruct', 'user.cassandane.#addressbooks.Default');

    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['emails'],
        }, 'R1']
    ]);
    $self->assert_deep_equals([{
        type => 'work',
        value => "beno\N{REPLACEMENT CHARACTER}t\@local",
        isDefault => JSON::true,
    }], $res->[0][1]{list}[0]{emails});
}

sub test_contact_apple_label_handling
    :min_version_3_5 :needs_component_jmap
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

    xlog $self, "create a contact with 3 labels: unassociated, shared, & unshared";
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
X-ABLabel:this-should-not-crash-cyrus
foo.ADR:;;123 Main Street;Any Town;LA;91921-1234;U.S.A.
foo.X-ABLabel:_\$!<foo>!\$_
foo.EMAIL;TYPE=work:bubba\@local
bar.X-ABLabel:bar
bar.TEL;VALUE=uri;TYPE="home":tel:+1-555-555-5555
email0.X-ABLabel:aaa
email0.EMAIL;TYPE=work:shrimp\@local
END:VCARD
EOF

    $card =~ s/\r?\n/\r\n/gs;

    $carddav->Request('PUT', $href, $card, 'Content-Type' => 'text/vcard');

    my $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['addresses', 'emails', 'phones'],
        }, 'R1']
    ]);

    $id = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($id);
    $self->assert_equals("foo", $res->[0][1]{list}[0]{addresses}[0]{label});
    $self->assert_equals("foo", $res->[0][1]{list}[0]{emails}[0]{label});
    $self->assert_equals("bar", $res->[0][1]{list}[0]{phones}[0]{label});

    xlog $self, "update contact";
    $res = $jmap->CallMethods([['Contact/set', {
        update => {
            $id => {
                emails => [{
                    type => "work",
                    label => undef,
                    value => "bubba\@local"
                },
                {       
                    type => "work",
                    label => "aaa",
                    value => "shrimp\@local"
                },
                {       
                    type => "personal",
                    label => "bbb",
                    value => "gump\@local"
                }],
                phones => [{
                    type => "home",
                    label => undef,
                    value => "tel:+1-555-555-5555"
                }]
            }
        }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['addresses', 'emails', 'phones', 'blobId'],
        }, 'R1']
    ]);

    $self->assert_equals("foo", $res->[0][1]{list}[0]{addresses}[0]{label});
    $self->assert_null($res->[0][1]{list}[0]{emails}[0]{label});
    $self->assert_null($res->[0][1]{list}[0]{phones}[0]{label});

    xlog $self, "download and check content";
    my $blob = $jmap->Download({ accept => 'text/vcard' },
                               'cassandane', $res->[0][1]{list}[0]{blobId});

    $self->assert_matches(qr/X-ABLabel:this-should-not-crash-cyrus/,
                          $blob->{content});

    $self->assert_matches(qr/foo\.X-ABLabel/, $blob->{content});
    $self->assert_matches(qr/foo\.ADR/, $blob->{content});

    $self->assert_null(grep { m/foo\.EMAIL/ } $blob->{content});
    $self->assert_null(grep { m/email0\./ } $blob->{content});
    $self->assert_matches(qr/email1\.X-ABLabel/, $blob->{content});
    $self->assert_matches(qr/email1\.EMAIL/, $blob->{content});
    $self->assert_matches(qr/email2\.X-ABLabel/, $blob->{content});
    $self->assert_matches(qr/email2\.EMAIL/, $blob->{content});

    $self->assert_null(grep { m/bar\.X-ABLabel/ } $blob->{content});
    $self->assert_null(grep { m/bar\.TEL/ } $blob->{content});
}

sub test_contact_set_importance_peruser
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $manjmap = Mail::JMAPTalk->new(
        user => 'manifold',
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $manjmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
		'https://cyrusimap.org/ns/jmap/contacts',
    ]);
    $admin->setacl("user.cassandane.#addressbooks.Default",
        "manifold" => 'lrswipkxtecdn') or die;

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                c1 => {
                    lastName => 'test',
                    importance => 1.0,
                },
            },
        }, 'R1'],
        ['Contact/get', {
            ids => ['#c1'],
            properties => ['importance'],
        }, 'R2'],
    ]);
    my $contactId = $res->[0][1]{created}{c1}{id};
    $self->assert_not_null($contactId);
    $self->assert_equals(1.0, $res->[1][1]{list}[0]{importance});

    $res = $manjmap->CallMethods([
        ['Contact/get', {
            accountId => 'cassandane',
            ids => [$contactId],
            properties => ['importance'],
        }, 'R1'],
        ['Contact/set', {
            accountId => 'cassandane',
            update => {
                $contactId => {
                    importance => 2.0,
                },
            },
        }, 'R2'],
        ['Contact/get', {
            accountId => 'cassandane',
            ids => [$contactId],
            properties => ['importance'],
        }, 'R3'],
    ]);

    $self->assert_equals(1.0, $res->[0][1]{list}[0]{importance});
    $self->assert(exists $res->[1][1]{updated}{$contactId});
    $self->assert_equals(2.0, $res->[2][1]{list}[0]{importance});

    $res = $jmap->CallMethods([
        ['Contact/get', {
            ids => ['#c1'],
            properties => ['importance'],
        }, 'R1'],
    ]);
    $self->assert_equals(1.0, $res->[0][1]{list}[0]{importance});
}

sub test_contact_set_importance_float
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                c1 => {
                    lastName => 'test',
                    importance => -122.129545321514,
                },
            },
        }, 'R1'],
        ['Contact/get', {
            ids => ['#c1'],
            properties => ['importance'],
        }, 'R2'],
    ]);
    my $contactId = $res->[0][1]{created}{c1}{id};
    $self->assert_not_null($contactId);
    $self->assert_equals(-122.129545321514, $res->[1][1]{list}[0]{importance});
}

sub test_contact_set_toolarge
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                1 => {
                    lastName => 'name',
                    notes => ('x' x 100000),
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('tooLarge', $res->[0][1]{notCreated}{1}{type});

}

sub test_contact_get_apple_countrycode
    :min_version_3_5 :needs_component_jmap
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
item1.ADR;type=WORK:;;2 Example Avenue;Anytown;NY;01111;USA
item1.X-ABADR:US
item1.X-ABLabel:xyz
item2.ADR;type=WORK:;;Beispielstrasse 2;IrgendwoStadt;IrgendwoLand;00000;Germany
item2.X-ABADR:de
END:VCARD
EOF

    $card =~ s/\r?\n/\r\n/gs;
    $carddav->Request('PUT', $href, $card, 'Content-Type' => 'text/vcard');

    my $res = $jmap->CallMethods([
        ['Contact/get', {
            properties => ['addresses']
        }, 'R1']
    ]);
    $self->assert_str_equals('us', $res->[0][1]{list}[0]{addresses}[0]{countryCode});
    $self->assert_str_equals('xyz', $res->[0][1]{list}[0]{addresses}[0]{label});
    $self->assert_str_equals('de', $res->[0][1]{list}[0]{addresses}[1]{countryCode});
}

sub test_contact_set_apple_countrycode
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    lastName => "Smith",
                    addresses => [{
                        type => "work",
                        label => "xyz",
                        street => "2 Example Avenue",
                        locality => "Anytown",
                        region => "NY",
                        postcode => "01111",
                        country => "USA",
                        countryCode => "us"
                    }, {
                        type => "work",
                        street => "Beispielstrasse 2",
                        locality => 'IrgendwoStadt',
                        region => 'IrgendwoLand',
                        postcode => '00000',
                        country => "Germany",
                        countryCode => 'DE',
                    }],
                },
            },
        }, 'R1'],
        ['Contact/get', {
            ids => ['#contact1'],
            properties => ['addresses'],
        }, 'R2'],
    ]);
    $self->assert_str_equals('us', $res->[1][1]{list}[0]{addresses}[0]{countryCode});
    $self->assert_str_equals('xyz', $res->[1][1]{list}[0]{addresses}[0]{label});
    $self->assert_str_equals('de', $res->[1][1]{list}[0]{addresses}[1]{countryCode});
}

sub test_contact_set_reject_duplicate_uid
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $carddav = $self->{carddav};

    $carddav->NewAddressBook('addrbookB') or die;

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contactA => {
                    uid => '123456789',
                    lastName => 'contactA',
                },
            }
        }, 'R1'],
    ]);
    my $contactA = $res->[0][1]{created}{contactA}{id};
    $self->assert_not_null($contactA);

    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contactB => {
                    addressbookId => 'addrbookB',
                    uid => '123456789',
                    lastName => 'contactB',
                },
            }
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{contactB}{type});
    $self->assert_deep_equals(['uid'],
        $res->[0][1]{notCreated}{contactB}{properties});
}


1;
