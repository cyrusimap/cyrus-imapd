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

sub test_setcontacts_multicontact
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

sub test_getcontactupdates
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get contacts";
    my $res = $jmap->Request([['getContacts', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "get contact updates";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);

    xlog "create contact #1";
    $res = $jmap->Request([['setContacts', {create => {"#1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"#1"}{id};

    xlog "get contact updates";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "create contact #2";
    $res = $jmap->Request([['setContacts', {create => {"#2" => {firstName => "second", lastName => "prev"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id2 = $res->[0][1]{created}{"#2"}{id};

    xlog "get contact updates (since last change)";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id2);
    $state = $res->[0][1]{newState};

    xlog "get contact updates (in bulk)";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $oldState);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);

    xlog "get contact updates from initial state (maxChanges=1)";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $oldState);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::true);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    my $interimState = $res->[0][1]{newState};

    xlog "get contact updates from interim state (maxChanges=10)";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $interimState);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id2);
    $state = $res->[0][1]{newState};

    xlog "destroy contact #1, update contact #2";
    $res = $jmap->Request([['setContacts', {
                    destroy => [$id1],
                    update => {$id2 => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');

    xlog "get contact updates";
    $res = $jmap->Request([['getContactUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id2);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 1);
    $self->assert_str_equals($res->[0][1]{removed}[0], $id1);

    xlog "destroy contact #2";
    $res = $jmap->Request([['setContacts', {destroy => [$id2]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
}

sub test_setcontactgroups
{

    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
                        "#1" => { firstName => "foo", lastName => "last1" },
                        "#2" => { firstName => "bar", lastName => "last2" }
                    }}, "R1"]]);
    my $contact1 = $res->[0][1]{created}{"#1"}{id};
    my $contact2 = $res->[0][1]{created}{"#1"}{id};

    xlog "create contact group with no contact ids";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "#1" => {name => "group1"}
                    }}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R2');
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get contact group $id";
    $res = $jmap->Request([['getContactGroups', { ids => [$id] }, "R3"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroups');
    $self->assert_str_equals($res->[0][2], 'R3');
    $self->assert_str_equals($res->[0][1]{list}[0]{name}, 'group1');
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(scalar @{$res->[0][1]{list}[0]{contactIds}}, 0);

    xlog "update contact group with invalid contact ids";
    $res = $jmap->Request([['setContactGroups', {update => {
                        $id => {name => "group1", contactIds => [$contact1, $contact2, 255]}
                    }}, "R4"]]);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert(exists $res->[0][1]{notUpdated}{$id});
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, 'invalidProperties');
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], 'contactIds[2]');
    $self->assert_str_equals($res->[0][2], 'R4');

    xlog "get contact group $id";
    $res = $jmap->Request([['getContactGroups', { ids => [$id] }, "R3"]]);
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(scalar @{$res->[0][1]{list}[0]{contactIds}}, 0);


    xlog "update contact group with valid contact ids";
    $res = $jmap->Request([['setContactGroups', {update => {
                        $id => {name => "group1", contactIds => [$contact1, $contact2]}
                    }}, "R4"]]);

    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact group $id";
    $res = $jmap->Request([['getContactGroups', { ids => [$id] }, "R3"]]);
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(scalar @{$res->[0][1]{list}[0]{contactIds}}, 2);
    $self->assert_str_equals($res->[0][1]{list}[0]{contactIds}[0], $contact1);
    $self->assert_str_equals($res->[0][1]{list}[0]{contactIds}[1], $contact2);
}

sub test_getcontactlist {
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
                        "#1" =>
                        {
                            firstName => "foo", lastName => "last1",
                            emails => [{
                                    type => "personal",
                                    value => "foo\@example.com"
                                }]
                        },
                        "#2" =>
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
                        "#3" =>
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
                        "#4" => {firstName => "bam", lastName => "last4",
                                 isFlagged => JSON::false }
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};
    my $id3 = $res->[0][1]{created}{"#3"}{id};
    my $id4 = $res->[0][1]{created}{"#4"}{id};

    xlog "create contact groups";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "#1" => {name => "group1", contactIds => [$id1, $id2]},
                        "#2" => {name => "group2", contactIds => [$id3]},
                        "#3" => {name => "group3", contactIds => [$id4]}
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $group1 = $res->[0][1]{created}{"#1"}{id};
    my $group2 = $res->[0][1]{created}{"#2"}{id};
    my $group3 = $res->[0][1]{created}{"#3"}{id};

    xlog "get unfiltered contact list";
    $res = $jmap->Request([ ['getContactList', { }, "R1"] ]);

    $self->assert_num_equals($res->[0][1]{total}, 4);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 4);

    xlog "filter by firstName";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 1);
    $self->assert_str_equals($res->[0][1]{contactIds}[0], $id1);

    xlog "filter by lastName";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 4);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 4);

    xlog "filter by firstName and lastName (one filter)";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { firstName => "bam", lastName => "last" }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 1);
    $self->assert_str_equals($res->[0][1]{contactIds}[0], $id4);

    xlog "filter by firstName and lastName (AND filter)";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { operator => "AND", conditions => [{
                                lastName => "last"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 1);
    $self->assert_str_equals($res->[0][1]{contactIds}[0], $id3);

    xlog "filter by firstName (OR filter)";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { operator => "OR", conditions => [{
                                firstName => "bar"
                            }, {
                                firstName => "baz"
                    }]}
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 2);

    xlog "filter by text";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { text => "some" }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 2);

    xlog "filter by email";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { email => "example.com" }
                }, "R1"] ]);
    $self->assert_num_equals($res->[0][1]{total}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 2);

    xlog "filter by isFlagged (true)";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { isFlagged => JSON::true }
                }, "R1"] ]);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 1);
    $self->assert_str_equals($res->[0][1]{contactIds}[0], $id2);

    xlog "filter by isFlagged (false)";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { isFlagged => JSON::false }
                }, "R1"] ]);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 3);

    xlog "filter by inContactGroup";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { inContactGroup => [$group1, $group3] }
                }, "R1"] ]);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 3);

    xlog "filter by inContactGroup and firstName";
    $res = $jmap->Request([ ['getContactList', {
                    filter => { inContactGroup => [$group1, $group3], firstName => "foo" }
                }, "R1"] ]);
    $self->assert_num_equals(scalar @{$res->[0][1]{contactIds}}, 1);
    $self->assert_str_equals($res->[0][1]{contactIds}[0], $id1);
}

sub test_getcontactgroupupdates
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
                        "#a" => {firstName => "a", lastName => "a"},
                        "#b" => {firstName => "b", lastName => "b"},
                        "#c" => {firstName => "c", lastName => "c"},
                        "#d" => {firstName => "d", lastName => "d"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $contactA = $res->[0][1]{created}{"#a"}{id};
    my $contactB = $res->[0][1]{created}{"#b"}{id};
    my $contactC = $res->[0][1]{created}{"#c"}{id};
    my $contactD = $res->[0][1]{created}{"#d"}{id};

    xlog "get contact groups state";
    $res = $jmap->Request([['getContactGroups', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "create contact group #1";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "#1" => {name => "first", contactIds => [$contactA, $contactB]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"#1"}{id};


    xlog "get contact group updates";
    $res = $jmap->Request([['getContactGroupUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);

    my $oldState = $state;
    $state = $res->[0][1]{newState};

    xlog "create contact group #2";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "#2" => {name => "second", contactIds => [$contactC, $contactD]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id2 = $res->[0][1]{created}{"#2"}{id};

    xlog "get contact group updates (since last change)";
    $res = $jmap->Request([['getContactGroupUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id2);
    $state = $res->[0][1]{newState};

    xlog "get contact group updates (in bulk)";
    $res = $jmap->Request([['getContactGroupUpdates', {
                    sinceState => $oldState
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $oldState);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 2);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);

    xlog "get contact group updates from initial state (maxChanges=1)";
    $res = $jmap->Request([['getContactGroupUpdates', {
                    sinceState => $oldState,
                    maxChanges => 1
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $oldState);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::true);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id1);
    my $interimState = $res->[0][1]{newState};

    xlog "get contact group updates from interim state (maxChanges=10)";
    $res = $jmap->Request([['getContactGroupUpdates', {
                    sinceState => $interimState,
                    maxChanges => 10
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $interimState);
    $self->assert_str_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 0);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id2);
    $state = $res->[0][1]{newState};

    xlog "destroy contact group #1, update contact group #2";
    $res = $jmap->Request([['setContactGroups', {
                    destroy => [$id1],
                    update => {$id2 => {name => "second (updated)"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');

    xlog "get contact group updates";
    $res = $jmap->Request([['getContactGroupUpdates', {
                    sinceState => $state
                }, "R2"]]);
    $self->assert_str_equals($res->[0][1]{oldState}, $state);
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_equals($res->[0][1]{hasMoreUpdates}, JSON::false);
    $self->assert_num_equals(scalar @{$res->[0][1]{changed}}, 1);
    $self->assert_str_equals($res->[0][1]{changed}[0], $id2);
    $self->assert_num_equals(scalar @{$res->[0][1]{removed}}, 1);
    $self->assert_str_equals($res->[0][1]{removed}[0], $id1);

    xlog "destroy contact group #2";
    $res = $jmap->Request([['setContactGroups', {destroy => [$id2]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
}

sub test_setcontacts
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $contact = {
        firstName => "first",
        lastName => "last"
    };

    my $res = $jmap->Request([['setContacts', {create => {"#1" => $contact }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"#1"}{id};

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

    # Non-JMAP properties.
    $contact->{"x-importance"} = 0;
    $contact->{"x-hasPhoto"} = JSON::false;
    $contact->{"addressbookId"} = 'Default';

    xlog "get contact $id";
    my $fetch = $jmap->Request([['getContacts', {}, "R2"]]);

    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $contact->{"x-href"} = $fetch->[0][1]{list}[0]{"x-href"};
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # isFlagged
    xlog "update isFlagged (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {isFlagged => 'nope'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "isFlagged");

    xlog "update isFlagged";
    $contact->{isFlagged} = JSON::true;
    $res = $jmap->Request([['setContacts', {update => {$id => {isFlagged => JSON::true} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # prefix
    xlog "update prefix (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {prefix => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "prefix");

    xlog "update prefix";
    $contact->{prefix} = 'foo';
    $res = $jmap->Request([['setContacts', {update => {$id => {prefix => 'foo'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # suffix
    xlog "update suffix (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {suffix => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "suffix");

    xlog "update suffix";
    $contact->{suffix} = 'bar';
    $res = $jmap->Request([['setContacts', {update => {$id => {suffix => 'bar'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # nickname
    xlog "update nickname (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {nickname => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "nickname");

    xlog "update nickname";
    $contact->{nickname} = 'nick';
    $res = $jmap->Request([['setContacts', {update => {$id => {nickname => 'nick'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # birthday
    xlog "update birthday (with null error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {birthday => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "birthday");

    xlog "update birthday (with JMAP datetime error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {birthday => '1979-04-01T00:00:00Z'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "birthday");

    xlog "update birthday";
    $contact->{birthday} = '1979-04-01'; # Happy birthday, El Barto!
    $res = $jmap->Request([['setContacts', {update => {$id => {birthday => '1979-04-01'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # anniversary
    xlog "update anniversary (with null error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {anniversary => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "anniversary");

    xlog "update anniversary (with JMAP datetime error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {anniversary => '1989-12-17T00:00:00Z'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "anniversary");

    xlog "update anniversary";
    $contact->{anniversary} = '1989-12-17'; # Happy anniversary, Simpsons!
    $res = $jmap->Request([['setContacts', {update => {$id => {anniversary => '1989-12-17'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # company
    xlog "update company (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {company => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "company");

    xlog "update company";
    $contact->{company} = 'acme';
    $res = $jmap->Request([['setContacts', {update => {$id => {company => 'acme'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # department
    xlog "update department (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {department => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "department");

    xlog "update department";
    $contact->{department} = 'looney tunes';
    $res = $jmap->Request([['setContacts', {update => {$id => {department => 'looney tunes'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # jobTitle
    xlog "update jobTitle (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {jobTitle => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "jobTitle");

    xlog "update jobTitle";
    $contact->{jobTitle} = 'director of everything';
    $res = $jmap->Request([['setContacts', {update => {$id => {jobTitle => 'director of everything'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # emails
    xlog "update emails (with missing type error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            emails => [{ value => "acme\@example.com" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "emails[0].type");

    xlog "update emails (with missing value error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            emails => [{ type => "other" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "emails[0].value");

    xlog "update emails";
    $contact->{emails} = [{ type => "work", value => "acme\@example.com", isDefault => JSON::true }];
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            emails => [{ type => "work", value => "acme\@example.com" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # phones
    xlog "update phones (with missing type error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            phones => [{ value => "12345678" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "phones[0].type");

    xlog "update phones (with missing value error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            phones => [{ type => "home" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "phones[0].value");

    xlog "update phones";
    $contact->{phones} = [{ type => "home", value => "12345678" }];
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            phones => [{ type => "home", value => "12345678" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # online
    xlog "update online (with missing type error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            online => [{ value => "http://example.com/me" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "online[0].type");

    xlog "update online (with missing value error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            online => [{ type => "uri" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "online[0].value");

    xlog "update online";
    $contact->{online} = [{ type => "uri", value => "http://example.com/me" }];
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            online => [{ type => "uri", value => "http://example.com/me" }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
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
    $res = $jmap->Request([['setContacts', {update => {$id => {
                            addresses => [{
                                    type => "home",
                                    street => "acme lane 1",
                                    locality => "acme city",
                                    region => "",
                                    postcode => "1234",
                                    country => "acme land"
                                }]
                        } }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);

    # notes
    xlog "update notes (with error)";
    $res = $jmap->Request([['setContacts', {update => {$id => {notes => undef} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{type}, "invalidProperties");
    $self->assert_str_equals($res->[0][1]{notUpdated}{$id}{properties}[0], "notes");

    xlog "update notes";
    $contact->{notes} = 'baz';
    $res = $jmap->Request([['setContacts', {update => {$id => {notes => 'baz'} }}, "R1"]]);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);
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

sub test_getmailboxes
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    $imaptalk->create("INBOX.foo.bar")
        or die "Cannot create mailbox INBOX.foo.bar: $@";

    xlog "get existing mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(scalar keys %m, 3);
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    my $bar = $m{"bar"};

    # INBOX
    $self->assert_str_equals($inbox->{name}, "Inbox");
    $self->assert_null($inbox->{parentId});
    $self->assert_str_equals($inbox->{role}, "inbox");
    $self->assert_num_equals($inbox->{sortOrder}, 0);
    $self->assert_equals($inbox->{mustBeOnlyMailbox}, JSON::true);
    $self->assert_equals($inbox->{mayReadItems}, JSON::true);
    $self->assert_equals($inbox->{mayAddItems}, JSON::true);
    $self->assert_equals($inbox->{mayRemoveItems}, JSON::true);
    $self->assert_equals($inbox->{mayCreateChild}, JSON::true);
    $self->assert_equals($inbox->{mayRename}, JSON::false);
    $self->assert_equals($inbox->{mayDelete}, JSON::false);
    $self->assert_num_equals($inbox->{totalMessages}, 0);
    $self->assert_num_equals($inbox->{unreadMessages}, 0);
    $self->assert_num_equals($inbox->{totalThreads}, 0);
    $self->assert_num_equals($inbox->{unreadThreads}, 0);

    # INBOX.foo
    $self->assert_str_equals($foo->{name}, "foo");
    $self->assert_null($foo->{parentId});
    $self->assert_null($foo->{role});
    $self->assert_num_equals($foo->{sortOrder}, 0);
    $self->assert_equals($foo->{mustBeOnlyMailbox}, JSON::true);
    $self->assert_equals($foo->{mayReadItems}, JSON::true);
    $self->assert_equals($foo->{mayAddItems}, JSON::true);
    $self->assert_equals($foo->{mayRemoveItems}, JSON::true);
    $self->assert_equals($foo->{mayCreateChild}, JSON::true);
    $self->assert_equals($foo->{mayRename}, JSON::true);
    $self->assert_equals($foo->{mayDelete}, JSON::true);
    $self->assert_num_equals($foo->{totalMessages}, 0);
    $self->assert_num_equals($foo->{unreadMessages}, 0);
    $self->assert_num_equals($foo->{totalThreads}, 0);
    $self->assert_num_equals($foo->{unreadThreads}, 0);

    # INBOX.foo.bar
    $self->assert_str_equals($bar->{name}, "bar");
    $self->assert_str_equals($bar->{parentId}, $foo->{id});
    $self->assert_null($bar->{role});
    $self->assert_num_equals($bar->{sortOrder}, 0);
    $self->assert_equals($bar->{mustBeOnlyMailbox}, JSON::true);
    $self->assert_equals($bar->{mayReadItems}, JSON::true);
    $self->assert_equals($bar->{mayAddItems}, JSON::true);
    $self->assert_equals($bar->{mayRemoveItems}, JSON::true);
    $self->assert_equals($bar->{mayCreateChild}, JSON::true);
    $self->assert_equals($bar->{mayRename}, JSON::true);
    $self->assert_equals($bar->{mayDelete}, JSON::true);
    $self->assert_num_equals($bar->{totalMessages}, 0);
    $self->assert_num_equals($bar->{unreadMessages}, 0);
    $self->assert_num_equals($bar->{totalThreads}, 0);
    $self->assert_num_equals($bar->{unreadThreads}, 0);
}

sub test_getmailboxes_specialuse
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Archive", "(USE (\\Archive))") || die;
    $imaptalk->create("INBOX.Drafts", "(USE (\\Drafts))") || die;
    $imaptalk->create("INBOX.Junk", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;
    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;

    xlog "get mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $archive = $m{"Archive"};
    my $drafts = $m{"Drafts"};
    my $junk = $m{"Junk"};
    my $sent = $m{"Sent"};
    my $trash = $m{"Trash"};

    $self->assert_str_equals($archive->{name}, "Archive");
    $self->assert_str_equals($archive->{role}, "archive");

    $self->assert_str_equals($drafts->{name}, "Drafts");
    $self->assert_null($drafts->{parentId});
    $self->assert_str_equals($drafts->{role}, "drafts");

    $self->assert_str_equals($junk->{name}, "Junk");
    $self->assert_null($junk->{parentId});
    $self->assert_str_equals($junk->{role}, "junk");

    $self->assert_str_equals($sent->{name}, "Sent");
    $self->assert_null($sent->{parentId});
    $self->assert_str_equals($sent->{role}, "sent");

    $self->assert_str_equals($trash->{name}, "Trash");
    $self->assert_null($trash->{parentId});
    $self->assert_str_equals($trash->{role}, "trash");
}

sub test_getmailboxes_properties
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get mailboxes with name property";
    my $res = $jmap->Request([['getMailboxes', { properties => ["name"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");
    $self->assert_num_equals(scalar keys %{$inbox}, 2); # id and name

    xlog "get mailboxes with erroneous property";
    $res = $jmap->Request([['getMailboxes', { properties => ["name", 123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $err = $res->[0][1];
    $self->assert_str_equals($err->{type}, "invalidArguments");
    $self->assert_str_equals($err->{arguments}[0], "properties");
}

sub test_getmailboxes_ids
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.foo") || die;

    xlog "get all mailboxes";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $inbox = $m{"Inbox"};
    my $foo = $m{"foo"};
    $self->assert_not_null($inbox);
    $self->assert_not_null($foo);

    xlog "get foo and unknown mailbox";
    $res = $jmap->Request([['getMailboxes', { ids => [$foo->{id}, "nope"] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $foo->{id});
    $self->assert_str_equals($res->[0][1]{notFound}[0], "nope");

    xlog "get mailbox with erroneous id";
    $res = $jmap->Request([['getMailboxes', { ids => [123]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'error');
    $self->assert_str_equals($res->[0][2], 'R1');

    my $err = $res->[0][1];
    $self->assert_str_equals($err->{type}, "invalidArguments");
    $self->assert_str_equals($err->{arguments}[0], "ids");
}

sub test_getmailboxes_nocalendars
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "get existing mailboxes";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'mailboxes');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $mboxes = $res->[0][1]{list};

    xlog "create calendar";
    $res = $jmap->Request([
            ['setCalendars', { create => { "#1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    xlog "get updated mailboxes";
    $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(scalar @{$res->[0][1]{list}}, scalar @{$mboxes});
}

sub test_setmailboxes
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get inbox";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);

    my $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "foo");
    $self->assert_null($mbox->{parentId});
    $self->assert_null($mbox->{role});
    $self->assert_num_equals($mbox->{sortOrder}, 0);
    $self->assert_equals($mbox->{mustBeOnlyMailbox}, JSON::true);
    $self->assert_equals($mbox->{mayReadItems}, JSON::true);
    $self->assert_equals($mbox->{mayAddItems}, JSON::true);
    $self->assert_equals($mbox->{mayRemoveItems}, JSON::true);
    $self->assert_equals($mbox->{mayCreateChild}, JSON::true);
    $self->assert_equals($mbox->{mayRename}, JSON::true);
    $self->assert_equals($mbox->{mayDelete}, JSON::true);
    $self->assert_num_equals($mbox->{totalMessages}, 0);
    $self->assert_num_equals($mbox->{unreadMessages}, 0);
    $self->assert_num_equals($mbox->{totalThreads}, 0);
    $self->assert_num_equals($mbox->{unreadThreads}, 0);

    xlog "update mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $id => {
                            name => "bar",
                            sortOrder => 10
             }}}, "R1"]
    ]);

    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{updated}[0], $id);

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{id}, $id);
    $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($mbox->{name}, "bar");
    $self->assert_num_equals($mbox->{sortOrder}, 10);

    xlog "destroy mailbox";
    $res = $jmap->Request([
            ['setMailboxes', { destroy => [ $id ] }, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_str_not_equals($res->[0][1]{newState}, $state);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id);

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{notFound}[0], $id);
}

sub test_setmailboxes_name_collision
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "get inbox";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "create three mailboxes named foo";
    $res = $jmap->Request([
            ['setMailboxes', { create =>
                    { "#1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
                        },
                        "#2" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
                        },
                        "#3" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => undef
                        }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});

    my $id1 = $res->[0][1]{created}{"#1"}{id};
    my $id2 = $res->[0][1]{created}{"#2"}{id};
    my $id3 = $res->[0][1]{created}{"#3"}{id};

    xlog "get mailbox $id1";
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "foo");

    xlog "get mailbox $id2";
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "foo");

    xlog "get mailbox $id3";
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "foo");

    xlog "rename all three mailboxes to bar";
    $res = $jmap->Request([
            ['setMailboxes', { update =>
                    { $id1 => { name => "bar" },
                      $id2 => { name => "bar" },
                      $id3 => { name => "bar" }
                  }}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox $id1";
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "get mailbox $id2";
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "get mailbox $id3";
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");
}

sub test_setmailboxes_name_interop
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "create mailbox via IMAP";
    $imaptalk->create("INBOX.foo")
        or die "Cannot create mailbox INBOX.foo: $@";

    xlog "get foo mailbox";
    my $res = $jmap->Request([['getMailboxes', {}, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $foo = $m{"foo"};
    my $id = $foo->{id};
    $self->assert_str_equals($foo->{name}, "foo");

    xlog "rename mailbox foo to oof via JMAP";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $id => { name => "oof" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox via IMAP";
    my $data = $imaptalk->list("INBOX.oof", "%");
    $self->assert_num_equals(scalar @{$data}, 1);

    xlog "rename mailbox oof to bar via IMAP";
    $imaptalk->rename("INBOX.oof", "INBOX.bar")
        or die "Cannot rename mailbox: $@";

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "bar");

    xlog "rename mailbox bar to baz via JMAP";
    $res = $jmap->Request([
            ['setMailboxes', { update => { $id => { name => "baz" }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog "get mailbox via IMAP";
    $data = $imaptalk->list("INBOX.baz", "%");
    $self->assert_num_equals(scalar @{$data}, 1);

    xlog "rename mailbox baz to IFeel\N{WHITE SMILING FACE} via IMAP";
    $imaptalk->rename("INBOX.baz", "INBOX.IFeel\N{WHITE SMILING FACE}")
        or die "Cannot rename mailbox: $@";

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{name}, "IFeel\N{WHITE SMILING FACE}");
}

sub test_setmailboxes_role
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    xlog "get inbox";
    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($inbox->{name}, "Inbox");

    my $state = $res->[0][1]{state};

    xlog "try to create mailbox with inbox role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "foo",
                            parentId => $inbox->{id},
                            role => "inbox"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $errType = $res->[0][1]{notCreated}{"#1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with trash role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "foo",
                            parentId => undef,
                            role => "trash"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});

    my $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);

    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "trash");

    xlog "get mailbox $id via IMAP";
    my $data = $imaptalk->xlist("INBOX.foo", "%");
    my %annots = map { $_ => 1 } @{$data->[0]->[0]};
    $self->assert(exists $annots{"\\Trash"});

    xlog "try to create another mailbox with trash role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "trash"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create mailbox with x-bam role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "baz",
                            parentId => undef,
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    $id = $res->[0][1]{created}{"#1"}{id};

    xlog "get mailbox $id";
    $res = $jmap->Request([['getMailboxes', { ids => [$id] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{role}, "x-bam");

    xlog "update of a mailbox role is always an error";
    $res = $jmap->Request([
            ['setMailboxes', { update => { "$id" => {
                            role => "x-baz"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{$id}{type};
    $errProp = $res->[0][1]{notUpdated}{$id}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "try to create another mailbox with the x-bam role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "bar",
                            parentId => $inbox->{id},
                            role => "x-bam"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "try to create a mailbox with an unknown, non-x role";
    $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "bam",
                            parentId => $inbox->{id},
                            role => "unknown"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"#1"}{type};
    $errProp = $res->[0][1]{notCreated}{"#1"}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "role" ]);

    xlog "create a specialuse Sent mailbox via IMAP";
    $imaptalk->create("INBOX.Sent", "(USE (\\Sent))") || die;

    xlog "create a specialuse Archive and Junk mailbox via IMAP";
    $imaptalk->create("INBOX.Multi", "(USE (\\Archive \\Junk))") || die;

    xlog "get mailboxes";
    $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $sent = $m{"Sent"};
    my $multi = $m{"Multi"};
    $self->assert_str_equals($sent->{role}, "sent");
    $self->assert_str_equals($multi->{role}, "archive");
}

sub test_setmailboxes_parent
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Unfortunately, we can't create reshuffle mailbox and their parents in one
    # big request, since Perl might reorder our map keys. This makes the JMAP
    # requests non-deterministic. */
    #
    # Create mailbxoes, foo, foo.bar, foo.bar.baz one by one..
    xlog "create mailbox foo";
    my $res = $jmap->Request([['setMailboxes', { create => {
                        "1" => { name => "foo", parentId => undef, role => undef }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    xlog "create mailbox foo.bar";
    $res = $jmap->Request([
            ['setMailboxes', { create => {
                        "2" => { name => "bar", parentId => $id1, role => undef }
                    }}, "R1"]
        ]);
    my $id2 = $res->[0][1]{created}{"2"}{id};
    xlog "create mailbox foo.bar.baz";
    $res = $jmap->Request([
            ['setMailboxes', { create => {
                        "3" => { name => "baz", parentId => $id2, role => undef }
                    }}, "R1"]
        ]);
    my $id3 = $res->[0][1]{created}{"3"}{id};

    # All set up?
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id1);
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "move foo.bar to bar";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id2 => { name => "bar", parentId => undef, role => undef }
                    }}, "R1"]
        ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog "move bar.baz to foo.baz";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id3 => { name => "baz", parentId => $id1, role => undef }
                    }}, "R1"]
        ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id3] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id1);

    xlog "move foo to bar.foo";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id1 => { name => "foo", parentId => $id2, role => undef }
                    }}, "R1"]
        ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "move foo to non-existent parent";
    $res = $jmap->Request([
            ['setMailboxes', { update => {
                        $id1 => { name => "foo", parentId => "nope", role => undef }
                    }}, "R1"]
        ]);
    my $errType = $res->[0][1]{notUpdated}{$id1}{type};
    my $errProp = $res->[0][1]{notUpdated}{$id1}{properties};
    $self->assert_str_equals($errType, "invalidProperties");
    $self->assert_deep_equals($errProp, [ "parentId" ]);
    $res = $jmap->Request([['getMailboxes', { ids => [$id1] }, "R1"]]);
    $self->assert_str_equals($res->[0][1]{list}[0]->{parentId}, $id2);

    xlog "attempt to destroy bar (which has child foo)";
    $res = $jmap->Request([
            ['setMailboxes', { destroy => [$id2] }, "R1"]
        ]);
    $errType = $res->[0][1]{notDestroyed}{$id2}{type};
    $self->assert_str_equals($errType, "mailboxHasChild");
    $res = $jmap->Request([['getMailboxes', { ids => [$id2] }, "R1"]]);
    $self->assert_null($res->[0][1]{list}[0]->{parentId});

    xlog "destroy all";
    $res = $jmap->Request([
            ['setMailboxes', { destroy => [$id3, $id1, $id2] }, "R1"]
        ]);
    $self->assert_str_equals($res->[0][1]{destroyed}[0], $id3);
    $self->assert_str_equals($res->[0][1]{destroyed}[1], $id1);
    $self->assert_str_equals($res->[0][1]{destroyed}[2], $id2);
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

sub test_setcontacts_importance_later
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

sub test_setcontacts_importance_upfront
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

sub test_setcontacts_importance_multiedit
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

sub test_setcontacts_importance_zero_multi
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

sub test_setcontacts_importance_zero_byself
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

sub test_getmessages
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->Request([['getMailboxes', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "";
    $body .= "Lorem ipsum dolor sit amet, consectetur adipiscing\r\n";
    $body .= "elit. Nunc in fermentum nibh. Vivamus enim metus.";

    my $now = DateTime->now();

    xlog "Generate a message in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        date => $now,
        from => Cassandane::Address->new(
            name => "Sally Sender",
            localpart => "sally",
            domain => "local"
        ),
        to => Cassandane::Address->new(
            name => "Tom To",
            localpart => 'tom',
            domain => 'local'
        ),
        cc => Cassandane::Address->new(
            name => "Cindy CeeCee",
            localpart => 'cindy',
            domain => 'local'
        ),
        bcc => Cassandane::Address->new(
            name => "Benny CarbonCopy",
            localpart => 'benny',
            domain => 'local'
        ),
        messageid => 'fake.123456789@local',
        extra_headers => [
            ['X-Tra', "foo bar\r\n baz"]
        ],
        body => $body
    );
    $self->make_message("Message A", %params) || die;

    xlog "get message list";
    $res = $jmap->Request([['getMessageList', {}, "R1"]]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{messageIds}}, 1);

    xlog "get messages";
    # Could also have set fetchMessages in getMessageList, but let's call
    # getMessages explicitely.
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_str_equals($msg->{mailboxIds}[0], $inboxid);
    $self->assert_num_equals(scalar @{$msg->{mailboxIds}}, 1);
    $self->assert_equals($msg->{isUnread}, JSON::true);
    $self->assert_equals($msg->{isFlagged}, JSON::false);
    $self->assert_equals($msg->{isAnswered}, JSON::false);
    $self->assert_equals($msg->{isDraft}, JSON::false);

    my $hdrs = $msg->{headers};
    $self->assert_str_equals($hdrs->{'Message-ID'}, '<fake.123456789@local>');
    $self->assert_str_equals($hdrs->{'X-Tra'}, 'foo bar baz');
    $self->assert_deep_equals($msg->{from}, {
            name => "Sally Sender",
            email => "sally\@local"
    });
    $self->assert_deep_equals($msg->{to}[0], {
            name => "Tom To",
            email => "tom\@local"
    });
    $self->assert_num_equals(scalar @{$msg->{to}}, 1);
    $self->assert_deep_equals($msg->{cc}[0], {
            name => "Cindy CeeCee",
            email => "cindy\@local"
    });
    $self->assert_num_equals(scalar @{$msg->{cc}}, 1);
    $self->assert_deep_equals($msg->{bcc}[0], {
            name => "Benny CarbonCopy",
            email => "benny\@local"
    });
    $self->assert_num_equals(scalar @{$msg->{bcc}}, 1);
    $self->assert_null($msg->{replyTo});
    $self->assert_str_equals($msg->{subject}, "Message A");

    my $datestr = $now->strftime('%Y-%m-%dT%TZ');
    $self->assert_str_equals($msg->{date}, $datestr);
    $self->assert_not_null($msg->{size});
}


sub test_getmessages_body_both
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= "This is the plain text part.";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= "<html>";
    $body .= "<body>";
    $body .= "<p>This is the html part.</p>";
    $body .= "</body>";
    $body .= "</html>";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($msg->{textBody}, 'This is the plain text part.');
    $self->assert_str_equals($msg->{htmlBody}, '<html><body><p>This is the html part.</p></body></html>');
}

sub test_getmessages_body_plain
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A plain text message.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($msg->{textBody}, 'A plain text message.');
    $self->assert_str_equals($msg->{htmlBody}, 'A plain text message.');
}

sub test_getmessages_body_html
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "<html><body><p>An html message.</p></body></html>";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "text/html",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($msg->{textBody}, '   AN HTML MESSAGE.   ');
    $self->assert_str_equals($msg->{htmlBody}, '<html><body><p>An html message.</p></body></html>');
}

sub test_getmessages_preview
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog "Generate a message in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A   plain\r\ntext message.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog "get message list";
    my $res = $jmap->Request([['getMessageList', {}, "R1"]]);

    xlog "get messages";
    $res = $jmap->Request([['getMessages', { ids => $res->[0][1]->{messageIds} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals($msg->{textBody}, "A   plain\r\ntext message.");
    $self->assert_str_equals($msg->{preview}, 'A plain text message.');
}

sub test_setmessages_draft
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "create drafts mailbox";
    my $res = $jmap->Request([
            ['setMailboxes', { create => { "#1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals($res->[0][0], 'mailboxesSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"#1"}{id};

    my $draft =  {
        mailboxIds => [$drafts],
        from => { name => "Yosemite Sam", email => "sam\@acme.local" },
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
            { name => "Rainer M\N{LATIN SMALL LETTER U WITH DIAERESIS}ller", email => "rainer\@de.local" },
        ],
        cc => [
            { name => "Elmer Fudd", email => "elmer\@acme.local" },
            { name => "Porky Pig", email => "porky\@acme.local" },
        ],
        bcc => [
            { name => "Wile E. Coyote", email => "coyote\@acme.local" },
        ],
        replyTo => { name => "", email => "the.other.sam\@acme.local" },
        subject => "Memo",
        textBody => "I'm givin' ya one last chance ta surrenda!",
        htmlBody => "Oh!!! I <em>hate</em> that Rabbit.",
        headers => {
            "Foo" => "bar\nbaz\nbam",
        }
    };

    xlog "Create a draft";
    $res = $jmap->Request([['setMessages', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog "Get draft $id";
    $res = $jmap->Request([['getMessages', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    # XXX $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_str_equals($msg->{textBody}, $draft->{textBody});
    $self->assert_str_equals($msg->{htmlBody}, $draft->{htmlBody});
    $self->assert_str_equals($msg->{headers}->{Foo}, $draft->{headers}->{Foo});
    $self->assert_equals($msg->{isDraft}, JSON::true);
}

sub test_setcalendarevents_schedule_request
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
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "send invitation as organizer to attendee";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "organizer" => {
                                "name" => "Cassandane",
                                "email" => "cassandane",
                            },
                            "attendees" => [{
                                "name" => "Bugs Bunny",
                                "email" => "bugs\@localhost",
                                "rsvp" => ""
                            }]
                        }
                    }}, "R1"]]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals($payload->{recipient}, "bugs\@localhost");
    $self->assert($ical =~ "METHOD:REQUEST");
    $self->assert($ical =~ "ATTENDEE;CN=Bugs Bunny;PARTSTAT=NEEDS-ACTION:mailto:bugs\@localhost");
}

sub test_setcalendarevents_schedule_reply
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
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "send reply as attendee to organizer";
    $res = $jmap->Request([['setCalendarEvents', { update => {
                        "$id" => {
                            "organizer" => {
                                "name" => "Bugs Bunny",
                                "email" => "bugs\@localhost"
                            },
                            "attendees" => [{
                                "name" => "Cassandane",
                                "email" => "cassandane",
                                "rsvp" => "maybe"
                            }]
                        }
                    }}, "R1"]]);


    my $data = $self->{instance}->getnotify();

    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals($payload->{recipient}, "bugs\@localhost");
    $self->assert($ical =~ "METHOD:REPLY");
    $self->assert($ical =~ "ATTENDEE;CN=Cassandane;PARTSTAT=TENTATIVE:mailto:cassandane");
}

sub test_setcalendarevents_schedule_cancel
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
                                "email" => "cassandane",
                            },
                            "attendees" => [{
                                "name" => "Bugs Bunny",
                                "email" => "bugs\@localhost",
                                "rsvp" => ""
                            }]
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"#1"}{id};

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "cancel event as organizer";
    $res = $jmap->Request([['setCalendarEvents', { destroy => [$id]}, "R1"]]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals($payload->{recipient}, "bugs\@localhost");
    $self->assert($ical =~ "METHOD:CANCEL");
}

1;
