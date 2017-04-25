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

package Cassandane::Cyrus::JMAPContacts;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk;
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
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'carddav jmap');
    $config->set(httpallowcompress => 'no');
    return $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap', 'http'],
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    xlog "Requesting JMAP access token";
    my $jmap = $self->{jmap};
    $jmap->Login($jmap->{user}, $jmap->{password}) || die;
}

sub test_setcontacts_multicontact
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->Request([['setContacts', {
        create => {
            "1" => {firstName => "first", lastName => "last"},
            "2" => {firstName => "second", lastName => "last"},
        }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

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
    :JMAP :min_version_3_0
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

    xlog "create contact 1";
    $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"1"}{id};

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

    xlog "create contact 2";
    $res = $jmap->Request([['setContacts', {create => {"2" => {firstName => "second", lastName => "prev"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id2 = $res->[0][1]{created}{"2"}{id};

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

    xlog "destroy contact 1, update contact 2";
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

    xlog "destroy contact 2";
    $res = $jmap->Request([['setContacts', {destroy => [$id2]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
}

sub test_setnickname
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
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

    $res = $jmap->Request([['setContacts', {update => {
                        $contact2 => { nickname => "" },
                    }}, "R2"]]);
    $self->assert_not_null($res);
}

sub test_setcontactgroups
    :JMAP :min_version_3_0
{

    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
                        "1" => { firstName => "foo", lastName => "last1" },
                        "2" => { firstName => "bar", lastName => "last2" }
                    }}, "R1"]]);
    my $contact1 = $res->[0][1]{created}{"1"}{id};
    my $contact2 = $res->[0][1]{created}{"2"}{id};

    xlog "create contact group with no contact ids";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "1" => {name => "group1"}
                    }}, "R2"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R2');
    my $id = $res->[0][1]{created}{"1"}{id};

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact group $id";
    $res = $jmap->Request([['getContactGroups', { ids => [$id] }, "R3"]]);
    $self->assert(exists $res->[0][1]{list}[0]{contactIds});
    $self->assert_num_equals(scalar @{$res->[0][1]{list}[0]{contactIds}}, 2);
    $self->assert_str_equals($res->[0][1]{list}[0]{contactIds}[0], $contact1);
    $self->assert_str_equals($res->[0][1]{list}[0]{contactIds}[1], $contact2);
}

sub test_getcontactlist
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
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
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};
    my $id4 = $res->[0][1]{created}{"4"}{id};

    xlog "create contact groups";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "1" => {name => "group1", contactIds => [$id1, $id2]},
                        "2" => {name => "group2", contactIds => [$id3]},
                        "3" => {name => "group3", contactIds => [$id4]}
                    }}, "R1"]]);

    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $group1 = $res->[0][1]{created}{"1"}{id};
    my $group2 = $res->[0][1]{created}{"2"}{id};
    my $group3 = $res->[0][1]{created}{"3"}{id};

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
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contacts";
    my $res = $jmap->Request([['setContacts', {create => {
                        "a" => {firstName => "a", lastName => "a"},
                        "b" => {firstName => "b", lastName => "b"},
                        "c" => {firstName => "c", lastName => "c"},
                        "d" => {firstName => "d", lastName => "d"}
                    }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $contactA = $res->[0][1]{created}{"a"}{id};
    my $contactB = $res->[0][1]{created}{"b"}{id};
    my $contactC = $res->[0][1]{created}{"c"}{id};
    my $contactD = $res->[0][1]{created}{"d"}{id};

    xlog "get contact groups state";
    $res = $jmap->Request([['getContactGroups', {}, "R2"]]);
    my $state = $res->[0][1]{state};

    xlog "create contact group 1";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "1" => {name => "first", contactIds => [$contactA, $contactB]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id1 = $res->[0][1]{created}{"1"}{id};


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

    xlog "create contact group 2";
    $res = $jmap->Request([['setContactGroups', {create => {
                        "2" => {name => "second", contactIds => [$contactC, $contactD]}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id2 = $res->[0][1]{created}{"2"}{id};

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

    xlog "destroy contact group 1, update contact group 2";
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

    xlog "destroy contact group 2";
    $res = $jmap->Request([['setContactGroups', {destroy => [$id2]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactGroupsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
}

sub test_setcontacts
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $contact = {
        firstName => "first",
        lastName => "last"
    };

    my $res = $jmap->Request([['setContacts', {create => {"1" => $contact }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog "get contact $id";
    $fetch = $jmap->Request([['getContacts', {}, "R2"]]);
    $self->assert_deep_equals($fetch->[0][1]{list}[0], $contact);
}


sub test_setcontacts_state
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create contact";
    my $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"1"}{id};
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
    $self->assert(exists $res->[0][1]{updated}{$id});
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

sub test_setcontacts_importance_later
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last"}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"1"}{id};

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -0.1);
}

sub test_setcontacts_importance_upfront
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with importance in initial create";
    my $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"1"}{id};

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -5.2);
}

sub test_setcontacts_importance_multiedit
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"1"}{id};

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, -0.2);
}

sub test_setcontacts_importance_zero_multi
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"1"}{id};

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'second');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0);
}

sub test_setcontacts_importance_zero_byself
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create with no importance";
    my $res = $jmap->Request([['setContacts', {create => {"1" => {firstName => "first", lastName => "last", "x-importance" => -5.2}}}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');
    my $id = $res->[0][1]{created}{"1"}{id};

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
    $self->assert(exists $res->[0][1]{updated}{$id});

    $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R4"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R4');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'first');
    $self->assert_num_equals($fetch->[0][1]{list}[0]{"x-importance"}, 0);
}

sub test_creationids
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "create and get contact group and contact";
    my $res = $jmap->Request([
        ['setContacts', {create => { "1" => { firstName => "foo", lastName => "last1" }, }}, "R2"],
        ['setContactGroups', {create => { "1" => {name => "group1", contactIds => ["#1"]} }}, "R2"],
        ['getContacts', {ids => ["#1"]}, "R3"],
        ['getContactGroups', {ids => ["#1"]}, "R4"],
    ]);
    my $contact = $res->[2][1]{list}[0];
    $self->assert_str_equals("foo", $contact->{firstName});

    my $group = $res->[3][1]{list}[0];
    $self->assert_str_equals("group1", $group->{name});

    $self->assert_str_equals($contact->{id}, $group->{contactIds}[0]);
}

sub test_categories
    :JMAP :min_version_3_0
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

    my $fetch = $jmap->Request([['getContacts', {ids => [$id]}, "R2"]]);
    $self->assert_not_null($fetch);
    $self->assert_str_equals($fetch->[0][0], 'contacts');
    $self->assert_str_equals($fetch->[0][2], 'R2');
    $self->assert_str_equals($fetch->[0][1]{list}[0]{firstName}, 'Forrest');

    my $res = $jmap->Request([['setContacts', {
                    update => {$id => {firstName => "foo"}}
                }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals($res->[0][0], 'contactsSet');
    $self->assert_str_equals($res->[0][2], 'R1');

    $data = $carddav->Request('GET', $href);
    $self->assert_matches(qr/cat1,cat2/, $data->{content});

}

1;
