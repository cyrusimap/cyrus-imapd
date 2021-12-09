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
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use Cwd qw(abs_path);
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
                 sync_log => 'yes',
                 icalendar_max_size => 100000,
                 jmap_nonstandard_extensions => 'yes');

    # Configure Sieve iMIP delivery
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj == 3 && $min == 0) {
        # need to explicitly add 'body' to sieve_extensions for 3.0
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags mailbox mboxmetadata servermetadata variables " .
            "body");
    }
    elsif ($maj < 3) {
        # also for 2.5 (the earliest Cyrus that Cassandane can test)
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags body");
    }
    $config->set(sievenotifier => 'mailto');
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(caldav_historical_age => -1);
    $config->set(virtdomains => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        deliver => 1,
        services => [ 'imap', 'sieve', 'http' ],
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);
}

sub test_calendar_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $id = $caldav->NewCalendar({ name => "calname", color => "aqua"});
    my $unknownId = "foo";

    xlog $self, "get existing calendar";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Calendar/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    $self->assert_str_equals($id, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('aqua', $res->[0][1]{list}[0]{color});

    xlog $self, "get existing calendar with select properties";
    $res = $jmap->CallMethods([['Calendar/get', { ids => [$id], properties => ["name"] }, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    $self->assert_str_equals($id, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals("calname", $res->[0][1]{list}[0]{name});
    $self->assert_null($res->[0][1]{list}[0]{color});

    xlog $self, "get unknown calendar";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$unknownId]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(0, scalar(@{$res->[0][1]{list}}));
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{notFound}}));
    $self->assert_str_equals($unknownId, $res->[0][1]{notFound}[0]);

    xlog $self, "get all calendars";
    $res = $jmap->CallMethods([['Calendar/get', {ids => undef}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(2, scalar(@{$res->[0][1]{list}}));
    $res = $jmap->CallMethods([['Calendar/get', {}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(2, scalar(@{$res->[0][1]{list}}));
}

sub test_calendar_get_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
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

    xlog $self, "create calendar";
    my $CalendarId = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lr') or die;

    xlog $self, "get calendar";
    my $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold'}, "R1"]]);
    $self->assert_str_equals('manifold', $res->[0][1]{accountId});
    $self->assert_str_equals("Manifold Calendar", $res->[0][1]{list}[0]->{name});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]->{mayReadItems});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]->{mayAddItems});
    my $id = $res->[0][1]{list}[0]->{id};

    xlog $self, "refetch calendar";
    $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold', ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{list}[0]->{id});

    xlog $self, "create another shared calendar";
    my $CalendarId2 = $mantalk->NewCalendar({name => 'Manifold Calendar 2'});
    $self->assert_not_null($CalendarId2);
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lr') or die;

    xlog $self, "remove access rights to calendar";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => '') or die;

    xlog $self, "refetch calendar (should fail)";
    $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold', ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);

    xlog $self, "remove access rights to all shared calendars";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => '') or die;

    xlog $self, "refetch calendar (should fail)";
    $res = $jmap->CallMethods([['Calendar/get', {accountId => 'manifold', ids => [$id]}, "R1"]]);
    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("accountNotFound", $res->[0][1]{type});
}


sub test_calendar_get_default
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # XXX - A previous CalDAV test might have created the default
    # calendar already. To make this test self-sufficient, we need
    # to create a test user just for this test. How?
    xlog $self, "get default calendar";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals("Default", $res->[0][1]{list}[0]{id});
}

sub test_calendar_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar";
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

    xlog $self, "get calendar $id";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{list}}));
    $self->assert_str_equals($id, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{name});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{isVisible});

    xlog $self, "update calendar $id";
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

    xlog $self, "get calendar $id";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals('bar', $res->[0][1]{list}[0]{name});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{isVisible});

    xlog $self, "destroy calendar $id";
    $res = $jmap->CallMethods([['Calendar/set', {destroy => ["$id"]}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{destroyed});
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);

    xlog $self, "get calendar $id";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);
}

sub test_calendar_set_state
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create with invalid state token";
    my $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => "badstate",
                    create => { "1" => { name => "foo" }}
                }, "R1"]
        ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog $self, "create with wrong state token";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => "987654321",
                    create => { "1" => { name => "foo" }}
                }, "R1"]
        ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});

    xlog $self, "create calendar";
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

    xlog $self, "update calendar $id with current state";
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

    xlog $self, "setCalendar noops must keep state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {}, "R1"],
            ['Calendar/set', {}, "R2"],
            ['Calendar/set', {}, "R3"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_equals($state, $res->[0][1]{newState});

    xlog $self, "update calendar $id with expired state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $oldState,
                    update => {"$id" => {name => "baz"}}
            }, "R1"]
    ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals("stateMismatch", $res->[0][1]{type});
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "get calendar $id to make sure state didn't change";
    $res = $jmap->CallMethods([['Calendar/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{state});
    $self->assert_str_equals('bar', $res->[0][1]{list}[0]{name});

    xlog $self, "destroy calendar $id with expired state";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $oldState,
                    destroy => [$id]
            }, "R1"]
    ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals("stateMismatch", $res->[0][1]{type});
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "destroy calendar $id with current state";
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");
    xlog $self, "create shared account";
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

    xlog $self, "share calendar home read-only to user";
    $admintalk->setacl("user.manifold.#calendars", cassandane => 'lr') or die;

    xlog $self, "create calendar (should fail)";
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
    $self->assert_str_equals('manifold', $res->[0][1]{accountId});
    $self->assert_str_equals("accountReadOnly", $res->[0][1]{notCreated}{1}{type});

    xlog $self, "share calendar home read-writable to user";
    $admintalk->setacl("user.manifold.#calendars", cassandane => 'lrswipkxtecdn') or die;

    xlog $self, "create calendar";
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
    $self->assert_str_equals('manifold', $res->[0][1]{accountId});
    my $CalendarId = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($CalendarId);

    xlog $self, "share calendar read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lr') or die;

    xlog $self, "update calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'manifold',
                    update => {$CalendarId => {
                            name => "bar",
                            isVisible => \0
            }}}, "R1"]
    ]);
    $self->assert_str_equals('manifold', $res->[0][1]{accountId});
    $self->assert(exists $res->[0][1]{updated}{$CalendarId});

    xlog $self, "destroy calendar $CalendarId (should fail)";
    $res = $jmap->CallMethods([['Calendar/set', {accountId => 'manifold', destroy => [$CalendarId]}, "R1"]]);
    $self->assert_str_equals('manifold', $res->[0][1]{accountId});
    $self->assert_str_equals("accountReadOnly", $res->[0][1]{notDestroyed}{$CalendarId}{type});

    xlog $self, "share read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "destroy calendar $CalendarId";
    $res = $jmap->CallMethods([['Calendar/set', {accountId => 'manifold', destroy => [$CalendarId]}, "R1"]]);
    $self->assert_str_equals('manifold', $res->[0][1]{accountId});
    $self->assert_str_equals($CalendarId, $res->[0][1]{destroyed}[0]);
}

sub test_calendar_set_sharewith
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    # need to version-gate jmap features that aren't in 3.5...
    my ($maj, $min) = Cassandane::Instance->get_version();

    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
    $admintalk->create("user.master");

    my $mastalk = Net::CalDAVTalk->new(
        user => "master",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    $admintalk->setacl("user.master", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.master", master => 'lrswipkxtecdn');

    xlog $self, "create calendar";
    my $CalendarId = $mastalk->NewCalendar({name => 'Shared Calendar'});
    $self->assert_not_null($CalendarId);

    xlog $self, "share to user with permission to share";
    $admintalk->setacl("user.master.#calendars.$CalendarId", "cassandane" => 'lrswipkxtecdan9') or die;

    xlog $self, "create third account";
    $admintalk->create("user.manifold");

    $admintalk->setacl("user.manifold", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", manifold => 'lrswipkxtecdn');

    xlog $self, "and a forth";
    $admintalk->create("user.paraphrase");

    $admintalk->setacl("user.paraphrase", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.paraphrase", paraphrase => 'lrswipkxtecdn');

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

    # Call CalDAV once to create paraphrase's calendar home #calendars
    my $partalk = Net::CalDAVTalk->new(
        user => "paraphrase",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog $self, "sharee gives third user access to shared calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'master',
                    update => { "$CalendarId" => {
                            "shareWith/manifold" => {
                                mayReadFreeBusy => JSON::true,
                                mayRead => JSON::true,
                                mayWrite => JSON::false,
                                mayAdmin => JSON::false
                            },
                            "shareWith/paraphrase" => {
                                mayReadFreeBusy => JSON::true,
                                mayRead => JSON::true,
                                mayWrite => JSON::true,
                                mayAdmin => JSON::false
                            },
             }}}, "R1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Calendar/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "fetch invites";
    my ($adds) = $mantalk->SyncEventLinks("/dav/notifications/user/manifold");
    $self->assert_equals(1, scalar %$adds);
    ($adds) = $partalk->SyncEventLinks("/dav/notifications/user/paraphrase");
    $self->assert_equals(1, scalar %$adds);

    xlog $self, "check ACL";
    my $acl = $admintalk->getacl("user.master.#calendars.$CalendarId");
    my %map = @$acl;
    $self->assert_str_equals('lrswipkxtecdan9', $map{cassandane});
    $self->assert_str_equals('lrs9', $map{manifold});
    $self->assert_str_equals('lrswiptedn9', $map{paraphrase});

    xlog $self, "check Outbox ACL";
    $acl = $admintalk->getacl("user.master.#calendars.Outbox");
    %map = @$acl;
    $self->assert_null($map{manifold});  # we don't create Outbox ACLs for read-only
    $self->assert_str_equals('78', $map{paraphrase});

    xlog $self, "check Principal ACL";
    $acl = $admintalk->getacl("user.master.#calendars");
    %map = @$acl;
    # both users get ACLs on the Inbox
    $self->assert_str_equals('lr', $map{manifold});
    $self->assert_str_equals('lr', $map{paraphrase});

    my $Name = $mantalk->GetProps('/dav/principals/user/master', 'D:displayname');
    $self->assert_str_equals('master', $Name);
    $Name = $partalk->GetProps('/dav/principals/user/master', 'D:displayname');
    $self->assert_str_equals('master', $Name);

    if ($maj > 3 || ($maj == 3 && $min >= 4)) {
        xlog $self, "check ACL on JMAP upload folder";
        $acl = $admintalk->getacl("user.master.#jmap");
        %map = @$acl;
        $self->assert_str_equals('lrswitedn', $map{cassandane});
        $self->assert_str_equals('lrs', $map{manifold});
        $self->assert_str_equals('lrswitedn', $map{paraphrase});
    }

    xlog $self, "Clear initial syslog";
    $self->{instance}->getsyslog();

    xlog $self, "Update sharewith just for manifold";
    $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'master',
                    update => { "$CalendarId" => {
                            "shareWith/manifold/mayWrite" => JSON::true,
             }}}, "R1"]
    ]);

    if ($self->{instance}->{have_syslog_replacement}) {
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/manifold\.\#notifications/, "@lines");
        $self->assert((not grep { /paraphrase\.\#notifications/ } @lines), Data::Dumper::Dumper(\@lines));
    }

    if ($maj > 3 || ($maj == 3 && $min >= 4)) {
        xlog $self, "check ACL on JMAP upload folder";
        $acl = $admintalk->getacl("user.master.#jmap");
        %map = @$acl;
        $self->assert_str_equals('lrswitedn', $map{cassandane});
        $self->assert_str_equals('lrswitedn', $map{manifold});
        $self->assert_str_equals('lrswitedn', $map{paraphrase});
    }

    xlog $self, "Remove the access for paraphrase";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'master',
                    update => { "$CalendarId" => {
                            "shareWith/paraphrase" => undef,
             }}}, "R1"]
    ]);

    $self->assert_not_null($res);
    $self->assert_str_equals('Calendar/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "check ACL";
    $acl = $admintalk->getacl("user.master.#calendars.$CalendarId");
    %map = @$acl;
    $self->assert_str_equals('lrswipkxtecdan9', $map{cassandane});
    $self->assert_str_equals('lrswiptedn9', $map{manifold});
    $self->assert_null($map{paraphrase});

    xlog $self, "check Outbox ACL";
    $acl = $admintalk->getacl("user.master.#calendars.Outbox");
    %map = @$acl;
    $self->assert_str_equals('78', $map{manifold});
    $self->assert_null($map{paraphrase});

    xlog $self, "check Principal ACL";
    $acl = $admintalk->getacl("user.master.#calendars");
    %map = @$acl;
    # both users get ACLs on the Inbox
    $self->assert_str_equals('lr', $map{manifold});
    $self->assert_null($map{paraphrase});

    xlog $self, "Check propfind";
    $Name = eval { $partalk->GetProps('/dav/principals/user/master', 'D:displayname') };
    my $error = $@;
    $self->assert_null($Name);
    $self->assert_matches(qr/403 Forbidden/, $error);

    if ($maj > 3 || ($maj == 3 && $min >= 4)) {
        xlog $self, "check ACL on JMAP upload folder";
        $acl = $admintalk->getacl("user.master.#jmap");
        %map = @$acl;
        $self->assert_str_equals('lrswitedn', $map{cassandane});
        $self->assert_str_equals('lrswitedn', $map{manifold});
        $self->assert_null($map{paraphrase});

        xlog $self, "Remove the access for cassandane";
        $res = $jmap->CallMethods([
                ['Calendar/set', {
                        accountId => 'master',
                        update => { "$CalendarId" => {
                                "shareWith/cassandane" => undef,
                 }}}, "R1"]
        ]);

        # GET session
        my $RawRequest = {
            headers => {
                'Authorization' => $jmap->auth_header(),
            },
            content => '',
        };
        my $RawResponse = $jmap->ua->get($jmap->uri(), $RawRequest);
        if ($ENV{DEBUGJMAP}) {
            warn "JMAP " . Dumper($RawRequest, $RawResponse);
        }
        $self->assert_str_equals('200', $RawResponse->{status});
        my $session = eval { decode_json($RawResponse->{content}) };
        $self->assert_not_null($session);
        $self->assert_not_null($session->{accounts}{cassandane});
        $self->assert_null($session->{accounts}{master});
    }
}

sub test_calendar_set_issubscribed
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create calendar
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                '1' => {
                    name => 'A',
                    color => 'blue',
                }
            },
        }, 'R1'],
        ['Calendar/get', {
            ids => ['#1'],
            properties => ['isSubscribed']
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{created}{1});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{isSubscribed});
    my $id = $res->[0][1]{created}{"1"}{id};

    # Can't unsubscribe own calendars
    $res = $jmap->CallMethods([
        ['Calendar/set',
            { update => {
                $id => {
                    isSubscribed => JSON::false,
                }
            }
        }, "R1"],
        ['Calendar/get', {
            ids => [$id],
            properties => ['isSubscribed']
        }, 'R2'],
    ]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$id});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{isSubscribed});
}

sub test_calendar_set_issubscribed_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
    $admintalk->create("user.other");

    $admintalk->setacl("user.other", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.other", other => 'lrswipkxtecdn');

    xlog $self, "create and share default calendar";
    my $othertalk = Net::CalDAVTalk->new(
        user => "other",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
    $admintalk->setacl('user.other.#calendars.Default', "cassandane" => 'lr') or die;

    # Get calendar
    my $res = $jmap->CallMethods([
        ['Calendar/get', {
            accountId => 'other',
            properties => ['isSubscribed']
        }, 'R!'],
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]{isSubscribed});
    my $id = $res->[0][1]{list}[0]{id};

    # Toggle isSubscribed on read-only shared calendar
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            accountId => 'other',
            update => {
                $id => {
                    isSubscribed => JSON::true,
                }
            }
        }, "R1"],
        ['Calendar/get', {
            accountId => 'other',
            ids => [$id],
            properties => ['isSubscribed']
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{isSubscribed});
}


sub test_calendar_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar";
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

    xlog $self, "get calendar updates without changes";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals(0, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "update name of calendar $id1, destroy calendar $id2";
    $res = $jmap->CallMethods([
            ['Calendar/set', {
                    ifInState => $state,
                    update => {"$id1" => {name => "foo (upd)"}},
                    destroy => [$id2]
            }, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});

    xlog $self, "get calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_str_equals("Calendar/changes", $res->[0][0]);
    $self->assert_str_equals("R1", $res->[0][2]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id1, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "update color of calendar $id1";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { $id1 => { color => "aqua" }}}, "R1" ]
        ]);
    $self->assert(exists $res->[0][1]{updated}{$id1});

    xlog $self, "get calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id1, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $state = $res->[0][1]{newState};

    xlog $self, "update sortOrder of calendar $id1";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { $id1 => { sortOrder => 5 }}}, "R1" ]
        ]);
    $self->assert(exists $res->[0][1]{updated}{$id1});

    xlog $self, "get calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state,
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id1, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $state = $res->[0][1]{newState};

    xlog $self, "get empty calendar updates";
    $res = $jmap->CallMethods([['Calendar/changes', {
                    "sinceState" => $state
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
}

sub test_calendar_set_error
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar with missing mandatory attributes";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {}}}, "R1"]
    ]);
    $self->assert_not_null($res);
    my $errType = $res->[0][1]{notCreated}{"1"}{type};
    my $errProp = $res->[0][1]{notCreated}{"1"}{properties};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals([ "name" ], $errProp);

    xlog $self, "create calendar with invalid optional attributes";
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
    $self->assert_str_equals("invalidProperties", $errType);
    my @errProp = sort @{$res->[0][1]{notCreated}{"1"}{properties}};
    $errProp = join(',', @errProp);
    $self->assert_str_equals($errProp,
                             "mayAddItems,mayDelete,mayModifyItems," .
                             "mayReadFreeBusy,mayReadItems,mayRemoveItems," .
                             "mayRename");

    xlog $self, "update unknown calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { "unknown" => {
                            name => "foo"
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{"unknown"}{type};
    $self->assert_str_equals("notFound", $errType);

    xlog $self, "create calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo",
                            sortOrder => 2,
                            isVisible => \1
             }}}, "R1"]
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "update calendar with immutable optional attributes";
    $res = $jmap->CallMethods([
            ['Calendar/set', { update => { $id => {
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{$id}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    @errProp = sort @{$res->[0][1]{notUpdated}{$id}{properties}};
    $errProp = join(',', @errProp);
    $self->assert_str_equals($errProp,
                             "mayAddItems,mayDelete,mayModifyItems," .
                             "mayReadFreeBusy,mayReadItems,mayRemoveItems," .
                             "mayRename");

    xlog $self, "destroy unknown calendar";
    $res = $jmap->CallMethods([
            ['Calendar/set', {destroy => ["unknown"]}, "R1"]
    ]);
    $errType = $res->[0][1]{notDestroyed}{"unknown"}{type};
    $self->assert_str_equals("notFound", $errType);

    xlog $self, "destroy calendar $id";
    $res = $jmap->CallMethods([['Calendar/set', {destroy => ["$id"]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}

sub test_calendar_set_badname
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar with excessively long name";
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

sub test_calendar_set_destroyspecials
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my @specialIds = ["Inbox", "Outbox", "Default", "Attachments"];

    xlog $self, "destroy special calendars";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { destroy => @specialIds }, "R1"]
    ]);
    $self->assert_not_null($res);

    my $errType;

    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj > 3 || ($maj == 3 && $min >= 5)) {
        # Default calendar may be destroyed from 3.5+
        $self->assert_deep_equals(['Default'], $res->[0][1]{destroyed});
    }
    else {
        # but previously, this was forbidden
        $errType = $res->[0][1]{notDestroyed}{"Default"}{type};
        $self->assert_str_equals("isDefault", $errType);
    }

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
    if (not exists $event->{title}) {
        $event->{title} = '';
    }
    if (not exists $event->{description}) {
        $event->{description} = '';
    }
    if (not exists $event->{descriptionContentType}) {
        $event->{descriptionContentType} = 'text/plain';
    }
    if (not exists $event->{showWithoutTime}) {
        $event->{showWithoutTime} = JSON::false;
    }
    if (not exists $event->{locations}) {
        $event->{locations} = undef;
    } elsif (defined $event->{locations}) {
        foreach my $loc (values %{$event->{locations}}) {
            if (not exists $loc->{name}) {
                $loc->{name} = '';
            }
            if (not exists $loc->{q{@type}}) {
                $loc->{q{@type}} = 'Location';
            }
        }
    }
    if (not exists $event->{virtualLocations}) {
        $event->{virtualLocations} = undef;
    } elsif (defined $event->{virtualLocations}) {
        foreach my $loc (values %{$event->{virtualLocations}}) {
            if (not exists $loc->{name}) {
                $loc->{name} = ''
            }
            if (not exists $loc->{description}) {
                $loc->{description} = undef;
            }
            if (not exists $loc->{uri}) {
                $loc->{uri} = undef;
            }
            if (not exists $loc->{q{@type}}) {
                $loc->{q{@type}} = 'VirtualLocation';
            }
        }
    }
    if (not exists $event->{keywords}) {
        $event->{keywords} = undef;
    }
    if (not exists $event->{locale}) {
        $event->{locale} = undef;
    }
    if (not exists $event->{links}) {
        $event->{links} = undef;
    } elsif (defined $event->{links}) {
        foreach my $link (values %{$event->{links}}) {
            if (not exists $link->{q{@type}}) {
                $link->{q{@type}} = 'Link';
            }
        }
    }
    if (not exists $event->{relatedTo}) {
        $event->{relatedTo} = undef;
    } elsif (defined $event->{relatedTo}) {
        foreach my $rel (values %{$event->{relatedTo}}) {
            if (not exists $rel->{q{@type}}) {
                $rel->{q{@type}} = 'Relation';
            }
        }
    }
    if (not exists $event->{participantId}) {
        # non-standard
        $event->{participantId} = undef;
    }
    if (not exists $event->{participants}) {
        $event->{participants} = undef;
    } elsif (defined $event->{participants}) {
        foreach my $p (values %{$event->{participants}}) {
            if (not exists $p->{linkIds}) {
                $p->{linkIds} = undef;
            }
            if (not exists $p->{participationStatus}) {
                $p->{participationStatus} = 'needs-action';
            }
            if (not exists $p->{expectReply}) {
                $p->{expectReply} = JSON::false;
            }
            if (not exists $p->{scheduleSequence}) {
                $p->{scheduleSequence} = 0;
            }
            if (not exists $p->{q{@type}}) {
                $p->{q{@type}} = 'Participant';
            }
        }
    }
    if (not exists $event->{replyTo}) {
        $event->{replyTo} = undef;
    }
    if (not exists $event->{recurrenceRule}) {
        $event->{recurrenceRule} = undef;
    } elsif (defined $event->{recurrenceRule}) {
        if (not exists $event->{recurrenceRule}{interval}) {
            $event->{recurrenceRule}{interval} = 1;
        }
        if (not exists $event->{recurrenceRule}{firstDayOfWeek}) {
            $event->{recurrenceRule}{firstDayOfWeek} = 'mo';
        }
        if (not exists $event->{recurrenceRule}{rscale}) {
            $event->{recurrenceRule}{rscale} = 'gregorian';
        }
        if (not exists $event->{recurrenceRule}{skip}) {
            $event->{recurrenceRule}{skip} = 'omit';
        }
        if (not exists $event->{recurrenceRule}{q{@type}}) {
            $event->{recurrenceRule}{q{@type}} = 'RecurrenceRule';
        }
    }
    if (not exists $event->{recurrenceOverrides}) {
        $event->{recurrenceOverrides} = undef;
    }
    if (not exists $event->{alerts}) {
        $event->{alerts} = undef;
    }
    elsif (defined $event->{alerts}) {
        foreach my $alert (values %{$event->{alerts}}) {
            if (not exists $alert->{action}) {
                $alert->{action} = 'display';
            }
            if (not exists $alert->{q{@type}}) {
                $alert->{q{@type}} = 'Alert';
            }
            if (not exists $alert->{relatedTo}) {
                $alert->{relatedTo} = undef;
            } elsif (defined $alert->{relatedTo}) {
                foreach my $rel (values %{$alert->{relatedTo}}) {
                    if (not exists $rel->{q{@type}}) {
                        $rel->{q{@type}} = 'Relation';
                    }
                }
            }
            if ($alert->{trigger} and $alert->{trigger}{q{@type}} eq 'OffsetTrigger') {
                if (not exists $alert->{trigger}{relativeTo}) {
                    $alert->{trigger}{relativeTo} = 'start';
                }
            }
        }
    }
    if (not exists $event->{useDefaultAlerts}) {
        $event->{useDefaultAlerts} = JSON::false;
    }
    if (not exists $event->{prodId}) {
        $event->{prodId} = undef;
    }
    if (not exists $event->{links}) {
        $event->{links} = undef;
    } elsif (defined $event->{links}) {
        foreach my $link (values %{$event->{links}}) {
            if (not exists $link->{cid}) {
                $link->{cid} = undef;
            }
            if (not exists $link->{contentType}) {
                $link->{contentType} = undef;
            }
            if (not exists $link->{size}) {
                $link->{size} = undef;
            }
            if (not exists $link->{title}) {
                $link->{title} = undef;
            }
            if (not exists $link->{q{@type}}) {
                $link->{q{@type}} = 'Link';
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

    xlog $self, "get default calendar id";
    my $res = $jmap->CallMethods([['Calendar/get', {ids => ["Default"]}, "R1"]]);
    $self->assert_str_equals("Default", $res->[0][1]{list}[0]{id});
    my $calid = $res->[0][1]{list}[0]{id};
    my $xhref = $res->[0][1]{list}[0]{"x-href"};

    # Create event via CalDAV to test CalDAV/JMAP interop.
    xlog $self, "create event (via CalDAV)";
    my $href = "$xhref/$id.ics";

    $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    xlog $self, "get event $id";
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
    :min_version_3_1 :needs_component_jmap
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
    $self->assert_str_equals("text/plain", $event->{descriptionContentType});
    $self->assert_equals($event->{freeBusyStatus}, "free");
    $self->assert_equals($event->{showWithoutTime}, JSON::false);
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('privacy');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("private", $event->{privacy});
}

sub test_calendarevent_get_properties
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('simple');

    my $event = $self->putandget_vevent($id, $ical, ["x-href", "calendarId"]);
    $self->assert_not_null($event);
    $self->assert_not_null($event->{id});
    $self->assert_not_null($event->{uid});
    $self->assert_not_null($event->{"x-href"});
    $self->assert_not_null($event->{calendarId});
    $self->assert_num_equals(5, scalar keys %$event);
}

sub test_calendarevent_get_relatedto
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('relatedto');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals($id, $event->{uid});
    $self->assert_deep_equals({
            "58ADE31-001" => {
                '@type' => 'Relation',
                relation => {
                    'first' => JSON::true,
                }
            },
            "58ADE31-003" => {
                '@type' => 'Relation',
                relation => {
                    'next' => JSON::true,
                }
            },
            "foo" => {
                '@type' => 'Relation',
                relation => {
                    'x-unknown1' => JSON::true,
                    'x-unknown2' => JSON::true,
                }
            },
            "bar" => {
                '@type' => 'Relation',
                relation => {}
            },
    }, $event->{relatedTo});
}

sub test_calendarevent_get_links
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('links');
    my $uri = "http://jmap.io/spec.html#calendar-events";

    my $links = {
        'fad3249914b09ede1558fa01004f4f8149559591' => {
            '@type' => 'Link',
            href => "http://jmap.io/spec.html#calendar-events",
            contentType => "text/html",
            size => 4480,
            title => "the spec",
            rel => "enclosure",
            cid => '123456789asd',
        },
        '113fa6c507397df199a18d1371be615577f9117f' => {
            '@type' => 'Link',
            href => "http://example.com/some.url",
        },
        'describedby-attach' => {
            '@type' => 'Link',
            href => "http://describedby/attach",
            rel => "describedby",
        },
        'describedby-url' => {
            '@type' => 'Link',
            href => "http://describedby/url",
            rel => 'describedby',
        }
    };

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_deep_equals($links, $event->{links});
}


sub test_calendarevent_get_rscale
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('rscale');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("Some day in Adar I", $event->{title});
    $self->assert_str_equals("yearly", $event->{recurrenceRule}{frequency});
    $self->assert_str_equals("hebrew", $event->{recurrenceRule}{rscale});
    $self->assert_str_equals("forward", $event->{recurrenceRule}{skip});
    $self->assert_num_equals(8, $event->{recurrenceRule}{byMonthDay}[0]);
    $self->assert_str_equals("5L", $event->{recurrenceRule}{byMonth}[0]);
}

sub test_calendarevent_get_endtimezone
    :min_version_3_1 :needs_component_jmap
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
    $self->assert_str_equals("end", $locations[0]{relativeTo});

}

sub test_calendarevent_get_ms_timezone
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('ms_timezone');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("2016-09-28T13:00:00", $event->{start});
    $self->assert_str_equals("America/New_York", $event->{timeZone});
    $self->assert_str_equals("PT2H", $event->{duration});
}

sub test_calendarevent_get_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('keywords');

    my $event = $self->putandget_vevent($id, $ical);
    my $keywords = {
        'foo' => JSON::true,
        'bar' => JSON::true,
        'baz' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $event->{keywords});
}

sub test_calendarevent_get_description
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('description');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("Hello, world!", $event->{description});
    $self->assert_str_equals("text/plain", $event->{descriptionContentType});
}

sub test_calendarevent_get_participants
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('participants');

    my $event = $self->putandget_vevent($id, $ical);

    my $wantParticipants = {
        '375507f588e65ec6eb800757ab94ccd10ad58599' => {
            '@type' => 'Participant',
            name => 'Monty Burns',
            roles => {
                'owner' => JSON::true,
                'attendee' => JSON::true,
            },
            participationStatus => 'accepted',
            sendTo => {
                imip => 'mailto:smithers@example.com',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
        },
        '39b16b858076733c1d890cbcef73eca0e874064d' => {
            '@type' => 'Participant',
            name => 'Homer Simpson',
            participationStatus => 'accepted',
            roles => {
                'optional' => JSON::true,
            },
            locationId => 'loc1',
            sendTo => {
                imip => 'mailto:homer@example.com',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
        },
        'carl' => {
            '@type' => 'Participant',
            name => 'Carl Carlson',
            participationStatus => 'tentative',
            roles => {
                'attendee' => JSON::true,
            },
            scheduleSequence => 3,
            scheduleUpdated => '2017-01-02T03:04:05Z',
            delegatedFrom => {
                'a6ef900d284067bb327d7be1469fb44693a5ec13' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:carl@example.com',
            },
            expectReply => JSON::false,
        },
        'a6ef900d284067bb327d7be1469fb44693a5ec13' => {
            '@type' => 'Participant',
            name => 'Lenny Leonard',
            participationStatus => 'delegated',
            roles => {
                'attendee' => JSON::true,
            },
            delegatedTo => {
                'carl' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:lenny@example.com',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
        },
        'd6db3540fe51335b7154f144456e9eac2778fc8f' => {
            '@type' => 'Participant',
            name => 'Larry Burns',
            participationStatus => 'declined',
            roles => {
                'attendee' => JSON::true,
            },
            memberOf => {
                '29a545214b66cbd7635fdec3a35d074ff3484479' => JSON::true,
            },
            scheduleUpdated => '2015-09-29T14:44:23Z',
            sendTo => {
                imip => 'mailto:larry@example.com',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
        },
    };
    $self->assert_deep_equals($wantParticipants, $event->{participants});
}

sub test_calendarevent_get_organizer
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('organizer');

    my $event = $self->putandget_vevent($id, $ical);
    my $wantParticipants = {
        'bf8360ce374961f497599431c4bacb50d4a67ca1' => {
            '@type' => 'Participant',
            name => 'Organizer',
            roles => {
                'owner' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:organizer@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
        '29deb29d758dbb27ffa3c39b499edd85b53dd33f' => {
            '@type' => 'Participant',
            roles => {
                'attendee' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:attendee@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
    };
    $self->assert_deep_equals($wantParticipants, $event->{participants});
    $self->assert_equals('mailto:organizer@local', $event->{replyTo}{imip});
}

sub test_calendarevent_organizer_noattendees_legacy
    :min_version_3_4 :max_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    # It's allowed to have an ORGANIZER even if there are no ATTENDEEs.
    # The expected behaviour is that there's just a single organizer in the
    # participants

    my ($id, $ical) = $self->icalfile('organizer_noattendees');

    my $event = $self->putandget_vevent($id, $ical);

    my $wantParticipants = {
        'bf8360ce374961f497599431c4bacb50d4a67ca1' => {
            '@type' => 'Participant',
            name => 'Organizer',
            roles => {
                'owner' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:organizer@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
    };
    $self->assert_deep_equals($wantParticipants, $event->{participants});
    $self->assert_equals('mailto:organizer@local', $event->{replyTo}{imip});
}

sub test_calendarevent_organizer_noattendees
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my ($event1Id, $ical) = $self->icalfile('organizer_noattendees');
    my $event = $self->putandget_vevent($event1Id, $ical);
    my $wantParticipants = {
        'bf8360ce374961f497599431c4bacb50d4a67ca1' => {
            '@type' => 'Participant',
            name => 'Organizer',
            roles => {
                'owner' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:organizer@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
    };
    my $wantReplyTo = {
        imip => 'mailto:organizer@local',
    },
    $self->assert_deep_equals($wantParticipants, $event->{participants});
    $self->assert_deep_equals($wantReplyTo, $event->{replyTo});

    xlog "Update event via JMAP";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $event1Id => {
                    participants => $wantParticipants,
                    replyTo => $wantReplyTo,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$event1Id],
            properties => ['participants', 'replyTo', 'x-href'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$event1Id});
    $self->assert_deep_equals($wantParticipants, $res->[1][1]{list}[0]{participants});
    $self->assert_deep_equals($wantReplyTo, $res->[1][1]{list}[0]{replyTo});

    my $xhref1 = $res->[1][1]{list}[0]{'x-href'};
    $self->assert_not_null($xhref1);

    xlog "Validate no ATTENDEE got added";
    $res = $caldav->Request('GET', $xhref1);
    $self->assert($res->{content} =~ m/ORGANIZER/);
    $self->assert(not($res->{content} =~ m/ATTENDEE/));

    xlog "Create event with owner-only participant via JMAP";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event2 => {
                    calendarId => 'Default',
                    title => "title",
                    "start"=> "2015-11-07T09:00:00",
                    "duration"=> "PT2H",
                    "timeZone" => "Europe/London",
                    replyTo => $wantReplyTo,
                    participants => $wantParticipants,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event2'],
            properties => ['participants', 'replyTo'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals($wantParticipants, $res->[1][1]{list}[0]{participants});
    $self->assert_deep_equals($wantReplyTo, $res->[1][1]{list}[0]{replyTo});

    my $xhref2 = $res->[0][1]{created}{event2}{'x-href'};
    $self->assert_not_null($xhref2);

    xlog "Validate an ATTENDEE got added";
    $res = $caldav->Request('GET', $xhref2);
    $self->assert($res->{content} =~ m/ORGANIZER/);
    $self->assert($res->{content} =~ m/ATTENDEE/);
}

sub test_calendarevent_attendee_noorganizer
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my ($eventId, $ical) = $self->icalfile('attendee_noorganizer');
    my $event = $self->putandget_vevent($eventId, $ical);
    my $wantParticipants = {
        '29deb29d758dbb27ffa3c39b499edd85b53dd33f' => {
            '@type' => 'Participant',
            'sendTo' => {
                'imip' => 'mailto:attendee@local'
            },
            'roles' => {
                'attendee' => JSON::true
            },
            'participationStatus' => 'needs-action',
            'expectReply' => JSON::false,
            'scheduleSequence' => 0
        }
    };
    $self->assert_deep_equals($wantParticipants, $event->{participants});
    $self->assert_null($event->{replyTo});

    xlog "Update event via JMAP";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    participants => $wantParticipants,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['participants', 'replyTo', 'x-href'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_deep_equals($wantParticipants, $res->[1][1]{list}[0]{participants});
    $self->assert_null($res->[1][1]{list}[0]{replyTo});

    my $xhref = $res->[1][1]{list}[0]{'x-href'};
    $self->assert_not_null($xhref);

    xlog "Validate no ORGANIZER got added";
    $res = $caldav->Request('GET', $xhref);
    $self->assert(not($res->{content} =~ m/ORGANIZER/));
    $self->assert($res->{content} =~ m/ATTENDEE/);

    xlog "Create event with no replyTo via JMAP (should fail)";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    calendarId => 'Default',
                    title => "title",
                    "start"=> "2015-11-07T09:00:00",
                    "duration"=> "PT2H",
                    "timeZone" => "Europe/London",
                    participants => $wantParticipants,
                },
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals(['replyTo', 'participants'],
        $res->[0][1]{notCreated}{1}{properties});
}

sub test_calendarevent_get_organizer_bogusuri
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    # As seen in the wild: an ORGANIZER/ATTENDEE with a value
    # that hasn't even an URI scheme.

    my ($id, $ical) = $self->icalfile('organizer_bogusuri');

    my $event = $self->putandget_vevent($id, $ical);

    my $wantParticipants = {
        '55d3677ce6a79b250d0fc3b5eed5130807d93dd3' => {
            '@type' => 'Participant',
            name => 'Organizer',
            roles => {
                'attendee' => JSON::true,
                'owner' => JSON::true,
            },
            sendTo => {
                other => '/foo-bar/principal/',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
        '29deb29d758dbb27ffa3c39b499edd85b53dd33f' => {
            '@type' => 'Participant',
            roles => {
                'attendee' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:attendee@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
    };
    $self->assert_deep_equals($wantParticipants, $event->{participants});
    $self->assert_null($event->{replyTo}{imip});
    $self->assert_str_equals('/foo-bar/principal/', $event->{replyTo}{other});
}

sub test_calendarevent_get_organizermailto
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('organizermailto');

    my $event = $self->putandget_vevent($id, $ical);

    my $wantParticipants = {
        'bf8360ce374961f497599431c4bacb50d4a67ca1' => {
            '@type' => 'Participant',
            name => 'Organizer',
            roles => {
                'owner' => JSON::true,
                'attendee' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:organizer@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
        '29deb29d758dbb27ffa3c39b499edd85b53dd33f' => {
            '@type' => 'Participant',
            name => 'Attendee',
            roles => {
                'attendee' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:attendee@local',
            },
            expectReply => JSON::false,
            scheduleSequence => 0,
            participationStatus => 'needs-action',
        },
    };
    $self->assert_deep_equals($wantParticipants, $event->{participants});
}

sub test_calendarevent_get_recurrence
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('recurrence');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event->{recurrenceRule});
    $self->assert_str_equals("RecurrenceRule", $event->{recurrenceRule}{q{@type}});
    $self->assert_str_equals("monthly", $event->{recurrenceRule}{frequency});
    $self->assert_str_equals("gregorian", $event->{recurrenceRule}{rscale});
    # This assertion is a bit brittle. It depends on the libical-internal
    # sort order for BYDAY
    $self->assert_deep_equals([{
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
            }], $event->{recurrenceRule}{byDay});
}

sub test_calendarevent_get_rdate_period
    :min_version_3_1 :needs_component_jmap
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('recurrenceoverrides');
    my $aid = $id . "-alarmuid";

    my $event = $self->putandget_vevent($id, $ical);
    my $o;

    $o = $event->{recurrenceOverrides}->{"2016-12-24T20:00:00"};
    $self->assert_not_null($o);

    $self->assert(exists $event->{recurrenceOverrides}->{"2016-02-01T13:00:00"});
    $self->assert_equals(JSON::true, $event->{recurrenceOverrides}->{"2016-02-01T13:00:00"}{excluded});

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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('alerts');

    my $alerts = {
        '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-1' => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => "start",
                offset => "-PT5M",
            },
            action => "email",
        },
        '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-2' => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'AbsoluteTrigger',
                when => "2016-09-28T13:55:00Z",
            },
            acknowledged => "2016-09-28T14:00:05Z",
            action => "display",
        },
        '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-3' => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => "start",
                offset => "PT10M",
            },
            action => "display",
        },
        '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-3-snoozed1' => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'AbsoluteTrigger',
                when => '2016-09-28T15:00:05Z',
            },
            action => "display",
            relatedTo => {
                '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-3' => {
                    '@type' => 'Relation',
                    relation => {
                        parent => JSON::true,
                    },
                }
            },
        },
        '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-3-snoozed2' => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'AbsoluteTrigger',
                when => '2016-09-28T15:00:05Z',
            },
            action => "display",
            relatedTo => {
                '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-3' => {
                    '@type' => 'Relation',
                    relation => {}
                },
            },
        },
        '0CF835D0-CFEB-44AE-904A-C26AB62B73BB-4' => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'AbsoluteTrigger',
                when => '1976-04-01T00:55:45Z',
            },
            action => "display",
        },
    };

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_str_equals(JSON::true, $event->{useDefaultAlerts});
    $self->assert_deep_equals($alerts, $event->{alerts});
}

sub test_calendarevent_get_locations
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("A location with a comma,\nand a newline.", $locations[0]{name});
}

sub test_calendarevent_get_locations_uri
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-uri');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    my $links = $event->{links};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("On planet Earth", $locations[0]{name});

    my @linkIds = keys %{$locations[0]{linkIds}};
    $self->assert_num_equals(1, scalar @linkIds);
    $self->assert_equals("skype:foo", $links->{$linkIds[0]}->{href});
}

sub test_calendarevent_get_locations_geo
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-geo');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("geo:37.386013,-122.082930", $locations[0]{coordinates});
}

sub test_calendarevent_get_locations_apple
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-apple');

    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values %{$event->{locations}};
    $self->assert_num_equals(1, scalar @locations);
    $self->assert_str_equals("a place in Vienna", $locations[0]{name});
    $self->assert_str_equals("geo:48.208304,16.371602", $locations[0]{coordinates});
}

sub test_calendarevent_get_virtuallocations_conference
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('locations-conference');

    my $event = $self->putandget_vevent($id, $ical);
    my $virtualLocations = $event->{virtualLocations};
    $self->assert_num_equals(2, scalar (values %{$virtualLocations}));

    my $loc1 = $virtualLocations->{loc1};
    $self->assert_str_equals('Moderator dial-in', $loc1->{name});
    $self->assert_str_equals('tel:+123451', $loc1->{uri});

    my $loc2 = $virtualLocations->{loc2};
    $self->assert_str_equals('Chat room', $loc2->{name});
    $self->assert_str_equals('xmpp:chat123@conference.example.com', $loc2->{uri});
}

sub createandget_event
{
    my ($self, $event, %params) = @_;

    my $jmap = $self->{jmap};
    my $accountId = $params{accountId} || 'cassandane';

    xlog $self, "create event";
    my $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => $accountId,
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub updateandget_event
{
    my ($self, $event) = @_;

    my $jmap = $self->{jmap};
    my $id = $event->{id};

    xlog $self, "update event $id";
    my $res = $jmap->CallMethods([['CalendarEvent/set', {update => {$id => $event}}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    return $ret;
}

sub createcalendar
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    return $res->[0][1]{created}{"1"}{id};
}

sub test_calendarevent_set_type
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
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
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "priority" => 9,
        "locale" => "en",
        "color" => "turquoise",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "participants" => undef,
        "alerts"=> undef,
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    $self->assert_num_equals(42, $event->{sequence});
}

sub test_calendarevent_set_subseconds
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    # subseconds were deprecated in 3.5 but included as experimental in 3.4

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        calendarId => $calid,
        uid => "58ADE31-custom-UID",
        title => "subseconds",
        start => "2011-12-04T04:05:06.78",
        created => "2019-06-29T11:58:12.412Z",
        updated => "2019-06-29T11:58:12.412Z",
        duration=> "PT5M3.45S",
        timeZone=> "Europe/Vienna",
        recurrenceRule => {
            '@type' => 'RecurrenceRule',
            frequency => "daily",
            until => '2011-12-10T04:05:06.78',
        },
        "replyTo" => {
            "imip" => 'mailto:foo@local',
        },
        "participants" => {
            'foo' => {
                '@type' => 'Participant',
                name => 'Foo',
                email => 'foo@local',
                roles => {
                    owner => JSON::true,
                    attendee => JSON::true,
                },
                sendTo => {
                    imip => 'mailto:foo@local',
                },
                scheduleSequence => 1,
                scheduleUpdated => '2018-07-06T05:03:02.123Z',
            },
        },
        alerts => {
            alert1 => {
                trigger => {
                    '@type' => 'OffsetTrigger',
                    relativeTo => "start",
                    offset => "-PT5M0.7S",
                },
                acknowledged => "2015-11-07T08:57:00.523Z",
                action => "display",
            },
        },
        recurrenceOverrides => {
            '2011-12-05T04:05:06.78' => {
                title => "overridden event"
            },
            '2011-12-06T04:05:06.78' => {
                excluded => JSON::true
            },
            '2011-12-07T11:00:00.99' => {},
            '2011-12-08T04:05:06.78' => {
                title => "overridden event with DTEND",
                duration => 'PT1H2.345S',
                locations => {
                    endLocation => {
                        '@type' => 'Location',
                        name => 'end location in another timezone',
                        relativeTo => 'end',
                        timeZone => 'Europe/London',
                    }
                },
            },
        },
    };

    my $ret = $self->createandget_event($event);

    # Known regresion: recurrenceRule.until
    $self->assert_str_equals('2011-12-10T04:05:06',
        $ret->{recurrenceRule}{until});
    $ret->{recurrenceRule}{until} = '2011-12-10T04:05:06.78';

    # Known regression: participant.scheduleUpdated
    $self->assert_str_equals('2018-07-06T05:03:02Z',
        $ret->{participants}{foo}{scheduleUpdated});
    $ret->{participants}{foo}{scheduleUpdated} = '2018-07-06T05:03:02.123Z';

    $self->assert_str_equals($event->{created}, $ret->{created});
    $self->assert_str_equals($event->{updated}, $ret->{updated});
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_bymonth
    :min_version_3_1 :needs_component_jmap
{
        my ($self) = @_;

        my $jmap = $self->{jmap};
        my $calid = "Default";

        my $event =  {
                "calendarId"=> $calid,
                "start"=> "2010-02-12T00:00:00",
                "recurrenceRule"=> {
                        "frequency"=> "monthly",
                        "interval"=> 13,
                        "byMonth"=> [
                                "4L"
                        ],
                        "count"=> 3,
                },
                "\@type"=> "jsevent",
                "title"=> "",
                "description"=> "",
                "locations"=> undef,
                "links"=> undef,
                "showWithoutTime"=> JSON::false,
                "duration"=> "PT0S",
                "timeZone"=> undef,
                "recurrenceOverrides"=> undef,
                "status"=> "confirmed",
                "freeBusyStatus"=> "busy",
                "replyTo"=> undef,
                "participants"=> undef,
                "participantId"=> undef,
                "useDefaultAlerts"=> JSON::false,
                "alerts"=> undef
        };

        my $ret = $self->createandget_event($event);
        $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_relatedto
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE31-custom-UID",
        "relatedTo" => {
            "uid1" => { relation => {
                'first' => JSON::true,
            }},
            "uid2" => { relation => {
                'parent' => JSON::true,
            }},
            "uid3" => { relation => {
                'x-unknown1' => JSON::true,
                'x-unknown2' => JSON::true
            }},
            "uid4" => { relation => {} },
        },
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "participants" => undef,
        "alerts"=> undef,
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    $self->assert_num_equals(42, $event->{sequence});
}

sub test_calendarevent_set_prodid
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
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
    $self->assert_str_equals($prodId, $ret->{prodId});
}

sub test_calendarevent_set_endtimezone
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "prodId" => "foo",
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($event, $ret);

    $event->{locations} = {
        "loc1" => {
            "timeZone" => "Europe/Berlin",
            "relativeTo" => "end",
        },
    };
    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarId => $event->{calendarId},
            locations => $event->{locations},
    });

    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_keywords
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "keywords" => {
            'foo' => JSON::true,
            'bar' => JSON::true,
            'baz' => JSON::true,
        },
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_keywords_patch
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "keywords" => {
            'foo' => JSON::true,
            'bar' => JSON::true,
            'baz' => JSON::true,
        },
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    my $eventId = $ret->{id};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'keywords/foo' => undef,
                    'keywords/bam' => JSON::true,
                },
            },
       }, 'R1'],
       ['CalendarEvent/get', {
            ids => [$eventId],
       }, 'R2'],
   ]);
   $self->assert(exists $res->[0][1]{updated}{$eventId});
   $ret = $res->[1][1]{list}[0];
   $self->assert_not_null($ret);

   delete $event->{keywords}{foo};
   $event->{keywords}{bam} = JSON::true;
   $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_endtimezone_recurrence
    :min_version_3_1 :needs_component_jmap
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
                "relativeTo" => "end",
            },
        },
        "showWithoutTime"=> JSON::false,
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
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_htmldescription
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "description"=> '<html><body>HTML with special chars : and ; and "</body></html>',
        "descriptionContentType" => 'text/html',
        "privacy" => "secret",
    };

    # This actually tests that Cyrus doesn't support HTML descriptions!
    my $res = $jmap->CallMethods([['CalendarEvent/set', {
        create => { "1" => $event, }
    }, "R1"]]);
    $self->assert_str_equals("invalidProperties", $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals("descriptionContentType", $res->[0][1]{notCreated}{"1"}{properties}[0]);
}

sub test_calendarevent_set_links
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "links" => {
            "spec" => {
                href => "http://jmap.io/spec.html#calendar-events",
                title => "the spec",
                rel => "enclosure",
            },
            "rfc5545" => {
               href => "https://tools.ietf.org/html/rfc5545",
               rel => "describedby",
            },
            "image" => {
               href => "https://foo.local/favicon.png",
               rel => "icon",
               cid => '123456789asd',
               display => 'badge',
            },
            "attach" => {
               href => "http://example.com/some.url",
               rel => "enclosure",
            },
        },
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_locations
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $locations = {
        # A couple of sparse locations
        locA => {
            name => "location A",
            description => "my great description",
        },
        locB => {
            name => "location B",
        },
        locC => {
            coordinates => "geo:48.208304,16.371602",
            name => "a place in Vienna",
        },
        locD => {
            coordinates => "geo:48.208304,16.371602",
        },
        locE => {
            name => "location E",
            linkIds => {
                'link1' => JSON::true,
                'link2' => JSON::true,
            },
        },
        # A full-blown location
        locG => {
            name => "location G",
            description => "a description",
            timeZone => "Europe/Vienna",
            coordinates => "geo:48.2010,16.3695,183",
            linkIds => {
                'link1' => JSON::true,
                'link2' => JSON::true,
            },
        },
        # A location with name that needs escaping
        locH => {
            name => "location H,\nhas funny chars.",
            description => "some boring\tdescription",
            timeZone => "Europe/Vienna",
        },
    };
    my $virtualLocations = {
        locF => {
            name => "location F",
            description => "a description",
            uri => "https://somewhere.local",
        },
    };

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "free",
        "locations" => $locations,
        "virtualLocations" => $virtualLocations,
        "links" => {
            link1 => { href => 'https://foo.local', rel => "enclosure" },
            link2 => { href => 'https://bar.local', rel => "enclosure" },
        },
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "recurrenceRule" => $recurrence,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $self->assert_normalized_event_equals($event, $ret);

    # Now delete the recurrence rule
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set',{
            update => {
                $event->{id} => {
                    recurrenceRule => undef,
                },
            },
        }, "R1"],
        ['CalendarEvent/get',{
            ids => [$event->{id}],
        }, "R2"],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$event->{id}});

    delete $event->{recurrenceRule};
    $ret = $res->[1][1]{list}[0];
    $self->assert_normalized_event_equals($event, $ret);
}


sub test_calendarevent_set_recurrenceoverrides
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "locations" => {
            locA => {
                "name" => "location A",
            },
            locB => {
                "coordinates" => "geo:48.208304,16.371602",
            },
        },
        "links" => {
            "link1" => {
                href => "http://jmap.io/spec.html#calendar-events",
                title => "the spec",
                rel => 'enclosure',
            },
            "link2" => {
                href => "https://tools.ietf.org/html/rfc5545",
                rel => 'enclosure',
            },
        },
        "recurrenceRule" => $recurrence,
        "recurrenceOverrides" => {
            "2016-02-01T09:00:00" => { excluded => JSON::true },
            "2016-02-03T09:00:00" => {},
            "2016-04-01T10:00:00" => {
                "description" => "don't come in without an April's joke!",
                "locations/locA/name" => "location A exception",
                "links/link2/title" => "RFC 5545",
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
    $self->assert_normalized_event_equals($event, $ret);

    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarId => $event->{calendarId},
            title => "updated title",
    });
    $event->{title} = "updated title";
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence_until
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $event = {
        "status" =>"confirmed",
        "calendarId" => $calid,
        "showWithoutTime" => JSON::false,
        "timeZone" => "America/New_York",
        "freeBusyStatus" =>"busy",
        "start" =>"2019-01-12T00:00:00",
        "useDefaultAlerts" => JSON::false,
        "uid" =>"76f46024-7284-4701-b93f-d9cd812f3f43",
        "title" =>"timed event with non-zero time until",
        "\@type" =>"jsevent",
        "recurrenceRule" =>{
            "frequency" =>"weekly",
            "until" =>"2019-04-20T23:59:59"
        },
        "description" =>"",
        "duration" =>"P1D"
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{recurrenceRule}->{until} = '2019-04-20T23:59:59';
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence_untilallday
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $event = {
        "status" =>"confirmed",
        "calendarId" => $calid,
        "showWithoutTime" => JSON::false, # for testing
        "timeZone" =>undef,
        "freeBusyStatus" =>"busy",
        "start" =>"2019-01-12T00:00:00",
        "useDefaultAlerts" => JSON::false,
        "uid" =>"76f46024-7284-4701-b93f-d9cd812f3f43",
        "title" =>"allday event with non-zero time until",
        "\@type" =>"jsevent",
        "recurrenceRule" =>{
            "frequency" =>"weekly",
            "until" =>"2019-04-20T23:59:59"
        },
        "description" =>"",
        "duration" =>"P1D"
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence_bymonthday
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

	my $event =  {
		"uid" => "90c2697e-acbc-4508-9e72-6b8828e8d9f3",
		"calendarId" => $calid,
		"start" => "2019-01-31T09:00:00",
		"duration" => "PT1H",
		"timeZone" => "Australia/Melbourne",
		"\@type" => "jsevent",
		"title" => "Recurrence test",
		"description" => "",
		"showWithoutTime" => JSON::false,
		"recurrenceRule" => {
			"frequency" => "monthly",
			"byMonthDay" => [
				-1
			]
		},
	};

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence_patch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "Create a recurring event with alert";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create =>  {
                1 => {
                    "calendarId" => 'Default',
                    "title"=> "title",
                    "description"=> "description",
                    "start"=> "2019-01-01T09:00:00",
                    "duration"=> "PT1H",
                    "timeZone" => "Europe/London",
                    "showWithoutTime"=> JSON::false,
                    "freeBusyStatus"=> "busy",
                    "recurrenceRule" => {
                        frequency => 'monthly',
                    },
                    "recurrenceOverrides" => {
                        '2019-02-01T09:00:00' => {
                            duration => 'PT2H',
                        },
                    },
                    alerts => {
                        alert1 => {
                            trigger => {
                                relativeTo => "start",
                                offset => "-PT5M",
                            },
                        },
                    }
                }
            }
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);

    xlog $self, "Patch alert in a recurrence override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2019-02-01T09:00:00/alerts/alert1/trigger/offset' => '-PT10M',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
}

sub test_calendarevent_set_participants
    :min_version_3_4 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => {
            "imip" => "mailto:foo\@local",
            "web" => "http://local/rsvp",

        },
        participantId => 'foo',
        "participants" => {
            'foo' => {
                name => 'Foo',
                kind => 'individual',
                roles => {
                    'owner' => JSON::true,
                    'attendee' => JSON::true,
                    'chair' => JSON::true,
                },
                locationId => 'loc1',
                participationStatus => 'accepted',
                expectReply => JSON::false,
                linkIds => {
                    'link1' => JSON::true,
                },
                participationComment => 'Sure; see you "soon"!',
                sendTo => {
                    imip => 'mailto:foo@local',
                },
            },
            'bar' => {
                name => 'Bar',
                kind => 'individual',
                roles => {
                    'attendee' => JSON::true,
                },
                locationId => 'loc2',
                participationStatus => 'needs-action',
                expectReply => JSON::true,
                delegatedTo => {
                    'bam' => JSON::true,
                },
                memberOf => {
                    'group' => JSON::true,
                },
                linkIds => {
                    'link1' => JSON::true,
                },
                email => 'bar2@local', # different email than sendTo
                sendTo => {
                    imip => 'mailto:bar@local',
                },
            },
            'bam' => {
                name => 'Bam',
                roles => {
                    'attendee' => JSON::true,
                },
                delegatedFrom => {
                    'bar' => JSON::true,
                },
                scheduleSequence => 7,
                scheduleUpdated => '2018-07-06T05:03:02Z',
                email => 'bam@local', # same email as sendTo
                sendTo => {
                    imip => 'mailto:bam@local',
                },
            },
            'group' => {
                name => 'Group',
                kind => 'group',
                roles => {
                    'attendee' => JSON::true,
                },
                email => 'group@local',
                sendTo => {
                    'imip' => 'mailto:groupimip@local',
                    'other' => 'tel:+1-123-5555-1234',
                },
            },
            'resource' => {
                name => 'Some resource',
                kind => 'resource',
                roles => {
                    'attendee' => JSON::true,
                },
                sendTo => {
                    imip => 'mailto:resource@local',
                },
            },
            'location' => {
                name => 'Some location',
                kind => 'location',
                roles => {
                    'attendee' => JSON::true,
                },
                locationId => 'loc1',
                sendTo => {
                    imip => 'mailto:location@local',
                },
            },
        },
        locations => {
            loc1 => {
                name => 'location1',
            },
            loc2 => {
                name => 'location2',
            },
        },
        links => {
            link1 => {
                href => 'https://somelink.local',
                rel => "enclosure",
            },
        },
        method => 'request',
    };

    my $ret = $self->createandget_event($event);
    $event->{participants}{foo}{sendTo} = { imip => 'mailto:foo@local' };
    delete $event->{method};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_participants_patch
    :min_version_3_4 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => {
            "imip" => "mailto:foo\@local",
        },
        "participants" => {
            'bar' => {
                name => 'Bar',
                roles => {
                    'attendee' => JSON::true,
                },
                participationStatus => 'needs-action',
                expectReply => JSON::true,
                sendTo => {
                    imip => 'mailto:bar@local',
                },
            },
        },
        method => 'request',
    };

    my $ret = $self->createandget_event($event);
    delete $event->{method};

    # Add auto-generated owner participant for ORGANIZER.
    $event->{participants}{'3e6a0e46cc0af22aff762f2e1869f23de7aca482'} = {
        roles => {
            'owner' => JSON::true,
        },
        sendTo => {
            imip => 'mailto:foo@local',
        },
    };
    $self->assert_normalized_event_equals($event, $ret);
    my $eventId = $ret->{id};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'participants/bar/participationStatus' => 'accepted',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $event->{participants}{'bar'}{participationStatus} = 'accepted';
    $ret = $res->[1][1]{list}[0];
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_participants_organame
    :min_version_3_4 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => {
            "imip" => "mailto:foo\@local",
        },
        "participants" => {
            'foo' => {
                '@type' => 'Participant',
                name => 'Foo',
                roles => {
                    'owner' => JSON::true,
                },
                sendTo => {
                    imip => 'mailto:foo@local',
                },
            },
            'bar' => {
                '@type' => 'Participant',
                name => 'Bar',
                kind => 'individual',
                roles => {
                    'attendee' => JSON::true,
                },
                sendTo => {
                    imip => 'mailto:bar@local',
                },
            },
        },
    };

    my $ret = $self->createandget_event($event);
    $event->{participants}{bar}{sendTo}{imip} = 'mailto:bar@local';
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_alerts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $alerts = {
        alert1 => {
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => "start",
                offset => "-PT5M",
            },
            acknowledged => "2015-11-07T08:57:00Z",
            action => "email",
        },
        alert2 => {
            trigger => {
                '@type' => 'AbsoluteTrigger',
                when => "2019-03-04T04:05:06Z",
            },
            action => "display",
            relatedTo => {
                'alert1' => {
                    relation => {
                        'parent' => JSON::true,
                    },
                },
            },
        },
        alert3 => {
            trigger => {
                '@type' => 'OffsetTrigger',
                offset => "PT1S",
            }
        },
        alert4 => {
            trigger => {
                '@type' => 'AbsoluteTrigger',
                when => "2019-03-04T05:06:07Z",
            },
            action => "display",
            relatedTo => {
                'alert1' => {
                    relation => { },
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
        "showWithoutTime"=> JSON::false,
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

sub test_calendarevent_set_alerts_description
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 =>  {
                    calendarId => 'Default',
                    title => 'title',
                    description => 'description',
                    start => '2015-11-07T09:00:00',
                    alerts =>  {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                },
                2 =>  {
                    calendarId => 'Default',
                    description => 'description',
                    start => '2016-11-07T09:00:00',
                    alerts =>  {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                },
                3 =>  {
                    calendarId => 'Default',
                    start => '2017-11-07T09:00:00',
                    alerts =>  {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $blobId1 = $res->[0][1]{created}{1}{'blobId'};
    $self->assert_not_null($blobId1);

    my $blobId2 = $res->[0][1]{created}{2}{'blobId'};
    $self->assert_not_null($blobId2);

    my $blobId3 = $res->[0][1]{created}{3}{'blobId'};
    $self->assert_not_null($blobId3);

    $res = $jmap->Download('cassandane', $blobId1);
    $self->assert($res->{content} =~ /BEGIN:VALARM[\s\S]+DESCRIPTION:title[\s\S]+END:VALARM/g);

    $res = $jmap->Download('cassandane', $blobId2);
    $self->assert($res->{content} =~ /BEGIN:VALARM[\s\S]+DESCRIPTION:description[\s\S]+END:VALARM/g);

    $res = $jmap->Download('cassandane', $blobId3);
    $self->assert($res->{content} =~ /BEGIN:VALARM[\s\S]+DESCRIPTION:reminder[\s\S]+END:VALARM/g);
}

sub test_calendarevent_set_participantid
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $participants = {
        "foo" => {
            email => 'foo@local',
            roles => {
                'attendee' => JSON::true,
            },
            locationId => "locX",
            sendTo => {
                imip => 'mailto:foo@local',
            },
        },
        "you" => {
            name => "Cassandane",
            email => 'cassandane@example.com',
            roles => {
                'owner' => JSON::true,
                'attendee' => JSON::true,
            },
            sendTo => {
                imip => 'mailto:cassandane@example.com',
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => { imip => "mailto:cassandane\@example.com" },
        "participants" => $participants,
        "participantId" => 'you',
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarId} = $ret->{calendarId};
    $event->{participantId} = 'you';

    $self->assert_normalized_event_equals($event, $ret);

    # check that we can fetch again a second time and still have the same data
    my $res = $jmap->CallMethods([['CalendarEvent/get', { ids => [ $event->{id} ] }, 'R1']]);
    $self->assert_normalized_event_equals($event, $res->[0][1]{list}[0]);
}

sub test_calendarevent_set_participants_justorga
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "status" => "confirmed",
        "replyTo" => {
            "imip" => "mailto:foo\@local",
        },
        participantId => 'foo',
        "participants" => {
            'foo' => {
                '@type' => 'Participant',
                name => 'Foo',
                roles => {
                    'owner' => JSON::true,
                },
                "sendTo" => {
                    "imip" => "mailto:foo\@local",
                },
                email => 'foo@local',
                participationStatus => 'needs-action',
                scheduleSequence => 0,
                expectReply => JSON::false,
            },
        },
    };

    my $ret = $self->createandget_event($event);
    delete $event->{method};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_created
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    my $eventId = $ret->{id};
    my $created = $ret->{created};
    $self->assert_not_null($created);
    my $updated = $ret->{updated};
    $self->assert_not_null($updated);

    sleep 1;

    # Created is preserved, updated isn't.
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'bar',
                },
            },
       }, 'R1'],
       ['CalendarEvent/get', {
            ids => [$eventId],
       }, 'R2'],
   ]);
   $self->assert(exists $res->[0][1]{updated}{$eventId});
   $ret = $res->[1][1]{list}[0];
   $self->assert_str_equals($created, $ret->{created});
   $self->assert_str_not_equals($updated, $ret->{updated});

   # Client can overwrite created and updated
   $created = '2015-01-01T00:00:01Z';
   $updated = '2015-01-01T00:00:02Z';
   $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    created => $created,
                    updated => $updated
                },
            },
       }, 'R1'],
       ['CalendarEvent/get', {
            ids => [$eventId],
       }, 'R2'],
   ]);
   $self->assert(exists $res->[0][1]{updated}{$eventId});
   $ret = $res->[1][1]{list}[0];
   $self->assert_str_equals($created, $ret->{created});
   $self->assert_str_equals($updated, $ret->{updated});
}

sub test_calendarevent_set_move
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendars A and B";
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

    xlog $self, "create event in calendar $calidA";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "foo's description",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        }
                    }}, "R1"]]);
    my $state = $res->[0][1]{newState};
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get calendar $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_str_equals($calidA, $event->{calendarId});
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog $self, "move event to unknown calendar";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id => {
                            "calendarId" => "nope",
                        }
                    }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals($state, $res->[0][1]{newState});

    xlog $self, "get calendar $id from untouched calendar $calidA";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_str_equals($calidA, $event->{calendarId});

    xlog $self, "move event to calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id => {
                            "calendarId" => $calidB,
                        }
                    }}, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $state = $res->[0][1]{newState};

    xlog $self, "get calendar $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_str_equals($calidB, $event->{calendarId});
}

sub test_calendarevent_set_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
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

    xlog $self, "create calendar";
    my $CalendarId1 = $mantalk->NewCalendar({name => 'Manifold Calendar'});
    $self->assert_not_null($CalendarId1);

    xlog $self, "share $CalendarId1 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lr') or die;

    my $event =  {
        "calendarId" => $CalendarId1,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "participants" => undef,
        "alerts" => {
            'foo' => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'OffsetTrigger',
                    relativeTo => "start",
                    offset => "-PT5M",
                },
                action => "email"
            }
        }
    };

    my $event2 =  {
        "calendarId" => $CalendarId1,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo2",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "participants" => undef,
        "alerts" => {
            'foo' => {
                trigger => {
                    '@type' => 'OffsetTrigger',
                    relativeTo => "start",
                    offset => "-PT5M",
                },
                action => "email"
            }
        }
    };

    xlog $self, "create event (should fail)";
    my $res = $jmap->CallMethods([['CalendarEvent/set',{
                    accountId => 'manifold',
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{notCreated}{1});

    xlog $self, "share $CalendarId1 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "create event";
    $res = $jmap->CallMethods([['CalendarEvent/set',{
                    accountId => 'manifold',
                    create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {
                    accountId => 'manifold',
                    ids => [$id]},
    "R1"]]);
    my $ret = $res->[0][1]{list}[0];
    $self->assert_normalized_event_equals($event, $ret);

    xlog $self, "update event";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId1,
                            "title" => "foo2",
                        },
    }}, "R1"]]);
    $self->assert_not_null($res->[0][1]{updated});

    xlog $self, "get calendar event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {
                    accountId => 'manifold',
                    ids => [$id]},
    "R1"]]);
    $ret = $res->[0][1]{list}[0];
    $self->assert_normalized_event_equals($event2, $ret);

    xlog $self, "share $CalendarId1 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lr') or die;

    xlog $self, "update event (should fail)";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId1,
                            "title" => "1(updated)",
                        },
    }}, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});

    xlog $self, "share calendar home read-writable to user";
    $admintalk->setacl("user.manifold.#calendars", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "create another calendar";
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

    xlog $self, "share $CalendarId1 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId1", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "share $CalendarId2 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lr') or die;

    xlog $self, "move event (should fail)";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId2,
                            "title" => "1(updated)",
                        },
    }}, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});

    xlog $self, "share $CalendarId2 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "move event";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    update => {
                        $id => {
                            "calendarId" => $CalendarId2,
                            "title" => "1(updated)",
                        },
    }}, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog $self, "share $CalendarId2 read-only to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lr') or die;

    xlog $self, "destroy event (should fail)";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    destroy => [ $id ],
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notDestroyed}{$id});

    xlog $self, "share $CalendarId2 read-writable to user";
    $admintalk->setacl("user.manifold.#calendars.$CalendarId2", "cassandane" => 'lrswipkxtecdn') or die;

    xlog $self, "destroy event";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    accountId => 'manifold',
                    destroy => [ $id ],
    }, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}


sub test_calendarevent_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendars A and B";
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

    xlog $self, "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        },
                        "2" => {
                            "calendarId" => $calidB,
                            "title" => "2",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "get zero calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', {sinceState => $state}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "update event #1 and #2";
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

    xlog $self, "get exactly one update";
    $res = $jmap->CallMethods([['CalendarEvent/changes', {
                    sinceState => $state,
                    maxChanges => 1
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::true, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "get the final update";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "update event #1 and destroy #2";
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

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id1, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id2, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "get zero calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', {sinceState => $state}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "move event #1 from calendar $calidA to $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    update => {
                        $id1 => {
                            "calendarId" => $calidB,
                        },
                    }
                }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{updated}});

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($id1, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};

    xlog $self, "update and remove event #1";
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

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $state = $res->[0][1]{newState};
}

sub test_calendarevent_changes_issue2558
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "get calendar event updates with bad state";
    my $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => 'nonsense' }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('R1', $res->[0][2]);

    xlog $self, "get calendar event updates without state";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_calendarevent_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendars A and B";
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

    xlog $self, "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "bar",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
                            "start" => "2016-07-01T10:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                        "2" => {
                            "calendarId" => $calidB,
                            "title" => "foo",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2016-01-01T00:00:00",
                            "duration" => "P2D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "get unfiltered calendar event list";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "get filtered calendar event list with flat filter";
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

    xlog $self, "get filtered calendar event list";
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

    xlog $self, "filter by calendar $calidA";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "inCalendars" => [ $calidA ],
                    }
                }, "R1"] ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

    xlog $self, "filter by calendar $calidA or $calidB";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "inCalendars" => [ $calidA, $calidB ],
                    }
                }, "R1"] ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter by calendar NOT in $calidA and $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "operator" => "NOT",
                        "conditions" => [{
                                "inCalendars" => [ $calidA, $calidB ],
                            }],
                    }}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{ids}});

    xlog $self, "limit results";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { limit => 1 }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});

    xlog $self, "skip result a position 1";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { position => 1 }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});

    xlog $self, "set negative position";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', { position => -1 }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
}

sub test_calendarevent_query_deleted_calendar
    :min_version_3_3 :needs_component_jmap :needs_component_httpd
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendars A and B";
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

    xlog $self, "create event #1 in calendar $calidA and event #2 in calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', {
                    create => {
                        "1" => {
                            "calendarId" => $calidA,
                            "title" => "foo",
                            "description" => "bar",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
                            "start" => "2016-07-01T10:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                        "2" => {
                            "calendarId" => $calidB,
                            "title" => "foo",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2016-01-01T00:00:00",
                            "duration" => "P2D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "get filtered calendar event list";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "after" => "2015-12-31T00:00:00Z",
                        "before" => "2016-12-31T23:59:59Z"
                    }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "CalDAV delete calendar as cassandane";
    $caldav->DeleteCalendar("/dav/calendars/user/cassandane/$calidA");

    xlog $self, "get filtered calendar event list";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "after" => "2015-12-31T00:00:00Z",
                        "before" => "2016-12-31T23:59:59Z"
                    }
                }, "R1"] ]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($id2, $res->[0][1]{ids}[0]);
}

sub test_calendarevent_query_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();

    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared account";
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

    xlog $self, "share calendar home to user";
    $admintalk->setacl("user.manifold.#calendars", cassandane => 'lrswipkxtecdn');

    # run tests for both the main and shared account
    foreach ("cassandane", "manifold") {
        my $account = $_;

        xlog $self, "create calendars A and B";
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

        if ($account eq 'manifold') {
            $admintalk->setacl("user.manifold.#calendars.$calidA", cassandane => 'lrswipkxtecdn');
            $admintalk->setacl("user.manifold.#calendars.$calidB", cassandane => 'lrswipkxtecdn');
        }

        xlog $self, "create event #1 in calendar $calidA and event #2 in calendar $calidB";
        $res = $jmap->CallMethods([['CalendarEvent/set', {
                        accountId => $account,
                        create => {
                            "1" => {
                                "calendarId" => $calidA,
                                "title" => "foo",
                                "description" => "bar",
                                "freeBusyStatus" => "busy",
                                "showWithoutTime" => JSON::false,
                                "start" => "2016-07-01T10:00:00",
                                "timeZone" => "Europe/Vienna",
                                "duration" => "PT1H",
                            },
                            "2" => {
                                "calendarId" => $calidB,
                                "title" => "foo",
                                "description" => "",
                                "freeBusyStatus" => "busy",
                                "showWithoutTime" => JSON::true,
                                "start" => "2016-01-01T00:00:00",
                                "duration" => "P2D",
                            }
                        }}, "R1"]]);
        my $id1 = $res->[0][1]{created}{"1"}{id};
        my $id2 = $res->[0][1]{created}{"2"}{id};

        xlog $self, "Run squatter";
        $self->{instance}->run_command({cyrus => 1}, 'squatter');

        xlog $self, "get unfiltered calendar event list";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', { accountId => $account }, "R1"] ]);
        $self->assert_num_equals(2, $res->[0][1]{total});
        $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($account, $res->[0][1]{accountId});

        xlog $self, "get filtered calendar event list with flat filter";
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

        xlog $self, "get filtered calendar event list";
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

        xlog $self, "filter by calendar $calidA";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "inCalendars" => [ $calidA ],
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

        xlog $self, "filter by calendar $calidA or $calidB";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "inCalendars" => [ $calidA, $calidB ],
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

        xlog $self, "filter by calendar NOT in $calidA and $calidB";
        $res = $jmap->CallMethods([['CalendarEvent/query', {
                        accountId => $account,
                        "filter" => {
                            "operator" => "NOT",
                            "conditions" => [{
                                    "inCalendars" => [ $calidA, $calidB ],
                                }],
                        }}, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]{ids}});

        xlog $self, "limit results";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', { accountId => $account, limit => 1 }, "R1"] ]);
        $self->assert_num_equals(2, $res->[0][1]{total});
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});

        xlog $self, "skip result a position 1";
        $res = $jmap->CallMethods([ ['CalendarEvent/query', { accountId => $account, position => 1 }, "R1"] ]);
        $self->assert_num_equals(2, $res->[0][1]{total});
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    }
}

sub test_calendarevent_query_datetime
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create events";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2016-01-01T08:00:00Z End: 2016-01-01T09:00:00Z
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
                            "start" => "2016-01-01T09:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                    }}, "R1"]]);

    xlog $self, "Run squatter";
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
                            "showWithoutTime" => JSON::false,
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
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create events";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2016-01-01 End: 2016-01-03
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2016-01-01T00:00:00",
                            "duration" => "P3D",
                        },
                    }}, "R1"]]);

    xlog $self, "Run squatter";
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
                            "showWithoutTime" => JSON::true,
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
    :min_version_3_1 :needs_component_jmap
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
                            "showWithoutTime"=> JSON::false,
                            "replyTo" => { imip => "mailto:tux\@local" },
                            "participants" => {
                                "tux" => {
                                    name => "",
                                    roles => {
                                        'owner' => JSON::true,
                                    },
                                    locationId => "loc1",
                                    sendTo => {
                                        imip => 'tux@local',
                                    },
                                },
                                "qux" => {
                                    name => "Quuks",
                                    roles => {
                                        'attendee' => JSON::true,
                                    },
                                    sendTo => {
                                        imip => 'qux@local',
                                    },
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
    $self->assert_not_null($id1);

    xlog $self, "Run squatter";
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
        $self->assert_num_equals(0, $res->[0][1]{total});

        # Assert that search by property name matches
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        "filter" => {
                            $propname => $propval,
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(1, $res->[0][1]{total});
        $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
        $self->assert_str_equals($id1, $res->[0][1]{ids}[0]);

        # Sanity check property name search
        $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                        "filter" => {
                            $propname => "nope",
                        }
                    }, "R1"] ]);
        $self->assert_num_equals(0, $res->[0][1]{total});
    }
}

sub test_calendarevent_query_unixepoch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create events";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
      "1" => {
        "calendarId" => $calid,
        "title" => "Establish first ARPANET link between UCLA and SRI",
        "description" => "",
        "freeBusyStatus" => "busy",
        "showWithoutTime" => JSON::false,
        "start" => "1969-11-21T17:00:00",
        "timeZone" => "America/Los_Angeles",
        "duration" => "PT1H",
      },
    }}, "R1"]]);

    xlog $self, "Run squatter";

    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "1969-01-01T00:00:00Z",
                        "before" => "1969-12-31T23:59:59Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "1949-06-20T00:00:00Z",
                        "before" => "1968-10-14T00:00:00Z",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});
}

sub test_calendarevent_query_sort
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                '1' => {
                    'calendarId' => $calid,
                    'uid' => 'event1uid',
                    'title' => 'event1',
                    'start' => '2019-10-01T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
                '2' => {
                    'calendarId' => $calid,
                    'uid' => 'event2uid',
                    'title' => 'event2',
                    'start' => '2018-10-01T12:00:00',
                    'timeZone' => 'Etc/UTC',
                },
        }
    }, 'R1']]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    my $eventId2 = $res->[0][1]{created}{2}{id};
    $self->assert_not_null($eventId1);
    $self->assert_not_null($eventId2);

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            sort => [{
                property => 'start',
                isAscending => JSON::true,
            }]
        }, 'R1']
    ]);
    $self->assert_deep_equals([$eventId2,$eventId1], $res->[0][1]{ids});

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            sort => [{
                property => 'start',
                isAscending => JSON::false,
            }]
        }, 'R1']
    ]);
    $self->assert_deep_equals([$eventId1,$eventId2], $res->[0][1]{ids});

}

sub test_calendarevent_query_anchor
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                '1' => {
                    'calendarId' => $calid,
                    'uid' => 'event1uid',
                    'title' => 'event1',
                    'start' => '2019-10-01T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
                '2' => {
                    'calendarId' => $calid,
                    'uid' => 'event2uid',
                    'title' => 'event2',
                    'start' => '2019-10-02T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
                '3' => {
                    'calendarId' => $calid,
                    'uid' => 'event3uid',
                    'title' => 'event3',
                    'start' => '2019-10-03T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
        }
    }, 'R1']]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    my $eventId2 = $res->[0][1]{created}{2}{id};
    my $eventId3 = $res->[0][1]{created}{3}{id};
    $self->assert_not_null($eventId1);
    $self->assert_not_null($eventId2);
    $self->assert_not_null($eventId3);

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            sort => [{
                property => 'start',
                isAscending => JSON::true,
            }],
            anchor => $eventId2,
        }, 'R1']
    ]);
    $self->assert_deep_equals([$eventId2,$eventId3], $res->[0][1]{ids});

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            sort => [{
                property => 'start',
                isAscending => JSON::true,
            }],
            anchor => $eventId3,
            anchorOffset => -2,
            limit => 1,
        }, 'R1']
    ]);
    $self->assert_deep_equals([$eventId1], $res->[0][1]{ids});

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            sort => [{
                property => 'start',
                isAscending => JSON::true,
            }],
            anchor => $eventId2,
            anchorOffset => -5,
        }, 'R1']
    ]);
    $self->assert_deep_equals([$eventId1, $eventId2, $eventId3], $res->[0][1]{ids});

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            sort => [{
                property => 'start',
                isAscending => JSON::true,
            }],
            anchor => $eventId2,
            anchorOffset => 5,
        }, 'R1']
    ]);
    $self->assert_deep_equals([], $res->[0][1]{ids});
}


sub test_calendarevent_set_caldav
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                        "1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]]);
    my $calid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "create event in calendar";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "foo",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get x-href of event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    my $xhref = $res->[0][1]{list}[0]{"x-href"};
    my $state = $res->[0][1]{state};

    xlog $self, "GET event $id in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    my $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:foo/, $ical);

    xlog $self, "DELETE event $id via CalDAV";
    $res = $caldav->Request('DELETE', $xhref);

    xlog $self, "get (non-existent) event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{notFound}[0]);

    xlog $self, "get calendar event updates";
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

    xlog $self, "PUT event with UID $id";
    $res = $caldav->Request('PUT', "$calid/$id.ics", $ical, 'Content-Type' => 'text/calendar');

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_equals($id, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "get x-href of event $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $xhref = $res->[0][1]{list}[0]{"x-href"};
    $state = $res->[0][1]{state};

    xlog $self, "update event $id";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        "$id" => {
                            "calendarId" => $calid,
                            "title" => "bam",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-10T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);

    xlog $self, "GET event $id in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:bam/, $ical);

    xlog $self, "destroy event $id";
    $res = $jmap->CallMethods([['CalendarEvent/set', { destroy => [$id] }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_equals($id, $res->[0][1]{destroyed}[0]);

    xlog $self, "PROPFIND calendar $calid for non-existent event $id in CalDAV";
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
    $self->assert_does_not_match(qr{$id}, $res);
}

sub test_calendarevent_set_schedule_request
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $participants = {
        "org" => {
            "name" => "Cassandane",
            roles => {
                'owner' => JSON::true,
            },
            sendTo => {
                imip => 'cassandane@example.com',
            },
        },
        "att" => {
            "name" => "Bugs Bunny",
            roles => {
                'attendee' => JSON::true,
            },
            sendTo => {
                imip => 'bugs@example.com',
            },
        },
    };

    # clean notification cache
    $self->{instance}->getnotify();

    xlog $self, "send invitation as organizer to attendee";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => "Default",
                            "title" => "foo",
                            "description" => "foo's description",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
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
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $participants = {
        "org" => {
            "name" => "Bugs Bunny",
            sendTo => {
                imip => 'mailto:bugs@example.com',
            },
            roles => {
                'owner' => JSON::true,
            },
        },
        "att" => {
            "name" => "Cassandane",
            sendTo => {
                imip => 'mailto:cassandane@example.com',
            },
            roles => {
                'attendee' => JSON::true,
            },
        },
    };

    xlog $self, "create event";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
        "1" => {
            "calendarId" => "Default",
            "title" => "foo",
            "description" => "foo's description",
            "freeBusyStatus" => "busy",
            "showWithoutTime" => JSON::false,
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

    xlog $self, "send reply as attendee to organizer";
    $participants->{att}->{participationStatus} = "tentative";
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

sub test_calendarevent_set_schedule_destroy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    my $calid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "send invitation as organizer";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
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
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    # clean notification cache
    $self->{instance}->getnotify();

    xlog $self, "cancel event as organizer";
    $res = $jmap->CallMethods([['CalendarEvent/set', { destroy => [$id]}, "R1"]]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:CANCEL");
}

sub test_calendarevent_set_schedule_cancel
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => { "1" => {
                            name => "foo", color => "coral", sortOrder => 1, isVisible => \1
             }}}, "R1"]
    ]);
    my $calid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "send invitation as organizer";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
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
                        }
                    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    # clean notification cache
    $self->{instance}->getnotify();

    xlog $self, "cancel event as organizer";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $id => {
                    status => 'cancelled',
                },
            },
        }, 'R1'],
    ]);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals("bugs\@example.com", $payload->{recipient});
    $self->assert($ical =~ "METHOD:CANCEL");
}

sub test_calendarevent_set_schedule_omit
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create event";
    my $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
        "1" => {
            "calendarId" => "Default",
            "title" => "foo",
            "description" => "foo's description",
            "freeBusyStatus" => "busy",
            "showWithoutTime" => JSON::false,
            "start" => "2015-10-06T16:45:00",
            "timeZone" => "Australia/Melbourne",
            "duration" => "PT1H",
            "replyTo" => { imip => "mailto:bugs\@example.com" },
            "participants" => {
                "org" => {
                    "name" => "Bugs Bunny",
                    "email" => "bugs\@example.com",
                     roles => {
                        'owner' => JSON::true,
                    },
                },
                "att" => {
                    "name" => "Cassandane",
                    "email" => "cassandane\@example.com",
                    roles => {
                        'attendee' => JSON::true,
                    },
                },
            },
        }
    }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    # clean notification cache
    $self->{instance}->getnotify();

    # delete event as attendee without setting any partstat.
    $res = $jmap->CallMethods([['CalendarEvent/set', {
        destroy => [$id],
    }, "R1"]]);

    # assert no notification is sent.
    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($imip);
}

sub test_misc_creationids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create and get calendar and event";
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
            "showWithoutTime" => JSON::true,
            "start" => "2015-10-06T00:00:00",
        }}}, "R2"],
        ['CalendarEvent/get', {ids => ["#e1"]}, "R3"],
        ['Calendar/get', {ids => ["#c1"]}, "R4"],
    ]);
    my $event = $res->[2][1]{list}[0];
    $self->assert_str_equals("bar", $event->{title});

    my $calendar = $res->[3][1]{list}[0];
    $self->assert_str_equals("foo", $calendar->{name});

    $self->assert_str_equals($calendar->{id}, $event->{calendarId});
}

sub test_misc_timezone_expansion
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
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
    :min_version_3_1 :needs_component_jmap
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
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "participants" => undef,
        "alerts"=> undef,
    };

    # An empty UID generates a random uid.
    my $ret = $self->createandget_event($event);
    my($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_not_null($ret->{id});
    $self->assert_str_equals($ret->{uid}, $ret->{id});
    $self->assert_str_equals($filename, $ret->{id});

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
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => $event,
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);
    $jmap->{CreatedIds} = undef;
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$eventId],
        }, 'R1'],
    ]);
    $ret = $res->[0][1]{list}[0];
    ($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_not_null($filename);
    $self->assert_str_not_equals($event->{uid}, $filename);
    $self->assert_str_equals($event->{uid}, $ret->{id});
}

sub test_calendarevent_copy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    xlog $self, "create shared accounts";
    $admintalk->create("user.other");

    my $othercaldav = Net::CalDAVTalk->new(
        user => "other",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    $admintalk->setacl('user.other', admin => 'lrswipkxtecdan');
    $admintalk->setacl('user.other', other => 'lrswipkxtecdn');
    
    xlog $self, "create source calendar";
    my $srcCalendarId = $caldav->NewCalendar({name => 'Source Calendar'});
    $self->assert_not_null($srcCalendarId);

    xlog $self, "create destination calendar";
    my $dstCalendarId = $othercaldav->NewCalendar({name => 'Destination Calendar'});
    $self->assert_not_null($dstCalendarId);

    xlog $self, "share calendar";
    $admintalk->setacl("user.other.#calendars.$dstCalendarId", "cassandane" => 'lrswipkxtecdn') or die;

    my $event =  {
        "calendarId" => $srcCalendarId,
        "uid" => "58ADE31-custom-UID",
        "title"=> "foo",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
        "status" => "tentative",
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "privacy" => "secret",
        "participants" => undef,
        "alerts"=> undef,
    };

    xlog $self, "create event";
    my $res = $jmap->CallMethods([['CalendarEvent/set',{
        create => {"1" => $event}},
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $eventId = $res->[0][1]{created}{"1"}{id};

    xlog $self, "copy event";
    $res = $jmap->CallMethods([['CalendarEvent/copy', {
        fromAccountId => 'cassandane',
        accountId => 'other',
        create => {
            1 => {
                id => $eventId,
                calendarId => $dstCalendarId,
            },
        },
        onSuccessDestroyOriginal => JSON::true,
    },
    "R1"]]);
    $self->assert_not_null($res->[0][1]{created});
    my $copiedEventId = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$copiedEventId],
        }, 'R1'],
        ['CalendarEvent/get', {
            accountId => undef,
            ids => [$eventId],
        }, 'R2'],
    ]);
    $self->assert_str_equals('foo', $res->[0][1]{list}[0]{title});
    $self->assert_str_equals($eventId, $res->[1][1]{notFound}[0]);
}

sub test_calendarevent_set_notitle
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        "calendarId" => $calid,
        "uid" => "58ADE314231-some-UID",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT5M",
        "sequence"=> 42,
        "timeZone"=> "Etc/UTC",
        "showWithoutTime"=> JSON::false,
        "locale" => "en",
    };

    my $ret = $self->createandget_event($event);
    $self->assert_str_equals("", $ret->{title});
    my $eventId= $ret->{id};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'foo',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['title']
        }, 'R2'],

    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals('foo', $res->[1][1]{list}[0]{title});
}

sub test_calendarevent_set_readonly
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");

    # Assert that calendar ACLs are enforced also for mailbox owner.

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                "1" => {
                    name => "",
                    color => "coral",
                    isVisible => \1
                }
            }
        }, "R1"],
        ['Calendar/get', {
            ids => ['#1'],
            properties => ['name'],
        }, "R2"],
    ]);
    my $calendarId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($calendarId);
    my $name = $res->[1][1]{list}[0]{'name'};
    $self->assert_not_null($name);

    $admintalk->setacl("user.cassandane.#calendars." . $name, "cassandane" => 'lrskxcan9') or die;

    $res = $jmap->CallMethods([
            ['Calendar/get',{
                ids => [$calendarId],
            }, "R2"],
            ['CalendarEvent/set',{
                create => {
                    "1" => {
                        "calendarId" => $calendarId,
                        "uid" => "58ADE31-custom-UID",
                        "title"=> "foo",
                        "start"=> "2015-11-07T09:00:00",
                        "duration"=> "PT5M",
                        "sequence"=> 42,
                        "timeZone"=> "Etc/UTC",
                        "showWithoutTime"=> JSON::false,
                        "locale" => "en",
                        "status" => "tentative",
                        "description"=> "",
                        "freeBusyStatus"=> "busy",
                        "privacy" => "secret",
                        "participants" => undef,
                        "alerts"=> undef,
                    }
                }
            }, "R2"],
        ]);

    my $calendar = $res->[0][1]{list}[0];
    $self->assert_equals(JSON::true, $calendar->{mayReadFreeBusy});
    $self->assert_equals(JSON::true, $calendar->{mayReadItems});
    $self->assert_equals(JSON::false, $calendar->{mayAddItems});
    $self->assert_equals(JSON::false, $calendar->{mayModifyItems});
    $self->assert_equals(JSON::false, $calendar->{mayRemoveItems});
    $self->assert_equals(JSON::true, $calendar->{mayRename});
    $self->assert_equals(JSON::true, $calendar->{mayDelete});
    $self->assert_equals(JSON::true, $calendar->{mayAdmin});

    $self->assert_not_null($res->[1][1]{notCreated}{1});
    $self->assert_str_equals("invalidProperties", $res->[1][1]{notCreated}{1}{type});
    $self->assert_str_equals("calendarId", $res->[1][1]{notCreated}{1}{properties}[0]);
}

sub test_calendarevent_set_rsvpsequence
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my ($id, $ical) = $self->icalfile('rsvpsequence');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_num_equals(1, $event->{sequence});

    my $participantId = $event->{participantId};
    $self->assert_not_null($participantId);

    my $eventId = $event->{id};

    # Update a partstat doesn't bump sequence.
    my $res = $jmap->CallMethods([
            ['CalendarEvent/set',{
                update => {
                    $eventId => {
                        ('participants/' . $participantId . '/participationStatus') => 'accepted',
                    }
                }
            }, "R1"],
            ['CalendarEvent/get',{
                ids => [$eventId],
                properties => ['sequence'],
            }, "R2"],
        ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_num_equals(1, $res->[1][1]{list}[0]->{sequence});

    # Neither does setting a per-user property.
    $res = $jmap->CallMethods([
            ['CalendarEvent/set',{
                update => {
                    $eventId => {
                        color => 'red',
                        'alerts/alert1/trigger/offset' => '-PT10M',
                    },
                }
            }, "R1"],
            ['CalendarEvent/get',{
                ids => [$eventId],
                properties => ['sequence'],
            }, "R2"],
        ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_num_equals(1, $res->[1][1]{list}[0]->{sequence});

    # But setting a property shared by all users does!
    $res = $jmap->CallMethods([
            ['CalendarEvent/set',{
                update => {
                    $eventId => {
                        title => 'foo',
                    },
                }
            }, "R1"],
            ['CalendarEvent/get',{
                ids => [$eventId],
                properties => ['sequence'],
            }, "R2"],
        ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_num_not_equals(1, $res->[1][1]{list}[0]->{sequence});
}

sub test_calendarevent_set_participants_recur
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $event =  {
        "calendarId" => $calid,
        "title"=> "title",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "showWithoutTime"=> JSON::false,
        "recurrenceRule"=> {
            "frequency"=> "weekly",
        },
        "replyTo" => {
            "imip" => "mailto:foo\@local",
        },
        "participants" => {
            'bar' => {
                roles => {
                    'attendee' => JSON::true,
                },
                expectReply => JSON::true,
                sendTo => {
                    imip => 'mailto:bar@local',
                },
            },
            'bam' => {
                email => 'bam@local',
                roles => {
                    'attendee' => JSON::true,
                },
                expectReply => JSON::true,
                sendTo => {
                    imip => 'mailto:bam@local',
                },
            },
        },
        method => 'request',
    };

    my $ret = $self->createandget_event($event);
    my $eventId = $ret->{id};
    $self->assert_not_null($eventId);

    my $barParticipantId;
    while (my ($key, $value) = each(%{$ret->{participants}})) {
        if ($value->{sendTo}{imip} eq 'mailto:bar@local') {
            $barParticipantId = $key;
            last;
        }
    }
    $self->assert_not_null($barParticipantId);

    my $recurrenceOverrides = {
        "2015-11-14T09:00:00" => {
            ('participants/' . $barParticipantId) => undef,
        },
    };

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides' => $recurrenceOverrides
                },
            },
       }, 'R1'],
       ['CalendarEvent/get', {
            ids => [$eventId],
       }, 'R2'],
   ]);
   $self->assert(exists $res->[0][1]{updated}{$eventId});

   $self->assert_deep_equals(
       $recurrenceOverrides, $res->[1][1]{list}[0]{recurrenceOverrides}
   );
}

sub test_calendarevent_get_floatingtzid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('floatingtzid');

    # As seen in the wild: A floating DTSTART and a DTEND with TZID.

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals("2019-03-10T11:15:00", $event->{start});
    $self->assert_str_equals("Europe/Amsterdam", $event->{timeZone});
    $self->assert_str_equals("PT1H45M", $event->{duration});
}

sub test_rscale_in_jmap_hidden_in_caldav
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

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
                "relativeTo" => "end",
            },
        },
        "showWithoutTime"=> JSON::false,
        "description"=> "",
        "freeBusyStatus"=> "busy",
        "prodId" => "foo",
        "recurrenceRule" => {
            "frequency" => "monthly",
            count => 12,
        },
    };

    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
    my $eventId = $ret->{id};

    # Overide one event, this causes rscale to get added
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    "recurrenceOverrides/2015-12-07T09:00:00" => {
                         exclude => JSON::true,
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
             ids => [$eventId],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $ret = $res->[1][1]{list}[0];
    $self->assert_not_null($ret);

    # rscale should now be in jmap
    $self->assert_deep_equals(
        {
            '@type' => 'RecurrenceRule',
            count          => 12,
            firstDayOfWeek => 'mo',
            frequency      => 'monthly',
            interval       => 1,
            rscale         => 'gregorian',
            skip           => 'omit'
        },
        $ret->{recurrenceRule},
    );

    # Make sure we have no rscale through caldav, most clients can't
    # handle it
    my $events = $caldav->GetEvents("$calid");
    $self->assert_deep_equals(
        {
            count => 12,
            frequency => 'monthly',
        },
        $events->[0]->{recurrenceRule},
    );
}

sub test_calendar_treat_as_mailbox
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create calendar";
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

    my $using = [
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
        'urn:ietf:params:jmap:mail',
    ];

    xlog $self, "rename as mailbox $id";
    $res = $jmap->CallMethods([
        ['Mailbox/set', { update => { $id => { name => "foobar" } } }, "R1"]
    ], $using);
    $self->assert_not_null($res);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_null($res->[0][1]{updated});
    $self->assert_not_null($res->[0][1]{notUpdated});
}

sub test_calendar_schedule_address_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create two calendars, one with an address set";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                 "1" => {
                            name => "foo",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1,
                 },
                 "2" => {
                            name => "bar",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1,
                            scheduleAddressSet => ['mailto:foo@example.com', 'mailto:bar@example.com'],
                 },
                 "3" => {
                            name => "baz",
                            color => "coral",
                            sortOrder => 2,
                            isVisible => \1,
                 },
            }}, "R1"]
    ]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Calendar/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});
    $self->assert_null($res->[0][1]{notCreated});

    xlog $self, "get calendars";
    $res = $jmap->CallMethods([['Calendar/get', {}, "R1"]]);

    my %byname = map { $_->{name} => $_ } @{$res->[0][1]{list}};

    $self->assert_deep_equals(['mailto:cassandane@example.com'], $byname{personal}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:cassandane@example.com'], $byname{foo}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:foo@example.com', 'mailto:bar@example.com'], $byname{bar}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:cassandane@example.com'], $byname{baz}{scheduleAddressSet});

    # explicitly update the values of two calendars, one to the explicit same value

    $jmap->CallMethods([['Calendar/set', { update => {
        $byname{foo}{id} => {
            scheduleAddressSet => ['mailto:foo2@example.com'],
        },
        $byname{baz}{id} => {
            scheduleAddressSet => ['mailto:cassandane@example.com'],
        },
    }}, "R1"]]);

    # map to names and then check values

    xlog $self, "get calendars";
    $res = $jmap->CallMethods([['Calendar/get', {}, "R1"]]);

    %byname = map { $_->{name} => $_ } @{$res->[0][1]{list}};

    $self->assert_deep_equals(['mailto:cassandane@example.com'], $byname{personal}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:foo2@example.com'], $byname{foo}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:foo@example.com', 'mailto:bar@example.com'], $byname{bar}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:cassandane@example.com'], $byname{baz}{scheduleAddressSet});

    # use CalDAV to update the default address!
    xlog $self, "Use CalDAV to update the default address";
    my $caldav = $self->{caldav};
    $caldav->Request(
      'PROPPATCH',
      "",
      x('D:propertyupdate', $caldav->NS(),
        x('D:set',
          x('D:prop',
            x('C:calendar-user-address-set',
              x('D:href', 'mailto:bar@example.com')
            )
          )
        )
      )
    );

    xlog $self, "get calendars";
    $res = $jmap->CallMethods([['Calendar/get', {}, "R1"]]);

    %byname = map { $_->{name} => $_ } @{$res->[0][1]{list}};

    $self->assert_deep_equals(['mailto:bar@example.com'], $byname{personal}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:foo2@example.com'], $byname{foo}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:foo@example.com', 'mailto:bar@example.com'], $byname{bar}{scheduleAddressSet});
    $self->assert_deep_equals(['mailto:cassandane@example.com'], $byname{baz}{scheduleAddressSet});
}

sub test_calendarevent_set_recurrenceoverrides_mixed_datetypes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my ($id, $ical) = $self->icalfile('recurrenceoverrides-mixed-datetypes');

    my $event = $self->putandget_vevent($id, $ical);
    my $wantOverrides = {
        "2018-05-01T00:00:00" => {
            start    => "2018-05-02T17:00:00",
            timeZone => "Europe/Vienna",
            duration => "PT1H",
            showWithoutTime => JSON::false,
        }
    };

    # Validate main event.
    $self->assert_str_equals('2016-01-01T00:00:00', $event->{start});
    $self->assert_equals(JSON::true, $event->{showWithoutTime});
    $self->assert_null($event->{timeZone});
    $self->assert_str_equals('P1D', $event->{duration});
    # Validate overrides.
    $self->assert_deep_equals($wantOverrides, $event->{recurrenceOverrides});
    my $eventId = $event->{id};

    # Add recurrenceOverrides with showWithoutTime=true
    # and showWithoutTime=false.
    $self->assert_not_null($eventId);
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    "recurrenceOverrides/2019-09-01T00:00:00" => {
                        start => "2019-09-02T00:00:00",
                        duration => 'P2D',
                    },
                    "recurrenceOverrides/2019-10-01T00:00:00" => {
                        start => "2019-10-02T15:00:00",
                        timeZone => "Europe/London",
                        duration => "PT2H",
                        showWithoutTime => JSON::false,
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', { ids => [$eventId] }, 'R2'],
    ]);

    $wantOverrides->{'2019-09-01T00:00:00'} = {
        start => "2019-09-02T00:00:00",
        duration => 'P2D',
    };
    $wantOverrides->{'2019-10-01T00:00:00'} = {
        start => "2019-10-02T15:00:00",
        timeZone => "Europe/London",
        duration => "PT2H",
        showWithoutTime => JSON::false,
    };
    $event = $res->[1][1]{list}[0];
    $self->assert_deep_equals($wantOverrides, $event->{recurrenceOverrides});
}

sub test_calendarevent_query_expandrecurrences
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create events";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => $calid,
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRule => {
                        frequency => 'weekly',
                        count => 3,
                    },
                    recurrenceOverrides => {
                        '2019-01-08T09:00:00' => {
                            start => '2019-01-08T12:00:00',
                        },
                        '2019-01-03T13:00:00' => {
                            title => 'rdate',
                        },
                    },
                },
                "2" => {
                    calendarId => $calid,
                    uid => 'event2uid',
                    title => "event2",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-02T11:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                },
            }
        }, 'R1']
    ]);

    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            filter => {
                before => '2019-02-01T00:00:00Z',
            },
            sort => [{
                property => 'start',
                isAscending => JSON::false,
            }],
            expandRecurrences => JSON::true,
        }, 'R1']
    ]);
    $self->assert_num_equals(5, $res->[0][1]{total});
    $self->assert_deep_equals([
            'event1uid;2019-01-15T09:00:00',
            'event1uid;2019-01-08T09:00:00',
            'event1uid;2019-01-03T13:00:00',
            'event2uid',
            'event1uid;2019-01-01T09:00:00',
    ], $res->[0][1]{ids});
}

sub test_calendarevent_get_recurrenceinstances
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => $calid,
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRule => {
                        frequency => 'weekly',
                        count => 5,
                    },
                    recurrenceOverrides => {
                        '2019-01-15T09:00:00' => {
                            title => 'override1',
                        },
                        '2019-01-10T12:00:00' => {
                            # rdate
                        },
                        '2019-01-22T09:00:00' => {
                            excluded => JSON::true,
                        },
                    },
                },
            }
        }, 'R1']
    ]);

    # This test hard-codes the ids of recurrence instances.
    # This might break if we change the id scheme.

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
                ids => [
                    'event1uid;2019-01-08T09:00:00',
                    'event1uid;2019-01-15T09:00:00',
                    'event1uid;2019-01-10T12:00:00',
                    'event1uid;2019-01-22T09:00:00', # is excluded
                    'event1uid;2019-12-01T09:00:00', # does not exist

                ],
                properties => ['start', 'title', 'recurrenceId'],
        }, 'R1'],
    ]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{list}});

    $self->assert_str_equals('event1uid;2019-01-08T09:00:00', $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('2019-01-08T09:00:00', $res->[0][1]{list}[0]{start});
    $self->assert_str_equals('2019-01-08T09:00:00', $res->[0][1]{list}[0]{recurrenceId});

    $self->assert_str_equals('event1uid;2019-01-15T09:00:00', $res->[0][1]{list}[1]{id});
    $self->assert_str_equals('override1', $res->[0][1]{list}[1]{title});
    $self->assert_str_equals('2019-01-15T09:00:00', $res->[0][1]{list}[1]{start});
    $self->assert_str_equals('2019-01-15T09:00:00', $res->[0][1]{list}[1]{recurrenceId});

    $self->assert_str_equals('event1uid;2019-01-10T12:00:00', $res->[0][1]{list}[2]{id});
    $self->assert_str_equals('2019-01-10T12:00:00', $res->[0][1]{list}[2]{start});
    $self->assert_str_equals('2019-01-10T12:00:00', $res->[0][1]{list}[2]{recurrenceId});

    $self->assert_num_equals(2, scalar @{$res->[0][1]{notFound}});
    $self->assert_str_equals('event1uid;2019-01-22T09:00:00', $res->[0][1]{notFound}[0]);
    $self->assert_str_equals('event1uid;2019-12-01T09:00:00', $res->[0][1]{notFound}[1]);
}

sub test_calendarevent_set_recurrenceinstances
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => $calid,
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRule => {
                        frequency => 'weekly',
                        count => 5,
                    },
                },
            }
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{created}{1});

    # This test hard-codes the ids of recurrence instances.
    # This might break if we change the id scheme.

    xlog $self, "Override a regular recurrence instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid;2019-01-15T09:00:00' => {
                    title => "override1",
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid;2019-01-15T09:00:00'});
    $self->assert_deep_equals({
            '2019-01-15T09:00:00' => {
                title => "override1",
            },
        }, $res->[1][1]{list}[0]{recurrenceOverrides}
    );

    xlog $self, "Update an existing override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid;2019-01-15T09:00:00' => {
                    title => "override1_updated",
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid;2019-01-15T09:00:00'});
    $self->assert_deep_equals({
            '2019-01-15T09:00:00' => {
                title => "override1_updated",
            },
        }, $res->[1][1]{list}[0]{recurrenceOverrides}
    );

    xlog $self, "Revert an override into a regular recurrence";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid;2019-01-15T09:00:00' => {
                    title => "event1", # original title
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid;2019-01-15T09:00:00'});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Set regular recurrence excluded";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid;2019-01-08T09:00:00' => {
                    excluded => JSON::true,
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid;2019-01-08T09:00:00'});
    $self->assert_deep_equals({
        '2019-01-08T09:00:00' => {
            excluded => JSON::true,
        }
    }, $res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Reset overrides";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid' => {
                    recurrenceOverrides => undef,
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid'});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Destroy regular recurrence instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => ['event1uid;2019-01-08T09:00:00'],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert_str_equals('event1uid;2019-01-08T09:00:00', $res->[0][1]{destroyed}[0]);
    $self->assert_deep_equals({
        '2019-01-08T09:00:00' => {
            excluded => JSON::true,
        }
    }, $res->[1][1]{list}[0]{recurrenceOverrides});
}

sub test_calendarevent_set_recurrenceinstances_rdate
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $calid = 'Default';

    xlog $self, "create event with RDATE";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => $calid,
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRule => {
                        frequency => 'weekly',
                        count => 5,
                    },
                    recurrenceOverrides => {
                        '2019-01-10T14:00:00' => {}
                    },
                },
            }
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{created}{1});

    # This test hard-codes the ids of recurrence instances.
    # This might break if we change the id scheme.

    xlog $self, "Delete RDATE by setting it excluded";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid;2019-01-10T14:00:00' => {
                    excluded => JSON::true,
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid;2019-01-10T14:00:00'});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Recreate RDATE";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                'event1uid' => {
                    recurrenceOverrides => {
                        '2019-01-10T14:00:00' => {}
                    },
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{'event1uid'});
    $self->assert_deep_equals({
            '2019-01-10T14:00:00' => { },
        },
        $res->[1][1]{list}[0]{recurrenceOverrides}
    );

    xlog $self, "Destroy RDATE";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => ['event1uid;2019-01-10T14:00:00'],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert_str_equals('event1uid;2019-01-10T14:00:00', $res->[0][1]{destroyed}[0]);
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});
}

sub test_calendarevent_set_invalidpatch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => 'Default',
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                },
            }
        }, 'R1']
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'alerts/alert1/trigger/offset' => '-PT5M',
                },
            }
        }, 'R1']
    ]);
    $self->assert_str_equals("invalidPatch", $res->[0][1]{notUpdated}{$eventId}{type});
}

sub test_calendarevent_blobid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create other user";

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.other");
    $admintalk->setacl("user.other", admin => 'lrswipkxtecdan') or die;
    $admintalk->setacl("user.other", other => 'lrswipkxtecdn') or die;

    my $service = $self->{instance}->get_service("http");
    my $otherJmap = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $otherJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    xlog $self, "create calendar event in other users calendar";

    my $res = $otherJmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => 'Default',
                    uid => 'event1uid1',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    alerts => {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => "start",
                                offset => "-PT5M",
                            },
                            action => "email",
                        },
                    },
                },
            }
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);

    xlog $self, "share calendar";

    $admintalk->setacl("user.other.#calendars.Default", cassandane => 'lrswipkxtecdn') or die;

    xlog $self, "set per-user event data for cassandane user";

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'other',
            update => {
                $eventId => {
                    alerts => {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => "start",
                                offset => "-PT10M",
                            },
                            action => "email",
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog $self, "get event blobIds for cassandane and other user";

    $res = $otherJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$eventId],
            properties => ['blobId'],
        }, 'R1']
    ]);

    # fetch a second time to make sure this works with a cached response
    $res = $otherJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$eventId],
            properties => ['blobId'],
        }, 'R1']
    ]);
    my $otherBlobId = $res->[0][1]{list}[0]{blobId};
    $self->assert_not_null($otherBlobId);

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$eventId],
            properties => ['blobId'],
        }, 'R1']
    ]);
    my $cassBlobId = $res->[0][1]{list}[0]{blobId};
    $self->assert_not_null($cassBlobId);

    xlog $self, "compare blob ids";

    $self->assert_str_not_equals($otherBlobId, $cassBlobId);

    xlog $self, "download blob with userdata";

    $res = $jmap->Download('other', $cassBlobId);
    $self->assert_str_equals("BEGIN:VCALENDAR", substr($res->{content}, 0, 15));
    $self->assert_num_not_equals(-1, index($res->{content}, 'TRIGGER:-PT10M'));
}

sub test_calendarevent_debugblobid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog $self, "create other user";

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.other");
    $admintalk->setacl("user.other", admin => 'lrswipkxtecdan') or die;
    $admintalk->setacl("user.other", other => 'lrswipkxtecdn') or die;

    my $service = $self->{instance}->get_service("http");
    my $otherJmap = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $otherJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    xlog $self, "create calendar event in other users calendar";

    my $res = $otherJmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarId => 'Default',
                    uid => 'event1uid1',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    alerts => {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => "start",
                                offset => "-PT5M",
                            },
                            action => "email",
                        },
                    },
                },
            }
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);

    xlog $self, "share calendar";

    $admintalk->setacl("user.other.#calendars.Default", cassandane => 'lrswipkxtecdn') or die;

    xlog $self, "set per-user event data for cassandane user";

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'other',
            update => {
                $eventId => {
                    alerts => {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => "start",
                                offset => "-PT10M",
                            },
                            action => "email",
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog $self, "get debugBlobId as regular user (should fail)";

    my $using = [
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/debug',
    ];

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$eventId],
            properties => ['debugBlobId'],
        }, 'R1']
    ], $using);
    $self->assert_null($res->[0][1]{list}[0]{debugBlobId});

    xlog $self, "get debugBlobId as admin user";

    my $adminJmap = Mail::JMAPTalk->new(
        user => 'admin',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $res = $adminJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$eventId],
            properties => ['debugBlobId'],
        }, 'R1']
    ], $using);
    my $debugBlobId = $res->[0][1]{list}[0]{debugBlobId};
    $self->assert_not_null($debugBlobId);

    xlog $self, "download debugBlob with userdata";

    $res = $adminJmap->Download('other', $debugBlobId);
    $self->assert_str_equals("multipart/mixed", substr($res->{headers}{'content-type'}, 0, 15));
    $self->assert_num_not_equals(-1, index($res->{content}, 'SUMMARY:event1'));

    xlog $self, "attempt to download debugBlob as non-admin";

    my $downloadUri = $jmap->downloaduri('other', $debugBlobId);
    my %Headers = (
        'Authorization' => $jmap->auth_header(),
    );
    my $RawResponse = $jmap->ua->get($downloadUri, { headers => \%Headers });
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawResponse);
    }
    $self->assert_str_equals('404', $RawResponse->{status});
}

sub test_crasher20191227
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 =>  {
                    "calendarId" => $calid,
                    "title"=> "title",
                    "description"=> "description",
                    "start"=> "2015-11-07T09:00:00",
                    "duration"=> "PT2H",
                    "timeZone" => "Europe/London",
                    "showWithoutTime"=> JSON::false,
                    recurrenceRule => {
                        frequency => 'weekly',
                    },
                    recurrenceOverrides => {
                        '2015-11-14T09:00:00' => {
                            title => 'foo',
                        },
                    },
                    "freeBusyStatus"=> "busy",
                    "status" => "confirmed",
                    "alerts" =>  {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => "start",
                                offset => "-PT5M",
                            },
                            acknowledged => "2015-11-07T08:57:00Z",
                            action => "email",
                        },
                    },
                    "useDefaultAlerts" => JSON::true,
                },
            },
        }, 'R1']
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2015-11-14T09:00:00' => {
                        alerts => undef,
                    }
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
}

sub test_calendarevent_get_utctime_with_tzid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    # As seen on the wires...
    my ($id, $ical) = $self->icalfile('utctime-with-tzid');

    my $event = $self->putandget_vevent($id, $ical, ['timeZone', 'start', 'duration']);
    $self->assert_not_null($event);
    $self->assert_str_equals('Europe/Vienna', $event->{timeZone});
    $self->assert_str_equals('2019-12-19T19:00:00', $event->{start});
    $self->assert_str_equals('PT2H20M', $event->{duration});
}

sub test_calendarevent_set_linksurl
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DTEND;TZID=Europe/Vienna:20160928T170000
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:test
URL:https://url.example.com
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT', '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/query',
                path => '/ids'
            },
            properties => ['links'],
        }, 'R2'],
    ]);
    my $eventId = $res->[1][1]{list}[0]{id};
    $self->assert_not_null($eventId);

    my $wantLinks = [{
        '@type' => 'Link',
        href => 'https://url.example.com',
        rel => 'describedby',
    }];

    my @links = values %{$res->[1][1]{list}[0]{links}};
    $self->assert_deep_equals($wantLinks, \@links);

    # Set some property other than links
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'update'
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['links'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    @links = values %{$res->[1][1]{list}[0]{links}};
    $self->assert_deep_equals($wantLinks, \@links);
    my $linkId = (keys %{$res->[1][1]{list}[0]{links}})[0];
    $self->assert_not_null($linkId);

    $res = $caldav->Request('GET', '/dav/calendars/user/cassandane/Default/test.ics');
    $ical = $res->{content} =~ s/\r\n[ \t]//rg;
    $self->assert($ical =~ /\nURL[^:]*:https:\/\/url\.example\.com/);

    # Even changing rel sticks links to their former iCalendar property
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    "links/$linkId/rel" => 'enclosure',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['links'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $wantLinks->[0]{rel} = 'enclosure';

    @links = values %{$res->[1][1]{list}[0]{links}};
    $self->assert_deep_equals($wantLinks, \@links);

    $res = $caldav->Request('GET', '/dav/calendars/user/cassandane/Default/test.ics');
    $ical = $res->{content} =~ s/\r\n[ \t]//rg;
    $self->assert($ical =~ /\nURL[^:]*:https:\/\/url\.example\.com/);
}

sub test_calendarevent_get_expandrecurrences_date
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
PRODID:-//FastMail/1.0/EN
BEGIN:VEVENT
DTEND;VALUE=DATE:20180423
DTSTAMP:20190505T204102Z
DTSTART;VALUE=DATE:20180422
RRULE:FREQ=YEARLY;COUNT=5
SEQUENCE:0
SUMMARY:Earth Day
UID:123456789
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT', '/dav/calendars/user/cassandane/Default/123456789.ics',
        $ical, 'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            filter => {
                after =>  '2020-04-21T14:00:00Z',
                before => '2020-04-22T13:59:59Z',
            },
            expandRecurrences => JSON::true,
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/query',
                path => '/ids',
            },
            properties => ['start'],
        }, 'R2'],
    ]);
    $self->assert_str_equals('2020-04-22T00:00:00', $res->[1][1]{list}[0]{start});
}

sub test_calendarevent_get_location_newline
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my ($id, $ical) = $self->icalfile('location-newline');
    my $event = $self->putandget_vevent($id, $ical);
    my @locations = values(%{$event->{locations}});
    $self->assert_num_equals(2, scalar @locations);
    $self->assert_str_equals("xyz\nxyz", $locations[0]{name});
    $self->assert_str_equals("xyz\nxyz", $locations[1]{name});
}

sub test_calendarevent_parse_singlecommand
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $id1 = '97c46ea4-4182-493c-87ef-aee4edc2d38b';
    my $ical1 = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:$id1
SUMMARY:bar
DESCRIPTION:
TRANSP:OPAQUE
DTSTART;VALUE=DATE:20151008
DTEND;VALUE=DATE:20151009
END:VEVENT
END:VCALENDAR
EOF

    my $id2 = '100959BC664CA650E933C892C@example.com';
    my $ical2 = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//Example Client//EN
BEGIN:VEVENT
UID:$id1
SUMMARY:foo
DESCRIPTION:
TRANSP:OPAQUE
DTSTART;VALUE=DATE:20151008
DTEND;VALUE=DATE:20151009
END:VEVENT
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
TRANSP:TRANSPARENT
STATUS:TENTATIVE
DTSTART;TZID=US/Eastern:20060102T120000
DURATION:PT1H
RRULE:FREQ=DAILY;COUNT=5
RDATE;TZID=US/Eastern;VALUE=PERIOD:20060102T150000/PT2H
SUMMARY:Event #2
DESCRIPTION:We are having a meeting all this week at 12 pm fo
 r one hour\, with an additional meeting on the first day 2 h
 ours long.\nPlease bring your own lunch for the 12 pm meetin
 gs.
UID:$id2
CONFERENCE;FEATURE=PHONE;
 LABEL=Attendee dial-in:tel:+1-888-555-0456,,,555123
END:VEVENT
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
DTSTART;TZID=US/Eastern:20060104T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060104T120000
SUMMARY:Event #2 bis
UID:$id2
END:VEVENT
END:VCALENDAR
EOF

    my $using = [
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/blob',
    ];

    my $res = $jmap->CallMethods([
        ['Blob/set',
           { create => {
               "ical1" => { content => $ical1, type => 'text/calendar' },
               "ical2" => { content => $ical2, type => 'text/calendar' },
               "junk" => { content => 'foo bar', type => 'text/calendar' }
             } }, 'R0'],
        ['CalendarEvent/parse', {
            blobIds => [ "#ical1", "foo", "#junk", "#ical2" ],
            properties => [ "\@type", "uid", "title", "start",
                            "recurrenceRule", "recurrenceOverrides" ]
         }, "R1"]],
        $using);
    $self->assert_not_null($res);
    $self->assert_str_equals('Blob/set', $res->[0][0]);
    $self->assert_str_equals('R0', $res->[0][2]);

    $self->assert_str_equals('CalendarEvent/parse', $res->[1][0]);
    $self->assert_str_equals('R1', $res->[1][2]);
    $self->assert_str_equals($id1, $res->[1][1]{parsed}{"#ical1"}{uid});
    $self->assert_str_equals("bar", $res->[1][1]{parsed}{"#ical1"}{title});
    $self->assert_str_equals("2015-10-08T00:00:00", $res->[1][1]{parsed}{"#ical1"}{start});
    $self->assert_null($res->[1][1]{parsed}{"#ical1"}{recurrenceRule});
    $self->assert_null($res->[1][1]{parsed}{"#ical1"}{recurrenceOverrides});

    $self->assert_str_equals("jsgroup", $res->[1][1]{parsed}{"#ical2"}{"\@type"});
    $self->assert_num_equals(2, scalar @{$res->[1][1]{parsed}{"#ical2"}{entries}});
    $self->assert_str_equals($id2, $res->[1][1]{parsed}{"#ical2"}{entries}[0]{uid});
    $self->assert_str_equals("Event #2", $res->[1][1]{parsed}{"#ical2"}{entries}[0]{title});
    $self->assert_not_null($res->[1][1]{parsed}{"#ical2"}{entries}[0]{recurrenceRule});
    $self->assert_not_null($res->[1][1]{parsed}{"#ical2"}{entries}[0]{recurrenceOverrides});
    $self->assert_str_equals($id1, $res->[1][1]{parsed}{"#ical2"}{entries}[1]{uid});
    $self->assert_str_equals("foo", $res->[1][1]{parsed}{"#ical2"}{entries}[1]{title});

    $self->assert_str_equals("#junk", $res->[1][1]{notParsable}[0]);
    $self->assert_str_equals("foo", $res->[1][1]{notFound}[0]);
}

sub test_calendarevent_set_too_large
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create calendar";
    my $res = $jmap->CallMethods([
            ['Calendar/set', { create => {
                        "1" => {
                            name => "A", color => "coral", sortOrder => 1, isVisible => JSON::true
                        }
             }}, "R1"]]);
    my $calid = $res->[0][1]{created}{"1"}{id};

    xlog $self, "create event in calendar";
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        "1" => {
                            "calendarId" => $calid,
                            "title" => "foo",
                            "description" => ('x' x 100000),
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    $self->assert_str_equals('tooLarge', $res->[0][1]{notCreated}{1}{type});
}

sub test_calendarevent_set_reject_duplicate_uid
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                eventA => {
                    calendarId => 'Default',
                    uid => '123456789',
                    title => 'eventA',
                    start => '2021-04-06T12:30:00',
                },
            }
        }, 'R1'],
    ]);
    my $eventA = $res->[0][1]{created}{eventA}{id};
    $self->assert_not_null($eventA);

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                calendarB => {
                    name => 'calendarB',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                eventB => {
                    calendarId => '#calendarB',
                    uid => '123456789',
                    title => 'eventB',
                    start => '2021-04-06T12:30:00',
                },
            }
        }, 'R2'],
    ]);
    $self->assert_not_null($res->[0][1]{created}{calendarB});
    $self->assert_str_equals('invalidProperties',
        $res->[1][1]{notCreated}{eventB}{type});
    $self->assert_deep_equals(['uid'],
        $res->[1][1]{notCreated}{eventB}{properties});
}

sub test_calendarevent_get_ignore_embedded_ianatz
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "Create VEVENT with bogus IANA VTIMEZONE";
    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//foo//bar//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Europe/Vienna
LAST-MODIFIED:20210802T073921Z
X-LIC-LOCATION:Europe/Vienna
BEGIN:STANDARD
TZNAME:-05
TZOFFSETFROM:-054517
TZOFFSETTO:-054517
DTSTART:16010101T000000
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20210328T010000
DTEND;TZID=Europe/Vienna:20210328T040000
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20201231T230000Z
CREATED:20201231T230000Z
ORGANIZER:mailto:cassandane@example.com
ATTENDEE:mailto:attendee@local
SUMMARY:test
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $ical,
        'Content-Type' => 'text/calendar');

    xlog "Assert start and duration";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['start', 'duration', 'timeZone'],
        }, 'R1'],
    ]);

    my $eventId = $res->[0][1]{list}[0]{id};
    $self->assert_str_equals('2021-03-28T01:00:00', $res->[0][1]{list}[0]{start});
    $self->assert_str_equals('PT2H', $res->[0][1]{list}[0]{duration});
    $self->assert_str_equals('Europe/Vienna', $res->[0][1]{list}[0]{timeZone});

    xlog "Assert timerange query";
    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            filter => {
                after =>  '2021-03-27T23:00:00Z',
                before => '2021-03-28T02:00:00Z'
            },
        }, 'R1'],
        ['CalendarEvent/query', {
            filter => {
                after =>  '2021-03-28T02:00:00Z',
                before => '2021-03-28T23:00:00Z'
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$eventId], $res->[0][1]{ids});
    $self->assert_deep_equals([], $res->[1][1]{ids});

    my @notifs = grep($_->{CLASS} eq 'IMIP', @{$self->{instance}->getnotify()});
    $self->assert_num_equals(1, scalar @notifs);
    my $message = decode_json($notifs[0]->{MESSAGE});
    my $event = $message->{patch};
    $self->assert_str_equals('2021-03-28T01:00:00', $event->{start});
    $self->assert_str_equals('PT2H', $event->{duration});
    $self->assert_str_equals('Europe/Vienna', $event->{timeZone});
}

sub test_calendar_get_freebusy_only
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create other user";
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.other');
    $admintalk->setacl('user.other', admin => 'lrswipkxtecdan') or die;
    $admintalk->setacl('user.other', other => 'lrswipkxtecdn') or die;

    my $service = $self->{instance}->get_service("http");
    my $otherJmap = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $otherJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $otherJmap->CallMethods([
        ['Calendar/get', {
            properties => ['id'],
        }, 'R1'],
    ]);
    $admintalk->setacl('user.other.#calendars.Default', cassandane => 'l9') or die;

    $res = $jmap->ua->get($jmap->uri(), {
        headers => {
            'Authorization' => $jmap->auth_header(),
        },
        content => '',
    });
    $self->assert_str_equals('200', $res->{status});
    my $session = eval { decode_json($res->{content}) };
    my $capabilities = $session->{accounts}{other}{accountCapabilities};
    $self->assert_not_null($capabilities->{'https://cyrusimap.org/ns/jmap/calendars'});

    $res = $jmap->CallMethods([
        ['Calendar/get', {
            accountId => 'other',
            properties => ['id'],
        }, 'R1'],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{list});

}

sub test_calendarevent_query_no_sched_inbox
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();
    my $caldav = $self->{caldav};

    $self->{store}->_select();
    $self->assert_num_equals(1, $imap->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:test
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $self->{instance}->deliver($msg);

    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $jmap->CallMethods([
        ['Calendar/get', { }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    my $defaultCalendarId = $res->[0][1]{list}[0]{id};

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', { }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/query',
                path => '/ids'
            },
            properties => ['calendarId'],
        }, 'R2'],
        ['CalendarEvent/query', {
            filter => {
                title => 'test',
            },
        }, 'R3'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R3',
                name => 'CalendarEvent/query',
                path => '/ids'
            },
            properties => ['calendarId'],
        }, 'R4'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($defaultCalendarId, $res->[1][1]{list}[0]{calendarId});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{ids}});
    $self->assert_str_equals($defaultCalendarId, $res->[3][1]{list}[0]{calendarId});
}

sub test_no_shared_calendar
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create other user";
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.other');
    $admintalk->setacl('user.other', admin => 'lrswipkxtecdan') or die;
    $admintalk->setacl('user.other', other => 'lrswipkxtecdn') or die;

    my $service = $self->{instance}->get_service("http");
    my $otherJmap = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $otherJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $otherJmap->CallMethods([
        ['Calendar/get', {
            properties => ['id'],
        }, 'R1'],
    ]);
    my $otherCalendarId = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($otherCalendarId);
    $admintalk->setacl('user.other.#calendars', cassandane => 'lr') or die;

    $res = $jmap->ua->get($jmap->uri(), {
        headers => {
            'Authorization' => $jmap->auth_header(),
        },
        content => '',
    });
    $self->assert_str_equals('200', $res->{status});
    my $session = eval { decode_json($res->{content}) };
    my $capabilities = $session->{accounts}{other}{accountCapabilities};
    $self->assert_not_null($capabilities->{'https://cyrusimap.org/ns/jmap/calendars'});

    $res = $jmap->CallMethods([
        ['Calendar/get', {
            accountId => 'other',
        }, 'R1'],
        ['Calendar/changes', {
            accountId => 'other',
            sinceState => '0',
        }, 'R2'],
        ['Calendar/set', {
            accountId => 'other',
            create => {
                calendar1 => {
                    name => 'test',
                },
            },
            update => {
                $otherCalendarId => {
                    name => 'test',
                },
            },
            destroy => [$otherCalendarId],
        }, 'R3'],
        ['CalendarEvent/get', {
            accountId => 'other',
        }, 'R4'],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{list});
    $self->assert_deep_equals([], $res->[1][1]{created});
    $self->assert_deep_equals([], $res->[1][1]{updated});
    $self->assert_deep_equals([], $res->[1][1]{destroyed});
    $self->assert_str_equals('accountReadOnly',
        $res->[2][1]{notCreated}{calendar1}{type});
    $self->assert_str_equals('notFound',
        $res->[2][1]{notUpdated}{$otherCalendarId}{type});
    $self->assert_str_equals('notFound',
        $res->[2][1]{notDestroyed}{$otherCalendarId}{type});
    $self->assert_deep_equals([], $res->[3][1]{list});
}


1;
