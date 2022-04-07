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
use Data::ICal;
use Data::Dumper;
use Data::GUID qw(guid_string);
use Storable 'dclone';
use Cwd qw(abs_path);
use File::Basename;
use XML::Spice;
use MIME::Base64 qw(encode_base64url decode_base64url);

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
                 jmap_nonstandard_extensions => 'yes',
                 defaultdomain => 'example.com');

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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'urn:ietf:params:jmap:calendars:preferences',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/debug',
    ]);
}

sub encode_eventid
{
    # This function hard-codes the event id format.
    # It might break if we change the id scheme.
    my ($uid, $recurid) = @_;
    my $eid = 'E';
    if ($recurid) {
        $eid .= 'R'
    }
    if ($uid =~ /[^0-9A-Za-z\-_]/) {
        $eid .= 'B';
    }
    $eid .= '-';
    if ($recurid) {
        $eid .= $recurid . '-';
    }
    if ($uid =~ /[^0-9A-Za-z\-_]/) {
        $eid .= encode_base64url($uid);
    }
    else {
        $eid .= $uid;
    }
    return $eid;
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
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::false, $res->[0][1]{list}[0]->{myRights}{mayWriteAll});
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
                                mayReadItems => JSON::true,
                                mayUpdatePrivate => JSON::true,
                            },
                            "shareWith/paraphrase" => {
                                mayReadFreeBusy => JSON::true,
                                mayReadItems => JSON::true,
                                mayWriteAll => JSON::true,
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
    $self->assert_str_equals('lrw59', $map{manifold});
    $self->assert_str_equals('lrswitedn79', $map{paraphrase});

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
        $self->assert_str_equals('lrw', $map{manifold});
        $self->assert_str_equals('lrswitedn', $map{paraphrase});
    }

    xlog $self, "Clear initial syslog";
    $self->{instance}->getsyslog();

    xlog $self, "Update sharewith just for manifold";
    $jmap->CallMethods([
            ['Calendar/set', {
                    accountId => 'master',
                    update => { "$CalendarId" => {
                            "shareWith/manifold/mayWriteAll" => JSON::true,
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
    $self->assert_str_equals('lrswitedn579', $map{manifold});
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
                            myRights => {
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
                            }
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notCreated}{"1"}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals(['myRights'], $res->[0][1]{notCreated}{"1"}{properties});

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
                            myRights => {
                            mayReadFreeBusy => \0, mayReadItems => \0,
                            mayAddItems => \0, mayModifyItems => \0,
                            mayRemoveItems => \0, mayRename => \0,
                            mayDelete => \0
                            }
             }}}, "R1"]
    ]);
    $errType = $res->[0][1]{notUpdated}{$id}{type};
    $self->assert_str_equals("invalidProperties", $errType);
    $self->assert_deep_equals(['myRights'], $res->[0][1]{notUpdated}{$id}{properties});

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
        $event->{q{@type}} = 'Event';
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
            foreach my $link (values %{$loc->{links}}) {
                if (not exists $link->{q{@type}}) {
                    $link->{q{@type}} = 'Link';
                }
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
            foreach my $link (values %{$p->{links}}) {
                if (not exists $link->{q{@type}}) {
                    $link->{q{@type}} = 'Link';
                }
            }
        }
    }
    if (not exists $event->{replyTo}) {
        $event->{replyTo} = undef;
    }
    if (not exists $event->{recurrenceRules}) {
        $event->{recurrenceRules} = undef;
    } elsif (defined $event->{recurrenceRules}) {
        foreach my $rrule (@{$event->{recurrenceRules}}) {
            if (not exists $rrule->{interval}) {
                $rrule->{interval} = 1;
            }
            if (not exists $rrule->{firstDayOfWeek}) {
                $rrule->{firstDayOfWeek} = 'mo';
            }
            if (not exists $rrule->{rscale}) {
                $rrule->{rscale} = 'gregorian';
            }
            if (not exists $rrule->{skip}) {
                $rrule->{skip} = 'omit';
            }
            if (not exists $rrule->{byDay}) {
                $rrule->{byDay} = undef;
            } elsif (defined $rrule->{byDay}) {
                foreach my $nday (@{$rrule->{byDay}}) {
                    if (not exists $nday->{q{@type}}) {
                        $nday->{q{@type}} = 'NDay';
                    }
                }
            }
            if (not exists $rrule->{q{@type}}) {
                $rrule->{q{@type}} = 'RecurrenceRule';
            }
        }
    }
    if (not exists $event->{excludedRecurrenceRules}) {
        $event->{excludedRecurrenceRules} = undef;
    } elsif (defined $event->{excludedRecurrenceRules}) {
        foreach my $exrule (@{$event->{excludedRecurrenceRules}}) {
            if (not exists $exrule->{interval}) {
                $exrule->{interval} = 1;
            }
            if (not exists $exrule->{firstDayOfWeek}) {
                $exrule->{firstDayOfWeek} = 'mo';
            }
            if (not exists $exrule->{rscale}) {
                $exrule->{rscale} = 'gregorian';
            }
            if (not exists $exrule->{skip}) {
                $exrule->{skip} = 'omit';
            }
            if (not exists $exrule->{byDay}) {
                $exrule->{byDay} = undef;
            } elsif (defined $exrule->{byDay}) {
                foreach my $nday (@{$exrule->{byDay}}) {
                    if (not exists $nday->{q{@type}}) {
                        $nday->{q{@type}} = 'NDay';
                    }
                }
            }
            if (not exists $exrule->{q{@type}}) {
                $exrule->{q{@type}} = 'RecurrenceRule';
            }
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
    if (not exists $event->{isDraft}) {
        $event->{isDraft} = JSON::false;
    }
    if (not exists $event->{excluded}) {
        $event->{excluded} = JSON::false,
    }

    if (not exists $event->{calendarIds}) {
        $event->{calendarIds} = undef;
    }
    if (not exists $event->{timeZone}) {
        $event->{timeZone} = undef;
    }

    if (not exists $event->{mayInviteSelf}) {
        $event->{mayInviteSelf} = JSON::false,
    }

    # undefine dynamically generated values
    $event->{created} = undef;
    $event->{updated} = undef;
    $event->{uid} = undef;
    $event->{id} = undef;
    $event->{"x-href"} = undef;
    $event->{sequence} = 0;
    $event->{prodId} = undef;
    $event->{isOrigin} = undef;
    delete($event->{blobId});
    delete($event->{debugBlobId});
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

    my ($uid, $ical) = $self->icalfile('simple');

    my $event = $self->putandget_vevent($uid, $ical);
    $self->assert_not_null($event);
    $self->assert_str_equals('Event', $event->{q{@type}});
    $self->assert_str_equals(encode_eventid($uid), $event->{id});
    $self->assert_str_equals($uid, $event->{uid});
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

    my $event = $self->putandget_vevent($id, $ical, ["x-href", "calendarIds"]);
    $self->assert_not_null($event);
    $self->assert_not_null($event->{id});
    $self->assert_not_null($event->{uid});
    $self->assert_not_null($event->{"x-href"});
    $self->assert_not_null($event->{calendarIds});
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
    $self->assert_str_equals("yearly", $event->{recurrenceRules}[0]{frequency});
    $self->assert_str_equals("hebrew", $event->{recurrenceRules}[0]{rscale});
    $self->assert_str_equals("forward", $event->{recurrenceRules}[0]{skip});
    $self->assert_num_equals(8, $event->{recurrenceRules}[0]{byMonthDay}[0]);
    $self->assert_str_equals("5L", $event->{recurrenceRules}[0]{byMonth}[0]);
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
                    calendarIds => {
                        'Default' => JSON::true,
                    },
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


    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3 || ($maj == 3 && $min < 7)) {
        # versions 3.7 or higher are tested in calendarevent_set_replyto
        xlog "Create event with no replyTo via JMAP (should fail)";
        $res = $jmap->CallMethods([
                ['CalendarEvent/set', {
                        create => {
                            1 => {
                                calendarIds => {
                                    'Default' => JSON::true,
                                },
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
    $self->assert_not_null($event->{recurrenceRules}[0]);
    $self->assert_str_equals("RecurrenceRule", $event->{recurrenceRules}[0]{q{@type}});
    $self->assert_str_equals("monthly", $event->{recurrenceRules}[0]{frequency});
    $self->assert_str_equals("gregorian", $event->{recurrenceRules}[0]{rscale});
    # This assertion is a bit brittle. It depends on the libical-internal
    # sort order for BYDAY
    $self->assert_deep_equals([{
                '@type' => 'NDay',
                "day" => "mo",
                "nthOfPeriod" => 2,
            }, {
                '@type' => 'NDay',
                "day" => "mo",
                "nthOfPeriod" => 1,
            }, {
                '@type' => 'NDay',
                "day" => "tu",
            }, {
                '@type' => 'NDay',
                "day" => "th",
                "nthOfPeriod" => -2,
            }, {
                '@type' => 'NDay',
                "day" => "sa",
                "nthOfPeriod" => -1,
            }, {
                '@type' => 'NDay',
                "day" => "su",
                "nthOfPeriod" => -3,
            }], $event->{recurrenceRules}[0]{byDay});
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
    $self->assert_num_equals(1, scalar @locations);

    $self->assert_str_equals("On planet Earth", $locations[0]->{name});

    my @links = values %{$locations[0]->{links}};
    $self->assert_num_equals(1, scalar @links);
    $self->assert_equals("skype:foo", $links[0]->{href});
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
        uid => "58ADE31-custom-UID",
        title => "subseconds",
        start => "2011-12-04T04:05:06.78",
        created => "2019-06-29T11:58:12.412Z",
        updated => "2019-06-29T11:58:12.412Z",
        duration=> "PT5M3.45S",
        timeZone=> "Europe/Vienna",
        recurrenceRules => [{
            '@type' => 'RecurrenceRule',
            frequency => "daily",
            until => '2011-12-10T04:05:06.78',
        }],
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
        $ret->{recurrenceRules}[0]{until});
    $ret->{recurrenceRules}[0]{until} = '2011-12-10T04:05:06.78';

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
                calendarIds => {
                    $calid => JSON::true,
                },
                "start"=> "2010-02-12T00:00:00",
                "recurrenceRules"=> [{
                        "frequency"=> "monthly",
                        "interval"=> 13,
                        "byMonth"=> [
                                "4L"
                        ],
                        "count"=> 3,
                }],
                "\@type"=> "Event",
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
    $event->{calendarIds} = $ret->{calendarIds};
    $self->assert_normalized_event_equals($event, $ret);

    $event->{locations} = {
        "loc1" => {
            "timeZone" => "Europe/Berlin",
            "relativeTo" => "end",
        },
    };
    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarIds => $event->{calendarIds},
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        "recurrenceRules" => [{
            "frequency" => "monthly",
            count => 12,
        }],
        "recurrenceOverrides" => {
            "2015-12-07T09:00:00" => {
                "locations/loc1/timeZone" => "America/New_York",
            },
        },
    };

    my $ret;

    $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarIds} = $ret->{calendarIds};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_htmldescription
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
    $event->{calendarIds} = $ret->{calendarIds};
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
            links => {
                link1 => {
                    href => 'https://foo.local',
                    rel => "enclosure",
                },
                link2 => {
                    href => 'https://bar.local',
                    rel => "enclosure",
                },
            },
        },
        # A full-blown location
        locG => {
            name => "location G",
            description => "a description",
            timeZone => "Europe/Vienna",
            coordinates => "geo:48.2010,16.3695,183",
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
        calendarIds => {
            $calid => JSON::true,
        },
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "free",
        "locations" => $locations,
        "virtualLocations" => $virtualLocations,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarIds} = $ret->{calendarIds};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $recurrenceRules = [{
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
    }];

    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
        "title"=> "title",
        "description"=> "description",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "showWithoutTime"=> JSON::false,
        "freeBusyStatus"=> "busy",
        "recurrenceRules" => $recurrenceRules,
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarIds} = $ret->{calendarIds};
    $self->assert_normalized_event_equals($event, $ret);

    # Now delete the recurrence rule
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set',{
            update => {
                $event->{id} => {
                    recurrenceRules => undef,
                },
            },
        }, "R1"],
        ['CalendarEvent/get',{
            ids => [$event->{id}],
        }, "R2"],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$event->{id}});

    delete $event->{recurrenceRules};
    $ret = $res->[1][1]{list}[0];
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrence_multivalued
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event =  {
        calendarIds => {
            Default => JSON::true,
        },
        title => "title",
        description => "description",
        start => "2015-11-07T09:00:00",
        duration => "PT1H",
        timeZone => "Europe/London",
        showWithoutTime => JSON::false,
        freeBusyStatus => "busy",
        recurrenceRules => [{
            frequency => 'weekly',
            count => 3,
        }, {
            frequency => 'daily',
            count => 4,
        }],
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarIds} = $ret->{calendarIds};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_exrule
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event =  {
        calendarIds => {
            Default => JSON::true,
        },
        title => "title",
        description => "description",
        start => "2020-12-03T09:00:00",
        duration => "PT1H",
        timeZone => "Europe/London",
        showWithoutTime => JSON::false,
        freeBusyStatus => "busy",
        recurrenceRules => [{
            frequency => 'weekly',
        }],
        excludedRecurrenceRules => [{
            frequency => 'monthly',
            byMonthDay => [1],
        }],
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarIds} = $ret->{calendarIds};
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_recurrenceoverrides
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $recurrenceRules = [{
        frequency => "monthly",
        count => 12,
    }];

    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
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
        "recurrenceRules" => $recurrenceRules,
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
    $event->{calendarIds} = $ret->{calendarIds};
    delete $event->{recurrenceOverrides}{"2016-07-01T09:00:00"}; # ignore patch with 'uid'
    $self->assert_normalized_event_equals($event, $ret);

    $ret = $self->updateandget_event({
            id => $event->{id},
            calendarIds => $event->{calendarIds},
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
        calendarIds => {
            $calid => JSON::true,
        },
        "showWithoutTime" => JSON::false,
        "timeZone" => "America/New_York",
        "freeBusyStatus" =>"busy",
        "start" =>"2019-01-12T00:00:00",
        "useDefaultAlerts" => JSON::false,
        "uid" =>"76f46024-7284-4701-b93f-d9cd812f3f43",
        "title" =>"timed event with non-zero time until",
        "\@type" =>"Event",
        "recurrenceRules" => [{
            "frequency" =>"weekly",
            "until" =>"2019-04-20T23:59:59"
        }],
        "description" =>"",
        "duration" =>"P1D"
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{recurrenceRules}[0]{until} = '2019-04-20T23:59:59';
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
        calendarIds => {
            $calid => JSON::true,
        },
        "showWithoutTime" => JSON::false, # for testing
        "timeZone" =>undef,
        "freeBusyStatus" =>"busy",
        "start" =>"2019-01-12T00:00:00",
        "useDefaultAlerts" => JSON::false,
        "uid" =>"76f46024-7284-4701-b93f-d9cd812f3f43",
        "title" =>"allday event with non-zero time until",
        "\@type" =>"Event",
        "recurrenceRules" => [{
            "frequency" =>"weekly",
            "until" =>"2019-04-20T23:59:59"
        }],
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
        calendarIds => {
            $calid => JSON::true,
        },
		"start" => "2019-01-31T09:00:00",
		"duration" => "PT1H",
		"timeZone" => "Australia/Melbourne",
		"\@type" => "Event",
		"title" => "Recurrence test",
		"description" => "",
		"showWithoutTime" => JSON::false,
		"recurrenceRules" => [{
			"frequency" => "monthly",
			"byMonthDay" => [
				-1
			]
		}],
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
                    calendarIds => {
                        Default => JSON::true,
                    },
                    "title"=> "title",
                    "description"=> "description",
                    "start"=> "2019-01-01T09:00:00",
                    "duration"=> "PT1H",
                    "timeZone" => "Europe/London",
                    "showWithoutTime"=> JSON::false,
                    "freeBusyStatus"=> "busy",
                    "recurrenceRules" => [{
                        frequency => 'monthly',
                    }],
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
        calendarIds => {
            $calid => JSON::true,
        },
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
                links => {
                    link1 => {
                        href => 'https://somelink.local',
                        rel => "enclosure",
                    },
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
                links => {
                    link1 => {
                        href => 'https://somelink.local',
                        rel => "enclosure",
                    },
                },
                email => 'bar2@local', # different email than sendTo
                sendTo => {
                    imip => 'mailto:bar@local',
                },
                invitedBy => 'foo',
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
    $event->{calendarIds} = $ret->{calendarIds};
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
                    calendarIds => {
                        Default => JSON::true,
                    },
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
                    calendarIds => {
                        Default => JSON::true,
                    },
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
                    calendarIds => {
                        Default => JSON::true,
                    },
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
    $self->assert($res->{content} =~ /BEGIN:VALARM[\s\S]+DESCRIPTION:Reminder[\s\S]+END:VALARM/g);
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
        calendarIds => {
            $calid => JSON::true,
        },
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
    };

    my $ret = $self->createandget_event($event);
    $event->{id} = $ret->{id};
    $event->{calendarIds} = $ret->{calendarIds};
    delete($ret->{participants}{foo}{scheduleStatus});

    $self->assert_normalized_event_equals($event, $ret);

    # check that we can fetch again a second time and still have the same data
    my $res = $jmap->CallMethods([['CalendarEvent/get', { ids => [ $event->{id} ] }, 'R1']]);
    $ret = $res->[0][1]{list}[0];
    delete($ret->{participants}{foo}{scheduleStatus});
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_participants_justorga
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
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

sub test_calendarevent_set_created_legacy
    :min_version_3_1 :max_version_3_6 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
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
                            calendarIds => {
                                $calidA => JSON::true,
                            },
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
    $self->assert_deep_equals({$calidA => JSON::true}, $event->{calendarIds});
    $self->assert_str_equals($state, $res->[0][1]{state});

    xlog $self, "move event to unknown calendar";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id => {
                            calendarIds => {
                                nope => JSON::true,
                            },
                        }
                    }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notUpdated}{$id}{type});
    $self->assert_str_equals($state, $res->[0][1]{newState});

    xlog $self, "get calendar $id from untouched calendar $calidA";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_deep_equals({$calidA => JSON::true}, $event->{calendarIds});

    xlog $self, "move event to calendar $calidB";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        $id => {
                            calendarIds => {
                                $calidB => JSON::true,
                            },
                        }
                    }}, "R1"]]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $state = $res->[0][1]{newState};

    xlog $self, "get calendar $id";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$id]}, "R1"]]);
    $event = $res->[0][1]{list}[0];
    $self->assert_str_equals($id, $event->{id});
    $self->assert_deep_equals({$calidB => JSON::true}, $event->{calendarIds});
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
        calendarIds => {
            $CalendarId1 => JSON::true,
        },
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
        calendarIds => {
            $CalendarId1 => JSON::true,
        },
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
                            calendarIds => {
                                $CalendarId1 => JSON::true,
                            },
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
                            calendarIds => {
                                $CalendarId1 => JSON::true,
                            },
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
                            calendarIds => {
                                $CalendarId2 => JSON::true,
                            },
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
                            calendarIds => {
                                $CalendarId2 => JSON::true,
                            },
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
                            calendarIds => {
                                $calidA => JSON::true,
                            },
                            "title" => "1",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                        },
                        "2" => {
                            calendarIds => {
                                $calidB => JSON::true,
                            },
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
                            calendarIds => {
                                $calidA => JSON::true,
                            },
                            "title" => "1(updated)",
                        },
                        $id2 => {
                            calendarIds => {
                                $calidB => JSON::true,
                            },
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
                            calendarIds => {
                                $calidA => JSON::true,
                            },
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
                            calendarIds => {
                                $calidB => JSON::true,
                            },
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
                            calendarIds => {
                                $calidB => JSON::true,
                            },
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
                            calendarIds => {
                                $calidA => JSON::true,
                            },
                            "title" => "foo",
                            "description" => "bar",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
                            "start" => "2016-07-01T10:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                        "2" => {
                            calendarIds => {
                                $calidB => JSON::true,
                            },
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
                        "after" => "2015-12-31T00:00:00",
                        "before" => "2016-12-31T23:59:59",
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
                                "after" => "2015-12-31T00:00:00",
                                "before" => "2016-12-31T23:59:59"
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
                    name => "A",
                },
                "2" => {
                    name => "B",
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
                            "calendarIds" => {
                                $calidA => JSON::true,
                            },
                            "title" => "foo",
                            "description" => "bar",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
                            "start" => "2016-07-01T10:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                        },
                        "2" => {
                            "calendarIds" => {
                                $calidB => JSON::true,
                            },
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
                        "after" => "2015-12-31T00:00:00",
                        "before" => "2016-12-31T23:59:59"
                    }
                }, "R1"] ]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "CalDAV delete calendar as cassandane";
    $caldav->DeleteCalendar("/dav/calendars/user/cassandane/$calidA");

    xlog $self, "get filtered calendar event list";
    $res = $jmap->CallMethods([ ['CalendarEvent/query', {
                    "filter" => {
                        "after" => "2015-12-31T00:00:00",
                        "before" => "2016-12-31T23:59:59"
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
                                calendarIds => {
                                    $calidA => JSON::true,
                                },
                                "title" => "foo",
                                "description" => "bar",
                                "freeBusyStatus" => "busy",
                                "showWithoutTime" => JSON::false,
                                "start" => "2016-07-01T10:00:00",
                                "timeZone" => "Europe/Vienna",
                                "duration" => "PT1H",
                            },
                            "2" => {
                                calendarIds => {
                                    $calidB => JSON::true,
                                },
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
                            "after" => "2015-12-31T00:00:00",
                            "before" => "2016-12-31T23:59:59",
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
                                    "after" => "2015-12-31T00:00:00",
                                    "before" => "2016-12-31T23:59:59"
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
                            calendarIds => {
                                $calid => JSON::true,
                            },
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
                        "after" =>  "2016-01-01T08:00:00",
                        "before" => "2016-01-01T09:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Check that boundaries are exclusive
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T09:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "before" =>  "2016-01-01T08:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});

    # Embedded subrange matches
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T08:15:00",
                        "before" => "2016-01-01T08:45:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Overlapping subrange matches
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T08:15:00",
                        "before" => "2016-01-01T09:15:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T07:45:00",
                        "before" => "2016-01-01T08:15:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Create an infinite recurring datetime event
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2017-01-01T08:00:00Z End: eternity
                        "1" => {
                            calendarIds => {
                                $calid => JSON::true,
                            },
                            "title" => "e",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::false,
                            "start" => "2017-01-01T09:00:00",
                            "timeZone" => "Europe/Vienna",
                            "duration" => "PT1H",
                            "recurrenceRules" => [{
                                "frequency" => "yearly",
                            }],
                        },
                    }}, "R1"]]);
    # Assert both events are found
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    # Search close to eternity
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2038-01-01T00:00:00",
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
                            calendarIds => {
                                $calid => JSON::true,
                            },
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
                        "after" =>  "2016-01-01T00:00:00",
                        "before" => "2016-01-03T23:59:59",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match after on the first second of the start day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00",
                        "before" => "2016-01-03T00:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match before on the last second of the end day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-03T23:59:59",
                        "before" => "2016-01-03T23:59:59",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match on interim day
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-02T00:00:00",
                        "before" => "2016-01-03T00:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Match on partially overlapping timerange
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2015-12-31T12:00:00",
                        "before" => "2016-01-01T12:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2015-01-03T12:00:00",
                        "before" => "2016-01-04T12:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # Difference from the spec: 'before' is defined to be exclusive, but
    # a full-day event starting on that day still matches.
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2015-12-31T00:00:00",
                        "before" => "2016-01-01T00:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    # In DAV db the event ends at 20160104. Test that it isn't returned.
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-04T00:00:00",
                        "before" => "2016-01-04T23:59:59",
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, $res->[0][1]{total});

    # Create an infinite recurring datetime event
    $res = $jmap->CallMethods([['CalendarEvent/set', { create => {
                        # Start: 2017-01-01T08:00:00Z End: eternity
                        "1" => {
                            calendarIds => {
                                $calid => JSON::true,
                            },
                            "title" => "2",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2017-01-01T00:00:00",
                            "duration" => "P1D",
                            "recurrenceRules" => [{
                                "frequency" => "yearly",
                            }],
                        },
                    }}, "R1"]]);
    # Assert both events are found
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2016-01-01T00:00:00",
                    },
                }, "R1"]]);
    $self->assert_num_equals(2, $res->[0][1]{total});
    # Search close to eternity
    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "2038-01-01T00:00:00",
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
                            calendarIds => {
                                Default => JSON::true,
                            },
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
                            recurrenceRules => [{
                                frequency => "monthly",
                                count => 12,
                            }],
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
        calendarIds => {
            $calid => JSON::true,
        },
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
                        "after" =>  "1969-01-01T00:00:00",
                        "before" => "1969-12-31T23:59:59",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, $res->[0][1]{total});

    $res = $jmap->CallMethods([['CalendarEvent/query', {
                    "filter" => {
                        "after" =>  "1949-06-20T00:00:00",
                        "before" => "1968-10-14T00:00:00",
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    'uid' => 'event1uid',
                    'title' => 'event1',
                    'start' => '2019-10-01T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
                '2' => {
                    calendarIds => {
                        $calid => JSON::true,
                    },
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    'uid' => 'event1uid',
                    'title' => 'event1',
                    'start' => '2019-10-01T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
                '2' => {
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    'uid' => 'event2uid',
                    'title' => 'event2',
                    'start' => '2019-10-02T10:00:00',
                    'timeZone' => 'Etc/UTC',
                },
                '3' => {
                    calendarIds => {
                        $calid => JSON::true,
                    },
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
                            calendarIds => {
                                $calid => JSON::true,
                            },
                            "title" => "foo",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-06T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);
    my $eventId1 = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get x-href of event $eventId1";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$eventId1]}, "R1"]]);
    my $xhref = $res->[0][1]{list}[0]{"x-href"};
    my $state = $res->[0][1]{state};

    xlog $self, "GET event $eventId1 in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    my $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:foo/, $ical);

    xlog $self, "DELETE event $eventId1 via CalDAV";
    $res = $caldav->Request('DELETE', $xhref);

    xlog $self, "get (non-existent) event $eventId1";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$eventId1]}, "R1"]]);
    $self->assert_str_equals($eventId1, $res->[0][1]{notFound}[0]);

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($eventId1, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]{newState};

    my $uid2 = '97c46ea4-4182-493c-87ef-aee4edc2d38b';
    $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:$uid2
SUMMARY:bar
DESCRIPTION:
TRANSP:OPAQUE
DTSTART;VALUE=DATE:20151008
DTEND;VALUE=DATE:20151009
END:VEVENT
END:VCALENDAR
EOF
    my $eventId2 = encode_eventid($uid2);

    xlog $self, "PUT event with UID $uid2";
    $res = $caldav->Request('PUT', "$calid/$uid2.ics", $ical, 'Content-Type' => 'text/calendar');

    xlog $self, "get calendar event updates";
    $res = $jmap->CallMethods([['CalendarEvent/changes', { sinceState => $state }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{updated}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{destroyed}});
    $self->assert_equals($eventId2, $res->[0][1]{created}[0]);
    $state = $res->[0][1]{newState};

    xlog $self, "get x-href of event $eventId2";
    $res = $jmap->CallMethods([['CalendarEvent/get', {ids => [$eventId2]}, "R1"]]);
    $xhref = $res->[0][1]{list}[0]{"x-href"};
    $state = $res->[0][1]{state};

    xlog $self, "update event $eventId2";
    $res = $jmap->CallMethods([['CalendarEvent/set', { update => {
                        "$eventId2" => {
                            calendarIds => {
                                $calid => JSON::true,
                            },
                            "title" => "bam",
                            "description" => "",
                            "freeBusyStatus" => "busy",
                            "showWithoutTime" => JSON::true,
                            "start" => "2015-10-10T00:00:00",
                            "duration" => "P1D",
                            "timeZone" => undef,
                        }
                    }}, "R1"]]);

    xlog $self, "GET event $eventId2 in CalDAV";
    $res = $caldav->Request('GET', $xhref);
    $ical = $res->{content};
    $self->assert_matches(qr/SUMMARY:bam/, $ical);

    xlog $self, "destroy event $eventId2";
    $res = $jmap->CallMethods([['CalendarEvent/set', { destroy => [$eventId2] }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_equals($eventId2, $res->[0][1]{destroyed}[0]);

    xlog $self, "PROPFIND calendar $calid for non-existent event UID $uid2 in CalDAV";
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
    $self->assert_does_not_match(qr{$uid2}, $res);
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
                            calendarIds => {
                                Default => JSON::true,
                            },
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
            calendarIds => {
                Default => JSON::true,
            },
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
                            calendarIds => {
                                $calid => JSON::true,
                            },
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
                            calendarIds => {
                                $calid => JSON::true,
                            },
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
            calendarIds => {
                Default => JSON::true,
            },
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
            calendarIds => {
                '#c1' => JSON::true,
            },
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

    $self->assert_deep_equals({$calendar->{id} => JSON::true}, $event->{calendarIds});
}

sub test_misc_timezone_expansion
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";
    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
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
        "recurrenceRules" => [{
            frequency => "weekly",
        }],
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
        calendarIds => {
            $calid => JSON::true,
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
        "privacy" => "secret",
        "participants" => undef,
        "alerts"=> undef,
    };

    # An empty UID generates a random uid.
    my $ret = $self->createandget_event($event);
    my($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_not_null($ret->{id});
    $self->assert_str_equals(encode_eventid($ret->{uid}), $ret->{id});
    $self->assert_str_equals(encode_eventid($filename), $ret->{id});

    # A sane UID maps to both the JMAP id and the DAV resource.
    $event->{uid} = "458912982-some_UID";
    delete $event->{id};
    $ret = $self->createandget_event($event);
    ($filename, $dirs, $suffix) = fileparse($ret->{"x-href"}, ".ics");
    $self->assert_str_equals($event->{uid}, $filename);
    $self->assert_str_equals(encode_eventid($event->{uid}), $ret->{id});

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
    $self->assert_str_equals("EB-", substr($ret->{id}, 0, 3));
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
        calendarIds => {
            $srcCalendarId => JSON::true,
        },
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
                calendarIds => {
                    $dstCalendarId => JSON::true,
                },
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
        calendarIds => {
            $calid => JSON::true,
        },
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
                        calendarIds => {
                            $calendarId => JSON::true,
                        },
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
    $self->assert_equals(JSON::true, $calendar->{myRights}->{mayReadFreeBusy});
    $self->assert_equals(JSON::true, $calendar->{myRights}->{mayReadItems});
    $self->assert_equals(JSON::false, $calendar->{myRights}->{mayWriteAll});
    $self->assert_equals(JSON::false, $calendar->{myRights}->{mayWriteOwn});
    $self->assert_equals(JSON::true, $calendar->{myRights}->{mayDelete});
    $self->assert_equals(JSON::true, $calendar->{myRights}->{mayAdmin});

    $self->assert_not_null($res->[1][1]{notCreated}{1});
    $self->assert_str_equals("invalidProperties", $res->[1][1]{notCreated}{1}{type});
    $self->assert_str_equals("calendarIds", $res->[1][1]{notCreated}{1}{properties}[0]);
}

sub test_calendarevent_set_rsvpsequence
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my ($id, $ical) = $self->icalfile('rsvpsequence');

    my $event = $self->putandget_vevent($id, $ical);
    $self->assert_not_null($event);
    $self->assert_num_equals(1, $event->{sequence});

    my $eventId = $event->{id};

    # Update a partstat doesn't bump sequence.
    my $res = $jmap->CallMethods([
            ['CalendarEvent/set',{
                update => {
                    $eventId => {
                        ('participants/me/participationStatus') => 'accepted',
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
        calendarIds => {
            $calid => JSON::true,
        },
        "title"=> "title",
        "start"=> "2015-11-07T09:00:00",
        "duration"=> "PT1H",
        "timeZone" => "Europe/London",
        "showWithoutTime"=> JSON::false,
        "recurrenceRules"=> [{
            "frequency"=> "weekly",
        }],
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
    my $admin = $self->{adminstore}->get_client();

    my $calid = "Default";
    my $event =  {
        calendarIds => {
            $calid => JSON::true,
        },
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
        "recurrenceRules" => [{
            "frequency" => "monthly",
            count => 12,
        }],
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
    $self->assert_deep_equals([
        {
            '@type' => 'RecurrenceRule',
            count          => 12,
            firstDayOfWeek => 'mo',
            frequency      => 'monthly',
            interval       => 1,
            rscale         => 'gregorian',
            skip           => 'omit'
        }],
        $ret->{recurrenceRules},
    );

    # FIXME Net-CalDAV talk needs to update
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
        'urn:ietf:params:jmap:calendars',
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'weekly',
                        count => 3,
                    }, {
                        frequency => 'hourly',
                        byHour => [9, 14, 22],
                        count => 2,
                    }],
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
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
                before => '2019-02-01T00:00:00',
            },
            sort => [{
                property => 'start',
                isAscending => JSON::false,
            }],
            expandRecurrences => JSON::true,
        }, 'R1']
    ]);
    $self->assert_num_equals(6, $res->[0][1]{total});
    $self->assert_deep_equals([
           encode_eventid('event1uid','20190115T090000'),
           encode_eventid('event1uid','20190108T090000'),
           encode_eventid('event1uid','20190103T130000'),
           encode_eventid('event2uid'),
           encode_eventid('event1uid','20190101T140000'),
           encode_eventid('event1uid','20190101T090000'),
    ], $res->[0][1]{ids});
}

sub test_calendarevent_query_expandrecurrences_with_exrule
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2020-08-04T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'weekly',
                        interval => 4,
                    }],
                    excludedRecurrenceRules => [{
                        frequency => 'monthly',
                        byMonthDay => [1],
                    }, {
                        frequency => 'monthly',
                        byMonthDay => [4,22],
                    }],
                    recurrenceOverrides => {
                        '2021-01-01T09:00:00' => {
                            title => 'rdate overrides exrule',
                        },
                    },
                },
            }
        }, 'R1']
    ]);

    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
            filter => {
                before => '2021-02-01T00:00:00',
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
         encode_eventid('event1uid','20210119T090000'),
         encode_eventid('event1uid','20210101T090000'),
         encode_eventid('event1uid','20201124T090000'),
         encode_eventid('event1uid','20201027T090000'),
         encode_eventid('event1uid','20200929T090000'),
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'weekly',
                        count => 5,
                    }, {
                        frequency => 'daily',
                        count => 2,
                    }],
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

    my @ids = (
        encode_eventid('event1uid','20190108T090000'),
        encode_eventid('event1uid','20190115T090000'),
        encode_eventid('event1uid','20190110T120000'),
        encode_eventid('event1uid','20190122T090000'), # is excluded
        encode_eventid('event1uid','20191201T090000'), # does not exist
        encode_eventid('event1uid','20190102T090000'), # from second rrule
    );
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
                ids => \@ids,
                properties => ['start', 'title', 'recurrenceId'],
        }, 'R1'],
    ]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]{list}});

    $self->assert_str_equals($ids[0], $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('2019-01-08T09:00:00', $res->[0][1]{list}[0]{start});
    $self->assert_str_equals('2019-01-08T09:00:00', $res->[0][1]{list}[0]{recurrenceId});

    $self->assert_str_equals($ids[1], $res->[0][1]{list}[1]{id});
    $self->assert_str_equals('override1', $res->[0][1]{list}[1]{title});
    $self->assert_str_equals('2019-01-15T09:00:00', $res->[0][1]{list}[1]{start});
    $self->assert_str_equals('2019-01-15T09:00:00', $res->[0][1]{list}[1]{recurrenceId});

    $self->assert_str_equals($ids[2], $res->[0][1]{list}[2]{id});
    $self->assert_str_equals('2019-01-10T12:00:00', $res->[0][1]{list}[2]{start});
    $self->assert_str_equals('2019-01-10T12:00:00', $res->[0][1]{list}[2]{recurrenceId});

    $self->assert_str_equals($ids[5], $res->[0][1]{list}[3]{id});
    $self->assert_str_equals('2019-01-02T09:00:00', $res->[0][1]{list}[3]{start});
    $self->assert_str_equals('2019-01-02T09:00:00', $res->[0][1]{list}[3]{recurrenceId});

    $self->assert_num_equals(2, scalar @{$res->[0][1]{notFound}});
    $self->assert_str_equals($ids[3], $res->[0][1]{notFound}[0]);
    $self->assert_str_equals($ids[4], $res->[0][1]{notFound}[1]);
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'weekly',
                        count => 5,
                    }],
                },
            }
        }, 'R1']
    ]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId1);

    # This test hard-codes the ids of recurrence instances.
    # This might break if we change the id scheme.

    xlog $self, "Override a regular recurrence instance";
    my $overrideId1 = encode_eventid('event1uid','20190115T090000');
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $overrideId1 => {
                    title => "override1",
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$overrideId1});
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
                $overrideId1 => {
                    title => "override1_updated",
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$overrideId1});
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
                $overrideId1 => {
                    title => "event1", # original title
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$overrideId1});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Set regular recurrence excluded";
    my $overrideId2 = encode_eventid('event1uid','20190108T090000');
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $overrideId2 => {
                    excluded => JSON::true,
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$overrideId2});
    $self->assert_deep_equals({
        '2019-01-08T09:00:00' => {
            excluded => JSON::true,
        }
    }, $res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Reset overrides";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId1 => {
                    recurrenceOverrides => undef,
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId1});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Destroy regular recurrence instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [$overrideId2],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['event1uid'],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert_str_equals($overrideId2, $res->[0][1]{destroyed}[0]);
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    uid => 'event1uid',
                    title => "event1",
                    description => "",
                    freeBusyStatus => "busy",
                    start => "2019-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'weekly',
                        count => 5,
                    }],
                    recurrenceOverrides => {
                        '2019-01-10T14:00:00' => {}
                    },
                },
            }
        }, 'R1']
    ]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId1);

    xlog $self, "Delete RDATE by setting it excluded";
    my $overrideId1 = encode_eventid('event1uid','20190110T140000');
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $overrideId1 => {
                    excluded => JSON::true,
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$overrideId1});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

    xlog $self, "Recreate RDATE";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId1 => {
                    recurrenceOverrides => {
                        '2019-01-10T14:00:00' => {}
                    },
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId1});
    $self->assert_deep_equals({
            '2019-01-10T14:00:00' => { },
        },
        $res->[1][1]{list}[0]{recurrenceOverrides}
    );

    xlog $self, "Destroy RDATE";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [$overrideId1],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert_str_equals($overrideId1, $res->[0][1]{destroyed}[0]);
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
                    calendarIds => {
                        Default => JSON::true,
                    },
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
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    xlog $self, "create calendar event in other users calendar";

    my $res = $otherJmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarIds => {
                        Default => JSON::true,
                    },
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

    xlog $self, "update event";

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'other',
            update => {
                $eventId => {
                    title => 'updatedTitle',
                }
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            accountId => 'other',
            ids => [$eventId],
            properties => ['blobId'],
        }, 'R1'],

    ]);
    $self->assert_str_equals($res->[0][1]{updated}{$eventId}{blobId},
        $res->[1][1]{list}[0]{blobId});
    $self->assert_str_not_equals($cassBlobId, $res->[1][1]{list}[0]{blobId});
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
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    xlog $self, "create calendar event in other users calendar";

    my $res = $otherJmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarIds => {
                        Default => JSON::true,
                    },
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

    xlog $self, "get debugBlobId as regular user";

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
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
    my $debugBlobId = $res->[0][1]{list}[0]{debugBlobId};
    $self->assert_not_null($debugBlobId);

    xlog $self, "attempt to download debugBlob as non-admin (should fail)";

    my $downloadUri = $jmap->downloaduri('other', $debugBlobId);
    my %Headers = (
        'Authorization' => $jmap->auth_header(),
    );
    my $RawResponse = $jmap->ua->get($downloadUri, { headers => \%Headers });
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawResponse);
    }
    $self->assert_str_equals('404', $RawResponse->{status});

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
    $debugBlobId = $res->[0][1]{list}[0]{debugBlobId};
    $self->assert_not_null($debugBlobId);

    xlog $self, "download debugBlob with userdata";

    $res = $adminJmap->Download('other', $debugBlobId);
    $self->assert_str_equals("multipart/mixed", substr($res->{headers}{'content-type'}, 0, 15));
    $self->assert_num_not_equals(-1, index($res->{content}, 'SUMMARY:event1'));
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
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    "title"=> "title",
                    "description"=> "description",
                    "start"=> "2015-11-07T09:00:00",
                    "duration"=> "PT2H",
                    "timeZone" => "Europe/London",
                    "showWithoutTime"=> JSON::false,
                    recurrenceRules => [{
                        frequency => 'weekly',
                    }],
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
                after =>  '2020-04-21T14:00:00',
                before => '2020-04-22T13:59:59',
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
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj == 3 && $min >= 6) {
        $self->assert_num_equals(1, scalar @locations);
        $self->assert_str_equals("xyz\nxyz", $locations[0]{name});
    }
    else {
        $self->assert_num_equals(2, scalar @locations);
        $self->assert_str_equals("xyz\nxyz", $locations[0]{name});
        $self->assert_str_equals("xyz\nxyz", $locations[1]{name});
    }
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
               "ical1" => { 'data:asText' => $ical1, type => 'text/calendar' },
               "ical2" => { 'data:asText' => $ical2, type => 'text/calendar' },
               "junk" => { 'data:asText' => 'foo bar', type => 'text/calendar' }
             } }, 'R0'],
        ['CalendarEvent/parse', {
            blobIds => [ "#ical1", "foo", "#junk", "#ical2" ],
            properties => [ "\@type", "uid", "title", "start",
                            "recurrenceRules", "recurrenceOverrides" ]
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
    $self->assert_str_equals($id2, $res->[1][1]{parsed}{"#ical2"}{entries}[1]{uid});
    $self->assert_str_equals("Event #2", $res->[1][1]{parsed}{"#ical2"}{entries}[1]{title});
    $self->assert_not_null($res->[1][1]{parsed}{"#ical2"}{entries}[1]{recurrenceRules});
    $self->assert_not_null($res->[1][1]{parsed}{"#ical2"}{entries}[1]{recurrenceOverrides});
    $self->assert_str_equals($id1, $res->[1][1]{parsed}{"#ical2"}{entries}[0]{uid});
    $self->assert_str_equals("foo", $res->[1][1]{parsed}{"#ical2"}{entries}[0]{title});

    $self->assert_str_equals("#junk", $res->[1][1]{notParsable}[0]);
    $self->assert_str_equals("foo", $res->[1][1]{notFound}[0]);
}

sub test_calendarevent_set_too_large
    :min_version_3_5 :needs_component_jmap :iCalendarMaxSize10k
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
                            "calendarIds" => {
                                $calid => JSON::true,
                            },
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
                    calendarIds => {
                        'Default' => JSON::true,
                    },
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
                    calendarIds => {
                        '#calendarB' => JSON::true,
                    },
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
                after =>  '2021-03-27T23:00:00',
                before => '2021-03-28T02:00:00'
            },
        }, 'R1'],
        ['CalendarEvent/query', {
            filter => {
                after =>  '2021-03-28T02:00:00',
                before => '2021-03-28T23:00:00'
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
            properties => ['calendarIds'],
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
            properties => ['calendarIds'],
        }, 'R4'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_deep_equals({
        $defaultCalendarId => JSON::true,
    }, $res->[1][1]{list}[0]{calendarIds});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{ids}});
    $self->assert_deep_equals({
        $defaultCalendarId => JSON::true,
    }, $res->[3][1]{list}[0]{calendarIds});
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
        'urn:ietf:params:jmap:calendars',
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

sub test_calendarevent_set_isdraft
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $calid = "Default";

    # Create events as draft and non-draft.

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    "title"=> "draft",
                    "start"=> "2019-12-05T09:00:00",
                    "duration"=> "PT5M",
                    "timeZone"=> "Etc/UTC",
                    "isDraft" => JSON::true,
                },
                2 => {
                    calendarIds => {
                        $calid => JSON::true,
                    },
                    "title"=> "non-draft",
                    "start"=> "2019-12-05T10:00:00",
                    "duration"=> "PT5M",
                    "timeZone"=> "Etc/UTC",
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1', '#2'], properties => ['isDraft'],
        }, 'R2']
    ]);
    my $eventDraftId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventDraftId);
    my $eventNonDraftId = $res->[0][1]{created}{2}{id};
    $self->assert_not_null($eventNonDraftId);

    my %events = map { $_->{id} => $_ } @{$res->[1][1]{list}};
    $self->assert_equals(JSON::true, $events{$eventDraftId}{isDraft});
    $self->assert_equals(JSON::false, $events{$eventNonDraftId}{isDraft});

    # Updating an arbitrary property preserves draft flag.

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventDraftId => {
                    description => "updated",
                },
                $eventNonDraftId => {
                    description => "updated",
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventDraftId, $eventNonDraftId], properties => ['isDraft'],
        }, 'R2']
    ]);
    $self->assert_not_null($res->[0][1]{updated}{$eventDraftId});
    $self->assert_not_null($res->[0][1]{updated}{$eventNonDraftId});

    %events = map { $_->{id} => $_ } @{$res->[1][1]{list}};
    $self->assert_equals(JSON::true, $events{$eventDraftId}{isDraft});
    $self->assert_equals(JSON::false, $events{$eventNonDraftId}{isDraft});

    # Toggle isDraft flags (only allowed from draft to non-draft)

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventDraftId => {
                    "isDraft" => JSON::false,
                },
                $eventNonDraftId => {
                    "isDraft" => JSON::true,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventDraftId, $eventNonDraftId], properties => ['isDraft'],
        }, 'R2']
    ]);
    $self->assert_not_null($res->[0][1]{updated}{$eventDraftId});
    $self->assert_not_null($res->[0][1]{notUpdated}{$eventNonDraftId});

    %events = map { $_->{id} => $_ } @{$res->[1][1]{list}};
    $self->assert_equals(JSON::false, $events{$eventDraftId}{isDraft});
    $self->assert_equals(JSON::false, $events{$eventNonDraftId}{isDraft});
}

sub test_calendarevent_get_utcstart
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Initialize calendar timezone.
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    timeZone => 'America/New_York',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    # Assert utcStart for main event and recurrenceOverrides.
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-06T11:21:01",
                    duration => "PT5M",
                    timeZone => "Europe/Vienna",
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 3,
                    }],
                    recurrenceOverrides => {
                        '2019-12-07T11:21:01.8' => {
                            start => '2019-12-07T13:00:00',
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => ['utcStart', 'utcEnd', 'recurrenceOverrides'],
        }, 'R2']
    ]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId1);
    my $event = $res->[1][1]{list}[0];
    $self->assert_not_null($event);

    $self->assert_str_equals('2019-12-06T10:21:01Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-06T10:26:01Z', $event->{utcEnd});
    $self->assert_str_equals('2019-12-07T12:00:00Z',
        $event->{recurrenceOverrides}{'2019-12-07T11:21:01'}{utcStart});
    $self->assert_str_equals('2019-12-07T12:05:00Z',
        $event->{recurrenceOverrides}{'2019-12-07T11:21:01'}{utcEnd});

    # Assert utcStart for regular recurrence instance.
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [encode_eventid('eventuid1local', '20191208T112101')],
            properties => ['utcStart', 'utcEnd'],
        }, 'R2']
    ]);
    $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);

    $self->assert_str_equals('2019-12-08T10:21:01Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-08T10:26:01Z', $event->{utcEnd});

    # Assert utcStart for floating event with calendar timeZone.
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                2 => {
                    uid => 'eventuid2local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event2",
                    start => "2019-12-08T23:30:00",
                    duration => "PT2H",
                    timeZone => undef,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#2'],
            properties => ['utcStart', 'utcEnd', 'timeZone'],
        }, 'R2']
    ]);
    my $eventId2 = $res->[0][1]{created}{2}{id};
    $self->assert_not_null($eventId2);
    $event = $res->[1][1]{list}[0];
    $self->assert_not_null($event);

    # Floating event time falls back to calendar time zone America/New_York.
    $self->assert_str_equals('2019-12-09T04:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-09T06:30:00Z', $event->{utcEnd});
}

sub test_calendarevent_utcstart_customtz
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    # Set custom calendar timezone. DST starts on December 1 at 2am.
    my $CalendarId = $CalDAV->NewCalendar({name => 'mycalendar'});
    $self->assert_not_null($CalendarId);
    my $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:calendar-timezone>
BEGIN:VCALENDAR
PRODID:-//Example Corp.//CalDAV Client//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:Test
LAST-MODIFIED:19870101T000000Z
BEGIN:STANDARD
DTSTART:19670601T020000
RRULE:FREQ=YEARLY;BYMONTHDAY=1;BYMONTH=6
TZOFFSETFROM:-0700
TZOFFSETTO:-0800
TZNAME:TST
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19871201T020000
RRULE:FREQ=YEARLY;BYMONTHDAY=1;BYMONTH=12
TZOFFSETFROM:-0800
TZOFFSETTO:-0700
TZNAME:TST
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
</C:calendar-timezone>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane/Default",
                       $proppatchXml, 'Content-Type' => 'text/xml');

    # Create floating time event.
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-11-30T23:30:00",
                    duration => "PT6H",
                    timeZone => undef,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => ['utcStart', 'utcEnd', 'timeZone'],
        }, 'R2']
    ]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId1);
    my $event = $res->[1][1]{list}[0];
    $self->assert_not_null($event);

    # Floating event time falls back to custom calendar time zone.
    $self->assert_str_equals('2019-12-01T07:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-01T12:30:00Z', $event->{utcEnd});

    # Assert event updates.
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId1 => {
                    utcStart => "2019-12-01T06:30:00Z",
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['start', 'utcStart', 'utcEnd', 'timeZone', 'duration'],
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId1});

    $event = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-11-30T22:30:00', $event->{start});
    $self->assert_str_equals('2019-12-01T06:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-01T11:30:00Z', $event->{utcEnd});
    $self->assert_null($event->{timeZone});
    $self->assert_str_equals('PT6H', $event->{duration});
}

sub test_calendarevent_set_utcstart
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Assert event creation.
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    utcStart => "2019-12-10T23:30:00Z",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                },
                2 => {
                    uid => 'eventuid2local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event2",
                    utcStart => "2019-12-10T23:30:00Z",
                    duration => "PT1H",
                    timeZone => undef, # floating
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => ['start', 'utcStart', 'utcEnd', 'timeZone', 'duration'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => ['#2'],
            properties => ['start', 'utcStart', 'utcEnd', 'timeZone', 'duration'],
        }, 'R3']
    ]);
    my $eventId1 = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId1);
    my $eventId2 = $res->[0][1]{created}{2}{id};
    $self->assert_not_null($eventId2);

    my $event1 = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-12-11T10:30:00', $event1->{start});
    $self->assert_str_equals('2019-12-10T23:30:00Z', $event1->{utcStart});
    $self->assert_str_equals('2019-12-11T00:30:00Z', $event1->{utcEnd});
    $self->assert_str_equals('Australia/Melbourne', $event1->{timeZone});
    $self->assert_str_equals('PT1H', $event1->{duration});

    my $event2 = $res->[2][1]{list}[0];
    $self->assert_str_equals('2019-12-10T23:30:00', $event2->{start});
    $self->assert_str_equals('2019-12-10T23:30:00Z', $event2->{utcStart});
    $self->assert_str_equals('2019-12-11T00:30:00Z', $event2->{utcEnd});
    $self->assert_str_equals('Etc/UTC', $event2->{timeZone});
    $self->assert_str_equals('PT1H', $event2->{duration});

    # Assert event updates.
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId1 => {
                    utcStart => "2019-12-11T01:30:00Z",
                },
                $eventId2 => {
                    utcStart => "2019-12-10T11:30:00Z",
                    duration => 'PT30M',
                    timeZone => 'America/New_York',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId1],
            properties => ['start', 'utcStart', 'utcEnd', 'timeZone', 'duration'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => [$eventId2],
            properties => ['start', 'utcStart', 'utcEnd', 'timeZone', 'duration'],
        }, 'R3']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId1});

    $event1 = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-12-11T12:30:00', $event1->{start});
    $self->assert_str_equals('2019-12-11T01:30:00Z', $event1->{utcStart});
    $self->assert_str_equals('2019-12-11T02:30:00Z', $event1->{utcEnd});
    $self->assert_str_equals('Australia/Melbourne', $event1->{timeZone});
    $self->assert_str_equals('PT1H', $event1->{duration});

    $event2 = $res->[2][1]{list}[0];
    $self->assert_str_equals('2019-12-10T06:30:00', $event2->{start});
    $self->assert_str_equals('2019-12-10T11:30:00Z', $event2->{utcStart});
    $self->assert_str_equals('2019-12-10T12:00:00Z', $event2->{utcEnd});
    $self->assert_str_equals('America/New_York', $event2->{timeZone});
    $self->assert_str_equals('PT30M', $event2->{duration});
}

sub test_calendarevent_set_utcstart_recur
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $proplist = [
        'start',
        'utcStart',
        'utcEnd',
        'timeZone',
        'duration',
        'recurrenceOverrides',
        'title'
    ];

    # Assert event creation.
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    utcStart => "2019-12-10T23:30:00Z",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 5,
                    }],
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => $proplist,
        }, 'R2']
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);

    my $event = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-12-11T10:30:00', $event->{start});
    $self->assert_str_equals('2019-12-10T23:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-11T00:30:00Z', $event->{utcEnd});
    $self->assert_str_equals('Australia/Melbourne', $event->{timeZone});
    $self->assert_str_equals('PT1H', $event->{duration});

    # Updating utcStart on a recurring event with no overrides is OK.
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    utcStart => "2019-12-11T01:30:00Z",
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    $event = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-12-11T12:30:00', $event->{start});
    $self->assert_str_equals('2019-12-11T01:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-11T02:30:00Z', $event->{utcEnd});
    $self->assert_str_equals('Australia/Melbourne', $event->{timeZone});
    $self->assert_str_equals('PT1H', $event->{duration});

    # Updating utcStart on a expanded recurrence instance is OK.
    my $eventInstanceId = encode_eventid('eventuid1local', '20191213T123000');
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventInstanceId => {
                    utcStart => "2019-12-13T03:30:00Z",
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventInstanceId],
            properties => $proplist,
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventInstanceId});

    $event = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-12-13T14:30:00', $event->{start});
    $self->assert_str_equals('2019-12-13T03:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-13T04:30:00Z', $event->{utcEnd});
    $self->assert_str_equals('Australia/Melbourne', $event->{timeZone});
    $self->assert_str_equals('PT1H', $event->{duration});

    # Now the event has a recurrenceOverride
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R2']
    ]);
    $event = $res->[0][1]{list}[0];

    # Main event times are unchanged.
    $self->assert_str_equals('2019-12-11T12:30:00', $event->{start});
    $self->assert_str_equals('2019-12-11T01:30:00Z', $event->{utcStart});
    $self->assert_str_equals('2019-12-11T02:30:00Z', $event->{utcEnd});
    $self->assert_str_equals('Australia/Melbourne', $event->{timeZone});
    $self->assert_str_equals('PT1H', $event->{duration});

    # Overriden instance times have changed.
    my $override = $event->{recurrenceOverrides}{'2019-12-13T12:30:00'};
    $self->assert_str_equals('2019-12-13T14:30:00', $override->{start});
    $self->assert_str_equals('2019-12-13T03:30:00Z', $override->{utcStart});
    $self->assert_str_equals('2019-12-13T04:30:00Z', $override->{utcEnd});

    # It's OK to loop back a recurring event with overrides and UTC times.
    $event->{title} = 'updated title';
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => $event,
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_deep_equals($event, $res->[1][1]{list}[0]);

    # But it is not OK to update UTC times in a recurring event with overrides.
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    utcStart => '2021-01-01T11:00:00Z',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    recurrenceOverrides => {
                        '2019-12-13T12:30:00' => {
                            utcStart => '2021-01-01T11:00:00Z',
                        },
                    },
                },
            },
        }, 'R2'],
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2019-12-13T12:30:00' => {
                        utcStart => '2021-01-01T11:00:00Z',
                    },
                },
            },
        }, 'R3'],
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2019-12-13T12:30:00/utcStart' => '2021-01-01T11:00:00Z',
                },
            },
        }, 'R4'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R5']
    ]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$eventId});
    $self->assert_not_null($res->[1][1]{notUpdated}{$eventId});
    $self->assert_not_null($res->[2][1]{notUpdated}{$eventId});
    $self->assert_not_null($res->[3][1]{notUpdated}{$eventId});
}

sub test_calendarevent_set_peruser
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # These properties are set per-user.
    my $proplist = [
        'freeBusyStatus',
        'color',
        'keywords',
        'useDefaultAlerts',
        'alerts',
    ];

    xlog "Create an event and assert default per-user props";
    my $defaultPerUserProps = {
        freeBusyStatus => 'busy',
        # color omitted by default
        keywords => undef,
        useDefaultAlerts => JSON::false,
        alerts => undef,
    };
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-10T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 5,
                    }],
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => $proplist,
        }, 'R2']
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);
    my $event = $res->[1][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($defaultPerUserProps, $event);

    xlog "Create other user and share owner calendar";
    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.cassandane.#calendars.Default", "other", "lrsiwntex") or die;
    my $service = $self->{instance}->get_service("http");
    my $otherJMAPTalk = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $otherJMAPTalk->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
        'urn:ietf:params:jmap:calendars',
    ]);

    xlog "Set and assert per-user properties for owner";
    my $ownerPerUserProps = {
        freeBusyStatus => 'free',
        color => 'blue',
        keywords => {
            'ownerKeyword' => JSON::true,
        },
        useDefaultAlerts => JSON::true,
        alerts => {
            alert1 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'OffsetTrigger',
                    relativeTo => 'start',
                    offset => "-PT5M",
                },
                action => "email",
            },
        },
    };
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => $ownerPerUserProps,
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $event = $res->[1][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($ownerPerUserProps, $event);

    xlog "Assert other user per-user properties for shared event";
    $res = $otherJMAPTalk->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => $proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals({
        # inherited from owner
        color => 'blue',
        keywords => {
            'ownerKeyword' => JSON::true,
        },
        # not inherited from owner
        freeBusyStatus => 'busy',
        useDefaultAlerts => JSON::false,
        alerts => undef,
    }, $event);

    xlog "Update and assert per-user props as other user";
    my $otherPerUserProps = {
        keywords => {
            'otherKeyword' => JSON::true,
        },
        color => 'red',
        freeBusyStatus => 'free',
        useDefaultAlerts => JSON::true,
        alerts => {
            alert2 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'AbsoluteTrigger',
                    when => "2019-03-04T04:05:06Z",
                },
                action => "display",
            },
        },
    };
    $res = $otherJMAPTalk->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => $otherPerUserProps,
            },
        }, 'R1'],
        ['CalendarEvent/get', {

            accountId => 'cassandane',
            ids => [$eventId],
            properties => $proplist,
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $event = $res->[1][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($otherPerUserProps, $event);

    xlog "Assert that owner kept their per-user props";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($ownerPerUserProps, $event);

    xlog "Remove per-user props as other user";
    $otherPerUserProps = {
        keywords => undef,
        freeBusyStatus => 'free',
        useDefaultAlerts => JSON::true,
        alerts => {
            alert2 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'AbsoluteTrigger',
                    when => "2019-03-04T04:05:06Z",
                },
                action => "display",
            },
        },
    };
    $res = $otherJMAPTalk->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    keywords => undef,
                    color => undef,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => $proplist,
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $event = $res->[1][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($otherPerUserProps, $event);

    xlog "Assert that owner kept their per-user props";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => $proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($ownerPerUserProps, $event);

}

sub test_calendarevent_set_peruser_secretary
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog 'Create sharee and share cassandane calendar';
    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user('sharee');
    $admintalk->setacl('user.cassandane.#calendars.Default', 'sharee', 'lrsiwntex') or die;
    my $service = $self->{instance}->get_service('http');
    my $shareejmap = Mail::JMAPTalk->new(
        user => 'sharee',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $shareejmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
        'urn:ietf:params:jmap:calendars',
    ]);

    xlog 'Set calendar home to secretary mode';
    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:JMAP="urn:ietf:params:jmap:calendars">
  <D:set>
    <D:prop>
      <JMAP:sharees-act-as>secretary</JMAP:sharees-act-as>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $caldav->Request('PROPPATCH', "/dav/calendars/user/cassandane", $xml,
        'Content-Type' => 'text/xml');

    xlog 'Create an event with per-user props as owner';
    my $perUserProps = {
        freeBusyStatus => 'free',
        color => 'blue',
        keywords => {
            'ownerKeyword' => JSON::true,
        },
        useDefaultAlerts => JSON::true,
        alerts => {
            alert1 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'OffsetTrigger',
                    relativeTo => 'start',
                    offset => '-PT5M',
                },
                action => 'email',
            },
        },
    };
    my @proplist = keys %$perUserProps;

    my $event = {
        uid => 'eventuid1',
        calendarIds => {
            Default => JSON::true,
        },
        title => 'event1',
        start => '2019-12-10T23:30:00',
        duration => 'PT1H',
        timeZone => 'Australia/Melbourne',
    };
    $event = { %$event, %$perUserProps };
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => $event,
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);

    xlog 'assert per-user properties for owner and sharee';
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => \@proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($perUserProps, $event);

    $res = $shareejmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => \@proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($perUserProps, $event);

    xlog 'Update per-user props as sharee';
    $perUserProps = {
        freeBusyStatus => 'busy',
        color => 'red',
        keywords => {
            'shareeKeyword' => JSON::true,
        },
        useDefaultAlerts => JSON::false,
        alerts => {
            alert1 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'OffsetTrigger',
                    relativeTo => 'start',
                    offset => '-PT10M',
                },
                action => 'display',
            },
        },
    };
    $res = $shareejmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => $perUserProps,
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog 'assert per-user properties for owner and sharee';
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => \@proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($perUserProps, $event);

    $res = $shareejmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => \@proplist,
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    delete @{$event}{qw/id uid @type/};
    $self->assert_deep_equals($perUserProps, $event);
}

sub test_calendarevent_set_linkblobid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Upload blob via JMAP";
    my $res = $jmap->Upload('jmapblob', "application/octet-stream");
    my $blobId = $res->{blobId};
    $self->assert_not_null($blobId);

    xlog "Create and assert event with a Link.blobId";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-10T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    links => {
                        link1 => {
                            rel => 'enclosure',
                            blobId => $blobId,
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => ['links', 'x-href'],
        }, 'R2']
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);
    my $event = $res->[1][1]{list}[0];
    $self->assert_str_equals('enclosure', $event->{links}{link1}{rel});
    $self->assert_str_equals($blobId, $event->{links}{link1}{blobId});
    $self->assert_null($event->{links}{link1}{href});

    xlog "download blob via CalDAV";
    my $service = $self->{instance}->get_service("http");
    my $href = 'http://' . $service->host() . ':'. $service->port() .
     '/dav/calendars/user/cassandane/Attachments/' .
     substr $event->{links}{link1}{blobId}, 1;
    my $RawRequest = {
        headers => {
            'Authorization' => $CalDAV->auth_header(),
        },
    };
    $res = $CalDAV->ua->get($href, $RawRequest);
    $self->assert_str_equals('jmapblob', $res->{content});

    xlog "Remove link from event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    links => undef,
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Add attachment via CalDAV";
    $RawRequest = {
        headers => {
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => 'attachment;filename=test',
            'Prefer' => 'return=representation',
            'Authorization' => $CalDAV->auth_header(),
        },
        content => 'davattach',
    };
    my $URI = $CalDAV->request_url($event->{'x-href'}) . '?action=attachment-add';
    my $RawResponse = $CalDAV->ua->post($URI, $RawRequest);

    warn "CalDAV " . Dumper($RawRequest, $RawResponse);
    $self->assert_str_equals('201', $RawResponse->{status});

    xlog "Download attachment via JMAP";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$event->{id}],
            properties => ['links', 'x-href'],
        }, 'R1']
    ]);
    $event = $res->[0][1]{list}[0];
    my $attachmentBlobId = (values %{$event->{links}})[0]{blobId};
    $self->assert_not_null($attachmentBlobId);
    $res = $jmap->Download('cassandane', $attachmentBlobId);
    $self->assert_str_equals('davattach', $res->{content});

    xlog "Delete event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [
                $eventId,
            ],
        }, 'R1']
    ]);
    $self->assert_str_equals($eventId, $res->[0][1]{destroyed}[0]);

    xlog "blobId and href are mutually exclusive";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-10T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    links => {
                        link1 => {
                            rel => 'enclosure',
                            blobId => $blobId,
                            href => 'somehref',
                        },
                    },
                },
                2 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-10T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    links => {
                        link1 => {
                            rel => 'enclosure',
                        },
                    },
                },
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['links/link1/href', 'links/link1/blobId'],
        $res->[0][1]{notCreated}{1}{properties});
    $self->assert_deep_equals(['links/link1/href', 'links/link1/blobId'],
        $res->[0][1]{notCreated}{2}{properties});
}

sub test_calendar_get_defaultalerts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    # Set alerts via CalDAV.
    my $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:default-alarm-vevent-datetime>
BEGIN:VALARM
UID:alert1
TRIGGER:-PT5M
ACTION:DISPLAY
DESCRIPTION:alarmTime1
END:VALARM
BEGIN:VALARM
UID:alert2
TRIGGER:PT0M
ACTION:DISPLAY
DESCRIPTION:alarmTime2
END:VALARM
</C:default-alarm-vevent-datetime>
    </D:prop>
  </D:set>
  <D:set>
    <D:prop>
<C:default-alarm-vevent-date>
BEGIN:VALARM
UID:alert3
TRIGGER:PT0S
ACTION:DISPLAY
DESCRIPTION:alarmDate1
END:VALARM
</C:default-alarm-vevent-date>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane/Default",
        $proppatchXml, 'Content-Type' => 'text/xml');

    my $res = $jmap->CallMethods([
        ['Calendar/get', {
            ids => ['Default'],
            properties => ['defaultAlertsWithTime', 'defaultAlertsWithoutTime'],
        }, 'R1']
    ]);
    $self->assert_deep_equals({
        alert1 => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => 'start',
                offset => '-PT5M',
            },
            action => 'display',
        },
        alert2 =>  {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => 'start',
                offset => 'PT0S',
            },
            action => 'display',
        }
    }, $res->[0][1]{list}[0]{defaultAlertsWithTime});
    $self->assert_deep_equals({
        alert3 => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => 'start',
                offset => 'PT0S',
            },
            action => 'display',
        },
    }, $res->[0][1]{list}[0]{defaultAlertsWithoutTime});
}

sub test_calendar_set_defaultalerts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    my $defaultAlertsWithTime = {
        alert1 => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => 'start',
                offset => '-PT1H',
            },
            action => 'email',
        },
        alert2 => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => 'start',
                offset => 'PT0S',
            },
            action => 'display',
        },
    };

    my $defaultAlertsWithoutTime = {
        alert3 => {
            '@type' => 'Alert',
            trigger => {
                '@type' => 'OffsetTrigger',
                relativeTo => 'start',
                offset => 'PT0S',
            },
            action => 'display',
        },
    };

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                1 => {
                    name => 'test',
                    color => 'blue',
                    defaultAlertsWithTime => $defaultAlertsWithTime,
                    defaultAlertsWithoutTime => $defaultAlertsWithoutTime,
                }
            }
        }, 'R1'],
        ['Calendar/get', {
            ids => ['#1'],
            properties => ['defaultAlertsWithTime', 'defaultAlertsWithoutTime'],
        }, 'R2']
    ]);
    my $calendarId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($calendarId);
    $self->assert_deep_equals($defaultAlertsWithTime,
        $res->[1][1]{list}[0]{defaultAlertsWithTime});
    $self->assert_deep_equals($defaultAlertsWithoutTime,
        $res->[1][1]{list}[0]{defaultAlertsWithoutTime});

    my $alert4 = {
        '@type' => 'Alert',
        trigger => {
            '@type' => 'OffsetTrigger',
            relativeTo => 'start',
            offset => '-PT30M',
        },
        action => 'display',
    };

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                $calendarId => {
                    'defaultAlertsWithTime/alert1' => undef,
                    'defaultAlertsWithTime/alert4' => $alert4,
                    'defaultAlertsWithoutTime/alert3/trigger/offset' => '-PT5M',
                }
            }
        }, 'R1'],
        ['Calendar/get', {
            ids => [$calendarId],
            properties => ['defaultAlertsWithTime', 'defaultAlertsWithoutTime'],
        }, 'R2']
                              ]);
    $self->assert(exists $res->[0][1]{updated}{$calendarId});
    $self->assert_null($res->[1][1]{list}[0]{defaultAlertsWithTime}{alert1});
    $self->assert_deep_equals($alert4,
        $res->[1][1]{list}[0]{defaultAlertsWithTime}{alert4});
    $self->assert_equals('-PT5M',
                         $res->[1][1]{list}[0]{defaultAlertsWithoutTime}{alert3}{trigger}{offset});

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                $calendarId => {
                    defaultAlertsWithTime => undef,
                    defaultAlertsWithoutTime => undef,
                }
            }
        }, 'R1'],
        ['Calendar/get', {
            ids => [$calendarId],
            properties => ['defaultAlertsWithTime', 'defaultAlertsWithoutTime'],
        }, 'R2']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$calendarId});
    $self->assert_null($res->[1][1]{list}[0]{defaultAlertsWithTime});
    $self->assert_null($res->[1][1]{list}[0]{defaultAlertsWithoutTime});
}

sub test_calendarevent_set_defaultalerts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Set default alerts on calendar and event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                    defaultAlertsWithoutTime => {
                        alert2 => {
                           '@type' => 'Alert',
                           trigger => {
                               '@type' => 'OffsetTrigger',
                               relativeTo => 'start',
                               offset => 'PT0S',
                           },
                           action => 'display',
                       },
                    },
                }
            }
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-19T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    useDefaultAlerts => JSON::true,
                },
                2 => {
                    uid => 'eventuid2local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event2",
                    start => "2020-01-19T00:00:00",
                    showWithoutTime => JSON::true,
                    duration => "P1D",
                    useDefaultAlerts => JSON::true,
                },
            },
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});
    my $event1Href = $res->[1][1]{created}{1}{'x-href'};
    $self->assert_not_null($event1Href);
    my $event2Href = $res->[1][1]{created}{2}{'x-href'};
    $self->assert_not_null($event2Href);

    my $CaldavResponse = $CalDAV->Request('GET', $event1Href);
    my $icaldata = $CaldavResponse->{content};
    $self->assert_matches(qr/TRIGGER;RELATED=START:-PT5M/, $icaldata);

    $CaldavResponse = $CalDAV->Request('GET', $event2Href);
    $icaldata = $CaldavResponse->{content};
    $self->assert_matches(qr/TRIGGER;RELATED=START:PT0S/, $icaldata);
}

sub test_calendarevent_set_defaultalerts_etag
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Set default alerts on calendar and event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-19T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    useDefaultAlerts => JSON::true,
                },
                2 => {
                    uid => 'eventuid2local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-21T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    useDefaultAlerts => JSON::false,
                },
            },
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});
    my $event1Href = $res->[1][1]{created}{1}{'x-href'};
    $self->assert_not_null($event1Href);
    my $event2Href = $res->[1][1]{created}{2}{'x-href'};
    $self->assert_not_null($event2Href);

    xlog "Get ETags of events";
    my %Headers;
    if ($CalDAV->{user}) {
        $Headers{'Authorization'} = $CalDAV->auth_header();
    }
    my $event1URI = $CalDAV->request_url($event1Href);
    my $Response = $CalDAV->{ua}->request('HEAD', $event1URI, {
            headers => \%Headers,
    });
    my $event1ETag = $Response->{headers}{etag};
    $self->assert_not_null($event1ETag);
    my $event2URI = $CalDAV->request_url($event2Href);
    $Response = $CalDAV->{ua}->request('HEAD', $event2URI, {
            headers => \%Headers,
    });
    my $event2ETag = $Response->{headers}{etag};
    $self->assert_not_null($event2ETag);

    xlog "Update default alerts";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert2 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT10M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Refetch ETags of events";
    $Response = $CalDAV->{ua}->request('HEAD', $event1URI, {
            headers => \%Headers,
    });
    $self->assert_not_null($Response->{headers}{etag});
    $self->assert_str_not_equals($event1ETag, $Response->{headers}{etag});
    $Response = $CalDAV->{ua}->request('HEAD', $event2URI, {
            headers => \%Headers,
    });
    $self->assert_not_null($Response->{headers}{etag});
    $self->assert_str_equals($event2ETag, $Response->{headers}{etag});
}

sub test_calendarevent_set_defaultalerts_etag_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Set default alerts on calendar";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Create other user and share owner calendar";
    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.cassandane.#calendars.Default", "other", "lrsiwntex") or die;
    my $service = $self->{instance}->get_service("http");
    my $otherJMAP = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    my $otherCalDAV = Net::CalDAVTalk->new(
        user => "other",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog "Create event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "eventCass",
                    start => "2020-01-19T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    useDefaultAlerts => JSON::true,
                    color => 'yellow',
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);
    my $cassHref = $res->[0][1]{created}{1}{'x-href'};
    $self->assert_not_null($cassHref);

    xlog "Get event as other user";
    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
        'urn:ietf:params:jmap:mail',
    ];
    $res = $otherJMAP->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            properties => ['x-href'],
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    my $otherHref = $res->[0][1]{list}[0]{'x-href'};
    $self->assert_not_null($otherHref);

    xlog "Set per-user prop to force per-user data split";
    $res = $otherJMAP->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    color => 'green',
                },
            },
        }, 'R1'],
    ], $using);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Get ETag of event as cassandane";
    my %Headers;
    if ($CalDAV->{user}) {
        $Headers{'Authorization'} = $CalDAV->auth_header();
    }
    my $cassURI = $CalDAV->request_url($cassHref);
    my $ua = $CalDAV->ua();
    my $Response = $ua->request('HEAD', $cassURI, {
        headers => \%Headers,
    });
    my $cassETag = $Response->{headers}{etag};
    $self->assert_not_null($cassETag);

    xlog "Get ETag of event as other";
    %Headers = ();
    if ($otherCalDAV->{user}) {
        $Headers{'Authorization'} = $otherCalDAV->auth_header();
    }
    my $otherURI = $otherCalDAV->request_url($otherHref);
    my $otherUa = $otherCalDAV->ua();
    $Response = $otherUa->request('HEAD', $otherURI, {
        headers => \%Headers,
    });
    my $otherETag = $Response->{headers}{etag};
    $self->assert_not_null($otherETag);

    xlog "Update default alerts for cassandane";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert2 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT10M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Refetch ETags of events";
    %Headers = ();
    if ($CalDAV->{user}) {
        $Headers{'Authorization'} = $CalDAV->auth_header();
    }
    $Response = $CalDAV->{ua}->request('HEAD', $cassURI, {
        headers => \%Headers,
    });
    $self->assert_not_null($Response->{headers}{etag});
    $self->assert_str_not_equals($cassETag, $Response->{headers}{etag});

    %Headers = ();
    if ($otherCalDAV->{user}) {
        $Headers{'Authorization'} = $otherCalDAV->auth_header();
    }
    $Response = $otherCalDAV->{ua}->request('HEAD', $otherURI, {
        headers => \%Headers,
    });
    $self->assert_not_null($Response->{headers}{etag});
    $self->assert_str_equals($otherETag, $Response->{headers}{etag});
}

sub test_calendarevent_set_defaultalerts_description
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Set default alerts on calendar and event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-19T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    useDefaultAlerts => JSON::true,
                },
            },
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});
    my $event1Href = $res->[1][1]{created}{1}{'x-href'};
    $self->assert_not_null($event1Href);

    my $CaldavResponse = $CalDAV->Request('GET', $event1Href);
    my $icaldata = $CaldavResponse->{content};
    $self->assert($icaldata =~ /BEGIN:VALARM[\s\S]+DESCRIPTION:event1[\s\S]+END:VALARM/g);
}

sub test_calendar_defaultalerts_synctoken
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Set default alerts on calendar";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Create events with and without default alerts";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-19T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    alerts => {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                offset => "-PT10M",
                            },
                         },
                    },
                },
                2 => {
                    uid => 'eventuid2local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event2",
                    start => "2020-01-21T13:00:00",
                    duration => "PT1H",
                    timeZone => "Europe/Vienna",
                    useDefaultAlerts => JSON::true,
                },
            },
        }, 'R1'],
    ]);
    my $event1Uid = $res->[0][1]{created}{1}{uid};
    $self->assert_not_null($event1Uid);
    my $event2Uid = $res->[0][1]{created}{2}{uid};
    $self->assert_not_null($event2Uid);

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ];

    xlog "Fetch sync token";
    my $Cal = $CalDAV->GetCalendar('Default');
    my $syncToken = $Cal->{syncToken};
    $self->assert_not_null($syncToken);

    xlog "Update default alerts on calendar";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert2 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT15M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Sync CalDAV changes";
    my ($adds, $removes, $errors) = $CalDAV->SyncEvents('Default', syncToken => $syncToken);

    $self->assert_num_equals(1, scalar @{$adds});
    $self->assert_str_equals($adds->[0]{uid}, $event2Uid);
    $self->assert_deep_equals($removes, []);
    $self->assert_deep_equals($errors, []);
}

sub test_calendar_defaultalerts_synctoken_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Create other user and share calendar";
    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.cassandane.#calendars.Default", "other", "lrsiwntex") or die;
    my $service = $self->{instance}->get_service("http");
    my $otherJMAP = Mail::JMAPTalk->new(
        user => 'other',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );

    xlog "Set default alerts on calendar";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT5M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Create events without default alerts";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-19T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    alerts => {
                        alert1 => {
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                offset => "-PT10M",
                            },
                         },
                    },
                },
                2 => {
                    uid => 'eventuid2local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event2",
                    start => "2020-01-21T13:00:00",
                    duration => "PT1H",
                    timeZone => "Europe/Vienna",
                    useDefaultAlerts => JSON::true,
                },
            },
        }, 'R1'],
    ]);
    my $event1Uid = $res->[0][1]{created}{1}{uid};
    $self->assert_not_null($event1Uid);
    my $event2Uid = $res->[0][1]{created}{2}{uid};
    $self->assert_not_null($event2Uid);
    my $event2Id = $res->[0][1]{created}{2}{id};
    $self->assert_not_null($event2Id);

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ];

    xlog "Set useDefaultAlerts to force per-user data split";
    $res = $otherJMAP->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $event2Id => {
                    color => 'green',
                    useDefaultAlerts => JSON::true,
                },
            },
        }, 'R1'],
    ], $using);
    $self->assert(exists $res->[0][1]{updated}{$event2Id});
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $event2Id => {
                    color => 'blue',
                    useDefaultAlerts => JSON::true,
                },
            },
        }, 'R1'],
    ], $using);
    $self->assert(exists $res->[0][1]{updated}{$event2Id});

    xlog "Fetch sync token";
    my $Cal = $CalDAV->GetCalendar('Default');
    my $syncToken = $Cal->{syncToken};
    $self->assert_not_null($syncToken);

    xlog "Update default alerts on calendar";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert2 => {
                            '@type' => 'Alert',
                            trigger => {
                                '@type' => 'OffsetTrigger',
                                relativeTo => 'start',
                                offset => '-PT15M',
                            },
                            action => 'display',
                        },
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Sync CalDAV changes";
    my ($adds, $removes, $errors) = $CalDAV->SyncEvents('Default', syncToken => $syncToken);

    $self->assert_num_equals(1, scalar @{$adds});
    $self->assert_str_equals($adds->[0]{uid}, $event2Uid);
    $self->assert_deep_equals($removes, []);
    $self->assert_deep_equals($errors, []);
}

sub test_calendar_set_destroy_events
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    xlog "Create calendar and event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                1 => {
                    name => 'test',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                2 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        '#1' => JSON::true,
                    },
                    title => "event1",
                    start => "2020-03-30T11:00:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                },
            },
        }, 'R2'],
    ]);
    my $calendarId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($calendarId);
    my $eventId = $res->[1][1]{created}{2}{id};
    $self->assert_not_null($eventId);

    xlog "Destroy calendar (with and without onDestroyEvents)";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            destroy => [$calendarId],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['id'],
        }, 'R2'],
        ['Calendar/set', {
            destroy => [$calendarId],
            onDestroyRemoveEvents => JSON::true,
        }, 'R3'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['id'],
        }, 'R2'],
    ]);
    $self->assert_str_equals('calendarHasEvents',
        $res->[0][1]{notDestroyed}{$calendarId}{type});
    $self->assert_str_equals($eventId, $res->[1][1]{list}[0]{id});
    $self->assert_deep_equals([$calendarId], $res->[2][1]{destroyed});
    $self->assert_deep_equals([$eventId], $res->[3][1]{notFound});
}

sub test_calendarevent_get_recurrenceoverrides_before_after
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog $self, "create events";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                "1" => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'daily',
                    }],
                    recurrenceOverrides => {
                        '2020-01-02T09:00:00' => {
                            title => 'override1',
                        },
                        '2020-01-03T09:00:00' => {
                            title => 'override2',
                        },
                        '2020-01-04T09:00:00' => {
                            title => 'override3',
                        },
                        '2020-01-05T09:00:00' => {
                            title => 'override4',
                        },
                    },
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#1'],
            properties => ['recurrenceOverrides'],
            recurrenceOverridesAfter => '2020-01-03T08:00:00Z',
            recurrenceOverridesBefore => '2020-01-05T08:00:00Z',
        }, 'R2'],
    ]);

    $self->assert_deep_equals({
        '2020-01-03T09:00:00' => {
            title => 'override2',
        },
        '2020-01-04T09:00:00' => {
            title => 'override3',
        },
    }, $res->[1][1]{list}[0]{recurrenceOverrides});
}


sub test_calendarevent_get_reducepartitipants
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    replyTo => {
                        imip => 'mailto:owner@example.com',
                    },
                    participants => {
                        owner => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:owner@example.com',
                            },
                        },
                        attendee1 => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:attendee1@example.com',
                            },
                        },
                        attendee2 => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:attendee2@example.com',
                            },
                        },
                        cassandane => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event1'],
            reduceParticipants => JSON::true,
            properties => ['participants'],
        }, 'R2'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    my $wantUris = {
        'mailto:owner@example.com' => 1,
        'mailto:cassandane@example.com' => 1,
    };
    my %haveUris = map { $_->{sendTo}{imip} => 1 }
            values %{$res->[1][1]{list}[0]{participants}};
    $self->assert_deep_equals($wantUris, \%haveUris);

    $caldav->Request(
      'PROPPATCH',
      '',
      x('D:propertyupdate', $caldav->NS(),
        x('D:set',
          x('D:prop',
            x('C:calendar-user-address-set',
              x('D:href', 'attendee1@example.com'),
            )
          )
        )
      )
    );

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$eventId],
            reduceParticipants => JSON::true,
            properties => ['participants'],
        }, 'R1'],
    ]);
    $wantUris = {
        'mailto:owner@example.com' => 1,
        'mailto:attendee1@example.com' => 1,
    };
    %haveUris = map { $_->{sendTo}{imip} => 1 }
            values %{$res->[0][1]{list}[0]{participants}};
    $self->assert_deep_equals($wantUris, \%haveUris);
}

sub test_calendarevent_set_schedulingmessages
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    # clean notification cache
    $self->{instance}->getnotify();

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        attendee1 => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:attendee1@example.com',
                            },
                        },
                    },
                },
            },
            sendSchedulingMessages => JSON::false,
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($imip);

    # clean notification cache
    $self->{instance}->getnotify();

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => "updatedEvent1",
                },
            },
            sendSchedulingMessages => JSON::true,
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    $data = $self->{instance}->getnotify();
    ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);

    my $payload = decode_json($imip->{MESSAGE});
    my $ical = $payload->{ical};

    $self->assert_str_equals('attendee1@example.com', $payload->{recipient});
    $self->assert($ical =~ "METHOD:REQUEST");
}

sub test_account_get_shareesactas
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $http = $self->{instance}->get_service("http");
    my $admintalk = $self->{adminstore}->get_client();

    my $getCapas = sub {
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
        return $session->{accounts}{cassandane}{accountCapabilities}{'urn:ietf:params:jmap:calendars'};
    };

    xlog "Sharees act as self";
    my $capas = $getCapas->();
    $self->assert_str_equals('self', $capas->{shareesActAs});

    xlog "Sharees act as secretary";

    my $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:JMAP="urn:ietf:params:jmap:calendars">
  <D:set>
    <D:prop>
      <JMAP:sharees-act-as>secretary</JMAP:sharees-act-as>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $caldav->Request('PROPPATCH', "/dav/calendars/user/cassandane", $xml,
        'Content-Type' => 'text/xml');

    $capas = $getCapas->();
    $self->assert_str_equals('secretary', $capas->{shareesActAs});

    $xml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:JMAP="urn:ietf:params:jmap:calendars">
  <D:set>
    <D:prop>
      <JMAP:sharees-act-as>self</JMAP:sharees-act-as>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $caldav->Request('PROPPATCH', "/dav/calendars/user/cassandane", $xml,
        'Content-Type' => 'text/xml');

    $capas = $getCapas->();
    $self->assert_str_equals('self', $capas->{shareesActAs});
}

sub test_calendarprincipal_get
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $CalDAV = $self->{caldav};

    # Set timezone
    my $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:calendar-timezone>
BEGIN:VCALENDAR
PRODID:-//CyrusIMAP.org//Cyrus 1.0//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:Europe/Berlin
COMMENT:[DE] Germany (most areas)
LAST-MODIFIED:20200820T145616Z
X-LIC-LOCATION:Europe/Berlin
X-PROLEPTIC-TZNAME:LMT
BEGIN:STANDARD
TZNAME:CET
TZOFFSETFROM:+005328
TZOFFSETTO:+0100
DTSTART:18930401T000000
END:STANDARD
BEGIN:DAYLIGHT
TZNAME:CEST
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
DTSTART:19810329T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
END:DAYLIGHT
BEGIN:STANDARD
TZNAME:CET
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
DTSTART:19961027T030000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
END:STANDARD
END:VTIMEZONE
END:VCALENDAR
</C:calendar-timezone>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane",
                       $proppatchXml, 'Content-Type' => 'text/xml');

    # Set description
    $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<C:calendar-description>A description</C:calendar-description>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/calendars/user/cassandane",
                       $proppatchXml, 'Content-Type' => 'text/xml');

    # Set name
    $proppatchXml = <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
<D:displayname>Cassandane User</D:displayname>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $CalDAV->Request('PROPPATCH', "/dav/principals/user/cassandane",
                       $proppatchXml, 'Content-Type' => 'text/xml');


    my $res = $jmap->CallMethods([
        ['Principal/get', {
            ids => ['cassandane', 'nope'],
        }, 'R1']
    ]);
    my $p = $res->[0][1]{list}[0];

    $self->assert_not_null($p->{account});
    delete ($p->{account});
    $self->assert_deep_equals({
        id => 'cassandane',
        name => 'Cassandane User',
        description => 'A description',
        email => 'cassandane@example.com',
        type => 'individual',
        timeZone => 'Europe/Berlin',
        mayGetAvailability => JSON::true,
        accountId => 'cassandane',
        sendTo => {
            imip => 'mailto:cassandane@example.com',
        },
    }, $p);
    $self->assert_deep_equals(['nope'], $res->[0][1]{notFound});
}

sub test_calendarprincipal_query
    :min_version_3_3 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    $self->{instance}->create_user("manifold");
    # Trigger creation of default calendar
    my $http = $self->{instance}->get_service("http");
    Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
    $admintalk->setacl("user.manifold", "cassandane", "lr") or die;
    $admintalk->setacl("user.manifold.#calendars", "cassandane", "lr") or die;
    $admintalk->setacl("user.manifold.#calendars.Default", "cassandane" => 'lr') or die;

    xlog "test filters";
    my $res = $jmap->CallMethods([
        ['Principal/query', {
            filter => {
                name => 'Test',
                email => 'cassandane@example.com',
                text => 'User',
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals(['cassandane'], $res->[0][1]{ids});

    xlog "test sorting";
    $res = $jmap->CallMethods([
        ['Principal/query', {
            sort => [{
                property => 'id',
            }],
        }, 'R1'],
        ['Principal/query', {
            sort => [{
                property => 'id',
                isAscending => JSON::false,
            }],
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['cassandane', 'manifold'], $res->[0][1]{ids});
    $self->assert_deep_equals(['manifold', 'cassandane'], $res->[1][1]{ids});
}

sub test_calendarprincipal_changes
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Principal/changes', {
        }, 'R1']
    ]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_calendarprincipal_querychanges
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Principal/queryChanges', {
            sinceQueryState => 'whatever',
        }, 'R1']
    ]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_calendarprincipal_set
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Principal/set', {
            create => {
                principal1 => {
                    timeZone => 'America/New_York',
                },
            },
            update => {
                cassandane => {
                    name => 'Xyz',
                },
                principal2 => {
                    timeZone => 'Europe/Berlin',
                },
            },
            destroy => ['principal3'],
        }, 'R1']
    ]);

    $self->assert_str_equals('forbidden',
        $res->[0][1]{notCreated}{principal1}{type});
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notUpdated}{principal2}{type});
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notDestroyed}{principal3}{type});

    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{cassandane}{type});
    $self->assert_deep_equals(['name'],
        $res->[0][1]{notUpdated}{cassandane}{properties});

    $res = $jmap->CallMethods([
        ['Principal/get', {
            ids => ['cassandane'],
            properties => ['timeZone'],
        }, 'R1'],
        ['Principal/set', {
            update => {
                cassandane => {
                    timeZone => 'Australia/Melbourne',
                },
            },
        }, 'R2'],
        ['Principal/get', {
            ids => ['cassandane'],
            properties => ['timeZone'],
        }, 'R3']
    ]);
    $self->assert_null($res->[0][1]{list}[0]{timeZone});
    $self->assert_deep_equals({}, $res->[1][1]{updated}{cassandane});
    $self->assert_str_equals('Australia/Melbourne',
        $res->[2][1]{list}[0]{timeZone});

    $self->assert_not_null($res->[1][1]{oldState});
    $self->assert_not_null($res->[1][1]{newState});
    $self->assert_str_not_equals($res->[1][1]{oldState}, $res->[1][1]{newState});

    my $oldState = $res->[1][1]{oldState};
    $res = $jmap->CallMethods([
        ['Principal/set', {
            ifInState => $oldState,
            update => {
                cassandane => {
                    timeZone => 'Asia/Tokyo',
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('stateMismatch', $res->[0][1]{type});
}

sub test_calendarprincipal_getavailability_showdetails
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                invisible => {
                    name => 'invisibleCalendar',
                    includeInAvailability => 'none',
                },
            },
        }, 'R1'],
    ]);
    my $invisibleCalendarId = $res->[0][1]{created}{invisible}{id};
    $self->assert_not_null($invisibleCalendarId);

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uid',
                    title => "event1",
                    start => "2020-07-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    status => 'confirmed',
                    recurrenceRules => [{
                        frequency => 'weekly',
                        count => 12,
                    }],
                    recurrenceOverrides => {
                        "2020-08-26T09:00:00" => {
                            start => "2020-08-26T13:00:00",
                        },
                    },
                },
                event2 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event2uid',
                    title => "event2",
                    start => "2020-08-07T11:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT3H",
                },
                event3 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event3uid',
                    title => "event3",
                    start => "2020-08-10T13:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    freeBusyStatus => 'free',
                },
                event4 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event4uid',
                    title => "event4",
                    start => "2020-08-12T09:30:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    status => 'tentative',
                },
                event5 => {
                    calendarIds => {
                        $invisibleCalendarId => JSON::true,
                    },
                    uid => 'event5uid',
                    title => "event5",
                    start => "2020-08-14T15:30:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                },
            },
        }, 'R1'],
        ['Principal/getAvailability', {
            id => 'cassandane',
            utcStart => '2020-08-01T00:00:00Z',
            utcEnd => '2020-09-01T00:00:00Z',
            showDetails => JSON::true,
            eventProperties => ['start', 'title'],
        }, 'R2'],
    ]);
    $self->assert_num_equals(5, scalar keys %{$res->[0][1]{created}});

    $self->assert_deep_equals([{
        utcStart => "2020-08-05T07:00:00Z",
        utcEnd => "2020-08-05T08:00:00Z",
        busyStatus => 'confirmed',
        event => {
            start => "2020-08-05T09:00:00",
            title => 'event1',
        },
    }, {
        utcStart => "2020-08-07T09:00:00Z",
        utcEnd => "2020-08-07T12:00:00Z",
        busyStatus => 'unavailable',
        event => {
            start => "2020-08-07T11:00:00",
            title => 'event2',
        },
    }, {
        utcStart => "2020-08-12T07:00:00Z",
        utcEnd => "2020-08-12T08:00:00Z",
        busyStatus => 'confirmed',
        event => {
            start => "2020-08-12T09:00:00",
            title => 'event1',
        },
    }, {
        utcStart => "2020-08-12T07:30:00Z",
        utcEnd => "2020-08-12T08:30:00Z",
        busyStatus => 'tentative',
        event => {
            start => "2020-08-12T09:30:00",
            title => 'event4',
        },
    }, {
        utcStart => "2020-08-19T07:00:00Z",
        utcEnd => "2020-08-19T08:00:00Z",
        busyStatus => 'confirmed',
        event => {
            start => "2020-08-19T09:00:00",
            title => 'event1',
        },
    }, {
        utcStart => "2020-08-26T11:00:00Z",
        utcEnd => "2020-08-26T12:00:00Z",
        busyStatus => 'confirmed',
        event => {
            start => "2020-08-26T13:00:00",
            title => 'event1',
        },
    }], $res->[1][1]{list});
}

sub test_calendarprincipal_getavailability_merged
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                # 09:00 to 10:30: Two events adjacent to each other.
                'event-0900-1000' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-0900-1000",
                    start => "2020-08-01T09:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT1H",
                },
                'event-1000-1030' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-1000-1030",
                    start => "2020-08-01T10:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT30M",
                },
                # 05:00 to 08:00: One event completely overlapping the other.
                'event-0500-0800' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-0500-0800",
                    start => "2020-08-01T05:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT3H",
                },
                'event-0600-0700' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-06:00-07:00",
                    start => "2020-08-01T06:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT1H",
                },
                # 01:00 to 03:00: One event partially overlapping the other.
                'event-0100-0200' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-0100-0200",
                    start => "2020-08-01T01:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT1H",
                },
                'event-0130-0300' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-0130-0300",
                    start => "2020-08-01T01:30:00",
                    timeZone => "Etc/UTC",
                    duration => "PT1H30M",
                },
                # 12:00 to 13:30: Overlapping events with differing busyStatus.
                'event-1200-1300-tentative' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-1200-1300-tentative",
                    start => "2020-08-01T12:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT1H",
                    status => 'tentative',
                },
                'event-1200-1330-confirmed' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-1200-1330-confirmed",
                    start => "2020-08-01T12:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT1H30M",
                    status => 'confirmed',
                },
                'event-1200-1230-unavailable' => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event-1200-1330-unavailable",
                    start => "2020-08-01T12:00:00",
                    timeZone => "Etc/UTC",
                    duration => "PT30M",
                },
            },
        }, 'R1'],
        ['Principal/getAvailability', {
            id => 'cassandane',
            utcStart => '2020-08-01T00:00:00Z',
            utcEnd => '2020-09-01T00:00:00Z',
        }, 'R2'],
    ]);
    $self->assert_num_equals(9, scalar keys %{$res->[0][1]{created}});

    $self->assert_deep_equals([{
        utcStart => "2020-08-01T01:00:00Z",
        utcEnd => "2020-08-01T03:00:00Z",
        busyStatus => 'unavailable',
        event => undef,
    }, {
        utcStart => "2020-08-01T05:00:00Z",
        utcEnd => "2020-08-01T08:00:00Z",
        busyStatus => 'unavailable',
        event => undef,
    }, {
        utcStart => "2020-08-01T09:00:00Z",
        utcEnd => "2020-08-01T10:30:00Z",
        busyStatus => 'unavailable',
        event => undef,
    }, {
        utcStart => "2020-08-01T12:00:00Z",
        utcEnd => "2020-08-01T13:30:00Z",
        busyStatus => 'confirmed',
        event => undef,
    }, {
        utcStart => "2020-08-01T12:00:00Z",
        utcEnd => "2020-08-01T12:30:00Z",
        busyStatus => 'unavailable',
        event => undef,
    }, {
        utcStart => "2020-08-01T12:00:00Z",
        utcEnd => "2020-08-01T13:00:00Z",
        busyStatus => 'tentative',
        event => undef,
    }], $res->[1][1]{list});
}

sub test_calendarsharenotification_get
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create sharee
    my $admin = $self->{adminstore}->get_client();
    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $manjmap->CallMethods([
        ['ShareNotification/get', {
        }, 'R1']
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    my $state = $res->[0][1]{state};

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    name => 'myname',
                    "shareWith/manifold" => {
                        mayReadFreeBusy => JSON::true,
                        mayReadItems => JSON::true,
                    },
                },
            },
        }, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    $res = $manjmap->CallMethods([
        ['ShareNotification/get', {
        }, 'R1']
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    my $notif = $res->[0][1]{list}[0];
    # Assert dynamically generated values.
    my $notifId = $notif->{id};
    $self->assert_not_null($notifId);
    delete($notif->{id});
    $self->assert_not_null($notif->{created});
    delete($notif->{created});
    # Assert remaining values.
    $self->assert_deep_equals({
        changedBy => {
            name => 'Test User',
            email => 'cassandane@example.com',
            principalId => 'cassandane',
        },
        objectType => 'Calendar',
        objectAccountId => 'cassandane',
        objectId => 'Default',
        oldRights => undef,
        newRights => {
            mayReadFreeBusy => JSON::true,
            mayReadItems => JSON::true,
            mayWriteAll => JSON::false,
            mayRSVP => JSON::false,
            mayDelete => JSON::false,
            mayAdmin => JSON::false,
            mayUpdatePrivate => JSON::false,
            mayWriteOwn => JSON::false,
        },
    }, $notif);

    $res = $manjmap->CallMethods([
        ['ShareNotification/get', {
            ids => [$notifId, 'nope'],
        }, 'R1']
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_deep_equals(['nope'], $res->[0][1]{notFound});
    $self->assert_str_not_equals($state, $res->[0][1]{state});
}

sub test_calendarsharenotification_set
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create sharee
    my $admin = $self->{adminstore}->get_client();
    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    name => 'myname',
                    "shareWith/manifold" => {
                        mayReadFreeBusy => JSON::true,
                        mayReadItems => JSON::true,
                    },
                },
            },
        }, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    $res = $manjmap->CallMethods([
        ['ShareNotification/get', {
        }, 'R1']
    ]);
    my $notif = $res->[0][1]{list}[0];
    my $notifId = $notif->{id};
    $self->assert_not_null($notifId);
    delete($notif->{id});

    $res = $manjmap->CallMethods([
        ['ShareNotification/set', {
            create => {
                newnotif => $notif,
            },
            update => {
                $notifId => $notif,
            },
        }, "R1"]
    ]);
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notCreated}{newnotif}{type});
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notUpdated}{$notifId}{type});
    $self->assert_not_null($res->[0][1]{newState});
    my $state = $res->[0][1]{newState};

    $res = $manjmap->CallMethods([
        ['ShareNotification/set', {
            destroy => [$notifId, 'unknownId'],
        }, "R1"]
    ]);
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});
    $self->assert_str_equals('notFound',
        $res->[0][1]{notDestroyed}{unknownId}{type});
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});

    $res = $manjmap->CallMethods([
        ['ShareNotification/get', {
            ids => [$notifId],
        }, 'R1']
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_deep_equals([$notifId], $res->[0][1]{notFound});
}

sub test_calendarsharenotification_changes
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create sharee
    my $admin = $self->{adminstore}->get_client();
    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $manjmap->CallMethods([
        ['ShareNotification/get', {
        }, 'R1']
    ]);
    my $state = $res->[0][1]{state};
    $self->assert_not_null($state);

    $res = $manjmap->CallMethods([
        ['ShareNotification/changes', {
            sinceState => $state,
        }, 'R1']
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    "shareWith/manifold" => {
                        mayReadFreeBusy => JSON::true,
                        mayReadItems => JSON::true,
                    },
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    $res = $manjmap->CallMethods([
        ['ShareNotification/changes', {
            sinceState => $state,
        }, 'R1']
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    my $notifId = $res->[0][1]{created}[0];
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                1 => {
                    name => 'someCalendar',
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                        },
                    },
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{created}{1});

    $res = $manjmap->CallMethods([
        ['ShareNotification/set', {
            destroy => [$notifId],
        }, "R1"]
    ]);
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});

    $res = $manjmap->CallMethods([
        ['ShareNotification/changes', {
            sinceState => $state,
            maxChanges => 1,
        }, 'R1']
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::true, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]{newState};

    $res = $manjmap->CallMethods([
        ['ShareNotification/changes', {
            sinceState => $state,
        }, 'R1']
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});
}

sub test_calendarsharenotification_query
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # Create sharee
    my $admin = $self->{adminstore}->get_client();
    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                A => {
                    name => 'A',
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                        },
                    },
                },
            },
        }, 'R1']
    ]);
    $self->assert_not_null($res->[0][1]{created}{A});

    sleep(1);

    $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                B => {
                    name => 'B',
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                        },
                    },
                },
            },
        }, 'R1']
    ]);
    $self->assert_not_null($res->[0][1]{created}{B});

    $res = $manjmap->CallMethods([
        ['ShareNotification/query', {
        }, 'R1'],
        ['ShareNotification/query', {
            sort => [{
                property => 'created',
                isAscending => JSON::false,
            }],
        }, 'R2'],
        ['ShareNotification/get', {
            properties => ['created'],
        }, 'R3'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[1][1]{ids}});

    my %notifTimestamps = map { $_->{id} => $_->{created} } @{$res->[2][1]{list}};
    $self->assert($notifTimestamps{$res->[0][1]{ids}[0]} lt
                  $notifTimestamps{$res->[0][1]{ids}[1]});
    $self->assert($notifTimestamps{$res->[1][1]{ids}[0]} gt
                  $notifTimestamps{$res->[1][1]{ids}[1]});

    my $notifIdT1 = $res->[0][1]{ids}[0];
    my $timestampT1 = $notifTimestamps{$notifIdT1};

    my $notifIdT2 = $res->[0][1]{ids}[1];
    my $timestampT2 = $notifTimestamps{$notifIdT2};

    $res = $manjmap->CallMethods([
        ['ShareNotification/query', {
            filter => {
                before => $timestampT2,
            },
        }, 'R1'],
        ['ShareNotification/query', {
            filter => {
                after => $timestampT2,
            },
        }, 'R2'],
        ['ShareNotification/query', {
            position => 1,
        }, 'R3'],
        ['ShareNotification/query', {
            anchor => $notifIdT2,
            anchorOffset => -1,
            limit => 1,
        }, 'R3'],
    ]);
    $self->assert_deep_equals([$notifIdT1], $res->[0][1]{ids});
    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_deep_equals([$notifIdT2], $res->[1][1]{ids});
    $self->assert_num_equals(1, $res->[1][1]{total});
    $self->assert_deep_equals([$notifIdT2], $res->[2][1]{ids});
    $self->assert_num_equals(2, $res->[2][1]{total});
    $self->assert_deep_equals([$notifIdT1], $res->[3][1]{ids});
    $self->assert_num_equals(2, $res->[2][1]{total});
}

sub test_calendarsharenotification_querychanges
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['ShareNotification/queryChanges', {
            sinceQueryState => 'whatever',
        }, 'R1']
    ]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_calendareventnotification_get
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    xlog "Create event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    title => 'event1',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    start => '2011-01-01T04:05:06',
                    duration => 'PT1H',
                },
            },
        }, 'R2'],
        ['CalendarEventNotification/get', {
        }, 'R3'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});
    my $eventId = $res->[1][1]{created}{event1}{id};
    $self->assert_not_null($eventId);
    # Event creator is not notified.
    $self->assert_num_equals(0, scalar @{$res->[2][1]{list}});

    # Event sharee is notified.
    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('created', $res->[0][1]{list}[0]{type});
    my $notif1 = $res->[0][1]{list}[0]{id};

    xlog "Update event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'event1updated',
                },
            },
        }, 'R1'],
        ['CalendarEventNotification/get', {
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    # Event updater is not notified.
    $self->assert_num_equals(0, scalar @{$res->[1][1]{list}});
    # Event sharee is notified.
    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    my %notifs = map { $_->{type} => $_ } @{$res->[0][1]{list}};
    $self->assert_str_equals($notif1, $notifs{created}{id});
    my $notif2 = $notifs{updated}{id};
    $self->assert_str_not_equals($notif2, $notif1);

    xlog "Destroy event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [$eventId],
        }, 'R1'],
        ['CalendarEventNotification/get', {
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$eventId], $res->[0][1]{destroyed});
    # Event destroyer is not notified.
    $self->assert_num_equals(0, scalar @{$res->[2][1]{list}});

    # Event sharee only sees destroy notification.
    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_not_equals($notif1, $res->[0][1]{list}[0]{id});
    $self->assert_str_not_equals($notif2, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals('destroyed', $res->[0][1]{list}[0]{type});
}

sub test_calendareventnotification_get_no_sharee
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create('user.cassandane.#jmapnotification') or die;
    $admin->setacl('user.cassandane.#jmapnotification',
        'cassandane' => 'lrswipkxtecdan') or die;

    xlog "Create event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    title => 'event1',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    start => '2011-01-01T04:05:06',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    $self->assert_num_equals(0,
        $admin->message_count('user.cassandane.#jmapnotification'));

    xlog "Update event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'event1Updated',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    $self->assert_num_equals(0,
        $admin->message_count('user.cassandane.#jmapnotification'));

    xlog "Destroy event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy =>  [ $eventId ],
        }, 'R1'],
    ]);
    $self->assert_deep_equals([$eventId], $res->[0][1]{destroyed});

    $self->assert_num_equals(0,
        $admin->message_count('user.cassandane.#jmapnotification'));
}

sub test_calendareventnotification_set
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    xlog "Create event";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    title => 'event1',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    start => '2011-01-01T04:05:06',
                    duration => 'PT1H',
                },
            },
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});
    my $eventId = $res->[1][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R2'],
    ]);

    my $notif = $res->[0][1]{list}[0];
    my $notifId = $notif->{id};
    $self->assert_not_null($notifId);
    delete($notif->{id});

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/set', {
            accountId => 'cassandane',
            create => {
                newnotif => $notif,
            },
            update => {
                $notifId => $notif,
            },
        }, "R1"]
    ]);
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notCreated}{newnotif}{type});
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notUpdated}{$notifId}{type});
    $self->assert_not_null($res->[0][1]{newState});
    my $state = $res->[0][1]{newState};

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/set', {
            accountId => 'cassandane',
            destroy => [$notifId, 'unknownId'],
        }, "R1"]
    ]);
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});
    $self->assert_str_equals('notFound',
        $res->[0][1]{notDestroyed}{unknownId}{type});
    $self->assert_not_null($res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
            ids => [$notifId],
        }, 'R1']
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_deep_equals([$notifId], $res->[0][1]{notFound});
}

sub test_calendareventnotification_query
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Create notifications";

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    title => 'event1',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    start => '2011-01-01T04:05:06',
                    duration => 'PT1H',
                },
            },
        }, 'R2'],
    ]);
    my $event1Id = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($event1Id);

    sleep(1);

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $event1Id => {
                    title => 'event1updated',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$event1Id});

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    my %notifs = map { $_->{type} => $_ } @{$res->[0][1]{list}};
    my $notif1 = $notifs{created};
    $self->assert_not_null($notif1);
    my $notif2 = $notifs{updated};
    $self->assert_not_null($notif2);

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
            filter => {
                type => 'created',
            },
        }, 'R1'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
            filter => {
                type => 'updated',
            },
        }, 'R2'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
            filter => {
                before => $notif2->{created},
            },
        }, 'R3'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
            filter => {
                after => $notif2->{created},
            },
        }, 'R4'],
    ]);
    $self->assert_deep_equals([$notif1->{id}], $res->[0][1]{ids});
    $self->assert_deep_equals([$notif2->{id}], $res->[1][1]{ids});
    $self->assert_deep_equals([$notif1->{id}], $res->[2][1]{ids});
    $self->assert_deep_equals([$notif2->{id}], $res->[3][1]{ids});

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event2 => {
                    title => 'event2',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    start => '2012-02-02T04:05:06',
                    duration => 'PT1H',
                },
            },
        }, 'R2'],
    ]);
    my $event2Id = $res->[0][1]{created}{event2}{id};
    $self->assert_not_null($event2Id);

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
            filter => {
                calendarEventIds => [$event2Id],
            },
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_not_equals($notif1->{id}, $res->[0][1]{ids}[0]);
    $self->assert_str_not_equals($notif2->{id}, $res->[0][1]{ids}[0]);
}

sub test_calendareventnotification_changes
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{list});
    my $state = $res->[0][1]{state};
    $self->assert_not_null($state);

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/changes', {
            sinceState => $state,
        }, 'R1'],
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog "create notification that cassandane will see";

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:testitip
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        $ical, 'Content-Type' => 'text/calendar',
               'Schedule-Sender-Address' => 'itipsender@local',
               'Schedule-Sender-Name' => 'iTIP Sender',
    );

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/changes', {
            sinceState => $state,
        }, 'R1'],
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_equals(JSON::false, $res->[0][1]{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    my $notifId = $res->[0][1]{created}[0];
    my $oldState = $state;
    $state = $res->[0][1]{newState};

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/set', {
            destroy => [$notifId],
        }, 'R1'],
    ]);
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/changes', {
            sinceState => $state,
        }, 'R1'],
    ]);
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});
}

sub test_calendareventnotification_changes_shared
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1']
    ]);
    my $state = $res->[0][1]{state};
    $self->assert_not_null($state);

    # This should work, but it currently doesn't.
    # At least we can check for the correct error.

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/queryChanges', {
            accountId => 'cassandane',
            sinceQueryState => $state,
        }, 'R1']
    ]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_calendareventnotification_querychanges
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEventNotification/queryChanges', {
            sinceQueryState => 'whatever',
        }, 'R1']
    ]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_calendareventnotification_aclcheck
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                sharedCalendar => {
                    name => 'sharedCalendar',
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
                unsharedCalendar => {
                    name => 'unsharedCalendar',
                },
            },
        }, 'R1'],
    ]);
    my $sharedCalendarId = $res->[0][1]{created}{sharedCalendar}{id};
    $self->assert_not_null($sharedCalendarId);
    my $unsharedCalendarId = $res->[0][1]{created}{unsharedCalendar}{id};
    $self->assert_not_null($unsharedCalendarId);

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{list});
    my $state = $res->[0][1]{state};

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                sharedEvent => {
                    title => 'sharedEvent',
                    calendarIds => {
                        $sharedCalendarId => JSON::true,
                    },
                    start => '2011-01-01T04:05:06',
                    duration => 'PT1H',
                },
                unsharedEvent => {
                    title => 'unsharedEvent',
                    calendarIds => {
                        $unsharedCalendarId => JSON::true,
                    },
                    start => '2012-02-02T04:05:06',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
    ]);
    my $sharedEventId = $res->[0][1]{created}{sharedEvent}{id};
    $self->assert_not_null($sharedEventId);
    my $unsharedEventId = $res->[0][1]{created}{unsharedEvent}{id};
    $self->assert_not_null($unsharedEventId);

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
            properties => ['calendarEventId'],
        }, 'R1'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals($sharedEventId, $res->[0][1]{list}[0]{calendarEventId});
    my $notifId = $res->[0][1]{list}[0]{id};
    $self->assert_deep_equals([$notifId], $res->[1][1]{ids});
}

sub test_calendareventnotification_caldav
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    xlog "User creates an event";

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:test
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('created', $res->[0][1]{list}[0]{type});
    $self->assert_str_equals('cassandane',
        $res->[0][1]{list}[0]{changedBy}{calendarPrincipalId});
    $self->assert_not_null($res->[0][1]{list}[0]{event});

    xlog "User updates an event";

    $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:testupdated
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    my %notifs = map { $_->{type} => $_ } @{$res->[0][1]{list}};
    $self->assert_not_null($notifs{'updated'}->{event});
    $self->assert_not_null($notifs{'updated'}->{eventPatch});
    $self->assert_str_equals('cassandane',
        $notifs{'updated'}->{changedBy}{calendarPrincipalId});

    xlog "User deletes an event";

    $caldav->Request('DELETE',
        '/dav/calendars/user/cassandane/Default/test.ics');

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('destroyed', $res->[0][1]{list}[0]{type});
    $self->assert_str_equals('cassandane',
        $res->[0][1]{list}[0]{changedBy}{calendarPrincipalId});
    $self->assert_not_null($res->[0][1]{list}[0]{event});

    xlog "iTIP handler creates an event";

    $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:testitip
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        $ical, 'Content-Type' => 'text/calendar',
               'Schedule-Sender-Address' => 'itipsender@local',
               'Schedule-Sender-Name' => '=?utf-8?q?iTIP_=E2=98=BA_Sender?=',
        );

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('created', $res->[0][1]{list}[0]{type});
    $self->assert_str_equals('itipsender@local',
        $res->[0][1]{list}[0]{changedBy}{email});
    $self->assert_str_equals("iTIP \N{WHITE SMILING FACE} Sender", # assert RFC0247 support
        $res->[0][1]{list}[0]{changedBy}{name});
    $self->assert_null($res->[0][1]{list}[0]{changedBy}{calendarPrincipalId});

    xlog "iTIP handler deletes an event";

    $caldav->Request('DELETE',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        undef,
        'Schedule-Sender-Address' => 'itipdeleter@local',
        'Schedule-Sender-Name' => 'iTIP Deleter');

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('destroyed', $res->[0][1]{list}[0]{type});
    $self->assert_str_equals('itipdeleter@local',
        $res->[0][1]{list}[0]{changedBy}{email});
    $self->assert_str_equals('iTIP Deleter',
        $res->[0][1]{list}[0]{changedBy}{name});
    $self->assert_null($res->[0][1]{list}[0]{changedBy}{calendarPrincipalId});
}

sub test_calendareventnotification_set_destroy
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.manifold");
    my $http = $self->{instance}->get_service("http");
    my $mantalk = Net::CalDAVTalk->new(
        user => "manifold",
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
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
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        manifold => {
                            mayReadFreeBusy => JSON::true,
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayAdmin => JSON::false
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
    ]);
    my $cassState = $res->[0][1]{state};
    $self->assert_not_null($cassState);

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
    ]);
    my $manState = $res->[0][1]{state};
    $self->assert_not_null($manState);

    xlog "create a notification that both cassandane and manifold will see";

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
DESCRIPTION:
SUMMARY:testitip
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        $ical, 'Content-Type' => 'text/calendar',
               'Schedule-Sender-Address' => 'itipsender@local',
               'Schedule-Sender-Name' => 'iTIP Sender',
    );

    xlog "fetch notifications";

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
        ['CalendarEventNotification/query', {
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            sinceState => $cassState,
        }, 'R3'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{created}});
    $cassState = $res->[2][1]{newState};

    my $notifId = $res->[1][1]{ids}[0];

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            accountId => 'cassandane',
            sinceState => $manState,
        }, 'R3'],
    ]);
    $self->{instance}->getsyslog(); # ignore seen.db DBERROR
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{created}});
    $manState = $res->[2][1]{newState};

    xlog "destroy notification as cassandane user";

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/set', {
            destroy => [$notifId],
        }, 'R1'],
    ]);
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});

    xlog "refetch notifications";

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
        ['CalendarEventNotification/query', {
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            sinceState => $cassState,
        }, 'R3'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{destroyed}});
    $cassState = $res->[2][1]{newState};

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            accountId => 'cassandane',
            sinceState => $manState,
        }, 'R3'],
    ]);
    $self->{instance}->getsyslog(); # ignore seen.db DBERROR
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{destroyed}});
    $manState = $res->[2][1]{newState};

    xlog "destroy notification as sharee";

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/set', {
            accountId => 'cassandane',
            destroy => [$notifId],
        }, 'R1'],
    ]);
    $self->assert_deep_equals([$notifId], $res->[0][1]{destroyed});

    xlog "refetch notifications";

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
        ['CalendarEventNotification/query', {
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            sinceState => $cassState,
        }, 'R3'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{created}});
    # XXX this should be 0 but we err on the safe side and report duplicate destroys
    $self->assert_num_equals(1, scalar @{$res->[2][1]{destroyed}});
    $cassState = $res->[2][1]{newState};

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            accountId => 'cassandane',
            sinceState => $manState,
        }, 'R3'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{created}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{destroyed}});
    $manState = $res->[2][1]{newState};

    $res = $jmap->CallMethods([
        ['CalendarEventNotification/get', {
        }, 'R1'],
        ['CalendarEventNotification/query', {
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            sinceState => $cassState,
        }, 'R3'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{destroyed}});

    $res = $manjmap->CallMethods([
        ['CalendarEventNotification/get', {
            accountId => 'cassandane',
        }, 'R1'],
        ['CalendarEventNotification/query', {
            accountId => 'cassandane',
        }, 'R2'],
        ['CalendarEventNotification/changes', {
            accountId => 'cassandane',
            sinceState => $manState,
        }, 'R3'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{created}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{destroyed}});
}

sub test_account_get_capabilities
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $http = $self->{instance}->get_service("http");
    my $admintalk = $self->{adminstore}->get_client();

    xlog "Get session object";

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

    my $capas = $session->{accounts}{cassandane}{accountCapabilities}{'urn:ietf:params:jmap:calendars'};
    $self->assert_not_null($capas);

    $self->assert_not_null($capas->{minDateTime});
    $self->assert_not_null($capas->{maxDateTime});
    $self->assert_not_null($capas->{maxExpandedQueryDuration});
    $self->assert(exists $capas->{maxParticipantsPerEvent});
    $self->assert_equals(JSON::true, $capas->{mayCreateCalendar});
    $self->assert_num_equals(1, $capas->{maxCalendarsPerEvent});

    $capas = $session->{accounts}{cassandane}{accountCapabilities}{'urn:ietf:params:jmap:principals'};
    $self->assert_not_null($capas);
    $self->assert_str_equals('cassandane', $capas->{currentUserPrincipalId});
    $self->assert_str_equals('cassandane',
        $capas->{'urn:ietf:params:jmap:calendars'}{accountId});
    $self->assert_equals(JSON::true,
        $capas->{'urn:ietf:params:jmap:calendars'}{mayGetAvailability});
    $self->assert_not_null($capas->{'urn:ietf:params:jmap:calendars'}{sendTo});

    $capas = $session->{accounts}{cassandane}{accountCapabilities}{'urn:ietf:params:jmap:principals:owner'};
    $self->assert_not_null($capas);
    $self->assert_str_equals('cassandane', $capas->{accountIdForPrincipal});
    $self->assert_str_equals('cassandane', $capas->{principalId});
}

sub test_calendarevent_set_links_dupids
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event =  {
        calendarIds => {
            Default => JSON::true,
        },
        title => 'event1',
        calendarIds => {
            Default => JSON::true,
        },
        start => '2011-01-01T04:05:06',
        duration => 'PT1H',
        links => {
            link1 => {
                href => 'https://local/link1',
                title => 'link1',
            },
            link2 => {
                href => 'https://local/link2',
                title => 'link2',
            },
        },
        locations => {
            loc1 => {
                name => 'loc1',
                links => {
                    link1 => {
                        href => 'https://local/loc1/link1',
                        title => 'loc1link1',
                    },
                    link2 => {
                        href => 'https://local/loc1/link2',
                        title => 'loc1link2',
                    },
                },
            },
            loc2 => {
                name => 'loc2',
                links => {
                    link1 => {
                        href => 'https://local/loc2/link1',
                        title => 'loc2link1',
                    },
                    link2 => {
                        href => 'https://local/loc2/link2',
                        title => 'loc2link2',
                    },
                },
            },
        },
        replyTo => {
            imip => 'mailto:orga@local',
        },
        participants => {
            part1 => {
                email => 'part1@local',
                sendTo => {
                    imip => 'mailto:part1@local',
                },
                roles => {
                    attendee => JSON::true,
                },
                links => {
                    link1 => {
                        href => 'https://local/part1/link1',
                        title => 'part1link1',
                    },
                    link2 => {
                        href => 'https://local/part1/link2',
                        title => 'part1link2',
                    },
                },
            },
            part2 => {
                email => 'part2@local',
                sendTo => {
                    imip => 'mailto:part2@local',
                },
                roles => {
                    attendee => JSON::true,
                },
                links => {
                    link1 => {
                        href => 'https://local/part2/link1',
                        title => 'part2link1',
                    },
                    link2 => {
                        href => 'https://local/part2/link2',
                        title => 'part2link2',
                    },
                },
            },
            orga => {
                email => 'orga@local',
                sendTo => {
                    imip => 'mailto:orga@local',
                },
                roles => {
                    owner => JSON::true,
                    attendee => JSON::true,
                },
            },
        }
    };
    my $ret = $self->createandget_event($event);
    $self->assert_normalized_event_equals($event, $ret);
}

sub test_calendarevent_set_participant_links_dir
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my ($id, $ical) = $self->icalfile('attendeedir');

    my $icshref = '/dav/calendars/user/cassandane/Default/attendeedir.ics';
    $caldav->Request('PUT', $icshref, $ical, 'Content-Type' => 'text/calendar');
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
        }, 'R1'],
    ]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);

    # Links generated from DIR parameter loop back to DIR.

    my $linkId = (keys %{$event->{participants}{attendee}{links}})[0];

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $event->{id} => {
                    'participants/attendee/links' => {
                        $linkId => {
                            href => 'https://local/attendee/dir2',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_not_null($res->[0][1]{updated}{$event->{id}});

    $res = $caldav->Request('GET', $icshref);
    $self->assert_matches(qr/DIR="https:/, $res->{content});
}

sub test_participantidentity_get
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $res = $jmap->CallMethods([
        ['ParticipantIdentity/get', {
        }, 'R1'],
    ]);

    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_deep_equals({
        imip => 'mailto:cassandane@example.com',
    }, $res->[0][1]{list}[0]{sendTo});
    my $partId1 = $res->[0][1]{list}[0]{id};

    $caldav->Request(
      'PROPPATCH',
      '',
      x('D:propertyupdate', $caldav->NS(),
        x('D:set',
          x('D:prop',
            x('C:calendar-user-address-set',
              x('D:href', 'mailto:cassandane@example.com'),
              x('D:href', 'mailto:foo@local'),
            )
          )
        )
      )
    );

    $res = $jmap->CallMethods([
        ['ParticipantIdentity/get', {
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([
        ['ParticipantIdentity/get', {
            ids => [$partId1, 'nope'],
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_deep_equals({
        imip => 'mailto:cassandane@example.com',
    }, $res->[0][1]{list}[0]{sendTo});
    $self->assert_deep_equals(['nope'], $res->[0][1]{notFound});
}

sub test_participantidentity_changes
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['ParticipantIdentity/changes', {
            sinceState => '0',
        }, 'R1']
    ]);
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_participantidentity_set
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['ParticipantIdentity/set', {
            create => {
                partid1 => {
                    sendTo => {
                        imip => 'mailto:foo@local',
                    },
                },
            },
            update => {
                partid2 => {
                    name => 'bar',
                },
            },
            destroy => ['partid3'],
        }, 'R1']
    ]);

    $self->assert_str_equals('forbidden',
        $res->[0][1]{notCreated}{partid1}{type});
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notUpdated}{partid2}{type});
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notDestroyed}{partid3}{type});
}

sub test_calendarevent_set_fullblown
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event1 = {
        calendarIds => {
            'Default' => JSON::true,
        },
        '@type' => 'Event',
        uid => 'event1uid',
        relatedTo => {
            relatedEventUid => {
                '@type' => 'Relation',
                relation => {
                    first => JSON::true,
                    next => JSON::true,
                    child => JSON::true,
                    parent => JSON::true,
                },
            },
        },
        prodId => '-//Foo//Bar//EN',
        created => '2020-12-21T07:47:00Z',
        updated => '2020-12-21T07:47:00Z',
        sequence => 3,
        title => 'event1title',
        description => 'event1description',
        descriptionContentType => 'text/plain',
        showWithoutTime => JSON::true,
        locations => {
            loc1 => {
                '@type' => 'Location',
                name => 'loc1name',
                description => 'loc1description',
                locationTypes => {
                    hotel => JSON::true,
                    other => JSON::true,
                },
                relativeTo => 'end',
                timeZone => 'Africa/Windhoek',
                coordinates => 'geo:-22.55941,17.08323',
                links => {
                    link1 => {
                        '@type' => 'Link',
                        href => 'https://local/loc1link1.jpg',
                        cid => 'foo@local',
                        contentType => 'image/jpeg',
                        size => 123,
                        rel => 'icon',
                        display => 'fullsize',
                        title => 'loc1title',
                    },
                },
            },
        },
        virtualLocations => {
            virtloc1 => {
                '@type' => 'VirtualLocation',
                name => 'virtloc1name',
                description => 'virtloca1description',
                uri => 'tel:+1-555-555-5555',
            },
        },
        links => {
            link1 => {
                '@type' => 'Link',
                href => 'https://local/link1.jpg',
                cid => 'foo@local',
                contentType => 'image/jpeg',
                size => 123,
                rel => 'icon',
                display => 'fullsize',
                title => 'link1title',
            },
        },
        locale => 'en',
        keywords => {
            keyword1 => JSON::true,
            keyword2 => JSON::true,
        },
        color => 'silver',
        recurrenceRules => [{
            '@type' => 'RecurrenceRule',
            frequency => 'monthly',
            interval => 2,
            rscale => 'gregorian',
            skip => 'forward',
            firstDayOfWeek => 'tu',
            byDay => [{
                '@type' => 'NDay',
                day => 'we',
                nthOfPeriod => 3,
            }],
            byMonthDay => [1,6,13,16,30],
            byHour => [7,13],
            byMinute => [2,46],
            bySecond => [5,10],
            bySetPosition => [1,5,9],
            count => 7,
        }],
        excludedRecurrenceRules => [{
            '@type' => 'RecurrenceRule',
            frequency => 'monthly',
            interval => 3,
            rscale => 'gregorian',
            skip => 'forward',
            firstDayOfWeek => 'tu',
            byDay => [{
                '@type' => 'NDay',
                day => 'we',
                nthOfPeriod => 3,
            }],
            byMonthDay => [1,6,13,16,30],
            byHour => [7,13],
            byMinute => [2,46],
            bySecond => [5,10],
            bySetPosition => [1,5,9],
            count => 7,
        }],
        recurrenceOverrides => {
            '2021-02-02T02:00:00' => {
                title => 'recurrenceOverrideTitle',
            },
        },
        priority => 7,
        freeBusyStatus => 'free',
        privacy => 'secret',
        replyTo => {
            imip => 'mailto:orga@local',
        },
        participants => {
            orga => {
                '@type' => 'Participant',
                email => 'orga@local',
                sendTo => {
                    imip => 'mailto:orga@local',
                },
                roles => {
                    owner => JSON::true,
                },
            },
            participant1 => {
                '@type' => 'Participant',
                name => 'participant1Name',
                email => 'participant1@local',
                description => 'participant1Description',
                sendTo => {
                    imip => 'mailto:participant1@local',
                    web => 'https://local/participant1',
                },
                kind => 'individual',
                roles => {
                    attendee => JSON::true,
                    chair => JSON::true,
                },
                locationId => 'loc1',
                language => 'de',
                participationStatus => 'tentative',
                participationComment => 'participant1Comment',
                expectReply => JSON::true,
                delegatedTo => {
                    participant2 => JSON::true,
                },
                delegatedFrom => {
                    participant3 => JSON::true,
                },
                links => {
                    link1 => {
                        '@type' => 'Link',
                        href => 'https://local/participant1link1.jpg',
                        cid => 'foo@local',
                        contentType => 'image/jpeg',
                        size => 123,
                        rel => 'describedby',
                        title => 'participant1title',
                    },
                },
            },
            participant2 => {
                '@type' => 'Participant',
                email => 'participant2@local',
                sendTo => {
                    imip => 'mailto:participant2@local',
                },
                roles => {
                    attendee => JSON::true,
                },
            },
            participant3 => {
                '@type' => 'Participant',
                email => 'participant3@local',
                sendTo => {
                    imip => 'mailto:participant3@local',
                },
                roles => {
                    attendee => JSON::true,
                },
            },
        },
        alerts => {
            alert1 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'OffsetTrigger',
                    offset => '-PT5M',
                    relativeTo => 'end',
                },
            },
            alert2 => {
                '@type' => 'Alert',
                trigger => {
                    '@type' => 'AbsoluteTrigger',
                    when => '2021-01-01T01:00:00Z',
                },
                acknowledged => '2020-12-21T07:47:00Z',
                relatedTo => {
                    alert1 => {
                        '@type' => 'Relation',
                        relation => {
                            parent => JSON::true,
                        },
                    },
                },
                action => 'email',
            },
        },

        start => '2021-01-01T01:00:00',
        timeZone => 'Europe/Berlin',
        duration => 'PT1H',
        status => 'tentative',
    };

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => $event1,
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event1'],
        }, 'R2'],
    ]);
    $self->assert_normalized_event_equals($event1, $res->[1][1]{list}[0]);
}

sub test_calendarevent_set_custom_timezones
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event1 = {
        calendarIds => {
            'Default' => JSON::true,
        },
        title => 'event1title',
        start => '2021-01-01T02:00:00',
        timeZone => '/customtzid',
        duration => 'PT1H',
        timeZones => {
            '/customtzid' => {
                '@type' => 'TimeZone',
                tzId => 'MyCustomTzId', # differs from "/customtzid"
                updated => '2021-01-01T01:00:00Z',
                url => 'https://local/customtzid',
                validUntil => '2022-01-01T01:00:00Z',
                aliases => {
                    MyCustomTzIdAlias => JSON::true,
                },
                standard => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-11-04T02:00:00',
                    offsetFrom => '-0400',
                    offsetTo => '-0500',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['11'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 1,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMST' => JSON::true,
                    },
                    comments => ['customcomment'],
                }],
                daylight => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-03-11T02:00:00',
                    offsetFrom => '-0500',
                    offsetTo => '-0400',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['3'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 2,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMDT' => JSON::true,
                    },
                    comments => ['customcomment'],
                }],
            },
        },
    };

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => $event1,
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event1'],
        }, 'R2'],
    ]);
    $self->assert_normalized_event_equals($event1, $res->[1][1]{list}[0]);
}

sub test_calendarevent_get_custom_timezones_orphans
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;

    my ($id, $ical) = $self->icalfile('orphaned-timezones');

    my $event = $self->putandget_vevent($id, $ical);

    #$self->assert_num_equals(1, scalar keys %{$event->{timeZones}});
    my @tzids = keys %{$event->{timeZones}};
    $self->assert_deep_equals(['/customtzid'], \@tzids);
}

sub test_calendarevent_set_custom_timezones_orphans
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event1 = {
        calendarIds => {
            'Default' => JSON::true,
        },
        title => 'event1title',
        start => '2021-01-01T02:00:00',
        timeZone => '/customtzid',
        duration => 'PT1H',
        timeZones => {
            '/orphantzid' => {
                '@type' => 'TimeZone',
                tzId => 'orphantzid',
                updated => '2021-01-01T01:00:00Z',
                validUntil => '2022-01-01T01:00:00Z',
                standard => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-11-04T02:00:00',
                    offsetFrom => '-0400',
                    offsetTo => '-0500',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['11'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 1,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMST' => JSON::true,
                    },
                }],
                daylight => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-03-11T02:00:00',
                    offsetFrom => '-0500',
                    offsetTo => '-0400',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['3'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 2,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                }],
            },
            '/customtzid' => {
                '@type' => 'TimeZone',
                tzId => 'customtzid',
                updated => '2021-01-01T01:00:00Z',
                url => 'https://local/customtzid',
                validUntil => '2022-01-01T01:00:00Z',
                aliases => {
                    customtzidAlias => JSON::true,
                },
                standard => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-11-04T02:00:00',
                    offsetFrom => '-0400',
                    offsetTo => '-0500',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['11'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 1,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMST' => JSON::true,
                    },
                    comments => ['customcomment'],
                }],
                daylight => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-03-11T02:00:00',
                    offsetFrom => '-0500',
                    offsetTo => '-0400',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['3'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 2,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMDT' => JSON::true,
                    },
                    comments => ['customcomment'],
                }],
            },
        },
    };

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => $event1,
            },
        }, 'R1'],
    ]);

    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{event1}{type});
    $self->assert_deep_equals(['timeZones/~1orphantzid'],
        $res->[0][1]{notCreated}{event1}{properties});
}

sub test_calendarevent_query_custom_timezones
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $event1 = {
        calendarIds => {
            'Default' => JSON::true,
        },
        title => 'event1title',
        start => '2021-01-01T02:00:00',
        timeZone => '/customtzid',
        duration => 'PT1H',
        timeZones => {
            '/customtzid' => {
                '@type' => 'TimeZone',
                tzId => 'MyCustomTzId',
                updated => '2021-01-01T01:00:00Z',
                url => 'https://local/customtzid',
                validUntil => '2022-01-01T01:00:00Z',
                aliases => {
                    MyCustomTzIdAlias => JSON::true,
                },
                standard => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-11-04T02:00:00',
                    offsetFrom => '-0400',
                    offsetTo => '-0500',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['11'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 1,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMST' => JSON::true,
                    },
                    comments => ['customcomment'],
                }],
                daylight => [{
                    '@type' => 'TimeZoneRule',
                    start => '2007-03-11T02:00:00',
                    offsetFrom => '-0500',
                    offsetTo => '-0400',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'yearly',
                        byMonth => ['3'],
                        byDay => [{
                            '@type' => 'NDay',
                            day => 'su',
                            nthOfPeriod => 2,
                        }],
                        interval => 1,
                        rscale => 'gregorian',
                        firstDayOfWeek => 'mo',
                        skip => 'omit',
                    }],
                    names => {
                        'CUSTOMDT' => JSON::true,
                    },
                    comments => ['customcomment'],
                }],
            },
        },
    };

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => $event1,
            },
        }, 'R1'],
        ['CalendarEvent/query', {
            filter => {
                after =>  '2021-01-01T07:00:00',
                before => '2021-01-01T08:00:00',
            },
        }, 'R2'],
        ['CalendarEvent/query', {
            filter => {
                after =>  '2021-01-01T02:00:00',
                before => '2021-01-01T03:00:00',
            },
        }, 'R3'],
    ]);
    $self->assert_not_null($res->[0][1]{created}{event1});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[2][1]{ids}});
}

sub test_calendarevent_set_schedulestatus
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'test',
                    replyTo => {
                        imip => 'mailto:orga@local',
                    },
                    participants => {
                        part1 => {
                            '@type' => 'Participant',
                            sendTo => {
                                imip => 'mailto:part1@local',
                            },
                            roles => {
                                attendee => JSON::true,
                            },
                            scheduleStatus => ['2.0', '2.4'],
                        },
                    },
                    start => '2021-01-01T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event1'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['2.0', '2.4'],
        $res->[1][1]{list}[0]{participants}{part1}{scheduleStatus});
}

sub test_calendarevent_guesstz
    :min_version_3_5 :needs_component_jmap :needs_dependency_guesstz
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $eventId = '123456789';
    my $ical = <<EOF;
BEGIN:VCALENDAR
PRODID: -//xxx//yyy//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:Custom
BEGIN:DAYLIGHT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
DTSTART:20070311T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
DTSTART:20071104T020000
RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:$eventId
DTSTAMP:20201226T180609
DTSTART;TZID=Custom:20201227T140000
DURATION:PT1H
SUMMARY:A summary
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($eventId,
        $ical, ['timeZone', 'timeZones']);
    $self->assert_str_equals('America/New_York', $event->{timeZone});
    $self->assert_null($event->{timeZones});
}

sub test_calendarevent_guesstz_gmt
    :min_version_3_5 :needs_component_jmap :needs_dependency_guesstz
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $eventId = '123456789';
    my $ical = <<EOF;
BEGIN:VCALENDAR
PRODID: -//xxx//yyy//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:Custom
LAST-MODIFIED:20210127T134508Z
X-LIC-LOCATION:Etc/GMT+8
X-PROLEPTIC-TZNAME:-08
BEGIN:STANDARD
TZNAME:-08
TZOFFSETFROM:-0800
TZOFFSETTO:-0800
DTSTART:16010101T000000
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:$eventId
DTSTAMP:20201226T180609
DTSTART;TZID=Custom:20201227T140000
DURATION:PT1H
SUMMARY:A summary
CLASS:PUBLIC
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($eventId,
        $ical, ['timeZone', 'timeZones']);
    $self->assert_str_equals('Etc/GMT+8', $event->{timeZone});
    $self->assert_null($event->{timeZones});
}

sub test_calendarevent_guesstz_recur
    :min_version_3_5 :needs_component_jmap :needs_dependency_guesstz
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $eventId = '123456789';
    my $ical = <<EOF;
BEGIN:VCALENDAR
PRODID: -//xxx//yyy//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:Custom
LAST-MODIFIED:20210127T134508Z
BEGIN:DAYLIGHT
TZNAME:CEST
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
DTSTART:19810329T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
END:DAYLIGHT
BEGIN:STANDARD
TZNAME:CET
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
DTSTART:19961027T030000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:$eventId
DTSTAMP:20201226T180609
DTSTART;TZID=Custom:20100101T140000
DURATION:PT1H
RRULE:FREQ=MONTHLY;COUNT=48
SUMMARY:A summary
CLASS:PUBLIC
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent($eventId,
        $ical, ['timeZone', 'timeZones']);
    $self->assert_str_equals('Europe/Berlin', $event->{timeZone});
    $self->assert_null($event->{timeZones});
}

sub test_calendar_set_sharewith_acl
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $admin->create("user.test1");

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                '1' => {
                    name => 'A',
                }
            },
        }, 'R1'],
    ]);
    my $calendarId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($calendarId);

    my @testCases = ({
        rights => {
            mayReadFreeBusy => JSON::true,
        },
        acl => '9',
    }, {
        rights => {
            mayReadItems => JSON::true,
        },
        acl => 'lrw',
    }, {
        rights => {
            mayWriteAll => JSON::true,
        },
        acl => 'switedn7',
        wantRights => {
            mayWriteAll => JSON::true,
            mayWriteOwn => JSON::true,
            mayUpdatePrivate => JSON::true,
            mayRSVP => JSON::true,
        },
    }, {
        rights => {
            mayWriteOwn => JSON::true,
        },
        acl => 'w6',
    }, {
        rights => {
            mayUpdatePrivate => JSON::true,
        },
        acl => 'w5',
    }, {
        rights => {
            mayRSVP => JSON::true,
        },
        acl => 'w7',
    }, {
        rights => {
            mayAdmin => JSON::true,
        },
        acl => 'wa',
   }, {
        rights => {
            mayDelete => JSON::true,
        },
        acl => 'wxc',
    });

    foreach(@testCases) {

        xlog "Run test for acl $_->{acl}";

        $res = $jmap->CallMethods([
            ['Calendar/set', {
                update => {
                    $calendarId => {
                        shareWith => {
                            test1 => $_->{rights},
                        },
                    },
                },
            }, 'R1'],
            ['Calendar/get', {
                ids => [$calendarId],
                properties => ['shareWith'],
            }, 'R2'],
        ]);

        $_->{wantRights} ||= $_->{rights};

        my %mergedrights = ((
            mayReadFreeBusy => JSON::false,
            mayReadItems => JSON::false,
            mayWriteAll => JSON::false,
            mayWriteOwn => JSON::false,
            mayUpdatePrivate => JSON::false,
            mayRSVP => JSON::false,
            mayAdmin => JSON::false,
            mayDelete => JSON::false,
        ), %{$_->{wantRights}});

        $self->assert_deep_equals(\%mergedrights,
            $res->[1][1]{list}[0]{shareWith}{test1});
        my %acl = @{$admin->getacl("user.cassandane.#calendars.$calendarId")};
        $self->assert_str_equals($_->{acl}, $acl{test1});
    }
}

sub test_calendarevent_set_writeown
    :needs_component_jmap :min_version_0_0 :max_version_0_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Create sharee user";
    my $admin = $self->{adminstore}->get_client();
    $self->{instance}->create_user("sharee");
    my $service = $self->{instance}->get_service("http");
    my $shareeJmap = Mail::JMAPTalk->new(
        user => 'sharee',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $shareeJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/calendars',
        'urn:ietf:params:jmap:calendars',
    ]);

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        sharee => {
                            mayReadItems => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayUpdatePrivate => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Create events";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                eventCassOwner => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'eventCassOwner',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        part1 => {
                            '@type' => 'Participant',
                            sendTo => {
                                imip => 'mailto:part1@local',
                            },
                            roles => {
                                attendee => JSON::true,
                            },
                        },
                    },
                    start => '2021-01-01T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
                eventShareeOwner => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'eventShareeOwner',
                    replyTo => {
                        imip => 'mailto:sharee@example.com',
                    },
                    participants => {
                        part1 => {
                            '@type' => 'Participant',
                            sendTo => {
                                imip => 'mailto:part1@local',
                            },
                            roles => {
                                attendee => JSON::true,
                            },
                        },
                    },
                    start => '2021-01-01T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
                eventNoOwner => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'eventNoOwner',
                    start => '2021-01-02T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
    ]);
    my $eventCassOwner = $res->[0][1]{created}{eventCassOwner}{id};
    $self->assert_not_null($eventCassOwner);
    my $eventShareeOwner = $res->[0][1]{created}{eventShareeOwner}{id};
    $self->assert_not_null($eventShareeOwner);
    my $eventNoOwner = $res->[0][1]{created}{eventNoOwner}{id};
    $self->assert_not_null($eventNoOwner);

    xlog "Update private event properties as sharee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventCassOwner => {
                    color => 'pink',
                },
                $eventShareeOwner => {
                    color => 'pink',
                },
                $eventNoOwner => {
                    color => 'pink',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventCassOwner});
    $self->assert(exists $res->[0][1]{updated}{$eventShareeOwner});
    $self->assert(exists $res->[0][1]{updated}{$eventNoOwner});

    xlog "Update non-private event properties as sharee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventCassOwner => {
                    title => 'eventCassOwnerUpdated',
                },
                $eventShareeOwner => {
                    title => 'eventShareeOwnerUpdated',
                },
                $eventNoOwner => {
                    title => 'eventNoOwnerUpdated',
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notUpdated}{$eventCassOwner}{type});
    $self->assert(exists $res->[0][1]{updated}{$eventShareeOwner});
    $self->assert(exists $res->[0][1]{updated}{$eventNoOwner});

    xlog "Destroy events as sharee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            destroy => [
                $eventCassOwner,
                $eventShareeOwner,
                $eventNoOwner,
            ],
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notDestroyed}{$eventCassOwner}{type});
    $self->assert(grep /$eventShareeOwner/, @{$res->[0][1]{destroyed}});
    $self->assert(grep /$eventNoOwner/, @{$res->[0][1]{destroyed}});
}

sub test_calendarevent_set_writeown_caldav
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create sharee user";
    my $admin = $self->{adminstore}->get_client();
    $self->{instance}->create_user("sharee");
    my $service = $self->{instance}->get_service("http");
    my $shareeCaldav = Net::CalDAVTalk->new(
        user => "sharee",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        sharee => {
                            mayReadItems => JSON::true,
                            mayWriteOwn => JSON::true,
                            mayUpdatePrivate => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "Create event with cassandane owner";
    my $cassOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:cassowner
ORGANIZER:mailto:cassandane@example.com
ATTENDEE:mailto:attendee@example.com
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $res = $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/cassowner.ics',
        $cassOwnerIcal, 'Content-Type' => 'text/calendar');

    xlog "Create event with sharee owner";
    my $shareeOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20161028T160000
DURATION:PT1H
UID:7e55d2c1-d197-4e51-b9b6-a78c8a38fd78
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:shareeowner
ORGANIZER:mailto:sharee@example.com
ATTENDEE:mailto:attendee@example.com
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/sharee/cassandane.Default/shareeowner.ics',
        $shareeOwnerIcal, 'Content-Type' => 'text/calendar');

    xlog "Create event with no owner";
    my $noOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20161128T160000
DURATION:PT1H
UID:80cdbc93-c602-4591-a8d2-f67a804e6acf
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:noowner
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/sharee/cassandane.Default/noowner.ics',
        $noOwnerIcal, 'Content-Type' => 'text/calendar');

    xlog "Update event with sharee owner as sharee";
    $shareeOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20161028T160000
DURATION:PT1H
UID:7e55d2c1-d197-4e51-b9b6-a78c8a38fd78
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:shareeownerUpdated
ORGANIZER:mailto:sharee@example.com
ATTENDEE:mailto:attendee@example.com
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $shareeCaldav->Request('PUT',
        '/dav/calendars/user/sharee/cassandane.Default/shareeowner.ics',
        $shareeOwnerIcal, 'Content-Type' => 'text/calendar');

    xlog "Update event with no owner as sharee";
    $noOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20161128T160000
DURATION:PT1H
UID:80cdbc93-c602-4591-a8d2-f67a804e6acf
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:noowner
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $shareeCaldav->Request('PUT',
        '/dav/calendars/user/sharee/cassandane.Default/noowner.ics',
        $noOwnerIcal, 'Content-Type' => 'text/calendar');

    xlog "Update per-user property as sharee";
    $cassOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:cassowner
COLOR:pink
ORGANIZER:mailto:cassandane@example.com
ATTENDEE;SCHEDULE-STATUS=1.1:mailto:attendee@example.com
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $shareeCaldav->Request('PUT',
        '/dav/calendars/user/sharee/cassandane.Default/cassowner.ics',
        $cassOwnerIcal, 'Content-Type' => 'text/calendar');

    xlog "Update property as sharee";
    $cassOwnerIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Vienna:20160928T160000
DURATION:PT1H
UID:40d6fe3c-6a51-489e-823e-3ea22f427a3e
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:cassownerUpdated
ORGANIZER:mailto:cassandane@example.com
ATTENDEE;SCHEDULE-STATUS=1.1:mailto:attendee@example.com
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    # annoyingly CalDAV talk aborts for HTTP status >= 400
    my $href = '/dav/calendars/user/sharee/cassandane.Default/cassowner.ics';
    my $rawResponse = $shareeCaldav->{ua}->request('PUT',
        $shareeCaldav->request_url($href), {
            content => $cassOwnerIcal,
            headers => {
                'Content-Type' => 'text/calendar',
                'Authorization' => $shareeCaldav->auth_header(),
            },
        },
    );
    $self->assert_num_equals(403, $rawResponse->{status});

    xlog "Delete event with sharee owner as sharee";
    $shareeCaldav->Request('DELETE',
        '/dav/calendars/user/sharee/cassandane.Default/shareeowner.ics');

    xlog "Delete event with no owner as sharee";
    $shareeCaldav->Request('DELETE',
        '/dav/calendars/user/sharee/cassandane.Default/noowner.ics');

    xlog "Delete event with cassandane owner as sharee";
    $href = '/dav/calendars/user/sharee/cassandane.Default/cassowner.ics';
    $rawResponse = $shareeCaldav->{ua}->request('DELETE',
        $shareeCaldav->request_url($href), {
            headers => {
                'Authorization' => $shareeCaldav->auth_header(),
            },
        },
    );
    $self->assert_num_equals(403, $rawResponse->{status});


}

sub test_calendarevent_get_recurrenceid
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//foo//bar//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART;TZID=Europe/Berlin:20160928T160000
RECURRENCE-ID;TZID=Europe/London:20160928T010000
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
PRIORITY:3
SEQUENCE:9
SUMMARY:test
RRULE:FREQ=MONTHLY
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT', 'Default/2a358cee-6489-4f14-a57f-c104db4dc357.ics', $ical,
        'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/query',
                path => '/ids'
            },
            properties => [
                'recurrenceId',
                'recurrenceIdTimeZone',
                'start',
                'timeZone',
            ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    my $event = $res->[1][1]{list}[0];

    $self->assert_str_equals('2016-09-28T16:00:00', $event->{start});
    $self->assert_str_equals('Europe/Berlin', $event->{timeZone});
    $self->assert_str_equals('2016-09-28T01:00:00', $event->{recurrenceId});
    $self->assert_str_equals('Europe/London', $event->{recurrenceIdTimeZone});
}

sub assert_rewrite_webdav_attachment_url_itip
    :min_version_3_5 :needs_component_jmap
{
    my ($self, $eventHref) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Assert ATTACH in iTIP message is a BINARY value";
    my $data = $self->{instance}->getnotify();
    my ($imip) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($imip);
    my $payload = decode_json($imip->{MESSAGE});

    my $ical = Data::ICal->new(data => $payload->{ical});
    my %entries = map { $_->ical_entry_type() => $_ } @{$ical->entries()};
    my $event = $entries{'VEVENT'};
    $self->assert_not_null($event);

    my $attach = $event->property('ATTACH');
    $self->assert_num_equals(1, scalar @{$attach});
    $self->assert_null($attach->[0]->parameters()->{'MANAGED-ID'});
    $self->assert_str_equals('BINARY', $attach->[0]->parameters()->{VALUE});
    $self->assert_str_equals('c29tZWJsb2I=', $attach->[0]->value()); # 'someblob' in base64

    xlog "Assert ATTACH on server is a WebDAV attachment URI";
    my $caldavResponse = $caldav->Request('GET', $eventHref);
    $ical = Data::ICal->new(data => $caldavResponse->{content});
    %entries = map { $_->ical_entry_type() => $_ } @{$ical->entries()};
    $event = $entries{'VEVENT'};
    $self->assert_not_null($event);

    $attach = $event->property('ATTACH');
    $self->assert_num_equals(1, scalar @{$attach});
    $self->assert_not_null($attach->[0]->parameters()->{'MANAGED-ID'});
    $self->assert_null($attach->[0]->parameters()->{VALUE});
    my $webdavAttachURI =
       $self->{instance}->{config}->get('webdav_attachments_baseurl') .
       '/dav/calendars/user/cassandane/Attachments/';
    $self->assert($attach->[0]->value() =~ /^$webdavAttachURI.+/);
}

sub test_rewrite_webdav_attachment_url_itip_jmap
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Upload blob via JMAP";
    my $res = $jmap->Upload('someblob', "application/octet-stream");
    my $blobId = $res->{blobId};
    $self->assert_not_null($blobId);

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "Create event with a Link.blobId";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                1 => {
                    uid => 'eventuid1local',
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-10T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    links => {
                        link1 => {
                            rel => 'enclosure',
                            blobId => $blobId,
                            contentType => 'image/jpg',
                        },
                    },
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        part1 => {
                            '@type' => 'Participant',
                            sendTo => {
                                imip => 'mailto:part1@local',
                            },
                            roles => {
                                attendee => JSON::true,
                            },
                        },
                    },
                    start => '2021-01-01T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($eventId);
    my $eventHref = $res->[0][1]{created}{1}{'x-href'};
    $self->assert_not_null($eventHref);

    $self->assert_rewrite_webdav_attachment_url_itip($eventHref);
}

sub test_rewrite_webdav_attachment_url_itip_caldav
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my $rawIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
ORGANIZER:cassandane@example.com
ATTENDEE:attendee@local
UID:123456789
TRANSP:OPAQUE
SUMMARY:test
DTSTART;TZID=Australia/Melbourne:20160831T153000
DURATION:PT1H
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $rawIcal,
        'Content-Type' => 'text/calendar');
    my $eventHref = '/dav/calendars/user/cassandane/Default/test.ics';

    # clean notification cache
    $self->{instance}->getnotify();

    xlog "Add attachment via CalDAV";
    my $url = $caldav->request_url($eventHref) . '?action=attachment-add';
    my $res = $caldav->ua->post($url, {
        headers => {
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => 'attachment;filename=test',
            'Prefer' => 'return=representation',
            'Authorization' => $caldav->auth_header(),
        },
        content => 'someblob',
    });
    $self->assert_str_equals('201', $res->{status});

    $self->assert_rewrite_webdav_attachment_url_itip($eventHref);
}

sub test_rewrite_webdav_attachment_binary_itip_caldav
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my $rawIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
ORGANIZER:cassandane@example.com
ATTENDEE:attendee@local
UID:123456789
TRANSP:OPAQUE
SUMMARY:test
DTSTART;TZID=Australia/Melbourne:20160831T153000
DURATION:PT1H
DTSTAMP:20150806T234327Z
SEQUENCE:0
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $rawIcal,
        'Content-Type' => 'text/calendar');
    my $eventHref = '/dav/calendars/user/cassandane/Default/test.ics';

    xlog "Add attachment via CalDAV";
    my $url = $caldav->request_url($eventHref) . '?action=attachment-add';
    my $res = $caldav->ua->post($url, {
        headers => {
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => 'attachment;filename=test',
            'Prefer' => 'return=representation',
            'Authorization' => $caldav->auth_header(),
        },
        content => 'someblob',
    });
    $self->assert_str_equals('201', $res->{status});

    # Now we have a blob "someblob" (c29tZWJsb2I=) in managed attachments.

    xlog "Create event via CalDAV";
    $rawIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
CREATED:20150806T234327Z
ORGANIZER:cassandane@example.com
ATTENDEE;PARTSTAT=DECLINED:attendee@local
UID:123456789
TRANSP:OPAQUE
SUMMARY:test
DTSTART;TZID=Australia/Melbourne:20160831T153000
DURATION:PT1H
DTSTAMP:20150806T234327Z
ATTACH;VALUE=BINARY:c29tZWJsb2I=
SEQUENCE:1
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $rawIcal,
        'Schedule-Sender-Address' => 'attendee@local',
        'Content-Type' => 'text/calendar');

    my $caldavResponse = $caldav->Request('GET', $eventHref);
    my $ical = Data::ICal->new(data => $caldavResponse->{content});
    my %entries = map { $_->ical_entry_type() => $_ } @{$ical->entries()};
    my $event = $entries{'VEVENT'};
    $self->assert_not_null($event);

    xlog "Assert BINARY ATTACH got rewritten to managed attachment URI";
    my $attach = $event->property('ATTACH');
    $self->assert_num_equals(1, scalar @{$attach});
    $self->assert_not_null($attach->[0]->parameters()->{'MANAGED-ID'});
    $self->assert_null($attach->[0]->parameters()->{VALUE});
    my $webdavAttachURI =
       $self->{instance}->{config}->get('webdav_attachments_baseurl') .
       '/dav/calendars/user/cassandane/Attachments/';
    $self->assert($attach->[0]->value() =~ /^$webdavAttachURI.+/);
}

sub test_calendarevent_get_attachbinary
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my $rawIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART:20160928T160000Z
DTEND:20160928T170000Z
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:test
ATTACH;VALUE=BINARY;ENCODING=BASE64;FMTTYPE=text/plain:aGVsbG8=
SEQUENCE:0
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $rawIcal,
        'Content-Type' => 'text/calendar');

    xlog "Fetch with Cyrus extension";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['links'],
        }, 'R1'],
    ]);
    my $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);

    my @links = values %{$event->{links}};
    $self->assert_num_equals(1, scalar @links);
    $self->assert_null($links[0]{href});
    $self->assert_str_equals('text/plain', $links[0]{contentType});
    my $blobId = $links[0]{blobId};
    $self->assert_not_null($blobId);

    xlog "Fetch blob";
    $res = $jmap->Download('cassandane', $blobId);
    $self->assert_str_equals("hello", $res->{content});

    xlog "Fetch without Cyrus extension";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['links'],
        }, 'R2'],
    ], [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
    ]);
    $event = $res->[0][1]{list}[0];
    $self->assert_not_null($event);

    @links = values %{$event->{links}};
    $self->assert_num_equals(1, scalar @links);
    $self->assert_str_equals('data:text/plain;base64,aGVsbG8=', $links[0]{href});
    $self->assert_str_equals('text/plain', $links[0]{contentType});
}

sub test_calendarevent_set_attachbinary_datauri
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create event with data: URI in Link.href";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2019-12-10T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    links => {
                        link => {
                            href =>'data:text/plain;base64,aGVsbG8=',
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event1'],
            properties => ['links', 'x-href'],
        }, 'R2'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    xlog "Fetch event without Cyrus extension";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => ['#event1'],
            properties => ['links'],
        }, 'R1'],
    ], [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
    ]);
    my $linkWithoutExt = (values %{$res->[0][1]{list}[0]{links}})[0];
    $self->assert_str_equals('data:text/plain;base64,aGVsbG8=',
        $linkWithoutExt->{href});
    $self->assert_null($linkWithoutExt->{blobId});
    $self->assert_str_equals('text/plain',
        $linkWithoutExt->{contentType});

    xlog "Fetch event with Cyrus extension";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => ['#event1'],
            properties => ['links', 'x-href'],
        }, 'R1'],
    ], [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);
    my $linkWithExt = (values %{$res->[0][1]{list}[0]{links}})[0];
    $self->assert_null($linkWithExt->{href});
    $self->assert_not_null($linkWithExt->{blobId});
    $self->assert_str_equals('text/plain', $linkWithExt->{contentType});
    my $xhref = $res->[0][1]{list}[0]{'x-href'};
    $self->assert_not_null($xhref);

    xlog "Assert ATTACH BINARY in VEVENT";
    my $caldavResponse = $caldav->Request('GET', $xhref);
    my $ical = Data::ICal->new(data => $caldavResponse->{content});
    my %entries = map { $_->ical_entry_type() => $_ } @{$ical->entries()};
    my $vevent = $entries{'VEVENT'};
    $self->assert_not_null($vevent);

    my $attach = $vevent->property('ATTACH');
    $self->assert_num_equals(1, scalar @{$attach});
    $self->assert_str_equals('BINARY', $attach->[0]->parameters()->{VALUE});
}

sub test_calendarevent_set_attachbinary_blobid
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create event via CalDAV";
    my $rawIcal = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
TRANSP:TRANSPARENT
DTSTART:20160928T160000Z
DTEND:20160928T170000Z
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:event1
ATTACH;VALUE=BINARY;ENCODING=BASE64;FMTTYPE=text/plain:aGVsbG8=
SEQUENCE:0
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $rawIcal,
        'Content-Type' => 'text/calendar');

    xlog "Fetch Link.blobId";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['links'],
        }, 'R1'],
    ]);
    my $event1 = $res->[0][1]{list}[0];
    $self->assert_not_null($event1);
    my $blobId1 = (values %{$event1->{links}})[0]->{blobId};
    $self->assert_not_null($blobId1);

    xlog "Assert blobId is a smart blob";
    $self->assert_str_equals("I", substr($blobId1, 0, 1));

    xlog "Create event with same blobId";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event2 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event2",
                    start => "2021-08-01T23:30:00",
                    duration => "PT1H",
                    timeZone => "Australia/Melbourne",
                    links => {
                        link => {
                            blobId => $blobId1,
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event2'],
            properties => ['links', 'x-href'],
        }, 'R2'],
    ]);
    my $event2 = $res->[1][1]{list}[0];
    $self->assert_not_null($event2);
    my $blobId2 = (values %{$event2->{links}})[0]->{blobId};

    xlog "Assert blobId is a G blob";
    $self->assert_str_equals("G", substr($blobId2, 0, 1));

    xlog "Assert /set response reported new blobId";
    $self->assert_str_equals($blobId2,
        $res->[0][1]{created}{event2}{"links/link/blobId"});
}

sub test_calendarevent_get_recurrenceid_date_start_datetime
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//foo//bar//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART;TZID=Europe/Berlin:20160901T161514
DURATION:PT1H
RRULE:FREQ=DAILY;COUNT=3
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:test
LAST-MODIFIED:20150928T132434Z
END:VEVENT
BEGIN:VEVENT
RECURRENCE-ID;TZID=Europe/Berlin:20160902T161514
DTSTART;TZID=Europe/Berlin:20160902T161514
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:testWithDateTimeRecurId
LAST-MODIFIED:20150928T132434Z
END:VEVENT
BEGIN:VEVENT
RECURRENCE-ID;TZID=Europe/Berlin:20160903
DTSTART;TZID=Europe/Berlin:20160903T161514
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:testWithDateRecurId
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF

    my $event = $self->putandget_vevent('2a358cee-6489-4f14-a57f-c104db4dc357',
        $ical, ['recurrenceOverrides']);

    $self->assert_deep_equals({
        '2016-09-02T16:15:14' => {
            title => 'testWithDateTimeRecurId',
        },
        '2016-09-03T16:15:14' => {
            title => 'testWithDateRecurId',
        },
    }, $event->{recurrenceOverrides});
}

sub test_calendarevent_query_with_timezone
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Create event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => 'event',
                    start => '2021-08-24T14:30:00',
                    duration => 'PT1H',
                    timeZone => 'Etc/UTC',
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);

    my @testCases = ({
        filter => {
            after => '2021-08-24T14:30:00',
        },
        wantIds => [$eventId],
    }, {
        filter => {
            after => '2021-08-25T00:30:00',
        },
        timeZone => 'Australia/Melbourne',
        wantIds => [$eventId],
    }, {
        filter => {
            before => '2021-08-24T15:30:00',
        },
        wantIds => [$eventId],
    }, {
        filter => {
            before => '2021-08-25T01:30:00',
        },
        timeZone => 'Australia/Melbourne',
        wantIds => [$eventId],
    });

    foreach(@testCases) {
        my $args = {
            filter => $_->{filter},
        };
        $args->{timeZone} = $_->{timeZone} if defined;

        $res = $jmap->CallMethods([
            ['CalendarEvent/query', $args, 'R1'],
        ]);
        $self->assert_deep_equals($_->{wantIds}, $res->[0][1]{ids});
    }
}

sub test_calendarevent_get_standalone_instances
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
RECURRENCE-ID;TZID=America/New_York:20210101T060000
DTSTART;TZID=Europe/Berlin:20210101T120000
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:instance1
SEQUENCE:0
LAST-MODIFIED:20150928T132434Z
END:VEVENT
BEGIN:VEVENT
RECURRENCE-ID;TZID=America/New_York:20210301T060000
DTSTART;TZID=America/New_York:20210301T080000
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:instance2
SEQUENCE:0
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $ical,
        'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/query', {
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/query',
                path => '/ids'
            },
            properties => [
                'recurrenceId',
                'recurrenceIdTimeZone',
                'start',
                'timeZone',
                'title',
                'uid',
            ],
        }, 'R2'],
    ]);

    my %events = map { $_->{title} => $_ } @{$res->[1][1]{list}};
    $self->assert_num_equals(2, scalar keys %events);
    $self->assert_str_not_equals($events{instance1}{id}, $events{instance2}{id});

    $self->assert_str_equals('2021-01-01T12:00:00',
        $events{instance1}{start});
    $self->assert_str_equals('Europe/Berlin',
        $events{instance1}{timeZone});
    $self->assert_str_equals('2021-01-01T06:00:00',
        $events{instance1}{recurrenceId});
    $self->assert_str_equals('America/New_York',
        $events{instance1}{recurrenceIdTimeZone});
    $self->assert_str_equals('2a358cee-6489-4f14-a57f-c104db4dc357',
        $events{instance1}{uid});

    $self->assert_str_equals('2021-03-01T08:00:00',
        $events{instance2}{start});
    $self->assert_str_equals('America/New_York',
        $events{instance2}{timeZone});
    $self->assert_str_equals('2021-03-01T06:00:00',
        $events{instance2}{recurrenceId});
    $self->assert_str_equals('America/New_York',
        $events{instance2}{recurrenceIdTimeZone});
    $self->assert_str_equals('2a358cee-6489-4f14-a57f-c104db4dc357',
        $events{instance2}{uid});
}

sub test_calendarevent_set_standalone_instances_create
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Get event state";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => [],
        }, 'R2'],
    ]);
    my $state = $res->[0][1]{state};

    xlog "Create standalone instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#instance1'],
            properties => ['start', 'timeZone', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R2'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R3'],
    ]);
    my $instance1Id = $res->[0][1]{created}{instance1}{id};
    $self->assert_not_null($instance1Id);
    my $xhref1 = $res->[0][1]{created}{instance1}{'x-href'};
    $self->assert_not_null($xhref1);
    $self->assert_str_equals('2021-01-01T11:11:11',
        $res->[1][1]{list}[0]{start});
    $self->assert_str_equals('Europe/Berlin',
        $res->[1][1]{list}[0]{timeZone});
    $self->assert_str_equals('2021-01-01T01:01:01',
        $res->[1][1]{list}[0]{recurrenceId});
    $self->assert_str_equals('Europe/London',
        $res->[1][1]{list}[0]{recurrenceIdTimeZone});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[1][1]{state});
    $self->assert_str_not_equals($state, $res->[2][1]{newState});
    $self->assert_deep_equals([$instance1Id], $res->[2][1]{created});
    $self->assert_deep_equals([], $res->[2][1]{updated});
    $self->assert_deep_equals([], $res->[2][1]{destroyed});
    $state = $res->[2][1]{newState};

    xlog "Can't create a new standalone instance with same recurrence id";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance2',
                    start => '2021-02-02T22:22:22',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R2'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{instance2}{type});
    $self->assert_deep_equals(['uid', 'recurrenceId'],
        $res->[0][1]{notCreated}{instance2}{properties});

    $self->assert_str_equals($state, $res->[0][1]{newState});
    $self->assert_str_equals($state, $res->[1][1]{newState});
    $self->assert_deep_equals([], $res->[1][1]{created});
    $self->assert_deep_equals([], $res->[1][1]{updated});
    $self->assert_deep_equals([], $res->[1][1]{destroyed});

    xlog "Create standalone instance with same uid but different recurrence id";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance2',
                    start => '2021-02-02T02:02:02',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-02-02T02:02:02',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#instance2'],
            properties => ['start', 'timeZone', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R2'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R3'],
    ]);
    my $instance2Id = $res->[0][1]{created}{instance2}{id};
    $self->assert_not_null($instance2Id);
    my $xhref2 = $res->[0][1]{created}{instance2}{'x-href'};
    $self->assert_not_null($xhref2);
    $self->assert_str_equals('2021-02-02T02:02:02',
        $res->[1][1]{list}[0]{start});
    $self->assert_str_equals('Europe/Berlin',
        $res->[1][1]{list}[0]{timeZone});
    $self->assert_str_equals('2021-02-02T02:02:02',
        $res->[1][1]{list}[0]{recurrenceId});
    $self->assert_str_equals('Europe/London',
        $res->[1][1]{list}[0]{recurrenceIdTimeZone});

    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[1][1]{state});
    $self->assert_str_not_equals($state, $res->[2][1]{newState});
    $self->assert_deep_equals([$instance2Id], $res->[2][1]{created});
    $self->assert_deep_equals([], $res->[2][1]{updated});
    $self->assert_deep_equals([], $res->[2][1]{destroyed});
    $state = $res->[2][1]{newState};

    xlog "Assert both events exist";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$instance1Id, $instance2Id],
            properties => ['title', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]{notFound}});

    xlog "Assert CalDAV resource contains both instances";
    $res = $caldav->Request('GET', $xhref1);
    $self->assert($res->{content} =~ m/SUMMARY:instance1/);
    $self->assert($res->{content} =~ m/SUMMARY:instance2/);
}

sub test_calendarevent_set_standalone_instances_update
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create standalone instances";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance2',
                    start => '2021-02-02T02:02:02',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-02-02T02:02:02',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
    ]);
    my $instance1Id = $res->[0][1]{created}{instance1}{id};
    $self->assert_not_null($instance1Id);
    my $instance2Id = $res->[0][1]{created}{instance2}{id};
    $self->assert_not_null($instance2Id);
    my $xhref1 = $res->[0][1]{created}{instance1}{'x-href'};
    $self->assert_not_null($xhref1);
    my $xhref2 = $res->[0][1]{created}{instance2}{'x-href'};
    $self->assert_not_null($xhref2);
    $self->assert_str_equals($xhref1, $xhref2);
    my $state = $res->[0][1]{newState};

    xlog "Update standalone instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $instance1Id => {
                    title => 'instance1Updated',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$instance1Id],
            properties => ['title', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => [$instance2Id],
            properties => ['title', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R3'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R4'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$instance1Id});
    $self->assert_str_equals('instance1Updated', $res->[1][1]{list}[0]{title});
    $self->assert_str_equals('instance2', $res->[2][1]{list}[0]{title});

    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[1][1]{state});
    $self->assert_str_not_equals($state, $res->[2][1]{state});
    $self->assert_str_not_equals($state, $res->[3][1]{newState});
    $self->assert_deep_equals([], $res->[3][1]{created});
    $self->assert_deep_equals([$instance1Id], $res->[3][1]{updated});
    $self->assert_deep_equals([], $res->[3][1]{destroyed});
    $state = $res->[3][1]{newState};

    xlog "Assert CalDAV resource contains both instances";
    $res = $caldav->Request('GET', $xhref1);
    $self->assert($res->{content} =~ m/SUMMARY:instance1Updated/);
    $self->assert($res->{content} =~ m/SUMMARY:instance2/);

    xlog "Can't change the recurrenceId or recurrenceIdTimeZone property";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $instance1Id => {
                    recurrenceId => '2021-03-03T03:03:03',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            update => {
                $instance1Id => {
                    recurrenceIdTimeZone => 'America/New_York',
                },
            },
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['recurrenceId'],
        $res->[0][1]{notUpdated}{$instance1Id}{properties});
    $self->assert_deep_equals(['recurrenceIdTimeZone'],
        $res->[1][1]{notUpdated}{$instance1Id}{properties});
}

sub test_calendarevent_set_standalone_instances_destroy
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create standalone instances";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance2',
                    start => '2021-02-02T02:02:02',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-02-02T02:02:02',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
    ]);
    my $instance1Id = $res->[0][1]{created}{instance1}{id};
    $self->assert_not_null($instance1Id);
    my $instance2Id = $res->[0][1]{created}{instance2}{id};
    $self->assert_not_null($instance2Id);
    my $xhref1 = $res->[0][1]{created}{instance1}{'x-href'};
    $self->assert_not_null($xhref1);
    my $xhref2 = $res->[0][1]{created}{instance2}{'x-href'};
    $self->assert_not_null($xhref2);
    $self->assert_str_equals($xhref1, $xhref2);
    my $state = $res->[0][1]{newState};

    xlog "Destroy first standalone instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [ $instance1Id ],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$instance1Id],
            properties => ['title', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => [$instance2Id],
            properties => ['title', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R3'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R4'],
    ]);
    $self->assert_deep_equals([$instance1Id], $res->[0][1]{destroyed});
    $self->assert_deep_equals([$instance1Id], $res->[1][1]{notFound});
    $self->assert_str_equals('instance2', $res->[2][1]{list}[0]{title});

    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[1][1]{state});
    $self->assert_str_not_equals($state, $res->[2][1]{state});
    $self->assert_str_not_equals($state, $res->[3][1]{newState});
    $self->assert_deep_equals([], $res->[3][1]{created});
    $self->assert_deep_equals([], $res->[3][1]{updated});
    $self->assert_deep_equals([$instance1Id], $res->[3][1]{destroyed});
    $state = $res->[3][1]{newState};

    xlog "Assert CalDAV resource still exists";
    $res = $caldav->Request('GET', $xhref1);
    $self->assert(not $res->{content} =~ m/SUMMARY:instance1/);
    $self->assert($res->{content} =~ m/SUMMARY:instance2/);

    xlog "Destroy second standalone instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [ $instance2Id ],
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$instance2Id],
            properties => ['title', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R2'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$instance2Id], $res->[0][1]{destroyed});
    $self->assert_deep_equals([$instance2Id], $res->[1][1]{notFound});

    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[1][1]{state});
    $self->assert_str_not_equals($state, $res->[2][1]{newState});
    $self->assert_deep_equals([], $res->[2][1]{created});
    $self->assert_deep_equals([], $res->[2][1]{updated});
    $self->assert_deep_equals([$instance2Id], $res->[2][1]{destroyed});
    $state = $res->[3][1]{newState};

    xlog "Assert CalDAV resource is gone";
    # Can't use CalDAV talk for GET on non-existent URLs
    my $xml = <<EOF;
<?xml version="1.0"?>
<a:propfind xmlns:a="DAV:">
 <a:prop><a:resourcetype/></a:prop>
</a:propfind>
EOF
    $res = $caldav->Request('PROPFIND', 'Default', $xml,
        'Content-Type' => 'application/xml',
        'Depth' => '1'
    );
    $self->assert_does_not_match(qr{event1uid}, $res);
}

sub test_calendarevent_set_standalone_instances_move
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create standalone instances";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance2',
                    start => '2021-02-02T02:02:02',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-02-02T02:02:02',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
        ['Calendar/set', {
            create => {
                calendarA => {
                    name => 'A',
                },
            },
        }, 'R2'],
    ]);
    my $instance1Id = $res->[0][1]{created}{instance1}{id};
    $self->assert_not_null($instance1Id);
    my $instance2Id = $res->[0][1]{created}{instance2}{id};
    $self->assert_not_null($instance2Id);
    my $state = $res->[0][1]{newState};
    my $calendarAId = $res->[1][1]{created}{calendarA}{id};
    $self->assert_not_null($calendarAId);

    xlog "Move standalone instance to other calendar";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $instance1Id => {
                    calendarIds => {
                        $calendarAId => JSON::true,
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$instance1Id],
            properties => ['calendarIds', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => [$instance2Id],
            properties => ['calendarIds', 'recurrenceId', 'recurrenceIdTimeZone'],
        }, 'R3'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R4'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$instance1Id});
    $self->assert_deep_equals({$calendarAId => JSON::true },
        $res->[1][1]{list}[0]{calendarIds});

    xlog "Moving one standalone instance also moves any other instances";
    $self->assert_deep_equals({$calendarAId => JSON::true },
        $res->[2][1]{list}[0]{calendarIds});

    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_not_equals($state, $res->[1][1]{state});
    $self->assert_str_not_equals($state, $res->[2][1]{state});
    $self->assert_str_not_equals($state, $res->[3][1]{newState});

    $self->assert_deep_equals([], $res->[3][1]{created});
    my @wantUpdated = sort ($instance1Id, $instance2Id);
    my @haveUpdated = sort @{$res->[3][1]{updated}};
    $self->assert_deep_equals(\@wantUpdated, \@haveUpdated);
    $self->assert_deep_equals([], $res->[3][1]{destroyed});
}

sub test_calendarevent_set_standalone_instances_to_main
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create standalone instance";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
    ]);
    my $instance1Id = $res->[0][1]{created}{instance1}{id};
    $self->assert_not_null($instance1Id);
    my $state = $res->[0][1]{newState};

    xlog "Can't convert a standalone instance to a main event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $instance1Id => {
                    recurrenceId => undef,
                },
            },
        }, 'R1'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R2'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{$instance1Id}{type});
    $self->assert_deep_equals([
            # XXX invalidProperties doesn't deduplicate,
            # but we'll only change this when we merged
            # this feature branch
            'recurrenceId', 'recurrenceId', 'recurrenceIdTimeZone'
    ], $res->[0][1]{notUpdated}{$instance1Id}{properties});

    $self->assert_str_equals($state, $res->[1][1]{newState});
    $self->assert_deep_equals([], $res->[1][1]{created});
    $self->assert_deep_equals([], $res->[1][1]{updated});
    $self->assert_deep_equals([], $res->[1][1]{destroyed});

    xlog "Create main event with the same uid";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'mainevent1',
                    start => '2020-12-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceRules => [{
                        '@type' => 'RecurrenceRule',
                        frequency => 'monthly',
                        count => 3,
                    }],
                },
            },
        }, 'R1'],
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R2'],
    ]);
    my $event1Id = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($event1Id);

    $self->assert_str_not_equals($state, $res->[1][1]{newState});
    $self->assert_deep_equals([$event1Id], $res->[1][1]{created});
    $self->assert_deep_equals([], $res->[1][1]{updated});
    $self->assert_deep_equals([$instance1Id], $res->[1][1]{destroyed});
}

sub test_session_capability_isrfc
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

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

    $self->assert_deep_equals(
        $session->{capabilities}{'https://cyrusimap.org/ns/jmap/calendars'},
        { isRFC => JSON::true });
}

sub test_calendaralert_notification
    :min_version_3_7 :needs_component_calalarmd :needs_component_jmap
{
    my ($self) = @_;
    my $caldav = $self->{caldav};
    my $jmap = $self->{jmap};

    my $calendarId = $caldav->NewCalendar({name => 'foo'});
    $self->assert_not_null($calendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$calendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
DURATION:PT1H
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:PT0S
ACTION:DISPLAY
SUMMARY: My alarm
UID:E157A1FC-06BB-4495-933E-4E99C79A8649
DESCRIPTION:My alarm has triggered
END:VALARM
BEGIN:VALARM
TRIGGER:PT1H
ACTION:DISPLAY
SUMMARY: My alarm without a uid
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    xlog "Get calendar event alert ids";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['alerts'],
        }, 'R1'],
    ]);

    my %alerts = %{$res->[0][1]{list}[0]{alerts}};
    my %alertIds = map { $alerts{$_}{trigger}{offset} => $_ } keys %alerts;
    $self->assert_num_equals(2, scalar keys %alertIds);

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    my $data = $self->{instance}->getnotify();
    my @events;
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                push @events, $e;
            }
        }
    }

    $self->assert_num_equals(1, scalar @events);
    $self->assert_str_equals('cassandane',
        $events[0]{userId}); # accountId
    $self->assert_str_equals('574E2CD0-2D2A-4554-8B63-C7504481D3A9',
        $events[0]{uid});
    $self->assert_str_equals(encode_eventid('574E2CD0-2D2A-4554-8B63-C7504481D3A9'),
        $events[0]{calendarEventId});
    $self->assert_str_equals('', $events[0]{recurrenceId});
    $self->assert_str_equals($alertIds{'PT0S'}, $events[0]{alertId});

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 3660 );

    $data = $self->{instance}->getnotify();
    @events = ();
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                push @events, $e;
            }
        }
    }

    $self->assert_num_equals(1, scalar @events);
    $self->assert_str_equals('cassandane',
        $events[0]{userId}); # accountId
    $self->assert_str_equals('574E2CD0-2D2A-4554-8B63-C7504481D3A9',
        $events[0]{uid});
    $self->assert_str_equals(encode_eventid('574E2CD0-2D2A-4554-8B63-C7504481D3A9'),
        $events[0]{calendarEventId});
    $self->assert_str_equals('', $events[0]{recurrenceId});
    $self->assert_str_equals($alertIds{'PT1H'}, $events[0]{alertId});
}

sub test_calendaralert_notification_recurring
    :min_version_3_5 :needs_component_calalarmd
{
    my ($self) = @_;
    my $caldav = $self->{caldav};

    my $calendarId = $caldav->NewCalendar({name => 'foo'});
    $self->assert_not_null($calendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start yesterday in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    $startdt->subtract(DateTime::Duration->new(days => 1));
    my $start = $startdt->strftime('%Y%m%dT%H%M%S');

    my $recurdt = $startdt->clone();
    $recurdt->add(DateTime::Duration->new(days => 1));
    my $recurid = $recurdt->strftime('%Y-%m-%dT%H:%M:%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$calendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$start
RRULE:FREQ=DAILY;COUNT=2
DURATION:PT1H
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
UID:E157A1FC-06BB-4495-933E-4E99C79A8649
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    my $data = $self->{instance}->getnotify();
    my @events;
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                push @events, $e;
            }
        }
    }

    $self->assert_num_equals(1, scalar @events);
    $self->assert_str_equals('cassandane',
        $events[0]{userId}); # accountId
    $self->assert_str_equals('574E2CD0-2D2A-4554-8B63-C7504481D3A9',
        $events[0]{uid});
    $self->assert_str_equals(encode_eventid('574E2CD0-2D2A-4554-8B63-C7504481D3A9'),
        $events[0]{calendarEventId});
    $self->assert_str_equals($recurid, $events[0]{recurrenceId});
    $self->assert_str_equals('E157A1FC-06BB-4495-933E-4E99C79A8649',
        $events[0]{alertId});
}

sub test_calendaralert_notification_standalone
    :min_version_3_5 :needs_component_calalarmd
{
    my ($self) = @_;
    my $caldav = $self->{caldav};

    my $calendarId = $caldav->NewCalendar({name => 'foo'});
    $self->assert_not_null($calendarId);

    my $now = DateTime->now();
    $now->set_time_zone('Australia/Sydney');
    # bump everything forward so a slow run (say: valgrind)
    # doesn't cause things to magically fire...
    $now->add(DateTime::Duration->new(seconds => 300));

    # define the event to start in a few seconds
    my $startdt = $now->clone();
    $startdt->add(DateTime::Duration->new(seconds => 2));
    my $icalStart = $startdt->strftime('%Y%m%dT%H%M%S');
    my $icalRecurid = $startdt->strftime('%Y%m%dT%H%M%S');
    my $recurid = $startdt->strftime('%Y-%m-%dT%H:%M:%S');

    # set the trigger to notify us at the start of the event
    my $trigger="PT0S";

    my $uuid = "574E2CD0-2D2A-4554-8B63-C7504481D3A9";
    my $href = "$calendarId/$uuid.ics";
    my $card = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
CALSCALE:GREGORIAN
BEGIN:VTIMEZONE
TZID:Australia/Sydney
BEGIN:STANDARD
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:+1100
TZOFFSETTO:+1000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700101T000000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=10
TZOFFSETFROM:+1000
TZOFFSETTO:+1100
END:DAYLIGHT
END:VTIMEZONE

BEGIN:VEVENT
CREATED:20150806T234327Z
UID:574E2CD0-2D2A-4554-8B63-C7504481D3A9
TRANSP:OPAQUE
SUMMARY:Simple
DTSTART;TZID=Australia/Sydney:$icalStart
RECURRENCE-ID;TZID=Australia/Sydney:$icalRecurid
DURATION:PT1H
DTSTAMP:20150806T234327Z
SEQUENCE:0
BEGIN:VALARM
TRIGGER:$trigger
ACTION:DISPLAY
SUMMARY: My alarm
UID:E157A1FC-06BB-4495-933E-4E99C79A8649
DESCRIPTION:My alarm has triggered
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT', $href, $card, 'Content-Type' => 'text/calendar');

    # clean notification cache
    $self->{instance}->getnotify();

    $self->{instance}->run_command({ cyrus => 1 }, 'calalarmd', '-t' => $now->epoch() + 60 );

    my $data = $self->{instance}->getnotify();
    my @events;
    foreach (@$data) {
        if ($_->{CLASS} eq 'EVENT') {
            my $e = decode_json($_->{MESSAGE});
            if ($e->{event} eq "CalendarAlarm") {
                push @events, $e;
            }
        }
    }

    $self->assert_num_equals(1, scalar @events);
    $self->assert_str_equals('cassandane',
        $events[0]{userId}); # accountId
    $self->assert_str_equals('574E2CD0-2D2A-4554-8B63-C7504481D3A9',
        $events[0]{uid});
    $self->assert_str_equals(encode_eventid('574E2CD0-2D2A-4554-8B63-C7504481D3A9', $icalRecurid),
        $events[0]{calendarEventId});
    $self->assert_str_equals($recurid, $events[0]{recurrenceId});
    $self->assert_str_equals('E157A1FC-06BB-4495-933E-4E99C79A8649',
        $events[0]{alertId});
}

sub test_calendareventnotification_imip
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    # CREATE

    my $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', { properties => ['id'] }, 'R1'],
        ['CalendarEventNotification/get', { }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});

    $self->assert_str_equals('sender@example.net',
        $res->[1][1]{list}[0]{changedBy}{email});
    $self->assert_str_equals('Sally Sender',
        $res->[1][1]{list}[0]{changedBy}{name});
    $self->assert_str_equals('created', $res->[1][1]{list}[0]{type});

    my $state = $res->[1][1]{state};
    $self->assert_not_null($state);

    # UPDATE

    $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An updated event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP update";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', { properties => ['id'] }, 'R1'],
        ['CalendarEventNotification/changes', {
            sinceState => $state },
        'R2'],
        ['CalendarEventNotification/get', {
            '#ids' => {
                resultOf => 'R2',
                name => 'CalendarEventNotification/changes',
                path => '/created'
            },
        }, 'R3'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    $self->assert_num_equals(1, scalar @{$res->[2][1]{list}});

    $self->assert_str_equals('sender@example.net',
        $res->[2][1]{list}[0]{changedBy}{email});
    $self->assert_str_equals('Sally Sender',
        $res->[2][1]{list}[0]{changedBy}{name});
    $self->assert_str_equals('updated', $res->[2][1]{list}[0]{type});

    $state = $res->[2][1]{state};
    $self->assert_not_null($state);

    # DELETE

    $imip = <<'EOF';
Date: Thu, 23 Sep 2021 10:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8202@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:CANCEL
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:3
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP cancellation";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id']
        }, 'R1'],
        ['CalendarEventNotification/changes', {
            sinceState => $state },
        'R2'],
        ['CalendarEventNotification/get', {
            '#ids' => {
                resultOf => 'R2',
                name => 'CalendarEventNotification/changes',
                path => '/created'
            },
        }, 'R3'],
    ]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{list}});

    $self->assert_str_equals('sender@example.net',
        $res->[2][1]{list}[0]{changedBy}{email});
    $self->assert_str_equals('Sally Sender',
        $res->[2][1]{list}[0]{changedBy}{name});
    $self->assert_str_equals('destroyed', $res->[2][1]{list}[0]{type});
}

sub test_calendarevent_defaultalerts_imip
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $alertWithTime = {
        '@type' => 'Alert',
        trigger => {
            '@type' => 'OffsetTrigger',
            relativeTo => 'start',
            offset => '-PT5M',
        },
        action => 'display',
    };
    my $alertWithoutTime = {
        '@type' => 'Alert',
        trigger => {
            '@type' => 'OffsetTrigger',
            relativeTo => 'start',
            offset => 'PT0S',
        },
        action => 'display',
    };

    xlog 'Set default alerts on calendar';
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    defaultAlertsWithTime => {
                        alert1 => $alertWithTime,
                    },
                    defaultAlertsWithoutTime => {
                        alert2 => $alertWithoutTime,
                    },
                }
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    my $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
X-APPLE-DEFAULT-ALARM;VALUE=BOOLEAN:FALSE
BEGIN:VALARM
UID:0CF835D0-CFEB-44AE-904A-C26AB62B73BB-1
TRIGGER:PT25M
ACTION:DISPLAY
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    xlog $self, "Assert that useDefaultAlerts is set";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'alerts', 'useDefaultAlerts']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{useDefaultAlerts});
    $self->assert_deep_equals({ alert1 => $alertWithTime },
        $res->[0][1]{list}[0]{alerts});

    my $eventId = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($eventId);

    my $customAlert = {
        '@type' => 'Alert',
        trigger => {
            '@type' => 'OffsetTrigger',
            relativeTo => 'start',
            offset => '-PT10M',
        },
        action => 'display',
    };

    xlog "Set custom alert on event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    alerts => {
                        alert1 => $customAlert,
                    },
                    useDefaultAlerts => JSON::false,
                },
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Update event via iTIP";
    $imip = <<'EOF';
Date: Thu, 23 Sep 2021 10:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Updated Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
BEGIN:VALARM
UID:0CF835D0-CFEB-44AE-904A-C26AB62B73BB-1
TRIGGER:PT25M
ACTION:DISPLAY
END:VALARM
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP update";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'alerts', 'useDefaultAlerts']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_equals(JSON::false,
        $res->[0][1]{list}[0]{useDefaultAlerts});
    $self->assert_deep_equals({ alert1 => $customAlert },
        $res->[0][1]{list}[0]{alerts});
}

sub create_user
{
    my ($self, $username) = @_;

    xlog $self, "create user $username";
    my $admin = $self->{adminstore}->get_client();
    $admin->create("user.$username");
    $admin->setacl("user.$username", admin => 'lrswipkxtecdan') or die;
    $admin->setacl("user.$username", $username => 'lrswipkxtecdn') or die;

    my $http = $self->{instance}->get_service("http");
    my $userJmap = Mail::JMAPTalk->new(
        user => $username,
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/jmap/',
    );
    $userJmap->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);

    my $userCalDAV = Net::CalDAVTalk->new(
        user => $username,
        password => 'pass',
        host => $http->host(),
        port => $http->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    return ($userJmap, $userCalDAV);
}

sub test_calendarevent_set_mayrsvp
    :needs_component_jmap :JMAPExtensions :NoAltNameSpace :min_version_0_0 :max_version_0_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my ($shareeJmap, $shareCalDAV) = $self->create_user('sharee');

    xlog "create and share event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'test',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        sharee => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:sharee@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                    },
                },
            },
        }, 'R1'],
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        'sharee' => {
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                        },
                    },
                },
            },
        }, 'R2'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);
    $self->assert(exists $res->[1][1]{updated}{Default});

    xlog "update as sharee without mayRSVP";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/sharee/participationStatus' => 'accepted',
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "assign mayRSVP to sharee",
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        'sharee' => {
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayRSVP => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "update as sharee with mayRSVP";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/sharee/participationStatus' => 'accepted',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
}

sub test_calendarevent_set_mayinviteself
    :needs_component_jmap :JMAPExtensions :NoAltNameSpace :min_version_0_0 :max_version_0_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my ($shareeJmap, $shareeCalDAV) = $self->create_user('sharee');

    xlog "create event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'eventuid',
                    title => 'test',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        someone => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);

    xlog "can not set mayInviteSelf on override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    recurrenceOverrides => {
                        '2022-02-03T22:22:22' => {
                            mayInviteSelf => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals({
        type => 'invalidProperties',
        properties => ['recurrenceOverrides/2022-02-03T22:22:22/mayInviteSelf'],
    }, $res->[0][1]{notUpdated}{$eventId});

    xlog "assign mayUpdatePrivate to sharee",
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        'sharee' => {
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "sharee can not invite self";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/sharee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:sharee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "set mayInviteSelf on event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    mayInviteSelf => JSON::true,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['mayInviteSelf'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mayInviteSelf});

    xlog "sharee can not invite self due to missing mayRSVP permission";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/sharee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:sharee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "assign mayRSVP to sharee",
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        'sharee' => {
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayRSVP => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "sharee invites self as attendee and chair";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/sharee' => {
                        roles => {
                            'attendee' => JSON::true,
                            'chair' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:sharee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "sharee invites self as attendee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/sharee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:sharee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => ['participants'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_not_null($res->[1][1]{list}[0]{participants}{sharee});
}

sub test_calendarevent_set_mayinviteothers
    :needs_component_jmap :JMAPExtensions :NoAltNameSpace :min_version_0_0 :max_version_0_0
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my ($shareeJmap, $shareeCalDAV) = $self->create_user('sharee');

    xlog "create event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'eventuid',
                    title => 'test',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        someone => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'accepted',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);

    xlog "can not set mayInviteOthers on override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    recurrenceOverrides => {
                        '2022-02-03T22:22:22' => {
                            mayInviteOthers => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals({
        type => 'invalidProperties',
        properties => ['recurrenceOverrides/2022-02-03T22:22:22/mayInviteOthers'],
    }, $res->[0][1]{notUpdated}{$eventId});

    xlog "assign mayUpdatePrivate and mayRSVP to sharee",
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        'sharee' => {
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayRSVP => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "sharee can not invite others";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/invitee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:invitee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "set mayInviteOthers on event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    mayInviteOthers => JSON::true,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['mayInviteOthers'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mayInviteOthers});

    xlog "sharee still can not invite others";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/invitee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:invitee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "add sharee to participants";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'participants/sharee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:sharee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "sharee can not invite others as attendee and chair";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/invitee' => {
                        roles => {
                            'attendee' => JSON::true,
                            'chair' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:invitee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('forbidden', $res->[0][1]{notUpdated}{$eventId}{type});

    xlog "sharee invites other";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $eventId => {
                    'participants/invitee' => {
                        roles => {
                            'attendee' => JSON::true,
                        },
                        sendTo => {
                            imip => 'mailto:invitee@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'accepted',
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => ['participants'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_not_null($res->[1][1]{list}[0]{participants}{invitee});
}

sub test_calendarevent_set_mayinvite_preserve_caldav
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "create event with mayInviteSelf and mayInviteOthers set";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'eventuid',
                    title => 'test',
                    start => '2021-01-01T11:11:11',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        someone => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                    },
                    mayInviteSelf => JSON::true,
                    mayInviteOthers => JSON::true,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event'],
            properties => ['mayInviteSelf', 'mayInviteOthers'],
        }, 'R2'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);
    my $href = $res->[0][1]{created}{event}{'x-href'};
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mayInviteSelf});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mayInviteOthers});

    xlog "remove mayInviteSelf via CalDAV";
    my $ical = $caldav->Request('GET', $href)->{content};
    $self->assert($ical =~ m/X-JMAP-MAY-INVITE-SELF;VALUE=BOOLEAN:TRUE/);

    $ical = join("\r\n",
        grep { !($_ =~ m/X-JMAP-MAY-INVITE-SELF;VALUE=BOOLEAN:TRUE/) }
        split(/\r\n/, $ical)
    );
    $ical = join("\r\n",
        grep { !($_ =~ m/X-JMAP-MAY-INVITE-OTHERS;VALUE=BOOLEAN:TRUE/) }
        split(/\r\n/, $ical)
    );
    $res = $caldav->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    xlog "assert mayInviteSelf and mayInviteOthers are preserved";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [$eventId],
            properties => ['mayInviteSelf', 'mayInviteOthers'],
        }, 'R2'],
    ]);
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{mayInviteSelf});
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{mayInviteOthers});
}

sub test_calendarevent_set_hideattendees_itip
    :needs_component_jmap :min_version_0_0 :max_version_0_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    # clean notification cache
    $self->{instance}->getnotify();

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        attendee1 => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:attendee1@example.com',
                            },
                        },
                        attendee2 => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:attendee2@example.com',
                            },
                        },
                    },
                    hideAttendees => JSON::true,
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    my $data = $self->{instance}->getnotify();

    my $imip = {};
    foreach my $notif (@$data) {
        if (not $notif->{METHOD} eq 'imip') {
            next;
        }
        my $msg = decode_json($notif->{MESSAGE});
        $imip->{$msg->{recipient}} = $msg;
    }

    $self->assert_num_equals(2, scalar keys %{$imip});

    $self->assert(not $imip->{'attendee1@example.com'}->{ical} =~
        m/attendee2\@example.com/);
    $self->assert($imip->{'attendee1@example.com'}->{ical} =~
        m/attendee1\@example.com/);

    $self->assert(not $imip->{'attendee2@example.com'}->{ical} =~
        m/attendee1\@example.com/);
    $self->assert($imip->{'attendee2@example.com'}->{ical} =~
        m/attendee2\@example.com/);
}

sub test_calendarevent_set_hideattendees
    :needs_component_jmap :min_version_0_0 :max_version_0_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my ($shareeJmap, $shareeCalDAV) = $self->create_user('sharee');

    xlog "create event and share with sharee";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 3,
                    }],
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        sharee => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:sharee@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                        attendee1 => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:attendee1@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'accepted',
                        },
                    },
                    recurrenceOverrides => {
                        '2020-01-02T09:00:00' => {
                            'participants/attendee2' => {
                                roles => {
                                    'attendee' => JSON::true,
                                },
                                sendTo => {
                                    imip => 'mailto:attendee2@example.com',
                                },
                                expectReply => JSON::true,
                                participationStatus => 'accepted',
                            },
                            'participants/attendee1/participationStatus' => 'tentative',
                        },

                    },
                    hideAttendees => JSON::true,
                },
            },
        }, 'R1'],
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        'sharee' => {
                            mayReadItems => JSON::true,
                            mayUpdatePrivate => JSON::true,
                            mayRSVP => JSON::true,
                        },
                    },
                },
            },
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => ['#event1'],
            properties => ['hideAttendees'],
        }, 'R3'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);
    $self->assert(exists $res->[1][1]{updated}{Default});
    $self->assert_equals(JSON::true, $res->[2][1]{list}[0]{hideAttendees});

    xlog "get event as sharee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$eventId],
            properties => ['participants', 'hideAttendees', 'recurrenceOverrides'],
        }, 'R1'],
    ]);
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{hideAttendees});

    $self->assert_not_null($res->[0][1]{list}[0]{participants}{cassandane});
    $self->assert_not_null($res->[0][1]{list}[0]{participants}{sharee});
    $self->assert_num_equals(2, scalar keys %{$res->[0][1]{list}[0]{participants}});
    $self->assert_deep_equals({ '2020-01-02T09:00:00' => {} },
        $res->[0][1]{list}[0]{recurrenceOverrides});
}

sub test_calendarevent_get_sentby_imip
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sentBy']
        }, 'R1'],
    ]);
    $self->assert_str_equals('sender@example.net', $res->[0][1]{list}[0]{sentBy});
}

sub test_calendarevent_get_sentby_caldav
    :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        $ical, 'Content-Type' => 'text/calendar',
               'Schedule-Sender-Address' => 'sender@example.net',
               'Schedule-Sender-Name' => 'Sally Sender',
    );

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sentBy']
        }, 'R1'],
    ]);
    $self->assert_str_equals('sender@example.net', $res->[0][1]{list}[0]{sentBy});
}

sub test_calendarevent_set_sentby
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    sentBy => 'sender@example.net',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event1', '#event2'],
            properties => ['sentBy'],
        }, 'R3'],
    ]);
    $self->assert_str_equals('sender@example.net', $res->[1][1]{list}[0]{sentBy});
}

sub test_calendar_set_unknown_calendarright
    :min_version_3_5 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    $self->create_user('sharee');

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        sharee => {
                            unknownCalendarRight => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);

    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{Default}{type});

    $self->assert_deep_equals(['shareWith/sharee/unknownCalendarRight'],
        $res->[0][1]{notUpdated}{Default}{properties});
}

sub test_calendarevent_itip_reply_sequence
    :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "PUT event for invitee";
    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:organizer@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;X-JMAP-ID=cassandane:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        $ical, 'Content-Type' => 'text/calendar');

    xlog "Assert sequence number";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sequence']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, $res->[0][1]{list}[0]{sequence});
    my $eventId = $res->[0][1]{list}[0]{id};

    xlog "Update invitee's participant";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            sendSchedulingMessages => JSON::true,
            update => {
                $eventId => {
                    'participants/cassandane/expectReply' => JSON::false,
                    'participants/cassandane/participationStatus' => 'accepted',
                    'participants/cassandane/scheduleSequence' => 1,
                    'participants/cassandane/scheduleUpdated' => '2022-01-20T14:56:36Z',
                },

            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_null($res->[0][1]{updated}{$eventId}{sequence});

    xlog "Assert sequence number did not increase";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sequence']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, $res->[0][1]{list}[0]{sequence});
}

sub test_calendarevent_itip_request_sequence
    :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "PUT event for organizer";
    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:cassandane@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;X-JMAP-ID=invitee:MAILTO:invitee@example.com
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/testitip.ics',
        $ical, 'Content-Type' => 'text/calendar');

    xlog "Assert sequence number";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sequence']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, $res->[0][1]{list}[0]{sequence});
    my $eventId = $res->[0][1]{list}[0]{id};

    xlog "Update per-user prop";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            sendSchedulingMessages => JSON::true,
            update => {
                $eventId => {
                    color => 'blue',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_null($res->[0][1]{updated}{$eventId}{sequence});

    xlog "Assert sequence number did not increase";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sequence']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, $res->[0][1]{list}[0]{sequence});

    xlog "Update shared prop";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            sendSchedulingMessages => JSON::true,
            update => {
                $eventId => {
                    title => 'updatedTitle',
                },

            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_num_equals(2, $res->[0][1]{updated}{$eventId}{sequence});

    xlog "Assert sequence number did increase";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'sequence']
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, $res->[0][1]{list}[0]{sequence});
}

sub test_calendarevent_set_locations_keep_location
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "PUT iCalendar event with apple location";
    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
SUMMARY:test
DTSTART;TZID=American/New_York:20210923T153000
DURATION:PT1H
DTSTAMP:20210923T034327Z
SEQUENCE:0
LOCATION:mainloc
X-APPLE-STRUCTURED-LOCATION
 ;VALUE=URI
 ;X-APPLE-RADIUS=14140.1607181516
 ;X-TITLE="mainloc"
 :geo:48.208304,16.371602
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    xlog "Assert locations in CalendarEvent";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['locations', 'x-href']
        }, 'R1'],
    ]);

    my $eventId = $res->[0][1]{list}[0]{id};
    my $locations = $res->[0][1]{list}[0]{locations};
    $self->assert_num_equals(1, scalar values %{$locations});
    $self->assert_deep_equals({
        '@type' => 'Location',
        name => 'mainloc',
        coordinates => 'geo:48.208304,16.371602',
    }, (values %{$locations})[0]);
    my $xhref = $res->[0][1]{list}[0]{'x-href'};
    $self->assert_not_null($xhref);

    xlog "Add location but preserve existing one";
    $locations->{'newlocation'} = {
        '@type' => 'Location',
        name => 'newloc',
        coordinates => 'geo:27.175015,78.042155',
    };
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    locations => $locations,
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    $res = $caldav->Request('GET', $xhref);

    my $vcal = Data::ICal->new(data => $res->{content});
    my %vcomps = map { $_->ical_entry_type() => $_ } @{$vcal->entries()};
    my $vevent = $vcomps{'VEVENT'};

    my $props = $vevent->property('X-APPLE-STRUCTURED-LOCATION');
    $self->assert_num_equals(1, scalar @{$props});
    $self->assert_not_null($props->[0]->parameters()->{'X-APPLE-RADIUS'});
    $self->assert_str_equals('geo:48.208304,16.371602', $props->[0]->value());

    $props = $vevent->property('LOCATION');
    $self->assert_num_equals(1, scalar @{$props});
    $self->assert_str_equals('mainloc', $props->[0]->value());

    $props = $vevent->property('X-JMAP-LOCATION');
    $self->assert_num_equals(1, scalar @{$props});
    $self->assert_str_equals('newloc', $props->[0]->value());

    xlog "Assert locations in CalendarEvent";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['locations', 'x-href']
        }, 'R1'],
    ]);
    $self->assert_deep_equals($locations, $res->[0][1]{list}[0]{locations});
}

sub test_calendarevent_get_duplicate_recurrence_ids
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
RECURRENCE-ID;TZID=America/New_York:20210101T060000
DTSTART;TZID=Europe/Berlin:20210101T120000
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:instance1
SEQUENCE:0
LAST-MODIFIED:20150928T132434Z
END:VEVENT
BEGIN:VEVENT
RECURRENCE-ID;TZID=America/New_York:20210101T060000
DTSTART;TZID=Europe/Berlin:20210101T120000
DURATION:PT1H
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:instance2
SEQUENCE:0
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT', 'Default/test.ics', $ical,
        'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['title', 'recurrenceId']
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('instance1', $res->[0][1]{list}[0]{title});
    $self->assert_str_equals('2021-01-01T06:00:00',
        $res->[0][1]{list}[0]{recurrenceId});
}

sub test_calendarevent_get_ignore_dead_standalone_instance
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
PRODID:-//Fastmail/2020.5/EN
BEGIN:VEVENT
CATEGORIES:CONFERENCE
DESCRIPTION:Be there or be square
DTEND:19960920T220000Z
DTSTAMP:19960704T120000Z
DTSTART:19960919T143000Z
ORGANIZER:MAILTO:jsmith@example.com
RECURRENCE-ID:19960919T143000
SEQUENCE:0
SUMMARY:Partyx
TRANSP:OPAQUE
UID:889i-uid1@example.com
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['title', 'recurrenceOverrides'],
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});

    $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
PRODID:-//Fastmail/2020.5/EN
BEGIN:VEVENT
CATEGORIES:CONFERENCE
DESCRIPTION:Be there or be square
DTEND:19960920T220000Z
DTSTAMP:19960704T120000Z
DTSTART:19960918T143000Z
ORGANIZER:MAILTO:jsmith@example.com
RRULE:FREQ=DAILY
SEQUENCE:0
SUMMARY:Party
TRANSP:OPAQUE
UID:889i-uid1@example.com
END:VEVENT
BEGIN:VEVENT
CATEGORIES:CONFERENCE
DESCRIPTION:Be there or be square
DTEND:19960920T220000Z
DTSTAMP:19960704T120000Z
DTSTART:19960918T143000Z
ORGANIZER:MAILTO:jsmith@example.com
RECURRENCE-ID:19960919T143000Z
SEQUENCE:1
SUMMARY:Partyx
TRANSP:OPAQUE
UID:889i-uid1@example.com
END:VEVENT
BEGIN:VEVENT
CATEGORIES:CONFERENCE
DESCRIPTION:Be there or be square
DTEND:19960920T220000Z
DTSTAMP:19960704T120000Z
DTSTART:19960918T143000Z
ORGANIZER:MAILTO:jsmith@example.com
RECURRENCE-ID:19960923T143000Z
SEQUENCE:1
SUMMARY:Partyx
TRANSP:OPAQUE
UID:889i-uid1@example.com
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['title', 'recurrenceOverrides'],
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('Party', $res->[0][1]{list}[0]{title});
    $self->assert_num_equals(2, scalar keys %{$res->[0][1]{list}[0]{recurrenceOverrides}});
    $self->assert_not_null($res->[0][1]{list}[0]{recurrenceOverrides}{'1996-09-19T14:30:00'});
    $self->assert_not_null($res->[0][1]{list}[0]{recurrenceOverrides}{'1996-09-23T14:30:00'});
}

sub test_calendarevent_set_standalone_instance_floatingtz
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
PRODID:-//Fastmail/2020.5/EN
BEGIN:VEVENT
CATEGORIES:CONFERENCE
DESCRIPTION:Be there or be square
DTSTAMP:19960704T120000Z
DTSTART:19960919T143000
DURATION:PT1H
RECURRENCE-ID:19960919T143000
SEQUENCE:0
SUMMARY:Partyx
TRANSP:OPAQUE
UID:889i-uid1@example.com
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => [
                'recurrenceId',
                'recurrenceIdTimeZone',
            ],
        }, 'R1'],
    ]);
    $self->assert_not_null($res->[0][1]{list}[0]{recurrenceId});
    $self->assert_null($res->[0][1]{list}[0]{recurrenceIdTimeZone});
    my $eventId = $res->[0][1]{list}[0]{id};

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'xxx',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => [
                'recurrenceId',
                'recurrenceIdTimeZone'],
        }, 'R1'],
    ]);
    $self->assert_not_null($res->[0][1]{list}[0]{recurrenceId});
    $self->assert_null($res->[0][1]{list}[0]{recurrenceIdTimeZone});
}


sub test_calendarevent_set_itip_preserve_partstat
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my ($otherJmap, $otherCalDAV) = $self->create_user('other');

    xlog 'create event and invite other user';
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => 'event1',
                    start => '2020-01-01T09:00:00',
                    timeZone => 'Europe/Vienna',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                'owner' => JSON::true,
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                        other => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:other@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);

    xlog 'Other user accepts invitation';
    $res = $otherJmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['participants'],
        }, 'R1'],
    ]);
    my $otherId = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($otherId);
    $self->assert_str_equals('needs-action',
        $res->[0][1]{list}[0]{participants}{other}{participationStatus});

    $res = $otherJmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $otherId => {
                    'participants/other/participationStatus' => 'accepted',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$otherId});

    xlog 'Reschedule event and send to other user';
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['participants'],
        }, 'R1'],
    ]);
    $self->assert_str_equals('accepted',
        $res->[0][1]{list}[0]{participants}{other}{participationStatus});

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    start => '2020-01-08T09:00:00',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', { }, 'R2'],

    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog 'Other user receives updated event, is still accepted';
    $res = $otherJmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['start', 'participants'],
        }, 'R1'],
    ]);
    $self->assert_str_equals('2020-01-08T09:00:00',
        $res->[0][1]{list}[0]{start});
    $self->assert_str_equals('accepted',
        $res->[0][1]{list}[0]{participants}{other}{participationStatus});
}

sub test_calendarevent_blob_lookup
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => 'event1',
                    start => '2020-01-01T09:00:00',
                    timeZone => 'Europe/Vienna',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event1}{id};
    $self->assert_not_null($eventId);
    my $blobId = $res->[0][1]{created}{event1}{blobId};
    $self->assert_not_null($blobId);

    $res = $jmap->CallMethods([
        ['Blob/lookup', {
            typeNames => [
                'CalendarEvent',
            ],
            ids => [$blobId],
        }, 'R1'],
    ], [
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/blob',
    ]);
    $self->assert_deep_equals([{
        id => $blobId,
        matchedIds => {
            CalendarEvent => [
                $eventId,
            ],
        },
    }], $res->[0][1]{list});
}

sub test_calendarevent_changes_ignore_specials
    :needs_component_sieve :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [],
        }, 'R1'],
    ]);
    my $state = $res->[0][1]{state};
    $self->assert_not_null($state);

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    $res = $jmap->CallMethods([
        ['CalendarEvent/changes', {
            sinceState => $state
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
}

sub test_calendarevent_get_standalone_instances_slow
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my $now = DateTime->now();
    $now->set_time_zone('Etc/UTC');
    my $dtstamp = $now->strftime('%Y%m%dT%H%M%SZ');
    $now->set_time_zone('Australia/Sydney');

    my $n = 700;

    my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
EOF

    for (my $i = 0; $i < $n; $i++) {
        my $t = $now->clone();
        $t->add(DateTime::Duration->new(days => $i));
        my $recurid = $t->strftime('%Y%m%dT%H%M%S');

        $ical .= <<EOF;
BEGIN:VEVENT
RECURRENCE-ID;TZID=Australia/Sydney:$recurid
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DURATION:PT1H
SUMMARY:event$i
DTSTART;TZID=Australia/Sydney:$recurid
CREATED:$dtstamp
DTSTAMP:$dtstamp
END:VEVENT
EOF
    }

    $ical .= <<EOF;
END:VEVENT
END:VCALENDAR
EOF

    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['recurrenceId'],
        }, 'R1'],
    ]);
    $self->assert_num_equals($n, scalar @{$res->[0][1]{list}});
}

sub test_calendarevent_get_privacy_ignore_override
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "PUT event where CLASS differs in override";
    my $ical = <<'EOF';
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
DTSTAMP:20210923T034327Z
DTSTART;TZID=American/New_York:20210101T153000
DURATION:PT1H
RRULE:FREQ=DAILY;COUNT=3
SUMMARY:An Event
SEQUENCE:1
CLASS:PRIVATE
END:VEVENT
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:6de280c9-edff-4019-8ebd-cfebc73f8201
RECURRENCE-ID:20210102T153000
DTSTAMP:20210923T034327Z
DTSTART;TZID=American/New_York:20210102T153000
DURATION:PT1H
SUMMARY:An event exception
SEQUENCE:1
CLASS:PUBLIC
END:VEVENT
END:VCALENDAR
EOF
    $caldav->Request('PUT',
        '/dav/calendars/user/cassandane/Default/test.ics',
        $ical, 'Content-Type' => 'text/calendar');

    xlog "Assert privacy of recurrence exception gets ignored";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['privacy', 'recurrenceOverrides']
        }, 'R1'],
    ]);
    $self->assert_str_equals('private', $res->[0][1]{list}[0]{privacy});
    $self->assert_deep_equals({ title => 'An event exception'},
        $res->[0][1]{list}[0]{recurrenceOverrides}{'2021-01-02T15:30:00'});
}

sub test_calendarevent_set_privacy_ignore_override
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Ignore overriden privacy in CalendarEvent/set";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    uid => 'event1uidlocal',
                    title => 'event1',
                    start => '2020-01-01T09:00:00',
                    timeZone => 'Europe/Vienna',
                    duration => 'PT1H',
                    privacy => 'private',
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 3,
                    }],
                    recurrenceOverrides => {
                        '2020-01-02T09:00:00' => {
                            title => 'event1Override',
                            privacy => 'secret',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $xhref = $res->[0][1]{created}{event1}{'x-href'};
    $self->assert_not_null($xhref);

    $res = $caldav->Request('GET', $xhref);
    $self->assert($res->{content} =~ m/CLASS:PRIVATE/);
    $self->assert(not $res->{content} =~ m/CLASS:CONFIDENTIAL/);
}


sub test_calendarevent_set_privacy
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "share calendar with cassandane user";
    my ($sharerJmap) = $self->create_user('sharer');
    my $res = $sharerJmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        cassandane => {
                            mayReadItems => JSON::true,
                            mayWriteAll => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ], [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:principals',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "may only create private event on owned calendar";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'sharer',
            create => {
                eventShared1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    title => 'eventShared1',
                    start => '2022-01-24T09:00:00',
                    timeZone => 'America/New_York',
                    privacy => 'public',
                },
                eventShared2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    title => 'eventShared2',
                    start => '2022-01-24T10:00:00',
                    timeZone => 'America/New_York',
                    privacy => 'secret',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                eventOwned1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    title => 'eventOwned1',
                    start => '2022-01-24T11:00:00',
                    timeZone => 'America/New_York',
                    privacy => 'secret',
                },
            },
        }, 'R2'],
    ]);

    my $eventShared1Id = $res->[0][1]{created}{eventShared1}{id};
    $self->assert_not_null($eventShared1Id);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{eventShared2}{type});
    $self->assert_deep_equals(['privacy'],
        $res->[0][1]{notCreated}{eventShared2}{properties});
    my $eventOwned1Id = $res->[1][1]{created}{eventOwned1}{id};
    $self->assert_not_null($eventOwned1Id);

    xlog "may not change public privacy on shared calendar";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'sharer',
            update => {
                $eventShared1Id => {
                    privacy => 'secret',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            update => {
                $eventOwned1Id => {
                    privacy => 'private',
                },
            },
        }, 'R2'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{$eventShared1Id}{type});
    $self->assert_deep_equals(['privacy'],
        $res->[0][1]{notUpdated}{$eventShared1Id}{properties});
    $self->assert(exists $res->[1][1]{updated}{$eventOwned1Id});
}

sub test_calendarevent_get_privacy_shared
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "share calendar";
    my ($shareeJmap) = $self->create_user('sharee');
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        sharee => {
                            mayReadItems => JSON::true,
                            mayWriteAll => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "create fullblown event for each privacy setting";
    my $eventTemplate = {
        calendarIds => {
            'Default' => JSON::true,
        },
        color => 'blue',
        created => '2020-12-21T07:47:00Z',
        description => 'description',
        duration => 'PT1H',
        excludedRecurrenceRules => [{
            frequency => 'daily',
            interval => 2,
            count => 1,
        }],
        keywords => {
            keyword1 => JSON::true,
        },
        links => {
            link1 => {
                href => 'https://local/link1.jpg',
            },
        },
        locale => 'en',
        locations => {
            loc1 => {
                name => 'name',
            },
        },
        participants => {
            participant1 => {
                sendTo => {
                    imip => 'mailto:participant1@local',
                },
                roles => {
                    attendee => JSON::true,
                },
            },
        },
        priority => 7,
        prodId => '-//Foo//Bar//EN',
        recurrenceOverrides => {
            '2021-01-02T01:00:00' => {
                title => 'overrideTitle',
                duration => 'PT2H',
            },
        },
        recurrenceRules => [{
            frequency => 'daily',
            count => 3,
        }],
        relatedTo => {
            '3a996522-dfc3-484c-bea9-070c408143ea' => { },
        },
        replyTo => {
            imip => 'mailto:orga@local',
        },
        sequence => 3,
        showWithoutTime => JSON::true,
        start => '2021-01-01T01:00:00',
        status => 'tentative',
        timeZone => 'Europe/Berlin',
        title => 'title',
        updated => '2020-12-21T07:47:00Z',
        virtualLocations => {
            virtloc1 => {
                name => 'name',
                uri => 'tel:+1-555-555-5555',
            },
        },
    };

    my @wantProperties = keys %{$eventTemplate};
    push @wantProperties, 'calendarIds', 'isDraft', 'utcStart', 'utcEnd';

    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                publicEvent => { ( privacy => 'public' ), %$eventTemplate },
                privateEvent => { ( privacy => 'private' ), %$eventTemplate },
                secretEvent => { ( privacy => 'secret' ), %$eventTemplate }
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#publicEvent'],
            properties => \@wantProperties,
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => ['#privateEvent'],
            properties => \@wantProperties,
        }, 'R3'],
        ['CalendarEvent/get', {
            ids => ['#secretEvent'],
            properties => \@wantProperties,
        }, 'R4'],
    ]);

    my $publicEvent = $res->[1][1]{list}[0];
    $self->assert_not_null($publicEvent);

    my $privateEvent = $res->[2][1]{list}[0];
    $self->assert_not_null($privateEvent);

    my $secretEvent = $res->[3][1]{list}[0];
    $self->assert_not_null($secretEvent);

    xlog "calendar owner may see all events and properties";
    foreach my $event ($publicEvent, $privateEvent, $secretEvent) {
        foreach my $prop (keys %{$eventTemplate}) {
            $self->assert_not_null($event->{$prop});
        }
    }

    xlog "sharee may see all properties of public event";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$publicEvent->{id}],
            properties => \@wantProperties,
        }, 'R1'],
    ]);
    my $sharedPublicEvent = $res->[0][1]{list}[0];
    delete($publicEvent->{'x-href'});
    delete($sharedPublicEvent->{'x-href'});
    delete($publicEvent->{'blobId'});
    delete($sharedPublicEvent->{'blobId'});
    delete($publicEvent->{'debugBlobId'});
    delete($sharedPublicEvent->{'debugBlobId'});
    $self->assert_deep_equals($publicEvent, $sharedPublicEvent);

    xlog "sharee may only see public properties of private event";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$privateEvent->{id}],
            properties => \@wantProperties,
        }, 'R1'],
    ]);
    my $sharedPrivateEvent = $res->[0][1]{list}[0];
    my %publicProps = (
        '@type' => 1,
        calendarIds => 1,
        created => 1,
        due => 1,
        duration => 1,
        estimatedDuration => 1,
        excludedRecurrenceRules => 1,
        freeBusyStatus => 1,
        id => 1,
        isDraft => 1,
        privacy => 1,
        recurrenceRules => 1,
        recurrenceOverrides => 1,
        sequence => 1,
        showWithoutTime => 1,
        start => 1,
        timeZone => 1,
        timeZones => 1,
        uid => 1,
        updated => 1,
        utcStart => 1,
        utcEnd => 1,
    );
    my @nonPublic;
    foreach my $prop (keys %{$privateEvent}) {
        if (not $publicProps{$prop}) {
            push @nonPublic, $prop;
        }
    }
    delete @{$privateEvent}{@nonPublic};
    delete $privateEvent->{recurrenceOverrides}{'2021-01-02T01:00:00'}{title};
    $self->assert_deep_equals($privateEvent, $sharedPrivateEvent);

    xlog "sharee must not see secret event";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            ids => [$secretEvent->{id}],
            properties => \@wantProperties,
        }, 'R1'],
    ]);
    $self->assert_deep_equals([$secretEvent->{id}], $res->[0][1]{notFound});
}

sub test_calendarevent_set_privacy_private_shared
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "share calendar";
    my ($shareeJmap) = $self->create_user('sharee');
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        sharee => {
                            mayReadItems => JSON::true,
                            mayWriteAll => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "get calendar event state as sharee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane', ids => []
        }, 'R1' ],
    ]);
    my $state = $res->[0][1]{state};

    xlog "create private event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                privateEvent => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2021-01-01T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    title => 'privateEvent',
                    privacy => 'private',
                },
            },
        }, 'R1'],
    ]);
    my $privateEventId = $res->[0][1]{created}{privateEvent}{id};
    $self->assert_not_null($privateEventId);

    xlog "sharee sees event";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            properties => ['id'],
        }, 'R1' ],
        ['CalendarEvent/changes', {
            accountId => 'cassandane',
            sinceState => $state,
        }, 'R1' ],
        ['CalendarEvent/query', {
            accountId => 'cassandane',
        }, 'R2' ],
    ]);
    $self->assert_str_equals($privateEventId, $res->[0][1]{list}[0]{id});
    $self->assert_deep_equals([$privateEventId], $res->[1][1]{created});
    $self->assert_deep_equals([$privateEventId], $res->[2][1]{ids});

    xlog "sharee can't update or destroy, or copy";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $privateEventId => {
                    start => '2022-02-02T02:00:00',
                },
            },
        }, 'R1' ],
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            destroy => [ $privateEventId ],
        }, 'R2' ],
        ['CalendarEvent/copy', {
            accountId => 'sharee',
            fromAccountId => 'cassandane',
            create => {
                privateEventCopy => {
                    id => $privateEventId,
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                },
            },
        }, 'R3' ],
    ]);
    $self->assert_str_equals('forbidden',
        $res->[0][1]{notUpdated}{$privateEventId}{type});
    $self->assert_str_equals('forbidden',
        $res->[1][1]{notDestroyed}{$privateEventId}{type});
    $self->assert_str_equals('forbidden',
        $res->[2][1]{notCreated}{privateEventCopy}{type});
}

sub test_calendarevent_set_privacy_secret_shared
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "share calendar";
    my ($shareeJmap) = $self->create_user('sharee');
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            update => {
                Default => {
                    shareWith => {
                        sharee => {
                            mayReadItems => JSON::true,
                            mayWriteAll => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{Default});

    xlog "get calendar event state as sharee";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane', ids => []
        }, 'R1' ],
    ]);
    my $state = $res->[0][1]{state};

    xlog "create secret event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                secretEvent => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2021-01-01T01:00:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    title => 'secretEvent',
                    privacy => 'secret',
                },
            },
        }, 'R1'],
    ]);
    my $secretEventId = $res->[0][1]{created}{secretEvent}{id};
    $self->assert_not_null($secretEventId);

    xlog "sharee can not see event";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'cassandane',
            properties => ['id'],
        }, 'R1' ],
        ['CalendarEvent/changes', {
            accountId => 'cassandane',
            sinceState => $state,
        }, 'R1' ],
        ['CalendarEvent/query', {
            accountId => 'cassandane',
        }, 'R2' ],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{list});
    $self->assert_deep_equals([], $res->[1][1]{created});
    $self->assert_deep_equals([], $res->[2][1]{ids});

    xlog "sharee can't update or destroy, or copy";
    $res = $shareeJmap->CallMethods([
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            update => {
                $secretEventId => {
                    start => '2022-02-02T02:00:00',
                },
            },
        }, 'R1' ],
        ['CalendarEvent/set', {
            accountId => 'cassandane',
            destroy => [ $secretEventId ],
        }, 'R2' ],
        ['CalendarEvent/copy', {
            accountId => 'sharee',
            fromAccountId => 'cassandane',
            create => {
                secretEventCopy => {
                    id => $secretEventId,
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                },
            },
        }, 'R3' ],
    ]);
    $self->assert_str_equals('notFound',
        $res->[0][1]{notUpdated}{$secretEventId}{type});
    $self->assert_str_equals('notFound',
        $res->[1][1]{notDestroyed}{$secretEventId}{type});
    $self->assert_str_equals('notFound',
        $res->[2][1]{notCreated}{secretEventCopy}{type});
}

sub test_calendarevent_set_created
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $t = DateTime->now();
    $t->set_time_zone('Etc/UTC');
    my $start = $t->strftime('%Y-%m-%dT%H:%M:%S');
    $t->add(DateTime::Duration->new(days => -2));
    my $past = $t->strftime('%Y-%m-%dT%H:%M:%SZ');
    $t->add(DateTime::Duration->new(days => 4));
    my $future = $t->strftime('%Y-%m-%dT%H:%M:%SZ');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                eventNoCreated => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => $start,
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'eventNoCreated',
                },
                eventCreatedInPast => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => $start,
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'eventCreatedInPast',
                    created => $past,
                },
                eventCreatedInFuture => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => $start,
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'eventCreatedInPast',
                    created => $future,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#eventNoCreated' ],
            properties => ['created', 'title'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => [ '#eventCreatedInPast' ],
            properties => ['created', 'title'],
        }, 'R3'],
        ['CalendarEvent/get', {
            ids => [ '#eventCreatedInFuture' ],
            properties => ['created', 'title'],
        }, 'R4'],
    ]);

    xlog "Event with no created property get set to now";
    my $created = $res->[1][1]{list}[0]{created};
    $self->assert(($past lt $created) and ($created lt $future));
    $self->assert_str_equals($created,
        $res->[0][1]{created}{eventNoCreated}{created});
    my $eventNoCreatedId = $res->[1][1]{list}[0]{id};

    xlog "Event with past created preserves value";
    $created = $res->[2][1]{list}[0]{created};
    $self->assert_str_equals($past, $created);
    $self->assert_null($res->[0][1]{created}{eventCreatedInPast}{created});

    xlog "Event with future created gets clamped to now";
    $created = $res->[3][1]{list}[0]{created};
    $self->assert(($past lt $created) and ($created lt $future));
    $self->assert_str_equals($created,
        $res->[0][1]{created}{eventCreatedInFuture}{created});

    xlog "Can update created value";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventNoCreatedId => {
                    created => $past,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ $eventNoCreatedId ],
            properties => ['created'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventNoCreatedId});
    $self->assert_str_equals($past, $res->[1][1]{list}[0]{created});
}

sub test_calendarevent_set_updated
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $t = DateTime->now();
    $t->set_time_zone('Etc/UTC');
    my $start = $t->strftime('%Y-%m-%dT%H:%M:%S');
    $t->add(DateTime::Duration->new(days => -2));
    my $past = $t->strftime('%Y-%m-%dT%H:%M:%SZ');

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => $start,
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    created => $past,
                    updated => $past,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['created', 'updated', 'title'],
        }, 'R2'],
    ]);

    $self->assert_str_equals($past, $res->[1][1]{list}[0]{created});
    my $updated = $res->[1][1]{list}[0]{updated};
    $self->assert($past lt $updated);
    $self->assert_str_equals($updated, $res->[0][1]{created}{event}{updated});
}

sub test_calendarevent_set_updated_scheduled_not_source
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $t = DateTime->now();
    $t->set_time_zone('Etc/UTC');
    my $start = $t->strftime('%Y-%m-%dT%H:%M:%S');
    my $now= $t->strftime('%Y-%m-%dT%H:%M:%SZ');
    $t->add(DateTime::Duration->new(days => -2));
    my $past = $t->strftime('%Y-%m-%dT%H:%M:%SZ');


    xlog "Create event where cassandane is invitee";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => $start,
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    created => $past,
                    updated => $past,
                    replyTo => {
                        imip => 'mailto:someone@example.com',
                    },
                    participants => {
                        cassandane => {
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'accepted',
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['updated'],
        }, 'R2'],
    ]);
    $self->assert_str_equals($past, $res->[1][1]{list}[0]{updated});
    my $eventId = $res->[1][1]{list}[0]{id};

    xlog "Change partstat of cassandane";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'participants/cassandane/participationStatus' => 'tentative',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['updated'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($past, $res->[1][1]{list}[0]{updated});

    xlog "Client updates updated property themselves";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    updated => $now,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['updated'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($now, $res->[1][1]{list}[0]{updated});
}

sub test_calendarevent_set_updated_scheduled_source
    :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $t = DateTime->now();
    $t->set_time_zone('Etc/UTC');
    my $start = $t->strftime('%Y-%m-%dT%H:%M:%S');
    my $now= $t->strftime('%Y-%m-%dT%H:%M:%SZ');
    $t->add(DateTime::Duration->new(days => -2));
    my $past = $t->strftime('%Y-%m-%dT%H:%M:%SZ');

    xlog "Create event where cassandane is owner";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => $start,
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    created => $past,
                    updated => $past,
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        someone => {
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['updated'],
        }, 'R2'],
    ]);
    my $updated = $res->[1][1]{list}[0]{updated};
    $self->assert($past lt $updated);
    my $eventId = $res->[1][1]{list}[0]{id};

    sleep(1);

    xlog "Invite someone else";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'participants/someoneelse' => {
                        sendTo => {
                            imip => 'mailto:someoneelse@example.com',
                        },
                        expectReply => JSON::true,
                        participationStatus => 'needs-action',
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['updated'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert($updated lt $res->[1][1]{list}[0]{updated});
    $updated = $res->[1][1]{list}[0]{updated};

    xlog "Client updates updated property themselves";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    updated => $past,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ '#event' ],
            properties => ['updated'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($updated, $res->[1][1]{list}[0]{updated});
}

sub test_calendarevent_set_method
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "method on main event is rejected";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2022-01-28T09:00:00',
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    method => 'request',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{event}{type});
    $self->assert_deep_equals(['method'],
        $res->[0][1]{notCreated}{event}{properties});

    xlog "method on override event is ignored"; # see RFC8984, section 4.3.5
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2022-01-28T09:00:00',
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                    recurrenceRules => [{
                        frequency => 'daily',
                    }],
                    recurrenceOverrides => {
                        '2022-01-29T09:00:00' => {
                            title => 'override',
                            method => 'request',
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event'],
            properties => ['title', 'method', 'recurrenceOverrides'],
        }, 'R2'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);
    $self->assert_null($res->[1][1]{list}[0]{method});
    $self->assert_deep_equals({
        '2022-01-29T09:00:00' => {
            title => 'override',
        },
    }, $res->[1][1]{list}[0]{recurrenceOverrides});

    xlog "can't set method in /update either";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    method => 'request',
                },
            },
        }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notUpdated}{$eventId}{type});
    $self->assert_deep_equals(['method'],
        $res->[0][1]{notUpdated}{$eventId}{properties});
}

sub test_calendarevent_set_replyto
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                eventReplyTo => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2022-01-28T09:00:00',
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    replyTo => {
                        imip => 'mailto:myreplyto@example.com',
                    },
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
                eventNoReplyTo => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2022-01-28T10:00:00',
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
                eventReplyToNoParticipants => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2022-01-28T11:00:00',
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                },
                eventNoScheduling => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    start => '2022-01-28T12:00:00',
                    timeZone => 'Etc/UTC',
                    duration => 'PT1H',
                    title => 'event',
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#eventReplyTo'],
            properties => ['replyTo'],
        }, 'R2'],
        ['CalendarEvent/get', {
            ids => ['#eventNoReplyTo'],
            properties => ['replyTo'],
        }, 'R3'],
    ]);

    xlog "Preserve client-set replyTo";
    $self->assert_deep_equals({
        imip => 'mailto:myreplyto@example.com',
    }, $res->[1][1]{list}[0]{replyTo});

    xlog "Use server-set replyTo if not set by client";
    $self->assert_deep_equals({
        imip => 'mailto:cassandane@example.com',
    }, $res->[0][1]{created}{eventNoReplyTo}{replyTo});
    $self->assert_deep_equals({
        imip => 'mailto:cassandane@example.com',
    }, $res->[2][1]{list}[0]{replyTo});

    xlog "Reject event with replyTo but no participants";
    $self->assert_str_equals('invalidProperties',
        $res->[0][1]{notCreated}{eventReplyToNoParticipants}{type});
    $self->assert_deep_equals(['replyTo', 'participants'],
        $res->[0][1]{notCreated}{eventReplyToNoParticipants}{properties});

    xlog "Use server-set replyTo when participants added in update";
    my $eventId = $res->[0][1]{created}{eventNoScheduling}{id};
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals({
        imip => 'mailto:cassandane@example.com',
    }, $res->[0][1]{updated}{$eventId}{replyTo});
}

sub test_calendarpreferences_set
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "Create calendar";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                calendar => {
                    name => 'Test',
                },
            }
        }, 'R1'],
    ]);
    my $calendarId = $res->[0][1]{created}{calendar}{id};
    $self->assert_not_null($calendarId);

    xlog "Fetch participant identities";
    $res = $jmap->CallMethods([
        ['ParticipantIdentity/get', {
        }, 'R1'],
    ]);
    my $participantId = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($participantId);

    xlog "Fetch preferences";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/get', {
        }, 'R1'],
    ]);
    $self->assert_deep_equals([{
        id => 'singleton',
        defaultCalendarId => undef,
        defaultParticipantIdentityId => undef,
    }], $res->[0][1]{list});
    my $state = $res->[0][1]{state};

    xlog "Set preferences";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultCalendarId => $calendarId,
                    defaultParticipantIdentityId => $participantId,
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{singleton});
    $self->assert_str_equals($state, $res->[0][1]{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]{newState});

    xlog "Fetch preferences by id";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/get', {
            ids => ['singleton'],
        }, 'R1'],
    ]);
    $self->assert_deep_equals([{
        id => 'singleton',
        defaultCalendarId => $calendarId,
        defaultParticipantIdentityId => $participantId,
    }], $res->[0][1]{list});

    xlog "Unset preferences";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultCalendarId => undef,
                    defaultParticipantIdentityId => undef,
                },
            },
        }, 'R1'],
        ['CalendarPreferences/get', {
            ids => ['singleton'],
        }, 'R2'],
    ]);
    xlog "Setting defaultCalendarId to null assigns a new default calendar";
    $self->assert_not_null($res->[0][1]{updated}{singleton}{defaultCalendarId});
    $self->assert_deep_equals([{
        id => 'singleton',
        defaultCalendarId => $res->[0][1]{updated}{singleton}{defaultCalendarId},
        defaultParticipantIdentityId => undef,
    }], $res->[1][1]{list});
}

sub deliver_imip {
    my ($self) = @_;

    my $uuid = guid_string();
    my $imip = <<"EOF";
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender\@example.net>
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
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));
};

sub test_calendarpreferences_defaultcalendar
    :min_version_3_7 :needs_component_jmap :needs_component_sieve
    :CalDAVNoDefaultCalendar
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admin = $self->{adminstore}->get_client();

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    xlog "Create special-named Default calendar";
    $caldav->NewCalendar({ id => 'Default' });

    my $res = $jmap->CallMethods([
        ['Calendar/get', { }, 'R1'],
    ]);
    $self->assert_str_equals('Default', $res->[0][1]{list}[0]{id});

    xlog "No defaultCalendar set";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/get', { }, 'R1'],
    ]);
    $self->assert_null($res->[0][1]{list}[0]{defaultCalendarId});

    xlog "Get CalendarEvent state";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', { }, 'R1'],
    ]);
    $self->assert_deep_equals([], $res->[0][1]{list});
    my $state = $res->[0][1]{state};

    xlog "Deliver message";
    $self->deliver_imip();

    xlog "Message should go into hard-coded Default calendar";
    $res = $jmap->CallMethods([
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/changes',
                path => '/created'
            },
            properties => ['calendarIds'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals({
        Default => JSON::true
    }, $res->[1][1]{list}[0]{calendarIds});
    $state = $res->[1][1]{state};

    xlog "Create calendars A, B and C";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                calendarA => {
                    name => 'A',
                },
                calendarB => {
                    name => 'B',
                },
                calendarC => {
                    name => 'C',
                },
            },
        }, 'R1'],
    ]);
    my $calendarA = $res->[0][1]{created}{calendarA}{id};
    $self->assert_not_null($calendarA);
    my $calendarB = $res->[0][1]{created}{calendarB}{id};
    $self->assert_not_null($calendarB);
    my $calendarC = $res->[0][1]{created}{calendarC}{id};
    $self->assert_not_null($calendarC);

    xlog "Make calendar C read-only to owner";
    $admin->setacl("user.cassandane.#calendars.$calendarC", cassandane => 'lrs') or die;

    xlog "Set calendarA as default";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultCalendarId => $calendarA,
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{singleton});

    xlog "Deliver message";
    $self->deliver_imip();

    xlog "Message should go into calendar A";
    $res = $jmap->CallMethods([
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/changes',
                path => '/created'
            },
            properties => ['calendarIds'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals({
        $calendarA => JSON::true
    }, $res->[1][1]{list}[0]{calendarIds});
    $state = $res->[1][1]{state};

    xlog "Destroying calendar A picks Default as new default";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            destroy => [$calendarA],
            onDestroyRemoveEvents => JSON::true,
        }, 'R1'],
        ['CalendarPreferences/get', {
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$calendarA], $res->[0][1]{destroyed});
    $self->assert_str_equals('Default', $res->[1][1]{list}[0]{defaultCalendarId});

    xlog "Can set defaultCalendarId to null, but new one gets picked immediately";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultCalendarId => undef,
                },
            },
        }, 'R1'],
        ['CalendarPreferences/get', {
        }, 'R2'],
    ]);
    $self->assert_str_equals($res->[0][1]{updated}{singleton}{defaultCalendarId},
        $res->[1][1]{list}[0]{defaultCalendarId});

    xlog "Destroy special calendar Default, new default is calendar B";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            destroy => [ 'Default' ],
            onDestroyRemoveEvents => JSON::true,
        }, 'R1'],
        ['CalendarPreferences/get', {
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['Default'], $res->[0][1]{destroyed});
    $self->assert_str_equals($calendarB, $res->[1][1]{list}[0]{defaultCalendarId});

    xlog "Get CalendarEvent state";
    $res = $jmap->CallMethods([
        ['Calendar/get', {
            properties => ['id'],
        }, 'R0'],
        ['CalendarEvent/get', {
            properties => ['id', 'calendarIds'],
        }, 'R1'],
        ['Calendar/get', {
            properties => ['id'],
        }, 'R2'],
    ]);
    $state = $res->[1][1]{state};

    xlog "Deliver message";
    $self->deliver_imip();

    xlog "Message should go into writable calendar B";
    $res = $jmap->CallMethods([
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/changes',
                path => '/created'
            },
            properties => ['calendarIds'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals({
        $calendarB => JSON::true
    }, $res->[1][1]{list}[0]{calendarIds});
    $state = $res->[1][1]{state};

    xlog "Destroy calendar B";
    $res = $jmap->CallMethods([
        ['Calendar/set', {
            destroy => [ $calendarB ],
            onDestroyRemoveEvents => JSON::true,
        }, 'R1'],
        ['CalendarPreferences/get', {
        }, 'R2'],
    ]);
    $self->assert_deep_equals([$calendarB], $res->[0][1]{destroyed});

    xlog "Read-only calendar C does not get picked as default";
    $self->assert_null($res->[1][1]{list}[0]{defaultCalendarId});

    xlog "Cannot set read-only calendar as default calendar";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultCalendarId => $calendarC,
                },
            },
        }, 'R1'],
        ['CalendarPreferences/get', {
        }, 'R2'],
    ]);
    $self->assert_deep_equals(['defaultCalendarId'],
        $res->[0][1]{notUpdated}{singleton}{properties});
    $self->assert_null($res->[1][1]{list}[0]{defaultCalendarId});
}

sub test_calendarpreferences_participantidentity
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    xlog "No defaultParticipantIdentityId set";
    my $res = $jmap->CallMethods([
        ['CalendarPreferences/get', { }, 'R1'],
    ]);
    $self->assert_null($res->[0][1]{list}[0]{defaultParticipantIdentityId});

    xlog 'Cyrus selects owner participant';
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_deep_equals({
        imip => 'mailto:cassandane@example.com',
    }, $res->[0][1]{created}{event1}{replyTo});

    xlog "Set scheduling addresses via CalDAV";
    my $xml = <<'EOF';
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
     <C:calendar-user-address-set>
       <D:href>mailto:alias1@example.com</D:href>
       <D:href>mailto:alias2@example.com</D:href>
       <D:href>mailto:alias3@example.com</D:href>
     </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $caldav->Request('PROPPATCH', "/dav/principals/user/cassandane",
                       $xml, 'Content-Type' => 'text/xml');

    xlog "No defaultParticipantIdentityId set";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/get', { }, 'R1'],
    ]);
    $self->assert_null($res->[0][1]{list}[0]{defaultParticipantIdentityId});

    xlog "Get participant identities";
    $res = $jmap->CallMethods([
        ['ParticipantIdentity/get', { }, 'R1'],
    ]);
    my $participantId = (grep {$_->{sendTo}{imip} eq 'mailto:alias2@example.com'}
        @{$res->[0][1]{list}})[0]{id};
    $self->assert_not_null($participantId);

    xlog "Set participant identity as default";
    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultParticipantIdentityId => $participantId,
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{singleton});

    xlog 'Cyrus uses default participant';
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event2 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => "event1",
                    start => "2020-01-01T09:00:00",
                    timeZone => "Europe/Vienna",
                    duration => "PT1H",
                    participants => {
                        someone => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => ['#event2'],
            properties => ['replyTo'],
        }, 'R2'],
    ]);
    $self->assert_deep_equals({
        imip => 'mailto:alias2@example.com',
    }, $res->[0][1]{created}{event2}{replyTo});

    xlog "Updated scheduling addresses keep default participant";
    $xml = <<'EOF';
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
     <C:calendar-user-address-set>
       <D:href>mailto:alias1@example.com</D:href>
       <D:href>mailto:alias2@example.com</D:href>
       <D:href>mailto:alias3@example.com</D:href>
       <D:href>mailto:alias4@example.com</D:href>
     </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $caldav->Request('PROPPATCH', "/dav/principals/user/cassandane",
                       $xml, 'Content-Type' => 'text/xml');

    $res = $jmap->CallMethods([
        ['CalendarPreferences/get', { }, 'R1']
    ]);
    $self->assert_str_equals($participantId,
        $res->[0][1]{list}[0]{defaultParticipantIdentityId});

    xlog "Removed default scheduling address reset default id";
    $xml = <<'EOF';
<?xml version="1.0" encoding="UTF-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
     <C:calendar-user-address-set>
       <D:href>mailto:alias4@example.com</D:href>
       <D:href>mailto:alias5@example.com</D:href>
     </C:calendar-user-address-set>
    </D:prop>
  </D:set>
</D:propertyupdate>
EOF
    $caldav->Request('PROPPATCH', "/dav/principals/user/cassandane",
                       $xml, 'Content-Type' => 'text/xml');

    $res = $jmap->CallMethods([
        ['CalendarPreferences/get', { }, 'R1']
    ]);
    $self->assert_null($res->[0][1]{list}[0]{defaultParticipantIdentityId});
}

sub test_calendarevent_encode_imip_uri
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
}
EOF
    );

    $self->{instance}->getnotify();

    xlog "Create event with percent-encoded participant uri";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarIds => {
                        Default => JSON::true,
                    },
                    title => 'event1',
                    start => '2020-01-01T09:00:00',
                    timeZone => 'Europe/Vienna',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        plusuri => {
                            roles => {
                                'attendee' => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:plus%2Buri@example.com',
                            },
                            expectReply => JSON::true,
                            participationStatus => 'needs-action',
                        },
                    },
                },
            },
            sendSchedulingMessages => JSON::true,
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => ['participants'],
        }, 'R2'],
    ]);

    xlog "Assert the Participant uri is encoded";
    $self->assert_str_equals('mailto:plus%2Buri@example.com',
        $res->[1][1]{list}[0]{participants}{plusuri}{sendTo}{imip});

    xlog "Assert the iCalendar data has the encoded URI";
    my $blobId = $res->[0][1]{created}{event1}{blobId};
    $res = $jmap->Download('cassandane', $blobId);
    my $ical = $res->{content};
    $self->assert($ical =~ /mailto:plus%2Buri\@example\.com/g);

    xlog "Assert the iMIP notification has the decoded recipient";
    my $data = $self->{instance}->getnotify();
    my ($imipnotif) = grep { $_->{METHOD} eq 'imip' } @$data;
    my $payload = decode_json($imipnotif->{MESSAGE});
    $self->assert_str_equals('plus+uri@example.com', $payload->{recipient});

    xlog "Assert the iTIP message has the encoded URI";
    my $itip = $payload->{ical};
    $self->assert($itip =~ /mailto:plus%2Buri\@example\.com/g);
    $self->assert($itip =~ "METHOD:REQUEST");

    xlog "Deliver iTIP REPLY for participant";
    $itip =~ s/METHOD:REQUEST/METHOD:REPLY/g;
    $itip =~ s/NEEDS-ACTION/ACCEPTED/g;

    my $imip = <<"EOF";
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <6de280c9-edff-4019-8ebd-cfebc73f8201\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: 6de280c9-edff-4019-8ebd-cfebc73f8201

$itip
EOF
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    xlog "Assert the participant status got updated";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['participants'],
        }, 'R1'],
    ]);
    $self->assert_str_equals('mailto:plus%2Buri@example.com',
        $res->[0][1]{list}[0]{participants}{plusuri}{sendTo}{imip});
    $self->assert_str_equals('accepted',
        $res->[0][1]{list}[0]{participants}{plusuri}{participationStatus});
}

sub test_calendarevent_set_standalone_itip
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Clear notification cache";
    $self->{instance}->getnotify();

    xlog "Create scheduled standalone instance";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance1 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T01:01:01',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                    replyTo => {
                        imip => 'mailto:organizer@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                            participationStatus => 'tentative',
                            expectReply => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $instance1Id = $res->[0][1]{created}{instance1}{id};
    $self->assert_not_null($instance1Id);

    xlog "Assert that iTIP notification is sent";
    my $data = $self->{instance}->getnotify();
    my ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);
    my $itip = decode_json($notif->{MESSAGE})->{ical};
    my $ical = Data::ICal->new(data => $itip);

    my @vevents = grep { $_->ical_entry_type() eq 'VEVENT' } @{$ical->entries()};
    $self->assert_num_equals(1, scalar @vevents);

    my $recurid = $vevents[0]->property('RECURRENCE-ID');
    $self->assert_num_equals(1, scalar @{$recurid});
    $self->assert_str_equals('20210101T010101', $recurid->[0]->value());

    my $attendees = $vevents[0]->property('ATTENDEE');
    $self->assert_num_equals(1, scalar @{$attendees});
    $self->assert_str_equals('mailto:cassandane@example.com',
        $attendees->[0]->value());
    $self->assert_str_equals('TENTATIVE',
        $attendees->[0]->parameters()->{'PARTSTAT'});

    xlog "Clear notification cache";
    $self->{instance}->getnotify();

    xlog "Create another standalone instance for that UID";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2022-02-02T02:02:02',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2022-02-02T02:02:02',
                    recurrenceIdTimeZone => 'Europe/London',
                    replyTo => {
                        imip => 'mailto:organizer@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                            participationStatus => 'accepted',
                            expectReply => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $instance2Id = $res->[0][1]{created}{instance2}{id};
    $self->assert_not_null($instance2Id);

    xlog "Assert iTIP notification just gets sent for new instance";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);
    $itip = decode_json($notif->{MESSAGE})->{ical};
    $ical = Data::ICal->new(data => $itip);

    @vevents = grep { $_->ical_entry_type() eq 'VEVENT' } @{$ical->entries()};
    $self->assert_num_equals(1, scalar @vevents);

    $recurid = $vevents[0]->property('RECURRENCE-ID');
    $self->assert_num_equals(1, scalar @{$recurid});
    $self->assert_str_equals('20220202T020202', $recurid->[0]->value());

    $attendees = $vevents[0]->property('ATTENDEE');
    $self->assert_num_equals(1, scalar @{$attendees});
    $self->assert_str_equals('mailto:cassandane@example.com',
        $attendees->[0]->value());
    $self->assert_str_equals('ACCEPTED',
        $attendees->[0]->parameters()->{'PARTSTAT'});

    xlog "Clear notification cache";
    $self->{instance}->getnotify();

    xlog "Update partstat in a standalone instance";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $instance2Id => {
                    'participants/cassandane/participationStatus' => 'declined',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$instance2Id});

    xlog "Assert iTIP notification only is sent for updated instance";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);
    $itip = decode_json($notif->{MESSAGE})->{ical};
    $ical = Data::ICal->new(data => $itip);

    @vevents = grep { $_->ical_entry_type() eq 'VEVENT' } @{$ical->entries()};
    $self->assert_num_equals(1, scalar @vevents);

    $recurid = $vevents[0]->property('RECURRENCE-ID');
    $self->assert_num_equals(1, scalar @{$recurid});
    $self->assert_str_equals('20220202T020202', $recurid->[0]->value());

    $attendees = $vevents[0]->property('ATTENDEE');
    $self->assert_num_equals(1, scalar @{$attendees});
    $self->assert_str_equals('mailto:cassandane@example.com',
        $attendees->[0]->value());
    $self->assert_str_equals('DECLINED',
        $attendees->[0]->parameters()->{'PARTSTAT'});

    xlog "Clear notification cache";
    $self->{instance}->getnotify();

    xlog "Create another standalone instance where PARTSTAT=NEEDS-ACTION";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance2 => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance3',
                    start => '2022-03-03T03:03:03',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2022-03-03T03:03:03',
                    recurrenceIdTimeZone => 'Europe/London',
                    replyTo => {
                        imip => 'mailto:organizer@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                            participationStatus => 'needs-action',
                            expectReply => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $instance3Id = $res->[0][1]{created}{instance2}{id};
    $self->assert_not_null($instance2Id);

    xlog "Assert no iTIP notification is sent";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($notif);
}

sub test_calendarevent_set_create_ignore_uid_in_special_calendar
    :min_version_3_7 :needs_component_jmap :needs_component_sieve
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admin = $self->{adminstore}->get_client();

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
}
EOF
    );

    my $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <7e017102-0caf-490a-bbdf-422141d34e75@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:7e017102-0caf-490a-bbdf-422141d34e75
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    xlog "Lookup event uid";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'uid'],
        }, 'R0'],
    ]);
    my $eventId = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($eventId);
    my $eventUid = $res->[0][1]{list}[0]{uid};
    $self->assert_not_null($eventUid);

    xlog "Destroy event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            destroy => [$eventId],
        }, 'R0'],
    ]);
    $self->assert_deep_equals([$eventId], $res->[0][1]{destroyed});

    xlog "Create event having the same uid";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => $eventUid,
                    title => 'test',
                    start => '2021-01-01T01:01:01',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
            },
        }, 'R1'],
    ]);
    $self->assert_not_null($res->[0][1]{created}{event});
}

sub test_calendarevent_set_replace_standalone_with_destroy
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Create standalone instance";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                instance => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-02T01:01:01',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceId => '2021-01-01T01:01:01',
                    recurrenceIdTimeZone => 'Europe/London',
                },
            },
        }, 'R1'],
    ]);
    my $instanceId = $res->[0][1]{created}{instance}{id};
    $self->assert_not_null($instanceId);

    xlog "Destroy standalone instance and create main event for same uid";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'instance1',
                    start => '2021-01-01T01:01:01',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 5,
                    }],
                },
            },
            destroy => [ $instanceId ],
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => [ 'recurrenceOverrides' ],
        }, 'R2'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);
    $self->assert_deep_equals([ $instanceId ], $res->[0][1]{destroyed});
    $self->assert_null($res->[1][1]{list}[0]{recurrenceOverrides});

}

sub test_calendarevent_set_reply_partstat_changed
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Clean notifications";
    $self->{instance}->getnotify();

    xlog "Create scheduled event";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'event',
                    start => '2021-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 30,
                    }],
                    replyTo => {
                        imip => 'mailto:organizer@example.com',
                    },
                    participants => {
                        cassandane => {
                            roles => {
                                attendee => JSON::true,
                            },
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                            participationStatus => 'needs-action',
                            expectReply => JSON::true,
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);

    xlog "Assert that no iTIP notification is sent";
    my $data = $self->{instance}->getnotify();
    my ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($notif);

    xlog "Clean notifications";
    $self->{instance}->getnotify();

    xlog "Update participationStatus";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'participants/cassandane/participationStatus' => 'accepted',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Assert that iTIP notification is sent";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);

    xlog "Clean notifications";
    $self->{instance}->getnotify();

    xlog "Update title";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    title => 'updated',
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Assert that no iTIP notification is sent";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($notif);

    xlog "Clean notifications";
    $self->{instance}->getnotify();

    xlog "Update participationStatus in recurrence override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    recurrenceOverrides => {
                        '2021-01-02T15:30:00' => {
                            'participants/cassandane/participationStatus' => 'declined',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Assert that iTIP notification is sent";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);

    xlog "Clean notifications";
    $self->{instance}->getnotify();

    xlog "Update title in recurrence override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2021-01-03T15:30:00' => {
                        title => 'updatedOverride',
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Assert that no iTIP notification is sent";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_null($notif);
}

sub test_calendarevent_set_destroy_itip
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};

    my %expectNotif = (
        'NEEDS-ACTION' => 0,
        'TENTATIVE' => 1,
        'ACCEPTED' => 1,
    );

    while (my ($partstat, $wantNotif) = each %expectNotif) {

        xlog "Create invite with PARTSTAT=$partstat";
        my $uid = 'event' . $partstat . 'uid';
        my $ical = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:$uid
DTSTART;TZID=Europe/Vienna:20160928T160000
DURATION:PT1H
DTSTAMP:20150928T132434Z
SUMMARY:event
LAST-MODIFIED:20150928T132434Z
ORGANIZER:mailto:someone\@example.com
ATTENDEE;RVSP=TRUE;PARTSTAT=$partstat:mailto:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF
        $caldav->Request('PUT', "/dav/calendars/user/cassandane/Default/event$partstat.ics",
            $ical, 'Content-Type' => 'text/calendar');

        my $eventId = encode_eventid($uid);

        xlog "Clean notifications";
        $self->{instance}->getnotify();

        xlog "Destroy event";
        my $res = $jmap->CallMethods([
            ['CalendarEvent/set', {
                destroy => [ $eventId ],
            }, 'R1'],
        ]);
        $self->assert_deep_equals([ $eventId ], $res->[0][1]{destroyed});

        my $data = $self->{instance}->getnotify();
        my ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
        if ($wantNotif) {
            xlog "Assert iTIP notification is sent";
            $self->assert_not_null($notif);
        } else {
            xlog "Assert no iTIP notification is sent";
            $self->assert_null($notif);
        }
    }
}

sub test_calendarevent_set_created_override
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $t = DateTime->now();
    $t->set_time_zone('Etc/UTC');
    my $now = $t->strftime('%Y-%m-%dT%H:%M:%SZ');
    $t->add(DateTime::Duration->new(days => -2));
    my $past = $t->strftime('%Y-%m-%dT%H:%M:%SZ');
    $t->add(DateTime::Duration->new(days => -2));
    my $waypast = $t->strftime('%Y-%m-%dT%H:%M:%SZ');
    $t->add(DateTime::Duration->new(days => 8));
    my $future = $t->strftime('%Y-%m-%dT%H:%M:%SZ');

    xlog "Create recurring event and set 'created' timestamp";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                event => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'event1uid',
                    title => 'event',
                    created => $past,
                    start => '2021-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    recurrenceRules => [{
                        frequency => 'daily',
                        count => 30,
                    }],
                },
            },
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{created}{event}{id};
    $self->assert_not_null($eventId);

    xlog "Add new override: created > main:created";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    recurrenceOverrides => {
                        '2021-01-02T15:30:00' => {
                            title => 'eventOverride',
                            created => $now,
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => ['created', 'recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($past, $res->[1][1]{list}[0]{created});
    $self->assert_str_equals($now, $res->[1][1]{list}[0]
        {recurrenceOverrides}{'2021-01-02T15:30:00'}{created});

    xlog "Add new override: created < main:created";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2021-01-03T15:30:00' => {
                        title => 'eventOverride',
                        created => $waypast,
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => ['created', 'recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($past, $res->[1][1]{list}[0]{created});
    $self->assert_str_equals($waypast, $res->[1][1]{list}[0]
        {recurrenceOverrides}{'2021-01-03T15:30:00'}{created});

    xlog "Add new override: created > now: server clamps to now";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2021-01-04T15:30:00' => {
                        title => 'eventOverride',
                        created => $future,
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => ['created', 'recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($past, $res->[1][1]{list}[0]{created});
    $self->assert_str_equals(substr($now, 0, 15),
        substr($res->[1][1]{list}[0]{recurrenceOverrides}
            {'2021-01-04T15:30:00'}{created}, 0, 15));

    xlog "Can change created of existing override";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'recurrenceOverrides/2021-01-02T15:30:00/created' => $waypast,
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => ['created', 'recurrenceOverrides'],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_str_equals($waypast, $res->[1][1]{list}[0]{recurrenceOverrides}
            {'2021-01-02T15:30:00'}{created});
}

sub test_itip_rsvp_organizer_change
    :min_version_3_7 :needs_component_jmap :needs_component_sieve
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
}
EOF
    );

    my $imip = <<'EOF';
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Sally Sender <sender@example.net>
To: Cassandane <cassandane@example.com>
Message-ID: <7e017102-0caf-490a-bbdf-422141d34e75@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:7e017102-0caf-490a-bbdf-422141d34e75
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:test
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User;X-JMAP-ID=organizerA:MAILTO:organizerA@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;X-JMAP-ID=cassandane:MAILTO:cassandane@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    xlog "Clear notifications";
    $self->{instance}->getnotify();

    xlog "Accept invitation in JMAP";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            properties => ['id', 'participants'],
        }, 'R1'],
    ]);
    my $eventId = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($eventId);
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    'participants/cassandane/participationStatus' => 'accepted',
                },
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});

    xlog "Assert that iTIP notification is sent";
    my $data = $self->{instance}->getnotify();
    my ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);

    xlog "Clear notifications";
    $self->{instance}->getnotify();

    xlog "Change organizer in JMAP";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventId => {
                    replyTo => {
                        imip => 'mailto:organizerB@example.net',
                    },
                    'participants/organizerA' => undef,
                },
            }
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ $eventId ],
            properties => [ 'replyTo' ],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$eventId});
    $self->assert_deep_equals({
        imip => 'mailto:organizerB@example.net',
    }, $res->[1][1]{list}[0]{replyTo});

    xlog "Assert that iTIP notification is sent";
    $data = $self->{instance}->getnotify();
    ($notif) = grep { $_->{METHOD} eq 'imip' } @$data;
    $self->assert_not_null($notif);
}

sub test_calendarevent_get_reset_iter
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Create events in calendar A and B, both have IMAP uid 1";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                calendarA => {
                    name => 'A',
                },
                calendarB => {
                    name => 'B',
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                eventA => {
                    calendarIds => {
                        '#calendarA' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'eventA-uid',
                    title => 'eventA',
                    start => '2021-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
                eventB => {
                    calendarIds => {
                        '#calendarB' => JSON::true,
                    },
                    '@type' => 'Event',
                    uid => 'eventB-uid',
                    title => 'eventB',
                    start => '2022-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
            },
        }, 'R2'],
        ['CalendarEvent/get', {
                properties => ['calendarIds', 'uid', 'title', 'start'],
        }, 'R2'],
    ]);

    xlog "Assert CalendarEvent/get iterator state is reset properly";
    $self->assert_num_equals(2, scalar @{$res->[2][1]{list}});
    $self->assert_str_not_equals((keys %{$res->[2][1]{list}[0]{calendarIds}})[0],
        (keys %{$res->[2][1]{list}[1]{calendarIds}})[0]);
    $self->assert_str_not_equals($res->[2][1]{list}[0]{uid},
        $res->[2][1]{list}[1]{uid});
    $self->assert_str_not_equals($res->[2][1]{list}[0]{title},
        $res->[2][1]{list}[1]{title});
    $self->assert_str_not_equals($res->[2][1]{list}[0]{start},
        $res->[2][1]{list}[1]{start});
}

sub test_calendarevent_get_isorigin
    :min_version_3_7 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Create events";
    my $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            create => {
                eventNoReplyTo => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'eventNoReplyTo',
                    start => '2021-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                },
                eventIsOrganizer => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'eventIsOrganizer',
                    start => '2021-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:cassandane@example.com',
                    },
                    participants => {
                        participant1 => {
                            sendTo => {
                                imip => 'mailto:someone@example.com',
                            },
                        },
                    },
                },
                eventIsInvitee => {
                    calendarIds => {
                        'Default' => JSON::true,
                    },
                    '@type' => 'Event',
                    title => 'eventIsInvitee',
                    start => '2021-01-01T15:30:00',
                    timeZone => 'Europe/Berlin',
                    duration => 'PT1H',
                    replyTo => {
                        imip => 'mailto:someone@example.com',
                    },
                    participants => {
                        participant1 => {
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            properties => ['isOrigin'],
        }, 'R2'],
    ]);

    my $eventNoReplyToId = $res->[0][1]{created}{eventNoReplyTo}{id};
    $self->assert_not_null($eventNoReplyToId);
    my $eventIsOrganizerId = $res->[0][1]{created}{eventIsOrganizer}{id};
    $self->assert_not_null($eventIsOrganizerId);
    my $eventIsInviteeId = $res->[0][1]{created}{eventIsInvitee}{id};
    $self->assert_not_null($eventIsInviteeId);

    $self->assert_equals(JSON::true, $res->[0][1]{created}{eventNoReplyTo}{isOrigin});
    $self->assert_equals(JSON::true, $res->[0][1]{created}{eventIsOrganizer}{isOrigin});
    $self->assert_equals(JSON::false, $res->[0][1]{created}{eventIsInvitee}{isOrigin});

    my %events = map { $_->{id} =>  $_ } @{$res->[1][1]{list}};
    $self->assert_equals(JSON::true, $events{$eventNoReplyToId}{isOrigin});
    $self->assert_equals(JSON::true, $events{$eventIsOrganizerId}{isOrigin});
    $self->assert_equals(JSON::false, $events{$eventIsInviteeId}{isOrigin});

    xlog "Add scheduling to formerly unscheduled event";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $eventNoReplyToId => {
                    replyTo => {
                        imip => 'mailto:someone@example.com',
                    },
                    participants => {
                        participant1 => {
                            sendTo => {
                                imip => 'mailto:cassandane@example.com',
                            },
                        },
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/get', {
            ids => [ $eventNoReplyToId ],
            properties => ['isOrigin'],
        }, 'R2'],
    ]);

    $self->assert_equals(JSON::false, $res->[0][1]{updated}{$eventNoReplyToId}{isOrigin});
    $self->assert_equals(JSON::false, $res->[1][1]{list}[0]{isOrigin});
}

1;
