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

package Cassandane::Cyrus::JMAPCore;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.12;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);

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

sub test_settings
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create users and give cassandane access to their mailboxes
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;
    $self->{instance}->create_user("bar");
    $admintalk->setacl("user.bar", "cassandane", "lrswp") or die;

        my $service = $self->{instance}->get_service("http");
        my $fooCalDAVTalk = Net::CalDAVTalk->new(
                user => "foo",
                password => 'pass',
                host => $service->host(),
                port => $service->port(),
                scheme => 'http',
                url => '/',
                expandurl => 1,
        );
        my $CalendarId = $fooCalDAVTalk->NewCalendar({name => 'foo'});
        $self->assert_not_null($CalendarId);
        $admintalk->setacl("user.foo.#calendars.$CalendarId", "cassandane" => 'lr') or die;
        $admintalk->setacl("user.foo.#addressbooks.Default", "cassandane" => '') or die;

    # Make sure that isReadOnly is false if ANY mailbox is read-writeable
    $self->{instance}->create_user("baz");
    $admintalk->create("user.baz.box1") or die;
    $admintalk->create("user.baz.box2") or die;
    $admintalk->setacl("user.baz.box1", "cassandane", "lrswp") or die;
    $admintalk->setacl("user.baz.box2", "cassandane", "lr") or die;
    # no access to qux
    $self->{instance}->create_user("qux");

    my $Request;
    my $Response;

    xlog "get settings";
    $Request = {
        headers => {
            'Authorization' => $jmap->auth_header(),
        },
        content => '',
    };
    $Response = $jmap->ua->get($jmap->uri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('200', $Response->{status});

    my $settings;
    $settings = eval { decode_json($Response->{content}) } if $Response->{success};

    $self->assert_not_null($settings->{username});
    $self->assert_not_null($settings->{accounts});
    $self->assert_not_null($settings->{apiUrl});
    $self->assert_not_null($settings->{downloadUrl});
    $self->assert_not_null($settings->{uploadUrl});
    $self->assert(exists $settings->{capabilities}->{"urn:ietf:params:jmap:core"});
    $self->assert(exists $settings->{capabilities}->{"urn:ietf:params:jmap:mail"});

    my $cap = $settings->{capabilities}->{"urn:ietf:params:jmap:core"};
    $self->assert($cap->{maxSizeUpload} > 0);
    $self->assert($cap->{maxConcurrentUpload} > 0);
    $self->assert($cap->{maxSizeRequest} > 0);
    $self->assert($cap->{maxConcurrentRequests} > 0);
    $self->assert($cap->{maxCallsInRequest} > 0);
    $self->assert($cap->{maxObjectsInGet} > 0);
    $self->assert($cap->{maxObjectsInSet} > 0);

    my $acc;
    my @wantHasDataFor;
    my @gotHasDataFor;
        my $accounts =  $settings->{accounts};
    $self->assert_num_equals(4, scalar keys %{$accounts});

    $acc = $accounts->{cassandane};
    $self->assert_str_equals("cassandane", $acc->{name});
    $self->assert_equals(JSON::true, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
    @wantHasDataFor = sort((
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'urn:ietf:params:jmap:contacts',
        'urn:ietf:params:jmap:calendars'
    ));
    @gotHasDataFor = sort @{$acc->{hasDataFor}};
    $self->assert_deep_equals(\@wantHasDataFor, \@gotHasDataFor);

    $acc = $accounts->{foo};
    $self->assert_str_equals("foo", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::true, $acc->{isReadOnly});
    @wantHasDataFor = sort ('urn:ietf:params:jmap:mail',
                            'urn:ietf:params:jmap:submission',
                            'urn:ietf:params:jmap:calendars');
    @gotHasDataFor = sort @{$acc->{hasDataFor}};
    $self->assert_deep_equals(\@wantHasDataFor, \@gotHasDataFor);

    $acc = $accounts->{bar};
    $self->assert_str_equals("bar", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
    $self->assert_num_equals(2, scalar @{$acc->{hasDataFor}});
    $self->assert_str_equals('urn:ietf:params:jmap:mail', $acc->{hasDataFor}[0]);

    $acc = $accounts->{baz};
    $self->assert_str_equals("baz", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
    $self->assert_num_equals(2, scalar @{$acc->{hasDataFor}});
    $self->assert_str_equals('urn:ietf:params:jmap:mail', $acc->{hasDataFor}[0]);
}

sub test_blob_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $data = $jmap->Upload("some test", "text/plain");

    my $resp = $jmap->Download('cassandane', $data->{blobId});

    $self->assert_str_equals('application/octet-stream', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    $resp = $jmap->Download({ accept => 'text/plain' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('text/plain', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    $resp = $jmap->Download({ accept => 'text/plain;q=0.9, text/html' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('text/html', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    $resp = $jmap->Download({ accept => '*/*' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('application/octet-stream', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    $resp = $jmap->Download({ accept => 'foo' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('application/octet-stream', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    $resp = $jmap->Download({ accept => 'foo*/bar' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('application/octet-stream', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    $resp = $jmap->Download({ accept => 'foo/(bar)' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('application/octet-stream', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});
}

sub test_created_ids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "send bogus creation ids map";
    my $RawRequest = {
        headers => {
            'Authorization' => $jmap->auth_header(),
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        },
        content => encode_json({
            using => ['urn:ietf:params:jmap:mail'],
            methodCalls => [['Identity/get', {}, 'R1']],
            createdIds => 'bogus',
        }),
    };
    my $RawResponse = $jmap->ua->post($jmap->uri(), $RawRequest);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawRequest, $RawResponse);
    }
    $self->assert_str_equals('400', $RawResponse->{status});

    xlog "create a mailbox without any client-supplied creation ids";
    my $JMAPRequest = {
        using => ['urn:ietf:params:jmap:mail'],
        methodCalls => [['Mailbox/set', {
            create => {
                "1" => {
                    name => "foo",
                    parentId => undef,
                    role => undef
                }
            }
        }, "R1"]],
    };
    my $JMAPResponse = $jmap->Request($JMAPRequest);
    my $mboxid1 = $JMAPResponse->{methodResponses}->[0][1]{created}{1}{id};
    $self->assert_not_null($mboxid1);
    $self->assert_null($JMAPResponse->{createdIds});

    xlog "get mailbox using client-supplied creation id";
    $JMAPRequest = {
        using => ['urn:ietf:params:jmap:mail'],
        methodCalls => [['Mailbox/get', { ids => ['#1'] }, 'R1']],
        createdIds => { 1 => $mboxid1 },
    };
    $JMAPResponse = $jmap->Request($JMAPRequest);
    $self->assert_str_equals($mboxid1, $JMAPResponse->{methodResponses}->[0][1]{list}[0]{id});
    $self->assert_not_null($JMAPResponse->{createdIds});

    xlog "create a mailbox with empty client-supplied creation ids";
    $JMAPRequest = {
        using => ['urn:ietf:params:jmap:mail'],
        methodCalls => [['Mailbox/set', {
            create => {
                "2" => {
                    name => "bar",
                    parentId => undef,
                    role => undef
                }
            }
        }, "R1"]],
        createdIds => {},
    };
    $JMAPResponse = $jmap->Request($JMAPRequest);
    my $mboxid2 = $JMAPResponse->{methodResponses}->[0][1]{created}{2}{id};
    $self->assert_str_equals($mboxid2, $JMAPResponse->{createdIds}{2});
}

sub test_echo
    :min_version_3_1 :needs_component_jmap
{

    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $req = {
        hello => JSON::true,
        max => 5,
        stuff => { foo => "bar", empty => JSON::null }
    };

    xlog "send ping";
    my $res = $jmap->CallMethods([['Core/echo', $req, "R1"]]);

    xlog "check pong";
    $self->assert_not_null($res);
    $self->assert_str_equals('Core/echo', $res->[0][0]);
    $self->assert_deep_equals($req, $res->[0][1]);
    $self->assert_str_equals('R1', $res->[0][2]);
}


1;
