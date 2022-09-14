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
use Mail::JMAPTalk 0.15;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Encode qw(decode_utf8);
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

sub test_capabilities
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    $self->{instance}->create_user("other");
    $admintalk->create("user.other.box1") or die;
    $admintalk->setacl("user.other.box1", "cassandane", "lrswp") or die;

    # Missing capability in 'using'
    my $res = $jmap->CallMethods([
        ['Core/echo', { hello => 'world' }, "R1"]
    ], []);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('unknownMethod', $res->[0][1]{type});

    # Missing capability in account capabilities
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            accountId => 'other'
        }, "R1"]
    ], [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:calendars',
        'https://cyrusimap.org/ns/jmap/calendars',
    ]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('accountNotSupportedByMethod', $res->[0][1]{type});
}

sub test_get_session
    :min_version_3_1 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;

    # need to version-gate jmap features that aren't in 3.2...
    my ($maj, $min) = Cassandane::Instance->get_version();

    my $buildinfo = Cassandane::BuildInfo->new();

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "setup shared accounts";
    $self->{instance}->create_user("account1");
    $self->{instance}->create_user("account2");
    $self->{instance}->create_user("account3");
    $self->{instance}->create_user("account4");

    # Account 1: read-only mail, calendars. No contacts.
    my $httpService = $self->{instance}->get_service("http");
    my $account1CalDAVTalk = Net::CalDAVTalk->new(
        user => "account1",
        password => 'pass',
        host => $httpService->host(),
        port => $httpService->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
    my $account1CalendarId = $account1CalDAVTalk->NewCalendar({name => 'calendar1'});
    $admintalk->setacl("user.account1", "cassandane", "lr") or die;
    $admintalk->setacl("user.account1.#calendars.Default", "cassandane" => 'lr') or die;
    $admintalk->setacl("user.account1.#addressbooks.Default", "cassandane" => '') or die;
    # Account 2: read/write mail
    $admintalk->setacl("user.account2", "cassandane", "lrswipkxtecdn") or die;
    # Account 3: no access

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

    # Validate session
    $self->assert_not_null($session->{username});
    $self->assert_not_null($session->{apiUrl});
    $self->assert_not_null($session->{downloadUrl});
    $self->assert_not_null($session->{uploadUrl});
    if ($maj > 3 || ($maj == 3 && $min >= 3)) {
        $self->assert_not_null($session->{eventSourceUrl});
    }
    $self->assert_not_null($session->{state});

    # Validate server capabilities
    my $capabilities = $session->{capabilities};
    $self->assert_not_null($capabilities);
    my $coreCapability = $capabilities->{'urn:ietf:params:jmap:core'};
    $self->assert_not_null($coreCapability);
    $self->assert($coreCapability->{maxSizeUpload} > 0);
    $self->assert($coreCapability->{maxConcurrentUpload} > 0);
    $self->assert($coreCapability->{maxSizeRequest} > 0);
    $self->assert($coreCapability->{maxConcurrentRequests} > 0);
    $self->assert($coreCapability->{maxCallsInRequest} > 0);
    $self->assert($coreCapability->{maxObjectsInGet} > 0);
    $self->assert($coreCapability->{maxObjectsInSet} > 0);
    $self->assert(exists $coreCapability->{collationAlgorithms});
    $self->assert_deep_equals({}, $capabilities->{'urn:ietf:params:jmap:mail'});
    $self->assert_deep_equals({}, $capabilities->{'urn:ietf:params:jmap:submission'});
    $self->assert_deep_equals({}, $capabilities->{'urn:ietf:params:jmap:calendars'});
    $self->assert_deep_equals({}, $capabilities->{'https://cyrusimap.org/ns/jmap/contacts'});
    $self->assert_deep_equals({ isRFC => JSON::true },
        , $capabilities->{'https://cyrusimap.org/ns/jmap/calendars'});
    if ($buildinfo->get('component', 'sieve')) {
        $self->assert_deep_equals({}, $capabilities->{'urn:ietf:params:jmap:vacationresponse'});
        if ($maj > 3 || ($maj == 3 && $min >= 3)) {
            # jmap sieve added in 3.3
            $self->assert_deep_equals({}, $capabilities->{'https://cyrusimap.org/ns/jmap/sieve'});
        }
    }

    # primaryAccounts
    my $expect_primaryAccounts = {
        'urn:ietf:params:jmap:mail' => 'cassandane',
        'urn:ietf:params:jmap:submission' => 'cassandane',
        'urn:ietf:params:jmap:calendars' => 'cassandane',
        'urn:ietf:params:jmap:principals' => 'cassandane',
        'https://cyrusimap.org/ns/jmap/contacts' => 'cassandane',
        'https://cyrusimap.org/ns/jmap/calendars' => 'cassandane',
    };
    if ($maj > 3 || ($maj == 3 && $min >= 3)) {
        # jmap backup and sieve added in 3.3
        $expect_primaryAccounts->{'https://cyrusimap.org/ns/jmap/backup'}
            = 'cassandane';
    }
    if ($buildinfo->get('component', 'sieve')) {
        $expect_primaryAccounts->{'urn:ietf:params:jmap:vacationresponse'}
            = 'cassandane';
        if ($maj > 3 || ($maj == 3 && $min >= 3)) {
            # jmap sieve added in 3.3
            $expect_primaryAccounts->{'https://cyrusimap.org/ns/jmap/sieve'}
            = 'cassandane';
        }
    }
    $self->assert_deep_equals($expect_primaryAccounts,
                              $session->{primaryAccounts});

    $self->assert_num_equals(3, scalar keys %{$session->{accounts}});
    $self->assert_not_null($session->{accounts}{cassandane});

    my $primaryAccount = $session->{accounts}{cassandane};
    $self->assert_not_null($primaryAccount);
    my $account1 = $session->{accounts}{account1};
    $self->assert_not_null($account1);
    my $account2 = $session->{accounts}{account2};
    $self->assert_not_null($account2);

    $self->assert_str_equals('cassandane', $primaryAccount->{name});
    $self->assert_equals(JSON::false, $primaryAccount->{isReadOnly});
    $self->assert_equals(JSON::true, $primaryAccount->{isPersonal});
    my $accountCapabilities = $primaryAccount->{accountCapabilities};
    $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:mail'});
    $self->assert_equals(JSON::true, $accountCapabilities->{'urn:ietf:params:jmap:mail'}{mayCreateTopLevelMailbox});
    $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:submission'});
    if ($buildinfo->get('component', 'sieve')) {
        $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:vacationresponse'});
    }
    $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:calendars'});
    $self->assert_not_null($accountCapabilities->{'https://cyrusimap.org/ns/jmap/contacts'});
    $self->assert_not_null($accountCapabilities->{'https://cyrusimap.org/ns/jmap/calendars'});

    # Account 1: read-only mail, calendars. No contacts.
    $self->assert_str_equals('account1', $account1->{name});
    $self->assert_equals(JSON::true, $account1->{isReadOnly});
    $self->assert_equals(JSON::false, $account1->{isPersonal});
    $accountCapabilities = $account1->{accountCapabilities};
    $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:mail'});
    $self->assert_equals(JSON::false, $accountCapabilities->{'urn:ietf:params:jmap:mail'}{mayCreateTopLevelMailbox});
    $self->assert_null($accountCapabilities->{'urn:ietf:params:jmap:submission'});
    if ($buildinfo->get('component', 'sieve')) {
        $self->assert_null($accountCapabilities->{'urn:ietf:params:jmap:vacationresponse'});
    }
    $self->assert_null($accountCapabilities->{'https://cyrusimap.org/ns/jmap/contacts'});
    $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:calendars'});
    $self->assert_not_null($accountCapabilities->{'https://cyrusimap.org/ns/jmap/calendars'});

    # Account 2: read/write mail
    $self->assert_str_equals('account2', $account2->{name});
    $self->assert_equals(JSON::false, $account2->{isReadOnly});
    $self->assert_equals(JSON::false, $account2->{isPersonal});
    $accountCapabilities = $account2->{accountCapabilities};
    $self->assert_not_null($accountCapabilities->{'urn:ietf:params:jmap:mail'});
    $self->assert_equals(JSON::true, $accountCapabilities->{'urn:ietf:params:jmap:mail'}{mayCreateTopLevelMailbox});
    $self->assert_null($accountCapabilities->{'urn:ietf:params:jmap:submission'});
    if ($buildinfo->get('component', 'sieve')) {
        $self->assert_null($accountCapabilities->{'urn:ietf:params:jmap:vacationresponse'});
    }
    $self->assert_null($accountCapabilities->{'urn:ietf:params:jmap:calendars'});
    $self->assert_null($accountCapabilities->{'https://cyrusimap.org/ns/jmap/contacts'});
    $self->assert_null($accountCapabilities->{'https://cyrusimap.org/ns/jmap/calendars'});
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

sub test_blob_download_name
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $data = $jmap->Upload("some test", "text/plain");

    my $resp = $jmap->Download('cassandane', $data->{blobId}, 'foo');
    $self->assert_str_equals('attachment; filename="foo"',
        $resp->{headers}{'content-disposition'});

    $resp = $jmap->Download('cassandane', $data->{blobId}, decode_utf8('тест.txt'));
    $self->assert_str_equals("attachment; filename*=utf-8''%D1%82%D0%B5%D1%81%D1%82.txt",
        $resp->{headers}{'content-disposition'});
}

sub test_created_ids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "send bogus creation ids map";
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

    xlog $self, "create a mailbox without any client-supplied creation ids";
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

    xlog $self, "get mailbox using client-supplied creation id";
    $JMAPRequest = {
        using => ['urn:ietf:params:jmap:mail'],
        methodCalls => [['Mailbox/get', { ids => ['#1'] }, 'R1']],
        createdIds => { 1 => $mboxid1 },
    };
    $JMAPResponse = $jmap->Request($JMAPRequest);
    $self->assert_str_equals($mboxid1, $JMAPResponse->{methodResponses}->[0][1]{list}[0]{id});
    $self->assert_not_null($JMAPResponse->{createdIds});
    $self->assert_str_equals($mboxid1, $JMAPResponse->{createdIds}{1});

    xlog $self, "create a mailbox with empty client-supplied creation ids";
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

    xlog $self, "create a mailbox with client-supplied creation ids";
    $JMAPRequest = {
        using => ['urn:ietf:params:jmap:mail'],
        methodCalls => [['Mailbox/set', {
            create => {
                "3" => {
                    name => "baz",
                    parentId => "#2",
                    role => undef
                }
            }
        }, "R1"]],
        createdIds => {
            1 => $mboxid1,
            2 => $mboxid2,
        },
    };
    $JMAPResponse = $jmap->Request($JMAPRequest);
    my $mboxid3 = $JMAPResponse->{methodResponses}->[0][1]{created}{3}{id};
    $self->assert_str_equals($mboxid1, $JMAPResponse->{createdIds}{1});
    $self->assert_str_equals($mboxid2, $JMAPResponse->{createdIds}{2});
    $self->assert_str_equals($mboxid3, $JMAPResponse->{createdIds}{3});

    xlog $self, "get mailbox and check parentid";
    $JMAPRequest = {
        using => ['urn:ietf:params:jmap:mail'],
        methodCalls => [['Mailbox/get', { ids => [$mboxid3], properties => ['parentId'] }, 'R1']],
    };
    $JMAPResponse = $jmap->Request($JMAPRequest);
    $self->assert_str_equals($mboxid3, $JMAPResponse->{methodResponses}->[0][1]{list}[0]{id});
    $self->assert_str_equals($mboxid2, $JMAPResponse->{methodResponses}->[0][1]{list}[0]{parentId});
    $self->assert_null($JMAPResponse->{createdIds});
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

    xlog $self, "send ping";
    my $res = $jmap->CallMethods([['Core/echo', $req, "R1"]]);

    xlog $self, "check pong";
    $self->assert_not_null($res);
    $self->assert_str_equals('Core/echo', $res->[0][0]);
    $self->assert_deep_equals($req, $res->[0][1]);
    $self->assert_str_equals('R1', $res->[0][2]);
}

sub test_identity_get
    :min_version_3_1 :needs_component_jmap
{

    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:submission',
    ];

    my $res = $jmap->CallMethods([
        ['Identity/get', { }, 'R1'],
        ['Identity/get', { ids => undef }, 'R2'],
        ['Identity/get', { ids => [] }, 'R3'],
    ], $using);

    $self->assert_str_equals('Identity/get', $res->[0][0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals('cassandane', $res->[0][1]{list}[0]{id});
    $self->assert_not_null($res->[0][1]->{state});
    $self->assert_str_equals('R1', $res->[0][2]);

    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals('cassandane', $res->[1][1]{list}[0]{id});
    $self->assert_not_null($res->[1][1]->{state});

    $self->assert_deep_equals([], $res->[2][1]{list});
    $self->assert_not_null($res->[2][1]->{state});
}

sub test_sessionstate
    :min_version_3_1 :needs_component_jmap :ReverseACLs
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    $self->{instance}->create_user("other");

    # Fetch sessionState
    my $JMAPRequest = {
        using => ['urn:ietf:params:jmap:core'],
        methodCalls => [['Core/echo', { }, 'R1']],
    };
    my $JMAPResponse = $jmap->Request($JMAPRequest);
    $self->assert_not_null($JMAPResponse->{sessionState});
    my $sessionState = $JMAPResponse->{sessionState};

    # Update ACL
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Fetch sessionState
    $JMAPResponse = $jmap->Request($JMAPRequest);
    $self->assert_str_not_equals($sessionState, $JMAPResponse->{sessionState});
    $sessionState = $JMAPResponse->{sessionState};

    # Update ACL
    $admintalk->setacl("user.other", "cassandane", "") or die;

    # Fetch sessionState
    $JMAPResponse = $jmap->Request($JMAPRequest);
    $self->assert_str_not_equals($sessionState, $JMAPResponse->{sessionState});
    $sessionState = $JMAPResponse->{sessionState};
}

sub test_using_unknown_capability
    :min_version_3_1 :needs_component_jmap
{

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $RawRequest = {
        headers => {
            'Authorization' => $jmap->auth_header(),
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        },
        content => encode_json({
            using => [
                'urn:ietf:params:jmap:core',
                'urn:foo' # Unknown capability
            ],
            methodCalls => [['Core/echo', { hello => JSON::true }, 'R1']],
        }),
    };
    my $RawResponse = $jmap->ua->post($jmap->uri(), $RawRequest);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawRequest, $RawResponse);
    }
    $self->assert_str_equals('400', $RawResponse->{status});

    my $Response = eval { decode_json($RawResponse->{content}) };
    $self->assert_str_equals('urn:ietf:params:jmap:error:unknownCapability', $Response->{type});
}

sub test_require_conversations
    :min_version_3_1 :needs_component_jmap :NoStartInstances
{
    my ($self) = @_;

    my $instance = $self->{instance};
    $instance->{config}->set(conversations => 'no');

    $self->_start_instances();
    $self->_setup_http_service_objects();

    my $jmap = $self->{jmap};
    my $JMAPRequest = {
        using => ['urn:ietf:params:jmap:core'],
        methodCalls => [['Core/echo', { }, 'R1']],
    };

    # request should fail
    my ($response, undef) = $jmap->Request($JMAPRequest);
    $self->assert(not $response->{success});

    if ($self->{instance}->{have_syslog_replacement}) {
        # httpd should syslog an error
        my @syslog = $self->{instance}->getsyslog();
        $self->assert_matches(
            qr/ERROR: cannot enable \w+ module with conversations disabled/,
            "@syslog"
        );
    }
}

sub test_eventsource
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $http = $self->{instance}->get_service("http");

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
    my $url = $session->{eventSourceUrl};
    $self->assert_not_null($url);

    $self->assert_num_equals(1, $url =~ s/\{types\}/Email/g);
    $self->assert_num_equals(1, $url =~ s/\{closeafter\}/state/g);
    $self->assert_num_equals(1, $url =~ s/\{ping\}/0/g);

    if (not $url =~ /^http/) {
        $url = "http://".$http->host().":".$http->port().$url;
    }

    $RawRequest->{headers}->{'Last-Event-Id'} = '0';
    $RawResponse = $jmap->ua->get($url, $RawRequest);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawRequest, $RawResponse);
    }
    $self->assert_str_equals('200', $RawResponse->{status});
    $self->assert_str_equals('text/event-stream',
                             $RawResponse->{headers}{'content-type'});
    $self->assert_null($RawResponse->{headers}{'content-length'});

    my %event = $RawResponse->{content} =~ /^(\w+): ?(.*)$/mg;
    $self->assert_not_null($event{id});
    $self->assert_str_equals('state', $event{event});

    my $data = eval { decode_json($event{data}) };
    $self->assert_not_null($data);
    $self->assert_str_equals('StateChange', $data->{'@type'});
    $self->assert_not_null($data->{changed});
    $self->assert_not_null($data->{changed}->{cassandane});
    $self->assert_not_null($data->{changed}->{cassandane}->{Email});
}

sub test_bearer_auth_jwt
    :min_version_3_5 :needs_component_jmap :NoAltNameSpace :HttpJWTAuthRSA
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $http = $self->{instance}->get_service("http");

    my $token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYXNzYW5kYW5lIn0.Eoa-9imqmFVYKU19yMaHZGEwiOWE3rSKQDw598rZYJvLqjrF8bG2fvMAUB6VeXxoJLca-uXAtTNHKBWYye9uvzTO3e8VMQOHHIb2RbBVyC7UxUEkbN8KC8YVrMNQoJDuugxeANKSrbmL8l6AtGEBK8iCoBnedleCzQ-nE7KtnwD356F63teK6jIoGW9KI0zNIeTe1k5Wh6NM3hZKC12mfU2JsOHTes-XH8lig2RQraBmdR1t9EKMTVztq-hXiVxvYtc3eIghdz5Ss52qr3VaCJJXExOXbnp0LwbUNUOFn1GCPfhRyEZdQxhGV19cO-RceIV1aawZnegdQS_kWERQNg";

    xlog "Use valid RS256 token";
    my $RawRequest = {
        headers => {
            'Authorization' => 'Bearer ' . $token,
        },
        content => '',
    };
    my $RawResponse = $jmap->ua->get($jmap->uri(), $RawRequest);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawRequest, $RawResponse);
    }
    $self->assert_str_equals('200', $RawResponse->{status});

    xlog "Use invalid RS256 token";
    $RawRequest = {
        headers => {
            'Authorization' => 'Bearer ' . substr $token, 0, -3
        },
        content => '',
    };
    $RawResponse = $jmap->ua->get($jmap->uri(), $RawRequest);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($RawRequest, $RawResponse);
    }
    $self->assert_str_equals('401', $RawResponse->{status});
}

sub test_blob_set_basic
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my $self = shift;
    my $instance = $self->{instance};

    xlog "Test without capability";
    my $jmap = $self->{jmap};
    my $res = $jmap->CallMethods([['Blob/upload', { create => { b1 => { data => [{'data:asText' => 'hello world'}] } } }, 'R1']]);
    $self->assert_str_equals($res->[0][0], 'error');

    # XXX: this will be replaced with the upstream one
    $jmap->AddUsing('https://cyrusimap.org/ns/jmap/blob');

    xlog "Regular Blob/upload works and returns a blobId";
    $res = $jmap->CallMethods([['Blob/upload', { create => { b1 => { data => [{'data:asText' => 'hello world'}] } } }, 'R1']]);
    $self->assert_str_equals('Blob/upload', $res->[0][0]);
    $self->assert_not_null($res->[0][1]{created}{b1}{id});
}

sub test_blob_lookup
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my $self = shift;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A plain text email.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get emails";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobId = $msg->{textBody}[0]{blobId};
    $self->assert_not_null($blobId);
    my $emailId = $msg->{id};
    $self->assert_not_null($emailId);
    my $threadId = $msg->{threadId};
    $self->assert_not_null($threadId);
    my $mailboxIds = $msg->{mailboxIds};
    my ($mailboxId) = keys %$mailboxIds;
    $self->assert_not_null($mailboxId);

    xlog "Test without capability";
    $res = $jmap->CallMethods([['Blob/lookup', { ids => [$blobId, 'unknown'], typeNames => ['Mailbox', 'Thread', 'Email'] }, 'R1']]);
    $self->assert_str_equals($res->[0][0], 'error');

    # XXX: this will be replaced with the upstream one
    $jmap->AddUsing('https://cyrusimap.org/ns/jmap/blob');

    xlog "Regular Blob/lookup works";
    $res = $jmap->CallMethods([['Blob/lookup', { ids => [$blobId, 'unknown'], typeNames => ['Mailbox', 'Thread', 'Email'] }, 'R1']]);
    $self->assert_str_equals($res->[0][0], 'Blob/lookup');
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals($blobId, $res->[0][1]{list}[0]{id});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}[0]{matchedIds}{Mailbox}});
    $self->assert_str_equals($mailboxId, $res->[0][1]{list}[0]{matchedIds}{Mailbox}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}[0]{matchedIds}{Thread}});
    $self->assert_str_equals($threadId, $res->[0][1]{list}[0]{matchedIds}{Thread}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}[0]{matchedIds}{Email}});
    $self->assert_str_equals($emailId, $res->[0][1]{list}[0]{matchedIds}{Email}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{notFound}});
    $self->assert_str_equals('unknown', $res->[0][1]{notFound}[0]);
}

sub test_blob_get
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my $self = shift;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A plain text email.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get emails";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobId = $msg->{textBody}[0]{blobId};
    $self->assert_not_null($blobId);

    xlog "Test without capability";
    $res = $jmap->CallMethods([['Blob/get', { ids => [$blobId], properties => [ 'data:asText', 'size' ] }, 'R1']]);
    $self->assert_str_equals($res->[0][0], 'error');

    # XXX: this will be replaced with the upstream one
    $jmap->AddUsing('https://cyrusimap.org/ns/jmap/blob');

    xlog "Regular Blob/get works and returns a blobId";
    $res = $jmap->CallMethods([['Blob/get', { ids => [$blobId], properties => [ 'data:asText', 'data:asBase64', 'size' ] }, 'R1']]);
    $self->assert_str_equals($res->[0][0], 'Blob/get');
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals($blobId, $res->[0][1]{list}[0]{id});
    $self->assert_str_equals($body, $res->[0][1]{list}[0]{'data:asText'});
    $self->assert_str_equals(encode_base64($body, ''), $res->[0][1]{list}[0]{'data:asBase64'});
    $self->assert_num_equals(length($body), $res->[0][1]{list}[0]{'size'});
}

sub test_blob_set_complex
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my $self = shift;
    my $jmap = $self->{jmap};

    # XXX: this will be replaced with the upstream one
    $jmap->AddUsing('https://cyrusimap.org/ns/jmap/blob');

    my $data = "The quick brown fox jumped over the lazy dog.";
    my $bdata = encode_base64($data, '');

    my $res;

    xlog "Regular Blob/upload works and returns the right data";
    $res = $jmap->CallMethods([
      ['Blob/upload', { create => { b1 => { data => [{'data:asText' => $data}] } } }, 'S1'],
      ['Blob/get', { ids => ['#b1'], properties => [ 'data:asText', 'size' ] }, 'G1'],
    ]);
    $self->assert_str_equals('Blob/upload', $res->[0][0]);
    $self->assert_str_equals('Blob/get', $res->[1][0]);
    $self->assert_str_equals($data, $res->[1][1]{list}[0]{'data:asText'});
    $self->assert_num_equals(length $data, $res->[1][1]{list}[0]{size});

    xlog "Base64 Blob/upload works and returns the right data";
    $res = $jmap->CallMethods([
      ['Blob/upload', { create => { b2 => { data => [{'data:asBase64' => $bdata}] } } }, 'S2'],
      ['Blob/get', { ids => ['#b2'], properties => [ 'data:asText', 'size', 'digest:sha' ] }, 'G2'],
      ['Blob/get', { ids => ['#b2'], offset => 4, length => 9, properties => [ 'data:asText', 'size', 'digest:sha', 'digest:sha-256' ] }, 'G2'],

    ]);
    $self->assert_str_equals('Blob/upload', $res->[0][0]);
    $self->assert_str_equals('Blob/get', $res->[1][0]);
    $self->assert_str_equals($data, $res->[1][1]{list}[0]{'data:asText'});
    $self->assert_num_equals(length $data, $res->[1][1]{list}[0]{size});
    $self->assert_str_equals("quick bro", $res->[2][1]{list}[0]{'data:asText'});
    $self->assert_str_equals("QiRAPtfyX8K6tm1iOAtZ87Xj3Ww=", $res->[2][1]{list}[0]{'digest:sha'});
    $self->assert_str_equals("gdg9INW7lwHK6OQ9u0dwDz2ZY/gubi0En0xlFpKt0OA=", $res->[2][1]{list}[0]{'digest:sha-256'});

    xlog "Complex expression works and returns the right data";
    my $target = "How quick was that?";
    $res = $jmap->CallMethods([
      ['Blob/upload', { create => { b4 => { data => [{'data:asText' => $data}] } } }, 'S4'],
      ['Blob/upload', { create => { mult => { data => [
        { 'data:asText' => 'How' },                      # 'How'
        { 'blobId' => '#b4', offset => 3, length => 7 }, # ' quick '
        { 'data:asText' => "was t" },                    # 'was t'
        { 'blobId' => '#b4', offset => 1, length => 1 }, # 'h'
        { 'data:asBase64' => encode_base64('at?', '') }, # 'at?'
      ] } } }, 'CAT'],
      ['Blob/get', { ids => ['#mult'], properties => [ 'data:asText', 'size' ] }, 'G4'],
    ]);
    $self->assert_str_equals('Blob/upload', $res->[0][0]);
    $self->assert_str_equals('Blob/upload', $res->[1][0]);
    $self->assert_str_equals('Blob/get', $res->[2][0]);
    $self->assert_str_equals($target, $res->[2][1]{list}[0]{'data:asText'});
    $self->assert_num_equals(length $target, $res->[2][1]{list}[0]{size});
}

sub test_blob_upload_repair_acl
    :min_version_3_7 :needs_component_jmap :JMAPExtensions
{
    my $self = shift;
    my $jmap = $self->{jmap};
    my $admin = $self->{adminstore}->get_client();

    $jmap->Upload("hello", "application/data");

    my $file = abs_path('data/mime/repair_acl.eml');
    open(my $fh, '<', $file);
    local $/;
    my $binary = <$fh>;
    close($fh);

    xlog "Assert that uploading duplicates does not fail";
    $admin->setacl("user.cassandane.#jmap", "cassandane", "lrswkcni") or die;
    my $res = $jmap->Upload($binary);
    my $blobId = $res->{blobId};
    $res = $jmap->Upload($binary, "message/rfc822");
    $self->assert_str_equals($blobId, $res->{blobId});

    xlog "Assert ACLs got repaired";
    my %acl = @{$admin->getacl("user.cassandane.#jmap")};
    $self->assert_str_equals("lrswitedn", $acl{cassandane});
}

sub test_blob_upload_type
    :min_version_3_7 :needs_component_jmap :JMAPExtensions
{
    my $self = shift;
    my $jmap = $self->{jmap};

    xlog "Assert client-supplied type is returned";
    my $res = $jmap->Upload("blob1", "text/plain");
    $self->assert_str_equals("text/plain", $res->{type});

    xlog "Assert client-supplied type is normalized";
    $res = $jmap->Upload("blob1", "text/plain;charset=latin1");
    $self->assert_str_equals("text/plain", $res->{type});

    xlog "Assert default server type";
    my $httpReq = {
        headers => {
            'Authorization' => $jmap->auth_header(),
        },
        content => 'blob2',
    };
    my $httpRes = $jmap->ua->post($jmap->uploaduri('cassandane'), $httpReq);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($httpReq, $httpRes);
    }
    $res = eval { decode_json($httpRes->{content}) };
    $self->assert_str_equals("application/octet-stream", $res->{type});
}

1;
