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

package Cassandane::Cyrus::JMAPAuth;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.07;
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
    return $class->SUPER::new({}, @args);
}

sub test_login
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "Request loginId";
    my $data = $jmap->AuthRequest({
       username => $jmap->{user},
       clientName => "client",
       clientVersion => "1",
       deviceName => "casstest",
    });
    $self->assert_not_null($data->{loginId});
    $self->assert_str_equals("password", $data->{methods}[0]->{type});

    xlog "Request access token";
    $data = $jmap->AuthRequest({
       loginId => $data->{loginId},
       type => "password",
       password => $jmap->{password},
    });
    $self->assert_not_null($data->{accessToken});
    $self->assert_str_equals($jmap->{user}, $data->{username});

    xlog "Validate primary account";
    my $acc = $data->{accounts}{$jmap->{user}};
    $self->assert_not_null($acc);
    $self->assert_not_null($acc->{name});
    $self->assert_equals(JSON::true, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});

    xlog "Set API url to $data->{apiUrl}";
    $jmap->{url} = $data->{apiUrl};

    xlog "Send some authenticated JMAP request";
    my $Request = {
      headers => {
        'Content-Type'  => "application/json",
        'Authorization' => "Bearer " . $data->{accessToken},
      },
      content => encode_json([['getMailboxes', {}, "R1"]]),
    };

    my $Response = $jmap->ua->post($jmap->uri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('200', $Response->{status});
}

sub test_revoke
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    xlog "log in";
    $jmap->Login($jmap->{user}, $jmap->{password}) || die;

    my $Request;
    my $Response;

    xlog "send some JMAP request";
    $Response = $jmap->Request([['getMailboxes', {}, "R1"]]);
    $self->assert_str_equals($Response->[0][0], 'mailboxes');

    xlog "revoke access token";
    $Request = {
        headers => {
            'Authorization' => "Bearer " . $jmap->{token},
        },
        content => '',
    };
    $Response = $jmap->ua->delete($jmap->authuri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('204', $Response->{status});

    xlog "send some JMAP request";
    $Request = {
      headers => {
        'Content-Type'  => "application/json",
        'Authorization' => "Bearer " . $jmap->{token},
      },
      content => encode_json([['getMailboxes', {}, "R1"]]),
    };
    $Response = $jmap->ua->post($jmap->uri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('401', $Response->{status});
}

sub test_settings
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    xlog "log in";
    $jmap->Login($jmap->{user}, $jmap->{password}) || die;

    my $Request;
    my $Response;

    xlog "get settings";
    $Request = {
        headers => {
            'Authorization' => "Bearer " . $jmap->{token},
        },
        content => '',
    };
    $Response = $jmap->ua->get($jmap->authuri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('201', $Response->{status});

    my $jdata;
    $jdata = eval { decode_json($Response->{content}) } if $Response->{success};

    $self->assert_not_null($jdata->{username});
    $self->assert_not_null($jdata->{accounts});
    $self->assert_not_null($jdata->{apiUrl});
    $self->assert_not_null($jdata->{downloadUrl});
    $self->assert_not_null($jdata->{uploadUrl});
}

sub test_login_wrongpass
    :JMAP :min_version_3_0
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    xlog "Request loginId";
    my $data = $jmap->AuthRequest({
       username => $jmap->{user},
       clientName => "client",
       clientVersion => "1",
       deviceName => "casstest",
    });
    $self->assert_not_null($data->{loginId});

    xlog "Request access token";
    my $res = $jmap->ua->post($jmap->authuri(), {
      headers => {
        'Content-Type'  => "application/json",
      },
      content => encode_json({
        loginId => $data->{loginId},
        type => "password",
        password => "bad",
      }),
    });
    $self->assert_str_equals('403', $res->{status});
}

sub test_multiple_accounts
    :JMAP :min_version_3_0
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
    # Make sure that isReadOnly is false if ANY mailbox is read-writeable
    $self->{instance}->create_user("baz");
    $admintalk->create("user.baz.box1") or die;
    $admintalk->create("user.baz.box2") or die;
    $admintalk->setacl("user.baz.box1", "cassandane", "lrswp") or die;
    $admintalk->setacl("user.baz.box2", "cassandane", "lr") or die;

    # no access to qux
    $self->{instance}->create_user("qux");

    xlog "log in";
    $jmap->Login($jmap->{user}, $jmap->{password}) || die;

    # refetch account settings
    my $Request;
    my $Response;

    xlog "get settings";
    $Request = {
        headers => {
            'Authorization' => "Bearer " . $jmap->{token},
        },
        content => '',
    };
    $Response = $jmap->ua->get($jmap->authuri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('201', $Response->{status});

    my $settings = eval { decode_json($Response->{content}) };
    my $accounts =  $settings->{accounts};
    $self->assert_num_equals(4, scalar keys %{$accounts});

    my $acc;

    $acc = $accounts->{cassandane};
    $self->assert_str_equals("cassandane", $acc->{name});
    $self->assert_equals(JSON::true, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});

    $acc = $accounts->{foo};
    $self->assert_str_equals("foo", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::true, $acc->{isReadOnly});

    $acc = $accounts->{bar};
    $self->assert_str_equals("bar", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});

    $acc = $accounts->{baz};
    $self->assert_str_equals("baz", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
}


1;
