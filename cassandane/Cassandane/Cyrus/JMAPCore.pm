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
use Mail::JMAPTalk 0.10;
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

sub test_settings
    :JMAP :min_version_3_1
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
    $self->assert_str_equals('201', $Response->{status});

    my $settings;
    $settings = eval { decode_json($Response->{content}) } if $Response->{success};

    $self->assert_not_null($settings->{username});
    $self->assert_not_null($settings->{accounts});
    $self->assert_not_null($settings->{apiUrl});
    $self->assert_not_null($settings->{downloadUrl});
    $self->assert_not_null($settings->{uploadUrl});
    $self->assert(exists $settings->{capabilities}->{"ietf:jmap"});
    $self->assert(exists $settings->{capabilities}->{"ietf:jmapmail"});

    my $cap = $settings->{capabilities}->{"ietf:jmap"};
    $self->assert($cap->{maxSizeUpload} > 0);
    $self->assert($cap->{maxConcurrentUpload} > 0);
    $self->assert($cap->{maxSizeRequest} > 0);
    $self->assert($cap->{maxConcurrentRequests} > 0);
    $self->assert($cap->{maxCallsInRequest} > 0);
    $self->assert($cap->{maxObjectsInGet} > 0);
    $self->assert($cap->{maxObjectsInSet} > 0);

    my $acc;
	my $accounts =  $settings->{accounts};
    $self->assert_num_equals(4, scalar keys %{$accounts});

    $acc = $accounts->{cassandane};
    $self->assert_str_equals("cassandane", $acc->{name});
    $self->assert_equals(JSON::true, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
    $self->assert_num_equals(1, scalar @{$acc->{hasDataFor}});
    $self->assert_str_equals('mail', $acc->{hasDataFor}[0]);

    $acc = $accounts->{foo};
    $self->assert_str_equals("foo", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::true, $acc->{isReadOnly});
    $self->assert_num_equals(1, scalar @{$acc->{hasDataFor}});
    $self->assert_str_equals('mail', $acc->{hasDataFor}[0]);

    $acc = $accounts->{bar};
    $self->assert_str_equals("bar", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
    $self->assert_num_equals(1, scalar @{$acc->{hasDataFor}});
    $self->assert_str_equals('mail', $acc->{hasDataFor}[0]);

    $acc = $accounts->{baz};
    $self->assert_str_equals("baz", $acc->{name});
    $self->assert_equals(JSON::false, $acc->{isPrimary});
    $self->assert_equals(JSON::false, $acc->{isReadOnly});
    $self->assert_num_equals(1, scalar @{$acc->{hasDataFor}});
    $self->assert_str_equals('mail', $acc->{hasDataFor}[0]);
}

1;
