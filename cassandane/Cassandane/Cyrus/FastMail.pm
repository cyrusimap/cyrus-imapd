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

package Cassandane::Cyrus::FastMail;
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

our $RNUM = 1;

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

sub _fmjmap_req
{
    my ($self, $cmd, %args) = @_;
    my $jmap = $self->{jmap};

    my $rnum = "R" . $RNUM++;
    my $res = $jmap->Request({methodCalls => [[$cmd, \%args, $rnum]], using => ["ietf:jmap"]});
    my $res1 = $res->{methodResponses}[0];
    $self->assert_not_null($res1);
    $self->assert_str_equals($rnum, $res1->[2]);
    return $res1;
}

sub _fmjmap_ok
{
    my ($self, $cmd, %args) = @_;
    my $res = $self->_fmjmap_req($cmd, %args);
    $self->assert_str_equals($cmd, $res->[0]);
    return $res->[1];
}

sub _fmjmap_err
{
    my ($self, $cmd, %args) = @_;
    my $res = $self->_fmjmap_req($cmd, %args);
    $self->assert_str_equals($res->[0], "error");
    return $res->[1];
}

sub test_ajaxui_jmapcontacts_contactgroup_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $service = $self->{instance}->get_service("http");

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.masteruser");
    $admintalk->setacl("user.masteruser", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.masteruser", masteruser => 'lrswipkxtecdn');
    $admintalk->create("user.masteruser.#addressbooks.Default");
    $admintalk->create("user.masteruser.#addressbooks.Shared");
    $admintalk->setacl("user.masteruser.#addressbooks.Default", "cassandane" => 'lrswipkxtecdn') or die;
    $admintalk->setacl("user.masteruser.#addressbooks.Shared", "cassandane" => 'lrswipkxtecdn') or die;

    my $mastertalk = Net::CardDAVTalk->new(
        user => "masteruser",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    xlog "create contact group";
    my $res = $self->_fmjmap_ok('ContactGroup/set',
        create => {
            "k2519" => {
                name => "personal group",
                addressbookId => 'Default',
                contactIds => [],
                otherAccountContactIds => {
                    masteruser => [],
                },
            },
        },
        update => {},
        destroy => [],
    );
    my $groupid = $res->{created}{"k2519"};
    $self->assert_not_null($groupid);

}

1;
