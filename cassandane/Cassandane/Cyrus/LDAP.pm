#!/usr/bin/perl
#
#  Copyright (c) 2011-2018 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::LDAP;
use strict;
use warnings;
use Cwd qw(realpath);
use Data::Dumper;
use Net::LDAP::Server::Test;
use Net::LDAP::Entry;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(
        ldap_base => "o=cyrus",
        ldap_group_base => "ou=groups,o=cyrus",
        ldap_domain_base_dn => "ou=domains,o=cyrus",
        ldap_user_attribute => "uid",
        ldap_member_attribute => "member",
        ldap_sasl => "no",
        auth_mech => 'pts',
        pts_module => 'ldap',
        ptloader_sock => '@basedir@/conf/ptsock',
    );

    my $self = $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => [qw( imap ptloader )],
        start_instances => 0,
    }, @args);

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->SUPER::set_up();

    $self->{ldapport} = Cassandane::PortManager::alloc();

    $self->{instance}->{config}->set(
        ldap_uri => "ldap://localhost:$self->{ldapport}/",
    );

    # arrange for the fakeldapd to be started
    # XXX make this run as a DAEMON rather than a START
    $self->{instance}->add_start(
        name => 'fakeldapd',
        argv => [
            realpath('utils/fakeldapd'),
            '-p', $self->{ldapport},
            '-l', realpath('data/data.ldif'),
        ],
    );

    $self->_start_instances();
}

sub tear_down
{
    my ($self) = @_;

    $self->SUPER::tear_down();
}

sub test_aaasetup
    :needs_dependency_ldap
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.cassandane.groupid");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());

    $admintalk->setacl("user.cassandane.groupid",
                       "group:foo",
                       "lrswipkxtecdan");
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());
}

1;
