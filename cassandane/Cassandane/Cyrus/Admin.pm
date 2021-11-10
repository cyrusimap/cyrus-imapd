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

package Cassandane::Cyrus::Admin;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config::default()->clone();
    $config->set( imap_admins => 'admin imapadmin' );
    return $class->SUPER::new({ config => $config, adminstore => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $imap = $self->{instance}->get_service('imap');
    $self->{imapadminstore} = $imap->create_store(username => 'imapadmin');
}

sub tear_down
{
    my ($self) = @_;

    $self->{imapadminstore}->disconnect();
    delete $self->{imapadminstore};

    $self->SUPER::tear_down();
}

sub test_imap_admins
{
    # test whether the imap_admins setting works correctly
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imapadmintalk = $self->{imapadminstore}->get_client();
    my $talk = $self->{store}->get_client();

    # we should be able to reconstruct as 'admin', because although
    # imap_admins overrides admins, we have 'admin' in imap_admins too
    # (it MUST be there for Cassandane itself to work)
    my $res = $admintalk->_imap_cmd("reconstruct" , 0, {}, "user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # we should not be able to reconstruct as 'cassandane', because
    # reconstruct is an admin-only command
    $res = $talk->_imap_cmd("reconstruct", 0, {}, "user.cassandane");
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    # we should be able to reconstruct as 'imapadmin', because this user
    # is in imap_admins
    $res = $imapadmintalk->_imap_cmd("reconstruct", 0, {}, "user.cassandane");
    $self->assert_str_equals('ok', $imapadmintalk->get_last_completion_response());
}

1;
