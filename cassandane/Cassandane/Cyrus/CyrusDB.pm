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

package Cassandane::Cyrus::CyrusDB;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ start_instances => 0 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

# Some databases aren't created automatically during a minimal
# startup on a new install, so run some commands such that they
# become extant.
sub _force_db_creations
{
    my ($self) = @_;

    # create a backups.db -- but only if backups are compiled in!
    eval {
        $self->{instance}->_find_binary('ctl_backups');

        xlog $self, "autovivify a backups.db";
        $self->{instance}->run_command({
            cyrus => 1,
        }, 'ctl_backups', 'list');
    };
}

sub test_alternate_quotadb_path
{
    my ($self) = @_;

    my $quota_db_path = $self->{instance}->get_basedir()
                        . '/conf/non-default-quotas.db';

    $self->{instance}->{config}->set(quota_db => 'twoskip');
    $self->{instance}->{config}->set(quota_db_path => $quota_db_path);
    $self->{instance}->start();

    $self->_force_db_creations();

    # Check that ctl_cyrusdb -c (checkpoint) uses correct db filename.
    # If it mistakenly tries to use the default filename, it will error
    # out due to it not existing.
    eval {
        $self->{instance}->run_command({
            cyrus => 1,
        }, 'ctl_cyrusdb', '-c');
    };
    $self->assert(not $@);

    # TODO more/better checks
}

sub test_mboxlistdb_skiplist
{
    my ($self) = @_;

    $self->{instance}->{config}->set(mboxlist_db => 'skiplist');
    $self->{instance}->start();

    # 'ctl_cyrusdb -r' will run on startup, and it should not crash!
}

1;
