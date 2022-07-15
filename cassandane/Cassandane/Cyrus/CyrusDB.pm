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
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;
use Cyrus::DList;

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

sub test_recover_uniqueid_from_header_legacymb
    :min_version_3_6 :MailboxLegacyDirs
{
    my ($self) = @_;
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';

    # first start will set up cassandane user
    $self->_start_instances();
    my $basedir = $self->{instance}->get_basedir();
    my $mailboxes_db = "$basedir/conf/mailboxes.db";
    $self->assert(-f $mailboxes_db, "$mailboxes_db not present");

    # find out the uniqueid of the inbox
    my $imaptalk = $self->{store}->get_client();
    my $res = $imaptalk->getmetadata("INBOX", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $uniqueid = $res->{INBOX}{$entry};
    xlog "XXX got uniqueid: " . Dumper \$uniqueid;
    $self->assert_not_null($uniqueid);
    $imaptalk->logout();
    undef $imaptalk;

    # stop service while tinkering
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # lose that uniqueid from mailboxes.db
    my $I = "I$uniqueid";
    my $N = "Nuser\x1fcassandane";
    $self->{instance}->run_dbcommand($mailboxes_db, "twoskip",
                                     [ 'DELETE', $I ]);
    my (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $N]);
    my $dlist = Cyrus::DList->parse_string($mbentry);
    my $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        [ 'SET', $N, $dlist->as_string() ]);

    my %updated = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip", ['SHOW']);
    xlog "updated mailboxes.db: " . Dumper \%updated;

    # bring service back up
    # ctl_cyrusdb -r should find and fix the missing uniqueid
    $self->{instance}->getsyslog();
    $self->{instance}->start();
    my $syslog = join(q{}, $self->{instance}->getsyslog());

    # should have still existed in cyrus.header
    $self->assert_does_not_match(
        qr{mailbox header had no uniqueid, creating one}, $syslog);

    # expect to find the log line
    $self->assert_matches(qr{mbentry had no uniqueid, setting from header},
                          $syslog);

    # should be the same uniqueid as before
    $imaptalk = $self->{store}->get_client();
    $res = $imaptalk->getmetadata("INBOX", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_str_equals($uniqueid, $res->{INBOX}{$entry});
}

1;
