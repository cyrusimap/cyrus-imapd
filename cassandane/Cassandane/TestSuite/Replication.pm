# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::Replication;
use strict;
use warnings;
use Data::Dumper;
use DateTime;

use Cyrus::DList;

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::CRLF;
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Util::Wait;
use Cassandane::Service;
use Cassandane::Config;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new({ replica => 1, adminstore => 1 }, @_);

    $self->needs('component', 'replication');
    return $self;
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

# XXX need a test for version 10 mailbox without guids in it!

#* create mailbox on master with no messages
#* sync_client to get it copied to replica
#* create a message in the mailbox on replica (imaptalk on replica_store)
#* delete the message from the replica (with expunge_mode default or expunge_mode immediate... try both)
#* run sync_client on the master again and make sure it successfully syncs up

sub assert_user_sub_exists
{
    my ($self, $instance, $user) = @_;

    my $subs = $instance->get_conf_user_file($user, 'sub');
    $self->assert_not_null($subs);

    xlog $self, "Looking for subscriptions file $subs";

    $self->assert_file_test($subs, '-f');
}

sub assert_user_sub_not_exists
{
    my ($self, $instance, $user) = @_;

    my $subs = $instance->get_conf_user_file($user, 'sub');
    return unless $subs;  # user might not exist

    xlog $self, "Looking for subscriptions file $subs";

    $self->assert_not_file_test($subs, '-f');
}

sub imap_getusergroup
{
    my ($self, $talk, $item) = @_;

    my $usergroups = {};
    my $handlers = {
        'usergroup' => sub {
            my (undef, $response) = @_;

            my %ug = @{$response};
            while (my ($user, $groups) = each %ug) {
                $usergroups->{$user} = { map { $_ => 1 } @{$groups} };
            }
        },
    };

    $talk->_imap_cmd('GETUSERGROUP', 0, $handlers, $item);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    return $usergroups;
}

# Run $code while another process holds $userid's namespace lock
# exclusively.  IMAP clients stay disconnected until the lock is released,
# because logging in would wait on it.  The holder gives up after a minute,
# so that a sync_client which waits for the lock can't hang the test.
sub hold_user_lock
{
    my ($self, $userid, $code) = @_;
    my $instance = $self->{instance};
    my $basedir = $instance->get_basedir();
    my $ready = "$basedir/userlock.$userid.ready";
    my $release = "$basedir/userlock.$userid.release";
    unlink($ready, $release);

    $self->_disconnect_all();
    my $holder = $instance->run_command({ cyrus => 1, background => 1 },
        'cyr_withlock_run', '-u', $userid, '--', '/bin/sh', '-c',
        "touch $ready; i=0; while [ ! -e $release ] && [ \$i -lt 600 ];"
        . " do sleep 0.1; i=\$((i+1)); done");
    timed_wait(sub { -e $ready },
               description => "lock on $userid to be held");

    my @ret = eval { $code->() };
    my $err = $@;

    open my $fh, '>', $release or die "$release: $!";
    close $fh;
    $instance->reap_command($holder);
    $self->_reconnect_all();

    die $err if $err;
    return @ret;
}

use Cassandane::Tiny::Loader;

1;
