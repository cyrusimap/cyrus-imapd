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

package Cassandane::Cyrus::Backups;
use strict;
use warnings;
use Data::Dumper;
use JSON::XS;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ backups => 1, adminstore => 1 }, @_);
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

sub do_backup
{
    my ($self, $params) = @_;

    die "params not a hashref"
        if defined $params and ref $params ne 'HASH';

    my $users = $params->{users};
    my $mailboxes = $params->{mailboxes};

    if (defined $users) {
        $users = [ $users ] if not ref $users;
        die "users is not an array reference" if ref $users ne 'ARRAY';
        xlog $self, "backing up users: @{$users}";
        $self->{instance}->run_command(
            { cyrus => 1},
            qw(sync_client -vv -n backup -u), @{$users});
    }

    if (defined $mailboxes) {
        $mailboxes = [ $mailboxes ] if not ref $mailboxes;
        die "mailboxes is not an array reference" if ref $mailboxes ne 'ARRAY';
        xlog $self, "backing up mailboxes: @{$mailboxes}";
        $self->{instance}->run_command(
            { cyrus => 1 },
            qw(sync_client -vv -n backup -m), @{$mailboxes});
    }

    if (not defined $users and not defined $mailboxes) {
        xlog $self, "backing up all users";
        # n.b. this does not include shared mailboxes! see sync_client(8)
        $self->{instance}->run_command(
            { cyrus => 1 },
            qw(sync_client -vv -n backup -A));
    }
}

sub do_xbackup
{
    my ($self, $pattern, $channel) = @_;

    die "do_xbackup needs a pattern" if not $pattern;
    $channel //= 'backup';

    my $admintalk = $self->{adminstore}->get_client();

    my %untagged;
    my $handler = sub {
        my ($response, $args, undef) = @_;
        return if scalar @{$args} != 2;
        my ($type, $val) = @{$args};
        push @{$untagged{uc $response}->{$type}}, $val;
    };
    my %callbacks = (
        'ok' => $handler,
        'no' => $handler,
    );

    $admintalk->_imap_cmd('xbackup', 0, \%callbacks,
                          $pattern, $channel);
    if (wantarray) {
        return ($admintalk->get_last_completion_response(), \%untagged);
    }
    else {
        return $admintalk->get_last_completion_response();
    }
}

sub cyr_backup_json
{
    my ($self, $params, $subcommand, @args) = @_;

    die "params not a hashref"
        if defined $params and ref $params ne 'HASH';
    die "invalid subcommand: $subcommand"
        if not grep { $_ eq $subcommand } qw(chunks mailboxes messages headers);

    my $instance = $params->{instance} // $self->{backups};
    my $user = $params->{user} // 'cassandane';
    my $mailbox = $params->{mailbox};

    my $out = "$instance->{basedir}/$self->{_name}"
          . "-cyr_backup-$user-json-$subcommand.stdout";
    my $err = "$instance->{basedir}/$self->{_name}"
          . "-cyr_backup-$user-json-$subcommand.stderr";

    my ($mode, $backup);
    if (defined $mailbox) {
        $mode = '-m';
        $backup = $mailbox;
    }
    else {
        $mode = '-u';
        $backup = $user;
    }

    $instance->run_command(
        { cyrus => 1,
          redirects => { 'stdout' => $out,
                         'stderr' => $err } },
        'cyr_backup', $mode, $backup, 'json', $subcommand, @args
    );

    local $/;
    open my $fh, '<', $out
        or die "Cannot open $out for reading: $!";
    my $data = JSON::decode_json(<$fh>);
    close $fh;

    return $data;
}

sub backup_exists
{
    my ($self, $mode, $backup) = @_;

    my $rc = $self->{backups}->run_command(
        {
            cyrus => 1,
            handlers => {
                exited_abnormally => sub {
                    my (undef, $code) = @_;
                    return $code
                },
            },
        },
        'ctl_backups', 'list', $mode, $backup
    );

    return $rc == 0;
}

sub assert_backups_exist
{
    my ($self, $params) = @_;

    my @users = exists $params->{users} ? @{$params->{users}} : ();
    my @mailboxes = exists $params->{mailboxes} ? @{$params->{mailboxes}} : ();
    my @filenames = exists $params->{filenames} ? @{$params->{filenames}} : ();

    foreach my $u (@users) {
        my $x = $self->backup_exists('-u', $u);
        $self->assert($x, "no backup found for user $u");
    }

    foreach my $m (@mailboxes) {
        my $x = $self->backup_exists('-m', $m);
        $self->assert($x, "no backup found for mailbox $m");
    }

    foreach my $f (@filenames) {
        my $x = $self->backup_exists('-f', $f);
        $self->assert($x, "no backup found for filename $f");
    }
}

sub assert_backups_not_exist
{
    my ($self, $params) = @_;

    my @users = exists $params->{users} ? @{$params->{users}} : ();
    my @mailboxes = exists $params->{mailboxes} ? @{$params->{mailboxes}} : ();
    my @filenames = exists $params->{filenames} ? @{$params->{filenames}} : ();

    foreach my $u (@users) {
        my $x = $self->backup_exists('-u', $u);
        $self->assert(!$x, "unexpected backup found for user $u");
    }

    foreach my $m (@mailboxes) {
        my $x = $self->backup_exists('-m', $m);
        $self->assert(!$x, "unexpected backup found for mailbox $m");
    }

    foreach my $f (@filenames) {
        my $x = $self->backup_exists('-f', $f);
        $self->assert(!$x, "unexpected backup found for filename $f");
    }
}

sub test_aaasetup
    :min_version_3_0 :needs_component_backup
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_basic
    :min_version_3_0 :needs_component_backup
{
    my ($self) = @_;

    $self->do_backup({ users => 'cassandane' });

    my $chunks = $self->cyr_backup_json({}, 'chunks');

    $self->assert_equals(1, scalar @{$chunks});
    $self->assert_equals(0, $chunks->[0]->{offset});
    $self->assert_equals(1, $chunks->[0]->{id});
    # an empty chunk has a 29 byte prefix
    # make sure the chunk isn't empty -- it should at least send through
    # the state of an empty inbox
    $self->assert($chunks->[0]->{length} > 29);
}

sub test_messages
    :min_version_3_0 :needs_component_backup
{
    my ($self) = @_;

    my %exp;

    $exp{A} = $self->make_message("Message A");
    $exp{B} = $self->make_message("Message B");
    $exp{C} = $self->make_message("Message C");
    $exp{D} = $self->make_message("Message D");

    $self->do_backup({ users => 'cassandane' });

    my $messages = $self->cyr_backup_json({}, 'messages');

    # backup should contain four messages
    $self->assert_equals(4, scalar @{$messages});

    my $headers = $self->cyr_backup_json({}, 'headers', map { $_->{guid} } @{$messages});

    # transform out enough data for comparison purposes
    my %expected = map {
        $_->get_guid() => $_->get_header('X-Cassandane-Unique')
    } values %exp;

    my %actual = map {
        $_ => $headers->{$_}->{'X-Cassandane-Unique'}->[0]
    } keys %{$headers};

    $self->assert_deep_equals(\%expected, \%actual);
}

sub test_shared_mailbox
    :min_version_3_0 :needs_component_backup :NoAltNamespace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # should definitely not be able to create a user that would conflict
    # with where shared mailbox backups are stored!
    $admintalk->create('user.%SHARED');
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());

    $admintalk->create('shared.folder');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setacl('shared.folder', 'cassandane' => 'lrswipkxtecdn');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $self->{store}->set_folder('shared.folder');
    my %exp;
    $exp{A} = $self->make_message("Message A");
    $exp{B} = $self->make_message("Message B");
    $exp{C} = $self->make_message("Message C");
    $exp{D} = $self->make_message("Message D");

    $self->do_backup({ mailboxes => 'shared.folder' });

    my $messages = $self->cyr_backup_json({ mailbox => 'shared.folder'},
                                          'messages');

    # backup should contain four messages
    $self->assert_equals(4, scalar @{$messages});

    my $headers = $self->cyr_backup_json({ mailbox => 'shared.folder' },
                                         'headers',
                                         map { $_->{guid} } @{$messages});

    # transform out enough data for comparison purposes
    my %expected = map {
        $_->get_guid() => $_->get_header('X-Cassandane-Unique')
    } values %exp;

    my %actual = map {
        $_ => $headers->{$_}->{'X-Cassandane-Unique'}->[0]
    } keys %{$headers};

    $self->assert_deep_equals(\%expected, \%actual);

    # XXX probably don't do this like this
    $self->{backups}->run_command(
        { cyrus => 1 },
        qw(ctl_backups -S -vvv verify -m shared.folder)
    );
}

sub test_deleted_mailbox
    :min_version_3_0 :needs_component_backup :NoAltNamespace
{
    my ($self) = @_;

    my $usertalk = $self->{store}->get_client();
    $usertalk->create('INBOX.foo');
    $self->assert_str_equals('ok', $usertalk->get_last_completion_response());

    $self->{store}->set_folder('INBOX.foo');

    my %exp;
    $exp{A} = $self->make_message("Message A");
    $exp{B} = $self->make_message("Message B");
    $exp{C} = $self->make_message("Message C");
    $exp{D} = $self->make_message("Message D");

    $self->do_backup({ users => 'cassandane' });

    # backup should contain four messages
    my $messages = $self->cyr_backup_json({}, 'messages');
    $self->assert_equals(4, scalar @{$messages});

    my $mailboxes = $self->cyr_backup_json({}, 'mailboxes');
	$self->assert_equals(2, scalar @{$mailboxes});
    $self->assert_deep_equals([qw(user.cassandane user.cassandane.foo)],
                              [ map { $_->{mboxname} } @{$mailboxes} ]);

    # delete the mailbox
    $usertalk->delete('INBOX.foo');
    $self->assert_str_equals('ok', $usertalk->get_last_completion_response());

    $self->do_backup({ users => 'cassandane' });

    $messages = $self->cyr_backup_json({}, 'messages');
    $self->assert_equals(4, scalar @{$messages});

    $mailboxes = $self->cyr_backup_json({}, 'mailboxes');
	$self->assert_equals(2, scalar @{$mailboxes});
    $self->assert_deep_equals([qw(user.cassandane DELETED.user.cassandane.foo)],
                              [ map { $_->{mboxname} =~ s/\.[A-F0-9]{8}$//r }
									@{$mailboxes} ]);

	my $deleted_mboxname = $mailboxes->[1]->{mboxname};

    # should be able to find the correct backup by the deleted name
    # and see the four messages in it
    $messages = $self->cyr_backup_json({ mailbox => $deleted_mboxname },
                                       'messages');
    $self->assert_equals(4, scalar @{$messages});
}

sub test_locks
    :min_version_3_0 :needs_component_backup
{
    my ($self) = @_;

    # make sure there's a backup file
    $self->do_backup({ users => 'cassandane' });

    # lock it for a while
    my $wait = 10; # seconds
    my $sleeper = $self->{backups}->run_command(
        { cyrus => 1, background => 1 },
        qw(ctl_backups -w -vvv lock -u cassandane -x ), "/bin/sleep $wait",
    );

    # give the sleeper a moment to start up so it can definitely get the
    # lock without racing against the next bit...
    sleep 2;

    # meanwhile, try to get another lock on the same backup
    my $errfile = $self->{backups}->get_basedir() . "/ctl_backups_lock.stderr";
    my ($code, $output);
    $self->{backups}->run_command(
        {
            cyrus => 1,
            handlers => {
                exited_abnormally => sub { (undef, $code) = @_ },
            },
            redirects => {
                stderr => $errfile,
            },
        },
        qw(ctl_backups -vvv lock -u cassandane -x ), "/bin/echo locked",
    );

    {
        local $/;
        open my $fh, '<', $errfile
            or die "Cannot open $errfile for reading: $!";
        $output = <$fh>;
        close $fh;
    }

    # clean up after the sleeper
    $self->{backups}->reap_command($sleeper);

    # expect the second lock failed, specifically due to being locked
    $self->assert_num_equals(75, $code); # EX_TEMPFAIL
    $self->assert_matches(qr{Mailbox is locked}, $output);
}

sub test_xbackup
    :min_version_3_0 :UnixHierarchySep :VirtDomains :needs_component_backup
{
    my ($self) = @_;
    my $id = 1;

    my @users = qw(
        user@example.com
        foo.bar@example.com
    );

    my @folders = qw( Drafts Sent Trash );

    # create the new users
    my $admintalk = $self->{adminstore}->get_client();
    foreach my $u (@users) {
        $self->{instance}->create_user($u, subdirs => \@folders);
    }

    # we also want to test the cassandane user (which was already created)
    unshift @users, 'cassandane';
    foreach my $f (@folders) {
        $admintalk->create("user/cassandane/$f");
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }

    # shouldn't be backup files for these users yet
    $self->assert_backups_not_exist({ users => \@users });

    # kick off a backup with xbackup and a pattern
    my ($status, $details) = $self->do_xbackup('user/*');
    $self->assert_str_equals('ok', $status);
    $self->assert_deep_equals([sort @users], [sort @{$details->{OK}->{USER}}]);

    # backups should exist now, but with no messages
    $self->assert_backups_exist({ users => \@users });
    foreach my $u (@users) {
        my $messages = $self->cyr_backup_json({ user => $u }, 'messages');
        $self->assert_num_equals(0, scalar @{$messages});
    }

    # add some content -- four messages per folder per user
    my %exp;
    foreach my $u (@users) {
        foreach my $f (@folders) {
            my ($l, $d) = split '@', $u;
            my $p = "user/$l/$f";
            $p .= "\@$d" if $d;
            $self->{adminstore}->set_folder($p);
            for (1..4) {
                $exp{$u}->{$f}->{$id} =
                    $self->make_message("Message $id",
                                        store => $self->{adminstore});
                $id++;
            }
        }
    }

    # let's xbackup and check each user individually
    foreach my $u (@users) {
        # run xbackup
        my ($status, $details) = $self->do_xbackup("user/$u");
        $self->assert_str_equals('ok', $status);
        $self->assert_deep_equals([$u], $details->{OK}->{USER});

        # backup should contain four messages per folder
        my $messages = $self->cyr_backup_json({ user => $u }, 'messages');
        $self->assert_num_equals(4 * scalar(@folders), scalar @{$messages});

        # check they're the right messages
        my $headers = $self->cyr_backup_json({ user => $u }, 'headers',
                                             map { $_->{guid} } @{$messages});

        my %expected = map {
            $_->get_guid() => $_->get_header('X-Cassandane-Unique')
        } map { values %{$_} } values %{$exp{$u}};

        my %actual = map {
            $_ => $headers->{$_}->{'X-Cassandane-Unique'}->[0]
        } keys %{$headers};

        $self->assert_deep_equals(\%expected, \%actual);
    }

    # let's also xbackup all users with a pattern
    ($status, $details)  = $self->do_xbackup("user/*");
    $self->assert_str_equals('ok', $status);

    # each user should only be processed once, even though "user/*" pattern
    # also matches all their subfolders
    $self->assert_deep_equals([sort @users], [sort @{$details->{OK}->{USER}}]);
}

sub test_xbackup_shared
    :min_version_3_0 :UnixHierarchySep :VirtDomains :needs_component_backup
{
    my ($self) = @_;
    my $id = 1;

    my @folders = qw( sh1 sh2 );
    my @subfolders = qw( foo bar baz );

    # create the shared folders
    my $admintalk = $self->{adminstore}->get_client();
    foreach my $top (@folders) {
        $admintalk->create($top);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
        $admintalk->setacl($top, 'admin' => 'lrswipkxtecdan');
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());

        foreach my $sub (@subfolders) {
            $admintalk->create("$top/$sub");
            $self->assert_str_equals('ok',
                $admintalk->get_last_completion_response());
            $admintalk->setacl("$top/$sub", 'admin' => 'lrswipkxtecdan');
            $self->assert_str_equals('ok',
                $admintalk->get_last_completion_response());
        }
    }

    # shouldn't be backup files for these mailboxes yet
    $self->assert_backups_not_exist({ mailboxes => \@folders });

    # kick off a backup with xbackup and a pattern
    my ($status, $details) = $self->do_xbackup('sh*');
    $self->assert_str_equals('ok', $status);
    $self->assert_num_equals(scalar(@folders) * (1 + scalar(@subfolders)),
                             scalar @{$details->{OK}->{MAILBOX}});

    # backups should exist now, but with no messages
    $self->assert_backups_exist({ mailboxes => \@folders });
    foreach my $f (@folders) {
        my $messages = $self->cyr_backup_json({ mailbox => $f }, 'messages');
        $self->assert_num_equals(0, scalar @{$messages});
    }

    # add some content -- four messages per folder
    my %exp;
    foreach my $top (@folders) {
        foreach my $sub (@subfolders) {
            my $p = "$top/$sub";
            $self->{adminstore}->set_folder($p);
            for (1..4) {
                $exp{$id} =
                    $self->make_message("Message $id",
                                        store => $self->{adminstore});
                $id++;
            }
        }
    }

    # xbackup again
    ($status, $details) = $self->do_xbackup('sh*');
    $self->assert_str_equals('ok', $status);
    $self->assert_num_equals(scalar(@folders) * (1 + scalar(@subfolders)),
                             scalar @{$details->{OK}->{MAILBOX}});

    # backup should contain four messages per subfolder per folder
    my $messages = $self->cyr_backup_json({ mailbox => $folders[0] },
                                          'messages');
    $self->assert_num_equals(4 * scalar(@folders) * scalar(@subfolders),
                             scalar @{$messages});

    # check they're the right messages
    my $headers = $self->cyr_backup_json({ mailbox => $folders[0] }, 'headers',
                                         map { $_->{guid} } @{$messages});

    my %expected = map {
        $_->get_guid() => $_->get_header('X-Cassandane-Unique')
    } values %exp;

    my %actual = map {
        $_ => $headers->{$_}->{'X-Cassandane-Unique'}->[0]
    } keys %{$headers};

    $self->assert_deep_equals(\%expected, \%actual);
}

1;
