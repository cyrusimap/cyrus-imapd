#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty. Ltd.  All rights reserved.
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
#  3. The name "Fastmail" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#         FastMail Pty. Ltd.
#         Level 1, 91 William St
#         Melbourne 3000
#         Victoria
#         Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by FastMail Pty. Ltd."
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Delete;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({ adminstore => 1 }, @args);
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

sub check_folder_ondisk
{
    my ($self, $folder, %params) = @_;

    my $instance = delete $params{instance} || $self->{instance};
    my $deleted = delete $params{deleted} || 0;
    my $exp = delete $params{expected};
    die "Bad params: " . join(' ', keys %params)
        if scalar %params;

    my $display_folder = ($deleted ? "DELETED " : "") . $folder;
    xlog "Checking that $display_folder exists on disk";

    my $dir;
    if ($deleted)
    {
        my @dirs = $instance->folder_to_deleted_directories($folder);
        $self->assert_equals(1, scalar(@dirs),
                             "too many directories for $display_folder");
        $dir = shift @dirs;
    }
    else
    {
        $dir = $instance->folder_to_directory($folder);
    }

    $self->assert_not_null($dir,
                           "directory missing for $display_folder");
    $self->assert( -f "$dir/cyrus.header",
                   "cyrus.header missing for $display_folder");
    $self->assert( -f "$dir/cyrus.index",
                   "cyrus.index missing for $display_folder");

    if (defined $exp)
    {
        map
        {
            my $uid = $_->uid();
            $self->assert( -f "$dir/$uid.",
                           "message $uid missing for $display_folder");
        } values %$exp;
    }
}

sub test_repeated_delete
    :DelayedDelete :SemidelayedExpunge :min_version_3_0
{
    my ($self) = @_;

    xlog "Testing that if a user deletes the same mailbox more than 20 times,";
    xlog "they only keep the most recent 20 DELETED folders";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';
    my $subfolder = 'INBOX.foo';

    for (1..30) {
        xlog "First create a sub folder $_";
        $talk->create($subfolder)
            or die "Cannot create folder $subfolder: $@";
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        xlog "Then delete it $_";
        $talk->delete($subfolder);

        my $admintalk = $self->{adminstore}->get_client();
        my $list = $admintalk->list("DELETED.user.cassandane.foo", "*");
        my $num = $_;
        $num = 20 if $num > 20;
        $self->assert_equals($num, scalar(@$list));

        xlog "And sleep until the name will have changed";
        sleep 2;
    }

}

sub check_folder_not_ondisk
{
    my ($self, $folder, %params) = @_;

    my $instance = delete $params{instance} || $self->{instance};
    my $deleted = delete $params{deleted} || 0;
    die "Bad params: " . join(' ', keys %params)
        if scalar %params;

    my $display_folder = ($deleted ? "DELETED " : "") . $folder;
    xlog "Checking that $display_folder does not exist on disk";

    if ($deleted)
    {
        my @dirs = $instance->folder_to_deleted_directories($folder);
        $self->assert_equals(0, scalar(@dirs),
                             "directory unexpectedly present for $display_folder");
    }
    else
    {
        my $dir = $instance->folder_to_directory($folder);
        $self->assert_null($dir,
                           "directory unexpectedly present for $display_folder");
    }
}

sub test_self_inbox_imm
    :ImmediateDelete :SemidelayedExpunge
{
    my ($self) = @_;

    xlog "Testing that a non-admin can delete an a subfolder";
    xlog "but cannot delete their own INBOX, immediate delete version";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';
    my $subfolder = 'INBOX.foo';

    xlog "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog "Generate a message in $subfolder";
    my %exp_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $exp_sub{A} = $self->make_message("Message $subfolder A");
    $self->check_messages(\%exp_sub);

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%exp_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog "can delete the subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or die "Cannot delete folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Cannot select the subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog "But the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    xlog "cannot delete our own $inbox";
    $talk->delete($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Operation is not supported/i, $talk->get_last_error());

    xlog "And the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);
}

sub test_self_inbox_del
    :DelayedDelete :SemidelayedExpunge
{
    my ($self) = @_;

    xlog "Testing that a non-admin can delete an a subfolder";
    xlog "but cannot delete their own INBOX, delayed delete version";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';
    my $subfolder = 'INBOX.foo';

    xlog "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog "Generate a message in $subfolder";
    my %exp_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $exp_sub{A} = $self->make_message("Message $subfolder A");
    $self->check_messages(\%exp_sub);

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%exp_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog "can delete the subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or die "Cannot delete folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Cannot select the subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog "But the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    xlog "cannot delete our own $inbox";
    $talk->delete($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Operation is not supported/i, $talk->get_last_error());

    xlog "And the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_ondisk($subfolder, deleted => 1, expected => \%exp_sub);

    $self->run_delayed_expunge();

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);
}

sub test_admin_inbox_imm
    :ImmediateDelete :SemidelayedExpunge
{
    my ($self) = @_;

    xlog "Testing that an admin can delete the INBOX of a user";
    xlog "and it will delete the whole user, immediate delete version";

    # can't do the magic disconnect handling on older perl
    return if ($] < 5.010);

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';

    xlog "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog "Generate a message in $subfolder";
    my %exp_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $exp_sub{A} = $self->make_message("Message $subfolder A");
    $self->check_messages(\%exp_sub);
    $talk->unselect();

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%exp_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog "admin can delete $inbox";
    $admintalk->delete($inbox);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    {
        # shut up
        local $SIG{__DIE__};
        local $SIG{__WARN__} = sub { 1 };

        xlog "Client was disconnected";
        my $Res = eval { $talk->select($inbox) };
        $self->assert_null($Res);

        # reconnect
        $talk = $store->get_client();
    }

    xlog "Cannot select $inbox anymore";
    $talk->select($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog "Cannot select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);
}

sub test_admin_inbox_del
    :DelayedDelete :SemidelayedExpunge
{
    my ($self) = @_;

    xlog "Testing that an admin can delete the INBOX of a user";
    xlog "and it will delete the whole user, delayed delete version";

    # can't do the magic disconnect handling on older perl
    return if ($] < 5.010);

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';

    xlog "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog "Generate a message in $subfolder";
    my %exp_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $exp_sub{A} = $self->make_message("Message $subfolder A");
    $self->check_messages(\%exp_sub);
    $talk->unselect();

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%exp_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog "admin can delete $inbox";
    $admintalk->delete($inbox);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    {
        # shut up
        local $SIG{__DIE__};
        local $SIG{__WARN__} = sub { 1 };

        xlog "Client was disconnected";
        my $Res = eval { $talk->select($inbox) };
        $self->assert_null($Res);

        # reconnect
        $talk = $store->get_client();
    }

    xlog "Cannot select $inbox anymore";
    $talk->select($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog "Cannot select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_ondisk($inbox, deleted => 1, expected => \%exp_inbox);
    $self->check_folder_ondisk($subfolder, deleted => 1, expected => \%exp_sub);

    $self->run_delayed_expunge();

    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);
}

sub test_bz3781
    :ImmediateDelete :SemidelayedExpunge
{
    my ($self) = @_;

    xlog "Testing that a folder can be deleted when there is";
    xlog "unexpected files in the proc directory (Bug 3781)";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';

    xlog "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->check_folder_ondisk($subfolder);

    xlog "Create unexpected files in proc directory";
    my $procdir = $self->{instance}->{basedir} . "/conf/proc";
    POSIX::close(POSIX::creat("$procdir/xxx", 0600)); # non-numeric name
    POSIX::close(POSIX::creat("$procdir/123", 0600)); # valid name but empty

    xlog "can delete $subfolder";
    $talk->delete($subfolder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Cannot select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);
}

sub test_cyr_expire_delete
    :DelayedDelete :min_version_3_0
{
    my ($self) = @_;

    my $store = $self->{store};
    my $adminstore = $self->{adminstore};
    my $talk = $store->get_client();
    my $admintalk = $adminstore->get_client();

    my $inbox = 'INBOX';
    my $subfoldername = 'foo';
    my $subfolder = 'INBOX.foo';
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Append a messages to $inbox";
    my %msg_inbox;
    $msg_inbox{A} = $self->make_message('Message A in $inbox');
    $self->check_messages(\%msg_inbox);

    xlog "Append 3 messages to $subfolder";
    my %msg_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $msg_sub{A} = $self->make_message('Message A in $subfolder');
    $msg_sub{B} = $self->make_message('Message B in $subfolder');
    $msg_sub{C} = $self->make_message('Message C in $subfolder');
    $self->check_messages(\%msg_sub);

    $self->check_folder_ondisk($inbox, expected => \%msg_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%msg_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog "Delete $subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or die "Cannot delete folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Ensure we can't select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);

    xlog "Ensure we still have messages in $inbox";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%msg_inbox);

    my $basedir = $self->{instance}->{basedir};
    -d "$basedir/data/DELETED/user/cassandane/$subfoldername" || die;

    xlog "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );
    -d "$basedir/data/DELETED/user/cassandane/$subfoldername" && die;
}

sub test_cyr_expire_delete_with_annotation
    :DelayedDelete :min_version_3_0
{
    my ($self) = @_;

    my $store = $self->{store};
    my $adminstore = $self->{adminstore};
    my $talk = $store->get_client();
    my $admintalk = $adminstore->get_client();

    my $inbox = 'INBOX';
    my $subfoldername = 'foo';
    my $subfolder = 'INBOX.foo';
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Append a messages to $inbox";
    my %msg_inbox;
    $msg_inbox{A} = $self->make_message('Message A in $inbox');
    $self->check_messages(\%msg_inbox);

    xlog "Setting /vendor/cmu/cyrus-imapd/delete annotation.";
    $talk->setmetadata($subfolder, "/shared/vendor/cmu/cyrus-imapd/delete", '3');

    xlog "Append 3 messages to $subfolder";
    my %msg_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $msg_sub{A} = $self->make_message('Message A in $subfolder');
    $msg_sub{B} = $self->make_message('Message B in $subfolder');
    $msg_sub{C} = $self->make_message('Message C in $subfolder');
    $self->check_messages(\%msg_sub);

    $self->check_folder_ondisk($inbox, expected => \%msg_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%msg_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog "Delete $subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or die "Cannot delete folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Ensure we can't select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);

    xlog "Ensure we still have messages in $inbox";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%msg_inbox);

    my $basedir = $self->{instance}->{basedir};
    -d "$basedir/data/DELETED/user/cassandane/$subfoldername" || die;

    xlog "Run cyr_expire -D now, it shouldn't delete.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );
    -d "$basedir/data/DELETED/user/cassandane/$subfoldername" || die;

    xlog "Run cyr_expire -D now, with -a, skipping annotation.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0', '-a' );
    -d "$basedir/data/DELETED/user/cassandane/$subfoldername" && die;
}

1;
