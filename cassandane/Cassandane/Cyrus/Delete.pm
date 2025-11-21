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

package Cassandane::Cyrus::Delete;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use File::Basename;

sub new
{
    my ($class, @args) = @_;

    my $buildinfo = Cassandane::BuildInfo->new();

    if ($buildinfo->get('component', 'httpd')) {
        my $config = Cassandane::Config->default()->clone();

        $config->set(conversations => 'yes',
                     httpmodules => 'carddav caldav');

        return $class->SUPER::new({
            config => $config,
            jmap => 1,
            adminstore => 1,
            services => [ 'imap', 'http', 'sieve' ]
        }, @args);
    }
    else {
        return $class->SUPER::new({ adminstore => 1 }, @args);
    }
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
    xlog $self, "Checking that $display_folder exists on disk";

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

sub check_folder_not_ondisk
{
    my ($self, $folder, %params) = @_;

    my $instance = delete $params{instance} || $self->{instance};
    my $deleted = delete $params{deleted} || 0;
    die "Bad params: " . join(' ', keys %params)
        if scalar %params;

    my $display_folder = ($deleted ? "DELETED " : "") . $folder;
    xlog $self, "Checking that $display_folder does not exist on disk";

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

sub check_syslog
{
    my ($self, $instance) = @_;

    my $remove_empty_pat = qr/Remove of supposedly empty directory/;

    $self->assert_null($instance->_check_syslog($remove_empty_pat));
}

sub test_self_inbox_imm
    :ImmediateDelete :SemidelayedExpunge :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing that a non-admin can delete an a subfolder";
    xlog $self, "but cannot delete their own INBOX, immediate delete version";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';
    my $subfolder = 'INBOX.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog $self, "Generate a message in $subfolder";
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

    xlog $self, "can delete the subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Cannot select the subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog $self, "But the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    xlog $self, "cannot delete our own $inbox";
    $talk->delete($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Operation is not supported/i, $talk->get_last_error());

    xlog $self, "And the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    $self->check_syslog($self->{instance});
}

sub test_self_inbox_del
    :DelayedDelete :SemidelayedExpunge :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing that a non-admin can delete an a subfolder";
    xlog $self, "but cannot delete their own INBOX, delayed delete version";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';
    my $subfolder = 'INBOX.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog $self, "Generate a message in $subfolder";
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

    xlog $self, "can delete the subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Cannot select the subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog $self, "But the message in $inbox is still there";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%exp_inbox);

    xlog $self, "cannot delete our own $inbox";
    $talk->delete($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Operation is not supported/i, $talk->get_last_error());

    xlog $self, "And the message in $inbox is still there";
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

    $self->check_syslog($self->{instance});
}

# old version of this test for builds without newer httpd features
# n.b. 2.5 httpd can't be built anymore because of dependency on
# very old libical
sub test_admin_inbox_imm_legacy
    :ImmediateDelete :SemidelayedExpunge :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing that an admin can delete the INBOX of a user";
    xlog $self, "and it will delete the whole user, immediate delete version";

    # can't do the magic disconnect handling on older perl
    return if ($] < 5.010);

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog $self, "Generate a message in $subfolder";
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

    xlog $self, "admin can delete $inbox";
    $admintalk->delete($inbox);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    {
        # shut up
        local $SIG{__DIE__};
        local $SIG{__WARN__} = sub { 1 };

        xlog $self, "Client was disconnected";
        my $Res = eval { $talk->select($inbox) };
        $self->assert_null($Res);

        # reconnect
        $talk = $store->get_client();
    }

    xlog $self, "Cannot select $inbox anymore";
    $talk->select($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog $self, "Cannot select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    $self->check_syslog($self->{instance});
}

sub test_admin_inbox_imm
    :ImmediateDelete :SemidelayedExpunge :NoAltNameSpace
    :needs_component_httpd
{
    my ($self) = @_;

    xlog $self, "Testing that an admin can delete the INBOX of a user";
    xlog $self, "and it will delete the whole user, immediate delete version";

    # can't do the magic disconnect handling on older perl
    return if ($] < 5.010);

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';
    my $sharedfolder = 'shared';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Create a shared folder";
    $admintalk->create($sharedfolder)
        or $self->fail("Cannot create folder $sharedfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $admintalk->setacl($sharedfolder, admin => 'lrswipkxtecdan');
    $admintalk->setacl($sharedfolder, cassandane => 'lrsip');

    xlog $self, "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog $self, "Generate a message in $subfolder";
    my %exp_sub;
    $store->set_folder($subfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $exp_sub{A} = $self->make_message("Message $subfolder A");
    $self->check_messages(\%exp_sub);
    $talk->unselect();

    xlog $self, "Generate a message in $sharedfolder";
    my %exp_shared;
    $store->set_folder($sharedfolder);
    $store->_select();
    $self->{gen}->set_next_uid(1);
    $exp_shared{A} = $self->make_message("Message $sharedfolder A");
    $self->check_messages(\%exp_shared);

    xlog $self, "Set \\Seen on message A";
    $talk->store('1', '+flags', '(\\Seen)');
    $talk->unselect();

    $self->check_folder_ondisk($inbox, expected => \%exp_inbox);
    $self->check_folder_ondisk($subfolder, expected => \%exp_sub);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog $self, "Subscribe to INBOX";
    $talk->subscribe("INBOX");

    xlog $self, "Install a sieve script";
    $self->{instance}->install_sieve_script(<<EOF
keep;
EOF
    );

    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "Verify user data files/directories exist";
    my $data = $self->{instance}->run_mbpath('-u', 'cassandane');
    $self->assert_file_test($data->{user}{'sub'}, '-f');
    $self->assert_file_test($data->{user}{seen}, '-f');
    $self->assert_file_test($data->{user}{dav}, '-f');
    $self->assert_file_test($data->{user}{counters}, '-f');
    $self->assert_file_test($data->{user}{conversations}, '-f');
    $self->assert_file_test($data->{user}{xapianactive}, '-f');
    $self->assert_file_test("$data->{user}{sieve}/defaultbc", '-f');
    $self->assert_file_test($data->{xapian}{t1}, '-d');

    xlog $self, "admin can delete $inbox";
    $admintalk->delete($inbox);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    {
        # shut up
        local $SIG{__DIE__};
        local $SIG{__WARN__} = sub { 1 };

        xlog $self, "Client was disconnected";
        my $Res = eval { $talk->select($inbox) };
        $self->assert_null($Res);

        # reconnect
        $talk = $store->get_client();
    }

    xlog $self, "Cannot select $inbox anymore";
    $talk->select($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog $self, "Cannot select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_not_ondisk($subfolder);
    $self->check_folder_not_ondisk($inbox, deleted => 1);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    my ($maj, $min) = Cassandane::Instance->get_version();

    xlog $self, "Verify user data directories have been deleted";
    if (($maj > 3 || ($maj == 3 && $min > 4))
        && !$self->{instance}->{config}->get_bool('mailbox_legacy_dirs'))
    {
        # Entire UUID-hashed directory should be removed
        $self->assert_not_file_test(dirname($data->{user}{dav}), '-e');
    }
    else {
        # Name-hashed directory will be left behind, so check individual files
        $self->assert_not_file_test($data->{user}{'sub'}, '-e');
        $self->assert_not_file_test($data->{user}{seen}, '-e');
        $self->assert_not_file_test($data->{user}{dav}, '-e');
        $self->assert_not_file_test($data->{user}{counters}, '-e');
        $self->assert_not_file_test($data->{user}{conversations}, '-e');
        $self->assert_not_file_test($data->{user}{xapianactive}, '-e');
    }
    $self->assert_not_file_test($data->{user}{sieve}, '-e');
    $self->assert_not_file_test($data->{xapian}{t1}, '-e');

    $self->check_syslog($self->{instance});
}

sub test_admin_inbox_del
    :DelayedDelete :SemidelayedExpunge :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing that an admin can delete the INBOX of a user";
    xlog $self, "and it will delete the whole user, delayed delete version";

    # can't do the magic disconnect handling on older perl
    return if ($] < 5.010);

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate a message in $inbox";
    my %exp_inbox;
    $exp_inbox{A} = $self->make_message("Message $inbox A");
    $self->check_messages(\%exp_inbox);

    xlog $self, "Generate a message in $subfolder";
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

    xlog $self, "admin can delete $inbox";
    $admintalk->delete($inbox);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    {
        # shut up
        local $SIG{__DIE__};
        local $SIG{__WARN__} = sub { 1 };

        xlog $self, "Client was disconnected";
        my $Res = eval { $talk->select($inbox) };
        $self->assert_null($Res);

        # reconnect
        $talk = $store->get_client();
    }

    xlog $self, "Cannot select $inbox anymore";
    $talk->select($inbox);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    xlog $self, "Cannot select $subfolder anymore";
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

    $self->check_syslog($self->{instance});
}

sub test_bz3781
    :ImmediateDelete :SemidelayedExpunge :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing that a folder can be deleted when there is";
    xlog $self, "unexpected files in the proc directory (Bug 3781)";

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'user.cassandane';
    my $subfolder = 'user.cassandane.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->check_folder_ondisk($subfolder);

    xlog $self, "Create unexpected files in proc directory";
    my $procdir = $self->{instance}->{basedir} . "/conf/proc";
    POSIX::close(POSIX::creat("$procdir/xxx", 0600)); # non-numeric name
    POSIX::close(POSIX::creat("$procdir/123", 0600)); # valid name but empty

    xlog $self, "can delete $subfolder";
    $talk->delete($subfolder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Cannot select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);

    # We should have generated an IOERROR
    $self->assert_syslog_matches($self->{instance},
                                 qr/IOERROR: bogus filename/);
}

sub test_cyr_expire_delete
    :DelayedDelete :min_version_3_0 :NoAltNameSpace
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
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Append a messages to $inbox";
    my %msg_inbox;
    $msg_inbox{A} = $self->make_message('Message A in $inbox');
    $self->check_messages(\%msg_inbox);

    xlog $self, "Append 3 messages to $subfolder";
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

    xlog $self, "Delete $subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Ensure we can't select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);

    xlog $self, "Ensure we still have messages in $inbox";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%msg_inbox);

    my ($datapath) = $self->{instance}->folder_to_deleted_directories("user.cassandane.$subfoldername");
    $self->assert_not_null($datapath);

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );

    # the folder should not exist now!
    $self->assert_not_file_test($datapath, '-d');

    # and not exist from mbpath either...
    $self->assert_null($self->{instance}->folder_to_deleted_directories("user.cassandane.$subfoldername"));

    $self->check_syslog($self->{instance});
}

sub test_allowdeleted
    :AllowDeleted :DelayedDelete :min_version_3_1 :NoAltNameSpace
{
    my ($self) = @_;

    my $store = $self->{store};
    my $adminstore = $self->{adminstore};
    my $talk = $store->get_client();
    my $admintalk = $adminstore->get_client();

    my $inbox = 'INBOX';
    my $subfolder = 'INBOX.foo';
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->make_message('A message');
    $talk->select("INBOX");
    $talk->copy("1:*", $subfolder);
    $talk->unselect();

    xlog $self, "Delete $subfolder";
    $talk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Check standard list only included Inbox";
    my $result = $talk->list('', '*');
    $self->assert_num_equals(1, scalar(@$result));

    xlog $self, "Check include-deleted LIST includes deleted mailbox";
    $result = $talk->list(['VENDOR.CMU-INCLUDE-DELETED'], '', '*');
    $self->assert_num_equals(2, scalar(@$result));
    $self->assert_str_equals("INBOX", $result->[0][2]);
    $self->assert_matches(qr/^DELETED./, $result->[1][2]);

    xlog $self, "Check that select of DELETED folder works and finds messages";
    $talk->select($result->[1][2]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    $self->check_syslog($self->{instance});
}

sub test_cyr_expire_delete_with_annotation
    :DelayedDelete :min_version_3_1 :NoAltNameSpace
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
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Append a messages to $inbox";
    my %msg_inbox;
    $msg_inbox{A} = $self->make_message('Message A in $inbox');
    $self->check_messages(\%msg_inbox);

    xlog $self, "Setting /vendor/cmu/cyrus-imapd/delete annotation.";
    $talk->setmetadata($subfolder, "/shared/vendor/cmu/cyrus-imapd/delete", '3');

    xlog $self, "Append 3 messages to $subfolder";
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

    xlog $self, "Delete $subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Ensure we can't select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);

    xlog $self, "Ensure we still have messages in $inbox";
    $store->set_folder($inbox);
    $store->_select();
    $self->check_messages(\%msg_inbox);

    my ($path) = $self->{instance}->folder_to_deleted_directories("user.cassandane.$subfoldername");
    $self->assert_file_test($path, '-d');

    xlog $self, "Run cyr_expire -D now, it shouldn't delete.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );
    $self->assert_file_test($path, '-d');

    xlog $self, "Run cyr_expire -D now, with -a, skipping annotation.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0', '-a' );
    $self->assert_not_file_test($path, '-d');

    $self->check_syslog($self->{instance});
}

# https://github.com/cyrusimap/cyrus-imapd/issues/2413
sub test_cyr_expire_dont_resurrect_convdb
    :Conversations :DelayedDelete :min_version_3_0 :NoAltNameSpace
{
    my ($self) = @_;

    my $store = $self->{store};
    my $adminstore = $self->{adminstore};
    my $talk = $store->get_client();
    my $admintalk = $adminstore->get_client();

    my $basedir = $self->{instance}->{basedir};

    my $inbox = 'INBOX';
    my $subfoldername = 'foo';
    my $subfolder = 'INBOX.foo';
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Append a messages to $inbox";
    my %msg_inbox;
    $msg_inbox{A} = $self->make_message('Message A in $inbox');
    $self->check_messages(\%msg_inbox);

    xlog $self, "Append 3 messages to $subfolder";
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

    # expect user has a conversations database
    my $convdbfile = $self->{instance}->get_conf_user_file("cassandane", "conversations");
    $self->assert_file_test($convdbfile, '-f');

    # log cassandane user out before it gets thrown out anyway
    undef $talk;
    $store->disconnect();

    xlog $self, "Delete cassandane user";
    $admintalk->delete("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # expect user does not have a conversations database
    $self->assert_not_file_test($convdbfile, '-f');
    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_ondisk($inbox, deleted => 1);

    xlog $self, "Run cyr_expire -E now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-E' => '1' );
    $self->check_folder_ondisk($inbox, deleted => 1);

    # expect user does not have a conversations database
    $self->assert_not_file_test($convdbfile, '-f');

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );
    $self->check_folder_not_ondisk($inbox, deleted => 1);

    # expect user does not have a conversations database
    $self->assert_not_file_test($convdbfile, '-f');

    $self->check_syslog($self->{instance});
}

sub test_no_delete_with_children
    :DelayedDelete :min_version_3_3
{
    my ($self) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $subfolder = 'INBOX.foo';
    my $subsubfolder = 'INBOX.foo.bar';

    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $talk->create($subsubfolder)
        or $self->fail("Cannot create folder $subsubfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $talk->delete($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    $self->check_syslog($self->{instance});
}

sub test_cyr_expire_inherit_annot
    :DelayedDelete :min_version_3_9 :NoAltNameSpace
{
    my ($self) = @_;
    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Create subfolder";
    my $subfolder = 'INBOX.A';
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Set /vendor/cmu/cyrus-imapd/expire annotation on inbox";
    $talk->setmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/expire", '1s');
    $self->assert_str_equals('ok', $talk->get_last_completion_response);

    xlog $self, "Create message";
    $store->set_folder($subfolder);
    $self->make_message('msg1') or die;

    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Run cyr_expire";
    sleep(2);
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-X' => '1s' );

    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_num_equals(0, $talk->get_response_code('exists'));

    $self->check_syslog($self->{instance});
}

sub test_cyr_expire_noexpire
    :DelayedDelete :min_version_3_9 :NoAltNameSpace
{
    my ($self) = @_;
    my $store = $self->{store};
    my $talk = $store->get_client();

    my $noexpire_annot = '/shared/vendor/cmu/cyrus-imapd/noexpire_until';

    xlog $self, "Create subfolder";
    my $subfolder = 'INBOX.A';
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Set /vendor/cmu/cyrus-imapd/expire annotation on subfolder";
    $talk->setmetadata($subfolder, "/shared/vendor/cmu/cyrus-imapd/expire", '1s');
    $self->assert_str_equals('ok', $talk->get_last_completion_response);

    xlog $self, "Create message";
    $store->set_folder($subfolder);
    $self->make_message('msg1') or die;

    xlog $self, "Set $noexpire_annot annotation on inbox";
    $talk->setmetadata('INBOX', $noexpire_annot, '0');
    $self->assert_str_equals('ok', $talk->get_last_completion_response);

    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    sleep(2);
    xlog $self, "Run cyr_expire";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-X' => '1s', '-v', '-v', '-v' );

    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Remove $noexpire_annot from inbox";
    $talk->setmetadata('INBOX', $noexpire_annot, '');
    $self->assert_str_equals('ok', $talk->get_last_completion_response);

    xlog $self, "Run cyr_expire";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-X' => '1s', '-v', '-v', '-v' );

    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_num_equals(0, $talk->get_response_code('exists'));

    $self->check_syslog($self->{instance});
}

sub test_cyr_expire_delete_noexpire
    :DelayedDelete :min_version_3_9 :NoAltNameSpace
{
    my ($self) = @_;
    my $store = $self->{store};
    my $adminstore = $self->{adminstore};
    my $talk = $store->get_client();
    my $admintalk = $adminstore->get_client();

    my $noexpire_annot = '/shared/vendor/cmu/cyrus-imapd/noexpire_until';

    my $subfoldername = 'foo';
    my $subfolder = 'INBOX.foo';
    $talk->create($subfolder)
        or $self->fail("Cannot create folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Setting /vendor/cmu/cyrus-imapd/delete annotation.";
    $talk->setmetadata($subfolder, "/shared/vendor/cmu/cyrus-imapd/delete", '1s');

    $self->check_folder_ondisk($subfolder);
    $self->check_folder_not_ondisk($subfolder, deleted => 1);

    xlog $self, "Delete $subfolder";
    $talk->unselect();
    $talk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Ensure we can't select $subfolder anymore";
    $talk->select($subfolder);
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $talk->get_last_error());

    $self->check_folder_not_ondisk($subfolder);

    my ($path) = $self->{instance}->folder_to_deleted_directories("user.cassandane.$subfoldername");
    $self->assert(-d "$path");

    xlog $self, "Set $noexpire_annot annotation on inbox";
    $talk->setmetadata('INBOX', $noexpire_annot, '0');
    $self->assert_str_equals('ok', $talk->get_last_completion_response);

    sleep(2);
    xlog $self, "Run cyr_expire";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '1s' );
    $self->assert(-d "$path");

    xlog $self, "Remove $noexpire_annot annotation from inbox";
    $talk->setmetadata('INBOX', $noexpire_annot, '');
    $self->assert_str_equals('ok', $talk->get_last_completion_response);

    xlog $self, "Run cyr_expire";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '1s' );
    $self->assert(!-d "$path");

    $self->check_syslog($self->{instance});
}

1;
