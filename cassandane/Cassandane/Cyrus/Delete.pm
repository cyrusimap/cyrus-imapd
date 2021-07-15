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

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use File::Basename;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'yes',
                 httpmodules => 'carddav caldav jmap');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http', 'sieve' ]
    }, @args);
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
}

sub test_admin_inbox_imm
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
    $self->assert( -f $data->{user}{'sub'});
    $self->assert( -f $data->{user}{dav});
    $self->assert( -f $data->{user}{counters});
    $self->assert( -f $data->{user}{conversations});
    $self->assert( -f $data->{user}{xapianactive});
    $self->assert( -f "$data->{user}{sieve}/defaultbc");
    $self->assert( -d $data->{xapian}{t1});

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

    xlog $self, "Verify user data directories have been deleted";
    $self->assert( !-e dirname($data->{user}{dav}));
    $self->assert( !-e $data->{user}{sieve});
    $self->assert( !-e $data->{xapian}{t1});
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

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated an IOERROR
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: bogus filename/, "@lines");
    }
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
    $self->assert(!-d $datapath);

    # and not exist from mbpath either...
    $self->assert_null($self->{instance}->folder_to_deleted_directories("user.cassandane.$subfoldername"));
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
    $self->assert(-d "$path");

    xlog $self, "Run cyr_expire -D now, it shouldn't delete.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );
    $self->assert(-d "$path");

    xlog $self, "Run cyr_expire -D now, with -a, skipping annotation.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0', '-a' );
    $self->assert(!-d "$path");
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
    $self->assert(-f $convdbfile);

    # log cassandane user out before it gets thrown out anyway
    undef $talk;
    $store->disconnect();

    xlog $self, "Delete cassandane user";
    $admintalk->delete("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # expect user does not have a conversations database
    $self->assert(!-f $convdbfile);
    $self->check_folder_not_ondisk($inbox);
    $self->check_folder_ondisk($inbox, deleted => 1);

    xlog $self, "Run cyr_expire -E now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-E' => '1' );
    $self->check_folder_ondisk($inbox, deleted => 1);

    # expect user does not have a conversations database
    $self->assert(!-f $convdbfile);

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );
    $self->check_folder_not_ondisk($inbox, deleted => 1);

    # expect user does not have a conversations database
    $self->assert(!-f $convdbfile);
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
}

1;
