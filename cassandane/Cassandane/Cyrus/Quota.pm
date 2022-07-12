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

package Cassandane::Cyrus::Quota;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::NetString;


sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1, services => ['smmap', 'imap'] }, @_);
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

sub slurp_file
{
    my ($filename) = @_;

    local $/;
    open my $f, '<', $filename
        or die "Cannot open $filename for reading: $!\n";
    my $str = <$f>;
    close $f;

    return $str;
}

sub _set_quotaroot
{
    my ($self, $quotaroot) = @_;
    $self->{quotaroot} = $quotaroot;
}

# Utility function to set quota limits and check that it stuck
sub _set_limits
{
    my ($self, %resources) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my $quotaroot = delete $resources{quotaroot} || $self->{quotaroot};
    my @quotalist;
    foreach my $resource (keys %resources)
    {
        my $limit = $resources{$resource}
            or die "No limit specified for $resource";
        push(@quotalist, uc($resource), $limit);
    }
    $self->{limits}->{$quotaroot} = { @quotalist };
    $admintalk->setquota($quotaroot, \@quotalist);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

# Utility function to check that quota's usages
# and limits are where we expect it to be
sub _check_usages
{
    my ($self, %expecteds) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my $quotaroot = delete $expecteds{quotaroot} || $self->{quotaroot};
    my $limits = $self->{limits}->{$quotaroot};

    my @result = $admintalk->getquota($quotaroot);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # check actual and expected number of resources do match
    $self->assert_num_equals(scalar(keys %$limits) * 3, scalar(@result));

    # Convert the IMAP result to a conveniently checkable hash.
    # By checkable, we mean that a failure in assert_deep_equals()
    # will give a human some idea of what went wrong.
    my %act;
    while (scalar(@result)) {
        my ($res, $used, $limit) = splice(@result, 0, 3);
        $res = uc($res);
        die "Resource $res appears twice in result"
            if defined $act{$res};
        $act{$res} = {
            used => $used,
            limit => $limit,
        };
    }

    # Build a conveniently checkable hash from %expecteds
    # and limits previously by _set_limits().
    my %exp;
    foreach my $res (keys %expecteds)
    {
        $exp{uc($res)} = {
            used => $expecteds{$res},
            limit => $limits->{uc($res)},
        };
    }

    # Now actually compare
    $self->assert_deep_equals(\%exp, \%act);
}

# Reset the recorded usage in the database.  Used for testing
# quota -f.  Rather hacky.  Both _set_quotaroot() and _set_limits()
# can be used to set default values.
sub _zap_quota
{
    my ($self, %params) = @_;

    my $quotaroot = $params{quotaroot} || $self->{quotaroot};
    my $limits = $params{limits} || $self->{limits}->{$quotaroot};
    my $useds = $params{useds} || {};
    $useds = { map { uc($_) => $useds->{$_} } keys %$useds };

    # double check that some other part of Cassandane didn't
    # accidentally futz with the expected quota db backend
    my $backend = $self->{instance}->{config}->get('quota_db');
    $self->assert_str_equals('quotalegacy', $backend)
        if defined $backend;        # the default value is also ok

    my ($uc) = ($quotaroot =~ m/^user[\.\/](.)/);
    my ($domain, $dirname);
    ($quotaroot, $domain) = split '@', $quotaroot;
    if ($domain) {
        my ($dc) = ($domain =~ m/^(.)/);
        $dirname = $self->{instance}->{basedir} . "/conf/domain/$dc/$domain";
    }
    else {
        $dirname = $self->{instance}->{basedir} . "/conf";
    }
    $dirname .= "/quota/$uc";
    my $qfn = $quotaroot;
    $qfn =~ s/\//\./g;
    my $filename = "$dirname/$qfn";
    mkpath $dirname;

    open QUOTA,'>',$filename
        or die "Failed to open $filename for writing: $!";

    # STORAGE is special and always present, but -1 if unlimited
    my $limit = $limits->{STORAGE} || -1;
    my $used = $useds->{STORAGE} || 0;
    print QUOTA "$used\n$limit";

    # other resources have a leading keyword if present
    my %keywords = ( MESSAGE => 'M', 'X-ANNOTATION-STORAGE' => 'AS' );
    foreach my $resource (keys %$limits)
    {
        my $kw = $keywords{$resource} or next;
        $limit = $limits->{$resource};
        $used = $useds->{$resource} || 0;
        print QUOTA " $kw $used $limit";
    }

    print QUOTA "\n";
    close QUOTA;

    $self->{instance}->_fix_ownership($self->{instance}{basedir} . "/conf/quota");
}

# Utility function to check that there is no quota
sub _check_no_quota
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my @res = $admintalk->getquota($self->{quotaroot});
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
}

sub _check_smmap
{
    my ($self, $name, $expected) = @_;
    my $service = $self->{instance}->get_service('smmap');
    my $sock = $service->get_socket();

    print_netstring($sock, "0 $name");
    my $res = get_netstring($sock);

    $self->assert($res =~ m/$expected/);
}

sub test_using_storage
{
    my ($self) = @_;

    xlog $self, "test increasing usage of the STORAGE quota resource as messages are added";
    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_limits(storage => 100000);
    $self->_check_usages(storage => 0);
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub")
    {
        $expecteds{$folder} = 0;
        $self->{store}->set_folder($folder);

        for (1..10)
        {
            my $msg = $self->make_message("Message $_",
                                          extra_lines => 10 + rand(5000));
            my $len = length($msg->as_string());
            $expecteds{$folder} += $len;
            $expected += $len;
            xlog $self, "added $len bytes of message";
            $self->_check_usages(storage => int($expected/1024));
        }
    }

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub"});
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'OK');

    # delete messages
    $talk->select("INBOX");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages(storage => int($expected/1024));
}

sub test_using_storage_late
{
    my ($self) = @_;

    xlog $self, "test setting STORAGE quota resource after messages are added";

    $self->_set_quotaroot('user.cassandane');
    $self->_check_no_quota();
    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub")
    {
        $expecteds{$folder} = 0;
        $self->{store}->set_folder($folder);

        for (1..10)
        {
            my $msg = $self->make_message("Message $_",
                                          extra_lines => 10 + rand(5000));
            my $len = length($msg->as_string());
            $expecteds{$folder} += $len;
            $expected += $len;
            xlog $self, "added $len bytes of message";
        }
    }

    $self->_set_limits(storage => 100000);
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'OK');

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub"});
    $self->_check_usages(storage => int($expected/1024));

    # delete messages
    $talk->select("INBOX");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages(storage => int($expected/1024));
}

sub test_exceeding_storage
{
    my ($self) = @_;

    xlog $self, "test exceeding the STORAGE quota limit";

    my $talk = $self->{store}->get_client();

    xlog $self, "set a low limit";
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(storage => 210);
    $self->_check_usages(storage => 0);

    xlog $self, "adding messages to get just below the limit";
    my %msgs;
    my $slack = 200 * 1024;
    my $n = 1;
    my $expected = 0;
    while ($slack > 1000)
    {
        my $nlines = int(($slack - 640) / 23);
        $nlines = 1000 if ($nlines > 1000);

        my $msg = $self->make_message("Message $n",
                                      extra_lines => $nlines);
        my $len = length($msg->as_string());
        $slack -= $len;
        $expected += $len;
        xlog $self, "added $len bytes of message";
        $msgs{$n} = $msg;
        $n++;
    }
    xlog $self, "check that the messages are all in the mailbox";
    $self->check_messages(\%msgs);
    xlog $self, "check that the usage is just below the limit";
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'OK');

    xlog $self, "add a message that exceeds the limit";
    my $nlines = int(($slack - 640) / 23) * 2;
    $nlines = 500 if ($nlines < 500);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $overmsg = eval { $self->make_message("Message $n", extra_lines => $nlines) };
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/over quota/i);

    xlog $self, "check that the exceeding message is not in the mailbox";
    $self->check_messages(\%msgs);

    xlog $self, "check that the quota usage is still the same";
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'OK');
}

sub test_move_near_limit
{
    my ($self) = @_;

    xlog $self, "test move near the STORAGE quota limit";

    my $talk = $self->{store}->get_client();

    xlog $self, "set a low limit";
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(storage => 210);
    $self->_check_usages(storage => 0);

    xlog $self, "adding messages to get just below the limit";
    my %msgs;
    my $slack = 200 * 1024;
    my $n = 1;
    my $expected = 0;
    while ($slack > 1000)
    {
        my $nlines = int(($slack - 640) / 23);
        $nlines = 1000 if ($nlines > 1000);

        my $msg = $self->make_message("Message $n",
                                      extra_lines => $nlines);
        my $len = length($msg->as_string());
        $slack -= $len;
        $expected += $len;
        xlog $self, "added $len bytes of message";
        $msgs{$n} = $msg;
        $n++;
    }
    xlog $self, "check that the messages are all in the mailbox";
    $self->check_messages(\%msgs);
    xlog $self, "check that the usage is just below the limit";
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'OK');

    xlog $self, "add a message that exceeds the limit";
    my $nlines = int(($slack - 640) / 23) * 2;
    $nlines = 500 if ($nlines < 500);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $overmsg = eval { $self->make_message("Message $n", extra_lines => $nlines) };
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/over quota/i);

    $talk->create("INBOX.target");

    xlog $self, "try to copy the messages";
    $talk->copy("1:*", "INBOX.target");
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/over quota/i);

    xlog $self, "move the messages";
    $talk->move("1:*", "INBOX.target");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub test_overquota
{
    my ($self) = @_;

    xlog $self, "test account which is over STORAGE quota limit";

    my $talk = $self->{store}->get_client();

    xlog $self, "set a low limit";
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(storage => 210);
    $self->_check_usages(storage => 0);

    xlog $self, "adding messages to get just below the limit";
    my %msgs;
    my $slack = 200 * 1024;
    my $n = 1;
    my $expected = 0;
    while ($slack > 1000)
    {
        my $nlines = int(($slack - 640) / 23);
        $nlines = 1000 if ($nlines > 1000);

        my $msg = $self->make_message("Message $n",
                                      extra_lines => $nlines);
        my $len = length($msg->as_string());
        $slack -= $len;
        $expected += $len;
        xlog $self, "added $len bytes of message";
        $msgs{$n} = $msg;
        $n++;
    }
    xlog $self, "check that the messages are all in the mailbox";
    $self->check_messages(\%msgs);
    xlog $self, "check that the usage is just below the limit";
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'OK');

    xlog $self, "reduce the quota limit";
    $self->_set_limits(storage => 100);

    xlog $self, "check that usage is unchanged";
    $self->_check_usages(storage => int($expected/1024));
    xlog $self, "check that smmap reports over quota";
    $self->_check_smmap('cassandane', 'TEMP');

    xlog $self, "try to add another message";
    my $overmsg = eval { $self->make_message("Message $n") };
    my $ex = $@;
    if ($ex) {
        $self->assert($ex =~ m/over quota/i);
    }
    else {
        $self->assert_str_equals('no', $talk->get_last_completion_response());
        $self->assert($talk->get_last_error() =~ m/over quota/i);
    }

    xlog $self, "check that the exceeding message is not in the mailbox";
    $self->check_messages(\%msgs);

    xlog $self, "check that the quota usage is still unchanged";
    $self->_check_usages(storage => int($expected/1024));
    $self->_check_smmap('cassandane', 'TEMP');

    my $delmsg = delete $msgs{1};
    my $dellen = length($delmsg->as_string());
    xlog $self, "delete the first message ($dellen bytes)";
    $talk->select("INBOX");
    $talk->store('1', '+flags', '(\\deleted)');
    $talk->close();

    xlog $self, "check that the deleted message is no longer in the mailbox";
    $self->check_messages(\%msgs);

    xlog $self, "check that the usage has gone down";
    $expected -= $dellen;
    $self->_check_usages(storage => int($expected/1024));

    xlog $self, "check that we are still over quota";
    $self->_check_smmap('cassandane', 'TEMP');
}

sub test_using_message
{
    my ($self) = @_;

    xlog $self, "test increasing usage of the MESSAGE quota resource as messages are added";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits(message => 50000);
    $self->_check_usages(message => 0);

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub")
    {
        $expecteds{$folder} = 0;
        $self->{store}->set_folder($folder);

        for (1..10)
        {
            my $msg = $self->make_message("Message $_");
            $expecteds{$folder}++;
            $expected++;
            $self->_check_usages(message => $expected);
        }
    }

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= $expecteds{"INBOX.sub"};
    $self->_check_usages(message => $expected);

    # delete messages
    $talk->select("INBOX");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages(message => $expected);
}

sub test_using_message_late
{
    my ($self) = @_;

    xlog $self, "test setting MESSAGE quota resource after messages are added";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();
    $self->_check_no_quota();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub")
    {
        $expecteds{$folder} = 0;
        $self->{store}->set_folder($folder);

        for (1..10)
        {
            my $msg = $self->make_message("Message $_");
            $expecteds{$folder}++;
            $expected++;
        }
    }

    $self->_set_limits(message => 50000);
    $self->_check_usages(message => $expected);

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= $expecteds{"INBOX.sub"};
    $self->_check_usages(message => $expected);

    # delete messages
    $talk->select("INBOX");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages(message => $expected);
}

sub test_exceeding_message
{
    my ($self) = @_;

    xlog $self, "test exceeding the MESSAGE quota limit";

    my $talk = $self->{store}->get_client();

    xlog $self, "set a low limit";
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(message => 10);
    $self->_check_usages(message => 0);

    xlog $self, "adding messages to get just below the limit";
    my %msgs;
    for (1..10)
    {
        $msgs{$_} = $self->make_message("Message $_");
    }
    xlog $self, "check that the messages are all in the mailbox";
    $self->check_messages(\%msgs);
    xlog $self, "check that the usage is just below the limit";
    $self->_check_usages(message => 10);

    xlog $self, "add a message that exceeds the limit";
    my $overmsg = eval { $self->make_message("Message 11") };
    # As opposed to storage checking, which is currently done after receiving t
    # (LITERAL) mail, message count checking is performed right away. This earl
    # NO response while writing the LITERAL triggered a die in early versions
    # of IMAPTalk, leaving the completion response undefined.
    my $ex = $@;
    if ($ex) {
        $self->assert($ex =~ m/over quota/i);
    }
    else {
        $self->assert_str_equals('no', $talk->get_last_completion_response());
        $self->assert($talk->get_last_error() =~ m/over quota/i);
    }

    xlog $self, "check that the exceeding message is not in the mailbox";
    $self->_check_usages(message => 10);
    $self->check_messages(\%msgs);
}

sub test_using_annotstorage_msg
{
    my ($self) = @_;

    xlog $self, "test setting X-ANNOTATION-STORAGE quota resource after";
    xlog $self, "per-message annotations are added";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);

    $talk->create("INBOX.sub1") || die "Failed to create subfolder";
    $talk->create("INBOX.sub2") || die "Failed to create subfolder";

    xlog $self, "make some messages to hang annotations on";
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub1", "INBOX.sub2")
    {
        $self->{store}->set_folder($folder);
        $expecteds{$folder} = 0;
        my $uid = 1;
        for (1..5)
        {
            $self->make_message("Message $uid");

            my $data = $self->make_random_data(10);
            $talk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
            $self->assert_str_equals('ok', $talk->get_last_completion_response());
            $uid++;
            $expecteds{$folder} += length($data);
            $expected += length($data);
            $self->_check_usages('x-annotation-storage' => int($expected/1024));
        }
    }

    xlog $self, "delete subfolder sub1";
    $talk->delete("INBOX.sub1") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub1"});

    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "delete messages in sub2";
    $talk->select("INBOX.sub2");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->expunge();

    $expected -= delete($expecteds{"INBOX.sub2"});

    xlog $self, "Unlike STORAGE, X-ANNOTATION-STORAGE quota is reduced immediately";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    $self->run_delayed_expunge();
    $talk = $self->{store}->get_client();

    xlog $self, "X-ANNOTATION-STORAGE quota should not have changed during delayed expunge";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "delete annotations on INBOX";
    $talk->select("INBOX");
    $talk->store('1:*', 'annotation', ['/comment', ['value.priv', undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_using_annotstorage_msg_late
{
    my ($self) = @_;

    xlog $self, "test increasing usage of the X-ANNOTATION-STORAGE quota";
    xlog $self, "resource as per-message annotations are added";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();

    $self->_check_no_quota();

    $talk->create("INBOX.sub1") || die "Failed to create subfolder";
    $talk->create("INBOX.sub2") || die "Failed to create subfolder";

    xlog $self, "make some messages to hang annotations on";
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub1", "INBOX.sub2")
    {
        $self->{store}->set_folder($folder);
        $expecteds{$folder} = 0;
        my $uid = 1;
        for (1..5)
        {
            $self->make_message("Message $uid");

            my $data = $self->make_random_data(10);
            $talk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
            $self->assert_str_equals('ok', $talk->get_last_completion_response());
            $uid++;
            $expecteds{$folder} += length($data);
            $expected += length($data);
        }
    }

    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "delete subfolder sub1";
    $talk->delete("INBOX.sub1") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub1"});
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "delete messages in sub2";
    $talk->select("INBOX.sub2");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->expunge();

    xlog $self, "X-ANNOTATION-STORAGE quota goes down immediately";
    $expected -= delete($expecteds{"INBOX.sub2"});
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    $self->run_delayed_expunge();
    $talk = $self->{store}->get_client();

    xlog $self, "X-ANNOTATION-STORAGE quota should have been unchanged by expunge";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "delete annotations on INBOX";
    $talk->select("INBOX");
    $talk->store('1:*', 'annotation', ['/comment', ['value.priv', undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_using_annotstorage_mbox
{
    my ($self) = @_;

    xlog $self, "test setting X-ANNOTATION-STORAGE quota resource after";
    xlog $self, "per-mailbox annotations are added";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    xlog $self, "store annotations";
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub")
    {
        $expecteds{$folder} = 0;
        $self->{store}->set_folder($folder);
        my $data = '';
        while ($expecteds{$folder} <= 60*1024)
        {
            my $moredata = $self->make_random_data(5);
            $data .= $moredata;
            $talk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $data });
            $self->assert_str_equals('ok', $talk->get_last_completion_response());
            $expecteds{$folder} += length($moredata);
            $expected += length($moredata);
            xlog $self, "EXPECTING $expected on $folder";
            $self->_check_usages('x-annotation-storage' => int($expected/1024));
        }
    }

    # delete subfolder
    xlog $self, "Deleting a folder";
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub"});
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    # delete remaining annotations
    $self->{store}->set_folder("INBOX");
    $talk->setmetadata($self->{store}->{folder}, '/private/comment', undef);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_using_annotstorage_mbox_late
{
    my ($self) = @_;

    xlog $self, "test increasing usage of the X-ANNOTATION-STORAGE quota";
    xlog $self, "resource as per-mailbox annotations are added";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();

    $self->_check_no_quota();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    xlog $self, "store annotations";
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub")
    {
        $expecteds{$folder} = 0;
        $self->{store}->set_folder($folder);
        my $data = '';
        while ($expecteds{$folder} <= 60*1024)
        {
            my $moredata = $self->make_random_data(5);
            $data .= $moredata;
            $talk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $data });
            $self->assert_str_equals('ok', $talk->get_last_completion_response());
            $expecteds{$folder} += length($moredata);
            $expected += length($moredata);
        }
    }

    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub"});
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    # delete remaining annotations
    $self->{store}->set_folder("INBOX");
    $talk->setmetadata($self->{store}->{folder}, '/private/comment', undef);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

#
# Test renames
#
sub test_quotarename
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $talk = $self->{store}->get_client();

    # Right - let's set ourselves a basic usage quota
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 10000,
    );
    $self->_check_usages(
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );

    my $expected_storage = 0;
    my $expected_message = 0;
    my $expected_annotation_storage = 0;
    my $uid = 1;
    for (1..10) {
        my $msg = $self->make_message("Message $_", extra_lines => 5000);
        $expected_storage += length($msg->as_string());
        $expected_message++;

        my $annotation = $self->make_random_data(1);
        $expected_annotation_storage += length($annotation);
        $talk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $annotation }]]);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $uid++;
    }

    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );

    $talk->create("INBOX.sub") || die "Failed to create subfolder";
    $self->{store}->set_folder("INBOX.sub");
    $talk->select($self->{store}->{folder}) || die;
    my $expected_storage_more = $expected_storage;
    my $expected_message_more = $expected_message;
    my $expected_annotation_storage_more = $expected_annotation_storage;
    $uid = 1;
    for (1..10) {

        my $msg = $self->make_message("Message $_",
                                      extra_lines => 10 + rand(5000));
        $expected_storage_more += length($msg->as_string());
        $expected_message_more++;

        my $annotation = $self->make_random_data(1);
        $expected_annotation_storage_more += length($annotation);
        $talk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $annotation }]]);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $uid++;
    }
    $self->{store}->set_folder("INBOX");
    $talk->select($self->{store}->{folder}) || die;

    $self->_check_usages(
        storage => int($expected_storage_more/1024),
        message => $expected_message_more,
        'x-annotation-storage' => int($expected_annotation_storage_more/1024),
    );

    $talk->rename("INBOX.sub", "INBOX.othersub") || die;
    $talk->select("INBOX.othersub") || die;

    # usage should be the same after a rename
    $self->_check_usages(
        storage => int($expected_storage_more/1024),
        message => $expected_message_more,
        'x-annotation-storage' => int($expected_annotation_storage_more/1024),
    );

    $talk->delete("INBOX.othersub") || die;

    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );
}

sub test_quota_d
    :UnixHierarchySep :AltNamespace :VirtDomains
{
    my ($self) = @_;

    my @users = qw(
        alice@foo.com
        bob@foo.com
        chris@bar.com
        dave@qux.com
    );

    my $admintalk = $self->{adminstore}->get_client();

    foreach my $user (@users) {
        $admintalk->create("user/$user");
        $self->_set_limits(
            quotaroot => "user/$user",
            storage => 100000,
            message => 50000,
            'x-annotation-storage' => 10000,
        );

        my $svc = $self->{instance}->get_service('imap');
        my $userstore = $svc->create_store(username => $user);
        my $usertalk = $userstore->get_client();

        foreach my $submbox ('Drafts', 'Junk', 'Sent', 'Trash') {
            xlog $self, "creating $submbox...";
            $usertalk->create($submbox);
            $self->assert_str_equals('ok',
                                    $usertalk->get_last_completion_response());
        }

        foreach my $mbox (qw(INBOX Drafts Sent Junk Trash)) {
            $usertalk->select($mbox);
            foreach (1..3) {
                $self->make_message("msg $_ in $mbox", store => $userstore);
            }
        }
    }

    xlog $self, "run quota";
    my $outfile = $self->{instance}->{basedir} . '/quota.out';
    $self->{instance}->run_command(
        { cyrus => 1,
          redirects => {
            stderr => $outfile,
            stdout => $outfile,
          },
        },
        'quota');

    # should have reported quotas for all users
    my $content = slurp_file($outfile);
    foreach my $user (@users) {
        $self->assert_matches(qr{$user}, $content);
    }

    xlog $self, "run quota -d foo.com";
    $outfile = $self->{instance}->{basedir} . '/quota_d.out';
    $self->{instance}->run_command(
        { cyrus => 1,
          redirects => {
            stderr => $outfile,
            stdout => $outfile,
          },
        },
        'quota', '-d', 'foo.com');

    # should not report quotas for users in other domains!
    $content = slurp_file($outfile);
    $self->assert_matches(qr{alice\@foo.com}, $content);
    $self->assert_matches(qr{bob\@foo.com}, $content);
    $self->assert_does_not_match(qr{chris\@bar.com}, $content);
    $self->assert_does_not_match(qr{dave\@qux.com}, $content);
}

# https://github.com/cyrusimap/cyrus-imapd/issues/2877
sub test_quota_f_no_improved_mboxlist_sort
    :unixHierarchySep :AltNamespace :VirtDomains :NoStartInstances
{
    my ($self) = @_;

    my $user = 'user1@example.com';
    my @otherusers = (
        'user0@example.com',
        'user1-z@example.com',
        'user2@example.com',
    );

    $self->{instance}->{config}->set('improved_mboxlist_sort', 'no');
    $self->_start_instances();

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user/$user");
    $self->assert_str_equals('ok',
                                $admintalk->get_last_completion_response());
    $admintalk->setacl("user/$user", $user, 'lrswipkxtecdan');
    $self->assert_str_equals('ok',
                                $admintalk->get_last_completion_response());

    xlog $self, "set ourselves a basic usage quota";
    $self->_set_limits(
        quotaroot => "user/$user",
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 10000,
    );
    $self->_check_usages(
        quotaroot => "user/$user",
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );

    # create some other users to tickle sort-order issues?
    foreach my $x (@otherusers) {
        $admintalk->create("user/$x");
        $self->_set_limits(
            quotaroot => "user/$x",
            storage => 100000,
            message => 50000,
            'x-annotation-storage' => 10000,
        );
    }

    my $svc = $self->{instance}->get_service('imap');
    my $userstore = $svc->create_store(username => $user);
    my $usertalk = $userstore->get_client();

    foreach my $submbox ('Drafts', 'Junk', 'Sent', 'Trash') {
        xlog $self, "creating $submbox...";
        $usertalk->create($submbox);
        $self->assert_str_equals('ok',
                                  $usertalk->get_last_completion_response());
    }

    $usertalk->list("", "*");

    foreach my $mbox (qw(INBOX Drafts Sent Junk Trash)) {
        $usertalk->select($mbox);
        foreach (1..3) {
            $self->make_message("msg $_ in $mbox", store => $userstore);
        }
    }

    xlog $self, "run quota -d";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'quota', '-d', 'example.com');

    xlog $self, "run quota -d -f";
    my $outfile = $self->{instance}->{basedir} . '/quota.out';
    my @data = $self->{instance}->run_command({
        cyrus => 1,
        redirects => {
            stderr => $outfile,
            stdout => $outfile,
        },
    }, 'quota', '-f', '-d', 'example.com');

    open(FH, "<", $outfile);
    local $/ = undef;
    my $str = <FH>;
    close(FH);
    xlog $self, $str;

    #example.com!user.user1.Junk: quota root example.com!user.user1 --> (none)
    $self->assert_does_not_match(qr{ quota root \S+ --> \(none\)}, $str);
}

sub test_quota_f_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "set ourselves a basic usage quota";
    $self->_set_limits(
        quotaroot => 'user/cassandane',
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 10000,
    );
    $self->_check_usages(
        quotaroot => 'user/cassandane',
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );

    xlog $self, "run quota -f";
    my @data = $self->{instance}->run_command({
        cyrus => 1,
        redirects => { stdout => $self->{instance}{basedir} . '/quota.out' },
    }, 'quota', '-f');

    open(FH, "<", $self->{instance}{basedir} . '/quota.out');
    local $/ = undef;
    my $str = <FH>;
    close(FH);

    $self->assert_matches(qr{STORAGE user/cassandane}, $str);
}

sub test_quota_f
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "set ourselves a basic usage quota";
    $self->_set_limits(
        quotaroot => 'user.cassandane',
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 10000,
    );
    $self->_check_usages(
        quotaroot => 'user.cassandane',
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );

    xlog $self, "create some messages to use various quota resources";
    $self->{instance}->create_user("quotafuser");
    $self->_set_limits(
        quotaroot => 'user.quotafuser',
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 10000,
    );
    $self->{adminstore}->set_folder("user.quotafuser");
    my $quotafuser_expected_storage = 0;
    my $quotafuser_expected_message = 0;
    my $quotafuser_expected_annotation_storage = 0;
    for (1..3) {
        my $msg = $self->make_message("QuotaFUser $_", store => $self->{adminstore}, extra_lines => 17000);
        $quotafuser_expected_storage += length($msg->as_string());
        $quotafuser_expected_message++;
    }
    my $annotation = $self->make_random_data(10);
    $quotafuser_expected_annotation_storage += length($annotation);
    $admintalk->setmetadata('user.quotafuser', '/private/comment', { Quote => $annotation });

    my $cassandane_expected_storage = 0;
    my $cassandane_expected_message = 0;
    my $cassandane_expected_annotation_storage = 0;
    for (1..10) {
        my $msg = $self->make_message("Cassandane $_", extra_lines => 5000);
        $cassandane_expected_storage += length($msg->as_string());
        $cassandane_expected_message++;
    }
    $annotation = $self->make_random_data(3);
    $cassandane_expected_annotation_storage += length($annotation);
    $admintalk->setmetadata('user.cassandane', '/private/comment', { Quote => $annotation });

    xlog $self, "check usages";
    $self->_check_usages(
        quotaroot => 'user.quotafuser',
        storage => int($quotafuser_expected_storage/1024),
        message => $quotafuser_expected_message,
        'x-annotation-storage' => int($quotafuser_expected_annotation_storage/1024),
    );
    $self->_check_usages(
        quotaroot => 'user.cassandane',
        storage => int($cassandane_expected_storage/1024),
        message => $cassandane_expected_message,
        'x-annotation-storage' => int($cassandane_expected_annotation_storage/1024),
    );

    xlog $self, "create a bogus quota file";
    $self->_zap_quota(quotaroot => 'user.quotafuser');

    xlog $self, "check usages";
    $self->_check_usages(
        quotaroot => 'user.quotafuser',
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );
    $self->_check_usages(
        quotaroot => 'user.cassandane',
        storage => int($cassandane_expected_storage/1024),
        message => $cassandane_expected_message,
        'x-annotation-storage' => int($cassandane_expected_annotation_storage/1024),
    );

    xlog $self, "find and add the quota";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');

    xlog $self, "check usages";
    $self->_check_usages(
        quotaroot => 'user.quotafuser',
        storage => int($quotafuser_expected_storage/1024),
        message => $quotafuser_expected_message,
        'x-annotation-storage' => int($quotafuser_expected_annotation_storage/1024),
    );
    $self->_check_usages(
        quotaroot => 'user.cassandane',
        storage => int($cassandane_expected_storage/1024),
        message => $cassandane_expected_message,
        'x-annotation-storage' => int($cassandane_expected_annotation_storage/1024),
    );

    xlog $self, "re-run the quota utility";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');

    xlog $self, "check usages";
    $self->_check_usages(
        quotaroot => 'user.quotafuser',
        storage => int($quotafuser_expected_storage/1024),
        message => $quotafuser_expected_message,
        'x-annotation-storage' => int($quotafuser_expected_annotation_storage/1024),
    );
    $self->_check_usages(
        quotaroot => 'user.cassandane',
        storage => int($cassandane_expected_storage/1024),
        message => $cassandane_expected_message,
        'x-annotation-storage' => int($cassandane_expected_annotation_storage/1024),
    );
}

# Test races between quota -f and updates to mailboxes
sub test_quota_f_vs_update
    :NoAltNameSpace
{
    my ($self) = @_;

    my $basefolder = "user.cassandane";
    my @folders = qw(a b c d e);
    my $msg;
    my $expected;

    xlog $self, "Set up a large but limited quota";
    $self->_set_quotaroot($basefolder);
    $self->_set_limits(storage => 1000000);
    $self->_check_usages(storage => 0);
    my $talk = $self->{store}->get_client();

    xlog $self, "Create some sub folders";
    for my $f (@folders)
    {
        $talk->create("$basefolder.$f") || die "Failed $@";
        $self->{store}->set_folder("$basefolder.$f");
        $msg = $self->make_message("Cassandane $f",
                                      extra_lines => 2000+rand(5000));
        $expected += length($msg->as_string());
    }
    # unselect so quota -f can lock the mailboxes
    $talk->unselect();

    xlog $self, "Check that we have some quota usage";
    $self->_check_usages(storage => int($expected/1024));

    xlog $self, "Start a quota -f scan";
    $self->{instance}->quota_Z_go($basefolder);
    $self->{instance}->quota_Z_go("$basefolder.a");
    $self->{instance}->quota_Z_go("$basefolder.b");
    my (@bits) = $self->{instance}->run_command({ cyrus => 1, background => 1 },
        'quota', '-Z', '-f', $basefolder);

    # waiting for quota -f to ensure that
    # a) the -Z mechanism is working and
    # b) quota -f has at least initialised and started scanning.
    $self->{instance}->quota_Z_wait("$basefolder.b");

    # quota -f is now waiting to be allowed to proceed to "c"

    xlog $self, "Mailbox update behind the scan";
    $self->{store}->set_folder("$basefolder.b");
    $msg = $self->make_message("Cassandane b UPDATE",
                                  extra_lines => 2000+rand(3000));
    $expected += length($msg->as_string());

    xlog $self, "Mailbox update in front of the scan";
    $self->{store}->set_folder("$basefolder.d");
    $msg = $self->make_message("Cassandane d UPDATE",
                                  extra_lines => 2000+rand(3000));
    $expected += length($msg->as_string());

    xlog $self, "Let quota -f continue and finish";
    $self->{instance}->quota_Z_go("$basefolder.c");
    $self->{instance}->quota_Z_go("$basefolder.d");
    $self->{instance}->quota_Z_go("$basefolder.e");
    $self->{instance}->quota_Z_wait("$basefolder.e");
    $self->{instance}->reap_command(@bits);

    xlog $self, "Check that we have the correct quota usage";
    $self->_check_usages(storage => int($expected/1024));
}

sub test_quota_f_nested_qr
    :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Test that quota -f correctly calculates the STORAGE quota";
    xlog $self, "with a nested quotaroot and a folder whose name sorts after";
    xlog $self, "the nested quotaroot [Bug 3621]";

    my $inbox = "user.cassandane";
    # These names are significant - we need subfolders both before and
    # after the subfolder on which we will set the nested quotaroot
    my @folders = ( $inbox, "$inbox.aaa", "$inbox.nnn", "$inbox.zzz" );

    xlog $self, "add messages to use some STORAGE quota";
    my %exp;
    my $n = 5;
    foreach my $f (@folders)
    {
        $self->{store}->set_folder($f);
        for (1..$n) {
            my $msg = $self->make_message("$f $_",
                                          extra_lines => 10 + rand(5000));
            $exp{$f} += length($msg->as_string());
        }
        $n += 5;
        xlog $self, "Expect " . $exp{$f} . " on " . $f;
    }

    xlog $self, "set a quota on inbox";
    $self->_set_limits(quotaroot => $inbox, storage => 100000);

    xlog $self, "should have correct STORAGE quota";
    my $ex0 = $exp{$inbox} + $exp{"$inbox.aaa"} + $exp{"$inbox.nnn"} + $exp{"$inbox.zzz"};
    $self->_check_usages(quotaroot => $inbox, storage => int($ex0/1024));

    xlog $self, "set a quota on inbox.nnn - a nested quotaroot";
    $self->_set_limits(quotaroot => "$inbox.nnn", storage => 200000);

    xlog $self, "should have correct STORAGE quota for both roots";
    my $ex1 = $exp{$inbox} + $exp{"$inbox.aaa"} + $exp{"$inbox.zzz"};
    my $ex2 = $exp{"$inbox.nnn"};
    $self->_check_usages(quotaroot => $inbox, storage => int($ex1/1024));
    $self->_check_usages(quotaroot => "$inbox.nnn", storage => int($ex2/1024));

    xlog $self, "create a bogus quota file";
    $self->_zap_quota(quotaroot => $inbox);
    $self->_zap_quota(quotaroot => "$inbox.nnn");
    $self->_check_usages(quotaroot => $inbox, storage => 0);
    $self->_check_usages(quotaroot => "$inbox.nnn", storage => 0);

    xlog $self, "run quota -f to find and add the quota";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');

    xlog $self, "check that STORAGE quota is restored for both roots";
    $self->_check_usages(quotaroot => $inbox, storage => int($ex1/1024));
    $self->_check_usages(quotaroot => "$inbox.nnn", storage => int($ex2/1024));

    xlog $self, "run quota -f again";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');

    xlog $self, "check that STORAGE quota is still correct for both roots";
    $self->_check_usages(quotaroot => $inbox, storage => int($ex1/1024));
    $self->_check_usages(quotaroot => "$inbox.nnn", storage => int($ex2/1024));
}

sub test_quota_f_prefix
{
    my ($self) = @_;

    xlog $self, "Testing prefix matches with quota -f [IRIS-1029]";

    my $admintalk = $self->{adminstore}->get_client();

    # surround with other users too
    $self->{instance}->create_user("aabefore",
                                   subdirs => [ qw(subdir subdir2) ]);

    $self->{instance}->create_user("zzafter",
                                   subdirs => [ qw(subdir subdir2) ]);

    $self->{instance}->create_user("base",
                                   subdirs => [ qw(subdir subdir2) ]);
    $self->_set_limits(quotaroot => 'user.base', storage => 1000000);
    my $exp_base = 0;

    xlog $self, "Adding messages to user.base";
    $self->{adminstore}->set_folder("user.base");
    for (1..10) {
        my $msg = $self->make_message("base $_",
                                      store => $self->{adminstore},
                                      extra_lines => 5000+rand(50000));
        $exp_base += length($msg->as_string());
    }

    xlog $self, "Adding messages to user.base.subdir2";
    $self->{adminstore}->set_folder("user.base.subdir2");
    for (1..10) {
        my $msg = $self->make_message("base subdir2 $_",
                                      store => $self->{adminstore},
                                      extra_lines => 5000+rand(50000));
        $exp_base += length($msg->as_string());
    }

    $self->{instance}->create_user("baseplus",
                                   subdirs => [ qw(subdir) ]);
    $self->_set_limits(quotaroot => 'user.baseplus', storage => 1000000);
    my $exp_baseplus = 0;

    xlog $self, "Adding messages to user.baseplus";
    $self->{adminstore}->set_folder("user.baseplus");
    for (1..10) {
        my $msg = $self->make_message("baseplus $_",
                                      store => $self->{adminstore},
                                      extra_lines => 5000+rand(50000));
        $exp_baseplus += length($msg->as_string());
    }

    xlog $self, "Adding messages to user.baseplus.subdir";
    $self->{adminstore}->set_folder("user.baseplus.subdir");
    for (1..10) {
        my $msg = $self->make_message("baseplus subdir $_",
                                      store => $self->{adminstore},
                                      extra_lines => 5000+rand(50000));
        $exp_baseplus += length($msg->as_string());
    }

    xlog $self, "Check that the quotas were updated as expected";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($exp_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($exp_baseplus/1024));

    xlog $self, "Run quota -f";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');

    xlog $self, "Check that the quotas were unchanged by quota -f";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($exp_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($exp_baseplus/1024));

    my $bogus_base = $exp_base + 20000 + rand(30000);
    my $bogus_baseplus = $exp_baseplus + 50000 + rand(80000);
    xlog $self, "Write incorrect values to the quota db";
    $self->_zap_quota(quotaroot => 'user.base',
                      useds => { storage => $bogus_base });
    $self->_zap_quota(quotaroot => 'user.baseplus',
                      useds => { storage => $bogus_baseplus });

    xlog $self, "Check that the quotas are now bogus";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($bogus_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($bogus_baseplus/1024));

    xlog $self, "Run quota -f with no prefix";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');

    xlog $self, "Check that the quotas were all fixed";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($exp_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($exp_baseplus/1024));

    xlog $self, "Write incorrect values to the quota db";
    $self->_zap_quota(quotaroot => "user.base",
                      useds => { storage => $bogus_base });
    $self->_zap_quota(quotaroot => "user.baseplus",
                      useds => { storage => $bogus_baseplus });

    xlog $self, "Check that the quotas are now bogus";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($bogus_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($bogus_baseplus/1024));

    xlog $self, "Run quota -f on user.base only";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f', 'user.base');

    xlog $self, "Check that only the user.base and user.baseplus quotas were fixed";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($exp_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($exp_baseplus/1024));

    xlog $self, "Write incorrect values to the quota db";
    $self->_zap_quota(quotaroot => "user.base",
                      useds => { storage => $bogus_base });
    $self->_zap_quota(quotaroot => "user.baseplus",
                      useds => { storage => $bogus_baseplus });

    xlog $self, "Check that the quotas are now bogus";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($bogus_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($bogus_baseplus/1024));

    xlog $self, "Run quota -f on user.baseplus only";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f', 'user.baseplus');

    xlog $self, "Check that only the user.baseplus quotas were fixed";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($bogus_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($exp_baseplus/1024));

    xlog $self, "Write incorrect values to the quota db";
    $self->_zap_quota(quotaroot => "user.base",
                      useds => { storage => $bogus_base });
    $self->_zap_quota(quotaroot => "user.baseplus",
                      useds => { storage => $bogus_baseplus });

    xlog $self, "Check that the quotas are now bogus";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($bogus_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($bogus_baseplus/1024));

    xlog $self, "Run quota -f -u on user base ";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f', '-u', 'base');

    xlog $self, "Check that only the user base quotas were fixed";
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($exp_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($bogus_baseplus/1024));

    xlog $self, "Run a final quota -f to fix up everything";
    $self->{instance}->run_command({ cyrus => 1 }, 'quota', '-f');
    $self->_check_usages(quotaroot => 'user.base',
                         storage => int($exp_base/1024));
    $self->_check_usages(quotaroot => 'user.baseplus',
                         storage => int($exp_baseplus/1024));
}

sub bogus_test_upgrade_v2_4
{
    my ($self) = @_;

    xlog $self, "test resources usage computing upon upgrading a cyrus v2.4 mailbox";

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);

    xlog $self, "store annotations";
    my $data = $self->make_random_data(10);
    my $expected_annotation_storage = length($data);
    $talk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $data });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->_check_usages('x-annotation-storage' => int($expected_annotation_storage/1024));

    xlog $self, "restore cyrus v2.4 mailbox content and quota file";
    $self->{instance}->unpackfile(abs_path('data/cyrus/quota_upgrade_v2_4.user.tar.gz'), 'data/user');
    $self->{instance}->unpackfile(abs_path('data/cyrus/quota_upgrade_v2_4.quota.tar.gz'), 'conf/quota/c');

    xlog $self, "upgrade to version 13 format (v2.5.0)";
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', '-V' => 13);

    # count messages and size from restored mailbox
    my $expected_storage = 0;
    my $expected_message = 0;
    $talk->select($self->{store}->{folder});
    my $responses = $talk->fetch('1:*', 'RFC822.SIZE');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($responses);
    foreach my $response (values(%$responses)) {
        $expected_message++;
        $expected_storage += $response->{'rfc822.size'};
    }
    $talk->close();

    # check we did restore something
    $self->assert_num_not_equals($expected_storage, 0);
    $self->assert_num_not_equals($expected_message, 0);

    # set quota limits on resources which did not exist in previous cyrus versions;
    # when the mailbox was upgraded, new resources quota usage shall have been
    # computed automatically
    $self->_set_limits(
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 10000,
    );
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );
}

sub test_bz3529
{
    my ($self) = @_;

    xlog $self, "testing annot storage quota when setting annots on multiple";
    xlog $self, "messages in a single STORE command, using quotalegacy backend.";

    # double check that some other part of Cassandane didn't
    # accidentally futz with the expected quota db backend
    my $backend = $self->{instance}->{config}->get('quota_db');
    $self->assert_str_equals('quotalegacy', $backend)
        if defined $backend;        # the default value is also ok

    $self->_set_quotaroot('user.cassandane');
    my $talk = $self->{store}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);

    xlog $self, "make some messages to hang annotations on";
#       $self->{store}->set_folder($folder);
    my $uid = 1;
    my %msgs;
    for (1..20)
    {
        $msgs{$uid} = $self->make_message("Message $uid");
        $msgs{$uid}->set_attribute('uid', $uid);
        $uid++;
    }

    my $data = $self->make_random_data(30);
    $talk->store('1:*', 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $expected = ($uid-1) * length($data);
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    # delete annotations
    $talk->store('1:*', 'annotation', ['/comment', ['value.priv', undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->_check_usages('x-annotation-storage' => 0);
}

# Magic: the word 'replication' in the name enables a replica
sub test_replication_storage
{
    my ($self) = @_;

    xlog $self, "testing replication of STORAGE quota";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set a STORAGE quota on the master";
    $mastertalk->setquota($folder, "(storage 12345)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 12345], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 12345], \@res);

    xlog $self, "change the STORAGE quota on the master";
    $mastertalk->setquota($folder, "(storage 67890)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 67890], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 67890], \@res);

    xlog $self, "clear the STORAGE quota on the master";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

# Magic: the word 'replication' in the name enables a replica
sub test_replication_message
{
    my ($self) = @_;

    xlog $self, "testing replication of MESSAGE quota";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set a STORAGE quota on the master";
    $mastertalk->setquota($folder, "(message 12345)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 12345], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 12345], \@res);

    xlog $self, "change the MESSAGE quota on the master";
    $mastertalk->setquota($folder, "(message 67890)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 67890], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 67890], \@res);

    xlog $self, "clear the MESSAGE quota on the master";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

# Magic: the word 'replication' in the name enables a replica
sub test_replication_annotstorage
{
    my ($self) = @_;

    xlog $self, "testing replication of X-ANNOTATION-STORAGE quota";

    my $folder = "user.cassandane";
    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set an X-ANNOTATION-STORAGE quota on the master";
    $mastertalk->setquota($folder, "(x-annotation-storage 12345)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 12345], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 12345], \@res);

    xlog $self, "change the X-ANNOTATION-STORAGE quota on the master";
    $mastertalk->setquota($folder, "(x-annotation-storage 67890)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 67890], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 67890], \@res);

    xlog $self, "add an annotation to use some quota";
    my $data = $self->make_random_data(13);
    my $msg = $self->make_message("Message A", store => $self->{master_store});
    $mastertalk->store('1', 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
## This doesn't work because per-mailbox annots are not
## replicated when sync_client is run in -u mode...sigh
#     $mastertalk->setmetadata($folder, '/private/comment', { Quote => $data });
#     $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    my $used = int(length($data)/1024);

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check the annotation used some quota on the master";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([
        'X-ANNOTATION-STORAGE', $used, 67890
    ], \@res);

    xlog $self, "check the annotation used some quota on the replica";
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([
        'X-ANNOTATION-STORAGE', $used, 67890
    ], \@res);

    xlog $self, "clear the X-ANNOTATION-STORAGE quota on the master";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}


sub XXtest_getset_multiple
{
    my ($self) = @_;

    xlog $self, "testing getting and setting multiple quota resources";

    my $admintalk = $self->{adminstore}->get_client();
    my $folder = "user.cassandane";
    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert($admintalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set both X-ANNOT-COUNT and X-ANNOT-SIZE quotas";
    $admintalk->setquota($folder, "(x-annot-count 20 x-annot-size 16384)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "get both resources back, and not STORAGE";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);

    xlog $self, "set the X-ANNOT-SIZE resource only";
    $admintalk->setquota($folder, "(x-annot-size 32768)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "get new -SIZE only and neither STORAGE nor -COUNT";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);

    xlog $self, "set all of -COUNT -SIZE and STORAGE";
    $admintalk->setquota($folder, "(x-annot-count 123 storage 123456 x-annot-size 65536)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "get back all three new values";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 123456, 'X-ANNOT-COUNT', 0, 123, 'X-ANNOT-SIZE', 0, 65536], \@res);

    xlog $self, "clear all quotas";
    $admintalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # Note: the RFC does not define what happens if you remove all the
    # quotas from a quotaroot.  Cyrus leaves the quotaroot around until
    # quota -f is run to clean it up.
    xlog $self, "get back an empty set of quotas, but the quota root still exists";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

# Magic: the word 'replication' in the name enables a replica
sub XXtest_replication_multiple
{
    my ($self) = @_;

    xlog $self, "testing replication of multiple quotas";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog $self, "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog $self, "set a X-ANNOT-COUNT and X-ANNOT-SIZE quotas on the master";
    $mastertalk->setquota($folder, "(x-annot-count 20 x-annot-size 16384)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);

    xlog $self, "set the X-ANNOT-SIZE quota on the master";
    $mastertalk->setquota($folder, "(x-annot-size 32768)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);

    xlog $self, "clear all the quotas";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog $self, "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

sub test_using_annotstorage_msg_copy_exdel
    :DelayedExpunge
{
    my ($self) = @_;

    xlog $self, "testing X-ANNOTATION-STORAGE quota usage as messages are COPYd";
    xlog $self, "and original messages are deleted, expunge_mode=delayed version";
    xlog $self, "(BZ3527)";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $from_folder = 'INBOX.from';
    my $to_folder = 'INBOX.to';

    xlog $self, "Check the expunge mode is \"delayed\"";
    my $expunge_mode = $self->{instance}->{config}->get('expunge_mode');
    $self->assert_str_equals('delayed', $expunge_mode);

    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);
    my $talk = $self->{store}->get_client();

    my $store = $self->{store};
    $store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Create subfolders to copy from and to";
    $talk = $store->get_client();
    $talk->create($from_folder)
        or die "Cannot create mailbox $from_folder: $@";
    $talk->create($to_folder)
        or die "Cannot create mailbox $to_folder: $@";

    $store->set_folder($from_folder);

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $expected = 0;
    my $uid = 1;
    for (1..20)
    {
        my $data = $self->make_random_data(10);
        my $msg = $self->make_message("Message $uid");
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($entry, $attrib, $data);
        $exp{$uid} = $msg;
        $talk->store('' . $uid, 'annotation', [$entry, [$attrib, { Quote => $data }]]);
        $expected += length($data);
        $uid++;
    }

    xlog $self, "Check the annotations are there";
    $self->check_messages(\%exp);
    xlog $self, "Check the quota usage is correct";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "COPY the messages";
    $talk = $store->get_client();
    $talk->copy('1:*', $to_folder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Messages are now in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage is now doubled";
    $self->_check_usages('x-annotation-storage' => int(2*$expected/1024));

    xlog $self, "Messages are still in the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Delete the messages from the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $talk = $store->get_client();
    $talk->store('1:*', '+flags', '(\\Deleted)');
    $talk->expunge();

    xlog $self, "Messages are gone from the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages({});

    xlog $self, "Messages are still in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage has reduced again";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    $self->run_delayed_expunge();

    xlog $self, "Check the quota usage is still the same";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_using_annotstorage_msg_copy_eximm
    :ImmediateExpunge
{
    my ($self) = @_;

    xlog $self, "testing X-ANNOTATION-STORAGE quota usage as messages are COPYd";
    xlog $self, "and original messages are deleted, expunge_mode=immediate version";
    xlog $self, "(BZ3527)";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $from_folder = 'INBOX.from';
    my $to_folder = 'INBOX.to';

    xlog $self, "Check the expunge mode is \"immediate\"";
    my $expunge_mode = $self->{instance}->{config}->get('expunge_mode');
    $self->assert_str_equals('immediate', $expunge_mode);

    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);
    my $talk = $self->{store}->get_client();

    my $store = $self->{store};
    $store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Create subfolders to copy from and to";
    $talk = $store->get_client();
    $talk->create($from_folder)
        or die "Cannot create mailbox $from_folder: $@";
    $talk->create($to_folder)
        or die "Cannot create mailbox $to_folder: $@";

    $store->set_folder($from_folder);

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $expected = 0;
    my $uid = 1;
    for (1..20)
    {
        my $data = $self->make_random_data(10);
        my $msg = $self->make_message("Message $uid");
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($entry, $attrib, $data);
        $exp{$uid} = $msg;
        $talk->store('' . $uid, 'annotation', [$entry, [$attrib, { Quote => $data }]]);
        $expected += length($data);
        $uid++;
    }

    xlog $self, "Check the annotations are there";
    $self->check_messages(\%exp);
    xlog $self, "Check the quota usage is correct";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "COPY the messages";
    $talk = $store->get_client();
    $talk->copy('1:*', $to_folder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Messages are now in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage is now doubled";
    $self->_check_usages('x-annotation-storage' => int(2*$expected/1024));

    xlog $self, "Messages are still in the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Delete the messages from the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $talk = $store->get_client();
    $talk->store('1:*', '+flags', '(\\Deleted)');
    $talk->expunge();

    xlog $self, "Messages are gone from the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages({});

    xlog $self, "Messages are still in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage is back to single";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_using_annotstorage_msg_copy_dedel
    :DelayedDelete
{
    my ($self) = @_;

    xlog $self, "testing X-ANNOTATION-STORAGE quota usage as messages are COPYd";
    xlog $self, "and original folder is deleted, delete_mode=delayed version";
    xlog $self, "(BZ3527)";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $from_folder = 'INBOX.from';
    my $to_folder = 'INBOX.to';

    xlog $self, "Check the delete mode is \"delayed\"";
    my $delete_mode = $self->{instance}->{config}->get('delete_mode');
    $self->assert_str_equals('delayed', $delete_mode);

    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);
    my $talk = $self->{store}->get_client();

    my $store = $self->{store};
    $store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Create subfolders to copy from and to";
    $talk = $store->get_client();
    $talk->create($from_folder)
        or die "Cannot create mailbox $from_folder: $@";
    $talk->create($to_folder)
        or die "Cannot create mailbox $to_folder: $@";

    $store->set_folder($from_folder);

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $expected = 0;
    my $uid = 1;
    for (1..20)
    {
        my $data = $self->make_random_data(10);
        my $msg = $self->make_message("Message $uid");
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($entry, $attrib, $data);
        $exp{$uid} = $msg;
        $talk->store('' . $uid, 'annotation', [$entry, [$attrib, { Quote => $data }]]);
        $expected += length($data);
        $uid++;
    }

    xlog $self, "Check the annotations are there";
    $self->check_messages(\%exp);
    xlog $self, "Check the quota usage is correct";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "COPY the messages";
    $talk = $store->get_client();
    $talk->copy('1:*', $to_folder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Messages are now in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage is now doubled";
    $self->_check_usages('x-annotation-storage' => int(2*$expected/1024));

    xlog $self, "Messages are still in the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Delete the origin folder";
    $talk = $store->get_client();
    $talk->unselect();
    $talk->delete($from_folder)
        or die "Cannot delete folder $from_folder: $@";

    xlog $self, "Messages are still in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    # Note that, unlike with delayed expunge, with delayed delete the
    # annotations are deleted immediately and so the negative delta to
    # quota is applied immediately.  Whether this is sensible is a
    # different question.

    xlog $self, "Check the quota usage is back to single";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    $self->run_delayed_expunge();

    xlog $self, "Check the quota usage is still back to single";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_using_annotstorage_msg_copy_deimm
    :ImmediateDelete
{
    my ($self) = @_;

    xlog $self, "testing X-ANNOTATION-STORAGE quota usage as messages are COPYd";
    xlog $self, "and original folder is deleted, delete_mode=immediate version";
    xlog $self, "(BZ3527)";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $from_folder = 'INBOX.from';
    my $to_folder = 'INBOX.to';

    xlog $self, "Check the delete mode is \"immediate\"";
    my $delete_mode = $self->{instance}->{config}->get('delete_mode');
    $self->assert_str_equals('immediate', $delete_mode);

    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_limits('x-annotation-storage' => 100000);
    $self->_check_usages('x-annotation-storage' => 0);
    my $talk = $self->{store}->get_client();

    my $store = $self->{store};
    $store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Create subfolders to copy from and to";
    $talk = $store->get_client();
    $talk->create($from_folder)
        or die "Cannot create mailbox $from_folder: $@";
    $talk->create($to_folder)
        or die "Cannot create mailbox $to_folder: $@";

    $store->set_folder($from_folder);

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $expected = 0;
    my $uid = 1;
    for (1..20)
    {
        my $data = $self->make_random_data(10);
        my $msg = $self->make_message("Message $uid");
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($entry, $attrib, $data);
        $exp{$uid} = $msg;
        $talk->store('' . $uid, 'annotation', [$entry, [$attrib, { Quote => $data }]]);
        $expected += length($data);
        $uid++;
    }

    xlog $self, "Check the annotations are there";
    $self->check_messages(\%exp);
    xlog $self, "Check the quota usage is correct";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));

    xlog $self, "COPY the messages";
    $talk = $store->get_client();
    $talk->copy('1:*', $to_folder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Messages are now in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage is now doubled";
    $self->_check_usages('x-annotation-storage' => int(2*$expected/1024));

    xlog $self, "Messages are still in the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Delete the origin folder";
    $talk = $store->get_client();
    $talk->unselect();
    $talk->delete($from_folder)
        or die "Cannot delete folder $from_folder: $@";

    xlog $self, "Messages are still in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Check the quota usage is back to single";
    $self->_check_usages('x-annotation-storage' => int($expected/1024));
}

sub test_reconstruct
{
    my ($self) = @_;

    xlog $self, "test resources usage calculated when reconstructing an index";

    $self->_set_quotaroot('user.cassandane');
    my $folder = 'INBOX';
    my $fentry = '/private/comment';
    my $mentry1 = '/comment';
    my $mentry2 = '/altsubject';
    my $mattrib = 'value.priv';

    my $store = $self->{store};
    $store->set_fetch_attributes('uid',
                                 "annotation ($mentry1 $mattrib)",
                                 "annotation ($mentry2 $mattrib)");
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits(
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 100000,
    );
    $self->_check_usages(
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );
    my $expected_annotation_storage = 0;
    my $expected_storage = 0;
    my $expected_message = 0;

    xlog $self, "store annotations";
    my $data = $self->make_random_data(10);
    $expected_annotation_storage += length($data);
    $talk->setmetadata($folder, $fentry, { Quote => $data });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "add some messages";
    my $uid = 1;
    my %exp;
    for (1..10)
    {
        my $msg = $self->make_message("Message $_",
                                      extra_lines => 10 + rand(5000));
        $exp{$uid} = $msg;
        my $data1 = $self->make_random_data(7);
        my $data2 = $self->make_random_data(3);
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($mentry1, $mattrib, $data1);
        $msg->set_annotation($mentry2, $mattrib, $data2);
        $talk->store('' . $uid, 'annotation',
                    [$mentry1, [$mattrib, { Quote => $data1 }],
                     $mentry2, [$mattrib, { Quote => $data2 }]]);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $expected_annotation_storage += (length($data1) + length($data2));
        $expected_storage += length($msg->as_string());
        $expected_message++;
        $uid++;
    }

    xlog $self, "Check the messages are all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the mailbox annotation is still there";
    my $res = $talk->getmetadata($folder, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "Check the quota usage is as expected";
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );

    $self->{store}->disconnect();
    $self->{adminstore}->disconnect();
    $talk = undef;
    $admintalk = undef;

    xlog $self, "Moving the cyrus.index file out of the way";
    my $datadir = $self->{instance}->folder_to_directory('user.cassandane');
    my $cyrus_index = "$datadir/cyrus.index";
    $self->assert(( -f $cyrus_index ));
    rename($cyrus_index, $cyrus_index . '.NOT')
        or die "Cannot rename $cyrus_index: $!";

    xlog $self, "Running reconstruct";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'reconstruct', 'user.cassandane');
    xlog $self, "Running quota -f";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'quota', '-f', "user.cassandane");

    $talk = $store->get_client();

    xlog $self, "Check the messages are still all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the mailbox annotation is still there";
    $res = $talk->getmetadata($folder, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "Check the quota usage is still as expected";
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR or two
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: opening index/, "@lines");
    }
}

sub test_reconstruct_orphans
{
    my ($self) = @_;

    xlog $self, "test resources usage calculated when reconstructing an index";
    xlog $self, "with messages disappearing, resulting in orphan annotations";

    $self->_set_quotaroot('user.cassandane');
    my $folder = 'INBOX';
    my $fentry = '/private/comment';
    my $mentry1 = '/comment';
    my $mentry2 = '/altsubject';
    my $mattrib = 'value.priv';

    my $store = $self->{store};
    $store->set_fetch_attributes('uid',
                                 "annotation ($mentry1 $mattrib)",
                                 "annotation ($mentry2 $mattrib)");
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits(
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 100000,
    );
    $self->_check_usages(
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );
    my $expected_annotation_storage = 0;
    my $expected_storage = 0;
    my $expected_message = 0;

    xlog $self, "store annotations";
    my $data = $self->make_random_data(10);
    $expected_annotation_storage += length($data);
    $talk->setmetadata($folder, $fentry, { Quote => $data });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "add some messages";
    my $uid = 1;
    my %exp;
    for (1..10)
    {
        my $msg = $self->make_message("Message $_",
                                      extra_lines => 10 + rand(5000));
        $exp{$uid} = $msg;
        my $data1 = $self->make_random_data(7);
        my $data2 = $self->make_random_data(3);
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($mentry1, $mattrib, $data1);
        $msg->set_annotation($mentry2, $mattrib, $data2);
        $talk->store('' . $uid, 'annotation',
                    [$mentry1, [$mattrib, { Quote => $data1 }],
                     $mentry2, [$mattrib, { Quote => $data2 }]]);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $expected_annotation_storage += (length($data1) + length($data2));
        $expected_storage += length($msg->as_string());
        $expected_message++;
        $uid++;
    }

    xlog $self, "Check the messages are all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the mailbox annotation is still there";
    my $res = $talk->getmetadata($folder, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "Check the quota usage is as expected";
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );

    $self->{store}->disconnect();
    $self->{adminstore}->disconnect();
    $talk = undef;
    $admintalk = undef;

    xlog $self, "Moving the cyrus.index file out of the way";
    my $datadir = $self->{instance}->folder_to_directory('user.cassandane');
    my $cyrus_index = "$datadir/cyrus.index";
    $self->assert(( -f $cyrus_index ));
    rename($cyrus_index, $cyrus_index . '.NOT')
        or die "Cannot rename $cyrus_index: $!";

    xlog $self, "Delete a couple of messages";
    foreach $uid (2, 7)
    {
        xlog $self, "Deleting uid $uid";
        unlink("$datadir/$uid.");

        my $msg = delete $exp{$uid};
        my $data1 = $msg->get_annotation($mentry1, $mattrib);
        my $data2 = $msg->get_annotation($mentry2, $mattrib);

        $expected_annotation_storage -= (length($data1) + length($data2));
        $expected_storage -= length($msg->as_string());
        $expected_message--;
    }

    xlog $self, "Running reconstruct";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'reconstruct', 'user.cassandane');
    xlog $self, "Running quota -f";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'quota', '-f', "user.cassandane");

    $talk = $store->get_client();

    xlog $self, "Check the messages are still all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the mailbox annotation is still there";
    $res = $talk->getmetadata($folder, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "Check the quota usage is still as expected";
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR or two
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: opening index/, "@lines");
    }
}

Cassandane::Cyrus::TestCase::magic(Bug3735 => sub {
    my ($testcase) = @_;
    $testcase->config_set(quota_db => 'quotalegacy');
    $testcase->config_set(hashimapspool => 1);
    $testcase->config_set(fulldirhash => 1);
    $testcase->config_set(virtdomains => 0);
});

sub test_bug3735
    :Bug3735
{
    my ($self) = @_;
    $self->{instance}->create_user("a");
    $self->{instance}->create_user("ab");
    $self->_set_quotaroot('user.a');
    $self->_set_limits(storage => 12345);
    $self->_set_quotaroot('user.ab');
    $self->_set_limits(storage => 12345);

    my $filename = $self->{instance}->{basedir} . "/bug3735.out";

    $self->{instance}->run_command({
        cyrus => 1,
        redirects => { stdout => $filename },
    }, 'quota', "user.a");

    open RESULTS, '<', $filename
        or die "Cannot open $filename for reading: $!";
    my @res = <RESULTS>;
    close RESULTS;

    $self->assert(grep { m/user\.ab/ } @res);
}

sub test_rename_withannot
{
    my ($self) = @_;
    my ($cyrus_version) = Cassandane::Instance->get_version();

    xlog $self, "test resources usage survives rename";

    $self->_set_quotaroot('user.cassandane');
    my $src = 'INBOX.src';
    my $dest = 'INBOX.dest';
    my $fentry = '/private/comment';
    my $mentry1 = '/comment';
    my $mentry2 = '/altsubject';
    my $mattrib = 'value.priv';
    my $vendsize = "/shared/vendor/cmu/cyrus-imapd/size";
    my $vendannot = "/shared/vendor/cmu/cyrus-imapd/annotsize";

    my $store = $self->{store};
    $store->set_fetch_attributes('uid',
                                 "annotation ($mentry1 $mattrib)",
                                 "annotation ($mentry2 $mattrib)");
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    $talk->create($src) || die "Failed to create subfolder";
    $store->set_folder($src);

    xlog $self, "set ourselves a basic limit";
    $self->_set_limits(
        storage => 100000,
        message => 50000,
        'x-annotation-storage' => 100000,
    );
    $self->_check_usages(
        storage => 0,
        message => 0,
        'x-annotation-storage' => 0,
    );
    my $expected_annotation_storage = 0;
    my $expected_storage = 0;
    my $expected_message = 0;

    xlog $self, "store annotations";
    my $data = $self->make_random_data(10);
    $expected_annotation_storage += length($data);
    $talk->setmetadata($src, $fentry, { Quote => $data });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "add some messages";
    my $uid = 1;
    my %exp;
    for (1..10)
    {
        my $msg = $self->make_message("Message $_",
                                      extra_lines => 10 + rand(5000));
        $exp{$uid} = $msg;
        my $data1 = $self->make_random_data(7);
        my $data2 = $self->make_random_data(3);
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($mentry1, $mattrib, $data1);
        $msg->set_annotation($mentry2, $mattrib, $data2);
        $talk->store('' . $uid, 'annotation',
                    [$mentry1, [$mattrib, { Quote => $data1 }],
                     $mentry2, [$mattrib, { Quote => $data2 }]]);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $expected_annotation_storage += (length($data1) + length($data2));
        $expected_storage += length($msg->as_string());
        $expected_message++;
        $uid++;
    }

    my $res;

    xlog $self, "Check the messages are all there";
    $self->check_messages(\%exp);

    xlog $self, "check that the used size matches";
    $res = $talk->getmetadata($src, $vendsize);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $src => { $vendsize => $expected_storage },
    }, $res);

    if ($cyrus_version >= 3) {
        xlog $self, "check that the annot size matches";
        $res = $talk->getmetadata($src, $vendannot);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $self->assert_deep_equals({
            $src => { $vendannot => $expected_annotation_storage },
        }, $res);
    }

    xlog $self, "Check the mailbox annotation is still there";
    $res = $talk->getmetadata($src, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $src => { $fentry => $data }
    }, $res);

    xlog $self, "Check the quota usage is as expected";
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );

    xlog $self, "rename $src to $dest";
    $talk->rename($src, $dest);
    $store->set_folder($dest);

    xlog $self, "Check the messages are all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the old mailbox annotation is not there";
    $res = $talk->getmetadata($src, $fentry);
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    xlog $self, "Check the new mailbox annotation is there";
    $res = $talk->getmetadata($dest, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $dest => { $fentry => $data }
    }, $res);

    xlog $self, "check that the used size still matches";
    $res = $talk->getmetadata($dest, $vendsize);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $dest => { $vendsize => $expected_storage },
    }, $res);

    if ($cyrus_version >= 3) {
        xlog $self, "check that the annot size still matches";
        $res = $talk->getmetadata($dest, $vendannot);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $self->assert_deep_equals({
            $dest => { $vendannot => $expected_annotation_storage },
        }, $res);
    }

    xlog $self, "Check the quota usage is still as expected";
    $self->_check_usages(
        storage => int($expected_storage/1024),
        message => $expected_message,
        'x-annotation-storage' => int($expected_annotation_storage/1024),
    );
}

sub test_num_folders_rename
{
    my ($self) = @_;
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(storage => 12345, 'x-num-folders' => 500);

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    $self->_check_usages(storage => 0, 'x-num-folders' => 2);

    $talk->create("INBOX.another");

    $self->_check_usages(storage => 0, 'x-num-folders' => 3);

    $talk->rename("INBOX.another", "INBOX.out");

    $self->_check_usages(storage => 0, 'x-num-folders' => 3);
}

sub test_num_folders_delete_immediate
{
    my ($self) = @_;
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(storage => 12345, 'x-num-folders' => 500);

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    $self->_check_usages(storage => 0, 'x-num-folders' => 2);

    $talk->create("INBOX.another");

    $self->_check_usages(storage => 0, 'x-num-folders' => 3);

    $talk->delete("INBOX.another");

    $self->_check_usages(storage => 0, 'x-num-folders' => 2);
}

sub test_num_folders_delete_delayed
    :DelayedDelete
{
    my ($self) = @_;
    $self->_set_quotaroot('user.cassandane');
    $self->_set_limits(storage => 12345, 'x-num-folders' => 500);

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    $self->_check_usages(storage => 0, 'x-num-folders' => 2);

    $talk->create("INBOX.another");

    $self->_check_usages(storage => 0, 'x-num-folders' => 3);

    $talk->delete("INBOX.another");

    $self->_check_usages(storage => 0, 'x-num-folders' => 2);
}

sub test_storage_convquota
    :min_version_3_3 :Conversations :ConversationsQuota
{
    my ($self) = @_;

    xlog $self, "test increasing usage of the STORAGE quota resource as messages are added";
    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_limits(storage => 100000);
    $self->_check_usages(storage => 0);
    my $talk = $self->{store}->get_client();

    my $KEY = "/private/vendor/cmu/cyrus-imapd/userrawquota";

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    $self->{store}->set_folder("INBOX");
    my $msg = $self->make_message("Message 1",
                                  extra_lines => 10 + rand(5000));
    my $size1 = length($msg->as_string());

    $self->{store}->set_folder("INBOX.sub");
    my $msg2 = $self->make_message("Message 2",
                                  extra_lines => 10 + rand(5000));
    my $size2 = length($msg2->as_string());

    my $data1 = $talk->getmetadata("", $KEY);
    my ($rawusage1) = $data1->{''}{$KEY} =~ m/STORAGE (\d+)/;

    $self->_check_usages(storage => int(($size1+$size2)/1024));
    $self->assert_num_equals(int(($size1+$size2)/1024), $rawusage1);

    $talk->select("INBOX");
    $talk->copy("1", "INBOX.sub");

    my $data2 = $talk->getmetadata("", $KEY);
    my ($rawusage2) = $data2->{''}{$KEY} =~ m/STORAGE (\d+)/;

    # quota usage hasn't changed, because we don't get double-charged
    $self->_check_usages(storage => int(($size1+$size2)/1024));
    # but raw usage has gone up by another copy of message 1
    $self->assert_num_equals(int(($size1+$size2+$size1)/1024), $rawusage2);

    $talk->delete("INBOX.sub");

    my $data3 = $talk->getmetadata("", $KEY);
    my ($rawusage3) = $data3->{''}{$KEY} =~ m/STORAGE (\d+)/;

    # we just lost all copies of message2
    $self->_check_usages(storage => int($size1/1024));
    # and also the second copy of message1, so just size1 left
    $self->assert_num_equals(int($size1/1024), $rawusage3);
}

1;
