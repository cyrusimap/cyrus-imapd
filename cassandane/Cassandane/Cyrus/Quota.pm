#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
package Cassandane::Cyrus::Quota;
use base qw(Cassandane::Cyrus::TestCase);
use IO::File;
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use Data::Dumper;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

sub _test_using_storage
{
    my ($self, $late) = @_;

    if ($late) {
        xlog "test setting STORAGE quota resource after messages are added";
    }
    else {
        xlog "test increasing usage of the STORAGE quota resource as messages are added";
    }

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my @res;
    if (!$late) {
	# Right - let's set ourselves a basic usage quota
	$admintalk->setquota("user.cassandane", "(storage 100000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('STORAGE', $res[0]);
	$self->assert_num_equals(0, $res[1]);
	$self->assert_num_equals(100000, $res[2]);
    }
    else {
	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('no', $admintalk->get_last_completion_response());
    }

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub") {
	$expecteds{$folder} = 0;
	$self->{store}->set_folder($folder);

	for (1..10) {
	    my $msg = $self->make_message("Message $_",
					  extra_lines => 10 + rand(5000));
	    my $len = length($msg->as_string());
	    $expecteds{$folder} += $len;
	    xlog "added $len bytes of message";

	    if (!$late) {
		@res = $admintalk->getquota("user.cassandane");
		$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
		$self->assert_num_equals(3, scalar @res);
		$self->assert_str_equals('STORAGE', $res[0]);
		$self->assert_num_equals(int(($expected+$expecteds{$folder})/1024), $res[1]);
	    }
	}
	$expected += $expecteds{$folder};
    }

    if ($late) {
	$admintalk->setquota("user.cassandane", "(storage 100000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('STORAGE', $res[0]);
	$self->assert_num_equals(int($expected/1024), $res[1]);
    }

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub"});

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('STORAGE', $res[0]);
    $self->assert_num_equals(int($expected/1024), $res[1]);

    # delete messages
    $talk->select("INBOX");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('STORAGE', $res[0]);
    $self->assert_num_equals($expected, $res[1]);
}

sub test_using_storage
{
    $_[0]->_test_using_storage(0);
}

sub test_using_storage_late
{
    $_[0]->_test_using_storage(1);
}

sub test_exceeding_storage
{
    my ($self) = @_;

    xlog "test exceeding the STORAGE quota limit";

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    xlog "set a low limit";
    $admintalk->setquota("user.cassandane", "(storage 210)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('STORAGE', $res[0]);
    $self->assert_num_equals(0, $res[1]);

    xlog "adding messages to get just below the limit";
    my %msgs;
    my $slack = 200 * 1024;
    my $n = 1;
    while ($slack > 1000)
    {
	my $nlines = int(($slack - 640) / 23);
	$nlines = 1000 if ($nlines > 1000);

	my $msg = $self->make_message("Message $n",
				      extra_lines => $nlines);
	my $len = length($msg->as_string());
	$slack -= $len;
	xlog "added $len bytes of message";
	$msgs{$n} = $msg;
	$n++;
    }
    xlog "check that the messages are all in the mailbox";
    $self->check_messages(\%msgs);

    xlog "add a message that exceeds the limit";
    my $nlines = int(($slack - 640) / 23) * 2;
    $nlines = 500 if ($nlines < 500);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    eval
    {
	my $msg = $self->make_message("Message $n",
				      extra_lines => $nlines);
    };
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/over quota/i);

    xlog "check that the exceeding message is not in the mailbox";
    $self->check_messages(\%msgs);
}

sub _test_using_message
{
    my ($self, $late) = @_;

    if ($late) {
        xlog "test setting MESSAGE quota resource after messages are added";
    }
    else {
        xlog "test increasing usage of the MESSAGE quota resource as messages are added";
    }

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my @res;
    if (!$late) {
	# Right - let's set ourselves a basic usage quota
	$admintalk->setquota("user.cassandane", "(MESSAGE 50000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('MESSAGE', $res[0]);
	$self->assert_num_equals(0, $res[1]);
	$self->assert_num_equals(50000, $res[2]);
    }
    else {
	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('no', $admintalk->get_last_completion_response());
    }

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    # append some messages
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub") {
	$expecteds{$folder} = 0;
	$self->{store}->set_folder($folder);

	for (1..10) {
	    my $msg = $self->make_message("Message $_");
	    $expecteds{$folder}++;

	    if (!$late) {
		@res = $admintalk->getquota("user.cassandane");
		$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
		$self->assert_num_equals(3, scalar @res);
		$self->assert_str_equals('MESSAGE', $res[0]);
		$self->assert_num_equals($expected+$expecteds{$folder}, $res[1]);
	    }
	}
	$expected += $expecteds{$folder};
    }

    if ($late) {
	$admintalk->setquota("user.cassandane", "(MESSAGE 50000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('MESSAGE', $res[0]);
	$self->assert_num_equals($expected, $res[1]);
    }

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= $expecteds{"INBOX.sub"};

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('MESSAGE', $res[0]);
    $self->assert_num_equals($expected, $res[1]);

    # delete messages
    $talk->select("INBOX");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('MESSAGE', $res[0]);
    $self->assert_num_equals($expected, $res[1]);
}

sub test_using_message
{
    $_[0]->_test_using_message(0);
}

sub test_using_message_late
{
    $_[0]->_test_using_message(1);
}

sub test_exceeding_message
{
    my ($self) = @_;

    xlog "test exceeding the MESSAGE quota limit";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog "set a low limit";
    $admintalk->setquota("user.cassandane", "(MESSAGE 10)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('MESSAGE', $res[0]);
    $self->assert_num_equals(0, $res[1]);

    xlog "adding messages to get just below the limit";
    for (1..10) {
	my $msg = $self->make_message("Message $_");
    }

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_num_equals(10, $res[1]);

    xlog "add a message that exceeds the limit";
    eval
    {
	my $msg = $self->make_message("Message $_");
    };
    # As opposed to storage checking, which is currently done after receiving the
    # (LITERAL) mail, message count checking is performed right away. This early
    # NO response while writing the LITERAL triggers a die in IMAPTalk, leaving
    # the completion response undefined.
    #$self->assert_str_equals('no', $talk->get_last_completion_response(), $talk->{LastError});
    $self->assert($talk->get_last_error() =~ m/over quota/i);

    xlog "check that the exceeding message is not in the mailbox";
    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_num_equals(10, $res[1]);
}

sub make_random_data
{
    my $kb = shift;
    my $data = '';
    while (!defined $kb || length($data) < 1028*$kb)
    {
	my $word = random_word();
	my $count = 10 + rand(90);
	while ($count > 0)
	{
	    $data .= " $word";
	    $count--;
	}
	last unless defined $kb;
    }
    return $data;
}

sub _test_using_annotstorage_msg
{
    my ($self, $late) = @_;

    if (!$late) {
	xlog "test setting X-ANNOTATION-STORAGE quota resource after";
	xlog "per-message annotations are added";
    }
    else {
	xlog "test increasing usage of the X-ANNOTATION-STORAGE quota";
	xlog "resource as per-message annotations are added";
    }

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my @res;
    if (!$late) {
	# Right - let's set ourselves a basic usage quota
	$admintalk->setquota("user.cassandane", "(x-annotation-storage 100000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
	$self->assert_num_equals(0, $res[1]);
    }
    else {
	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('no', $admintalk->get_last_completion_response());
    }

    $talk->create("INBOX.sub1") || die "Failed to create subfolder";
    $talk->create("INBOX.sub2") || die "Failed to create subfolder";

    xlog "make some messages to hang annotations on";
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub1", "INBOX.sub2") {
	$self->{store}->set_folder($folder);
	$expecteds{$folder} = 0;
	my $uid = 1;
	for (1..5) {
	    $self->make_message("Message $uid");

            my $data = make_random_data(10);
	    $talk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
	    $self->assert_str_equals('ok', $talk->get_last_completion_response());
	    $uid++;
	    $expecteds{$folder} += length($data);

	    if (!$late) {
		@res = $admintalk->getquota("user.cassandane");
		$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
		$self->assert_num_equals(3, scalar @res);
		$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
		$self->assert_num_equals(int(($expected+$expecteds{$folder})/1024), $res[1]);
	    }
	}
	$expected += $expecteds{$folder};
    }

    if ($late) {
	$admintalk->setquota("user.cassandane", "(x-annotation-storage 100000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
	$self->assert_num_equals(int($expected/1024), $res[1]);
    }

    # delete subfolder
    $talk->delete("INBOX.sub1") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub1"});

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals(int($expected/1024), $res[1]);

    # delete messages
    $talk->select("INBOX.sub2");
    $talk->store('1:*', '+flags', '(\\deleted)');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->close();
    $expected -= delete($expecteds{"INBOX.sub2"});

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals(int($expected/1024), $res[1]);

    # delete annotations
    $talk->select("INBOX");
    $talk->store('1:*', 'annotation', ['/comment', ['value.priv', undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $talk->close();
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals($expected, $res[1]);
}

sub test_using_annotstorage_msg
{
    $_[0]->_test_using_annotstorage_msg(0);
}

sub test_using_annotstorage_msg_late
{
    $_[0]->_test_using_annotstorage_msg(1);
}

sub _test_using_annotstorage_mbox
{
    my ($self, $late) = @_;

    if (!$late) {
	xlog "test setting X-ANNOTATION-STORAGE quota resource after";
	xlog "per-mailbox annotations are added";
    }
    else {
	xlog "test increasing usage of the X-ANNOTATION-STORAGE quota";
	xlog "resource as per-mailbox annotations are added";
    }

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my @res;
    if (!$late) {
	# Right - let's set ourselves a basic usage quota
	$admintalk->setquota("user.cassandane", "(x-annotation-storage 100000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
	$self->assert_num_equals(0, $res[1]);
	$self->assert_num_equals(100000, $res[2]);
    }
    else {
	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('no', $admintalk->get_last_completion_response());
    }

    $talk->create("INBOX.sub") || die "Failed to create subfolder";

    xlog "store annotations";
    my %expecteds = ();
    my $expected = 0;
    foreach my $folder ("INBOX", "INBOX.sub") {
	$expecteds{$folder} = 0;
	$self->{store}->set_folder($folder);
	my $data = '';
	while ($expecteds{$folder} <= 60*1024)
	{
	    $data .= make_random_data(5);
	    $expecteds{$folder} = length($data);

	    $talk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $data });
	    $self->assert_str_equals('ok', $talk->get_last_completion_response());

	    if (!$late) {
		@res = $admintalk->getquota("user.cassandane");
		$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
		$self->assert_num_equals(3, scalar @res);
		$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
		$self->assert_num_equals(int(($expected+$expecteds{$folder})/1024), $res[1]);
	    }
	}
	$expected += $expecteds{$folder};
    }

    if ($late) {
	$admintalk->setquota("user.cassandane", "(x-annotation-storage 100000)");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
	$self->assert_num_equals(int($expected/1024), $res[1]);
   }

    # delete subfolder
    $talk->delete("INBOX.sub") || die "Failed to delete subfolder";
    $expected -= delete($expecteds{"INBOX.sub"});

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals(int($expected/1024), $res[1]);

    # delete remaining annotations
    $self->{store}->set_folder("INBOX");
    $talk->setmetadata($self->{store}->{folder}, '/private/comment', undef);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $expected -= delete($expecteds{"INBOX"});
    $self->assert_num_equals(0, $expected);

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals($expected, $res[1]);
}

sub test_using_annotstorage_mbox
{
    $_[0]->_test_using_annotstorage_mbox(0);
}

sub test_using_annotstorage_mbox_late
{
    $_[0]->_test_using_annotstorage_mbox(1);
}

#
# Test renames
#
sub test_quotarename
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(STORAGE 100000 MESSAGE 50000 X-ANNOTATION-STORAGE 10000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @res);
    $self->assert_num_equals(0, $res[1]);
    $self->assert_num_equals(0, $res[4]);
    $self->assert_num_equals(0, $res[7]);

    my $expected_storage = 0;
    my $expected_message = 0;
    my $expected_annotation_storage = 0;
    my $uid = 1;
    for (1..10) {
	my $msg = $self->make_message("Message $_", extra_lines => 5000);
	$expected_storage += length($msg->as_string());
	$expected_message++;

	my $annotation = make_random_data(1);
	$expected_annotation_storage += length($annotation);
	$imaptalk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $annotation }]]);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
	$uid++;
    }

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @res);
    my $base_storage_usage = $res[1];
    my $base_message_usage = $res[4];
    my $base_annotation_storage_usage = $res[7];
    $self->assert_num_equals(int($expected_storage/1024), $base_storage_usage);
    $self->assert_num_equals($expected_message, $base_message_usage);
    $self->assert_num_equals(int($expected_annotation_storage/1024), $base_annotation_storage_usage);

    $imaptalk->create("INBOX.sub") || die "Failed to create subfolder";
    $self->{store}->set_folder("INBOX.sub");
    $imaptalk->select($self->{store}->{folder}) || die;
    my $expected_storage_more = $expected_storage;
    my $expected_message_more = $expected_message;
    my $expected_annotation_storage_more = $expected_annotation_storage;
    $uid = 1;
    for (1..10) {

	my $msg = $self->make_message("Message $_",
				      extra_lines => 10 + rand(5000));
	$expected_storage_more += length($msg->as_string());
	$expected_message_more++;

	my $annotation = make_random_data(1);
	$expected_annotation_storage_more += length($annotation);
	$imaptalk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $annotation }]]);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
	$uid++;
    }
    $self->{store}->set_folder("INBOX");
    $imaptalk->select($self->{store}->{folder}) || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @res);
    my $more_storage_usage = $res[1];
    my $more_message_usage = $res[4];
    my $more_annotation_storage_usage = $res[7];
    $self->assert_num_equals(int($expected_storage_more/1024), $more_storage_usage);
    $self->assert_num_equals($expected_message_more, $more_message_usage);
    $self->assert_num_equals(int($expected_annotation_storage_more/1024), $more_annotation_storage_usage);

    $imaptalk->rename("INBOX.sub", "INBOX.othersub") || die;
    $imaptalk->select("INBOX.othersub") || die;

    # usage should be the same after a rename
    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @res);
    $self->assert_num_equals($more_storage_usage, $res[1], "Storage usage should be unchanged after a rename ($more_storage_usage, $res[1])");
    $self->assert_num_equals($more_message_usage, $res[4], "Message usage should be unchanged after a rename ($more_message_usage, $res[4])");
    $self->assert_num_equals($more_annotation_storage_usage, $res[7], "Annotation storage usage should be unchanged after a rename ($more_annotation_storage_usage, $res[7])");

    $imaptalk->delete("INBOX.othersub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @res);
    $self->assert_num_equals($base_storage_usage, $res[1], "Storage usage should drop back after a delete ($base_storage_usage, $res[1])");
    $self->assert_num_equals($base_message_usage, $res[4], "Message usage should drop back after a delete ($base_message_usage, $res[4])");
    $self->assert_num_equals($base_annotation_storage_usage, $res[7], "Annotation storage usage should drop back after a delete ($base_annotation_storage_usage, $res[7])");
}

sub test_quota_f
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(STORAGE 100000 MESSAGE 50000 X-ANNOTATION-STORAGE 10000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $admintalk->create("user.quotafuser");
    $admintalk->setacl("user.quotafuser", "admin", 'lrswipkxtecda');
    $self->{adminstore}->set_folder("user.quotafuser");
    my $quotafuser_expected_storage = 0;
    my $quotafuser_expected_message = 0;
    my $quotafuser_expected_annotation_storage = 0;
    for (1..3) {
	my $msg = $self->make_message("QuotaFUser $_", store => $self->{adminstore}, extra_lines => 17000);
	$quotafuser_expected_storage += length($msg->as_string());
	$quotafuser_expected_message++;
    }
    for (1..10) {
	$self->make_message("Cassandane $_", extra_lines => 5000);
    }

    my $annotation = make_random_data(10);
    $admintalk->setmetadata($self->{adminstore}->{folder}, '/private/comment', { Quote => $annotation });
    $quotafuser_expected_annotation_storage = length($annotation);
    $admintalk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $annotation });

    my @origcasres = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @origcasres);

    # create a bogus quota file
    mkdir("$self->{instance}{basedir}/conf/quota");
    mkdir("$self->{instance}{basedir}/conf/quota/q");
    my $fh = IO::File->new(">$self->{instance}{basedir}/conf/quota/q/user.quotafuser") || die "Failed to open quota file";
    print $fh "0\n100000 M 0 50000 AS 0 10000\n";
    close($fh);
    $self->{instance}->_fix_ownership("$self->{instance}{basedir}/conf/quota");

    # find and add the quota
    $self->{instance}->run_utility('quota', '-f');

    my @res = $admintalk->getquota("user.quotafuser");
    $self->assert_num_equals(9, scalar @res);
    my @casres = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @casres);

    # re-run the quota utility
    $self->{instance}->run_utility('quota', '-f');

    my @res2 = $admintalk->getquota("user.quotafuser");
    $self->assert_num_equals(9, scalar @res2);
    my @casres2 = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(9, scalar @casres2);

    $self->assert_num_equals(int($quotafuser_expected_storage/1024), $res[1]);
    $self->assert_num_equals($quotafuser_expected_message, $res[4]);
    $self->assert_num_equals(int($quotafuser_expected_annotation_storage/1024), $res[7]);

    # usage should be unchanged
    $self->assert($res[1] == $res2[1] && $res[4] == $res2[4] && $res[7] == $res2[7] && 
		  $casres[1] == $casres2[1] && $casres[4] == $casres2[4] && $casres[7] == $casres2[7] &&
		  $casres[1] == $origcasres[1] && $casres[4] == $origcasres[4] && $casres[7] == $origcasres[7], 
		  "Quota mismatch: quotafuser (1: " . Dumper(\@res) . ", 2: " . Dumper(\@res2) . ") " .
		  "cassandane (0: " . Dumper(\@origcasres) . ", 1: " . Dumper(\@casres) . ", 2: " . Dumper(\@casres2) . ")");
}

# Test races between quota -f and updates to mailboxes
sub test_quota_f_vs_update
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();
    my $basefolder = "user.cassandane";
    my @folders = qw(a b c d e);
    my @res;
    my $msg;
    my $expected;

    xlog "Set up a large but limited quota";
    $admintalk->setquota($basefolder, "(storage 1000000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    @res = $admintalk->getquota($basefolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 1000000], \@res);

    xlog "Create some sub folders";
    for my $f (@folders)
    {
	$imaptalk->create("$basefolder.$f") || die "Failed $@";
	$self->{store}->set_folder("$basefolder.$f");
	$msg = $self->make_message("Cassandane $f",
				      extra_lines => 2000+rand(5000));
	$expected += length($msg->as_string());
    }
    # unselect so quota -f can lock the mailboxes
    $imaptalk->unselect();

    xlog "Check that we have some quota usage";
    @res = $admintalk->getquota($basefolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', int($expected/1024), 1000000], \@res);
    my @origres = (@res);

    xlog "Start a quota -f scan";
    $self->{instance}->quota_Z_go($basefolder);
    $self->{instance}->quota_Z_go("$basefolder.a");
    $self->{instance}->quota_Z_go("$basefolder.b");
    my (@bits) = $self->{instance}->start_utility_bg('quota', '-Z', '-f', $basefolder);

    # waiting for quota -f to ensure that
    # a) the -Z mechanism is working and
    # b) quota -f has at least initialised and started scanning.
    $self->{instance}->quota_Z_wait("$basefolder.b");

    # quota -f is now waiting to be allowed to proceed to "c"

    xlog "Mailbox update behind the scan";
    $self->{store}->set_folder("$basefolder.b");
    $msg = $self->make_message("Cassandane b UPDATE",
				  extra_lines => 2000+rand(3000));
    $expected += length($msg->as_string());

    xlog "Mailbox update in front of the scan";
    $self->{store}->set_folder("$basefolder.d");
    $msg = $self->make_message("Cassandane d UPDATE",
				  extra_lines => 2000+rand(3000));
    $expected += length($msg->as_string());

    xlog "Let quota -f continue and finish";
    $self->{instance}->quota_Z_go("$basefolder.c");
    $self->{instance}->quota_Z_go("$basefolder.d");
    $self->{instance}->quota_Z_go("$basefolder.e");
    $self->{instance}->quota_Z_wait("$basefolder.e");
    $self->{instance}->reap_utility_bg(@bits);

    xlog "Check that we have the correct quota usage";
    @res = $admintalk->getquota($basefolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', int($expected/1024), 1000000], \@res);
    $self->assert($res[1] != $origres[1]);
}

sub test_prefix_mboxexists
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->create("user.base");
    $admintalk->create("user.base.subdir");
    $admintalk->create("user.base.subdir2");
    $admintalk->setacl("user.base", "admin", 'lrswipkxtecda');
    $admintalk->setacl("user.base.subdir2", "admin", 'lrswipkxtecda');
    $self->{adminstore}->set_folder("user.base");
    for (1..3) {
	$self->make_message("base $_", store => $self->{adminstore}, extra_lines => 12345);
    }
    $self->{adminstore}->set_folder("user.base.subdir2");
    for (1..3) {
	$self->make_message("base $_", store => $self->{adminstore}, extra_lines => 12345);
    }

    $admintalk->create("user.baseplus");
    $admintalk->create("user.baseplus.subdir");
    $admintalk->setacl("user.baseplus", "admin", 'lrswipkxtecda');
    $admintalk->setacl("user.baseplus.subdir", "admin", 'lrswipkxtecda');
    $admintalk->setquota("user.baseplus", "(storage 1000000)");
    $self->{adminstore}->set_folder("user.baseplus");
    for (1..3) {
	$self->make_message("baseplus $_", store => $self->{adminstore}, extra_lines => 31419);
    }
    $self->{adminstore}->set_folder("user.baseplus.subdir");
    for (1..3) {
	$self->make_message("baseplus $_", store => $self->{adminstore}, extra_lines => 31419);
    }

    my @origplus = $admintalk->getquota("user.baseplus");
    $self->assert_num_equals(3, scalar @origplus);

    $self->{instance}->run_utility('quota', '-f', "user.base");

    my @nextplus = $admintalk->getquota("user.baseplus");
    $self->assert_num_equals(3, scalar @nextplus);

    # usage should be unchanged
    $self->assert($origplus[1] == $nextplus[1],
		  "usage of subdir (1: $origplus[1], 2: $nextplus[1])");
}

# Magic: the word 'replication' in the name enables a replica
sub test_replication_storage
{
    my ($self) = @_;

    xlog "testing replication of STORAGE quota";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog "set a STORAGE quota on the master";
    $mastertalk->setquota($folder, "(storage 12345)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 12345], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 12345], \@res);

    xlog "change the STORAGE quota on the master";
    $mastertalk->setquota($folder, "(storage 67890)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 67890], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 67890], \@res);

    xlog "clear the STORAGE quota on the master";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
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

    xlog "testing replication of MESSAGE quota";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog "set a STORAGE quota on the master";
    $mastertalk->setquota($folder, "(message 12345)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 12345], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 12345], \@res);

    xlog "change the MESSAGE quota on the master";
    $mastertalk->setquota($folder, "(message 67890)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 67890], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['MESSAGE', 0, 67890], \@res);

    xlog "clear the MESSAGE quota on the master";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
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

    xlog "testing replication of X-ANNOTATION-STORAGE quota";

    my $folder = "user.cassandane";
    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my @res;

    xlog "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog "set an X-ANNOTATION-STORAGE quota on the master";
    $mastertalk->setquota($folder, "(x-annotation-storage 12345)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 12345], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 12345], \@res);

    xlog "change the X-ANNOTATION-STORAGE quota on the master";
    $mastertalk->setquota($folder, "(x-annotation-storage 67890)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 67890], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOTATION-STORAGE', 0, 67890], \@res);

    xlog "add an annotation to use some quota";
    my $data = make_random_data(13);
    my $msg = $self->make_message("Message A", store => $self->{master_store});
    $mastertalk->store('1', 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
## This doesn't work because per-mailbox annots are not
## replicated when sync_client is run in -u mode...sigh
#     $mastertalk->setmetadata($folder, '/private/comment', { Quote => $data });
#     $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    my $used = int(length($data)/1024);

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check the annotation used some quota on the master";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([
	'X-ANNOTATION-STORAGE', $used, 67890
    ], \@res);

    xlog "check the annotation used some quota on the replica";
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([
	'X-ANNOTATION-STORAGE', $used, 67890
    ], \@res);

    xlog "clear the X-ANNOTATION-STORAGE quota on the master";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
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

    xlog "testing getting and setting multiple quota resources";

    my $admintalk = $self->{adminstore}->get_client();
    my $folder = "user.cassandane";
    my @res;

    xlog "checking there are no initial quotas";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert($admintalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog "set both X-ANNOT-COUNT and X-ANNOT-SIZE quotas";
    $admintalk->setquota($folder, "(x-annot-count 20 x-annot-size 16384)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog "get both resources back, and not STORAGE";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);

    xlog "set the X-ANNOT-SIZE resource only";
    $admintalk->setquota($folder, "(x-annot-size 32768)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog "get new -SIZE only and neither STORAGE nor -COUNT";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);

    xlog "set all of -COUNT -SIZE and STORAGE";
    $admintalk->setquota($folder, "(x-annot-count 123 storage 123456 x-annot-size 65536)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog "get back all three new values";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals(['STORAGE', 0, 123456, 'X-ANNOT-COUNT', 0, 123, 'X-ANNOT-SIZE', 0, 65536], \@res);

    xlog "clear all quotas";
    $admintalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # Note: the RFC does not define what happens if you remove all the
    # quotas from a quotaroot.  Cyrus leaves the quotaroot around until
    # quota -f is run to clean it up.
    xlog "get back an empty set of quotas, but the quota root still exists";
    @res = $admintalk->getquota($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

# Magic: the word 'replication' in the name enables a replica
sub XXtest_replication_multiple
{
    my ($self) = @_;

    xlog "testing replication of multiple quotas";

    my $mastertalk = $self->{master_adminstore}->get_client();
    my $replicatalk = $self->{replica_adminstore}->get_client();

    my $folder = "user.cassandane";
    my @res;

    xlog "checking there are no initial quotas";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('no', $mastertalk->get_last_completion_response());
    $self->assert($mastertalk->get_last_error() =~ m/Quota root does not exist/i);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('no', $replicatalk->get_last_completion_response());
    $self->assert($replicatalk->get_last_error() =~ m/Quota root does not exist/i);

    xlog "set a X-ANNOT-COUNT and X-ANNOT-SIZE quotas on the master";
    $mastertalk->setquota($folder, "(x-annot-count 20 x-annot-size 16384)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-COUNT', 0, 20, 'X-ANNOT-SIZE', 0, 16384], \@res);

    xlog "set the X-ANNOT-SIZE quota on the master";
    $mastertalk->setquota($folder, "(x-annot-size 32768)");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals(['X-ANNOT-SIZE', 0, 32768], \@res);

    xlog "clear all the quotas";
    $mastertalk->setquota($folder, "()");
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());

    xlog "run replication";
    $self->run_replication();
    $mastertalk = $self->{master_adminstore}->get_client();
    $replicatalk = $self->{replica_adminstore}->get_client();

    xlog "check that the new quota is at both ends";
    @res = $mastertalk->getquota($folder);
    $self->assert_str_equals('ok', $mastertalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
    @res = $replicatalk->getquota($folder);
    $self->assert_str_equals('ok', $replicatalk->get_last_completion_response());
    $self->assert_deep_equals([], \@res);
}

1;
