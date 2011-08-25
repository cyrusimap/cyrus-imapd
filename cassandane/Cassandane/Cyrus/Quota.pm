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

sub test_using_storage
{
    my ($self) = @_;

    xlog "test increasing usage of the STORAGE quota resource as messages are added";

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(storage 100000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('STORAGE', $res[0]);
    $self->assert_num_equals(0, $res[1]);

    my $expected = 0;
    for (1..10) {

	my $msg = $self->make_message("Message $_",
				      extra_lines => 10 + rand(5000));
	my $len = length($msg->as_string());
	$expected += $len;
	xlog "added $len bytes of message";

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('STORAGE', $res[0]);
	$self->assert_num_equals(int($expected/1024), $res[1]);
    }
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

sub test_using_annotstorage_msg
{
    my ($self) = @_;

    xlog "test increasing usage of the X-ANNOTATION-STORAGE quota";
    xlog "resource as per-message annotations are added";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(x-annotation-storage 100000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals(0, $res[1]);

    xlog "make some messages to hang annotations on";
    my $expected = 0;
    my @msgs;
    my @annots;
    my $uid = 1;
    while ($expected <= 110*1024)
    {
	push(@msgs, $self->make_message("Message $uid"));
	my $data = make_random_data();
	push(@annots, $data);
	$expected += length($data);
    }

    xlog "store annotations";
    $expected = 0;
    $uid = 1;
    while (my $msg = shift @msgs)
    {
	my $data = shift @annots;

	$talk->store('' . $uid, 'annotation', ['/comment', ['value.priv', { Quote => $data }]]);
	$self->assert_str_equals('ok', $talk->get_last_completion_response());
	$uid++;
	$expected += length($data);

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
	$self->assert_num_equals(int($expected/1024), $res[1]);
    }
}

sub test_using_annotstorage_mbox
{
    my ($self) = @_;

    xlog "test increasing usage of the X-ANNOTATION-STORAGE quota";
    xlog "resource as per-mailbox annotations are added";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(x-annotation-storage 100000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_num_equals(3, scalar @res);
    $self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
    $self->assert_num_equals(0, $res[1]);

    xlog "store annotations";
    my $expected = 0;
    my $data = '';
    while ($expected <= 60*1024)
    {
	$data .= make_random_data();
	$expected = length($data);

	$talk->setmetadata($self->{store}->{folder}, '/private/comment', { Quote => $data });
	$self->assert_str_equals('ok', $talk->get_last_completion_response());

	@res = $admintalk->getquota("user.cassandane");
	$self->assert_str_equals('ok', $admintalk->get_last_completion_response());
	$self->assert_num_equals(3, scalar @res);
	$self->assert_str_equals('X-ANNOTATION-STORAGE', $res[0]);
	$self->assert_num_equals(int($expected/1024), $res[1]);
    }
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
    $admintalk->setquota("user.cassandane", "(storage 100000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_num_equals(0, $res[1]);

    for (1..10) {
	$self->make_message("Message $_", extra_lines => 5000);
    }

    @res = $admintalk->getquota("user.cassandane");

    my $base_usage = $res[1];
    $self->assert_num_not_equals(0, $base_usage, "10 messages should use some quota: " . Dumper(\@res));

    $imaptalk->create("INBOX.sub") || die;
    $imaptalk->select($self->{store}->{folder}) || die;
    $imaptalk->copy("1:5", "INBOX.sub") || die;
    $imaptalk->select("INBOX.sub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);

    my $more_usage = $res[1];
    $self->assert_num_not_equals($base_usage, $more_usage, "another 15 messages should use more quota ($base_usage, $more_usage)");

    $imaptalk->rename("INBOX.sub", "INBOX.othersub") || die;
    $imaptalk->select("INBOX.othersub") || die;

    # usage should be the same after a rename
    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals($more_usage, $res[1], "Usage should be unchanged after a rename ($more_usage, $res[1])");

    $imaptalk->delete("INBOX.othersub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals($base_usage, $res[1], "Usage should drop back after a delete ($base_usage, $res[1])");
}

sub test_quota_f
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(storage 100000)");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $admintalk->create("user.quotafuser");
    $admintalk->setacl("user.quotafuser", "admin", 'lrswipkxtecda');
    $self->{adminstore}->set_folder("user.quotafuser");
    for (1..3) {
	$self->make_message("QuotaFUser $_", store => $self->{adminstore}, extra_lines => 17000);
    }
    for (1..10) {
	$self->make_message("Cassandane $_", extra_lines => 5000);
    }

    $admintalk->create("user.zlateuser");
    $admintalk->setacl("user.zlateuser", "admin", 'lrswipkxtecda');
    $self->{adminstore}->set_folder("user.zlateuser");
    for (1..7) {
	$self->make_message("Lateuser $_", store => $self->{adminstore}, extra_lines => 1200);
    }
    $admintalk->setquota("user.zlateuser", "(storage 750000)") || die "Failed $@";

    my @origcasres = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @origcasres);

    my @origzres = $admintalk->getquota("user.zlateuser");
    $self->assert_num_equals(3, scalar @origzres);

    # create a bogus quota file
    mkdir("$self->{instance}{basedir}/conf/quota");
    mkdir("$self->{instance}{basedir}/conf/quota/q");
    my $fh = IO::File->new(">$self->{instance}{basedir}/conf/quota/q/user.quotafuser") || die "Failed to open quota file";
    print $fh "0\n100000\n";
    close($fh);
    $self->{instance}->_fix_ownership("$self->{instance}{basedir}/conf/quota");

    # find and add the quota
    $self->{instance}->run_utility('quota', '-f');

    my @res = $admintalk->getquota("user.quotafuser");
    $self->assert_num_equals(3, scalar @res);
    my @casres = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @casres);
    my @zres = $admintalk->getquota("user.zlateuser");
    $self->assert_num_equals(3, scalar @zres);

    # re-run the quota utility
    $self->{instance}->run_utility('quota', '-f');

    my @res2 = $admintalk->getquota("user.quotafuser");
    $self->assert_num_equals(3, scalar @res2);
    my @casres2 = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @casres2);
    my @zres2 = $admintalk->getquota("user.zlateuser");
    $self->assert_num_equals(3, scalar @zres2);

    # usage should be unchanged
    $self->assert($res[1] == $res2[1] && 
		  $casres[1] == $casres2[1] &&
		  $casres[1] == $origcasres[1], 
		  $zres[1] == $zres2[1] &&
		  $zres[1] == $origzres[1], 
		  "Quota mismatch: quotafuser (1: $res[1], 2: $res2[1]) " .
		  "cassandane (0:$origcasres[1], 1:$casres[1], 2:$casres2[1]) " .
		  "zlateuser (0:$origzres[1], 1:$zres[1], 2:$zres2[1])");
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
