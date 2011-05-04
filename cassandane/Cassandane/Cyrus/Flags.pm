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
package Cassandane::Cyrus::Flags;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;
use Data::Dumper;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{instance} = Cassandane::Instance->new();
    $self->{instance}->add_service('imap');

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    my $imapsvc = $self->{instance}->get_service('imap');
    $self->{store} = $imapsvc->create_store();
#     $self->{adminstore} = $imapsvc->create_store(username => 'admin');

#     my $admintalk = $self->{adminstore}->get_client();
}

sub tear_down
{
    my ($self) = @_;

    $self->{store}->disconnect()
	if defined $self->{store};
    $self->{store} = undef;
#     $self->{adminstore}->disconnect()
# 	if defined $self->{adminstore};
#     $self->{adminstore} = undef;
    $self->{instance}->stop();
}

sub make_message
{
    my ($self, $subject, @attrs) = @_;

    $self->{store}->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, @attrs);
    $self->{store}->write_message($msg);
    $self->{store}->write_end();

    return $msg;
}

sub check_messages
{
    my ($self, %params) = @_;
    my $actual = {};
    my $expected = $params{expected} || $self->{expected};
    my $store = $params{store} || $self->{store};
    my $checkl = $params{check} || [];
    my %checkh;

    map { $checkh{$_} = 1; } @$checkl;

    xlog "check_messages";

    $store->read_begin();
    while (my $msg = $store->read_message())
    {
	my $subj = $msg->get_header('subject');
	$self->assert(!defined $actual->{$subj});
	$actual->{$subj} = $msg;
    }
    $store->read_end();

    $self->assert(scalar keys %$actual == scalar keys %$expected);

    foreach my $expmsg (values %$expected)
    {
	my $subj = $expmsg->get_header('subject');
	my $actmsg = $actual->{$subj};

	xlog "checking subject \"$subj\"";
	$self->assert_not_null($actmsg);

	if ($checkh{id})
	{
	    xlog "checking id";
	    $self->assert_not_null($expmsg->get_attribute('id'));
	    $self->assert_not_null($actmsg->get_attribute('id'));
	    $self->assert_num_equals($expmsg->get_attribute('id'),
				     $actmsg->get_attribute('id'));
	}

	if ($checkh{uid})
	{
	    xlog "checking uid";
	    $self->assert_not_null($expmsg->get_attribute('uid'));
	    $self->assert_not_null($actmsg->get_attribute('uid'));
	    $self->assert_num_equals($expmsg->get_attribute('uid'),
				     $actmsg->get_attribute('uid'));
	}

	if ($checkh{flags})
	{
	    xlog "checking flags";
	    $self->assert_not_null($expmsg->get_attribute('flags'));
	    $self->assert_not_null($actmsg->get_attribute('flags'));
	    $self->assert_deep_equals($expmsg->get_attribute('flags'),
				      $actmsg->get_attribute('flags'));
	}

	xlog "checking x-cassandane-unique";
	$self->assert_not_null($actmsg->get_header('x-cassandane-unique'));
	$self->assert_str_equals($actmsg->get_header('x-cassandane-unique'),
			         $expmsg->get_header('x-cassandane-unique'));
    }

    return $actual;
}


#
# Test that
#  - the \Deleted flag can be set
#  - the message still exists with \Deleted in flags
#  - after EXPUNGE the message is gone
#  - UIDs remain stable after the expunge
#  - message numbers remain contiguous after the expunge
#    even when UIDs aren't contiguous anymore
#
sub test_deleted
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    $msg{C} = $self->make_message('Message C');
    $msg{C}->set_attributes(id => 3,
			    uid => 3,
			    flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Mark the middle message \\Deleted";
    $talk->store('2', '+flags', '(\\Deleted)');
    $msg{B}->set_attribute(flags => ['\\Deleted']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Expunge the middle message";
    $talk->expunge();
    delete $msg{B};
    $msg{A}->set_attribute(id => 1);
    $msg{C}->set_attribute(id => 2);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);
#
#     $talk->store($seq', '+flags', '(\\flagged)') or die $@;
}

#
# Test that
#  - the \Seen flag can be set
#  - the \Seen flag can be cleared again
#  - other messages don't get the \Seen flag
#  - once set, it's persistent across sessions
#
# Note that we do this test again for \Flagged because
# \Seen is a special case in the backend.
#
# TODO: test that \Seen gets set as a side effect of
# doing body fetches.
#
sub test_seen
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \\Seen on message A";
    $talk->store('1', '+flags', '(\\Seen)');
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Clear \\Seen on message A";
    $talk->store('1', '-flags', '(\\Seen)');
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \\Seen on message A again";
    $talk->store('1', '+flags', '(\\Seen)');
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Reconnect, \\Seen should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->_connect();
    $self->{store}->_select();
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);
}

#
# Test that
#  - the \Flagged flag can be set
#  - the \Flagged flag can be cleared again
#  - other messages don't get the \Flagged flag
#  - once set, it's persistent across sessions
#
sub test_flagged
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \\Flagged on message A";
    $talk->store('1', '+flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Clear \\Flagged on message A";
    $talk->store('1', '-flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \\Flagged on message A again";
    $talk->store('1', '+flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Reconnect, \\Flagged should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->_connect();
    $self->{store}->_select();
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);
}

#
# Test that
#  - the $Foobar flag can be set
#  - the $Foobar flag can be cleared again
#  - other messages don't get the $Foobar flag
#  - once set, it's persistent across sessions
#
# This is basically the same test as for \Flagged but with a user flag,
# which is an entirely different code path in the server.
#
sub test_userflag
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \$Foobar on message A";
    $talk->store('1', '+flags', '($Foobar)');
    $msg{A}->set_attribute(flags => ['$Foobar']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Clear \$Foobar on message A";
    $talk->store('1', '-flags', '($Foobar)');
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \$Foobar on message A again";
    $talk->store('1', '+flags', '($Foobar)');
    $msg{A}->set_attribute(flags => ['$Foobar']);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Reconnect, \$Foobar should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->_connect();
    $self->{store}->_select();
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);
}

#
# Test that
#  - 128 separate user flags can be used
#  - no more can be used
#
use constant MAX_USER_FLAGS => 128;
sub test_max_userflags
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    my %allflags;
    for (my $i = 0 ; $i < MAX_USER_FLAGS ; $i++)
    {
	my $flag;

	for (;;)
	{
	    $flag = '$' . ucfirst(random_word());
	    if (!defined $allflags{$flag})
	    {
		$allflags{$flag} = $i;
		last;
	    }
	}

	xlog "Set $flag on message A";
	$talk->store('1', '+flags', "($flag)");
	$msg{A}->set_attribute(flags => [$flag]);
	$self->check_messages(expected => \%msg,
			      check => [qw(id uid flags)]);

	xlog "Clear $flag on message A";
	$talk->store('1', '-flags', "($flag)");
	$msg{A}->set_attribute(flags => []);
	$self->check_messages(expected => \%msg,
			      check => [qw(id uid flags)]);
    }

    xlog "Cannot set one more wafer-thin user flag";
    my $flag = '$Farnarkle';
    $self->assert_null($allflags{$flag});
    my $r = $talk->store('1', '+flags', "($flag)");
    my $e = $@;
    $self->assert_null($r);
    $self->assert_matches(qr/Too many user flags in mailbox/, $e);

    xlog "Can set all the flags at once";
    my @flags = sort { $allflags{$a} <=> $allflags{$b} } (keys %allflags);
    xlog "Set all the user flags on message A";
    $talk->store('1', '+flags', '(' . join(' ',@flags) . ')');
    $msg{A}->set_attribute(flags => [@flags]);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Reconnect, all the flags should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->_connect();
    $self->{store}->_select();
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);
}

#
# Test that
#  - multiple flags can be set together
#  - flags can be set and cleared without affecting other flags
#  - other messages aren't affected by those changes
#  - flags are persistent across sessions
#
sub test_multi_flags
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set many flags on message A";
    $talk->store('1', '+flags', '(\\Answered \\Flagged \\Draft \\Deleted \\Seen)');
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Flagged \\Draft \\Deleted \\Seen)]);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Clear \\Flagged on message A";
    $talk->store('1', '-flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Draft \\Deleted \\Seen)]);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Clear \\Draft and \\Deleted on message A";
    $talk->store('1', '-flags', '(\\Draft \\Deleted)');
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Seen)]);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set \\Draft and \\Flagged on message A";
    $talk->store('1', '+flags', '(\\Draft \\Flagged)');
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Flagged \\Draft \\Seen)]);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Set to just \\Answered and \\Seen on message A";
    $talk->store('1', 'flags', '(\\Answered \\Seen)');
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Seen)]);
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);

    xlog "Walk through every combination of flags";
    my %rev_map = (
	1 => '\\Answered',
	2 => '\\Flagged',
	4 => '\\Draft',
	8 => '\\Deleted',
	16 => '\\Seen' );
    my $max = (2 ** scalar keys %rev_map) - 1;
    for (my $i = 0 ; $i <= $max ; $i++)
    {
	my @flags;
	for (my $m = 1 ; defined($rev_map{$m}) ; $m *= 2)
	{
	    push(@flags, $rev_map{$m}) if ($i & $m);
	}
	xlog "Setting " . join(',',@flags) . " on message A";
	$talk->store('1', 'flags', '(' . join(' ',@flags) . ')');
	$msg{A}->set_attribute(flags => \@flags);
	$self->check_messages(expected => \%msg,
			      check => [qw(id uid flags)]);
    }

    xlog "Reconnect, all the flags should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->_connect();
    $self->{store}->_select();
    $self->check_messages(expected => \%msg,
			  check => [qw(id uid flags)]);
}

# Get the modseq of a given returned message
sub get_modseq
{
    my ($actual, $which) = @_;

    my $msl = $actual->{'Message ' . $which}->get_attribute('modseq');
    return undef unless defined $msl;
    return undef unless ref $msl eq 'ARRAY';
    return undef unless scalar @$msl == 1;
    return 0 + $msl->[0];
}

# Get the highestmodseq of the folder
sub get_highestmodseq
{
    my ($self) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $stat = $talk->status($store->{folder}, '(highestmodseq)');
    return undef unless defined $stat;
    return undef unless ref $stat eq 'HASH';
    return undef unless defined $stat->{highestmodseq};
    return 0 + $stat->{highestmodseq};
}

#
# Test interaction between RFC4551 modseq and STORE FLAGS
#  - setting a flag bumps the message's modseq
#    and the folder's highestmodseq
#  - clearing a flag bumps the message's modseq etc
#  - setting an already-set flag does not bump modseq
#    (actually this isn't explicitly stated in RFC4551)
#  - clearing an already-clear flag does not bump modseq
#    (actually this isn't explicitly stated in RFC4551)
#  - modseq of other messages is never affected
#
# TODO: test that changing a flag results in an untagged
#       FETCH response.
# TODO: test the .SILENT suffix
# TODO: test the UNCHANGEDSINCE modifier
# TODO: test the MODIFIED response code
#
sub test_modseq
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags modseq));

    xlog "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
			    uid => 1,
			    flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
			    uid => 2,
			    flags => []);
    my $act0 = $self->check_messages(expected => \%msg,
				     check => [qw(id uid flags)]);
    my $hms0 = $self->get_highestmodseq();

    xlog "Set \\Flagged on message A";
    $talk->store('1', '+flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    my $act1 = $self->check_messages(expected => \%msg,
				     check => [qw(id uid flags)]);
    my $hms1 = $self->get_highestmodseq();
    xlog "A should have a new modseq higher than any other message";
    $self->assert(get_modseq($act1, 'A') > get_modseq($act0, 'A'));
    $self->assert(get_modseq($act1, 'A') > get_modseq($act0, 'B'));
    $self->assert(get_modseq($act1, 'B') == get_modseq($act0, 'B'));
    $self->assert($hms1 > $hms0);
    $self->assert(get_modseq($act1, 'A') == $hms1);

    xlog "Set \\Flagged on message A while already set";
    $talk->store('1', '+flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    my $act2 = $self->check_messages(expected => \%msg,
				     check => [qw(id uid flags)]);
    my $hms2 = $self->get_highestmodseq();
    xlog "A should have not changed modseq";
    $self->assert(get_modseq($act2, 'A') == get_modseq($act1, 'A'));
    $self->assert(get_modseq($act2, 'B') == get_modseq($act1, 'B'));
    $self->assert($hms2 == $hms1);
    $self->assert(get_modseq($act2, 'A') == $hms2);

    xlog "Clear \\Flagged on message A";
    $talk->store('1', '-flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => []);
    my $act3 = $self->check_messages(expected => \%msg,
				     check => [qw(id uid flags)]);
    my $hms3 = $self->get_highestmodseq();
    xlog "A should have a new modseq higher than any other message";
    $self->assert(get_modseq($act3, 'A') > get_modseq($act2, 'A'));
    $self->assert(get_modseq($act3, 'A') > get_modseq($act2, 'B'));
    $self->assert(get_modseq($act3, 'B') == get_modseq($act2, 'B'));
    $self->assert($hms3 > $hms2);
    $self->assert(get_modseq($act3, 'A') == $hms3);

    xlog "Clear \\Flagged on message A while already clear";
    $talk->store('1', '-flags', '(\\Flagged)');
    $msg{A}->set_attribute(flags => []);
    my $act4 = $self->check_messages(expected => \%msg,
				     check => [qw(id uid flags)]);
    my $hms4 = $self->get_highestmodseq();
    xlog "A should have not changed modseq";
    $self->assert(get_modseq($act4, 'A') == get_modseq($act3, 'A'));
    $self->assert(get_modseq($act4, 'B') == get_modseq($act3, 'B'));
    $self->assert($hms4 == $hms3);
    $self->assert(get_modseq($act4, 'A') == $hms4);
}

1;
