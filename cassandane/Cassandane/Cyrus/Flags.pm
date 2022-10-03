#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Flags;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use JSON;

sub new
{
    my $class = shift;
    return $class->SUPER::new({adminstore => 1}, @_);
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

    xlog $self, "Append 3 messages";
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
    $self->check_messages(\%msg);

    xlog $self, "Mark the middle message \\Deleted";
    my $res = $talk->store('2', '+flags', '(\\Deleted)');
    $self->assert_deep_equals({ '2' => { 'flags' => [ '\\Deleted' ] }}, $res);
    $msg{B}->set_attribute(flags => ['\\Deleted']);
    $self->check_messages(\%msg);

    xlog $self, "Expunge the middle message";
    $talk->expunge();
    delete $msg{B};
    $msg{A}->set_attribute(id => 1);
    $msg{C}->set_attribute(id => 2);
    $self->check_messages(\%msg);
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

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Seen on message A";
    my $res = $talk->store('1', '+flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Seen on message A";
    $res = $talk->store('1', '-flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Seen on message A again";
    $res = $talk->store('1', '+flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Reconnect, \\Seen should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
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
sub test_seen_otheruser
{
    my ($self) = @_;

    # no particular reason to use an admin rather than just another user,
    # but it's easy
    my $admintalk = $self->{adminstore}->get_client();

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));
    $self->{adminstore}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    # select AFTER creating messages so we don't get \Recent
    $admintalk->select('user.cassandane');
    $admintalk->unselect();
    $admintalk->select('user.cassandane');

    xlog $self, "Set \\Seen on message A";
    my $res = $talk->store('1', '+flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);
    $self->check_messages(\%msg, store => $self->{adminstore});
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Seen on message A as admin";
    $res = $admintalk->store('1', '+flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);
    $self->check_messages(\%msg, store => $self->{adminstore});
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Seen on message A";
    $res = $talk->store('1', '-flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $self->check_messages(\%msg, store => $self->{adminstore});
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Seen on message A as admin";
    $res = $admintalk->store('1', '-flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $self->check_messages(\%msg, store => $self->{adminstore});
    $self->check_messages(\%msg);
}

# https://github.com/cyrusimap/cyrus-imapd/issues/3240
sub test_seen_sharedmb_nosharedseen
    :UnixHierarchySep :AltNamespace
{
    my ($self) = @_;

    my $folder = 'shared';

    # shared mailbox with sharedseen=false
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create($folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setacl('shared', 'cassandane' => 'lrswipkxtecdan');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setmetadata($folder,
        '/shared/vendor/cmu/cyrus-imapd/sharedseen' => 'false'
    );
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());


    # add some messages
    my $talk = $self->{store}->get_client();
    $self->{store}->set_folder("Shared Folders/$folder");
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    # fiddle with seen flag, making sure we get both the expected results
    # and the expected untagged fetch response
    xlog $self, "Set \\Seen on message A";
    my $res = $talk->store('1', '+flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Seen on message A";
    $res = $talk->store('1', '-flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Seen on message A again";
    $res = $talk->store('1', '+flags', '(\\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    # seen flag should survive a reconnect
    xlog $self, "Reconnect, \\Seen should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
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

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Flagged on message A";
    my $res = $talk->store('1', '+flags', '(\\Flagged)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Flagged' ] }}, $res);
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Flagged on message A";
    $res = $talk->store('1', '-flags', '(\\Flagged)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Flagged on message A again";
    $res = $talk->store('1', '+flags', '(\\Flagged)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Flagged' ] }}, $res);
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    $self->check_messages(\%msg);

    xlog $self, "Reconnect, \\Flagged should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
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

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \$Foobar on message A";
    my $res = $talk->store('1', '+flags', '($Foobar)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '$Foobar' ] }}, $res);
    $msg{A}->set_attribute(flags => ['$Foobar']);
    $self->check_messages(\%msg);

    xlog $self, "Clear \$Foobar on message A";
    $res = $talk->store('1', '-flags', '($Foobar)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \$Foobar on message A again";
    $res = $talk->store('1', '+flags', '($Foobar)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '$Foobar' ] }}, $res);
    $msg{A}->set_attribute(flags => ['$Foobar']);
    $self->check_messages(\%msg);

    xlog $self, "Reconnect, \$Foobar should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
}

#
# Test that
#  - the $Foobar flag can be set
#  - the $Foobar flag can be cleared again
#  - cyr_expire -t can remove the $Foobar flag from the mailbox permanentflags
#
#
sub test_expunge_removeflag
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    my $perm = $talk->get_response_code('permanentflags');
    my @flags = grep { !m{^\\} } @$perm;
    $self->assert_deep_equals([], \@flags);

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set \$Foobar on message A";
    my $res = $talk->store('1', '+flags', '($Foobar)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '$Foobar' ] }}, $res);
    $msg{A}->set_attribute(flags => ['$Foobar']);
    $self->check_messages(\%msg);

    xlog $self, "Clear \$Foobar on message A";
    $res = $talk->store('1', '-flags', '($Foobar)');
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $msg{A}->set_attribute(flags => []);
    $self->check_messages(\%msg);

    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $talk = $self->{store}->get_client();

    $self->check_messages(\%msg);

    xlog $self, "Flag is still in the mailbox";

    $perm = $talk->get_response_code('permanentflags');
    @flags = grep { !m{^\\} } @$perm;
    $self->assert_deep_equals(['$Foobar'], \@flags);

    $self->{store}->disconnect();

    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-t');

    $self->{store}->connect();
    $self->{store}->_select();
    $talk = $self->{store}->get_client();

    $perm = $talk->get_response_code('permanentflags');
    @flags = grep { !m{^\\} } @$perm;
    $self->assert_deep_equals([], \@flags);
}

#
# Test that
#  - 100 separate user flags can be used
#  - no more can be used
#  - (we lock out at 100 except for replication to avoid
#  -  one-extra problems)
#
use constant MAX_USER_FLAGS => 100;
sub test_max_userflags
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

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

        xlog $self, "Set $flag on message A";
        my $res = $talk->store('1', '+flags', "($flag)");
        $self->assert_deep_equals({ '1' => { 'flags' => [ "$flag" ] }},
                                  $res);
        $msg{A}->set_attribute(flags => [$flag]);
        $self->check_messages(\%msg);

        xlog $self, "Clear $flag on message A";
        $res = $talk->store('1', '-flags', "($flag)");
        $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
        $msg{A}->set_attribute(flags => []);
        $self->check_messages(\%msg);
    }

    xlog $self, "Cannot set one more wafer-thin user flag";
    my $flag = '$Farnarkle';
    $self->assert_null($allflags{$flag});
    my $res = $talk->store('1', '+flags', "($flag)");
    my $e = $@;
    $self->assert_null($res);
    $self->assert_matches(qr/Too many user flags in mailbox/, $e);

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated an IOERROR
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: out of flags/, "@lines");
    }

    xlog $self, "Can set all the flags at once";
    my @flags = sort { $allflags{$a} <=> $allflags{$b} } (keys %allflags);
    xlog $self, "Set all the user flags on message A";
    $res = $talk->store('1', '+flags', '(' . join(' ',@flags) . ')');
    $self->assert_deep_equals({ '1' => { 'flags' => [ @flags ] }},
                              $res);
    $msg{A}->set_attribute(flags => [@flags]);
    $self->check_messages(\%msg);

    xlog $self, "Reconnect, all the flags should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
}

#
# Test that
#  - more than 32 flags can be searched for
#  - no more can be used
#
sub test_search_allflags
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add messages and flags";

    my %msg;
    for (my $i = 1 ; $i <= MAX_USER_FLAGS ; $i++)
    {
        my $flag = "flag$i";
        $msg{$i} = $self->make_message("Message $i");
        xlog $self, "Set $flag on message $i";
        my $res = $talk->store($i, '+flags', "($flag)");
        $self->assert_deep_equals({ "$i" => { 'flags' => [
                                        '\\Recent', $flag
                                  ]}}, $res);
    }

    # for debugging
    $talk->fetch('1:*', '(uid flags)');

    for (my $i = 1 ; $i <= MAX_USER_FLAGS ; $i++) {
        xlog $self, "Can search for flag $i";
        my $uids = $talk->search("keyword", "flag$i");
        $self->assert_equals(1, scalar(@$uids));
        $self->assert_equals($i, $uids->[0]);
    }
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

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Set many flags on message A";
    my $res = $talk->store('1', '+flags',
                           '(\\Answered \\Flagged \\Draft \\Deleted \\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [
                                qw(\\Answered \\Flagged \\Draft
                                   \\Deleted \\Seen)
                              ]}}, $res);
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Flagged \\Draft \\Deleted \\Seen)]);
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Flagged on message A";
    $res = $talk->store('1', '-flags', '(\\Flagged)');
    $self->assert_deep_equals({ '1' => { 'flags' => [
                                qw(\\Answered \\Draft \\Deleted \\Seen)
                              ]}}, $res);
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Draft \\Deleted \\Seen)]);
    $self->check_messages(\%msg);

    xlog $self, "Clear \\Draft and \\Deleted on message A";
    $res = $talk->store('1', '-flags', '(\\Draft \\Deleted)');
    $self->assert_deep_equals({ '1' => { 'flags' => [
                                qw(\\Answered \\Seen)
                              ]}}, $res);
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Seen)]);
    $self->check_messages(\%msg);

    xlog $self, "Set \\Draft and \\Flagged on message A";
    $res = $talk->store('1', '+flags', '(\\Draft \\Flagged)');
    $self->assert_deep_equals({ '1' => { 'flags' => [
                                qw(\\Answered \\Flagged \\Draft \\Seen)
                              ]}}, $res);
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Flagged \\Draft \\Seen)]);
    $self->check_messages(\%msg);

    xlog $self, "Set to just \\Answered and \\Seen on message A";
    $res = $talk->store('1', 'flags', '(\\Answered \\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [
                                qw(\\Answered \\Seen)
                              ]}}, $res);
    $msg{A}->set_attribute(flags => [qw(\\Answered \\Seen)]);
    $self->check_messages(\%msg);

    xlog $self, "Walk through every combination of flags";
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
        xlog $self, "Setting " . join(',',@flags) . " on message A";
        my $res = $talk->store('1', 'flags', '(' . join(' ',@flags) . ')');
        $self->assert_deep_equals({ '1' => { 'flags' => \@flags }}, $res);
        $msg{A}->set_attribute(flags => \@flags);
        $self->check_messages(\%msg);
    }

    xlog $self, "Reconnect, all the flags should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
}

# Quoth RFC 4314:
#  STORE operation SHOULD NOT fail if the user has rights to modify
#  at least one flag specified in the STORE, as the tagged NO
#  response to a STORE command is not handled very well by deployed
#  clients
sub test_multi_flags_acl
    :min_version_3_5 :NoAltNamespace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    my %acls = (
        '\\Seen' => 's',
        '\\Deleted' => 't',
        '\\Flagged' => 'w',
    );
    my @flags = sort keys %acls;

    my $firsttime = 1;
    while (my ($flag, $acl_bit) = each %acls) {
        xlog $self, "testing flag $flag";
        # reset to no flags set
        $admintalk->setacl("user.cassandane", "cassandane", "lrstw") or die;
        $talk->unselect();
        $talk->select('INBOX');
        my $res = $talk->store('1', 'flags', '()');
        if ($firsttime) {
            $self->assert_deep_equals({}, $res);
            $firsttime = 0;
        }
        else {
            $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
        }
        $msg{A}->set_attribute(flags => []);
        $self->check_messages(\%msg);

        # limit user access
        $admintalk->setacl("user.cassandane", "cassandane", "lr$acl_bit")
            or die;
        $talk->unselect();
        $talk->select('INBOX');

        # set a bunch of flags
        $res = $talk->store('1', '+flags', "(@flags)");

        # it should work, but only the allowed flag should have been set
        $self->assert_deep_equals({ '1' => { 'flags' => [ $flag ] }}, $res);
        $self->assert_equals('ok', $talk->get_last_completion_response());
        $msg{A}->set_attribute(flags => [$flag]);
        $self->check_messages(\%msg);

        # reset to all flags set
        $admintalk->setacl("user.cassandane", "cassandane", "lrstw") or die;
        $talk->unselect();
        $talk->select('INBOX');
        $res = $talk->store('1', 'flags', "(@flags)");
        $self->assert_not_null($res);
        $self->assert_deep_equals([@flags], [sort @{$res->{1}->{flags}}]);
        $msg{A}->set_attribute(flags => [@flags]);
        $self->check_messages(\%msg);

        # limit user access
        $admintalk->setacl("user.cassandane", "cassandane", "lr$acl_bit")
            or die;
        $talk->unselect();
        $talk->select('INBOX');

        # remove a bunch of flags
        $res = $talk->store('1', '-flags', "(@flags)");

        # it should work, but only the allowed flag should have been changed
        $self->assert_not_null($res);
        $self->assert_deep_equals([ grep { $_ ne $flag } @flags ],
                                  [ sort @{$res->{1}->{flags}} ]);
        $self->assert_equals('ok', $talk->get_last_completion_response());
        $msg{A}->set_attribute(flags => [ grep { $_ ne $flag } @flags ]);
        $self->check_messages(\%msg);

        # explicit set with any of them missing permission should fail
        $res = $talk->store('1', 'flags', "(@flags)");

        # nothing should have changed
        $self->assert_null($res);
        $self->assert_equals('no', $talk->get_last_completion_response());
        $self->check_messages(\%msg);

        # no flags we're allowed to change
        $res = $talk->store('1', '+flags',
                     '(' . join(' ', grep { $_ ne $flag } @flags) . ')');

        # nothing should have changed
        $self->assert_null($res);
        $self->assert_equals('no', $talk->get_last_completion_response());
        $self->check_messages(\%msg);

        # no flags we're allowed to change
        $res = $talk->store('1', '-flags',
                     '(' . join(' ', grep { $_ ne $flag } @flags) . ')');

        # nothing should have changed
        $self->assert_null($res);
        $self->assert_equals('no', $talk->get_last_completion_response());
        $self->check_messages(\%msg);
    }
}

sub test_explicit_store_acl
    :NoAltNamespace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    # add a message
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $self->check_messages(\%msg);

    # set some flags on it
    my $res = $talk->store('1', '+flags', '(\\Deleted \\Seen)');
    $self->assert_deep_equals({ '1' => { 'flags' => [ qw(\\Deleted \\Seen)] }},
                              $res);
    $msg{A}->set_attribute(flags => [ '\\Deleted', '\\Seen' ]);
    $self->check_messages(\%msg);

    # remove 't' right from user
    my %acl = @{ $admintalk->getacl('user.cassandane') };
    $self->assert_equals('ok', $admintalk->get_last_completion_response());
    xlog "acl: " . Dumper \%acl;
    $self->assert_not_null($acl{'cassandane'});
    $acl{'cassandane'} =~ s/t//g;
    $admintalk->setacl("user.cassandane", "cassandane", $acl{'cassandane'});
    $self->assert_equals('ok', $admintalk->get_last_completion_response());

    # try to set flags to a new set not containing \Deleted or \Seen.
    # \Seen should be removed, but \Deleted must not be
    $talk->unselect();
    $talk->select('INBOX');
    $res = $talk->store('1', 'flags', '(\\Flagged)');
    $self->assert_deep_equals({ '1' => { 'flags' => [
                                qw(\\Flagged \\Deleted)
                              ]}}, $res);
    $msg{A}->set_attribute(flags => [ '\\Flagged', '\\Deleted' ]);
    $self->check_messages(\%msg);
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

# Get the modseq from a FETCH response
sub get_modseq_from_fetch
{
    my ($fetched, $i) = @_;

    my $msl = $fetched->{$i}->{modseq};
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
#
sub test_modseq
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags modseq));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    my $act0 = $self->check_messages(\%msg);
    my $hms0 = $self->get_highestmodseq();

    xlog $self, "Set \\Flagged on message A";
    my $res = $talk->store('1', '+flags', '(\\Flagged)');
    $self->assert_not_null($res);
    $self->assert_deep_equals([ '\\Flagged' ], $res->{1}->{flags});
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    my $act1 = $self->check_messages(\%msg);
    my $hms1 = $self->get_highestmodseq();
    xlog $self, "A should have a new modseq higher than any other message";
    $self->assert(get_modseq($act1, 'A') > get_modseq($act0, 'A'));
    $self->assert(get_modseq($act1, 'A') > get_modseq($act0, 'B'));
    $self->assert(get_modseq($act1, 'B') == get_modseq($act0, 'B'));
    $self->assert($hms1 > $hms0);
    $self->assert(get_modseq($act1, 'A') == $hms1);

    xlog $self, "Set \\Flagged on message A while already set";
    $res = $talk->store('1', '+flags', '(\\Flagged)');
    $self->assert_deep_equals({}, $res);
    $self->assert_equals('ok', $talk->get_last_completion_response());
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    my $act2 = $self->check_messages(\%msg);
    my $hms2 = $self->get_highestmodseq();
    xlog $self, "A should have not changed modseq";
    $self->assert(get_modseq($act2, 'A') == get_modseq($act1, 'A'));
    $self->assert(get_modseq($act2, 'B') == get_modseq($act1, 'B'));
    $self->assert($hms2 == $hms1);
    $self->assert(get_modseq($act2, 'A') == $hms2);

    xlog $self, "Clear \\Flagged on message A";
    $res = $talk->store('1', '-flags', '(\\Flagged)');
    $self->assert_not_null($res);
    $self->assert_deep_equals([], $res->{1}->{flags});
    $msg{A}->set_attribute(flags => []);
    my $act3 = $self->check_messages(\%msg);
    my $hms3 = $self->get_highestmodseq();
    xlog $self, "A should have a new modseq higher than any other message";
    $self->assert(get_modseq($act3, 'A') > get_modseq($act2, 'A'));
    $self->assert(get_modseq($act3, 'A') > get_modseq($act2, 'B'));
    $self->assert(get_modseq($act3, 'B') == get_modseq($act2, 'B'));
    $self->assert($hms3 > $hms2);
    $self->assert(get_modseq($act3, 'A') == $hms3);

    xlog $self, "Clear \\Flagged on message A while already clear";
    $res = $talk->store('1', '-flags', '(\\Flagged)');
    $self->assert_deep_equals({}, $res);
    $self->assert_equals('ok', $talk->get_last_completion_response());
    $msg{A}->set_attribute(flags => []);
    my $act4 = $self->check_messages(\%msg);
    my $hms4 = $self->get_highestmodseq();
    xlog $self, "A should have not changed modseq";
    $self->assert(get_modseq($act4, 'A') == get_modseq($act3, 'A'));
    $self->assert(get_modseq($act4, 'B') == get_modseq($act3, 'B'));
    $self->assert($hms4 == $hms3);
    $self->assert(get_modseq($act4, 'A') == $hms4);
}

#
# Test UNCHANGEDSINCE modifier; RFC4551 section 3.2.
# - changing a flag with current modseq equal to the
#   UNCHANGEDSINCE value
#       - updates the flag
#       - updates modseq
#       - sends an untagged FETCH response
#       - the FETCH response has the new modseq
#       - returns an OK response
#       - the UID does not appear in the MODIFIED response code
# - ditto less than
# - changing a flag with current modseq greater than the
#   UNCHANGEDSINCE value
#       - doesn't update the flag
#       - doesn't update modseq
#       - sent no FETCH untagged response
#       - returns an OK response
#       - but reports the UID in the MODIFIED response code
#
sub test_unchangedsince
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags modseq));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    my $act0 = $self->check_messages(\%msg);

    my %fetched;
    my $modified;
    my %handlers =
    (
        fetch => sub
        {
            my ($response, $rr, $id) = @_;

            # older versions of Mail::IMAPTalk don't have
            # the 3rd argument.  We can't test properly in
            # those circumstances.
            $self->assert_not_null($id);

            $fetched{$id} = $rr;
        },
        modified => sub
        {
            my ($response, $rr) = @_;
            # we should not get more than one of these ever
            $self->assert_null($modified);
            $modified = $rr;
        }
    );

    # Note: Mail::IMAPTalk::store() doesn't support modifiers
    # so we have to resort to the lower level interface.

    xlog $self, "Changing a flag with current modseq == UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 '1', ['unchangedsince', get_modseq($act0, 'A')],
                  '+flags', ['\\Flagged']);
    my $res1 = $talk->get_last_completion_response();
    #   - updates the flag
    $msg{A}->set_attribute(flags => ['\\Flagged']);
    my $act1 = $self->check_messages(\%msg);
    xlog $self, "returns an OK response?";
    $self->assert_str_equals('ok', $res1);
    xlog $self, "updated modseq?";
    $self->assert(get_modseq($act1, 'A') > get_modseq($act0, 'A'));
    xlog $self, "returned no MODIFIED response code?";
    $self->assert_null($modified);
    xlog $self, "sent an untagged FETCH response?";
    $self->assert_num_equals(1, scalar keys %fetched);
    $self->assert_not_null($fetched{1});
    xlog $self, "the FETCH response has the new modseq?";
    $self->assert_num_equals(get_modseq($act1, 'A'),
                             get_modseq_from_fetch(\%fetched, 1));

    xlog $self, "Changing a flag with current modseq < UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 '1', ['unchangedsince', get_modseq($act1, 'A')+1],
                  '-flags', ['\\Flagged']);
    my $res2 = $talk->get_last_completion_response();
    #   - updates the flag
    $msg{A}->set_attribute(flags => []);
    my $act2 = $self->check_messages(\%msg);
    xlog $self, "returns an OK response?";
    $self->assert_str_equals('ok', $res2);
    xlog $self, "updated modseq?";
    $self->assert(get_modseq($act2, 'A') > get_modseq($act0, 'A'));
    xlog $self, "returned no MODIFIED response code?";
    $self->assert_null($modified);
    xlog $self, "sent an untagged FETCH response?";
    $self->assert_num_equals(1, scalar keys %fetched);
    $self->assert_not_null($fetched{1});
    xlog $self, "the FETCH response has the new modseq?";
    $self->assert_num_equals(get_modseq($act2, 'A'),
                             get_modseq_from_fetch(\%fetched, 1));

    xlog $self, "Changing a flag with current modseq > UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 '1', ['unchangedsince', get_modseq($act2, 'A')-1],
                  '+flags', ['\\Flagged']);
    my $res3 = $talk->get_last_completion_response();
    #   - doesn't update the flag
    $msg{A}->set_attribute(flags => []);
    my $act3 = $self->check_messages(\%msg);
    xlog $self, "returns an OK response?";
    $self->assert_str_equals('ok', $res3);
    xlog $self, "didn't update modseq?";
    $self->assert_num_equals(get_modseq($act3, 'A'), get_modseq($act2, 'A'));
    xlog $self, "reports the UID in the MODIFIED response code?";
    $self->assert_not_null($modified);
    $self->assert_deep_equals($modified, [1]);
    xlog $self, "sent no FETCH untagged response?";
    $self->assert_num_equals(0, scalar keys %fetched);
}

#
# More tests for UNCHANGEDSINCE, RFC4551 section 3.2.
#
# - success/failure is per-message, i.e. the update can
#   fail on one message and succeed on another.
# - example 11: STORE UNCHANGEDSINCE +FLAGS \Seen on a set
#   of messages where some are expunged and some have been
#   modified since: response is NO because of the expunged
#   messages, with a MODIFIED response code.
#
#
#
# TODO: Once the client specified the UNCHANGEDSINCE modifier in a STORE
# command, the server MUST include the MODSEQ fetch response data items
# in all subsequent unsolicited FETCH responses.  Once the client
# specified the UNCHANGEDSINCE modifier in a STORE command, the server
# MUST include the MODSEQ fetch response data items in all subsequent
# unsolicited FETCH responses.
#
# TODO the untagged FETCH response is returned even when
#   .SILENT is used
#
sub test_unchangedsince_multi
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags modseq));

    xlog $self, "Add some messages";
    my %msg;
    for (my $i = 1 ; $i <= 26 ; $i++)
    {
        my $letter = chr(64 + $i);  # A ... Z
        $msg{$letter} = $self->make_message('Message ' . $letter);
        $msg{$letter}->set_attributes(id => $i,
                                      uid => $i,
                                      flags => []);
    }

    xlog $self, "Bump the modseq on M,N,O";
    my $res = $talk->store('13,14,15', '+flags', '(\\Draft)');
    $self->assert_deep_equals({
        '13' => { 'flags' => [ '\\Draft' ] },
        '14' => { 'flags' => [ '\\Draft' ] },
        '15' => { 'flags' => [ '\\Draft' ] },
    }, $res);
    $msg{M}->set_attribute(flags => ['\\Draft']);
    $msg{N}->set_attribute(flags => ['\\Draft']);
    $msg{O}->set_attribute(flags => ['\\Draft']);

    my $act0 = $self->check_messages(\%msg);

    {
        my $store2 = $self->{instance}->get_service('imap')->create_store();
        $store2->connect();
        $store2->_select();
        my $talk2 = $store2->get_client();
        xlog $self, "Delete and expunge D,E,F from another session";
        for (my $i = 4 ; $i <= 6 ; $i++)
        {
            my $letter = chr(64 + $i);  # D, E, F
            my $res = $talk2->store($i, '+flags', '(\\Deleted)');
            $self->assert_deep_equals({
                "$i" => { 'flags' => [ '\\Deleted' ] }
            }, $res);
            delete $msg{$letter};
        }
        $talk2->expunge();
        $store2->disconnect();
    }


    my %fetched;
    my $modified;
    my %handlers =
    (
        fetch => sub
        {
            my ($response, $rr, $id) = @_;

            # older versions of Mail::IMAPTalk don't have
            # the 3rd argument.  We can't test properly in
            # those circumstances.
            $self->assert_not_null($id);

            $fetched{$id} = $rr;
        },
        modified => sub
        {
            my ($response, $rr) = @_;
            # we should not get more than one of these ever
            $self->assert_null($modified);
            $modified = $rr;
        }
    );

    # Note: Mail::IMAPTalk::store() doesn't support modifiers
    # so we have to resort to the lower level interface.

    xlog $self, "Changing a flag on multiple messages";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 \'1:*', ['unchangedsince', get_modseq($act0, 'Z')],
                  '+flags', ['\\Flagged']);
    my $res1 = $talk->get_last_completion_response();

    $msg{A}->set_attribute(flags => ['\\Flagged']);
    $msg{B}->set_attribute(flags => ['\\Flagged']);
    $msg{C}->set_attribute(flags => ['\\Flagged']);
    # D,E,F deleted
    $msg{G}->set_attribute(flags => ['\\Flagged']);
    $msg{H}->set_attribute(flags => ['\\Flagged']);
    $msg{I}->set_attribute(flags => ['\\Flagged']);
    $msg{J}->set_attribute(flags => ['\\Flagged']);
    $msg{K}->set_attribute(flags => ['\\Flagged']);
    $msg{L}->set_attribute(flags => ['\\Flagged']);
    # M,N,O should fail the conditional store
    $msg{M}->set_attribute(flags => ['\\Draft']);
    $msg{N}->set_attribute(flags => ['\\Draft']);
    $msg{O}->set_attribute(flags => ['\\Draft']);
    $msg{P}->set_attribute(flags => ['\\Flagged']);
    $msg{Q}->set_attribute(flags => ['\\Flagged']);
    $msg{R}->set_attribute(flags => ['\\Flagged']);
    $msg{S}->set_attribute(flags => ['\\Flagged']);
    $msg{T}->set_attribute(flags => ['\\Flagged']);
    $msg{U}->set_attribute(flags => ['\\Flagged']);
    $msg{V}->set_attribute(flags => ['\\Flagged']);
    $msg{W}->set_attribute(flags => ['\\Flagged']);
    $msg{X}->set_attribute(flags => ['\\Flagged']);
    $msg{Y}->set_attribute(flags => ['\\Flagged']);
    $msg{Z}->set_attribute(flags => ['\\Flagged']);
    # We start a new session in check_messages, so we
    # have to renumber here to account for deletion
    for (my $i = 7 ; $i <= 26 ; $i++)
    {
        my $letter = chr(64 + $i);  # G ... Z
        $msg{$letter}->set_attribute(id => $i-3);
    }
    my $act1 = $self->check_messages(\%msg);

# TODO: this fails with current Cyrus code
#     xlog $self, "returns a NO response?";
#     $self->assert_str_equals('NO', $res1);

    xlog $self, "updated modseq?";
    $self->assert(get_modseq($act1, 'A') > get_modseq($act0, 'A'));
    $self->assert(get_modseq($act1, 'B') > get_modseq($act0, 'B'));
    $self->assert(get_modseq($act1, 'C') > get_modseq($act0, 'C'));
    # D,E,F deleted
    $self->assert(get_modseq($act1, 'G') > get_modseq($act0, 'G'));
    $self->assert(get_modseq($act1, 'H') > get_modseq($act0, 'H'));
    $self->assert(get_modseq($act1, 'I') > get_modseq($act0, 'I'));
    $self->assert(get_modseq($act1, 'J') > get_modseq($act0, 'J'));
    $self->assert(get_modseq($act1, 'K') > get_modseq($act0, 'K'));
    $self->assert(get_modseq($act1, 'L') > get_modseq($act0, 'L'));
    # M,N,O have the same modseq
    $self->assert(get_modseq($act1, 'M') == get_modseq($act0, 'M'));
    $self->assert(get_modseq($act1, 'N') == get_modseq($act0, 'N'));
    $self->assert(get_modseq($act1, 'O') == get_modseq($act0, 'O'));
    $self->assert(get_modseq($act1, 'P') > get_modseq($act0, 'P'));
    $self->assert(get_modseq($act1, 'Q') > get_modseq($act0, 'Q'));
    $self->assert(get_modseq($act1, 'R') > get_modseq($act0, 'R'));
    $self->assert(get_modseq($act1, 'S') > get_modseq($act0, 'S'));
    $self->assert(get_modseq($act1, 'T') > get_modseq($act0, 'T'));
    $self->assert(get_modseq($act1, 'U') > get_modseq($act0, 'U'));
    $self->assert(get_modseq($act1, 'V') > get_modseq($act0, 'V'));
    $self->assert(get_modseq($act1, 'W') > get_modseq($act0, 'W'));
    $self->assert(get_modseq($act1, 'X') > get_modseq($act0, 'X'));
    $self->assert(get_modseq($act1, 'Y') > get_modseq($act0, 'Y'));
    $self->assert(get_modseq($act1, 'Z') > get_modseq($act0, 'Z'));

    xlog $self, "returned MODIFIED response code?";
    $self->assert_not_null($modified);
    $self->assert_deep_equals($modified, ['13:15']);

    xlog $self, "sent untagged FETCH responses with the new modseq?";
    # also tells about the 3 messages which were deleted since
    # the last command
    $self->assert_num_equals(23, scalar keys %fetched);
    foreach my $i (1..3, 7..12, 16..26)
    {
        my $letter = chr(64 + $i);
        $self->assert_not_null($fetched{$i});
        $self->assert_num_equals(get_modseq($act1, $letter),
                                 get_modseq_from_fetch(\%fetched, $i));
    }

}

# check that seen flags are set correctly on body fetch
sub test_setseen
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add three messages";
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
    $self->check_messages(\%msg);

    xlog $self, "Fetch body of message A";
    my $res = $talk->fetch('1', '(body[])');
    $self->assert_deep_equals([ '\\Seen' ], $res->{1}->{flags});
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Fetch body.peek of message B";
    $res = $talk->fetch('2', '(body.peek[])');
    $self->assert(not exists $res->{2}->{flags});
    $self->check_messages(\%msg);

    xlog $self, "Fetch binary of message C";
    $res = $talk->fetch('3', '(binary[])');
    $self->assert_deep_equals([ '\\Seen' ], $res->{3}->{flags});
    $msg{C}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Reconnect, \\Seen should still be on messages A and C";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
}

# check that seen flags are set correctly on body fetch
# even if the flag was removed in the same session
sub test_setseen_after_store
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add two messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $self->check_messages(\%msg);

    xlog $self, "Fetch body of message A";
    $talk->fetch('1', '(body[])');
    $msg{A}->set_attribute(flags => ['\\Seen']);
    $self->check_messages(\%msg);

    xlog $self, "Fetch remove the flag again, and immediately fetch the body";
    my $res = $talk->store('1', '-flags.silent', "(\\Seen)");
#    $self->assert_deep_equals({}, $res);
    # XXX flags.silent should cause there to not be an untagged response
    # XXX unless the affected data was also modified by another user, but
    # XXX for some reason Cyrus still returns it here?
    $self->assert_deep_equals({ '1' => { 'flags' => [] }}, $res);
    $talk->fetch('1', '(body[])');
    $self->check_messages(\%msg);

    xlog $self, "Reconnect, \\Seen should still be on message A";
    $self->{store}->disconnect();
    $self->{store}->connect();
    $self->{store}->_select();
    $self->check_messages(\%msg);
}

sub test_setseen_notify
    :Conversations :FastMailEvent :min_version_3_0
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Throw away existing notify";
    $self->{instance}->getnotify();

    xlog $self, "Add a messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $self->check_messages(\%msg);

    my $notify1 = $self->{instance}->getnotify();

    $msg{A}->set_attribute(flags => ['\\Seen']);
    my $res = $talk->store('1', '+flags', '\\Seen');
    $self->assert_deep_equals({ '1' => { 'flags' => [ '\\Seen' ] }}, $res);

    my $notify2 = $self->{instance}->getnotify();

    my $payload1 = decode_json($notify1->[0]{MESSAGE});
    my $payload2 = decode_json($notify2->[0]{MESSAGE});
    $self->assert($payload2->{modseq} > $payload1->{modseq}, "modseq has increased: $payload2->{modseq} > $payload1->{modseq}");
}

1;
