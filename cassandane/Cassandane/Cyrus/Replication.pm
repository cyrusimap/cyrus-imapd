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

package Cassandane::Cyrus::Replication;
use strict;
use warnings;
use Data::Dumper;
use DateTime;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Service;
use Cassandane::Config;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ replica => 1 }, @_);
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
# Test replication of messages APPENDed to the master
#
sub test_append
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog $self, "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);
}

#
# Test handling of replication when append fails due to disk error
#
sub test_appendone_diskfull
    :NoStartInstances :min_version_3_5
{
    my ($self) = @_;

    my $canary = << 'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>
Subject: this is just to say
X-Cassandane-Unique: canary

I have eaten
the canary
that was in
the coal mine

and which
you were probably
saving
for emergencies

Forgive me
it was delicious
so tweet
and so coaled
EOF
    $canary =~ s/\n/\r\n/g;
    my $canaryguid = "f2eaa91974c50ec3cfb530014362e92efb06a9ba";

    $self->{replica}->{config}->set('debug_writefail_guid' => $canaryguid);
    $self->_start_instances();

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my %exp;
    $exp{1} = Cassandane::Message->new(raw => $canary,
                                       attrs => { UID => 1 }),
    $self->_save_message($exp{1}, $master_store);

    xlog $self, "message should be on master only";
    $self->check_messages(\%exp, keyed_on => 'uid', store => $master_store);
    $self->check_messages({}, keyed_on => 'uid', store => $replica_store);

    xlog $self, "running replication...";
    eval {
        $self->run_replication();
    };
    my $e = $@;

    # sync_client should have exited with an error
    $self->assert($e);
    $self->assert_matches(qr/child\sprocess\s
                            \(binary\ssync_client\spid\s\d+\)\s
                            exited\swith\scode/x,
                          $e->to_string());

    if ($self->{instance}->{have_syslog_replacement}) {
        # sync_client should have logged the BAD response
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: received bad response/, "@lines");

        # sync server should have logged the write error
        @lines = $self->{replica}->getsyslog();
        $self->assert_matches(qr{IOERROR:\sfailed\sto\supload\sfile
                                 (?:\s\(simulated\))?:\sguid=<$canaryguid>
                              }x,
                              "@lines");
    }
}

#
# Test handling of replication when append fails due to disk error
#
sub test_appendmulti_diskfull
    :CSyncReplication :NoStartInstances :min_version_3_5
{
    my ($self) = @_;

    my $canary = << 'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>
Subject: this is just to say
X-Cassandane-Unique: canary

I have eaten
the canary
that was in
the coal mine

and which
you were probably
saving
for emergencies

Forgive me
it was delicious
so tweet
and so coaled
EOF
    $canary =~ s/\n/\r\n/g;
    my $canaryguid = "f2eaa91974c50ec3cfb530014362e92efb06a9ba";

    $self->{replica}->{config}->set('debug_writefail_guid' => $canaryguid);
    $self->_start_instances();

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my %exp;
    $exp{1} = $self->make_message("msg 1", uid => 1, store => $master_store);
    $exp{2} = $self->make_message("msg 2", uid => 2, store => $master_store);
    $exp{3} = Cassandane::Message->new(raw => $canary,
                                       attrs => { UID => 3 }),
    $self->_save_message($exp{3}, $master_store);
    $exp{4} = $self->make_message("msg 4", uid => 4, store => $master_store);

    xlog $self, "messages should be on master only";
    $self->check_messages(\%exp, keyed_on => 'uid', store => $master_store);
    $self->check_messages({}, keyed_on => 'uid', store => $replica_store);

    xlog $self, "running replication...";
    eval {
        $self->run_replication();
    };
    my $e = $@;

    # sync_client should have exited with an error
    $self->assert($e);
    $self->assert_matches(qr/child\sprocess\s
                            \(binary\ssync_client\spid\s\d+\)\s
                            exited\swith\scode/x,
                          $e->to_string());

    if ($self->{instance}->{have_syslog_replacement}) {
        # sync_client should have logged the BAD response
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: received bad response/, "@lines");

        # sync server should have logged the write error
        @lines = $self->{replica}->getsyslog();
        $self->assert_matches(qr{IOERROR:\sfailed\sto\supload\sfile
                                 (?:\s\(simulated\))?:\sguid=<$canaryguid>
                              }x,
                              "@lines");

        # contents of message 4 should not appear on the wire (or logs) as
        # junk commands!  we need sync_server specifically for this (and not
        # a replication-aware imapd), because only sync_server logs bad
        # commands.
        $self->assert_does_not_match(qr/IOERROR:\sreceived\sbad\scommand:\s
                                        command=<Return-path:>/x,
                                     "@lines");
    }
}

#
# Test handling of replication when append fails due to disk error
#
sub test_syncall_failinguser
    :NoStartInstances :min_version_3_6
{
    my ($self) = @_;

    my $canary = << 'EOF';
From: Fred J. Bloggs <fbloggs@fastmail.fm>
To: Sarah Jane Smith <sjsmith@tard.is>
Subject: this is just to say
X-Cassandane-Unique: canary

I have eaten
the canary
that was in
the coal mine

and which
you were probably
saving
for emergencies

Forgive me
it was delicious
so tweet
and so coaled
EOF
    $canary =~ s/\n/\r\n/g;
    my $canaryguid = "f2eaa91974c50ec3cfb530014362e92efb06a9ba";

    $self->{replica}->{config}->set('debug_writefail_guid' => $canaryguid);
    $self->_start_instances();

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    $self->{instance}->create_user("a_early");
    $self->{instance}->create_user("z_late");

    my $mastersvc = $self->{instance}->get_service('imap');
    my $astore = $mastersvc->create_store(username => "a_early");
    my $zstore = $mastersvc->create_store(username => "z_late");
    my $replicasvc = $self->{replica}->get_service('imap');
    my $replica_astore = $replicasvc->create_store(username => "a_early");
    my $replica_zstore = $replicasvc->create_store(username => "z_late");

    xlog $self, "Creating a message in each user";
    my %apreexp;
    my %cpreexp;
    my %zpreexp;
    $apreexp{1} = $self->make_message("Message A", store => $astore);
    $cpreexp{1} = $self->make_message("Message C", store => $master_store);
    $zpreexp{1} = $self->make_message("Message Z", store => $zstore);

    xlog $self, "Running all user replication";
    $self->run_replication(allusers => 1);

    xlog $self, "Creating a second message for each user (cassandane having the canary)";
    my %aexp = %apreexp;
    my %cexp = %cpreexp;
    my %zexp = %zpreexp;
    $aexp{2} = $self->make_message("Message A2", store => $astore);
    $cexp{2} = Cassandane::Message->new(raw => $canary,
                                       attrs => { UID => 2 }),
    $self->_save_message($cexp{2}, $master_store);
    $zexp{2} = $self->make_message("Message Z2", store => $zstore);

    xlog $self, "new messages should be on master only";
    $self->check_messages(\%aexp, keyed_on => 'uid', store => $astore);
    $self->check_messages(\%apreexp, keyed_on => 'uid', store => $replica_astore);
    $self->check_messages(\%cexp, keyed_on => 'uid', store => $master_store);
    $self->check_messages(\%cpreexp, keyed_on => 'uid', store => $replica_store);
    $self->check_messages(\%zexp, keyed_on => 'uid', store => $zstore);
    $self->check_messages(\%zpreexp, keyed_on => 'uid', store => $replica_zstore);

    xlog $self, "running replication...";
    eval {
        $self->run_replication(allusers => 1);
    };
    my $e = $@;

    # sync_client should have exited with an error
    $self->assert($e);
    $self->assert_matches(qr/child\sprocess\s
                            \(binary\ssync_client\spid\s\d+\)\s
                            exited\swith\scode/x,
                          $e->to_string());

    if ($self->{instance}->{have_syslog_replacement}) {
        # sync_client should have logged the BAD response
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: received bad response/, "@lines");

        # sync server should have logged the write error
        @lines = $self->{replica}->getsyslog();
        $self->assert_matches(qr{IOERROR:\sfailed\sto\supload\sfile
                                 (?:\s\(simulated\))?:\sguid=<$canaryguid>
                              }x,
                              "@lines");
    }

    xlog $self, "Check that cassandane user wasn't updated, both others were";
    $self->check_replication('a_early');
    $self->check_replication('z_late');

    $self->check_messages(\%aexp, keyed_on => 'uid', store => $astore);
    $self->check_messages(\%aexp, keyed_on => 'uid', store => $replica_astore);
    $self->check_messages(\%cexp, keyed_on => 'uid', store => $master_store);
    $self->check_messages(\%cpreexp, keyed_on => 'uid', store => $replica_store);
    $self->check_messages(\%zexp, keyed_on => 'uid', store => $zstore);
    $self->check_messages(\%zexp, keyed_on => 'uid', store => $replica_zstore);
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog $self, "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog $self, "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog $self, "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    $self->run_replication();
    if ($self->{instance}->{have_syslog_replacement}) {
        # replication will generate a couple of SYNCERRORS in syslog
        my @syslog = $self->{instance}->getsyslog();

        my $pattern = qr{
            \bSYNCERROR:\sguid\smismatch
            (?: \suser\.cassandane\s5\b
              | :\smailbox=<user\.cassandane>\suid=<5>
            )
        }x;

        $self->assert_matches($pattern, "@syslog");
    }
    $self->check_replication('cassandane');


    %exp = (%mexp, %rexp);
    # we could calculate 6 and 7 by sorting from GUID, but easiest is to ignore UIDs
    $exp{E}->set_attribute(uid => undef);
    $exp{F}->set_attribute(uid => undef);
    xlog $self, "After replication, the master should have all 6 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should have all 6 messages";
    $self->check_messages(\%exp, store => $replica_store);
}

#
# Test replication of mailbox only after a rename
#
sub test_splitbrain_mailbox
    :min_version_3_1 :max_version_3_4 :NoAltNameSpace
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $mastertalk = $master_store->get_client();
    my $replicatalk = $replica_store->get_client();

    $mastertalk->create("INBOX.src-name");

    xlog $self, "run initial replication";
    $self->run_replication();
    $self->check_replication('cassandane');

    $mastertalk = $master_store->get_client();
    $mastertalk->rename("INBOX.src-name", "INBOX.dest-name");

    $self->{instance}->getsyslog();
    $self->{replica}->getsyslog();

    xlog $self, "try replicating just the mailbox by name fails due to duplicate uniqueid";
    eval { $self->run_replication(mailbox => 'user.cassandane.dest-name') };
    $self->assert_matches(qr/exited with code 1/, "$@");

    if ($self->{instance}->{have_syslog_replacement}) {
        my @mastersyslog = $self->{instance}->getsyslog();
        my @replicasyslog = $self->{replica}->getsyslog();

        my $master_pattern = qr{
            \bMAILBOX\sreceived\sNO\sresponse:\sIMAP_MAILBOX_MOVED\b
        }x;

        my $replica_pattern = qr{
            (?: \bSYNCNOTICE:\sfailed\sto\screate\smailbox
                \suser\.cassandane\.dest-name\b
              | \bSYNCNOTICE:\smailbox\suniqueid\salready\sin\suse:
                \smailbox=<user\.cassandane\.dest-name>
            )
        }x;

        $self->assert_matches($master_pattern, "@mastersyslog");
        $self->assert_matches($replica_pattern, "@replicasyslog");
    }

    xlog $self, "Run a full user replication to repair";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "Rename again";
    $mastertalk = $master_store->get_client();
    $mastertalk->rename("INBOX.dest-name", "INBOX.foo");
    my $file = $self->{instance}->{basedir} . "/sync.log";
    open(FH, ">", $file);
    print FH "MAILBOX user.cassandane.foo\n";
    close(FH);

    $self->{instance}->getsyslog();
    $self->{replica}->getsyslog();
    xlog $self, "Run replication from a file with just the mailbox name in it";
    $self->run_replication(inputfile => $file, rolling => 1);

    if ($self->{instance}->{have_syslog_replacement}) {
        my @mastersyslog = $self->{instance}->getsyslog();
        my @replicasyslog = $self->{replica}->getsyslog();

        my $master_pattern = qr{
            \bdo_folders\(\):\supdate\sfailed:\suser\.cassandane\.foo\b
        }x;

        my $replica_pattern1 = qr{
            (?: \bSYNCNOTICE:\sfailed\sto\screate\smailbox
                \suser\.cassandane\.foo\b
              | \bSYNCNOTICE:\smailbox\suniqueid\salready\sin\suse:
                \smailbox=<user\.cassandane\.foo>
            )
        }x;

        my $replica_pattern2 = qr{
            \bRename:\suser.cassandane\.dest-name\s->\suser\.cassandane\.foo\b
        }x;

        # initial failures
        $self->assert_matches($master_pattern, "@mastersyslog");
        $self->assert_matches($replica_pattern1, "@replicasyslog");
        # later success
        $self->assert_matches($replica_pattern2, "@replicasyslog");
    }

    # replication fixes itself
    $self->check_replication('cassandane');
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain_masterexpunge
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog $self, "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog $self, "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog $self, "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    xlog $self, "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('5', '+flags', '(\\Deleted)');
    $talk->expunge();
    delete $mexp{E};

    xlog $self, "No replication, the master now only has 4 messages";
    $self->check_messages(\%mexp, store => $master_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    %exp = (%mexp, %rexp);
    # we know that the message should be prompoted to UID 6
    $exp{F}->set_attribute(uid => 6);
    xlog $self, "After replication, the master should have all 5 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should have the same 5 messages";
    $self->check_messages(\%exp, store => $replica_store);

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR/SYNCNOTICE or two
        my @master_lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/SYNC(?:ERROR|NOTICE): guid mismatch/,
                              "@master_lines");
        my @replica_lines = $self->{replica}->getsyslog();
        $self->assert_matches(qr/SYNC(?:ERROR|NOTICE): guid mismatch/,
                              "@replica_lines");
    }
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain_replicaexpunge
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog $self, "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog $self, "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog $self, "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    xlog $self, "Delete and expunge the message on the master";
    my $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $rtalk->store('5', '+flags', '(\\Deleted)');
    $rtalk->expunge();
    delete $rexp{F};

    xlog $self, "No replication, the replica now only has 4 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    %exp = (%mexp, %rexp);
    # we know that the message should be prompoted to UID 6
    $exp{E}->set_attribute(uid => 6);
    xlog $self, "After replication, the master should have all 5 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should have the same 5 messages";
    $self->check_messages(\%exp, store => $replica_store);

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR or two
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/SYNCERROR: guid mismatch/, "@lines");
    }
}

#
# Test replication of messages APPENDed to the master
#
sub test_splitbrain_bothexpunge
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "generating messages A..D";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{D} = $self->make_message("Message D", store => $master_store);

    xlog $self, "Before replication, the master should have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "Before replication, the replica should have no messages";
    $self->check_messages({}, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, the master should still have all four messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should now have all four messages";
    $self->check_messages(\%exp, store => $replica_store);

    my %mexp = %exp;
    my %rexp = %exp;

    $mexp{E} = $self->make_message("Message E", store => $master_store);
    $rexp{F} = $self->make_message("Message F", store => $replica_store);

    # uid is 5 at both ends
    $rexp{F}->set_attribute(uid => 5);

    xlog $self, "No replication, the master should have its 5 messages";
    $self->check_messages(\%mexp, store => $master_store);
    xlog $self, "No replication, the replica should have the other 5 messages";
    $self->check_messages(\%rexp, store => $replica_store);

    xlog $self, "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('5', '+flags', '(\\Deleted)');
    $talk->expunge();
    delete $mexp{E};

    xlog $self, "Delete and expunge the message on the master";
    my $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $rtalk->store('5', '+flags', '(\\Deleted)');
    $rtalk->expunge();
    delete $rexp{F};

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, the master should have just the original 4 messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication, the replica should have the same 4 messages";
    $self->check_messages(\%exp, store => $replica_store);
}

# trying to reproduce error reported in https://git.cyrus.foundation/T228
sub test_alternate_globalannots
    :NoStartInstances
{
    my ($self) = @_;

    # first, set a different annotation_db_path on the master server
    my $annotation_db_path = $self->{instance}->get_basedir()
                             . "/conf/non-default-annotations.db";
    $self->{instance}->{config}->set('annotation_db_path' => $annotation_db_path);

    # now we can start the instances
    $self->_start_instances();

    # A replication will automatically occur when the instances are started,
    # in order to make sure the cassandane user exists on both hosts.
    # So if we get here without crashing, replication works.
    xlog $self, "initial replication was successful";

    $self->assert(1);
}

sub test_sieve_replication
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on master
    $self->{instance}->install_sieve_script($scriptcontent, name=>$scriptname);

    # then, verify that sieve script exists on master but not on replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, run replication,
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that sieve script exists on both master and replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_exists
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on both master and replica
    $self->{instance}->install_sieve_script($scriptcontent, name=>$scriptname);
    $self->{replica}->install_sieve_script($scriptcontent, name=>$scriptname);

    # then, verify that sieve script exists on both
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);

    # then, run replication,
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that sieve script still exists on both master and replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_different
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $script1name = 'test1';
    my $script1content = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    my $script2name = 'test2';
    my $script2content = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "more testing";
}
EOF

    # first, verify that neither script exists on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $script1name, 0);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $script1name, 0);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script2name, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install different sieve script on master and replica
    $self->{instance}->install_sieve_script($script1content, name=>$script1name);
    $self->{replica}->install_sieve_script($script2content, name=>$script2name);

    # then, verify that each sieve script exists on one only
    $self->assert_sieve_exists($self->{instance}, $user, $script1name, 0);
    $self->assert_sieve_active($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name, 0);

    $self->assert_sieve_exists($self->{replica}, $user, $script2name, 0);
    $self->assert_sieve_active($self->{replica}, $user, $script2name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script1name, 0);

    # then, run replication,
    # the one that exists on master only will be replicated
    # the one that exists on replica only will be deleted
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that scripts are in expected state
    $self->assert_sieve_exists($self->{instance}, $user, $script1name, 1);
    $self->assert_sieve_active($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name, 1);

    $self->assert_sieve_exists($self->{replica}, $user, $script1name, 1);
    $self->assert_sieve_active($self->{replica}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script2name, 1);
}

sub test_sieve_replication_stale
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptoldcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    my $scriptnewcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "more testing";
}
EOF

    # first, verify that script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install "old" script on replica...
    $self->{replica}->install_sieve_script($scriptoldcontent, name=>$scriptname);

    # ... and "new" script on master, a little later
    sleep 2;
    $self->{instance}->install_sieve_script($scriptnewcontent, name=>$scriptname);

    # then, verify that different sieve script content exists at each end
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);
    $self->assert_sieve_matches($self->{instance}, $user, $scriptname,
                                $scriptnewcontent);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
    $self->assert_sieve_matches($self->{replica}, $user, $scriptname,
                                $scriptoldcontent);

    # then, run replication,
    # the one that exists on replica is different to and older than the one
    # on master, so it will be replaced with the one from master
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that scripts are in expected state
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);
    $self->assert_sieve_matches($self->{instance}, $user, $scriptname,
                                $scriptnewcontent);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
    $self->assert_sieve_matches($self->{replica}, $user, $scriptname,
                                $scriptnewcontent);
}

sub test_sieve_replication_delete_unactivate
    :needs_component_sieve
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on replica only
    $self->{replica}->install_sieve_script($scriptcontent, name=>$scriptname);

    # then, verify that sieve script exists on replica only
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);

    # then, run replication,
    $self->run_replication();
    $self->check_replication('cassandane');

    # then, verify that sieve script no longer exists on either
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_noactive($self->{instance}, $user, $scriptname);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_noactive($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_unixhs
    :needs_component_sieve :UnixHierarchySep
{
    my ($self) = @_;

    my $user = 'some.body';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF
    $self->{instance}->create_user($user);

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on master
    $self->{instance}->install_sieve_script($scriptcontent,
                                            name=>$scriptname,
                                            username=>$user);

    # then, verify that sieve script exists on master but not on replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, run replication,
    $self->run_replication(user=>$user);
    $self->check_replication($user);

    # then, verify that sieve script exists on both master and replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_exists_unixhs
    :needs_component_sieve :UnixHierarchySep
{
    my ($self) = @_;

    my $user = 'some.body';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF
    $self->{instance}->create_user($user);

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on both master and replica
    $self->{instance}->install_sieve_script($scriptcontent,
                                            name=>$scriptname,
                                            username=>$user);
    $self->{replica}->install_sieve_script($scriptcontent,
                                           name=>$scriptname,
                                           username=>$user);

    # then, verify that sieve script exists on both
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);

    # then, run replication,
    $self->run_replication(user=>$user);
    $self->check_replication($user);

    # then, verify that sieve script still exists on both master and replica
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
}

sub test_sieve_replication_different_unixhs
    :needs_component_sieve :UnixHierarchySep
{
    my ($self) = @_;

    my $user = 'some.body';
    my $script1name = 'test1';
    my $script1content = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    my $script2name = 'test2';
    my $script2content = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "more testing";
}
EOF
    $self->{instance}->create_user($user);

    # first, verify that neither script exists on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $script1name, 0);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $script1name, 0);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script2name, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install different sieve script on master and replica
    $self->{instance}->install_sieve_script($script1content,
                                            name=>$script1name,
                                            username=>$user);
    $self->{replica}->install_sieve_script($script2content,
                                           name=>$script2name,
                                           username=>$user);

    # then, verify that each sieve script exists on one only
    $self->assert_sieve_exists($self->{instance}, $user, $script1name, 0);
    $self->assert_sieve_active($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name, 0);

    $self->assert_sieve_exists($self->{replica}, $user, $script2name, 0);
    $self->assert_sieve_active($self->{replica}, $user, $script2name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script1name, 0);

    # then, run replication,
    # the one that exists on master only will be replicated
    # the one that exists on replica only will be deleted
    $self->run_replication(user=>$user);
    $self->check_replication($user);

    # then, verify that scripts are in expected state
    $self->assert_sieve_exists($self->{instance}, $user, $script1name, 1);
    $self->assert_sieve_active($self->{instance}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{instance}, $user, $script2name, 1);

    $self->assert_sieve_exists($self->{replica}, $user, $script1name, 1);
    $self->assert_sieve_active($self->{replica}, $user, $script1name);
    $self->assert_sieve_not_exists($self->{replica}, $user, $script2name, 1);
}

sub test_sieve_replication_stale_unixhs
    :needs_component_sieve :UnixHierarchySep
{
    my ($self) = @_;

    my $user = 'some.body';
    my $scriptname = 'test1';
    my $scriptoldcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF

    my $scriptnewcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "more testing";
}
EOF
    $self->{instance}->create_user($user);

    # first, verify that script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install "old" script on replica...
    $self->{replica}->install_sieve_script($scriptoldcontent,
                                           name=>$scriptname,
                                           username=>$user);

    # ... and "new" script on master, a little later
    sleep 2;
    $self->{instance}->install_sieve_script($scriptnewcontent,
                                            name=>$scriptname,
                                            username=>$user);

    # then, verify that different sieve script content exists at each end
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);
    $self->assert_sieve_matches($self->{instance}, $user, $scriptname,
                                $scriptnewcontent);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
    $self->assert_sieve_matches($self->{replica}, $user, $scriptname,
                                $scriptoldcontent);

    # then, run replication,
    # the one that exists on replica is different to and older than the one
    # on master, so it will be replaced with the one from master
    $self->run_replication(user=>$user);
    $self->check_replication($user);

    # then, verify that scripts are in expected state
    $self->assert_sieve_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{instance}, $user, $scriptname);
    $self->assert_sieve_matches($self->{instance}, $user, $scriptname,
                                $scriptnewcontent);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);
    $self->assert_sieve_matches($self->{replica}, $user, $scriptname,
                                $scriptnewcontent);
}

sub test_sieve_replication_delete_unactivate_unixhs
    :needs_component_sieve :UnixHierarchySep
{
    my ($self) = @_;

    my $user = 'some.body';
    my $scriptname = 'test1';
    my $scriptcontent = <<'EOF';
require ["reject","fileinto"];
if address :is :all "From" "autoreject@example.org"
{
        reject "testing";
}
EOF
    $self->{instance}->create_user($user);

    # first, verify that sieve script does not exist on master or replica
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{replica}, $user);

    # then, install sieve script on replica only
    $self->{replica}->install_sieve_script($scriptcontent,
                                           name=>$scriptname,
                                           username=>$user);

    # then, verify that sieve script exists on replica only
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 0);
    $self->assert_sieve_noactive($self->{instance}, $user, $scriptname);

    $self->assert_sieve_exists($self->{replica}, $user, $scriptname, 0);
    $self->assert_sieve_active($self->{replica}, $user, $scriptname);

    # then, run replication,
    $self->run_replication(user=>$user);
    $self->check_replication($user);

    # then, verify that sieve script no longer exists on either
    $self->assert_sieve_not_exists($self->{instance}, $user, $scriptname, 1);
    $self->assert_sieve_noactive($self->{instance}, $user, $scriptname);

    $self->assert_sieve_not_exists($self->{replica}, $user, $scriptname, 1);
    $self->assert_sieve_noactive($self->{replica}, $user, $scriptname);
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

# this test is too tricky to get working on uuid mailboxes
sub test_replication_mailbox_too_old
    :max_version_3_4
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $exit_code;

    my $master_instance = $self->{instance};
    my $replica_instance = $self->{replica};

    # logs will all be in the master instance, because that's where
    # sync_client runs from.
    my $log_base = "$master_instance->{basedir}/$self->{_name}";

    # add a version9 mailbox to the replica only, and try to replicate.
    # replication will fail, because the initial GET USER will barf
    # upon encountering the old mailbox.
    $replica_instance->install_old_mailbox($user, 9);
    my $log_firstreject = "$log_base-firstreject.stderr";
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
        redirects => { stderr => $log_firstreject },
    );
    $self->assert_equals(1, $exit_code);
    $self->assert(qr/USER received NO response: IMAP_MAILBOX_NOTSUPPORTED/,
                  slurp_file($log_firstreject));

    # add the version9 mailbox to the master, and try to replicate.
    # mailbox will be found and rejected locally, and replication will
    # fail.
    $master_instance->install_old_mailbox($user, 9);
    my $log_localreject = "$log_base-localreject.stderr";
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
        redirects => { stderr => $log_localreject },
    );
    $self->assert_equals(1, $exit_code);
    $self->assert(qr/Operation is not supported on mailbox/,
                  slurp_file($log_localreject));

    # upgrade the version9 mailbox on the master, and try to replicate.
    # replication will fail, because the initial GET USER will barf
    # upon encountering the old mailbox.
    $master_instance->run_command({ cyrus => 1 }, qw(reconstruct -V max -u), $user);
    my $log_remotereject = "$log_base-remotereject.stderr";
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
        redirects => { stderr => $log_remotereject },
    );
    $self->assert_equals(1, $exit_code);
    $self->assert(qr/USER received NO response: IMAP_MAILBOX_NOTSUPPORTED/,
                  slurp_file($log_remotereject));

    # upgrade the version9 mailbox on the replica, and try to replicate.
    # replication will succeed because both ends are capable of replication.
    $replica_instance->run_command({ cyrus => 1 }, qw(reconstruct -V max -u), $user);
    $exit_code = 0;
    $self->run_replication(
        user => $user,
        handlers => {
            exited_abnormally => sub { (undef, $exit_code) = @_; },
        },
    );
    $self->assert_equals(0, $exit_code);
}

# XXX need a test for version 10 mailbox without guids in it!

# this test is too tricky to get working on uuid mailboxes
sub test_replication_mailbox_new_enough
    :max_version_3_4
{
    my ($self) = @_;

    my $user = 'cassandane';
    my $exit_code = 0;

    # successfully replicate a mailbox new enough to contain guids
    my $mailbox10 = $self->{instance}->install_old_mailbox($user, 10);
    $self->run_replication(mailbox => $mailbox10);

    # successfully replicate a mailbox new enough to contain guids
    my $mailbox12 = $self->{instance}->install_old_mailbox($user, 12);
    $self->run_replication(mailbox => $mailbox12);
}

#* create mailbox on master with no messages
#* sync_client to get it copied to replica
#* create a message in the mailbox on replica (imaptalk on replica_store)
#* delete the message from the replica (with expunge_mode default or expunge_mode immediate... try both)
#* run sync_client on the master again and make sure it successfully syncs up

sub test_replication_repair_zero_msgs
{
    my ($self) = @_;

    my $mastertalk = $self->{master_store}->get_client();
    my $replicatalk = $self->{replica_store}->get_client();

    # raise the modseq on the master end
    $mastertalk->setmetadata("INBOX", "/shared/comment", "foo");
    $mastertalk->setmetadata("INBOX", "/shared/comment", "");
    $mastertalk->setmetadata("INBOX", "/shared/comment", "foo");
    $mastertalk->setmetadata("INBOX", "/shared/comment", "");

    my $msg = $self->make_message("to be deleted", store => $self->{replica_store});

    $replicatalk->store($msg->{attrs}->{uid}, '+flags', '(\\deleted)');
    $replicatalk->expunge();

    $self->run_replication(user => 'cassandane');
}

sub test_replication_with_modified_seen_flag
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    $master_store->set_fetch_attributes(qw(uid flags));

    my $replica_store = $self->{replica_store};
    $replica_store->set_fetch_attributes(qw(uid flags));


    xlog $self, "generating messages A & B";
    my %exp;
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(id => 1, uid => 1, flags => []);
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{B}->set_attributes(id => 2, uid => 2, flags => []);

    xlog $self, "Before replication: Ensure that master has two messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "Before replication: Ensure that replica has no messages";
    $self->check_messages({}, store => $replica_store);

    xlog $self, "Run Replication!";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication: Ensure that master has two messages";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "After replication: Ensure replica now has two messages";
    $self->check_messages(\%exp, store => $replica_store);

    xlog $self, "Set \\Seen on Message B";
    my $mtalk = $master_store->get_client();
    $master_store->_select();
    $mtalk->store('2', '+flags', '(\\Seen)');
    $exp{B}->set_attributes(flags => ['\\Seen']);
    $mtalk->unselect();
    xlog $self, "Before replication: Ensure that master has two messages and flags are set";
    $self->check_messages(\%exp, store => $master_store);

    xlog $self, "Before replication: Ensure that replica does not have the \\Seen flag set on Message B";
    my $rtalk = $replica_store->get_client();
    $replica_store->_select();
    my $res = $rtalk->fetch("2", "(flags)");
    my $flags = $res->{2}->{flags};
    $self->assert(not grep { $_ eq "\\Seen"} @$flags);

    xlog $self, "Run Replication!";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication: Ensure that replica does have the \\Seen flag set on Message B";
    $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $res = $rtalk->fetch("2", "(flags)");
    $flags = $res->{2}->{flags};
    $self->assert(grep { $_ eq "\\Seen"} @$flags);

    xlog $self, "Clear \\Seen flag on Message B on master.";
    $mtalk = $master_store->get_client();
    $master_store->_select();
    $mtalk->store('2', '-flags', '(\\Seen)');

    xlog $self, "Run Replication!";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication: Check both master and replica has no \\Seen flag on Message C";
    $mtalk = $master_store->get_client();
    $master_store->_select();
    $res = $mtalk->fetch("2", "(flags)");
    $flags = $res->{2}->{flags};
    $self->assert(not grep { $_ eq "\\Seen"} @$flags);

    $rtalk = $replica_store->get_client();
    $replica_store->_select();
    $res = $rtalk->fetch("3", "(flags)");
    $flags = $res->{3}->{flags};
    $self->assert(not grep { $_ eq "\\Seen"} @$flags);
}

sub assert_user_sub_exists
{
    my ($self, $instance, $user) = @_;

    my $subs = $instance->get_conf_user_file($user, 'sub');

    xlog $self, "Looking for subscriptions file $subs";

    $self->assert(( -f $subs ));
}

sub assert_user_sub_not_exists
{
    my ($self, $instance, $user) = @_;

    my $subs = $instance->get_conf_user_file($user, 'sub');

    xlog $self, "Looking for subscriptions file $subs";

    $self->assert(( ! -f $subs ));
}

sub test_subscriptions
{
    my ($self) = @_;

    my $user = 'brandnew';
    $self->{instance}->create_user($user);

    # verify that subs file does not exist on master
    # verify that subs file does not exist on replica
    $self->assert_user_sub_not_exists($self->{instance}, $user);
    $self->assert_user_sub_not_exists($self->{replica}, $user);

    # set up and verify some subscriptions on master
    my $mastersvc = $self->{instance}->get_service('imap');
    my $masterstore = $mastersvc->create_store(username => $user);
    my $mastertalk = $masterstore->get_client();

    $mastertalk->create("INBOX.Test") || die;
    $mastertalk->create("INBOX.Test.Sub") || die;
    $mastertalk->create("INBOX.Test Foo") || die;
    $mastertalk->create("INBOX.Test Bar") || die;
    $mastertalk->subscribe("INBOX") || die;
    $mastertalk->subscribe("INBOX.Test") || die;
    $mastertalk->subscribe("INBOX.Test.Sub") || die;
    $mastertalk->subscribe("INBOX.Test Foo") || die;
    $mastertalk->delete("INBOX.Test.Sub") || die;

    my $subdata = $mastertalk->lsub("", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.Test'
          ],
          [
            [],
            '.',
            'INBOX.Test Foo'
          ],
    ]);

    # drop the conf dir lock, so the subs get written out
    $mastertalk->logout();

    # verify that subs file exists on master
    # verify that subs file does not exist on replica
    $self->assert_user_sub_exists($self->{instance}, $user);
    $self->assert_user_sub_not_exists($self->{replica}, $user);

    # run replication
    $self->run_replication(user => $user);
    $self->check_replication($user);

    # verify that subs file exists on master
    # verify that subs file exists on replica
    $self->assert_user_sub_exists($self->{instance}, $user);
    $self->assert_user_sub_exists($self->{replica}, $user);

    # verify replica store can see subs
    my $replicasvc = $self->{replica}->get_service('imap');
    my $replicastore = $replicasvc->create_store(username => $user);
    my $replicatalk = $replicastore->get_client();

    $subdata = $replicatalk->lsub("", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.Test'
          ],
          [
            [],
            '.',
            'INBOX.Test Foo'
          ],
    ]);
}

sub test_subscriptions_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $user = 'brand.new';
    $self->{instance}->create_user($user);

    # verify that subs file does not exist on master
    # verify that subs file does not exist on replica
    $self->assert_user_sub_not_exists($self->{instance}, $user);
    $self->assert_user_sub_not_exists($self->{replica}, $user);

    # set up and verify some subscriptions on master
    my $mastersvc = $self->{instance}->get_service('imap');
    my $masterstore = $mastersvc->create_store(username => $user);
    my $mastertalk = $masterstore->get_client();

    $mastertalk->create("INBOX/Test") || die;
    $mastertalk->create("INBOX/Test/Sub") || die;
    $mastertalk->create("INBOX/Test Foo") || die;
    $mastertalk->create("INBOX/Test Bar") || die;
    $mastertalk->subscribe("INBOX") || die;
    $mastertalk->subscribe("INBOX/Test") || die;
    $mastertalk->subscribe("INBOX/Test/Sub") || die;
    $mastertalk->subscribe("INBOX/Test Foo") || die;
    $mastertalk->delete("INBOX/Test/Sub") || die;

    my $subdata = $mastertalk->lsub("", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '/',
            'INBOX'
          ],
          [
            [
              '\\HasChildren'
            ],
            '/',
            'INBOX/Test'
          ],
          [
            [],
            '/',
            'INBOX/Test Foo'
          ],
    ]);

    # drop the conf dir lock, so the subs get written out
    $mastertalk->logout();

    # verify that subs file exists on master
    # verify that subs file does not exist on replica
    $self->assert_user_sub_exists($self->{instance}, $user);
    $self->assert_user_sub_not_exists($self->{replica}, $user);

    # run replication
    $self->run_replication(user => $user);
    $self->check_replication($user);

    # verify that subs file exists on master
    # verify that subs file exists on replica
    $self->assert_user_sub_exists($self->{instance}, $user);
    $self->assert_user_sub_exists($self->{replica}, $user);

    # verify replica store can see subs
    my $replicasvc = $self->{replica}->get_service('imap');
    my $replicastore = $replicasvc->create_store(username => $user);
    my $replicatalk = $replicastore->get_client();

    $subdata = $replicatalk->lsub("", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '/',
            'INBOX'
          ],
          [
            [
              '\\HasChildren'
            ],
            '/',
            'INBOX/Test'
          ],
          [
            [],
            '/',
            'INBOX/Test Foo'
          ],
    ]);
}

# this is testing a bug where DELETED namespace lookup in mboxlist_mboxtree
# wasn't correctly looking only for children of that name, so it would try
# to delete the wrong user's mailbox.
sub test_userprefix
    :DelayedDelete
{
    my ($self) = @_;
    $self->{instance}->create_user("ua");
    $self->{instance}->create_user("uab");

    my $mastersvc = $self->{instance}->get_service('imap');
    my $astore = $mastersvc->create_store(username => "ua");
    my $atalk = $astore->get_client();
    my $bstore = $mastersvc->create_store(username => "uab");
    my $btalk = $bstore->get_client();

    xlog "Creating some users with some deleted mailboxes";
    $atalk->create("INBOX.hi");
    $atalk->create("INBOX.no");
    $atalk->delete("INBOX.hi");

    $btalk->create("INBOX.boo");
    $btalk->create("INBOX.noo");
    $btalk->delete("INBOX.boo");

    $self->run_replication(user => "ua");
    $self->run_replication(user => "uab");

    my $masterstore = $mastersvc->create_store(username => 'admin');
    my $admintalk = $masterstore->get_client();

    xlog "Deleting the user with the prefix name";
    $admintalk->delete("user.ua");
    $self->run_replication(user => "ua");
    $self->run_replication(user => "uab");
    # This would fail at the end with syslog IOERRORs before the bugfix:
    # >1580698085>S1 SYNCAPPLY UNUSER ua
    # <1580698085<* BYE Fatal error: Internal error: assertion failed: imap/mboxlist.c: 868: user_isnamespacelocked(userid)
    # 0248020101/sync_client[20041]: IOERROR: UNUSER received * response: 
    # Error from sync_do_user(ua): bailing out!
}

# this is testing a bug where DELETED namespace lookup in mboxlist_mboxtree
# wasn't correctly looking only for children of that name, so it would try
# to delete the wrong user's mailbox.
sub test_reset_on_master
    :DelayedDelete :min_version_3_3
{
    my ($self) = @_;
    $self->{instance}->create_user("user2");

    my $mastersvc = $self->{instance}->get_service('imap');
    my $astore = $mastersvc->create_store(username => "user2");
    my $atalk = $astore->get_client();

    xlog "Creating some users with some deleted mailboxes";
    $atalk->create("INBOX.hi");
    $atalk->create("INBOX.no");
    $atalk->delete("INBOX.hi");

    $self->run_replication(user => "user2");

    # reset user2
    $self->{instance}->run_command({cyrus => 1}, 'sync_reset', '-f', "user2");

    my $file = $self->{instance}->{basedir} . "/sync.log";
    open(FH, ">", $file);
    print FH "UNMAILBOX user.user2.hi\n";
    print FH "MAILBOX user.user2.hi\n";
    print FH "UNMAILBOX user.user2.no\n";
    print FH "MAILBOX user.user2.no\n";
    print FH "MAILBOX user.cassandane\n";
    close(FH);

    $self->{instance}->getsyslog();
    $self->{replica}->getsyslog();
    xlog $self, "Run replication from a file with just the mailbox name in it";
    $self->run_replication(inputfile => $file, rolling => 1);

    # XXX is this test useless if we can't check syslog?
    if ($self->{instance}->{have_syslog_replacement}) {
        my @mastersyslog = $self->{instance}->getsyslog();

        my $pattern = qr{
            \bSYNCNOTICE:\sattempt\sto\sUNMAILBOX\swithout\sa\stombstone
            (?: \suser\.user2\.no\b
              | :\smailbox=<user\.user2\.no>
            )
        }x;

        $self->assert_matches($pattern, "@mastersyslog");
    }
}

# this is testing a bug where sync_client would abort on zero-length file
sub test_sync_empty_file
    :DelayedDelete :min_version_3_3
{
    my ($self) = @_;

    $self->run_replication();

    my $file = $self->{instance}->{basedir} . "/sync.log";
    open(FH, ">", $file);
    close(FH);

    xlog $self, "Run replication from an empty file";
    $self->run_replication(inputfile => $file, rolling => 1);
}

sub test_sync_log_mailbox_with_spaces
    :DelayedDelete :NoStartInstances
{
    my ($self) = @_;

    my $channel = 'eggplant'; # look it's gotta be called something

    # make sure we get a sync log file in a predictable location
    $self->{instance}->{config}->set('sync_log' => 'yes');
    $self->{instance}->{config}->set('sync_log_channels' => $channel);
    $self->_start_instances();

    # make some folders with and without spaces
    my $master_store = $self->{master_store};
    my $mastertalk = $master_store->get_client();

    $mastertalk->create("INBOX.2nd level with spaces");
    $self->assert_str_equals('ok',
                             $mastertalk->get_last_completion_response());

    $mastertalk->create("INBOX.foo");
    $self->assert_str_equals('ok',
                             $mastertalk->get_last_completion_response());

    $mastertalk->create("INBOX.foo.3rd level with spaces");
    $self->assert_str_equals('ok',
                             $mastertalk->get_last_completion_response());

    # make sure the contents of the sync log file are correctly quoted
    my $sync_log_fname = $self->{instance}->get_basedir()
                       . "/conf/sync/$channel/log";

    open my $fh, '<', $sync_log_fname or die "open $sync_log_fname: $!";
    while (<$fh>) {
		# We can take some shortcuts here because we're only testing
	    # for correct quoting of mailbox names with/without SPACES,
        # and not other non-atom characters.
        # We're also only acting on mailboxes, so we don't need this
        # parser to consider any other log entries.
        # An exhaustive test would be more complicated!
        chomp;

        if (m/^MAILBOX "(.*)"$/) {
            # Argument is quoted!
            # We expect that we only added quotes where the single
            # mboxname contained spaces, so assert that it contains
            # spaces
            $self->assert_matches(qr/\s/, $1);
        }
        elsif (m/^MAILBOX ([^"].*[^"])$/) {
            # Argument is not quoted!
            # We expect that if there were spaces, it would have been
            # quoted, so assert that there are no spaces.
            $self->assert_does_not_match(qr/\s/, $1);
        }
        else {
            # something weird here! always assert
            $self->assert(undef, "found unrecognised line in sync_log: $_");
        }
    }
    close $fh;

    # no need to even replicate anything; everything we cared about was
    # in the sync log :)
}

sub test_intermediate_rename
    :AllowMoves :Replication :SyncLog :DelayedDelete :min_version_3_3
{
    my ($self) = @_;

    my $mtalk = $self->{master_store}->get_client();

    $mtalk->create('INBOX.a.b');

    # replicate and check initial state
    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    # reconnect
    $mtalk = $self->{master_store}->get_client();

    $mtalk->create('INBOX.a');
    $mtalk->rename('INBOX.a', 'INBOX.new');

    #$self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->run_replication();

    $self->check_replication('cassandane');
}

sub test_intermediate_upgrade
    :AllowMoves :Replication :SyncLog :DelayedDelete :min_version_3_3
{
    my ($self) = @_;

    my $mtalk = $self->{master_store}->get_client();

    $mtalk->create('INBOX.a.b');

    # replicate and check initial state
    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    # reconnect
    $mtalk = $self->{master_store}->get_client();

    $mtalk->create('INBOX.a');

    $self->run_replication(rolling => 1, inputfile => $synclogfname) if -f $synclogfname;

    $self->check_replication('cassandane');
}

sub test_clean_remote_shutdown_while_rolling
    :CSyncReplication :SyncLog :min_version_3_5
{
    my ($self) = @_;

    my $mtalk = $self->{master_store}->get_client();

    $mtalk->create('INBOX.a.b');

    # get a rolling sync_client started
    # XXX can't just run_replication bc it expects sync_client to finish
    my @cmd = qw( sync_client -v -v -o -R );
    my $sync_client_pid = $self->{instance}->run_command(
        {
            cyrus => 1,
            background => 1,
            handlers => {
                exited_abnormally => sub {
                    my ($child, $code) = @_;
                    xlog "child process $child->{binary}\[$child->{pid}\]"
                        . " exited with code $code";
                    return $code;
                },
            },
        },
        @cmd);

    # make sure sync_client has time to connect in the first place
    sleep 3;

    # stop the replica
    $self->{replica}->stop();

    # make more changes on master
    $mtalk = $self->{master_store}->get_client();
    $mtalk->create('INBOX.a.b.c');

    # give sync_client another moment to wake up and see the new log entry
    sleep 3;

    # by now it should have noticed the disconnected replica, and either
    # shut itself down cleanly, or IOERRORed

    # it should have exited already, but signal it if it hasn't, and
    # do the cleanup
    my $ec = $self->{instance}->stop_command($sync_client_pid);

    # if it exited itself, this will be zero.  if it hung around until
    # signalled, 75.
    $self->assert_equals(0, $ec);

    # should not be errors in syslog!
}

sub test_rolling_retry_wait_limit
    :CSyncReplication :NoStartInstances :min_version_3_5
{
    my ($self) = @_;
    my $maxwait = 20;

    $self->{instance}->{config}->set(
        'sync_log' => 1,
        'sync_reconnect_maxwait' => "${maxwait}s",
    );
    $self->_start_instances();

    # stop the replica
    $self->{replica}->stop();

    # get a rolling sync_client started, which won't be able to connect
    # XXX can't just run_replication bc it expects sync_client to finish
    my $errfile = "$self->{instance}->{basedir}/stderr.out";
    my @cmd = qw( sync_client -v -v -o -R );
    my $sync_client_pid = $self->{instance}->run_command(
        {
            cyrus => 1,
            background => 1,
            handlers => {
                exited_abnormally => sub {
                    my ($child, $code) = @_;
                    xlog "child process $child->{binary}\[$child->{pid}\]"
                        . " exited with code $code";
                    return $code;
                },
            },
            redirects => { stderr => $errfile },
        },
        @cmd);

    # wait around for a while to give sync_client time to go through its
    # reconnect loop a few times.  first will be 15, then 20, then 20,
    # then 20 (but we'll kill it 5s in)
    sleep 60;

    # grant mercy
    my $ec = $self->{instance}->stop_command($sync_client_pid);

    # if it exited itself, this will be zero.  if it hung around until
    # signalled, 75.
    $self->assert_equals(75, $ec);

    # check stderr for "retrying in ... seconds" lines, making sure none
    # exceed our limit
    my $output = slurp_file($errfile);
    my @waits = $output =~ m/retrying in (\d+) seconds/g;
    $self->assert_num_lte($maxwait, $_) for @waits;
    $self->assert_deep_equals([ 15, 20, 20, 20 ], \@waits);
}

#
# Test empty mailbox gets overwritten
#
sub test_splitbrain_different_uniqueid_unused
    :min_version_3_5
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $mtalk = $master_store->get_client();
    my $rtalk = $replica_store->get_client();

    $mtalk->create('INBOX.subfolder');
    my $mres = $mtalk->status("INBOX.subfolder", ['mailboxid']);
    my $mid = $mres->{mailboxid}[0];
    $rtalk->create('INBOX.subfolder');
    my $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    my $rid = $rres->{mailboxid}[0];

    $self->assert_not_null($mid);
    $self->assert_not_null($rid);
    $self->assert_str_not_equals($mid, $rid);

    $master_store->set_folder("INBOX.subfolder");

    $self->make_message("Message A", store => $master_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    $rtalk = $replica_store->get_client();
    $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    $rid = $rres->{mailboxid}[0];

    $self->assert_str_equals($mid, $rid);
}

#
# Test non-empty mailbox causes replication to abort
#
sub test_splitbrain_different_uniqueid_nonempty
    :min_version_3_5
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $mtalk = $master_store->get_client();
    my $rtalk = $replica_store->get_client();

    $mtalk->create('INBOX.subfolder');
    my $mres = $mtalk->status("INBOX.subfolder", ['mailboxid']);
    my $mid = $mres->{mailboxid}[0];
    $rtalk->create('INBOX.subfolder');
    my $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    my $rid = $rres->{mailboxid}[0];

    $self->assert_not_null($mid);
    $self->assert_not_null($rid);
    $self->assert_str_not_equals($mid, $rid);

    $master_store->set_folder("INBOX.subfolder");
    $replica_store->set_folder("INBOX.subfolder");

    $self->make_message("Message A", store => $master_store);
    $self->make_message("Message B", store => $replica_store);

    # this will fail
    eval {
        $self->run_replication();
    };

    if ($self->{instance}->{have_syslog_replacement}) {
        # sync_client should have logged the failure
        my @mlines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: user replication failed/, "@mlines");
        $self->assert_matches(qr/MAILBOX received NO response: IMAP_MAILBOX_MOVED/, "@mlines");

        # sync server should have logged the failure
        my @rlines = $self->{replica}->getsyslog();
        $self->assert_matches(qr/SYNCERROR: mailbox uniqueid changed - retry/, "@rlines");
    }

    $rtalk = $replica_store->get_client();
    $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    $rid = $rres->{mailboxid}[0];

    $self->assert_str_not_equals($mid, $rid);
}

#
# Test mailbox that's had email but is now empty again
#
sub test_splitbrain_different_uniqueid_used
    :min_version_3_5
{
    my ($self) = @_;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $mtalk = $master_store->get_client();
    my $rtalk = $replica_store->get_client();

    $mtalk->create('INBOX.subfolder');
    my $mres = $mtalk->status("INBOX.subfolder", ['mailboxid']);
    my $mid = $mres->{mailboxid}[0];
    $rtalk->create('INBOX.subfolder');
    my $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    my $rid = $rres->{mailboxid}[0];

    $self->assert_not_null($mid);
    $self->assert_not_null($rid);
    $self->assert_str_not_equals($mid, $rid);

    $master_store->set_folder("INBOX.subfolder");
    $replica_store->set_folder("INBOX.subfolder");

    $self->make_message("Message A", store => $master_store);
    $self->make_message("Message B", store => $replica_store);

    $rtalk->select('INBOX.subfolder');
    $rtalk->store('1:*', '+flags', '\\Deleted');
    $rtalk->expunge();

    # this will fail
    eval {
        $self->run_replication();
    };

    if ($self->{instance}->{have_syslog_replacement}) {
        # sync_client should have logged the failure
        my @mlines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: user replication failed/, "@mlines");
        $self->assert_matches(qr/MAILBOX received NO response: IMAP_MAILBOX_MOVED/, "@mlines");

        # sync server should have logged the failure
        my @rlines = $self->{replica}->getsyslog();
        $self->assert_matches(qr/SYNCERROR: mailbox uniqueid changed - retry/, "@rlines");
    }

    $rtalk = $replica_store->get_client();
    $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    $rid = $rres->{mailboxid}[0];

    $self->assert_str_not_equals($mid, $rid);

    xlog "Trying again with no-copyback";
    $self->run_replication(nosyncback => 1);
    $self->check_replication('cassandane');

    $rtalk = $replica_store->get_client();
    $rres = $rtalk->status("INBOX.subfolder", ['mailboxid']);
    $rid = $rres->{mailboxid}[0];

    $self->assert_str_equals($mid, $rid);
}

sub test_delete_longname
    :AllowMoves :Replication :SyncLog :DelayedDelete :min_version_3_3
{
    my ($self) = @_;

    my $mtalk = $self->{master_store}->get_client();

    #define MAX_MAILBOX_NAME 490
    my $name = "INBOX.this is a really long name 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1.2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2.3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3.foo";
    my ($success) = $mtalk->create($name);
    die "Failed to create" unless $success;

    # replicate and check initial state
    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    # reconnect
    $mtalk = $self->{master_store}->get_client();

    $mtalk->delete($name);

    $self->run_replication(rolling => 1, inputfile => $synclogfname) if -f $synclogfname;

    $self->check_replication('cassandane');
}

1;
