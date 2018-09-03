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

package Cassandane::Cyrus::Conversations;
use strict;
use warnings;
use DateTime;
use URI::Escape;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::ThreadedGenerator;
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(to_iso8601 from_iso8601
                                  from_rfc822
                                  to_rfc3501 from_rfc3501);

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    $config->set(ctl_conversationsdb_conversations_max_thread => 5);
    return $class->SUPER::new({ config => $config }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my ($maj, $min) = Cassandane::Instance->get_version();

    # basecid was added after 3.0
    if ($maj > 3 or ($maj == 3 and $min > 0)) {
       $self->{store}->set_fetch_attributes('uid', 'cid', 'basecid');
    }
    else {
       $self->{store}->set_fetch_attributes('uid', 'cid');
    }
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

# The resulting CID when a clash happens is supposed to be
# the MAXIMUM of all the CIDs.  Here we use the fact that
# CIDs are expressed in a form where lexical order is the
# same as numeric order.
sub choose_cid
{
    my (@cids) = @_;
    @cids = sort { $b cmp $a } @cids;
    return $cids[0];
}

#
# Test APPEND of messages to IMAP
#
sub test_append
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating message C";
    $exp{C} = $self->make_message("Message C");
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    my $actual = $self->check_messages(\%exp);

    xlog "generating message D";
    $exp{D} = $self->make_message("Message D");
    $exp{D}->set_attributes(uid => 4, cid => $exp{D}->make_cid());
    $self->check_messages(\%exp);
}

#
# Test APPEND of messages to IMAP
#
sub test_append_reply
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating message B";
    $exp{B} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{B}->set_attributes(uid => 2, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);
}

#
# Test APPEND of messages to IMAP
#
sub test_append_reply_200
    :min_version_3_1
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating replies";
    for (1..99) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }
    $exp{"B"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{"B"}->set_attributes(uid => 101, cid => $exp{B}->make_cid(), basecid => $exp{A}->make_cid());
    for (1..99) {
      $exp{"B$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"B$_"}->set_attributes(uid => 101+$_, cid => $exp{B}->make_cid(), basecid => $exp{A}->make_cid());
    }
    $exp{"C"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    $exp{"C"}->set_attributes(uid => 201, cid => $exp{C}->make_cid(), basecid => $exp{A}->make_cid());

    $self->check_messages(\%exp, keyed_on => 'uid');
}

#
# test reconstruct of larger conversation
#
sub test_reconstruct_splitconv
    :min_version_3_1
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating replies";
    for (1..20) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }

    $self->check_messages(\%exp, keyed_on => 'uid');

    # first run WITHOUT splitting
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-R', '-r');

    $self->check_messages(\%exp, keyed_on => 'uid');

    # then run WITH splitting, and see the changed CIDs
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-R', '-r', '-S');

    for (5..9) {
      $exp{"A$_"}->set_attributes(cid => $exp{"A5"}->make_cid(), basecid => $exp{A}->make_cid());
    }
    for (10..14) {
      $exp{"A$_"}->set_attributes(cid => $exp{"A10"}->make_cid(), basecid => $exp{A}->make_cid());
    }
    for (15..19) {
      $exp{"A$_"}->set_attributes(cid => $exp{"A15"}->make_cid(), basecid => $exp{A}->make_cid());
    }
    $exp{"A20"}->set_attributes(cid => $exp{"A20"}->make_cid(), basecid => $exp{A}->make_cid());

    $self->check_messages(\%exp, keyed_on => 'uid');
}

#
# Test APPEND of messages to IMAP
#
sub test_replication_reply_200
    :min_version_3_1
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    $master_store->set_fetch_attributes('uid', 'cid', 'basecid');
    $replica_store->set_fetch_attributes('uid', 'cid', 'basecid');

    $self->assert($master_store->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    xlog "checking message A on master";
    $self->check_messages(\%exp, store => $master_store);
    xlog "running replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    xlog "checking message A on replica";
    $self->check_messages(\%exp, store => $replica_store);

    xlog "generating replies";
    for (1..99) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $master_store);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }
    $exp{"B"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $master_store);
    $exp{"B"}->set_attributes(uid => 101, cid => $exp{B}->make_cid(), basecid => $exp{A}->make_cid());
    for (1..99) {
      $exp{"B$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $master_store);
      $exp{"B$_"}->set_attributes(uid => 101+$_, cid => $exp{B}->make_cid(), basecid => $exp{A}->make_cid());
    }
    $exp{"C"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $master_store);
    $exp{"C"}->set_attributes(uid => 201, cid => $exp{C}->make_cid(), basecid => $exp{A}->make_cid());

    # this shouldn't make any difference, but it doesn when you're not logging annotation
    # usage for split conversations properly, so just leaving it here to break this unrelated-ish test and gain
    # the benefits of check_replication's annotsize check
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', '-u' => 'cassandane');

    $self->check_messages(\%exp, keyed_on => 'uid', store => $master_store);
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, keyed_on => 'uid', store => $replica_store);

    xlog "Creating a message on the replica now to make sure it gets the right CID";
    $exp{"D"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $replica_store);
    $exp{"D"}->set_attributes(uid => 202, cid => $exp{C}->make_cid(), basecid => $exp{A}->make_cid());
    $self->check_messages(\%exp, keyed_on => 'uid', store => $replica_store);
}

#
# Test APPEND of messages to IMAP
#
sub test_replication_reconstruct
    :min_version_3_1
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    $master_store->set_fetch_attributes('uid', 'cid', 'basecid');
    $replica_store->set_fetch_attributes('uid', 'cid', 'basecid');

    $self->assert($master_store->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    xlog "checking message A on master";
    $self->check_messages(\%exp, store => $master_store);
    xlog "running replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    xlog "checking message A on replica";
    $self->check_messages(\%exp, store => $replica_store);

    xlog "generating replies";
    for (1..20) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $master_store);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }

    $self->check_messages(\%exp, keyed_on => 'uid', store => $master_store);
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, keyed_on => 'uid', store => $replica_store);

    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-R', '-r', '-S');

    for (5..9) {
      $exp{"A$_"}->set_attributes(cid => $exp{"A5"}->make_cid(), basecid => $exp{A}->make_cid());
    }
    for (10..14) {
      $exp{"A$_"}->set_attributes(cid => $exp{"A10"}->make_cid(), basecid => $exp{A}->make_cid());
    }
    for (15..19) {
      $exp{"A$_"}->set_attributes(cid => $exp{"A15"}->make_cid(), basecid => $exp{A}->make_cid());
    }
    $exp{"A20"}->set_attributes(cid => $exp{"A20"}->make_cid(), basecid => $exp{A}->make_cid());

    $self->check_messages(\%exp, keyed_on => 'uid', store => $master_store);
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, keyed_on => 'uid', store => $replica_store);

    xlog "Creating a message on the replica now to make sure it gets the right CID";
    $exp{"D"} = $self->make_message("Re: Message A", references => [ $exp{A} ], store => $replica_store);
    $exp{"D"}->set_attributes(uid => 22, cid => $exp{"A20"}->make_cid(), basecid => $exp{A}->make_cid());
    $self->check_messages(\%exp, keyed_on => 'uid', store => $replica_store);
}


#
# Test APPEND of messages to IMAP which results in a CID clash.
#
sub bogus_test_append_clash
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    my $actual = $self->check_messages(\%exp);

    xlog "generating message C";
    my $ElCid = choose_cid($exp{A}->get_attribute('cid'),
                           $exp{B}->get_attribute('cid'));
    $exp{C} = $self->make_message("Message C",
                                  references => [ $exp{A}, $exp{B} ],
                                 );
    $exp{C}->set_attributes(uid => 3, cid => $ElCid);

    # Since IRIS-293, inserting this message will have the side effect
    # of renumbering some of the existing messages.  Predict and test
    # which messages get renumbered.
    my $nextuid = 4;
    foreach my $s (qw(A B))
    {
        if ($actual->{"Message $s"}->make_cid() ne $ElCid)
        {
            $exp{$s}->set_attributes(uid => $nextuid, cid => $ElCid);
            $nextuid++;
        }
    }

    $self->check_messages(\%exp);
}

#
# Test APPEND of messages to IMAP which results in multiple CID clashes.
#
sub bogus_test_double_clash
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $self->check_messages(\%exp);

    xlog "generating message C";
    $exp{C} = $self->make_message("Message C");
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    my $actual = $self->check_messages(\%exp);

    xlog "generating message D";
    my $ElCid = choose_cid($exp{A}->get_attribute('cid'),
                           $exp{B}->get_attribute('cid'),
                           $exp{C}->get_attribute('cid'));
    $exp{D} = $self->make_message("Message D",
                                  references => [ $exp{A}, $exp{B}, $exp{C} ],
                                 );
    $exp{D}->set_attributes(uid => 4, cid => $ElCid);

    # Since IRIS-293, inserting this message will have the side effect
    # of renumbering some of the existing messages.  Predict and test
    # which messages get renumbered.
    my $nextuid = 5;
    foreach my $s (qw(A B C))
    {
        if ($actual->{"Message $s"}->make_cid() ne $ElCid)
        {
            $exp{$s}->set_attributes(uid => $nextuid, cid => $ElCid);
            $nextuid++;
        }
    }

    $self->check_messages(\%exp);
}

#
# Test that a CID clash resolved on the master is replicated
#
sub bogus_test_replication_clash
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    xlog "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    $master_store->set_fetch_attributes('uid', 'cid');
    $replica_store->set_fetch_attributes('uid', 'cid');

    # Double check that we're connected to the servers
    # we wanted to be connected to.
    $self->assert($master_store->{host} eq $replica_store->{host});
    $self->assert($master_store->{port} != $replica_store->{port});

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($master_store->get_client()->capability()->{xconversations});
    $self->assert($replica_store->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);

    xlog "generating message B";
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);

    xlog "generating message C";
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    $self->run_replication();
    $self->check_replication('cassandane');
    my $actual = $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);

    xlog "generating message D";
    my $ElCid = choose_cid($exp{A}->get_attribute('cid'),
                           $exp{B}->get_attribute('cid'),
                           $exp{C}->get_attribute('cid'));
    $exp{D} = $self->make_message("Message D",
                                  store => $master_store,
                                  references => [ $exp{A}, $exp{B}, $exp{C} ],
                                 );
    $exp{D}->set_attributes(uid => 4, cid => $ElCid);

    # Since IRIS-293, inserting this message will have the side effect
    # of renumbering some of the existing messages.  Predict and test
    # which messages get renumbered.
    my $nextuid = 5;
    foreach my $s (qw(A B C))
    {
        if ($actual->{"Message $s"}->make_cid() ne $ElCid)
        {
            $exp{$s}->set_attributes(uid => $nextuid, cid => $ElCid);
            $nextuid++;
        }
    }

    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);
}

sub test_xconvfetch
    :min_version_3_0
{
    my ($self) = @_;
    my $store = $self->{store};

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($store->get_client()->capability()->{xconversations});

    xlog "generating messages";
    my $generator = Cassandane::ThreadedGenerator->new();
    $store->write_begin();
    while (my $msg = $generator->generate())
    {
        $store->write_message($msg);
    }
    $store->write_end();

    xlog "reading the whole folder again to discover CIDs etc";
    my %cids;
    my %uids;
    $store->read_begin();
    while (my $msg = $store->read_message())
    {
        my $uid = $msg->get_attribute('uid');
        my $cid = $msg->get_attribute('cid');
        my $threadid = $msg->get_header('X-Cassandane-Thread');
        if (defined $cids{$cid})
        {
            $self->assert_num_equals($threadid, $cids{$cid});
        }
        else
        {
            $cids{$cid} = $threadid;
            xlog "Found CID $cid";
        }
        $self->assert_null($uids{$uid});
        $uids{$uid} = 1;
    }
    $store->read_end();

    xlog "Using XCONVFETCH on each conversation";
    foreach my $cid (keys %cids)
    {
        xlog "XCONVFETCHing CID $cid";

        my $result = $store->xconvfetch_begin($cid);
        $self->assert_not_null($result->{xconvmeta});
        $self->assert_num_equals(1, scalar keys %{$result->{xconvmeta}});
        $self->assert_not_null($result->{xconvmeta}->{$cid});
        $self->assert_not_null($result->{xconvmeta}->{$cid}->{modseq});
        while (my $msg = $store->xconvfetch_message())
        {
            my $muid = $msg->get_attribute('uid');
            my $mcid = $msg->get_attribute('cid');
            my $threadid = $msg->get_header('X-Cassandane-Thread');
            $self->assert_str_equals($cid, $mcid);
            $self->assert_num_equals($cids{$cid}, $threadid);
            $self->assert_num_equals(1, $uids{$muid});
            $uids{$muid} |= 2;
        }
        $store->xconvfetch_end();
    }

    xlog "checking that all the UIDs in the folder were XCONVFETCHed";
    foreach my $uid (keys %uids)
    {
        $self->assert_num_equals(3, $uids{$uid});
    }
}

#
# Test APPEND of a new composed draft message to the Drafts folder by
# the Fastmail webui, which sets the X-ME-Message-ID header to thread
# conversations but not any of Message-ID, References, or In-Reply-To.
#
sub bogus_test_fm_webui_draft
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog "generating message A";
    $exp{A} = $self->{gen}->generate(subject => 'Draft message A');
    $exp{A}->remove_headers('Message-ID');
#     $exp{A}->add_header('X-ME-Message-ID', '<fake.header@i.am.a.draft>');
    $exp{A}->add_header('X-ME-Message-ID', '<fake1700@fastmail.fm>');
    $exp{A}->set_attribute(cid => $exp{A}->make_cid());

    $self->{store}->write_begin();
    $self->{store}->write_message($exp{A});
    $self->{store}->write_end();
    $self->check_messages(\%exp);

    xlog "generating message B";
    $exp{B} = $exp{A}->clone();
    $exp{B}->set_headers('Subject', 'Draft message B');
    $exp{B}->set_body("Completely different text here\r\n");

    $self->{store}->write_begin();
    $self->{store}->write_message($exp{B});
    $self->{store}->write_end();
    $self->check_messages(\%exp);
}

#
# Test a COPY between folders owned by different users
#
sub bogus_test_cross_user_copy
    :min_version_3_0
{
    my ($self) = @_;
    my $bobuser = "bob";
    my $bobfolder = "user.$bobuser";

    xlog "Testing COPY between folders owned by different users [IRIS-893]";

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    my $srv = $self->{instance}->get_service('imap');

    $self->{instance}->create_user($bobuser);

    my $adminstore = $srv->create_store(username => 'admin');
    my $adminclient = $adminstore->get_client();
    $adminclient->setacl('user.cassandane', $bobuser => 'lrswipkxtecda')
        or die "Cannot setacl on user.cassandane: $@";

    xlog "generating two messages";
    my %exp;
    $exp{A} = $self->{gen}->generate(subject => 'Message A');
    my $cid = $exp{A}->make_cid();
    $exp{A}->set_attribute(cid => $cid);
    $exp{B} = $self->{gen}->generate(subject => 'Message B',
                                     references => [ $exp{A} ]);
    $exp{B}->set_attribute(cid => $cid);

    xlog "Writing messaged to user.cassandane";
    $self->{store}->write_begin();
    $self->{store}->write_message($exp{A});
    $self->{store}->write_message($exp{B});
    $self->{store}->write_end();
    xlog "Check that the messages made it";
    $self->check_messages(\%exp);

    my $bobstore = $srv->create_store(username => $bobuser);
    $bobstore->set_fetch_attributes('uid', 'cid');
    my $bobclient = $bobstore->get_client();
    $bobstore->set_folder('user.cassandane');
    $bobstore->_select();
    $bobclient->copy(2, $bobfolder)
        or die "Cannot COPY message to $bobfolder";

    xlog "Check that the message made it to $bobfolder";
    my %bobexp;
    $bobexp{B} = $exp{B}->clone();
    $bobexp{B}->set_attributes(uid => 1, cid => $exp{B}->make_cid());
    $bobstore->set_folder($bobfolder);
    $self->check_messages(\%bobexp, store => $bobstore);
}

1;
