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

use lib '../perl/imap';
use Cyrus::IndexFile;

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();

    my $buildinfo = Cassandane::BuildInfo->new();

    # if we're gonna try and run jmap tests, set up config for it
    if ($buildinfo->get('component', 'jmap')) {
        $config->set(caldav_realm => 'Cassandane',
                     conversations => 'yes',
                     conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                     jmapsubmission_deleteonsend => 'no',
                     ctl_conversationsdb_conversations_max_thread => 5,
                     httpmodules => 'carddav caldav jmap',
                     httpallowcompress => 'no');

        return $class->SUPER::new({
            config => $config,
            jmap => 1,
            adminstore => 1,
            services => [ 'imap', 'http' ]
        }, @args);
    }
    else {
        $config->set(conversations => 'yes',
                     conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                     ctl_conversationsdb_conversations_max_thread => 5);

        return $class->SUPER::new({ config => $config }, @args);
    }
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message C";
    $exp{C} = $self->make_message("Message C");
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    my $actual = $self->check_messages(\%exp);

    xlog $self, "generating message D";
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating replies";
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
# Test MOVE of messages after conversation split
#
sub test_move_200
    :min_version_3_1
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating replies";
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

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.foo");
    $talk->select("INBOX");
    # NOTE: 110 here becomes 109 after '9' is already moved
    $talk->fetch('9,110', '(emailid threadid)');
    $talk->move('9', "INBOX.foo");
    $talk->move('109', "INBOX.foo");
    $talk->select("INBOX.foo");
    my $res = $talk->fetch('1:2', '(emailid threadid)');
    my $emailid1 = $res->{1}{emailid}[0];
    my $threadid1 = $res->{1}{threadid}[0];
    my $emailid2 = $res->{2}{emailid}[0];
    my $threadid2 = $res->{2}{threadid}[0];
    $self->assert_str_equals($threadid1, 'T' . $exp{A}->make_cid());
    $self->assert_str_equals($threadid2, 'T' . $exp{B}->make_cid());

    # XXX probably should split the jmap stuff below into a separate
    # XXX test, so we can just mark it :needs_component_jmap instead
    # XXX of hacking it up like this... :)
    my $buildinfo = Cassandane::BuildInfo->new();
    if (not $buildinfo->get('component', 'jmap')) {
        return;
    }

    my $jmap = $self->{jmap};
    xlog $self, "create bar mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "bar",
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $bar = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
            ['Email/set', { update => {
                 $emailid1 => { mailboxIds => { $bar => $JSON::true } },
                 $emailid2 => { mailboxIds => { $bar => $JSON::true } },
             }}, "R1"]
    ]);

    $self->assert_str_equals('Email/set', $res->[0][0]);
    $self->assert(exists $res->[0][1]{updated}{$emailid1});
    $self->assert(exists $res->[0][1]{updated}{$emailid2});
    $self->assert_str_equals('R1', $res->[0][2]);

    $res = $jmap->CallMethods([
            ['Email/get', { ids => [$emailid1,$emailid2], properties => ['threadId']
             }, "R1"]
    ]);

    $self->assert_str_equals('Email/get', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    my %map = map { $_->{id} => $_->{threadId} } @{$res->[0][1]{list}};
    $self->assert_str_equals($map{$emailid1}, $threadid1);
    $self->assert_str_equals($map{$emailid2}, $threadid2);
}

#
# Test normalisation of Subjects containing nonascii whitespace
#
# At present, non-breaking space is the only nonascii whitespace
# our normalisation supports
#
# The normalisation function is properly tested in the cunit tests,
# but we need a test out here too to verify that it works when
# decoded from the real world!
#
sub test_normalise_nonascii_whitespace
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog $self, "generating message A";
    # we saw in the wild a message with an encoded nbsp in the subject...
    $exp{A} = $self->make_message("=?UTF-8?Q?hello=C2=A0there?=");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    # ... but the reply had replaced this with a normal space
    $exp{B} = $self->make_message("Re: hello there", references => [ $exp{A} ]);
    $exp{B}->set_attributes(uid => 2, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating replies";
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
sub _munge_annot_crc
{
    my ($instance, $file, $value) = @_;

    # this needs a bit of magic to know where to write... so
    # we do some hard-coded cyrus.index handling
    my $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    my $index = Cyrus::IndexFile->new($fh);

    my $header = $index->header();
    $header->{SyncCRCsAnnot} = $value;
    $index->rewrite_header($header);

    $fh->close();
}
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    xlog $self, "checking message A on master";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "running replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    xlog $self, "checking message A on replica";
    $self->check_messages(\%exp, store => $replica_store);

    xlog $self, "generating replies";
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

    # corrupt the sync_annot_crc at both ends and check that we can fix it without syncback
    xlog $self, "Damaging annotations CRCs";
    my $mpath = $self->{instance}->folder_to_directory('user.cassandane');
    my $rpath = $self->{replica}->folder_to_directory('user.cassandane');
    _munge_annot_crc($self->{instance}, "$mpath/cyrus.index", 1);
    _munge_annot_crc($self->{replica}, "$rpath/cyrus.index", 2);

    $self->run_replication(nosyncback => 1);
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, keyed_on => 'uid', store => $replica_store);

    xlog $self, "Creating a message on the replica now to make sure it gets the right CID";
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    xlog $self, "checking message A on master";
    $self->check_messages(\%exp, store => $master_store);
    xlog $self, "running replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    xlog $self, "checking message A on replica";
    $self->check_messages(\%exp, store => $replica_store);

    xlog $self, "generating replies";
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

    xlog $self, "Creating a message on the replica now to make sure it gets the right CID";
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    my $actual = $self->check_messages(\%exp);

    xlog $self, "generating message C";
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating message C";
    $exp{C} = $self->make_message("Message C");
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    my $actual = $self->check_messages(\%exp);

    xlog $self, "generating message D";
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

    xlog $self, "need a master and replica pair";
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

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);

    xlog $self, "generating message B";
    $exp{B} = $self->make_message("Message B", store => $master_store);
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $self->run_replication();
    $self->check_replication('cassandane');
    $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);

    xlog $self, "generating message C";
    $exp{C} = $self->make_message("Message C", store => $master_store);
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    $self->run_replication();
    $self->check_replication('cassandane');
    my $actual = $self->check_messages(\%exp, store => $master_store);
    $self->check_messages(\%exp, store => $replica_store);

    xlog $self, "generating message D";
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

    xlog $self, "generating messages";
    my $generator = Cassandane::ThreadedGenerator->new();
    $store->write_begin();
    while (my $msg = $generator->generate())
    {
        $store->write_message($msg);
    }
    $store->write_end();

    xlog $self, "reading the whole folder again to discover CIDs etc";
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
            xlog $self, "Found CID $cid";
        }
        $self->assert_null($uids{$uid});
        $uids{$uid} = 1;
    }
    $store->read_end();

    xlog $self, "Using XCONVFETCH on each conversation";
    foreach my $cid (keys %cids)
    {
        xlog $self, "XCONVFETCHing CID $cid";

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

    xlog $self, "checking that all the UIDs in the folder were XCONVFETCHed";
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

    xlog $self, "generating message A";
    $exp{A} = $self->{gen}->generate(subject => 'Draft message A');
    $exp{A}->remove_headers('Message-ID');
#     $exp{A}->add_header('X-ME-Message-ID', '<fake.header@i.am.a.draft>');
    $exp{A}->add_header('X-ME-Message-ID', '<fake1700@fastmail.fm>');
    $exp{A}->set_attribute(cid => $exp{A}->make_cid());

    $self->{store}->write_begin();
    $self->{store}->write_message($exp{A});
    $self->{store}->write_end();
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
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

    xlog $self, "Testing COPY between folders owned by different users [IRIS-893]";

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    my $srv = $self->{instance}->get_service('imap');

    $self->{instance}->create_user($bobuser);

    my $adminstore = $srv->create_store(username => 'admin');
    my $adminclient = $adminstore->get_client();
    $adminclient->setacl('user.cassandane', $bobuser => 'lrswipkxtecda')
        or die "Cannot setacl on user.cassandane: $@";

    xlog $self, "generating two messages";
    my %exp;
    $exp{A} = $self->{gen}->generate(subject => 'Message A');
    my $cid = $exp{A}->make_cid();
    $exp{A}->set_attribute(cid => $cid);
    $exp{B} = $self->{gen}->generate(subject => 'Message B',
                                     references => [ $exp{A} ]);
    $exp{B}->set_attribute(cid => $cid);

    xlog $self, "Writing messaged to user.cassandane";
    $self->{store}->write_begin();
    $self->{store}->write_message($exp{A});
    $self->{store}->write_message($exp{B});
    $self->{store}->write_end();
    xlog $self, "Check that the messages made it";
    $self->check_messages(\%exp);

    my $bobstore = $srv->create_store(username => $bobuser);
    $bobstore->set_fetch_attributes('uid', 'cid');
    my $bobclient = $bobstore->get_client();
    $bobstore->set_folder('user.cassandane');
    $bobstore->_select();
    $bobclient->copy(2, $bobfolder)
        or die "Cannot COPY message to $bobfolder";

    xlog $self, "Check that the message made it to $bobfolder";
    my %bobexp;
    $bobexp{B} = $exp{B}->clone();
    $bobexp{B}->set_attributes(uid => 1, cid => $exp{B}->make_cid());
    $bobstore->set_folder($bobfolder);
    $self->check_messages(\%bobexp, store => $bobstore);
}

#
# Test APPEND of messages to IMAP
#
sub test_replication_trashseen
    :min_version_3_1
{
    my ($self) = @_;
    my %exp;

    # check IMAP server has the XCONVERSATIONS capability
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    $master_store->set_fetch_attributes('uid', 'cid');
    $replica_store->set_fetch_attributes('uid', 'cid');

    my $mtalk = $master_store->get_client();

    $self->assert($mtalk->capability()->{xconversations});

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    xlog $self, "checking message A on master";
    $self->check_messages(\%exp, store => $master_store);

    $mtalk->create("INBOX.Trash");
    $mtalk->select("INBOX");
    $mtalk->store('1', '+flags', '\\Seen');
    $mtalk->move('1', 'INBOX.Trash');
    $mtalk->select('INBOX.Trash');
    $mtalk->store('1', '-flags', '\\Seen');

    xlog $self, "running replication";
    $self->run_replication();
    $self->check_replication('cassandane');
}

#
# Test limits on GUID duplicates
#
sub test_guid_duplicate_same_folder
    :min_version_3_3 :LowEmailLimits
{
    my ($self) = @_;
    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.dest");

    $talk->select("INBOX");
    my $r1 = $talk->copy("1", "INBOX.dest");
    my $r2 = $talk->copy("1", "INBOX.dest");
    my $r3 = $talk->copy("1", "INBOX.dest");
    $self->assert_not_null($r1);
    $self->assert_not_null($r2);
    $self->assert_null($r3);
    $self->assert_matches(qr/Too many identical emails/, $talk->get_last_error());

    if ($self->{instance}->{have_syslog_replacement}) {
        my @lines = $self->{instance}->getsyslog();
        $self->assert(grep { m/IOERROR: conversations GUID limit/ } @lines);
    }

    $talk->select("INBOX.dest");
    my $data = $talk->fetch("1:*", "(emailid threadid uid)");
    $self->assert_not_null($data->{1});
    $self->assert_not_null($data->{2});
    $self->assert_null($data->{3});
}

sub test_guid_duplicate_total_count
    :min_version_3_3 :LowEmailLimits
{
    my ($self) = @_;
    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.M1");
    $talk->create("INBOX.M2");
    $talk->create("INBOX.M3");
    $talk->create("INBOX.M4");
    $talk->create("INBOX.M5");

    $talk->select("INBOX");

    my $r1 = $talk->copy("1", "INBOX.M1");
    my $r2 = $talk->copy("1", "INBOX.M2");
    my $r3 = $talk->copy("1", "INBOX.M3");
    my $r4 = $talk->copy("1", "INBOX.M4");
    my $r5 = $talk->copy("1", "INBOX.M5");

    $self->assert_not_null($r1);
    $self->assert_not_null($r2);
    $self->assert_not_null($r3);
    $self->assert_not_null($r4);
    $self->assert_null($r5);
    $self->assert_matches(qr/Too many identical emails/, $talk->get_last_error());

    if ($self->{instance}->{have_syslog_replacement}) {
        my @lines = $self->{instance}->getsyslog();
        $self->assert(grep { m/IOERROR: conversations GUID limit/ } @lines);
    }
}

#
# Test limits on GUID duplicates
#
sub test_guid_duplicate_expunges
    :min_version_3_3 :LowEmailLimits :DelayedExpunge
{
    my ($self) = @_;
    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    $talk->create("INBOX.dest");

    for (1..9) {
        $talk->select("INBOX");
        my $r = $talk->copy("1", "INBOX.dest");
        $self->assert_not_null($r);
        $talk->select("INBOX.dest");
        $talk->store('1:*', '+flags', '(\\Deleted)');
        $talk->expunge();
    }

    $talk->select("INBOX");
    my $r = $talk->copy("1", "INBOX.dest");
    $self->assert_null($r);
    $self->assert_matches(qr/Too many identical emails/, $talk->get_last_error());

    if ($self->{instance}->{have_syslog_replacement}) {
        my @lines = $self->{instance}->getsyslog();
        $self->assert(grep { m/IOERROR: conversations GUID limit/ } @lines);
    }
}

# Test APPEND of two messages, the second of which has a different subject,
# and would otherwise have threaded, but also has an X-ME-Message-ID header
# and make sure they don't thread
#
sub test_x_me_message_id_nomatch_threading
    :min_version_3_0
{
    my ($self) = @_;
    my %exp;

    xlog $self, "generating message A";
    $exp{A} = $self->{gen}->generate(subject => 'Message A');
    $exp{A}->set_headers('Message-ID', '<fake1700@example.com>');
    $exp{A}->set_attribute(cid => $exp{A}->make_cid());

    $self->{store}->write_begin();
    $self->{store}->write_message($exp{A});
    $self->{store}->write_end();
    $self->check_messages(\%exp);

    xlog $self, "generating message B";
    $exp{B} = $exp{A}->clone();
    $exp{B}->set_headers('Message-ID', '<fake1701@example.com>');
    $exp{B}->set_headers('In-Reply-To', '<fake1700@example.com>');
    $exp{B}->set_headers('X-ME-Message-ID', '<unknown-id@example.com>');
    $exp{B}->set_headers('Subject', 'Message B');
    $exp{B}->set_body("Completely different text here\r\n");
    $exp{B}->set_attribute(cid => $exp{B}->make_cid());

    $self->{store}->write_begin();
    $self->{store}->write_message($exp{B});
    $self->{store}->write_end();
    $self->check_messages(\%exp);
}

1;
