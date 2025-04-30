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
use Cassandane::Util::Slurp;
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

        return $class->SUPER::new({
            config => $config,
            adminstore => 1,
        }, @args);
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
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_1 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_1 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my %exp;

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
# test upgrade tooling
#
sub test_upgrade
    :min_version_3_12 :Conversations
{
    my ($self) = @_;
    my %exp;

    my $talk = $self->{store}->get_client();

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    $talk->create('foo');

    # shouldn't reconstruct
    xlog $self, "Upgrade shouldn't have anything to do";
    my $basedir = $self->{instance}->{basedir};
    my $outfile = "$basedir/conv-output1.txt";
    $self->{instance}->run_command({ cyrus => 1, redirects => { stdout => $outfile } }, 'ctl_conversationsdb', '-U', '-r', '-v');
    my $data = slurp_file($outfile);
    $self->assert_matches(qr/already version/, $data);

    # nuke the version key
    my $dirs = $self->{instance}->run_mbpath(-u => 'cassandane');
    my $format = $self->{instance}->{config}->get('conversations_db');
    $self->{instance}->run_dbcommand($dirs->{user}{conversations}, $format, ['DELETE', '$VERSION']);

    xlog $self, "Upgrade with deleted VERSION should recalc";
    $outfile = "$basedir/conv-output2.txt";
    $self->{instance}->run_command({ cyrus => 1, redirects => { stdout => $outfile } }, 'ctl_conversationsdb', '-U', '-r', '-v');
    $data = slurp_file($outfile);
    $self->assert_matches(qr/user.cassandane.foo/, $data);


    xlog $self, "Upgrade again should have nothing to do";
    $outfile = "$basedir/conv-output3.txt";
    $self->{instance}->run_command({ cyrus => 1, redirects => { stdout => $outfile } }, 'ctl_conversationsdb', '-U', '-r', '-v');
    $data = slurp_file($outfile);
    $self->assert_matches(qr/already version/, $data);
}

#
# test reconstruct of larger conversation
#
sub test_reconstruct_splitconv
    :min_version_3_1 :Conversations
{
    my ($self) = @_;
    my %exp;

    my $talk = $self->{store}->get_client();

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating replies";
    for (1..20) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }

    $talk->create('foo');
    $talk->copy('1:*', 'foo');

    $self->check_messages(\%exp, keyed_on => 'uid');

    # first run WITHOUT splitting
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-R', '-r');

    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("foo");
    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("INBOX");

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
    $talk->select("foo");
    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("INBOX");

    # zero everything out
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-z', 'cassandane');

    # rebuild
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-b', 'cassandane');

    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("foo");
    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("INBOX");

    # support for -Z was added after 3.8
    my ($maj, $min) = Cassandane::Instance->get_version();
    return if ($maj < 3 or ($maj == 3 and $min < 8));

    # zero out ONLY two CIDs
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb',
                                    '-Z' => $exp{"A15"}->make_cid(),
                                    '-Z' => $exp{"A10"}->make_cid(),
                                    'cassandane');
    for (10..19) {
      $exp{"A$_"}->set_attributes(cid => undef, basecid => undef);
    }

    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("foo");
    $self->check_messages(\%exp, keyed_on => 'uid');
    $talk->select("INBOX");
}

#
# test clearing the modseq
#
sub test_clearmodseq
    :min_version_3_1 :Conversations
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setquota('user.cassandane', ['STORAGE', 500000]);

    for (1..20) {
      $self->make_message("Message A$_");
    }

    my $precounters = $self->{store}->get_counters();
    # we've made a bunch of changes, this should be more than 10!
    $self->assert($precounters->{highestmodseq} > 10, "$precounters->{highestmodseq} > 10");

    # zero out the modseqs
    $self->{instance}->run_command({ cyrus => 1 }, 'ctl_conversationsdb', '-M', 'cassandane');

    my $midcounters = $self->{store}->get_counters();
    # we haven't made any changes, should actually be zero!
    $self->assert($midcounters->{highestmodseq} < 10, "$midcounters->{highestmodseq} < 10");

    $self->make_message("Message B1");
    $self->make_message("Message B2");

    my $postcounters = $self->{store}->get_counters();
    # we've only created two more emails, it shouldn't have bounced higher
    $self->assert($postcounters->{highestmodseq} < 10, "$postcounters->{highestmodseq} < 10");

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
    :min_version_3_1 :needs_component_replication :Conversations
{
    my ($self) = @_;
    my %exp;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    $master_store->set_fetch_attributes('uid', 'cid', 'basecid');
    $replica_store->set_fetch_attributes('uid', 'cid', 'basecid');

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
    :min_version_3_1 :needs_component_replication :Conversations
{
    my ($self) = @_;
    my %exp;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    $master_store->set_fetch_attributes('uid', 'cid', 'basecid');
    $replica_store->set_fetch_attributes('uid', 'cid', 'basecid');

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
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_0 :needs_component_replication :Conversations
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

#
# Test APPEND of a new composed draft message to the Drafts folder by
# the Fastmail webui, which sets the X-ME-Message-ID header to thread
# conversations but not any of Message-ID, References, or In-Reply-To.
#
sub bogus_test_fm_webui_draft
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my %exp;

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
    :min_version_3_0 :Conversations
{
    my ($self) = @_;
    my $bobuser = "bob";
    my $bobfolder = "user.$bobuser";

    xlog $self, "Testing COPY between folders owned by different users [IRIS-893]";

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
    :min_version_3_1 :needs_component_replication :Conversations
{
    my ($self) = @_;
    my %exp;

    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    $master_store->set_fetch_attributes('uid', 'cid');
    $replica_store->set_fetch_attributes('uid', 'cid');

    my $mtalk = $master_store->get_client();

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

    $self->assert_syslog_matches($self->{instance},
                                 qr{IOERROR: conversations GUID limit});

    $talk->select("INBOX.dest");
    my $data = $talk->fetch("1:*", "(emailid threadid uid)");
    $self->assert_not_null($data->{1});
    $self->assert_not_null($data->{2});
    $self->assert_null($data->{3});
}

#
# Test limits on GUID duplicates copying to source
#
sub test_guid_duplicate_same_destination
    :min_version_3_3 :LowEmailLimits
{
    my ($self) = @_;
    my %exp;

    xlog $self, "generating messages";
    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $exp{B} = $self->make_message("Message B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());
    $exp{C} = $self->make_message("Message C");
    $exp{C}->set_attributes(uid => 3, cid => $exp{C}->make_cid());
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    $talk->select("INBOX");
    my $r1 = $talk->copy("2", "INBOX");
    my $r2 = $talk->copy("1:*", "INBOX");
    $self->assert_not_null($r1);
    $self->assert_null($r2);
    $self->assert_matches(qr/Too many identical emails/, $talk->get_last_error());

    $self->assert_syslog_matches($self->{instance},
                                 qr{IOERROR: conversations GUID limit});

    my $data = $talk->fetch("1:*", "(emailid threadid uid)");
    $self->assert_not_null($data->{1});
    $self->assert_not_null($data->{2});
    $self->assert_not_null($data->{3});
    $self->assert_not_null($data->{4});
    $self->assert_null($data->{5});
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
    $self->assert_syslog_matches($self->{instance},
                                 qr{IOERROR: conversations GUID limit});
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

    $self->assert_syslog_matches($self->{instance},
                                 qr{IOERROR: conversations GUID limit});
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

sub test_rename_between_users
        :NoAltNameSpace
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create shared account";
    $admintalk->create("user.manifold");

    $admintalk->setacl("user.manifold", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", manifold => 'lrswipkxtecdan');
    $admintalk->setacl("user.manifold", cassandane => 'lrswipkxtecdn');

    # Reset the conv.db versions to 1 (to force UUID-based MAILBOXIDs)
    my $dirs = $self->{instance}->run_mbpath(-u => 'cassandane');
    my $mdirs = $self->{instance}->run_mbpath(-u => 'manifold');

    my $format = $self->{instance}->{config}->get('conversations_db');
    $self->{instance}->run_dbcommand($dirs->{user}{conversations}, $format,
                                     ['SET', '$VERSION', '1']);
    $self->{instance}->run_dbcommand($mdirs->{user}{conversations}, $format,
                                     ['SET', '$VERSION', '1']);

    my $talk = $self->{store}->get_client();

    $self->{store}->set_folder("INBOX");
    $self->make_message("Inbox Msg");

    $talk->create("INBOX.foo");
    $self->{store}->set_folder("INBOX.foo");
    $self->make_message("Foo Msg");

    $talk->create("INBOX.bar");
    $self->{store}->set_folder("INBOX.bar");
    $self->make_message("Bar Msg");

    $self->{store}->set_folder("user.manifold");
    $self->make_message("Man Msg");

    # folder IDs should be "INBOX", "foo", "bar"

    my $res = $talk->status('INBOX.foo', ['mailboxid']);
    my $fooid = $res->{'mailboxid'}->[0];

    my %data = $self->{instance}->run_dbcommand($dirs->{user}{conversations}, $format, ['SHOW']);
    my %mdata = $self->{instance}->run_dbcommand($mdirs->{user}{conversations}, $format, ['SHOW']);

    my $folders = Cyrus::DList->parse_string($data{'$FOLDER_IDS'})->as_perl;
    my $mfolders = Cyrus::DList->parse_string($mdata{'$FOLDER_IDS'})->as_perl;

    $self->assert_num_equals(3, scalar @$folders);
    $self->assert_num_equals(1, scalar @$mfolders);
    $self->assert_str_equals($fooid, $folders->[1]);

    xlog $self, "Rename folder to other user";
    $talk->rename("INBOX.foo", "user.manifold.foo");

    $admintalk->create('user.manifold.extra');
    $self->{store}->set_folder("user.manifold.extra");
    $self->make_message("Extra Msg");

    %data = $self->{instance}->run_dbcommand($dirs->{user}{conversations}, $format, ['SHOW']);
    %mdata = $self->{instance}->run_dbcommand($mdirs->{user}{conversations}, $format, ['SHOW']);

    $folders = Cyrus::DList->parse_string($data{'$FOLDER_IDS'})->as_perl;
    $mfolders = Cyrus::DList->parse_string($mdata{'$FOLDER_IDS'})->as_perl;
    $self->assert_num_equals(3, scalar @$folders);
    $self->assert_num_equals(3, scalar @$mfolders);
    $self->assert_str_equals('-', $folders->[1]);
    $self->assert_str_equals($fooid, $mfolders->[1]);

    $talk->create("INBOX.again");
    $self->{store}->set_folder("INBOX.again");
    $self->make_message("Again Msg");

    $res = $talk->status('INBOX.again', ['mailboxid']);
    my $againid = $res->{'mailboxid'}->[0];

    $talk->rename("user.manifold.foo", "INBOX.foo");

    %data = $self->{instance}->run_dbcommand($dirs->{user}{conversations}, $format, ['SHOW']);
    %mdata = $self->{instance}->run_dbcommand($mdirs->{user}{conversations}, $format, ['SHOW']);
    $folders = Cyrus::DList->parse_string($data{'$FOLDER_IDS'})->as_perl;
    $mfolders = Cyrus::DList->parse_string($mdata{'$FOLDER_IDS'})->as_perl;
    $self->assert_num_equals(4, scalar @$folders);
    $self->assert_num_equals(3, scalar @$mfolders);
    $self->assert_str_equals($againid, $folders->[1]);
    $self->assert_str_equals($fooid, $folders->[3]);
    $self->assert_str_equals('-', $mfolders->[1]);
}

#
# Test user rename without splitting conversations
#
sub test_rename_user_nosplitconv
    :AllowMoves :Replication :needs_component_replication :Conversations
{
    my ($self) = @_;

    xlog $self, "Test user rename without splitting conversations";

    my %exp;

    my $master_store = $self->{master_store};
    $master_store->set_fetch_attributes('uid', 'cid', 'basecid');

    xlog $self, "generating message A";
    $exp{A} = $self->make_message("Message A", store => $master_store);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());
    $self->check_messages(\%exp);

    xlog $self, "generating replies";
    for (1..20) {
        $exp{"A$_"} = $self->make_message("Re: Message A",
                                          references => [ $exp{A} ],
                                          store => $master_store);
        $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }

    my $talk = $master_store->get_client();
    $talk->create('foo');
    $talk->copy('1:*', 'foo');

    $self->check_messages(\%exp, keyed_on => 'uid', store => $master_store);
    $self->check_conversations();

    $self->run_replication();
    $self->check_replication('cassandane');

    # Reduce the conversation thread size
    my $config = $self->{instance}->{config};
    $config->set(conversations_max_thread => 5);
    $config->generate($self->{instance}->_imapd_conf());

    $config = $self->{replica}->{config};
    $config->set(conversations_max_thread => 5);
    $config->generate($self->{replica}->_imapd_conf());

    # Rename the user
    my $admintalk = $self->{adminstore}->get_client();
    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    $self->{adminstore}->set_folder("user.newuser");
    $self->{adminstore}->set_fetch_attributes('uid', 'cid', 'basecid');
    $self->check_messages(\%exp, keyed_on => 'uid', store => $self->{adminstore});
    $self->check_conversations();

    $self->run_replication(user => 'newuser');
    $self->check_replication('newuser');
}

sub test_unmap_failed_appends
    :NoCheckSyslog
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    my $mime = <<'EOF';
From: from@local
To: to@local
Subject: test
Date: Mon, 14 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain

test
EOF
    $mime =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $mime) || die $@;

    # look up the PID of the imapd process
    my @lines = grep(/imap\[\d+\]: command: \w+ Append$/,
        $self->{instance}->getsyslog());
    $self->assert_num_equals(1, scalar @lines);

    my ($pid) = $lines[0] =~ /imap\[(\d+)\]:/;
    $self->assert_not_null($pid);

    # append duplicate messages until we reach the GUID limit
    foreach (1..100) {
        $imap->append('INBOX', $mime);
        my $res = $imap->get_last_completion_response;
        if ('ok' ne $res) {
            last;
        }
    }

    # make sure that conversation.db got unmapped completely
    my $dangling_maps = `grep conversations.db /proc/$pid/maps 2>&1`;
    $self->assert_str_equals('', $dangling_maps);
}

1;
