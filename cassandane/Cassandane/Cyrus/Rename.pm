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

package Cassandane::Cyrus::Rename;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

Cassandane::Cyrus::TestCase::magic(MetaPartition => sub {
    shift->config_set(
        'metapartition-default' => '@basedir@/meta',
        'metapartition_files' => 'header index'
    );
});


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

#
# Test LSUB behaviour
#
sub test_rename_asuser
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.user-src") || die;
    $self->{store}->set_folder("INBOX.user-src");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();
    $imaptalk->select("INBOX.user-src") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->rename("INBOX.user-src", "INBOX.user-dst") || die;
    $imaptalk->select("INBOX.user-dst") || die;
    my @postdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postdata);
}

#
# Test Bug #3586 - rename subfolders
#
sub test_rename_subfolder
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.user-src.subdir") || die;
    $self->{store}->set_folder("INBOX.user-src.subdir");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();
    $imaptalk->select("INBOX.user-src.subdir") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->rename("INBOX.user-src", "INBOX.user-dst") || die;
    $imaptalk->select("INBOX.user-dst.subdir") || die;
    my @postdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postdata);
}

#
# Test Deep rename (intermediates)
#
sub test_rename_deep_subfolder
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.user-src.a.b.c.subdir") || die;
    $self->{store}->set_folder("INBOX.user-src.a.b.c.subdir");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();
    $imaptalk->select("INBOX.user-src.a.b.c.subdir") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->rename("INBOX.user-src", "INBOX.user-dst") || die;
    $imaptalk->select("INBOX.user-dst.a.b.c.subdir") || die;
    my @postdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postdata);
}

#
# Test Deep rename inside a user (intermediates)
#
sub test_rename_user_deep_subfolder
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.user-src.a.b.c.subdir") || die;
    $self->{store}->set_folder("INBOX.user-src.a.b.c.subdir");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();
    $imaptalk->select("INBOX.user-src.a.b.c.subdir") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->rename("INBOX.user-src.a", "INBOX.user-src.z") || die;
    $imaptalk->select("INBOX.user-src.z.b.c.subdir") || die;
    my @postdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postdata);
}

#
# Test big conversation rename
#
sub test_rename_user_bigconversation
    :AllowMoves :Conversations :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Test user rename with a big conversation";

    my %exp;

    $admintalk->create("user.cassandane.foo") || die;
    $admintalk->create("user.cassandane.bar") || die;
    $admintalk->create("user.cassandane.foo.sub") || die;

    $self->{store}->set_folder("INBOX.foo");
    $self->{store}->set_fetch_attributes('uid');

    $exp{A} = $self->make_message("Message A");

    for (1..200) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    }

    $self->check_conversations();

    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    $res = $admintalk->select("user.newuser.foo.sub");
    $self->assert(not $admintalk->get_last_error());
    $self->check_conversations();
}

#
# Test big conversation rename
#
sub test_rename_user_midsizeconversation
    :AllowMoves :Conversations :min_version_3_0 :NoAltNameSpace
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Test user rename with a big conversation";

    my %exp;

    $admintalk->create("user.cassandane.foo") || die;
    $admintalk->create("user.cassandane.bar") || die;
    $admintalk->create("user.cassandane.foo.sub") || die;

    $self->{store}->set_folder("INBOX.foo");
    $self->{store}->set_fetch_attributes('uid', 'cid');

    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    for (1..80) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }

    $self->check_conversations();

    $self->check_messages(\%exp, keyed_on => 'uid');

    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    $res = $admintalk->select("user.newuser.foo.sub");
    $self->assert(not $admintalk->get_last_error());

    $self->{adminstore}->set_folder("user.newuser.foo");
    $self->{adminstore}->set_fetch_attributes('uid', 'cid');
    $self->check_messages(\%exp, keyed_on => 'uid', store => $self->{adminstore});

    $self->check_conversations();
}

#
# Test big conversation rename
#
sub test_rename_bigconversation
     :Conversations :min_version_3_0
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my %exp;

    $imaptalk->create("INBOX.user-src.subdir") || die;
    $self->{store}->set_folder("INBOX.user-src.subdir");
    $self->{store}->set_fetch_attributes('uid');

    $exp{A} = $self->make_message("Message A");

    for (1..200) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
    }

    $imaptalk->select("INBOX.user-src.subdir") || die;

    $self->check_conversations();

    $imaptalk->rename("INBOX.user-src", "INBOX.user-dst") || die;
    $imaptalk->select("INBOX.user-dst.subdir") || die;

    $self->check_conversations();
}

#
# Test mid-sized conversation rename
#
sub test_rename_midsizeconversation
     :Conversations :min_version_3_0
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my %exp;

    $imaptalk->create("INBOX.user-src.subdir") || die;
    $self->{store}->set_folder("INBOX.user-src.subdir");
    $self->{store}->set_fetch_attributes('uid', 'cid');

    $exp{A} = $self->make_message("Message A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    for (1..80) {
      $exp{"A$_"} = $self->make_message("Re: Message A", references => [ $exp{A} ]);
      $exp{"A$_"}->set_attributes(uid => 1+$_, cid => $exp{A}->make_cid());
    }
    $self->check_messages(\%exp, keyed_on => 'uid');

    $self->check_conversations();

    $imaptalk->select("INBOX.user-src.subdir") || die;

    $imaptalk->rename("INBOX.user-src", "INBOX.user-dst") || die;
    $imaptalk->select("INBOX.user-dst.subdir") || die;

    $self->{store}->set_folder("INBOX.user-dst.subdir");
    $self->check_messages(\%exp, keyed_on => 'uid');

    $self->check_conversations();
}

#
# Test Bug #3634 - rename inbox -> inbox.sub
#
sub test_rename_inbox
    :Conversations :min_version_3_0
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $self->{store}->set_folder("INBOX");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();

    $imaptalk->select("INBOX") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $self->check_conversations();

    $imaptalk->rename("INBOX", "INBOX.dst") || die;

    $imaptalk->select("INBOX") || die;
    my @postinboxdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(0, scalar @postinboxdata);

    $imaptalk->select("INBOX.dst") || die;
    my @postdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postdata);

    $self->check_conversations();
}

#
# Test evil INBOX rename possibilities
#
sub test_rename_inbox_intermediate
    :Conversations :min_version_3_1
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $self->{store}->set_folder("INBOX");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();

    $imaptalk->select("INBOX") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->create("INBOX.foo.bar");
    $imaptalk->rename("INBOX.foo", "INBOX") && die "rename should fail";

    $imaptalk->select("INBOX") || die;
    my @postinboxdata = $imaptalk->search("KEYWORD" => "\$NotJunk");
    $self->assert_num_equals(1, scalar @postinboxdata);
}

#
# Test rename a folder with subfolders
#
sub test_rename_withsub_dom
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.a");
    $imaptalk->create("INBOX.b");
    $imaptalk->create("INBOX.c");

    $self->{store}->set_folder("INBOX.c");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();

    $imaptalk->select("INBOX.c") || die;
    my @predata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $imaptalk->rename("INBOX.c", "INBOX.b.c") || die;
    $imaptalk->rename("INBOX.b", "INBOX.a.b") || die;

    $imaptalk->select("INBOX.a.b.c") || die;
    my @postdata = $imaptalk->search("SEEN");
    $self->assert_num_equals(1, scalar @postdata);
}

#
# Test rename a folder with subfolders, domain user
#
sub test_rename_withsub
    :VirtDomains
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $self->{instance}->create_user("renameuser\@example.com");
    my $domstore = $self->{instance}->get_service('imap')->create_store(username => "renameuser\@example.com");
    my $domtalk = $domstore->get_client();

    $domtalk->create("INBOX.a");
    $domtalk->create("INBOX.b");
    $domtalk->create("INBOX.c");

    $domstore->set_folder("INBOX.c");
    $domstore->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $domstore->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $domstore->write_end();

    $domtalk->select("INBOX.c") || die;
    my @predata = $domtalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $domtalk->rename("INBOX.c", "INBOX.b.c") || die;
    $domtalk->rename("INBOX.b", "INBOX.a.b") || die;

    $domtalk->select("INBOX.a.b.c") || die;
    my @postdata = $domtalk->search("SEEN");
    $self->assert_num_equals(1, scalar @postdata);
}

sub test_rename_conversations
    :Conversations :VirtDomains :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $self->{instance}->create_user("renameuser\@example.com");
    my $domstore = $self->{instance}->get_service('imap')->create_store(username => "renameuser\@example.com");
    my $domtalk = $domstore->get_client();

    $domtalk->create("INBOX.a");
    $domtalk->create("INBOX.b");
    $domtalk->create("INBOX.c");

    $domstore->set_folder("INBOX.c");
    $domstore->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $domstore->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $domstore->write_end();

    $domtalk->select("INBOX.c") || die;
    my @predata = $domtalk->search("SEEN");
    $self->assert_num_equals(1, scalar @predata);

    $domtalk->rename("INBOX.c", "INBOX.b.c") || die;
    $domtalk->rename("INBOX.b", "INBOX.a.b") || die;

    $domtalk->select("INBOX.a.b.c") || die;
    my @postdata = $domtalk->search("SEEN");
    $self->assert_num_equals(1, scalar @postdata);
}

sub get_partition
{
    my ($talk, $folder) = @_;

    my $key = '/shared/vendor/cmu/cyrus-imapd/partition';
    my $md = $talk->getmetadata($folder, $key);

    return undef if $talk->get_last_completion_response() ne 'ok';
    return $md->{$folder}->{$key};
}

sub test_rename_user
    :Partition2 :AllowMoves
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Test Cyrus extension which renames a user to a different partition";

    # set up a sub mailbox
    $admintalk->create('user.cassandane.submailbox');
    $self->assert_str_equals('ok',
                             $admintalk->get_last_completion_response());

    # rename to same name (only) should fail
    $admintalk->rename('user.cassandane', 'user.cassandane');
    $self->assert_str_equals('no',
                             $admintalk->get_last_completion_response());
    $self->assert_matches(qr{Mailbox already exists},
                          $admintalk->get_last_error());

    # rename to same name with new partition should succeed
    $admintalk->rename('user.cassandane', 'user.cassandane', 'p2');
    $self->assert_str_equals('ok',
                             $admintalk->get_last_completion_response());

    # rename to same name with same partition should fail
    $admintalk->rename('user.cassandane', 'user.cassandane', 'p2');
    $self->assert_str_equals('no',
                             $admintalk->get_last_completion_response());
    $self->assert_matches(qr{Mailbox already exists},
                          $admintalk->get_last_error());

    # rename to new name with new partition should fail
    $admintalk->rename('user.cassandane', 'user.bob', 'default');
    $self->assert_str_equals('no',
                             $admintalk->get_last_completion_response());
    $self->assert_matches(qr{Cross-server or cross-partition move w/rename not supported},
                          $admintalk->get_last_error());

    # rename to new name without partition should not change partition
    my $before_partition = get_partition($admintalk, 'user.cassandane');
    $self->assert_not_null($before_partition);
    $admintalk->rename('user.cassandane', 'user.bob');
    $self->assert_str_equals('ok',
                             $admintalk->get_last_completion_response());
    my $after_partition = get_partition($admintalk, 'user.bob');
    $self->assert_equals($before_partition, $after_partition);
    my $sub_partition = get_partition($admintalk, 'user.bob.submailbox');
    $self->assert_equals($after_partition, $sub_partition);

    # XXX rename to new name with explicit current partition should succeed
    # XXX not implemented, but would be nice :)
#    $before_partition = get_partition($admintalk, 'user.bob');
#    $self->assert_not_null($before_partition);
#    $admintalk->rename('user.bob', 'user.cassandane', $before_partition);
#    $self->assert_str_equals('ok',
#                             $admintalk->get_last_completion_response());
#    $after_partition = get_partition($admintalk, 'user.cassandane');
#    $self->assert_str_equals($before_partition, $after_partition);
}

sub test_rename_deepuser
    :AllowMoves :Replication :SyncLog
{
    my ($self) = @_;

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Test user rename";

    $admintalk->create("user.cassandane.foo") || die;
    $admintalk->create("user.cassandane.bar") || die;
    $admintalk->create("user.cassandane.bar.sub") || die;

    # replicate and check initial state
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('cassandane');
    unlink($synclogfname);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    $res = $admintalk->select("user.newuser.bar.sub");
    $self->assert(not $admintalk->get_last_error());

    # replicate and check the renames
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('newuser');
}

sub test_rename_paths
    :MetaPartition :NoAltNameSpace
{
    my ($self) = @_;
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.rename-src.sub") || die;

    $self->{store}->set_folder("INBOX.rename-src.sub");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();

    # check source files exist
    my $srcdata = $self->{instance}->run_mbpath('user.cassandane.rename-src.sub');
    -d "$srcdata->{data}" || die;
    -d "$srcdata->{meta}" || die;
    -f "$srcdata->{meta}/cyrus.header" || die;
    -f "$srcdata->{meta}/cyrus.index" || die;
    -f "$srcdata->{data}/cyrus.cache" || die;
    -f "$srcdata->{data}/1." || die;

    # and target don't
    my $dstdata = eval { $self->{instance}->run_mbpath('user.cassandane.rename-dst.sub') };
    $self->assert(not $dstdata or (not -d $dstdata->{data} and not -d $dstdata->{meta}));

    $imaptalk->rename("INBOX.rename-src.sub", "INBOX.rename-dst.sub");

    # check dest files exist
    $dstdata = $self->{instance}->run_mbpath('user.cassandane.rename-dst.sub');
    -d "$dstdata->{data}" || die;
    -d "$dstdata->{meta}" || die;
    -f "$dstdata->{meta}/cyrus.header" || die;
    -f "$dstdata->{meta}/cyrus.index" || die;
    -f "$dstdata->{data}/cyrus.cache" || die;
    -f "$dstdata->{data}/1." || die;

    # and src don't any more (unless UUID when the paths are the same!)
    $srcdata->{data} ne $dstdata->{data} && -d "$srcdata->{data}" && die;
    $srcdata->{meta} ne $dstdata->{meta} && -d "$srcdata->{meta}" && die;
}

sub test_rename_deepuser_unixhs
    :AllowMoves :Replication :SyncLog :UnixHierarchySep
{
    my ($self) = @_;

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Test user rename";

    $admintalk->create("user/cassandane/foo") || die;
    $admintalk->create("user/cassandane/bar") || die;
    $admintalk->create("user/cassandane/bar/sub") || die;

    # replicate and check initial state
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('cassandane');
    unlink($synclogfname);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    my $res = $admintalk->rename('user/cassandane', 'user/new.user');
    $self->assert(not $admintalk->get_last_error());

    $res = $admintalk->select("user/new.user/bar/sub");
    $self->assert(not $admintalk->get_last_error());

    # replicate and check the renames
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('new.user');
}

sub _match_intermediates
{
    my ($self, %expect) = @_;
    my @lines = $self->{instance}->getsyslog();
    #'Aug 23 12:34:20 bat 0234200101/ctl_cyrusdb[14527]: mboxlist: creating intermediate with children: user.cassandane.a (ec10f137-1bee-443e-8cb2-c6c893463b0a)',
    #'Aug 23 12:34:20 bat 0234200101/ctl_cyrusdb[14527]: mboxlist: deleting intermediate with no children: user.cassandane.hanging (b13ba9d4-9d40-4474-911f-77346a73d747)',
    for (@lines) {
        if (m/mboxlist: creating intermediate with children: (.*?)($| \()/) {
            my $mbox = $1;
            $self->assert(exists $expect{$mbox}, "didn't expect touch of $mbox");
            my $val = delete $expect{$mbox};
            $self->assert(!$val, "create when expected delete of $mbox");
        }
        if (m/mboxlist: deleting intermediate with no children: (.*?)($| \()/) {
            my $mbox = $1;
            $self->assert(exists $expect{$mbox}, "didn't expect touch of $mbox");
            my $val = delete $expect{$mbox};
            $self->assert(!!$val, "delete when expected create of $mbox");
        }
    }
    use Data::Dumper;
    $self->assert_num_equals(0, scalar keys %expect, "EXPECTED TO SEE " . Dumper(\%expect, \@lines));
}

sub _dbset
{
    my ($self, $key, $value) = @_;
    $self->{instance}->run_command(
        { cyrus => 1 },
        'cyr_dbtool',
        "$self->{instance}->{basedir}/conf/mailboxes.db",
        'twoskip',
        defined($value)
          ? ('set', $key => $value)
          : ('delete', $key),
    );
}

sub test_intermediate_cleanup
    :min_version_3_1 :max_version_3_4 :NoAltNameSpace :NoAltNameSpace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.a.b.c.subdir") || die;
    $imaptalk->create("INBOX.x.y.z.subdir") || die;
    $imaptalk->create("INBOX.INBOX.subinbox") || die;
    $imaptalk->create("INBOX.INBOX.a.b") || die;

    _match_intermediates($self,
        'user.cassandane.a' => undef,
        'user.cassandane.a.b' => undef,
        'user.cassandane.a.b.c' => undef,
        'user.cassandane.x' => undef,
        'user.cassandane.x.y' => undef,
        'user.cassandane.x.y.z' => undef,
        'user.cassandane.INBOX.a' => undef,
    );

    $imaptalk->create("INBOX.x.y");

    _match_intermediates($self);

    $imaptalk->delete("INBOX.x.y.z.subdir");

    _match_intermediates($self,
        'user.cassandane.x.y.z' => 1,
    );

    $imaptalk->delete("INBOX.x.y");

    _match_intermediates($self,
        'user.cassandane.x' => 1,
    );

    $imaptalk->delete("INBOX.INBOX.a.b");

    _match_intermediates($self,
        'user.cassandane.INBOX.a' => 1,
    );

    _dbset($self, 'user.cassandane.old', '%(I 66eb299a-35a8-423d-a0a6-90cbacfd153a T di C 1 F 1 M 1538674002)');

    $imaptalk->create("INBOX.old.foo");

    _match_intermediates($self,
        'user.cassandane.old' => undef,
    );

    $imaptalk->delete("INBOX.old.foo");

    _match_intermediates($self,
        'user.cassandane.old' => 1,
    );

    my %set = (
      'user.cassandane.hanging' => '%(I b13ba9d4-9d40-4474-911f-77346a73d747 T i C 1 F 1 M 1538674002)',
      'user.cassandane.a'       => undef,
      'user.cassandane.a.b'     => undef,
      'user.cassandane.x'       => '%(I 7c89e632-04a0-4560-9a59-18b07c13ddff T i C 1 F 1 M 1538674002)',
      'user.cassandane.x.y'     => '%(I 385d7a66-6173-4b5e-9340-0301ac55b373 T i C 1 F 1 M 1538674002)',
    );

    # NOTE: This is all very specific!
    foreach my $key (keys %set) {
      _dbset($self, $key, $set{$key});
    }

    $self->{instance}->getsyslog();

    # perform startup magic
    $self->{instance}->run_command(
        { cyrus => 1 },
        'ctl_cyrusdb', '-r',
    );

    _match_intermediates($self, %set);
}

1;
