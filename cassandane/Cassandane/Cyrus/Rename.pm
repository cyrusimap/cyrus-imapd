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

sub check_conversations
{
    my ($self) = @_;
    my $filename = $self->{instance}{basedir} . "/ctl_conversationsdb.out";
    $self->{instance}->run_command({
        cyrus => 1,
        redirects => {stdout => $filename},
    }, 'ctl_conversationsdb', '-A', '-r', '-v');

    local $/;
    open FH, '<', $filename
        or die "Cannot open $filename for reading: $!";
    my $str = <FH>;
    close(FH);

    xlog "RESULT: $str";
    $self->assert_matches(qr/is OK/, $str);
    $self->assert($str !~ m/is BROKEN/);
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

    xlog "Test user rename with a big conversation";

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
    :AllowMoves :Conversations :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    xlog "Test user rename with a big conversation";

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

sub test_rename_user
    :Partition2
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    xlog "Test Cyrus extension which renames a user to a different partition";

    $admintalk->rename('user.cassandane', 'user.cassandane'); # should have an error;
    $self->assert($admintalk->get_last_error());

    $admintalk->rename('user.cassandane', 'user.cassandane', 'p2') || die; # partition move
}

sub test_rename_deepuser
    :AllowMoves
{
    my ($self) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    xlog "Test user rename";

    $admintalk->create("user.cassandane.foo") || die;
    $admintalk->create("user.cassandane.bar") || die;
    $admintalk->create("user.cassandane.bar.sub") || die;

    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    $res = $admintalk->select("user.newuser.bar.sub");
    $self->assert(not $admintalk->get_last_error());
}

sub test_rename_paths
    :MetaPartition
{
    my ($self) = @_;
    my $basedir = $self->{instance}->{basedir};
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.rename-src.sub") || die;

    $self->{store}->set_folder("INBOX.rename-src.sub");
    $self->{store}->write_begin();
    my $msg1 = $self->{gen}->generate(subject => "subject 1");
    $self->{store}->write_message($msg1, flags => ["\\Seen", "\$NotJunk"]);
    $self->{store}->write_end();

    # check source files exist
    -d "$basedir/data/user/cassandane/rename-src/sub" || die;
    -d "$basedir/meta/user/cassandane/rename-src/sub" || die;
    -f "$basedir/meta/user/cassandane/rename-src/sub/cyrus.header" || die;
    -f "$basedir/meta/user/cassandane/rename-src/sub/cyrus.index" || die;
    -f "$basedir/data/user/cassandane/rename-src/sub/cyrus.cache" || die;
    -f "$basedir/data/user/cassandane/rename-src/sub/1." || die;

    # and target don't
    -d "$basedir/data/user/cassandane/rename-dst" && die;
    -d "$basedir/meta/user/cassandane/rename-dst" && die;

    $imaptalk->rename("INBOX.rename-src.sub", "INBOX.rename-dst.sub");

    # check dest files exist
    -d "$basedir/data/user/cassandane/rename-dst/sub" || die;
    -d "$basedir/meta/user/cassandane/rename-dst/sub" || die;
    -f "$basedir/meta/user/cassandane/rename-dst/sub/cyrus.header" || die;
    -f "$basedir/meta/user/cassandane/rename-dst/sub/cyrus.index" || die;
    -f "$basedir/data/user/cassandane/rename-dst/sub/cyrus.cache" || die;
    -f "$basedir/data/user/cassandane/rename-dst/sub/1." || die;

    # and src don't
    -d "$basedir/data/user/cassandane/rename-src" && die;
    -d "$basedir/meta/user/cassandane/rename-src" && die;
}

1;
