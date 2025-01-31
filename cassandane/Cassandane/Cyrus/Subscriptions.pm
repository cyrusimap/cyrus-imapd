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

package Cassandane::Cyrus::Subscriptions;
use strict;
use warnings;
use DateTime;
use Data::Dumper;
use File::Basename;
use File::Copy;
use File::Path qw(mkpath);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Mboxname;
use Cassandane::Util::Log;
use Cassandane::Util::Words;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's create ourselves some users and subscriptions
    # sub folders of the main user
    $admintalk->create("user.cassandane.asub");
    $admintalk->create("user.cassandane.asub.deeper");

    # sub folders of another user - one is subscribable
    $self->{instance}->create_user("other",
                                   subdirs => [ 'sub', ['sub', 'folder'] ]);
    $admintalk->setacl("user.other.sub.folder", "cassandane", "lrs");

    my $usertalk = $self->{store}->get_client();
    $usertalk->subscribe("INBOX");
    $usertalk->subscribe("INBOX.asub");
    $usertalk->subscribe("user.other.sub.folder");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test LSUB behaviour
#
sub test_lsub_toplevel
    :NoAltNameSpace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $alldata = $imaptalk->lsub("", "*");
    $self->assert_deep_equals($alldata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [],
            '.',
            'INBOX.asub'
          ],
          [
            [],
            '.',
            'user.other.sub.folder'
          ]
    ], "LSUB all data mismatch: "  . Dumper($alldata));

    my $topdata = $imaptalk->lsub("", "%");
    $self->assert_deep_equals($topdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [
              '\\Noselect',
              '\\HasChildren'
            ],
            '.',
            'user'
          ],
    ], "LSUB top data mismatch:" . Dumper($topdata));
}

sub test_lsub_delete
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.deltest") || die;
    $imaptalk->create("INBOX.deltest.sub1") || die;
    $imaptalk->create("INBOX.deltest.sub2") || die;
    $imaptalk->subscribe("INBOX.deltest") || die;
    $imaptalk->subscribe("INBOX.deltest.sub2") || die;
    my $subdata = $imaptalk->lsub("INBOX.deltest", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.deltest'
          ],
          [
            [],
            '.',
            'INBOX.deltest.sub2'
          ],
    ], "LSUB deltest setup mismatch: " . Dumper($subdata));

    $imaptalk->delete("INBOX.deltest.sub2");
    my $onedata = $imaptalk->lsub("INBOX.deltest", "*");
    $self->assert_deep_equals($onedata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.deltest'
          ],
    ], "LSUB deltest.sub2 after delete mismatch: " . Dumper($onedata));
}

sub test_lsub_extrachild
    :NoAltNameSpace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Test") || die;
    $imaptalk->create("INBOX.Test.Sub") || die;
    $imaptalk->create("INBOX.Test Foo") || die;
    $imaptalk->create("INBOX.Test Bar") || die;
    $imaptalk->subscribe("INBOX.Test") || die;
    $imaptalk->subscribe("INBOX.Test.Sub") || die;
    $imaptalk->subscribe("INBOX.Test Foo") || die;
    $imaptalk->delete("INBOX.Test.Sub") || die;
    my $subdata = $imaptalk->lsub("", "*");
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
          [
            [],
            '.',
            'INBOX.asub'
          ],
          [
            [],
            '.',
            'user.other.sub.folder'
          ],
    ], "LSUB extrachild mismatch: " . Dumper($subdata));
}

sub v2
{
    my ($first, @rest) = @_;

    my $v2 = 'N' . $first;
    $v2 .= "\x1f" . $_ for @rest;
    return $v2;
}

sub upgrade_from_2_common
{
    my ($self, $domain) = @_;

    # hardcoded localparts because we need to predict particular badness
    my $user1 = 'matt';
    my $user2 = 'matthew';

    # optional domain for testing with/without virtdomains.
    # we only test with no domain or the same domain, because #5146 didn't
    # happen if the two users were in different domains, so there wouldn't be
    # a "bad" db record to "fix"
    if ($domain) {
        $user1 .= "\@$domain";
        $user2 .= "\@$domain";
    }

    my $config = $self->{instance}->{config};
    my $sep = $config->get_bool('unixhierarchysep', 'on') ? '/' : '.';

    my $user1_inbox = Cassandane::Mboxname->new(config => $config);
    $user1_inbox->from_username($user1);

    my @user1_mailboxes = map {
        $user1_inbox->make_child($_);
    } random_words(3);

    $self->{instance}->create_user($user1,
                                   subdirs => \@user1_mailboxes);

    my $user2_inbox = Cassandane::Mboxname->new(config => $config);
    $user2_inbox->from_username($user2);

    my @user2_mailboxes = map {
        $user2_inbox->make_child($_);
    } random_words(3);

    $self->{instance}->create_user($user2,
                                   subdirs => \@user2_mailboxes);

    my $mbpath = $self->{instance}->run_mbpath('-u', $user1);
    my $subdb = $mbpath->{user}->{sub};
    my $engine = $self->{instance}->{config}->get('subscription_db') || 'flat';

    # generate user1 subscriptions in the v2 format
    my @items = (
        # version key
        [ 'SET', "\x1fVER\x1f", '2' ],
        # subscribe to own inbox (user.matt)
        [ 'SET', v2('INBOX') ],
        # subscribe to own subdirs (user.matt.foo)
        (map { [ 'SET', v2('INBOX', $_->box()) ] } @user1_mailboxes),
        # some bad subscriptions as if we had hit bug #5146
        [ 'SET', v2('INBOXhew') ], # user.matthew
        (map { [ 'SET', v2('INBOXhew', $_->box()) ] } @user2_mailboxes),
    );

    # XXX run_dbcommand needs the file to already exist
    mkpath(dirname($subdb));
    open my $fh, '>', $subdb or die "open $subdb: $!";
    close $fh;

    # create v2 subscriptions file
    $self->{instance}->run_dbcommand($subdb, $engine, @items);

    # make a copy of sub.db pre-upgrade in case we want to look at it later
    copy($subdb, "$subdb.orig");

    # discard syslog accumulated so far
    $self->{instance}->getsyslog();

    # list user1's subscriptions normally (db should be upgraded on open)
    my $service = $self->{instance}->get_service('imap');
    my $store = $service->create_store(username => $user1);
    my $talk = $store->get_client();

    my $subdata = $talk->lsub("", "*");
    $self->assert_mailbox_structure($subdata, $sep, {
        $user1_inbox->to_external('owner') => [],
        (map { $_->to_external('owner') => [] } @user1_mailboxes),
        $user2_inbox->to_external('other') => [ '\\HasChildren' ],
        (map { $_->to_external('other') => [] } @user2_mailboxes),
    });
    $talk->logout();

    # check that we upgraded
    $self->assert_syslog_matches($self->{instance},
                                 qr{upgrading user subscriptions});
    my (undef, $version) = $self->{instance}->run_dbcommand($subdb, $engine,
        [ 'GET', "\x1fVER\x1f" ]
    );
    $self->assert_num_equals(3, $version);

    # list user's subscriptions again
    $talk = $store->get_client();

    $subdata = $talk->lsub("", "*");
    $self->assert_mailbox_structure($subdata, $sep, {
        $user1_inbox->to_external('owner') => [],
        (map { $_->to_external('owner') => [] } @user1_mailboxes),
        $user2_inbox->to_external('other') => [ '\\HasChildren' ],
        (map { $_->to_external('other') => [] } @user2_mailboxes),
    });
    $talk->logout();

    # better not have upgraded this time
    $self->assert_syslog_does_not_match($self->{instance},
                                        qr{upgrading user subscriptions});
}

sub test_upgrade_from_2
{
    my ($self) = @_;

    $self->upgrade_from_2_common(undef);
}

sub test_upgrade_from_2_vd
    :VirtDomains :CrossDomains
{
    my ($self) = @_;

    $self->upgrade_from_2_common('example.com');
}

1;
