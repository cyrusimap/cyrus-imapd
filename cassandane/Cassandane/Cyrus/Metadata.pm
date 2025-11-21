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

package Cassandane::Cyrus::Metadata;
use strict;
use warnings;
use DateTime;
use File::Temp qw(:POSIX);
use Config;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use lib '../perl/imap';
use Cyrus::DList;

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({ adminstore => 1 }, @args);
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
# Create and save two messages to two stores, according to GUID
# on the messages, so that the first store gets the message with
# the lower GUID and the second store the message with the higher
# GUID.  Both cases need to be done in a controlled manner in order
# to exercise some of the more obscure code paths in message
# replication.
#
# Returns: Message, Message in the order they went to Stores
#
sub make_message_pair
{
    my ($self, $store0, $store1) = @_;

    # Generate two messages and detect their resulting GUIDs
    my $msg0 = $self->{gen}->generate(subject => 'Message Zero');
    my $msg1 = $self->{gen}->generate(subject => 'Message One');
    my $guid0 = $msg0->get_guid();
    my $guid1 = $msg1->get_guid();
    xlog $self, "Message 'Message Zero' has GUID $guid0";
    xlog $self, "Message 'Message One' has GUID $guid1";

    # choose ordering of messages
    $self->assert_str_not_equals($guid0, $guid1);
    if ($guid0 gt $guid1)
    {
        # swap
        my $t = $msg0;
        $msg0 = $msg1;
        $msg1 = $t;
    }

    # Save and return the messages
    $self->_save_message($msg0, $store0);
    $self->_save_message($msg1, $store1);
    return ($msg0, $msg1);
}

# List annotations actually stored in the database.
sub list_annotations
{
    my ($self, %params) = @_;

    my $scope = delete $params{scope} || 'global';
    my $mailbox = delete $params{mailbox} || 'user.cassandane';
    my $tombstones = delete $params{tombstones};
    my $withmdata = delete $params{withmdata};
    my $instance = delete $params{instance} || $self->{instance};
    my $uids = delete $params{uids};
    die "Unknown parameters: " . join(' ', map { $_ . '=' . $params{$_}; } keys %params)
        if scalar %params;

    my $basedir = $instance->{basedir};

    my $mailbox_db;
    if ($scope eq 'global' || $scope eq 'mailbox')
    {
        $mailbox_db = "$basedir/conf/annotations.db";
    }
    elsif ($scope eq 'message')
    {
        my $mb = $mailbox;
        my $datadir = $self->{instance}->folder_to_directory($mailbox);
        $mailbox_db = "$datadir/cyrus.annotations";
    }
    else
    {
        die "Unknown scope: $scope";
    }

    my $format = $instance->{config}->get('annotation_db');

    my @annots;

    my $res = $instance->run_dbcommand_cb(sub {
        my ($key, $value) = @_;
        my ($uid, $item, $userid, @rest) = split '\0', $key;
        my ($data, $modseq, $flags);
        if (substr($value, 0, 1) eq '%') {
            my $dlist = Cyrus::DList->parse_string($value, 0);
            my $hash = $dlist->as_perl;
            $data = $hash->{V};
            $modseq = $hash->{M};
            $flags = $hash->{F} ? 1 : 0;  # XXX - parse more options later
        }
        else {
            my $offset = 0;
            my $vallen = unpack('N', substr($value, $offset, 4));
            $offset += 8; # 4 more bytes of rubbish
            $data = substr($value, $offset, $vallen);
            $offset += $vallen + 1; # trailing null
            my $strend = index($value, "\0", $offset);
            my $type = substr($value, $offset, ($strend - $offset));
            $offset = $strend + 1;
            my $modtime = unpack('N', substr($value, $offset, 4));
            $offset += 8; # 4 more bytes of rubbish again
            $modseq = unpack('x[N]N', substr($value, $offset, 8));
            $offset += 8;
            $flags = unpack('C', substr($value, $offset, 1));
        }

        if ($flags and not $tombstones) {
            return;
        }
        my $annot = {
            uid => ($scope eq 'message' ? $uid : 0),
            mboxname => ($scope eq 'message' ? $mailbox : $uid),
            entry => $item,
            userid => $userid,
            data => $data,
        };

        if ($withmdata) {
            $annot->{modseq} = $modseq;
            $annot->{flags} = $flags;
        }

        if ($uids) {
            my %wantuids = map { $_ => 1 } $uids;
            if ($uids and not exists($wantuids{$annot->{uid}})) {
                return;
            }
        }

        if ($annot->{userid} eq '[.OwNeR.]') {
            $annot->{userid} = 'cassandane'; # XXX - strip owner from $mailbox?
        }

        push(@annots, $annot);
    }, $mailbox_db, $format, ['SHOW']);

    # enforce a stable order so we have some chance of
    # comparing the results
    @annots = sort {
        $a->{mboxname} cmp $b->{mboxname} ||
        $a->{uid} <=> $b->{uid} ||
        $a->{userid} cmp $b->{userid} ||
        $a->{entry} cmp $b->{entry};
    } @annots;

    return \@annots;
}

sub list_uids
{
    my ($self, $store) = @_;
    my @uids;

        $store->read_begin();
        while (my $msg = $store->read_message())
        {
        push(@uids, $msg->uid);
        }
        $store->read_end();

    return \@uids;
}

sub check_msg_annotation_replication
{
    my ($self, $master_store, $replica_store, %params) = @_;

    my $master_annots = $self->list_annotations((%params,
            scope => 'message',
            instance => $self->{instance},
            withmdata => 1,
            tombstones => 1,
            uids => $self->list_uids($master_store),
        ));
    my $replica_annots = $self->list_annotations((%params,
            scope => 'message',
            instance => $self->{replica},
            withmdata => 1,
            tombstones => 1,
            uids => $self->list_uids($replica_store),
        ));

    $self->assert_deep_equals($master_annots, $replica_annots);
}

sub set_msg_annotation
{
    my ($self, $store, $uid, $entry, $attrib, $value) = @_;

    $store ||= $self->{store};
    $store->connect();
    $store->_select();
    my $talk = $store->get_client();
    # Note $value might have no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('' . $uid, 'annotation', [$entry, [$attrib, { Quote => $value }]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

# Not sure if this cases can even work...
# sub test_msg_replication_mod_bot_mse

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

# sub test_mbox_replication_new_rep
# sub test_mbox_replication_new_bot
# sub test_mbox_replication_mod_mas
# sub test_mbox_replication_mod_rep
# sub test_mbox_replication_mod_bot
# sub test_mbox_replication_del_mas
# sub test_mbox_replication_del_rep
# sub test_mbox_replication_del_bot

sub folder_delete_mboxa_common
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    # data thanks to hipsteripsum.me
    my $folder = 'INBOX.williamsburg';
    my $fentry = '/private/comment';
    my $data = $self->make_random_data(0.3, maxreps => 15);

    xlog $self, "create a mailbox";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "set and then get the same back again";
    $imaptalk->setmetadata($folder, $fentry, $data)
        or die "Cannot setmetadata: $@";
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    my $res = $imaptalk->getmetadata($folder, $fentry)
        or die "Cannot getmetadata: $@";
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "delete the mailbox";
    $imaptalk->delete($folder)
        or die "Cannot delete mailbox $folder: $@";

    xlog $self, "create a new mailbox with the same name";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "new mailbox reports NIL for the per-mailbox metadata";
    $res = $imaptalk->getmetadata($folder, $fentry)
        or die "Cannot getmetadata: $@";
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => undef }
    }, $res);
}

sub folder_delete_mboxm_common
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    # data thanks to hipsteripsum.me
    my $folder = 'INBOX.williamsburg';
    my $fentry = '/private/comment';
    my $data = $self->make_random_data(0.3, maxreps => 15);

    xlog $self, "create a mailbox";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "set and then get the same back again";
    $imaptalk->setmetadata($folder, $fentry, $data)
        or die "Cannot setmetadata: $@";
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    my $res = $imaptalk->getmetadata($folder, $fentry)
        or die "Cannot getmetadata: $@";
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "delete the mailbox";
    $imaptalk->delete($folder)
        or die "Cannot delete mailbox $folder: $@";

    xlog $self, "cannot get metadata for deleted mailbox";
    $res = $imaptalk->getmetadata($folder, $fentry);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/does not exist/i);

    xlog $self, "create a new mailbox with the same name";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "new mailbox reports NIL for the per-mailbox metadata";
    $res = $imaptalk->getmetadata($folder, $fentry)
        or die "Cannot getmetadata: $@";
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => undef }
    }, $res);
}

sub folder_delete_msg_common
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    # data thanks to hipsteripsum.me
    my $folder = 'INBOX.williamsburg';
    my $mentry = '/comment';
    my $mattrib = 'value.priv';
    $self->{store}->set_fetch_attributes('uid', "annotation ($mentry $mattrib)");
    $self->{store}->set_folder($folder);

    xlog $self, "create a mailbox";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "add some messages";
    my $uid = 1;
    my %exp;
    for (1..10)
    {
        my $msg = $self->make_message("Message $_");
        $exp{$uid} = $msg;
        $msg->set_attribute('uid', $uid);
        my $data = $self->make_random_data(0.3, maxreps => 15);
        $msg->set_annotation($mentry, $mattrib, $data);
        $imaptalk->store('' . $uid, 'annotation',
                        [$mentry, [$mattrib, $data]]);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $uid++;
    }

    xlog $self, "Check the messages are all there";
    $self->check_messages(\%exp);

    xlog $self, "delete the mailbox";
    $imaptalk->unselect();
    $imaptalk->delete($folder)
        or die "Cannot delete mailbox $folder: $@";

    xlog $self, "create a new mailbox with the same name";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "create some new messages";
    %exp = ();
    $uid = 1;
    for (1..10)
    {
        my $msg = $self->make_message("Message NEW $_");
        $exp{$uid} = $msg;
        $msg->set_attribute('uid', $uid);
        # Note: no annotation on the new message
        $uid++;
    }

    xlog $self, "new mailbox reports NIL for the per-message metadata";
    $self->check_messages(\%exp);
}

# This is like Mail::IMAPTalk::getmetadata, but
# a) doesn't assume incorrect placement of the options, and
# b) handles the METADATA LONGENTRIES response code
sub getmetadata
{
    my ($talk, @args) = @_;

    my $res = {};

    my %handlers =
    (
        metadata => sub
        {
            my ($response, $rr, $id) = @_;
            if ($rr->[0] =~ m/^longentries/i)
            {
                $res->{longentries} = 0 + $rr->[1];
            }
            else
            {
                my $f = $talk->_unfix_folder_name($rr->[0]);
                my %kv = ( @{$rr->[1]} );
                map { $res->{$f}->{$_} = $kv{$_}; } keys %kv;
            }
        }
    );

    my $r = $talk->_imap_cmd('getmetadata', 0, \%handlers, @args);
    return if !defined $r;
    return $res;
}

use Cassandane::Tiny::Loader 'tiny-tests/Metadata';

1;
