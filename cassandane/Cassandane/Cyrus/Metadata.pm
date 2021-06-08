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

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

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

# Undo the binary escaping used by cvt_cyrusdb, which uses \xff as the
# escape character and escapes \0 \t \r \n and \xff.  We need to do this
# because both the key and value in the annotations DB use \0 as field
# separators and we need to parse them correctly.
sub unescape
{
    my ($s) = @_;
    my $r = '';

    for (;;)
    {
        my  ($pre, $byte, $post) =
                ($s =~ m/^([\0-\xfe]*)\xff([\x80-\xff])(.*)$/);
        last if !defined $byte;

        $r .= $pre;
        if ($byte eq '\xff')
        {
            $r .= '\xff';
        }
        else
        {
            $r .= chr(ord($byte) & ~0x80);
        }

        last if !defined $post;
        $s = $post;
    }

    $r .= $s;

    return $r;
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

    my $tmpfile = tmpnam();
    my $format = $instance->{config}->get('annotation_db');
    $format = $format // 'skiplist';

    $instance->run_command({ cyrus => 1 },
                        'cvt_cyrusdb',
                        $mailbox_db, $format,
                        $tmpfile, 'flat');

    my @annots;
    open TMP, '<', $tmpfile
        or die "Cannot open $tmpfile for reading: $!";
    while (<TMP>)
    {
        chomp;
        my ($key, $value) = split(/\t/, $_, 2);
        my @f = split(/\0/, unescape($key), 4);
        $value = unescape($value);

        # Damn stupid database format has sizeof(long) bytes of length.
        my ($length) = unpack("N", $value);

    # In records written by older versions of Cyrus, there will be
    # binary encoded content-type and modifiedsince values after the
    # data. We don't care about those anymore, but need to skip past
    # them the entry metadata.
    my @entry = split(/\0/, substr($value, $Config{longsize}), 3);
    my $annot = {
            uid => ($scope eq 'message' ? $f[0] : 0),
            mboxname => ($scope eq 'message' ? $mailbox : $f[0]),
            entry => $f[1],
            userid => $f[2],
            data => $entry[0],
        };

    if ($entry[2]) {
        my ($modseq, $flags) =
            unpack("Q>C", bytes::substr($entry[2], $Config{longsize}));
        if ($flags and not $tombstones) {
            next;
        }
        if ($withmdata) {
            $annot->{modseq} = $modseq;
            $annot->{flags} = $flags;
        }
    }

    if ($uids) {
        my %wantuids = map { $_ => 1 } $uids;
        if ($uids and not exists($wantuids{$annot->{uid}})) {
            next;
        }
    }

        push(@annots, $annot);
    }
    close(TMP);
    unlink($tmpfile);

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
        push(@uids, $msg->{uid});
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

#
# Test the capabilities
#
sub test_capabilities
{
    my ($self) = @_;
    my $imaptalk = $self->{store}->get_client();

    my $caps = $imaptalk->capability();
    xlog $self, "RFC5257 defines capability ANNOTATE-EXPERIMENT-1";
    $self->assert_not_null($caps->{"annotate-experiment-1"});
    xlog $self, "RFC5464 defines capability METADATA";
    $self->assert_not_null($caps->{"metadata"});
}

sub test_nonexistant_mailbox
{
    my ($self) = @_;
    my $imaptalk = $self->{store}->get_client();
    my $entry = '/shared/comment';
    my $folder = 'INBOX.nonesuch';
    # data thanks to hipsteripsum.me
    my $value1 = "Farm-to-table";

    my $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/does not exist/i);
    $self->assert_null($res);

    $res = $imaptalk->setmetadata($folder, $entry, $value1);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/does not exist/i);
    $self->assert_null($res);
}


#
# Test the cyrus annotations
#
sub test_shared
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "reading read_only Cyrus annotations";
    my $res = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/shared');
    my $r = $res->{INBOX};
    $self->assert_not_null($r);

    xlog $self, "checking specific entries";
    # Note: lastupdate will be a time string close within the
    # last second, but I'm too lazy to check that properly
    $self->assert_not_null($r->{'/shared/vendor/cmu/cyrus-imapd/lastupdate'});
    delete $r->{'/shared/vendor/cmu/cyrus-imapd/lastupdate'};
    # Note: uniqueid will be a hash of some information that
    # we can't entirely predict
    $self->assert_not_null($r->{'/shared/vendor/cmu/cyrus-imapd/uniqueid'});
    delete $r->{'/shared/vendor/cmu/cyrus-imapd/uniqueid'};
    my %specific_entries = (
            '/shared/vendor/cmu/cyrus-imapd/squat' => undef,
            '/shared/vendor/cmu/cyrus-imapd/size' => '0',
            '/shared/vendor/cmu/cyrus-imapd/sieve' => undef,
            '/shared/vendor/cmu/cyrus-imapd/sharedseen' => 'false',
            '/shared/vendor/cmu/cyrus-imapd/pop3showafter' => undef,
            '/shared/vendor/cmu/cyrus-imapd/pop3newuidl' => 'true',
            '/shared/vendor/cmu/cyrus-imapd/partition' => 'default',
            '/shared/vendor/cmu/cyrus-imapd/news2mail' => undef,
            '/shared/vendor/cmu/cyrus-imapd/lastpop' => undef,
            '/shared/vendor/cmu/cyrus-imapd/expire' => undef,
            '/shared/vendor/cmu/cyrus-imapd/duplicatedeliver' => 'false',
            '/shared/specialuse' => undef,
            '/shared/thread' => undef,
            '/shared/sort' => undef,
            '/shared/specialuse' => undef,
            '/shared/comment' => undef,
            '/shared/checkperiod' => undef,
            '/shared/check' => undef,
            '/shared' => undef,
    );
    # Note: annotsize/synccrcs new in 3.0
    my ($maj, $min, $rev) = Cassandane::Instance->get_version();
    if ($maj >= 3) {
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/annotsize'} = '0';
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/synccrcs'} = '0 0';
    }
    # We introduced vendor/cmu/cyrus-imapd/{archive,delete} in 3.1.0
    if ($maj > 3 or ($maj == 3 and $min >= 1)) {
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/archive'} = undef;
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/delete'} = undef;
    }
    # We introduced vendor/cmu/cyrus-imapd/sortorder in 3.1.3
    if ($maj > 3 or ($maj == 3 and ($min > 1 or ($min == 1 and $rev >= 3)))) {
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/sortorder'} = undef;
    }
    # synccrcs got a new default in 3.1.7, and hasalarms got added
    # XXX Not sure how useful it is to keep subdividing our 3.1 tests, we
    # XXX expect this unstable series to be a moving target.  Once 3.2 forks
    # XXX I think we def should collapse all these 3.1s into a single 3.1
    if ($maj > 3 or ($maj == 3 and ($min > 1 or ($min == 1 and $rev >= 7)))) {
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/synccrcs'} =
            '0 12345678';
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/hasalarms'} = 'false';
    }
    # foldermodsseq was added in 3.2.0
    if ($maj > 3 or ($maj == 3 and ($min > 1))) {
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/foldermodseq'} = 4;
    }
    # We introduced vendor/cmu/cyrus-imapd/search-fuzzy-always in 3.3.0
    if ($maj > 3 or ($maj == 3 and $min >= 3)) {
        $specific_entries{'/shared/vendor/cmu/cyrus-imapd/search-fuzzy-always'} = undef;
    }
    $self->assert_deep_equals(\%specific_entries, $r);

    # individual item fetch:
    my $part = $imaptalk->getmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/partition");
    $self->assert_str_equals('default', $part->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/partition"});

    # duplicate deliver should be false
    $self->assert_str_equals('false', $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/duplicatedeliver"});

    # set duplicate deliver (as admin)
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setmetadata('user.cassandane', "/shared/vendor/cmu/cyrus-imapd/duplicatedeliver", 'true');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # and make sure the change sticks
    my $dup = $imaptalk->getmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/duplicatedeliver");
    $self->assert_str_equals('true', $dup->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/duplicatedeliver"});
}

#
# Test the /private/specialuse annotation defined by RFC6154.
#
sub test_specialuse
{
    my ($self) = @_;

    xlog $self, "testing /private/specialuse";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $entry = '/private/specialuse';
    my $sentry = '/shared/specialuse';
    my @testcases = (
        # Cyrus has no virtual folders, so cannot do \All
        {
            folder => 'a',
            specialuse => '\All',
            result => 'no'
        },
        {
            folder => 'b',
            specialuse => '\Archive',
            result => 'ok'
        },
        {
            folder => 'c',
            specialuse => '\Drafts',
            result => 'ok'
        },
        # Cyrus has no virtual folders, so cannot do \Flagged
        {
            folder => 'd',
            specialuse => '\Flagged',
            result => 'no'
        },
        {
            folder => 'e',
            specialuse => '\Junk',
            result => 'ok'
        },
        {
            folder => 'f',
            specialuse => '\Sent',
            result => 'ok'
        },
        {
            folder => 'g',
            specialuse => '\Trash',
            result => 'ok'
        },
        # Tokens not defined in the RFC are rejected
        {
            folder => 'h',
            specialuse => '\Nonesuch',
            result => 'no'
        },
    );

    xlog $self, "First create all the folders";
    foreach my $tc (@testcases)
    {
        $imaptalk->create("INBOX.$tc->{folder}")
            or die "Cannot create mailbox INBOX.$tc->{folder}: $@";
    }

    foreach my $tc (@testcases)
    {
        my $folder = "INBOX.$tc->{folder}";

        xlog $self, "initial value for $folder is NIL";
        $res = $imaptalk->getmetadata($folder, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);
        delete $res->{$sentry}; # may return a shared entry as well...
        $self->assert_deep_equals({
            $folder => { $entry => undef }
        }, $res);

        xlog $self, "can set $folder to $tc->{specialuse}";
        $imaptalk->setmetadata($folder, $entry, $tc->{specialuse});
        $self->assert_str_equals($tc->{result}, $imaptalk->get_last_completion_response());

        xlog $self, "can get the set value back";
        $res = $imaptalk->getmetadata($folder, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);
        delete $res->{$sentry}; # may return a shared entry as well...
        my $expected = {
                $folder => { $entry => ($tc->{result} eq 'ok' ?  $tc->{specialuse} : undef) }
            };
        $self->assert_deep_equals($expected, $res);
    }

    xlog $self, "can get same values in a new connection";
    $self->{store}->disconnect();
    $imaptalk = $self->{store}->get_client();

    foreach my $tc (@testcases)
    {
        my $folder = "INBOX.$tc->{folder}";

        $res = $imaptalk->getmetadata($folder, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);
        delete $res->{$sentry}; # may return a shared entry as well...
        my $expected = {
                $folder => { $entry => ($tc->{result} eq 'ok' ?  $tc->{specialuse} : undef) }
            };
        $self->assert_deep_equals($expected, $res);
    }

    xlog $self, "can delete values";
    foreach my $tc (@testcases)
    {
        next unless ($tc->{result} eq 'ok');
        my $folder = "INBOX.$tc->{folder}";

        $imaptalk->setmetadata($folder, $entry, undef);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

        $res = $imaptalk->getmetadata($folder, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);
        delete $res->{$sentry}; # may return a shared entry as well...
        my $expected = {
                $folder => { $entry => undef }
            };
        $self->assert_deep_equals($expected, $res);
    }

}

sub test_createspecialuse
    :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "testing create specialuse";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $entry = '/private/specialuse';
    my $folder = "INBOX.Archive";
    my $use = "\\Archive";
    $imaptalk->create($folder, "(USE ($use))")
        or die "Cannot create mailbox $folder with special-use $use: $@";

    xlog $self, "initial value for $folder is $use";
    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        $folder => { $entry => $use }
    }, $res);
}

sub test_comment
{
    my ($self) = @_;

    xlog $self, "testing /shared/comment";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $entry = '/shared/comment';
    my $value1 = "Hello World this is a value";

    xlog $self, "initial value is NIL";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    xlog $self, "cannot set the value as ordinary user";
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/permission denied/i);

    xlog $self, "can set the value as admin";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "can get the set value back";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "the annot gives the same value in a new connection";
    $self->{adminstore}->disconnect();
    $imaptalk = $self->{adminstore}->get_client();
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "can delete value";
    $imaptalk->setmetadata("", $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => undef }
    };
    $self->assert_deep_equals($expected, $res);
}

sub test_comment_repl
    :Replication :SyncLog
{
    my ($self) = @_;

    xlog $self, "testing /shared/comment";

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->assert_not_null($self->{replica});

    my $imaptalk = $self->{master_store}->get_client();

    my $res;
    my $entry = '/shared/comment';
    my $value1 = "Hello World this is a value";

    xlog $self, "initial value is NIL";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    xlog $self, "can set the value as admin";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "replica value is NIL";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    xlog $self, "the annot gives the same value on the replica";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "can delete value";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => undef }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "run replication to clear annot";
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    xlog $self, "replica value is NIL";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

}

#
# Test the /shared/motd server annotation.
#
# Note: this needs the Mail::IMAPTalk install to have commit
# "Alert reponse is remainder of line, put that in the response code"
#
sub test_motd
{
    my ($self) = @_;

    xlog $self, "testing /shared/motd";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $entry = '/shared/motd';
    my $value1 = "Hello World this is a value";

    xlog $self, "No ALERT was received when we connected";
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    $self->assert_null($imaptalk->get_response_code('alert'));

    xlog $self, "initial value is NIL";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    xlog $self, "cannot set the value as ordinary user";
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/permission denied/i);

    xlog $self, "can set the value as admin";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "can get the set value back";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "a new connection will get an ALERT with the motd value";
    $self->{adminstore}->disconnect();
    $imaptalk = $self->{adminstore}->get_client();
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    my $alert = $imaptalk->get_response_code('alert');
    $self->assert_not_null($alert);
    $self->assert_str_equals($value1, $alert);

    xlog $self, "the annot gives the same value in the new connection";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "can delete value";
    $imaptalk->setmetadata("", $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => undef }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "a new connection no longer gets an ALERT";
    $self->{adminstore}->disconnect();
    $imaptalk = $self->{adminstore}->get_client();
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    $self->assert_null($imaptalk->get_response_code('alert'));
}

#
# Test the /shared/foobar server annotation replicates correctly
#
sub test_shared_global_annot_replication
    :Replication :SyncLog :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog $self, "testing /shared/foobar";

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->assert_not_null($self->{replica});

    my $imaptalk = $self->{master_store}->get_client();

    my $res;
    my $entry = '/shared/foobar';
    my $value1 = "Hello World this is a value - with a random annot";

    xlog $self, "initial value is NIL";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    xlog $self, "cannot set the value as ordinary user";
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/permission denied/i);

    xlog $self, "can set the value as admin";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "can get the set value back";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    $self->{adminstore}->disconnect();
    $imaptalk = $self->{adminstore}->get_client();

    xlog $self, "the annot gives the same value in the new connection";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "replica value is NIL";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    xlog $self, "the annot gives the same value on the replica";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "can delete value";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => undef }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "run replication to clear annot";
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    xlog $self, "replica value is NIL";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);
}

#
# Test the /private/foobar server annotation replicates correctly
#
sub test_private_global_annot_replication
    :Replication :SyncLog :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog $self, "testing /private/foobar";

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->assert_not_null($self->{replica});

    my $imaptalk = $self->{master_store}->get_client();

    my $res;
    my $entry = '/private/foobar';
    my $value1 = "Hello World this is a value - with a random annot";

    xlog $self, "initial value is NIL";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    xlog $self, "can set the value as ordinary user";
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "can get the set value back";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    $self->{master_store}->disconnect();
    $imaptalk = $self->{master_store}->get_client();

    xlog $self, "the annot gives the same value in the new connection";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "replica value is NIL";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);

    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    xlog $self, "the annot gives the same value on the replica";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "can delete value";
    $imaptalk = $self->{master_store}->get_client();
    $imaptalk->setmetadata("", $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
            "" => { $entry => undef }
    };
    $self->assert_deep_equals($expected, $res);

    xlog $self, "run replication to clear annot";
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    unlink($synclogfname);

    xlog $self, "replica value is NIL";
    $imaptalk = $self->{replica_store}->get_client();
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
        "" => { $entry => undef }
    }, $res);
}

#
# Test the /shared/vendor/cmu/cyrus-imapd/size annotation
# which reports the total byte count of the RFC822 message
# sizes in the mailbox.
#
sub test_size
{
    my ($self) = @_;

    xlog $self, "testing /shared/vendor/cmu/cyrus-imapd/size";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $folder_cass = 'INBOX';
    my $folder_admin = 'user.cassandane';
    $self->{store}->set_folder($folder_cass);
    my $entry = '/shared/vendor/cmu/cyrus-imapd/size';

    xlog $self, "initial value is numeric zero";
    $res = $imaptalk->getmetadata($folder_cass, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder_cass => { $entry => "0" }
    }, $res);

    xlog $self, "cannot set the value as ordinary user";
    $imaptalk->setmetadata($folder_cass, $entry, '123');
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/permission denied/i);

    xlog $self, "cannot set the value as admin either";
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setmetadata($folder_admin, $entry, '123');
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert($admintalk->get_last_error() =~ m/permission denied/i);

    xlog $self, "adding a message bumps the value by the message's size";
    my $expected = 0;
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $expected += length($msg{A}->as_string());

    $res = $imaptalk->getmetadata($folder_cass, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder_cass => { $entry => "" . $expected }
    }, $res);

    xlog $self, "adding a 2nd message bumps the value by the message's size";
    $msg{B} = $self->make_message('Message B');
    $expected += length($msg{B}->as_string());

    $res = $imaptalk->getmetadata($folder_cass, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder_cass => { $entry => "" . $expected }
    }, $res);

    # TODO: removing a message doesn't reduce the value until (possibly delayed) expunge
}

sub test_uniqueid
    :ImmediateDelete
{
    my ($self) = @_;

    xlog $self, "testing /shared/vendor/cmu/cyrus-imapd/uniqueid";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    # data thanks to hipsteripsum.me
    my @folders = ( qw(INBOX.etsy INBOX.etsy
                       INBOX.sartorial
                       INBOX.dreamcatcher.keffiyeh) );
    my @uuids;
    my %uuids_seen;
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';

    xlog $self, "create the folders";
    foreach my $f (@folders)
    {
        $imaptalk->create($f)
            or die "Cannot create mailbox $f: $@";
        $res = $imaptalk->getmetadata($f, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);
        my $uuid = $res->{$f}{$entry};
        $self->assert_not_null($uuid);
        $self->assert($uuid =~ m/^[0-9a-z-]+$/);
        $imaptalk->delete($f)
            or die "Cannot delete mailbox $f: $@";
        push(@uuids, $uuid);
        # all the uniqueids must be unique (duh)
        $self->assert(!defined $uuids_seen{$uuid});
        $uuids_seen{$uuid} = 1;
    }

    # Do the logging in a 2nd pass in the hope of maximising
    # our chances of getting all the creates in one second
    for (my $i = 0 ; $i < scalar(@folders) ; $i++)
    {
        xlog $self, "uniqueid of " . $folders[$i] . " was \"" . $uuids[$i] .  "\"";
    }
}


sub test_private
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "testing private metadata operations";

    xlog $self, "testing specific entries";
    my $res = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/private');
    my $r = $res->{INBOX};
    $self->assert_not_null($r);
    my %specific_entries = (
            '/private/vendor/cmu/cyrus-imapd/squat' => undef,
            '/private/vendor/cmu/cyrus-imapd/sieve' => undef,
            '/private/vendor/cmu/cyrus-imapd/news2mail' => undef,
            '/private/vendor/cmu/cyrus-imapd/expire' => undef,
            '/private/thread' => undef,
            '/private/sort' => undef,
            '/private/comment' => undef,
            '/private/checkperiod' => undef,
            '/private/check' => undef,
            '/private/specialuse' => undef,
            '/private' => undef,
    );
    my ($maj, $min, $rev) = Cassandane::Instance->get_version();
    # We introduced vendor/cmu/cyrus-imapd/{archive,delete} in 3.1.0
    if ($maj > 3 or ($maj == 3 and $min >= 1)) {
        $specific_entries{'/private/vendor/cmu/cyrus-imapd/archive'} = undef;
        $specific_entries{'/private/vendor/cmu/cyrus-imapd/delete'} = undef;
    }
    # We introduced vendor/cmu/cyrus-imapd/sortorder in 3.1.3
    if ($maj > 3 or ($maj == 3 and ($min > 1 or ($min == 1 and $rev >= 3)))) {
        $specific_entries{'/private/vendor/cmu/cyrus-imapd/sortorder'} = undef;
    }
    # We introduced vendor/cmu/cyrus-imapd/search-fuzzy-always in 3.3.0
    if ($maj > 3 or ($maj == 3 and $min >= 3)) {
        $specific_entries{'/private/vendor/cmu/cyrus-imapd/search-fuzzy-always'} = undef;
    }
    $self->assert_deep_equals(\%specific_entries, $r);

    $imaptalk->setmetadata('INBOX', "/private/comment", "This is a comment");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    my $com = $imaptalk->getmetadata('INBOX', "/private/comment");
    $self->assert_str_equals("This is a comment", $com->{INBOX}{"/private/comment"});

    # remove it again
    $imaptalk->setmetadata('INBOX', "/private/comment", undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $com = $imaptalk->getmetadata('INBOX', "/private/comment");
    $self->assert_null($com->{INBOX}{"/private/comment"});
}

sub test_embedded_nuls
{
    my ($self) = @_;

    xlog $self, "testing getting and setting embedded NULs";

    my $imaptalk = $self->{store}->get_client();
    my $folder = 'INBOX.test_embedded_nuls';
    my $entry = '/private/comment';
    my $binary = "Hello\0World";

    xlog $self, "create a temporary mailbox";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "initially, NIL is reported";
    my $res = $imaptalk->getmetadata($folder, $entry)
        or die "Cannot get metadata: $@";
    $self->assert_num_equals(1, scalar keys %$res);
    $self->assert_null($res->{$folder}{$entry});

    xlog $self, "set and then get the same back again";
    $imaptalk->setmetadata($folder, $entry, $binary);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals($binary, $res->{$folder}{$entry});

    xlog $self, "remove it again";
    $imaptalk->setmetadata($folder, $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "check it's gone now";
    $res = $imaptalk->getmetadata($folder, $entry)
        or die "Cannot get metadata: $@";
    $self->assert_num_equals(1, scalar keys %$res);
    $self->assert_null($res->{$folder}{$entry});

    xlog $self, "clean up temporary mailbox";
    $imaptalk->delete($folder)
        or die "Cannot delete mailbox $folder: $@";
}

sub test_permessage_getset
{
    my ($self) = @_;

    xlog $self, "testing getting and setting message scope annotations";

    my $talk = $self->{store}->get_client();

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{B} = $self->make_message('Message B');
    $msg{C} = $self->make_message('Message C');

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";
    my $value2 = "Goodnight\0Irene";
    my $value3 = "Gump";

    xlog $self, "fetch an annotation - should be no values";
    my $res = $talk->fetch('1:*',
                           ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => undef } } },
                2 => { annotation => { $entry => { $attrib => undef } } },
                3 => { annotation => { $entry => { $attrib => undef } } },
            },
            $res);

    xlog $self, "store an annotation";
    $talk->store('1', 'annotation',
                 [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => $value1 } } },
                2 => { annotation => { $entry => { $attrib => undef } } },
                3 => { annotation => { $entry => { $attrib => undef } } },
            },
            $res);

    xlog $self, "store an annotation with an embedded NUL";
    $talk->store('3', 'annotation',
                 [$entry, [$attrib, $value2]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => $value1 } } },
                2 => { annotation => { $entry => { $attrib => undef } } },
                3 => { annotation => { $entry => { $attrib => $value2 } } },
            },
            $res);

    xlog $self, "store multiple annotations";
    # Note $value3 has no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('1:*', 'annotation',
                 [$entry, [$attrib, { Quote => $value3 }]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => $value3 } } },
                2 => { annotation => { $entry => { $attrib => $value3 } } },
                3 => { annotation => { $entry => { $attrib => $value3 } } },
            },
            $res);

    xlog $self, "delete an annotation";
    # Note $value3 has no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('2', 'annotation',
                 [$entry, [$attrib, undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => $value3 } } },
                2 => { annotation => { $entry => { $attrib => undef } } },
                3 => { annotation => { $entry => { $attrib => $value3 } } },
            },
            $res);

    xlog $self, "delete all annotations";
    # Note $value3 has no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('1:*', 'annotation',
                 [$entry, [$attrib, undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => undef } } },
                2 => { annotation => { $entry => { $attrib => undef } } },
                3 => { annotation => { $entry => { $attrib => undef } } },
            },
            $res);
}

sub test_permessage_unknown
{
    my ($self) = @_;

    xlog $self, "testing getting and setting unknown annotations on a message";
    xlog $self, "where this is forbidden by the default config";

    xlog $self, "Append a message";
    my %msg;
    $msg{A} = $self->make_message('Message A');

    my $entry = '/thisentryisnotdefined';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    xlog $self, "fetch annotation - should be no values";
    my $talk = $self->{store}->get_client();
    my $res = $talk->fetch('1:*',
                           ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => undef } } }
            },
            $res);

    xlog $self, "store annotation - should fail";
    $talk->store('1', 'annotation',
                 [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see nothing";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => undef } } }
            },
            $res);
}

sub test_permessage_unknown_allowed
    :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog $self, "testing getting and setting unknown annotations on a message";
    xlog $self, "with config allowing this";

    xlog $self, "Append a message";
    my %msg;
    $msg{A} = $self->make_message('Message A');

    my $entry = '/thisentryisnotdefined';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    xlog $self, "fetch annotation - should be no values";
    my $talk = $self->{store}->get_client();
    my $res = $talk->fetch('1:*',
                           ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => undef } } }
            },
            $res);

    xlog $self, "store annotation - should succeed";
    $talk->store('1', 'annotation',
                 [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch the annotation again, should see the value";
    $res = $talk->fetch('1:*',
                        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => { annotation => { $entry => { $attrib => $value1 } } }
            },
            $res);
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

sub test_msg_replication_new_mas
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case new_mas: new message appears, on master only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_new_rep
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case new_rep: new message appears, on replica only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $replica_exp{A} = $self->make_message('Message A', store => $replica_store);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $value1);
    $replica_exp{A}->set_attribute('uid', 1);
    $replica_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before replication, message is missing from the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before replication, message is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    $master_exp{A} = $replica_exp{A}->clone();
    xlog $self, "After replication, message is now present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After replication, message is still present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_new_bot_mse_gul
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case new_bot_mse_gul: new messages appear, on both master " .
         "and replica, with equal modseqs, lower GUID on master.";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA = "Hello World";
    my $valueB = "Hello Dolly";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation to each store";
    my ($msgA, $msgB) = $self->make_message_pair($master_store, $replica_store);
    my %master_exp = ( A => $msgA );
    my %replica_exp = ( B => $msgB );
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB);
    $replica_exp{B}->set_attribute('uid', 1);
    $replica_exp{B}->set_annotation($entry, $attrib, $valueB);

    xlog $self, "Before replication, only message A is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before replication, only message B is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, both messages are now present and renumbered on the master";
    $master_exp{B} = $replica_exp{B}->clone();
    $master_exp{A}->set_attribute('uid', 2);
    $master_exp{B}->set_attribute('uid', 3);
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After replication, both messages are now present and renumbered on the replica";
    $replica_exp{A} = $master_exp{A}->clone();
    $replica_exp{A}->set_attribute('uid', 2);
    $replica_exp{B}->set_attribute('uid', 3);
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR or two
        my @lines = $self->{instance}->getsyslog();

        my $pattern = qr{
            \bSYNCERROR:\sguid\smismatch
            (?: \suser\.cassandane\s1\b
              | :\smailbox=<user\.cassandane>\suid=<1>
            )
        }x;

        $self->assert_matches($pattern, "@lines");
    }
}

sub test_msg_replication_new_bot_mse_guh
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case new_bot_mse_guh: new messages appear, on both master " .
         "and replica, with equal modseqs, higher GUID on master.";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA = "Hello World";
    my $valueB = "Hello Dolly";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation to each store";
    my ($msgB, $msgA) = $self->make_message_pair($replica_store, $master_store);
    my %master_exp = ( A => $msgA );
    my %replica_exp = ( B => $msgB );
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB);
    $replica_exp{B}->set_attribute('uid', 1);
    $replica_exp{B}->set_annotation($entry, $attrib, $valueB);

    xlog $self, "Before replication, only message A is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before replication, only message B is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After replication, both messages are now present and renumbered on the master";
    $master_exp{B} = $replica_exp{B}->clone();
    $master_exp{B}->set_attribute('uid', 2);
    $master_exp{A}->set_attribute('uid', 3);
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After replication, both messages are now present and renumbered on the replica";
    $replica_exp{A} = $master_exp{A}->clone();
    $replica_exp{B}->set_attribute('uid', 2);
    $replica_exp{A}->set_attribute('uid', 3);
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR or two
        my @lines = $self->{instance}->getsyslog();

        my $pattern = qr{
            \bSYNCERROR:\sguid\smismatch
            (?: \suser\.cassandane\s1\b
              | :\smailbox=<user\.cassandane>\suid=<1>
            )
        }x;

        $self->assert_matches($pattern, "@lines");
    }
}


sub test_msg_replication_mod_mas
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case mod_mas: message is modified, on master only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Set an annotation on the master";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before second replication, the message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, the message annotation is missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After second replication, the message annotation is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message annotation is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}


sub test_msg_replication_mod_rep
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case mod_rep: message is modified, on replica only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Set an annotation on the master";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before second replication, the message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, the message annotation is missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After second replication, the message annotation is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message annotation is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_mod_bot_msl
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case mod_bot_msl: message is modified, on both ends, " .
         "modseq lower on master";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA = "Hello World";
    my $valueB1 = "Jeepers";
    my $valueB2 = "Creepers";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Set an annotation once on the master, twice on the replica";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB1);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB2);
    $replica_exp{A}->set_annotation($entry, $attrib, $valueB2);

    xlog $self, "Before second replication, one message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, a different message annotation is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the annotation change";
    $self->run_replication();
    $self->check_replication('cassandane');

    $master_exp{A}->set_annotation($entry, $attrib, $valueB2);
    xlog $self, "After second replication, the message annotation is updated on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message annotation is still present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_mod_bot_msh
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case mod_bot_msh: message is modified, on both ends, " .
         "modseq higher on master";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA1 = "Hello World";
    my $valueA2 = "and friends";
    my $valueB = "Jeepers";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Set an annotation twice on the master, once on the replica";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA1);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA2);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA2);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB);
    $replica_exp{A}->set_annotation($entry, $attrib, $valueB);

    xlog $self, "Before second replication, one message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, a different message annotation is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the annotation change";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A}->set_annotation($entry, $attrib, $valueA2);
    xlog $self, "After second replication, the message annotation is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message annotation is updated on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_exp_mas
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case exp_mas: message is expunged, on master only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    delete $master_exp{A};
    xlog $self, "Before second replication, the message is now missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, the message is still present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the expunge";
    $self->run_replication();
    $self->check_replication('cassandane');

    delete $replica_exp{A};
    xlog $self, "After second replication, the message is still missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message is now missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_exp_rep
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case exp_rep: message is expunged, on replica only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Delete and expunge the message on the replica";
    my $talk = $replica_store->get_client();
    $replica_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    delete $replica_exp{A};
    xlog $self, "Before second replication, the message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, the message is now missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the expunge";
    $self->run_replication();
    $self->check_replication('cassandane');

    delete $master_exp{A};
    xlog $self, "After second replication, the message is now missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message is still missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_exp_bot
{
    my ($self) = @_;

    xlog $self, "testing replication of message scope annotations";
    xlog $self, "case exp_bot: message is expunged, on both ends";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog $self, "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the message";
    $self->run_replication();
    $self->check_replication('cassandane');

    $replica_exp{A} = $master_exp{A}->clone();
    xlog $self, "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    xlog $self, "Delete and expunge the message on the replica";
    $talk = $replica_store->get_client();
    $replica_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    delete $master_exp{A};
    delete $replica_exp{A};
    xlog $self, "Before second replication, the message is now missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "Before second replication, the message is now missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Replicate the expunge";
    $self->run_replication();
    $self->check_replication('cassandane');

    xlog $self, "After second replication, the message is still missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog $self, "After second replication, the message is still missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog $self, "Check that annotations in the master and replica DB match";
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_new_mas_partial_wwsw
{
    my ($self) = @_;

    xlog $self, "testing partial replication of message scope annotations";
    xlog $self, "case master to replica: write, write, sync, write";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);

    xlog $self, "Write an annotation twice";
    $self->set_msg_annotation($master_store, 1, '/comment', 'value.priv', 'c1');
    $self->set_msg_annotation($master_store, 1, '/comment', 'value.priv', 'c2');

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);

    xlog $self, "Write another annotation";
    $self->set_msg_annotation($master_store, 1, '/altsubject', 'value.priv', 'a1');

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_replication_new_mas_partial_wwd
{
    my ($self) = @_;

    xlog $self, "testing partial replication of message scope annotations";
    xlog $self, "case master to replica: write, write, delete";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};

    xlog $self, "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);

    xlog $self, "Write an annotation";
    $self->set_msg_annotation($master_store, 1, '/comment', 'value.priv', 'c1');

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);

    xlog $self, "Write another annotation";
    $self->set_msg_annotation($master_store, 1, '/altsubject', 'value.priv', 'a1');

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);

    xlog $self, "Delete the first annotation";
    $self->set_msg_annotation($master_store, 1, '/comment', 'value.priv', '');

    xlog $self, "Run replication";
    $self->run_replication();
    $self->check_msg_annotation_replication($master_store, $replica_store);
}

sub test_msg_sort_order
{
    my ($self) = @_;

    xlog $self, "testing RFC5257 SORT command ANNOTATION order criterion";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    # 20 random dictionary words
    my @values = ( qw(gradual flips tempe cud flaunt nina crackle congo),
                   qw(buttons coating byrd arise ayyubid badgers argosy),
                   qw(sutton dallied belled fondues mimi) );
    # the expected result of sorting those words alphabetically
    my @exp_order = ( 15, 12, 13, 14, 18, 9, 11, 10, 8,
                      7, 4, 17, 5, 2, 19, 1, 20, 6, 16, 3 );

    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append some messages and store annotations";
    my %exp;
    for (my $i = 0 ; $i < 20 ; $i++)
    {
        my $letter = chr(ord('A')+$i);
        my $uid = $i+1;
        my $value = $values[$i];

        $exp{$letter} = $self->make_message("Message $letter");
        $self->set_msg_annotation(undef, $uid, $entry, $attrib, $value);
        $exp{$letter}->set_attribute('uid', $uid);
        $exp{$letter}->set_annotation($entry, $attrib, $value);
    }
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    xlog $self, "run the SORT command with an ANNOTATION order criterion";
    my $res = $talk->sort("(ANNOTATION $entry $attrib)", 'utf-8', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(\@exp_order, $res);
}

sub test_msg_sort_search
{
    my ($self) = @_;

    xlog $self, "testing RFC5257 SORT command ANNOTATION search criterion";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    # 10 random dictionary words, and 10 carefully chosen ones
    my @values = ( qw(deirdre agreed feedback cuspids breeds decreed greedily),
                   qw(gibbers eakins flash needful yules linseed equine hangman),
                   qw(hatters ragweed pureed cloaked heedless) );
    # the expected result of sorting the words with 'eed' alphabetically
    my @exp_order = ( 2, 5, 6, 3, 7, 20, 13, 11, 18, 17 );
    # the expected result of search for words with 'eed' and uid order
    my @exp_search = ( 2, 3, 5, 6, 7, 11, 13, 17, 18, 20 );

    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $now = DateTime->now->epoch;
    for (my $i = 0 ; $i < 20 ; $i++)
    {
        my $letter = chr(ord('A')+$i);
        my $uid = $i+1;
        my $value = $values[$i];
        my $date = DateTime->from_epoch(epoch => $now - (20-$i)*60);

        $exp{$letter} = $self->make_message("Message $letter",
                                            date => $date);
        $self->set_msg_annotation(undef, $uid, $entry, $attrib, $value);
        $exp{$letter}->set_attribute('uid', $uid);
        $exp{$letter}->set_annotation($entry, $attrib, $value);
    }
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    xlog $self, "run the SORT command with an ANNOTATION search criterion";
    my $res = $talk->sort("(DATE)", 'utf-8',
                          'ANNOTATION', $entry, $attrib, { Quote => "eed" });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(\@exp_search, $res);

    xlog $self, "run the SORT command with both ANNOTATION search & order criteria";
    $res = $talk->sort("(ANNOTATION $entry $attrib)", 'utf-8',
                       'ANNOTATION', $entry, $attrib, { Quote => "eed" });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(\@exp_order, $res);
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

#
# Test interaction between RFC4551 modseq and STORE ANNOTATION
#  - setting an annotation the message's modseq
#    and the folder's highestmodseq
#  - deleting an annotation bumps the message's modseq etc
#  - modseq of other messages is never affected
#
sub test_modseq
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid modseq));

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{B} = $self->make_message('Message B');
    $msg{C} = $self->make_message('Message C');

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    xlog $self, "fetch an annotation - should be no values";
    my $hms0 = $self->get_highestmodseq();
    my $res = $talk->fetch('1:*',
                           ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => {
                        modseq => [$hms0-2],
                        annotation => { $entry => { $attrib => undef } }
                     },
                2 => {
                        modseq => [$hms0-1],
                        annotation => { $entry => { $attrib => undef } }
                     },
                3 => {
                        modseq => [$hms0],
                        annotation => { $entry => { $attrib => undef } }
                     },
            },
            $res);

    xlog $self, "store an annotation";
    $talk->store('1', 'annotation',
                 [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch an annotation - should be updated";
    my $hms1 = $self->get_highestmodseq();
    $self->assert($hms1 > $hms0);
    $res = $talk->fetch('1:*',
                        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => {
                        modseq => [$hms1],
                        annotation => { $entry => { $attrib => $value1 } }
                     },
                2 => {
                        modseq => [$hms0-1],
                        annotation => { $entry => { $attrib => undef } }
                     },
                3 => {
                        modseq => [$hms0],
                        annotation => { $entry => { $attrib => undef } }
                     },
            },
            $res);

    xlog $self, "delete an annotation";
    $talk->store('1', 'annotation',
                 [$entry, [$attrib, undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch an annotation - should be updated";
    my $hms2 = $self->get_highestmodseq();
    $self->assert($hms2 > $hms1);
    $res = $talk->fetch('1:*',
                        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => {
                        modseq => [$hms2],
                        annotation => { $entry => { $attrib => undef } }
                     },
                2 => {
                        modseq => [$hms0-1],
                        annotation => { $entry => { $attrib => undef } }
                     },
                3 => {
                        modseq => [$hms0],
                        annotation => { $entry => { $attrib => undef } }
                     },
            },
            $res);
}

#
# Test UNCHANGEDSINCE modifier; RFC4551 section 3.2.
# - changing an annotation with current modseq equal to the
#   UNCHANGEDSINCE value
#       - updates the annotation
#       - updates modseq
#       - sends an untagged FETCH response
#       - the FETCH response has the new modseq
#       - returns an OK response
#       - the UID does not appear in the MODIFIED response code
# - ditto less than
# - changing an annotation with current modseq greater than the
#   UNCHANGEDSINCE value
#       - doesn't update the annotation
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
    $self->{store}->set_fetch_attributes(qw(uid modseq));

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{B} = $self->make_message('Message B');
    $msg{C} = $self->make_message('Message C');
    my $hms0 = $self->get_highestmodseq();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";
    my $value2 = "Janis Joplin";
    my $value3 = "Phantom of the Opera";

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

    xlog $self, "setting an annotation with current modseq == UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 '1', ['unchangedsince', $hms0-2],
                 'annotation', [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch an annotation - should be updated";
    my $hms1 = $self->get_highestmodseq();
    $self->assert($hms1 > $hms0);
    my $res = $talk->fetch('1:*',
                           ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => {
                        modseq => [$hms1],
                        annotation => { $entry => { $attrib => $value1 } }
                     },
                2 => {
                        modseq => [$hms0-1],
                        annotation => { $entry => { $attrib => undef } }
                     },
                3 => {
                        modseq => [$hms0],
                        annotation => { $entry => { $attrib => undef } }
                     },
            },
            $res);

    xlog $self, "setting an annotation with current modseq < UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 '1', ['unchangedsince', $hms1+1],
                 'annotation', [$entry, [$attrib, $value2]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "fetch an annotation - should be updated";
    my $hms2 = $self->get_highestmodseq();
    $self->assert($hms2 > $hms1);
    $res = $talk->fetch('1:*',
                        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => {
                        modseq => [$hms2],
                        annotation => { $entry => { $attrib => $value2 } }
                     },
                2 => {
                        modseq => [$hms0-1],
                        annotation => { $entry => { $attrib => undef } }
                     },
                3 => {
                        modseq => [$hms0],
                        annotation => { $entry => { $attrib => undef } }
                     },
            },
            $res);

    xlog $self, "setting an annotation with current modseq > UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
                 '1', ['unchangedsince', $hms2-1],
                 'annotation', [$entry, [$attrib, $value3]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "didn't update modseq?";
    my $hms3 = $self->get_highestmodseq();
    $self->assert($hms3 == $hms2);
    xlog $self, "fetch an annotation - should not be updated";
    $res = $talk->fetch('1:*',
                        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
            {
                1 => {
                        # unchanged
                        modseq => [$hms2],
                        annotation => { $entry => { $attrib => $value2 } }
                     },
                2 => {
                        modseq => [$hms0-1],
                        annotation => { $entry => { $attrib => undef } }
                     },
                3 => {
                        modseq => [$hms0],
                        annotation => { $entry => { $attrib => undef } }
                     },
            },
            $res);
    xlog $self, "reports the UID in the MODIFIED response code?";
    $self->assert_not_null($modified);
    $self->assert_deep_equals($modified, [1]);
    xlog $self, "sent no FETCH untagged response?";
    $self->assert_num_equals(0, scalar keys %fetched);
}


sub test_mbox_replication_new_mas
{
    my ($self) = @_;

    xlog $self, "testing replication of mailbox scope annotations";
    xlog $self, "case new_mas: new message appears, on master only";

    xlog $self, "need a master and replica pair";
    $self->assert_not_null($self->{replica});
    my $master_store = $self->{master_store};
    my $replica_store = $self->{replica_store};
    my $master_talk = $master_store->get_client();
    my $replica_talk = $replica_store->get_client();

    my $folder = 'INBOX';
    my $entry = '/private/comment';
    my $value1 = "Hello World";
    my $res;

    xlog $self, "store an annotation";
    $master_talk->setmetadata($folder, $entry, $value1);
    $self->assert_str_equals('ok', $master_talk->get_last_completion_response());

    xlog $self, "Before replication, annotation is present on the master";
    $res = $master_talk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $master_talk->get_last_completion_response());
    $self->assert_deep_equals({ $folder => { $entry => $value1 } }, $res);

    xlog $self, "Before replication, annotation is missing from the replica";
    $res = $replica_talk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $replica_talk->get_last_completion_response());
    $self->assert_deep_equals({ $folder => { $entry => undef } }, $res);

    xlog $self, "run replication";
    $self->run_replication();
    $self->check_replication('cassandane');
    $master_talk = $master_store->get_client();
    $replica_talk = $replica_store->get_client();

    xlog $self, "After replication, annotation is still present on the master";
    $res = $master_talk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $master_talk->get_last_completion_response());
    $self->assert_deep_equals({ $folder => { $entry => $value1 } }, $res);

    xlog $self, "After replication, annotation is now present on the replica";
    $res = $replica_talk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $replica_talk->get_last_completion_response());
    $self->assert_deep_equals({ $folder => { $entry => $value1 } }, $res);
}

# sub test_mbox_replication_new_rep
# sub test_mbox_replication_new_bot
# sub test_mbox_replication_mod_mas
# sub test_mbox_replication_mod_rep
# sub test_mbox_replication_mod_bot
# sub test_mbox_replication_del_mas
# sub test_mbox_replication_del_rep
# sub test_mbox_replication_del_bot

sub test_copy_messages
{
    my ($self) = @_;

    xlog $self, "testing COPY with message scope annotations (BZ3528)";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $from_folder = 'INBOX.from';
    my $to_folder = 'INBOX.to';

    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog $self, "Create subfolders to copy from and to";
    my $store = $self->{store};
    my $talk = $store->get_client();
    $talk->create($from_folder)
        or die "Cannot create mailbox $from_folder: $@";
    $talk->create($to_folder)
        or die "Cannot create mailbox $to_folder: $@";

    $store->set_folder($from_folder);

    my @data_by_uid = (
        undef,
        # data thanks to hipsteripsum.me
        "american apparel",
        "mixtape aesthetic",
        "organic quinoa"
    );

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $uid = 1;
    while (defined $data_by_uid[$uid])
    {
        my $data = $data_by_uid[$uid];
        my $msg = $self->make_message("Message $uid");
        $msg->set_attribute('uid', $uid);
        $msg->set_annotation($entry, $attrib, $data);
        $exp{$uid} = $msg;
        $self->set_msg_annotation(undef, $uid, $entry, $attrib, $data);
        $uid++;
    }

    xlog $self, "Check the annotations are there";
    $self->check_messages(\%exp);

    xlog $self, "COPY the messages";
    $talk = $store->get_client();
    $talk->copy('1:*', $to_folder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Messages are now in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Messages are still in the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages(\%exp);

    xlog $self, "Delete the messages from the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $talk = $store->get_client();
    $talk->store('1:*', '+flags', '(\\Deleted)');
    $talk->expunge();

    xlog $self, "Messages are gone from the origin folder";
    $store->set_folder($from_folder);
    $store->_select();
    $self->check_messages({});

    xlog $self, "Messages are still in the destination folder";
    $store->set_folder($to_folder);
    $store->_select();
    $self->check_messages(\%exp);

}

sub test_expunge_messages
{
    my ($self) = @_;

    xlog $self, "testing expunge of messages with message scope";
    xlog $self, "annotations [IRIS-1553]";

    my $entry = '/comment';
    my $attrib = 'value.priv';

    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    my $talk = $self->{store}->get_client();
    $talk->uid(1);

    my @data_by_uid = (
        undef,
        # data thanks to hipsteripsum.me
        "polaroid seitan",
        "bicycle rights",
        "bushwick gastropub"
    );

    xlog $self, "Append some messages and store annotations";
    my %exp;
    my $uid = 1;
    while (defined $data_by_uid[$uid])
    {
        my $data = $data_by_uid[$uid];
        my $msg = $self->make_message("Message $uid");
        $msg->set_annotation($entry, $attrib, $data);
        $exp{$uid} = $msg;
        $self->set_msg_annotation(undef, $uid, $entry, $attrib, $data);
        $uid++;
    }

    xlog $self, "Check the annotations are there";
    $self->check_messages(\%exp, keyed_on => 'uid');

    xlog $self, "Check the annotations are in the DB too";
    my $r = $self->list_annotations(scope => 'message');
    $self->assert_deep_equals([
        {
            mboxname => 'user.cassandane',
            uid => 1,
            entry => $entry,
            userid => 'cassandane',
            data => $data_by_uid[1]
        },
        {
            mboxname => 'user.cassandane',
            uid => 2,
            entry => $entry,
            userid => 'cassandane',
            data => $data_by_uid[2]
        },
        {
            mboxname => 'user.cassandane',
            uid => 3,
            entry => $entry,
            userid => 'cassandane',
            data => $data_by_uid[3]
        }
    ], $r);

    $uid = 1;
    while (defined $data_by_uid[$uid])
    {
        xlog $self, "Delete message $uid";
        $talk->store($uid, '+flags', '(\\Deleted)');
        $talk->expunge();

        xlog $self, "Check the annotation is gone";
        delete $exp{$uid};
        $self->check_messages(\%exp);
        $uid++;
    }

    xlog $self, "Check the annotations are still in the DB";
    $r = $self->list_annotations(scope => 'message');
    $self->assert_deep_equals([
        {
            mboxname => 'user.cassandane',
            uid => 1,
            entry => $entry,
            userid => 'cassandane',
            data => $data_by_uid[1]
        },
        {
            mboxname => 'user.cassandane',
            uid => 2,
            entry => $entry,
            userid => 'cassandane',
            data => $data_by_uid[2]
        },
        {
            mboxname => 'user.cassandane',
            uid => 3,
            entry => $entry,
            userid => 'cassandane',
            data => $data_by_uid[3]
        }
    ], $r);

    $self->run_delayed_expunge();

    xlog $self, "Check the annotations are gone from the DB";
    $r = $self->list_annotations(scope => 'message');
    $self->assert_deep_equals([], $r);
}

sub test_cvt_cyrusdb
{
    my ($self) = @_;

    xlog $self, "test cvt_cyrusdb between annotation db and flat files (BZ2686)";

    my $folder = 'INBOX';
    my $fentry = '/private/comment';
    my $mentry = '/comment';
    my $mattrib = 'value.priv';
    my $evilchars = " \t\r\n\0\001";

    my $store = $self->{store};
    $store->set_fetch_attributes('uid', "annotation ($mentry $mattrib)");
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "store annotations";
    my $data = $self->make_random_data(2, maxreps => 20, separators => $evilchars);
    $talk->setmetadata($folder, $fentry, $data);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "add some messages";
    my $uid = 1;
    my %exp;
    for (1..10)
    {
        my $msg = $self->make_message("Message $_");
        $exp{$uid} = $msg;
        $msg->set_attribute('uid', $uid);
        my $data = $self->make_random_data(7, maxreps => 20, separators => $evilchars);
        $msg->set_annotation($mentry, $mattrib, $data);
        $talk->store('' . $uid, 'annotation',
                    [$mentry, [$mattrib, $data]]);
        $self->assert_str_equals('ok', $talk->get_last_completion_response());
        $uid++;
    }

    xlog $self, "Check the messages are all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the mailbox annotation is still there";
    my $res = $talk->getmetadata($folder, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);

    xlog $self, "Shut down the instance";
    $self->{store}->disconnect();
    $self->{adminstore}->disconnect();
    $talk = undef;
    $admintalk = undef;
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    xlog $self, "Convert the global annotation db to flat";
    my $basedir = $self->{instance}->{basedir};
    my $global_db = "$basedir/conf/annotations.db";
    my $global_flat = "$basedir/xann.txt";
    my $format = $self->{instance}->{config}->get('annotation_db');
    $format = $format // 'skiplist';

    $self->assert(( ! -f $global_flat ));
    $self->{instance}->run_command({ cyrus => 1 },
                                   'cvt_cyrusdb',
                                   $global_db, $format,
                                   $global_flat, 'flat');
    $self->assert(( -f $global_flat ));

    xlog $self, "Convert the mailbox annotation db to flat";
    my $datapath = $self->{instance}->folder_to_directory('user.cassandane');
    my $mailbox_db = "$datapath/cyrus.annotations";
    my $mailbox_flat = "$basedir/xcassann.txt";

    $self->assert(( ! -f $mailbox_flat ));
    $self->{instance}->run_command({ cyrus => 1 },
                                   'cvt_cyrusdb',
                                   $mailbox_db, $format,
                                   $mailbox_flat, 'flat');
    $self->assert(( -f $mailbox_flat ));

    xlog $self, "Move aside the original annotation dbs";
    rename($global_db, "$global_db.NOT")
        or die "Cannot rename $global_db to $global_db.NOT: $!";
    rename($mailbox_db, "$mailbox_db.NOT")
        or die "Cannot rename $mailbox_db to $mailbox_db.NOT: $!";
    $self->assert(( ! -f $global_db ));
    $self->assert(( ! -f $mailbox_db ));

    xlog $self, "restore the global annotation db from flat";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'cvt_cyrusdb',
                                   $global_flat, 'flat',
                                   $global_db, $format);
    $self->assert(( -f $global_db ));

    xlog $self, "restore the mailbox annotation db from flat";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'cvt_cyrusdb',
                                   $mailbox_flat, 'flat',
                                   $mailbox_db, $format);
    $self->assert(( -f $mailbox_db ));

    xlog $self, "Start the instance up again and reconnect";
    $self->{instance}->start();
    $talk = $store->get_client();

    xlog $self, "Check the messages are still all there";
    $self->check_messages(\%exp);

    xlog $self, "Check the mailbox annotation is still there";
    $res = $talk->getmetadata($folder, $fentry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_deep_equals({
        $folder => { $fentry => $data }
    }, $res);
}

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

sub test_folder_delete_mboxa_dmimm
    :ImmediateDelete
{
    my ($self) = @_;

    xlog $self, "test that per-mailbox GETMETADATA annotations are";
    xlog $self, "deleted with the mailbox; delete_mode = immediate (BZ2685)";

    $self->assert_str_equals('immediate',
                    $self->{instance}->{config}->get('delete_mode'));

    $self->folder_delete_mboxa_common();
}

sub test_folder_delete_mboxa_dmdel
    :DelayedDelete
{
    my ($self) = @_;

    xlog $self, "test that per-mailbox GETMETADATA annotations are";
    xlog $self, "deleted with the mailbox; delete_mode = delayed (BZ2685)";

    $self->assert_str_equals('delayed',
                    $self->{instance}->{config}->get('delete_mode'));

    $self->folder_delete_mboxa_common();
}

sub test_folder_delete_mboxm_dmimm
    :ImmediateDelete
{
    my ($self) = @_;

    xlog $self, "test that per-mailbox GETMETADATA annotations are";
    xlog $self, "deleted with the mailbox; delete_mode = immediate (BZ2685)";

    $self->assert_str_equals('immediate',
                    $self->{instance}->{config}->get('delete_mode'));

    $self->folder_delete_mboxm_common();
}

sub test_folder_delete_mboxm_dmdel
    :DelayedDelete
{
    my ($self) = @_;

    xlog $self, "test that per-mailbox GETMETADATA annotations are";
    xlog $self, "deleted with the mailbox; delete_mode = delayed (BZ2685)";

    $self->assert_str_equals('delayed',
                    $self->{instance}->{config}->get('delete_mode'));

    $self->folder_delete_mboxm_common();
}

sub test_folder_delete_msg_dmimm
    :ImmediateDelete
{
    my ($self) = @_;

    xlog $self, "test that per-message annotations are";
    xlog $self, "deleted with the mailbox; delete_mode = immediate (BZ2685)";

    $self->assert_str_equals('immediate',
                    $self->{instance}->{config}->get('delete_mode'));

    $self->folder_delete_msg_common();
}

sub test_folder_delete_msg_dmdel
    :DelayedDelete
{
    my ($self) = @_;

    xlog $self, "test that per-message annotations are";
    xlog $self, "deleted with the mailbox; delete_mode = delayed (BZ2685)";

    $self->assert_str_equals('delayed',
                    $self->{instance}->{config}->get('delete_mode'));

    $self->folder_delete_msg_common();
}

sub test_folder_move_partition
    :Partition2
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $folder = 'user.asd';
    my $entry = '/shared/vendor/cmu/cyrus-imapd/expire';
    my $value = '13';

    $admintalk->create($folder);
    $self->assert_equals('ok', $admintalk->get_last_completion_response());

    # annotation should be set yet
    my $res = $admintalk->getmetadata($folder, $entry);
    $self->assert_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals({
        $entry => undef,
    }, $res->{$folder});

    # set an annotation
    $admintalk->setmetadata($folder, $entry, $value);
    $self->assert_equals('ok', $admintalk->get_last_completion_response());

    # annotation should be set now
    $res = $admintalk->getmetadata($folder, $entry);
    $self->assert_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals({
        $entry => $value,
    }, $res->{$folder});

    # move the mailbox to the other partition
    $admintalk->rename($folder, $folder, 'p2');
    $self->assert_equals('ok', $admintalk->get_last_completion_response());

    # annotation should still be set
    $res = $admintalk->getmetadata($folder, $entry);
    $self->assert_equals('ok', $admintalk->get_last_completion_response());
    $self->assert_deep_equals({
        $entry => $value,
    }, $res->{$folder});
}

sub test_getmetadata_multiple_folders
{
    my ($self) = @_;

    xlog $self, "test the Cyrus-specific extension to the GETMETADATA";
    xlog $self, "syntax which allows specifying a parenthesised list";
    xlog $self, "of folder names [IRIS-1109]";

    my $imaptalk = $self->{store}->get_client();
    # data thanks to hipsteripsum.me
    my @folders = ( qw(INBOX.denim INBOX.sustainable INBOX.biodiesel.vinyl) );
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';
    my %uuids;

    xlog $self, "Create folders";
    foreach my $f (@folders)
    {
        $imaptalk->create($f)
            or die "Cannot create mailbox $f: $@";

        my $res = $imaptalk->getmetadata($f, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);

        my $uuid = $res->{$f}{$entry};
        $self->assert_not_null($uuid);
        $self->assert($uuid =~ m/^[0-9a-z-]+$/);
        $uuids{$f} = $uuid;
    }

    xlog $self, "Getting metadata with a list of folder names";
    my @f2;
    my %exp;
    foreach my $f (@folders)
    {
        push(@f2, $f);
        $exp{$f} = { $entry => $uuids{$f} };

        my $res = $imaptalk->getmetadata(\@f2, $entry);
        $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
        $self->assert_not_null($res);

        $self->assert_deep_equals(\%exp, $res);
    }
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

sub test_getmetadata_maxsize
{
    my ($self) = @_;

    xlog $self, "test the GETMETADATA command with the MAXSIZE option";

    my $imaptalk = $self->{store}->get_client();
    # data thanks to hipsteripsum.me
    my $folder = 'INBOX.denim';
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';
    my $res;

    xlog $self, "Create folder";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);

    my $uuid = $res->{$folder}{$entry};
    $self->assert_not_null($uuid);
    $self->assert($uuid =~ m/^[0-9a-z-]+$/);

    xlog $self, "Getting metadata with no MAXSIZE";
    $res = getmetadata($imaptalk, $folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { $entry => $uuid } } , $res);

    xlog $self, "Getting metadata with a large MAXSIZE in the right place";
    $res = getmetadata($imaptalk, [ MAXSIZE => 2048 ], $folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { $entry => $uuid } } , $res);

    xlog $self, "Getting metadata with a small MAXSIZE in the right place";
    $res = getmetadata($imaptalk, [ MAXSIZE => 8 ], $folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({ longentries => length($uuid) } , $res);

    xlog $self, "Getting metadata with a large MAXSIZE in the wrong place";
    $res = getmetadata($imaptalk, $folder, [ MAXSIZE => 2048 ], $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { $entry => $uuid } } , $res);

    xlog $self, "Getting metadata with a small MAXSIZE in the wrong place";
    $res = getmetadata($imaptalk, $folder, [ MAXSIZE => 8 ], $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({ longentries => length($uuid) } , $res);
}

sub test_getmetadata_depth
    :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog $self, "test the GETMETADATA command with DEPTH option";

    my $imaptalk = $self->{store}->get_client();
    # data thanks to hipsteripsum.me
    my $folder = 'INBOX.denim';
    my %entries = (
        '/shared/selvage' => 'locavore',
        '/shared/selvage/portland' => 'ennui',
        '/shared/selvage/leggings' => 'scenester',
        '/shared/selvage/portland/mustache' => 'terry richardson',
        '/shared/selvage/portland/mustache/american' => 'messenger bag',
        '/shared/selvage/portland/mustache/american/apparel' => 'street art',
    );
    my $rootentry = '/shared/selvage';
    my $res;

    xlog $self, "Create folder";
    $imaptalk->create($folder)
        or die "Cannot create mailbox $folder: $@";

    xlog $self, "Setup metadata";
    foreach my $entry (sort keys %entries)
    {
        $imaptalk->setmetadata($folder, $entry, $entries{$entry})
            or die "Cannot setmetadata: $@";
    }

    xlog $self, "Getting metadata with no DEPTH";
    $res = getmetadata($imaptalk, $folder, $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { $rootentry => $entries{$rootentry} } } , $res);

    xlog $self, "Getting metadata with DEPTH 0 in the right place";
    $res = getmetadata($imaptalk, $folder, [ DEPTH => 0 ], $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { $rootentry => $entries{$rootentry} } } , $res);

    xlog $self, "Getting metadata with DEPTH 1 in the right place";
    my @subset = ( qw(/shared/selvage /shared/selvage/portland /shared/selvage/leggings) );
    $res = getmetadata($imaptalk, $folder, [ DEPTH => 1 ], $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { map { $_ => $entries{$_} } @subset } }, $res);

    xlog $self, "Getting metadata with DEPTH infinity in the right place";
    $res = getmetadata($imaptalk, $folder, [ DEPTH => 'infinity' ], $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { %entries } } , $res);

    xlog $self, "Getting metadata with DEPTH 0 in the wrong place";
    $res = getmetadata($imaptalk, $folder, [ DEPTH => 0 ], $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { $rootentry => $entries{$rootentry} } } , $res);

    xlog $self, "Getting metadata with DEPTH 1 in the wrong place";
    $res = getmetadata($imaptalk, $folder, [ DEPTH => 1 ], $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { map { $_ => $entries{$_} } @subset } }, $res);

    xlog $self, "Getting metadata with DEPTH infinity in the wrong place";
    $res = getmetadata($imaptalk, $folder, [ DEPTH => 'infinity' ], $rootentry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({ $folder => { %entries } } , $res);
}

sub test_set_specialuse_twice
{
    my ($self) = @_;

    xlog $self, "testing if we could /private/specialuse twice on a folder";

    my $imaptalk = $self->{store}->get_client();
    my $entry = '/private/specialuse';
    my $sentry = '/shared/specialuse';
    my $folder1 = 'INBOX.bar';
    my $folder2 = 'INBOX.foo';
    my $specialuse1 = '\Sent \Trash';
    my $specialuse2 = '\Sent \Trash \Junk';
    my $specialuse3 = '\Sent';
    my $specialuse4 = '\Drafts';
    my $specialuse5 = '\Junk \Archive';
    my $specialuse6 = '\Drafts \Archive';
    my $res;

    xlog $self, "Create a folder $folder1";
    $imaptalk->create($folder1)
        or die "Cannot create mailbox $folder1: $@";

    xlog $self, "Create a folder $folder2";
    $imaptalk->create($folder2)
        or die "Cannot create mailbox $folder2: $@";

    $res = $imaptalk->getmetadata($folder1, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    delete $res->{$sentry};
    $self->assert_deep_equals({
        $folder1 => { $entry => undef }
        }, $res);


    xlog $self, "Set $folder1 to be $specialuse1";
    $imaptalk->setmetadata($folder1, $entry, $specialuse1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder2 to be $specialuse4";
    $imaptalk->setmetadata($folder2, $entry, $specialuse4);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder1 to $specialuse2, and it should work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse2);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder1 to $specialuse1, and it should work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder1 to $specialuse3, and it should work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse2);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder1 to $specialuse1, and it should work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder1 to $specialuse4, and it should not work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse4);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder1 to $specialuse5, and it should work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse5);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Set $folder2 to be $specialuse1";
    $imaptalk->setmetadata($folder2, $entry, $specialuse1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Now set $folder1 to $specialuse6, and it should work.";
    $imaptalk->setmetadata($folder1, $entry, $specialuse6);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
}

1;
