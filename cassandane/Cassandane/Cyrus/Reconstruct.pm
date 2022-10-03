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

package Cassandane::Cyrus::Reconstruct;
use strict;
use warnings;
use Data::Dumper;
use File::Copy;
use IO::File;
use JSON;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

use lib '../perl/imap';
use Cyrus::DList;
use Cyrus::HeaderFile;
use Cyrus::IndexFile;

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
# Test zeroed out data across the UID
#
sub test_reconstruct_zerouid
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    for (1..10) {
        my $msg = $self->{gen}->generate(subject => "subject $_");
        $self->{store}->write_message($msg, flags => ["\\Seen", "\$NotJunk"]);
    }
    $self->{store}->write_end();
    $imaptalk->select("INBOX") || die;

    my @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct');

    @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    # this needs a bit of magic to know where to write... so
    # we do some hard-coded cyrus.index handling
    my $dir = $self->{instance}->folder_to_directory('user.cassandane');
    my $file = "$dir/cyrus.index";
    my $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    my $index = Cyrus::IndexFile->new($fh);

    my $offset = $index->header('StartOffset') + (5 * $index->header('RecordSize'));
    warn "seeking to offset $offset";
    $fh->seek($offset, 0);
    $fh->syswrite("\0\0\0\0\0\0\0\0", 8);
    $fh->close();

    # this time, the reconstruct will fix up the broken record and re-insert later
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', 'user.cassandane');

    @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(not grep { $_ == 6 } @records);
    $self->assert(grep { $_ == 11 } @records);
}

#
# Test truncated file
#
sub test_reconstruct_truncated
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    for (1..10) {
        my $msg = $self->{gen}->generate(subject => "subject $_");
        $self->{store}->write_message($msg, flags => ["\\Seen", "\$NotJunk"]);
    }
    $self->{store}->write_end();
    $imaptalk->select("INBOX") || die;

    my @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct');

    @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    # this needs a bit of magic to know where to write... so
    # we do some hard-coded cyrus.index handling
    my $dir = $self->{instance}->folder_to_directory('user.cassandane');
    my $file = "$dir/cyrus.index";
    my $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    my $index = Cyrus::IndexFile->new($fh);

    my $offset = $index->header('StartOffset') + (5 * $index->header('RecordSize'));
    $fh->truncate($offset);
    $fh->close();

    # this time, the reconstruct will create the records again
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', 'user.cassandane');

    # XXX - this actually deletes everything, so we unselect and reselect.  A
    # too-short cyrus.index is a fatal error, so we don't even try to read it.
    $imaptalk->unselect();
    $imaptalk->select("INBOX") || die;

    @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);
    $self->assert(not grep { $_ == 11 } @records);

    if ($self->{instance}->{have_syslog_replacement}) {
        # We should have generated a SYNCERROR or two
        my @lines = $self->{instance}->getsyslog();
        $self->assert_matches(qr/IOERROR: refreshing index/, "@lines");
    }
}
#
# Test removed file
#
sub test_reconstruct_removedfile
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    for (1..10) {
        my $msg = $self->{gen}->generate(subject => "subject $_");
        $self->{store}->write_message($msg, flags => ["\\Seen", "\$NotJunk"]);
    }
    $self->{store}->write_end();
    $imaptalk->select("INBOX") || die;

    my @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct');

    @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    # this needs a bit of magic to know where to write... so
    # we do some hard-coded cyrus.index handling
    my $dir = $self->{instance}->folder_to_directory('user.cassandane');
    unlink("$dir/6.");

    # this time, the reconstruct will fix up the broken record and re-insert later
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', 'user.cassandane');

    @records = $imaptalk->search("all");
    $self->assert_num_equals(9, scalar @records);
    $self->assert(not grep { $_ == 6 } @records);
}

#
# Test snoozed annotation fixup
#
# XXX need to downgrade min version if this is backported to 3.2
sub test_reconstruct_snoozed
    :min_version_3_3
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    for (1..10) {
        my $msg = $self->{gen}->generate(subject => "subject $_");
        $self->{store}->write_message($msg, flags => ["\\Seen", "\$NotJunk"]);
    }
    $self->{store}->write_end();
    $imaptalk->select("INBOX") || die;

    my @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct');

    @records = $imaptalk->search("all");
    $self->assert_num_equals(10, scalar @records);
    $self->assert(grep { $_ == 6 } @records);

    $imaptalk->store('5', 'annotation', ["/vendor/cmu/cyrus-imapd/snoozed",
        ['value.shared', { Quote => encode_json({until => '2020-01-01T00:00:00'}) }],
    ]);

    # this needs a bit of magic to know where to write... so
    # we do some hard-coded cyrus.index handling
    my $dir = $self->{instance}->folder_to_directory('user.cassandane');
    my $file = "$dir/cyrus.index";
    my $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    my $index = Cyrus::IndexFile->new($fh);

    while (my $record = $index->next_record_hash()) {
        if ($record->{Uid} == 5) {
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '1');
        }
        else {
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '0');
        }
    }
    close($fh);

    # the reconstruct shouldn't change anything
    $self->{instance}->getsyslog();
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', 'user.cassandane');
    my @lines = $self->{instance}->getsyslog();
    $self->assert_does_not_match(qr/mismatch/, "@lines");

    xlog $self, "update some \\Snoozed flags";
    $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    $index = Cyrus::IndexFile->new($fh);

    while (my $record = $index->next_record_hash()) {
        if ($record->{Uid} == 5) {
            # nuke the Snoozed flag
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '1');
            substr($record->{SystemFlags}, 5, 1) = '0';
            $index->rewrite_record($record);
        }
        elsif ($record->{Uid} == 6) {
            # add the Snoozed flag
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '0');
            substr($record->{SystemFlags}, 5, 1) = '1';
            $index->rewrite_record($record);
        }
        else {
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '0');
        }
    }
    close($fh);

    # this reconstruct should change things back!
    $self->{instance}->getsyslog();
    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', 'user.cassandane');
    @lines = $self->{instance}->getsyslog();
    $self->assert_matches(qr/uid 5 snoozed mismatch/, "@lines");
    $self->assert_matches(qr/uid 6 snoozed mismatch/, "@lines");

    xlog $self, "check that the values are changed back";
    $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file" unless $fh;
    $index = Cyrus::IndexFile->new($fh);

    while (my $record = $index->next_record_hash()) {
        if ($record->{Uid} == 5) {
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '1');
        }
        else {
            $self->assert_str_equals(substr($record->{SystemFlags}, 5, 1), '0');
        }
    }
    close($fh);
}

sub test_reconstruct_uniqueid_from_header_path_legacymb
    :min_version_3_7 :MailboxLegacyDirs :NoStartInstances
{
    my ($self) = @_;
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';

    # first start will set up cassandane user
    $self->_start_instances();
    my $basedir = $self->{instance}->get_basedir();
    my $mailboxes_db = "$basedir/conf/mailboxes.db";
    $self->assert(-f $mailboxes_db, "$mailboxes_db not present");

    # find out the uniqueid of the inbox
    my $imaptalk = $self->{store}->get_client();
    my $res = $imaptalk->getmetadata("INBOX", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $uniqueid = $res->{INBOX}{$entry};
    $self->assert_not_null($uniqueid);
    $imaptalk->logout();
    undef $imaptalk;

    # stop service while tinkering
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # get header path
    my $cyrus_header = $self->{instance}->folder_to_directory('INBOX')
                       . '/cyrus.header';
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");

    # lose uniqueid from cyrus.header
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    copy($cyrus_header, "$cyrus_header.OLD");
    my $hf = Cyrus::HeaderFile->new_file("$cyrus_header.OLD");
    my $dlist = Cyrus::DList->parse_string($hf->{dlistheader});
    my $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    my $out = IO::File->new($cyrus_header, 'w');
    $hf->write_newheader($out, $dlist->as_string());

    # reconstruct -P should find and fix the missing uniqueid
    $self->{instance}->getsyslog();
    $self->{instance}->run_command({ cyrus => 1 },
                                   'reconstruct', '-P', $cyrus_header);
    my $syslog = join(q{}, $self->{instance}->getsyslog());

    # should not have existed in cyrus.header, get from mbentry
    $self->assert_matches(
        qr{mailbox header had no uniqueid, setting from mbentry}, $syslog);

    # bring service back up
    $self->{instance}->start();

    # header should have the same uniqueid as before
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    $hf = Cyrus::HeaderFile->new_file($cyrus_header);
    $self->assert_str_equals($uniqueid, $hf->{header}->{UniqueId});
}

sub test_reconstruct_uniqueid_from_header_path_uuidmb
    :min_version_3_7 :NoStartInstances
{
    my ($self) = @_;
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';

    # first start will set up cassandane user
    $self->_start_instances();
    my $basedir = $self->{instance}->get_basedir();
    my $mailboxes_db = "$basedir/conf/mailboxes.db";
    $self->assert(-f $mailboxes_db, "$mailboxes_db not present");

    # find out the uniqueid of the inbox
    my $imaptalk = $self->{store}->get_client();
    my $res = $imaptalk->getmetadata("INBOX", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $uniqueid = $res->{INBOX}{$entry};
    $self->assert_not_null($uniqueid);
    $imaptalk->logout();
    undef $imaptalk;

    # stop service while tinkering
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # get header path
    my $cyrus_header = $self->{instance}->folder_to_directory('INBOX')
                       . '/cyrus.header';
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");

    # lose that uniqueid from mailboxes.db
    my $I = "I$uniqueid";
    my $N = "Nuser\x1fcassandane";
    $self->{instance}->run_dbcommand($mailboxes_db, "twoskip",
                                     [ 'DELETE', $I ]);
    my (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $N]);
    my $dlist = Cyrus::DList->parse_string($mbentry);
    my $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        [ 'SET', $N, $dlist->as_string() ]);

    my %updated = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip", ['SHOW']);
    xlog "updated mailboxes.db: " . Dumper \%updated;

    # lose it from cyrus.header too
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    copy($cyrus_header, "$cyrus_header.OLD");
    my $hf = Cyrus::HeaderFile->new_file("$cyrus_header.OLD");
    $dlist = Cyrus::DList->parse_string($hf->{dlistheader});
    $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    my $out = IO::File->new($cyrus_header, 'w');
    $hf->write_newheader($out, $dlist->as_string());

    # reconstruct -P should find and fix the missing uniqueid
    $self->{instance}->getsyslog();
    $self->{instance}->run_command({ cyrus => 1 },
                                   'reconstruct', '-P', $cyrus_header);
    my $syslog = join(q{}, $self->{instance}->getsyslog());

    # should not have existed in cyrus.header, get from path
    $self->assert_matches(
        qr{mailbox header had no uniqueid, setting from path}, $syslog);

    # bring service back up
    $self->{instance}->start();

    # header should have the same uniqueid as before
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    $hf = Cyrus::HeaderFile->new_file($cyrus_header);
    $self->assert_str_equals($uniqueid, $hf->{header}->{UniqueId});

    # mbentry should have the same uniqueid as before
    (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $N]);
    $dlist = Cyrus::DList->parse_string($mbentry);
    $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});

    # $I entry should be back
    my ($key, $value) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $I]);
    $self->assert_str_equals($I, $key);
    $dlist = Cyrus::DList->parse_string($value);
    $hash = $dlist->as_perl();
    $self->assert_str_equals("user\x1fcassandane", $hash->{N});
}

sub test_reconstruct_uniqueid_from_header_uuidmb
    :min_version_3_7 :NoStartInstances
{
    my ($self) = @_;
    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';

    # first start will set up cassandane user
    $self->_start_instances();
    my $basedir = $self->{instance}->get_basedir();
    my $mailboxes_db = "$basedir/conf/mailboxes.db";
    $self->assert(-f $mailboxes_db, "$mailboxes_db not present");

    # find out the uniqueid of the inbox
    my $imaptalk = $self->{store}->get_client();
    my $res = $imaptalk->getmetadata("INBOX", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $uniqueid = $res->{INBOX}{$entry};
    $self->assert_not_null($uniqueid);
    $imaptalk->logout();
    undef $imaptalk;

    # stop service while tinkering
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # get header path
    my $cyrus_header = $self->{instance}->folder_to_directory('INBOX')
                       . '/cyrus.header';
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");

    # lose that uniqueid from mailboxes.db
    my $I = "I$uniqueid";
    my $N = "Nuser\x1fcassandane";
    $self->{instance}->run_dbcommand($mailboxes_db, "twoskip",
                                     [ 'DELETE', $I ]);
    my (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $N]);
    my $dlist = Cyrus::DList->parse_string($mbentry);
    my $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        [ 'SET', $N, $dlist->as_string() ]);

    my %updated = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip", ['SHOW']);
    xlog "updated mailboxes.db: " . Dumper \%updated;

    # reconstruct -P should find and fix the missing uniqueid
    $self->{instance}->getsyslog();
    $self->{instance}->run_command({ cyrus => 1 },
                                   'reconstruct', '-P', $cyrus_header);
    my $syslog = join(q{}, $self->{instance}->getsyslog());

    # should have still existed in cyrus.header
    $self->assert_does_not_match(qr{mailbox header had no uniqueid}, $syslog);

    # expect to find the log line
    $self->assert_matches(qr{setting mbentry uniqueid from header}, $syslog);

    # bring service back up
    $self->{instance}->start();

    # header should have the same uniqueid as before
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    my $hf = Cyrus::HeaderFile->new_file($cyrus_header);
    $self->assert_str_equals($uniqueid, $hf->{header}->{UniqueId});

    # mbentry should have the same uniqueid as before
    (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $N]);
    $dlist = Cyrus::DList->parse_string($mbentry);
    $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});

    # $I entry should be back
    my ($key, $value) = $self->{instance}->run_dbcommand(
        $mailboxes_db, "twoskip",
        ['SHOW', $I]);
    $self->assert_str_equals($I, $key);
    $dlist = Cyrus::DList->parse_string($value);
    $hash = $dlist->as_perl();
    $self->assert_str_equals("user\x1fcassandane", $hash->{N});
}

1;
