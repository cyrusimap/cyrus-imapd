# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::CyrusDB;
use strict;
use warnings;
use Data::Dumper;
use File::Copy;
use IO::File;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

use lib '../perl/imap';
use Cyrus::DList;
use Cyrus::HeaderFile;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ start_instances => 0 }, @_);
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

# Some databases aren't created automatically during a minimal
# startup on a new install, so run some commands such that they
# become extant.
sub _force_db_creations
{
    my ($self) = @_;

    # nothing currently required here!
}

sub test_alternate_quotadb_path
{
    my ($self) = @_;

    my $quota_db_path = $self->{instance}->get_basedir()
                        . '/conf/non-default-quotas.db';

    $self->{instance}->{config}->set(quota_db => 'twoskip');
    $self->{instance}->{config}->set(quota_db_path => $quota_db_path);
    $self->{instance}->start();

    $self->_force_db_creations();

    # Check that ctl_cyrusdb -c (checkpoint) uses correct db filename.
    # If it mistakenly tries to use the default filename, it will error
    # out due to it not existing.
    eval {
        $self->{instance}->run_command({
            cyrus => 1,
        }, 'ctl_cyrusdb', '-c');
    };
    $self->assert(not $@);

    # TODO more/better checks
}

sub test_mboxlistdb_skiplist
{
    my ($self) = @_;

    $self->{instance}->{config}->set(mboxlist_db => 'skiplist');
    $self->{instance}->start();

    # 'ctl_cyrusdb -r' will run on startup, and it should not crash!
}

sub test_recover_uniqueid_from_header_legacymb
    :min_version_3_6 :MailboxLegacyDirs
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
    xlog "XXX got uniqueid: " . Dumper \$uniqueid;
    $self->assert_not_null($uniqueid);
    $imaptalk->logout();
    undef $imaptalk;

    # stop service while tinkering
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # lose that uniqueid from mailboxes.db
    my $I = "I$uniqueid";
    my $N = "Nuser\x1fcassandane";
    my $format = $self->{instance}->{config}->get('mboxlist_db');
    $self->{instance}->run_dbcommand($mailboxes_db, $format,
                                     [ 'DELETE', $I ]);
    my (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        ['SHOW', $N]);
    my $dlist = Cyrus::DList->parse_string($mbentry);
    my $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        [ 'SET', $N, $dlist->as_string() ]);

    my %updated = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format, ['SHOW']);
    xlog "updated mailboxes.db: " . Dumper \%updated;

    # bring service back up
    # ctl_cyrusdb -r should find and fix the missing uniqueid
    $self->{instance}->getsyslog();
    $self->{instance}->start();
    if ($self->{instance}->{have_syslog_replacement}) {
        my $syslog = join(q{}, $self->{instance}->getsyslog());

        # should have still existed in cyrus.header
        $self->assert_does_not_match(
            qr{mailbox header had no uniqueid, creating one}, $syslog);

        # expect to find the log line
        $self->assert_matches(qr{mbentry had no uniqueid, setting from header},
                              $syslog);
    }

    # header should have the same uniqueid as before
    my $cyrus_header = $self->{instance}->folder_to_directory('INBOX')
                       . '/cyrus.header';
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    my $hf = Cyrus::HeaderFile->new_file($cyrus_header);
    $self->assert_str_equals($uniqueid, $hf->{header}->{UniqueId});

    # mbentry should have the same uniqueid as before
    (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        ['SHOW', $N]);
    $dlist = Cyrus::DList->parse_string($mbentry);
    $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});

    # $I entry should be back
    my ($key, $value) = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        ['SHOW', $I]);
    $self->assert_str_equals($I, $key);
    $dlist = Cyrus::DList->parse_string($value);
    $hash = $dlist->as_perl();
    $self->assert_str_equals("user\x1fcassandane", $hash->{N});
}

sub test_recover_create_missing_uniqueid_legacymb
    :min_version_3_6 :MailboxLegacyDirs
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

    # lose that uniqueid from mailboxes.db
    my $I = "I$uniqueid";
    my $N = "Nuser\x1fcassandane";
    my $format = $self->{instance}->{config}->get('mboxlist_db');
    $self->{instance}->run_dbcommand($mailboxes_db, $format,
                                     [ 'DELETE', $I ]);
    my (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        ['SHOW', $N]);
    my $dlist = Cyrus::DList->parse_string($mbentry);
    my $hash = $dlist->as_perl();
    $self->assert_str_equals($uniqueid, $hash->{I});
    $hash->{I} = undef;
    $dlist = Cyrus::DList->new_perl('', $hash);
    $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        [ 'SET', $N, $dlist->as_string() ]);

    my %updated = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format, ['SHOW']);
    xlog "updated mailboxes.db: " . Dumper \%updated;

    # lose it from cyrus.header too
    my $cyrus_header = $self->{instance}->folder_to_directory('INBOX')
                       . '/cyrus.header';
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    copy($cyrus_header, "$cyrus_header.OLD");
    my $hf = Cyrus::HeaderFile->new_file("$cyrus_header.OLD");
    $self->assert_str_equals($uniqueid, $hf->{header}->{UniqueId});
    $hf->{header}->{UniqueId} = undef;
    my $out = IO::File->new($cyrus_header, 'w');
    $hf->write_header($out, $hf->{header});

    # bring service back up
    # ctl_cyrusdb -r should find and fix the missing uniqueid
    $self->{instance}->getsyslog();
    $self->{instance}->start();
    if ($self->{instance}->{have_syslog_replacement}) {
        my $syslog = join(q{}, $self->{instance}->getsyslog());

        # expect to find it was missing in the header
        $self->assert_matches(qr{mailbox header had no uniqueid, creating one},
                              $syslog);

        # expect to find it was missing from mbentry
        $self->assert_matches(qr{mbentry had no uniqueid, setting from header},
                              $syslog);
    }

    # should not be the same uniqueid as before
    $imaptalk = $self->{store}->get_client();
    $res = $imaptalk->getmetadata("INBOX", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_not_null($res->{INBOX}{$entry});
    my $newuniqueid = $res->{INBOX}{$entry};
    $self->assert_str_not_equals($uniqueid, $newuniqueid);

    # header file should have the new uniqueid
    $cyrus_header = $self->{instance}->folder_to_directory('INBOX')
                    . '/cyrus.header';
    $self->assert(-f $cyrus_header, "couldn't find cyrus.header file");
    $hf = Cyrus::HeaderFile->new_file($cyrus_header);
    $self->assert_str_equals($newuniqueid, $hf->{header}->{UniqueId});

    # mbentry should have the new uniqueid
    (undef, $mbentry) = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        ['SHOW', $N]);
    $dlist = Cyrus::DList->parse_string($mbentry);
    $hash = $dlist->as_perl();
    $self->assert_str_equals($newuniqueid, $hash->{I});

    # new runq entry should exist
    my $newI = "I$newuniqueid";
    my ($key, $value) = $self->{instance}->run_dbcommand(
        $mailboxes_db, $format,
        ['SHOW', $newI]);
    $self->assert_str_equals($newI, $key);
    $dlist = Cyrus::DList->parse_string($value);
    $hash = $dlist->as_perl();
    $self->assert_str_equals("user\x1fcassandane", $hash->{N});
}

sub test_recover_skipstamp
{
    my ($self) = @_;

    my $dbdir = $self->{instance}->get_basedir() . "/conf/db";

    # no 'ctl_cyrusdb -r' on startup
    $self->{instance}->remove_start('recover');
    $self->{instance}->start();

    # expect skipstamp file to be missing
    $self->assert_not_file_test("$dbdir/skipstamp", '-e');

    # cyrus processes will whinge about missing skipstamp file
    if ($self->{instance}->{have_syslog_replacement}) {
        my $syslog = join "\n", $self->{instance}->getsyslog();
        $self->assert_matches(qr/skipstamp is missing/, $syslog);
        $self->assert_matches(qr/DBERROR: skipstamp/, $syslog);
    }

    # shut down, enable recover, and restart
    $self->{instance}->stop();
    # n.b. no "re_use_dir" here, because we need cyrus.conf regenerated
    $self->{instance}->add_recover();
    $self->{instance}->start();

    # skipstamp file should be present now
    $self->assert_file_test("$dbdir/skipstamp", '-e');

    if ($self->{instance}->{have_syslog_replacement}) {
        my $syslog = join "\n", $self->{instance}->getsyslog();

        # recover should have logged itself updating skipstamp
        $self->assert_matches(qr/updating recovery stamp/, $syslog);

        # cyrus processes should not whinge about missing skipstamp file
        $self->assert_does_not_match(qr/skipstamp is missing/, $syslog);
        $self->assert_does_not_match(qr/DBERROR: skipstamp/, $syslog);
    }
}

sub create_empty_file
{
    my ($fname) = @_;

    open my $fh, '>', $fname
        or die "create_empty_file($fname): $!";
    close $fh;
}

sub test_recover_skipcleanshutdown
{
    my ($self) = @_;

    my $dbdir = $self->{instance}->get_basedir() . "/conf/db";

    # need to start up once to create a reusable basedir
    $self->{instance}->start();
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # act like we were previously shut down cleanly by some rc script,
    # but without a skipstamp somehow
    create_empty_file("$dbdir/skipcleanshutdown");
    unlink "$dbdir/skipstamp";
    $self->assert_not_file_test("$dbdir/skipstamp", '-e');

    # start 'er up
    $self->{instance}->start();

    # recover should have created a skipstamp file, despite skipcleanshutdown
    $self->assert_file_test("$dbdir/skipstamp", '-e');
    my $prev_skipstamp_mtime = (stat "$dbdir/skipstamp")[9];

    # and skipcleanshutdown should have been removed
    $self->assert_not_file_test("$dbdir/skipcleanshutdown", '-e');

    if ($self->{instance}->{have_syslog_replacement}) {
        my $syslog = join "\n", $self->{instance}->getsyslog();

        # recover should not claim this was a normal start
        $self->assert_does_not_match(qr/starting normally/, $syslog);

        # recover should have logged itself updating skipstamp
        $self->assert_matches(qr/updating recovery stamp/, $syslog);

        # cyrus processes should not whinge about missing skipstamp file
        $self->assert_does_not_match(qr/skipstamp is missing/, $syslog);
        $self->assert_does_not_match(qr/DBERROR: skipstamp/, $syslog);
    }

    # shut down "cleanly" again, but this time leaving skipstamp alone
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;
    create_empty_file("$dbdir/skipcleanshutdown");

    # restart
    $self->{instance}->start();

    # skipstamp file should be present and unmodified since previous run
    $self->assert_file_test("$dbdir/skipstamp", '-e');
    my $skipstamp_mtime = (stat "$dbdir/skipstamp")[9];
    $self->assert_num_equals($prev_skipstamp_mtime, $skipstamp_mtime);

    # and skipcleanshutdown should have been removed
    $self->assert_not_file_test("$dbdir/skipcleanshutdown", '-e');

    if ($self->{instance}->{have_syslog_replacement}) {
        my $syslog = join "\n", $self->{instance}->getsyslog();

        # recover should claim this was a normal start
        $self->assert_matches(qr/starting normally/, $syslog);

        # recover should not have updated skipstamp
        $self->assert_does_not_match(qr/updating recovery stamp/, $syslog);

        # cyrus processes should not whinge about missing skipstamp file
        $self->assert_does_not_match(qr/skipstamp is missing/, $syslog);
        $self->assert_does_not_match(qr/DBERROR: skipstamp/, $syslog);
    }
}

1;
