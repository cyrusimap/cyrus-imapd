# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::SearchSquat;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    return $class->SUPER::new({ config => $config }, @args);
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

sub run_squatter
{
    my ($self, @args) = @_;

    my $outfname = $self->{instance}->{basedir} . "/squatter.out";
    my $errfname = $self->{instance}->{basedir} . "/squatter.err";

    $self->{instance}->run_command({
            cyrus => 1,
            redirects => {
                stdout => $outfname,
                stderr => $errfname,
            },
        },
        'squatter',
        @args
    );

    return (slurp_file($outfname), slurp_file($errfname));
}

# XXX version gated to 3.4+ for now to keep travis happy, but if we
# XXX backport the fix we should change or remove the gate...
sub test_simple
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $self->make_message("term2", body => "term1") || die;
    $self->make_message("term2", body => "term1") || die;
    $self->make_message("term1", body => "term2") || die;
    $self->make_message("term3", body => "term4") || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @tests = ({
        search => ['body', 'term1'],
        wantUids => [1,2],
    }, {
        search => ['text', 'term1'],
        wantUids => [1,2,3],
    }, {
        search => ['subject', 'term2'],
        wantUids => [1,2],
    }, {
        search => ['subject', 'term3'],
        wantUids => [4],
    }, {
        search => ['body', 'term4'],
        wantUids => [4],
    }, {
        search => ['fuzzy', 'body', 'term4'],
        wantUids => [4],
    }, {
        # we don't index content-type, make sure we actually didn't
        search => ['from', 'text/plain'],
        wantUids => [],
    }, {
        # we don't index content-type, make sure we actually didn't
        search => ['to', 'text/plain'],
        wantUids => [],
    }, {
        # we don't index content-type, make sure we actually didn't
        search => ['subject', 'text/plain'],
        wantUids => [],
    });

    foreach (@tests) {
        $self->{instance}->getsyslog();

        my $uids = $imap->search(@{$_->{search}}) || die;
        $self->assert_deep_equals($_->{wantUids}, $uids);

        $self->assert_syslog_matches($self->{instance}, qr{Squat run});
    }
}

sub test_one_doc_per_message
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    # make some messages where the only indexed field is the body
    foreach my $body (qw(term1 term1 term2 term4)) {
        $self->make_message(undef,
                            from => undef,
                            to => undef,
                            body => $body) || die;
    }

    # make enough other messages such that an incremental reindex
    # will need to realloc doc_ID_map
    for (1..50) {
        $self->make_message() || die;
    }

    $self->run_squatter();

    my @tests = ({
        search => ['body', 'term1'],
        wantUids => [1,2],
    }, {
        search => ['body', 'term2'],
        wantUids => [3],
    }, {
        search => ['body', 'term3'],
        wantUids => [],
    }, {
        search => ['body', 'term4'],
        wantUids => [4],
    });

    foreach (@tests) {
        $self->{instance}->getsyslog();

        my $uids = $imap->search(@{$_->{search}}) || die;
        $self->assert_deep_equals($_->{wantUids}, $uids);

        $self->assert_syslog_matches($self->{instance}, qr/Squat run/);
    }

    # make some more messages
    foreach my $body (qw(term5 term6 term6 term8)) {
        $self->make_message(undef,
                            from => undef,
                            to => undef,
                            body => $body) || die;
    }

    # incremental reindex
    my (undef, $err) = $self->run_squatter('-i', '-v');
    $self->assert_matches(qr{indexed 4 messages}, $err);

    push @tests, {
        search => ['body', 'term5'],
        wantUids => [55],
    }, {
        search => ['body', 'term6'],
        wantUids => [56, 57],
    }, {
        search => ['body', 'term7'],
        wantUids => [],
    }, {
        search => ['body', 'term8'],
        wantUids => [58],
    };

    # better not be any off-by-one errors in search results!
    foreach (@tests) {
        $self->{instance}->getsyslog();

        my $uids = $imap->search(@{$_->{search}}) || die;
        $self->assert_deep_equals($_->{wantUids}, $uids);

        $self->assert_syslog_matches($self->{instance}, qr/Squat run/);
    }
}

# XXX version gated to 3.4+ for now to keep travis happy, but if we
# XXX backport the fix we should change or remove the gate...
sub test_skip_unmodified
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $self->make_message() || die;

    sleep(1);

    $self->{instance}->getsyslog();
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
    $self->assert_syslog_does_not_match($self->{instance},
                                        qr{Squat skipping mailbox});

    $self->{instance}->getsyslog();
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-v', '-s', '0');
    $self->assert_syslog_matches($self->{instance},
                                 qr{Squat skipping mailbox});
}

sub test_nonincremental
    :SearchEngineSquat
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();
    my $n = 0;

    for (1..5) {
        # make a new message
        $self->make_message();
        $n++;

        # do a full reindex
        my (undef, $err) = $self->run_squatter('-vv');

        # better have indexed them all, not just the new one!
        $self->assert_matches(qr{indexed $n messages}, $err);
    }

    # make a message with no subject, to, or from
    $self->make_message(undef, to => undef, from => undef);
    $n++;

    # do a full reindex
    my (undef, $err) = $self->run_squatter('-vv');

    # better have indexed them all, not just the new one!
    $self->assert_matches(qr{indexed $n messages}, $err);
}

sub test_incremental
    :SearchEngineSquat
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();
    my $err;

    # some initial messages - enough to definitely force a doc_ID_map realloc
    # when incrementally reindexing later
    for (1..50) {
        $self->make_message();
    }

    # make a message with no subject, to, or from
    # this used to trigger an indexing bug and produce a corrupt index,
    # which would lead to a crash during incremental reindex
    my $weird = $self->make_message(undef, to => undef, from => undef);
    xlog "weird message:\n" . $weird->as_string();

    sleep(1);

    # initial non-incremental index
    (undef, $err) = $self->run_squatter('-vv');
    $self->assert_matches(qr{indexed 51 messages}, $err);

    # incremental reindex with no changes to mailbox
    (undef, $err) = $self->run_squatter('-i', '-vv');
    $self->assert_matches(qr{indexed 0 messages}, $err);

    # delete, expunge, and cyr_expire some messages
    # n.b. this does not unindex the message in any way
    $imap->store('5', '+flags', '(\\Deleted)');
    $self->assert_str_equals('ok', $imap->get_last_completion_response());
    $imap->expunge();
    $self->assert_str_equals('ok', $imap->get_last_completion_response());
    $self->{instance}->run_command({cyrus => 1}, 'cyr_expire', '-X', '0');

    # incremental reindex after one message expunged
    (undef, $err) = $self->run_squatter('-i', '-vv');
    $self->assert_matches(qr{indexed 0 messages}, $err);

    # make one new message
    for (1) {
        $self->make_message();
    }
    sleep(1);

    # incremental reindex after one new message
    (undef, $err) = $self->run_squatter('-i', '-vv');
    $self->assert_matches(qr{indexed 1 messages}, $err);

    # incremental reindex with no changes to mailbox
    (undef, $err) = $self->run_squatter('-i', '-vv');
    $self->assert_matches(qr{indexed 0 messages}, $err);

    # make some new messages
    for (1..10) {
        $self->make_message();
    }
    sleep(1);

    # incremental reindex after new messages
    (undef, $err) = $self->run_squatter('-i', '-vv');
    $self->assert_matches(qr{indexed 10 messages}, $err);

    # incremental reindex with no changes to mailbox
    (undef, $err) = $self->run_squatter('-i', '-vv');
    $self->assert_matches(qr{indexed 0 messages}, $err);
}

sub test_relocate_legacy_searchdb
    :DelayedDelete :min_version_3_6 :MailboxLegacyDirs
    :Admin :SearchEngineSquat :NoAltNamespace :VirtDomains
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser\@example.com";
    my $subfolder = "user.magicuser.foo\@example.com";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'relocate_by_id', '-u' => "magicuser\@example.com" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_relocate_legacy_nosearchdb
    :DelayedDelete :min_version_3_6 :MailboxLegacyDirs
    :Admin :SearchEngineSquat :NoAltNamespace :VirtDomains
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser\@example.com";
    my $subfolder = "user.magicuser.foo\@example.com";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Don't create the search database!
    # A user who's never been indexed should still relocate cleanly

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'relocate_by_id', '-u' => "magicuser\@example.com" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_unindexed
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $self->make_message("needle 1", body => "needle") || die;
    $self->make_message("xxxxxx 2", body => "xxxxxx") || die;

    $self->run_squatter;

    my $uids = $imap->search('text', 'needle');
    $self->assert_deep_equals([1], $uids);

    $self->make_message("needle 3", body => "needle") || die;
    $self->make_message("xxxxxx 4", body => "xxxxxx") || die;

    # Do not rerun squatter. Make sure search only returns
    # a matching unindexed message.

    $uids = $imap->search('text', 'needle');
    $self->assert_deep_equals([1,3], $uids);
}

sub test_unindexed_fuzzy
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $self->make_message("needle 1", body => "needle") || die;
    $self->make_message("xxxxxx 2", body => "xxxxxx") || die;

    $self->run_squatter;

    my $uids = $imap->search('fuzzy', 'body', 'needle');
    $self->assert_deep_equals([1], $uids);

    $self->make_message("needle 3", body => "needle") || die;
    $self->make_message("xxxxxx 4", body => "xxxxxx") || die;

    # Do not rerun squatter. Make sure search only returns
    # a matching unindexed message.

    $uids = $imap->search('fuzzy', 'body', 'needle');
    $self->assert_deep_equals([1,3], $uids);
}

sub test_unindexed_since
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    my $past_dt = DateTime->last_day_of_month(year => 2023, month => 12);

    $self->make_message("needle 1", body => "needle") || die;
    $self->make_message("xxxxxx 2", body => "xxxxxx") || die;
    $self->make_message("old 3", date => $past_dt, body => "needle") || die;

    $self->run_squatter;

    my $uids = $imap->search('text', 'needle', 'since', '1-Feb-2024');
    $self->assert_deep_equals([1], $uids);

    $uids = $imap->search('text', 'needle', 'not', 'since', '1-Feb-2024');
    $self->assert_deep_equals([3], $uids);

    $self->make_message("needle 4", body => "needle") || die;
    $self->make_message("xxxxxx 5", body => "xxxxxx") || die;
    $self->make_message("old 6", date => $past_dt, body => "needle") || die;

    # Do not rerun squatter. Make sure search only returns
    # a matching unindexed message.

    $uids = $imap->search('text', 'needle', 'since', '1-Feb-2024');
    $self->assert_deep_equals([1,4], $uids);

    $uids = $imap->search('text', 'needle', 'not', 'since', '1-Feb-2024');
    $self->assert_deep_equals([3, 6], $uids);
}

sub test_since
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    my $past_dt = DateTime->last_day_of_month(year => 2023, month => 12);

    $self->make_message("needle 1", body => "needle") || die;
    $self->make_message("xxxxxx 2", body => "xxxxxx") || die;
    $self->make_message("old 3", date => $past_dt, body => "needle") || die;

    $self->run_squatter;

    my $uids = $imap->search('since', '1-Feb-2024');
    $self->assert_deep_equals([1,2], $uids);

    $uids = $imap->search('not', 'since', '1-Feb-2024');
    $self->assert_deep_equals([3], $uids);

    $self->make_message("needle 4", body => "needle") || die;
    $self->make_message("xxxxxx 5", body => "xxxxxx") || die;
    $self->make_message("old 6", date => $past_dt, body => "needle") || die;

    # Do not rerun squatter. Make sure search only returns
    # a matching unindexed message.

    $uids = $imap->search('since', '1-Feb-2024');
    $self->assert_deep_equals([1,2,4,5], $uids);

    $uids = $imap->search('not', 'since', '1-Feb-2024');
    $self->assert_deep_equals([3,6], $uids);
}

1;
