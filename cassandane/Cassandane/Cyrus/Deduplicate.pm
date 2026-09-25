# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Deduplicate;
use strict;
use warnings;
use IO::File;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Config;
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

# Exit codes deduplicate uses from sysexits.h. Parse sysexits at
# runtime to be more dynamic.
my %EX;
BEGIN {
    %EX = (
        EX_USAGE     => 64,
        EX_DATAERR   => 65,
        EX_NOUSER    => 67,
        EX_CANTCREAT => 73,
        EX_TEMPFAIL  => 75,
    );
    foreach my $path (qw(/usr/include/sysexits.h
                         /usr/local/include/sysexits.h)) {
        next unless -f $path;
        open(my $fh, '<', $path) or next;
        while (<$fh>) {
            $EX{$1} = $2 if m/^\s*#define\s+(EX_\w+)\s+(\d+)/ && exists $EX{$1};
        }
        close($fh);
        last;
    }
}

sub new
{
    my $class = shift;

    # altnamespace off makes more sense for deduplicate
    my $config = Cassandane::Config->default()->clone();
    $config->set(altnamespace => 'no');

    return $class->SUPER::new({ adminstore => 1, config => $config }, @_);
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

# Run deduplicate with the given arguments, capturing its output.
# Returns (exitcode, stdout, stderr).
sub run_deduplicate
{
    my ($self, @args) = @_;

    my $basedir = $self->{instance}->get_basedir();
    my $n = ++$self->{_dedup_run};
    my $outfile = "$basedir/$$-dedup.$n.out";
    my $errfile = "$basedir/$$-dedup.$n.err";

    my $code = 0;
    eval {
        $self->{instance}->run_command({
            cyrus => 1,
            redirects => {
                stdout => $outfile,
                stderr => $errfile,
            },
        }, 'deduplicate', @args);
    };
    if ($@) {
        ($code) = $@ =~ m/exited with code (\d+)/;
        die $@ unless defined $code;
    }

    return ($code, slurp_file($outfile), slurp_file($errfile));
}

# Generate one message and append the identical bytes to each named
# folder (creating folders as needed), so every copy shares one GUID.
# Returns the message, whose get_guid() matches the database keys.
sub make_duplicate
{
    my ($self, $subject, @folders) = @_;

    my $talk = $self->{store}->get_client();
    my $msg = $self->{gen}->generate(subject => $subject);
    foreach my $folder (@folders) {
        if (lc $folder ne 'inbox' && !$self->{_folders_made}->{$folder}) {
            $talk->create($folder);
            $self->assert_str_equals('ok',
                $talk->get_last_completion_response());
            $self->{_folders_made}->{$folder} = 1;
        }
        $self->{store}->set_folder($folder);
        $self->_save_message($msg);
    }

    return $msg;
}

# stat one spool file, returns (dev, ino, nlink, size), or the empty
# list if the file does not exist.
sub stat_msg_file
{
    my ($self, $folder, $uid) = @_;

    my $dir = $self->{instance}->folder_to_directory($folder);
    $self->assert_not_null($dir);
    my @st = stat("$dir/$uid.");
    return unless scalar @st;
    return ($st[0], $st[1], $st[3], $st[7]);
}

# Assert every listed [ folder, uid ] spool file shares a single inode.
sub assert_linked
{
    my ($self, @msgs) = @_;

    my (@first, @st);
    foreach my $m (@msgs) {
        @st = $self->stat_msg_file(@$m);
        $self->assert(scalar @st, "missing spool file for @$m");
        @first = @st unless scalar @first;
        $self->assert_num_equals($first[0], $st[0]);
        $self->assert_num_equals($first[1], $st[1]);
    }
}

# Assert two [ folder, uid ] spool files do not share an inode.
sub assert_not_linked
{
    my ($self, $a, $b) = @_;

    my @sta = $self->stat_msg_file(@$a);
    my @stb = $self->stat_msg_file(@$b);
    $self->assert(scalar @sta);
    $self->assert(scalar @stb);
    $self->assert($sta[0] != $stb[0] || $sta[1] != $stb[1]);
}

# Dump a database and parse it into { guid => record count }.
sub dump_guids
{
    my ($self, $db) = @_;

    my ($code, $out, undef) = $self->run_deduplicate('-Z', '-f', $db);
    $self->assert_num_equals(0, $code);

    my (%guids, $cur);
    foreach my $line (split /\n/, $out) {
        if ($line =~ m/^([0-9a-f]{40}):$/) {
            $cur = $1;
            $guids{$cur} = 0;
        }
        elsif (defined $cur && $line =~ m/^-> uid=\d+ mailbox=\d+/) {
            $guids{$cur}++;
        }
    }
    return \%guids;
}

#
# Tier 1: core build / dump / link round trip
#

sub test_build_dump_roundtrip
{
    my ($self) = @_;

    xlog $self, "one duplicated message and one singleton";
    my $dupe = $self->make_duplicate('duplicated', 'INBOX', 'INBOX.sub');
    my $single = $self->make_duplicate('singleton', 'INBOX');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code, undef, undef) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "dump must show the header and both GUIDs";
    (my $c, my $out, undef) = $self->run_deduplicate('-Z', '-f', $db);
    $self->assert_num_equals(0, $c);
    $self->assert_matches(qr/^!deduplicate_version: /m, $out);
    my ($count) = $out =~ m/^!count: (\d+)$/m;
    $self->assert_not_null($count);
    my @dict = ($out =~ m/^mailbox \d+: /mg);
    $self->assert_num_equals($count, scalar @dict);

    my $guids = $self->dump_guids($db);
    $self->assert_num_equals(2, scalar keys %$guids);
    $self->assert_num_equals(2, $guids->{lc $dupe->get_guid()});
    $self->assert_num_equals(1, $guids->{lc $single->get_guid()});
}

sub test_build_verbosity
{
    my ($self) = @_;

    my $msg = $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');
    my $guid = lc $msg->get_guid();
    my $db = $self->{instance}->get_basedir() . "/dedup.db";

    xlog $self, "no -v: nothing printed per record";
    my ($code, $out) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_does_not_match(qr/\Q$guid\E/i, $out);
    unlink $db;

    xlog $self, "-v: just the guid";
    ($code, $out) = $self->run_deduplicate('-B', '-f', $db, '-v');
    $self->assert_num_equals(0, $code);
    my @lines = grep { /^$guid$/i } split /\n/, $out;
    $self->assert_num_equals(2, scalar @lines);    # one per copy
    unlink $db;

    xlog $self, "-vv: adds mailbox name and uid";
    ($code, $out) = $self->run_deduplicate('-B', '-f', $db, '-vv');
    $self->assert_num_equals(0, $code);
    $self->assert_matches(qr/^\S+ \d+ \Q$guid\E$/im, $out);
    unlink $db;

    xlog $self, "-vvv: adds dev:ino and nlink of the spool file";
    ($code, $out) = $self->run_deduplicate('-B', '-f', $db, '-vvv');
    $self->assert_num_equals(0, $code);
    $self->assert_matches(qr/^\S+ \d+ \d+:\d+ \d+ \Q$guid\E$/im, $out);
}

sub test_link_basic
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');
    $self->assert_not_linked(['INBOX', 1], ['INBOX.other', 1]);

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "no -v: link mode is quiet by default";
    my $out;
    ($code, $out) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_does_not_match(qr/^link /m, $out);

    $self->assert_linked(['INBOX', 1], ['INBOX.other', 1]);
    my (undef, undef, $nlink, undef) = $self->stat_msg_file('INBOX', 1);
    $self->assert_num_equals(2, $nlink);

    xlog $self, "both copies must still be identical over IMAP";
    my $talk = $self->{store}->get_client();
    $talk->select('INBOX');
    my $res1 = $talk->fetch('1', 'rfc822');
    $talk->select('INBOX.other');
    my $res2 = $talk->fetch('1', 'rfc822');
    $self->assert_str_equals($res1->{1}->{rfc822}, $res2->{1}->{rfc822});
}

sub test_link_verbosity
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "-v: a real link is reported per relinked file";
    my $out;
    ($code, $out) = $self->run_deduplicate('-L', '-f', $db, '-v');
    $self->assert_num_equals(0, $code);
    $self->assert_matches(qr/^link /m, $out);

    $self->assert_linked(['INBOX', 1], ['INBOX.other', 1]);
}

sub test_link_dry_run
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "dry run reports but must not change the spool";
    (my $c, my $out, undef) = $self->run_deduplicate('-L', '-f', $db,
                                                     '-d', '-c', '-v');
    $self->assert_num_equals(0, $c);
    $self->assert_matches(qr/^would link /m, $out);
    $self->assert_matches(qr/bytes would be saved by hardlinking/, $out);
    $self->assert_matches(qr/^1 inodes would be freed by hardlinking$/m, $out);
    $self->assert_not_linked(['INBOX', 1], ['INBOX.other', 1]);

    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_linked(['INBOX', 1], ['INBOX.other', 1]);
}

sub test_link_idempotent
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);

    my (undef, $ino) = $self->stat_msg_file('INBOX', 1);

    xlog $self, "a second link run must be a clean no-op";
    (my $c, my $out, undef) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $c);
    $self->assert_does_not_match(qr/^link /m, $out);

    my (undef, $ino2, $nlink) = $self->stat_msg_file('INBOX', 1);
    $self->assert_num_equals($ino, $ino2);
    $self->assert_num_equals(2, $nlink);
}

sub test_link_savings
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.a', 'INBOX.b');
    my (undef, undef, undef, $size) = $self->stat_msg_file('INBOX', 1);

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "three copies collapse onto one inode, freeing two";
    (my $c, my $out, undef) = $self->run_deduplicate('-L', '-f', $db, '-c');
    $self->assert_num_equals(0, $c);
    my ($saved) = $out =~ m/^(\d+) bytes saved by hardlinking$/m;
    $self->assert_not_null($saved);
    $self->assert_num_equals(2 * $size, $saved);
    $self->assert_matches(qr/^2 inodes freed by hardlinking$/m, $out);

    $self->assert_linked(['INBOX', 1], ['INBOX.a', 1], ['INBOX.b', 1]);
    my (undef, undef, $nlink) = $self->stat_msg_file('INBOX', 1);
    $self->assert_num_equals(3, $nlink);
}

#
# Tier 2: CLI handling and database validation
#

sub test_cli_modes
{
    my ($self) = @_;

    my $db = $self->{instance}->get_basedir() . "/dedup.db";

    xlog $self, "mode flags are mutually exclusive";
    my ($code) = $self->run_deduplicate('-B', '-L', '-f', $db);
    $self->assert_num_equals($EX{EX_USAGE}, $code);
    ($code) = $self->run_deduplicate('-B', '-B', '-f', $db);
    $self->assert_num_equals($EX{EX_USAGE}, $code);

    xlog $self, "a mode flag and -f are both required";
    ($code) = $self->run_deduplicate('-f', $db);
    $self->assert_num_equals($EX{EX_USAGE}, $code);
    ($code) = $self->run_deduplicate('-B');
    $self->assert_num_equals($EX{EX_USAGE}, $code);

    xlog $self, "only build mode takes mailbox arguments";
    ($code) = $self->run_deduplicate('-L', '-f', $db, 'user.cassandane');
    $self->assert_num_equals($EX{EX_USAGE}, $code);

    xlog $self, "a single mode flag works";
    $self->make_duplicate('message', 'INBOX');
    ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    ($code) = $self->run_deduplicate('-Z', '-f', $db);
    $self->assert_num_equals(0, $code);
}

sub test_build_refuses_existing
{
    my ($self) = @_;

    $self->make_duplicate('message', 'INBOX');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_file_test($db, '-f');

    (my $c, undef, my $err) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals($EX{EX_CANTCREAT}, $c);
    $self->assert_matches(qr/already exists/, $err);
}

sub test_build_no_match
{
    my ($self) = @_;

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code, undef, $err) = $self->run_deduplicate('-B', '-f', $db,
                                                     'nonexistent.folder.*');
    $self->assert_num_equals($EX{EX_NOUSER}, $code);
    $self->assert_matches(qr/No matching mailboxes/, $err);

    xlog $self, "a failed build must remove its partial output";
    $self->assert_not_file_test($db, '-e');
}

sub test_rejects_foreign_db
{
    my ($self) = @_;

    xlog $self, "a twoskip file that is not a deduplicate database";
    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    $self->{instance}->run_command({ cyrus => 1 },
        'cyr_dbtool', '-n', $db, 'twoskip', 'set', 'foo', 'bar');
    $self->assert_file_test($db, '-f');

    my ($code, undef, $err) = $self->run_deduplicate('-Z', '-f', $db);
    $self->assert_num_equals($EX{EX_DATAERR}, $code);
    $self->assert_matches(qr/not a deduplicate database/, $err);

    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals($EX{EX_DATAERR}, $code);
    ($code) = $self->run_deduplicate('-P', '-f', $db);
    $self->assert_num_equals($EX{EX_DATAERR}, $code);
}

sub test_prune
{
    my ($self) = @_;

    xlog $self, "two duplicate groups and three singletons";
    my $dupea = $self->make_duplicate('dupe A', 'INBOX', 'INBOX.a');
    my $dupeb = $self->make_duplicate('dupe B', 'INBOX', 'INBOX.b');
    my @singles;
    foreach my $n (1..3) {
        push @singles, $self->make_duplicate("single $n", 'INBOX');
    }

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    my $guids = $self->dump_guids($db);
    $self->assert_num_equals(5, scalar keys %$guids);

    xlog $self, "dry run reports the singletons but changes nothing";
    (my $c, my $out, undef) = $self->run_deduplicate('-P', '-f', $db,
                                                     '-d', '-v');
    $self->assert_num_equals(0, $c);
    my @would = ($out =~ m/^would prune /mg);
    $self->assert_num_equals(3, scalar @would);
    $self->assert_matches(qr/^3 singleton entries would be pruned$/m, $out);
    $guids = $self->dump_guids($db);
    $self->assert_num_equals(5, scalar keys %$guids);

    xlog $self, "prune drops exactly the singletons and compacts";
    my $size_before = -s $db;
    ($c, $out, undef) = $self->run_deduplicate('-P', '-f', $db, '-v');
    $self->assert_num_equals(0, $c);
    my @pruned = ($out =~ m/^prune /mg);
    $self->assert_num_equals(3, scalar @pruned);
    $self->assert_matches(qr/^3 singleton entries pruned$/m, $out);

    $guids = $self->dump_guids($db);
    $self->assert_num_equals(2, scalar keys %$guids);
    $self->assert_num_equals(2, $guids->{lc $dupea->get_guid()});
    $self->assert_num_equals(2, $guids->{lc $dupeb->get_guid()});
    foreach my $single (@singles) {
        $self->assert_null($guids->{lc $single->get_guid()});
    }

    my $size_after = -s $db;
    $self->assert($size_after < $size_before,
        "repack did not shrink the database " .
        "($size_after >= $size_before)");

    xlog $self, "the pruned database still drives a correct link phase";
    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_linked(['INBOX', 1], ['INBOX.a', 1]);
    $self->assert_linked(['INBOX', 2], ['INBOX.b', 1]);
}

#
# Tier 3: staleness is tolerated, real failures are not
#

sub test_link_stale_unlinked_file
    :DelayedExpunge
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.a', 'INBOX.b');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "expunge the INBOX copy and unlink it, like cyr_expire";
    my $talk = $self->{store}->get_client();
    $talk->select('INBOX');
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-X', '0');
    my @st = $self->stat_msg_file('INBOX', 1);
    $self->assert_num_equals(0, scalar @st);

    xlog $self, "benign staleness: exit 0, survivors still linked";
    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_linked(['INBOX.a', 1], ['INBOX.b', 1]);
}

sub test_link_stale_deleted_mailbox
    :ImmediateDelete
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.a', 'INBOX.b');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "delete a whole mailbox between build and link";
    my $talk = $self->{store}->get_client();
    $talk->delete('INBOX.b');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_linked(['INBOX', 1], ['INBOX.a', 1]);
}

sub test_link_renamed_mailbox
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX.src', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "records name mailboxes by uniqueid, so a rename " .
                "between build and link must still resolve";
    my $talk = $self->{store}->get_client();
    $talk->rename('INBOX.src', 'INBOX.dst');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_linked(['INBOX.dst', 1], ['INBOX.other', 1]);
}

sub test_link_size_mismatch_fails
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "grow one copy: same GUID recorded, different size";
    my $dir = $self->{instance}->folder_to_directory('INBOX.other');
    $self->assert_not_null($dir);
    my $path = "$dir/1.";
    my $orig_size = -s $path;
    my $fh = IO::File->new($path, '>>') or die "open $path: $!";
    $fh->print("xx");
    $fh->close();

    (my $c, undef, my $err) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals($EX{EX_TEMPFAIL}, $c);
    $self->assert_matches(qr/size mismatch/, $err);
    $self->assert_matches(qr/entries failed to link/, $err);
    $self->assert_not_linked(['INBOX', 1], ['INBOX.other', 1]);

    # restore the file so Cassandane's end-of-test reconstruct sanity
    # check does not trip over our deliberate corruption
    truncate($path, $orig_size) or die "truncate $path: $!";
}

sub test_link_verify_mismatch
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "flip one byte in place: same size, same recorded " .
                "GUID, different content, only -V catches this";
    my (undef, undef, undef, $size) = $self->stat_msg_file('INBOX.other', 1);
    my $dir = $self->{instance}->folder_to_directory('INBOX.other');
    $self->assert_not_null($dir);
    my $path = "$dir/1.";
    my $fh = IO::File->new($path, '+<') or die "open $path: $!";
    $fh->seek($size - 2, 0);
    $fh->read(my $byte, 1);
    my $newbyte = $byte eq 'x' ? 'y' : 'x';
    $fh->seek($size - 2, 0);
    $fh->syswrite($newbyte, 1);
    $fh->close();

    (my $c, undef, my $err) = $self->run_deduplicate('-L', '-f', $db, '-V');
    $self->assert_num_equals($EX{EX_TEMPFAIL}, $c);
    $self->assert_matches(qr/content mismatch/, $err);
    $self->assert_not_linked(['INBOX', 1], ['INBOX.other', 1]);

    # restore the byte so Cassandane's end-of-test reconstruct sanity
    # check does not trip over our deliberate corruption
    $fh = IO::File->new($path, '+<') or die "open $path: $!";
    $fh->seek($size - 2, 0);
    $fh->syswrite($byte, 1);
    $fh->close();
}

#
# Tier 4: boundaries and build options
#

sub test_cross_user_same_partition
{
    my ($self) = @_;

    $self->{instance}->create_user('other');

    xlog $self, "the same message delivered to two users";
    my $msg = $self->make_duplicate('duplicated', 'INBOX');
    $self->{adminstore}->set_folder('user.other');
    $self->_save_message($msg, $self->{adminstore});

    $self->assert_not_linked(['user.cassandane', 1], ['user.other', 1]);

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);

    $self->assert_linked(['user.cassandane', 1], ['user.other', 1]);
}

sub test_cross_partition_same_device
    :Partition2
{
    my ($self) = @_;

    # in the test environment both partitions live on one filesystem,
    # so cross-partition duplicates are linkable and this exercises
    # the cross-partition staging path. In production, partitions on
    # separate filesystems are skipped by the device check instead
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.cassandane.p2', 'p2');
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());
    $self->{_folders_made}->{'INBOX.p2'} = 1;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.p2');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);

    $self->assert_linked(['INBOX', 1], ['INBOX.p2', 1]);
}

sub test_build_partition_filter
    :Partition2
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.cassandane.p2', 'p2');
    $self->assert_str_equals('ok',
        $admintalk->get_last_completion_response());
    $self->{_folders_made}->{'INBOX.p2'} = 1;

    my $msg = $self->make_duplicate('duplicated', 'INBOX', 'INBOX.p2');
    my $guid = lc $msg->get_guid();

    my $db = $self->{instance}->get_basedir() . "/dedup.db";

    xlog $self, "-p default only scans the default partition";
    my ($code) = $self->run_deduplicate('-B', '-f', $db, '-p', 'default');
    $self->assert_num_equals(0, $code);
    my $guids = $self->dump_guids($db);
    $self->assert_num_equals(1, $guids->{$guid});
    unlink $db;

    xlog $self, "-p p2 only scans the p2 partition";
    ($code) = $self->run_deduplicate('-B', '-f', $db, '-p', 'p2');
    $self->assert_num_equals(0, $code);
    $guids = $self->dump_guids($db);
    $self->assert_num_equals(1, $guids->{$guid});
    unlink $db;

    xlog $self, "no -p scans every partition";
    ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);
    $guids = $self->dump_guids($db);
    $self->assert_num_equals(2, $guids->{$guid});
}

sub test_archived_message
    :ArchivePartition :min_version_3_0
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "archive the messages after the build, and the link " .
                "phase resolves current paths, so it must follow";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A', '0');

    my $data = $self->{instance}->run_mbpath('user.cassandane');
    my $archivedir = $data->{archive};
    $self->assert_file_test("$archivedir/1.", '-f');

    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);

    my $data2 = $self->{instance}->run_mbpath('user.cassandane.other');
    my @st1 = stat("$archivedir/1.");
    my @st2 = stat($data2->{archive} . "/1.");
    $self->assert(scalar @st1 && scalar @st2);
    $self->assert_num_equals($st1[1], $st2[1]);
}

sub test_build_skip_expunged
    :DelayedExpunge
{
    my ($self) = @_;

    my $msg = $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    xlog $self, "expunge the INBOX copy. With delayed expunge its " .
                "spool file stays on disk";
    my $talk = $self->{store}->get_client();
    $talk->select('INBOX');
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();
    my @st = $self->stat_msg_file('INBOX', 1);
    $self->assert(scalar @st);

    my $basedir = $self->{instance}->get_basedir();
    my ($code) = $self->run_deduplicate('-B', '-f', "$basedir/dedup1.db",
                                        '-e');
    $self->assert_num_equals(0, $code);
    my $guids = $self->dump_guids("$basedir/dedup1.db");
    $self->assert_num_equals(1, $guids->{lc $msg->get_guid()});

    ($code) = $self->run_deduplicate('-B', '-f', "$basedir/dedup2.db");
    $self->assert_num_equals(0, $code);
    $guids = $self->dump_guids("$basedir/dedup2.db");
    $self->assert_num_equals(2, $guids->{lc $msg->get_guid()});
}

sub test_build_skip_deleted
    :DelayedDelete :AllowDeleted
{
    my ($self) = @_;

    my $msg = $self->make_duplicate('duplicated', 'INBOX', 'INBOX.doomed');

    xlog $self, "with delayed delete the mailbox moves under " .
                "DELETED.* and its spool file stays on disk";
    my $talk = $self->{store}->get_client();
    $talk->delete('INBOX.doomed');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $basedir = $self->{instance}->get_basedir();
    my ($code) = $self->run_deduplicate('-B', '-f', "$basedir/dedup1.db",
                                        '-x');
    $self->assert_num_equals(0, $code);
    my $guids = $self->dump_guids("$basedir/dedup1.db");
    $self->assert_num_equals(1, $guids->{lc $msg->get_guid()});

    ($code) = $self->run_deduplicate('-B', '-f', "$basedir/dedup2.db");
    $self->assert_num_equals(0, $code);
    $guids = $self->dump_guids("$basedir/dedup2.db");
    $self->assert_num_equals(2, $guids->{lc $msg->get_guid()});
}

sub test_stale_tmp_cleanup
{
    my ($self) = @_;

    $self->make_duplicate('duplicated', 'INBOX', 'INBOX.other');

    my $db = $self->{instance}->get_basedir() . "/dedup.db";
    my ($code) = $self->run_deduplicate('-B', '-f', $db);
    $self->assert_num_equals(0, $code);

    xlog $self, "plant a stray tmp file where a crashed run would " .
                "have left one, and the relink must consume it";
    my $dir = $self->{instance}->folder_to_directory('INBOX.other');
    $self->assert_not_null($dir);
    my $stray = "$dir/1..dedup";
    my $fh = IO::File->new($stray, '>') or die "open $stray: $!";
    $fh->print("junk");
    $fh->close();

    ($code) = $self->run_deduplicate('-L', '-f', $db);
    $self->assert_num_equals(0, $code);
    $self->assert_linked(['INBOX', 1], ['INBOX.other', 1]);
    $self->assert_not_file_test($stray, '-e');
}

1;
