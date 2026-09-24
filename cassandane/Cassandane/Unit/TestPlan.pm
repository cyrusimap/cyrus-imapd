# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::TestPlan;
use strict;
use warnings;
use experimental 'signatures';

use File::Find;
use File::Temp qw(tempfile);
use File::Path qw(mkpath);
use Data::Dumper;
use Cassandane::Util::Log;
use Cassandane::Unit::TestSuite;
use Cassandane::Unit::TestPlanItem;
use Cassandane::Unit::WorkerPool;

my @default_test_roots = (
    'Cassandane/Test',
    'Cassandane/Cyrus',
);

sub new
{
    my ($class, %opts) = @_;
    my $self = {
        schedule => {},
        keep_going => delete $opts{keep_going} || 0,
        log_directory => delete $opts{log_directory},
        maxworkers => delete $opts{maxworkers} || 1,
        skip_slow => delete $opts{skip_slow} // 1,
        test_roots => delete $opts{test_roots} // [ @default_test_roots ],
    };
    die "Unknown options: " . join(' ', keys %opts)
        if scalar %opts;
    return bless $self, $class;
}

sub _get_item
{
    my ($self, $suite) = @_;
    return $self->{schedule}->{$suite} ||=
        Cassandane::Unit::TestPlanItem->new($suite);
}

sub _schedule
{
    my ($self, $neg, $path, $testname, $spec) = @_;
    return if ($path =~ m/\/TestSuite\.pm$/);

    my $suite = $path;
    $suite =~ s/\.pm$//;
    $suite =~ s/\//::/g;

    if ($neg eq '!')
    {
        if (defined $testname)
        {
            # disable a specific test
            $self->_get_item($suite)->_deny($testname);
        }
        else
        {
            # remove entire suite
            delete $self->{schedule}->{$suite};
        }
    }
    else
    {
        # add to the schedule
        my $item = $self->_get_item($suite);
        if (defined $testname)
        {
            $item->_allow($testname, $spec) if $testname;
        }
    }
}

# Turns a glob into an anchored regex.  '*' matches any run of characters,
# including none, and nothing else is special.
sub _glob_to_regex ($glob)
{
    my @hunks = split /\*+/, $glob, -1;
    my $regex = join q{.*}, map {; quotemeta } @hunks;

    return qr{\A$regex\z};
}

# Given a path whose last component may be a glob -- ".../Cyrus/JMAP*" --
# return the suite files it matches, in sorted order.  Returns nothing if
# there's no glob to expand, or if the directory that would hold the matches
# doesn't exist, so the caller can use this to ask "is this a globbed suite
# name?" without checking first.
sub _glob_suites ($path)
{
    my ($dir, $leaf) = ($path =~ m/^(.*)\/([^\/]+)$/);
    return if not defined $leaf;
    return if $leaf !~ m/\*/;
    return if not -d $dir;

    my $regex = _glob_to_regex($leaf);

    opendir my $dh, $dir
        or die "Cannot open directory $dir for reading: $!";
    my @moniker = grep {; my $m = $_; $m =~ s/\.pm$// and $m =~ $regex }
                  readdir $dh;
    closedir $dh;

    return map {; "$dir/$_" } sort @moniker;
}

# Returns a list of [ $neg, $ostype, $ospath, $testname ] tuples.  It's a list
# because one specification can name more than one test case.
#
# An exact name is resolved against the roots in order and the first hit wins,
# so that a test case in an earlier root shadows one of the same name later on.  A
# globbed test case name is instead collected from every root, because "JMAP*"
# plainly means all of them and not just the ones in whichever root happened to
# match first.
sub _parse_test_spec
{
    my ($self, $name) = @_;

    my ($neg, $path) = ($name =~ m/^([~!]?)(.*)$/);
    $path =~ s/\.pm$//g;
    $path =~ s/::/\//g;
    $path =~ s/\./\//g;
    $path =~ s/\/+/\//g;
    $path =~ s/^\/*//;
    $path =~ s/\/*$//;

    $neg = '!' if $neg eq '~';

    # '*' has to be quoted in every shell worth using, so let '+' mean the same
    # thing.  Neither suite names nor test names can contain a '+', so there's
    # no loss in functionality.
    $path =~ s/\+/*/g;

    # Allow Cyrus::TesterJMAP and TesterJMAP to work
    my @paths;

    my @dirs = split('/', $path);

    while (@dirs) {
        push @paths, join('/', @dirs);
        shift @dirs;
    }

    foreach my $candidate (@paths) {
        my @globbed;

        foreach my $root ($self->{test_roots}->@*)
        {
            return [ $neg, q{d}, $candidate, undef ]
                if ($root eq $candidate);

            my $fpath = $candidate;
            $fpath = "$root/$candidate"
                if ("$root/" ne substr($candidate, 0, length($root)+1));

            return [ $neg, q{d}, $fpath, undef ]
                if ( -d $fpath );
            return [ $neg, q{f}, "$fpath.pm", undef ]
                if ( -f "$fpath.pm" );

            # the whole thing may be a globbed suite name, with no test named
            push @globbed, map {; [ $neg, q{f}, $_, undef ] }
                           _glob_suites($fpath);

            my $test;
            ($fpath, $test) = ($fpath =~ m/^(.*)\/([^\/]+)$/);
            next unless defined $test;

            $test = _glob_to_regex($test) if $test =~ m/\*/;

            return [ $neg, q{f}, "$fpath.pm", $test ]
                if ( -f "$fpath.pm" );

            # ... or the suite part alone may be globbed, with a test after it
            push @globbed, map {; [ $neg, q{f}, $_, $test ] }
                           _glob_suites($fpath);
        }

        return @globbed if @globbed;
    }

    die "Unrecognised test specification: $name";
}

sub _default_test_list
{
    my ($self) = @_;

    my $cassini = Cassandane::Cassini->instance();
    my @tosuppress = split /\s+/, $cassini->val('cassandane', 'suppress', '');

    my %default;
    my %suppressed;
    @default{$self->{test_roots}->@*} = ();

    # skip suppressions
    foreach my $s (@tosuppress) {
        if (exists $default{$s}) {
            # if it's named explicitly in the default list, un-name it
            delete $default{$s};
        }
        else {
            # otherwise, add a negation for it
            $suppressed{"!$s"} = undef;
        }
    }

    die "no default tests" if not scalar keys %default;
    return (sort(keys %default), sort(keys %suppressed));
}

sub schedule
{
    my ($self, @names) = @_;

    if (not scalar @names) {
        # if no names provided, use default list
        @names = $self->_default_test_list();
    }
    elsif (not scalar grep { m/^[^!~]/ } @names) {
        # if only negations provided, start with default list
        @names = ($self->_default_test_list(), @names);
    }

    foreach my $name (@names)
    {
        foreach my $spec ($self->_parse_test_spec($name))
        {
            my ($neg, $type, $path, $test) = @$spec;

            if ($type eq 'd')
            {
                opendir DIR, $path
                    or die "Cannot open directory $path for reading: $!";
                while ($_ = readdir DIR)
                {
                    next unless m/\.pm$/;
                    $self->_schedule($neg, "$path/$_", undef, $name);
                }
                closedir DIR;
            }
            else
            {
                $self->_schedule($neg, $path, $test, $name);
            }
        }
    }

    $self->_check_selections();
    $self->_check_not_empty();
}

# Every specification can be fine, but we still have nothing to run, because a
# negation can cancel out a selection: "ACL !ACL" is nothing.
sub _check_not_empty ($self)
{
    foreach my $item (values $self->{schedule}->%*)
    {
        return if grep {; $item->_is_allowed($_) } $item->_test_names();
    }

    die "No tests to run: the test plan is empty\n";
}

# Check what the specifications that named individual tests actually selected.
# This can't happen while they're being parsed, because it needs the suites to
# be loaded, which can't happen until we know which suites to load.
#
# A specification that matches no tests at all is fatal.  It's nearly always a
# typo, and you think everything passed, but actually nothing ran.
sub _check_selections ($self)
{
    # One specification can be applied to several suites, so gather up
    # everything it matched before judging it.  "JMAP*.blob_get" has done its
    # job if any one of the JMAP suites has that test; it's only a mistake if
    # none of them do.
    my (@specs, %matched);

    foreach my $item ($self->{schedule}->@{ sort keys $self->{schedule}->%* })
    {
        foreach my $match ($item->_get_candidates())
        {
            my $spec = $match->{spec};

            push @specs, $spec if not $matched{$spec};
            $matched{$spec} //= [];
            push $matched{$spec}->@*, $match->{tests}->@*;
        }
    }

    my @unmatched = grep {; ! $matched{$_}->@* } @specs;
    die "No tests matched: " . join(q{, }, @unmatched) . "\n" if @unmatched;
}

sub check_sanity
{
    my ($self, %params) = @_;

    my $nonfatal = delete $params{nonfatal};

    # collect tiny-tests directories that are used by test modules
    my %used_tt_dirs;
    find({
        no_chdir => 1,
        wanted => sub {
            my $fname = $File::Find::name;

            return if not -f $fname;
            return if $fname !~ m/\.pm$/;

            my ($moniker) = $fname =~ m{([^/]+)\.pm$};

            open my $fh, '<', $fname or die "open $fname: $!";
            while (<$fh>) {
                if (m{^\s*use\s+Cassandane::Tiny::Loader;\s*$})
                {
                    push @{$used_tt_dirs{"tiny-tests/$moniker"}}, $fname;
                }
            }
            close $fh;
        },
    }, $self->{test_roots}->@*);

    # collect tiny-tests directories that exist on disk
    my %real_tt_dirs;
    find({
        no_chdir => 1,
        wanted => sub {
            my $fname = $File::Find::name;

            my ($tt, $suite, $test) = split q{/}, $fname, 3;
            return if not $suite;

            # ignore dot-dirs
            return if $suite =~ m{\A\.};

            if (not $test) {
                # explicit initialisation to detect directories with no files
                $real_tt_dirs{"$tt/$suite"} //= 0;
                return;
            }

            $real_tt_dirs{"$tt/$suite"} ++;
        },
    }, 'tiny-tests') if -d 'tiny-tests';

    my @tt_errors;

    # whinge about bad test modules
    while (my ($tt, $modules) = each %used_tt_dirs) {
        # XXX this one might not be an error if we start doing this
        # XXX intentionally, perhaps to run the same group of tests under
        # XXX different setups or configurations
        push @tt_errors, "@{$modules} share tiny-tests directory $tt"
            if scalar @{$modules} > 1;

        push @tt_errors, "$modules->[0] uses nonexistent tiny-tests directory $tt"
            if not exists $real_tt_dirs{$tt};
    }

    # whinge about orphaned directories
    while (my ($tt, $ntests) = each %real_tt_dirs) {
        push @tt_errors, "$tt directory is not used by any tests"
            if not $used_tt_dirs{$tt};

        push @tt_errors, "$tt directory contains no tests"
            if not $ntests;
    }

    # whinge about 'tiny-tests' directories in unexpected places
    # start searching in the parent directory so that we're checking the
    # whole cyrus-imapd repository -- but not things in dot-dirs, because we
    # might use them (like cyrus-imapd.git/.claude/worktrees) for in-repo
    # worktrees.  A worktree will, of course, contain tiny-tests.
    my @unexpected_tt_dirs = grep {
        chomp;
        $_ ne '../cassandane/tiny-tests';
    } qx{find .. -path '../.*' -prune -o -type d -name tiny-tests -print};
    push @tt_errors, "unexpected extra tiny-tests directories: @unexpected_tt_dirs"
        if @unexpected_tt_dirs;

    if (@tt_errors) {
        print STDERR "$_\n" for @tt_errors;

        if ($nonfatal) {
            warn 'bad tiny-tests detected';
        }
        else {
            die 'bad tiny-tests detected';
        }
    }
}

#
# Get the entire expanded schedule as specific {suite,testname} tuples,
# sorted in alphabetic order on suite name then testname.
#
sub _get_schedule
{
    my ($self) = @_;

    my @items = sort { $a->{suite} cmp $b->{suite} } values %{$self->{schedule}};
    my @res;
    foreach my $item (@items)
    {
        foreach my $name ($item->_test_names())
        {
            next unless $item->_is_allowed($name);

            push @res, {
                suite => $item->{suite},
                testname => $name,
            };
        }
    }
    return @res;
}

# Sort and return the schedule as a list of "suite.test" strings
# e.g. "Cassandane::Cyrus::Quota.using_storage".
sub list
{
    my ($self) = @_;

    my @res;
    foreach my $witem ($self->_get_schedule())
    {
        push(@res, "$witem->{suite}.$witem->{testname}");
    }

    return @res;
}

# Choose the log file a work item's output will go to.  This happens in the
# parent, before the item is handed to a worker, so that the parent can still
# read the output if the worker never comes back to say where it went.
sub _make_logfile
{
    my ($self, $witem) = @_;

    my $logfh;
    my $logfile;
    if (defined $self->{log_directory})
    {
        # Log directory specified so create the log file
        # there with a semi-obvious name
        if (! -d $self->{log_directory})
        {
            mkpath($self->{log_directory})
                or die "Cannot create directory $self->{log_directory}: $!";
        }
        my $template = $witem->{suite} .  '.' .  $witem->{testname} .  '.XXXXXX';
        $template =~ s/::/./g;
        ($logfh, $logfile) = tempfile($template,
                                      DIR => $self->{log_directory},
                                      SUFFIX => '.log',
                                      UNLINK => 0);
        chmod(0644, $logfile);
    }
    else
    {
        # Create a per-test temporary logfile
        ($logfh, $logfile) = tempfile(UNLINK => 0);
    }
    close $logfh;

    $witem->{logfile} = $logfile;
}

sub _dump_logfile
{
    my ($logfile) = @_;

    open LOGFILE, '<', $logfile
        or die "Cannot open $logfile for reading: $!";
    while (<LOGFILE>)
    {
        print STDERR $_;
    }
    close LOGFILE;
}

# Whatever the test wrote while it ran.  The worker pointed the test's output
# at this file; a report quotes it under a failure.
sub _annotations_from
{
    my ($logfile) = @_;
    return if not defined $logfile;

    open my $fh, '<', $logfile
        or die "Cannot open $logfile for reading: $!";
    local $/;
    return <$fh>;
}

sub _finish_workitem
{
    my ($self, $witem, $result) = @_;

    if ($witem->{outcome} eq 'skip')
    {
        unlink($witem->{logfile}) if (!defined $self->{log_directory});

        # A skipped test has no result to add: it never started, so nothing
        # counts it as a run.  The listeners still hear about it, because a
        # skip is worth reporting.
        $result->tell_listeners(add_skip => $witem);
        return;
    }

    $witem->{annotations} = _annotations_from($witem->{logfile});
    _dump_logfile($witem->{logfile}) if (get_verbose > 1);
    unlink($witem->{logfile}) if (!defined $self->{log_directory});

    # The test ran in a worker, which has no listeners to tell.  Send the
    # start_test event now, so that the formatters hear about the test
    # before they hear how it went.
    $result->start_test($witem);

    if ($witem->{outcome} eq 'pass')
    {
        $result->add_pass($witem);
    }
    elsif ($witem->{outcome} eq 'fail')
    {
        $result->add_failure($witem);
    }
    elsif ($witem->{outcome} eq 'error')
    {
        $result->add_error($witem);
    }
    else
    {
        die "Unknown outcome '$witem->{outcome}' for"
            . " $witem->{suite}.$witem->{testname}";
    }
    $result->end_test($witem);
}

# The runner hands the whole plan to run(), rather than one suite at a time,
# so that every scheduled test lands in one result and one summary.
#
# Tests always run in a worker, even when there is only one worker to run
# them: one way of working is worth more than the fork it costs.
sub run
{
    my ($self, $result) = @_;

    # we expand the schedule before forking the
    # workers so that we can just hand the reference
    # to the worker
    my @workitems = $self->_get_schedule();

    # try to clean up after ourselves on interrupt
    my $interrupted = 0;
    $SIG{INT} = sub {
        $interrupted ++;
        # third ^C will terminate without cleanup
        $SIG{INT} = 'DEFAULT' if $interrupted >= 2;
    };

    # we want an error not a signal
    $SIG{PIPE} = 'IGNORE';

    # Just In Case any code samples this in a TestSuite c'tor
    $ENV{CASSANDANE_WORKER_ID} = 'invalid';

    my $pool = Cassandane::Unit::WorkerPool->new(
        maxworkers => $self->{maxworkers} || 1,
        skip_slow  => $self->{skip_slow},
    );

    my ($witem, $done);
    $pool->start();
    # first ^C stops spawning new work items
    while ($interrupted < 1 && ($witem = shift @workitems))
    {
        if ($self->{keep_going} || $result->was_successful())
        {
            $self->_make_logfile($witem);
            $pool->assign($witem);
        }
        while ($done = $pool->retrieve(0))
        {
            $self->_finish_workitem($done, $result);
        }
    }
    # second ^C stops waiting for work items to finish
    while ($interrupted < 2 && ($done = $pool->retrieve(1)))
    {
        $self->_finish_workitem($done, $result);
    }
    $pool->stop();

    return $result->was_successful();
}

1;
