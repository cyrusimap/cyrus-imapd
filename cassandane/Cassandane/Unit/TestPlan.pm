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
use Cassandane::Unit::TestCase;
use Cassandane::Unit::TestPlanItem;
use Cassandane::Unit::WorkerListener;
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
        slow_only => delete $opts{slow_only} // 0,
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
    return if ($path =~ m/\/TestCase\.pm$/);

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
        my @names = map {; s/^test_//r } $item->_get_loaded_suite()->names()->@*;

        return if grep {; $item->_is_allowed($_) } @names;
    }

    die "No tests to run: the test plan is empty\n";
}

# Check what the specifications that named individual tests actually selected.
# This can't happen while they're being parsed, because it needs the suites to
# be loaded, which can't happen until we know which suites to load.
#
# A specification that matches no tests at all is fatal.  It's nearly always a
# typo, and you think everything passed, but actually nothing ran.
#
# A specification that matches only slow tests turns the skip_slow filter off,
# on the grounds that you can't have meant to ask for tests that were then
# going to be filtered out from under you.
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

    foreach my $spec (@specs)
    {
        my @tests = $matched{$spec}->@*;

        if ($self->{skip_slow} and @tests == grep {; /_slow$/ } @tests)
        {
            xlog "$spec was explicitly requested. Enabling slow tests!";
            $self->{skip_slow} = 0;
        }

        if ($self->{slow_only} and not grep {; $_ =~ m/_slow$/ } @tests)
        {
            xlog "$spec was explicitly requested. Enabling regular tests!";
            $self->{slow_only} = 0;
        }
    }
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
        my $loaded = $item->_get_loaded_suite();
        foreach my $name (sort @{$loaded->names()})
        {
            $name =~ s/^test_//;
            next unless $item->_is_allowed($name);

            my (@settings) = Cassandane::Unit::TestCase->make_parameter_settings($item->{suite});
            foreach my $setting (@settings)
            {
                push(@res, {
                    suite => $item->{suite},
                    testname => $name,
                    result => 'unknown',
                    exception => undef,
                    logfile => undef,
                    parameter_setting => $setting,
                });
            }
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

sub _setup_logfile
{
    my ($self, $witem) = @_;

    # Flush the old stdout/stderr
    ${\*STDOUT}->flush;
    ${\*STDERR}->flush;

    # Save the old stdout/stderr - this is important
    # for the single threaded case where inter-test
    # messages go to the original stdout.
    open my $oldout, '>&', \*STDOUT
        or die "Cannot save STDOUT";
    open my $olderr, '>&', \*STDERR
        or die "Cannot save STDERR";

    my $logfh;
    my $logfile;
    srand;   # XXX does this fix the tempfile() issue (#42)?
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

    unless ($ENV{CASSANDANE_LIVE_OUTPUT}) {
      # Redirect both STDOUT and STDERR to the log file
      open STDOUT, '>&', $logfh
          or die "Cannot redirect STDOUT";
      open STDERR, '>&', $logfh
          or die "Cannot redirect STDERR";
      close $logfh;
    }

    $witem->{logfile} = $logfile;
    $self->{oldout} = $oldout;
    $self->{olderr} = $olderr;
}

# Redirect STDOUT and STDERR back to their original fds
sub _restore_stdout
{
    my ($self) = @_;

    ${\*STDOUT}->flush;
    open STDOUT, '>&', $self->{oldout}
        or die "Cannot restore STDOUT";
    close $self->{oldout};
    $self->{oldout} = undef;

    ${\*STDERR}->flush;
    open STDERR, '>&', $self->{olderr}
        or die "Cannot restore STDERR";
    close $self->{olderr};
    $self->{olderr} = undef;
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

sub _get_suite_and_test
{
    my ($self, $witem) = @_;
    my $suite = $self->_get_item($witem->{suite})->_get_loaded_suite();
    my ($test) = grep { $_->name() eq 'test_' . $witem->{testname}; } @{$suite->tests()};
    return ($suite, $test);
}

sub _run_workitem
{
    my ($self, $witem, $result, $runner, $annotate_flag) = @_;
    my ($suite, $test) = $self->_get_suite_and_test($witem);
    Cassandane::Unit::TestCase->enable_test($witem->{testname});
    $self->_setup_logfile($witem);
    Cassandane::Unit::TestCase->apply_parameter_setting($witem->{parameter_setting});
    $suite->run($result, $runner);

    if ($test->can('post_tear_down'))
    {
        eval
        {
            $test->post_tear_down($witem->{result});
        };
        my $ex = $@;
        if ($ex)
        {
            $result->add_error($test,
                               Test::Unit::Error->make_new_from_error($ex));
        }
    }

    $self->_restore_stdout();
    if ($annotate_flag)
    {
        $test->annotate_from_file($witem->{logfile});
        _dump_logfile($witem->{logfile}) if (get_verbose > 1);
        unlink($witem->{logfile}) if (!defined $self->{log_directory});
    }
}

sub _finish_workitem
{
    my ($self, $witem, $result, $runner) = @_;
    my ($suite, $test) = $self->_get_suite_and_test($witem);

    # The test was actually started earlier by _run_workitem, but its
    # start_test event wasn't sent.  It might have got swallowed due to
    # the output format listeners being removed in the workitem handling.
    # Send the event again now, to make sure the formatters actually get
    # it...
    $result->start_test($test);
    # But! If they're computing their own start time based on this event
    # they'll get it wrong.  We know the real start time, so tell the
    # formatter to use that instead.
    if ($runner->can('tell_formatters'))
    {
        $runner->tell_formatters('fake_start_time',
                                 $test,
                                 $witem->{start_time});
    }

    $test->annotate_from_file($witem->{logfile});
    _dump_logfile($witem->{logfile}) if (get_verbose > 1);
    unlink($witem->{logfile}) if (!defined $self->{log_directory});

    if ($witem->{result} eq 'pass')
    {
        $result->add_pass($test);
    }
    elsif ($witem->{result} eq 'fail')
    {
        $witem->{exception}->{'-object'} = $test;
        $result->add_failure($test, $witem->{exception});
    }
    elsif ($witem->{result} eq 'error')
    {
        $witem->{exception}->{'-object'} = $test;
        $result->add_error($test, $witem->{exception});
    }
    $result->end_test($test);
}

sub _setup_worker_listeners
{
    my ($result, $wlistener) = @_;

    # Remove the output format listener
    my @list;
    my $found = 0;
    foreach my $ll (@{$result->{_Listeners}})
    {
        push(@list, $ll)
            unless defined $ll->{remove_me_in_cassandane_child};
        $found ||= (ref($ll) eq ref($wlistener));
    }
    push(@list, $wlistener)
        unless $found;
    $result->{_Listeners} = \@list;
}

# The 'run' method makes this class look sufficiently like a
# Test::Unit::TestCase that Test::Unit::TestRunner will happily run it.
# This enables us to run all our scheduled tests with a single
# TestResult and a single summary of errors.
sub run
{
    my ($self, $result, $runner) = @_;

    my $maxworkers = $self->{maxworkers} || 1;

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

    if ($maxworkers > 1)
    {
        # multi-threaded case: use worker pool

        # we want an error not a signal
        $SIG{PIPE} = 'IGNORE';

        # Just In Case any code samples this in a TestCase c'tor
        $ENV{TEST_UNIT_WORKER_ID} = 'invalid';

        my $wlistener = Cassandane::Unit::WorkerListener->new();

        my $pool = Cassandane::Unit::WorkerPool->new(
            maxworkers => $maxworkers,
            handler => sub {
                my ($witem) = @_;
                $wlistener->{witem} = $witem;
                _setup_worker_listeners($result, $wlistener);
                $self->_run_workitem($witem, $result, $runner, 0);
            },
        );
        my $witem;
        $pool->start();
        # first ^C stops spawning new work items
        while ($interrupted < 1 && ($witem = shift @workitems))
        {
            $pool->assign($witem)
                if ($self->{keep_going} || $result->was_successful());
            while ($witem = $pool->retrieve(0))
            {
                $self->_finish_workitem($witem, $result, $runner);
            }
        }
        # second ^C stops waiting for work items to finish
        while ($interrupted < 2 && ($witem = $pool->retrieve(1)))
        {
            $self->_finish_workitem($witem, $result, $runner);
        }
        $pool->stop();
    }
    else
    {
        # single threaded case: just run it all in-process
        foreach my $witem (@workitems)
        {
            $self->_run_workitem($witem, $result, $runner, 1);
            last if ($interrupted || !($self->{keep_going} || $result->was_successful()));
        }
    }

    return $result->was_successful();
}

1;
