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

package Cassandane::Unit::TestPlanItem;
use strict;
use warnings;
use IO::Handle;
use POSIX;
use Time::HiRes qw(time);

use lib '.';
use Cassandane::Unit::TestCase;

sub new
{
    my ($class, $suite) = @_;
    my $self = {
        suite => $suite,
        loaded_suite => undef,
        denied => {},
        allowed => {},
    };
    return bless $self, $class;
}

sub _get_loaded_suite
{
    my ($self) = @_;
    return $self->{loaded_suite} ||= Test::Unit::Loader::load($self->{suite});
}

sub _is_allowed
{
    my ($self, $name) = @_;

    # Rules are:
    # deny if method has been explicitly denied
    return 0 if $self->{denied}->{$name};
    # allow if method has been explicitly allowed
    return 1 if $self->{allowed}->{$name};
    # deny if anything is explicitly allowed
    return 0 if scalar keys %{$self->{allowed}};
    # finally, allow
    return 1;
}

sub _deny
{
    my ($self, $name) = @_;
    $self->{denied}->{$name} = 1;
}

sub _allow
{
    my ($self, $name) = @_;
    $self->{allowed}->{$name} = 1;
}

package Cassandane::Unit::Worker;
use Storable qw(freeze thaw);
use MIME::Base64;

my $nextid = 1;

sub new
{
    my ($class) = @_;
    my $self = {
        id => $nextid++,
        pid => undef,
        downpipe => undef,
        uppipe => undef,
        busy => 0,
        handler => undef,
    };
    return bless $self, $class;
}

sub _pipe_read_fh
{
    my ($r, $w) = @_;

    POSIX::close($w);
    my $fh = IO::Handle->new_from_fd($r, "r");
    $fh->autoflush(1);
    return $fh;
}

sub _pipe_write_fh
{
    my ($r, $w) = @_;

    POSIX::close($r);
    my $fh = IO::Handle->new_from_fd($w, "w");
    $fh->autoflush(1);
    return $fh;
}

sub start
{
    my ($self) = @_;

    my ($dr, $dw) = POSIX::pipe();
    die "Cannot create down pipe: $!"
        unless defined $dw;

    my ($ur, $uw) = POSIX::pipe();
    die "Cannot create up pipe: $!"
        unless defined $uw;

    my $pid = fork();
    die "Cannot fork: $!" unless defined $pid;

    if ($pid)
    {
        # parent
        $self->{downpipe} = _pipe_write_fh($dr, $dw);
        $self->{uppipe} = _pipe_read_fh($ur, $uw);
        $self->{pid} = $pid;
    }
    else
    {
        # child
        $self->{downpipe} = _pipe_read_fh($dr, $dw);
        $self->{uppipe} = _pipe_write_fh($ur, $uw);
        $ENV{TEST_UNIT_WORKER_ID} = $self->{id};    # 1, 2, 3...
        $ENV{TEST_UNIT_BASENAME} = $0;
        $0 = "$ENV{TEST_UNIT_BASENAME} ($ENV{TEST_UNIT_WORKER_ID})";
        $self->_mainloop();
        exit(0);
    }
}

sub _send
{
    my ($fh, $fmt, @args) = @_;
    my $msg = sprintf($fmt, @args);
# print STDERR "--> \"$msg\"\n";
    syswrite($fh, $msg)
        or die "Cannot write to pipe: $!";
}

sub _receive
{
    my ($fh) = @_;
    my $msg = $fh->gets()
        or return;
# print STDERR "<-- \"$msg\"\n";
    chomp $msg;
    return $msg;
}

sub _mainloop
{
    my ($self) = @_;

    while (my $msg = _receive($self->{downpipe}))
    {
        my ($command, @args) = split(/\s+/, $msg);

        if ($command eq 'stop')
        {
            return;
        }
        elsif ($command eq 'run')
        {
            my ($witem) = thaw(decode_base64($args[0]));
            $0 = "$ENV{TEST_UNIT_BASENAME} ($ENV{TEST_UNIT_WORKER_ID}) $witem->{suite}.$witem->{testname}";
            $self->{handler}->($witem);
            $0 = "$ENV{TEST_UNIT_BASENAME} ($ENV{TEST_UNIT_WORKER_ID})";
            _send($self->{uppipe},
                  "done %s\n", encode_base64(freeze($witem), ''));
        }
        else
        {
            print STDERR "_mainloop: unknown command '$command'\n";
        }
    }
}

sub get_reply
{
    my ($self) = @_;
    return if !$self->{busy};
    my $msg = _receive($self->{uppipe});
    return if !defined $msg;
    my ($command, @args) = split(/\s+/, $msg);
    die "Unknown message \"$msg\""
        if ($command ne 'done');
    $self->{busy} = 0;
    my ($witem) = thaw(decode_base64($args[0]));
    return $witem;
}

sub assign
{
    my ($self, $witem) = @_;
    $witem->{start_time} = time();
    _send($self->{downpipe},
          "run %s\n", encode_base64(freeze($witem), ''));
    $self->{busy} = 1;
}

sub stop
{
    my ($self) = @_;
    eval
    {
        # We don't care if this dies, it just
        # means the Worker has died prematurely.
        _send($self->{downpipe}, "stop\n");
    };
    while (1)
    {
        my $res = waitpid($self->{pid}, 0);
        last if ($res < 0 || $res == $self->{pid});
    }
    $self->_cleanup();
}

sub _cleanup
{
    my ($self) = @_;

    if ($self->{downpipe})
    {
        close $self->{downpipe};
        $self->{downpipe} = undef;
    }

    if ($self->{uppipe})
    {
        close $self->{uppipe};
        $self->{uppipe} = undef;
    }

    $self->{pid} = undef;
}

sub DESTROY
{
    my ($self) = @_;
    $self->_cleanup();
}

package Cassandane::Unit::WorkerPool;

use Errno qw(EINTR);

sub new
{
    my ($class, %params) = @_;
    my $self = {
        workers => [],
        maxworkers => 2,
        pending => [],
        handler => sub { die "This should not happen"; },
    };
    foreach my $p (qw(maxworkers handler))
    {
        $self->{$p} = $params{$p} if $params{$p};
    }
    return bless $self, $class;
}

sub start
{
    my ($self) = @_;

    while (scalar @{$self->{workers}} < $self->{maxworkers})
    {
        my $w = Cassandane::Unit::Worker->new();
        $w->{handler} = $self->{handler};
        $w->start();
        push(@{$self->{workers}}, $w);
    }
}

# Assign an work item to an idle worker if necessary
# block until a worker is idle.
sub assign
{
    my ($self, $witem) = @_;

    my @idle = grep { !$_->{busy}; } @{$self->{workers}};
    my $w = shift @idle || $self->_wait();
    $w->assign($witem);
}

# Wait for a Worker to send back a completed work item.
# Mark the Worker idle, remember its work item where
# retrieve() will find it, and returns the Worker.
sub _wait
{
    my ($self) = @_;


    # Build the bit mask for select()
    my $rbits = '';
    foreach my $w (@{$self->{workers}})
    {
        next if (!$w->{busy});
        vec($rbits, fileno($w->{uppipe}), 1) = 1;
    }

    # select() with no timeout
    my $res;
    do {
        $res = select($rbits, undef, undef, undef);
    } while ($res < 0 && $! == EINTR);
    die "select failed: $!" if ($res < 0);

    # discover which of our workers has responded
    foreach my $w (@{$self->{workers}})
    {
        if (vec($rbits, fileno($w->{uppipe}), 1))
        {
            push(@{$self->{pending}}, $w->get_reply());
            return $w;
        }
    }
    die "Unexpected result from select: $res";
}

# Retrieve a completed work item.  If $blocking is true,
# wait if necessary (used when draining i.e. no more work
# items will be made available).
sub retrieve
{
    my ($self, $blocking) = @_;

    if ($blocking && !scalar @{$self->{pending}})
    {
        my @busy = grep { $_->{busy}; } @{$self->{workers}};
        $self->_wait() if (scalar @busy);
    }
    return shift @{$self->{pending}};
}

# reap all workers
sub stop
{
    my ($self) = @_;

    while (my $w = pop @{$self->{workers}})
    {
        $w->stop();
    }
}

sub DESTROY
{
    my ($self) = @_;
    $self->stop();
}

package Cassandane::Unit::WorkerListener;
use base qw(Test::Unit::Listener);
use Cassandane::Util::Log;

sub new
{
    my ($class) = shift;
    my $self = {
        witem => undef,
    };
    return bless $self, $class;
}

sub start_suite
{
    my ($self, $suite) = @_;
    # nothing to see here
}

sub start_test
{
    my ($self, $test) = @_;
    # nothing to see here
}

sub end_test
{
    my ($self, $test) = @_;
    # nothing to see here
}

sub end_suite
{
    my ($self, $suite) = @_;
    # nothing to see here
}

sub add_error
{
    my ($self, $test, $exception) = @_;
    my $witem = $self->{witem};
    $witem->{result} = 'error';

    # Remove '-object' which points at the TestCase, which will have all
    # sorts of stuff we can't thaw.  We have enough information to
    # discover the right TestCase in the parent process.
    $exception->{'-object'} = undef;
    $witem->{exception} = $exception;
}

sub add_failure
{
    my ($self, $test, $exception) = @_;
    my $witem = $self->{witem};
    $witem->{result} = 'fail';

    # Remove '-object' which points at the TestCase, which will have all
    # sorts of stuff we can't thaw.  We have enough information to
    # discover the right TestCase in the parent process.
    $exception->{'-object'} = undef;
    $witem->{exception} = $exception;
}

sub add_pass
{
    my ($self, $test) = @_;
    my $witem = $self->{witem};
    $witem->{result} = 'pass';
}

package Cassandane::Unit::TestPlan;
use File::Temp qw(tempfile);
use File::Path qw(mkpath);
use Data::Dumper;
use Cassandane::Util::Log;

my @test_roots = (
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
    my ($self, $neg, $path, $testname) = @_;
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
            $item->_allow($testname) if $testname;
        }
    }
}

# Returns ($neg, $ostype, $ospath, $testname)
sub _parse_test_spec
{
    my ($name) = @_;

    my ($neg, $path) = ($name =~ m/^([~!]?)(.*)$/);
    $path =~ s/\.pm$//g;
    $path =~ s/::/\//g;
    $path =~ s/\./\//g;
    $path =~ s/\/+/\//g;
    $path =~ s/^\/*//;
    $path =~ s/\/*$//;

    $neg = '!' if $neg eq '~';

    # Allow Cyrus::TesterJMAP and TesterJMAP to work
    my @paths;

    my @dirs = split('/', $path);

    while (@dirs) {
        push @paths, join('/', @dirs);
        shift @dirs;
    }

    foreach my $candidate (@paths) {
        foreach my $root (@test_roots)
        {
            return ($neg, 'd', $candidate, undef)
                if ($root eq $candidate);

            my $fpath = $candidate;
            $fpath = "$root/$candidate"
                if ("$root/" ne substr($candidate, 0, length($root)+1));

            return ($neg, 'd', $fpath, undef)
                if ( -d $fpath );
            return ($neg, 'f', "$fpath.pm", undef)
                if ( -f "$fpath.pm" );

            my $test;
            ($fpath, $test) = ($fpath =~ m/^(.*)\/([^\/]+)$/);
            next unless defined $test;
            return ($neg, 'f', "$fpath.pm", $test)
                if ( -f "$fpath.pm" );
        }
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
    @default{@test_roots} = ();

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
        my ($neg, $type, $path, $test) = _parse_test_spec($name);

        # slow test explicitly requested by name, so turn off the filter
        if (defined $test and $test =~ m/_slow$/ and not $neg) {
            xlog "$name was explicitly requested. Enabling slow tests!";
            $self->{skip_slow} = 0;
        }

        if ($type eq 'd')
        {
            opendir DIR, $path
                or die "Cannot open directory $path for reading: $!";
            while ($_ = readdir DIR)
            {
                next unless m/\.pm$/;
                $self->_schedule($neg, "$path/$_", undef);
            }
            closedir DIR;
        }
        else
        {
            $self->_schedule($neg, $path, $test);
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

    # Redirect both STDOUT and STDERR to the log file
    open STDOUT, '>&', $logfh
        or die "Cannot redirect STDOUT";
    open STDERR, '>&', $logfh
        or die "Cannot redirect STDERR";
    close $logfh;

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
            $test->post_tear_down();
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

    $result->start_test($test);
    if ($runner->can('fake_start_time'))
    {
        $runner->fake_start_time($test, $witem->{start_time});
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
