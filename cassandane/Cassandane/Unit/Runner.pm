# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Runner;
use strict;
use warnings;
use experimental 'signatures';

use Benchmark;
use File::Temp qw(tempfile);
use File::Path qw(mkpath);

use Cassandane::Util::Log;
use Cassandane::Unit::FailedTests;
use Cassandane::Unit::WorkerPool;

sub new
{
    my ($class, %opts) = @_;

    my $self = {
        listeners  => [ Cassandane::Unit::FailedTests->new() ],
        failures   => [],
        errors     => [],
        run_count  => 0,
        skips      => [],

        keep_going    => delete $opts{keep_going} || 0,
        log_directory => delete $opts{log_directory},
        maxworkers    => delete $opts{maxworkers} || 1,
        skip_slow     => delete $opts{skip_slow} // 1,
    };

    die "Unknown options: " . join(' ', keys %opts)
        if scalar %opts;

    return bless $self, $class;
}

sub add_listener ($self, $listener)
{
    push $self->{listeners}->@*, $listener;
    return;
}

sub tell_listeners ($self, $event, @args)
{
    $_->$event(@args) for $self->{listeners}->@*;
    return;
}

sub start_test ($self, $witem)
{
    $self->{run_count}++;
    $self->tell_listeners(start_test => $witem);
    return;
}

sub end_test ($self, $witem)
{
    $self->tell_listeners(end_test => $witem);
    return;
}

sub add_pass ($self, $witem)
{
    $self->tell_listeners(add_pass => $witem);
    return;
}

sub add_failure ($self, $witem)
{
    push $self->{failures}->@*, $witem;
    $self->tell_listeners(add_failure => $witem);
    return;
}

sub add_error ($self, $witem)
{
    push $self->{errors}->@*, $witem;
    $self->tell_listeners(add_error => $witem);
    return;
}

sub add_skip ($self, $witem)
{
    push $self->{skips}->@*, $witem;
    $self->tell_listeners(add_skip => $witem);
    return;
}

sub was_successful ($self)
{
    return !$self->{failures}->@* && !$self->{errors}->@*;
}

# How the run went, as plain data, for a listener to report at the end.
sub result_summary ($self)
{
    return {
        was_successful => ($self->was_successful ? 1 : 0),
        run_count      => $self->{run_count},
        failures       => [ $self->{failures}->@* ],
        errors         => [ $self->{errors}->@* ],
        skips          => [ $self->{skips}->@* ],
    };
}

sub do_run
{
    my ($self, $plan) = @_;

    my $start_time = new Benchmark();
    $self->_run_plan($plan);
    my $end_time = new Benchmark();

    $self->tell_listeners(finished => $self->result_summary,
                          $start_time, $end_time);

    return $self->was_successful;
}

# Choose the log file a work item's output will go to.  This happens in the
# parent, so the parent can still read the output if the worker never comes
# back to say where it went.
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
    my ($self, $witem) = @_;

    if ($witem->{outcome} eq 'skip')
    {
        unlink($witem->{logfile}) if (!defined $self->{log_directory});

        $self->add_skip($witem);
        return;
    }

    $witem->{annotations} = _annotations_from($witem->{logfile});
    _dump_logfile($witem->{logfile}) if (get_verbose > 1);
    unlink($witem->{logfile}) if (!defined $self->{log_directory});

    # The test ran in a worker, which has no listeners to tell.  Send the
    # start_test event now, so that the formatters hear about the test
    # before they hear how it went.
    $self->start_test($witem);

    if ($witem->{outcome} eq 'pass')
    {
        $self->add_pass($witem);
    }
    elsif ($witem->{outcome} eq 'fail')
    {
        $self->add_failure($witem);
    }
    elsif ($witem->{outcome} eq 'error')
    {
        $self->add_error($witem);
    }
    else
    {
        die "Unknown outcome '$witem->{outcome}' for"
            . " $witem->{suite}.$witem->{testname}";
    }
    $self->end_test($witem);
}

sub _run_plan
{
    my ($self, $plan) = @_;

    my @workitems = $plan->@*;

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
        if ($self->{keep_going} || $self->was_successful())
        {
            $self->_make_logfile($witem);
            $pool->assign($witem);
        }
        while ($done = $pool->retrieve(0))
        {
            $self->_finish_workitem($done);
        }
    }
    # second ^C stops waiting for work items to finish
    while ($interrupted < 2 && ($done = $pool->retrieve(1)))
    {
        $self->_finish_workitem($done);
    }
    $pool->stop();

    return $self->was_successful();
}

1;
