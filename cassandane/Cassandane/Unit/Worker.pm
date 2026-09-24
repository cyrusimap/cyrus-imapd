# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Worker;
use strict;
use warnings;
use experimental 'signatures';

use IO::Handle;
use POSIX ();
use Time::HiRes qw(time);
use JSON::XS ();
use Error qw(:try);

use Cassandane::Error;
use Cassandane::Failure;

# $0 as it was before a worker renamed itself, so that it can keep saying which
# test it is on.  Only ever set in a worker, after the fork.
my $basename;

# One message per line, so the encoding has to fit on one line.  Totally "plain
# data" protocol, no blessed objects, just good ol' JSON.
my $JSON = JSON::XS->new->ascii->canonical;

# The id is the pool slot this worker fills: it appears in the process title,
# and Cassandane derives the worker's port range from it.
sub new
{
    my ($class, $id, %params) = @_;
    my $self = {
        id => $id,
        pid => undef,
        downpipe => undef,
        uppipe => undef,
        busy => 0,
        dead => 0,
        skip_slow => $params{skip_slow} // 1,
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
        $ENV{CASSANDANE_WORKER_ID} = $self->{id};    # 1, 2, 3...
        $basename = $0;
        $0 = "$basename ($self->{id})";
        $self->_mainloop();
        exit(0);
    }
}

sub _send
{
    my ($fh, $fmt, @args) = @_;
    my $msg = sprintf($fmt, @args);
# print STDERR "--> \"$msg\"\n";

    # syswrite is under no obligation to write the whole buffer at once, and a
    # short write wouldn't be noticed here: it would surface much later, and
    # somewhere else, as a message the other end can't parse.
    my $sent = 0;
    while ($sent < length $msg)
    {
        my $n = syswrite($fh, $msg, length($msg) - $sent, $sent);
        die "Cannot write to pipe: $!" if not defined $n;
        die "Cannot write to pipe: wrote nothing" if $n == 0;
        $sent += $n;
    }
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
        my ($command, $payload) = split(/\s+/, $msg, 2);

        if ($command eq 'stop')
        {
            return;
        }
        elsif ($command eq 'run')
        {
            my $assignment = $JSON->decode($payload);
            $0 = "$basename ($self->{id})"
               . " $assignment->{suite}.$assignment->{testname}";
            my $outcome = $self->_run_test($assignment);
            $0 = "$basename ($self->{id})";
            _send($self->{uppipe}, "done %s\n", $JSON->encode($outcome));
        }
        else
        {
            print STDERR "_mainloop: unknown command '$command'\n";
        }
    }
}

sub _run_test
{
    my ($self, $witem) = @_;
    my $test = _test_for($witem);

    # Every worker inherited the same random seed from the parent when it was
    # forked, so without this they would all generate the same message ids,
    # names and UUIDs as each other, test for test.
    srand;

    $self->_capture_output($witem->{logfile});

    my $outcome;
    if (my $reason = $self->_skip_reason($test))
    {
        $outcome = { outcome => 'skip', reason => $reason };
    }
    else
    {
        $outcome = _outcome_of($test);
    }

    if ($test->can('post_tear_down'))
    {
        eval
        {
            $test->post_tear_down($outcome->{outcome});
        };
        my $ex = $@;
        if ($ex)
        {
            my $report = Cassandane::Error->from_thrown($ex)->stringify;
            $outcome = { outcome => 'error', report => $report };
        }
    }

    $self->_restore_stdout();

    return $outcome;
}

sub _test_for ($witem)
{
    return $witem->{suite}->new("test_$witem->{testname}");
}

# Run one test and say how it went.  A Cassandane::Failure means the test ran
# and came out wrong; anything else thrown means it never got to say.
sub _outcome_of ($test)
{
    my $outcome;

    try {
        $test->run_bare();
        $outcome = { outcome => 'pass' };
    }
    catch Cassandane::Failure with {
        $outcome = { outcome => 'fail', report => shift->stringify };
    }
    catch Error with {
        my $thrown = shift;
        $thrown = Cassandane::Error->from_thrown($thrown)
            if not $thrown->isa('Cassandane::Error');
        $outcome = { outcome => 'error', report => $thrown->stringify };
    }
    otherwise {
        my $report = Cassandane::Error->from_thrown(shift)->stringify;
        $outcome = { outcome => 'error', report => $report };
    };

    return $outcome;
}

# The filters that decide whether a test runs at all.  The first one with an
# answer wins, and its answer is why the test was skipped.  Order matters,
# because some have side effects: a test's :want_service_http attribute is
# honoured by a filter.
sub _skip_reason ($self, $test)
{
    my @filters = qw(skip_version skip_missing_features
                     skip_runtime_check
                     enable_wanted_properties);

    push @filters, 'skip_slow' if $self->{skip_slow};

    foreach my $token (@filters)
    {
        my $reason = $test->filter_method($token);
        return $reason if $reason;
    }

    return;
}

# Point this process's STDOUT and STDERR at the log file, keeping the
# originals so that they can be put back once the test is done.
sub _capture_output
{
    my ($self, $logfile) = @_;

    ${\*STDOUT}->flush;
    ${\*STDERR}->flush;

    open my $oldout, '>&', \*STDOUT
        or die "Cannot save STDOUT";
    open my $olderr, '>&', \*STDERR
        or die "Cannot save STDERR";

    unless ($ENV{CASSANDANE_LIVE_OUTPUT}) {
      open STDOUT, '>>', $logfile
          or die "Cannot redirect STDOUT to $logfile: $!";
      open STDERR, '>>', $logfile
          or die "Cannot redirect STDERR to $logfile: $!";
    }

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

# Collect the worker's answer and fold it into the work item we assigned.
# Nothing identifies the work item on the wire: a worker runs one at a time,
# and we still have the copy we sent it.
sub get_reply
{
    my ($self) = @_;
    return if !$self->{busy};
    my $msg = _receive($self->{uppipe});
    my $witem = delete $self->{witem};

    if (!defined $msg)
    {
        # End of file: the worker exited without answering.  It isn't going to
        # become idle on its own, and leaving it marked busy means select()
        # wakes on its dead pipe forever, so retire it here.
        $self->{busy} = 0;
        $self->{dead} = 1;

        return if not $witem;

        $witem->{outcome} = 'error';
        $witem->{report} =
            "worker $self->{id} exited without reporting a result";
        return $witem;
    }

    my ($command, $payload) = split(/\s+/, $msg, 2);
    die "Unknown message \"$msg\""
        if ($command ne 'done');
    $self->{busy} = 0;

    return { %$witem, %{ $JSON->decode($payload) } };
}

sub assign
{
    my ($self, $witem) = @_;
    $witem->{start_time} = time();
    $self->{witem} = $witem;
    _send($self->{downpipe},
          "run %s\n", $JSON->encode(_assignment($witem)));
    $self->{busy} = 1;
}

# What the worker needs in order to run the test, and nothing else.
sub _assignment
{
    my ($witem) = @_;
    return { map {; $_ => $witem->{$_} } qw(suite testname logfile) };
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

1;
