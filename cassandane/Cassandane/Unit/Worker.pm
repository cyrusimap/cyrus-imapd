# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Worker;
use strict;
use warnings;

use IO::Handle;
use POSIX ();
use Time::HiRes qw(time);
use JSON::XS ();

my $nextid = 1;

# One message per line, so the encoding has to fit on one line.  Totally "plain
# data" protocol, no blessed objects, just good ol' JSON.
my $JSON = JSON::XS->new->ascii->canonical;

sub new
{
    my ($class) = @_;
    my $self = {
        id => $nextid++,
        pid => undef,
        downpipe => undef,
        uppipe => undef,
        busy => 0,
        dead => 0,
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
            $0 = "$ENV{TEST_UNIT_BASENAME} ($ENV{TEST_UNIT_WORKER_ID}) $assignment->{suite}.$assignment->{testname}";
            my $outcome = $self->{handler}->($assignment);
            $0 = "$ENV{TEST_UNIT_BASENAME} ($ENV{TEST_UNIT_WORKER_ID})";
            _send($self->{uppipe}, "done %s\n", $JSON->encode($outcome));
        }
        else
        {
            print STDERR "_mainloop: unknown command '$command'\n";
        }
    }
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
        $witem->{failure} = {
            text => "worker $self->{id} exited without reporting a result",
        };
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
