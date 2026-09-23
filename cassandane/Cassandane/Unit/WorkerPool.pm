# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::WorkerPool;
use strict;
use warnings;

use Errno qw(EINTR);

use Cassandane::Unit::Worker;

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

    while ((my $id = scalar @{$self->{workers}} + 1) <= $self->{maxworkers})
    {
        push(@{$self->{workers}}, $self->_new_worker($id));
    }
}

sub _new_worker
{
    my ($self, $id) = @_;

    my $w = Cassandane::Unit::Worker->new($id);
    $w->{handler} = $self->{handler};
    $w->start();

    return $w;
}

# Assign an work item to an idle worker if necessary
# block until a worker is idle.
sub assign
{
    my ($self, $witem) = @_;

    my $w;
    while (1)
    {
        ($w) = grep { !$_->{busy} && !$_->{dead}; } @{$self->{workers}};
        last if $w;

        die "No worker survives to run $witem->{suite}.$witem->{testname}"
            if !grep { $_->{busy}; } @{$self->{workers}};

        $self->_wait();
    }
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
    my $nbusy = 0;
    foreach my $w (@{$self->{workers}})
    {
        next if (!$w->{busy});
        vec($rbits, fileno($w->{uppipe}), 1) = 1;
        $nbusy++;
    }
    die "Waiting for a worker, but none is busy" if !$nbusy;

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
            my $witem = $w->get_reply();
            push(@{$self->{pending}}, $witem) if defined $witem;
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

    # A worker that died instead of replying leaves nothing to retrieve, so
    # keep waiting while any worker is still busy: otherwise one death would
    # abandon the work items the other workers are still running.
    while ($blocking && !scalar @{$self->{pending}})
    {
        last if !grep { $_->{busy}; } @{$self->{workers}};
        $self->_wait();
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

1;
