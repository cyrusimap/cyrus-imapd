#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
use Cassandane::Unit::TestCase;
use IO::Handle;
use POSIX qw(pipe);
package Cassandane::Unit::TestPlanItem;

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

my $nextid = 1;

sub new
{
    my ($class) = @_;
    my $self = {
	id => $nextid++,
	pid => undef,
	downpipe => undef,
	uppipe => undef,
	eitem => undef,
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
	$self->_mainloop();
	exit(0);
    }
}

sub _send
{
    my ($fh, $fmt, @args) = @_;
    my $msg = sprintf($fmt, @args);
# print STDERR "--> \"$msg\"\n";
    syswrite($fh, $msg);
}

sub _receive
{
    my ($fh) = @_;
    my $msg = $fh->gets();
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
	    my $eitem = { suite => $args[0], test => $args[1] };
	    my $res = $self->{handler}->($eitem);
	    _send($self->{uppipe}, "%s\n", ($res ? 'success' : 'failure'));
	}
	else
	{
	    print STDERR "_mainloop: unknown command '$command'\n";
	}
    }
}

sub result
{
    my ($self) = @_;
    return if !$self->{eitem};
    my $msg = _receive($self->{uppipe});
    my $res;
    return if !defined $msg;
    chomp $msg;
    if ($msg eq 'success')
    {
	$res = 1;
    }
    elsif ($msg eq 'failure')
    {
	$res = 0;
    }
    else
    {
	die "Unknown result \"$msg\"";
    }
    my $eitem = $self->{eitem};
    $eitem->{result} = $res;
    $self->{eitem} = undef;
    return $eitem;
}

sub assign
{
    my ($self, $eitem) = @_;
    _send($self->{downpipe},
	  "run %s %s\n", $eitem->{suite}, $eitem->{test});
    $self->{eitem} = $eitem;
}

sub stop
{
    my ($self) = @_;
    _send($self->{downpipe}, "stop\n");
    while (1)
    {
	my $res = waitpid($self->{pid}, 0);
	return if $res < 0;
	next if $res == 0;
	next if $res != $self->{pid};
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

# Assign an eitem to an idle worker if necessary
# block until a worker is idle.
sub assign
{
    my ($self, $eitem) = @_;

    my @idle = grep { !$_->{eitem}; } @{$self->{workers}};
    my $w = shift @idle || $self->_wait();
    $w->assign($eitem);
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
	next if (!$w->{eitem});
	vec($rbits, fileno($w->{uppipe}), 1) = 1;
    }

    # select() with no timeout
    my $res = select($rbits, undef, undef, undef);
    die "select failed: $!" if ($res < 0);

    # discover which of our workers has responded
    foreach my $w (@{$self->{workers}})
    {
	if (vec($rbits, fileno($w->{uppipe}), 1))
	{
	    push(@{$self->{pending}}, $w->result());
	    return $w;
	}
    }
    die "Unexpected result from select: $res";
}

# Retrieve a completed work item
sub retrieve
{
    my ($self) = @_;

    my $eitem = shift @{$self->{pending}};
    return $eitem;
}

# Retrieve a completed work item, waiting if necessary.
# Used when draining i.e. no more work items will be
# made available.
sub drain
{
    my ($self) = @_;

    if (!scalar @{$self->{pending}})
    {
	my @busy = grep { $_->{eitem}; } @{$self->{workers}};
	$self->_wait() if (scalar @busy);
    }
    return $self->retrieve();
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

package Cassandane::Unit::TestPlan;

my @default_names = (
    'Cassandane::Test',
    'Cassandane::Cyrus',
);

sub new
{
    my ($class, %opts) = @_;
    my $self = {
	schedule => {},
	keep_going => delete $opts{keep_going} || 0,
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
    my ($self, $neg, $suite, $test) = @_;
    if ($neg eq '!')
    {
	if (defined $test)
	{
	    # disable a specific test
	    $self->_get_item($suite)->_deny($test);
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
	if (defined $test)
	{
	    $item->_allow($test) if $test;
	}
    }
}

sub schedule
{
    my ($self, @names) = @_;

    @names = @default_names
	if !scalar @names;

    foreach my $name (@names)
    {
	my ($neg, $sname, $tname) = ($name =~ m/^(!?)([^.]+)(\.[^.]+)?$/);
	$tname =~ s/^\.// if defined $tname;

	$self->schedule(@default_names)
	    if $neg eq '!' && !scalar %{$self->{schedule}};

	my $dir = $sname;
	$dir =~ s/::/\//g;
	my $file = "$dir.pm";

	if ( -d $dir )
	{
	    die "Cannot specify directory.testname" if defined $tname;
	    opendir DIR, $dir
		or die "Cannot open directory $dir for reading: $!";
	    while ($_ = readdir DIR)
	    {
		next unless m/\.pm$/;
		next if m/^TestCase\.pm$/;
		$_ = "$dir/$_";
		s/\.pm$//;
		s/\//::/g;
		$self->_schedule($neg, $_, undef);
	    }
	    closedir DIR;
	}
	elsif ( -f $file )
	{
	    $self->_schedule($neg, $sname, $tname);
	}
	elsif ( -f "Cassandane/Cyrus/$file" )
	{
	    $self->_schedule($neg, "Cassandane::Cyrus::$sname", $tname);
	}
    }
}


#
# Get the entire expanded schedule as specific {suite,test} name tuples,
# sorted in alphabetic order on suite name then test name.
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
	    push(@res, {
		suite => $item->{suite},
		test => $name,
	    });
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
    foreach my $eitem ($self->_get_schedule())
    {
	push(@res, "$eitem->{suite}.$eitem->{test}");
    }

    return @res;
}

sub _run_eitem
{
    my ($self, $eitem, $result, $runner) = @_;

    my $suite = $self->_get_item($eitem->{suite})->_get_loaded_suite();
    Cassandane::Unit::TestCase->enable_test($eitem->{test});
    return $suite->run($result, $runner);
}

# The 'run' method makes this class look sufficiently like a
# Test::Unit::TestCase that Test::Unit::TestRunner will happily run it.
# This enables us to run all our scheduled tests with a single
# TestResult and a single summary of errors.
sub run
{
    my ($self, $result, $runner) = @_;
    my $passed = 1;

    my $maxworkers = 2;

    # we expand the schedule before forking the
    # workers so that we can just hand the reference
    # to the worker
    my @items = $self->_get_schedule();

    if ($maxworkers > 1)
    {
	# multi-threaded case: use worker pool
	my $pool = Cassandane::Unit::WorkerPool->new(
	    maxworkers => $maxworkers,
	    handler => sub {
		my ($eitem) = @_;
		return $self->_run_eitem($eitem, $result, $runner);
	    },
	);
	my $eitem;
	$pool->start();
	while ($eitem = shift @items)
	{
	    $pool->assign($eitem);
	    while ($eitem = $pool->retrieve())
	    {
		$passed &&= $eitem->{result};
	    }
	}
	while ($eitem = $pool->drain())
	{
	    $passed &&= $eitem->{result};
	}
	$pool->stop();
    }
    else
    {
	# single threaded case: just run it all in-process

	if (!$self->{keep_going})
	{
	    # Hacky!
	    no warnings;
	    *Test::Unit::Result::should_stop = sub
	    {
		my ($self) = @_;
		return !$self->was_successful();
	    };
	}

	foreach my $eitem (@items)
	{
	    $passed &&= $self->_run_eitem($eitem, $result, $runner);
	}
    }

    return $passed;
}

1;
