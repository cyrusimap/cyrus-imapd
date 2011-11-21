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
package Cassandane::Unit::TestPlan;

my @default_names = (
    'Cassandane::Test',
    'Cassandane::Cyrus',
);

sub new
{
    my $class = shift;
    my $self = {
	schedule => {},
    };
    bless $self, $class;
    return $self;
}

sub _schedule
{
    my ($self, $neg, $suite, $test) = @_;
    if ($neg eq '!')
    {
	if (defined $test)
	{
	    # disable a specific test
	    $self->{schedule}->{$suite} ||= { suite => $suite, tests => {} };
	    $self->{schedule}->{$suite}->{tests}->{"!$test"} = 1;
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
	$self->{schedule}->{$suite} ||= { suite => $suite, tests => {} };
	if (defined $test)
	{
	    $self->{schedule}->{$suite}->{tests}->{$test} = 1;
	}
	else
	{
	    $self->{schedule}->{$suite}->{tests} = {};
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

sub _get_schedule
{
    my ($self) = @_;
    return sort { $a->{suite} cmp $b->{suite} } values %{$self->{schedule}};
}

# Sort and return the schedule as a list of "suite.test" strings
# e.g. "Cassandane::Cyrus::Quota.using_storage".
sub list
{
    my ($self) = @_;
    my @res;

    foreach my $item ($self->_get_schedule())
    {
	my $suite = Test::Unit::Loader::load($item->{suite});
	map {
	    $_ =~ s/^test_//;
	    push(@res, "$item->{suite}.$_");
	} sort @{$suite->names()};
    }

    return @res;
}

# The 'run' method makes this class look sufficiently like a
# Test::Unit::TestCase that Test::Unit::TestRunner will happily run it.
# This enables us to run all our scheduled tests with a single
# TestResult and a single summary of errors.
sub run
{
    my ($self, $result, $runner) = @_;
    my $passed = 1;

    foreach my $item ($self->_get_schedule())
    {
	my $suite = Test::Unit::Loader::load($item->{suite});
	Cassandane::Unit::TestCase->enable_tests(keys %{$item->{tests}});
	$passed = 0
	    if (!$suite->run($result, $runner));
    }

    return $passed;
}

1;
