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
use Cassandane::Unit::Runner;
use Cassandane::Unit::TestCase;
use Cassandane::Util::Log;
use Cassandane::Instance;

my $format = 'tap';
my $output_dir = 'reports';
my $do_list = 0;
my @default_names = (
    'Cassandane::Test',
    'Cassandane::Cyrus',
);
my @names;
my %schedule;

sub schedulex
{
    my ($neg, $suite, $test) = @_;
    if ($neg eq '!')
    {
	if (defined $test)
	{
	    # disable a specific test
	    $schedule{$suite} ||= { suite => $suite, tests => {} };
	    $schedule{$suite}->{tests}->{"!$test"} = 1;
	}
	else
	{
	    # remove entire suite
	    delete $schedule{$suite};
	}
    }
    else
    {
	# add to the schedule
	$schedule{$suite} ||= { suite => $suite, tests => {} };
	if (defined $test)
	{
	    $schedule{$suite}->{tests}->{$test} = 1;
	}
	else
	{
	    $schedule{$suite}->{tests} = {};
	}
    }
}

sub schedule
{
    my (@names) = @_;

    @names = @default_names
	if !scalar @names;

    foreach my $name (@names)
    {
	my ($neg, $sname, $tname) = ($name =~ m/^(!?)([^.]+)(\.[^.]+)?$/);
	$tname =~ s/^\.// if defined $tname;

	schedule(@default_names)
	    if $neg eq '!' && !scalar %schedule;

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
		$_ = "$dir/$_";
		s/\.pm$//;
		s/\//::/g;
		schedulex($neg, $_, undef);
	    }
	    closedir DIR;
	}
	elsif ( -f $file )
	{
	    schedulex($neg, $sname, $tname);
	}
	elsif ( -f "Cassandane/Cyrus/$file" )
	{
	    schedulex($neg, "Cassandane::Cyrus::$sname", $tname);
	}
    }
}

sub get_schedule
{
    return sort { $a->{suite} cmp $b->{suite} } values %schedule;
}

my %runners =
(
    tap => sub
    {
	my $runner = Cassandane::Unit::Runner->new();
	my $passed = 1;
	$runner->filter('x');
	foreach my $item (get_schedule())
	{
	    Cassandane::Unit::TestCase->enable_tests(keys %{$item->{tests}});
	    $passed = 0
		unless $runner->start($item->{suite});
	}
	return $passed;
    }
);

eval
{
    require Test::Unit::Runner::XML;

    $runners{xml} = sub
    {
	my (@suites) = @_;

	mkdir($output_dir);
	my $runner = Test::Unit::Runner::XML->new($output_dir);
	$runner->filter('x');
	foreach my $item (get_schedule())
	{
	    Cassandane::Unit::TestCase->enable_tests(keys %{$item->{tests}});
	    $runner->start(Test::Unit::Loader::load($item->{suite}));
	}
	return $runner->all_tests_passed();
    };
    $format = 'xml';
} or print STDERR "Sorry, XML output format not available.\n";


sub usage
{
    printf STDERR "Usage: testrunner.pl [ -f xml | -f tap ] [testname...]\n";
    exit(1);
}

while (my $a = shift)
{
    if ($a eq '-f')
    {
	$format = shift;
	usage unless defined $runners{$format};
    }
    elsif ($a eq '-v' || $a eq '--verbose')
    {
	set_verbose(1);
    }
    elsif ($a eq '--valgrind')
    {
	Cassandane::Instance->set_defaults(valgrind => 1);
    }
    elsif ($a eq '-l' || $a eq '--list')
    {
	$do_list = 1;
    }
    elsif ($a =~ m/^-/)
    {
	usage;
    }
    else
    {
	push(@names, $a);
    }
}

if ($do_list)
{
    # Build a schedule comprising all tests
    schedule();
    # Sort and dump the schedule
    foreach my $item (get_schedule())
    {
	my @tests = @{Test::Unit::Loader::load($item->{suite})->names()};
	map {
	    $_ =~ s/^test_//;
	    print $item->{suite} . ".$_\n";
	} sort @tests;
    }
    exit 0;
}
else
{
    # Build the schedule
    schedule(@names);
    # Run the schedule
    exit(! $runners{$format}->());
}

