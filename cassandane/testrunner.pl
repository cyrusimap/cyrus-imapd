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
use Cassandane::Util::Setup;
use Cassandane::Unit::Runner;
use Cassandane::Unit::TestPlan;
use Cassandane::Util::Log;
use Cassandane::Cassini;
use Cassandane::Instance;

my $format = 'tap';
my $output_dir = 'reports';
my $do_list = 0;
my $do_cleanup = 0;
my @names;

# This disgusting hack makes Test::Unit report a useful stack trace for
# it's assert failures instead of just a file name and line number.
{
    use Error;
    use Test::Unit::Exception;

    # We also convert string exceptions into Test::Unit errors.
    $SIG{__DIE__} = sub
    {
	my ($e) = @_;
	if (!ref($e))
	{
	    my ($text, $file, $line) = ($e =~ m/^(.*) at (.*\.pm) line (\d+)/);
	    if ($line)
	    {
		local $Error::Depth = 1;
		Test::Unit::Error->throw('-text' => "Perl exception: $text\n");
	    }
	}
	die @_;
    };

    # Disable the warning about redefining T:U:E:stringify.
    # We know what we're doing, dammit.
    no warnings;
    # This makes Error->new() capture a full stacktrace
    $Error::Debug = 1;
    *Test::Unit::Exception::stringify = sub
    {
	my ($self) = @_;
	my $s = '';

	my $o = $self->object;
	$s .= $o->to_string() . "\n " if $o && $o->can('to_string');

	# Note, -stacktrace includes -text

	my $st = $self->{-stacktrace};
	# Prune all Test::Unit internal calls
	$st =~ s/Test::Unit::TestCase::run_test.*/[...framework calls elided...]/s;
	$s .= $st;

	return $s;
    };
};


my %runners =
(
    tap => sub
    {
	my ($plan) = @_;
	my $runner = Cassandane::Unit::Runner->new();
	$runner->filter('x');
	return $runner->do_run($plan, 0);
    }
);

eval
{
    require Test::Unit::Runner::XML;

    $runners{xml} = sub
    {
	my ($plan) = @_;

	if ( ! -d $output_dir )
	{
	    mkdir($output_dir)
		or die "Cannot make output directory \"$output_dir\": $!";
	}
	my $runner = Test::Unit::Runner::XML->new($output_dir);
	$runner->filter('x');
	$runner->start($plan);
	return $runner->all_tests_passed();
    };
    $format = 'xml';
} or print STDERR "Sorry, XML output format not available.\n";

become_cyrus();

sub usage
{
    printf STDERR "Usage: testrunner.pl [ -f xml | -f tap ] [testname...]\n";
    exit(1);
}

while (my $a = shift)
{
    if ($a eq '--config')
    {
	my $filename = shift;
	Cassandane::Cassini->new(filename => $filename);
    }
    elsif ($a eq '-c' || $a eq '--cleanup')
    {
	$do_cleanup = 1;
    }
    elsif ($a eq '-f')
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

Cassandane::Instance::cleanup_leftovers()
    if ($do_cleanup);

my $plan = Cassandane::Unit::TestPlan->new();

if ($do_list)
{
    # Build a plan comprising all tests
    $plan->schedule();
    # dump the plan to stdout
    foreach my $nm ($plan->list())
    {
	print "$nm\n";
    }
    exit 0;
}
else
{
    # Build the schedule per commandline
    $plan->schedule(@names);
    # Run the schedule
    exit(! $runners{$format}->($plan));
}

