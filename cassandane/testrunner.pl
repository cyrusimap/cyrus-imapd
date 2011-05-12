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
use Test::Unit::TestRunner;
use Cassandane::Util::Log;

my $format = 'tap';
my $output_dir = 'reports';
my $do_list = 0;
my @default_names = (
    'Cassandane::Test',
    'Cassandane::Cyrus',
);
my @names;

my %runners =
(
    tap => sub
    {
	my (@suites) = @_;

	my $runner = Test::Unit::TestRunner->new();
	my $passed = 1;
	foreach my $suite (@suites)
	{
	    $passed = 0
		unless $runner->start($suite);
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
	foreach my $suite (@suites)
	{
	    $runner->start(Test::Unit::Loader::load($suite));
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

@names = @default_names
    unless scalar @names;

my @suites;
foreach my $name (@names)
{
    my $dir = $name;
    $dir =~ s/::/\//g;
    my $file = "$dir.pm";

    if ( -d $dir )
    {
	opendir DIR, $dir
	    or die "Cannot open directory $dir for reading: $!";
	while ($_ = readdir DIR)
	{
	    next unless m/\.pm$/;
	    $_ = "$dir/$_";
	    s/\.pm$//;
	    s/\//::/g;
	    push(@suites, $_);
	}
	closedir DIR;
    }
    elsif ( -f $file )
    {
	push(@suites, $name);
    }
}

if ($do_list) {
    foreach my $item (@suites)
    {
	print "$item\n";
    }
    exit 0;
}

# printf STDERR "List of suites: %s\n", join(' ',@suites);

exit(! $runners{$format}->(@suites));
