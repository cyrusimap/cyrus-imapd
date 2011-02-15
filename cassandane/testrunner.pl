#!/usr/bin/perl

use strict;
use warnings;
use Test::Unit::TestRunner;
use Test::Unit::Runner::XML;

my $format = 'xml';
my $output_dir = 'reports';
my @suite_prefixes = (
    'Cassandane::Test'
);

my %runners =
(
    xml => sub
    {
	my (@suites) = @_;

	mkdir($output_dir);
	my $runner = Test::Unit::Runner::XML->new($output_dir);
	foreach my $suite (@suites)
	{
	    $runner->start(Test::Unit::Loader::load($suite));
	}
	return $runner->all_tests_passed();
    },
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


sub usage
{
    printf STDERR "Usage: testrunner.pl [ -f xml | -f tap ]\n";
    exit(1);
}

while (my $a = shift)
{
    if ($a eq '-f')
    {
	$format = shift;
	usage unless defined $runners{$format};
    }
    elsif ($a =~ m/^-/)
    {
	usage;
    }
    else
    {
	usage;
    }
}

my @suites;
foreach my $prefix (@suite_prefixes)
{
    my $dir = $prefix;
    $dir =~ s/::/\//g;
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

# printf STDERR "List of suites: %s\n", join(' ',@suites);

exit(! $runners{$format}->(@suites));
