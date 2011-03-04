#!/usr/bin/perl

use strict;
use warnings;
use Test::Unit::TestRunner;
use Test::Unit::Runner::XML;
use Cassandane::Util::Log;

my $format = 'xml';
my $output_dir = 'reports';
my @default_names = (
    'Cassandane::Test',
    'Cassandane::Cyrus',
);
my @names;

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

# printf STDERR "List of suites: %s\n", join(' ',@suites);

exit(! $runners{$format}->(@suites));
