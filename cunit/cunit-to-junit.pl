#!/usr/bin/env perl

use strict;
use warnings;
use XML::DOM;
use File::Path qw(mkpath rmtree);
use File::Basename qw(dirname);
use Data::Dumper;
use Carp;

my $verbose = 0;
my $infile = 'CUnitAutomated-Results.xml';
my $outbase = 'reports/TEST-';

sub get_child
{
    my ($node, $name) = @_;

    croak "Invalid document"
        unless defined $node;
    my $kids = $node->getElementsByTagName($name, 0);
    croak "Invalid document: name=$name"
        unless (defined $kids && $kids->getLength == 1);
    return $kids->item(0);
}

sub get_child_maybe
{
    my ($node, $name) = @_;

    croak "Invalid document"
        unless defined $node;
    my $kids = $node->getElementsByTagName($name, 0);
    return undef
        if !defined $kids;
    return undef
        if $kids->getLength == 0;
    croak "Invalid document"
        if $kids->getLength > 1;
    return $kids->item(0);
}

sub get_children
{
    my ($node, $name) = @_;

    croak "Invalid document"
        unless defined $node;
    return ( $node->getElementsByTagName($name, 0) );
}

sub get_content
{
    my ($node, $name) = @_;

    croak "Invalid document"
        unless defined $node;
    my $s = $node->getFirstChild->getData;
    if (defined $s)
    {
        $s =~ s/^\s+//;
        $s =~ s/\s+$//;
    }
    return $s;
}

my @suites;
sub get_suite
{
    my ($sname) = @_;

    printf STDERR "Suite \"%s\"\n", $sname if $verbose;

    my @existing = grep { $_->{name} eq $sname; } @suites;
    return $existing[0] if scalar @existing;

    my $s = {
        name => $sname,
        nerrors => 0,
        tests => [],
        tests_by_name => {},
    };
    push(@suites, $s);
    return $s;
}

sub _add_test
{
    my ($s, $tname) = @_;

    my $t = $s->{tests_by_name}->{$tname};
    if (!defined $t)
    {
        $t = {
            name => $tname,
            errors => [],
        };
        push(@{$s->{tests}}, $t);
        $s->{tests_by_name}->{$tname} = $t;
    }
    return $t;
}

sub add_pass
{
    my ($s, $tname) = @_;
    printf STDERR "     Test \"%s\": pass\n", $tname if $verbose;
    _add_test($s, $tname);
}

sub add_fail
{
    my ($s, $tname, $msg) = @_;
    printf STDERR "     Test \"%s\": fail\n     %s\n", $tname, $msg
            if $verbose;
    my $t = _add_test($s, $tname);
    push(@{$t->{errors}}, $msg);
    $s->{nerrors}++;
}

my $parser = new XML::DOM::Parser;
my $doc = $parser->parsefile($infile);

my $root = get_child($doc, 'CUNIT_TEST_RUN_REPORT');
my $result = get_child($root, 'CUNIT_RESULT_LISTING');

foreach my $suite (get_children($result, 'CUNIT_RUN_SUITE'))
{
    my $succ = get_child_maybe($suite, 'CUNIT_RUN_SUITE_SUCCESS');
    my $fail = get_child_maybe($suite, 'CUNIT_RUN_SUITE_FAILURE');

    if (defined $succ)
    {
        my $s = get_suite(get_content(get_child($succ, 'SUITE_NAME')));

        foreach my $record (get_children($succ, 'CUNIT_RUN_TEST_RECORD'))
        {
            my $tr;

            $tr = get_child_maybe($record, 'CUNIT_RUN_TEST_SUCCESS');
            if (defined $tr)
            {
                my $tname = get_content(get_child($tr, 'TEST_NAME'));
                add_pass($s, $tname);
                next;
            }

            foreach $tr (get_children($record, 'CUNIT_RUN_TEST_FAILURE'))
            {
                my $tname = get_content(get_child($tr, 'TEST_NAME'));
                my $fname = get_content(get_child($tr, 'FILE_NAME'));
                my $lineno = get_content(get_child($tr, 'LINE_NUMBER'));
                my $cond = get_content(get_child($tr, 'CONDITION'));
                add_fail($s, $tname, "$fname:$lineno: $cond");
                next;
            }
        }
    }
    elsif (defined $fail)
    {
        # TODO: there must be a way in the jUnit output format
        # to report a failure of the suite fixture code, but
        # I have no idea what it is.  Instead use a fake test name.
        my $s = get_suite(get_content(get_child($fail, 'SUITE_NAME')));
        my $reason = get_content(get_child($fail, 'FAILURE_REASON'));

        my $tname = '__wtf';
        if ($reason =~ m/cleanup/i)
        {
            $tname = '__cleanup';
        }
        elsif ($reason =~ m/initialization/i)
        {
            $tname = '__cleanup';
        }

        add_fail($s, $tname, $reason);
    }
    else
    {
        carp "Neither a CUNIT_RUN_SUITE_SUCCESS nor a " .
             "CUNIT_RUN_SUITE_FAILURE child are present";
    }

}

my $dir = dirname($outbase . 'foo');
rmtree($dir) if (defined $dir && $dir ne '.');
my $nrun = 0;
my $nfailed = 0;

foreach my $s (@suites)
{
    my $sdoc = XML::DOM::Document->new();

    $nfailed += $s->{nerrors};

    my $selt = $sdoc->createElement('testsuite');
    $selt->setAttribute(failures => 0);
    $selt->setAttribute(errors => $s->{nerrors});
    $selt->setAttribute(time => "0.001");
    $selt->setAttribute(tests => scalar @{$s->{tests}});
    $selt->setAttribute(name => $s->{name});
    $sdoc->appendChild($selt);

    foreach my $t (@{$s->{tests}})
    {
        $nrun++;

        my $telt = $sdoc->createElement('testcase');
        $telt->setAttribute(time => "0.001");
        $telt->setAttribute(name => $t->{name});
        $selt->appendChild($telt);

        foreach my $e (@{$t->{errors}})
        {
            my $eelt = $sdoc->createElement('error');
            $eelt->appendChild($sdoc->createTextNode($e));
            $telt->appendChild($eelt);
        }
    }

    my $fname = $outbase . $s->{name} . '.xml';
    mkpath(dirname($fname));
    $sdoc->printToFile($fname);
}

print "$0: ran $nrun tests, $nfailed failed\n";
exit(1) if ($nfailed > 0);
