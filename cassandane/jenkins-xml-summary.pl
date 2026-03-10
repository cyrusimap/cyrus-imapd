#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;
use XML::DOM;
use Getopt::Long;

my $report_dir = 'reports';
my $build_url;

sub usage
{
    print STDERR "Usage: $0 [--build-url=URL] [--report-dir=DIR]\n";
    exit(1);
}

GetOptions(
    "report-dir=s" => \$report_dir,
    "build-url=s" => \$build_url,
    "help" => \&usage,
) or usage;
usage if scalar(@ARGV);

my @report_files;
opendir REPORTDIR, $report_dir
    or die "Cannot open directory $report_dir for reading: $!";
while (my $e = readdir REPORTDIR)
{
    push(@report_files, "$report_dir/$e") if ($e =~ m/^TEST-.*\.xml$/);
}
closedir REPORTDIR;
@report_files = sort { $a cmp $b } @report_files;


# want this url
# http://ci.cyrusimap.org/view/All/job/cyrus-imapd-master/400/
#
#   testReport/%28root%29/Cassandane__Cyrus__Quota/test_exceeding_message/
#
# get this in $BUILD_URL
# http://ci.cyrusimap.org/view/All/job/cyrus-imapd-master/400/

print "Test failures and errors summary\n";
print "================================\n";
my $nrun = 0;
my $nerrors = 0;
my $nfailures = 0;
foreach my $file (@report_files)
{
    my $parser = new XML::DOM::Parser;
    my $doc = $parser->parsefile($file);

    my ($xsuite, @wtf) = $doc->getElementsByTagName('testsuite', 0);
    die "Invalid document $file"
        if (!defined $xsuite || scalar(@wtf));

    my $suite = $xsuite->getAttribute('name');

    foreach my $xcase ( $xsuite->getElementsByTagName('testcase', 0) )
    {
        my $case = $xcase->getAttribute('name');
        $case =~ s/^test_//;

        my $status = 1;
        $nrun++;
        my (@xfails) = $xcase->getElementsByTagName('failure', 0);
        if (scalar @xfails)
        {
            $nfailures++;
            $status = 0;
        }
        my (@xerrors) = $xcase->getElementsByTagName('error', 0);
        if (scalar @xerrors)
        {
            $nerrors++;
            $status = 0;
        }

        next if $status;

        print "\n$suite.$case\n";

        if (defined $build_url)
        {
            my $quoted_suite = $suite;
            $quoted_suite =~ s/[:\/]/_/g;
            my $url = "$build_url/testReport/%28root%29/$quoted_suite/test_$case/";
            print "    $url\n";
        }
    }
}
print "\n$nrun run, $nfailures failures, $nerrors errors\n";
