#!/usr/bin/perl
#
#  Copyright (c) 2012 Opera Software Australia Pty. Ltd.  All rights
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
#       Opera Software Australia Pty. Ltd.
#       Level 50, 120 Collins St
#       Melbourne 3000
#       Victoria
#       Australia
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
