#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Cyrus::TesterCardDAV;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use JSON::XS;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Cassini;

my $basedir;
my $binary;
my $testdir;
my %suppressed;
my %expected;

my $KNOWN_ERRORS = <<EOF;
default-addressbook/Change property/2 | 1
default-addressbook/Change property/4 | 1
default-addressbook/Existing property/1 | 1
default-addressbook/No default delete/4 | 1
directory/GET on collections/4 | 1
directory/GET on collections/5 | 1
directory/GET on collections/8 | 1
errorcondition/PUT/2 | 1
errorcondition/PUT/5 | 1
errorcondition/PUT/8 | 1
errors/ERROR CONDITIONS/25 | 1
errors/ERROR CONDITIONS/26 | 1
errors/ERROR CONDITIONS/8 | 1
get/GET on resource/2 | 1
get/GET on resource/3 | 1
mkcol/MKCOL with body/1 | 1
mkcol/OPTIONS header/2 | 1
nonascii/high-ascii addressbook data/3 | 1
nonascii/high-ascii addressbook data/4 | 1
nonascii/Non-utf-8 address data/1 | 1
nonascii/Non-utf-8 address data/2 | 1
nonascii/Non-utf-8 address data/3 | 1
proppatch/prop patches/4 | 1
proppatch/prop patch property attributes/1 | 1
proppatch/prop patch property attributes/2 | 1
put/PUT groups/1 | 1
put/PUT VCARD/6 | 1
put/PUT VCARD/7 | 1
put/PUT with X- using VALUE != TEXT/1 | 1
put/Test \\ escapes/1 | 1
reports/basic query reports/10 | 1
reports/basic query reports/1 | 1
reports/basic query reports/11 | 1
reports/basic query reports/12 | 1
reports/basic query reports/13 | 1
reports/basic query reports/14 | 1
reports/basic query reports/15 | 1
reports/basic query reports/16 | 1
reports/basic query reports/17 | 1
reports/basic query reports/18 | 1
reports/basic query reports/19 | 1
reports/basic query reports/20 | 1
reports/basic query reports/2 | 1
reports/basic query reports/21 | 1
reports/basic query reports/22 | 1
reports/basic query reports/23 | 1
reports/basic query reports/24 | 1
reports/basic query reports/25 | 1
reports/basic query reports/26 | 1
reports/basic query reports/27 | 1
reports/basic query reports/28 | 1
reports/basic query reports/29 | 1
reports/basic query reports/30 | 1
reports/basic query reports/3 | 1
reports/basic query reports/31 | 1
reports/basic query reports/32 | 1
reports/basic query reports/33 | 1
reports/basic query reports/4 | 1
reports/basic query reports/5 | 1
reports/basic query reports/6 | 1
reports/basic query reports/7 | 1
reports/basic query reports/8 | 1
reports/basic query reports/9 | 1
sync-report/simple reports - diff token - no props/1 | 1
sync-report/simple reports - diff token - props/1 | 1
sync-report/simple reports - empty token - no props/1 | 1
sync-report/simple reports - empty token - no props/13 | 1
sync-report/simple reports - empty token - no props/5 | 1
sync-report/simple reports - empty token - no props/9 | 1
sync-report/simple reports - empty token - props/1 | 1
sync-report/simple reports - empty token - props/2 | 1
sync-report/simple reports - empty token - props/3 | 1
sync-report/simple reports - empty token - props/4 | 1
sync-report/support-report-set/1 | 1
sync-report/support-report-set/2 | 1
well-known/Simple GET tests/3 | 1
well-known/Simple GET tests/4 | 1
well-known/Simple PROPFIND tests/1 | 1
well-known/Simple PROPFIND tests/2 | 1
well-known/Simple PROPFIND tests/3 | 1
well-known/Simple PROPFIND tests/4 | 1
well-known/Simple PROPFIND tests/5 | 1
well-known/Simple PROPFIND tests/6 | 1
EOF

sub init
{
    my $cassini = Cassandane::Cassini->instance();
    $basedir = $cassini->val('caldavtester', 'basedir');
    return unless defined $basedir;
    $basedir = abs_path($basedir);

    my $supp = $cassini->val('caldavtester', 'suppress-carddav',
                             '');
    map { $suppressed{$_} = 1; } split(/\s+/, $supp);

    foreach my $row (split /\n/, $KNOWN_ERRORS) {
        next if $row =~ m/\s*\#/;
        next unless $row =~ m/\S/;
        my ($key, @items) = split /\s*\|\s*/, $row;
        $expected{$key} = \@items;
    }

    $binary = "$basedir/testcaldav.py";
    $testdir = "$basedir/scripts/tests/CardDAV";
}
init;

sub new
{
    my $class = shift;

    my $buildinfo = Cassandane::BuildInfo->new();

    if (not defined $basedir or not $buildinfo->get('component', 'httpd')) {
        # don't bother setting up, we're not running tests anyway
        return $class->SUPER::new({}, @_);
    }

    my $config = Cassandane::Config->default()->clone();
    $config->set(servername => "127.0.0.1"); # urlauth needs matching servername
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'carddav');
    $config->set(httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    if (not defined $basedir
        or not $self->{instance}->{buildinfo}->get('component', 'httpd'))
    {
        # don't bother setting up further, we're not running tests anyway
        return;
    }

    my $admintalk = $self->{adminstore}->get_client();

    for (1..40) {
        my $name = sprintf("user%02d", $_);
        $admintalk->create("user.$name");
        $admintalk->setacl("user.$name", admin => 'lrswipkxtecda');
        $admintalk->setacl("user.$name", $name => 'lrswipkxtecd');
    }
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub list_tests
{
    my @tests;

    if (!defined $basedir)
    {
        return ( 'test_warning_caldavtester_is_not_installed' );
    }

    open(FH, "-|", 'find', $testdir, '-name' => '*.xml');
    while (<FH>)
    {
        chomp;
        next unless s{^$testdir/}{};
        next unless s{\.xml$}{};
        next if $suppressed{$_};
        push(@tests, "test_$_");
    }
    close(FH);

    return @tests;
}

sub run_test
{
    my ($self) = @_;

    if (!defined $basedir)
    {
        xlog "CalDAVTester tests are not enabled.  To enabled them, please";
        xlog "install CalDAVTester from http://calendarserver.org/wiki/CalDAVTester";
        xlog "and edit [caldavtester]basedir in cassandane.ini";
        xlog "This is not a failure";
        return;
    }

    my $name = $self->name();
    $name =~ s/^test_//;
    my $testname = $name;
    $testname .= ".xml";

    my $logdir = "$self->{instance}->{basedir}/rawlog/";
    mkdir($logdir);

    my $svc = $self->{instance}->get_service('http');
    my $params = $svc->store_params();

    my $rundir = "$self->{instance}->{basedir}/run";
    mkdir($rundir);

    system('ln', '-s', "$testdir", "$rundir/tests");
    system('ln', '-s', "$basedir", "$rundir/data");

    # XXX - make the config file!
    my $configfile = "$rundir/serverinfo.xml";
    {
        open(FH, "<", abs_path("data/caldavtester-serverinfo-template.xml"));
        local $/ = undef;
        my $config = <FH>;
        $config =~ s/SERVICE_HOST/$params->{host}/g;
        $config =~ s/SERVICE_PORT/$params->{port}/g;
        close(FH);
        open(FH, ">", $configfile);
        print FH $config;
        close(FH);
    }

    my $errfile = $self->{instance}->{basedir} .  "/$name.errors";
    my $outfile = $self->{instance}->{basedir} .  "/$name.stdout";
    my $status;
    my @verbose;
    if (get_verbose) {
        push @verbose, "--always-print-request", "--always-print-response";
    }
    $self->{instance}->run_command({
            redirects => { stderr => $errfile, stdout => $outfile },
            workingdir => $logdir,
            handlers => {
                exited_normally => sub { $status = 1; },
                exited_abnormally => sub { $status = 0; },
            },
        },
        $binary,
        "--basedir" => $rundir,
        "--observer=jsondump",
        @verbose,
        $testname);

    my $json;
    {
        open(FH, '<', $outfile) or die "Cannot open $outfile for reading $!";
        local $/ = undef;
        my $output = <FH>;
        $json = decode_json($output);
        close(FH);
    }

    if (0 && (!$status || get_verbose)) {
        foreach my $file ($errfile) {
            next unless -f $file;
            open FH, '<', $file
                or die "Cannot open $file for reading: $!";
            local $/ = undef;
            xlog $self, <FH>;
            close FH;
        }
    }

    $json->[0]{name} = $name; # short name at top level
    $self->assert(_check_result($name, $json->[0]));
}

sub _check_result {
    my $name = shift;
    my $json = shift;
    my $res = 1;

    if (defined $json->{result}) {
        if ($json->{result} == 0) {
            xlog "$name [OK]";
        }
        elsif ($json->{result} == 1) {
            xlog "$name [FAILED]";
            $res = 0;
        }
        elsif ($json->{result} == 3) {
            xlog "$name [SKIPPED]";
        }
        if (exists $expected{$name}) {
            if ($json->{result} == $expected{$name}[0]) {
                xlog "EXPECTED RESULT FOR $name";
                $res = 1;
            }
            else {
                xlog "UNEXPECTED RESULT FOR $name: " . $expected{$name}[1] if $expected{$name}[1];
                $res = 0; # yep, even if we succeeded
            }
        }
        xlog $json->{details} if $json->{result};
    }

    xlog "FAILED WHEN NOT EXPECTED $name" unless $res;

    if ($json->{tests}) {
        foreach my $test (@{$json->{tests}}) {
            $res = 0 unless _check_result("$name/$test->{name}", $test);
        }
    }

    return $res;
}

1;
