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

package Cassandane::Cyrus::TesterJMAP;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use JSON::XS qw(encode_json);
use File::Find;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Cassini;

my $basedir;
my $binary;
my $testdir;
my $authortestdir;
my %suppressed;

sub cyrus_version_supports_jmap
{
    my ($maj, $min) = Cassandane::Instance->get_version();

    return 0 if ($maj < 3);  # not supported before 3.x
    return 0 if ($maj == 3 && $min == 0); # not supported in 3.0.x
    return 1; # supported in everything newer
}

sub init
{

    my $cassini = Cassandane::Cassini->instance();
    $basedir = $cassini->val('jmaptester', 'basedir');
    return unless defined $basedir;
    $basedir = abs_path($basedir);

    my $supp = $cassini->val('jmaptester', 'suppress', '');
    map { $suppressed{$_} = 1; } split(/\s+/, $supp);

    $testdir = "$basedir/t";
    $authortestdir = "$basedir/xt";
}
init;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(servername => "127.0.0.1"); # urlauth needs matching servername
    $config->set(virtdomains => 'userid');
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpallowcompress => 'no');
    $config->set(conversations => 'yes');

    if (cyrus_version_supports_jmap()) {
        $config->set(httpmodules => 'jmap');
    }

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
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub find_tests
{
    my ($dir) = @_;

    my @tests;

    find(
        sub {
            my $file = $File::Find::name;

            return unless $file =~ s/\.t$//;
            return unless -f "$file.t";
            $file =~ s/^$basedir\/?//;
            $file =~ s{/}{:}g;
            return if $suppressed{$file};
            push @tests, "test_$file";
        },
        $dir,
    );

    return @tests;
}

sub list_tests
{
    my @tests;

    if (!cyrus_version_supports_jmap())
    {
        return ( 'test_jmaptest_disabled' );
    }

    if (!defined $basedir)
    {
        return ( 'test_warning_jmaptester_is_not_installed' );
    }

    @tests = find_tests($testdir);

    if ($ENV{AUTHOR_TESTING}) {
        push @tests, find_tests($authortestdir);
    }

    return @tests;
}

sub run_test
{
    my ($self) = @_;

    if (!defined $basedir)
    {
        xlog "JMAP Tests are not enabled.  To enabled them, please";
        xlog "install JMAP-TestSuite from https://github.com/fastmail/JMAP-TestSuite";
        xlog "and edit [jmaptester]basedir in cassandane.ini";
        xlog "This is not a failure";
        return;
    }

    if (!cyrus_version_supports_jmap())
    {
        xlog "The version of Cyrus being tested does not support JMAP";
        xlog "JMAP-TestSuite tests skipped";
        return;
    }

    my $name = $self->name();
    $name =~ s/^test_//;

    my $configfile = "$self->{instance}->{basedir}/testerconfig.json";
    my $errfile = $self->{instance}->{basedir} .  "/$name.errors";
    my $outfile = $self->{instance}->{basedir} .  "/$name.stdout";
    my $logdir = $self->{instance}->{basedir} .  "/logdir";

    my $service = $self->{instance}->get_service("http");

    local $ENV{JMAP_SERVER_ADAPTER_FILE} = $configfile;

    open(FH, ">$configfile");

    print FH encode_json({
        adapter => 'Cyrus',
        base_uri => 'http://' . $service->host() . ':' . $service->port() . '/',
        credentials => [
            {
                username => 'cassandane',
                password => 'pass',
            },
        ],
    });
    close(FH);

    my $status = 0;

    mkdir($logdir);

    $name =~ s{:}{/}g;

    $self->{instance}->run_command({
            redirects => { stderr => $errfile, stdout => $outfile },
            workingdir => $logdir,
            handlers => {
                exited_normally => sub { $status = 1; },
                exited_abnormally => sub { $status = 0; },
            },
        },
        "perl", '-I' => "$basedir/lib",
         "$basedir/$name.t",
    );

    if ((!$status || get_verbose)) {
        if (-f $errfile) {
            open FH, '<', $errfile
                or die "Cannot open $errfile for reading: $!";
            while (readline FH) {
                xlog $_;
            }
            close FH;
        }
        opendir(DH, $logdir) or die "Can't open logdir $logdir";
        while (my $item = readdir(DH)) {
            next unless $item =~ m/^rawlog\./;
            print "============> $item <=============\n";
            open(FH, '<', "$logdir/$item") or die "Can't open $logdir/$item";
            while (readline FH) {
                print $_;
            }
            close(FH);
        }
    }

    $self->assert($status);
}

1;
