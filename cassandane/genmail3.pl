#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;
use DateTime;

use lib '.';
use Cassandane::SequenceGenerator;
use Cassandane::ThreadedGenerator;
use Cassandane::MessageStoreFactory;

sub usage
{
    print STDERR "Usage: genmail3.pl [ --threaded ] -u uri\n";
    print STDERR "       genmail3.pl [ --threaded ] [ -U user ]\n";
    print STDERR "                   [ -P password ] [ -F folder ]\n";
    print STDERR "                   [ -h host ] [ -p port ]\n";
    print STDERR "       genmail3.pl [ --threaded ] path\n";
    exit(1);
}

my $mode = 'sequence';
my $maxmessages;
my %params = (
        type => 'imap',
        host => 'localhost',
        port => 29100,
        folder => 'inbox',
        username => 'cassandane',
        password => 'testpw',
        verbose => 0,
);
while (my $a = shift)
{
    if ($a eq '-u')
    {
        usage() if defined $params{uri};
        %params = ( uri => shift, verbose => $params{verbose} );
    }
    elsif ($a eq '-h' || $a eq '--host')
    {
        $params{host} = shift;
        usage() unless defined $params{host};
    }
    elsif ($a eq '-p' || $a eq '--port')
    {
        $params{port} = shift;
        usage() unless defined $params{port};
    }
    elsif ($a eq '-F' || $a eq '--folder')
    {
        $params{folder} = shift;
        usage() unless defined $params{folder};
    }
    elsif ($a eq '-U' || $a eq '--user')
    {
        $params{username} = shift;
        usage() unless defined $params{username};
    }
    elsif ($a eq '-P' || $a eq '--password')
    {
        $params{password} = shift;
        usage() unless defined $params{password};
    }
    elsif ($a eq '-v' || $a eq '--verbose')
    {
        $params{verbose} = 1;
    }
    elsif ($a eq '-T' || $a eq '--threaded')
    {
        $mode = 'threaded';
    }
    elsif ($a eq '-m' || $a eq '--max-messages')
    {
        $maxmessages = shift || usage;
        $maxmessages = int(0+$maxmessages);
    }
    elsif ($a =~ m/^-/)
    {
        usage();
    }
    else
    {
        usage() if defined $params{path};
        %params = ( path => $a, verbose => $params{verbose} );
    }
}

my $store = Cassandane::MessageStoreFactory->create(%params);
my $now = DateTime->now()->epoch();
my $gen;
if ($mode eq 'sequence')
{
    $gen = Cassandane::SequenceGenerator->new();
}
elsif ($mode eq 'threaded')
{
    $gen = Cassandane::ThreadedGenerator->new();
}

$store->write_begin();
while (my $msg = $gen->generate())
{
    last if (defined $maxmessages && $maxmessages-- == 0);
    $store->write_message($msg);
}
$store->write_end();
