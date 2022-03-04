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
        port => 9100,
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
