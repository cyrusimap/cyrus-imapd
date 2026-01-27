#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;
use DateTime;

use lib '.';
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: genmail3.pl [ -f format [maildir] | -u uri]";
}

my %params;
while (my $a = shift)
{
    if ($a eq '-f')
    {
        usage() if defined $params{uri};
        $params{type} = shift;
    }
    elsif ($a eq '-u')
    {
        usage() if defined $params{type};
        $params{uri} = shift;
    }
    elsif ($a eq '-v')
    {
        $params{verbose} = 1;
    }
    elsif ($a =~ m/^-/)
    {
        usage();
    }
    else
    {
        usage() if defined $params{path};
        $params{path} = $a;
    }
}

my $store = Cassandane::MessageStoreFactory->create(%params);

$store->read_begin();
while (my $msg = $store->read_message())
{
    print "From - bogus\r\n";
    print $msg;
}
$store->read_end();
