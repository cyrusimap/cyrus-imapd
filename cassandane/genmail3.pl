#!/usr/bin/perl

use strict;
use warnings;
use DateTime;
use Cassandane::Generator;
use Cassandane::Util::DateTime qw(to_iso8601);
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
my $now = DateTime->now()->epoch();
my $gen = Cassandane::Generator->new();

$store->write_begin();
for (my $offset = -86400*10 ; $offset <= 0 ; $offset += 3600)
{
    my $then = DateTime->from_epoch(epoch => $now + $offset);
    my $msg = $gen->generate(
	date => $then,
	subject => "message at " . to_iso8601($then),
    );
    $store->write_message($msg);
}
$store->write_end();
