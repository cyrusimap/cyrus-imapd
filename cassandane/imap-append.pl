#!/usr/bin/perl

use strict;
use warnings;
use DateTime;
use Cassandane::Generator;
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: imap-append.pl [ -f format [maildir] | -u uri]";
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
	usage() if defined $params{filename};
	$params{filename} = $a;
    }
}

my $imap_store = Cassandane::MessageStoreFactory->create(
	type => 'imap',
	host => 'storet1m.internal',
	port => 2143,
	folder => 'inbox',
	username => 'muttster@vmtom.com',
	password => 'testpw',
	verbose => 1,
    );
my $mbox_store = Cassandane::MessageStoreFactory->create(%params);

$imap_store->write_begin();
$mbox_store->read_begin();
while (my $msg = $mbox_store->read_message())
{
    $imap_store->write_message($msg);
}
$mbox_store->read_end();
$imap_store->write_end();
