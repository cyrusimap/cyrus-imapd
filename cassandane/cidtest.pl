#!/usr/bin/perl

use strict;
use warnings;
use DateTime;
use Cassandane::MessageStoreFactory;
use Cassandane::Util::DateTime qw(from_rfc3501 to_iso8601);

sub usage
{
    die "Usage: cidtest.pl [ -f format [maildir] | -u uri]";
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

$store->set_fetch_attributes('uid', 'internaldate', 'cid')
    or die "Not an IMAP store";
$store->read_begin();
printf "UID       DATE             CID        MESSAGE-ID\n";
printf "--- ---------------- ---------------- ----------\n";
while (my $msg = $store->read_message())
{
    printf "%3u %16s %16s %s\n",
	    $msg->get_attribute('uid'),
	    to_iso8601(from_rfc3501($msg->get_attribute('internaldate'))),
	    $msg->get_attribute('cid'),
	    $msg->get_header('message-id');
}
$store->read_end();


