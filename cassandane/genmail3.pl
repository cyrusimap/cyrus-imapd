#!/usr/bin/perl

use strict;
use warnings;
use DateTime;
use Cassandane::Generator;
use Cassandane::Util::DateTime qw(to_iso8601);
# use Cassandane::MboxMessageStore;
# use Cassandane::MaildirMessageStore;
use Cassandane::IMAPMessageStore;

my $now = DateTime->now()->epoch();
my $gen = Cassandane::Generator->new();
# my $store = Cassandane::MboxMessageStore->new();
# my $store = Cassandane::MaildirMessageStore->new( directory => 'foo' );
my $store = Cassandane::IMAPMessageStore->new(
	host => '127.0.0.2',
	port => 2143,
	folder => 'inbox.showaftertest2',
	username => 'test@vmtom.com',
	password => 'testpw',
	verbose => 1
    );

$store->begin();
for (my $offset = -86400*10 ; $offset <= 0 ; $offset += 3600)
{
    my $then = DateTime->from_epoch(epoch => $now + $offset);
    my $msg = $gen->generate(
	date => $then,
	subject => "message at " . to_iso8601($then),
    );
    $store->message($msg);
}
$store->end();
