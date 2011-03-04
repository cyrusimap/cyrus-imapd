#!/usr/bin/perl

use strict;
use warnings;
use DateTime;
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: sprinkle.pl imapuri mbox ...";
}

my $base_folder;
my $num_remaining = 0;
my $num_written = 0;
my @words;
my $verbose = 1;

# Extract some well-formatted short words from the dictionary file
sub read_words
{
    my $filename = "/usr/share/dict/words";
    my $i = 0;
    my $stride = 200;
    open DICT,'<',$filename
	or die "Cannot open $filename for reading: $!";
    while (<DICT>)
    {
	chomp;
	$_ = lc;
	next unless m/^[a-z]+$/;
	next if length $_ > 5 || length $_ < 2;
	next if $i++ < $stride;
	$i = 0;
	push(@words, $_);
	last if scalar @words == 200;
    }
    close DICT;
}

sub choose_folder
{
    my @parts;
    my $nparts = int(rand(7));

    for (my $i = 0 ; $i < $nparts ; $i++)
    {
	push(@parts, $words[int(rand(scalar @words))]);
    }

    my $folder = join('.', ($base_folder, @parts));
    xlog "choosing folder $folder";
    return $folder;
}

sub sprinkle
{
    my ($path, $imap_store) = @_;

    my $mbox_store = Cassandane::MessageStoreFactory->create((
			type => 'mbox',
			path => $path ))
	or die "Cannot create MBOX message store";

    $mbox_store->read_begin();
    while (my $msg = $mbox_store->read_message())
    {
	if ($num_remaining == 0)
	{
	    $imap_store->write_end()
		if $num_written;
	    $imap_store->set_folder(choose_folder());
	    $imap_store->write_begin();
	    $num_remaining = 1 + int(rand(300));
	    $num_written = 0;
	    xlog "choosing $num_remaining messages";
	}
	$imap_store->write_message($msg);
	$num_remaining--;
	$num_written++;
    }
    $mbox_store->read_end();
}

read_words();
my $imap_store = Cassandane::MessageStoreFactory->create((
	type => 'imap',
	host => 'slott02',
	port => 2144,
	folder => 'inbox.sprinkle',
	username => 'test@vmtom.com',
	password => 'testpw',
	verbose => ($verbose > 1 ? 1 : 0),
    ))
    or die "Cannot create IMAP message store";
$base_folder = $imap_store->{folder};

while (my $a = shift)
{
    sprinkle($a, $imap_store);
}

$imap_store->write_end()
    if $num_written;
$imap_store->disconnect();

