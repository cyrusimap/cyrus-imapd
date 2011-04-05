#!/usr/bin/perl

package Cassandane::Util::Words;
use strict;
use warnings;

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &random_word
    );

my @words;

# Extract some well-formatted short words from the dictionary file
sub _read_words
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

sub random_word
{
    _read_words()
	if (!scalar @words);
    return $words[int(rand(scalar @words))];
}

1;
