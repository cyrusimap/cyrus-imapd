# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Words;
use strict;
use warnings;
use List::Util qw(shuffle uniq);

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &random_word
    &random_words
);

my @words;
my @remaining;

use constant WORDFILE => '/usr/share/dict/words';
use constant STRIDE => 7;
use constant MAX_WORDS => 2048;
use constant MIN_LENGTH => 2;
use constant MAX_LENGTH => 7;

# Extract some well-formatted short words from the dictionary file
sub _read_words
{
    my $i = 0;
    open DICT,'<',WORDFILE
        or die "Cannot open " . WORDFILE . " for reading: $!";
    while (<DICT>)
    {
        chomp;
        $_ = lc;
        next unless m/^[a-z]+$/;
        next if length $_ > MAX_LENGTH || length $_ < MIN_LENGTH;
        next if $i++ < STRIDE;
        $i = 0;
        push(@words, $_);
        last if scalar @words == MAX_WORDS;
    }
    close DICT;

    @words = uniq @words;
}

sub random_word
{
    _read_words() unless scalar @words;
    @remaining = shuffle @words unless scalar @remaining;
    return shift @remaining;
}

sub random_words
{
    my ($count) = @_;
    my @random_words;

    while ($count-- > 0) {
        push @random_words, random_word();
    }

    return wantarray ? @random_words : "@random_words";
}

1;
