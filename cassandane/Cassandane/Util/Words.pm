#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Util::Words;
use strict;
use warnings;

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &random_word
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
}

sub random_word
{
    _read_words()
        if (!scalar @words);
    @remaining = @words unless scalar @remaining;
    return $remaining[int(rand(scalar @remaining))];
}

1;
