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
use Cassandane::Util::Log;
use Cassandane::Util::Words;
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: sprinkle.pl imapuri mbox ...";
}

my $base_folder;
my $num_remaining = 0;
my $num_written = 0;
my $verbose = 1;

sub choose_folder
{
    my @parts;
    my $nparts = int(rand(7));

    for (my $i = 0 ; $i < $nparts ; $i++)
    {
        push(@parts, random_word());
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

