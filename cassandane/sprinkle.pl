#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

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

