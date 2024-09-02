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
use Cassandane::Generator;
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: imap-append.pl [ -f format [maildir] | -u uri]";
}

my %imap_params = (
        type => 'imap',
        host => 'localhost',
        port => 9100,
        folder => 'inbox',
        username => 'cassandane',
        password => 'testpw',
);
my %mbox_params;
while (my $a = shift)
{
    if ($a eq '-f')
    {
        usage() if defined $mbox_params{uri};
        $mbox_params{type} = shift;
    }
    elsif ($a eq '-u')
    {
        usage() if defined $mbox_params{type};
        $mbox_params{uri} = shift;
    }
    elsif ($a eq '-h' || $a eq '--host')
    {
        $imap_params{host} = shift;
        usage() unless defined $imap_params{host};
    }
    elsif ($a eq '-p' || $a eq '--port')
    {
        $imap_params{port} = shift;
        usage() unless defined $imap_params{port};
    }
    elsif ($a eq '-F' || $a eq '--folder')
    {
        $imap_params{folder} = shift;
        usage() unless defined $imap_params{folder};
    }
    elsif ($a eq '-U' || $a eq '--user')
    {
        $imap_params{username} = shift;
        usage() unless defined $imap_params{username};
    }
    elsif ($a eq '-P' || $a eq '--password')
    {
        $imap_params{password} = shift;
        usage() unless defined $imap_params{password};
    }
    elsif ($a eq '-v' || $a eq '--verbose')
    {
        $mbox_params{verbose} = 1;
        $imap_params{verbose} = 1;
    }
    elsif ($a =~ m/^-/)
    {
        usage();
    }
    else
    {
        usage() if defined $mbox_params{filename};
        $mbox_params{filename} = $a;
    }
}

my $imap_store = Cassandane::MessageStoreFactory->create(%imap_params);
my $mbox_store = Cassandane::MessageStoreFactory->create(%mbox_params);

$imap_store->write_begin();
$mbox_store->read_begin();
while (my $msg = $mbox_store->read_message())
{
    $imap_store->write_message($msg);
}
$mbox_store->read_end();
$imap_store->write_end();
