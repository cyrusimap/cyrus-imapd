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
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: genmail3.pl [ -f format [maildir] | -u uri]";
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

$store->read_begin();
while (my $msg = $store->read_message())
{
    print "From - bogus\r\n";
    print $msg;
}
$store->read_end();
