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

package Cassandane::PortManager;
use strict;
use warnings;

use lib '.';
use Cassandane::Cassini;

my $base_port;
my $max_ports = 20;
my $next_port = 0;
my %allocated;

sub alloc
{
    if (!defined $base_port)
    {
        my $workerid = $ENV{TEST_UNIT_WORKER_ID} || '1';
        die "Invalid TEST_UNIT_WORKER_ID - code not run in Worker context"
            if (defined($workerid) && $workerid eq 'invalid');
        my $cassini = Cassandane::Cassini->instance();
        my $cassini_base_port = $cassini->val('cassandane', 'base_port') // 0;
        $base_port = 0 + $cassini_base_port || 9100;
        $base_port += $max_ports * ($workerid-1);
    }
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
        my $port = $base_port + (($next_port + $i) % $max_ports);
        if (!$allocated{$port})
        {
            $allocated{$port} = 1;
            $next_port++;
            return $port;
        }
    }
    die "No ports remaining";
}

sub free_all
{
    return unless defined $base_port;
    my @freed;
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
        my $port = $base_port + $i;
        if ($allocated{$port})
        {
            $allocated{$port} = 0;
            push(@freed, $port);
        }
    }
    return @freed;
}

1;
