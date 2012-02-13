#!/usr/bin/perl
#
#  Copyright (c) 2011-2012 Opera Software Australia Pty. Ltd.  All rights
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
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
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

package Cassandane::PortManager;
use strict;
use warnings;
use Error qw(:try);
use Cassandane::Util::Log;
use Cassandane::MessageStoreFactory;

my $base_port;
my $max_ports = 10;
my $next_port = 0;
my %allocated;
my %trace;

sub alloc
{
    if (!defined $base_port)
    {
	my $workerid = $ENV{TEST_UNIT_WORKER_ID} || '1';
	die "Invalid TEST_UNIT_WORKER_ID - code not run in Worker context"
	    if (defined($workerid) && $workerid eq 'invalid');
	$base_port = 9100 + $max_ports * ($workerid-1);
    }
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
	my $port = $base_port + (($next_port + $i) % $max_ports);
	if (!$allocated{$port})
	{
	    $allocated{$port} = 1;
	    $next_port++;
	    $trace{$port} = Carp::longmess('');
	    return $port;
	}
    }
    die "No ports remaining";
}

sub free
{
    my ($port) = @_;
    return unless defined $port;
    return unless ($port =~ m/^\d+$/);
    $allocated{$port} = 0;
    $trace{$port} = undef;
}

sub assert_all_free
{
    return unless defined $base_port;
    for (my $i = 0 ; $i < $max_ports ; $i++)
    {
	my $port = $base_port + $i;
	if ($allocated{$port})
	{
	    print STDERR "WARNING: Port $port never freed.  Allocated " . $trace{$port};
	    $allocated{$port} = 0;
	    $trace{$port} = undef;
	}
    }
# We could just 'die' here with the trace in the die argument,
# but the global string die handler carefully strips out the file
# and line number from $@, and the stack trace from Carp matches
# that regexp.  Throwing an Error avoids that.
# 	throw Error::Simple($message);
# Woops, it turns out we can't really throw any kind of exception
# at all, because if the test fails we end up seeing only the
# PortManager complaint and not the original failure.
}

1;
