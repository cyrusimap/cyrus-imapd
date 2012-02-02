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

package Cassandane::Util::Log;
use strict;
use warnings;
use Sys::Syslog qw(:standard :macros);

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &xlog &set_verbose &get_verbose &xlog_set_listener
    );

my $verbose = 0;
my $listener;

openlog('cassandane', '', LOG_LOCAL6)
    or die "Cannot openlog";

sub xlog
{
    my ($pkg, $file, $line) = caller;
    $pkg =~ s/^Cassandane:://;
    my $msg = "=====> " . $pkg . "[" . $line . "] " . join(' ', @_);
    print STDERR "$msg\n" if $verbose;
    syslog(LOG_ERR, "$msg");
    $listener->($msg) if (defined $listener);
}

sub set_verbose
{
    my ($v) = @_;
    $verbose = 0 + $v;
}

sub get_verbose
{
    return $verbose;
}

sub xlog_set_listener
{
    my ($ll) = @_;
    $listener = $ll;
}

1;
