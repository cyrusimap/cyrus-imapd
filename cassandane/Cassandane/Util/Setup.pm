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

package Cassandane::Util::Setup;
use strict;
use warnings;
use base qw(Exporter);
use POSIX;
use User::pwent;
use Data::Dumper;

use lib '.';
use Cassandane::Util::Log;

our @EXPORT = qw(&become_cyrus);

my $me = $0;
my @saved_argv = @ARGV;

sub become_cyrus
{
    my $cyrus = $ENV{CYRUS_USER};
    $cyrus //= 'cyrus';
    my $pw = getpwnam($cyrus);
    die "No user named '$cyrus'"
        unless defined $pw;
    my $uid = getuid();
    if ($uid == $pw->uid)
    {
        xlog "already running as user $cyrus" if get_verbose;
    }
    elsif ($uid == 0)
    {
        xlog "setuid from root to $cyrus" if get_verbose;
        setgid($pw->gid)
            or die "Cannot setgid to group $pw->gid: $!";
        setuid($pw->uid)
            or die "Cannot setuid to group $pw->uid: $!";
    }
    else
    {
        xlog "using sudo to re-run as user $cyrus" if get_verbose;
        my @cmd = ( qw(sudo -u), $cyrus, $me, @saved_argv );
        exec(@cmd);
    }
}

1;
