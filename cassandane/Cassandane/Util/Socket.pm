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

package Cassandane::Util::Socket;
use strict;
use warnings;
use base qw(Exporter);
use IO::Socket::INET;
use IO::Socket::INET6;
use IO::Socket::UNIX;

use lib '.';
use Cassandane::Util::Log;

our @EXPORT = qw(create_client_socket);

sub create_client_socket
{
    my ($af, $host, $port) = @_;
    my $sock;

    if ($af eq 'inet')
    {
        $host ||= '127.0.0.1';
        xlog "create_client_socket INET host=$host port=$port";
        return IO::Socket::INET->new(
            Type => SOCK_STREAM,
            PeerHost => $host,
            PeerPort => $port);
    }
    elsif ($af eq 'inet6')
    {
        # IO::Socket::INET6 doesn't have an option to pass
        # an address which is explicitly *without* the optional
        # :port part, but it does allow us to use the same []
        # syntax for surrounding IPv6 address literals as Cyrus
        $host ||= '::1';
        xlog "create_client_socket INET6 addr=[$host]:$port";
        return IO::Socket::INET6->new(
            Domain => AF_INET6,
            Type => SOCK_STREAM,
            PeerAddr => "[$host]:$port");
    }
    elsif ($af eq 'unix')
    {
        xlog "create_client_socket UNIX peer=$port";
        return IO::Socket::UNIX->new(
            Type => SOCK_STREAM,
            Peer => $port);
    }
    die "Cannot create sock for address family \"$af\"";
}


1;
