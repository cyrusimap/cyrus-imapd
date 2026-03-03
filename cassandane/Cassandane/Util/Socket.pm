# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Socket;
use strict;
use warnings;
use base qw(Exporter);
use IO::Socket::INET;
use IO::Socket::INET6;
use IO::Socket::UNIX;

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
