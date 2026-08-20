# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::HttpH2;
use strict;
use warnings;

use IO::Socket::INET;
use IO::Select;
use MIME::Base64 qw(encode_base64);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

=head1 NAME

Cassandane::Cyrus::HttpH2 - HTTP/2 tests

=head1 OVERVIEW

This suite provides the method C<< L</http2_request> >> for testing HTTP/2.

Tests speak I<cleartext> HTTP/2 using the "prior knowledge" connection preface
(RFC 7540 section 3.4): no TLS, and no C<Upgrade: h2c> handshake.  Cyrus
accepts this on any plain C<http> service, so a test can open an ordinary
socket and start sending HTTP/2 frames.

=cut

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 httpmodules => 'caldav',
                 calendar_user_address_set => 'example.com');

    my $self = $class->SUPER::new({
        config => $config,
        services => [ 'imap', 'http' ],
    }, @args);

    $self->needs('component', 'httpd');

    return $self;
}

# Skip the whole suite unless the HTTP/2 client library is available.
sub skip_check
{
    my ($self) = @_;
    return "Protocol::HTTP2 is not installed"
        unless eval { require Protocol::HTTP2::Client; 1 };
    return undef;
}

=head1 METHODS

=head2 http2_request

    my $res = $self->http2_request(
        method  => 'PUT',
        path    => '/dav/calendars/user/cassandane/Default/x.ics',
        headers => [ 'content-type' => 'text/calendar' ],
        body    => $ical,
    );
    # $res->{status}, $res->{headers} (hashref), $res->{body}

Performs a single HTTP/2 request over cleartext on a new connection to the
instance's C<http> service, and returns the response as a hashref with
C<status> (the C<:status> pseudo-header, an integer), C<headers> (a hashref of
the remaining response headers), and C<body> (the response body).

Options:

=over 4

=item C<method>

the request method (default C<GET>).

=item C<path>

the request target (default C<'/'>).

=item C<headers>

an arrayref of additional request header name/value pairs.

=item C<body>

the request body, sent as HTTP/2 DATA frames.  No C<content-length> is sent;
the body is delimited by end-of-stream, as HTTP/2 allows.

=item C<username> / C<password>

HTTP Basic credentials to send.  Default to the C<cassandane> test user; pass
C<< username => undef >> for no auth.

=item C<timeout>

seconds to wait for the response (default 30)

=back

=cut

sub http2_request
{
    my ($self, %args) = @_;

    require Protocol::HTTP2::Client;

    my $method  = $args{method}  // 'GET';
    my $path    = $args{path}    // '/';
    my $headers = $args{headers} // [];
    my $timeout = $args{timeout} // 30;

    my $service = $self->{instance}->get_service('http');
    my $host = $service->host;
    my $port = $service->port;

    my @req_headers = @$headers;
    my $username = exists $args{username} ? $args{username} : 'cassandane';
    if (defined $username) {
        my $password = $args{password} // 'pass';
        unshift @req_headers,
            'authorization' => 'Basic '
                             . encode_base64("$username:$password", '');
    }

    my $res = { status => undef, headers => {}, body => '' };
    my $done;

    my $client = Protocol::HTTP2::Client->new;
    $client->request(
        ':scheme'    => 'http',
        ':authority' => "$host:$port",
        ':method'    => $method,
        ':path'      => $path,
        headers      => \@req_headers,
        (defined $args{body} ? (data => $args{body}) : ()),
        on_done      => sub {
            my ($resp_headers, $resp_body) = @_;
            my @h = @{ $resp_headers // [] };
            while (my ($k, $v) = splice @h, 0, 2) {
                if ($k eq ':status') { $res->{status} = 0 + $v }
                else                 { $res->{headers}{$k} = $v }
            }
            $res->{body} = $resp_body // '';
            $done = 1;
        },
    );

    my $sock = IO::Socket::INET->new(
        PeerHost => $host,
        PeerPort => $port,
        Proto    => 'tcp',
    ) or die "connect to $host:$port failed: $!";
    $sock->blocking(0);

    my $sel = IO::Select->new($sock);
    my $deadline = time() + $timeout;

    while (!$done && time() < $deadline) {
        while (my $frame = $client->next_frame) {
            $sel->can_write(5) or last;
            my $off = 0;
            while ($off < length $frame) {
                my $w = syswrite($sock, $frame, length($frame) - $off, $off);
                last if !defined $w;
                $off += $w;
            }
        }

        if ($sel->can_read(5)) {
            my $buf;
            my $r = sysread($sock, $buf, 65536);
            last if defined $r && $r == 0;   # peer closed
            $client->feed($buf) if $r;
        }
    }

    $sock->close;

    # We die only when the peer never produced a terminal response event: a
    # well-behaved server always sets $done.  We deliberately don't require a
    # parsed :status -- a server that answers an aborted upload with several
    # header blocks on one stream (see the maxmessagesize test) leaves
    # Protocol::HTTP2 unable to hand us a clean status, and such a caller
    # should assert on server state instead.
    die "no HTTP/2 response within ${timeout}s" unless $done;

    return $res;
}

use Cassandane::Tiny::Loader;

1;
