# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::HTTP;
use strict;
use warnings;

use Net::HTTP;
use Net::HTTPS;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Wire;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(tls_server_cert => '@basedir@/conf/certs/cert.pem',
                 tls_server_key => '@basedir@/conf/certs/key.pem',
                 http_h2_altsvc => '127.0.0.1:8443');

    my $self = $class->SUPER::new({
        config => $config,
        install_certificates => 1,
        services => [ 'imap', 'http', 'https' ],
    }, @_);

    $self->needs('component', 'httpd');
    $self->needs('dependency', 'nghttp2');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

# RFC 7540 section 11.2, plus ALTSVC from RFC 7838 section 4.
my %H2_FRAME_NAME = (
    0x0 => 'DATA',
    0x1 => 'HEADERS',
    0x2 => 'PRIORITY',
    0x3 => 'RST_STREAM',
    0x4 => 'SETTINGS',
    0x5 => 'PUSH_PROMISE',
    0x6 => 'PING',
    0x7 => 'GOAWAY',
    0x8 => 'WINDOW_UPDATE',
    0x9 => 'CONTINUATION',
    0xA => 'ALTSVC',
);

# Render a byte string both ways for the wire log: hex is unambiguous,
# but frame payloads are often mostly text, where hex alone is
# miserable to read.  wire_recv() escapes the unprintable bytes.
sub _hex_and_raw
{
    my ($bytes) = @_;
    return sprintf("hex: %s\nraw: %s", unpack('H*', $bytes), $bytes);
}

# The far end of a socket, to label its half of the wire log.
sub _peer_of
{
    my ($s) = @_;
    my $peer = eval { $s->peerhost . ':' . $s->peerport };
    return $peer // 'unknown peer';
}

# Net::HTTP parses real HTTP/1.1 responses for us, but tests still
# write their own raw request bytes with http1_send() -- so they
# stay free to send whatever a full client wouldn't let them.
sub http1_connect
{
    my ($self) = @_;
    my $service = $self->{instance}->get_service('http');

    my $s = Net::HTTP->new(PeerAddr => $service->host,
                           PeerPort => $service->port);
    $self->assert_not_null($s, "couldn't connect to http service: $@");
    return $s;
}

# Same as http1_connect(), but TLS-wrapped from the start (the
# "https" service) -- cert verification is off since Cassandane's is
# self-signed and this suite doesn't care about TLS trust.
sub https1_connect
{
    my ($self) = @_;
    my $service = $self->{instance}->get_service('https');

    my $s = Net::HTTPS->new(PeerAddr => $service->host,
                            PeerPort => $service->port,
                            SSL_verify_mode => 0);
    $self->assert_not_null($s, "couldn't connect to https service: $@");
    return $s;
}

# Write raw request bytes to a connected socket, logging them.  The
# caller composes the request itself, so what lands in the test log
# is what went out, not a reconstruction that could disagree.
sub http1_send
{
    my ($s, @chunks) = @_;
    my $bytes = join('', @chunks);

    wire_sent(_peer_of($s), $bytes);
    print $s $bytes;

    return;
}

# Read one HTTP/1.x response (status, headers lowercased, and the
# entity body if any) from a socket returned by http1_connect() or
# https1_connect().
sub http1_read_response
{
    my ($s) = @_;

    my ($code, $message, @kv) = $s->read_response_headers;
    my %headers;
    my $log = "HTTP/" . $s->peer_http_version . " $code $message\n";
    while (@kv) {
        my ($k, $v) = splice(@kv, 0, 2);
        $headers{lc $k} = $v;
        $log .= "$k: $v\n";
    }

    my $body = '';
    # read_entity_body() warns about HEAD-detection state only
    # write_request() sets (harmless, we never send HEAD); a lexical
    # "no warnings" can't reach a warning from inside Net::HTTP itself.
    local $SIG{__WARN__} = sub {
        warn @_ unless $_[0] =~ /uninitialized value \$method/;
    };
    while (1) {
        my $chunk;
        my $n = $s->read_entity_body($chunk, 4096);
        die "read_entity_body failed: $!" unless defined $n;
        last unless $n;
        $body .= $chunk;
    }

    wire_recv(_peer_of($s), "$log\n$body");

    return { status => $code, headers => \%headers, body => $body };
}

# Read exactly $len raw bytes, e.g. a post-upgrade frame header,
# logging them.
sub http1_read_bytes
{
    my ($s, $len) = @_;
    my $buf = _read_bytes($s, $len);

    wire_recv(_peer_of($s),
              sprintf("%d bytes\n%s", length $buf, _hex_and_raw($buf)));

    return $buf;
}

# http1_read_bytes() without the logging, for callers that can say
# something more useful about the bytes than "here they are".  Uses
# my_read(), not sysread(): Net::HTTP may already have buffered these
# bytes internally while parsing the preceding response.
sub _read_bytes
{
    my ($s, $len) = @_;
    my $buf = '';

    while (length($buf) < $len) {
        my $chunk;
        my $n = $s->my_read($chunk, $len - length($buf));
        die "socket read failed: $!" unless defined $n;
        die "unexpected EOF from socket" if $n == 0;
        $buf .= $chunk;
    }

    return $buf;
}

# Read one HTTP/2 frame (RFC 7540 4.1: 9-byte header + payload) off a
# socket already upgraded to h2c.
sub h2_read_frame
{
    my ($s) = @_;

    my $header = _read_bytes($s, 9);
    my ($b0, $b1, $b2, $type, $flags) = unpack('C5', $header);
    my $len = ($b0 << 16) | ($b1 << 8) | $b2;
    my ($stream_id) = unpack('N', substr($header, 5, 4));
    $stream_id &= 0x7fffffff;

    my $payload = $len ? _read_bytes($s, $len) : '';

    wire_recv(_peer_of($s),
              sprintf("HTTP/2 %s frame, flags 0x%02x, stream %d, %d bytes\n%s",
                      $H2_FRAME_NAME{$type} // sprintf('0x%02x', $type),
                      $flags, $stream_id, $len, _hex_and_raw($payload)));

    return { type => $type, flags => $flags,
            stream_id => $stream_id, payload => $payload };
}

use Cassandane::Tiny::Loader;

1;
