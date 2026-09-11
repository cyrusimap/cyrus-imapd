# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::HTTP;
use strict;
use warnings;

use Errno;
use IO::Select;
use MIME::Base64 qw(encode_base64);
use Net::HTTP;
use Net::HTTPS;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

=head1 NAME

Cassandane::Cyrus::HTTP - HTTP/1.x tests

=head1 OVERVIEW

This suite tests the HTTP/1.x server at the wire level, in either of two
styles.  C<http1_connect> and its companions hand back a L<Net::HTTP> socket:
the test writes its own request bytes but gets the response parsed for it,
which suits tests whose interest is in the reply.  C<< L</http1_request> >>
instead assembles the request from named pieces and returns the response as
raw bytes, which suits tests of malformed framing a real client would never
produce, or of a connection the server answers on more than once.

=cut

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(tls_server_cert => '@basedir@/conf/certs/cert.pem',
                 tls_server_key => '@basedir@/conf/certs/key.pem',
                 http_h2_altsvc => '127.0.0.1:8443',
                 caldav_realm => 'Cassandane',
                 httpmodules => 'caldav',
                 calendar_user_address_set => 'example.com');

    my $self = $class->SUPER::new({
        config => $config,
        install_certificates => 1,
        services => [ 'imap', 'http', 'https' ],
    }, @_);

    $self->needs('component', 'httpd');
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

# Net::HTTP parses real HTTP/1.1 responses for us, but tests still
# write their own raw request bytes with print $s "..." -- so they
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

# Read one HTTP/1.x response (status, headers lowercased, and the
# entity body if any) from a socket returned by http1_connect() or
# https1_connect().
sub http1_read_response
{
    my ($s) = @_;

    my ($code, undef, @kv) = $s->read_response_headers;
    my %headers;
    while (@kv) {
        my ($k, $v) = splice(@kv, 0, 2);
        $headers{lc $k} = $v;
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

    return { status => $code, headers => \%headers, body => $body };
}

# Read exactly $len raw bytes, e.g. a post-upgrade frame header. Uses
# my_read(), not sysread(): Net::HTTP may already have buffered these
# bytes internally while parsing the preceding response.
sub http1_read_bytes
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

    my $header = http1_read_bytes($s, 9);
    my ($b0, $b1, $b2, $type, $flags) = unpack('C5', $header);
    my $len = ($b0 << 16) | ($b1 << 8) | $b2;
    my ($stream_id) = unpack('N', substr($header, 5, 4));
    $stream_id &= 0x7fffffff;

    my $payload = $len ? http1_read_bytes($s, $len) : '';

    return { type => $type, flags => $flags,
            stream_id => $stream_id, payload => $payload };
}

=head1 METHODS

=head2 http1_request

    my $res = $self->http1_request(
        method   => 'PUT',
        path     => '/dav/calendars/user/cassandane/Default/x.ics',
        headers  => [ 'transfer-encoding' => 'chunked',
                      'content-type'      => 'text/calendar' ],
        raw_body => "100000000\r\n\r\n...",
    );
    # $res->{raw}       -- the full response, verbatim
    # $res->{statuses}  -- arrayref of the numeric statuses of each response
    #                      seen on the connection (more than one indicates the
    #                      server treated trailing bytes as a second request)

Sends a single HTTP/1.1 request on a new connection to the instance's C<http>
service and returns the raw response.  The response is read until the server
closes the connection or an idle timeout elapses, so a keep-alive connection on
which the server answered more than once (e.g. after request smuggling) is
captured in full.

Options:

=over 4

=item C<method> / C<path>

request method (default C<GET>) and target (default C<'/'>).

=item C<headers>

arrayref of additional request header name/value pairs.

=item C<body>

a request body; C<Content-Length> is added automatically.

=item C<raw_body>

Body bytes sent verbatim, with no C<Content-Length> added and no framing
applied.  Use this to craft chunked bodies (well-formed or not).  Mutually
exclusive with C<body>.

=item C<username> / C<password>

HTTP Basic credentials.  Default to the C<cassandane> test user; pass C<<
username => undef >> for no auth.

=item C<timeout>

Seconds to wait for response bytes (default 30)

=back

=cut

sub http1_request
{
    my ($self, %args) = @_;

    my $method  = $args{method}  // 'GET';
    my $path    = $args{path}    // '/';
    my $headers = $args{headers} // [];
    my $timeout = $args{timeout} // 30;

    die "http1_request: pass at most one of body/raw_body"
        if defined $args{body} && defined $args{raw_body};

    my $service = $self->{instance}->get_service('http');

    my @h = @$headers;
    my $username = exists $args{username} ? $args{username} : 'cassandane';
    if (defined $username) {
        my $password = $args{password} // 'pass';
        push @h, 'authorization' =>
            'Basic ' . encode_base64("$username:$password", '');
    }

    my $body = defined $args{raw_body} ? $args{raw_body} : $args{body};
    if (defined $args{body}) {
        push @h, 'content-length' => length $args{body};
    }

    my $req = "$method $path HTTP/1.1\r\n";
    $req .= "Host: " . $service->address() . "\r\n";
    while (my ($k, $v) = splice @h, 0, 2) {
        $req .= "$k: $v\r\n";
    }
    $req .= "\r\n";
    $req .= $body if defined $body;

    my $sock = $service->get_socket()
        or die "connect to the http service failed: $!";

    # A server that rejects a request part way through its body closes the
    # connection before we have written all of it -- which is a response to
    # read, not a failure.  $SIG{PIPE} is only set to IGNORE for multi-worker
    # runs, so make that true here regardless.
    local $SIG{PIPE} = 'IGNORE';

    for (my $off = 0; $off < length $req; ) {
        my $n = $sock->syswrite($req, length($req) - $off, $off);
        if (!defined $n) {
            last if $!{EPIPE} || $!{ECONNRESET};
            die "write to the http service failed: $!";
        }
        $off += $n;
    }

    my $sel = IO::Select->new($sock);
    my $raw = '';
    while ($sel->can_read($timeout)) {
        my $buf;
        my $n = $sock->sysread($buf, 65536);
        last if !defined $n || $n == 0;   # error or peer closed
        $raw .= $buf;
    }
    $sock->close;

    my @statuses = $raw =~ m{^HTTP/1\.[01] (\d{3})}mg;

    return { raw => $raw, statuses => \@statuses };
}

use Cassandane::Tiny::Loader;

1;
