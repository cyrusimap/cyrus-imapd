# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::HTTP;
use strict;
use warnings;

use Net::HTTP;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $self = $class->SUPER::new({
        services => [ 'imap', 'http' ],
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

# Read one HTTP/1.x response (status, headers lowercased, and the
# entity body if any) from a socket returned by http1_connect().
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

use Cassandane::Tiny::Loader;

1;
