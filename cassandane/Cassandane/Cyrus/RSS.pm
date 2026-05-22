# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::RSS;
use strict;
use warnings;
use HTTP::Tiny;
use MIME::Base64 qw(encode_base64);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Message;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(httpmodules => 'rss');
    $config->set(httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ],
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

# Issue a GET against the RSS namespace, authenticated as cassandane.
sub _rss_get
{
    my ($self, $path) = @_;

    my $service = $self->{instance}->get_service("http");
    my $url = sprintf("http://%s:%s%s",
                      $service->host(), $service->port(), $path);

    my $auth = 'Basic ' . encode_base64('cassandane:pass', '');
    return HTTP::Tiny->new()->get($url, {
        headers => { Authorization => $auth },
    });
}

# Deliver a raw RFC822 message to cassandane@INBOX.
sub _deliver_raw
{
    my ($self, $raw) = @_;
    $self->{instance}->deliver(Cassandane::Message->new(raw => $raw));
}

# Assert that a hostile string survives a round trip through delivery + RSS
# rendering only in escaped form: the unescaped sentinel must not appear in
# the response body.
sub _assert_rss_does_not_contain
{
    my ($self, %args) = @_;

    my $raw      = $args{raw}      || die "missing raw";
    my $sentinel = $args{sentinel} || die "missing sentinel";
    my $path     = $args{path}     || '/rss/INBOX/';
    my $label    = $args{label}    || 'rss response';

    $self->_deliver_raw($raw);

    my $res = $self->_rss_get($path);
    $self->assert($res->{success}, "$label: HTTP request succeeded "
                                 . "(status=$res->{status})");

    my $body = $res->{content} // q{};
    $self->assert(index($body, $sentinel) == -1,
        "$label: response body must not contain unescaped '$sentinel'");
}

use Cassandane::Tiny::Loader;

1;
