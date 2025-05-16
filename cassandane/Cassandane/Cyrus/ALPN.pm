#!/usr/bin/perl
#
#  Copyright (c) 2011-2024 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::ALPN;
use strict;
use warnings;
use Cwd qw(abs_path);
use Data::Dumper;
use HTTP::Tiny;
use IO::Socket::SSL;
use XML::Spice;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

# When ALPN negotiation fails, depending on the openssl version, we might get
# a sensible error message, or an opaque reference to "1120".
# https://github.com/openssl/openssl/issues/24300
my $alpn_fail_pattern = qr{(?: tlsv1\salert\sno\sapplication\sprotocol
                            |  ssl3_read_bytes:reason\(1120\)
                            )}x;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(tls_server_cert => '@basedir@/conf/certs/cert.pem',
                 tls_server_key => '@basedir@/conf/certs/key.pem',
                 allowstarttls => 'on',
                 httpmodules => 'caldav');

    my $self = $class->SUPER::new({
        config => $config,
        install_certificates => 1,
        services => [ 'imap', 'imaps' ],
    }, @_);

    $self->needs('dependency', 'openssl');
    $self->needs('dependency', 'openssl_alpn');

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

sub do_imap_starttls
{
    my ($self, $talk, $alpn_map) = @_;
    my $ca_file = abs_path("data/certs/cacert.pem");

    $talk->_imap_cmd('starttls', 0, 'starttls');

    die $talk->get_last_error()
        if $talk->get_last_completion_response() ne 'ok';

    IO::Socket::SSL->start_SSL($talk->{Socket},
                               SSL_ca_file => $ca_file,
                               SSL_verifycn_scheme => 'none',
                               SSL_alpn_protocols => $alpn_map,
    );

    if (ref $talk->{Socket} ne 'IO::Socket::SSL') {
        # TLS negotiation failed!
        eval {
            # connection will be dropped by server; make sure $talk notices
            local $SIG{__DIE__};
            $talk->logout() if $talk->state() > Mail::IMAPTalk::Unconnected;
        };
        die "TLS negotiation failed: $SSL_ERROR";
    }
}

# check if we selected the expected ALPN protocol.
# if the underlying IO::Socket::SSL object isn't accessible, pass undef
# and this check will examine logs instead
sub assert_alpn_protocol
{
    my ($self, $socket, $protocol) = @_;

    if ($socket) {
        if ($protocol) {
            $self->assert_str_equals($protocol, $socket->alpn_selected());
        }
        else {
            $self->assert_null($socket->alpn_selected());
        }
    }
    else {
        return if !$self->{instance}->{have_syslog_replacement};

        my @lines = $self->{instance}->getsyslog(qr{starttls: \S+ with cipher});
        $self->assert_num_equals(1, scalar @lines);

        if ($protocol) {
            $self->assert_matches(qr{; application protocol = $protocol},
                                  $lines[0]);
        }
        else {
            $self->assert_does_not_match(qr{; application protocol =},
                                         $lines[0]);
        }
    }
}

sub test_imap_none
{
    my ($self) = @_;

    # get a pristine connection
    $self->{store}->disconnect();
    my $talk = $self->{store}->get_client(NoLogin => 1);

    $self->do_imap_starttls($talk, undef);

    $talk->login('cassandane', 'secret');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $talk->select("INBOX");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->assert_alpn_protocol($talk->{Socket}, undef);
}

sub test_imap_good
{
    my ($self) = @_;

    # get a pristine connection
    $self->{store}->disconnect();
    my $talk = $self->{store}->get_client(NoLogin => 1);

    $self->do_imap_starttls($talk, [ 'imap' ]);

    $talk->login('cassandane', 'secret');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $talk->select("INBOX");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->assert_alpn_protocol($talk->{Socket}, 'imap');
}

sub test_imap_bad
{
    my ($self) = @_;

    # get a pristine connection
    $self->{store}->disconnect();
    my $talk = $self->{store}->get_client(NoLogin => 1);

    eval {
        $self->do_imap_starttls($talk, [ 'bogus' ]);
    };

    my $e = $@;
    $self->assert_not_null($e);
    $self->assert_matches($alpn_fail_pattern, $e);
    $self->assert_num_equals(Mail::IMAPTalk::Unconnected, $talk->state());
}

sub test_imaps_none
{
    my ($self) = @_;

    my $imaps = $self->{instance}->get_service('imaps');
    my $store = $imaps->create_store(username => 'cassandane');
    my $talk = $store->get_client(OverrideALPN => undef);

    $talk->select("INBOX");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->assert_alpn_protocol($talk->{Socket}, undef);
}

sub test_imaps_good
{
    my ($self) = @_;

    my $imaps = $self->{instance}->get_service('imaps');
    my $store = $imaps->create_store(username => 'cassandane');
    my $talk = $store->get_client(); # correct ALPN map is the default

    $talk->select("INBOX");
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    $self->assert_alpn_protocol($talk->{Socket}, 'imap');
}

sub test_imaps_bad
{
    my ($self) = @_;

    my $imaps = $self->{instance}->get_service('imaps');
    my $store = $imaps->create_store(username => 'cassandane');
    my $talk;

    eval {
        $talk = $store->get_client(OverrideALPN => [ 'bogus' ]);
    };
    my $e = $@;

    $self->assert_not_null($e);
    $self->assert_matches($alpn_fail_pattern, $e);
}

sub do_https_request
{
    my ($self, $service, $alpn_map) = @_;

    my $ca_file = abs_path("data/certs/cacert.pem");

    my $client = HTTP::Tiny->new(verify_SSL => 1,
                                 SSL_options => {
                                    SSL_ca_file => $ca_file,
                                    SSL_verifycn_scheme => 'none',
                                    SSL_alpn_protocols => $alpn_map,
                                 });

    my $url = sprintf("https://%s:%s@%s:%s/dav/calendars",
                      'cassandane', 'secret',
                      $service->host(), $service->port());

    my $content = x('D:propfind', { 'xmlns:D' => 'DAV:' },
                    x('D:prop',
                      x('D:current-user-principal')));

    my $response = $client->request('PROPFIND', $url, {
        headers => {
            'content-type' => 'application/xml; charset=utf8',
        },
        content => "$content", # stringify the XML::Spice::Chunk
    });

    return $response;
}

sub test_https_none
    :want_service_https :needs_component_httpd
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = undef;

    my $response = $self->do_https_request($https, $alpn_map);

    $self->assert_num_equals(1, $response->{success});
    $self->assert_alpn_protocol(undef, undef);
}

sub test_https_http10
    :want_service_https :needs_component_httpd
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = [ 'http/1.0' ];

    my $response = $self->do_https_request($https, $alpn_map);

    $self->assert_num_equals(1, $response->{success});
    $self->assert_alpn_protocol(undef, $alpn_map->[0]);
}

sub test_https_http11
    :want_service_https :needs_component_httpd
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = [ 'http/1.1' ];

    my $response = $self->do_https_request($https, $alpn_map);

    $self->assert_num_equals(1, $response->{success});
    $self->assert_alpn_protocol(undef, $alpn_map->[0]);
}

sub test_https_multi
    :want_service_https :needs_component_httpd
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = [ 'http/1.1', 'http/1.0' ];

    my $response = $self->do_https_request($https, $alpn_map);

    $self->assert_num_equals(1, $response->{success});
    $self->assert_alpn_protocol(undef, $alpn_map->[0]);
}

sub test_https_h2
    :want_service_https :needs_component_httpd :needs_dependency_nghttp2
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = [ 'h2' ];

    my $response = $self->do_https_request($https, $alpn_map);

    # HTTP::Tiny can't speak h2, so the request itself will fail
    $self->assert_num_equals(0, $response->{success});
    $self->assert_str_equals('Internal Exception', $response->{reason});

    # but we can still examine the log to check the ALPN result
    $self->assert_alpn_protocol(undef, $alpn_map->[0]);
}

sub test_https_multi2
    :want_service_https :needs_component_httpd :needs_dependency_nghttp2
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = [ 'h2', 'http/1.1', 'http/1.0' ];

    my $response = $self->do_https_request($https, $alpn_map);

    # HTTP::Tiny can't speak h2, so the request itself will fail
    $self->assert_num_equals(0, $response->{success});
    $self->assert_str_equals('Internal Exception', $response->{reason});

    # but we can still examine the log to check the ALPN result
    $self->assert_alpn_protocol(undef, $alpn_map->[0]);
}

sub test_https_bad
    :want_service_https :needs_component_httpd
{
    my ($self) = @_;

    # skip past setup logs
    $self->{instance}->getsyslog();

    my $https = $self->{instance}->get_service('https');
    my $alpn_map = [ 'bogus' ];

    my $response = $self->do_https_request($https, $alpn_map);

    $self->assert_num_equals(0, $response->{success});
    $self->assert_str_equals('Internal Exception', $response->{reason});
    $self->assert_matches($alpn_fail_pattern, $response->{content});
}

1;
