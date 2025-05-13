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

package Cassandane::Cyrus::StartTLS;
use strict;
use warnings;
use JSON::XS;
use Convert::Base64;
use Mail::JMAPTalk 0.13;
use Cwd qw(abs_path);
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Socket;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'yes',
                 httpmodules => 'jmap',
                 http_allowplaintext => 'off',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        httpmurder => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    $self->needs('component', 'murder');
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

sub test_imap_disabled
    :TLS :needs_dependency_openssl
{
    my ($self) = @_;

    # get a pristine connection
    $self->{store}->disconnect();
    my $talk = $self->{store}->get_client(NoLogin => 1);

    # STARTTLS should NOT be advertised
    my $res = $talk->capability();
    $self->assert_null($res->{starttls});

    # STARTTLS should be unrecognized command
    $talk->_imap_cmd('starttls', 0, 'starttls');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());
}

sub test_imap_enabled
    :TLS :needs_dependency_openssl :NoStartInstances
    :SuppressLSAN(libcrypto.so libssl.so)
{
    my ($self) = @_;

    $self->config_set(allowstarttls => 'on');

    $self->_start_instances();

    # get a pristine connection
    $self->{store}->disconnect();
    my $talk = $self->{store}->get_client(NoLogin => 1);

    # STARTTLS should be advertised
    my $res = $talk->capability();
    $self->assert_not_null($res->{starttls});

    # STARTTLS should succeed
    $talk->_imap_cmd('starttls', 0, 'starttls');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    my $ca_file = abs_path("data/certs/cacert.pem");
    IO::Socket::SSL->start_SSL($talk->{Socket},
                               SSL_ca_file => $ca_file,
                               SSL_verifycn_scheme => 'none',
    );
    $self->assert_str_equals('IO::Socket::SSL', ref $talk->{Socket});
}

sub test_http_disabled
    :TLS :needs_dependency_openssl
{
    my ($self) = @_;

    my $ca_file = abs_path("data/certs/cacert.pem");
    my $http = HTTP::Tiny->new(
        max_redirect => 0,
        SSL_options => {
            SSL_ca_file => $ca_file,
            SSL_verifycn_scheme => 'none'
        }
    );

    # frontend should NOT offer TLS upgrade and should redirect to https://
    my $frontend_svc = $self->{frontend}->get_service("http");
    my $frontend_host = $frontend_svc->host();
    my $frontend_port = $frontend_svc->port();

    my $scheme = "http";
    my $host = "$frontend_host:$frontend_port";
    my $hier_part = "//$host/jmap/";
    my $url = "$scheme:$hier_part";

    my $req = {
        method => 'GET',
        uri => $url,
        headers => {
            'Host' => $host,
            'Connection' => 'Upgrade',
            'Upgrade' => 'TLS/1.2'
        },
        content => '',
    };

    my $res = $http->request('GET', $url);
    $self->assert_str_equals('301', $res->{status});
    $self->assert_matches(qr/https:$hier_part/, $res->{headers}->{location});

    # backend should NOT offer TLS upgrade and should redirect to https://
    my $backend_svc = $self->{instance}->get_service("http");
    my $backend_host = $backend_svc->host();
    my $backend_port = $backend_svc->port();

    $host = "$backend_host:$backend_port";
    $hier_part = "//$host/jmap/";
    $url = "$scheme:$hier_part";

    $req = {
        method => 'GET',
        uri => $url,
        headers => {
            'Host' => $host,
            'Connection' => 'Upgrade',
            'Upgrade' => 'TLS/1.2'
        },
        content => '',
    };

    $res = $http->request('GET', $url);
    $self->assert_str_equals('301', $res->{status});
    $self->assert_matches(qr/https:$hier_part/, $res->{headers}->{location});
}

sub test_http_enabled
    :TLS :needs_dependency_openssl :NoStartInstances
    :SuppressLSAN(libcrypto.so libssl.so)
{
    my ($self) = @_;

    $self->config_set(allowstarttls => 'on');

    $self->_start_instances();
    $self->_setup_http_service_objects();

    my $ca_file = abs_path("data/certs/cacert.pem");
    my $http = HTTP::Tiny->new(
        max_redirect => 0,
        SSL_options => {
            SSL_ca_file => $ca_file,
            SSL_verifycn_scheme => 'none'
        }
    );

    # frontend should NOT offer TLS upgrade and should redirect to https://
    my $frontend_svc = $self->{frontend}->get_service("http");
    my $frontend_host = $frontend_svc->host();
    my $frontend_port = $frontend_svc->port();

    my $scheme = "http";
    my $host = "$frontend_host:$frontend_port";
    my $hier_part = "//$host/jmap/";
    my $url = "$scheme:$hier_part";

    my $req = {
        method => 'GET',
        uri => $url,
        headers => {
            'Host' => $host,
            'Connection' => 'Upgrade',
            'Upgrade' => 'TLS/1.2'
        },
        content => '',
    };

    my $res = $http->request('GET', $url);
    $self->assert_str_equals('301', $res->{status});
    $self->assert_matches(qr/https:$hier_part/, $res->{headers}->{location});

    # backend should offer TLS upgrade
    my $backend_svc = $self->{instance}->get_service("http");
    my $backend_host = $backend_svc->host();
    my $backend_port = $backend_svc->port();

    $host = "$backend_host:$backend_port";
    $hier_part = "//$host/jmap/";
    $url = "$scheme:$hier_part";

    $req = {
        method => 'GET',
        uri => $url,
        headers => {
            'Host' => $host,
            'Connection' => 'Upgrade',
            'Upgrade' => 'TLS/1.2'
        },
        content => '',
    };

    $res = $http->request('GET', $url);
    $self->assert_str_equals('426', $res->{status});

    # TLS upgrade should succeed (and request authentication)
    $http->{handle}->write_request($req);
    $res = $http->{handle}->read_response_header;
    $self->assert_str_equals('101', $res->{status});

    $http->{handle}->start_ssl( $backend_host );
    $res = $http->{handle}->read_response_header;
    $self->assert_str_equals('401', $res->{status});
}

1;
