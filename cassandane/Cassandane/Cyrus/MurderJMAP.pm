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

package Cassandane::Cyrus::MurderJMAP;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set('conversations' => 'yes');
    $config->set_bits('httpmodules', 'jmap');

    return $class->SUPER::new({
        config => $config,
        httpmurder => 1,
        jmap => 1,
        adminstore => 1
    }, @args);
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

sub test_aaa_setup
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

# XXX This can't pass because we don't support multiple murder services
# XXX at once, but renaming out the "bogus" and running it, and it failing,
# XXX proves the infrastructure to prevent requesting both works.
sub bogustest_aaa_imapjmap_setup
    :IMAPMurder
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_frontend_commands
    :needs_component_jmap :min_version_3_5
{
    my ($self) = @_;
    my $result;

    my $frontend_svc = $self->{frontend}->get_service("http");
    my $frontend_host = $frontend_svc->host();
    my $frontend_port = $frontend_svc->port();
    my $proxy_re = qr{
        \b
        ( localhost | $frontend_host )
        : $frontend_port
        \b
    }x;

    my $frontend_jmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $frontend_host,
        port => $frontend_port,
        scheme => 'http',
        url => '/jmap/',
    );

    # upload a blob
    my ($resp, $data) = $frontend_jmap->Upload("some test", "text/plain");

    # request should have been proxied
    $self->assert_matches($proxy_re, $resp->{headers}{via});

    # download the same blob
    $resp = $frontend_jmap->Download({ accept => 'text/plain' },
                                     'cassandane', $data->{blobId});

    # request should have been proxied
    $self->assert_matches($proxy_re, $resp->{headers}{via});

    # content should match
    $self->assert_str_equals('text/plain', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    # XXX test other commands
}

sub test_backend1_commands
    :needs_component_jmap :min_version_3_5
{
    my ($self) = @_;
    my $result;

    my $backend1_svc = $self->{instance}->get_service("http");
    my $backend1_host = $backend1_svc->host();
    my $backend1_port = $backend1_svc->port();

    my $backend1_jmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $backend1_host,
        port => $backend1_port,
        scheme => 'http',
        url => '/jmap/',
    );

    # upload a blob
    my ($resp, $data) = $backend1_jmap->Upload("some test", "text/plain");

    # request should not have been proxied
    $self->assert_null($resp->{headers}{via});

    # download the same blob
    $resp = $backend1_jmap->Download({ accept => 'text/plain' },
                                     'cassandane', $data->{blobId});

    # request should not have been proxied
    $self->assert_null($resp->{headers}{via});

    # content should match
    $self->assert_str_equals('text/plain', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    # XXX test other commands
}

sub test_backend2_commands
    :needs_component_jmap :min_version_3_5
{
    my ($self) = @_;
    my $result;

    my $backend2_svc = $self->{backend2}->get_service("http");
    my $backend2_host = $backend2_svc->host();
    my $backend2_port = $backend2_svc->port();

    my $backend2_jmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $backend2_host,
        port => $backend2_port,
        scheme => 'http',
        url => '/jmap/',
    );

    # try to upload a blob
    my ($resp, $data) = $backend2_jmap->Upload("some test", "text/plain");

    # user doesn't exist on this backend, so upload url should not exist
    $self->assert_num_equals(404, $resp->{status});
    $self->assert_str_equals('Not Found', $resp->{reason});

    $self->assert_null($data);

#    # XXX test other commands
}

1;
