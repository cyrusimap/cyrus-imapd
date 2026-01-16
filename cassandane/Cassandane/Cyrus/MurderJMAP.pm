# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::MurderJMAP;
use strict;
use warnings;
use Data::Dumper;

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

    my $self = $class->SUPER::new({
        config => $config,
        httpmurder => 1,
        jmap => 1,
        adminstore => 1
    }, @args);

    $self->needs('component', 'murder');
    $self->needs('component', 'jmap');
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
    :min_version_3_5
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

    my $frontend_jmap = $self->{frontend}->new_jmaptester_for_user(
        $self->default_user,
    );

    # upload a blob
    my $upload_res = $frontend_jmap->upload({
        accountId => 'cassandane',
        blob      => \"some test",
        type      => 'text/plain',
    });

    # request should have been proxied
    $self->assert_matches($proxy_re, $upload_res->http_response->header('Via'));

    # download the same blob
    my $resp = $frontend_jmap->Download({ accept => 'text/plain' },
                                     'cassandane', $upload_res->blob_id);

    # request should have been proxied
    $self->assert_matches($proxy_re, $resp->{headers}{via});

    # content should match
    $self->assert_str_equals('text/plain', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    # XXX test other commands
}

sub test_backend1_commands
    :min_version_3_5
{
    my ($self) = @_;
    my $result;

    my $backend1_svc = $self->{instance}->get_service("http");
    my $backend1_host = $backend1_svc->host();
    my $backend1_port = $backend1_svc->port();

    my $backend1_jmap = $self->{instance}->new_jmaptester_for_user(
        $self->default_user,
    );

    # upload a blob
    my $upload_res = $backend1_jmap->upload({
        accountId => 'cassandane',
        blob      => \"some test",
        type      => 'text/plain',
    });

    # request should not have been proxied
    $self->assert_null($upload_res->http_response->header('Via'));

    # download the same blob
    my $resp = $backend1_jmap->Download({ accept => 'text/plain' },
                                     'cassandane', $upload_res->blob_id);

    # request should not have been proxied
    $self->assert_null($resp->{headers}{via});

    # content should match
    $self->assert_str_equals('text/plain', $resp->{headers}{'content-type'});
    $self->assert_str_equals('some test', $resp->{content});

    # XXX test other commands
}

sub test_backend2_commands
    :min_version_3_5
{
    my ($self) = @_;
    my $result;

    my $backend2_svc = $self->{backend2}->get_service("http");
    my $backend2_host = $backend2_svc->host();
    my $backend2_port = $backend2_svc->port();

    my $backend2_jmap = $self->{backend2}->new_jmaptester_for_user(
        $self->default_user,
    );

    # try to upload a blob
    my $upload_res = $backend2_jmap->upload({
        accountId => 'cassandane',
        blob      => \"some test",
        type      => 'text/plain',
    });

    # user doesn't exist on this backend, so upload url should not exist
    $self->assert_num_equals(404, $upload_res->http_response->code);
    $self->assert_str_equals('Not Found', $upload_res->http_response->message);

    $self->assert(!$upload_res->is_success);

#    # XXX test other commands
}

1;
