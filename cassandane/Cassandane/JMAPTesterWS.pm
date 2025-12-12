package Cassandane::JMAPTesterWS;
use Moo;

# Ugh. We must load AnyEvent::Loop before JMAP::Tester::WebSocket,
# otherwise AnyEvent in Cassandane::Instance::notifyd will use
# AnyEvent::Impl::IOAsync which is ... not actually running (except
# when ::WebSocket makes a request) ... which will make the perl
# notifyd process hang and lock up the tests
require AnyEvent::Loop;

extends 'JMAP::Tester::WebSocket';

use experimental 'signatures';
use MIME::Base64 ();

with 'Cassandane::JMAPTesterRole';

sub set_scheme_and_host_and_port ($self, $scheme, $host, $port) {
    my $ws_scheme = $scheme eq 'https' ? 'wss' : 'ws';

    $self->ws_api_uri("$ws_scheme://$host:$port/jmap/ws/");
    $self->authentication_uri("$scheme://$host:$port/jmap");
    $self->upload_uri("$scheme://$host:$port/jmap/upload/{accountId}/");

    # The session actually provides a query string of "?accept={type}" but our
    # tests don't reliably provide type, and we can't just use the Accept
    # header they send, because sometimes they send an Accept that's
    # preferential or wildcardy.  So, we'll just not include that parameter
    # here.  This is crap, but it's a transition toward less crap.
    $self->download_uri("$scheme://$host:$port/jmap/download/{accountId}/{blobId}/{name}");

    return;
}

sub set_username_and_password ($self, $username, $password) {
    my $auth = q{Basic } .  MIME::Base64::encode_base64(
                   join(q{:}, $username, $password),
                   q{},
               );

    $self->ua->set_default_header(
        'Authorization' => $auth
    );

    $self->authorization($auth);
}

no Moo;
1;
