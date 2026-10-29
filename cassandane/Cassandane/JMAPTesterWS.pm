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

with 'Cassandane::Role::JMAPTester';

around set_scheme_and_host_and_port => sub ($orig, $self, $scheme, $host, $port) {
    $self->$orig($scheme, $host, $port);

    my $ws_scheme = $scheme eq 'https' ? 'wss' : 'ws';
    $self->ws_api_uri("$ws_scheme://$host:$port/jmap/ws/");

    return;
};

around set_username_and_password => sub ($orig, $self, $username, $password) {
    $self->$orig($username, $password);

    my $auth = $self->ua->get_default_header('Authorization');

    $self->authorization($auth);
};

# Extra headers to send with the upgrade request, as a list of name/value
# pairs.  JMAP::Tester::WebSocket builds that request itself and only adds
# Authorization, so append these to the headers it passes.
has upgrade_headers => (is => 'rw', default => sub { [] });

around connect_ws => sub ($orig, $self, @args) {
    my @extra = $self->upgrade_headers->@*;
    return $self->$orig(@args) if !@extra;

    my $new = \&Protocol::WebSocket::Request::new;
    no warnings 'redefine';
    local *Protocol::WebSocket::Request::new = sub ($class, %arg) {
        push $arg{headers}->@*, @extra;
        return $new->($class, %arg);
    };

    return $self->$orig(@args);
};

no Moo;
1;
