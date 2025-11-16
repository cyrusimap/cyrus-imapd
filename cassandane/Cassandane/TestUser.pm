package Cassandane::TestUser;
use Moo;

use Cwd ();

has username => (is => 'ro', required => 1);
has password => (is => 'ro', required => 1);
has instance => (is => 'ro', required => 1);

has _common_service_args => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        my $service = $self->{instance}->get_service("https");
        $service ||= $self->{instance}->get_service("http");

        $service
          || Carp::confess("can't create a TestUser without an http service configured");

        my $ca_file = Cwd::abs_path("data/certs/cacert.pem");

        my %common_args = (
            user => 'cassandane',
            password => 'pass',
            host => $service->host(),
            port => $service->port(),
            scheme => ($service->is_ssl() ? 'https' : 'http'),
            SSL_options => {
                SSL_ca_file => $ca_file,
                SSL_verifycn_scheme => 'none',
            },
        );

        return \%common_args;
    },
);

has jmap => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        local $ENV{PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT} =
            Cassandane::Cyrus::TestCase::_need_http_tiny_env();

        unless ($self->instance->{config}->get_bit('httpmodules', 'jmap')) {
            Carp::croak("User JMAP client requested, but jmap httpmodule not enabled");
        }

        require Mail::JMAPTalk;
        $ENV{DEBUGJMAP} = 1;
        my $jmap = Mail::JMAPTalk->new(
            $self->_common_service_args->%*,
            url => '/jmap/',
        );

        # preload default UA while the HTTP::Tiny env var is still set
        $jmap->ua();

        return $jmap;
    }
);

has carddav => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        local $ENV{PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT} =
            Cassandane::Cyrus::TestCase::_need_http_tiny_env();

        unless ($self->instance->{config}->get_bit('httpmodules', 'carddav')) {
            Carp::croak("User CardDAV client requested, but carddav httpmodule not enabled");
        }

        require Net::CardDAVTalk;
        return Net::CardDAVTalk->new(
            $self->_common_service_args->%*,
            url => '/',
            expandurl => 1,
        );
    },
);

has caldav => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        local $ENV{PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT} =
            Cassandane::Cyrus::TestCase::_need_http_tiny_env();

        unless ($self->instance->{config}->get_bit('httpmodules', 'caldav')) {
            Carp::croak("User CalDAV client requested, but caldav httpmodule not enabled");
        }

        require Net::CalDAVTalk;
        my $caldav = Net::CalDAVTalk->new(
            $self->_common_service_args->%*,
            url => '/',
            expandurl => 1,
        );

        # XXX get users all with domain, etc.
        $caldav->UpdateAddressSet("Test User", $self->username . '@example.com');

        return $caldav;
    },
);

sub imap {
    my ($self) = @_;

    my $imap_svc = $self->instance->get_service('imap');
    my $imap_store = $imap_svc->create_store(username => $self->username);

    return $imap_store->get_client;
}

for my $pair (
  [ addressbooks => 'AddressBook' ],
  [ contacts     => 'ContactCard' ],
  [ emails       => 'Email' ],
  [ mailboxes    => 'Mailbox' ],
) {
  my ($attr, $moniker) = @$pair;
  my $class = "Cassandane::TestEntity::Factory::$moniker";

  has $attr => (
      is => 'ro',
      lazy => 1,
      default => sub {
          eval "require $class; 1" || Carp::croak("can't load $moniker: $@");
          return $class->new({ user => $_[0] });
      },
  );
}

no Moo;
1;
