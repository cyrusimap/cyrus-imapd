package Cassandane::TestUser;
use Moo;

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
        return if !$service; # XXX die

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

has addressbooks => (
    is => 'ro',
    lazy => 1,
    default => sub {
        require Cassandane::TestEntity::Factory::AddressBook;
        return Cassandane::TestEntity::Factory::AddressBook->new({ user => $_[0] });
    },
);

has contacts => (
    is => 'ro',
    lazy => 1,
    default => sub {
        require Cassandane::TestEntity::Factory::ContactCard;
        return Cassandane::TestEntity::Factory::ContactCard->new({ user => $_[0] });
    },
);

has emails => (
    is => 'ro',
    lazy => 1,
    default => sub {
        require Cassandane::TestEntity::Factory::Email;
        return Cassandane::TestEntity::Factory::Email->new({ user => $_[0] });
    },
);

has mailboxes => (
    is => 'ro',
    lazy => 1,
    default => sub {
        require Cassandane::TestEntity::Factory::Mailbox;
        return Cassandane::TestEntity::Factory::Mailbox->new({ user => $_[0] });
    },
);

no Moo;
1;
