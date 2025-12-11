package Cassandane::TestUser;
use Moo;

use experimental 'signatures';

use Carp ();
use Cwd ();

has username => (is => 'ro', required => 1);
has password => (is => 'ro', required => 1);
has instance => (is => 'ro', required => 1);

has jmap => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        $self->new_jmaptester;
    }
);

has entity_jmap => (
    # This is just a persistent JMAP client with all the "using" turned on.
    is => 'ro',
    lazy => 1,
    default => sub ($self) {
        $self->new_jmaptester;
    }
);

# Either 0-arg to get a default-config one, or provide just [using...] for
# custom using, or {k=>v,...} to override constructor args.
sub new_jmaptester ($self, $new_arg = undef) {
    $self->instance->new_jmaptester_for_user($self, $new_arg);
}

has carddav => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        $self->instance->new_carddavtalk_for_user($self);
    },
);

has caldav => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        $self->instance->new_caldavtalk_for_user($self);
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
