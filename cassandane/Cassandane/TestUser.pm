package Cassandane::TestUser;
use Moo;

=head1 NAME

Cassandane::TestUser - a handle on a Cyrus user with test-related methods

=head1 SYNOPSIS

Every test case gets one user created by default, and it's easy to make more,
either with or without setup actions:

    # get the default user, usually "cassandane"
    my $user = $test_case->default_user;

    # create a user and do some basic in-Cyrus setup
    my $user = $test_case->instance->create_user("someuser");

    # create a TestUser object, but don't touch Cyrus
    my $user = $test_case->instance->create_user_without_setup("someuser");

Once you have them, you can get pre-authenticated clients for various protocols
with the L</jmap>, L</caldav>, L</carddav>, or L</imap> methods.

You can also easily create test data using the entity system, for which see the
L</Test Entities> section below or L<Cassandane::TestEntity>.

=cut

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

has jmap_ws => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        $self->new_jmaptester_ws;
    }
);

has entity_jmap => (
    # This is just a persistent JMAP client with all the "using" turned on.
    is => 'ro',
    lazy => 1,
    default => sub ($self) {
        $self->new_jmaptester({
          ident => "entity_jmap/" . $self->username,
        });
    }
);

=head1 METHODS

=head2 new_jmaptester

    my $tester = $user->new_jmaptester;

This returns a new L<Cassandane::JMAPTester> authenticated as this user.  A
hashref can be passed as an argument, in which case it will be used as
additional arguments to the JMAPTester constructor.

If the argument is an arrayref, it will be used as the default C<using> for the
JMAPTester.

=cut

# Either 0-arg to get a default-config one, or provide just [using...] for
# custom using, or {k=>v,...} to override constructor args.
sub new_jmaptester ($self, $new_arg = undef) {
    $self->instance->new_jmaptester_for_user($self, $new_arg);
}

=head2 new_jmaptester_ws

    my $tester_ws = $user->new_jmaptester_ws;

This returns a new L<Cassandane::JMAPTesterWS> authenticated as this user.
That's just a JMAPTester that uses websockets.

Otherwise, this method has the same behavior as L</new_jmaptester>.

=cut

sub new_jmaptester_ws ($self, $new_arg = undef) {
    $self->instance->new_jmaptester_ws_for_user($self, $new_arg);
}

=head2 carddav

    my $carddav = $user->carddav;

This returns a (possibly cached) L<Net::CardDAVTalk> client for this user.

=cut

has carddav => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        $self->instance->new_carddavtalk_for_user($self);
    },
);

=head2 caldav

    my $carddav = $user->caldav;

This returns a (possibly cached) L<Net::CalDAVTalk> client for this user.

=cut

has caldav => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my ($self) = @_;
        $self->instance->new_caldavtalk_for_user($self);
    },
);

=head2 imap

    my $imap = $user->imap;

This returns a fresh L<Mail::IMAPTalk> client for this user.  Because IMAP is
stateful, this method never returns a cached client.

=cut

sub imap {
    my ($self) = @_;

    my $imap_svc = $self->instance->get_service('imap');
    my $imap_store = $imap_svc->create_store(username => $self->username);

    return $imap_store->get_client;
}

=head2 Test Entities

Apart from making it easy to get protocol clients, one of the most useful
behaviors of a TestUser is the L<test entity system|Cassandane::TestEntity>.
This makes it easy to create plausible test data without lots of tedious method
calls.

The following methods return factories for the relevant datatypes:

=over 4

=item addressbooks

returns a L<Cassandane::TestEntity::DataType::AddressBook> factory

=item contacts

returns a L<Cassandane::TestEntity::DataType::ContactCard> factory

=item emails

returns a L<Cassandane::TestEntity::DataType::Email> factory

=item mailboxes

returns a L<Cassandane::TestEntity::DataType::Mailbox> factory

=back

With these factories, you do lots of useful things described in their
documentation, but most simply the operations below, which work for every
datatype.  Mailboxes are just used as an example.

    my $mailbox = $user->mailboxes->get($mailbox_id);
    my $new_mailbox = $user->mailboxes->create({ prop1 => val1, ... });

    $mailbox->update({ prop1 => val1 });

=cut

for my $pair (
    [ addressbooks => 'AddressBook' ],
    [ contacts     => 'ContactCard' ],
    [ emails       => 'Email' ],
    [ mailboxes    => 'Mailbox' ],
) {
    my ($attr, $moniker) = @$pair;
    my $module = "Cassandane::TestEntity::DataType::$moniker";
    my $class  = "Cassandane::TestEntity::Factory::$moniker";

    has $attr => (
        is => 'ro',
        lazy => 1,
        default => sub {
            eval "require $module; 1" || Carp::croak("can't load $moniker: $@");
            return $class->new({ user => $_[0] });
        },
    );
}

no Moo;
1;
