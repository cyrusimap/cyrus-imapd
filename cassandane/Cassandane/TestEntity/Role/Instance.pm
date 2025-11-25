package Cassandane::TestEntity::Role::Instance;
use Moo::Role;

use experimental 'signatures';

use Sub::Install ();

requires 'datatype'; # Email, Mailbox, etc.

requires 'datatype_properties'; # qw( foo bar baz )

sub initialize_accessors {
    my ($class) = @_;
    # Obnoxious, needs to be called on each instance class.
    for my $property ($class->datatype_properties) {
        Sub::Install::install_sub({
            as   => $property,
            into => $class,
            code => sub {
                my ($self, @rest) = @_;
                @rest > 1 && Carp::confess("too many arguments to ->$property");
                @rest == 0 && return $self->properties->{$property};

                $self->factory->_update($self => { $property => $rest[0] });
            },
        });
    }
}

has factory => (
    is => 'ro',
    required => 1,
    handles  => [ qw( user ) ],
);

has id => (
    is       => 'ro',
    required => 1,
);

has properties => (
    is    => 'ro',
    lazy  => 1,
    clearer  => 'clear_properties',
    default  => sub ($self) {
        $self->factory->_get_properties($self->id);
    },
);

no Moo::Role;
1;
