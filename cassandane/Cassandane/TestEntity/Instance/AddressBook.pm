package Cassandane::TestEntity::Instance::AddressBook;
use Moo;

with 'Cassandane::TestEntity::Role::Instance';

sub datatype { 'AddressBook' }

sub datatype_properties {
    qw( id name )
}

sub create_card {
    my ($self, $props) = @_;

    $self->user->contacts->create({
        %$props,
        addressBookIds => { $self->id => JSON::true() },
    });
}

__PACKAGE__->initialize_accessors;

no Moo;
1;
