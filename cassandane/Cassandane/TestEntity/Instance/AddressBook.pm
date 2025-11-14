package Cassandane::TestEntity::Instance::AddressBook;
use Moo;

use lib '.';
use Cassandane::TestEntity::AutoSetup properties => [ qw( id from ) ];

sub create_card {
    my ($self, $props) = @_;

    $self->user->contacts->create({
        %$props,
        addressBookIds => { $self->id => JSON::true() },
    });
}

no Moo;
1;
