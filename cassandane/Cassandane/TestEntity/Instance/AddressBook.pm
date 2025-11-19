package Cassandane::TestEntity::Instance::AddressBook;
use Moo;

use Cassandane::TestEntity::AutoSetup properties => [ qw(
    id name description sortOrder isDefault isSubscribed
    shareWith myRights
) ];

with 'Cassandane::TestEntity::Role::ShareableInstance';

sub create_card {
    my ($self, $prop) = @_;

    $self->user->contacts->create({
        %$prop,
        addressBookIds => { $self->id => JSON::true() },
    });
}

sub create_card_group {
    my ($self, $prop) = @_;

    $self->user->contacts->create({
        %$prop,
        kind => 'group',
        addressBookIds => { $self->id => JSON::true() },
    });
}

no Moo;
1;
