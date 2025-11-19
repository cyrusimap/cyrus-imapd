package Cassandane::TestEntity::Instance::AddressBook;
use Moo;

use Cassandane::TestEntity::AutoSetup properties => [ qw(
    id name description sortOrder isDefault isSubscribed
    shareWith myRights
) ];

with 'Cassandane::TestEntity::Role::ShareableInstance';

sub create_card {
    my ($self, $props) = @_;

    $self->user->contacts->create({
        %$props,
        addressBookIds => { $self->id => JSON::true() },
    });
}

no Moo;
1;
