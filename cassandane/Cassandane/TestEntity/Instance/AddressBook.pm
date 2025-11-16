package Cassandane::TestEntity::Instance::AddressBook;
use Moo;

use lib '.';
use Cassandane::TestEntity::AutoSetup properties => [ qw(
    id name description sortOrder isDefault isSubscribed
    shareWith myRights
) ];

sub create_card {
    my ($self, $props) = @_;

    $self->user->contacts->create({
        %$props,
        addressBookIds => { $self->id => JSON::true() },
    });
}

no Moo;
1;
