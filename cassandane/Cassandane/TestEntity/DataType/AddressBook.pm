use v5.28.0;
package Cassandane::TestEntity::DataType::AddressBook;

package Cassandane::TestEntity::Factory::AddressBook {
    use Moo;

    sub fill_in_creation_defaults {
        my ($self, $prop) = @_;

        state $i = 1;
        $prop->{name} //= 'Address Book #' . $i++;

        return;
    }

    use Cassandane::TestEntity::AutoSetup;

    no Moo;
}

package Cassandane::TestEntity::Instance::AddressBook {
    use Moo;

    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        name description sortOrder isDefault isSubscribed
        shareWith myRights
    ) ];

    with 'Cassandane::TestEntity::Role::ShareableInstance';

    sub create_card {
        my ($self, $prop) = @_;
        $prop //= {};

        $self->user->contacts->create({
            %$prop,
            addressBookIds => { $self->id => JSON::true() },
        });
    }

    sub create_card_group {
        my ($self, $prop) = @_;
        $prop //= {};

        $self->user->contacts->create({
            %$prop,
            kind => 'group',
            addressBookIds => { $self->id => JSON::true() },
        });
    }

    no Moo;
}

1;
