use v5.28.0;
package Cassandane::TestEntity::DataType::AddressBook;

=head1 NAME

Cassandane::TestEntity::DataType::AddressBook - the AddressBook entity datatype

=cut

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

=head1 INSTANCE METHODS

=cut

package Cassandane::TestEntity::Instance::AddressBook {
    use Moo;

    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        name description sortOrder isDefault isSubscribed
        shareWith myRights
    ) ];

    with 'Cassandane::TestEntity::Role::ShareableInstance';

=head2 create_card

    my $card = $abook->create_card({ ... });

This method creates a ContactCard instance that's in C<< $abook >> and no other
address books.

=cut

    sub create_card {
        my ($self, $prop) = @_;
        $prop //= {};

        $self->user->contacts->create({
            %$prop,
            addressBookIds => { $self->id => JSON::true() },
        });
    }

=head2 create_card_group

    my $card = $abook->create_card_group({ ... });

This method is identical to C<create_card>, but will always set the C<kind>
property to "group".

=cut

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
