package Cassandane::TestEntity::Factory::AddressBook;
use Moo;

use feature 'state';

sub fill_in_creation_defaults {
    my ($self, $prop) = @_;

    state $i = 1;
    $prop->{name} //= 'Address Book #' . $i++;

    return;
}

use Cassandane::TestEntity::AutoSetup;

no Moo;
1;
