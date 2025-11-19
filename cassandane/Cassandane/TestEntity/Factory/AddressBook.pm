package Cassandane::TestEntity::Factory::AddressBook;
use Moo;

use lib '.';
use Cassandane::TestEntity::AutoSetup;

use feature 'state';

sub fill_in_creation_defaults {
    my ($self, $prop) = @_;

    state $i = 1;
    $prop->{name} //= 'Address Book #' . $i++;

    return;
}

no Moo;
1;
