package Cassandane::TestEntity::Factory::AddressBook;
use Moo;

with 'Cassandane::TestEntity::Role::Factory';

use feature 'state';

require Cassandane::TestEntity::Instance::AddressBook;

sub datatype { 'AddressBook' }

sub instance_class  { 'Cassandane::TestEntity::Instance::AddressBook' }

sub fill_in_creation_defaults {
    my ($self, $prop) = @_;

    state $i = 1;
    $prop->{name} //= 'Address Book #' . $i++;

    return;
}

no Moo;
1;
