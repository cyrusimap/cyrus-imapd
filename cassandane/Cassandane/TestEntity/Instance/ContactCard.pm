package Cassandane::TestEntity::Instance::ContactCard;
use Moo;

with 'Cassandane::TestEntity::Role::Instance';

sub datatype { 'ContactCard' }

sub datatype_properties {
    qw( id addressBookIds kind members name prodId )
}

__PACKAGE__->initialize_accessors;

no Moo;
1;
