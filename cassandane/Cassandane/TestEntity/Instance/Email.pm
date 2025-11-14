package Cassandane::TestEntity::Instance::Email;
use Moo;

with 'Cassandane::TestEntity::Role::Instance';

sub datatype { 'Email' }

sub datatype_properties {
    qw( id from )
}

__PACKAGE__->initialize_accessors;

no Moo;
1;
