package Cassandane::TestEntity::Factory::Email;
use Moo;

with 'Cassandane::TestEntity::Role::Factory';

use feature 'state';

require Cassandane::TestEntity::Instance::Email;

sub datatype { 'Email' }

sub instance_class  { 'Cassandane::TestEntity::Instance::Email' }

no Moo;
1;
