package Cassandane::TestEntity::Instance::Email;
use Moo;

use lib '.';
use Cassandane::TestEntity::AutoSetup properties => [ qw( id from ) ];

no Moo;
1;
