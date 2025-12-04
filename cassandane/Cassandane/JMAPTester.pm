package Cassandane::JMAPTester;
use Moo;
extends 'JMAP::Tester';

has fallback_account_id => (
    is       => 'ro',
    required => 1,
);

no Moo;
1;
