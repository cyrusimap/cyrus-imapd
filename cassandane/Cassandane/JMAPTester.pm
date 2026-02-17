package Cassandane::JMAPTester;
use Moo;
extends 'JMAP::Tester';

use experimental 'signatures';
use MIME::Base64 ();

with 'Cassandane::Role::JMAPTester';

has '+default_arguments' => (
  lazy    => 1,
  default => sub ($self) {
    return { accountId => $self->fallback_account_id };
  },
);

no Moo;
1;
