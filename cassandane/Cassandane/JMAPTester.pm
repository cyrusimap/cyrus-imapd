package Cassandane::JMAPTester;
use Moo;
extends 'JMAP::Tester';

sub CallMethods {
  my ($self, $sentences, $using, %headers) = @_;

  %headers
    && Carp::confess("Cassandane::JMAPTester does not support custom HTTP headers");

  my $res = $self->request({
    methodCalls => $sentences,
    ($using ? (using => $using) : ()),
  });

  return $res->as_stripped_triples;
}

no Moo;
1;
