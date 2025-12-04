package Cassandane::JMAPTester;
use Moo;
extends 'JMAP::Tester';

has fallback_account_id => (
    is       => 'ro',
    required => 1,
);

# This emulates JMAPTalk's CallMethods, which returns the plain ol'
# array-of-arrays that is the methodResponses
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

# This emulates JMAPTalk's Upload, called like this:
#   $jmaptalk->Upload(\%optional_headers?, $bytes, $content_type, $accountId)
#
# scalar context, JMAPTalk returns the decoded result data
# list context, JMAPTalk returns (the underlying UA response, the decoded result)
#
# We will start by forbidding custom headers or list context.
sub Upload {
    my $self    = shift;
    my $headers = (ref $_[0] eq 'HASH') ? shift : {};
    my $bytes   = shift;
    my $type    = shift;
    my $accountId = shift // $self->fallback_account_id;

    wantarray
        && Carp::confess("Cassandane::JMAPTester can't emulate JMAPTalk->Upload in list context");

    my $upload = $self->upload({
        type => $type,
        blob => \$bytes,
        accountId => $accountId,
    });

    return $upload->{payload};
}

no Moo;
1;
