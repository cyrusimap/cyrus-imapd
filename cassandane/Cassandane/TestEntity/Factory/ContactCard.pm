package Cassandane::TestEntity::Factory::ContactCard;
use Moo;

use lib '.';
use Cassandane::TestEntity::AutoSetup;

use Data::GUID ();

sub fill_in_creation_defaults {
    my ($self, $prop) = @_;
    $prop->{kind} //= 'individual';

    $prop->{created} //= do {
        my $now = DateTime->now();
        $now->strftime('%Y-%m-%dT%H:%M:%SZ');
    };

    $prop->{'@type'} //= 'Card';
    $prop->{version} //= '1.0';

    $prop->{prodId} //= '-//Cyrus IMAP//Cassandane/'; # make better

    $prop->{uid} //= Data::GUID->new->as_string;

    return;
}

no Moo;
1;
