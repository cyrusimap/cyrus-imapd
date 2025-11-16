package Cassandane::TestEntity::Instance::ContactCard;
use Moo;

use lib '.';

# The properties here are from RFC 9553 (plus id and addressBookIds) in order
# listed in the RFC.
use Cassandane::TestEntity::AutoSetup properties => [ qw(
    id addressBookIds
    version created kind language members prodId relatedTo uid updated
    name organizations speakToAs titles
    emails onlineServices phones preferredContactLanguages
    calendars schedulingAddresses
    addresses
    cryptoKeys directories links media
    localizations
    anniversaries keywords notes personalInfo
) ];

sub _as_vcard {
    my ($self, $version) = @_;

    my $href = $self->properties->{'cyrusimap.org:href'};
    my $res = $self->user->carddav->Request(
        'GET', $href, '',
        Accept => "text/vcard; version=$version",
    );

    return $res->{content};
}

sub as_vcard3 {
    my ($self) = @_;
    $self->_as_vcard('3.0');
}

sub as_vcard4 {
    my ($self) = @_;
    $self->_as_vcard('4.0');
}

no Moo;
1;
