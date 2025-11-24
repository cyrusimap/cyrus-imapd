package Cassandane::TestEntity::Instance::ContactCard;
use Moo;


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

sub _as_vcard_struct {
    my ($self, $version) = @_;
    my $vcard = $self->_as_vcard($version);

    require Text::VCardFast;
    my $struct = Text::VCardFast::vcard2hash($vcard);

    $struct || Carp::confess("can't parse $vcard");

    $struct->{objects}->@* == 1
      || Carp::confess("didn't get exactly one object when parsing vcard");

    return $struct->{objects}[0];
}

sub as_vcard3_struct {
    my ($self) = @_;
    $self->_as_vcard_struct('3.0');
}

sub as_vcard4_struct {
    my ($self) = @_;
    $self->_as_vcard_struct('4.0');
}

no Moo;
1;
