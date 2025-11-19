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

sub add_member {
    my ($self, $card_or_uid) = @_;

    if (ref $card_or_uid && !$card_or_uid->isa(__PACKAGE__)) {
        Carp::confess("argument to ->add_member must be a ContactCard or UID string");
    }

    my $kind = $self->kind;
    $kind eq 'group' || Carp::confess("called ->add_member on a non-group (kind is $kind)");

    my $uid = ref $card_or_uid ? $card_or_uid->uid : $card_or_uid;
    my %new_members = map {; $_ => JSON::true() } (
        keys %{ $self->members // {} },
        $uid
    );

    # We're sending _all_ the members instead of patching because the "update
    # instance in situ" code in $factory->_update is not sophisticated enough
    # to cope with patches.  We need to address that. -- rjbs, 2025-11-19
    $self->factory->_update($self => { members => \%new_members });
    return;
}

sub create_member {
    my ($self, $props) = @_;

    my $kind = $self->kind;
    $kind eq 'group' || Carp::confess("called ->create_member on a non-group (kind is $kind)");

    my $card = $self->factory->create($props);
    $self->add_member($card);

    return $card;
}

no Moo;
1;
