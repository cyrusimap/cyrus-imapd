use v5.28.0;
package Cassandane::TestEntity::DataType::ContactCard;

package Cassandane::TestEntity::Factory::ContactCard {
    use Moo;

    use Data::GUID ();

    sub create_group {
        my ($self, $prop) = @_;
        $self->create({
            %$prop,
            kind => 'group',
        });
    }

    sub fill_in_creation_defaults {
        my ($self, $prop) = @_;

        if ($prop->{name} && ! ref $prop->{name}) {
            $prop->{name} = { full => $prop->{name} };
        }

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

    use Cassandane::TestEntity::AutoSetup;

    no Moo;
}

package Cassandane::TestEntity::Instance::ContactCard {
    use Moo;

    # The properties here are from RFC 9553 (plus id and addressBookIds) in
    # order listed in the RFC.
    use Cassandane::TestEntity::AutoSetup properties => [ qw(
        addressBookIds
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
            'GET', "$href", '',
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

    sub add_member {
        my ($self, $card_or_uid) = @_;

        if (ref $card_or_uid && !$card_or_uid->isa(__PACKAGE__)) {
            Carp::confess("argument to ->add_member must be a ContactCard or UID string");
        }

        my $kind = $self->kind;
        $kind eq 'group'
            || Carp::confess("called ->add_member on a non-group (kind is $kind)");

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
        $kind eq 'group'
            || Carp::confess("called ->create_member on a non-group (kind is $kind)");

        my $card = $self->factory->create($props);
        $self->add_member($card);

        return $card;
    }

    no Moo;
}

1;
