package Cassandane::TestEntity::Instance::ContactCard;
use Moo;

with 'Cassandane::TestEntity::Role::Instance';

sub datatype { 'ContactCard' }

sub datatype_properties {
    qw( id addressBookIds kind members name prodId )
}

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

__PACKAGE__->initialize_accessors;

no Moo;
1;
