# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
package Cyrus::IMAPOptions::Option;
use Moo;
use feature 'state';

use File::Basename;
use Types::Standard qw(ArrayRef Bool Enum Int Maybe Split Str);

my @option_types = qw(BITFIELD BYTESIZE DURATION ENUM INT
                      STRING STRINGLIST SWITCH);

has name => (
    isa => Str,
    is => 'ro',
    required => 1,
);
has type => (
    isa => Enum[@option_types],
    is => 'ro',
    required => 1,
);
has allowed_values => (
    isa => ArrayRef->of(Str)->plus_coercions(Split[qr/\s/]),
    is => 'ro',
    predicate => 1,
    coerce => 1,
);
has default_value => (
    isa => Maybe[Str] | ArrayRef[Str],
    is => 'ro',
    required => 1,
);
has last_modified => (
    isa => Str,
    is => 'ro',
    required => 1,
);
has deprecated_since => (
    isa => Maybe[Str],
    is => 'ro',
    predicate => 1,
);
has replaced_by => (
    isa => Maybe[Str],
    is => 'ro',
    predicate => 1,
);
has for_documentation_only => (
    isa => Bool,
    is => 'ro',
    default => undef,
);
has documentation => (
    isa => Maybe[ArrayRef[Str]],
    is => 'ro',
    predicate => 1,
);

around BUILDARGS => sub
{
    my ($orig, $class, @args) = @_;

    my $args = $class->$orig(@args);

    if (my $filename = delete $args->{from_file}) {
        _from_file($args, $filename);
    }

    return $args;
};

sub _type_allows_null
{
    my ($type) = @_;

    state %allows_null = map { $_ => 1 } qw(BYTESIZE DURATION STRING STRINGLIST);

    return exists $allows_null{$type};
}

sub _from_file
{
    my ($args, $filename) = @_;

    open my $in, '<', $filename or die "$filename: $!";

    do {
        # read header as a paragraph so we can unfold wrapped lines
        local $/ = q{};
        foreach my $header (split /\n(?!\s)/, <$in>) {
            chomp $header;
            $header =~ s/\n(\s)/$1/g; # unfold

            my ($field, $value) = split q{:\s?}, $header, 2;

            $field = lc $field;
            $field =~ tr/a-z_/_/cs;

            $args->{$field} = $value;
        }
    };

    if (not eof $in) {
        $args->{documentation} = [ <$in> ];
    }
    close $in;

    # name field must match filename
    die "name must match filename"
        if $args->{name} ne fileparse($filename);

    if ($args->{type} eq 'BITFIELD') {
        # BITFIELD type can have multiple values: split on whitespace
        $args->{default_value} = [ split /\s/, $args->{default_value} ];
    }
    elsif ($args->{default_value} eq 'NULL') {
        die "$args->{type} cannot have NULL default_value"
            if not _type_allows_null($args->{type});

        $args->{default_value} = undef;
    }
    else {
        # nothing to transform
    }
}

sub BUILD
{
    my ($self, $args) = @_;

    my $type = $self->type;
    my $dv = $self->default_value;

    die "$type can not have NULL default_value"
        unless defined $dv || _type_allows_null($type);

    if ($type eq 'STRINGLIST' || $type eq 'ENUM') {
        # STRINGLIST, ENUM must have Allowed-Values field
        # Default-Value must be ONE of Allowed-Values, or NULL for STRINGLIST
        die "$type must have allowed_values"
            if not $self->has_allowed_values;

        die "default_value '$dv' not allowed"
            if not $self->is_allowed_value($dv);
    }
    elsif ($type eq 'BITFIELD') {
        # BITFIELD must have Allowed-Values field
        # Default-Value must be SUBSET of Allowed-Values
        die "$type must have allowed_values"
            if not $self->has_allowed_values;

        my $type_check = ArrayRef[Str];

        die $type_check->get_message($dv)
            if not $type_check->check($dv);

        foreach my $v (@$dv) {
            die "default_value '$v' not allowed"
                if not $self->is_allowed_value($v);
        }
    }
    else {
        # other types may not have Allowed-Values field
        die "$type can not have allowed_values"
            if $self->has_allowed_values;
    }

    # Last-Modified must be a version number or UNRELEASED
    _parse_version('last_modified', $self->last_modified);

    if ($self->has_deprecated_since) {
        # if set, Deprecated-Since must be a version number or UNRELEASED
        _parse_version('deprecated_since', $self->deprecated_since);
    }

    if ($self->has_replaced_by) {
        # Replaced-By is only valid when Deprecated-Since is set
        die "replaced_by requires deprecated_since"
            if not $self->has_deprecated_since;
    }
}

sub is_allowed_value
{
    my ($self, $value) = @_;

    if (defined $value) {
        my $found = grep { $_ eq $value } @{$self->allowed_values};
        return !!$found;
    }
    else {
        return !!_type_allows_null($self->{type});
    }
}

sub _parse_version
{
    my ($field, $version) = @_;

    if ($version =~ m{ ^ (\d+) \. (\d+) \. (\d+) $ }x) {
        my ($maj, $min, $rev) = (0 + $1, 0 + $2, 0 + $3);

        die "major version too large: $maj" if $maj > 255;
        die "minor version too large: $min" if $min > 255;
        die "revision too large: $rev" if $rev > 255;

        return sprintf '0x%2.2X%2.2X%2.2X00', $maj, $min, $rev;
    }
    elsif ($version eq 'UNRELEASED') {
        return '0xFFFFFFFF';
    }
    else {
        die "$field must be a version number or UNRELEASED";
    }
}

1;
