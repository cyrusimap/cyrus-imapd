package Cyrus::Mbname;

use warnings;
use strict;

use Moo;
use Types::Standard qw(ArrayRef Value Int);

# internal data structure (real things)
has boxes => (is => 'rw', isa => ArrayRef);
has localpart => (is => 'rw', isa => Value);
has domain => (is => 'rw', isa => Value);
has is_deleted => (is => 'rw', isa => Int);

sub new_intname {
    my $class = shift;
    my $intname = shift;

    my %self;
    if ($intname =~ s/(.*?)\!//) {
        $self{domain} = $1;
    }

    my @boxes = split /\./, $intname;

    # convert to internal names
    s/\^/./g for @boxes;

    if (@boxes > 2 and $boxes[0] eq 'DELETED') {
        shift @boxes;
        $self{is_deleted} = hex(pop @boxes);
    }

    if (@boxes > 1 and $boxes[0] eq 'user') {
        shift @boxes;
        $self{localpart} = shift @boxes;
    }

    $self{boxes} = \@boxes;

    return bless \%self, ref($class) || $class;
}

sub new_dbname {
    my $class = shift;
    my $dbname = shift;

    # allow 'N' for new-style keys, an 'R' for 'RESTORED' domain
    die "Not a dbname $dbname" if $dbname =~ m/^[A-MO-QS-Z]/;
    unless ($dbname =~ s/^N//) {
        return $class->new_intname($dbname);
    }

    my %self;
    if ($dbname =~ s/(.*?)\x1d//) {
        $self{domain} = $1;
    }

    my @boxes = split /\x1f/, $dbname;

    if (@boxes > 2 and $boxes[0] eq 'DELETED') {
        shift @boxes;
        $self{is_deleted} = hex(pop @boxes);
    }

    if (@boxes > 1 and $boxes[0] eq 'user') {
        shift @boxes;
        $self{localpart} = shift @boxes;
    }

    $self{boxes} = \@boxes;

    return bless \%self, ref($class) || $class;
}

sub new_userfolder {
    my $class = shift;
    my $username = shift;
    my $folder = shift;

    my %self;
    if ($username =~ s/\@(.*)//) {
        $self{domain} = $1;
    }
    $self{localpart} = $username;

    if (defined $folder) {
        my @boxes = split /\./, $folder;

        # convert to internal names
        s/\^/./g for @boxes;

        if (@boxes > 2 and $boxes[0] eq 'DELETED') {
            shift @boxes;
            $self{is_deleted} = hex(pop @boxes);
        }

        if ($boxes[0] eq 'INBOX') {
            shift @boxes;
        }

        elsif($boxes[0] eq 'user') {
            shift @boxes;
            $self{localpart} = shift @boxes;
        }

        else {
            die "Unknown top-level $boxes[0]";
        }

        $self{boxes} = \@boxes;
    }
    else {
        $self{boxes} = [];    # INBOX
    }

    return bless \%self, ref($class) || $class;
}

sub new_adminfolder {
    # this is basically new_intname, but with the domain on the end...
    my $class = shift;
    my $adminfolder = shift;

    my %self;
    if ($adminfolder =~ s/\@([^@]+)$//) {
        $self{domain} = $1;
    }

    my @boxes = split /\./, $adminfolder;

    # convert to internal names
    s/\^/./g for @boxes;

    if (@boxes > 1 and $boxes[0] eq 'user') {
        shift @boxes;
        $self{localpart} = shift @boxes;
    }

    if (@boxes > 2 and $boxes[0] eq 'DELETED') {
        shift @boxes;
        $self{is_deleted} = hex(pop @boxes);
    }

    $self{boxes} = \@boxes;

    return bless \%self, ref($class) || $class;
}

# XXX - dunno how to write these mooselike, so doing them by hand
# in particular, they don't cache or do anything smart yet!

sub intname {
    my $self = shift;
    my $res = '';
    if ($self->{domain}) {
        $res .= $self->{domain} . '!';
    }

    my @boxes = @{$self->{boxes}||[]};

    if ($self->{localpart}) {
        unshift @boxes, $self->{localpart};
        unshift @boxes, 'user';
    }

    if ($self->{is_deleted}) {
        unshift @boxes, 'DELETED';
        push @boxes, sprintf("%08X", $self->{is_deleted});
    }

    s/\./\^/g for @boxes;

    return $res . join('.', @boxes);
}

sub adminfolder {
    my $self = shift;
    my $res = '';
    if ($self->{domain}) {
        $res = '@' . $self->{domain};
    }

    my @boxes = @{$self->{boxes}||[]};

    if ($self->{localpart}) {
        unshift @boxes, $self->{localpart};
        unshift @boxes, 'user';
    }

    if ($self->{is_deleted}) {
        unshift @boxes, 'DELETED';
        push @boxes, sprintf("%08X", $self->{is_deleted});
    }

    s/\./\^/g for @boxes;

    return join('.', @boxes) . $res;
}

sub dbname {
    my $self = shift;
    my $res = '';
    if ($self->{domain}) {
        $res .= $self->{domain} . "\x1d";
    }

    my @boxes = @{$self->{boxes}||[]};

    if ($self->{localpart}) {
        unshift @boxes, $self->{localpart};
        unshift @boxes, 'user';
    }

    if ($self->{is_deleted}) {
        unshift @boxes, 'DELETED';
        push @boxes, sprintf("%08X", $self->{is_deleted});
    }

    return $res . join("\x1f", @boxes);
}

sub userfolder {
    my $self = shift;
    my $username = shift;
    my $domain = $self->{domain};
    my $localpart = $self->{localpart};

    # let's see if this is a different user!
    if ($username) {
        if ($username =~ s/\@(.*)//) {
            $domain = $1;
        }
        $localpart = $username;
    }

    my @boxes = @{$self->{boxes}||[]};

    my $diffuser;
    if ($domain ne $self->{domain}) {
        $diffuser = $self->username;
    }
    elsif ($localpart ne $self->{localpart}) {
        $diffuser = $self->localpart;
    }

    if ($diffuser) {
        unshift @boxes, $diffuser;
        unshift @boxes, 'user';
    }
    else {
        # this user, it's my INBOX!
        unshift @boxes, 'INBOX';
    }

    if ($self->is_deleted) {
        unshift @boxes, 'DELETED';
        push @boxes, sprintf("%08X", $self->is_deleted);
    }

    s/\./\^/g for @boxes;

    return join('.', @boxes);
}

sub extuserfolder {
    my $self = shift;

    die "Not a userfolder" unless ($self->{localpart} and not $self->{is_deleted});
    my @boxes = @{$self->{boxes}||[]};

    return 'INBOX' unless @boxes;

    # XXX - weird INBOX cases

    return join('/', @boxes);
}

sub username {
    my $self = shift;
    return unless $self->{localpart};
    return $self->{domain} ? "$self->{localpart}\@$self->{domain}" : $self->{localpart};
}

sub is_inbox {
    my $self = shift;
    return 0 unless $self->{localpart};
    return 0 if @{$self->boxes};
    return 1;
}

1;
