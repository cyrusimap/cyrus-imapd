#!/usr/bin/perl

package Cassandane::Message;
use strict;
use warnings;
use overload qw("") => \&as_string;

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	headers => [],
	headers_by_name => {},
	body => undef,
    };

    bless $self, $class;

    $self->set_lines(@{$params{lines}})
	if (defined $params{lines});

    return $self;
}

sub _clear()
{
    my ($self) = @_;
    $self->{headers} = [];
    $self->{headers_by_name} = {};
    $self->{body} = undef;
}

sub _canon_name($)
{
    my ($name) = @_;

    my @cc = split(/-/, lc($name));
    map
    {
	$_ = ucfirst($_);
	$_ = 'ID' if m/^Id$/;
    } @cc;
    return join('-', @cc);
}

sub get_headers
{
    my ($self, $name) = @_;
    $name = lc($name);
    return $self->{headers_by_name}->{$name};
}

sub set_headers
{
    my ($self, $name, @values) = @_;

    $name = lc($name);
    map { $_ = "" . $_ } @values;
    $self->{headers_by_name}->{$name} = \@values;
    my @headers = grep { $_->{name} ne $name } @{$self->{headers}};
    foreach my $v (@values)
    {
	push(@headers, { name => $name, value => "" . $v });
    }
    $self->{headers} = \@headers;
}

sub remove_headers
{
    my ($self, $name) = @_;

    $name = lc($name);
    delete $self->{headers_by_name}->{$name};
    my @headers = grep { $_->{name} ne $name } @{$self->{headers}};
    $self->{headers} = \@headers;
}

sub add_header
{
    my ($self, $name, $value) = @_;

    $value = "" . $value;

    $name = lc($name);
    my $values = $self->{headers_by_name}->{$name} || [];
    push(@$values, $value);
    $self->{headers_by_name}->{$name} = $values;

    push(@{$self->{headers}}, { name => $name, value => $value });
}

sub set_body
{
    my ($self, $text) = @_;
    $self->{body} = $text;
}

sub get_body
{
    my ($self) = @_;
    return $self->{body};
}

sub as_string
{
    my ($self) = @_;
    my $s = '';

    foreach my $h (@{$self->{headers}})
    {
	$s .= _canon_name($h->{name}) . ": " . $h->{value} . "\r\n";
    }
    $s .= "\r\n";
    $s .= $self->{body}
	if defined $self->{body};

    return $s;
}

sub set_lines
{
    my ($self, @lines) = @_;
    my $pending = '';

#     print STDERR "Message::set_lines\n";
    $self->_clear();

    # First parse the headers
    while (scalar @lines)
    {
	my $line = shift @lines;
	# remove trailing end of line chars
	$line =~ s/[\r\n]*$//;

# 	printf STDERR "    raw line \"%s\"\n", $line;

	if ($line =~ m/^\s/)
	{
	    # continuation line -- collapse FWS and gather the line
	    $line =~ s/^\s*/ /;
	    $pending .= $line;
# 	    printf STDERR "    gathering continuation line\n";
	    next;
	}
#  	printf STDERR "    pending \"%s\"\n", $pending;

	# Not a continuation line; handle the previous pending line
	if ($pending ne '')
	{
# 	    printf STDERR "    finished joined line \"%s\"\n", $pending;
	    my ($name, $value) = ($pending =~ m/^([A-Za-z0-9-]+):\s*(.*)$/);

	    die "Malformed RFC822 header at or near \"$pending\""
		unless defined $value;

# 	    printf STDERR "    saving header %s=%s\n", $name, $value;
	    $self->add_header($name, $value);
	}

	last if ($line eq '');
	$pending = $line;
    }
#     printf STDERR "    finished with headers, next line is \"%s\"\n", $lines[0];

    # Now collect the body...assuming any remains.
    if (scalar @lines)
    {
	$self->set_body(join('', map { s/[\r\n]*$//; "$_\r\n"; } @lines));
    }
}

1;
