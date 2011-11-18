#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Message;
use strict;
use warnings;
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(from_rfc3501);
use Digest::SHA1 qw(sha1_hex);
use base qw(Clone Exporter);
use overload qw("") => \&as_string;

our @EXPORT = qw(base_subject);

sub new
{
    my $class = shift;
    my %params = @_;
    my $self = {
	headers => [],
	headers_by_name => {},
	body => undef,
	# Other message attributes - e.g. IMAP uid & internaldate
	attrs => {},
    };

    bless $self, $class;

    $self->set_lines(@{$params{lines}})
	if (defined $params{lines});
    $self->set_raw($params{raw})
	if (defined $params{raw});
    $self->set_fh($params{fh})
	if (defined $params{fh});
    # do these one by one to normalise the incoming keys
    # and any other logic that set_attribute() wants to do.
    if (defined $params{attrs})
    {
	while (my ($n, $v) = each %{$params{attrs}})
	{
	    if (lc($n) eq 'annotation')
	    {
		$self->_set_annotations_from_fetch($v);
		next;
	    }
	    $self->set_attribute($n, $v);
	}
    }

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

    my @cc = split(/([^[:alnum:]])+/, lc($name));
    map
    {
	$_ = ucfirst($_);
	$_ = 'ID' if m/^Id$/;
    } @cc;
    return join('', @cc);
}

sub get_headers
{
    my ($self, $name) = @_;
    $name = lc($name);
    return $self->{headers_by_name}->{$name};
}

sub get_header
{
    my ($self, $name) = @_;
    $name = lc($name);
    my $values = $self->{headers_by_name}->{$name};
    return undef
	unless defined $values;
    die "Too many values for header \"$name\""
	unless (scalar @$values == 1);
    return $values->[0];
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

sub set_attribute
{
    my ($self, $name, $value) = @_;
    $self->{attrs}->{lc($name)} = $value;
}

sub set_attributes
{
    my ($self, @args) = @_;

    while (my $name = shift @args)
    {
	my $value = shift @args;
	$self->set_attribute($name, $value);
    }
}

sub has_attribute
{
    my ($self, $name) = @_;
    return exists $self->{attrs}->{lc($name)};
}

sub get_attribute
{
    my ($self, $name) = @_;
    return $self->{attrs}->{lc($name)};
}

sub _annotation_key
{
    my ($self, $ea) = @_;
    return "annotation $ea->{entry} $ea->{attrib}";
}

sub _validate_ea
{
    my ($self, $ea) = @_;

    die "Bad entry \"$ea->{entry}\""
	unless $ea->{entry} =~ m/^(\/[a-z0-9.]+)*$/i;
    die "Bad attrib \"$ea->{attrib}\""
	unless $ea->{attrib} =~ m/^value.(shared|priv)$/i;
}

sub has_annotation
{
    my $self = shift;
    my $ea = shift;
    if (ref $ea ne 'HASH')
    {
	$ea = { entry => $ea, attrib => shift };
    }

    $self->_validate_ea($ea);
    return $self->has_attribute($self->_annotation_key($ea));
}

sub get_annotation
{
    my $self = shift;
    my $ea = shift;
    if (ref $ea ne 'HASH')
    {
	$ea = { entry => $ea, attrib => shift };
    }

    $self->_validate_ea($ea);
    return $self->get_attribute($self->_annotation_key($ea));
}

sub list_annotations
{
    my ($self) = @_;
    my @res;

    foreach my $key (keys %{$self->{attrs}})
    {
	my ($dummy, $entry, $attrib) = split / /,$key;
	next unless defined $attrib && $dummy eq 'annotation';
	push (@res, { entry => $entry, attrib => $attrib });
    }
    return @res;
}

sub set_annotation
{
    my $self = shift;
    my $ea = shift;
    if (ref $ea ne 'HASH')
    {
	$ea = { entry => $ea, attrib => shift };
    }
    my $value = shift;

    $self->_validate_ea($ea);
    $self->set_attribute($self->_annotation_key($ea), $value);
}

sub _set_annotations_from_fetch
{
    my ($self, $fetchitem) = @_;
    my $ea = {};

    while ($ea->{entry} = shift @$fetchitem)
    {
	my $attvalues = shift @$fetchitem;
	die "Bad array in annotation data"
	    unless ref($attvalues) eq 'ARRAY';
	die "Bad array in annotation data (2)"
	    unless (scalar(@$attvalues) % 2 == 0);

	while ($ea->{attrib} = shift @$attvalues)
	{
	    my $value = shift @$attvalues;
	    $self->set_annotation($ea, $value);
	}
    }
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

#     xlog "set_lines";
    $self->_clear();

    # First parse the headers
    while (scalar @lines)
    {
	my $line = shift @lines;
	# remove trailing end of line chars
	$line =~ s/[\r\n]*$//;

# 	xlog "    raw line \"$line\"";

	if ($line =~ m/^\s/)
	{
	    # continuation line -- collapse FWS and gather the line
	    $line =~ s/^\s*/ /;
	    $pending .= $line;
# 	    xlog "    gathering continuation line";
	    next;
	}
#  	xlog "    pending \"$pending\"";

	# Not a continuation line; handle the previous pending line
	if ($pending ne '')
	{
# 	    xlog "    finished joined line \"$pending\"";
	    my ($name, $value) = ($pending =~ m/^([!-9;-~]+):\s*(.*)$/);

	    die "Malformed RFC822 header at or near \"$pending\""
		unless defined $value;

# 	    xlog "    saving header $name=$value";
	    $self->add_header($name, $value);
	}

	last if ($line eq '');
	$pending = $line;
    }
#     xlog "    finished with headers, next line is \"" . $lines[0] . "\"";

    # Now collect the body...assuming any remains.
    my $body = '';
    foreach my $line (@lines)
    {
	$line =~ s/[\r\n]*$//;
	$body .= $line . "\r\n";
    }
    $self->set_body($body);
}

sub set_fh
{
    my ($self, $fh) = @_;
    my @lines;
    while (<$fh>)
    {
	push(@lines, $_);
    }
    $self->set_lines(@lines);
}

sub set_raw
{
    my ($self, $raw) = @_;
    my $fh;
    open $fh,'<',\$raw
	or die "Cannot open in-memory file for reading: $!";
    $self->set_fh($fh);
    close $fh;
}


sub set_internaldate
{
    my ($self, $id) = @_;

    if (ref $id eq 'DateTime')
    {
	$self->{internaldate} = $id;
    }
    else
    {
	$self->{internaldate} = from_rfc3501($id);
    }
}

# Calculate and return the GUID of the message
sub get_guid
{
    my ($self) = @_;

    return sha1_hex($self->as_string());
}

# Calculate a CID from a message - this is the CID that the
# first message in a new conversation will be assigned.
sub make_cid
{
    my ($self) = @_;

    return substr(sha1_hex($self->as_string()), 0, 16);
}

# Handy accessors

sub uid { return shift->get_attribute('uid'); }
sub cid { return shift->get_attribute('cid'); }
sub guid { return shift->get_guid(); }
sub from { return shift->get_header('from'); }
sub to { return shift->get_header('to'); }
sub subject { return shift->get_header('subject'); }
sub size { return length(shift->as_string); }

# Utility functions

# Given a subject string, return the "base subject"
# as defined by RFC5256.  Used for SORT & THREAD.
sub base_subject
{
    my ($_) = @_;

    # (1) [ ignoring the RFC2047 decoding ]
    # Convert all tabs and continuations to space.
    # Convert all multiple spaces to a single space.
    s/\s+/ /g;

    # (2) Remove all trailing text of the subject that
    # matches the subj-trailer ABNF; repeat until no
    # more matches are possible.
    while (s/(\s|\(fwd\))$//i) { }

    for (;;)
    {
	# (3) Remove all prefix text of the subject that
	# matches the subj-leader ABNF.
	my $n = 0;
	while (s/^\s+// ||
	       s/^\[[^][]*\]\s*// ||
	       s/^re\s*(\[[^][]*\])?://i ||
	       s/^fw\s*(\[[^][]*\])?://i ||
	       s/^fwd\s*(\[[^][]*\])?://i)
	{
	    $n++;
	}
	last if !$n;

	# (4) If there is prefix text of the subject that
	# matches the subj-blob ABNF, and removing that
	# prefix leaves a non-empty subj-base, then remove
	# the prefix text.
	my ($prefix, $base) = m/^\[[^][]*\]\s*(.*)$/;
	last if !defined $prefix;
	$_ = $base if ($base ne '');
    }
    # (5) Repeat (3) and (4) until no matches remain.

    return $_;
}

1;
