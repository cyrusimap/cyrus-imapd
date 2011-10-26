#!/usr/bin/perl -cw
#
# Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use warnings;
use strict;

package Cyrus::Annotator::Message;

use MIME::Base64 qw(decode_base64);
use MIME::QuotedPrint qw(decode_qp);
use Encode qw(decode);

our $VERSION = '1.00';

=head1 NAME

Cyrus::Annotator::Message - representation of a message to annotate

=head1 SYNOPSIS

  use warnings;
  use strict;
  package MyAnnotatorDaemon;
  use base Cyrus::Annotator::Daemon;

  sub annotate_message
  {
      my ($message) = @_;

      $message->set_flag('\Flagged');
      $message->set_shared_annotation('/comment', 'Hello!!');
  }

  MyAnnotatorDaemon->run();

=head1 DESCRIPTION

This module encapsulates a message which is being processed by the
annotator daemon.

=head1 METHODS

Cyrus::Annotator::Message has the following methods.

=over 4

=item I<new(%args)>

Takes the following args:

 # required
 * BODYSTRUCTURE => parsed bodystructure

 # optional (but you need to provide SOMETHING if your code uses any
 # of the accessors)
 * GUID => 40 character sha1
 * HEADER => Mail::Header object with headers pre-parsed
 * FILENAME => path to rfc822 file

 # totally optional (will be considered empty if not set)
 * FLAGS => array of already set flags
 * ANNOTATAIONS => array of already set annotations

=cut

sub new {
    my $class = shift;
    my %args = @_;

    my %flags;
    my %annots;

    my $fs = $args{FLAGS} || [];
    my $as = $args{ANNOTATAIONS} || [];

    for my $name (@$fs) {
	$flags{$name} = {
	    value => 1,
	    orig => 1,
	};
    }

    for my $obj (@$as) {
	my ($entry, $type, $value) = @$obj;
	$annots{$entry}{$type} = {
	    value => $value,
	    orig => $value,
	};
    }

    my $self = bless {
	filename => $args{FILENAME},
	bodystructure => $args{BODYSTRUCTURE},
	guid => $args{GUID},
	header => $args{HEADER},
	flag => \%flags,
	annot => \%annots,
    }, ref($class) || $class;
}


=item I<fh()>

returns a read-only filehandle to the raw (rfc822) representation
of the full message.

=cut

sub fh {
    my $self = shift;

    unless ($self->{fh}) {
	die "Need a filename" unless $self->{filename};
	require "IO/File.pm";
	$self->{fh} = IO::File->new($self->{filename}, 'r');
    }

    # Move back to start of message
    seek $self->{fh}, 0, 0;

    return $self->{fh};
}

=item I<decode_part($Part, $Content)>

Given some content, decode it from the part's content
encoding and charset.

=cut

sub decode_part {
    my $self = shift;
    my ($Part, $Content) = @_;

    if (lc $Part->{'Content-Transfer-Encoding'} eq 'base64') {
	# remove trailing partial value
	$Content =~ tr{[A-Za-z0-9+/=]}{}cd;
	my $extra = length($Content) % 4;
	if ($extra) {
	    warn "stripping $extra chars " . length($Content);
	    $Content = substr($Content, 0, -$extra);
	}
	$Content = decode_base64($Content);
    }
    elsif (lc $Part->{'Content-Transfer-Encoding'} eq 'quoted-printable') {
	# remove trailing partial value
	$Content =~ s/=.?$//;
	$Content = decode_qp($Content);
    }

    my $charset = $Part->{'Content-Type'}{charset} || 'iso-8859-1';

    return eval { decode($charset, $Content) } || decode('iso-8859-1', $Content);
}

=item I<read_part_content($Part, $nbytes)>

returns the first n bytes of the bodypart passed.  This is a section of the
bodystructure (hashref).  If no part is passed, it's the raw message.

If no 'nbytes' is passed, read the entire part.

=cut

sub read_part_content {
    my $self = shift;
    my ($Part, $nbytes) = @_;

    unless ($Part) {
	$Part = $self->bodystructure();
    }

    my $fh = $self->fh();

    die "No Offset for part"
	unless defined $Part->{Offset};
    die "No Size for part"
	unless defined $Part->{Size};

    unless (defined $nbytes and $nbytes > $Part->{Size}) {
	$nbytes = $Part->{Size};
    }

    seek $fh, $Part->{Offset}, 0
	or die "Cannot seek: $!";

    my $Content = '';
    read $fh, $Content, $nbytes
	or die "Cannot read: $!";

    return $self->decode_part($Part, $Content);
}

=item I<header()>

returns a Mail::Header object containing all the headers of the message.

=cut

sub header {
    my $self = shift;

    unless ($self->{header}) {
	require "Mail/Header.pm";
	$self->{header} = Mail::Header->new($self->fh());
    }

    return $self->{header};
}

=item I<bodystructure()>

returns a structure 

is a structure closely based on the IMAP BODYSTRUCTURE, decoded into a
hash, including recursively all MIME sections.  In general, the
following items are defined for all body structures:

=over 4

=item * MIME-Type

=item * MIME-Subtype

=item * Content-Type

=item * Content-Description

=item * Content-Dispositon

=item * Content-Language

=back

Body structures which have a MIME-Type of 'multipart' contain the
following items:

=over 4

=item * MIME-Subparts

=back

For body structures B<except> those that have a MIME-Type of
'multipart', the following are defined:

=over 4

=item * Content-ID

=item * Content-Description

=item * Content-Transfer-Encoding

=item * Content-MD5

=item * Size

=item * Lines

=item * Offset

=item * HeaderSize

=back

=item I<guid()>

returns the hex encoded (40 character) sha1 of the rfc822 representation.

=item I<has_flag($name)>

=item I<set_flag($name)>

=item I<clear_flag($name)>

Check for the boolean value of a flag with $name, set the flag and remove
the flag respectively.

Note that changes are not immediate.  They will be applied by the annotator
at the end.

For example:

  $message->set_flag("\\Flagged");

=cut

sub bodystructure {
   my $self = shift;
   return $self->{bodystructure};
}


sub get_flag {
    my $self = shift;
    my ($name) = @_;

    return $self->{flag}{$name}{value};
}

sub set_flag_value {
    my $self = shift;
    my ($name, $value) = @_;
    $self->{flag}{$name}{orig} = 0
	unless exists $self->{flag}{$name}{orig};
    $self->{flag}{$name}{value} = $value;
}

sub set_flag {
    my $self = shift;
    my ($name) = @_;
    $self->set_flag_value($name, 1);
}

sub clear_flag {
    my $self = shift;
    my ($name) = @_;
    $self->set_flag_value($name, 0);
}

=item I<get_shared_annotation($entry)>

=item I<get_private_annotation($entry)>

=item I<set_shared_annotation($entry, $value)>

=item I<set_private_annotation($entry, $value)>

=item I<clear_shared_annotation($entry)>

=item I<clear_private_annotation($entry)>

Get, set and clear the value of an annotation, either shared or private.  The
"get" accessors return a string with the value.  Clear is the same as set
with $value of the empty string ('').

For example:

  $message->set_shared_annotation('/comment', 'Hello World');

=cut

sub get_annotation {
    my $self = shift;
    my ($entry, $type) = @_;

    return $self->{annot}{$entry}{$type}{value};
}

sub set_annotation {
    my $self = shift;
    my ($entry, $type, $value) = @_;
    $value = '' unless defined $value;
    $self->{annot}{$entry}{$type}{orig} = ''
	unless exists $self->{annot}{$entry}{$type}{orig};
    $self->{annot}{$entry}{$type}{value} = $value;
}

sub get_shared_annotation {
    my $self = shift;
    my ($entry) = @_;
    return $self->get_annotation($entry, 'value.shared');
}

sub set_shared_annotation {
    my $self = shift;
    my ($entry, $value) = @_;
    return $self->set_annotation($entry, 'value.shared', $value);
}

sub clear_shared_annotation {
    my $self = shift;
    my ($entry) = @_;
    return $self->set_annotation($entry, 'value.shared', '');
}

sub get_private_annotation {
    my $self = shift;
    my ($entry) = @_;
    return $self->get_annotation($entry, 'value.private');
}

sub set_private_annotation {
    my $self = shift;
    my ($entry, $value) = @_;
    return $self->set_annotation($entry, 'value.private', $value);
}

sub clear_private_annotation {
    my $self = shift;
    my ($entry) = @_;
    return $self->set_annotation($entry, 'value.private', '');
}

=item I<get_changed()>

returns two arrayrefs - [['flagname', 'bool']] and [['entry', 'type', 'value']], e.g.

[["\\Flagged", 1]], [['/comment', 'value.shared', 'Hello World']]

=cut

sub get_changed {
    my $self = shift;
    my @flags;
    my @annots;

    foreach my $name (sort keys %{$self->{flag}}) {
	my $item = $self->{flag}{$name};
	push @flags, [$name, $item->{value}]
	    unless $item->{value} == $item->{orig};
    }

    foreach my $entry (sort keys %{$self->{annot}}) {
	foreach my $type (sort keys %{$self->{annot}{$entry}}) {
	    my $item = $self->{annot}{$entry}{$type};
	    push @annots, [$entry, $type, $item->{value}]
		unless $item->{value} eq $item->{orig};
	}
    }

    return (\@flags, \@annots);
}

=back

=head1 SEE ALSO

I<RFC3501>, I<RFC5257>.

=head1 AUTHOR

Greg Banks E<lt>gnb@fastmail.fmE<gt>.
Bron Gondwana E<lt>brong@fastmail.fmE<gt>.

=cut

1;
