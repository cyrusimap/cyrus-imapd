# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;

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
 * ANNOTATIONS => array of already set annotations

=cut

sub new {
    my $class = shift;
    my %args = @_;

    my %flags;
    my %annots;

    my $fs = $args{FLAGS} || [];
    my $as = $args{ANNOTATIONS} || [];

    for my $name (@$fs) {
        $flags{$name} = {
            value => 1,
            orig => 1,
        };
    }

    while (my $entry = shift @$as) {
        my $rest = shift @$as;
        my ($type, $value) = @$rest;
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
            # warn "stripping $extra chars " . length($Content);
            $Content = substr($Content, 0, -$extra);
        }
        $Content = decode_base64($Content);
    }
    elsif (lc $Part->{'Content-Transfer-Encoding'} eq 'quoted-printable') {
        # remove trailing partial value
        $Content =~ s/=.?$//;
        $Content = decode_qp($Content);
    }

    my $charset = lc($Part->{'Content-Type'}{charset} || 'iso-8859-1');

    # If no charset is present, it defaults to ascii. But some systems
    #  send 8-bit data. For them, assume iso-8859-1, ascii is a subset anyway
    $charset = 'iso-8859-1'
        if $charset eq 'ascii' || $charset eq 'us-ascii';

    # Fix up some bogus formatted iso charsets
    $charset =~ s/^(iso)[\-_]?(\d+)[\-_](\d+)[\-_]?\w*/$1-$2-$3/i;

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

    if (!defined($nbytes) || $Part->{Size} < $nbytes) {
        $nbytes = $Part->{Size};
    }

    seek $fh, $Part->{Offset}, 0
        or die "Cannot seek: $!";

    my $Content = '';

    # Could be 0 length body, only die on undef (real error)
    my $r = read($fh, $Content, $nbytes);
    die "Cannot read: $!" if !defined $r;

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

=item * Content-Disposition

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

sub get_flags {
    my $self = shift;
    return grep { $self->{flag}{$_}{value} } keys %{$self->{flag}};
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
                unless is_eq($item->{value}, $item->{orig});
        }
    }

    return (\@flags, \@annots);
}

sub is_eq {
    my ($l, $r) = @_;
    if (defined $l && defined $r) {
        return $l eq $r;
    }
    else {
        return !defined $l && !defined $r;
    }
}

=back

=head1 SEE ALSO

I<RFC3501>, I<RFC5257>.

=head1 AUTHOR

Greg Banks E<lt>gnb@fastmail.fmE<gt>.
Bron Gondwana E<lt>brong@fastmail.fmE<gt>.

=cut

1;
