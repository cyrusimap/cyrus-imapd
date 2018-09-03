#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Message;
use strict;
use warnings;
use base qw(Clone Exporter);
use overload qw("") => \&as_string;

use lib '.';
use Cassandane::Util::Log;
use Cassandane::Util::DateTime qw(to_rfc3501);
use Cassandane::Util::SHA;

use Math::Int64;

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

sub _canon_value
{
    my ($value) = @_;

    # Lines in RFC2822 are separated by CR+LF.  Lone CR or LF
    # is not legal, so we replace them with CR+LF.
    # Header field continuation lines (the 2nd or subsequent line)
    # are marked with a leading linear whitespace, so we insert a TAB
    # character if the input didn't have any.
    my $res = "";
    foreach my $l (split(/[\r\n]+/, $value))
    {
        $res .= ($res ne "" && !($l =~ m/^[ \t]/) ? "\t" : "");
        $res .= $l;
        $res .= "\r\n";
    }
    $res .= "\r\n" if ($res eq "");
    return $res;
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

    # XXX This should probably be unshift rather than push, so that headers
    # added chronologically later appear at the top rather than the bottom of
    # the resulting header block.  But changing it also requires changing a
    # bunch of tests' expected results, so that's a project for another time.
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

    foreach my $entry (keys %$fetchitem)
    {
        $ea->{entry} = $entry;
        my $av = $fetchitem->{$entry};
        foreach my $attrib (keys %$av)
        {
            $ea->{attrib} = $attrib;
            $self->set_annotation($ea, $av->{$attrib});
        }
    }
}

sub as_string
{
    my ($self) = @_;
    my $s = '';

    foreach my $h (@{$self->{headers}})
    {
        $s .= _canon_name($h->{name}) . ": " .  _canon_value($h->{value});
    }
    $s .= "\r\n";
    $s .= $self->{body}
        if defined $self->{body};

    return $s;
}

sub set_lines
{
    my ($self, @lines) = @_;
    my @pending;

#     xlog "set_lines";
    $self->_clear();

    # First parse the headers
    while (scalar @lines)
    {
        my $line = shift @lines;
        # remove trailing end of line chars
        $line =~ s/[\r\n]*$//;

#       xlog "    raw line \"$line\"";

        if ($line =~ m/^\s/)
        {
            # continuation line -- gather the line
            push(@pending, $line);
#           xlog "    gathering continuation line";
            next;
        }
#       xlog "    pending \"" . join("CRLF", @pending) . "\"";

        # Not a continuation line; handle the previous pending line
        if (@pending)
        {
#           xlog "    finished joined line \"$pending\"";
            my $first = shift @pending;
            my ($name, $value) = ($first =~ m/^([!-9;-~]+):(.*)$/);

            die "Malformed RFC822 header at or near \"$first\""
                unless defined $value;

            $value = join("\r\n", ($value, @pending));

            # Lose a single SP after the : which we will be putting
            # back when we canonicalise on output.  This is technically
            # wrong but does make for prettier output *and* circular
            # consistency with most messages in the wild.
            $value =~ s/^ //;

#           xlog "    saving header $name=$value";
            $self->add_header($name, $value);
        }

        last if ($line eq '');
        @pending = ( $line );
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
        $id = to_rfc3501($id);
    }
    $self->set_attribute(internaldate => $id);
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

    my $sha1 = sha1($self->as_string());
    my $cid = Math::Int64::uint64(0);
    for (0..7) {
        $cid <<= 8;
        $cid |= ord(substr($sha1, $_, 1));
    }
    $cid ^= Math::Int64::string_to_uint64("0x91f3d9e10b690b12", 16); # chosen by fair dice roll
    my $res = lc Math::Int64::uint64_to_string($cid, 16);
    return sprintf("%016s", $res);
}

# Handy accessors

sub uid { return shift->get_attribute('uid'); }
sub cid { return shift->get_attribute('cid'); }
sub guid { return shift->get_guid(); }
sub from { return shift->get_header('from'); }
sub to { return shift->get_header('to'); }
sub subject { return shift->get_header('subject'); }
sub messageid { return shift->get_header('message-id'); }
sub date { return shift->get_header('date'); }
sub size { return length(shift->as_string); }

# Utility functions

# Given a subject string, return the "base subject"
# as defined by RFC5256.  Used for SORT & THREAD.
sub base_subject
{
    my ($s) = @_;

    # Lexical $_ is a 5.10ism dammit
    my $saved_ = $_;
    $_ = $s;

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

    $s = $_;
    $_ = $saved_;
    return $s;
}

1;
