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
package Cyrus::Annotator::Daemon;
use base qw(Net::Server);
# use Data::Dumper;
use Unix::Syslog qw(:macros);
use Cyrus::Annotator::Message;
use File::Path;
use Encode qw(decode);

our $VERSION = '1.00';

# XXX we should honor the cyrus_user setting
use constant USER  => 'cyrus';
use constant GROUP => 'mail';

use constant RUNPREFIX  => '/var/run/annotatord';
use constant APPNAME => 'annotatord';
use constant PIDFILE => RUNPREFIX . '.pid';
use constant SOCKPATH => RUNPREFIX . '.socket';

# Levels are: LOG_DEBUG (7), LOG_INFO (6), *LOG_NOTICE (5), LOG_WARNING (4), LOG_ERR (3)
use constant LOG_LEVEL => LOG_INFO;

=head1 NAME

Cyrus::Annotator::Daemon - framework for writing annotator daemons for Cyrus

=head1 SYNOPSIS

  use warnings;
  use strict;
  package MyAnnotatorDaemon;
  use Cyrus::Annotator::Daemon;
  our @ISA = qw(Cyrus::Annotator::Daemon);

  sub annotate_message
  {
      my ($self, $message) = @_;

      $message->set_flag('\Flagged');
      $message->set_shared_annotation('/comment', 'Hello!!');
  }

  MyAnnotatorDaemon->run();

=head1 DESCRIPTION

This module provides a framework for writing daemons which can be used
to add annotations or flags to messages which are delivered into the
Cyrus mail server.

To use Cyrus::Annotator::Daemon, write a Perl script which creates an
object derived from it; see the Synopsis above.  Run this script as
root, and it will daemonize itself.  Then add this line to the
imapd.conf file

  annotation_callout: /var/run/annotatord.socket

and restart Cyrus.

=head1 METHODS

Cyrus::Annotator::Daemon has the following methods.

=over 4
=cut

my @default_args = (
    personality => 'Net::Server',
    appname => APPNAME,

    user => USER,
    group => GROUP,
    pid_file => PIDFILE,
    background => 1,
    size_limit => 256,

    syslog_level => LOG_LEVEL,
    syslog_facility => LOG_LOCAL6,
    syslog_ident => APPNAME,
    log_file => 'Sys::Syslog',

    proto => 'unix',
    port => SOCKPATH . '|SOCK_STREAM|unix'
);

sub new
{
    my ($class, @args) = @_;
    my $self = $class->SUPER::new(@args);

    return $self;
}

=item I<run(...options...)>

This class method can be used to create an instance of
Cyrus::Annotator::Daemon and to run it's main loop.  Note that
Cyrus::Annotator::Daemon derives from Net::Server, and any of that
module's options can be used.

For example:

  MyAnnotatorDaemon->run(personality => 'Fork');

Cyrus::Annotator::Daemon changes some of the Net::Server defaults,
including:

=over 4

=item * Logging is to syslog using facility I<local6>.

=item * The network socket is a I<SOCK_STREAM> UNIX domain
socket bound to I</var/run/annotatord.socket>.

=item * A PID file is written to I</var/run/annotatord.pid>.

=item * The daemon runs in the background, as user I<cyrus> and group I<mail>.

=back

=cut

sub run
{
    my ($class, @args) = @_;
    my %aa = (@default_args, @args);
    return $class->SUPER::run(%aa);
}


# Can pass a file handle or string
# Returns two item list of ($ParsedData, $Remainder)
# All lines must be \r\n terminated

sub _dlist_parse {
  my $Input = shift;
  my ($Atom, $CurAtom, $Line, @AtomStack) = (undef, undef);
  my $AtomRef = \$Atom;

  if (ref($Input)) {
    $Line = <$Input> || die "No input data: $!";
  } else {
    $Line = $Input;
  }

  # While this is a recursive structure, doing some profiling showed
  #  that this call was taking up quite a bit of time in the application
  #  I was using this module with. Thus I've tried to optimise the code
  #  a bit by turning it into a loop with an explicit stack and keeping
  #  the most common cases quick.

  # Always do this once, and keep doing it while we're within
  #   a bracketed list of items
  do {

    # Single item? (and any trailing space)
    if ($Line =~ m/\G([^()\"{}\s]+)(?: |\z|(?=\)))/gc) {
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $1 eq 'NIL' ? undef : $1;
      } else {
        $$AtomRef = $1 eq 'NIL' ? undef : $1;
      }
    }

    # Quoted section? (but non \" end quote and any trailing space)
    elsif ($Line =~ m/\G"((?:\\.|[^"])*?)"(?: |\z|(?=\)))/gc) {
      # Unquote quoted items
      ($CurAtom = $1) =~ s/\\(.)/$1/g;
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $CurAtom;
      } else {
        $$AtomRef = $CurAtom;
      }
    }

    # Bracket?
    elsif ($Line =~ m/\G\(/gc) {
      # Begin a new sub-array
      my $CurAtom = [];
      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $CurAtom;
      } else {
        $$AtomRef = $CurAtom;
      }

      # Check for simple response list to fast parse
      if ($Line =~ m/\G([^()\"{}~\s]+(?: [^()\"{}~\s]+)*)\) ?/gc) {
        push @$CurAtom, map { $_ eq 'NIL' ? undef : $_ } split(' ', $1);

      } else {
        # Add current ref to stack and update
        push @AtomStack, $AtomRef;
        $AtomRef = $CurAtom;
      }

    }

    # End bracket? (and possible trailing space)
    elsif ($Line =~ m/\G\) ?/gc) {
      # Close existing sub-array
      if (!scalar @AtomStack) {
        die "Unexpected close bracket in IMAP response : '$Line'";
      }
      $AtomRef = pop @AtomStack;
    }

    # Literal or binary literal? (Must end line)
    elsif ($Line =~ m/\G~?\{(\d+)\}\r\n/gc) {
      my $Bytes = $1;
      $CurAtom = undef;

      # Literal is next $Bytes of data, and possible space
      if (ref($Input)) {
        read($Input, $CurAtom, $Bytes) || die "No input data";
        $Line = <$Input>;
      } else {
        $CurAtom = substr($Line, pos($Line), $Bytes);
        pos($Line) += length($CurAtom);
      }
      $Line =~ m/\G ?/gc;

      # Add to current atom. If there's a stack, must be within a bracket
      if (scalar @AtomStack) {
        push @$AtomRef, $CurAtom;
      } else {
        $$AtomRef = $CurAtom;
      }
    }

    # End of line?
    elsif ($Line =~ m/\G(?:\r\n)?$/gc) {
      # Should not be within brackets
      if (scalar @AtomStack) {
        die "Unexpected end of line in IMAP response : '$Line'";
      }
      # Otherwise fine, we're about to exit anyway
    }

    else {
      die "Error parsing atom in IMAP response : '" . substr($Line, pos($Line), 100) . "'";
    }

  # Repeat while we're within brackets
  } while (scalar @AtomStack);

  my $Remainder = substr($Line, pos($Line));

  return ($Atom, $Remainder);
}

sub _parse_list_to_hash {
  my $ContentHashList = shift || [];
  my $Recursive = shift;

  ref($ContentHashList) eq 'ARRAY' || return { };

  my %Res;
  while (@$ContentHashList) {
    my ($Param, $Val) = (shift @$ContentHashList, shift @$ContentHashList);

    $Val = _parse_list_to_hash($Val, $Recursive-1)
      if (ref($Val) && $Recursive);

    $Res{lc($Param)} = $Val;
  }

  return \%Res;
}

sub _parse_bodystructure {
  my ($Bs, $IncludeRaw, $DecodeUTF8, $PartNum, $IsMultipart) = @_;
  my %Res;

  # If the first item is a reference, then it's a MIME multipart structure
  if (ref($Bs->[0])) {

    # Multipart items are of the form: [ part 1 ] [ part 2 ] ...
    #  "MIME-Subtype" "Content-Type" "Content-Disposition" "Content-Language"

    # Process each mime sub-part recursively
    my ($Part, @SubParts);
    for ($Part = 1; ref($Bs->[0]); $Part++) {
      my $SubPartNum = ($PartNum ? $PartNum . "." : "") . $Part;
      my $Res = _parse_bodystructure(shift(@$Bs), $IncludeRaw, $DecodeUTF8, $SubPartNum, 1);
      push @SubParts, $Res;
    }

    # Setup multi-part hash
    %Res = (
      'MIME-Subparts',       \@SubParts,
      'MIME-Type',           'multipart',
      'MIME-Subtype',        lc(shift(@$Bs)),
      'Content-Type',        _parse_list_to_hash(shift(@$Bs)),
      'Content-Disposition', _parse_list_to_hash(shift(@$Bs), 1),
      'Content-Language',    shift(@$Bs),
      'Content-Location',    shift(@$Bs),
      # Shouldn't be anything after this. Add as remainder if there is
      'Remainder',           $Bs
    );
  }

  # Otherwise it's a normal MIME entity
  else {

    # Get the mime type and sub-type
    my ($MimeType, $MimeSubtype) = (lc(shift(@$Bs)), lc(shift(@$Bs)));

    # Partnum for getting the text part of an entity. Do this
    #  here so recursive call works for any embedded messages
    $PartNum = $PartNum ? $PartNum . '.1' : '1'
      if !$IsMultipart;

    # Pull out special fields for 'text' or 'message/rfc822' types
    if ($MimeType eq 'text') {
      %Res = (
        'Lines',   splice(@$Bs, 5, 1)
      );
    } elsif ($MimeType eq 'message' && $MimeSubtype eq 'rfc822') {

      # message/rfc822 includes the messages envelope and bodystructure
      my @MsgParts = splice(@$Bs, 5, 3);
      %Res = (
        'Message-Envelope',       _parse_envelope(shift(@MsgParts), $IncludeRaw, $DecodeUTF8),
        'Message-Bodystructure',  _parse_bodystructure(shift(@MsgParts), $IncludeRaw, $DecodeUTF8, $PartNum),
        'Message-Lines',          shift(@MsgParts)
      );
    }

    # All normal mime-entities have these parts
    %Res = (
      %Res,
      'MIME-Type',                  $MimeType,
      'MIME-Subtype',               $MimeSubtype,
      'Content-Type',               _parse_list_to_hash(shift(@$Bs)),
      'Content-ID',                 shift(@$Bs),
      'Content-Description',        shift(@$Bs),
      'Content-Transfer-Encoding',  shift(@$Bs),
      'Size',                       shift(@$Bs),
      'Content-MD5',                shift(@$Bs),
      'Content-Disposition',        _parse_list_to_hash(shift(@$Bs), 1),
      'Content-Language',           shift(@$Bs),
      'Content-Location',           shift(@$Bs),
      # Shouldn't be anything after this. Add as remainder if there is
      'Remainder',                  $Bs
    );

    # Extra information for the annotation callout - gnb 20110420
    my $Extra = shift(@$Bs);
    if ($Extra) {
      $Extra = _parse_list_to_hash($Extra, 0);
      # Make casing consistent for users
      $Res{Offset} = $Extra->{offset};
      $Res{HeaderSize} = $Extra->{headersize};
    }

  }

  # Finally set the IMAP body part number and overall mime type
  $Res{'IMAP-Partnum'} = $PartNum || '';
  $Res{'MIME-TxtType'} = $Res{'MIME-Type'} . '/' . $Res{'MIME-Subtype'};

  return \%Res;
}

# Regexps used to determine if header is MIME encoded (we remove . from
#  especials because of dumb ANSI_X3.4-1968 encoding)
my $RFC2047Token = qr/[^\x00-\x1f\(\)\<\>\@\,\;\:\"\/\[\]\?\=\ ]+/;
my $NeedDecodeUTF8Regexp = qr/=\?$RFC2047Token\?$RFC2047Token\?[^\?]*\?=/;

sub _parse_envelope {
  my ($Env, $IncludeRaw, $DecodeUTF8) = @_;

  # Check envelope assumption
  scalar(@$Env) == 10
    || die "IMAPTalk: Wrong number of fields in envelope structure " . Dumper($Env);

  _decode_utf8($Env->[1]) if $DecodeUTF8 && defined($Env->[1]) && $Env->[1] =~ $NeedDecodeUTF8Regexp;

  # Setup hash directly from envelope structure
  my %Res = (
    'Date',        $Env->[0],
    'Subject',     $Env->[1],
    'From',        _parse_email_address($Env->[2], $DecodeUTF8),
    'Sender',      _parse_email_address($Env->[3], $DecodeUTF8),
    'Reply-To',    _parse_email_address($Env->[4], $DecodeUTF8),
    'To',          _parse_email_address($Env->[5], $DecodeUTF8),
    'Cc',          _parse_email_address($Env->[6], $DecodeUTF8),
    'Bcc',         _parse_email_address($Env->[7], $DecodeUTF8),
    ($IncludeRaw ? (
      'From-Raw',    $Env->[2],
      'Sender-Raw',  $Env->[3],
      'Reply-To-Raw',$Env->[4],
      'To-Raw',      $Env->[5],
      'Cc-Raw',      $Env->[6],
      'Bcc-Raw',     $Env->[7],
    ) : ()),
    'In-Reply-To', $Env->[8],
    'Message-ID',  $Env->[9]
  );

  return \%Res;
}

sub _parse_email_address {
  my $EmailAddressList = shift || [];
  my $DecodeUTF8 = shift;

  # Email addresses always come as a list of addresses (possibly in groups)
  my @EmailGroups = ([ undef ]);
  foreach my $Adr (@$EmailAddressList) {

    # Check address assumption
    scalar(@$Adr) == 4
      || die "IMAPTalk: Wrong number of fields in email address structure " . Dumper($Adr);

    # No hostname is start/end of group
    if (!defined $Adr->[0] && !defined $Adr->[3]) {
      push @EmailGroups, [ $Adr->[2] ];
      next;
    }

    # Build 'ename@ecorp.com' part
    my $EmailStr = (defined $Adr->[2] ? $Adr->[2] : '')
                 . '@'
                 . (defined $Adr->[3] ? $Adr->[3] : '');
    # If the email address has a name, add it at the start and put <> around address
    if (defined $Adr->[0] and $Adr->[0] ne '') {
      _decode_utf8($Adr->[0]) if $DecodeUTF8 && $Adr->[0] =~ $NeedDecodeUTF8Regexp;
      # Strip any existing \"'s
      $Adr->[0] =~ s/\"//g;
      $EmailStr = '"' . $Adr->[0] . '" <' . $EmailStr . '>';
    }

    push @{$EmailGroups[-1]}, $EmailStr;
  }

  # Join the results with commas between each address, and "groupname: adrs ;" for groups
  for (@EmailGroups) {
    my $GroupName = shift @$_;
    ($_ = undef), next if !defined $GroupName && !@$_;
    my $EmailAdrs = join ", ", @$_;
    $_ = defined($GroupName) ? $GroupName . ': ' . $EmailAdrs . ';' : $EmailAdrs;
  }

  return join " ", grep { defined $_ } @EmailGroups;
}

sub _decode_utf8 {
  # Fix dumb, dumb ANSI_X3.4-1968 encoding. It's not actually a valid
  #  charset according to RFC2047, "." is an especial, so Encode ignores it
  # See http://en.wikipedia.org/wiki/ASCII for other aliases
  $_[0] =~ s/=\?ANSI_X3\.4-(?:1968|1986)\?/=?US-ASCII?/gi;
  eval { $_[0] = decode('MIME-Header', $_[0]); };
}

sub _read_args
{
    my $Nbytes;
    my $Data = '';

    for (;;) {
        $Nbytes = readline STDIN;
        last unless defined $Nbytes;
        chomp $Nbytes;
        $Nbytes = 0 + $Nbytes;
#       printf "nbytes=%d\n", $nbytes;
        last if (!$Nbytes);
        read STDIN, $Data, $Nbytes, length($Data);
    }

    return $Data;
}

sub _format_string
{
    my ($s) = @_;

    return "NIL" unless defined $s;

    my $len = length($s);

    if ($len > 1024 || $s =~ m/[\\"\012\015\200-\377]/) {
        # don't try to quote this, use a literal
        return "{$len}\r\n$s";
    }
    else {
        return "\"$s\"";
    }
}

sub _emit_results
{
    my ($self, $message) = @_;
    my @results;
    my $sep = '';

    my ($flags, $annots) = $message->get_changed();

    foreach my $a (@$annots) {
        my ($entry, $type, $value) = @$a;
        my $format_val = _format_string($value);
        push @results, "ANNOTATION ($entry ($type $format_val))";
    }

    foreach my $f (@$flags) {
        my ($name, $set) = @$f;
        my $op = $set ? "+FLAGS" : "-FLAGS";
        push @results, "$op $name";
    }

    print "(" . join(' ', @results) . ")\n";
}

sub process_request
{
    my ($self) = @_;

    eval {
        $self->log(3, "Reading request");
        my $ArgsString = _read_args();
        die "Failed to read args" unless $ArgsString;

        my ($ArgsList, $Remainder) = _dlist_parse($ArgsString);
        die "Failed to parse args $ArgsString" unless $ArgsList;

        my %ArgsHash = @$ArgsList;

        # parse the argshash out here
        $ArgsHash{BODYSTRUCTURE} = _parse_bodystructure(delete $ArgsHash{BODY});

        my $message = Cyrus::Annotator::Message->new(%ArgsHash);

        $self->annotate_message($message);

        $self->log(3, "Emitting result");
        $self->_emit_results($message);
    };
    if ($@) {
        $self->log(2, "Caught and ignored error: $@");
    }
}

=item I<annotate_message($message)>

You need to provide a method of this name.  It will be called whenever
Cyrus notifies the annotator daemon that a new message is available, and
may set or clear any flags (system or user flags) or annotations.  Note
that to set any annotations which aren't builtin to Cyrus, you will
first need to configure them using I<annotation_definitions> option in
the I<imapd.conf> file.

The I<$message> object is a Cyrus::Annotator::Message which can be
examined, and on which flags and annotations can be set.

=cut

sub annotate_message
{
    my ($self, $message) = @_;

    die "Please define an annotate_message() sub";
}

sub post_configure
{
    my ($self) = @_;

    unlink(SOCKPATH);

    $self->SUPER::post_configure();
}

=back

=head1 SEE ALSO

I<Net::Server>, B<imapd.conf>(5), I<RFC3501>, I<RFC5257>.

=head1 AUTHOR

Greg Banks E<lt>gnb@fastmail.fmE<gt>.

=cut

1;
