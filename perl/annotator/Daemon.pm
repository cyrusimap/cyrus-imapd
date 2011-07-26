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
use Exporter qw(import);
# use Data::Dumper;
use Unix::Syslog qw(:macros);
use File::Path;

our $VERSION = '1.00';
our @EXPORT = qw(PRIVATE SHARED);

use constant USER  => 'cyrus';
use constant GROUP => 'mail';
use constant RUNPREFIX  => '/var/run/annotatord';
use constant APPNAME => 'annotatord';
use constant PIDFILE => RUNPREFIX . '.pid';
use constant SOCKPATH => RUNPREFIX . '.socket';

# Levels are: LOG_DEBUG (7), LOG_INFO (6), *LOG_NOTICE (5), LOG_WARNING (4), LOG_ERR (3)
use constant LOG_LEVEL => LOG_INFO;

# Exported constants
use constant PRIVATE => 0;
use constant SHARED => 1;

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
      my ($self, $args) = @_;

      $self->set_flag('\Flagged');
      $self->set_annotation('/comment', SHARED, 'Hello!!');
  }

  MyAnnotatorDaemon->run();

=head1 DESCRIPTION

This module provides a framework for writing daemons which can be used
to add annotations or flags to messages which are delivered into the
Cyrus mail server.

To use Cyrus::Annotator::Daemon, write a Perl script which creates an
object derived from it; see the Synposis above.  Run this script as
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
    my $self = $class->SUPER::new(@default_args, @args);

    $self->{annotations} = [];
    $self->{flags} = [];

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

    return $class->SUPER::run(@default_args, @args);
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

      # Literal ends with \r\n, and possible space
      if (ref($Input)) {
        read($Input, $CurAtom, $Bytes) || die "No input data";
        $Line = <$Input>;
        $Line =~ /^\r\n$/ || die "No expected EOL at end of literal";
        $Line = <$Input>;
      } else {
        $CurAtom = substr($Line, pos($Line), $Bytes);
        pos($Line) += length($CurAtom);
        $Line =~ /\G\r\n/gc || die "No expected EOL at end of literal";
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

sub _read_args
{
    my $Nbytes;
    my $Data = '';

    for (;;) {
	$Nbytes = readline STDIN;
	last unless defined $Nbytes;
	chomp $Nbytes;
	$Nbytes = 0 + $Nbytes;
# 	printf "nbytes=%d\n", $nbytes;
	last if (!$Nbytes);
	read STDIN, $Data, $Nbytes, length($Data);
    }

    return $Data;
}

sub _print_string
{
    my ($s) = @_;

    if (!defined $s)
    {
	print "NIL";
    }
    elsif ($s =~ m/[\\"\012\015\200-\377]/)
    {
	# don't try to quote this, use a literal
	printf "{%u}\r\n%s", length($s), $s;
    }
    else
    {
	printf "\"%s\"", $s;
    }
}

sub _emit_results
{
    my ($self) = @_;
    my $sep = '';

    print "(";

    foreach my $a (@{$self->{annotations}})
    {
	print $sep;
	printf "ANNOTATION (%s (%s ",
		$a->{entry},
		($a->{shared} ? "value.shared" : "value.priv");
	_print_string($a->{value});
	print "))";
	$sep = " ";
    }

    foreach my $f (@{$self->{flags}})
    {
	print $sep;
	printf "%s %s",
		($f->{set} ? "+FLAGS" : "-FLAGS"),
		$f->{flag};
	$sep = " ";
    }

    print ")\n";
}

sub process_request
{
    my ($self) = @_;

    eval {
	$self->{annotations} = [];
	$self->{flags} = [];

	$self->log(2, "Reading request");
	my $ArgsString = _read_args();
	die "Failed to read args" unless $ArgsString;

	my ($ArgsList, $Remainder) = _dlist_parse($ArgsString);
	die "Failed to parse args $ArgsString" unless $ArgsList;

	my %ArgsHash = @$ArgsList;

	my $fh = IO::File->new("<$ArgsHash{FILENAME}")
	    || die "Failed to read file $ArgsHash{FILENAME}";

	my $body = _parse_bodystructure($ArgsHash{BODY}, 1, 1)
	    || die "Failed to parse bodystructure $ArgsHash{BODY}";

	$self->annotate_message({
	    FH => $fh,
	    BODY => $body,
	    ANNOTATIONS => $ArgsHash{ANNOTATIONS},
	    FLAGS => $ArgsHash{FLAGS},
	    GUID => $ArgsHash{GUID},
	});

	$fh->close();

	$self->log(2, "Emitting result");
	$self->_emit_results();
    };
    if ($@) {
	$self->log(2, "Caught and ignored error: $@");
    }
}

=item I<annotate_message($args)>

You need to provide a method of this name.  It will be called whenever
Cyrus notifies the annotator daemon that a new message is available, and
may set or clear any flags (system or user flags) or annotations.  Note
that to set any annotations which aren't builtin to Cyrus, you will
first need to configure them using I<annotation_definitions> option in
the I<imapd.conf> file.

The I<$args> hash contains the following information from Cyrus.

=over 4

=item I<FH>

is a read-only IO:File handle to the spool file.  You can not change
the content of the spool file.

=item I<FLAGS>

is an array containing any system or user flags already proposed for
the message (e.g. if specified by the user when APPENDing a message).

=item I<ANNOTATIONS>

is an array containing any annotations already proposed for the message
(e.g. if specified by the user when APPENDing a message).

=item I<BODY>

is a structure closely based on the IMAP BODYSTRUCTURE, decoded into a
hash, including recursively all MIME sections.  In general, the
following items are defined for all body structures:

=item I<GUID>

is the hex encoded (40 character) sha1 of the spool file.

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

=back

=cut

sub annotate_message
{
    my ($self, $args) = @_;

    die "Please define an annotate_message() sub";
}

sub post_configure
{
    my ($self) = @_;

    unlink(SOCKPATH);

    $self->SUPER::post_configure();
}

sub _get_annotation
{
    my ($self, $entry, $shared) = @_;

    my @res = grep
	{ $_->{entry} eq $entry && $_->{shared} == $shared }
	@{$self->{annotations}};
    my $a = shift @res;
    if (!defined $a)
    {
	$a = {
	    entry => $entry,
	    shared => $shared,
	    value => undef
	};
	push(@{$self->{annotations}}, $a);
    }
    return $a;
}

=item I<add_annotation($entry, $sharedflag, $value)>

When called from the I<annotate_message> method, arranges for the IMAP
per-message annotation named by I<$entry> and I<$sharedflag> to be set
on the current message.  The arguments are:

=over 4

=item I<$entry>

is the name of an annotation, for example I</comment>.

=item I<$sharedflag>

is one of the constants I<SHARED> or I<PRIVATE>.

=item I<$value>

is a scalar containing the new value for the annotation.  Note that
I<$value> is a binary blob, not a string.  Passing I<undef> is
equivalent to calling I<remove_annotation>.

=back

For example:

  $self->add_annotation('/comment', SHARED, 'Hello World');

=cut

sub add_annotation
{
    my ($self, $entry, $shared, $value) = @_;
    my $a = $self->_get_annotation($entry, $shared);
    $a->{value} = $value;
}

=item I<remove_annotation($entry, $sharedflag)>

When called from the I<annotate_message> method, arranges for the IMAP
per-message annotation named by I<$entry> and I<$sharedflag> to be
removed from the current message.  The arguments I<$entry> and
I<$sharedflag> are as for I<add_annotation>.  For example:

  $self->remove_annotation('/comment', PRIVATE);

=cut

sub remove_annotation
{
    my ($self, $entry, $shared) = @_;
    my $a = $self->_get_annotation($entry, $shared);
    $a->{value} = undef;
}

sub _get_flag
{
    my ($self, $flag) = @_;

    my @res = grep
	{ $_->{flag} eq $flag }
	@{$self->{flags}};
    my $f = shift @res;
    if (!defined $f)
    {
	$f = {
	    flag => $flag,
	    set => 0,
	};
	push(@{$self->{flags}}, $f);
    }
    return $f;
}

=item I<set_flag($flag)>

When called from the I<annotate_message> method, arranges for the IMAP
flag named by I<$flag> to be set on the current message.  For example:

  $self->set_flag('\Flagged');

=cut

sub set_flag
{
    my ($self, $flag) = @_;
    my $a = $self->_get_flag($flag);
    $a->{set} = 1;
}

=item I<clear_flag($flag)>

When called from the I<annotate_message> method, arranges for the IMAP
flag named by I<$flag> to be cleared on the current message.  For
example:

  $self->clear_flag('\Seen');

=cut

sub clear_flag
{
    my ($self, $flag) = @_;
    my $a = $self->_get_flag($flag);
    $a->{set} = 0;
}

=back

=head1 SEE ALSO

I<Net::Server>, B<imapd.conf>(5), I<RFC3501>, I<RFC5257>.

=head1 AUTHOR

Greg Banks E<lt>gnb@fastmail.fmE<gt>.

=cut

1;
