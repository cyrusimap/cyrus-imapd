# 
# Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
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

package Cyrus::IMAP;

use strict;
use vars qw($VERSION @ISA);

require DynaLoader;

@ISA = qw(DynaLoader);
$VERSION = '1.00';

bootstrap Cyrus::IMAP $VERSION;

use Carp;
use IO::File;

#
# Wrapper for imclient__send().  Since the C version is a vargs routine which
# parses a format string to determine its arguments, and there is no non-
# varargs variant, we must do the varargs part in Perl (or reimplement
# imclient_send() in Perl, which would be far more painful).
#
# * 'fmt' is a printf-like specification of the command.  It must not
# * include the tag--that is automatically added by imclient_send().
# * The defined %-sequences are as follows:
# *
# *   %% -- %
# *   %a -- atom
# *   %s -- astring (will be quoted or literalized as needed)
# *   %d -- decimal
# *   %u -- unsigned decimal
# *   %v -- #astring (arg is an null-terminated array of (char *)
# *         which are written as space separated astrings)
# *   %B -- (internal use only) base64-encoded data at end of command line
#
# @@@@@ we don't even try to deal with sync literals; we do the nonsync version
# instead.  fixing this requires access to the internals of the C imclient_send
# implementation, or a vector-based interface to imclient_send.
#
sub send {
  my ($self, $cb, $rock, $fmt, @rest) = @_;
  my $res = '';
  while ($fmt =~ /^([^%]*)%(.)(.*)$/s) {
    $res .= $1;
    if ($2 eq 'a') {
      # atom
      $res .= scalar shift(@rest);
    }
    elsif ($2 eq 's') {
      # astring
      $res .= $self->_stringize(shift(@rest));
    }
    elsif ($2 eq 'd') {
      # decimal
      $res .= (0 + scalar shift(@rest));
    }
    elsif ($2 eq 'u') {
      # unsigned decimal; perl cares not for C lossage...
      $res .= (0 + scalar shift(@rest));
    }
    elsif ($2 eq 'v') {
      # #astring
      my $spc = '';
      if (ref($rest[0]) =~ /(^|=)HASH($|\()/) {
	my %vals = %{shift(@rest)};
	foreach (keys %vals) {
	  $res .= $self->_stringize($_) . ' ' .
	          $self->_stringize($vals{$_}) . $spc;
	  $spc = ' ';
	}
      } else {
	foreach (@{shift(@rest)}) {
	  $res .= $self->_stringize($_) . $spc;
	  $spc = ' ';
	}
      }
    }
    else {
      # anything else (NB: we respect %B being labeled "internal only")
      # NB: unlike the C version, we do not fail when handed an unknown escape
      $res .= $2;
    }
    $fmt = $3;
  }
  $res .= $fmt;
  $self->_send($cb, $rock, $res);
}

sub _cc {
  my $res = 2;
  local($^W) = 0;
  if (length($_[0]) >= 1024) {
    0;
  } else {
    foreach (map {unpack 'C', $_} split(//, $_[0])) {
      if ($_==0 || $_==10 || $_==13 || $_==34 || $_==92 || $_>=128) {
	$res = 0;
      }
      elsif ($_<33 || $_==37 || $_==40 || $_==41 || $_==42 || $_==123) {
	$res = 1 if $res == 2;
      }
    }
    $res;
  }
}

sub _stringize {
  my ($self, $str) = @_;
  my $res;
  my $cc = _cc($str);
  my $nz = ($str ne '');

  if ($nz && $cc == 2) {
    $str;
  }
  elsif ($cc) {
    # DOH! would be needed except imclient devolves to a LITERAL in this case.
    #$str =~ s/([\\\"])/\\$1/g;
    '"' . $str . '"';
  }
  elsif ($self->flags & &CONN_NONSYNCLITERAL) {
    '{' . length($str) . "+}\r\n$str";
  }
  else {
    # ugh!  UGH!
    # we cannot do this for now; we just use a nonsyncliteral and hope for
    # the best.  need a vector interface to imclient_send().
    '{' . length($str) . "+}\r\n$str";
  }
}

#
# As with send, authenticate needs a wrapper.  This is primarily a workaround
# for a SASL bug (or so I'm informed) with PLAIN authentication; however, we
# also take the oppurtunity to add a hash-based interface.
#
sub authenticate {
  my ($self, $first) = @_;
  my (%opts, $rc);
  if (defined $first &&
      $first =~ /^-\w+|Mechanism|Service|User|Minssf|Maxssf|Password$/) {
    (undef, %opts) = @_;
    foreach (qw(mechanism service user minssf maxssf password)) {
      $opts{'-' . $_} = $opts{ucfirst($_)} if !defined($opts{'-' . $_});
    }
  } else {
    (undef, $opts{-mechanism}, $opts{-service}, $opts{-user}, $opts{-minssf},
     $opts{-maxssf}, $opts{-password}) = @_;
  }
  if (!defined($opts{-mechanism})) {
    $opts{-mechanism} = '';
    $self->addcallback({-trigger => 'CAPABILITY',
			-callback => sub {my %a = @_;
					  map {$opts{-mechanism} .= $_ . ' '
						 if s/^AUTH=//}
					  split(/ /, $a{-text})}});
    $self->send(undef, undef, 'CAPABILITY');
    $self->addcallback({-trigger => 'CAPABILITY'});
    $opts{-mechanism} .= 'PLAIN';
  }
  $opts{-service} = "imap" if !defined($opts{-service});
  $opts{-minssf} = 0 if !defined($opts{-minssf});
  $opts{-maxssf} = 10000 if !defined($opts{-maxssf});
  $opts{-user} = $ENV{USER} || $ENV{LOGNAME} || (getpwuid($<))[0]
    if !defined($opts{-user});
  $rc = 0;
  if (defined($opts{-mechanism}) && lc($opts{-mechanism}) ne 'login') {
    $rc = $self->_authenticate($opts{-mechanism}, $opts{-service},
			       $opts{-user}, $opts{-minssf}, $opts{-maxssf});
  }
  $opts{-mechanism} ||= 'plain';
  if (!$rc && $opts{-mechanism} =~ /(\b|^)(plain|login)($|\b)/i) {
    $opts{-user} = getlogin if !defined($opts{-user});
    $opts{-user} = (getpwuid($<))[0] if !defined($opts{-user});
    $opts{-user} = "nobody" if !defined($opts{-user});
    # claimed to be a SASL bug:  "AUTHENTICATE PLAIN" fails.  in any case, we
    # also should provide a way to talk to pre-SASL Cyrus or even (shock
    # horror) non-Cyrus IMAP servers...
    # suck...
    if (!defined($opts{-password})) {
      my $tty = (IO::File->new('/dev/tty', O_RDWR) ||
		 *STDERR || *STDIN || *STDOUT);
      $tty->autoflush(1);
      $tty->print("IMAP Password: ");
      my $ostty;
      chomp($ostty = `stty -g`);
      system "stty -echo -icanon min 1 time 0 2>/dev/null || " .
	     "stty -echo cbreak";
      chomp($opts{-password} = $tty->getline);
      $tty->print("\013\010");
      system "stty $ostty";
    }
    # according to send(), password will be quoted or literalized as needed
    my ($kw, $text) = $self->send(undef, undef, 'LOGIN %a %s',
				  $opts{-user}, $opts{-password});
    $opts{-password} = "\0" x length($opts{-password});
    if ($kw eq 'OK') {
      $rc = 1;
    } else {
      $rc = undef;
      carp "$text";
    }
  }
  $rc;
}

1;
__END__

=head1 NAME

Cyrus::IMAP - Interface to Cyrus imclient library

=head1 SYNOPSIS

  use Cyrus::IMAP;

  my $client = Cyrus::IMAP->new('mailhost'[, $flags]);
  $flags = Cyrus::IMAP::CONN_NONSYNCLITERAL;
  $client->setflags($flags);
  $client->clearflags(Cyrus::IMAP::CONN_INITIALRESPONSE);
  $flags = $client->flags;
  $server = $client->servername;
  $client->authenticate;
  $flags = Cyrus::IMAP::CALLBACK_NUMBERED || Cyrus::IMAP::CALLBACK_NOLITERAL;
  $client->addcallback({-trigger => $str, -flags => $flags,
			-callback => \&cb, -rock => \$var}, ...);
  $client->send(\&callback, \&cbdata, $format, ...);
  $client->processoneevent;
  ($result, $text) = $client->send(undef, undef, $format, ...);
  ($fd, $writepending) = $client->getselectinfo;

=head1 DESCRIPTION

The Cyrus::IMAP module provides an interface to the Cyrus B<imclient>
library.  These are primarily useful for implementing B<cyradm> operations
within a Perl script; there are easier ways to implement general client
operations, although they may be more limited in terms of authentication
options when talking to a Cyrus imapd.

In the normal case, one will attach to a Cyrus server and authenticate
using the best available method:

	my $client = Cyrus::IMAP::new('imap');
	$client->authenticate;
	if (!$client->send('', '', 'CREATE %s', 'user.' . $username)) {
	  warn "createmailbox user.$username: $@";
	}

In simple mode as used above, C<send()> is invoked with C<undef>, C<0>, or
C<''> for the callback and rock (callback data) arguments; it returns a list
of C<($result, $text)> from the command.  If invoked in scalar context, it
returns C<$result> and places C<$text> in C<$@>.  In this mode, there is no
need to use C<processoneevent()>.  If more control is desired, use the callback
and rock arguments and invoke C<processoneevent()> regularly to receive
results from the IMAP server.  If still more control is needed, the
C<getselectinfo()> method returns a list containing a file descriptor (I<not>
Perl filehandle) which can be passed to select(); if the second element of the
list is true, you should include it in the write mask as well as the read mask
because the B<imclient> library needs to perform queued output.

For more information, consult the Cyrus documentation.

=head1 NOTES

C<send()> behaves as if the C<Cyrus::IMAP::CONN_NONSYNCLITERAL> flag is always
set.  This is because it is a wrapper for the C version, which cannot be made
directly available from Perl, and synchronous literals require interaction
with the IMAP server while parsing the format string.  This is planned to be
fixed in the future.

The C<'LOGIN'> mechanism can be used to authenticate with a plaintext username
and password.  This is intended as a workaround for a bug in early SASL
implementations; use of Cyrus::IMAP with non-Cyrus servers is not recommended,
primarily because there are easier ways to implement IMAP client functionality
in Perl.  (However, if you need SASL support, C<Cyrus::IMAP> is currently the
only way to get it.)

The file descriptor returned by C<getselectinfo()> should not be used for
anything other than C<select()>.  In particular, I/O on the file descriptor
will almost certainly cause more problems than whatever problem you think
you are trying to solve.

The B<imparse> library routines are not implemented, because they are little
more than a (failed) attempt to make parsing as simple in C as it is in Perl.

This module exists primarily so we can integrate Cyrus administration into
our Perl-based account management system, and secondarily so that we can
rewrite B<cyradm> in a sensible language instead of Tcl.  Usability for other
purposes is not guaranteed.

=head1 AUTHOR

Brandon S. Allbery, allbery@ece.cmu.edu

=head1 SEE ALSO

Cyrus::IMAP::Admin
perl(1), cyradm(1), imclient(3), imapd(8).

=cut
