package Cyrus::IMAP::IMSP;
use strict;
use Cyrus::IMAP;
use vars qw($VERSION
	    *get *set *unset);

$VERSION = '1.00';

#
# This is a derivative of the Cyrus::IMAP::Admin perl module, 
# adapted to run the IMSP set, unset, and get commands 
# instead of various IMAP administrative commands.
#

# New is "inherited" from the CYRUS::IMAP class except for one change:
# If only a server name was provided as an argument,
# change the default port number argument to the IMSP port (406).
sub new {
  my $class = shift;
  my $self = bless {}, $class;
  push @_, '406' if ($#_ == 0);  # If only one argument
  $self->{cyrus} = Cyrus::IMAP->new(@_) or $self = undef;
  $self;
}

# <Comments supplied by the author of Admin.pm>
# yuck.
# I intended this to be a subclass of Cyrus::IMAP, but that's a scalar ref so
# there's nowhere to hang the error information.  Indexing a "private" hash
# with the scalar sucks fully as much IMHO.  So we forward the Cyrus::IMAP
# methods on demand.
#
# yes, this is ugly.  but the overhead is minimized this way.
sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  no strict 'refs';
  $AUTOLOAD =~ s/^.*:://;
  my $sub = $Cyrus::IMAP::{$AUTOLOAD};
  *$AUTOLOAD = sub { &$sub($_[0]->{cyrus}, @_[1..$#_]); };
  goto &$AUTOLOAD;
}

# Set returns a standard result code. 
sub set {
  my ($self, $option, $value) = @_;
  $value = '' if !defined($value);
  my ($rc, $msg) = $self->send('', '', 'SET %s %s', $option, $value);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    $self->{error} = $msg;
    undef;
  }
}

# The draft says that UNSET could return an untagged OPTION reply
# but our server never does that so I'll sweep that case under the rug.
sub unset {
  my ($self, $option) = @_;
  my ($rc, $msg) = $self->send('', '', 'UNSET %s', $option);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    $self->{error} = $msg;
    undef;
  }
}

#
# Given a string, returns an array of two elements:
#   the first word of the string
#   the remainder of the string, minus the space separator
# If a parsing error occurs, only an error message is returned.
# The rules for what comprises a word are loosely based on the IMSP spec.
#   Atoms: <any characters except space, quote, etc.>*
#   Quoted strings:  <quote> <anything but quote>* <quote>
#   Literals: {<byte-count}\n\r<sequence of byte-count characters>
#
sub next_word {
  $_ = pop @_;
  my($firstword) = '';
  my($firstchar) = substr($_, $[, 1);

  # Quoted
  if ($firstchar eq '"') {
    s/^\"([^\"]*)\"// || 
      return "Bad format while decoding QUOTED-STRING in reply from GET";
    $firstword = $1;
  } 
  # Literal
  elsif ($firstchar eq '{') {
    s/^{([0-9]*)}\r\n// || 
      return "Bad format while decoding LITERAL in reply from GET";
    # Pull out the specified number of characters
    $firstword = substr($_, $[, $1);
    # Now remove those characters from the string
    substr($_, $[, $1) = '';
  } 
  # Must be Atom
  else {
    s/([^ ]*)// || 
      return "Bad format while decoding ATOM in reply from GET";
    $firstword = $1;
  }
  # Eat the space following the word (this fails if it was the last word)
  s/^ //;

  return ($firstword, $_);
}

#
# The untagged OPTION reply has one of these two formats:
#   "OPTION" SPACE atom SPACE astring SPACE "[READ-ONLY]"
#   "OPTION" SPACE atom SPACE astring SPACE "[READ-WRITE]"
# The access flag is not given back to the user.
#
sub get {
  my ($self, $option) = @_;
  my %info = ();
  $self->addcallback({-trigger => 'OPTION',
		      -callback => sub {
			my %d = @_;
			my $replyline = $d{-text};
			(my $opt, $replyline) = next_word($replyline);
			die $opt if (!defined $replyline);
			(my $val, $replyline) = next_word($replyline);
			die $val if (!defined $replyline);
			(my $acc, $replyline) = next_word($replyline);
			die $acc if (!defined $replyline);
			$d{-rock}{$opt} = $val;
		      },
		      -rock => \%info});
  my ($rc, $msg) = $self->send('', '', 'GET %s', $option);
  $self->addcallback({-trigger => 'OPTION'});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    %info;
  } else {
    $self->{error} = $msg;
    ();
  }
}

sub error {
  my $self = shift;
  $self->{error};
}

1;
__END__

=head1 NAME

Cyrus::IMAP::IMSP - Perl module for Cyrus IMSP user options

=head1 SYNOPSIS

  use Cyrus::IMAP::IMSP;

  my $client = Cyrus::IMAP::IMSP->new('imsphost'[, $port[, $flags]]);
  $rc = $client->set('mailreader.window.size', '200x300');
  %options = $client->get('mailreader.*')
  $rc = $client->unset('mailreader.window.size');

=head1 DESCRIPTION

This module is a Perl interface to the Cyrus IMSP functions that
relate to user options (preferences). Only three IMSP operations are
implemented: set, unset, and get.

=head1 METHODS

=over 4

=item new($server[, $port[, $flags]])

Instantiates a B<Cyrus::IMAP::IMSP> object.  This is in fact a Cyrus::IMAP
object with a few additional methods, so all Cyrus::IMAP methods are
available if needed.  (In particular, you will always want to use the
C<authenticate> method.)

=item error

Return the last error that occurred, or undef if the last operation was
successful.  This is in some cases (such as C<get>) the only way to
distinguish between a successful return of an empty list and an error return.

Calling C<error> does not reset the error state, so it is legal to write:

    %options = $client->get($option);
    print STDERR "Error: ", $client->error if $client->error;

=item set($option, $value)

Sets the option named by $option to the value in $value.

There are no restrictions or quoting rules needed to protect special
characters in the value argument. (The Cyrus::IMAP layer will take care
those details by adding double quotes or a literal introducer.)

If successful, returns 1. Otherwise, returns undef and makes an error
message available through the "error" function.

=item unset($option)

Removes the option named by $option. The option is completely removed
from the user's name space but will revert to a site-wide default if
one has been set. Note that this is different from assigning an option
the null value with set($option, '').

If you try to unset an option that does not exist, an error is
returned saying that the option was already unset.

If successful, returns 1. Otherwise, returns undef and makes an error
message available through the "error" function.

=item get($option_pattern)

Get takes either an option name or a pattern of names to fetch. The
pattern can contain either "*" or "%" wildcards anywhere in the
string. The usual IMAP wildcard semantics apply.

The return value is a hash of options with each key being an option
name and each value being the option's value string. If an empty hash
is returned, it's either because there were no matching options or
because some error happened. Check the "error" function to see which
was the case.

The IMSP protocol also returns an access flag of "[READ-WRITE]" or
"[READ-ONLY]" but that information is discarded by this function. A
more complicated function that returns both the value and the access
flag could be added later if needed.

=back

=head1 AUTHOR

Brandon S. Allbery, allbery@ece.cmu.edu
IMSP modifications by Joseph Jackson, jackson@CMU.EDU

=head1 SEE ALSO

Cyrus::IMAP
perl(1), cyradm(1), imapd(8).

=cut
