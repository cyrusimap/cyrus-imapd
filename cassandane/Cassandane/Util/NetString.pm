# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# code for reading and writing "netstrings", originally from FastMail's
# server utilities.
#
# A netstring is defined as:
# LENGTH COLON DATA COMMA
# where length is decimal [0-9]+ and is a count of BYTES
#
# Examples:
# 0:,
# 12:Hello world!,
#
# NOTE - there are no trailing endlines, just the comma.

package Cassandane::Util::NetString;
use strict;
use warnings;
use vars qw(@ISA @EXPORT);

@ISA = qw(Exporter);
@EXPORT = qw(print_netstring get_netstring);

sub print_netstring {
  my $fh   = shift;
  my $data = shift;

  die "Printing undefined network string" unless defined $data;

  my $size = length $data;

  print $fh "$size:$data,"
}

sub get_netstring {
  my $fh = shift;

  my($r, $ns);
  my $s = "";
  my $len = 0;

  # read the length
  for (;;) {
    defined($r = read($fh, $s, 1)) or return undef;

    return "" if !$r;
    last if $s eq ":";
    return undef if $s !~ /^[0-9]$/;

    $len = 10 * $len + $s;
    return undef if $len > 200000000;
  }

  $s = "";

  # read the string 'body'
  defined($r = read($fh, $s, $len)) or return undef;
  return "" if (!$r and $len != 0); # zero length is OK
  $ns = $s;

  # read the trailing comma
  defined($r = read($fh, $s, 1)) or return undef;
  return "" if !$r;
  return undef if $s ne ",";

  return $ns;
}

1;
