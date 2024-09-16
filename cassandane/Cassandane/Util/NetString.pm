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
