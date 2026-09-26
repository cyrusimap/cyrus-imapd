# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;
use feature qw(signatures lexical_subs);
no warnings qw(experimental::signatures experimental::lexical_subs);
use Test::More;

use Cyrus::DList;

# atoms, quoted strings, literals, NIL, nesting and kvlists
my $input = join('',
  'MAILBOX %(UNIQUEID abc MBOXNAME "user.foo bar" NONE NIL ',
  'LIT {5+}', "\r\n", 'hel"o ',
  'RECORD (%(UID 1 FLAGS (\Seen \Answered)) %(UID 2 FLAGS ())) ',
  'ANNOTATIONS ())',
);

my $dlist = Cyrus::DList->parse_string($input, 1);
is($dlist->{key}, 'MAILBOX', 'top-level key parsed');

my $perl = $dlist->as_perl;
delete $perl->{__kvlist_order};
delete $_->{__kvlist_order} for @{$perl->{RECORD}};

is_deeply($perl, {
  UNIQUEID => 'abc',
  MBOXNAME => 'user.foo bar',
  NONE => undef,
  LIT => 'hel"o',
  RECORD => [
    { UID => 1, FLAGS => ['\Seen', '\Answered'] },
    { UID => 2, FLAGS => [] },
  ],
  ANNOTATIONS => [],
}, 'structure round-trips to perl');

# file literal
my $file = Cyrus::DList->parse_string(
  "%{default 0123456789abcdef0123456789abcdef01234567 4}\r\nabcd", 0);
is($file->{type}, 'file', 'file literal parsed');
is_deeply(
  [ @{$file}{qw(partition guid size data)} ],
  [ 'default', '0123456789abcdef0123456789abcdef01234567', 4, 'abcd' ],
  'file literal fields',
);

# unkeyed list with a literal that contains delimiters
my $tricky = Cyrus::DList->parse_string("(a {3+}\r\n) ( b)", 0);
is_deeply($tricky->as_perl, ['a', ') (', 'b'], 'literal body is opaque');

# as_string / parse_string round trip
my $out = $dlist->as_string;
my $again = Cyrus::DList->parse_string($out, 0);
is($again->as_string, $out, 'as_string is stable under reparse');

# parse time must scale linearly with input size
{
  require Time::HiRes;
  my $rec = '%(UID 1 MODSEQ 12345 FLAGS (\Seen) GUID '
          . '0123456789abcdef0123456789abcdef01234567)';
  my sub timed ($n) {
    my $s = 'X (' . join(' ', ($rec) x $n) . ')';
    my $t = Time::HiRes::time();
    Cyrus::DList->parse_string($s, 1);
    return Time::HiRes::time() - $t;
  }
  my $small = timed(2000);
  my $large = timed(16000);
  cmp_ok($large, '<', 24 * ($small + 0.01),
         "8x input parses in under 24x time ($small vs $large)");
}

done_testing;
