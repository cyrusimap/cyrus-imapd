# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::CRLF;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);

use Cassandane::Util::CRLF;

sub _assert_crlf
{
    my ($self, $desc, $in, $want) = @_;

    $self->assert_str_equals($want, to_crlf($in), $desc);
}

sub test_to_crlf
{
    my ($self) = @_;

    $self->_assert_crlf('lf becomes crlf',        "a\nb",      "a\r\nb");
    $self->_assert_crlf('crlf is idempotent',     "a\r\nb",    "a\r\nb");
    $self->_assert_crlf('mixed is normalized',    "a\nb\r\nc", "a\r\nb\r\nc");
    $self->_assert_crlf('trailing lf converted',  "a\n",       "a\r\n");
    $self->_assert_crlf('blank lines preserved',  "a\n\nb",    "a\r\n\r\nb");
    $self->_assert_crlf('no newlines untouched',  "abc",       "abc");
    $self->_assert_crlf('empty string',           "",          "");
    $self->_assert_crlf('bare cr is not an eol',  "a\rb",      "a\rb");
    $self->_assert_crlf('cr before crlf kept',    "a\r\r\nb",  "a\r\r\nb");
    $self->_assert_crlf('line fold (SP) safe',    "a\n b",      "a\r\n b");
    $self->_assert_crlf('line fold (VT) safe',    "a\n\tb",     "a\r\n\tb");
}

# to_crlf returns a copy; the caller's string must be left as it was, because
# several call sites convert into a new variable and go on using the original.
sub test_to_crlf_does_not_modify_argument
{
    my ($self) = @_;

    my $orig = "a\nb\n";
    my $conv = to_crlf($orig);

    $self->assert_str_equals("a\nb\n", $orig);
    $self->assert_str_equals("a\r\nb\r\n", $conv);
}

1;
