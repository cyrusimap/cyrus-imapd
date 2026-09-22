# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Failure;
use strict;
use warnings;

use parent qw(Cassandane::Exception);

=head1 NAME

Cassandane::Failure - the exception meaning "this test failed"

=head1 DESCRIPTION

This is the thing you throw when your test fails.  There's a distinction in
Cassandane between "I asserted that this property would hold, and it didn't"
and "a totally unexpected error occurred, like the disk filled".

The first one should be a Cassandane::Failure.  The other one is basically any
other thrown exception.

=cut

1;
