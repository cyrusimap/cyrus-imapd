# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# A fixture suite for Cassandane::Test::Planner.  Not a test!  See the
# README in the parent directory.
package Cassandane::Fixture::Planner::Alpha::GlobOne;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestSuite);

sub test_alpha { }
sub test_beta { }
sub test_gamma_slow { }

1;
