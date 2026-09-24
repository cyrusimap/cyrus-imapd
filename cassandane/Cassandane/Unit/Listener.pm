# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Listener;
use strict;
use warnings;
use experimental 'signatures';

# A Listener is a thing that "events" get broadcast to, saying a test started
# or finisher or passed or failed or whatever.  Events are just method calls.
#
# Every event handler is a no-op in this base class, so as subclass can just
# handle the things it cares about.

# A test is about to run, or has finished running.
sub start_test ($self, $test) { }
sub end_test ($self, $test) { }

# How it went.  Exactly one of these arrives between start_test and end_test.
# A failure or an error comes with the report to print for it: a string, so
# that a worker can send the parent's listeners exactly what its own would
# have heard.
sub add_pass ($self, $test) { }
sub add_failure ($self, $test, $report) { }
sub add_error ($self, $test, $report) { }
sub add_skip ($self, $test, $reason) { } # won't have a start/end

# Every test that was going to run has run.
sub finished ($self, $result, $start_time, $end_time) { }

1;
