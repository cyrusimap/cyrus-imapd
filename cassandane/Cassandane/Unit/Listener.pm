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
#
# An event is what the worker send back: a hashref with suite, testname,
# outcome, report (for a failure or an error), reason (for a skip), and
# annotations (whatever the test wrote while it ran).

# A test is about to run, or has finished running.
sub start_test ($self, $witem) { }
sub end_test ($self, $witem) { }

# How it went.  Exactly one of these arrives between start_test and end_test.
sub add_pass ($self, $witem) { }
sub add_failure ($self, $witem) { }
sub add_error ($self, $witem) { }
sub add_skip ($self, $witem) { } # won't have a start/end

# Every test that was going to run has run.  The summary is plain data: see
# Cassandane::Unit::Runner::result_summary.
sub finished ($self, $summary, $start_time, $end_time) { }

1;
