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

package Cassandane::Cyrus::TesterCalDAV;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use JSON::XS;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Cassini;
use Net::CalDAVTalk;

my $basedir;
my $binary;
my $testdir;
my %suppressed;
my %expected;

my $KNOWN_ERRORS = <<EOF;
aclreports/supported-report-set property/1 | 1
aclreports/supported-report-set property/2 | 1
alarm-dismissal/Bad property value/1 | 1
caldavIOP/1. Event Creation/1.3 | 1
caldavIOP/2. Event Modification/2.4 | 1
caldavIOP/2. Event Modification/2.7 | 1
caldavIOP/2. Event Modification/2.9 | 1
conditional/Last_modified handling/1 | 1
conditional/Last_modified handling/3 | 1
copymove/COPY/MOVE and Properties/2 | 1
ctag/Scheduling/3 | 1
ctag/Scheduling/4 | 1
ctag/Scheduling/5 | 1
duplicate_uids/Create duplicate/2 | 1
encodedURIs/calendar resource/5 | 1
encodedURIs/calendar resource/6 | 1
encodedURIs/calendar resource/7 | 1
encodedURIs/calendar resource/8 | 1
encodedURIs/calendar resource/9 | 1
encodedURIs/calendar resource double-encoded/2 | 1
encodedURIs/calendar resource double-encoded/5 | 1
encodedURIs/calendar resource double-encoded/6 | 1
encodedURIs/calendar resource double-encoded/7 | 1
encodedURIs/calendar resource double-encoded/8 | 1
encodedURIs/calendar resource double-encoded/9 | 1
errors/COPY/12 | 1
errors/MOVE/12 | 1
errors/PUT/10 | 1
errors/PUT/11 | 1
errors/PUT/13 | 1
errors/PUT/16 | 1
errors/PUT/17 | 1
errors/PUT/19 | 1
errors/PUT/22 | 1
errors/PUT/23 | 1
errors/PUT/25 | 1
errors/PUT/26 | 1
errors/PUT/3 | 1
errors/PUT/4 | 1
errors/REPORT/filter/6 | 1
errors/REPORT/filter/9 | 1
errors/Unauthenticated versus Forbidden/1 | 1
errors/Unauthenticated versus Forbidden/2 | 1
freebusy/Freebusy - mixed timed and all-day/3 | 1
freebusy/Freebusy - mixed timed and all-day/4 | 1
implicitallday/Attendee Recurrence Override/-1 | 1
implicitallday/Attendee Recurrence Override/11 | 1
implicitallday/Attendee Recurrence Override/12 | 1
implicitallday/Attendee Recurrence Override/13 | 1
implicitallday/Attendee Recurrence Override/15 | 1
implicitallday/Attendee Recurrence Override/16 | 1
implicitallday/Attendee Recurrence Override/17 | 1
implicitallday/Attendee Recurrence Override/2 | 1
implicitallday/Attendee Recurrence Override/3 | 1
implicitallday/Attendee Recurrence Override/4 | 1
implicitallday/Attendee Recurrence Override/6 | 1
implicitallday/Attendee Recurrence Override/7 | 1
implicitallday/Attendee Recurrence Override/8 | 1
implicitallday/Simple Changes/-1 | 1
implicitallday/Simple Changes/11 | 1
implicitallday/Simple Changes/12 | 1
implicitallday/Simple Changes/13 | 1
implicitallday/Simple Changes/15 | 1
implicitallday/Simple Changes/16 | 1
implicitallday/Simple Changes/17 | 1
implicitallday/Simple Changes/2 | 1
implicitallday/Simple Changes/3 | 1
implicitallday/Simple Changes/4 | 1
implicitallday/Simple Changes/6 | 1
implicitallday/Simple Changes/7 | 1
implicitallday/Simple Changes/8 | 1
implicitattendeedelete/Non-recurring/10 | 1
implicitattendeedelete/Non-recurring/-1 | 1
implicitattendeedelete/Non-recurring/11 | 1
implicitattendeedelete/Non-recurring/14 | 1
implicitattendeedelete/Non-recurring/15 | 1
implicitattendeedelete/Non-recurring/16 | 1
implicitattendeedelete/Non-recurring/20 | 1
implicitattendeedelete/Non-recurring/2 | 1
implicitattendeedelete/Non-recurring/21 | 1
implicitattendeedelete/Non-recurring/22 | 1
implicitattendeedelete/Non-recurring/23 | 1
implicitattendeedelete/Non-recurring/3 | 1
implicitattendeedelete/Non-recurring/4 | 1
implicitattendeedelete/Non-recurring/5 | 1
implicitattendeedelete/Non-recurring/6 | 1
implicitattendeedelete/Non-recurring/7 | 1
implicitattendeedelete/Recurring with master/10 | 1
implicitattendeedelete/Recurring with master/-1 | 1
implicitattendeedelete/Recurring with master/11 | 1
implicitattendeedelete/Recurring with master/12 | 1
implicitattendeedelete/Recurring with master/13 | 1
implicitattendeedelete/Recurring with master/14 | 1
implicitattendeedelete/Recurring with master/15 | 1
implicitattendeedelete/Recurring with master/16 | 1
implicitattendeedelete/Recurring with master/18 | 1
implicitattendeedelete/Recurring with master/20 | 1
implicitattendeedelete/Recurring with master/2 | 1
implicitattendeedelete/Recurring with master/21 | 1
implicitattendeedelete/Recurring with master/22 | 1
implicitattendeedelete/Recurring with master/23 | 1
implicitattendeedelete/Recurring with master/24 | 1
implicitattendeedelete/Recurring with master/25 | 1
implicitattendeedelete/Recurring with master/26 | 1
implicitattendeedelete/Recurring with master/28 | 1
implicitattendeedelete/Recurring with master/29 | 1
implicitattendeedelete/Recurring with master/3 | 1
implicitattendeedelete/Recurring with master/4 | 1
implicitattendeedelete/Recurring with master/5 | 1
implicitattendeedelete/Recurring with master/6 | 1
implicitattendeedelete/Recurring with master/7 | 1
implicitattendeedelete/Recurring without master/10 | 1
implicitattendeedelete/Recurring without master/-1 | 1
implicitattendeedelete/Recurring without master/11 | 1
implicitattendeedelete/Recurring without master/12 | 1
implicitattendeedelete/Recurring without master/13 | 1
implicitattendeedelete/Recurring without master/14 | 1
implicitattendeedelete/Recurring without master/15 | 1
implicitattendeedelete/Recurring without master/16 | 1
implicitattendeedelete/Recurring without master/18 | 1
implicitattendeedelete/Recurring without master/20 | 1
implicitattendeedelete/Recurring without master/2 | 1
implicitattendeedelete/Recurring without master/21 | 1
implicitattendeedelete/Recurring without master/22 | 1
implicitattendeedelete/Recurring without master/23 | 1
implicitattendeedelete/Recurring without master/24 | 1
implicitattendeedelete/Recurring without master/25 | 1
implicitattendeedelete/Recurring without master/26 | 1
implicitattendeedelete/Recurring without master/28 | 1
implicitattendeedelete/Recurring without master/29 | 1
implicitattendeedelete/Recurring without master/3 | 1
implicitattendeedelete/Recurring without master/4 | 1
implicitattendeedelete/Recurring without master/5 | 1
implicitattendeedelete/Recurring without master/6 | 1
implicitattendeedelete/Recurring without master/7 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/10 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/-1 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/11 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/12 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/13 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/14 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/15 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/16 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/18 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/20 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/2 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/21 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/22 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/23 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/24 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/25 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/26 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/28 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/29 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/3 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/4 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/5 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/6 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/7 | 1
implicitattendeedelete/Recurring without master - delete of undeclined instance/8 | 1
implicitbadclients/All-day freebusy floating/1 | 1
implicitbadclients/Client drops a cancelled overridden instance/11 | 1
implicitbadclients/Client drops a cancelled overridden instance/2 | 1
implicitbadclients/Client drops a cancelled overridden instance/3 | 1
implicitbadclients/Client drops a cancelled overridden instance/4 | 1
implicitbadclients/Client drops a cancelled overridden instance/6 | 1
implicitbadclients/Client drops a cancelled overridden instance/7 | 1
implicitbadclients/Client drops a cancelled overridden instance/8 | 1
implicitbadclients/Client drops a cancelled overridden instance/9 | 1
implicitbadclients/Client drops an overridden instance/11 | 1
implicitbadclients/Client drops an overridden instance/2 | 1
implicitbadclients/Client drops an overridden instance/3 | 1
implicitbadclients/Client drops an overridden instance/4 | 1
implicitbadclients/Client drops an overridden instance/6 | 1
implicitbadclients/Client drops an overridden instance/7 | 1
implicitbadclients/Client drops an overridden instance/8 | 1
implicitbadclients/Client drops an overridden instance/9 | 1
implicitbatchrefresh/Invite and one reply/2 | 1
implicitbatchrefresh/Invite and one reply/3 | 1
implicitbatchrefresh/Invite and one reply/4 | 1
implicitbatchrefresh/Invite and one reply/5 | 1
implicitbatchrefresh/Invite and one reply/6 | 1
implicitbatchrefresh/Invite and one reply/7 | 1
implicitbatchrefresh/Invite and one reply/9 | 1
implicitbatchrefresh/Invite and two interleaved replies/1 | 1
implicitbatchrefresh/Invite and two interleaved replies/11 | 1
implicitbatchrefresh/Invite and two interleaved replies/2 | 1
implicitbatchrefresh/Invite and two interleaved replies/3 | 1
implicitbatchrefresh/Invite and two interleaved replies/4 | 1
implicitbatchrefresh/Invite and two interleaved replies/5 | 1
implicitbatchrefresh/Invite and two interleaved replies/7 | 1
implicitbatchrefresh/Invite and two interleaved replies/8 | 1
implicitbatchrefresh/Invite and two interleaved replies/9 | 1
implicitbatchrefresh/Invite and two quick replies/10 | 1
implicitbatchrefresh/Invite and two quick replies/1 | 1
implicitbatchrefresh/Invite and two quick replies/2 | 1
implicitbatchrefresh/Invite and two quick replies/3 | 1
implicitbatchrefresh/Invite and two quick replies/4 | 1
implicitbatchrefresh/Invite and two quick replies/5 | 1
implicitbatchrefresh/Invite and two quick replies/6 | 1
implicitbatchrefresh/Invite and two quick replies/7 | 1
implicitbatchrefresh/Invite and two quick replies/8 | 1
implicitcalendartransp/Default Calendar/1 | 1
implicitcalendartransp/New Calendar/2 | 1
implicitcalendartransp/New Calendar - free-busy-set compatibility/12 | 1
implicitcalendartransp/New Calendar - free-busy-set compatibility/13 | 1
implicitcalendartransp/New Calendar - free-busy-set compatibility/14 | 1
implicitcalendartransp/New Calendar - free-busy-set compatibility/16 | 1
implicitcalendartransp/New Calendar - free-busy-set compatibility/2 | 1
implicitcalendartransp/New Calendar - free-busy-set compatibility/3 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/2 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/3 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/4 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/5 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/6 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/7 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/9 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/10 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/11 | 1
implicitcancels/Non-recurring add only STATUS:CANCELLED/-1 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/2 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/3 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/4 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/5 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/6 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/7 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/9 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/10 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/11 | 1
implicitcancels/Non-recurring add STATUS:CANCELLED and change summary/-1 | 1
implicitcancels/Non-recurring - DELETE/1 | 1
implicitcancels/Non-recurring - DELETE/2 | 1
implicitcancels/Non-recurring - DELETE/3 | 1
implicitcancels/Non-recurring - DELETE/4 | 1
implicitcancels/Non-recurring - remove/1 | 1
implicitcancels/Non-recurring - remove/2 | 1
implicitcancels/Non-recurring - remove/3 | 1
implicitcancels/Non-recurring - remove/4 | 1
implicitcancels/Non-recurring with time-shift - remove/-1 | 1
implicitcancels/Non-recurring with time-shift - remove/2 | 1
implicitcancels/Non-recurring with time-shift - remove/3 | 1
implicitcancels/Non-recurring with time-shift - remove/5 | 1
implicitcancels/Non-recurring with time-shift - remove/6 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/10 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/-1 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/11 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/13 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/14 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/15 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/2 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/3 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/4 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/5 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/6 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/7 | 1
implicitcancels/Organizer add attendee to instance they were initially not part of/9 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/10 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/-1 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/11 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/13 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/14 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/15 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/2 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/3 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/4 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/5 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/6 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/7 | 1
implicitcancels/Organizer re-invite, after Attendee EXDATE/9 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/10 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/11 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/12 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/13 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/2 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/3 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/4 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/5 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/6 | 1
implicitcancels/Organzier DELETE, Attendee EXDATE/7 | 1
implicitcancels/Override - remove - some/-1 | 1
implicitcancels/Override - remove - some/2 | 1
implicitcancels/Override - remove - some/5 | 1
implicitcancels/Partial - DELETE - all/1 | 1
implicitcancels/Partial - DELETE - all/2 | 1
implicitcancels/Partial - DELETE - all/3 | 1
implicitcancels/Partial - DELETE - all/4 | 1
implicitcancels/Partial - DELETE - some/-1 | 1
implicitcancels/Partial - DELETE - some/1 | 1
implicitcancels/Partial - DELETE - some/2 | 1
implicitcancels/Partial - DELETE - some/3 | 1
implicitcancels/Partial - DELETE - some/4 | 1
implicitcancels/Partial - DELETE - some/5 | 1
implicitcancels/Partial - remove - all/1 | 1
implicitcancels/Partial - remove - all/2 | 1
implicitcancels/Partial - remove - all/3 | 1
implicitcancels/Partial - remove - all/4 | 1
implicitcancels/Partial - remove - some/-1 | 1
implicitcancels/Partial - remove - some/1 | 1
implicitcancels/Partial - remove - some/2 | 1
implicitcancels/Partial - remove - some/3 | 1
implicitcancels/Partial - remove - some/4 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/2 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/3 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/4 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/5 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/6 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/7 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/9 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/10 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/11 | 1
implicitcancels/Recurring add only STATUS:CANCELLED to override/-1 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/2 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/3 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/4 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/5 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/6 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/7 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/9 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/10 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/11 | 1
implicitcancels/Recurring add STATUS:CANCELLED to override, change master summary/-1 | 1
implicitcancels/Recurring cancelled override remains at override time/10 | 1
implicitcancels/Recurring cancelled override remains at override time/-1 | 1
implicitcancels/Recurring cancelled override remains at override time/11 | 1
implicitcancels/Recurring cancelled override remains at override time/13 | 1
implicitcancels/Recurring cancelled override remains at override time/14 | 1
implicitcancels/Recurring cancelled override remains at override time/15 | 1
implicitcancels/Recurring cancelled override remains at override time/2 | 1
implicitcancels/Recurring cancelled override remains at override time/3 | 1
implicitcancels/Recurring cancelled override remains at override time/4 | 1
implicitcancels/Recurring cancelled override remains at override time/5 | 1
implicitcancels/Recurring cancelled override remains at override time/6 | 1
implicitcancels/Recurring cancelled override remains at override time/7 | 1
implicitcancels/Recurring cancelled override remains at override time/9 | 1
implicitcancels/Recurring - DELETE - all/1 | 1
implicitcancels/Recurring - DELETE - all/2 | 1
implicitcancels/Recurring - DELETE - all/3 | 1
implicitcancels/Recurring - DELETE - all/4 | 1
implicitcancels/Recurring - DELETE - some/-1 | 1
implicitcancels/Recurring - DELETE - some/1 | 1
implicitcancels/Recurring - DELETE - some/2 | 1
implicitcancels/Recurring - DELETE - some/3 | 1
implicitcancels/Recurring - DELETE - some/4 | 1
implicitcancels/Recurring - DELETE - some/5 | 1
implicitcancels/Recurring (override) with time-shift - remove/-1 | 1
implicitcancels/Recurring (override) with time-shift - remove/2 | 1
implicitcancels/Recurring (override) with time-shift - remove/3 | 1
implicitcancels/Recurring (override) with time-shift - remove/5 | 1
implicitcancels/Recurring (override) with time-shift - remove/6 | 1
implicitcancels/Recurring (override) with time-shift - remove/7 | 1
implicitcancels/Recurring (override) with time-shift - removed from master only/-1 | 1
implicitcancels/Recurring (override) with time-shift - removed from master only/2 | 1
implicitcancels/Recurring (override) with time-shift - removed from master only/3 | 1
implicitcancels/Recurring (override) with time-shift - removed from master only/5 | 1
implicitcancels/Recurring (override) with time-shift - removed from master only/6 | 1
implicitcancels/Recurring (override) with time-shift - removed from master only/7 | 1
implicitcancels/Recurring - remove - all/1 | 1
implicitcancels/Recurring - remove - all/2 | 1
implicitcancels/Recurring - remove - all/3 | 1
implicitcancels/Recurring - remove - all/4 | 1
implicitcancels/Recurring - remove - some/-1 | 1
implicitcancels/Recurring - remove - some/1 | 1
implicitcancels/Recurring - remove - some/2 | 1
implicitcancels/Recurring - remove - some/3 | 1
implicitcancels/Recurring - remove - some/4 | 1
implicitcancels/Recurring - remove - some/5 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/-1 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/1 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/2 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/3 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/4 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/5 | 1
implicitcancels/Recurring - remove - some - attendee still cancelled/6 | 1
implicitcancels/Recurring - remove - twice/-1 | 1
implicitcancels/Recurring - remove - twice/1 | 1
implicitcancels/Recurring - remove - twice/2 | 1
implicitcancels/Recurring - remove - twice/3 | 1
implicitcancels/Recurring - remove - twice/4 | 1
implicitcancels/Recurring - remove - twice/5 | 1
implicitcancels/Recurring - remove - twice/6 | 1
implicitcancels/Recurring with time-shift - remove/-1 | 1
implicitcancels/Recurring with time-shift - remove/2 | 1
implicitcancels/Recurring with time-shift - remove/3 | 1
implicitcancels/Recurring with time-shift - remove/5 | 1
implicitcancels/Recurring with time-shift - remove/6 | 1
implicitcancels/Recurring with time-shift - remove/7 | 1
implicitcompatibility/Attendee instance override as master/11 | 1
implicitcompatibility/Attendee instance override as master/2 | 1
implicitcompatibility/Attendee instance override as master/3 | 1
implicitcompatibility/Attendee instance override as master/4 | 1
implicitcompatibility/Attendee instance override as master/6 | 1
implicitcompatibility/Attendee instance override as master/7 | 1
implicitcompatibility/Attendee instance override as master/8 | 1
implicitcompatibility/Attendee instance override as master/9 | 1
implicitcompatibility/Attendee two instance override as master/11 | 1
implicitcompatibility/Attendee two instance override as master/2 | 1
implicitcompatibility/Attendee two instance override as master/3 | 1
implicitcompatibility/Attendee two instance override as master/4 | 1
implicitcompatibility/Attendee two instance override as master/6 | 1
implicitcompatibility/Attendee two instance override as master/7 | 1
implicitcompatibility/Attendee two instance override as master/8 | 1
implicitcompatibility/Attendee two instance override as master/9 | 1
implicitdefaultcalendar/Auto-create default calendar on scheduling/-1 | 1
implicitdefaultcalendar/Auto-create default calendar on scheduling/1 | 1
implicitdefaultcalendar/Auto-create default calendar on scheduling/3 | 1
implicitdefaultcalendar/Auto-create default calendar on scheduling/4 | 1
implicitdefaultcalendar/Auto-create default calendar on scheduling/6 | 1
implicitdefaultcalendar/Default Property/1 | 1
implicitdefaultcalendar/Delete previously default calendar/1 | 1
implicitdefaultcalendar/Delete previously default calendar/2 | 1
implicitdefaultcalendar/Delete previously default calendar/3 | 1
implicitdefaultcalendar/Move default calendar/1 | 1
implicitdefaultcalendar/Move default calendar/2 | 1
implicitdefaultcalendar/Set empty Property/2 | 1
implicitdefaultcalendar/Set invalid Property/2 | 1
implicitdefaultcalendar/Set valid Property/1 | 1
implicitdefaultcalendar/Set valid Property/2 | 1
implicitdefaultcalendar/Set valid Property/3 | 1
implicitdeletecalendar/Invite Calendar Delete/10 | 1
implicitdeletecalendar/Invite Calendar Delete/1 | 1
implicitdeletecalendar/Invite Calendar Delete/11 | 1
implicitdeletecalendar/Invite Calendar Delete/4 | 1
implicitdeletecalendar/Invite Calendar Delete/5 | 1
implicitdeletecalendar/Invite Calendar Delete/9 | 1
implicitdeletecalendar/Simple Calendar Delete/3 | 1
implicitdeletecalendar/Simple Calendar Delete/4 | 1
impliciterrors/Allowed Organizers/1 | 1
impliciterrors/Attempt to remove Organizer/2 | 1
impliciterrors/Attempt to remove Organizer/3 | 1
impliciterrors/Attempt to remove Organizer/4 | 1
impliciterrors/Attempt to remove Organizer/5 | 1
impliciterrors/Attempt to remove Organizer/8 | 1
impliciterrors/Attempt to remove Organizer/9 | 1
impliciterrors/Bad content-type on Inbox/2 | 1
impliciterrors/Bad content-type on Inbox/5 | 1
impliciterrors/Canonical paths/2 | 1
impliciterrors/Canonical paths/3 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/1 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/11 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/2 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/3 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/4 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/6 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/7 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/8 | 1
impliciterrors/Invalid Attendee PUT of missing cancelled instance/9 | 1
impliciterrors/Invalid Attendee PUT using Organizer on server/1 | 1
impliciterrors/Invalid Attendee PUT using Organizer on server/2 | 1
impliciterrors/Invalid Attendee PUT without own ATTENDEE property/-1 | 1
impliciterrors/Invalid Attendee PUT without own ATTENDEE property/2 | 1
impliciterrors/Invalid Attendee PUT without own ATTENDEE property/3 | 1
impliciterrors/Invalid Attendee PUT without own ATTENDEE property/4 | 1
impliciterrors/Invalid Attendee PUT without own ATTENDEE property/5 | 1
impliciterrors/Invalid Organizer PUT of orphaned instance/1 | 1
impliciterrors/Invalid Organizer PUT of orphaned instance/2 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/-1 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/1 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/2 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/3 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/4 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/5 | 1
impliciterrors/Organizer invites attendee to one instance then adds them to all/6 | 1
impliciterrors/Organizer PUT remove recurrence and master override/-1 | 1
impliciterrors/Organizer PUT remove recurrence and master override/1 | 1
impliciterrors/Organizer PUT remove recurrence and master override/2 | 1
impliciterrors/Organizer PUT remove recurrence and master override/3 | 1
impliciterrors/Organizer PUT remove recurrence and master override/4 | 1
impliciterrors/Organizer PUT remove recurrence and master override/5 | 1
impliciterrors/Organizer TRANSP leakage/-1 | 1
impliciterrors/Organizer TRANSP leakage/1 | 1
impliciterrors/Organizer TRANSP leakage/2 | 1
impliciterrors/Organizer TRANSP leakage/3 | 1
impliciterrors/Organizer TRANSP leakage/4 | 1
impliciterrors/Organizer TRANSP leakage/5 | 1
impliciterrors/Organizer TRANSP leakage/6 | 1
impliciterrors/Organizer TRANSP leakage/7 | 1
impliciterrors/Recurrence expand with expand EXDATE/10 | 1
impliciterrors/Recurrence expand with expand EXDATE/1 | 1
impliciterrors/Recurrence expand with expand EXDATE/2 | 1
impliciterrors/Recurrence expand with expand EXDATE/3 | 1
impliciterrors/Recurrence expand with expand EXDATE/4 | 1
impliciterrors/Recurrence expand with expand EXDATE/6 | 1
impliciterrors/Recurrence expand with expand EXDATE/7 | 1
impliciterrors/Recurrence expand with expand EXDATE/8 | 1
impliciterrors/Recurrence expand with expand EXDATE/9 | 1
impliciterrors/Two EXDATEs/2 | 1
impliciterrors/Two EXDATEs/4 | 1
impliciterrors/Two EXDATEs/8 | 1
impliciterrors/Two EXDATEs/9 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/10 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/-1 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/11 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/12 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/14 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/2 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/3 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/4 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/6 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/7 | 1
implicitfreebusy/Organizer invites Attendee and checks free busy/8 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/-1 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/1 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/2 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/3 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/4 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/6 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/7 | 1
implicitfreebusy/Organizer invites auto-accept Attendee and checks free busy/8 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/10 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/-1 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/1 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/11 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/12 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/2 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/3 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/4 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/6 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/7 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/8 | 1
implicitfreebusy/Organizer invites auto-accept Attendee to one instance and checks free busy/9 | 1
implicitimip/Attempt to store externally organized event/2 | 1
implicitimip/Attempt to store local organized event with SCHEDULE-AGENT=SERVER and attendee/1 | 1
implicitimip/Attempt to store local organized event with SCHEDULE-AGENT=SERVER and attendee/2 | 1
implicitimip/Store externally organized event without matching attendee/2 | 1
implicitimip/Store externally organized event without matching attendee/4 | 1
implicitimip/Store externally organized event without matching attendee/6 | 1
implicitimip/Store local organized event S-A=NONE with attendee then get invite from local organizer/-1 | 1
implicitimip/Store local organized event S-A=NONE with attendee then get invite from local organizer/1 | 1
implicitimip/Store local organized event S-A=NONE with attendee then get invite from local organizer/2 | 1
implicitimip/Store local organized event S-A=NONE with attendee then get invite from local organizer/4 | 1
implicitimip/Store local organized event S-A=NONE with attendee then get invite from local organizer/5 | 1
implicitimip/Store local organized event S-A=NONE with attendee then get invite from local organizer/6 | 1
implicitimip/Store local organized event S-A=NONE without attendee then get invite from local organizer/-1 | 1
implicitimip/Store local organized event S-A=NONE without attendee then get invite from local organizer/1 | 1
implicitimip/Store local organized event S-A=NONE without attendee then get invite from local organizer/2 | 1
implicitimip/Store local organized event S-A=NONE without attendee then get invite from local organizer/4 | 1
implicitimip/Store local organized event S-A=NONE without attendee then get invite from local organizer/5 | 1
implicitimip/Store local organized event S-A=NONE without attendee then get invite from local organizer/6 | 1
implicitimip/Store local organized event without attendee then get invite from local organizer/-1 | 1
implicitimip/Store local organized event without attendee then get invite from local organizer/2 | 1
implicitimip/Store local organized event without attendee then get invite from local organizer/4 | 1
implicitimip/Store local organized event without attendee then get invite from local organizer/5 | 1
implicitimip/Store local organized event without attendee then get invite from local organizer/6 | 1
implicitimip/Store unorganized event then get invite from local organizer/-1 | 1
implicitimip/Store unorganized event then get invite from local organizer/1 | 1
implicitimip/Store unorganized event then get invite from local organizer/2 | 1
implicitimip/Store unorganized event then get invite from local organizer/4 | 1
implicitimip/Store unorganized event then get invite from local organizer/5 | 1
implicitimip/Store unorganized event then get invite from local organizer/6 | 1
implicitimip/Store unorganized event then get invite from local organizer/7 | 1
implicitimip/Store unorganized event then get invite from local organizer/8 | 1
implicitlarge/#1 Large invite/10 | 1
implicitlarge/#1 Large invite/11 | 1
implicitlarge/#1 Large invite/12 | 1
implicitlarge/#1 Large invite/13 | 1
implicitlarge/#1 Large invite/2 | 1
implicitlarge/#1 Large invite/3 | 1
implicitlarge/#1 Large invite/4 | 1
implicitlarge/#1 Large invite/5 | 1
implicitlarge/#1 Large invite/6 | 1
implicitlarge/#1 Large invite/7 | 1
implicitlarge/#1 Large invite/8 | 1
implicitlarge/#1 Large invite/9 | 1
implicitoptions/OPTIONS header/1 | 1
implicitoptions/OPTIONS header/2 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/10 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/-1 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/11 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/12 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/15 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/16 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/17 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/2 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/3 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/4 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/6 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/7 | 1
implicitpartstatchange/Organizer Change without prior refresh with Schedule-Tag/8 | 1
implicitpartstatchange/Recurrence/10 | 1
implicitpartstatchange/Recurrence/11 | 1
implicitpartstatchange/Recurrence/13 | 1
implicitpartstatchange/Recurrence/14 | 1
implicitpartstatchange/Recurrence/15 | 1
implicitpartstatchange/Recurrence/17 | 1
implicitpartstatchange/Recurrence/18 | 1
implicitpartstatchange/Recurrence/19 | 1
implicitpartstatchange/Recurrence/20 | 1
implicitpartstatchange/Recurrence/2 | 1
implicitpartstatchange/Recurrence/3 | 1
implicitpartstatchange/Recurrence/4 | 1
implicitpartstatchange/Recurrence/6 | 1
implicitpartstatchange/Recurrence/7 | 1
implicitpartstatchange/Recurrence/8 | 1
implicitpartstatchange/Recurrence/9 | 1
implicitpartstatchange/Simple Changes/10 | 1
implicitpartstatchange/Simple Changes/11 | 1
implicitpartstatchange/Simple Changes/13 | 1
implicitpartstatchange/Simple Changes/14 | 1
implicitpartstatchange/Simple Changes/15 | 1
implicitpartstatchange/Simple Changes/17 | 1
implicitpartstatchange/Simple Changes/18 | 1
implicitpartstatchange/Simple Changes/19 | 1
implicitpartstatchange/Simple Changes/20 | 1
implicitpartstatchange/Simple Changes/2 | 1
implicitpartstatchange/Simple Changes/3 | 1
implicitpartstatchange/Simple Changes/4 | 1
implicitpartstatchange/Simple Changes/6 | 1
implicitpartstatchange/Simple Changes/7 | 1
implicitpartstatchange/Simple Changes/8 | 1
implicitpartstatchange/Simple Changes/9 | 1
implicitprivateevents/Simple Event/13 | 1
implicitprivateevents/Simple Event/2 | 1
implicitprivateevents/Simple Event/3 | 1
implicitprivateevents/Simple Event/4 | 1
implicitprivateevents/Simple Event/6 | 1
implicitprivateevents/Simple Event/7 | 1
implicitprivateevents/Simple Event/8 | 1
implicitpublicproperties/Simple Event/-1 | 1
implicitpublicproperties/Simple Event/2 | 1
implicitpublicproperties/Simple Event/3 | 1
implicitpublicproperties/Simple Event/4 | 1
implicitpublicproperties/Simple Event/5 | 1
implicitpublicproperties/Simple Event/6 | 1
implicitpublicproperties/Simple Event/7 | 1
implicitpublicproperties/Simple Event/8 | 1
implicitrecur1/All-day override/-1 | 1
implicitrecur1/All-day override/2 | 1
implicitrecur1/All-day override/3 | 1
implicitrecur1/All-day override/4 | 1
implicitrecur1/All-day override/7 | 1
implicitrecur1/All-day override/8 | 1
implicitrecur1/All-day override/9 | 1
implicitrecur1/Attendee Instance Delete/10 | 1
implicitrecur1/Attendee Instance Delete/-1 | 1
implicitrecur1/Attendee Instance Delete/11 | 1
implicitrecur1/Attendee Instance Delete/12 | 1
implicitrecur1/Attendee Instance Delete/2 | 1
implicitrecur1/Attendee Instance Delete/3 | 1
implicitrecur1/Attendee Instance Delete/4 | 1
implicitrecur1/Attendee Instance Delete/6 | 1
implicitrecur1/Attendee Instance Delete/7 | 1
implicitrecur1/Attendee Instance Delete/8 | 1
implicitrecur1/Cancel Override/2 | 1
implicitrecur1/Cancel Override/3 | 1
implicitrecur1/Cancel Override/4 | 1
implicitrecur1/Cancel Override/7 | 1
implicitrecur1/Cancel Override/8 | 1
implicitrecur1/Override only in Request/-1 | 1
implicitrecur1/Override only in Request/12 | 1
implicitrecur1/Override only in Request/13 | 1
implicitrecur1/Override only in Request/14 | 1
implicitrecur1/Override only in Request/17 | 1
implicitrecur1/Override only in Request/18 | 1
implicitrecur1/Override only in Request/19 | 1
implicitrecur1/Override only in Request/2 | 1
implicitrecur1/Override only in Request/3 | 1
implicitrecur1/Override only in Request/4 | 1
implicitrecur1/Override only in Request/7 | 1
implicitrecur1/Override only in Request/8 | 1
implicitrecur1/Override only in Request/9 | 1
implicitrecur1/RRULE Addition/Removal/10 | 1
implicitrecur1/RRULE Addition/Removal/-1 | 1
implicitrecur1/RRULE Addition/Removal/11 | 1
implicitrecur1/RRULE Addition/Removal/12 | 1
implicitrecur1/RRULE Addition/Removal/13 | 1
implicitrecur1/RRULE Addition/Removal/14 | 1
implicitrecur1/RRULE Addition/Removal/15 | 1
implicitrecur1/RRULE Addition/Removal/17 | 1
implicitrecur1/RRULE Addition/Removal/18 | 1
implicitrecur1/RRULE Addition/Removal/19 | 1
implicitrecur1/RRULE Addition/Removal/20 | 1
implicitrecur1/RRULE Addition/Removal/2 | 1
implicitrecur1/RRULE Addition/Removal/21 | 1
implicitrecur1/RRULE Addition/Removal/22 | 1
implicitrecur1/RRULE Addition/Removal/3 | 1
implicitrecur1/RRULE Addition/Removal/4 | 1
implicitrecur1/RRULE Addition/Removal/6 | 1
implicitrecur1/RRULE Addition/Removal/7 | 1
implicitrecur1/RRULE Addition/Removal/8 | 1
implicitrecur1/RRULE Changes/-1 | 1
implicitrecur1/RRULE Changes/2 | 1
implicitrecur1/RRULE Changes/3 | 1
implicitrecur1/RRULE Changes/4 | 1
implicitrecur1/RRULE Changes/6 | 1
implicitrecur1/RRULE Changes/7 | 1
implicitrecur1/RRULE Changes/8 | 1
implicitrecur1/RRULE Truncation/-1 | 1
implicitrecur1/RRULE Truncation/11 | 1
implicitrecur1/RRULE Truncation/12 | 1
implicitrecur1/RRULE Truncation/13 | 1
implicitrecur1/RRULE Truncation/2 | 1
implicitrecur1/RRULE Truncation/3 | 1
implicitrecur1/RRULE Truncation/4 | 1
implicitrecur1/RRULE Truncation/6 | 1
implicitrecur1/RRULE Truncation/7 | 1
implicitrecur1/RRULE Truncation/8 | 1
implicitrecur1/RRULE with DTSTART change/-1 | 1
implicitrecur1/RRULE with DTSTART change/11 | 1
implicitrecur1/RRULE with DTSTART change/12 | 1
implicitrecur1/RRULE with DTSTART change/13 | 1
implicitrecur1/RRULE with DTSTART change/2 | 1
implicitrecur1/RRULE with DTSTART change/3 | 1
implicitrecur1/RRULE with DTSTART change/4 | 1
implicitrecur1/RRULE with DTSTART change/6 | 1
implicitrecur1/RRULE with DTSTART change/7 | 1
implicitrecur1/RRULE with DTSTART change/8 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/10 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/11 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/2 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/3 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/4 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/5 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/6 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/7 | 1
implicitrecur2/Attendee decline instance, then organizer cancel/9 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/10 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/11 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/2 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/3 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/4 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/5 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/6 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/7 | 1
implicitrecur2/Attendee remove instance, then organizer cancel/9 | 1
implicitrecur2/Initial event/2 | 1
implicitrecur2/Initial event/3 | 1
implicitrecur2/Initial event/4 | 1
implicitrecur2/Initial event/6 | 1
implicitrecur2/Initial event/7 | 1
implicitrecur2/Initial event/8 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/10 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/11 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/2 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/3 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/4 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/6 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/7 | 1
implicitrecur2/Organizer invites other Attendee to one instance only/9 | 1
implicitrecur2/Organizer override remove/10 | 1
implicitrecur2/Organizer override remove/11 | 1
implicitrecur2/Organizer override remove/2 | 1
implicitrecur2/Organizer override remove/3 | 1
implicitrecur2/Organizer override remove/4 | 1
implicitrecur2/Organizer override remove/5 | 1
implicitrecur2/Organizer override remove/6 | 1
implicitrecur2/Organizer override remove/7 | 1
implicitrecur2/Organizer override remove/9 | 1
implicitrecur2/Organizer truncate/2 | 1
implicitrecur2/Organizer truncate/3 | 1
implicitrecur2/Organizer truncate/4 | 1
implicitrecur2/Organizer truncate/6 | 1
implicitrecur2/Organizer truncate/7 | 1
implicitrecur2/Organizer truncate/9 | 1
implicitreschedule/Non-recurring/10 | 1
implicitreschedule/Non-recurring/-1 | 1
implicitreschedule/Non-recurring/11 | 1
implicitreschedule/Non-recurring/12 | 1
implicitreschedule/Non-recurring/2 | 1
implicitreschedule/Non-recurring/3 | 1
implicitreschedule/Non-recurring/4 | 1
implicitreschedule/Non-recurring/6 | 1
implicitreschedule/Non-recurring/7 | 1
implicitreschedule/Non-recurring/8 | 1
implicitreschedule/Recurring overridden/10 | 1
implicitreschedule/Recurring overridden/-1 | 1
implicitreschedule/Recurring overridden/11 | 1
implicitreschedule/Recurring overridden/12 | 1
implicitreschedule/Recurring overridden/2 | 1
implicitreschedule/Recurring overridden/3 | 1
implicitreschedule/Recurring overridden/4 | 1
implicitreschedule/Recurring overridden/6 | 1
implicitreschedule/Recurring overridden/7 | 1
implicitreschedule/Recurring overridden/8 | 1
implicitscenario1/Alarms/-1 | 1
implicitscenario1/Alarms/11 | 1
implicitscenario1/Alarms/12 | 1
implicitscenario1/Alarms/13 | 1
implicitscenario1/Alarms/18 | 1
implicitscenario1/Alarms/2 | 1
implicitscenario1/Alarms/22 | 1
implicitscenario1/Alarms/23 | 1
implicitscenario1/Alarms/3 | 1
implicitscenario1/Alarms/4 | 1
implicitscenario1/Alarms/6 | 1
implicitscenario1/Alarms/7 | 1
implicitscenario1/Alarms/8 | 1
implicitscenario1/Attendee Delete/10 | 1
implicitscenario1/Attendee Delete/11 | 1
implicitscenario1/Attendee Delete/12 | 1
implicitscenario1/Attendee Delete/2 | 1
implicitscenario1/Attendee Delete/3 | 1
implicitscenario1/Attendee Delete/4 | 1
implicitscenario1/Attendee Delete/6 | 1
implicitscenario1/Attendee Delete/7 | 1
implicitscenario1/Attendee Delete/8 | 1
implicitscenario1/Duplicate Attendee/10 | 1
implicitscenario1/Duplicate Attendee/2 | 1
implicitscenario1/Duplicate Attendee/3 | 1
implicitscenario1/Duplicate Attendee/4 | 1
implicitscenario1/Duplicate Attendee/6 | 1
implicitscenario1/Duplicate Attendee/7 | 1
implicitscenario1/Duplicate Attendee/8 | 1
implicitscenario1/No master Organizer/11 | 1
implicitscenario1/No master Organizer/12 | 1
implicitscenario1/No master Organizer/13 | 1
implicitscenario1/No master Organizer/2 | 1
implicitscenario1/No master Organizer/3 | 1
implicitscenario1/No master Organizer/4 | 1
implicitscenario1/No master Organizer/6 | 1
implicitscenario1/No master Organizer/7 | 1
implicitscenario1/No master Organizer/8 | 1
implicitscenario1/No X- properties/10 | 1
implicitscenario1/No X- properties/-1 | 1
implicitscenario1/No X- properties/2 | 1
implicitscenario1/No X- properties/3 | 1
implicitscenario1/No X- properties/4 | 1
implicitscenario1/No X- properties/9 | 1
implicitscenario1/Organizer Delete/11 | 1
implicitscenario1/Organizer Delete/13 | 1
implicitscenario1/Organizer Delete/14 | 1
implicitscenario1/Organizer Delete/2 | 1
implicitscenario1/Organizer Delete/3 | 1
implicitscenario1/Organizer Delete/4 | 1
implicitscenario1/Organizer Delete/6 | 1
implicitscenario1/Organizer Delete/7 | 1
implicitscenario1/Organizer Delete/8 | 1
implicitscenario1/Per-Attendee X- properties/10 | 1
implicitscenario1/Per-Attendee X- properties/-1 | 1
implicitscenario1/Per-Attendee X- properties/11 | 1
implicitscenario1/Per-Attendee X- properties/2 | 1
implicitscenario1/Per-Attendee X- properties/3 | 1
implicitscenario1/Per-Attendee X- properties/4 | 1
implicitscenario1/Per-Attendee X- properties/5 | 1
implicitscenario1/Per-Attendee X- properties/6 | 1
implicitscenario1/Per-Attendee X- properties/7 | 1
implicitscenario1/Per-Attendee X- properties/9 | 1
implicitscenario1/Recurring Alarms/10 | 1
implicitscenario1/Recurring Alarms/-1 | 1
implicitscenario1/Recurring Alarms/12 | 1
implicitscenario1/Recurring Alarms/13 | 1
implicitscenario1/Recurring Alarms/2 | 1
implicitscenario1/Recurring Alarms/3 | 1
implicitscenario1/Recurring Alarms/4 | 1
implicitscenario1/Recurring Alarms/6 | 1
implicitscenario1/Recurring Alarms/7 | 1
implicitscenario1/Recurring Alarms/8 | 1
implicitscenario1/Simple Changes/-1 | 1
implicitscenario1/Simple Changes/11 | 1
implicitscenario1/Simple Changes/13 | 1
implicitscenario1/Simple Changes/14 | 1
implicitscenario1/Simple Changes/16 | 1
implicitscenario1/Simple Changes/18 | 1
implicitscenario1/Simple Changes/19 | 1
implicitscenario1/Simple Changes/2 | 1
implicitscenario1/Simple Changes/22 | 1
implicitscenario1/Simple Changes/3 | 1
implicitscenario1/Simple Changes/5 | 1
implicitscenario1/Simple Changes/7 | 1
implicitscenario1/Simple Changes/8 | 1
implicitscenario1/TZID reset/-1 | 1
implicitscenario1/TZID reset/2 | 1
implicitscenario1/TZID reset/3 | 1
implicitscenario1/TZID reset/4 | 1
implicitscenario1/TZID reset/6 | 1
implicitscenario1/TZID reset/7 | 1
implicitscenario1/TZID reset/8 | 1
implicitscenario1/TZID reset/9 | 1
implicitscenario2/DST Shift change/10 | 1
implicitscenario2/DST Shift change/-1 | 1
implicitscenario2/DST Shift change/11 | 1
implicitscenario2/DST Shift change/12 | 1
implicitscenario2/DST Shift change/2 | 1
implicitscenario2/DST Shift change/3 | 1
implicitscenario2/DST Shift change/4 | 1
implicitscenario2/DST Shift change/6 | 1
implicitscenario2/DST Shift change/7 | 1
implicitscenario2/DST Shift change/8 | 1
implicitscenario2/Simple Changes/-1 | 1
implicitscenario2/Simple Changes/11 | 1
implicitscenario2/Simple Changes/12 | 1
implicitscenario2/Simple Changes/13 | 1
implicitscenario2/Simple Changes/14 | 1
implicitscenario2/Simple Changes/17 | 1
implicitscenario2/Simple Changes/2 | 1
implicitscenario2/Simple Changes/3 | 1
implicitscenario2/Simple Changes/4 | 1
implicitscenario2/Simple Changes/6 | 1
implicitscenario2/Simple Changes/7 | 1
implicitscenario2/Simple Changes/8 | 1
implicitscenario3/First cancel/2 | 1
implicitscenario3/First cancel/3 | 1
implicitscenario3/First cancel/4 | 1
implicitscenario3/First cancel/6 | 1
implicitscenario3/First cancel/8 | 1
implicitscenario3/Initial event/2 | 1
implicitscenario3/Initial event/3 | 1
implicitscenario3/Initial event/4 | 1
implicitscenario3/Initial event/6 | 1
implicitscenario3/Initial event/7 | 1
implicitscenario3/Initial event/8 | 1
implicitscenario3/Second cancel/2 | 1
implicitscenario3/Second cancel/3 | 1
implicitscenario3/Second cancel/4 | 1
implicitscenario3/Second cancel/6 | 1
implicitscenario3/Second cancel/8 | 1
implicitscheduleagent/Organizer CLIENT/7 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/10 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/-1 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/11 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/5 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/6 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/7 | 1
implicitscheduleagent/Organizer CLIENT->SERVER/9 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/10 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/-1 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/11 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/12 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/13 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/14 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/2 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/3 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/4 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/6 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start)/9 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/10 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/-1 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/11 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/12 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/13 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/2 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/3 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/4 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/5 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/6 | 1
implicitscheduleagent/Organizer CLIENT->SERVER (no ATTENDEE at start recurring)/9 | 1
implicitscheduleagent/Organizer SERVER->NONE, no matching ATTENDEE/1 | 1
implicitscheduleagent/Organizer SERVER->NONE, no matching ATTENDEE/2 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/-1 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/11 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/12 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/13 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/15 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/16 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/2 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/21 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/22 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/23 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/25 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/26 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/3 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/31 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/33 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/34 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/35 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/4 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/6 | 1
implicitscheduleagent/Simple invite of three attendees - two initially not auto-scheduled/7 | 1
implicitscheduletag/Update to resource with schedule-tag behavior/3a | 1
implicitscheduletag/Update to resource with schedule-tag behavior/3b | 1
implicitsecurity/Prevent ATTENDEE party crash/2 | 1
implicitsecurity/Prevent ATTENDEE party crash/3 | 1
implicitsecurity/Prevent ATTENDEE party crash/4 | 1
implicitsecurity/Prevent ATTENDEE party crash/7 | 1
implicitsecurity/Prevent ATTENDEE party crash/8 | 1
implicitsecurity/Prevent ATTENDEE party crash/9 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/10 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/11 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/12 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/13 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/2 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/3 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/4 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/6 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - an attendee) via overwrite/8 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/10 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/11 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/12 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/13 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/2 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/3 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/4 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/6 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER (someone else - not an attendee) via overwrite/8 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/10 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/11 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/12 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/13 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/2 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/3 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/4 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/6 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/7 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via new event/9 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/10 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/11 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/12 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/13 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/2 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/3 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/4 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/6 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/8 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER via overwrite/9 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/10 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/2 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/3 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/5 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/6 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/7 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/8 | 1
implicitsecurity/Prevent ATTENDEE switching ORGANIZER without them as ATTENDEE via overwrite/9 | 1
implicitsecurity/Prevent ORGANIZER forgeries/10 | 1
implicitsecurity/Prevent ORGANIZER forgeries/2 | 1
implicitsecurity/Prevent ORGANIZER forgeries/3 | 1
implicitsecurity/Prevent ORGANIZER forgeries/4 | 1
implicitsecurity/Prevent ORGANIZER forgeries/7 | 1
implicitsecurity/Prevent ORGANIZER forgeries/8 | 1
implicitsecurity/Prevent ORGANIZER forgeries/9 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/10 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/2 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/3 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/5 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/7 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/8 | 1
implicitsecurity/Prevent ORGANIZER switching ORGANIZER without them as ATTENDEE via overwrite/9 | 1
implicitsequence/Lower Sequence/12 | 1
implicitsequence/Lower Sequence/13 | 1
implicitsequence/Lower Sequence/2 | 1
implicitsequence/Lower Sequence/3 | 1
implicitsequence/Lower Sequence/4 | 1
implicitsequence/Lower Sequence/7 | 1
implicitsequence/Lower Sequence/8 | 1
implicitsequence/Lower Sequence/9 | 1
implicitsequence/Recreate with Lower Sequence/-1 | 1
implicitsequence/Recreate with Lower Sequence/11 | 1
implicitsequence/Recreate with Lower Sequence/12 | 1
implicitsequence/Recreate with Lower Sequence/13 | 1
implicitsequence/Recreate with Lower Sequence/2 | 1
implicitsequence/Recreate with Lower Sequence/3 | 1
implicitsequence/Recreate with Lower Sequence/4 | 1
implicitsequence/Recreate with Lower Sequence/8 | 1
implicitsequence/Recreate with Lower Sequence/9 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/11 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/12 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/13 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/15 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/2 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/3 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/4 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/6 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/7 | 1
implicittimezones/Change event spanning a DST transition with R-IDs on either side/8 | 1
implicittodo/Attendee Delete/10 | 1
implicittodo/Attendee Delete/11 | 1
implicittodo/Attendee Delete/12 | 1
implicittodo/Attendee Delete/2 | 1
implicittodo/Attendee Delete/3 | 1
implicittodo/Attendee Delete/4 | 1
implicittodo/Attendee Delete/6 | 1
implicittodo/Attendee Delete/7 | 1
implicittodo/Attendee Delete/8 | 1
implicittodo/Client removing properties fix/10 | 1
implicittodo/Client removing properties fix/-1 | 1
implicittodo/Client removing properties fix/2 | 1
implicittodo/Client removing properties fix/3 | 1
implicittodo/Client removing properties fix/4 | 1
implicittodo/Client removing properties fix/6 | 1
implicittodo/Client removing properties fix/7 | 1
implicittodo/Client removing properties fix/8 | 1
implicittodo/Client removing properties fix/9 | 1
implicittodo/Organizer Delete/11 | 1
implicittodo/Organizer Delete/12 | 1
implicittodo/Organizer Delete/13 | 1
implicittodo/Organizer Delete/2 | 1
implicittodo/Organizer Delete/3 | 1
implicittodo/Organizer Delete/4 | 1
implicittodo/Organizer Delete/6 | 1
implicittodo/Organizer Delete/7 | 1
implicittodo/Organizer Delete/8 | 1
implicittodo/Per-attendee completed/10 | 1
implicittodo/Per-attendee completed/-1 | 1
implicittodo/Per-attendee completed/11 | 1
implicittodo/Per-attendee completed/13 | 1
implicittodo/Per-attendee completed/14 | 1
implicittodo/Per-attendee completed/15 | 1
implicittodo/Per-attendee completed/16 | 1
implicittodo/Per-attendee completed/18 | 1
implicittodo/Per-attendee completed/2 | 1
implicittodo/Per-attendee completed/3 | 1
implicittodo/Per-attendee completed/4 | 1
implicittodo/Per-attendee completed/6 | 1
implicittodo/Per-attendee completed/7 | 1
implicittodo/Per-attendee completed/9 | 1
implicittodo/Simple Changes/11 | 1
implicittodo/Simple Changes/12 | 1
implicittodo/Simple Changes/13 | 1
implicittodo/Simple Changes/15 | 1
implicittodo/Simple Changes/16 | 1
implicittodo/Simple Changes/17 | 1
implicittodo/Simple Changes/19 | 1
implicittodo/Simple Changes/2 | 1
implicittodo/Simple Changes/3 | 1
implicittodo/Simple Changes/4 | 1
implicittodo/Simple Changes/6 | 1
implicittodo/Simple Changes/7 | 1
implicittodo/Simple Changes/8 | 1
implicitxdash/Attendee to Organizer/10 | 1
implicitxdash/Attendee to Organizer/-1 | 1
implicitxdash/Attendee to Organizer/11 | 1
implicitxdash/Attendee to Organizer/13 | 1
implicitxdash/Attendee to Organizer/14 | 1
implicitxdash/Attendee to Organizer/15 | 1
implicitxdash/Attendee to Organizer/16 | 1
implicitxdash/Attendee to Organizer/17 | 1
implicitxdash/Attendee to Organizer/18 | 1
implicitxdash/Attendee to Organizer/19 | 1
implicitxdash/Attendee to Organizer/20 | 1
implicitxdash/Attendee to Organizer/2 | 1
implicitxdash/Attendee to Organizer/21 | 1
implicitxdash/Attendee to Organizer/22 | 1
implicitxdash/Attendee to Organizer/23 | 1
implicitxdash/Attendee to Organizer/24 | 1
implicitxdash/Attendee to Organizer/25 | 1
implicitxdash/Attendee to Organizer/26 | 1
implicitxdash/Attendee to Organizer/27 | 1
implicitxdash/Attendee to Organizer/28 | 1
implicitxdash/Attendee to Organizer/29 | 1
implicitxdash/Attendee to Organizer/3 | 1
implicitxdash/Attendee to Organizer/4 | 1
implicitxdash/Attendee to Organizer/5 | 1
implicitxdash/Attendee to Organizer/6 | 1
implicitxdash/Attendee to Organizer/7 | 1
implicitxdash/Attendee to Organizer/8 | 1
implicitxdash/Attendee to Organizer/9 | 1
implicitxdash/Organizer to Attendee/10 | 1
implicitxdash/Organizer to Attendee/-1 | 1
implicitxdash/Organizer to Attendee/11 | 1
implicitxdash/Organizer to Attendee/12 | 1
implicitxdash/Organizer to Attendee/2 | 1
implicitxdash/Organizer to Attendee/3 | 1
implicitxdash/Organizer to Attendee/4 | 1
implicitxdash/Organizer to Attendee/5 | 1
implicitxdash/Organizer to Attendee/6 | 1
implicitxdash/Organizer to Attendee/7 | 1
implicitxdash/Organizer to Attendee/8 | 1
json/Freebusy json/2 | 1
mkcalendar/MKCALENDAR with body/3 | 1
nonascii/Non-ascii calendar data/1 | 1
nonascii/Non-ascii calendar data/2 | 1
nonascii/Non-ascii calendar data/3 | 1
nonascii/Non-ascii calendar data/4 | 1
nonascii/Non-ascii calendar data/5 | 1
nonascii/Non-utf-8 calendar data/1 | 1
nonascii/Non-utf-8 calendar data/2 | 1
nonascii/Non-utf-8 calendar data/3 | 1
nonascii/POSTs/1 | 1
nonascii/POSTs/2 | 1
nonascii/PUT with CN re-write/1 | 1
nonascii/PUT with CN re-write/2 | 1
options/OPTIONS+DAV/1 | 1
options/OPTIONS+DAV/2 | 1
polls/PUT VPOLL - no scheduling/2 | 1
polls/PUT VPOLL - simple scheduling/-1 | 1
polls/PUT VPOLL - simple scheduling/2 | 1
polls/PUT VPOLL - simple scheduling/3 | 1
polls/PUT VPOLL - simple scheduling/4 | 1
polls/PUT VPOLL - simple scheduling/5 | 1
polls/PUT VPOLL - simple scheduling/6 | 1
polls/PUT VPOLL - simple scheduling/7 | 1
polls/PUT VPOLL - simple scheduling/8 | 1
polls/PUT VPOLL - Two voter scheduling/-1 | 1
polls/PUT VPOLL - Two voter scheduling/2 | 1
polls/PUT VPOLL - Two voter scheduling/3 | 1
polls/PUT VPOLL - Two voter scheduling/4 | 1
polls/PUT VPOLL - Two voter scheduling/5 | 1
polls/PUT VPOLL - Two voter scheduling/6 | 1
polls/PUT VPOLL - Two voter scheduling/7 | 1
polls/PUT VPOLL - Two voter scheduling/8 | 1
polls/PUT VPOLL - Two voter scheduling/9 | 1
prefer/representation schedule PUT/1 | 1
prefer/representation schedule PUT/2 | 1
prefer/representation schedule PUT/3 | 1
prefer/representation schedule PUT/4 | 1
prefer/representation schedule PUT/5 | 1
propfind/Depth:infinity disabled/2 | 1
propfind/Depth:infinity disabled/3 | 1
propfind/Depth:infinity disabled/4 | 1
propfind/Depth:infinity disabled/5 | 1
propfind/Depth:infinity disabled/6 | 1
propfind/Depth:infinity disabled/7 | 1
propfind/prop all/3 | 1
propfind/prop names/3 | 1
propfind/regular calendar prop finds/3 | 1
propfind/regular home prop finds/3 | 1
proppatch/prop patches/4 | 1
proppatch/prop patch property attributes/1 | 1
proppatch/prop patch property attributes/2 | 1
put/PUTs with ^ parameter encoding/1 | 1
put/PUT VEVENT/1 | 1
put/PUT with Content-Type parameters/3 | 1
put/PUT with relaxed parsing/1 | 1
put/PUT with relaxed parsing/2 | 1
put/PUT with X- using VALUE != TEXT/1 | 1
quota/Quota after collection create/2 | 1
quota/Quota after collection create, and PUT/3 | 1
quota/Quota after empty collection delete/2 | 1
quota/Quota after non-empty collection delete/1 | 1
quota/Quota after non-empty collection delete/2 | 1
quota/Quota enabled by default on calendar home and below only/3 | 1
quota/Quota enabled by default on calendar home and below only/4 | 1
reports/alarm time-range query reports/1 | 1
reports/alarm time-range query reports/3 | 1
reports/alarm time-range query reports/4 | 1
reports/alarm time-range query reports/5 | 1
reports/basic query reports/11 | 1
reports/basic query reports/13 | 1
reports/basic query reports/15 | 1
reports/basic query reports/16 | 1
reports/basic query reports/17a | 1
reports/basic query reports/19a | 1
reports/basic query reports/21 | 1
reports/basic query reports/23 | 1
reports/basic query reports/24 | 1
reports/basic query reports/25 | 1
reports/basic query reports/2a | 1
reports/basic query reports/3 | 1
reports/basic query reports/4 | 1
reports/basic query reports/5 | 1
reports/basic query reports/6 | 1
reports/basic query reports/7 | 1
reports/basic query reports/8 | 1
reports/basic query reports/9 | 1
reports/free-busy reports/1 | 1
reports/free-busy reports/2 | 1
reports/limit/expand recurrence in reports/10 | 1
reports/limit/expand recurrence in reports/11 | 1
reports/limit/expand recurrence in reports/12 | 1
reports/limit/expand recurrence in reports/9a | 1
reports/query reports with filtered data/1 | 1
reports/query reports with filtered data/2 | 1
reports/time-range query reports/10 | 1
reports/time-range query reports/11 | 1
reports/time-range query reports/12a | 1
reports/time-range query reports/16 | 1
reports/time-range query reports/19a | 1
reports/time-range query reports/2 | 1
reports/time-range query reports/21a | 1
reports/time-range query reports/23a | 1
reports/time-range query reports/4 | 1
reports/time-range query reports/6 | 1
reports/time-range query reports/7 | 1
reports/time-range query reports/8 | 1
rscale/Bad data/2 | 1
rscale/Chinese MonthDay Skip/1 | 1
rscale/Chinese MonthDay Skip/2 | 1
rscale/Chinese MonthDay Skip/3 | 1
rscale/Chinese MonthDay Skip/4 | 1
rscale/Chinese Monthly Skip/1 | 1
rscale/Chinese Monthly Skip/2 | 1
rscale/Chinese Monthly Skip/3 | 1
rscale/Chinese Monthly Skip/4 | 1
rscale/Ethiopic, Last Day Of Year/1 | 1
rscale/Gregorian Monthly Skip/1 | 1
rscale/Gregorian Monthly Skip/2 | 1
rscale/Gregorian Monthly Skip/3 | 1
rscale/Gregorian Monthly Skip/4 | 1
rscale/Gregorian Yearly Skip/1 | 1
rscale/Gregorian Yearly Skip/2 | 1
rscale/Gregorian Yearly Skip/3 | 1
rscale/Gregorian Yearly Skip/4 | 1
scheduleimplicit-compatability/OPTIONS header/1 | 1
scheduleimplicit-compatability/OPTIONS header/2 | 1
scheduleimplicit-compatability/POSTs ignored/1 | 1
schedulenomore/SCHEDULE Fails/1 | 1
schedulepost/POST Errors/10 | 1
schedulepost/POST Errors/1 | 1
schedulepost/POST Errors/11 | 1
schedulepost/POST Errors/2 | 1
schedulepost/POST Errors/3 | 1
schedulepost/POST Errors/4 | 1
schedulepost/POST Errors/5 | 1
schedulepost/POST Errors/6 | 1
schedulepost/POST Errors/7 | 1
schedulepost/POST Errors/8 | 1
schedulepost/POST Errors/9 | 1
schedulepost/POSTs/1 | 1
schedulepost/POSTs/5 | 1
schedulepost/POSTs/6 | 1
schedulepost/POSTs free busy/1 | 1
schedulepost/POSTs free busy/2 | 1
schedulepost/POSTs free busy/3 | 1
schedulepost/POSTs free busy/4 | 1
schedulepost/Reports on Inbox/Outbox/3 | 1
schedulepost/Reports on Inbox/Outbox/4 | 1
schedulepost/Reports on Inbox/Outbox/5 | 1
schedulepost/Reports on Inbox/Outbox/6 | 1
scheduleprops/free-busy-set/10 | 1
scheduleprops/free-busy-set/1 | 1
scheduleprops/free-busy-set/3 | 1
scheduleprops/free-busy-set/4 | 1
scheduleprops/free-busy-set/9 | 1
servertoserverincoming/POST Errors/1 | 1
servertoserverincoming/POST Errors/2 | 1
servertoserverincoming/POST Errors/3 | 1
servertoserverincoming/POST Errors/4 | 1
servertoserverincoming/POST Errors/5 | 1
servertoserverincoming/POST Errors/6 | 1
servertoserverincoming/POST free-busy/1 | 1
servertoserverincoming/POST free-busy/2 | 1
servertoserverincoming/POST invite one user/1 | 1
servertoserverincoming/POST invite one user/2 | 1
servertoserverincoming/POST invite two users/1 | 1
servertoserverincoming/POST invite two users/2 | 1
servertoserverincoming/POST invite two users/3 | 1
servertoserveroutgoing/POST free-busy/1 | 1
servertoserveroutgoing/POST invite/1 | 1
sync-report/simple reports - diff token - no props - calendar depth | 1
sync-report/simple reports - diff token - no props - calendar depth:1/1 | 1
sync-report/simple reports - diff token - props/1 | 1
sync-report/simple reports - empty inbox/1 | 1
sync-report/simple reports - empty token - no props/1 | 1
sync-report/simple reports - empty token - no props/13 | 1
sync-report/simple reports - empty token - no props/5 | 1
sync-report/simple reports - empty token - no props/9 | 1
sync-report/simple reports - empty token - props/1 | 1
sync-report/simple reports - empty token - props/2 | 1
sync-report/simple reports - empty token - props/3 | 1
sync-report/simple reports - empty token - props/4 | 1
sync-report/simple reports - sync-level/7 | 1
sync-report/simple reports - valid token/1 | 1
sync-report/support-report-set/sync-token property/1 | 1
sync-report/support-report-set/sync-token property/2 | 1
timezonestdservice/Expand/1 | 1
timezonestdservice/Expand/2 | 1
timezonestdservice/Expand/3 | 1
timezonestdservice/Expand/4 | 1
timezonestdservice/GET well-known/1 | 1
timezonestdservice/Invalid query action=expand/10 | 1
timezonestdservice/Invalid query action=expand/1 | 1
timezonestdservice/Invalid query action=expand/2 | 1
timezonestdservice/Invalid query action=expand/3 | 1
timezonestdservice/Invalid query action=expand/4 | 1
timezonestdservice/Invalid query action=expand/5 | 1
timezonestdservice/Invalid query action=expand/6 | 1
timezonestdservice/Invalid query action=expand/7 | 1
timezonestdservice/Invalid query action=expand/8 | 1
timezonestdservice/Invalid query action=expand/9 | 1
timezonestdservice/Invalid query action=find/1 | 1
timezonestdservice/Invalid query action=find/2 | 1
timezonestdservice/Invalid query action=find/3 | 1
timezonestdservice/Invalid query action=get/1 | 1
timezonestdservice/Invalid query action=get/2 | 1
timezonestdservice/Non-query GET/1 | 1
timezonestdservice/PROPFIND timezone-service-set/1 | 1
timezonestdservice/Query action=get/1 | 1
timezonestdservice/Query action=get/2 | 1
timezonestdservice/Query action=get/3 | 1
timezonestdservice/Query bogus parameters/1 | 1
timezonestdservice/Query bogus parameters/2 | 1
timezonestdservice/Query method=capabilities/1 | 1
timezonestdservice/Query method=find/1 | 1
timezonestdservice/Query method=find/2 | 1
timezonestdservice/Query method=find/3 | 1
timezonestdservice/Query method=find/4 | 1
timezonestdservice/Query method=find/5 | 1
timezonestdservice/Query method=find/6 | 1
timezonestdservice/Query method=find/7 | 1
timezonestdservice/Query method=find/8 | 1
timezonestdservice/Query method=find/9 | 1
timezonestdservice/Query method=list/1 | 1
timezones/Timezone cache/2 | 1
timezones/Timezone cache/4 | 1
timezones/Timezone cache - aliases/2 | 1
timezones/Timezone cache - aliases/4 | 1
timezones/Timezone properties/6 | 1
webcal/GET on calendar collection after DELETE/1 | 1
webcal/GET on calendar collection after DELETE/2 | 1
webcal/GET on calendar collection after initial PUT/1 | 1
webcal/GET on calendar collection after initial PUT/2 | 1
webcal/GET on calendar collection after PUT/1 | 1
webcal/GET on calendar collection after PUT/2 | 1
webcal/GET on empty calendar collection/1 | 1
webcal/GET on empty calendar collection/2 | 1
well-known/Simple GET tests/3 | 1
well-known/Simple GET tests/4 | 1
well-known/Simple PROPFIND tests/1 | 1
well-known/Simple PROPFIND tests/2 | 1
well-known/Simple PROPFIND tests/3 | 1
well-known/Simple PROPFIND tests/4 | 1
well-known/Simple PROPFIND tests/5 | 1
well-known/Simple PROPFIND tests/6 | 1
EOF

sub init
{
    my $cassini = Cassandane::Cassini->instance();
    $basedir = $cassini->val('caldavtester', 'basedir');
    return unless defined $basedir;
    $basedir = abs_path($basedir);

    my $supp = $cassini->val('caldavtester', 'suppress-caldav',
                             '');
    map { $suppressed{$_} = 1; } split(/\s+/, $supp);

    foreach my $row (split /\n/, $KNOWN_ERRORS) {
        next if $row =~ m/^\s*\#/;
        next unless $row =~ m/\S/;
        my ($key, @items) = split /\s*\|\s*/, $row;
        $expected{$key} = \@items;
    }

    $binary = "$basedir/testcaldav.py";
    $testdir = "$basedir/scripts/tests/CalDAV";
}
init;

sub new
{
    my $class = shift;

    my $buildinfo = Cassandane::BuildInfo->new();

    if (not defined $basedir or not $buildinfo->get('component', 'httpd')) {
        # don't bother setting up, we're not running tests anyway
        return $class->SUPER::new({}, @_);
    }

    my $config = Cassandane::Config->default()->clone();
    $config->set(servername => "127.0.0.1"); # urlauth needs matching servername
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'caldav');
    $config->set(httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    if (not defined $basedir
        or not $self->{instance}->{buildinfo}->get('component', 'httpd'))
    {
        # don't bother setting up further, we're not running tests anyway
        return;
    }

    my $admintalk = $self->{adminstore}->get_client();
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    $ENV{JMAP_ALWAYS_FULL} = 1;

    for (1..40) {
        my $name = sprintf("user%02d", $_);
        my $displayname = sprintf("User %02d", $_);
        $admintalk->create("user.$name");
        $admintalk->setacl("user.$name", admin => 'lrswipkxtecda');
        $admintalk->setacl("user.$name", $name => 'lrswipkxtecd');

        my $CalDAV = Net::CalDAVTalk->new(
            user => $name,
            password => 'pass',
            host => $service->host(),
            port => $service->port(),
            scheme => 'http',
            url => '/',
            expandurl => 1,
        );

        eval {
            # this fails on older Cyruses -- but don't crash during set_up!
            $CalDAV->UpdateAddressSet($displayname, "$name\@example.com");
        };
    }
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub list_tests
{
    my @tests;

    if (!defined $basedir)
    {
        return ( 'test_warning_caldavtester_is_not_installed' );
    }

    open(FH, "-|", 'find', $testdir, '-name' => '*.xml');
    while (<FH>)
    {
        chomp;
        next unless s{^$testdir/}{};
        next unless s{\.xml$}{};
        next if $suppressed{$_};
        push(@tests, "test_$_");
    }
    close(FH);

    return @tests;
}

sub run_test
{
    my ($self) = @_;

    if (!defined $basedir)
    {
        xlog "CalDAVTester tests are not enabled.  To enabled them, please";
        xlog "install CalDAVTester from http://calendarserver.org/wiki/CalDAVTester";
        xlog "and edit [caldavtester]basedir in cassandane.ini";
        xlog "This is not a failure";
        return;
    }

    my $name = $self->name();
    $name =~ s/^test_//;
    my $testname = $name;
    $testname .= ".xml";

    my $logdir = "$self->{instance}->{basedir}/rawlog/";
    mkdir($logdir);

    my $svc = $self->{instance}->get_service('http');
    my $params = $svc->store_params();

    my $rundir = "$self->{instance}->{basedir}/run";
    mkdir($rundir);

    system('ln', '-s', "$testdir", "$rundir/tests");
    system('ln', '-s', "$basedir", "$rundir/data");

    # XXX - make the config file!
    my $configfile = "$rundir/serverinfo.xml";
    {
        open(FH, "<", abs_path("data/caldavtester-serverinfo-template.xml"));
        local $/ = undef;
        my $config = <FH>;
        $config =~ s/SERVICE_HOST/$params->{host}/g;
        $config =~ s/SERVICE_PORT/$params->{port}/g;
        close(FH);
        open(FH, ">", $configfile);
        print FH $config;
        close(FH);
    }

    my $errfile = $self->{instance}->{basedir} .  "/$name.errors";
    my $outfile = $self->{instance}->{basedir} .  "/$name.stdout";
    my $status;
    my @verbose;
    if (get_verbose) {
        push @verbose, "--always-print-request", "--always-print-response";
    }
    $self->{instance}->run_command({
            redirects => { stderr => $errfile, stdout => $outfile },
            workingdir => $logdir,
            handlers => {
                exited_normally => sub { $status = 1; },
                exited_abnormally => sub { $status = 0; },
            },
        },
        $binary,
        "--basedir" => $rundir,
        "--observer=jsondump",
        @verbose,
        $testname);

    my $json;
    {
        open(FH, '<', $outfile) or die "Cannot open $outfile for reading $!";
        local $/ = undef;
        my $output = <FH>;
        $output =~ s/^.*?\[/[/s;
        $json = decode_json($output);
        close(FH);
    }

    if (0 && (!$status || get_verbose)) {
        foreach my $file ($errfile) {
            next unless -f $file;
            open FH, '<', $file
                or die "Cannot open $file for reading: $!";
            local $/ = undef;
            xlog $self, <FH>;
            close FH;
        }
    }

    $json->[0]{name} = $name; # short name at top level
    $self->assert(_check_result($name, $json->[0]));
}

sub _check_result {
    my $name = shift;
    my $json = shift;
    my $res = 1;

    if (defined $json->{result}) {
        if ($json->{result} == 0) {
            xlog "$name [OK]";
        }
        elsif ($json->{result} == 1) {
            xlog "$name [FAILED]";
            $res = 0;
        }
        elsif ($json->{result} == 3) {
            xlog "$name [SKIPPED]";
        }
        if (exists $expected{$name}) {
            if ($json->{result} == $expected{$name}[0]) {
                xlog "EXPECTED RESULT FOR $name";
                $res = 1;
            }
            else {
                xlog "UNEXPECTED RESULT FOR $name: " . $expected{$name}[1] if $expected{$name}[1];
                $res = 0; # yep, even if we succeeded
            }
        }
        xlog $json->{details} if $json->{result};
    }

    xlog "FAILED WHEN NOT EXPECTED $name" unless $res;

    if ($json->{tests}) {
        foreach my $test (@{$json->{tests}}) {
            $res = 0 unless _check_result("$name/$test->{name}", $test);
        }
    }

    return $res;
}

1;
