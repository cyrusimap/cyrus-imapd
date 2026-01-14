# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::MasterEvent;
use strict;
use warnings;

use base qw(Cassandane::MasterEntry);

sub new
{
    return shift->SUPER::new(@_);
}

sub _otherparams
{
    my ($self) = @_;
    return ( qw(period at cron) );
}

1;
