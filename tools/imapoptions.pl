#!/usr/bin/env perl
# imapoptions.pl - process imapoptions files into various formats
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";

use Cyrus::IMAPOptions::App;
Cyrus::IMAPOptions::App->run;
