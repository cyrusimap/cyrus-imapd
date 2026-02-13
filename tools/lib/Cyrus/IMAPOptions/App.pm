# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
package Cyrus::IMAPOptions::App;
use warnings;
use strict;
use App::Cmd::Setup -app;

sub common_opt_spec
{
    return (
        [ 'forbid-unreleased', 'forbid imapoptions marked UNRELEASED' ],
        [ 'cc=s', 'specify the C compiler in use', { default => 'gcc' } ],
    );
}

1;
