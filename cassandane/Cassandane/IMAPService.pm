# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::IMAPService;
use strict;
use warnings;

use base qw(Cassandane::Service);
use Cassandane::Util::Log;

sub new
{
    my ($class, %params) = @_;
    my $ssl = scalar grep { $_ eq '-s' } @{$params{argv}};
    my $type = $ssl ? 'imaps' : 'imap';
    my $self = $class->SUPER::new(type => $type, %params);
    return $self;
}

# Return a hash of parameters suitable for passing
# to MessageStoreFactory::create.
sub store_params
{
    my ($self, %inparams) = @_;

    my $outparams = $self->SUPER::store_params(%inparams);
    $outparams->{folder} ||= 'inbox';
    return $outparams;
}

1;
