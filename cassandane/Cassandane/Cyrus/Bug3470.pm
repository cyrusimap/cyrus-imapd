# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Bug3470;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(virtdomains => 'userid');
    $config->set(unixhierarchysep => 'on');
    $config->set(altnamespace => 'yes');

    return $class->SUPER::new({ config => $config }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $imaptalk = $self->{store}->get_client();

    # Bug #3470 folders
    # sub folders only
    $imaptalk->create("Drafts") || die;
    $imaptalk->create("2001/05/wk18") || die;
    $imaptalk->create("2001/05/wk19") || die;
    $imaptalk->create("2001/05/wk20") || die;
    $imaptalk->subscribe("2001/05/wk20") || die;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test LSUB behaviour
#
sub test_list_percent
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my @inbox_flags = qw( \\HasNoChildren );
    my @inter_flags = qw( \\HasChildren );
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3) {
        unshift @inbox_flags, qw( \\Noinferiors );
        unshift @inter_flags, qw( \\Noselect );
    }
    elsif ($maj == 3 && $min < 5) {
        unshift @inter_flags, qw( \\Noselect );
    }

    my $alldata = $imaptalk->list("", "%");
    $self->assert_deep_equals($alldata, [
          [
            \@inbox_flags,
            '/',
            'INBOX'
          ],
          [
            \@inter_flags,
            '/',
            '2001'
          ],
          [
            [
              '\\HasNoChildren'
            ],
            '/',
            'Drafts'
          ]
    ], "LIST data mismatch: "  . Dumper($alldata, \@inbox_flags));
}

#
# Test LSUB behaviour
#
sub test_list_2011
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my @inter_flags = qw( \\HasChildren );
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3 || ($maj == 3 && $min < 5)) {
        unshift @inter_flags, qw( \\Noselect );
    }

    my $alldata = $imaptalk->list("", "2001");
    $self->assert_deep_equals($alldata, [
          [
            \@inter_flags,
            '/',
            '2001'
          ]
    ], "LIST data mismatch: "  . Dumper($alldata));
}

sub test_lsub
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $alldata = $imaptalk->lsub("", "2001");
    $self->assert_deep_equals($alldata, [
          [
            [
              '\\Noselect',
              '\\HasChildren'
            ],
            '/',
            '2001'
          ]
    ], "LSUB data mismatch: "  . Dumper($alldata));
}

1;
