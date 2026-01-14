# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Alpaca;
use strict;
use warnings;
use Cwd qw(abs_path);
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Socket;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(allowstarttls => 'on');

    return $class->SUPER::new({config => $config}, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub imap_cmd_with_tag
{
    my ($talk, $tag, @args) = @_;

    die "not a Mail::IMAPTalk object" if ref $talk ne 'Mail::IMAPTalk';

    # override next tag with the tag we want to use
    local $talk->{CmdId} = $tag;

    # suppress an expected warning from _imap_cmd because we (probably)
    # just set CmdId to something non-numeric
    local $SIG{__WARN__} = sub {
        if ($_[0] !~ m/^Argument "\Q$tag\E" isn't numeric /) {
            warn @_;
        }
    };

    return $talk->_imap_cmd(@args);
}

use Cassandane::Tiny::Loader;

1;
