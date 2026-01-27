# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::ID;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ }, @_);
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

sub test_cmd_id
{
    my ($self) = @_;

    # Purge any syslog lines before this test runs.
    $self->{instance}->getsyslog();

    my $imaptalk = $self->{store}->get_client();

    return if not $imaptalk->capability()->{id};

    my $res = $imaptalk->id(name => "cassandane");
    xlog $self, Dumper $res;

    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    # should have logged some timer output, which should include the sess id,
    # and since we sent a client id via IMAP ID, we should get that, too!
    if ($self->{instance}->{have_syslog_replacement}) {
        # make sure that the connection is ended so that imapd reset happens
        $imaptalk->logout();
        undef $imaptalk;

        my @behavior_lines = $self->{instance}->getsyslog(qr/session ended/);

        $self->assert_num_gte(1, scalar @behavior_lines);

        $self->assert_matches(qr/\bid\.name=<cassandane>/, $_) for @behavior_lines;
    }
}

sub test_cmd_id_nil_cant_unget
{
    my ($self) = @_;

    # Purge any syslog lines before this test runs.
    $self->{instance}->getsyslog();

    my $imaptalk = $self->{store}->get_client();

    # Construct an ID command where the 'N' in NULL is the 4096'th character
    # in the prot buffer.
    # This will require a new read to get the rest of the command,
    # but will also prohibit calling prot_ungetc('N').
    # Successful execution of the command will verify that we have fixed the
    # parsing issue.
    # If the previous bug returns, imapd will fatal() attempting to prot_unget()
    my $x = 'x' x 1014;
    $imaptalk->{CmdId} = 'XX';
    $imaptalk->_imap_cmd('ID', 0, {},
                         qq{("a" "$x" "b" "$x" "c" "$x" "d" "$x" "e" NIL)});
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
}

1;
