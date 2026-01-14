# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cyrus::SyncProto;

use strict;
use warnings;

use Mail::IMAPTalk;
use Cyrus::DList;
use MIME::Base64;
use Digest::SHA;
use Digest::CRC qw(crc32);

=pod
=head1 NAME

Cyrus::SyncProto  -

=head1 EXAMPLES

=cut
=head1 PUBLIC API
=over
=item Cyrus::SyncProto->new()
=cut

my $digest = Digest::SHA->new();

sub new {
  my $class = shift;
  my $talk = shift;

  my $Self = bless {
    verbose => 1,
    talk => $talk,
    tag => 1,
  }, ref($class) || $class;

  return $Self;
}

sub mailbox_crc {
  my $Self = shift;
  my $mailbox = shift;
  my $crc = 0;
  foreach my $record (@{$mailbox->{RECORD}}) {
    $crc ^= $Self->record_crc($record);
  }
  return $crc;
}

sub record_crc {
  my $Self = shift;
  my $record = shift;

  my $flagcrc = 0;
  foreach my $flag (@{$record->{FLAGS}}) {
    my $item = lc($flag);
    return 0 if $item eq '\\expunged'; # specialcase
    $flagcrc ^= crc32($item);
  }

  my $str = "$record->{UID} $record->{MODSEQ} $record->{LAST_UPDATED} ($flagcrc) $record->{INTERNALDATE} $record->{GUID}";

  return crc32($str);
}

sub _dlitem {
  my $item = shift;
  return Cyrus::DList->new_perl(undef, $item)->as_string();
}

sub dlwrite {
  my $Self = shift;
  my $command = join(' ', map { _dlitem($_) } @_);
  my $tag = sprintf("S%08d", $Self->{tag}++);
  $Self->{talk}->_imap_socket_out("$tag SYNC$command\r\n");
  my %data;
  my $onecmd = '';
  while (my $line = $Self->{talk}->_imap_socket_read_line()) {
    if ($line =~ s/^(\* )// || $line =~ m/^( )/) {
      if ($onecmd && $1 eq '* ') {
        my $val = Cyrus::DList->parse_string($onecmd, 1);
        push @{$data{$val->{key}}}, $val->as_perl();
        $onecmd = '';
      }
      $onecmd .= $line;
      while ($onecmd =~ m/(\d+)\+?\}\s*$/s) {
        my $length = $1;
        my $buf = $Self->{talk}->_imap_socket_read_bytes($length);
        $onecmd .= "\r\n" . $buf;
        $onecmd .= $Self->{talk}->_imap_socket_read_line();
      }
      next;
    }
    if ($onecmd) {
      my $val = Cyrus::DList->parse_string($onecmd, 1);
      push @{$data{$val->{key}}}, $val->as_perl();
      $onecmd = '';
    }
    die "dlwrite failed @_ => $line" unless $line =~ m{^$tag OK }i;
    last;
  }
  return \%data;
}

sub user_acl {
  my $user = shift;
  return "admin\tlrswipkxtecda\t$user\tlrswipkxtecd\tanyone\tp\t";
}

sub mailbox_user {
  my $mailbox = shift;
  my $domain;
  if ($mailbox =~ s/^([^\!]+)\!//) {
    $domain = $1;
  }
  die "not a user folder" unless $mailbox =~ m/^user\.([^\.]+)/;
  return $domain ? "$1\@$domain" : $1;
}

sub apply_sub {
  my $Self = shift;
  my $mailbox = shift;
  my $user = shift;

  return $Self->dlwrite('APPLY', 'SUB', { MBOXNAME => $mailbox, USERID => $user });
}

sub apply_unsub {
  my $Self = shift;
  my $mailbox = shift;
  my $user = shift;

  return $Self->dlwrite('APPLY', 'UNSUB', { MBOXNAME => $mailbox, USERID => $user });
}

sub apply_unuser {
  my $Self = shift;
  my $user = shift;

  return $Self->dlwrite('APPLY', 'UNUSER', $user);
}

sub apply_unmailbox {
  my $Self = shift;
  my $mailbox = shift;

  return $Self->dlwrite('APPLY', 'UNMAILBOX', $mailbox);
}

sub get_user {
  my $Self = shift;
  my $user = shift;

  return $Self->dlwrite("GET", "USER", $user);
}

sub get_mailboxes {
  my $Self = shift;
  my @mailboxes = shift;

  return $Self->dlwrite("GET", "MAILBOXES", [@mailboxes]);
}

=back
=head1 AUTHOR AND COPYRIGHT

Bron Gondwana <brong@fastmail.fm> - Copyright 2017 FastMail

Licenced under the same terms as Cyrus IMAPd.

=cut

1;
