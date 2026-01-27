# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cyrus::ImapClone;

use strict;
use warnings;
use Date::Parse;
use Cyrus::SyncProto;
use Mail::IMAPTalk;
use Data::Dumper;
use Digest::SHA qw(sha1_hex);
use Tie::DataUUID qw($uuid);
use IO::Socket::SSL;
use JSON::XS;
use IO::File;

=pod
=head1 NAME

Cyrus::ImapClone  - A pure perl interface to clone Cyrus Mailbox.

=head1 EXAMPLES

=cut
=head1 PUBLIC API
=over
=item Cyrus::ImapClone->new()
=cut

sub new {
  my $class = shift;
  my %args = @_;

  my $syncssl = $args{syncssl};
  my $st = Mail::IMAPTalk->new(
    Server => $args{synchost},
    Port => $args{syncport},
    Username => $args{syncuser},
    Password => $args{syncpass},
    AuthzUser => $args{syncauthz},
    UseSSL => $syncssl,
    UseBlocking => $syncssl,
    UseCompress => 1,
  );
  die "Failed to setup sync talk" unless $st;
  my $sp = Cyrus::SyncProto->new($st);
  if ($args{syncwipe}) {
    $sp->dlwrite('APPLY', 'UNUSER', $args{synctarget});
    $st->logout();
    return;
  }
  my $userdata = $sp->dlwrite('GET', 'USER', $args{synctarget});

  my $usessl = $args{imapssl};
  my $it = Mail::IMAPTalk->new(
    Server => $args{imaphost},
    Port => $args{imapport},
    Username => $args{imapuser},
    Password => $args{imappass},
    AuthzUser => $args{imapauthz},
    SSL_verify_mode => SSL_VERIFY_NONE,
    UseSSL => $usessl,
    UseBlocking => $usessl,
    UseCompress => 1,
  );

  return bless {
    syncer => $sp,
    synctalk => $st,
    imaptalk => $it,
    userdata => $userdata,
    targetuser => $args{synctarget},
  }, ref($class) || $class;
}

sub done {
  my $Self = shift;
  eval { $Self->{imaptalk}->logout() };
  eval { $Self->{synctalk}->logout() };
}

sub DESTROY {
  my $Self = shift;
  $Self->done();
}

sub batchfillrecords {
  my $Self = shift;
  my $mboxname = shift;
  my $records = shift;

  my %todo = %$records;
  my $total = scalar keys %todo;

  # batch in units of max 10 megabytes plus 1 message
  while (%todo) {
    my $size = 0;
    my %batch;
    foreach my $uid (sort {$a <=> $b} keys %todo) {
      $batch{$uid} = delete $todo{$uid};
      $size += $batch{$uid}{SIZE};
      last if $size > 1024 * 1024 * 10; # 10 megabytes
    }
    $Self->fillrecords($mboxname, \%batch);
    last unless %todo;
    print "Batching - still " . scalar(keys %todo) . "/$total to go for $mboxname\n" if $Self->{verbose};
  }
}

sub fillrecords {
  my $Self = shift;
  my $mboxname = shift;
  my $records = shift;

  # XXX - smaller batch to control memory usage?

  my $imap = $Self->{imaptalk};
  my $fetch = $imap->fetch([sort {$a <=> $b} keys %$records], '(rfc822)');
  my @apply;
  foreach my $uid (sort {$a <=> $b} keys %$records) {
    die "MISSING $uid" unless $fetch->{$uid};
    die "SIZE MISSMATCH $uid" unless $records->{$uid}{SIZE} == length($fetch->{$uid}{rfc822});
    $records->{$uid}{GUID} = sha1_hex($fetch->{$uid}{rfc822});
  }

  # let's try to reserve first
  my @names = map { $_->{MBOXNAME} } @{$Self->{userdata}{MAILBOX}};
  my %guids = map { $_->{GUID} => 1 } values %$records;
  my $res = $Self->{syncer}->dlwrite('APPLY', 'RESERVE', {PARTITION => 'default', MBOXNAME => \@names, GUID => [sort keys %guids]});
  my %missing = map { $_ => 1 } @{$res->{MISSING}[0]};

  return unless %missing;

  foreach my $uid (sort {$a <=> $b} keys %$records) {
    next unless $missing{$records->{$uid}{GUID}};
    push @apply, \['default', $records->{$uid}{GUID}, $records->{$uid}{SIZE}, $fetch->{$uid}{rfc822}];
  }

  return unless @apply;

  $Self->{syncer}->dlwrite('APPLY', 'MESSAGE', \@apply);
}

sub syncmailbox {
  my $Self = shift;
  my $mboxname = shift;
  my $existing = shift;

  if ($existing) {
    my $status = $Self->{imaptalk}->status($Self->_sync_to_imap($mboxname), "(HIGHESTMODSEQ UIDVALIDITY)");
    die "UIDVALIDITY CHANGED" if ($existing->{UIDVALIDITY} != $status->{uidvalidity});
    return if ($existing->{HIGHESTMODSEQ} == $status->{highestmodseq});
  }

  $Self->{imaptalk}->examine($Self->_sync_to_imap($mboxname));
  my $imap = $Self->{imaptalk};
  my %idata = (
    UIDVALIDITY => $imap->get_response_code('uidvalidity') + 0,
    LAST_UID => $imap->get_response_code('uidnext') - 1,
    HIGHESTMODSEQ => $imap->get_response_code('highestmodseq') || 1,
    EXISTS => $imap->get_response_code('exists') || 0,
  );

  # basic sanity checks
  die "UIDVALIDITY CHANGED" if ($existing and $existing->{UIDVALIDITY} != $idata{UIDVALIDITY});
  return if ($existing and $existing->{HIGHESTMODSEQ} == $idata{HIGHESTMODSEQ});

  my $sdata = $Self->readup($mboxname, $existing);

  # basic sanity checks again with latest data
  die "UIDVALIDITY CHANGED " . Dumper($sdata) if ($sdata and $sdata->{UIDVALIDITY} != $idata{UIDVALIDITY});
  return if ($existing and $existing->{HIGHESTMODSEQ} == $idata{HIGHESTMODSEQ});

  # sanity range checks
  die "FUTURE CHANGED MODSEQ $sdata->{HIGHESTMODSEQ} > $idata{HIGHESTMODSEQ}" if ($sdata and $sdata->{HIGHESTMODSEQ} > $idata{HIGHESTMODSEQ});
  die "FUTURE CHANGED UIDS $sdata->{LAST_UID} > $idata{LAST_UID}" if ($sdata and $sdata->{LAST_UID} > $idata{LAST_UID});

  my $time = time();

  unless ($sdata) {
    print "NEW MAILBOX $mboxname: $idata{EXISTS}\n" if $Self->{verbose};

    my %mb = (
      ACL => Cyrus::SyncProto::user_acl($Self->{targetuser}),
      HIGHESTMODSEQ => 0,
      LAST_APPENDDATE => 0,
      LAST_UID => 0,
      MBOXNAME => $mboxname,
      OPTIONS => 'P',
      PARTITION => 'default',
      POP3_LAST_LOGIN => 0,
      POP3_SHOW_AFTER => 0,
      QUOTAROOT => $Self->_imap_to_sync('INBOX'),
      RECENTTIME => 0,
      RECENTUID => 0,
      RECORD => [],
      SYNC_CRC => 0,
      SYNC_ANNOT_CRC => 0,
      UIDVALIDITY => $idata{UIDVALIDITY},
      UNIQUEID => $uuid,
    );

    push @{$Self->{userdata}{MAILBOX}}, \%mb;

    $sdata = { %mb, RECORD => [] };
  }

  my $recentuid = $idata{LAST_UID};
  my @applyrecords;

  # clever logic here..
  if ($sdata->{LAST_UID}) {
    # re-fetch flags only
    my $end = $sdata->{LAST_UID};
    my $fetch = $imap->fetch("1:$end", "(uid flags modseq)", "(changedsince $sdata->{HIGHESTMODSEQ})");
    foreach my $record (grep { _notexpunged($_) } @{$sdata->{RECORD}}) {
      my $uid = $record->{UID};
      next unless $fetch->{$uid};
      my @flags = @{$fetch->{$uid}{flags}};
      if (grep { lc $_ eq '\\recent' } @flags) {
        $recentuid = $uid if $recentuid > $uid;
      }

      # update the record and the CRC
      $sdata->{SYNC_CRC} ^= $Self->{syncer}->record_crc($record);
      $record->{FLAGS} = _cleanflags(@flags);
      $record->{MODSEQ} = $fetch->{$uid}{modseq}[0];
      $record->{LAST_UPDATED} = $time;
      $sdata->{SYNC_CRC} ^= $Self->{syncer}->record_crc($record);
      push @applyrecords, $record;
    }
  }

  my $first = $sdata->{LAST_UID} + 1;
  my $last = $idata{LAST_UID};
  if ($last >= $first) {
    my $fetch = $imap->fetch("$first:$last", "(uid flags modseq internaldate rfc822.size)");
    my %records;
    foreach my $uid (sort {$a <=> $b} keys %$fetch) {
      my @flags = @{$fetch->{$uid}{flags}};
      if (grep { lc $_ eq '\\recent' } @flags) {
        $recentuid = $uid if $recentuid > $uid;
      }

      $records{$uid} = {
        # ANNOTATIONS => [],
        FLAGS => _cleanflags(@flags),
        # GUID to be filled
        INTERNALDATE => _mkunixtime($fetch->{$uid}{internaldate}),
        LAST_UPDATED => $time,
        MODSEQ => $fetch->{$uid}{modseq}[0],
        SIZE => $fetch->{$uid}{'rfc822.size'},
        UID => $uid,
      };
    }
    $Self->batchfillrecords($mboxname, \%records);
    foreach my $uid (sort {$a <=> $b} keys %records) {
      push @applyrecords, $records{$uid};
      push @{$sdata->{RECORD}}, $records{$uid};
      $sdata->{SYNC_CRC} ^= $Self->{syncer}->record_crc($records{$uid});
    }
  }

  if ($idata{EXISTS} != scalar(grep { _notexpunged($_) } @{$sdata->{RECORD}})) {
    # we need to expunge something - let's see what..
    print "DOING EXPUNGE CHECK FOR $mboxname\n" if $Self->{verbose};
    my $uids = $imap->search('uid', "1:$last");
    my %exists = map { $_ => 1 } @$uids;
    foreach my $record (grep { _notexpunged($_) } @{$sdata->{RECORD}}) {
      next if $exists{$record->{UID}};
      # update the record and the CRC
      $sdata->{SYNC_CRC} ^= $Self->{syncer}->record_crc($record);
      push @{$record->{FLAGS}}, "\\Expunged";
      $record->{MODSEQ} = $idata{HIGHESTMODSEQ};
      $record->{LAST_UPDATED} = $time;
      push @applyrecords, $record;
    }
  }

  $sdata->{HIGHESTMODSEQ} = $idata{HIGHESTMODSEQ};
  $sdata->{LAST_UID} = $idata{LAST_UID};
  $sdata->{RECENTTIME} = $time;
  $sdata->{RECENTUID} = $recentuid;

  $Self->{syncer}->dlwrite('APPLY', 'MAILBOX', {%$sdata, RECORD => [sort { $a->{UID} <=> $b->{UID} } @applyrecords]});

  $Self->writedown($sdata);
}

sub readup {
  my $Self = shift;
  my $mboxname = shift;
  my $existing = shift;

  if ($existing and $Self->{cachedir} and $Self->cachepath($existing->{UNIQUEID})) {
    my $file = IO::File->new($Self->cachepath($existing->{UNIQUEID}), "r");
    my $data = eval { $file->getline() };
    my $perl = eval { decode_json($data) };
    if ($perl and $perl->{UNIQUEID} eq $existing->{UNIQUEID} and $perl->{HIGHESTMODSEQ} eq $existing->{HIGHESTMODSEQ} and $perl->{UIDVALIDITY} eq $existing->{UIDVALIDITY} and $perl->{LAST_UID} eq $existing->{LAST_UID}) {
      print "READING $mboxname FROM CACHE\n" if $Self->{verbose};
      return $perl;
    }
    else {
      use Data::Dumper;
      my %check =  map { $_ => $perl->{$_} } qw(UNIQUEID HIGHESTMODSEQ UIDVALIDITY LAST_UID);
      print "INVALID $mboxname CACHE: " . Dumper(\%check, $existing) if $Self->{verbose};
    }
  }

  my $res = eval { $Self->{syncer}->dlwrite('GET', 'FULLMAILBOX', $mboxname)->{MAILBOX}[0] };

  $Self->writedown($res) if $res;

  return $res;
}

sub writedown {
  my $Self = shift;
  my $data = shift;
  return unless $Self->{cachedir};
  my @records = sort { $a->{UID} <=> $b->{UID} } @{$data->{RECORD}};
  $data->{RECORD} = \@records;
  eval {
    my $file = IO::File->new($Self->cachepath($data->{UNIQUEID}, 1), 'w');
    $file->print(encode_json($data));
  };
}

sub cachepath {
  my $Self = shift;
  my $uniqueid = shift;
  my $make = shift;
  return unless $Self->{cachedir};
  my $dir = "$Self->{cachedir}/$Self->{targetuser}";
  my $path = "$dir/$uniqueid.cache";
  return (-f $path ? $path : undef) unless $make;
  mkdir $dir unless -d $dir;
  return $path;
}

sub _notexpunged {
  my $record = shift;
  my @expunged = grep { lc $_ eq '\\expunged' } @{$record->{FLAGS}};
  return not scalar @expunged;
}

sub _cleanflags {
  my @flags = @_;
  my @clean = grep { lc $_ ne '\\recent' } @flags;
  return \@clean;
}

sub _mkunixtime {
  my $time = shift;
  return str2time($time);
}

sub syncmailboxes {
  my $Self = shift;
  my $userdata = $Self->{userdata};

  my $list = $Self->{imaptalk}->list('INBOX', '*');
  my %mbox = map { $Self->_imap_to_sync($_->[2]) => 1 } @$list;

  foreach my $mailbox (@{$userdata->{MAILBOX}}) {
    if (delete $mbox{$mailbox->{MBOXNAME}}) {
      $Self->syncmailbox($mailbox->{MBOXNAME}, $mailbox);
    } else {
      $Self->{syncer}->apply_unmailbox($mailbox->{MBOXNAME});
    }
  }
  foreach my $new (sort keys %mbox) {
    $Self->syncmailbox($new);
  }
}

sub syncsubs {
  my $Self = shift;
  my $userdata = $Self->{userdata};
  my $lsub = $Self->{imaptalk}->lsub('INBOX', '*');
  my %sub = map { $Self->_imap_to_sync($_->[2]) => 1 } @$lsub;

  foreach my $existing (@{$userdata->{LSUB}[0]}) {
    next if delete $sub{$existing};
    $Self->{syncer}->apply_unsub($existing, $Self->{targetuser});
  }
  foreach my $new (keys %sub) {
    $Self->{syncer}->apply_sub($new, $Self->{targetuser});
  }
}

sub syncquota {
  my $Self = shift;
  my $userdata = $Self->{userdata};
  my $quota = $Self->{imaptalk}->getquotaroot('INBOX');
  my $name = $quota->{quotaroot}[1];
  my $amount = $quota->{$name}[2];
  my $existing = $Self->{userdata}{QUOTA}[0];
  if ($existing and not $amount) {
    $Self->{syncer}->dlwrite('APPLY', 'UNQUOTA', $existing->{ROOT});
    return;
  }
  return if not $amount;
  return if ($existing and $amount == $existing->{STORAGE});
  $Self->{syncer}->dlwrite('APPLY', 'QUOTA', { ROOT => $Self->_imap_to_sync('INBOX'), STORAGE => $amount });
}

sub syncuser {
  my $Self = shift;
  $Self->syncmailboxes();
  $Self->syncsubs();
  $Self->syncquota();
  return 1;
}

sub _imap_to_sync {
  my $Self = shift;
  my $name = shift;
  my ($l, $d) = _splituser($Self->{targetuser});
  my $res = '';
  $res = "$d!" if $d;
  $res .= "user.$l";
  $name =~ s/^INBOX//i;
  return "$res$name";
}

sub _sync_to_imap {
  my $Self = shift;
  my $name = shift;
  $name =~ s/^(.*\!)//;
  $name =~ s/^user\.[^.]+//;
  return "INBOX$name";
}

sub _splituser {
  my $user = shift;
  return split /\@/, $user;
}

=back
=head1 AUTHOR AND COPYRIGHT

Bron Gondwana <brong@fastmail.fm> - Copyright 2017 FastMail

Licenced under the same terms as Cyrus IMAPd.

=cut

1;
