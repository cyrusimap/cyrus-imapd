#  Copyright (c) 2022 Fastmail.  All rights reserved.
#
# Author: Bron Gondwana <brong@fastmailteam.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package Cyrus::AccountSync;

use strict;
use warnings;

use Digest::SHA qw(sha1_hex);
use JSON::XS;
use Cyrus::Mbname;
use Data::Dumper;
use Tie::DataUUID qw{$uuid};

=pod
=head1 NAME

Cyrus::AccountSync - dump and undump entire accounts

=head1 EXAMPLES

=cut
=head1 PUBLIC API
=over
=item Cyrus::AccountSync->new($SyncProto);
=cut

sub new {
  my $class = shift;
  my $sync = shift;

  my $Self = bless {
    sync => $sync,
  }, ref($class) || $class;

  return $Self;
}

sub dump_user {
  my $self = shift;
  my %opts = @_;

  die "need username" unless $opts{username};

  my %res;

  my $info = $self->{sync}->dlwrite("GET", "USER", $opts{username});

  # no user?
  return unless $info->{MAILBOX};

  my %subs = map { $_ => 1 } @{$info->{LSUB}[0]||[]};

  my @folders;
  for my $folder (@{$info->{MAILBOX}}) {
    my $fi = $self->{sync}->dlwrite("GET", "FULLMAILBOX", $folder->{MBOXNAME});
    my @emails;
    for my $record (@{$fi->{MAILBOX}[0]{RECORD}||[]}) {
      my $res = $self->{sync}->dlwrite("GET", "FETCH", {
        PARTITION => $folder->{PARTITION},
        MBOXNAME => $folder->{MBOXNAME},
        UNIQUEID => $folder->{UNIQUEID},
        GUID => $record->{GUID},
        UID => $record->{UID},
      });
      my $ref = $res->{MESSAGE}[0];
      my $data = $$ref->[3];
      my %email = (
        uid => $record->{UID} + 0,
        flags => $record->{FLAGS},
        modseq => $record->{MODSEQ} + 0,
        internalDate => $record->{INTERNALDATE} + 0,
        rawMessage => $data,
      );
      if ($opts{objectid}) {
        $email{emailId} = "M" . substr($record->{GUID}, 0, 24);
      }
      push @emails, \%email;
    }
    my $annots = _parseannots($fi->{MAILBOX}[0]{ANNOTATIONS});
    my $use = $annots->{$opts{username}}{"/specialuse"};
    my %frecord = (
      name => _mkname($opts{username}, $folder->{MBOXNAME}),
      uidValidity => $folder->{UIDVALIDITY} + 0,
      nextUid => $folder->{LAST_UID} + 1,
      highestModificationSequenceValue => $folder->{HIGHESTMODSEQ} + 0,
      emails => \@emails,
    );
    $frecord{subscribed} = $JSON::true if $subs{$folder->{MBOXNAME}};
    $frecord{specialUse} = $use if $use;
    if ($opts{objectid}) {
      $frecord{mailboxId} = $folder->{UNIQUEID};
    }
    push @folders, \%frecord;
  }

  $res{mailboxes} = \@folders;

  return \%res;
}

sub delete_user {
  my $self = shift;
  my %opts = @_;
  # remove the existing user
  return $self->{sync}->dlwrite("APPLY", "UNUSER", $opts{username});
}

sub undump_user {
  my $self = shift;
  my %opts = @_;

  die "need username" unless $opts{username};
  die "need data" unless $opts{data};

  my $info = $self->{sync}->dlwrite("GET", "USER", $opts{username});
  die "user $opts{username} exists" if keys %$info;

  my $partition = $opts{partition} || 'default';

  my $mailboxes = $opts{data}{mailboxes};

  my $acl = $opts{acl} || "$opts{username}	lrswipkxtecdan	admin	lrswipkxtecdan	anyone	p	",

  my $time = time();
  my @subs;

  for my $mailbox (@$mailboxes) {
    # create the emails first
    my @upload;
    my @records;
    for my $email (@{$mailbox->{emails}||[]}) {
      my $data = $email->{rawMessage};
      my $size = length($data);
      my $guid = sha1_hex($data);
      push @upload, \[$partition, $guid, $size, $data];
      my $internaldate = $email->{internalDate} // $time;
      my $modseq = $email->{modseq} || 1;
      my $flags = $email->{flags} || [];
      my %record = (
        ANNOTATIONS => [], # skip savedate and such for now
        GUID => $guid,
        FLAGS => $flags,
        INTERNALDATE => $internaldate,
        LAST_UPDATED => $internaldate,
        MODSEQ => $modseq,
        SIZE => $size,
        UID => $email->{uid},
      );
      push @records, \%record;
    }
    $self->{sync}->dlwrite("APPLY", "MESSAGE", \@upload) if @upload;
    my $mbname = Cyrus::Mbname->new_extuserfolder($opts{username}, $mailbox->{name});
    my $intname = $mbname->intname;
    my $highestmodseq = $mailbox->{highestModificationSequenceValue} || 1;
    my $uidvalidity = $mailbox->{uidValidity} || $time;
    my $last_uid = $mailbox->{nextUid} ? $mailbox->{nextUid} - 1 : 0;
    my $uniqueid = $mailbox->{mailboxId} || "$uuid";
    my @annotations;
    if ($mailbox->{specialUse}) {
      push @annotations, {
        'ENTRY' => '/specialuse',
        'MODSEQ' => '0',
        'USERID' => $opts{username},
        'VALUE' => $mailbox->{specialUse},
      };
    }
    my %maildata = (
      'ACL' => $acl,
      'ANNOTATIONS' => \@annotations,
      'CREATEDMODSEQ' => '1',
      'FOLDERMODSEQ' => '1',
      'HIGHESTMODSEQ' => "$highestmodseq",
      'LAST_APPENDDATE' => '0',
      'LAST_UID' => "$last_uid",
      'MBOXNAME' => $intname,
      'OPTIONS' => 'P',
      'PARTITION' => $partition,
      'POP3_LAST_LOGIN' => '0',
      'POP3_SHOW_AFTER' => '0',
      'RECENTTIME' => '0',
      'RECENTUID' => '0',
      'RECORD' => \@records,
      'UIDVALIDITY' => $uidvalidity,
      'UNIQUEID' => $uniqueid,
    );

    $self->{sync}->dlwrite('APPLY', 'MAILBOX', \%maildata);

    push @subs, $intname if $mailbox->{subscribed};
  }

  if (@subs) {
    $self->{sync}->dlwrite('APPLY', 'SUB', { USERID => $opts{username}, MBOXNAME => $_ }) for @subs;
  }
}

sub _mkname {
  my $username = shift;
  my $mboxname = shift;

  my $mbname = Cyrus::Mbname->new_intname($mboxname);
  return $mbname->extuserfolder;

}

sub _parseannots {
  my $annots = shift || [];
  my %res;
  for my $item (@$annots) {
    $res{$item->{USERID}//''}{$item->{ENTRY}} = $item->{VALUE};
  }
  return \%res;
}

1;
