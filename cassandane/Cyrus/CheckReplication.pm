#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cyrus::CheckReplication;

use strict;
use warnings;
use Mail::IMAPTalk;
use Encode;
use Data::Dumper;
use Carp;
use JSON::XS;

sub Dump {
  local $Data::Dumper::Indent = 1;
  local $Data::Dumper::Sortkeys = 1;
  return Data::Dumper::Dumper(@_);
}

sub deepeq {
  return JSON::XS->new->utf8->canonical->encode([$_[0]]) eq JSON::XS->new->utf8->canonical->encode([$_[1]]);
}

# Hello object orientation, friend of all "need state support in
# a multi-thread safe way" code.

# Functions
sub new {
  my $class = shift;
  my %Opts = @_;

  die "NEED s1" unless $Opts{IMAPs1};
  die "NEED s2" unless $Opts{IMAPs2};
  die "NEED CyrusName" unless $Opts{CyrusName};

  # sensible defaults
  $Opts{NumRepeats} = 3 if not exists $Opts{NumRepeats};
  $Opts{SleepTime} = 2 if not exists $Opts{SleepTime};
  $Opts{Messages} = [];

  my $Self = bless \%Opts, ref($class) || $class;

  if ($Opts{TraceImap}) {
    $Self->{IMAPs1}->set_tracing(sub { $Self->do_output("IMAP_MASTER: " . shift) });
    $Self->{IMAPs2}->set_tracing(sub { $Self->do_output("IMAP_REPLICA: " . shift) });
  }

  $Self->{IMAPs1}->{PreserveINBOX} = 1;
  $Self->{IMAPs2}->{PreserveINBOX} = 1;
  $Self->{IMAPs1}->uid(1);
  $Self->{IMAPs2}->uid(1);

  return $Self;
}

sub CheckUserReplication {
  my ($Self, $Level) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  # Folder list from both servers
  my $IMAPs1List = $IMAPs1->list("INBOX.*", '*')
    || die "Could not list all folders: $@";
  my $IMAPs2List = $IMAPs2->list("INBOX.*", '*')
    || die "Could not list all folders: $@";

  $IMAPs1List = [] if !ref $IMAPs1List;
  $IMAPs2List = [] if !ref $IMAPs2List;

  my @s1List = ("INBOX", map { $_->[2] } @$IMAPs1List);
  my @s2List = ("INBOX", map { $_->[2] } @$IMAPs2List);

  my %s1Hash = map { $_ => 1 } @s1List;
  my %s2Hash = map { $_ => 1 } @s2List;

  my @Missings1 = grep { !$s1Hash{$_} } @s2List;
  my @Missings2 = grep { !$s2Hash{$_} } @s1List;

  if (@Missings1 || @Missings2) {
    $Self->do_repeat($Repeat, $CyrusName, "Folders mismatch", join(', ', @Missings1), join(', ', @Missings2))
      || goto RepeatCheck;
  }

  # Check subscriptions
  $Self->CheckUserSubs();

  # Check quota
  $Self->CheckUserQuota();

  # Compare each folder
  foreach my $Folder (@s1List) {
    $Self->debug("$CyrusName checking folder $Folder");
    my $MsgsExist = $Self->CheckFolderBasic($Folder);
    next if $Level == 0 || !$MsgsExist;

    $IMAPs1->examine($Folder);
    $IMAPs2->examine($Folder);
    $Self->CheckFolderFlags($Folder);
    if ($Self->{CheckMetadata} &&
        $IMAPs1->capability()->{'metadata'} &&
        $IMAPs2->capability()->{'metadata'}) {
      $Self->debug("$CyrusName checking metadata $Folder");
      $Self->CheckFolderMetadata($Folder);
    }
    # yes, they really did
    if ($Self->{CheckAnnotations} &&
        $IMAPs1->capability()->{'annotate-experiment-1'} &&
        $IMAPs2->capability()->{'annotate-experiment-1'}) {
      $Self->debug("$CyrusName checking annotations $Folder");
      $Self->CheckFolderAnnots($Folder);
    }
    if ($Self->{CheckConversations} &&
        $IMAPs1->capability()->{'xconversations'} &&
        $IMAPs2->capability()->{'xconversations'}) {
      $Self->debug("$CyrusName checking conversations $Folder");
      $Self->CheckFolderConversations($Folder);
    }
    $Self->CheckFolderModseq($Folder);
    next if $Level == 1;

    $Self->CheckFolderSizes($Folder);
    next if $Level == 2;

    $Self->CheckFolderEnvelopes($Folder);
    next if $Level == 3;

    # Force recheck of all sha1's on disk. Need level = 99
    next if $Level < 99;
    $Self->debug("$CyrusName full sha1 check for folder $Folder");
    $Self->CheckFullSHA1($Folder);
  }

  return $Self->{has_error};
}

sub CheckUserQuota {
  my ($Self) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  $Self->debug("$CyrusName checking quota");

  my $Repeat = 0;
  RepeatCheck:

  my $s1Quota = $IMAPs1->getquotaroot('INBOX');
  my $s1QuotaRoot = $s1Quota->{quotaroot}->[1] || '';
  my (undef, $s1MBUsed, $s1MBTotal) = @{$s1Quota->{$s1QuotaRoot} || []};
  $s1MBUsed ||= 0;
  $s1MBTotal ||= 0;

  my $s2Quota = $IMAPs2->getquotaroot('INBOX');
  my $s2QuotaRoot = $s2Quota->{quotaroot}->[1] || '';
  my (undef, $s2MBUsed, $s2MBTotal) = @{$s2Quota->{$s2QuotaRoot} || []};
  $s2MBUsed ||= 0;
  $s2MBTotal ||= 0;

  if ($s1MBUsed != $s2MBUsed || $s1MBTotal != $s2MBTotal) {
    $Self->do_repeat($Repeat, $CyrusName, "Quota mismatch: $s1MBUsed/$s1MBTotal vs $s2MBUsed/$s2MBTotal")
      || goto RepeatCheck;
  }
}

sub CheckUserSubs {
  my ($Self) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  $Self->debug("$CyrusName checking subscriptions");

  my $Repeat = 0;
  RepeatCheck:

  my $s1Subs = $IMAPs1->lsub('*', '*');
  if (!$s1Subs) {
    $Self->error("$CyrusName Couldn't subs on master: $@");
    return;
  }
  $s1Subs = [] unless ref($s1Subs) eq 'ARRAY';
  @$s1Subs = map { $_->[2] } @$s1Subs;
  @$s1Subs = grep { !/^user\./ } @$s1Subs if $Self->{IgnoreSharedSubs};
  my %s1data = map { $_ => 1 } @$s1Subs;

  my $s2Subs = $IMAPs2->lsub('*', '*');
  if (!$s2Subs) {
    $Self->error("$CyrusName Couldn't subs on replica: $@");
    return;
  }
  $s2Subs = [] unless ref($s2Subs) eq 'ARRAY';
  @$s2Subs = map { $_->[2] } @$s2Subs;
  @$s2Subs = grep { !/^user\./ } @$s2Subs if $Self->{IgnoreSharedSubs};
  my %s2data = map { $_ => 1 } @$s2Subs;

  my %ids = (%s1data, %s2data);

  foreach my $id (keys %ids) {
    if (!$s1data{$id} || !$s2data{$id}) {
      my $On = !$s1data{$id} ? "master" : "replica";
      $Self->do_repeat($Repeat, $CyrusName, "Missing subscription to $id on $On")
        || goto RepeatCheck;
    }
  }
}

sub CheckFolderBasic {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1Status = $IMAPs1->status($Folder, '(messages uidnext unseen recent uidvalidity highestmodseq)');
  if (!$s1Status) {
    $Self->error("$CyrusName Couldn't get status of '$Folder' on master: $@");
    return;
  }
  my $s2Status = $IMAPs2->status($Folder, '(messages uidnext unseen recent uidvalidity highestmodseq)');
  if (!$s2Status) {
    $Self->error("$CyrusName Couldn't get status of '$Folder' on replica: $@");
    return;
  }

  for (qw(messages uidnext unseen recent uidvalidity highestmodseq)) {
    unless (defined $s1Status->{$_} and defined $s2Status->{$_}) {
      $Self->error("$CyrusName status on $Folder undefined for $_");
      next;
    }
    if ($s1Status->{$_} != $s2Status->{$_}) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched $Folder/$_", "master=$s1Status->{$_}, replica=$s2Status->{$_}")
        || goto RepeatCheck;
    }
  }

  return ($s1Status->{messages} || $s2Status->{messages});
}

sub CheckFolderConversations {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1CIDs = $Self->do_fetch($IMAPs1, $CyrusName, 'cid') || return;
  my $s2CIDs = $Self->do_fetch($IMAPs2, $CyrusName, 'cid') || return;

  my %ids = (%$s1CIDs, %$s2CIDs);

  for (sort {$a <=> $b } keys %ids) {
    my $s1c = eval { join(' ', sort map { lc $_ } @{$s1CIDs->{$_}{cid}}) } || '';
    my $s2c = eval { join(' ', sort map { lc $_ } @{$s2CIDs->{$_}{cid}}) } || '';
    if ($s1c ne $s2c) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched cid for $Folder/$_", "master=$s1c, replica=$s2c")
        || goto RepeatCheck;
    }
  }

  my $s1Stat = $IMAPs1->status($Folder, "(xconvmodseq xconvexists xconvunseen)");
  my $s2Stat = $IMAPs2->status($Folder, "(xconvmodseq xconvexists xconvunseen)");

  foreach my $key (qw(xconvmodseq xconvexists xconvunseen)) {
    if ($s1Stat->{$key} != $s2Stat->{$key}) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched $key for $Folder", "master=$s1Stat->{$key}, replica=$s2Stat->{$key}")
        || goto RepeatCheck;
    }
  }
}

sub CheckFolderFlags {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1Flags = $Self->do_fetch($IMAPs1, $CyrusName, 'flags') || return;
  my $s2Flags = $Self->do_fetch($IMAPs2, $CyrusName, 'flags') || return;

  my %ids = (%$s1Flags, %$s2Flags);

  my %SkipFlags = (); #map { $_ => 1 } qw(\Recent \Seen);

  for (sort {$a <=> $b } keys %ids) {
    my $s1f = eval { join(' ', sort map { lc $_ } grep { !$SkipFlags{$_} } @{$s1Flags->{$_}{flags}}) } || '';
    my $s2f = eval { join(' ', sort map { lc $_ } grep { !$SkipFlags{$_} } @{$s2Flags->{$_}{flags}}) } || '';
    if ($s1f ne $s2f) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched flags for $Folder/$_", "master=$s1f, replica=$s2f")
        || goto RepeatCheck;
    }
  }
}

sub CheckFolderAnnots {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1Annot = $Self->do_fetch($IMAPs1, $CyrusName, '(annotation (* value))') || return;
  my $s2Annot = $Self->do_fetch($IMAPs2, $CyrusName, '(annotation (* value))') || return;

  my %ids = (%$s1Annot, %$s2Annot);

  for (sort {$a <=> $b } keys %ids) {
    unless (deepeq($s1Annot->{$_}, $s2Annot->{$_})) {
      my $s1v = Dump($s1Annot->{$_});
      my $s2v = Dump($s2Annot->{$_});
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched annots for $Folder/$_", "master=$s1v, replica=$s2v")
        || goto RepeatCheck;
    }
  }
}

sub CheckFolderMetadata {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1data = $IMAPs1->getmetadata($Folder, {DEPTH => 'infinity'}, '/private', '/shared');
  my $s2data = $IMAPs2->getmetadata($Folder, {DEPTH => 'infinity'}, '/private', '/shared');

  delete $s1data->{$Folder}{'/shared/vendor/cmu/cyrus-imapd/lastupdate'};
  delete $s2data->{$Folder}{'/shared/vendor/cmu/cyrus-imapd/lastupdate'};

  unless (deepeq($s1data, $s2data)) {
    # this field is not replicated and not consistent...
    my $s1v = Dump($s1data);
    my $s2v = Dump($s2data);
    $Self->do_repeat($Repeat, $CyrusName, "mistmatched metadata for $Folder", "master=$s1v, replica=$s2v")
      || goto RepeatCheck;
  }
}

sub CheckFolderEnvelopes {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1Res = $Self->do_fetch($IMAPs1, $CyrusName, 'envelope') || return;
  my $s2Res = $Self->do_fetch($IMAPs2, $CyrusName, 'envelope') || return;

  my %ids = (%$s1Res, %$s2Res);

  for (sort { $a <=> $b } keys %ids) {
    my $s1h = eval { $s1Res->{$_}{'envelope'} } || {};
    my $s2h = eval { $s2Res->{$_}{'envelope'} } || {};
    my $s1e = join(' ', map { "($_: " . ($s1h->{$_}||'') . ")" } sort keys %$s1h);
    my $s2e = join(' ', map { "($_: " . ($s2h->{$_}||'') . ")" } sort keys %$s2h);
    if ($s1e and not $s2e) {
      $Self->error("$CyrusName for '$Folder', '$_', exists only on replica");
    }
    elsif ($s2e and not $s1e) {
      $Self->do_repeat($Repeat, $CyrusName, "only exists on master $Folder/$_", "master=$s1e")
        || goto RepeatCheck;
    }
    elsif ($s1e ne $s2e) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched envelopes for $Folder/$_", "master=$s1e, replica=$s2e")
        || goto RepeatCheck;
    }
  }
}

sub CheckFolderSizes {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1Res = $Self->do_fetch($IMAPs1, $CyrusName, ['rfc822.size', 'digest.sha1']) || return;
  my $s2Res = $Self->do_fetch($IMAPs2, $CyrusName, ['rfc822.size', 'digest.sha1']) || return;

  my %ids = (%$s1Res, %$s2Res);

  for (sort { $a <=> $b } keys %ids) {
    my $s1f = eval { $s1Res->{$_}{'rfc822.size'} } || '';
    my $s2f = eval { $s2Res->{$_}{'rfc822.size'} } || '';
    my $s1g = eval { $s1Res->{$_}{'digest.sha1'} } || '';
    my $s2g = eval { $s2Res->{$_}{'digest.sha1'} } || '';
    if ($s1f and not $s2f) {
      $Self->error("$CyrusName for '$Folder', '$_', exists only on replica");
    }
    elsif ($s2f and not $s1f) {
      $Self->do_repeat($Repeat, $CyrusName, "only exists on master $Folder/$_", "master=$s1f, $s1g")
        || goto RepeatCheck;
    }
    elsif ($s1f ne $s2f) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched sizes for $Folder/$_", "master=$s1f, replica=$s2f")
        || goto RepeatCheck;
    }
    elsif ($s1g ne $s2g) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched guids for $Folder/$_", "master=$s1g, replica=$s2g")
        || goto RepeatCheck;
    }
    # every 1000th message
    elsif ($s1f and $s1f < 70000 and rand(1000) >= 999) { # 70k seems a resonable limit
      $Self->debug("Doing sha1 check on $CyrusName/$Folder/$_");
      my $s1message = $IMAPs1->fetch($_, 'rfc822.sha1');
      my $s2message = $IMAPs2->fetch($_, 'rfc822.sha1');
      next unless ($s1message->{$_}{'rfc822.sha1'} and $s2message->{$_}{'rfc822.sha1'}); # deleted?
      unless ($s1message->{$_}{'rfc822.sha1'} eq $s2message->{$_}{'rfc822.sha1'}) {
        $Self->error("$CyrusName for '$Folder', '$_', messages do not match");
      }
    }
  }
}

sub CheckFolderModseq {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1ms = $Self->do_fetch($IMAPs1, $CyrusName, 'modseq') || return;
  my $s2ms = $Self->do_fetch($IMAPs2, $CyrusName, 'modseq') || return;

  my %ids = (%$s1ms, %$s2ms);

  my %SkipFlags = (); #map { $_ => 1 } qw(\Recent \Seen);

  for (sort {$a <=> $b } keys %ids) {
    my $s1m = $s1ms->{$_}{modseq}[0] || 0;
    my $s2m = $s2ms->{$_}{modseq}[0] || 0;
    if ($s1m ne $s2m) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched modseq for $Folder/$_", "master=$s1m, replica=$s2m")
        || goto RepeatCheck;
    }
  }
}

sub CheckFullSHA1 {
  my ($Self, $Folder) = @_;
  my $IMAPs1 = $Self->{IMAPs1};
  my $IMAPs2 = $Self->{IMAPs2};
  my $CyrusName = $Self->{CyrusName};

  my $Repeat = 0;
  RepeatCheck:

  my $s1Res = $Self->do_fetch($IMAPs1, $CyrusName, 'rfc822.sha1') || return;
  my $s2Res = $Self->do_fetch($IMAPs2, $CyrusName, 'rfc822.sha1') || return;

  my %ids = (%$s1Res, %$s2Res);

  for (sort { $a <=> $b } keys %ids) {
    my $s1s = eval { $s1Res->{$_}{'rfc822.sha1'} } || '';
    my $s2s = eval { $s2Res->{$_}{'rfc822.sha1'} } || '';
    if ($s1s and not $s2s) {
      $Self->error("$CyrusName for '$Folder', sha1 of '$_', exists only on replica");
    }
    elsif ($s2s and not $s1s) {
      $Self->do_repeat($Repeat, $CyrusName, "only sha1 exists on master $Folder/$_", "master=$s1s")
        || goto RepeatCheck;
    }
    elsif ($s1s ne $s2s) {
      $Self->do_repeat($Repeat, $CyrusName, "mistmatched sha1 for $Folder/$_", "master=$s1s, replica=$s2s")
        || goto RepeatCheck;
    }
  }
}

sub do_fetch {
  my $Self = shift;
  my ($IMAP, $CyrusName, @Items) = @_;

  # $IMAP->fetch(...) currently returns undef if no messages because:
  # . fetch 1:* flags
  # . NO No matching messages (0.000 sec)
  # This sub returns {} for a fetch on an empty folder

  my $Uids = $IMAP->search('1:*');
  if (!$Uids) {
    $Self->error("$CyrusName Couldn't search '$IMAP->{CurrentFolder}' on $IMAP->{SType}: $@");
    return undef;
  }

  my $Res = $Items[0] eq 'flags' ? $IMAP->fetch_flags('1:*') : $IMAP->fetch('1:*', @Items);
  $Res = {} if !$Res && ref($Uids) && !@$Uids;
  if (!$Res) {
    $Self->error("$CyrusName Couldn't fetch $Items[0] in '$IMAP->{CurrentFolder}' on $IMAP->{SType}: $@");
    return undef;
  }

  return $Res;
}

sub do_repeat {
  my $Self = shift;
  $_[0]++;
  my ($Repeat, $UserName, $Msg, @Data) = @_;
  if ($Repeat <= $Self->{NumRepeats}) {
    $Self->debug("$UserName, $Msg @Data, try $Repeat");
    sleep($Self->{SleepTime}) if $Self->{SleepTime};
    return 0;
  }

  my $Error = join ", ", map { ref($_) ? Dump($_) : $_ } @Data;
  $Self->error("$UserName, $Msg: $Error");

  # Reset repeat count
  return 1;
}

sub get_type {
  my $Msg = shift;
  return 'QUOTA' if $Msg =~ m/Quota mismatch/;
  return 'CONV' if $Msg =~ m/xconv/i;
  return 'RECONSTRUCT';
}

# Logging

sub notice {
  my $Self = shift;
  my $Message = shift;
  unless ($Self->{Quiet}) {
    $Self->do_output("NOTICE: $Message");
  }
}

sub debug {
  my $Self = shift;
  my $Message = shift;
  if ($Self->{Debug}) {
    $Self->do_output("DEBUG: $Message");
  }
}

sub error {
  my $Self = shift;
  my $Message = shift;
  $Self->{HasError} = 1;
  $Self->do_output("ERROR: $Message");
}

sub do_output {
  my $Self = shift;
  my $Message = shift;
  chomp($Message);
  unless ($Self->{Silent}) {
    if ($Self->{LogFile}) {
      $Self->{LogFile}->print("$Message\n");
    }
    else {
      print "$Message\n";
    }
  }
  push @{$Self->{Messages}}, $Message;
}

sub GetMessages {
  my $Self = shift;
  $Self->{Messages} ||= [];
  return wantarray ? @{$Self->{Messages}} : $Self->{Messages};
}

sub HasError {
  my $Self = shift;
  return $Self->{HasError};
}

sub _fname {
  my $CyrusName = shift;
  my $Folder = shift;

  my $Domain;
  if ($CyrusName =~ s{\@(.*)}{}) {
    $Domain = $1;
  }

  $Folder =~ s{^INBOX}{user.$CyrusName};
  $Folder .= '@' . $Domain if $Domain;

  return $Folder;
}

1;
