#
# Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
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

package Cyrus::IMAP::Admin;
use strict;
use Cyrus::IMAP;
use vars qw($VERSION
            *create *delete *deleteacl *listacl *list *rename *setacl
            *subscribed *quota *quotaroot *info *setinfo *xfer
            *subscribe *unsubscribe);

$VERSION = '1.00';

#
# NB:  there are hooks (which error out in all cases) for IMSP support in Tcl
# cyradm.  I'll add them if I ever see what they're supposed to do... after
# coming up with perl IMSP/ACAP hooks.
#
# ASSUMPTION:  the somewhat unwieldy cyradm names are because the interpreter
# causes collisions, so I can get away with shorter versions here.
#

# callback when referral stream closes
sub _cb_ref_eof {
  my %cb = @_;
  # indicate that the connection went away
  print STDERR "\nReferral connection to server lost.\n";
  ${$cb{-rock}} = undef;
}

sub new {
  my $class = shift;
  my $self = bless {}, $class;
  $self->{cyrus} = Cyrus::IMAP->new(@_) or $self = undef;

  # Figure out if the remote supports MAILBOX-REFERRALS
  # This is sort of annoying that authenticate also issues a CAPABILITY
  # but the API makes it difficult to get at the results of that command.
  if(defined($self)) {
    $self->{support_referrals} = 0;
    $self->{support_annotatemore} = 0;
    $self->{support_list_extended} = 0;
    $self->{support_list_special_use} = 0;
    $self->{support_create_special_use} = 0;
    $self->{authopts} = [];
    $self->addcallback({-trigger => 'CAPABILITY',
                        -callback => sub {my %a = @_;
                                          map {
                                                # RFC 2193 IMAP4 Mailbox Referrals
                                                $self->{support_referrals} = 1
                                                  if /^MAILBOX-REFERRALS$/i;
                                                $self->{support_annotatemore} = 1
                                                  if /^ANNOTATEMORE$/i;
                                                $self->{support_metadata} = 1
                                                  if /^METADATA$/i;
                                                # RFC 5258 IMAPv4 - LIST Command Extensions
                                                $self->{support_list_extended} = 1
                                                  if /^LIST-EXTENDED$/i;
                                                # RFC 6154 - IMAP LIST Extension for Special-Use Mailboxes
                                                $self->{support_list_special_use} = 1
                                                  if /^SPECIAL-USE$/i;
                                                # RFC 6154 - IMAP LIST Extension for Special-Use Mailboxes
                                                $self->{support_create_special_use} = 1
                                                  if /^CREATE-SPECIAL-USE$/i;
                                              }
                                          split(/ /, $a{-text})}});
    $self->send(undef, undef, 'CAPABILITY');
    $self->addcallback({-trigger => 'CAPABILITY'});
  }

  $self;
}

# yuck.
# I intended this to be a subclass of Cyrus::IMAP, but that's a scalar ref so
# there's nowhere to hang the error information.  Indexing a "private" hash
# with the scalar sucks fully as much IMHO.  So we forward the Cyrus::IMAP
# methods on demand.
#
# yes, this is ugly.  but the overhead is minimized this way.
sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  no strict 'refs';
  $AUTOLOAD =~ s/^.*:://;
  my $sub = $Cyrus::IMAP::{$AUTOLOAD};
  *$AUTOLOAD = sub { &$sub($_[0]->{cyrus}, @_[1..$#_]); };
  goto &$AUTOLOAD;
}

# Wrap around Cyrus::IMAP's authenticate, so that we are sure to
# send an rlist command if they support referrals
sub authenticate {
    my $self = shift;
    if(@_) {
      $self->{authopts} = \@_;
    }
    my $rc = $self->{cyrus}->authenticate(@_);
    if($rc && $self->{support_referrals}) {
      # Advertise our desire for referrals
      my $msg;
      ($rc, $msg) = $self->send('', '', 'RLIST "" ""');
      if($rc eq "OK") {
        $rc = 1;
      } else {
        $rc = 0;
      }
    }
    return $rc;
}

# Spit out a reference to the previous authentication options:
sub _getauthopts {
    my $self = shift;
    return $self->{authopts};
}

sub reconstruct {
    my ($self, $mailbox, $recurse) = @_;
    my $rc;
    my $msg;
    if($recurse == 1) {
      ($rc, $msg) = $self->send('', '', 'RECONSTRUCT %s RECURSIVE',
                                $mailbox);
    } else {
      ($rc, $msg) = $self->send('', '', 'RECONSTRUCT %s', $mailbox);
    }
    $self->{error} = $msg;
    if($rc eq "OK") {
      $rc = 1;
    } else {
      if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
        my ($refserver, $box) = $self->fromURL($1);
        my $port = 143;

        if($refserver =~ /:/) {
          $refserver =~ /([^:]+):(\d+)/;
          $refserver = $1; $port = $2;
        }

        my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
          or die "cyradm: cannot connect to $refserver\n";
        $cyradm->addcallback({-trigger => 'EOF',
                              -callback => \&_cb_ref_eof,
                              -rock => \$cyradm});
        $cyradm->authenticate(@{$self->_getauthopts()})
          or die "cyradm: cannot authenticate to $refserver\n";

        my $ret = $cyradm->reconstruct($mailbox,$recurse);
        $self->{error} = $cyradm->{error};
        $cyradm = undef;
        return $ret;
      } else {
        $rc = 0;
      }
    }
    return $rc;
}

sub createmailbox {
  my ($self, $mbx, $partition, $opts) = @_;
  my $cmd = "CREATE %s";
  my @args = ();
  # RFC 3501 + cyrus:    CREATE mailbox [partition]
  # RFC 4466 + RFC 6154: CREATE mailbox ([PARTITION partition ]USE (special-use))
  if (defined ($$opts{'-specialuse'})) {
    if($self->{support_create_special_use}) {
      if (defined ($partition)) {
        $cmd .= " (PARTITION %a USE (%a))" ;
        push @args, ($partition, $$opts{'-specialuse'});
      } else {
        $cmd .= " (USE (%a))" ;
        push @args, $$opts{'-specialuse'};
      }
    } else {
      $self->{error} = "Remote does not support CREATE-SPECIAL-USE.";
      return undef;
    }
  } elsif (defined ($partition)) {
    $cmd .= " %a";
    push @args, $partition;
  }
  my ($rc, $msg) = $self->send('', '', $cmd, $mbx, @args);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->createmailbox($box);
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}
*create = *createmailbox;

sub deletemailbox {
  my ($self, $mbx) = @_;
  my ($rc, $msg) = $self->send('', '', 'DELETE %s', $mbx);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->deletemailbox($box);
      $self->{error} = $cyradm->error;
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}
*delete = *deletemailbox;

sub deleteaclmailbox {
  my ($self, $mbx, @acl) = @_;
  my $cnt = 0;
  my $res = '';
  my ($rc, $msg);
  foreach my $acl (@acl) {
    ($rc, $msg) = $self->send('', '', 'DELETEACL %s %s', $mbx, $acl);
    if ($rc eq 'OK') {
      $cnt++;
    } else {
      if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
        my ($refserver, $box) = $self->fromURL($1);
        my $port = 143;

        if($refserver =~ /:/) {
          $refserver =~ /([^:]+):(\d+)/;
          $refserver = $1; $port = $2;
        }

        my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
          or die "cyradm: cannot connect to $refserver\n";
        $cyradm->addcallback({-trigger => 'EOF',
                              -callback => \&_cb_ref_eof,
                              -rock => \$cyradm});
        $cyradm->authenticate(@{$self->_getauthopts()})
          or die "cyradm: cannot authenticate to $refserver\n";

        $cnt += $cyradm->deleteaclmailbox($mbx,$acl);

        $res .= "\n" if $res ne '';
        $res .= $acl . ': ' . $cyradm->{error};

        $cyradm = undef;
      } else {
        $rc = 0;
      }
      $res .= "\n" if $res ne '';
      $res .= $acl . ': ' . $msg;
    }
  }
  if ($res eq '') {
    $self->{error} = undef;
  } else {
    $self->{error} = $res;
  }
  $cnt;
}
*deleteacl = *deleteaclmailbox;

sub listaclmailbox {
  my ($self, $mbx) = @_;
  my %info = ();
  $self->addcallback({-trigger => 'ACL',
                      -callback => sub {
                        my %d = @_;
                        return unless $d{-text} =~ s/^\"*\Q$mbx\E\"*\s+//;
                        while ($d{-text} =~ s/(\S+)\s+(\S+)\s*//) {
                          $d{-rock}{$1} = $2;
                        }
                      },
                      -rock => \%info});
  my ($rc, $msg) = $self->send('', '', 'GETACL %s', $mbx);
  $self->addcallback({-trigger => 'ACL'});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    %info;
  } else {
    $self->{error} = $msg;
    ();
  }
}
*listacl = *listaclmailbox;

sub listmailbox {
  my ($self, $pat, $ref, $opts) = @_;
  $ref ||= "";
  my @info = ();
  my $list_cmd;
  my @list_sel;
  my @list_ret;
  if($self->{support_referrals}) {
    if ($self->{support_list_extended}) {
      $list_cmd = 'LIST';
      push @list_sel, "REMOTE";
    } else {
      $list_cmd = 'RLIST';
    }
  } else {
    $list_cmd = 'LIST';
  }

  if(defined ($$opts{'-sel-special-use'}) && !$self->{support_list_special_use}) {
    $self->{error} = "Remote does not support SPECIAL-USE.";
    return undef;
  }

  if((defined ($$opts{'-sel-special-use'}) ||
      defined ($$opts{'-sel-recursivematch'}) ||
      defined ($$opts{'-sel-subscribed'}))
     && !$self->{support_list_extended}) {
    $self->{error} = "Remote does not support LIST-EXTENDED.";
    return undef;
  }

  if ($self->{support_list_extended}) {
    push @list_ret, "SUBSCRIBED";
    # "The RECURSIVEMATCH option MUST NOT occur as the only selection
    #  option (or only with REMOTE), as it only makes sense when other
    #  selection options are also used."
    push @list_sel, "RECURSIVEMATCH"
      if defined ($$opts{'-sel-recursivematch'});

    push @list_sel, "SUBSCRIBED"
      if defined ($$opts{'-sel-subscribed'});

    if($self->{support_list_special_use}) {
      # always return special-use flags
      push @list_ret, "SPECIAL-USE";
      push @list_sel, "SPECIAL-USE"
        if defined ($$opts{'-sel-special-use'});
    }
  }

  # RFC 5258:
  # "By adding options to the LIST command, we are announcing the intent
  # to phase out and eventually to deprecate the RLIST and RLSUB commands
  # described in [MBRef])."
  #
  # This should never trigger: MAILBOX-REFERRALS and SPECIAL-USE but no
  # LIST-EXTENDED.
  if ($list_cmd eq "RLIST" && (scalar (@list_ret) > 0 || scalar (@list_sel) > 0)) {
    $self->{error} = "Invalid capabilities: MAILBOX-REFERRALS and SPECIAL-USE but no LIST-EXTENDED.";
    return undef;
  }

  $self->addcallback({-trigger => 'LIST',
                      -callback => sub {
                        my %d = @_;
                        next unless $d{-text} =~ s/^\(([^\)]*)\) //;
                        my $attrs = $1;
                        my $sep = '';
                        my $mbox;
                        my $extended;
                        # NIL or (attrs) "sep" "str"
                        if ($d{-text} =~ /^N/) {
                          return if $d{-text} !~ s/^NIL//;
                        }
                        elsif ($d{-text} =~ s/\"\\?(.)\"//) {
                          $sep = $1;
                        }
                        return unless $d{-text} =~ s/^ //;
                        if ($d{-text} =~ /{\d+}(.*)/) {
                          # cope with literals (?)
                          (undef, $mbox) = split(/\n/, $d{-text});
                        } elsif ($d{-text} =~ /^\"(([^\\\"]*\\)*[^\\\"]*)\"/) {
                          ($mbox = $1) =~ s/\\(.)/$1/g;
                        } else {
                          $d{-text} =~ s/^([]!\#-[^-~]+)//;
                          $mbox = $1;
                        }
                        if ($d{-text} =~ s/^ \(("{0,1}[^" ]+"{0,1} \("[^"]*"\))\)//) {
                          # RFC 5258: mbox-list-extended =  "(" [mbox-list-extended-item
                          #              *(SP mbox-list-extended-item)] ")"
                          $extended = $1;
                        }
                        push @{$d{-rock}}, [$mbox, $attrs, $sep, $extended];
                      },
                      -rock => \@info});

  # list =      "LIST" [SP list-select-opts] SP mailbox SP mbox-or-pat
  #             [SP list-return-opts]
  my @args = ();
  my $cmd = $list_cmd;
  if (scalar (@list_sel) > 0) {
    $cmd .= " (%a)";
    push @args, join (" ", @list_sel);
  }
  $cmd .= " %s %s";
  push @args, ($ref, $pat);
  if (scalar (@list_ret) > 0) {
    $cmd .= " RETURN (%a)";
    push @args, join (" ", @list_ret);
  }
  my ($rc, $msg) = $self->send('', '', $cmd, @args);
  $self->addcallback({-trigger => $list_cmd});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    @info;
  } else {
    $self->{error} = $msg;
    ();
  }
}
*list = \&listmailbox;

sub listsubscribed {
  my ($self, $pat, $ref) = @_;
  $ref ||= $pat;
  my @info = ();
  my $list_cmd;
  if($self->{support_referrals}) {
    $list_cmd = 'RLSUB';
  } else {
    $list_cmd = 'LSUB';
  }
  $self->addcallback({-trigger => 'LSUB',
                      -callback => sub {
                        my %d = @_;
                        next unless $d{-text} =~ s/^\(([^\)]*)\) //;
                        my $attrs = $1;
                        my $sep = '';
                        # NIL or (attrs) "sep" "str"
                        if ($d{-text} =~ /^N/) {
                          return if $d{-text} !~ s/^NIL//;
                        }
                        elsif ($d{-text} =~ s/\"\\?(.)\"//) {
                          $sep = $1;
                        }
                        return unless $d{-text} =~ s/^ //;
                        my $mbox;
                        if ($d{-text} =~ /\"(([^\\\"]*\\.)*[^\\\"]*)\"/) {
                          ($mbox = $1) =~ s/\\(.)/$1/g;
                        } else {
                          $d{-text} =~ /^([]!\#-[^-~]+)/;
                          $mbox = $1;
                        }
                        push @{$d{-rock}}, [$mbox, $attrs, $sep];
                      },
                      -rock => \@info});
  my ($rc, $msg) = $self->send('', '', "$list_cmd %s %s", $pat, $ref);
  $self->addcallback({-trigger => $list_cmd});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    @info;
  } else {
    $self->{error} = $msg;
    ();
  }
}
*subscribed = \&listsubscribed;

sub listquota {
  my ($self, $root) = @_;
  my @info = ();
  $self->addcallback({-trigger => 'QUOTA',
                      -callback => sub {
                        my %d = @_;
                        next unless
                          $d{-text} =~ s/^\S+.* \((\S*) *?(\S*) *?(\S*)\)//;
                        push @{$d{-rock}}, $1, [$2, $3];
                      },
                      -rock => \@info});
  my ($rc, $msg) = $self->send('', '', 'GETQUOTA %s', $root);
  $self->addcallback({-trigger => 'QUOTA'});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    @info;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my @ret = $cyradm->listquota($root);
      $self->{error} = $cyradm->{error};
      $cyradm = undef;
      return @ret;
    } else {
      $self->{error} = $msg;
      ();
    }
  }
}
*quota = *listquota;

sub listquotaroot {
  my ($self, $root) = @_;
  my $qr = '';
  my @info = ();
  $self->addcallback({-trigger => 'QUOTAROOT',
                      -callback => sub {
                        my %d = @_;
                        return unless ( $d{-text} =~ /^\"[^\"]+\" \"([^\"]+)\"/ or
                                       $d{-text} =~ /^\"[^\"]+\" (\S+)/ or
                                       $d{-text} =~ /[^\"]\S+ \"([^\"]+)\"/ or
                                       $d{-text} =~ /^[^\"]\S+ (\S+)/
                                       );
                        ${$d{-rock}} = $1;
                      },
                      -rock => \$qr},
                     {-trigger => 'QUOTA',
                      -callback => sub {
                        my %d = @_;
                        return unless
                          $d{-text} =~ s/\((\S+) (\S+) (\S+)\)$//;
                        push @{$d{-rock}}, $1, [$2, $3];
                      },
                      -rock => \@info});
  my ($rc, $msg) = $self->send('', '', 'GETQUOTAROOT %s', $root);
  $self->addcallback({-trigger => 'QUOTA'}, {-trigger => 'QUOTAROOT'});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    ($qr, @info);
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my @ret = $cyradm->listquotaroot($root);
      $self->{error} = $cyradm->{error};
      $cyradm = undef;
      return @ret;
    } else {
      $self->{error} = $msg;
      ();
    }
  }
}
*quotaroot = *listquotaroot;

sub renamemailbox {
  my ($self, $src, $dest, $ptn) = @_;

  $self->addcallback({-trigger => 'NO',
                      -callback => sub {
                        print $_ . "\n";
                      }});

  my ($rc, $msg);
  if ($ptn) {
    ($rc, $msg) = $self->send('', '', 'RENAME %s %s %a', $src, $dest, $ptn);
  }
  else {
    ($rc, $msg) = $self->send('', '', 'RENAME %s %s', $src, $dest);
  }

  $self->addcallback({-trigger => 'NO'});

  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} &&
       $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\s+([^\]\s]+)\]|) {
      # We need two referrals for this to be valid
      my ($refserver, $box) = $self->fromURL($1);
      my ($refserver2, $nbox) = $self->fromURL($2);
      my $port = 143;

      if(!($refserver eq $refserver2)) {
        $self->{error} = "Inter-server referral.  Not implemented.";
        return 1;
      }

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->renamemailbox($box, $box, $nbox);
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}
*rename = *renamemailbox;

sub xfermailbox {
  my ($self, $mbox, $server, $ptn) = @_;

  $self->addcallback({-trigger => 'NO',
                      -callback => sub {
                        print $_ . "\n";
                      }});

  my ($rc, $msg) = $self->send('', '', 'XFER %s %s%a%a', $mbox, $server,
                               $ptn ? ' ' : $ptn, $ptn);

  $self->addcallback({-trigger => 'NO'});

  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    $self->{error} = $msg;
    undef;
  }
}
*xfer = *xfermailbox;

# hm.  this list can't be confused with valid ACL values as of 1.6.19, except
# for "all".  sigh.
my %aclalias = (none => '',
                read => 'lrs',
                post => 'lrsp',
                append => 'lrsip',
                write => 'lrswipkxte',
                delete => 'lrxte',
                all => 'lrswipkxtea');

sub setaclmailbox {
  my ($self, $mbx, %acl) = @_;
  my $cnt = 0;
  my $res = '';
  my ($rc, $msg);
  foreach my $id (keys %acl) {
    $acl{$id} = $aclalias{$acl{$id}} if defined $aclalias{$acl{$id}};
    ($rc, $msg) = $self->send('', '', 'SETACL %s %s %s', $mbx, $id, $acl{$id});
    if ($rc eq 'OK') {
      $cnt++;
    } else {
      if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
        my ($refserver, $box) = $self->fromURL($1);
        my $port = 143;

        if($refserver =~ /:/) {
          $refserver =~ /([^:]+):(\d+)/;
          $refserver = $1; $port = $2;
        }

        my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
          or die "cyradm: cannot connect to $refserver\n";
        $cyradm->addcallback({-trigger => 'EOF',
                              -callback => \&_cb_ref_eof,
                              -rock => \$cyradm});
        $cyradm->authenticate(@{$self->_getauthopts()})
          or die "cyradm: cannot authenticate to $refserver\n";

        my $ret = $cyradm->setaclmailbox($mbx, %acl);
        if(defined($ret)) {
          $cnt++;
          $rc = 'OK';
        } else {
          $res .= "\n" if $res ne '';
          $res .= $id . ': ' . $acl{$id} . ': ' . $cyradm->{error};
        }
      } else {
        $res .= "\n" if $res ne '';
        $res .= $id . ': ' . $acl{$id} . ': ' . $msg;
      }
    }
  }
  if ($rc eq 'OK') {
    $self->{error} = undef;
    $cnt;
  } else {
    $self->{error} = $res;
    undef;
  }
}
*setacl = *setaclmailbox;

sub setquota {
  my ($self, $mbx, %quota) = @_;
  foreach my $id (keys %quota) {
    if ($id !~ /^[]!\#-[^-~]+$/) {
        $self->{error} = $id . ': not an atom';
        return undef;
    }
    if ($quota{$id} !~ /^\d+$/) {
        $self->{error} = $id . ': ' . $quota{$id} . ': not a number';
        return undef;
    }
  }
  my ($rc, $msg) = $self->send('', '', 'SETQUOTA %s (%v)', $mbx, \%quota);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->setquota($mbx, %quota);
      $cyradm = undef;
      return $ret;
    } else {
      $self->{error} = $msg;
      undef;
    }
  }
}


# map protocol name to user visible name
sub _attribname2access {
  my $k = shift;

  if ($k eq 'value.priv' ) {
     return 'private';
  } elsif ($k eq 'value.shared') {
     return 'shared';
  } else {
    return $k;
  }
}

sub getinfo {
  my $self = shift;
  my $box = shift;
  my @entries = @_;

  if(!defined($box)) {
    $box = "";
  }

  if(!$self->{support_annotatemore}) {
    $self->{error} = "Remote does not support ANNOTATEMORE.";
    return undef;
  }

  my %info = ();
  $self->addcallback({-trigger => 'ANNOTATION',
                      -callback => sub {
                        my %d = @_;
                        my $text = $d{-text};

                        # There were several draft iterations of this,
                        # but since we send only the latest form command,
                        # this is the only possible response.

                        # Regex 1 (Shared-Folder, user folder looks similar):
                        # cyrus imapd 2.5.0
                        # folder "/vendor/cmu/cyrus-imapd/expire" ("value.shared" "90")
                        # 1      2                                 3              4
                        # folder "/vendor/cmu/cyrus-imapd/pop3showafter" ("value.shared" NIL)
                        # 1      2                                        3              4
                        # folder "/specialuse" ("value.priv" NIL "value.shared" NIL)
                        # 1      2              3            4   5              6

                        # cyrus imapd 2.4.17
                        # "folder" "/vendor/cmu/cyrus-imapd/partition" ("value.shared" "default")
                        # 1        2                                    3              4

                        # cyrus imapd 2.2.13
                        # "folder" "/vendor/cmu/cyrus-imapd/expire" ("value.shared" "90")
                        # 1        2                                 3              4

                        # Regex 1: server info
                        # cyrus imapd 2.5.0
                        # "" "/comment" ("value.shared" "test")
                        # 1  2           3              4
                        # "" "/motd" ("value.shared" NIL)
                        # 1  2        3              4
                        # "" "/vendor/cmu/cyrus-imapd/expire" ("value.priv" NIL "value.shared" NIL)
                        # 1  2                                 3            4   5              6

                        # cyrus imapd 2.4.17
                        # "" "/vendor/cmu/cyrus-imapd/freespace" ("value.shared" "3122744")
                        # 1  2                                    3              4

                        # Regex 2
                        # cyrus imapd 2.5.0 (user folder, authorized as user)
                        # Note: two lines
                        # INBOX.Sent "/specialuse" ("value.priv" {5}\r\n
                        # \Sent)>
                        # 1          2              3            4\r\n
                        # 5

                        if ($text =~
                               /^\s*\"?([^"]*)"?\s+"?([^"]*)"?\s+\(\"?([^"\{]*)\"?\s+\"?([^"\{]*)\"?(?:\s+\"?([^"\{]*)\"?\s+\"?([^"\{]*)\"?)?\)/) {
                          my $key;
                          if($1 ne "") {
                                $key = "/mailbox/$2";
                          } else {
                                $key = "/server/$2";
                          }
                          $d{-rock}->{"$1"}->{_attribname2access($3)}->{$key} = $4;
                          $d{-rock}->{"$1"}->{_attribname2access($5)}->{$key} = $6 if (defined ($5) && defined ($6));
                        }  elsif ($text =~
                               /^\s*"([^"]*)"\s+"([^"]*)"\s+\("([^"\{]*)"\s+\{(.*)\}\r\n/ ||
                           $text =~
                               /^\s*([^\s]+)\s+"([^"]*)"\s+\("([^"\{]*)"\s+\{(.*)\}\r\n/) {
                          my $len = $4;
                          $text =~ s/^\s*"*([^"\s]*)"*\s+"([^"]*)"\s+\("([^"\{]*)"\s+\{(.*)\}\r\n//s;
                          $text = substr($text, 0, $len);
                          # Single annotation (literal style),
                          # possibly multiple values -- multiple
                          # values not tested.

                          my $key;
                          if($1 ne "") {
                                $key = "/mailbox/$2";
                          } else {
                                $key = "/server$2";
                          }
                          $d{-rock}{"$1"}->{_attribname2access($3)}->{$key} = $text;
                        } else {
                          ; # XXX: unrecognized line, how to notify caller?
                        }
                      },
                      -rock => \%info});

  # send getannotation "/mailbox/name/* or /server/*"
  my($rc, $msg);
  if(scalar(@entries)) {
    foreach my $annot (@entries) {
      ($rc, $msg) = $self->send('', '', 'GETANNOTATION %s %q ("value.priv" "value.shared")',
                                $box, $annot);
      last if($rc ne 'OK');
    }
  } else {
    ($rc, $msg) = $self->send('', '', 'GETANNOTATION %s "*" ("value.priv" "value.shared")',
                              $box);
  }
  $self->addcallback({-trigger => 'ANNOTATION'});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    %info;
  } else {
    $self->{error} = $msg;
    ();
  }
}
*info = *getinfo;

sub mboxconfig {
  my ($self, $mailbox, $entry, $value, $private) = @_;

  my %values = ( "comment" => "/comment",
                 "expire" => "/vendor/cmu/cyrus-imapd/expire",
                 "news2mail" => "/vendor/cmu/cyrus-imapd/news2mail",
                 "sharedseen" => "/vendor/cmu/cyrus-imapd/sharedseen",
                 "sieve" => "/vendor/cmu/cyrus-imapd/sieve",
                 "squat" => "/vendor/cmu/cyrus-imapd/squat",
                 "pop3showafter" => "/vendor/cmu/cyrus-imapd/pop3showafter" );

  if(!$self->{support_annotatemore}) {
    $self->{error} = "Remote does not support ANNOTATEMORE.";
    return undef;
  }

  if(exists($values{$entry})) {
    $entry = $values{$entry};
  } else {
    $self->{error} = "Unknown parameter $entry" unless substr($entry,0,1) eq "/";
  }

  my ($rc, $msg);

  $value = undef if($value eq "none");
  my $attribname;
  if (defined ($private)) {
    $attribname = "value.priv";
  } else {
    $attribname = "value.shared";
  }

  if(defined($value)) {
    ($rc, $msg) = $self->send('', '',
                              'SETANNOTATION %q %q (%q %q)',
                              $mailbox, $entry, $attribname, $value);
  } else {
    ($rc, $msg) = $self->send('', '',
                              'SETANNOTATION %q %q (%q NIL)',
                              $mailbox, $entry, $attribname);
  }

  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->mboxconfig($mailbox, $entry, $value);
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}

sub setinfoserver {
  my ($self, $entry, $value) = @_;

  if(!$self->{support_annotatemore}) {
    $self->{error} = "Remote does not support ANNOTATEMORE.";
    return undef;
  }

  my %values = ( "comment" => "/comment",
                 "motd" => "/motd",
                 "admin" => "/admin",
                 "shutdown" => "/vendor/cmu/cyrus-imapd/shutdown",
                 "expire" => "/vendor/cmu/cyrus-imapd/expire",
                 "squat" => "/vendor/cmu/cyrus-imapd/squat");

  $entry = $values{$entry} if (exists($values{$entry}));

  $value = undef if($value eq "none");

  my ($rc, $msg);

  if(defined($value)) {
    ($rc, $msg) = $self->send('', '',
                              "SETANNOTATION \"\" %q (\"value.shared\" %q)",
                              $entry, $value);
  } else {
    ($rc, $msg) = $self->send('', '',
                              "SETANNOTATION \"\" %q (\"value.shared\" NIL)",
                              $entry);
  }

  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    $self->{error} = $msg;
    undef;
  }
}
*setinfo = *setinfoserver;

sub getmetadata {
  my $self = shift;
  my $box = shift;
  my @entries = @_;

  if(!defined($box)) {
    $box = "";
  }

  if(!$self->{support_metadata}) {
    $self->{error} = "Remote does not support METADATA.";
    return undef;
  }

  my %info = ();
  $self->addcallback({-trigger => 'METADATA',
                      -callback => sub {
                        my %d = @_;
                        my $text = $d{-text};

                        # There were several draft iterations of this,
                        # but since we send only the latest form command,
                        # this is the only possible response.

                        if ($text =~
                                /^\s*\"?([^\(]*?)\"?\s+\(\"?([^"\{]*)\"?\s+\"?([^"\)\{]*)\"?\)/) {
                            my $mdbox = $1;
                            my $mdkey = $2;
                            my $mdvalue = $3;
                            if($mdbox ne "") {
                                $mdkey = "/mailbox/$mdkey";
                                if ($mdkey =~ /private/) {
                                    $d{-rock}->{"$mdbox"}->{'private'}->{$mdkey} = $mdvalue;
                                } elsif ($mdkey =~ /shared/) {
                                    $d{-rock}->{"$mdbox"}->{'shared'}->{$mdkey} = $mdvalue;
                                }
                          } else {
                                $mdkey = "/server/$mdkey";
                                if ($mdkey =~ /private/) {
                                    $d{-rock}->{"$mdbox"}->{'private'}->{$mdkey} = $mdvalue;
                                } elsif ($mdkey =~ /shared/) {
                                    $d{-rock}->{"$mdbox"}->{'shared'}->{$mdkey} = $mdvalue;
                                }
                            }
                        }  elsif ($text =~
                                /^\s*\"?([^\(]*?)\"?\s+\(\"?([^"\{]*?)\"?\s+\{(.*)\}\r\n/) {
                          my $mdbox = $1;
                          my $mdkey = $2;
                          my $len = $3;
                          $text =~ s/^\s*\"?([^\(]*?)\"?\s+\(\"?([^"]*)\"?\s+\{(.*)\}\r\n//s;
                          my $mdvalue = substr($text, 0, $len);
                          # Single annotation (literal style),
                          # possibly multiple values -- multiple
                          # values not tested.
                          if($mdbox ne "") {
                              $mdkey = "/mailbox/$mdkey";
                              if ($mdkey =~ /private/) {
                                  $d{-rock}->{"$mdbox"}->{'private'}->{$mdkey} = $mdvalue;
                              } elsif ($mdkey =~ /shared/) {
                                  $d{-rock}->{"$mdbox"}->{'shared'}->{$mdkey} = $mdvalue;
                              }
                          } else {
                              $mdkey = "/server/$mdkey";
                              if ($mdkey =~ /private/) {
                                  $d{-rock}->{"$mdbox"}->{'private'}->{$mdkey} = $mdvalue;
                              } elsif ($mdkey =~ /shared/) {
                                  $d{-rock}->{"$mdbox"}->{'shared'}->{$mdkey} = $mdvalue;
                              }
                          }
                        } else {
                            ; # XXX: unrecognized line, how to notify caller?
                          1;
                        }
                      },
                      -rock => \%info});

  # send getmetadata "/mailbox/name/* or /private/* and /shared/*"
  my($rc, $msg);
  if(scalar(@entries)) {
    foreach my $annot (@entries) {
      ($rc, $msg) = $self->send('', '', "GETMETADATA %s (%q)",
                                $box, $annot);
      last if($rc ne 'OK');
    }
  } else {
    ($rc, $msg) = $self->send('', '', "GETMETADATA %s (\"/private/*\")",
                              $box);
    ($rc, $msg) = $self->send('', '', "GETMETADATA %s (\"/shared/*\")",
                              $box);
  }
  $self->addcallback({-trigger => 'METADATA'});
  if ($rc eq 'OK') {
    $self->{error} = undef;
    %info;
  } else {
    $self->{error} = $msg;
    ();
  }
}
*info = *getmetadata;

sub setmetadata {
  my ($self, $mailbox, $entry, $value, $private) = @_;

  my %values = ( "comment" => "/private/comment",
                 "expire" => "/shared/vendor/cmu/cyrus-imapd/expire",
                 "news2mail" => "/shared/vendor/cmu/cyrus-imapd/news2mail",
                 "sharedseen" => "/shared/vendor/cmu/cyrus-imapd/sharedseen",
                 "sieve" => "/shared/vendor/cmu/cyrus-imapd/sieve",
                 "specialuse" => "/private/specialuse",
                 "squat" => "/shared/vendor/cmu/cyrus-imapd/squat",
                 "pop3showafter" => "/shared/vendor/cmu/cyrus-imapd/pop3showafter" );

  if(!$self->{support_metadata}) {
    $self->{error} = "Remote does not support METADATA.";
    return undef;
  }

  if(exists($values{$entry})) {
    $entry = $values{$entry};
  } else {
    $self->{error} = "Unknown parameter $entry" unless substr($entry,0,1) eq "/";
  }

  my ($rc, $msg);

  $value = undef if($value eq "none");
  if (defined ($private)) {
    $entry =~ s/^\/shared\//\/private\//i;
  }

  if(defined($value)) {
    ($rc, $msg) = $self->send('', '',
                              "SETMETADATA %q (%q %q)",
                              $mailbox, $entry, $value);
  } else {
    ($rc, $msg) = $self->send('', '',
                              "SETMETADATA %q (%q NIL)",
                              $mailbox, $entry);
  }

  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->mboxconfig($mailbox, $entry, $value);
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}
*setinfo = *setmetadata;

sub subscribemailbox {
  my ($self, $mbx) = @_;
  my ($rc, $msg) = $self->send('', '', 'SUBSCRIBE %s', $mbx);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->subscribemailbox($box);
      $self->{error} = $cyradm->error;
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}
*subscribe = *subscribemailbox;

sub unsubscribemailbox {
  my ($self, $mbx) = @_;
  my ($rc, $msg) = $self->send('', '', 'UNSUBSCRIBE %s', $mbx);
  if ($rc eq 'OK') {
    $self->{error} = undef;
    1;
  } else {
    if($self->{support_referrals} && $msg =~ m|^\[REFERRAL\s+([^\]\s]+)\]|) {
      my ($refserver, $box) = $self->fromURL($1);
      my $port = 143;

      if($refserver =~ /:/) {
        $refserver =~ /([^:]+):(\d+)/;
        $refserver = $1; $port = $2;
      }

      my $cyradm = Cyrus::IMAP::Admin->new($refserver, $port)
        or die "cyradm: cannot connect to $refserver\n";
      $cyradm->addcallback({-trigger => 'EOF',
                            -callback => \&_cb_ref_eof,
                            -rock => \$cyradm});
      $cyradm->authenticate(@{$self->_getauthopts()})
        or die "cyradm: cannot authenticate to $refserver\n";

      my $ret = $cyradm->unsubscribemailbox($box);
      $self->{error} = $cyradm->error;
      $cyradm = undef;
      return $ret;
    }
    $self->{error} = $msg;
    undef;
  }
}
*unsubscribe = *unsubscribemailbox;

sub error {
  my $self = shift;
  $self->{error};
}

1;
__END__

=head1 NAME

Cyrus::IMAP::Admin - Cyrus administrative interface Perl module

=head1 SYNOPSIS

  use Cyrus::IMAP::Admin;

  my $client = Cyrus::IMAP::Admin->new('mailhost'[, $flags]);
  $rc = $client->create('user.auser'[, $partition]);
  $rc = $client->delete('user.auser');
  $rc = $client->deleteacl('user.buser', 'user1', 'user2');
  %acls = $client->listacl('user.buser');
  @mailboxes = $client->list('*');
  @mailboxes = $client->list('%', 'user.');
  @mailboxes = $client->subscribed('*');
  %quota = $client->quota($root);
  ($root, %quota) = $client->quotaroot($mailbox);
  $rc = $client->rename($old, $new[, $partition]);
  $rc = $client->setacl($mailbox, $user =E<gt> $acl[, ...]);
  $rc = $client->setquota($mailbox, $resource =E<gt> $quota[, ...]);
  $rc = $client->xfer($mailbox, $server[, $partition]);

=head1 DESCRIPTION

This module is a Perl interface to Cyrus administrative functions.  It is used
to implement Cyrus::IMAP::Admin::Shell (otherwise known as B<cyradm> and also
available for use in Perl administrative programs.

=head1 METHODS

Many of the methods have a B<cyradm>-compatible name and a shorter name.
The shorter name is shown in the synopsis when it exists; the
B<cyradm>-compatible name should be reasonably obvious.

In general, methods return undef or empty lists on error.  In some cases
a method may return an empty list without an error (i.e. C<list> of a
nonexistent hierarchy), so it may be necessary to check the error state
explicitly via the C<error> method.

=over 4

=item new($server[, $flags])

Instantiates a B<cyradm> object.  This is in fact an Cyrus::IMAP object with
a few additional methods, so all Cyrus::IMAP methods are available if needed.
(In particular, you will always want to use the C<authenticate> method.)

=item error

Return the last error that occurred, or undef if the last operation was
successful.  This is in some cases (such as C<list>) the only way to
distinguish between a successful return of an empty list and an error return.

Calling C<error> does not reset the error state, so it is legal to write:

    @folders = $cyradm->list($spec);
    print STDERR "Error: ", $cyradm->error if $cyradm->error;

=item createmailbox($mailbox[[, $partition], \%opts])

=item create($mailbox[, $partition])

Create a new mailbox on the specified or default partition.

=item deletemailbox($mailbox)

=item delete($mailbox)

Delete a mailbox.  As with B<cyradm>, you will probably need to add the B<c>
ACL for yourself to the mailbox with C<setaclmailbox> first.

=item deleteaclmailbox($mailbox, $user[, ...])

=item deleteacl($mailbox, $user[, ...])

Delete one or more ACL from a mailbox.

=item listaclmailbox($mailbox)

=item listacl($mailbox)

Returns a hash of mailbox ACLs, with each key being a Cyrus user and the
corresponding value being the ACL.

=item listmailbox($pattern[[, $reference], \%opts])

=item list($pattern[[, $reference], \%opts])

List mailboxes matching the specified pattern, starting from the specified
reference.  The result is a list; each element is an array containing the
mailbox name, attributes, and the separator.  (This interface may change.)

=item listsubscribed($pattern[, $reference])

=item subscribed($pattern[, $reference])

Like C<listmailbox> but only shows subscribed mailboxes.

=item listquota($root)

=item quota($root)

Returns a hash specifying the quota for the specified quota root.  Use
C<listquotaroot> to find the quota root for a mailbox.

=item listquotaroot($mailbox)

=item quotaroot($mailbox)

Returns a list, the first element is the quota root for the mailbox and
remaining elements are a hash specifying its quota.

=item renamemailbox($from, $to[, $partition])

=item rename($from, $to[, $partition])

Renames the specified mailbox, optionally moving it to a different partition.

=item setaclmailbox($mailbox, $user =E<gt> $acl[, ...])

=item setacl($mailbox, $user =E<gt> $acl[, ...])

Set ACLs on a mailbox.  The ACL may be one of the special strings C<none>,
C<read> (C<lrs>), C<post> (C<lrsp>), C<append> (C<lrsip>), C<write>
(C<lrswipkxte>), C<delete> (C<lrxte>), or C<all> (C<lrswipkxte>), or
any combinations of the ACL codes:

=over 4

=item l

Lookup (mailbox is visible to LIST/LSUB, SUBSCRIBE mailbox)

=item r

Read (SELECT/EXAMINE the mailbox, perform STATUS)

=item s

Seen (set/clear \SEEN flag via STORE, also set \SEEN flag during
    APPEND/COPY/FETCH BODY[...])

=item w

Write flags other than \SEEN and \DELETED

=item i

Insert (APPEND, COPY destination)

=item p

Post (send mail to mailbox)

=item k

Create mailbox (CREATE new sub-mailboxes, parent for new mailbox in RENAME)

=item x

Delete mailbox (DELETE mailbox, old mailbox name in RENAME)

=item t

Delete messages (set/clear \DELETED flag via STORE, also set \DELETED
    flag during APPEND/COPY)

=item e

Perform EXPUNGE and expunge as part of CLOSE

=item a

Administer (SETACL/DELETEACL/GETACL/LISTRIGHTS)

=back

=item setquota($mailbox, $resource, $quota[, ...])

Set quotas on a mailbox.  Note that Cyrus currently only defines one resource,
C<STORAGE>.  As defined in RFC 2087, the units are groups of 1024 octets
(i.e. Kilobytes)

=item xfermailbox($mailbox, $server[, $partition])

=item xfer($mailbox, $server[, $partition])

Transfers (relocates) the specified mailbox to a different server.

=back

=head1 AUTHOR

Brandon S. Allbery, allbery@ece.cmu.edu

=head1 SEE ALSO

Cyrus::IMAP
Cyrus::IMAP::Shell
perl(1), cyradm(1), imapd(8).

=cut
