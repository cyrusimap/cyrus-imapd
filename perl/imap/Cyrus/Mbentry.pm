package Cyrus::Mbentry;
use Moo;
use Cyrus::DList;
use Cyrus::Mbname;

use Types::Standard qw(HashRef Value Int Bool Any);

# XXX: unused so far
use constant USER_ACL => 'lrswipcdn';
use constant ADMIN_ACL => 'lrswipcdan';
use constant ANY_ACL => 'p';

has intname => (isa => Value, is => 'rw');
has name => (isa => Any, is => 'ro', lazy => 1, default => sub { Cyrus::Mbname->new_dbname(shift->intname) });

has is_uuid => (isa => Bool, is => 'ro');
has acls => (isa => HashRef, is => 'rw');
has createdmodseq => (isa => Int, is => 'rw');
has foldermodseq => (isa => Int, is => 'rw');
has mtime => (isa => Int, is => 'rw');
has partition => (isa => Value, is => 'rw');
has type => (isa => Value, is => 'rw');
has uniqueid => (isa => Value, is => 'rw');
has uidvalidity => (isa => Int, is => 'rw');

sub _parse_dlist {
  my ($self, $name, $details) = @_;
  my $dlist = Cyrus::DList->parse_string($details, 0);
  if ($name =~ m/^N/) {
    $name = Cyrus::Mbname->new_dbname($name)->intname();
    $self->{is_uuid} = 1;
  }
  if ($name =~ m/^I/) {
    $self->{uniqueid} = substr($name, 1);
    $self->{is_uuid} = 1;
  }
  $self->{intname} = $name;
  $self->{type} = 'e';
  foreach my $item (@{$dlist->{data}}) {
    if ($item->{key} eq 'A') {
      my %acls;
      foreach my $sub (@{$item->{data}}) {
        $acls{$sub->{key}} = $sub->{data};
      }
      $self->{acls} = \%acls;
    }
    if ($item->{key} eq 'C') {
      $self->{createdmodseq} = $item->{data};
    }
    if ($item->{key} eq 'F') {
      $self->{foldermodseq} = $item->{data};
    }
    if ($item->{key} eq 'H') {
      for my $histitem (@{$item->{data}}) {
        my %hist;
        for my $field (@{$histitem->{data}}) {
          if ($field->{key} eq 'F') {
            $hist{foldermodseq} = $field->{data};
          }
          if ($field->{key} eq 'M') {
            $hist{mtime} = $field->{data};
          }
          if ($field->{key} eq 'N') {
            $hist{name} = Cyrus::Mbname->new_dbname("N$field->{data}")->intname();
          }
        }
        push @{$item->{name_history}}, \%hist;
      }
    }
    if ($item->{key} eq 'M') {
      $self->{mtime} = $item->{data};
    }
    if ($item->{key} eq 'N') {
      $self->{intname} = Cyrus::Mbname->new_dbname("N$item->{data}")->intname();
    }
    if ($item->{key} eq 'P') {
      $self->{partition} = $item->{data};
    }
    if ($item->{key} eq 'I') {
      $self->{uniqueid} = $item->{data};
    }
    if ($item->{key} eq 'V') {
      $self->{uidvalidity} = $item->{data};
    }
    if ($item->{key} eq 'T') {
      $self->{type} = $item->{data};
    }
  }
  return $self;
}

sub parse {
  my $Proto = shift;
  my $Class = ref($Proto) || $Proto;
  my $Self = {};
  bless($Self, $Class);

  my ($MailboxName, $MailboxDetails) = @_;

  if ($MailboxDetails =~ m/^\%/) {
    return $Self->_parse_dlist($MailboxName, $MailboxDetails);
  }

  # old formats
  if ($MailboxDetails =~ s/^\((.*?)\) //) {
    my $named = $1;
    my %named = split / /, $named;
    $Self->{uniqueid} = $named{uniqueid} if exists $named{uniqueid};
    $Self->{specialuse} = $named{specialuse} if exists $named{specialuse};
    # XXX - the rest
  }
  # XXX - it's mbtype, not "flag" - though it's also always 0...
  my ($Flag, $Partition, $ACLs) = ($MailboxDetails =~ /^(\d) (\w+) (.*)/);
  $Flag == 0 || die "Unexpected flag: $Flag";
  my %ACLs = split("\t",$ACLs);
  $Self->{type} = 'e';
  $Self->{partition} = $Partition;
  $Self->{acls} = \%ACLs;
  $Self->{name} = $MailboxName;

  return $Self;
}

sub FormatDBOld {
  my $Self = shift;
  my %named;
  $named{uniqueid} = $Self->{uniqueid} if exists $Self->{uniqueid};
  $named{specialuse} = $Self->{specialuse} if exists $Self->{specialuse};
  my $str = '';
  if (%named) {
    $str = '(' . join(" ", map { "$_ $named{$_}" } sort keys %named) . ') ';
  }
  return $str . "0 " . $Self->{partition} . " " . join("\t", %{$Self->{acls}}) . "\t";
}

sub has_type {
  my $self = shift;
  my $arg = shift;
  return $self->type =~ m/$arg/;
}

# convenience functions
sub is_tombstone { shift->has_type('d') }
sub is_intermediate { shift->has_type('i') }

# mbname wrappers

sub username { shift->name->username }
sub userfolder { shift->name->userfolder }
sub adminfolder { shift->name->adminfolder }

1;
