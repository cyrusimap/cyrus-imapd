package Cassandane::Unit::RunnerXML;

use XML::Generator;
use Time::HiRes qw(time);
use Sys::Hostname;
use POSIX qw(strftime);

use strict;
use warnings;
use vars qw($VERSION);
use base qw(Test::Unit::Runner);

# $Id: XML.pm 27 2004-08-24 11:22:24Z andrew $
$VERSION = '0.1';

sub new {
    my ($class, $directory, $generator) = @_;

    $generator ||= XML::Generator->new(escape => 'always', pretty => 2);

    return bless({directory => $directory, gen => $generator,
		  all_tests_passed => 1,
		  classrecs => {}},
		 $class);
}

sub all_tests_passed {
    my ($self) = @_;

    return $self->{all_tests_passed};
}

sub start {
    my ($self, $suite) = @_;

    my $result = $self->create_test_result();
    $result->add_listener($self);
    my $start_time = time();
    $suite->run($result, $self);
    $self->_emit_xml();
}

sub _classrec {
    my ($self, $test) = @_;

    return $self->{classrecs}->{ref($test)} ||= {
		testrecs => {}, tests => 0,
		errors => 0, failures => 0,
		timestamp => strftime("%Y-%m-%dT%H:%M:%S", gmtime(time())),
		};
}

sub _testrec {
    my ($self, $test) = @_;

    my $cr = $self->_classrec($test);
    return $cr->{testrecs}->{$test->name()} ||=
		{ start_time => 0, node => undef, child_nodes => [] };
}

sub add_pass {}

sub _extype
{
    my ($exception) = @_;
    my $o = $exception->object();
    return $o->to_string()
	if (defined $o && $o->can('to_string'));
    return "unknown";
}

sub add_failure {
    my ($self, $test, $exception) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    $cr->{failures}++;
    $self->{all_tests_passed} = 0;
    push(@{$tr->{child_nodes}},
	 $self->{gen}->failure({type => _extype($exception),
				message => $exception->get_message()},
				$exception->stringify()));
}

sub add_error {
    my ($self, $test, $exception) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    $cr->{errors}++;
    $self->{all_tests_passed} = 0;
    push(@{$tr->{child_nodes}},
	 $self->{gen}->error({type => _extype($exception),
			      message => $exception->get_message()},
			      $exception->stringify()));
}

sub start_test {
    my ($self, $test) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    $tr->{start_time} = time();
    $cr->{tests}++;
}

sub fake_start_time {
    my ($self, $test, $time) = @_;

    my $tr = $self->_testrec($test);
    $tr->{start_time} = $time;
}

sub end_test {
    my ($self, $test) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    my $time = time() - $tr->{start_time};
    $tr->{node} = $self->{gen}->testcase({name => $test->name(),
					  classname => ref($test),
					  time => sprintf('%.4f', $time)},
					  @{$tr->{child_nodes}});
    $cr->{time} += $time;
}

sub _emit_xml {
    my ($self) = @_;

    my $hostname = hostname();

    foreach my $class (keys %{$self->{classrecs}}) {
	my $cr = $self->{classrecs}->{$class};

	my $output = IO::File->new(">" . $self->_xml_filename($class));
	unless(defined($output)) {
	    die("Can't open " . $self->_xml_filename($class) . ": $!");
	}

	my $time = sprintf('%.4f', $cr->{time});
	my @child_nodes = map { $_->{node}; } (values %{$cr->{testrecs}});
	unshift(@child_nodes, $self->{gen}->properties());
	my $system_out = 'system-out';
	push(@child_nodes, $self->{gen}->$system_out());
	my $system_err = 'system-err';
	push(@child_nodes, $self->{gen}->$system_err());
	my $xml = $self->{gen}->testsuite({tests => $cr->{tests},
					   failures => $cr->{failures},
					   errors => $cr->{errors},
					   time => $time,
					   name => $class,
					   hostname => $hostname,
					   timestamp => $cr->{timestamp}},
					  @child_nodes);
	$output->print($xml);
	$output->close();
    }
}

sub _xml_filename {
    my ($self, $class) = @_;

    $class =~ s/::/./g;
    return File::Spec->catfile($self->{directory}, "TEST-${class}.xml");
}

1;

__END__


=head1 NAME

Test::Unit::Runner::XML - Generate XML reports from unit test results 

=head1 SYNOPSIS

    use Test::Unit::Runner::XML;

    mkdir("test_reports");
    my $runner = Test::Unit::Runner::XML->new("test-reports");
    $runner->start($test);
    exit(!$runner->all_tests_passed());

=head1 DESCRIPTION

Test::Unit::Runner::XML generates XML reports from unit test results. The
reports are in the same format as those produced by Ant's JUnit task, 
allowing them to be used with Java continuous integration and reporting tools.

=head1 CONSTRUCTOR

    Test::Unit::Runner::XML->new($directory)

Construct a new runner that will write XML reports into $directory

=head1 METHODS 

=head2 start

    $runner->start($test);

Run the L<Test::Unit::Test> $test and generate XML reports from the results.

=head2 all_tests_passed

    exit(!$runner->all_tests_passed());

Return true if all tests executed by $runner since it was constructed passed.

=head1 AUTHOR

Copyright (c) 2004 Andrew Eland, E<lt>andrew@andreweland.orgE<gt>.

All rights reserved. This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

=over 4

=item *

L<Test::Unit>

=item *

L<Test::Unit::TestRunner>

=item *

The Ant JUnit task, http://ant.apache.org/

=cut


