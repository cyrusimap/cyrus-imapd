use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'SIEVE::managesieve',
    'VERSION_FROM' => 'managesieve.pm', # finds $VERSION
    'LIBS'	=> ['-L../lib/ -lisieve -lsasl -L../../../lib/ -lcyrus -lssl -lcrypto'],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '-I../lib/ -I../../../lib/',# isieve stuff and prot stuff
);
