use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
   module_name => 'IO::Async::SSL',
   requires => {
      'IO::Async::Loop' => '0.61', # new Listen API
      'IO::Async::Handle' => '0.29',
      'IO::Async::Protocol::Stream' => 0,
      'IO::Async::Stream' => '0.59',
      'IO::Socket::SSL' => 0,
   },
   recommends => {
      'Mozilla::CA' => 0,
   },
   build_requires => {
      'IO::Async::OS' => 0,
      'Test::More' => '0.88', # done_testing
   },
   auto_configure_requires => 0, # Don't add M::B to configure_requires
   license => 'perl',
   create_makefile_pl => 'traditional',
   create_license => 1,
   create_readme  => 1,
);

$build->create_build_script;
