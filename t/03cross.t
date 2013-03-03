#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use IO::Async::Test;

use IO::Async::Loop;
use IO::Async::SSL;
use IO::Async::SSLStream;
use Socket qw( unpack_sockaddr_in );

my $loop = IO::Async::Loop->new;

testing_loop( $loop );

{
   my $listen_sock;
   my $accepted_sock;

   $loop->SSL_listen(
      family  => "inet",
      host    => "localhost",
      service => "",

      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_listen => sub { $listen_sock = shift },
      on_accept => sub { $accepted_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_listen_error  => sub { die "Cannot listen - $_[-1]\n" },
      on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
   );

   wait_for { defined $listen_sock };

   my $port = ( unpack_sockaddr_in $listen_sock->sockname )[0];

   my $connected_sock;

   $loop->SSL_connect(
      family  => "inet",
      host    => "localhost",
      service => $port,

      SSL_verify_mode => 0,

      on_connected => sub { $connected_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_connect_error => sub { die "Cannot connect\n" },
      on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
   );

   wait_for { defined $connected_sock and defined $accepted_sock };

   is_deeply( [ unpack_sockaddr_in $connected_sock->sockname ],
              [ unpack_sockaddr_in $accepted_sock->peername ],
              'Sockets crossconnected' );

   my @c_lines;
   my $c_stream = IO::Async::SSLStream->new(
      handle => $connected_sock,
      on_read => sub {
         my ( $self, $buffref, $closed ) = @_;
         push @c_lines, $1 while $$buffref =~ s/^(.*)\n//;
         return 0;
      },
   );
   $loop->add( $c_stream );

   my @a_lines;
   my $a_stream = IO::Async::SSLStream->new(
      handle => $accepted_sock,
      on_read => sub {
         my ( $self, $buffref, $closed ) = @_;
         push @a_lines, $1 while $$buffref =~ s/^(.*)\n//;
         return 0;
      },
   );
   $loop->add( $a_stream );

   $a_stream->write( "Send a line\n" );

   wait_for { @c_lines };

   is( $c_lines[0], "Send a line", 'Line received by openssl' );

   $c_stream->write( "Reply a line\n" );

   wait_for { @a_lines };

   is( $a_lines[0], "Reply a line", 'Line received by local socket' );

   undef @c_lines;
   undef @a_lines;

   $a_stream->write( ("X" x 1_000_000 ) . "\n" );

   wait_for { @c_lines };

   is( length $c_lines[0], 1_000_000, 'Bulk data received by openssl' );

   $c_stream->write( ("X" x 1_000_000 ) . "\n" );

   wait_for { @a_lines };

   is( length $a_lines[0], 1_000_000, 'Bulk data received by local socket' );

   undef @c_lines;
   undef @a_lines;

   # syswrite() more than we sysread(), so as to try to provoke a condition where
   # SSL_read() reads all the data from the socket, making it not read-ready, but
   # that we haven't yet got all the data at the on_read level.
   local $IO::Async::Stream::WRITELEN = 16384;
   local $IO::Async::Stream::READLEN  =   128;

   $a_stream->write( ("X" x 1024 ) . "\n" );

   wait_for { @c_lines };

   is( length $c_lines[0], 1024, 'Data received by openssl without stall' );

   $c_stream->write( ("X" x 1024 ) . "\n" );

   wait_for { @a_lines };

   is( length $a_lines[0], 1024, 'Data received by local socket without stall' );
}

SKIP: {
   skip "IO::Async too old to support ->connect extension", 1 if $IO::Async::Loop::VERSION < '0.31';

   my $listen_sock;
   my $accepted_sock;

   $loop->SSL_listen(
      family  => "inet",
      host    => "localhost",
      service => "",

      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_listen => sub { $listen_sock = shift },
      on_accept => sub { $accepted_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_listen_error  => sub { die "Cannot listen - $_[-1]\n" },
      on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
   );

   wait_for { defined $listen_sock };

   my $port = ( unpack_sockaddr_in $listen_sock->sockname )[0];

   my $connected_sock;

   $loop->connect(
      extensions => [ 'SSL' ],

      family  => "inet",
      host    => "localhost",
      service => $port,

      SSL_verify_mode => 0,

      on_connected => sub { $connected_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_connect_error => sub { die "Cannot connect\n" },
      on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
   );

   wait_for { defined $connected_sock and defined $accepted_sock };

   is_deeply( [ unpack_sockaddr_in $connected_sock->sockname ],
              [ unpack_sockaddr_in $accepted_sock->peername ],
              'Sockets crossconnected using ->connect extensions' );
}

SKIP: {
   skip "IO::Async too old to support ->listen extension", 1 if $IO::Async::Loop::VERSION < '0.40';

   my $listen_sock;
   my $accepted_sock;

   $loop->listen(
      extensions => [ 'SSL' ],

      family  => "inet",
      host    => "localhost",
      service => "",

      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_listen => sub { $listen_sock = shift },
      on_accept => sub { $accepted_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_listen_error  => sub { die "Cannot listen - $_[-1]\n" },
      on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
   );

   wait_for { defined $listen_sock };

   my $port = ( unpack_sockaddr_in $listen_sock->sockname )[0];

   my $connected_sock;

   $loop->connect(
      extensions => [ 'SSL' ],

      family  => "inet",
      host    => "localhost",
      service => $port,

      SSL_verify_mode => 0,

      on_connected => sub { $connected_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_connect_error => sub { die "Cannot connect\n" },
      on_ssl_error     => sub { die "SSL error - $_[-1]\n" },
   );

   wait_for { defined $connected_sock and defined $accepted_sock };

   is_deeply( [ unpack_sockaddr_in $connected_sock->sockname ],
              [ unpack_sockaddr_in $accepted_sock->peername ],
              'Sockets crossconnected using ->listen extensions' );
}

{
   my $listen_sock;
   my $accepted_sock;

   $loop->listen(
      family   => "inet",
      host     => "localhost",
      service  => "",
      socktype => "stream",

      on_listen => sub { $listen_sock = shift },
      on_accept => sub { $accepted_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_listen_error  => sub { die "Cannot listen - $_[-1]\n" },
   );

   wait_for { defined $listen_sock };

   my $port = ( unpack_sockaddr_in $listen_sock->sockname )[0];

   my $connected_sock;
   my $client_errored;

   $loop->SSL_connect(
      family  => "inet",
      host    => "localhost",
      service => $port,

      SSL_verify_mode => 0,

      on_connected => sub { $connected_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_connect_error => sub { die "Cannot connect\n" },
      on_ssl_error     => sub { $client_errored++ },
   );

   wait_for { defined $accepted_sock };

   $accepted_sock->syswrite( "A line of plaintext content\n" );

   wait_for { $client_errored };

   ok( 1, "Client socket indicates error" );
}

{
   my $listen_sock;
   my $server_errored;

   $loop->SSL_listen(
      family  => "inet",
      host    => "localhost",
      service => "",

      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_listen => sub { $listen_sock = shift },
      on_accept => sub { die "Test failed early - SSL listen succeeded" },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_listen_error  => sub { die "Cannot listen - $_[-1]\n" },
      on_ssl_error     => sub { $server_errored++ },
   );

   wait_for { defined $listen_sock };

   my $port = ( unpack_sockaddr_in $listen_sock->sockname )[0];

   my $connected_sock;

   $loop->connect(
      family   => "inet",
      host     => "localhost",
      service  => $port,
      socktype => "stream",

      on_connected => sub { $connected_sock = shift },

      on_resolve_error => sub { die "Cannot resolve - $_[-1]\n" },
      on_connect_error => sub { die "Cannot connect\n" },
   );

   wait_for { defined $connected_sock };

   $connected_sock->syswrite( "A line of plaintext content\n" );

   wait_for { $server_errored };

   ok( 1, "Server socket indicates error" );
}

done_testing;
