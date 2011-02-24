#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 5;

use IO::Async::Test;

use IO::Async::Loop;
use IO::Async::SSL;
use IO::Async::SSLStream;

my $loop = IO::Async::Loop->new;

testing_loop( $loop );

{
   my ( $server_sock, $client_sock ) = $loop->socketpair or
      die "Cannot socketpair - $!";

   $server_sock->blocking( 0 );
   $client_sock->blocking( 0 );

   my ( $server_upgraded, $client_upgraded );

   $loop->SSL_upgrade(
      handle => $server_sock,
      SSL_server => 1,
      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_upgraded => sub { $server_upgraded++ },
      on_error => sub { die "Test failed early - $_[-1]" },
   );

   $loop->SSL_upgrade(
      handle => $client_sock,

      on_upgraded => sub { $client_upgraded++ },
      on_error => sub { die "Test failed early - $_[-1]" },
   );

   wait_for { $server_upgraded and $client_upgraded };

   ok( 1, "Sockets upgraded" );

   my @server_lines;
   my $server_stream = IO::Async::SSLStream->new(
      handle => $server_sock,
      on_read => sub {
         my ( $self, $buffref, $closed ) = @_;
         push @server_lines, $1 while $$buffref =~ s/^(.*)\n//;
         return 0;
      },
   );
   $loop->add( $server_stream );

   my @client_lines;
   my $client_stream = IO::Async::SSLStream->new(
      handle => $client_sock,
      on_read => sub {
         my ( $self, $buffref, $closed ) = @_;
         push @client_lines, $1 while $$buffref =~ s/^(.*)\n//;
         return 0;
      },
   );
   $loop->add( $client_stream );

   $server_stream->write( "Send a line\n" );

   wait_for { @client_lines };

   is( $client_lines[0], "Send a line", 'Line received by client' );

   $client_stream->write( "Reply a line\n" );

   wait_for { @server_lines };

   is( $server_lines[0], "Reply a line", 'Line received by server' );
}

{
   my ( $server_sock, $client_sock ) = $loop->socketpair or
      die "Cannot socketpair - $!";

   $server_sock->blocking( 0 );
   $client_sock->blocking( 0 );

   my $client_errored;
   $loop->SSL_upgrade(
      handle => $client_sock,

      on_upgraded => sub { die "Test failed early - SSL upgrade succeeded" },
      on_error => sub { $client_errored++ },
   );

   $server_sock->syswrite( "A line of plaintext content\n" );

   wait_for { $client_errored };

   ok( 1, "Client socket indicates error" );
}

{
   my ( $server_sock, $client_sock ) = $loop->socketpair or
      die "Cannot socketpair - $!";

   $server_sock->blocking( 0 );
   $client_sock->blocking( 0 );

   my $server_errored;
   $loop->SSL_upgrade(
      handle => $server_sock,
      SSL_server => 1,
      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_upgraded => sub { die "Test failed early - SSL upgrade succeeded" },
      on_error => sub { $server_errored++ },
   );

   $client_sock->syswrite( "A line of plaintext content\n" );

   wait_for { $server_errored };

   ok( 1, "Server socket indicates error" );
}
