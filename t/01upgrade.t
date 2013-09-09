#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use IO::Async::Test;

use IO::Async::OS;
use IO::Async::Loop;
use IO::Async::SSL;
use IO::Async::SSLStream;

my $loop = IO::Async::Loop->new;

testing_loop( $loop );

{
   my ( $server_sock, $client_sock ) = IO::Async::OS->socketpair or
      die "Cannot socketpair - $!";

   $server_sock->blocking( 0 );
   $client_sock->blocking( 0 );

   my ( $server_upgraded, $client_upgraded );

   my $server_f = $loop->SSL_upgrade(
      handle => $server_sock,
      SSL_server => 1,
      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_upgraded => sub { $server_upgraded++ },
      on_error => sub { die "Test failed early - $_[-1]" },
   );

   my $client_f = $loop->SSL_upgrade(
      handle => $client_sock,
      SSL_verify_mode => 0,

      on_upgraded => sub { $client_upgraded++ },
      on_error => sub { die "Test failed early - $_[-1]" },
   );

   ok( defined $server_f, 'defined ->SSL_upgrade Future for server' );
   ok( defined $client_f, 'defined ->SSL_upgrade Future for client' );

   wait_for { $server_f->is_ready and $client_f->is_ready };

   ok( $server_upgraded, 'server upgraded' );
   ok( $client_upgraded, 'client upgraded' );

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
   my ( $server_sock, $client_sock ) = IO::Async::OS->socketpair or
      die "Cannot socketpair - $!";

   $server_sock->blocking( 0 );
   $client_sock->blocking( 0 );

   my $client_errored;
   my $f = $loop->SSL_upgrade(
      handle => $client_sock,
      SSL_verify_mode => 0,

      on_upgraded => sub { die "Test failed early - SSL upgrade succeeded" },
      on_error => sub { $client_errored++ },
   );

   $server_sock->syswrite( "A line of plaintext content\n" );

   wait_for { $f->is_ready };

   ok( scalar $f->failure, '$f indicates client upgrade failure' );
   ok( $client_errored, 'on_error invoked for client upgrade failure' );
}

{
   my ( $server_sock, $client_sock ) = IO::Async::OS->socketpair or
      die "Cannot socketpair - $!";

   $server_sock->blocking( 0 );
   $client_sock->blocking( 0 );

   my $server_errored;
   my $f = $loop->SSL_upgrade(
      handle => $server_sock,
      SSL_server => 1,
      SSL_key_file  => "t/privkey.pem",
      SSL_cert_file => "t/server.pem",

      on_upgraded => sub { die "Test failed early - SSL upgrade succeeded" },
      on_error => sub { $server_errored++ },
   );

   $client_sock->syswrite( "A line of plaintext content\n" );

   wait_for { $f->is_ready };

   ok( scalar $f->failure, '$f indicates server upgrade failure' );
   ok( $server_errored, 'on_error invoked for server upgrade failure' );
}

done_testing;
