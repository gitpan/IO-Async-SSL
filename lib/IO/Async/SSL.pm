#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2010 -- leonerd@leonerd.org.uk

package IO::Async::SSL;

use strict;
use warnings;

our $VERSION = '0.01';

use Carp;

use IO::Socket::SSL qw( $SSL_ERROR SSL_WANT_READ SSL_WANT_WRITE );
use POSIX qw( EAGAIN );

use IO::Async::Handle 0.29;

=head1 NAME

C<IO::Async::SSL> - Use SSL/TLS with L<IO::Async>

=head1 SYNOPSIS

 use IO::Async::Loop;
 use IO::Async::SSL;
 use IO::Async::SLStream;

 my $loop = IO::Async::Loop->new();

 $loop->SSL_connect(
    host     => "www.example.com",
    service  => "https",

    on_connected => sub {
       my ( $sock ) = @_;

       my $stream = IO::Async::SSLStream->new(
          handle => $sock,
          on_read => sub {
             ...
          },
       );

       $loop->add( $stream );
       
       ...
    },

    on_resolve_error => sub { print STDERR "Cannot resolve - $_[0]\n"; },
    on_connect_error => sub { print STDERR "Cannot connect\n"; },
    on_ssl_error     => sub { print STDERR "Cannot negotiate SSL - $_[-1]\n"; },
 );

=head1 DESCRIPTION

This module extends L<IO::Async::Loop> to allow the use of SSL or TLS-based
connections using L<IO::Socket::SSL>. It provides two extension methods on the
C<IO::Async::Loop> class, which extend C<connect> and C<listen>, to yield
C<IO::Socket::SSL>-upgraded socket handles. These socket handles must then be
wrapped in instances of L<IO::Async::SSLStream>.

=cut

=head1 METHODS

=cut

=head2 $loop->SSL_connect( %params )

This method performs a non-blocking connection to a given address or set of
addresses, upgrades the socket to SSL, then invokes the C<on_connected>
continuation when the SSL-wrapped socket is ready for use by the application.

It takes all the same arguments as C<IO::Async::Loop::connect()>. Any argument
whose name starts C<SSL_> will be passed on to the L<IO::Socket::SSL>
constructor rather than the Loop's C<connect> method. It is not required to
pass the C<socktype> option, as SSL implies this will be C<stream>.

In addition, the following arguments are required:

=over 8

=item on_ssl_error => CODE

A continuation that is invoked if C<IO::Socket::SSL> detects an SSL-based
error once the actual stream socket is connected.

=back

=cut

# This is seven shades of evil
# ... fun though
sub IO::Async::Loop::SSL_connect
{
   my $loop = shift;
   my %args = @_;

   my %ssl_args = map { $_ => delete $args{$_} } grep m/^SSL_/, keys %args;

   my $on_connected = delete $args{on_connected} or croak "Expected 'on_connected'";
   my $on_ssl_error = delete $args{on_ssl_error} or croak "Expected 'on_ssl_error'";

   $loop->connect(
      socktype => 'stream', # SSL over DGRAM or RAW makes no sense
      %args,
      on_connected => sub {
         my ( $socket ) = @_;

         $socket = IO::Socket::SSL->start_SSL( $socket, 
            SSL_startHandshake => 0,
            %ssl_args,
         ) or return $on_ssl_error->( "$!" );

         my $ready = sub {
            my ( $self ) = @_;
            if( $socket->connect_SSL ) {
               $loop->remove( $self );
               $on_connected->( $socket );
               return;
            }

            $! == EAGAIN
               or return $on_ssl_error( "$!" );

            $self->want_readready ( $SSL_ERROR == SSL_WANT_READ );
            $self->want_writeready( $SSL_ERROR == SSL_WANT_WRITE );
         };

         $loop->add( my $handle = IO::Async::Handle->new(
            handle => $socket,
            on_read_ready  => $ready,
            on_write_ready => $ready,
         ) );

         $ready->( $handle );
      },
   );
}

=head2 $loop->SSL_listen( %params )

This method sets up a listening socket using the addresses given, and will
invoke the C<on_accept> callback each time a new connection is accepted on the
socket and the initial SSL negotiation has been completed.

It takes all the same arguments as C<IO::Async::Loop::listen()>. Any argument
whose name starts C<SSL_> will be passed on to the L<IO::Socket::SSL>
constructor rather than the Loop's C<listen> method. It is not required to
pass the C<socktype> option, as SSL implies this will be C<stream>.

In addition, the following arguments are rquired:

=over 8

=item on_ssl_error => CODE

A continuation that is invoked if C<IO::Socket::SSL> detects an SSL-based
error once the actual stream socket is connected.

=back

The underlying L<IO::Socket::SSL> socket will also require the server key and
certificate for a server-mode socket. See its documentation for more details.

=cut

# More evil
sub IO::Async::Loop::SSL_listen
{
   my $loop = shift;
   my %args = @_;

   my %ssl_args = map { $_ => delete $args{$_} } grep m/^SSL_/, keys %args;

   my $on_accept    = delete $args{on_accept}    or croak "Expected 'on_accept'";
   my $on_ssl_error = delete $args{on_ssl_error} or croak "Expected 'on_ssl_error'";

   $loop->listen(
      socktype => 'stream',
      %args,
      on_accept => sub {
         my ( $socket ) = @_;

         $socket = IO::Socket::SSL->start_SSL( $socket,
            SSL_startHandshake => 0,
            SSL_server => 1,
            %ssl_args,
         ) or return $on_ssl_error->( "$!" );

         my $ready = sub {
            my ( $self ) = @_;
            if( $socket->accept_SSL ) {
               $loop->remove( $self );
               $on_accept->( $socket );
               return;
            }

            $! == EAGAIN
               or return $on_ssl_error( "$!" );

            $self->want_readready ( $SSL_ERROR == SSL_WANT_READ );
            $self->want_writeready( $SSL_ERROR == SSL_WANT_WRITE );
         };

         $loop->add( my $handle = IO::Async::Handle->new(
            handle => $socket,
            on_read_ready  => $ready,
            on_write_ready => $ready,
         ) );

         $ready->( $handle );
      },
   );
}

# Keep perl happy; keep Britain tidy
1;

__END__

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>
