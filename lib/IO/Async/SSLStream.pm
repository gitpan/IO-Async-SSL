#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2010-2013 -- leonerd@leonerd.org.uk

package IO::Async::SSLStream;

use strict;
use warnings;
use base qw( IO::Async::Stream );
IO::Async::Stream->VERSION( '0.59' );

our $VERSION = '0.11';

use IO::Socket::SSL qw( $SSL_ERROR SSL_WANT_READ SSL_WANT_WRITE );
use POSIX qw( EAGAIN );

=head1 NAME

C<IO::Async::SSLStream> - read and write buffers around an SSL connection

=head1 DESCRIPTION

This subclass of L<IO::Async::Stream> provides support for using an SSL
connection, as created by L<IO::Async::SSL>'s C<SSL_connect> or C<SSL_listen>
extension methods. After one of these methods has provided a socket handle, it
should be wrapped in an L<IO::Async::SSLStream> object to provide the usual
C<on_read> callback.

It provides no extra methods and consumes no extra configuration parameters;
treat it the same as a regular C<IO::Async::Stream> object.

See the main L<IO::Async::SSL> documentation for an example of its use.

=cut

sub _init
{
   my $self = shift;
   my ( $params ) = @_;

   $params->{reader} = \&sslread;
   $params->{writer} = \&sslwrite;

   $self->SUPER::_init( $params );
}

sub sslread
{
   my $stream = shift;
   my ( $fh, undef, $len ) = @_;

   my $ret = $stream->_sysread( $fh, $_[1], $len );

   my $read_wants_write = !defined $ret && $! == EAGAIN && $SSL_ERROR == SSL_WANT_WRITE;
   $stream->want_writeready_for_read( $read_wants_write );

   # It's possible SSL_read took all the data out of the filehandle, thus
   # making it not appear read-ready any more.
   if( $fh->pending ) {
      $stream->loop->later( sub { $stream->on_read_ready } );
   }

   return $ret;
}

sub sslwrite
{
   my $stream = shift;
   my ( $fh, $buf, $len ) = @_;

   my $ret = $stream->_syswrite( $fh, $_[1], $len );

   my $write_wants_read = !defined $ret && $! == EAGAIN && $SSL_ERROR == SSL_WANT_READ;
   $stream->want_readready_for_write( $write_wants_read );
   # If write wants read, there's no point waiting on writereadiness either
   $stream->want_writeready_for_write( !$write_wants_read );

   return $ret;
}

=head1 BUGS

=over 4

=item *

Currently, this subclass does not completely handle the C<autoflush> configure
option. It is possible for the C<SSL_write(3ssl)> call to fail with C<EAGAIN>
and C<SSL_WANT_READ>, indicating that it wishes to read (perhaps to obtain
fresh keys from the server). In this case, the subclass will not correctly
poll for readability and retry the write operation. This bug does not occur
with regular C<write> with C<autoflush> turned off.

=back

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>

=cut

0x55AA;
