package Net::Azure::BlobService;
use HTTP::Date;
use Digest::MD5 qw(md5_base64);
use Digest::SHA qw(hmac_sha256_base64);
use MIME::Base64;
use Moose;

has 'primary_access_key' => ( is => 'ro', isa => 'Str', required => 1 );
has 'user_agent' => (
    is      => 'ro',
    isa     => 'LWP::UserAgent',
    default => sub {
        my $ua = LWP::UserAgent->new;
        $ua->env_proxy;
        return $ua;
    }
);

sub sign_http_request {
    my ( $self, $http_request ) = @_;

    my $host = $http_request->uri->host;
    my ($account) = $host =~ /^(.+?)\./;

    $http_request->header( ':x-ms-version', '2011-08-18' );
    $http_request->header( 'Date',          time2str() );
    $http_request->content_length( length $http_request->content );

    my $canonicalized_headers = join "",
        map { lc( substr( $_, 1 ) ) . ':' . $http_request->header($_) . "\n" }
        sort grep {/^:x-ms/i} $http_request->header_field_names;

    my $canonicalized_resource
        = '/' . $account . $http_request->uri->path . join "", map {
              "\n"
            . lc($_) . ':'
            . join( ',', sort $http_request->uri->query_param($_) )
        } sort $http_request->uri->query_param;

    my $string_to_sign
        = $http_request->method . "\n"
        . ( $http_request->header('Content-Encoding')    // '' ) . "\n"
        . ( $http_request->header('Content-Language')    // '' ) . "\n"
        . ( $http_request->header('Content-Length')      // '' ) . "\n"
        . ( $http_request->header('Content-MD5')         // '' ) . "\n"
        . ( $http_request->header('Content-Type')        // '' ) . "\n"
        . ( $http_request->header('Date')                // '' ) . "\n"
        . ( $http_request->header('If-Modified-Since')   // '' ) . "\n"
        . ( $http_request->header('If-Match')            // '' ) . "\n"
        . ( $http_request->header('If-None-Match')       // '' ) . "\n"
        . ( $http_request->header('If-Unmodified-Since') // '' ) . "\n"
        . ( $http_request->header('Range')               // '' ) . "\n"
        . $canonicalized_headers
        . $canonicalized_resource;

    my $signature = hmac_sha256_base64( $string_to_sign,
        decode_base64( $self->primary_access_key ) );
    $signature .= '=';

    $http_request->header( 'Authorization',
        "SharedKey " . $account . ":" . $signature );
    return $http_request;
}

sub make_http_request {
    my ( $self, $http_request ) = @_;
    $self->sign_http_request($http_request);
    return $self->user_agent->request($http_request);
}

__PACKAGE__->meta->make_immutable;
