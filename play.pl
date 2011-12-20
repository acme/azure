#!/home/acme/Public/perl-5.14.2/bin/perl
use strict;
use warnings;
use 5.14.0;
use Digest::MD5 qw(md5_base64);
use Digest::SHA qw(hmac_sha256_base64);
use HTTP::Date;
use HTTP::Request;
use HTTP::Request::Common qw(GET HEAD PUT DELETE);
use LWP::UserAgent;
use MIME::Base64;
use URI::URL;
use URI::QueryParam;
use XML::LibXML;

my $account = 'astray';

my $primary_access_key
    = 'XXX';

# Get Blob Service Properties
my $uri = URI->new("https://$account.blob.core.windows.net/");
$uri->query_form( [ restype => 'service', comp => 'properties' ] );
my $request = GET $uri;

# Create Container
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container' ] );
# my $request = PUT $uri;

# List Containers
# my $uri = URI->new("https://$account.blob.core.windows.net/");
# $uri->query_form( [ comp => 'list' ] );
# my $request = GET $uri;

# Get Container Properties
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container' ] );
# my $request = GET $uri;

# Put Container Metadata
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container', comp => 'metadata' ] );
# my $request = PUT $uri, ':x-ms-meta-Category' => 'Images';

# Get Container Metadata
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container', comp => 'metadata' ] );
# my $request = GET $uri;

# Get Container ACL
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container', comp => 'acl' ] );
# my $request = GET $uri;

# Delete Container
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container' ] );
# my $request = DELETE $uri;

# List Blobs
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer");
# $uri->query_form( [ restype => 'container', comp => 'list', include => 'metadata' ] );
# my $request = GET $uri;

# Put Blob
# my $uri = URI->new(
#    "https://$account.blob.core.windows.net/mycontainer/myblockblob");
# my $content = '<p>Hello there!</p>';
# my $request = PUT $uri,
#     'Content-Type'        => 'text/html; charset=UTF-8',
#     ':x-ms-meta-Category' => 'Web pages',
#     ':x-ms-blob-type'     => 'BlockBlob',
#     'Content-MD5'         => md5_base64($content) . '==',
#     'If-None-Match'       => '*',
#     'Content'             => $content;

# Get Blob
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer/myblockblob");
# my $request = GET $uri, 'If-Match', '0x8CE8CF67ABC00F3';

# Get Blob Properties
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer/myblockblob");
# my $request = HEAD $uri, 'If-Match', '0x8CE8CF67ABC00F3';

# Get Blob Metadata
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer/myblockblob");
# $uri->query_form( [ comp => 'metadata' ] );
# my $request = GET $uri, 'If-Match', '0x8CE8CF67ABC00F3';

# Set Blob Metadata
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer/myblockblob");
# $uri->query_form( [ comp => 'metadata' ] );
# my $request = PUT $uri, ':x-ms-meta-Colour', 'Orange', 'If-Match', '0x8CE8CF67ABC00F3';

# Lease Blob
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer/myblockblob");
# $uri->query_form( [ comp => 'lease' ] );
# my $request = PUT $uri, ':x-ms-lease-action', 'acquire';

# Delete Blob
# my $uri = URI->new("https://$account.blob.core.windows.net/mycontainer/myblockblob");
# my $request = DELETE $uri, 'If-Match', '0x8CE8CF7243F2B5C';

# And now the library code

$request->header( ':x-ms-version', '2011-08-18' );
$request->header( 'Date',          time2str() );
$request->content_length( length $request->content );

my $canonicalized_headers = join "",
    map { lc( substr( $_, 1 ) ) . ':' . $request->header($_) . "\n" }
    sort grep {/^:x-ms/i} $request->header_field_names;

# say "headers: $canonicalized_headers";

my $canonicalized_resource = '/' . $account . $request->uri->path . join "",
    map {
          "\n"
        . lc($_) . ':'
        . join( ',', sort $request->uri->query_param($_) )
    } sort $request->uri->query_param;

# say "resource: [$canonicalized_resource]";

my $string_to_sign
    = $request->method . "\n"
    . ( $request->header('Content-Encoding')    // '' ) . "\n"
    . ( $request->header('Content-Language')    // '' ) . "\n"
    . ( $request->header('Content-Length')      // '' ) . "\n"
    . ( $request->header('Content-MD5')         // '' ) . "\n"
    . ( $request->header('Content-Type')        // '' ) . "\n"
    . ( $request->header('Date')                // '' ) . "\n"
    . ( $request->header('If-Modified-Since')   // '' ) . "\n"
    . ( $request->header('If-Match')            // '' ) . "\n"
    . ( $request->header('If-None-Match')       // '' ) . "\n"
    . ( $request->header('If-Unmodified-Since') // '' ) . "\n"
    . ( $request->header('Range')               // '' ) . "\n"
    . $canonicalized_headers
    . $canonicalized_resource;

say $string_to_sign;

my $signature = hmac_sha256_base64( $string_to_sign,
    decode_base64($primary_access_key) );
$signature .= '=';

#say $signature;

$request->header( 'Authorization', "SharedKey $account:$signature" );

say $request->as_string;

my $ua = LWP::UserAgent->new;
$ua->env_proxy;

my $response = $ua->request($request);

if ( $response->is_success ) {
    say $response->as_string;
    my $xml = $response->decoded_content;
    say $xml;
    my $dom = XML::LibXML->load_xml( string => $xml );
    say $dom->toString(1);
} else {
    die $response->status_line;
}
