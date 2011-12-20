#!/home/acme/Public/perl-5.14.2/bin/perl
use strict;
use warnings;
use 5.14.0;
use Digest::MD5 qw(md5_base64);
use Digest::SHA qw(hmac_sha256_base64);
use HTTP::Date;
use HTTP::Request;
use LWP::UserAgent;
use MIME::Base64;
use URI::QueryParam;
use XML::LibXML;

my $account = 'astray';

my $primary_access_key
    = 'XXX';

# Get Blob Service Properties
my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/?restype=service&comp=properties" );

# Create Container
# my $request = HTTP::Request->new( PUT => "https://$account.blob.core.windows.net/mycontainer?restype=container" );

# List Containers
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/?comp=list" );

# Get Container Properties
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/mycontainer?restype=container" );

# Put Container Metadata
# my $request = HTTP::Request->new( PUT => "https://$account.blob.core.windows.net/mycontainer?restype=container&comp=metadata" );
# $request->header( ':x-ms-meta-Category', 'Images' );

# Get Container Metadata
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/mycontainer?restype=container&comp=metadata" );

# Get Container ACL
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/mycontainer?restype=container&comp=acl" );

# Delete Container
# my $request = HTTP::Request->new( DELETE => "https://$account.blob.core.windows.net/mycontainer?restype=container" );

# List Blobs
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/mycontainer?restype=container&comp=list&include=metadata" );

# Put Blob
# my $request = HTTP::Request->new( PUT => "https://$account.blob.core.windows.net/mycontainer/myblockblob" );
# $request->content_type( 'text/html; charset=UTF-8' );
# $request->header( ':x-ms-meta-Category', 'Web pages' );
# $request->header( ':x-ms-blob-type', 'BlockBlob' );
# $request->content('<p>Hello there!</p>');
# $request->header( 'Content-MD5', md5_base64($request->content).'==' );
# $request->header( 'If-None-Match', '*' );

# Get Blob
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/mycontainer/myblockblob" );
# $request->header( 'If-Match', '0x8CE8CA7ECD349BE' );

# Get Blob Properties
# my $request = HTTP::Request->new( HEAD => "https://$account.blob.core.windows.net/mycontainer/myblockblob" );
# $request->header( 'If-Match', '0x8CE8CA7ECD349BE' );

# Get Blob Metadata
# my $request = HTTP::Request->new( GET => "https://$account.blob.core.windows.net/mycontainer/myblockblob?comp=metadata" );

# Set Blob Metadata
# my $request = HTTP::Request->new( PUT => "https://$account.blob.core.windows.net/mycontainer/myblockblob?comp=metadata" );
# $request->header( ':x-ms-meta-Colour', 'Orange' );

# Delete Blob
# my $request = HTTP::Request->new( DELETE => "https://$account.blob.core.windows.net/mycontainer/myblockblob" );
# $request->header( 'If-Match', '0x8CE8CA7ECD349BE' );

# Lease Blob
# my $request = HTTP::Request->new( PUT => "https://$account.blob.core.windows.net/mycontainer/myblockblob?comp=lease" );
# $request->header( ':x-ms-lease-action', 'acquire' );

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
