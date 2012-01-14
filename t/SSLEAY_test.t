use strict;
use warnings;

use Net::SSLeay;
use Test::More;
use Net::Server;
use File::Temp;

use_ok 'Net::Server::Proto::SSLEAY';

# Find free port
my $sock = IO::Socket::INET->new(
    LocalHost => '127.0.0.1',
    Proto     => 'tcp',
    Listen    => 1
);
my $port = $sock->sockport;
$sock->close;

my $pem = do {
    local $/;
    <DATA>;
};

my ($pem_fh, $pem_filename) =
  File::Temp::tempfile(SUFFIX => '.pem', UNLINK => 1);

print $pem_fh $pem;
$pem_fh->close;

local @ARGV = (
    '--SSL_cert_file' => $pem_filename,
    '--SSL_key_file'  => $pem_filename
);

my $res;

subtest 'Test Syswrite' =>
  sub { test_server('Net::Server::Test::Syswrite', $port) };

done_testing;

sub test_server {
    my ($server, $port) = @_;
    my $read;

    no strict 'refs';
    pipe($read, ${"${server}::pipe"});
    use strict 'refs';

    my $pid = fork;
    die unless defined $pid;

    if ($pid) {
        <$read>;
        my $remote = IO::Socket::INET->new(
            PeerAddr => 'localhost',
            PeerPort => $port,
            Proto    => 'tcp'
        );

        my $ctx = Net::SSLeay::CTX_new()
          or die_now("Failed to create SSL_CTX $!");
        Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL)
          and die_if_ssl_error("ssl ctx set options");
        my $ssl = Net::SSLeay::new($ctx)
          or die_now("Failed to create SSL $!");

        Net::SSLeay::set_fd($ssl, $remote->fileno);
        Net::SSLeay::connect($ssl);

        Net::SSLeay::write($ssl, "foo bar");
        my $res = Net::SSLeay::read($ssl);
        is $res, "foo bar", "received correct data from server";
    }
    else {
        close STDERR;
        $server->run(
            port  => "$port",
            proto => 'ssleay',
        );
        exit;
    }
}

package Net::Server::Test::Syswrite;
use base qw(Net::Server);
use IO::Socket;

our $pipe;

sub accept {
    my $self = shift;

    warn $pipe;
    $pipe->write("go!\n");
    $pipe->flush;

    return $self->SUPER::accept();
}

sub process_request {
    my $self = shift;

    my $string = "foo bar\n";
    my $offset = 0;

    my $total = 0;
    my $buf;

    # Wait data
    my $vec = '';
    vec($vec, $self->{server}->{client}->fileno, 1) = 1;

    until ($buf) {
        select($vec, undef, undef, undef);
        $self->{server}->{client}->sysread(\$buf, 100, $total);
    }

    select(undef, $vec, undef, undef);

    $self->{server}->{client}->syswrite($buf);

    $self->server_close;
}

__END__
-----BEGIN CERTIFICATE-----
MIICKTCCAZICCQDFxHnOjdmTTjANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTIwMTE0MTgzMjMwWhcN
NzUxMTE0MTIwNDE0WjBZMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0
ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDDAls
b2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKLGfQantHdi/0cd
eoOHRbWKChpI/g84hU8SnwmrSMZR0x76vDLKMDYohISoKxRPx6j2M2x3P4K+kEJm
C5H9iGdD9p9ljGnRdkGp5yYeuwWfePRb4AOwP5qgQtEb0OctFIMjcAIIAw/lsnUs
hGnom0+uA9W2H63PgO0o4qiVAn7NAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEATDGA
dYRl5wpsYcpLgNzu0M4SENV0DAE2wNTZ4LIR1wxHbcxdgzMhjp0wwfVQBTJFNqWu
DbeIFt4ghPMsUQKmMc4+og2Zyll8qev8oNgWQneKjDAEKKpzdvUoRZyGx1ZocGzi
S4LDiMd4qhD+GGePcHwmR8x/okoq58xZO/+Qygc=
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCixn0Gp7R3Yv9HHXqDh0W1igoaSP4POIVPEp8Jq0jGUdMe+rwy
yjA2KISEqCsUT8eo9jNsdz+CvpBCZguR/YhnQ/afZYxp0XZBqecmHrsFn3j0W+AD
sD+aoELRG9DnLRSDI3ACCAMP5bJ1LIRp6JtPrgPVth+tz4DtKOKolQJ+zQIDAQAB
AoGASXDmvhbyfJ8k8HAjc66XzBWxAzUFs9Zbh1aufM1UM259o8+bFAtXf0f+ql+5
uBtaySf0Aa8374SNT/f8pmzOmpiXMvYRz8Z5Gc6JYpYd/PrCoSCGtP+NdCvk7Y5c
eUmmpiEto4+fgCAKrtqc5jm8eBWn/yNhQNDBVJ9qX+kXQOECQQDVBLvBZaECSMTm
djKuPlZ93cmyI7g+TURTl2N08fz4xQVVbo5+AV0GsEZupBpTgrHpLTk8gKP/nfdR
9KWZldbZAkEAw55+SqrVTv4cI0fMvC0t8Wl46zTkY9tK65TGnbO1DbTQh9qs+NwH
+v3uu47ef5w/73xLtDjQouz//0z5rgF3FQJAfrmOKQOYwY8g9CmlBNu5ALAM6Zku
ZoH4//G0DUJYyHYNMkHPK08MVIpRnEisELpTtPBeeIvfBJapJ2xvh+sIIQJASeY4
I5EB4EOS8akQKQ6QSqDjs0dZ+HdBiFm95pmbDkB+frQXoDPPN/xyEZzZZS/r31b/
amgEOWh7FUFJGXkoOQJBALfOgsiss0lASlOXAg1rwO4m2OaDiaEde01PLcSjIaKl
Qfbzc7ZYF+fGDsHHlD5Kgj1CGaWCVVHqCv4UHSrA/gM=
-----END RSA PRIVATE KEY-----
