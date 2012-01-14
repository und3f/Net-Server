BEGIN { $| = 1; print "1..5\n"; }


### load the module
END {print "not ok 1\n" unless $loaded;}
use Net::Server;
$loaded = 1;
print "ok 1\n";


### test fork - don't care about platform
my $fork = 0;
eval {
  my $pid = fork;
  die unless defined $pid; # can't fork
  exit unless $pid;        # can fork, exit child
  $fork = 1;
  print "ok 2\n";
};
print "not ok 2\n" if $@;


### become a new type of server
package Net::Server::Test;
@ISA = qw(Net::Server);
use IO::Socket;
local $SIG{ALRM} = sub { die "timeout"; };
my $alarm = 5;


### test and setup pipe
local *READ;
local *WRITE;
my $pipe = 0;
eval {

  ### prepare pipe
  pipe( READ, WRITE );
  READ->autoflush(  1 );
  WRITE->autoflush( 1 );

  ### test pipe
  print WRITE "hi\n";
  die unless scalar(<READ>) eq "hi\n";

  $pipe = 1;
  print "ok 3\n";

};
print "not ok 3\n" if $@;


### find some open ports
### This is a departure from previously hard
### coded ports.  Each of the server tests
### will use it's own unique ports to avoid
### reuse problems on some systems.
my $start_port = 20600;
my $num_ports  = 1;
my @ports      = ();
for my $i (0..99){
  my $sock = IO::Socket::INET->new(PeerAddr => 'localhost',
				   PeerPort => ($start_port + $i),
                                   Timeout  => 2,
				   Proto    => 'tcp');
  push @ports, ($start_port + $i) if ! defined $sock;
  last if $num_ports == @ports;
}
if( $num_ports == @ports ){
  print "ok 4\n";
}else{
  print "not ok 4\n";
}

SKIP: {
if ($num_ports != @ports) {
    print "ok 5 # skip Not attempting connections because ports not setup properly\n";
    last SKIP;
}


### extend the accept method a little
### we will use this to signal that
### the server is ready to accept connections
sub accept {
  my $self = shift;
  
  print WRITE "ready!\n";

  return $self->SUPER::accept();
}


### start up a vanilla server and connect to it
if( $fork && $pipe ){

  eval {
    alarm $alarm;

    my $pid = fork;

    ### can't proceed unless we can fork
    die unless defined $pid;

    ### parent does the client
    if( $pid ){

      <READ>; ### wait until the child writes to us

      ### connect to child under udp
      my $remote = IO::Socket::INET->new(PeerAddr => 'localhost',
                                         PeerPort => $ports[0],
                                         Proto    => 'udp');
      ### send a packet, get a packet
      $remote->send("Are you there?",0);
      my $data = undef;
      $remote->recv($data,4096,0);  
      die "No data returned" unless defined $data;


      ### connect to child under tcp
      $remote = IO::Socket::INET->new(PeerAddr => 'localhost',
                                      PeerPort => $ports[0],
                                      Proto    => 'tcp');
      die "No socket returned" unless defined $remote;

      ### sample a line
      my $line = <$remote>;
      die "No line returned" unless $line =~ /Net::Server/;

      ### shut down the server
      print $remote "exit\n";
      print "ok 5\n";

    ### child does the server
    }else{

      ### start the server
      close STDERR;
      Net::Server::Test->run(port => "$ports[0]/tcp",
                             port => "$ports[0]/udp");
      exit;

    }

    alarm 0;
  };

  print "not ok 5\n" if $@;

}else{
  print "not ok 5\n";
}

} # end of SKIP
