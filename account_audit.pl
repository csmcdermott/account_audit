#!/usr/bin/perl

use strict;
use lib './deps/lib/perl5/site_perl/5.8.8';
use Term::ReadKey;
use Net::SSH::Expect;
my $timeout = 15;

print "Please enter your SSH username: \n";
chomp(my $sshuser = <STDIN>);
ReadMode 2;
print "Please enter your SSH password: \n";
chomp(my $password = <STDIN>);
ReadMode 0;

my $config = "./hosts.txt";
open my $FH, $config or die $!;
my @hosts = <$FH>;
close $FH;

my %results;

foreach my $host (@hosts) {
  &fetch_admins($host);
}

my $output = "./report.csv";
open my $OUTPUT, ">$output" or die $!;
print $OUTPUT "Hostname, Username, Comment, Privileges\n";
foreach my $host (keys %results) {
  foreach my $user (keys %{ $results{$host} }) {
    foreach my $priv (@{ $results{$host}{$user} }) {
      print $OUTPUT "$host, $user, $priv\n";
    }
  }
}
close $OUTPUT;

#########################################################################

sub fetch_admins {
  my $hostname = shift;
  chomp($hostname);
  print "fetching accounts on $hostname\n";

  my $ssh = Net::SSH::Expect->new (
    host => $hostname,
    user => $sshuser,
  #  password => $password,
    raw_pty => 1
  );

  ####### USE THIS FOR PUBLIC KEY AUTHENTICATION #######
  $ssh->run_ssh();
  ######################################################

  ######## USE THIS FOR PASSWORD AUTHENTICATION ########
  #my $login_output = $ssh->login() or return(1);
  #if ($login_output !~ /Last login/) {
  #  print "ERROR: Could not log in to $hostname.\n";
  #  return 1;
  #}
  ######################################################

  $ssh->exec("stty raw -echo");

  my @grep_results = $ssh->exec('egrep ":0:0:" /etc/passwd');
  foreach (@grep_results) {
    /^(\S+):\S+:0:0:(\S*?):/;
    my $username = $1;
    my $comment = $2;
    push(@{ $results{$hostname}{$username} }, "UID 0");
  }

  my $output = $ssh->exec("sudo cat /etc/sudoers");
  if ($output =~ /Password:|\[*sudo\]* password for/) {
    $ssh->send($password);
    $output = $ssh->read_all(20);
  }
  my @sudo_results = split('\n', $output);
  if (scalar @sudo_results < 1) {
    print "ERROR: No results from sudoers on $hostname.\n";
    return 1;
  }
  my (%command_aliases, %user_aliases);
  foreach (@sudo_results) {
    if (/^#/) {
      next;
    } elsif (/Cmnd_Alias\s+(\S+)\s*=\s*(.*)/i) {
      $command_aliases{$1} = $2;
      #print "Found cmnd_alias $1, saving $2\n";
    } elsif (/User_Alias\s+(\S+)\s*=\s*(.*)/i) {
      my @users = split(",", $2);
      foreach my $user (@users) {
        push (@{ $user_aliases{$1} }, $user . " via $1 alias");
      }
    } elsif (/Host_Alias/) {
      next;
    } elsif (/Defaults/) {
      next;
    } elsif (/LS_COLORS|LANG|LC_MEASUREMENT|LC_PAPER|_XKB_CHARSET/) {
      next;
    } elsif (/\[*\S+@\S+[\s:~]*\]*/) {
      next;
    } elsif (/\%(\S+)\s+(.*)/) {
      my $group = $1;
      my $privs = $2;
      #print "Privs: $privs\n";
      foreach (keys %command_aliases) {
       # print " * Checking $_\n";
        if ($privs =~ /^(.*)$_/) {
          my $start = $1;
       #   print "Matched $_, saving $start\n";
          $privs = "(via $_ alias) " . $start . $command_aliases{$_};
       #   print "New privs: $privs\n";
        }
      }
      my $group_output = $ssh->exec("grep ^$group /etc/group");
      if ($group_output =~ /(\S+):x:(\d+):(\S*)/) {
        my $gid = $2;
        my $list_of_members = $3;
        my $gid_result = $ssh->exec("grep $gid /etc/passwd");
        my $owner;
        if ($gid_result =~ /^(\S+):x:.+$gid.+:/) {
          $owner = $1;
        } else {
          next;
        }
        push(@{ $results{$hostname}{$owner .  " (via $group group)"} }, $privs);
        my @members = split(',', $list_of_members);
        foreach (@members) {
          if (/\[\S+@\S+[\s:~]*\]/) {
            next;
          } elsif (/:x:\d+/) {
            next;
          }
          push(@{ $results{$hostname}{$_ .  " (via $group group)"} }, $privs);
        }
      } else {
        print "ERROR: Couldn't parse group membership for $group.\n";
        next;
      }
    } elsif (/(\S+)\s+(.*)/) {
      my $username = $1;
      my $privs = $2;
      if (exists $command_aliases{$privs}) {
        $privs = $command_aliases{$privs};
      }
      if (exists $user_aliases{$username}) {
        foreach (@{ $user_aliases{$username} }) {
          push(@{ $results{$hostname}{$_} }, $privs);
        }
      } else {
        push(@{ $results{$hostname}{$username} }, $privs);
      }
    } else {
      next;
    }
  }
  $ssh->close();
}
