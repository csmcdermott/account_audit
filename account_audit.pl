#!/usr/bin/perl

use strict;
use lib './deps/lib/perl5/site_perl/5.8.8';
use Term::ReadKey;
#use Expect;
use Net::SSH::Expect;
#$Expect::Exp_Internal = 1;
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
    password => $password,
    raw_pty => 1,
    debug => 1
  );

  print "attempting login\n";
  my $login_output = $ssh->login() or return(1);
  if ($login_output !~ /Last login/) {
    print "ERROR: Could not log in to $hostname.\n";
    return 1;
  }
  print "finished logging in... setting raw stty\n";
  $ssh->exec("stty raw -echo");

  print "greping passwd\n";
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
    } elsif (/Cmnd_Alias\s+(\S+)\s*=\s*(.*)/) {
      $command_aliases{$1} = $2;
    } elsif (/User_Alias\s+(\S+)\s*=\s*(.*)/) {
      $user_aliases{$1} = $2;
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
      if (exists $command_aliases{$privs}) {
        my $privs = $command_aliases{$privs};
      }
      my $group_output = $ssh->exec("grep $group /etc/group");
      my @members = split(',', $group_output);
      foreach (@members) {
        if (/\[\S+@\S+[\s:~]*\]/) {
          next;
        } elsif (/$group:x:\d+/) {
          next;
        }
        push(@{ $results{$hostname}{$_ .  " (via $group group)"} }, $privs);
      }
    } elsif (/(\S+)\s+(.*)/) {
      my $username = $1;
      my $privs = $2;
      if (exists $user_aliases{$username}) {
        my $username = $user_aliases{$username};
      }
      if (exists $command_aliases{$privs}) {
        my $privs = $command_aliases{$privs};
      }
      if ($results{$hostname}{$username} eq "UID 0") {
        next;
      } else {
        push(@{ $results{$hostname}{$username} }, $privs);
      }
    } else {
      next;
    }
  }
  $ssh->close();
}

