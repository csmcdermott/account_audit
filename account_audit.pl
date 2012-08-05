#!/usr/bin/perl

use strict;
use lib './deps/lib/perl5/site_perl/5.8.8';
use Term::ReadKey;
use Net::SSH::Expect;
my $timeout = 15;
my $DEBUG = 0;

if (@ARGV[0] eq '-d') {
  $DEBUG = 1;
  &logthis("DEBUG", "Debugging enabled.");
}

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

my ($count, @sudoers, %cmnd_aliases, %user_aliases, %admins);
foreach my $host (@hosts) {
  chomp($host);
  &logthis("STATUS", "Examining $host.");
  my $ssh = &login($host);
  &fetch_uid_0($host, $ssh);
  @sudoers = &fetch_sudoers($ssh, $password);
  if (scalar @sudoers < 1) {
    &logthis("ERROR", "Could not get contents of /etc/sudoers on $host.");
    next;
  }
  &load_cmnd_aliases($host);
  &load_user_aliases($host);
  &parse_groups($host, $ssh);
  &parse_users($host);
  $ssh->close();
  $count++;
}

&report();
&logthis("STATUS", "All done. Checked $count hosts.");

#########################################################################

sub report {
  &logthis("DEBUG", "Printing report.");
  my $output = "./report.csv";
  open my $OUTPUT, ">$output" or die $!;
  print $OUTPUT "Hostname, Username, Comment, Privileges\n";
  foreach my $host (keys %admins) {
    foreach my $user (keys %{ $admins{$host} }) {
      foreach my $priv (@{ $admins{$host}{$user} }) {
        print $OUTPUT "$host, $user, $priv\n";
      }
    }
  }
  close $OUTPUT;
}

# This module can authenticate with either a password, or
# public key auth. But the code is different so you have 
# to manually switch between the commented sections.
sub login {
  my $hostname = shift;
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
  return $ssh;
}

# Any user with uid 0 has effective root privileges, so start
# by grabbing those.
sub fetch_uid_0 {
  my ($hostname, $ssh) = @_;
  &logthis("DEBUG", "Fetching all users with uid 0 from $hostname.");
  my @grep_results = $ssh->exec('egrep ":0:0:" /etc/passwd');
  foreach (@grep_results) {
    /^(\S+):\S+:0:0:(\S*?):/;
    my $username = $1;
    my $comment = $2;
    push(@{ $admins{$hostname}{$username} }, "UID 0");
    &logthis("DEBUG", "Adding $username to list.");
  }
}

# Next grab the contents of /etc/sudoers and store it in the
# @sudoers array.
sub fetch_sudoers {
  my ($ssh, $password) = @_;
  &logthis("DEBUG", "Fetching contents of /etc/sudoers.");
  my $output = $ssh->exec("sudo cat /etc/sudoers");
  if ($output =~ /Password:|\[*sudo\]* password for/) {
    $ssh->send($password);
    $output = $ssh->read_all(5);
  }
  my @sudo_results = split('\n', $output);
  return @sudo_results;
}

# Parse /etc/sudoers lines for Cmnd_aliases, and store them in
# a global hash called %cmnd_aliases, along with the
# privileges granted through that alias.
sub load_cmnd_aliases {
  &logthis("DEBUG", "Loading up cmnd_aliases.");
  foreach (@sudoers) {
    if (/Cmnd_Alias\s+(\S+)\s*=\s*(.*)/i) {
      &logthis("DEBUG", "Adding cmnd_alias $1");
      $cmnd_aliases{$1} = $2;
    }
  }
}

# Parse /etc/sudoers lines for User_aliases, and store them in
# a global hash called %user_aliases, along with a list of
# users that belong to that alias.
sub load_user_aliases {
  &logthis("DEBUG", "Loading up user_aliases.");
  foreach (@sudoers) {
    if (/User_Alias\s+(\S+)\s*=\s*(.*)/i) {
      my @users = split(",", $2);
      foreach my $user (@users) {
        &logthis("DEBUG", "Adding user_alias $1");
        push (@{ $user_aliases{$1} }, $user . " (via $1 alias)");
      }
    }
  }
}

# Parse /etc/sudoers lines for system groups, and add
# the members of any groups defined to the global hash
# %admins.
sub parse_groups {
  my ($hostname, $ssh) = @_;
  &logthis("DEBUG", "Parsing system groups.");
  foreach (@sudoers) {
    if (/^#/) {
      next;
    } elsif (/Cmnd_Alias/i) {
      next;
    } elsif (/User_Alias/i) {
      next;
    } elsif (/Host_Alias/i) {
      next;
    } elsif (/Defaults/i) {
      next;
    } elsif (/LS_COLORS|LANG|LC_MEASUREMENT|LC_PAPER|_XKB_CHARSET/) {
      next;
    } elsif (/\[*\S+@\S+[\s:~]*\]*/) {
      next;
    } elsif (/\%(\S+)\s+(.*)/) {
      my $group = $1;
      my $privs = $2;
      &logthis("DEBUG", "Expanding group: $group.");
      foreach (keys %cmnd_aliases) {
        if ($privs =~ /^(.*)$_/) {
          &logthis("DEBUG", "Expanding cmnd_alias: $_.");
          my $start = $1;
          $privs = "(via $_ alias) " . $start . $cmnd_aliases{$_};
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
        &logthis("DEBUG", "Adding $group group owner: $owner to admins.");
        push(@{ $admins{$hostname}{$owner .  " (via $group group)"} }, $privs);
        my @members = split(',', $list_of_members);
        foreach (@members) {
          if (/\[\S+@\S+[\s:~]*\]/) {
            next;
          } elsif (/:x:\d+/) {
            next;
          }
          &logthis("DEBUG", "Adding $group group member: $_ to admins.");
          push(@{ $admins{$hostname}{$_ .  " (via $group group)"} }, $privs);
        }
      } else {
        &logthis("ERROR", "Couldn't parse group membership for $group group on $hostname.");
        next;
      }
    }
  }
}

# Parse /etc/sudoers lines for privilege grants, and add them to the
# global hash %admins.
sub parse_users {
  my $hostname = shift;
  &logthis("DEBUG", "Parsing regular users.");
  foreach (@sudoers) {
    if (/^#/) {
      next;
    } elsif (/Cmnd_Alias/i) {
      next;
    } elsif (/User_Alias/i) {
      next;
    } elsif (/Host_Alias/i) {
      next;
    } elsif (/Defaults/i) {
      next;
    } elsif (/LS_COLORS|LANG|LC_MEASUREMENT|LC_PAPER|_XKB_CHARSET/) {
      next;
    } elsif (/\[*\S+@\S+[\s:~]*\]*/) {
      next;
    } elsif (/\%(\S+)\s+(.*)/) {
      next;
    } elsif (/^(\S+)\s+(.*)/) {
      my $username = $1;
      my $privs = $2;
      foreach (keys %cmnd_aliases) {
        if ($privs =~ /^(.*)$_/) {
          &logthis("DEBUG", "Expanding cmnd_alias: $_.");
          my $start = $1;
          $privs = "(via $_ alias) " . $start . $cmnd_aliases{$_};
        }
      }
      if (defined $user_aliases{$username}) {
        foreach (@{ $user_aliases{$username} }) {
          &logthis("DEBUG", "Expanding user_alias: $username.");
          push(@{ $admins{$hostname}{$_} }, $privs);
        }
      } else {
        &logthis("DEBUG", "Adding user: $username to admins.");
        push(@{ $admins{$hostname}{$username} }, $privs);
      }
    } else {
      next;
    }
  }
}

# Send appropriate messages to STDOUT.
sub logthis {
  my ($channel, $message) = @_;
  if ($channel eq "ERROR") {
    print "$channel: $message\n";
  } elsif ($channel eq "STATUS") {
    print "$channel: $message\n";
  } elsif ($channel eq "DEBUG" && $DEBUG) {
    print "$channel: $message\n";
  }
}
