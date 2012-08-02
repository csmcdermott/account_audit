account_audit
=============

Perl script to audit accounts with privileged access across a linux environment

hosts.txt contains a list of hostnames or IP addresses. When the script runs
it will prompt for credentials. Those credentials must be valid to log in 
over SSH and execute "sudo cat /etc/sudoers". All required modules are
included in the deps folder, although of course they may not work with
your version of perl so feel free to point the script at some other library
location.

Results are output to report.csv.
