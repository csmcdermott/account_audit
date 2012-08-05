account_audit
=============

Perl script to audit accounts with privileged access across a linux environment

hosts.txt contains a list of hostnames or IP addresses. When the script runs
it will prompt for credentials. Those credentials must be valid to log in 
over SSH and execute "sudo cat /etc/sudoers". All required modules are
included in the deps folder, although of course they may not work with
your version of perl so feel free to point the script at some other library
location.

If Cmnd_alias, User_alias, or system groups are in use, they will be expanded
and the resultant set of privileges will be indidivually listed out. If a user
is granted redundant or overlapping privileges by different grant lines, all
entries will be listed invidually - this script makes no attempts to
de-duplicate.

Results are output to report.csv.
