another_shellshock_test
=======================

Some scripts to test for the "ShellShock" vulnerability (CVE-2014-6271).

- shellshock_local.sh
  Test for the two known (by me) version of this vulnerability:
  - env x='() { :;}; echo vulnerable' bash -c echo;
  - rm -f echo; env X='() { (a)=>\' bash -c "echo echo vulnerable" 2>/dev/null; cat echo
Do not run this script inside folders cotaining files names "echo", as it wil delete them. (sry for that)


- shellshock_cgi.py
  *Work in progress* Alternative: https://github.com/scottjpack/shellshock_scanner
