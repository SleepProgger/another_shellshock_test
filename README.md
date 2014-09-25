another_shellshock_test
=======================

Some scripts to test for the "ShellShock" vulnerability (CVE-2014-6271).

## shellshock_local.sh
Test for the two known (by me) version of this vulnerability:
- env x='() { :;}; echo vulnerable' bash -c echo;
- rm -f echo; env X='() { (a)=>\' bash -c "echo echo vulnerable" 2>/dev/null; cat echo
Do not run this script inside folders cotaining files names "echo", as it wil delete them. (sry for that)


## shellshock_cgi.py
Test if a cgi script is vulnerable.
USAGE:
 - ./shellshock_cgi.py url1 url2 url3
 - cat somefile | ./shellshock_cgi.py
ATM. only suports GET requests and deliver the exploit in the User_Agent. This could be changed in a short amount of time, though.

It runs two tests:
- text_attack: Tries to inject a known text into the result. Succesfull if the cgis STDOUT is returned as response.
- timing attack: Tries to inject a call to sleep.

EXAMPLE:
'''
user@host:~/workspace/security/shellshock$ ./shellshock_cgi.py http://localhost/index.html http://localhost/lol.php
- testing: http://localhost/index.html
Timing attack vulnerable: False
Known text attack vulnerable: False

- testing: http://localhost/lol.php
Timing attack vulnerable: True
Known text attack vulnerable: True
'''
