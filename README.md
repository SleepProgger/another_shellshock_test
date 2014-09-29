another_shellshock_test
=======================

Some scripts to test for the "ShellShock" vulnerability (CVE-2014-6271).

The codename for this scripts is SHIT (SHellshock Injection Test) *harrharr.

*Please only use this script in environments where you are allowed to. *


## shellshock_local.sh
Test for the two known (by me) version of this vulnerability on the local system:
- env x='() { :;}; echo vulnerable' bash -c echo;
- rm -f echo; env X='() { (a)=>\' bash -c "echo echo vulnerable" 2>/dev/null; cat echo
! THIS SCRIPT WILL REMOVE ANY FILE NAMED echo IN THE CURRENT DIRECTORY. (Sorry for that)

A better script for this purpose is located here: https://github.com/hannob/bashcheck

## shellshock_cgi.py
Test if given cgi script are vulnerable.
USAGE:
 - ./shellshock_cgi.py url1 url2 url3
 - cat somefile | ./shellshock_cgi.py

It runs two tests:
- text_attack: Tries to inject a known text into the result. Succesfull if the cgis STDOUT is returned as response.
- timing attack: Tries to inject a call to sleep.

ATM. only suports GET requests and deliver the exploit in the User_Agent. This could be changed in a short amount of time, though.

EXAMPLE:
```
user@host:~/workspace/security/shellshock$ ./shellshock_cgi.py http://localhost/index.html http://localhost/lol.php
- testing: http://localhost/index.html
Timing attack vulnerable: False
Known text attack vulnerable: False

- testing: http://localhost/lol.php
Timing attack vulnerable: True
Known text attack vulnerable: True
```


## shellshock_dhcp.py
POC / Tester for the shellshock exploit via dchp clients.
In general you could just set up a dhcp server and set the option flag, but this way it would be more difficult to only test specific clients, spoof server and some other stuff.  

I am using the dhcp option 114 (url) as default field to supply the shellshock string.
But there seem to be a bunch of possible fields (See end of README).  
Without any parameter, the script will use the dhcp settings from the first dhcp server answering.
Client REQUESTs will always be ACKed (with inserted exploit).
DISCOVER requests will be answered with data supplied from the real dhcp server, or given as script parameter.  
  
The script will spoof the servers address if the package is send to a specific server.

The default command to execute is "/usr/bin/id > /tmp/test_x". Adjust it, for example. to a bash poor mans shell to call back to a server of yours to collect vulnerable addresses.  

You have to be lucky for the exploit to work, or guarantee that your machine answers faster as the real dhcp server.  
I only tested with dhclient so far, but it should work with every dhcp client invoking (the vulnerable version of) bash scripts and passing env variables.

EXAMPLE:
- Only listen for two given MAC addresses (use the data supplied by the real dhcp server):  
./shellshock_dhcp.pyshellshock_dhcp.py -w 08:00:27:09:84:a9 05:01:27:19:84:e9  

- Use the script without a real dhcp server. OFC you'll have to supply al needed values.  
./shellshock_dhcp.pyshellshock_dhcp.py --static-data --gateway 192.168.100.152 --server-ip 192.168.0.1 --subnet-mask 255.255.255.0 -o 80  
  
  
USAGE:
    usage: dhcp.py [-h] [-i INTERFACE] [-b MAC [MAC ...]] [-w MAC [MAC ...]] [-s]
                   [--ip IP] [--dns-server DNS_SERVER] [--gateway GATEWAY]
                   [--subnet-mask SUBNET_MASK] [--mac MAC] [--server-ip SERVER_IP]
                   [-l LEASE] [-c COMMAND] [-o OPTION]

    optional arguments:
      -h, --help            show this help message and exit
      -i INTERFACE, --interface INTERFACE
                            Use the given interface for sniffing and sending.
      -b MAC [MAC ...], --blacklist MAC [MAC ...]
                            Never react to package from given MAC.
      -w MAC [MAC ...], --whitelist MAC [MAC ...]
                            Only react to packages from given MAC.
      -s, --static-data     If given no dhcp request is done to get the settings.
                            If used --gateway, --dns-server and --subnet-mask
                            should be supplied.
      --ip IP               If given send this IP to the client(s) on DISCOVER.
      --dns-server DNS_SERVER
                            If given send this DNS server IP to the client(s) on
                            DISCOVER and REQUEST.
      --gateway GATEWAY     If given send this gateway IP to the client(s) on
                            DISCOVER and REQUEST.
      --subnet-mask SUBNET_MASK
                            If given send this subnet mask to the client(s) on
                            DISCOVER and REQUEST.
      --mac MAC             Use the given MAC address if not supplied by client.
                            If not given we use the mac from the real server, or a
                            random random one (if --static-data is given)..
      --server-ip SERVER_IP
                            Use the given IP address if not supplied by client. If
                            not given we use the IP from the real server, or a
                            random random one (if --static-data is given)..
      -l LEASE, --lease LEASE
                            Lease time to use.
      -c COMMAND, --command COMMAND
                            The command to execute on the client machine.
      -o OPTION, --option OPTION
                            The option flag to use for the payload.


INSTALL:
You will need python 2.7 and scapy (apt-get install scapy).  
It could work on windows, but to be honest, i didn't test it.  
The script (as every scapy script) need to be run as root.  
   
This script is pretty much in an alpha state, plus it is the first project i did with scapy and i am no network pro after all, so be aware that there could be (and probably will be) bugs.  
In general there is still much to do, and i would bet that there are a bunch of cases where the script will just crash ;)  

Also be aware that this script could lead to a hickup in the dhcp servers cache and also on the dhcp client. (For the last one just remove the lease files and restart your interface)  

Only works with IPv4 addresses ATM.
 
 
 

*Working (at least on my test system) options which allow strings as data and get passed to the dhclient scripts:*
114  
242  
80  
133  
137  
83  
195  
250  
224  
108  
163  
174
