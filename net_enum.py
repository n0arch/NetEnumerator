#!/usr/bin/env python
"""enumerate known systems on the network via scapy ARPping
   displays ARP, NIP and IP of LAN devices

   Usage: 
     $ python net_enum.py <interface_name>
     $ python net_enum.py eth0
"""


# import logging to suppress scapy output unless error
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

from scapy.all import *
import sys
import time
import netifaces as ni


NETMASK_TABLE='NetmaskTable.txt'
MAC_OUI='oui.txt'

class c:
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

def _get_local_ip(iface):
    # Need to fix the full_net var
    my_ip = []
    ip = ni.ifaddresses(iface)[2][0]['addr']
    mask = ni.ifaddresses(iface)[2][0]['netmask']
    for i in ip.split('.'):
        my_ip.append(i)
    with open(NETMASK_TABLE, 'r') as f:
        for line in f:
            if mask in line:
                cidr = line.split()
                full_addr = my_ip[0]+'.'+my_ip[1]+'.'+my_ip[2]+'.0'+cidr[1]
    print '\nScanning network: '+full_addr
    return full_addr

def _get_nip(mac):
    newmac = mac.replace(':','-')
    with open(MAC_OUI, 'r') as f:
        for line in f:
            if newmac.upper() in line:
                nip = line.split()
                return ' '.join(nip[2:])

def _get_arp(localip):
    macs = []
    ips = []
    nips = []
    global ans, unans
    try:
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=localip), timeout=2, verbose=0)
        for snd, rcv in ans:
            macs.append(rcv.sprintf(r'%Ether.src%'))
            ips.append(rcv.sprintf(r'%ARP.psrc%'))
        count = 0
        print "Discovered {} hosts on the network\n".format(len(macs))
        while count < len(macs):
            oui = _get_nip(macs[count][:8])
            print c.OK+"MANUFACTURER: "+c.END+oui+"\n"+c.OK+"MAC: "+c.END+macs[count]+"\n"+c.OK+"IP: "+c.END+ips[count]
	    count = count + 1
    except Exception, e:
        print c.FAIL+"Runtime Error: "+c.END+str(e)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        start = time.time()
        iface = sys.argv[1]
        _get_arp(_get_local_ip(iface))
        end = time.time()
        elapsed = int(end - start)
        print "\nScan completed in "+str(elapsed)+" seconds\n"
    else:
        print c.FAIL+"SYNTAX ERROR:"+c.END+" No interface selected\n\tpython netEnum.py <interface_name>"
