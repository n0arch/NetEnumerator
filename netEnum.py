#!/usr/bin/env python
## enumerate known systems on the network
## displays ARP, NIP and IP of LAN devices
## discovery via arping

# import logging to suppress scapy output unless error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys, time
from myColors import colors as c
import netifaces as ni

#function to retrieve IP of local interface
def getLocalIP(iface):
    myIP = []
    ip = ni.ifaddresses(iface)[2][0]['addr']
    mask = ni.ifaddresses(iface)[2][0]['netmask']
    for i in ip.split('.'):
        myIP.append(i)
    with open("netmasktable.txt", 'r') as f:
        for line in f:
            if mask in line:
                cidr = line.split()
                fullNet = myIP[0]+'.'+myIP[1]+'.'+myIP[2]+'.0'+cidr[1]
    print "\nScanning network: "+fullNet
    return fullNet

def getNIP(MAC):
    newmac = MAC.replace(':','-')
    with open("oui.txt", 'r') as f:
        for line in f:
            if newmac.upper() in line:
                nip = line.split()
                return ' '.join(nip[2:])

def getARP(localip):
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
        print "Discovered %s hosts on the network\n" % len(macs)
        while count < len(macs):
            oui = getNIP(macs[count][:8])
            print c.OK+"MANUFACTURER: "+c.END+oui+"\n"+c.OK+"MAC: "+c.END+macs[count]+"\n"+c.OK+"IP: "+c.END+ips[count]
            #print macs[count][:8]
	    count = count + 1
    except Exception, e:
        print c.FAIL+"Runtime Error: "+c.END+str(e)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        start = time.time()
        iface = sys.argv[1]
        getARP(getLocalIP(iface))
        end = time.time()
        elapsed = int(end - start)
        print "\nScan completed in "+str(elapsed)+" seconds\n"
    else:
        print c.FAIL+"SYNTAX ERROR:"+c.END+" No interface selected\n\tpython netEnum.py <interface_name>"
