# this program will resolve each packet based on the methods added in this program
# rules will be resolved based on the methods found in this program

from Rules import *
from scapy.all import *
from threading import *
import time

ip_limit = 10
tcp_limit = 10
udp_limit = 10
duration = 20

lock = threading.Lock()

def setRules():
    readRules()

def triggerAlert(msg):
    print(msg)
    
# Resolves the packet based on implementations. support IP TCP UDP
def resolveRule(packet):
    if packet.haslayer(IP):
        resolveIP(packet)
    if packet.haslayer(TCP):
        resolveTCP(packet)
    if packet.haslayer(UDP):
        resolveUDP(packet)


# Resolve's IP
def resolveIP(packet):
    if("ip_src" in rules):
        if(packet[IP].src in (rules.get("ip_src")).keys()):
            resolveTarget("IP", packet[IP].src, "ip_src", packet)
    if("ip_dst" in rules):
        if(packet[IP].dst in (rules.get("ip_dst")).keys()):
            resolveTarget("IP", packet[IP].dst, "ip_dst", packet)
        
# Resolve's TCP
def resolveTCP(packet):
    if("tcp_sport" in rules):
        if(str(packet[TCP].sport) in (rules.get("tcp_sport")).keys()):
            resolveTarget("TCP", str(packet[TCP].sport), "tcp_sport", packet)
    if("tcp_dport" in rules):
        if(str(packet[TCP].dport) in (rules.get("tcp_dport")).keys()):
            resolveTarget("TCP", str(packet[TCP].dport), "tcp_dport", packet)

# Resolve's TCP
def resolveUDP(packet):
    if("udp_sport" in rules):
        if(str(packet[UDP].sport) in (rules.get("udp_sport")).keys()):
            resolveTarget("UDP", str(packet[UDP].sport), "udp_sport", packet)
    if("udp_dport" in rules):
        if(str(packet[UDP].dport) in (rules.get("udp_dport")).keys()):
            resolveTarget("UDP", str(packet[UDP].dport), "udp_dport", packet)

# Checks if a packet hits the limit and does an action when it does            
def resolveTarget(protocol, packet_target, rule_target, packet):
    list_of_targets = (rules.get(rule_target))
    counter = list_of_targets[packet_target]
    list_of_targets[packet_target] = counter + 1
    if(protocol == "IP"):
        if(list_of_targets[packet_target] == ip_limit):
            #ipAction(packet)
            x = threading.Thread(target=ipAction, args=(packet, list_of_targets, rule_target, packet_target))
            x.daemon = True
            x.start()
    if(protocol == "TCP"):
        if(list_of_targets[packet_target] == tcp_limit):
            #tcpAction(packet)
            y = threading.Thread(target=tcpAction, args=(packet, list_of_targets, rule_target, packet_target))
            y.daemon = True
            y.start()
    if(protocol == "UDP"):
        if(list_of_targets[packet_target] == udp_limit):
            #udpAction(packet)
            z = threading.Thread(target=udpAction, args=(packet, list_of_targets, rule_target, packet_target))
            z.daemon = True
            z.start()
    
# Action for ip packets
def ipAction(packet, list_of_targets, rule_target, packet_target):
    toggleIP("-A", packet, rule_target)
    time.sleep(duration)
    toggleIP("-D", packet, rule_target)
    clearCounter(list_of_targets, packet_target)
        
# Action for tcp packets
def tcpAction(packet, list_of_targets, rule_target, packet_target):
    toggleTCP("-A", packet, rule_target)
    time.sleep(duration)
    toggleTCP("-D", packet, rule_target)
    clearCounter(list_of_targets, packet_target)
        
# Action for udp packets
def udpAction(packet, list_of_targets, rule_target, packet_target):
    toggleUDP("-A", packet, rule_target)
    time.sleep(duration)
    toggleUDP("-D", packet, rule_target)
    clearCounter(list_of_targets, packet_target)

# clears the counter for the current violating rule
def clearCounter(list_of_targets, packet_target):
    lock.acquire()
    list_of_targets[packet_target] = 0
    lock.release()
    
# do the corresponding action for the rule
def toggleIP(action, packet, rule_target):
    if(rule_target == "ip_src"):
        subprocess.call("sudo " + "/sbin/iptables " + action + " FORWARD -s " + packet[IP].src + " -j DROP", shell=True)
    elif(rule_target == "ip_dst"):
        subprocess.call("sudo " + "/sbin/iptables " + action + " FORWARD -d " + packet[IP].dst + " -j DROP", shell=True)

# do the corresponding action for the rule
def toggleTCP(action, packet, rule_target):
    if(rule_target == "tcp_sport"):
        subprocess.call("sudo " + "/sbin/iptables " + action + " FORWARD -p tcp --sport " + str(packet[TCP].sport) + " -j DROP", shell=True)
    elif(rule_target == "tcp_dport"):
        subprocess.call("sudo " + "/sbin/iptables " + action + " FORWARD -p tcp --dport " + str(packet[TCP].dport) + " -j DROP", shell=True)
        
# do the corresponding action for the rule
def toggleUDP(action, packet, rule_target):
    if(rule_target == "udp_sport"):
        subprocess.call("sudo " + "/sbin/iptables " + action + " FORWARD -p udp --sport " + str(packet[TCP].sport) + " -j DROP", shell=True)
    elif(rule_target == "udp_dport"):
        subprocess.call("sudo " + "/sbin/iptables " + action + " FORWARD -p udp --dport " + str(packet[TCP].sport) + " -j DROP", shell=True)