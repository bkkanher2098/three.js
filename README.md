import scapy.all as sc

def scan(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for answer in answered_list:
        print(f"IP: {answer[1].psrc} \t MAC: {answer[1].hwsrc}")

scan("192.168.1.1/24")
