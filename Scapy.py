import scapy.all as scapy
def sniff(interface):
        scapy.sniff(iface=interface, store=False, prn=lambda  x: x.summary())
interface = "wlan0"
sniff(interface)
print(scapy)
