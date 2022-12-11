import scapy.all as scapy
from scapy_http import http
import optparse


def listen_packets(interface):
    # gelen paketlerin hepsi dinlenir ve onları kendimize çekeriz
    # store: alınan paketlerin bellekte depolanması
    # prn: callback function
    scapy.sniff(iface=interface, store=False, prn=analyze_packets)


def analyze_packets(packet):
    # packet.show()
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--interface", dest="interface", help="Enter Interface")
    options = parse_object.parse_args()[0]

    if not options.interface:
        print("Enter İnterface")

    return options


user = get_user_input()
user_interface = user.interface

listen_packets(user_interface)
