import argparse
from scapy.all import sniff, ARP, Ether, srp
from colorama import init, Fore, Style


init(autoreset=True)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=1, verbose=False)
    for sent, received in answered:
        return received.hwsrc

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            real_mac = get_mac(packet[ARP].psrc)
            spoofed_mac = packet[ARP].hwsrc

            if real_mac and real_mac != spoofed_mac:
                print(f"{Fore.RED}[!] ARP Spoofing detected!")
                print(f"{Fore.YELLOW}[-] IP Address: {packet[ARP].psrc}")
                print(f"{Fore.GREEN}[✓] Real MAC: {real_mac}")
                print(f"{Fore.RED}[✗] Spoofed MAC: {spoofed_mac}\n")

        except Exception:
            pass

def start_sniffing(interface):
    print(f"{Fore.CYAN}[*] Listening on interface: {interface}...\n")
    sniff(iface=interface, store=False, prn=detect_arp_spoof)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple ARP spoofing detector")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff (e.g., eth0, wlan0)")
    args = parser.parse_args()

    start_sniffing(args.interface)