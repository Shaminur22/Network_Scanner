from scapy.all import *
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
from sys import exit, stderr, argv

class NetworkScanner:
    def __init__(self, hosts):
        self.hosts = hosts
        self.alive = {}
        self.create_packet()
        self.send_packet()
        self.get_alive()
        self.print_alive()

    def create_packet(self):
        layer1 = Ether(dst="ff:ff:ff:ff:ff:ff")
        layer2 = ARP(pdst=self.hosts)
        self.packet = layer1 / layer2

    def send_packet(self):
        answered, unanswered = srp(self.packet, timeout=1, verbose=False)
        if answered:
            self.answered = answered
        else:
            print("No hosts are up!")
            exit(1)

    def get_alive(self):
        for sent, received in self.answered:
            self.alive[received.psrc] = received.hwsrc

    def print_alive(self):
        table = PrettyTable(["IP", "MAC", "VENDOR"])
        mac_lookup = MacLookup()
        for ip, mac in self.alive.items():
            try:
                vendor = mac_lookup.lookup(mac)
                table.add_row([ip, mac, vendor])
            except:
                table.add_row([ip, mac, "UNKNOWN"])
        print(table)

def get_args():
    parser = ArgumentParser(description="Network Scanner")
    parser.add_argument("--hosts", dest="hosts", required=True, help="Hosts to scan (e.g., 192.168.1.0/24)")
    args = parser.parse_args()
    return args.hosts

if __name__ == "__main__":
    hosts = get_args()
    NetworkScanner(hosts)
