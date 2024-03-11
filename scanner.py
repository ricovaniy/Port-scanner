import concurrent.futures
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from arg_parser import configure_parser, ScannerArgs
from scapy.layers.inet import IP, TCP
from scapy.all import *
import socket

class Scanner:
    id = random.randint(0,10000)
    UDP_Requsts={
        'HTTP': b'GET / HTTP/1.1',
        'DNS': struct.pack("!HHHHHH", id, 256, 1, 0, 0, 0),
        'ECHO': b"ping"
    }
    protocols_for_udp={
        80: "HTTP",
        53: "DNS",
        7: "ECHO"
    }
    def __init__(self, args: ScannerArgs) -> None:
        self.ip = args.target
        self.ports = args.ports
        self.timeout = args.timeout
        self.threads_num = args.threads_num
        self.verbose = args.verbose
        self.guess = args.guess
        self.sorted_ports = self.parse_ports()

    def parse_ports(self) -> Dict[str, set]:
        sorted_ports = {
            "udp": set(),
            "tcp": set()
        }
        for port in self.ports:
            protocol = port[:3]
            if '/' not in port:
                sorted_ports[protocol].update(range(1, 65536))
            for p in port[4:].split(','):
                if "-" in p:
                    start = int(p.split("-")[0])
                    end = int(p.split("-")[1])
                    sorted_ports[protocol].update(range(start, end + 1))
                else:
                    sorted_ports[protocol].update([p])
        return sorted_ports

    def scan_ports(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers = self.threads_num) as executor:

            tcp_futures = [executor.submit(self.scan_tcp, tcp_port) for tcp_port in self.sorted_ports["tcp"]]


            udp_futures = [executor.submit(self.scan_udp, udp_port) for udp_port in self.sorted_ports["udp"]]


            concurrent.futures.wait(tcp_futures + udp_futures)

    def scan_tcp(self, tcp_port):
        is_open = False
        protocol = ""
        start = time.time()
        syn_packet = IP(dst=self.ip) / TCP(dport=int(tcp_port), flags="S")
        resp_packet = sr1(syn_packet, timeout=self.timeout, verbose=False)
        end = time.time()
        if resp_packet:
            if resp_packet.getlayer('TCP').flags & 0x12 != 0:
                is_open = True
            if self.guess:
                protocol = resp_packet.sprintf('%TCP.sport%')
                if protocol == "domain":
                    protocol = "DNS"
                else:
                    protocol = protocol.upper()
        if is_open:
            print(f"TCP {tcp_port} {round(end-start, 3) if self.verbose else ''}s  {protocol}")

    def scan_udp(self, udp_port):
        if not udp_port:
            return
        protocol = ""
        start = time.time()
        for protocol_type in self.UDP_Requsts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                addr = (self.ip, int(udp_port))
                sock.sendto(self.UDP_Requsts[protocol_type], addr)
                data = sock.recvfrom(1000)
                sock.close()
                if data:
                    if self.guess:
                        if int(udp_port) in self.protocols_for_udp:
                            protocol = self.protocols_for_udp[int(udp_port)]
                    end = time.time()
                    print(f"UDP {udp_port} {round(end-start, 3) if self.verbose else ''} {protocol}")
                    return
            except TimeoutError:
                continue


if __name__ == "__main__":
    parser = configure_parser()
    args = parser.parse_args()
    scanner = Scanner(args)
    scanner.scan_ports()