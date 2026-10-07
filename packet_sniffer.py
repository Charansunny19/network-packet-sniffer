import socket
import struct
import threading
import time
from datetime import datetime


class PacketSniffer:
    def __init__(self):
        self.running = False
        self.thread = None

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0

        self.packets = []
        self.lock = threading.Lock()

    def reset(self):
        with self.lock:
            self.packet_count = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.other_count = 0
            self.packets = []

    def start(self):
        if self.running:
            return

        self.reset()
        self.running = True

        self.thread = threading.Thread(
            target=self.capture_packets,
            daemon=True
        )
        self.thread.start()

    def stop(self):
        self.running = False

    def log_packet(self, packet):
        try:
            with open("packet_log.txt", "a", encoding="utf-8") as file:
                file.write(
                    f"{packet['time']} | "
                    f"{packet['protocol']} | "
                    f"{packet['source']}:{packet['source_port']} -> "
                    f"{packet['destination']}:{packet['destination_port']} | "
                    f"{packet['size']} bytes\n"
                )
        except Exception:
            pass

    def add_packet(self, packet):
        with self.lock:
            self.packet_count += 1

            protocol = packet["protocol"]

            if protocol == "TCP":
                self.tcp_count += 1
            elif protocol == "UDP":
                self.udp_count += 1
            elif protocol == "ICMP":
                self.icmp_count += 1
            else:
                self.other_count += 1

            self.packets.insert(0, packet)

            # Keep only the latest 100 packets in memory
            self.packets = self.packets[:100]

        self.log_packet(packet)

    def parse_packet(self, raw_data):
        if len(raw_data) < 34:
            return None

        # Ethernet header
        ethernet_header = raw_data[:14]

        eth_dest, eth_src, eth_protocol = struct.unpack(
            "!6s6sH",
            ethernet_header
        )

        # IPv4 only
        if eth_protocol != 0x0800:
            return None

        ip_header = raw_data[14:34]

        version_ihl = ip_header[0]

        version = version_ihl >> 4
        ihl = version_ihl & 0x0F

        if version != 4:
            return None

        ip_header_length = ihl * 4

        ttl = ip_header[8]
        protocol = ip_header[9]

        source_ip = socket.inet_ntoa(ip_header[12:16])
        destination_ip = socket.inet_ntoa(ip_header[16:20])

        protocol_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, f"OTHER ({protocol})")

        source_port = "-"
        destination_port = "-"
        payload_size = 0

        transport_start = 14 + ip_header_length

        # TCP
        if protocol == 6:

            if len(raw_data) >= transport_start + 20:

                tcp_header = raw_data[
                    transport_start:transport_start + 20
                ]

                source_port, destination_port = struct.unpack(
                    "!HH",
                    tcp_header[:4]
                )

                data_offset = (tcp_header[12] >> 4) * 4

                payload_start = transport_start + data_offset

                if len(raw_data) > payload_start:
                    payload_size = len(raw_data) - payload_start

        # UDP
        elif protocol == 17:

            if len(raw_data) >= transport_start + 8:

                udp_header = raw_data[
                    transport_start:transport_start + 8
                ]

                source_port, destination_port, udp_length, checksum = struct.unpack(
                    "!HHHH",
                    udp_header
                )

                payload_size = max(0, udp_length - 8)

        # ICMP
        elif protocol == 1:

            if len(raw_data) > transport_start:
                payload_size = len(raw_data) - transport_start

        packet = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "protocol": protocol_name,
            "source": source_ip,
            "destination": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "size": len(raw_data),
            "payload": payload_size,
            "ttl": ttl
        }

        return packet

    def capture_packets(self):

        try:

            # Raw IPv4 socket
            sniffer = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP
            )

            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

            # Bind socket to local machine
            sniffer.bind((local_ip, 0))

            # Include IP headers
            sniffer.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_HDRINCL,
                1
            )

            # Windows raw socket capture mode
            sniffer.ioctl(
                socket.SIO_RCVALL,
                socket.RCVALL_ON
            )

            print(f"[+] Listening on {local_ip}")

            while self.running:

                raw_data, address = sniffer.recvfrom(65535)

                packet = self.parse_packet(raw_data)

                if packet:
                    self.add_packet(packet)

            try:
                sniffer.ioctl(
                    socket.SIO_RCVALL,
                    socket.RCVALL_OFF
                )
            except Exception:
                pass

            sniffer.close()

        except PermissionError:

            print(
                "[!] Permission denied. "
                "Run the application as Administrator/root."
            )

            self.running = False

        except Exception as error:

            print(f"[!] Sniffer error: {error}")

            self.running = False

    def get_data(self):

        with self.lock:

            total = self.packet_count

            if total > 0:

                tcp_percentage = round(
                    self.tcp_count / total * 100, 2
                )

                udp_percentage = round(
                    self.udp_count / total * 100, 2
                )

                icmp_percentage = round(
                    self.icmp_count / total * 100, 2
                )

            else:

                tcp_percentage = 0
                udp_percentage = 0
                icmp_percentage = 0

            return {
                "running": self.running,
                "total": self.packet_count,
                "tcp": self.tcp_count,
                "udp": self.udp_count,
                "icmp": self.icmp_count,
                "other": self.other_count,
                "tcp_percentage": tcp_percentage,
                "udp_percentage": udp_percentage,
                "icmp_percentage": icmp_percentage,
                "packets": list(self.packets)
            }


sniffer = PacketSniffer()