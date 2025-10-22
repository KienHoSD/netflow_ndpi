    from scapy.packet import Packet
    from scapy.layers.inet import ICMP
    from scapy.layers.dns import DNS
    from ndpi import NDPI, NDPIFlow, ffi
    import re

    from . import constants
    from .features.context import PacketDirection, get_packet_flow_key
    from .features.flag_count import FlagCount
    from .features.flow_bytes import FlowBytes
    from .features.packet_count import PacketCount
    from .features.packet_length import PacketLength
    from .features.packet_time import PacketTime
    from .utils import get_statistics, get_logger


    class Flow:
        """This class summarizes the values of the features of the network flows"""

        def __init__(self, packet: Packet, direction: PacketDirection, attack: str):
            """This method initializes an object from the Flow class.

            Args:
                packet (Any): A packet from the network.
                direction (Enum): The direction the packet is going ove the wire.
            """

            (
                self.src_ip,
                self.dest_ip,
                self.src_port,
                self.dest_port,
            ) = get_packet_flow_key(packet, direction)

            # Initialize flow properties with the first packet
            self.packets = [(packet, direction)]  # Add the first packet
            self.flow_interarrival_time = []
            self.start_timestamp = packet.time
            self.latest_timestamp = packet.time  # Initialize latest_timestamp too
            self.protocol = packet.proto
            self.logger = get_logger(True)

            # Add NDPI protocol detection attribute
            self.nDPI = NDPI()
            # self.ndpi_flow = None
            self.ndpi_flow = NDPIFlow()
            self.detected_protocol = None

            # Initialize window sizes
            self.init_window_size = {PacketDirection.FORWARD: 0, PacketDirection.REVERSE: 0}
            try:
                if "TCP" in packet:
                    self.init_window_size[direction] = packet["TCP"].window
            except Exception:
                pass

            # Initialize active/idle tracking
            self.start_active = packet.time
            self.last_active = 0
            self.active = []
            self.idle = []

            self.forward_bulk_last_timestamp = 0
            self.forward_bulk_start_tmp = 0
            self.forward_bulk_count = 0
            self.forward_bulk_count_tmp = 0
            self.forward_bulk_duration = 0
            self.forward_bulk_packet_count = 0
            self.forward_bulk_size = 0
            self.forward_bulk_size_tmp = 0
            self.backward_bulk_last_timestamp = 0
            self.backward_bulk_start_tmp = 0
            self.backward_bulk_count = 0
            self.backward_bulk_count_tmp = 0
            self.backward_bulk_duration = 0
            self.backward_bulk_packet_count = 0
            self.backward_bulk_size = 0
            self.backward_bulk_size_tmp = 0

            # New attributes help resulting 43 features and more (set the default values here)
            self.ttls = []
            self.tcp_windows_in = []  # forward
            self.tcp_windows_out = []  # reverse
            self.packet_lengths = []
            self.tcp_seq_forward = set()
            self.tcp_seq_reverse = set()
            self.retransmitted_in_bytes = 0
            self.retransmitted_in_pkts = 0
            self.retransmitted_out_bytes = 0
            self.retransmitted_out_pkts = 0
            self.first_fwd_time = packet.time if direction == PacketDirection.FORWARD else None
            self.last_fwd_time = packet.time if direction == PacketDirection.FORWARD else None
            self.first_bwd_time = packet.time if direction == PacketDirection.REVERSE else None
            self.last_bwd_time = packet.time if direction == PacketDirection.REVERSE else None
            self.l7_proto = 0              # 0 = unknown/undetected protocol (nDPI standard)
            self.icmp_ipv4_type = -1       # -1 = not ICMP traffic (distinguishes from type 0)
            self.icmp_type = -1            # -1 = not ICMP traffic (distinguishes from type 0)
            self.set_icmp = False
            self.dns_query_id = -1         # -1 = not DNS traffic (distinguishes from ID 0)
            self.dns_query_type = -1       # -1 = not DNS traffic (distinguishes from type 0)
            self.set_dns_query = False
            self.dns_ttl_answer = -1       # -1 = no DNS answer/not DNS (distinguishes from TTL 0)
            self.set_dns_ttl = False
            self.ftp_command_ret_code = -1 # -1 = not FTP traffic (distinguishes from code 0)
            self.ftp_buffer = b""
            self.label = 0
            self.attack = "Benign"

            if attack != None:
                self.attack=attack
                self.label=1

            # Collect data from first packet
            self._collect_packet_data(packet, direction)

        def _collect_packet_data(self, packet: Packet, direction: PacketDirection):
            """Collect additional data from packet for new features."""
            pkt_len = len(packet)
            self.packet_lengths.append(pkt_len)

            if packet.haslayer("IP"):
                try:
                    self.ttls.append(packet["IP"].ttl)
                except Exception:
                    pass

            if packet.haslayer("TCP"):
                try:
                    tcp = packet["TCP"]
                    window = tcp.window
                    if direction == PacketDirection.FORWARD:
                        self.tcp_windows_in.append(window)
                        seq = tcp.seq
                        if seq in self.tcp_seq_forward:
                            self.retransmitted_in_pkts += 1
                            self.retransmitted_in_bytes += pkt_len
                        else:
                            self.tcp_seq_forward.add(seq)
                    else:
                        self.tcp_windows_out.append(window)
                        seq = tcp.seq
                        if seq in self.tcp_seq_reverse:
                            self.retransmitted_out_pkts += 1
                            self.retransmitted_out_bytes += pkt_len
                        else:
                            self.tcp_seq_reverse.add(seq)
                except Exception:
                    pass

            # Update direction times
            if direction == PacketDirection.FORWARD:
                if self.first_fwd_time is None:
                    self.first_fwd_time = packet.time
                self.last_fwd_time = packet.time
            else:
                if self.first_bwd_time is None:
                    self.first_bwd_time = packet.time
                self.last_bwd_time = packet.time

            # Try detect L7 protocol (0 = unknown)
            if self.l7_proto == 0:
                self._detect_l7_proto(packet)

            if packet.proto == 1:  # ICMP
                if packet.haslayer("ICMP") and self.set_icmp == False:
                    try:
                        icmp = packet["ICMP"]
                        # Get ICMP type and code safely
                        type_val = getattr(icmp, 'type', 0)
                        code_val = getattr(icmp, 'code', 0)
                        self.icmp_type = type_val * 256 + code_val
                        self.icmp_ipv4_type = type_val
                        self.logger.debug(f"ICMP Type: {self.icmp_type}, ICMP IPv4 Type: {self.icmp_ipv4_type}")
                        self.set_icmp = True  # Only set once per flow
                    except Exception:
                        # Fallback if ICMP parsing fails
                        self.icmp_type = 0
                        self.icmp_ipv4_type = 0
            elif packet.haslayer(DNS) and (self.set_dns_query == False or self.set_dns_ttl == False):
                try:
                    dns = packet["DNS"]
                    if dns.qd and self.set_dns_query == False:
                        self.dns_query_id = dns.id
                        if dns.qd:
                            self.dns_query_type = dns.qd[0].qtype
                        self.set_dns_query = True  # Only set once per flow
                    if dns.an and self.set_dns_ttl == False:
                        for rr in dns.an:
                            if rr.type == 1:  # A record
                                self.dns_ttl_answer = rr.ttl
                                break
                        self.set_dns_ttl = True  # Only set once per flow    
                except Exception:
                    pass
            elif packet.haslayer("TCP") and (packet["TCP"].dport == 21 or packet["TCP"].sport == 21):
                payload = bytes(packet["TCP"].payload)
                if payload:
                    # keep a buffer to handle cases where a line spans multiple packets
                    self.ftp_buffer += payload
                    lines = re.split(b"\r?\n", self.ftp_buffer)
                    self.ftp_buffer = lines[-1]  # Keep the last partial line in buffer
                    for line in lines[:-1]:  # Process complete lines
                        # line must start with 3 digits
                        if line[:3].isdigit():
                            # final reply if 4th char is space (not dash)
                            if len(line) >= 4 and line[3:4] == b" ":
                                try:
                                    self.ftp_command_ret_code = int(line[:3])
                                    break
                                except ValueError:
                                    continue

        def _packet_ip_bytes(self, packet: Packet):
            """Return Layer-3 (IP/IPv6) bytes for nDPI, or None if not IP."""
            try:
                if packet.haslayer("IP"):
                    return bytes(packet["IP"])  # IPv4 L3 bytes
                if packet.haslayer("IPv6"):
                    return bytes(packet["IPv6"])  # IPv6 L3 bytes
            except Exception:
                pass
            return None

        def _detect_l7_proto(self, packet: Packet):
            """Detect application layer protocol using nDPI (feed IP bytes, like ndpi_example)."""
            try:
                ip_bytes = self._packet_ip_bytes(packet)
                if ip_bytes is None:
                    # Not an IP packet; leave as unknown
                    return
                time_ms = int(packet.time * 1000)
                self.detected_protocol = self.nDPI.process_packet(self.ndpi_flow, ip_bytes, time_ms, ffi.NULL)
                # Use app_protocol (0 means unknown yet)
                self.l7_proto = getattr(self.detected_protocol, "app_protocol", 0) or 0
            except Exception:
                # Fallback if NDPI fails
                self.l7_proto = 0

        def count_packets_in_range(self, min_len: int, max_len: int) -> int:
            """Count packets with lengths in the given range."""
            return sum(1 for length in self.packet_lengths if min_len <= length < max_len)

        def get_tcp_flags(self) -> int:
            """Get combined TCP flags as bitmask."""
            flags = 0
            flag_count = FlagCount(self)
            if flag_count.count("FIN") > 0:
                flags |= 1
            if flag_count.count("SYN") > 0:
                flags |= 2
            if flag_count.count("RST") > 0:
                flags |= 4
            if flag_count.count("PSH") > 0:
                flags |= 8
            if flag_count.count("ACK") > 0:
                flags |= 16
            if flag_count.count("URG") > 0:
                flags |= 32
            if flag_count.count("ECE") > 0:
                flags |= 64
            return flags

        def get_client_tcp_flags(self) -> int:
            """TCP flags from client (forward)."""
            flags = 0
            flag_count = FlagCount(self)
            if flag_count.count("FIN", PacketDirection.FORWARD) > 0:
                flags |= 1
            if flag_count.count("SYN", PacketDirection.FORWARD) > 0:
                flags |= 2
            if flag_count.count("RST", PacketDirection.FORWARD) > 0:
                flags |= 4
            if flag_count.count("PSH", PacketDirection.FORWARD) > 0:
                flags |= 8
            if flag_count.count("ACK", PacketDirection.FORWARD) > 0:
                flags |= 16
            if flag_count.count("URG", PacketDirection.FORWARD) > 0:
                flags |= 32
            if flag_count.count("ECE", PacketDirection.FORWARD) > 0:
                flags |= 64
            return flags

        def get_server_tcp_flags(self) -> int:
            """TCP flags from server (reverse)."""
            flags = 0
            flag_count = FlagCount(self)
            if flag_count.count("FIN", PacketDirection.REVERSE) > 0:
                flags |= 1
            if flag_count.count("SYN", PacketDirection.REVERSE) > 0:
                flags |= 2
            if flag_count.count("RST", PacketDirection.REVERSE) > 0:
                flags |= 4
            if flag_count.count("PSH", PacketDirection.REVERSE) > 0:
                flags |= 8
            if flag_count.count("ACK", PacketDirection.REVERSE) > 0:
                flags |= 16
            if flag_count.count("URG", PacketDirection.REVERSE) > 0:
                flags |= 32
            if flag_count.count("ECE", PacketDirection.REVERSE) > 0:
                flags |= 64
            return flags

        def get_duration_in(self) -> float:
            """Duration of incoming packets."""
            if self.first_fwd_time is not None and self.last_fwd_time is not None:
                return self.last_fwd_time - self.first_fwd_time
            return 0.0

        def get_duration_out(self) -> float:
            """Duration of outgoing packets."""
            if self.first_bwd_time is not None and self.last_bwd_time is not None:
                return self.last_bwd_time - self.first_bwd_time
            return 0.0

        @property
        def min_ttl(self):
            return min(self.ttls) if self.ttls else 0

        @property
        def max_ttl(self):
            return max(self.ttls) if self.ttls else 0

        @property
        def max_tcp_win_in(self):
            return max(self.tcp_windows_in) if self.tcp_windows_in else 0

        @property
        def max_tcp_win_out(self):
            return max(self.tcp_windows_out) if self.tcp_windows_out else 0

        def get_data(self, include_fields=None) -> dict:
            """This method obtains the values of the features extracted from each flow.

            Note:
                Only some of the network data plays well together in this list.
                Time-to-live values, window values, and flags cause the data to
                separate out too much.

            Returns:
            list: returns a List of values to be outputted into a csv file.

            """

            flow_bytes = FlowBytes(self)
            flag_count = FlagCount(self)
            packet_count = PacketCount(self)
            packet_length = PacketLength(self)
            packet_time = PacketTime(self)
            flow_iat = get_statistics(self.flow_interarrival_time)
            forward_iat = get_statistics(
                packet_time.get_packet_iat(PacketDirection.FORWARD)
            )
            backward_iat = get_statistics(
                packet_time.get_packet_iat(PacketDirection.REVERSE)
            )
            active_stat = get_statistics(self.active)
            idle_stat = get_statistics(self.idle)

            # If protocol still unknown, let nDPI try a last-guess (like ndpi_example.giveup)
            try:
                if self.l7_proto == 0 and self.ndpi_flow is not None:
                    guessed = self.nDPI.giveup(self.ndpi_flow)
                    self.l7_proto = getattr(guessed, "app_protocol", self.l7_proto) or self.l7_proto
            except Exception:
                pass

            data = {
                "IPV4_SRC_ADDR": self.src_ip,
                "L4_SRC_PORT": self.src_port,
                "IPV4_DST_ADDR": self.dest_ip,
                "L4_DST_PORT": self.dest_port,
                "PROTOCOL": self.protocol,
                "L7_PROTO": self.l7_proto,
                "IN_BYTES": packet_length.get_total(PacketDirection.FORWARD),
                "IN_PKTS": packet_count.get_total(PacketDirection.FORWARD),
                "OUT_BYTES": packet_length.get_total(PacketDirection.REVERSE),
                "OUT_PKTS": packet_count.get_total(PacketDirection.REVERSE),
                "TCP_FLAGS": self.get_tcp_flags(),
                "CLIENT_TCP_FLAGS": self.get_client_tcp_flags(),
                "SERVER_TCP_FLAGS": self.get_server_tcp_flags(),
                "FLOW_DURATION_MILLISECONDS": round(packet_time.get_duration() * 1000),
                "DURATION_IN": round(self.get_duration_in()),
                "DURATION_OUT": round(self.get_duration_out()),
                "MIN_TTL": self.min_ttl,
                "MAX_TTL": self.max_ttl,
                "LONGEST_FLOW_PKT": packet_length.get_max(),
                "SHORTEST_FLOW_PKT": packet_length.get_min(),
                "MIN_IP_PKT_LEN": packet_length.get_min(),
                "MAX_IP_PKT_LEN": packet_length.get_max(),
                "SRC_TO_DST_SECOND_BYTES": round(packet_length.get_total(PacketDirection.FORWARD) / packet_time.get_duration()) if packet_time.get_duration() > 0 else 0,
                "DST_TO_SRC_SECOND_BYTES": round(packet_length.get_total(PacketDirection.REVERSE) / packet_time.get_duration()) if packet_time.get_duration() > 0 else 0,
                "RETRANSMITTED_IN_BYTES": self.retransmitted_in_bytes,
                "RETRANSMITTED_IN_PKTS": self.retransmitted_in_pkts,
                "RETRANSMITTED_OUT_BYTES": self.retransmitted_out_bytes,
                "RETRANSMITTED_OUT_PKTS": self.retransmitted_out_pkts,
                "SRC_TO_DST_AVG_THROUGHPUT": round(packet_length.get_total(PacketDirection.FORWARD) / packet_time.get_duration()) if packet_time.get_duration() > 0 else 0,
                "DST_TO_SRC_AVG_THROUGHPUT": round(packet_length.get_total(PacketDirection.REVERSE) / packet_time.get_duration()) if packet_time.get_duration() > 0 else 0,
                "NUM_PKTS_UP_TO_128_BYTES": self.count_packets_in_range(0, 128),
                "NUM_PKTS_128_TO_256_BYTES": self.count_packets_in_range(128, 256),
                "NUM_PKTS_256_TO_512_BYTES": self.count_packets_in_range(256, 512),
                "NUM_PKTS_512_TO_1024_BYTES": self.count_packets_in_range(512, 1024),
                "NUM_PKTS_1024_TO_1514_BYTES": self.count_packets_in_range(1024, 1514),
                "TCP_WIN_MAX_IN": self.max_tcp_win_in,
                "TCP_WIN_MAX_OUT": self.max_tcp_win_out,
                "ICMP_TYPE": self.icmp_type,
                "ICMP_IPV4_TYPE": self.icmp_ipv4_type,
                "DNS_QUERY_ID": self.dns_query_id,
                "DNS_QUERY_TYPE": self.dns_query_type,
                "DNS_TTL_ANSWER": self.dns_ttl_answer,
                "FTP_COMMAND_RET_CODE": self.ftp_command_ret_code,
                "FLOW_START_MILLISECONDS": round(self.start_timestamp * 1000),
                "FLOW_END_MILLISECONDS": round(self.latest_timestamp * 1000),
                "SRC_TO_DST_IAT_MIN": round(forward_iat["min"] * 1000) if forward_iat["min"] is not None else 0,
                "SRC_TO_DST_IAT_MAX": round(forward_iat["max"] * 1000) if forward_iat["max"] is not None else 0,
                "SRC_TO_DST_IAT_AVG": round(forward_iat["mean"] * 1000) if forward_iat["mean"] is not None else 0,
                "SRC_TO_DST_IAT_STDDEV": round(forward_iat["std"] * 1000) if forward_iat["std"] is not None else 0,
                "DST_TO_SRC_IAT_MIN": round(backward_iat["min"] * 1000) if backward_iat["min"] is not None else 0,
                "DST_TO_SRC_IAT_MAX": round(backward_iat["max"] * 1000) if backward_iat["max"] is not None else 0,
                "DST_TO_SRC_IAT_AVG": round(backward_iat["mean"] * 1000) if backward_iat["mean"] is not None else 0,
                "DST_TO_SRC_IAT_STDDEV": round(backward_iat["std"] * 1000) if backward_iat["std"] is not None else 0,
                "Label": self.label,
                "Attack": self.attack,
            }

            

            if include_fields is not None:
                data = {k: v for k, v in data.items() if k in include_fields}

            return data

        def add_packet(self, packet: Packet, direction: PacketDirection) -> None:
            """Adds a packet to the current list of packets.

            Args:
                packet: Packet to be added to a flow
                direction: The direction the packet is going in that flow

            """
            self.packets.append((packet, direction))

            # Calculate interarrival time using the previous latest_timestamp
            # This check prevents adding a 0 IAT for the very first packet added after init
            if len(self.packets) > 1:
                self.flow_interarrival_time.append(packet.time - self.latest_timestamp)

            # Update latest timestamp
            self.latest_timestamp = max(packet.time, self.latest_timestamp)

            # Update flow bulk and subflow stats
            self.update_flow_bulk(packet, direction)
            self.update_subflow(packet)

            # Update initial window size if not already set for this direction
            try:
                if "TCP" in packet and self.init_window_size[direction] == 0:
                    self.init_window_size[direction] = packet["TCP"].window
            except Exception:
                pass

            # Collect additional data
            self._collect_packet_data(packet, direction)

            # Note: start_timestamp and protocol are set in __init__

        def update_subflow(self, packet: Packet):
            """Update subflow

            Args:
                packet: Packet to be parse as subflow

            """
            last_timestamp = (
                self.latest_timestamp if self.latest_timestamp != 0 else packet.time
            )
            if (packet.time - last_timestamp) > constants.CLUMP_TIMEOUT:
                self.update_active_idle(packet.time - last_timestamp)

        def update_active_idle(self, current_time):
            """Adds a packet to the current list of packets.

            Args:
                packet: Packet to be update active time

            """
            if (current_time - self.last_active) > constants.ACTIVE_TIMEOUT:
                duration = abs(self.last_active - self.start_active)
                if duration > 0:
                    self.active.append(duration)
                self.idle.append(current_time - self.last_active)
                self.start_active = current_time
                self.last_active = current_time
            else:
                self.last_active = current_time

        def update_flow_bulk(self, packet: Packet, direction: PacketDirection):
            """Update bulk flow

            Args:
                packet: Packet to be parse as bulk

            """
            payload_size = len(PacketCount.get_payload(packet))
            if payload_size == 0:
                return
            if direction == PacketDirection.FORWARD:
                if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                    self.forward_bulk_start_tmp = 0
                if self.forward_bulk_start_tmp == 0:
                    self.forward_bulk_start_tmp = packet.time
                    self.forward_bulk_last_timestamp = packet.time
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size
                else:
                    if (
                        packet.time - self.forward_bulk_last_timestamp
                    ) > constants.CLUMP_TIMEOUT:
                        self.forward_bulk_start_tmp = packet.time
                        self.forward_bulk_last_timestamp = packet.time
                        self.forward_bulk_count_tmp = 1
                        self.forward_bulk_size_tmp = payload_size
                    else:  # Add to bulk
                        self.forward_bulk_count_tmp += 1
                        self.forward_bulk_size_tmp += payload_size
                        if self.forward_bulk_count_tmp == constants.BULK_BOUND:
                            self.forward_bulk_count += 1
                            self.forward_bulk_packet_count += self.forward_bulk_count_tmp
                            self.forward_bulk_size += self.forward_bulk_size_tmp
                            self.forward_bulk_duration += (
                                packet.time - self.forward_bulk_start_tmp
                            )
                        elif self.forward_bulk_count_tmp > constants.BULK_BOUND:
                            self.forward_bulk_packet_count += 1
                            self.forward_bulk_size += payload_size
                            self.forward_bulk_duration += (
                                packet.time - self.forward_bulk_last_timestamp
                            )
                        self.forward_bulk_last_timestamp = packet.time
            else:
                if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                    self.backward_bulk_start_tmp = 0
                if self.backward_bulk_start_tmp == 0:
                    self.backward_bulk_start_tmp = packet.time
                    self.backward_bulk_last_timestamp = packet.time
                    self.backward_bulk_count_tmp = 1
                    self.backward_bulk_size_tmp = payload_size
                else:
                    if (
                        packet.time - self.backward_bulk_last_timestamp
                    ) > constants.CLUMP_TIMEOUT:
                        self.backward_bulk_start_tmp = packet.time
                        self.backward_bulk_last_timestamp = packet.time
                        self.backward_bulk_count_tmp = 1
                        self.backward_bulk_size_tmp = payload_size
                    else:  # Add to bulk
                        self.backward_bulk_count_tmp += 1
                        self.backward_bulk_size_tmp += payload_size
                        if self.backward_bulk_count_tmp == constants.BULK_BOUND:
                            self.backward_bulk_count += 1
                            self.backward_bulk_packet_count += self.backward_bulk_count_tmp
                            self.backward_bulk_size += self.backward_bulk_size_tmp
                            self.backward_bulk_duration += (
                                packet.time - self.backward_bulk_start_tmp
                            )
                        elif self.backward_bulk_count_tmp > constants.BULK_BOUND:
                            self.backward_bulk_packet_count += 1
                            self.backward_bulk_size += payload_size
                            self.backward_bulk_duration += (
                                packet.time - self.backward_bulk_last_timestamp
                            )
                        self.backward_bulk_last_timestamp = packet.time

        @property
        def duration(self):
            return self.latest_timestamp - self.start_timestamp
