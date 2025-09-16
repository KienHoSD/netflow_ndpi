from scapy.packet import Packet
from scapy.layers.inet import ICMP
from ndpi import NDPI, NDPIFlow, ffi

from . import constants
from .features.context import PacketDirection, get_packet_flow_key
from .features.flag_count import FlagCount
from .features.flow_bytes import FlowBytes
from .features.packet_count import PacketCount
from .features.packet_length import PacketLength
from .features.packet_time import PacketTime
from .utils import get_statistics


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Packet, direction: PacketDirection):
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

        # Add NDPI protocol detection attribute
        self.nDPI = NDPI()
        self.ndpi_flow = None
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

        # New attributes for UNSW-NB15 features
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
        self.l7_proto = 0
        self.icmp_ipv4_type = 0
        self.icmp_type = 0
        self.dns_query_id = 0
        self.dns_query_type = 0
        self.dns_ttl_answer = 0
        self.ftp_command_ret_code = 0

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

        # Detect L7 protocol
        if self.l7_proto is None:
            self._detect_l7_proto(packet)

        if packet.proto == 1:  # ICMP
            if packet.haslayer("ICMP"):
                icmp_types = ICMP.types
                name_to_value = {name: value for name, value in icmp_types.items()}
                type_val = name_to_value.get(str(packet["ICMP"].type).lower(), 0)
                code_val = int(packet["ICMP"].code) if hasattr(packet["ICMP"], 'code') else 0
                self.icmp_type = type_val * 256 + code_val
                self.icmp_ipv4_type = type_val
        elif packet.haslayer("DNS"):
            try:
                dns = packet["DNS"]
                if dns.qd:
                    self.dns_query_id = dns.id
                    if dns.qd:
                        self.dns_query_type = dns.qd[0].qtype
                if dns.an:
                    for rr in dns.an:
                        if rr.type == 1:  # A record
                            self.dns_ttl_answer = rr.ttl
                            break
            except Exception:
                pass
        elif packet.haslayer("TCP") and (packet["TCP"].dport == 21 or packet["TCP"].sport == 21):
            try:
                payload = bytes(packet["TCP"].payload)
                if payload:
                    lines = payload.split(b'\r\n')
                    for line in lines:
                        if line and line[0:3].isdigit():
                            try:
                                self.ftp_command_ret_code = int(line[0:3])
                                break
                            except:
                                pass
            except Exception:
                pass

    def _detect_l7_proto(self, packet: Packet):
        """Detect application layer protocol based on ports."""
        self.ndpi_flow = NDPIFlow()
        self.detected_protocol = self.nDPI.process_packet(self.ndpi_flow, bytes(packet), int(packet.time * 1000), ffi.NULL)
        self.l7_proto = self.detected_protocol.app_protocol

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
            "Label": "",
            "Attack": "",
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
