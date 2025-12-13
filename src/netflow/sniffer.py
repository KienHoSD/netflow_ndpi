import argparse
import time

from scapy.sendrecv import AsyncSniffer

from netflow.flow_session import FlowSession
from netflow.constants import GC_INTERVAL, CHECK_INTERVAL
import threading


def _start_periodic_gc(session, interval=GC_INTERVAL):
    stop_event = threading.Event()

    def _gc_loop():
        while not stop_event.wait(interval):
            try:
                session.garbage_collect(time.time())
            except Exception:
                # Don't let GC threading failures kill the process
                session.logger.exception("Periodic GC error")

    t = threading.Thread(target=_gc_loop, name="flow-gc", daemon=True)
    t.start()
    # attach to session so we can stop it later
    session._gc_thread = t
    session._gc_stop = stop_event


def create_sniffer(
    input_file, input_interface, output_mode, output, fields=None, version=None, verbose=False, max_flows=None, max_time=None, label=None, attack=None, bpf_filter=None, web_listen=None
):
    if fields is not None:
        fields = fields.split(",")

    netflow_version_one_fields = ["IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL",
                                  "TCP_FLAGS", "L7_PROTO", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS"]
    netflow_version_two_fields = netflow_version_one_fields + ["CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "DURATION_IN", "DURATION_OUT",
                                                               "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
                                                               "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES",
                                                               "DST_TO_SRC_SECOND_BYTES", "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
                                                               "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
                                                               "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
                                                               "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
                                                               "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
                                                               "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
                                                               "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
                                                               "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE"]
    netflow_version_three_fields = netflow_version_two_fields + ["FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
                                                                 "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX",
                                                                 "SRC_TO_DST_IAT_AVG", "SRC_TO_DST_IAT_STDDEV",
                                                                 "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX",
                                                                 "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV"]

    if version is not None and fields is None:
        if version == '1':
            fields = netflow_version_one_fields
        elif version == '2':
            fields = netflow_version_two_fields
        elif version == '3':
            fields = netflow_version_three_fields
        else:
            raise ValueError("Unsupported NetFlow version. Supported versions are 1, 2, and 3.")

    # Default to version 2 if neither version nor fields are specified
    if version is None and fields is None:
        version = '2'
        fields = netflow_version_two_fields

    if label is True:
        fields.extend(["Label", "Attack"])
    else:
        if "Label" in fields:
            fields.remove("Label")
        if "Attack" in fields:
            fields.remove("Attack")

    # Pass config to FlowSession constructor
    session = FlowSession(
        output_mode=output_mode,
        output=output,
        fields=fields,
        verbose=verbose,
        attack=attack
    )

    _start_periodic_gc(session, interval=GC_INTERVAL)

    if input_file:
        sniffer = AsyncSniffer(
            offline=input_file,
            filter=bpf_filter,
            prn=session.process,
            store=False,
            promisc=False  # Disable promiscuous mode for better stability
        )
    else:
        sniffer = AsyncSniffer(
            iface=input_interface,
            filter=bpf_filter,
            prn=session.process,
            store=False,
            promisc=False  # Disable promiscuous mode for better stability
        )
    return sniffer, session


def main():
    parser = argparse.ArgumentParser()

    # Only require one of -i / -f when not using web GUI
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )
    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        "-c",
        "--csv",
        action="store_const",
        const="csv",
        dest="output_mode",
        help="output flows as csv",
    )
    output_group.add_argument(
        "-u",
        "--url",
        action="store_const",
        const="url",
        dest="output_mode",
        help="output flows as request to url",
    )
    output_group.add_argument(
        "-w",
        "--web",
        action="store_const",
        const="web_gui",
        dest="output_mode",
        help="start web-based GUI for real-time visualization and intrusion detection",
    )

    parser.add_argument(
        "output",
        help="output file name (in csv mode) or url (in url mode), optional for web GUI",
        nargs="?",
        default=None
    )

    # Web GUI specific options
    parser.add_argument(
        "--host",
        action="store",
        dest="web_host",
        default="127.0.0.1",
        help="web GUI host address (default: 127.0.0.1, use 0.0.0.0 for all interfaces)",
    )
    
    parser.add_argument(
        "--port",
        action="store",
        type=int,
        dest="web_port",
        default=5000,
        help="web GUI port (default: 5000)",
    )

    include_fields = parser.add_mutually_exclusive_group(required=False)
    include_fields.add_argument(
        "--fields",
        action="store",
        dest="fields",
        help="comma separated fields to include in output (default: all)",
    )
    include_fields.add_argument(
        "--version",
        action="store",
        dest="version",
        help="which version of NetFlow features to include (support: 1,2,3) (default: 2)",
    )

    parser.add_argument(
        "--max-flows",
        action="store",
        type=int,
        dest="max_flows",
        help="maximum number of flows to capture before terminating (default: unlimited)",
    )

    parser.add_argument(
        "--max-time",
        action="store",
        type=int,
        dest="max_time",
        help="maximum time in seconds to capture before terminating (default: unlimited)",
    )

    label_related = parser.add_mutually_exclusive_group(required=False)
    label_related.add_argument(
        "--no-label",
        action="store_false",
        dest="label",
        help="remove Label/Attack column from output (default: False)",
        default=True
    )
    label_related.add_argument(
        "--attack",
        action="store",
        type=str,
        dest="attack",
        help="indicate the type of attack of current flow capturing"
    )

    parser.add_argument(
        "--filter",
        action="store",
        dest="bpf_filter",
        help="BPF (Berkeley Packet Filter) to apply (default: 'ip and (tcp or udp or icmp)')",
        default="ip and (tcp or udp or icmp)"
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="more verbose")

    args = parser.parse_args()

    if args.output_mode == "web_gui":
        try:
            from netflow.web_gui import app, socketio, set_capture_interface, set_filter, set_output_file
            
            # Set the interface if provided
            if args.input_interface:
                set_capture_interface(args.input_interface)
            else:
                set_capture_interface(None)  # Capture from all interfaces
            set_filter(args.bpf_filter)
            
            host = args.web_host
            port = args.web_port
            print("=" * 60)
            print(f"Starting NetFlow Web GUI")
            print("=" * 60)
            if args.input_interface:
                print(f"Interface    : {args.input_interface}")
            else:
                print(f"Interface    : All interfaces")
            print(f"BPF Filter   : {args.bpf_filter}")
            print(f"Web Address  : http://{host}:{port}")
            if args.output:
                set_output_file(args.output)
            else:
                set_output_file(None)
            print("=" * 60)
            print(f"\nOpen http://{host}:{port} in your browser to view the dashboard")
            print("Press Ctrl+C to stop\n")
            socketio.run(app, host=host, port=port, debug=args.verbose)
            return
        except ImportError as e:
            print(f"Error: Web GUI dependencies not installed. Please install them first.")
            print(f"Run: pip install flask flask-socketio pandas torch dgl networkx category-encoders scikit-learn catboost plotly")
            print(f"Error details: {e}")
            return
        except Exception as e:
            print(f"Error starting Web GUI: {e}")
            return

    sniffer, session = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.fields,
        args.version,
        args.verbose,
        args.max_flows,
        args.max_time,
        args.label,
        args.attack,
        args.bpf_filter
    )

    # Start the sniffer
    try:
        sniffer.start()
    except Exception as e:
        print(f"Error starting sniffer: {e}")
        return

    # Check if sniffer started successfully
    if not hasattr(sniffer, 'running') or not sniffer.running:
        print("Sniffer failed to start properly")
        return

    start_time = time.time()
    stop_reason = None

    try:
        while sniffer.running:
            time.sleep(CHECK_INTERVAL)  # Sleep briefly to avoid busy waiting

            # Check max flows condition
            if args.max_flows and session.flow_count >= args.max_flows:
                stop_reason = f"Reached maximum flow count: {args.max_flows}"
                break

            # Check max time condition
            if args.max_time and (time.time() - start_time) >= args.max_time:
                stop_reason = f"Reached maximum time: {args.max_time} seconds"
                break

    except KeyboardInterrupt:
        stop_reason = "Interrupted by user"
    except Exception as e:
        stop_reason = f"Error during sniffing: {e}"
        print(f"Sniffing error: {e}")
    finally:
        if stop_reason:
            print(f"Stopping sniffer: {stop_reason}")

        # Safely stop the sniffer if it's still running
        try:
            if hasattr(sniffer, 'running') and sniffer.running:
                sniffer.stop()
        except Exception as e:
            print(f"Warning: Error stopping sniffer: {e}")

        # Stop periodic GC if present
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)

        # Join the sniffer thread safely
        try:
            if hasattr(sniffer, 'join'):
                sniffer.join(timeout=2.0)
        except Exception as e:
            print(f"Warning: Error joining sniffer thread: {e}")

        # Flush all flows at the end
        try:
            session.flush_flows()
        except Exception as e:
            print(f"Warning: Error flushing flows: {e}")


if __name__ == "__main__":
    main()
