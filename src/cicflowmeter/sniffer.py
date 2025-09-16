import argparse
import time

from scapy.sendrecv import AsyncSniffer

from cicflowmeter.flow_session import FlowSession
import threading

GC_INTERVAL = 1.0  # seconds (tune as needed)


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
    input_file, input_interface, output_mode, output, fields=None, verbose=False, max_flows=None, max_time=None
):
    assert (input_file is None) ^ (input_interface is None), (
        "Either provide interface input or file input not both"
    )
    if fields is not None:
        fields = fields.split(",")

    # Pass config to FlowSession constructor
    session = FlowSession(
        output_mode=output_mode,
        output=output,
        fields=fields,
        verbose=verbose,
    )

    _start_periodic_gc(session, interval=GC_INTERVAL)

    if input_file:
        sniffer = AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
    else:
        sniffer = AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
    return sniffer, session


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
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

    parser.add_argument(
        "output",
        help="output file name (in csv mode) or url (in url mode)",
    )

    parser.add_argument(
        "--fields",
        action="store",
        dest="fields",
        help="comma separated fields to include in output (default: all)",
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

    parser.add_argument("-v", "--verbose", action="store_true", help="more verbose")

    args = parser.parse_args()

    sniffer, session = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.fields,
        args.verbose,
        args.max_flows,
        args.max_time,
    )
    
    # Start the sniffer
    sniffer.start()
    
    start_time = time.time()
    stop_reason = None
    
    try:
        while sniffer.running:
            time.sleep(0.1)  # Check every 100ms
            
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
    finally:
        if stop_reason:
            print(f"Stopping sniffer: {stop_reason}")
        sniffer.stop()
        
        # Stop periodic GC if present
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        sniffer.join()
        # Flush all flows at the end
        session.flush_flows()


if __name__ == "__main__":
    main()
