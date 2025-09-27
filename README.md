# Python NetFlow NDPI

This is a Python implementation of NetFlow (a fork of [cicflowmeter](https://github.com/hieulw/cicflowmeter)) with nDPI integration for enhanced protocol detection. It captures network traffic and extracts flow features, supporting both offline pcap files and real-time packet capture from network interfaces with imitation of nProbe tool by Ntop, extract 43 NetFlow version 9 features. For more details on the features, read [Towards a Standard Feature Set for Network Intrusion Detection System Datasets](https://arxiv.org/pdf/2101.11315).

### Installation

Need to build (and install) nDPI first:

```sh
git clone --branch dev https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
sudo make install # optional
cd .. # go back to parent directory
```

Then install this package:

```sh
git clone https://github.com/KienHoSD/netflow_ndpi.git
cd netflow_ndpi
uv sync
source .venv/bin/activate
```

The file structure should look like this:

```
nDPI/
├── build/
├── python/
└── ...
netflow_ndpi/
├── .venv/
├── src/
│   └── netflow/
│       ├── __init__.py
│       ├── features.py
│       ├── flow.py
│       ├── ndpi.py
│       ├── sniffer.py
│       └── utils.py
├── tests/
│   └── test_sniffer.py
├── README.md
└── ...
```

### Usage

```sh
usage: netflow [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) (-c | -u) [--fields FIELDS | --version VERSION] [--max-flows MAX_FLOWS] [--max-time MAX_TIME] [--label] [--attack ATTACK]
               [--filter BPF_FILTER] [-v]
               output

positional arguments:
  output                output file name (in csv mode) or url (in url mode)

options:
  -h, --help            show this help message and exit
  -i, --interface INPUT_INTERFACE
                        capture online data from INPUT_INTERFACE
  -f, --file INPUT_FILE
                        capture offline data from INPUT_FILE
  -c, --csv             output flows as csv
  -u, --url             output flows as request to url
  --fields FIELDS       comma separated fields to include in output (default: all)
  --version VERSION     which version of NetFlow features to include (support: 1,2,3) (default: 2)
  --max-flows MAX_FLOWS
                        maximum number of flows to capture before terminating (default: unlimited)
  --max-time MAX_TIME   maximum time in seconds to capture before terminating (default: unlimited)
  --label               add Label/Attack column to output (default: True)
  --attack ATTACK       indicate the type of attack of current flow capturing
  --filter BPF_FILTER   BPF (Berkeley Packet Filter) to apply (default: 'ip and (tcp or udp or icmp)')
  -v, --verbose         more verbose
```

Convert pcap file to flow csv:

```
netflow -f example.pcap -c flows.csv
```

Sniff packets real-time from interface to flow request: (**need root permission**)

```
netflow -i eth0 -u http://localhost:8080/predict
```

Sniff packets real-time from interface to flow csv with custom fields and max time:

```
netflow -i eth0 -c flows.csv --fields "Src IP, Dst IP, Protocol, Timestamp, Label" --max-time 60 --label
```

### References:

1. https://arxiv.org/abs/2011.09144
2. https://github.com/hieulw/cicflowmeter
3. https://github.com/ntop/nDPI
