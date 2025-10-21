# Python NetFlow NDPI

This is a Python implementation of NetFlow (a fork of [cicflowmeter](https://github.com/hieulw/cicflowmeter)) with nDPI integration for enhanced protocol detection. It captures network traffic and extracts flow features, supporting both offline pcap files and real-time packet capture from network interfaces with imitation of nProbe tool by Ntop, can help extract 3 different version of NetFlow (V1,V2,V3) and more. For more details on the NetFlow features [click here](https://staff.itee.uq.edu.au/marius/NIDS_datasets/).

### Installation

Need to install [denpendencies](https://github.com/ntop/nDPI?tab=readme-ov-file#how-to-compile-ndpi) and compile nDPI library first:

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
```

The file structure should look like this:

```
nDPI/
├── build/
├── python/
└── ...
netflow_ndpi/
├── .venv/
├── dist/
├── src/
├── .gitignore
├── LICENSE
├── Makefile
├── pyproject.toml
├── README.md
└── ...
```

### Usage

```sh
usage: netflow [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) (-c | -u) [--fields FIELDS | --version VERSION] [--max-flows MAX_FLOWS] [--max-time MAX_TIME] [--no-label | --attack ATTACK]
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
  --no-label            remove Label/Attack column from output (default: False)
  --attack ATTACK       indicate the type of attack of current flow capturing
  --filter BPF_FILTER   BPF (Berkeley Packet Filter) to apply (default: 'ip and (tcp or udp or icmp)')
  -v, --verbose         more verbose
```

Note: Need to run with sudo to use NDPI library and sniff packets from interface.

Convert pcap file to flow csv:

```
sudo .venv/bin/netflow -f example.pcap -c flows.csv
```

Sniff packets real-time from interface to flow request:

```
sudo .venv/bin/netflow -i eth0 -u http://localhost:8080/predict
```

Sniff packets real-time from interface to flow csv with custom fields without labels and max time:

```
sudo .venv/bin/netflow -i eth0 -c flows.csv --fields "IPV4_SRC_ADDR,L4_SRC_PORT,PROTOCOL,L7_PROTO" --max-time 60 --no-label
```

### Using PyPy for performance

PyPy can improve long-running captures thanks to JIT. See docs for setup and tips:

- docs/pypy.md

Quick start with uv and PyPy:

```sh
export UV_PYTHON=$(command -v pypy3)
uv sync
sudo .venv/bin/netflow -i eth0 -c flows.csv
```

### References:

1. https://staff.itee.uq.edu.au/marius/NIDS_datasets/
2. https://github.com/hieulw/cicflowmeter
3. https://github.com/ntop/nDPI
