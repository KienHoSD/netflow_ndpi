# Python CICFlowMeter NDPI

This is a Python implementation of CICFlowMeter with nDPI integration for enhanced protocol detection. It captures network traffic and extracts flow features, supporting both offline pcap files and real-time packet capture from network interfaces with imitation of nProbe tool by Ntop, extract 43 NetFlow version 9 features. For more details on the features, read [Towards a Standard Feature Set for Network Intrusion Detection System Datasets](https://arxiv.org/pdf/2101.11315).

### Installation

```sh
git clone https://github.com/KienHoSD/cicflowmeter_ndpi.git
git clone --branch dev https://github.com/ntop/nDPI.git nDPI
cd nDPI
./autogen.sh
./configure
make
sudo make install
cd ../cicflowmeter
uv sync
source .venv/bin/activate
```

### Usage

```sh
usage: cicflowmeter [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) (-c | -u) [--fields FIELDS] [-v] output

positional arguments:
  output                output file name (in csv mode) or url (in url mode)

options:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE, --interface INPUT_INTERFACE
                        capture online data from INPUT_INTERFACE
  -f INPUT_FILE, --file INPUT_FILE
                        capture offline data from INPUT_FILE
  -c, --csv             output flows as csv
  -u, --url             output flows as request to url
  --fields FIELDS       comma separated fields to include in output (default: all)
  -v, --verbose         more verbose
```

Convert pcap file to flow csv:

```
cicflowmeter -f example.pcap -c flows.csv
```

Sniff packets real-time from interface to flow request: (**need root permission**)

```
cicflowmeter -i eth0 -u http://localhost:8080/predict
```

### References:

1. https://www.unb.ca/cic/research/applications.html#CICFlowMeter
2. https://github.com/hieulw/cicflowmeter
3. https://github.com/ntop/nDPI
4. https://arxiv.org/abs/2101.11315
