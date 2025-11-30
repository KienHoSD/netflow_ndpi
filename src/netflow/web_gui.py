from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request
from random import random
from time import sleep
from threading import Thread, Event

from scapy.sendrecv import sniff
from scapy.packet import Packet

from .flow import Flow
from .features.context import PacketDirection, get_packet_flow_key

import numpy as np
import pickle
import csv
import traceback

import json
import pandas as pd

import ipaddress
from urllib.request import urlopen

import torch
import torch.nn as nn
import torch.nn.functional as F
import dgl
import dgl.function as fn
import networkx as nx
import category_encoders as ce
from sklearn.preprocessing import Normalizer
from catboost import CatBoostClassifier

import plotly
import plotly.graph_objs

from ndpi import NDPI

import warnings
import time
warnings.filterwarnings("ignore")


def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        # response from url(if res==None then check connection)
        data = json.load(res)
        # will load the json response into data
        return data['country']
    except Exception:
        return None


# Initialize nDPI for protocol detection and naming
ndpi_detector = NDPI()


def get_app_name_from_flow(flow_obj):
    """Get application name from Flow object using nDPI
    
    Args:
        flow_obj: Flow object that contains detected_protocol from nDPI
        
    Returns:
        str: Application protocol name (e.g., 'HTTP', 'DNS', 'TLS')
    """
    try:
        if flow_obj and hasattr(flow_obj, 'detected_protocol') and flow_obj.detected_protocol:
            # Use nDPI's protocol_name method to get the protocol name
            # This follows the ndpi_example.py pattern
            proto_name = ndpi_detector.protocol_name(flow_obj.detected_protocol)
            return proto_name if proto_name else "Unknown"
        return "Unknown"
    except Exception as e:
        print(f"Error getting app name: {e}")
        return "Unknown"

# ========== Graph Neural Network Models ==========
class SAGELayer(nn.Module):
    def __init__(self, ndim_in, edims, ndim_out, activation):
        super(SAGELayer, self).__init__()
        self.W_apply = nn.Linear(ndim_in + edims, ndim_out)
        self.activation = F.relu
        self.W_edge = nn.Linear(128 * 2, 256)
        self.reset_parameters()

    def reset_parameters(self):
        gain = nn.init.calculate_gain('relu')
        nn.init.xavier_uniform_(self.W_apply.weight, gain=gain)

    def message_func(self, edges):
        return {'m': edges.data['h']}

    def forward(self, g_dgl, nfeats, efeats):
        with g_dgl.local_scope():
            g = g_dgl
            g.ndata['h'] = nfeats
            g.edata['h'] = efeats
            g.update_all(self.message_func, fn.mean('m', 'h_neigh'))
            g.ndata['h'] = F.relu(self.W_apply(torch.cat([g.ndata['h'], g.ndata['h_neigh']], 2)))

            # Compute edge embeddings
            u, v = g.edges()
            edge = self.W_edge(torch.cat((g.srcdata['h'][u], g.dstdata['h'][v]), 2))
            return g.ndata['h'], edge


class SAGE(nn.Module):
    def __init__(self, ndim_in, ndim_out, edim, activation):
        super(SAGE, self).__init__()
        self.layers = nn.ModuleList()
        self.layers.append(SAGELayer(ndim_in, edim, 128, F.relu))

    def forward(self, g, nfeats, efeats, corrupt=False):
        if corrupt:
            e_perm = torch.randperm(g.number_of_edges())
            efeats = efeats[e_perm]
        for i, layer in enumerate(self.layers):
            nfeats, e_feats = layer(g, nfeats, efeats)
        return nfeats.sum(1), e_feats.sum(1)


class Discriminator(nn.Module):
    def __init__(self, n_hidden):
        super(Discriminator, self).__init__()
        self.weight = nn.Parameter(torch.Tensor(n_hidden, n_hidden))
        self.reset_parameters()

    def uniform(self, size, tensor):
        bound = 1.0 / (size ** 0.5)
        if tensor is not None:
            tensor.data.uniform_(-bound, bound)

    def reset_parameters(self):
        size = self.weight.size(0)
        self.uniform(size, self.weight)

    def forward(self, features, summary):
        features = torch.matmul(features, torch.matmul(self.weight, summary))
        return features


class DGI(nn.Module):
    def __init__(self, ndim_in, ndim_out, edim, activation):
        super(DGI, self).__init__()
        self.encoder = SAGE(ndim_in, ndim_out, edim, F.relu)
        self.discriminator = Discriminator(256)
        self.loss = nn.BCEWithLogitsLoss()

    def forward(self, g, n_features, e_features):
        positive = self.encoder(g, n_features, e_features, corrupt=False)
        negative = self.encoder(g, n_features, e_features, corrupt=True)

        positive = positive[1]
        negative = negative[1]

        summary = torch.sigmoid(positive.mean(dim=0))

        positive = self.discriminator(positive, summary)
        negative = self.discriminator(negative, summary)

        l1 = self.loss(positive, torch.ones_like(positive))
        l2 = self.loss(negative, torch.zeros_like(negative))

        return l1 + l2


__author__ = 'hoang'


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

# turn the flask app into a socketio app
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

# random result Generator Thread
thread = Thread()
gc_thread = Thread()
thread_stop_event = Event()

# Configuration for packet capture
capture_interface = None  # None means capture from all interfaces

f = open("output_logs.csv", 'w')
w = csv.writer(f)
f2 = open("input_logs.csv", 'w')
w2 = csv.writer(f2)


# NetFlow feature columns based on your training data
netflow_features = [
    "PROTOCOL", "L7_PROTO", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES", "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS", "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT", "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID",
    "DNS_QUERY_TYPE", "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE"
]

cols = ['FlowID'] + netflow_features + [
    'IPV4_SRC_ADDR', 'L4_SRC_PORT', 'IPV4_DST_ADDR', 'L4_DST_PORT',
    'FLOW_START_MILLISECONDS', 'FLOW_END_MILLISECONDS',
    'Classification', 'Probability', 'Risk'
]

flow_count = 0
flow_df = pd.DataFrame(columns=cols)
MAX_FLOW_HISTORY = 1000  # Keep only recent flows to limit memory

src_ip_dict = {}
current_flows = {}
FlowTimeout = 600
MAX_ACTIVE_FLOWS = 200  # Limit concurrent flows

# Categorical columns that need encoding
categorical_cols = ['TCP_FLAGS', 'L7_PROTO', 'PROTOCOL', 'CLIENT_TCP_FLAGS',
                    'SERVER_TCP_FLAGS', 'ICMP_TYPE', 'ICMP_IPV4_TYPE',
                    'DNS_QUERY_ID', 'DNS_QUERY_TYPE', 'FTP_COMMAND_RET_CODE']

# Columns to normalize (all except categorical)
cols_to_norm = [col for col in netflow_features if col not in categorical_cols]

# Load models
print("Loading models...")
try:
    # Select device (Use CPU for simplicity)
    device = 'cpu'
    print(f"Using device: {device}")

    # Load DGI model
    ndim_in = 39  # number of features after encoding (without IPs, Ports)
    edim = len(netflow_features)
    dgi_model = DGI(ndim_in=ndim_in, ndim_out=128, edim=edim, activation=F.relu)
    dgi_model.load_state_dict(torch.load('src/netflow/models/best_dgi_CSE_real_traffic.pkl', map_location=device))
    dgi_model.to(device)
    dgi_model.eval()

    # Load CatBoost classifier
    catboost_model = CatBoostClassifier()
    catboost_model.load_model('src/netflow/models/best_catboost_classifier_unsw_fuse.cbm')

    # Initialize encoder and scaler (will be fitted on first batch)
    encoder = ce.TargetEncoder(cols=categorical_cols)
    scaler = Normalizer()
    models_loaded = True

except Exception as e:
    print(f"Error loading models: {e}")
    traceback.print_exc()
    models_loaded = False

# Store flows for batch processing
flow_buffer = []
flow_objects_buffer = []  # Store Flow objects to access nDPI data
BATCH_SIZE = 5  # Process flows in batches to create graphs


def extract_flow_features(flow_data):
    """Extract NetFlow features from Flow object data"""
    features = {}
    for feat in netflow_features:
        features[feat] = flow_data.get(feat, 0)

    # Add IP addresses for graph construction
    features['IPV4_SRC_ADDR'] = str(flow_data.get('IPV4_SRC_ADDR', '0.0.0.0'))
    features['IPV4_DST_ADDR'] = str(flow_data.get('IPV4_DST_ADDR', '0.0.0.0'))
    features['L4_SRC_PORT'] = str(flow_data.get('L4_SRC_PORT', 0))
    features['L4_DST_PORT'] = str(flow_data.get('L4_DST_PORT', 0))
    features['FLOW_START_MILLISECONDS'] = flow_data.get('FLOW_START_MILLISECONDS', 0)
    features['FLOW_END_MILLISECONDS'] = flow_data.get('FLOW_END_MILLISECONDS', 0)

    return features


def process_flow_batch(flows_data):
    """Process a batch of flows using DGI + CatBoost"""

    if not models_loaded or len(flows_data) == 0:
        return []

    try:
        # Create DataFrame from flows
        df = pd.DataFrame(flows_data)

        # Handle inf values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Encode categorical features - convert to numeric codes
        X = df[netflow_features].copy()

        for col in categorical_cols:
            if col in X.columns:
                # Convert to categorical codes (numeric)
                X[col] = pd.Categorical(X[col].astype(str)).codes

        # Ensure all columns are numeric
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

        # Normalize numerical features
        X[cols_to_norm] = scaler.fit_transform(X[cols_to_norm])

        # Create feature vector for each edge - now all numeric
        X['h'] = X.values.tolist()

        # Build graph from flows
        temp_df = pd.concat([X[['h']], df[['IPV4_SRC_ADDR', 'IPV4_DST_ADDR']]], axis=1)

        g = nx.from_pandas_edgelist(
            temp_df,
            "IPV4_SRC_ADDR",
            "IPV4_DST_ADDR",
            ["h"],
            create_using=nx.MultiGraph()
        )
        g = g.to_directed()

        # Convert to DGL
        g_dgl = dgl.from_networkx(g, edge_attrs=['h'])

        # Initialize node features on the correct device
        nfeat_weight = torch.ones([g_dgl.number_of_nodes(), len(netflow_features)], device=device)
        g_dgl.ndata['h'] = torch.reshape(nfeat_weight, (nfeat_weight.shape[0], 1, nfeat_weight.shape[1]))

        # Reshape edge features and ensure they are on the device
        g_dgl.edata['h'] = torch.reshape(g_dgl.edata['h'],
                                         (g_dgl.edata['h'].shape[0], 1,
                                          g_dgl.edata['h'].shape[1])).to(device)

        # Move graph data to device (DGL will keep graph structure and move tensors)
        g_dgl = g_dgl.to(device)

        # Get embeddings from DGI
        with torch.no_grad():
            embeddings = dgi_model.encoder(g_dgl, g_dgl.ndata['h'], g_dgl.edata['h'])[1]
            embeddings = embeddings.detach().cpu().numpy()
        
        # Memory cleanup: delete graph objects after use
        del g_dgl, g, temp_df, nfeat_weight

        # Multimodal (Fusion) Learning: Combine embeddings with raw features
        # This matches the training approach in the notebook
        df_emb = pd.DataFrame(embeddings)
        df_raw = X.copy().drop(columns=['h'])
        df_fuse = pd.concat([df_emb.reset_index(drop=True), df_raw.reset_index(drop=True)], axis=1)
        
        # Memory cleanup
        del df_emb, embeddings

        # Predict using CatBoost on fused features
        predictions = catboost_model.predict(df_fuse)
        probabilities = catboost_model.predict_proba(df_fuse)

        results = []
        for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
            max_proba = float(proba.max())

            # Calculate risk based on probability
            if pred != 0:  # Not benign
                risk_score = float(proba[int(pred)] if int(pred) < len(proba) else max_proba)
            else:
                risk_score = float(1 - proba[0])  # Risk is inverse of benign probability

            if risk_score > 0.8:
                risk = "<p style=\"color:red;\">Very High</p>"
            elif risk_score > 0.6:
                risk = "<p style=\"color:orangered;\">High</p>"
            elif risk_score > 0.4:
                risk = "<p style=\"color:orange;\">Medium</p>"
            elif risk_score > 0.2:
                risk = "<p style=\"color:green;\">Low</p>"
            else:
                risk = "<p style=\"color:limegreen;\">Minimal</p>"

            attack_types = ['Benign', 'Brute Force -Web', 'Brute Force -XSS',
                            'DoS attacks-GoldenEye', 'DoS attacks-Hulk',
                            'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris',
                            'FTP-BruteForce', 'Infilteration', 'SQL Injection',
                            'SSH-Bruteforce']
            classification = attack_types[int(pred)] if int(pred) < len(attack_types) else 'Unknown'

            results.append({
                'classification': classification,
                'probability': max_proba,
                'risk': risk
            })

        return results

    except Exception as e:
        traceback.print_exc()
        return []


def classify(flow_data, flow_obj=None):
    """Classify a single flow
    
    Args:
        flow_data: Dictionary of flow features
        flow_obj: Optional Flow object for accessing nDPI detected protocol
    """
    global flow_count, flow_buffer, flow_objects_buffer, flow_df

    # Extract features
    features = extract_flow_features(flow_data)

    # Increment flow counter
    flow_count += 1

    # Format IP addresses with country flags
    feature_string = []
    for i, ip_key in enumerate(['IPV4_SRC_ADDR', 'IPV4_DST_ADDR']):
        ip = features[ip_key]
        try:
            if not ipaddress.ip_address(ip).is_private:
                country = ipInfo(ip)
                if country is not None and country not in ['ano', 'unknown']:
                    img = f' <img src="static/images/blank.gif" class="flag flag-{country.lower()}" title="{country}">'
                else:
                    img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
            else:
                img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
            feature_string.append(ip + img)
        except:
            feature_string.append(ip)

    # Add ports
    feature_string.append(str(features['L4_SRC_PORT']))
    feature_string.append(str(features['L4_DST_PORT']))

    # Track source IP
    src_ip = features['IPV4_SRC_ADDR']
    if src_ip in src_ip_dict:
        src_ip_dict[src_ip] += 1
    else:
        src_ip_dict[src_ip] = 1

    # Add to buffer for batch processing
    flow_buffer.append(features)
    flow_objects_buffer.append(flow_obj)  # Store Flow object for nDPI data

    # Process batch if buffer is full
    if len(flow_buffer) >= BATCH_SIZE:
        print(f"[DEBUG] Buffer full! Processing batch of {len(flow_buffer)} flows...")
        results = process_flow_batch(flow_buffer)

        if results and len(results) > 0:
            print(f"[DEBUG] Got {len(results)} results for {len(flow_buffer)} flows")
            # Results might have more entries than flows due to directed graph edges
            # Take only the first N results matching buffer size
            num_flows = min(len(results), len(flow_buffer))

            # Emit model-based results
            for idx in range(num_flows):
                current_flow_id = flow_count - len(flow_buffer) + idx + 1
                flow_features = flow_buffer[idx]
                flow_object = flow_objects_buffer[idx] if idx < len(flow_objects_buffer) else None
                result = results[idx]

                classification = result['classification']
                proba_score = result['probability']
                risk = result['risk']

                # Create record
                record = [current_flow_id] + [flow_features.get(f, 0) for f in netflow_features] + [
                    flow_features['IPV4_SRC_ADDR'],
                    flow_features['L4_SRC_PORT'],
                    flow_features['IPV4_DST_ADDR'],
                    flow_features['L4_DST_PORT'],
                    flow_features['FLOW_START_MILLISECONDS'],
                    flow_features['FLOW_END_MILLISECONDS'],
                    classification,
                    proba_score,
                    risk
                ]

                flow_df.loc[len(flow_df)] = record
                
                # Memory optimization: Keep only recent flows
                if len(flow_df) > MAX_FLOW_HISTORY:
                    flow_df = flow_df.iloc[-MAX_FLOW_HISTORY:].reset_index(drop=True)

                # Log
                w.writerow([f'Flow #{current_flow_id}'])
                w.writerow(['Classification:'] + [classification] + [proba_score])
                w.writerow(
                    ['--------------------------------------------------------------------------------------------------'])

                # Emit to frontend
                ip_data = {'SourceIP': list(src_ip_dict.keys()), 'count': list(src_ip_dict.values())}
                ip_data_json = pd.DataFrame(ip_data).to_json(orient='records')

                # Format display data to match table columns:
                # Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Flow start time, Flow last seen, App name, PID, Prediction, Prob, Risk
                disp_src = str(flow_features.get('IPV4_SRC_ADDR', '0.0.0.0'))
                disp_dst = str(flow_features.get('IPV4_DST_ADDR', '0.0.0.0'))
                disp_sport = str(flow_features.get('L4_SRC_PORT', '0'))
                disp_dport = str(flow_features.get('L4_DST_PORT', '0'))
                protocol = flow_features.get('PROTOCOL', 0)
                flow_start = flow_features.get('FLOW_START_MILLISECONDS', 0)
                flow_end = flow_features.get('FLOW_END_MILLISECONDS', 0)
                # Get app name from nDPI using Flow object
                app_name = get_app_name_from_flow(flow_object) if flow_object else "Unknown"
                pid = 'N/A'

                display_data = [current_flow_id, disp_src, disp_sport, disp_dst, disp_dport,
                                protocol, flow_start, flow_end, app_name, pid, classification, proba_score, risk]
                socketio.emit('newresult', {'result': display_data,
                              "ips": json.loads(ip_data_json)}, namespace='/test')
        else:
            # Fallback: emit placeholder rows so UI is not empty
            for idx, flow_features in enumerate(flow_buffer):
                current_flow_id = flow_count - len(flow_buffer) + idx + 1
                flow_object = flow_objects_buffer[idx] if idx < len(flow_objects_buffer) else None
                classification = 'Pending'
                proba_score = 0.0
                risk = 'Processing'

                record = [current_flow_id] + [flow_features.get(f, 0) for f in netflow_features] + [
                    flow_features.get('IPV4_SRC_ADDR', '0.0.0.0'),
                    flow_features.get('L4_SRC_PORT', '0'),
                    flow_features.get('IPV4_DST_ADDR', '0.0.0.0'),
                    flow_features.get('L4_DST_PORT', '0'),
                    flow_features.get('FLOW_START_MILLISECONDS', 0),
                    flow_features.get('FLOW_END_MILLISECONDS', 0),
                    classification,
                    proba_score,
                    risk
                ]
                flow_df.loc[len(flow_df)] = record

                ip_data = {'SourceIP': list(src_ip_dict.keys()), 'count': list(src_ip_dict.values())}
                ip_data_json = pd.DataFrame(ip_data).to_json(orient='records')

                # Format display data to match table columns:
                # Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Flow start time, Flow last seen, App name, PID, Prediction, Prob, Risk
                disp_src = str(flow_features.get('IPV4_SRC_ADDR', '0.0.0.0'))
                disp_dst = str(flow_features.get('IPV4_DST_ADDR', '0.0.0.0'))
                disp_sport = str(flow_features.get('L4_SRC_PORT', '0'))
                disp_dport = str(flow_features.get('L4_DST_PORT', '0'))
                protocol = flow_features.get('PROTOCOL', 0)
                flow_start = flow_features.get('FLOW_START_MILLISECONDS', 0)
                flow_end = flow_features.get('FLOW_END_MILLISECONDS', 0)
                # Get app name from nDPI using Flow object
                app_name = get_app_name_from_flow(flow_object) if flow_object else "Unknown"
                pid = 'N/A'

                display = [current_flow_id, disp_src, disp_sport, disp_dst, disp_dport, protocol,
                           flow_start, flow_end, app_name, pid, classification, proba_score, risk]
                socketio.emit('newresult', {'result': display,
                              "ips": json.loads(ip_data_json)}, namespace='/test')

        # Clear buffers
        flow_buffer = []
        flow_objects_buffer = []

    return feature_string + ['Pending...', 0.0, 'Processing']


def newPacket(packet: Packet):
    """Process a new packet and update flows"""
    try:
        # Memory protection: limit active flows
        if len(current_flows) >= MAX_ACTIVE_FLOWS:
            # Force cleanup of oldest flows
            oldest_key = min(current_flows.keys(), key=lambda k: current_flows[k].latest_timestamp)
            flow_data = current_flows[oldest_key].get_data()
            classify(flow_data, current_flows[oldest_key])
            del current_flows[oldest_key]
        
        # Get flow key
        direction = PacketDirection.FORWARD
        flow_key = get_packet_flow_key(packet, direction)

        if flow_key is None:
            return

        src_ip, dest_ip, src_port, dest_port = flow_key
        fwd_key = f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"
        bwd_key = f"{dest_ip}:{dest_port}-{src_ip}:{src_port}"

        # Check if flow exists
        if fwd_key in current_flows:
            flow = current_flows[fwd_key]

            # Check for timeout
            if (packet.time - flow.latest_timestamp) > FlowTimeout:
                flow_data = flow.get_data()
                classify(flow_data, flow)  # Pass Flow object
                del current_flows[fwd_key]

                # Create new flow
                flow = Flow(packet, PacketDirection.FORWARD, attack=None)
                current_flows[fwd_key] = flow
            else:
                # Add packet to existing flow
                flow.add_packet(packet, PacketDirection.FORWARD)

                # Check for flow termination (FIN or RST)
                if packet.haslayer("TCP"):
                    tcp = packet["TCP"]
                    if tcp.flags & 0x01 or tcp.flags & 0x04:  # FIN or RST
                        flow_data = flow.get_data()
                        classify(flow_data, flow)  # Pass Flow object
                        del current_flows[fwd_key]

        elif bwd_key in current_flows:
            flow = current_flows[bwd_key]

            # Check for timeout
            if (packet.time - flow.latest_timestamp) > FlowTimeout:
                flow_data = flow.get_data()
                classify(flow_data, flow)  # Pass Flow object
                del current_flows[bwd_key]

                # Create new flow
                flow = Flow(packet, PacketDirection.FORWARD, attack=None)
                current_flows[fwd_key] = flow
            else:
                # Add packet to existing flow (reverse direction)
                flow.add_packet(packet, PacketDirection.REVERSE)

                # Check for flow termination
                if packet.haslayer("TCP"):
                    tcp = packet["TCP"]
                    if tcp.flags & 0x01 or tcp.flags & 0x04:  # FIN or RST
                        flow_data = flow.get_data()
                        classify(flow_data, flow)  # Pass Flow object
                        del current_flows[bwd_key]
        else:
            # Create new flow
            flow = Flow(packet, PacketDirection.FORWARD, attack=None)
            current_flows[fwd_key] = flow

    except AttributeError:
        # Not IP or TCP/UDP packet
        return
    except Exception as e:
        print(f"Error in newPacket: {e}")
        traceback.print_exc()


def snif_and_detect():
    """Sniff packets and detect attacks"""
    while not thread_stop_event.isSet():
        if capture_interface:
            print(f"Begin Sniffing on interface: {capture_interface}".center(60, ' '))
        else:
            print("Begin Sniffing on all interfaces".center(60, ' '))

        # Only capture ICMP, TCP, and UDP packets
        sniff(
            iface=capture_interface,  # None means all interfaces
            prn=newPacket,
            store=False,
            filter="ip and (tcp or udp or icmp)"
        )

        # Process remaining flows
        for flow_key, flow in list(current_flows.items()):
            flow_data = flow.get_data()
            classify(flow_data, flow)  # Pass Flow object

        # Process any remaining flows in buffer
        if len(flow_buffer) > 0:
            process_flow_batch(flow_buffer)
            flow_buffer.clear()
            flow_objects_buffer.clear()


def garbage_collect_inactive_flows(scan_interval_seconds: int = 5):
    """Background task to remove inactive flows from memory.

    A flow is considered inactive if now - latest_timestamp > FlowTimeout.
    Before removal, we classify the flow once to emit/save results.
    """
    global current_flows
    while not thread_stop_event.isSet():
        try:
            now = time.time()
            stale_keys = []
            # Work on a snapshot to avoid dict size change during iteration
            for key, flow in list(current_flows.items()):
                try:
                    if (now - flow.latest_timestamp) > FlowTimeout:
                        flow_data = flow.get_data()
                        classify(flow_data, flow)
                        stale_keys.append(key)
                except Exception as e:
                    print(f"[GC] Error processing flow {key}: {e}")
                    traceback.print_exc()

            for key in stale_keys:
                current_flows.pop(key, None)

        except Exception as e:
            print(f"[GC] Collector error: {e}")
            traceback.print_exc()
        # Sleep between scans
        sleep(scan_interval_seconds)


@app.route('/')
def index():
    # only by sending this page first will the client be connected to the socketio instance
    return render_template('index.html')


@app.route('/flow-detail')
def flow_detail():
    """Show detailed information about a specific flow"""
    flow_id = request.args.get('flow_id', default=-1, type=int)

    if flow_id == -1 or flow_id not in flow_df['FlowID'].values:
        return "Flow not found", 404

    flow = flow_df.loc[flow_df['FlowID'] == flow_id]

    if len(flow) == 0:
        return "Flow not found", 404

    # Get flow classification and risk
    classification = flow['Classification'].values[0] if 'Classification' in flow.columns else 'Unknown'
    risk = flow['Risk'].values[0] if 'Risk' in flow.columns else 'Unknown'
    probability = flow['Probability'].values[0] if 'Probability' in flow.columns else 0.0

    # Create simple feature importance plot using top features
    feature_values = {}
    for feat in netflow_features[:10]:  # Top 10 features
        if feat in flow.columns:
            feature_values[feat] = flow[feat].values[0]

    plot_div = plotly.offline.plot({
        "data": [
            plotly.graph_objs.Bar(
                x=list(feature_values.keys()),
                y=list(feature_values.values())
            )
        ],
        "layout": plotly.graph_objs.Layout(
            title="Top Flow Features",
            xaxis=dict(title="Feature"),
            yaxis=dict(title="Value")
        )
    }, include_plotlyjs=False, output_type='div')

    return render_template(
        'detail.html',
        tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')],
        exp=f"<h3>Classification: {classification}</h3><p>Probability: {probability:.4f}</p>",
        ae_plot=plot_div,
        risk=f"Risk: {risk}"
    )


@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
    global thread, gc_thread
    print('Client connected')

    # Start the random result generator thread only if the thread has not been started before.
    if not thread.is_alive():
        print("Starting Sniffer Thread")
        thread = socketio.start_background_task(snif_and_detect)

    # Start garbage collector thread if not already running
    if not gc_thread.is_alive():
        print("Starting Garbage Collector Thread")
        gc_thread = socketio.start_background_task(garbage_collect_inactive_flows)


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


@socketio.on('re_evaluate_flow', namespace='/test')
def handle_re_evaluation(data):
    """Re-evaluate a specific flow by its ID"""
    global flow_df

    flow_id = data.get('flow_id')
    print(f'Re-evaluating flow {flow_id}')

    if flow_id is None:
        return

    # Find the flow in the dataframe
    flow_records = flow_df[flow_df['FlowID'] == int(flow_id)]

    if len(flow_records) == 0:
        print(f'Flow {flow_id} not found')
        return

    flow_record = flow_records.iloc[0]

    # Extract features for re-evaluation
    features = {}
    for feat in netflow_features:
        features[feat] = flow_record.get(feat, 0)

    features['IPV4_SRC_ADDR'] = str(flow_record.get('IPV4_SRC_ADDR', '0.0.0.0'))
    features['IPV4_DST_ADDR'] = str(flow_record.get('IPV4_DST_ADDR', '0.0.0.0'))
    features['L4_SRC_PORT'] = flow_record.get('L4_SRC_PORT', 0)
    features['L4_DST_PORT'] = flow_record.get('L4_DST_PORT', 0)
    features['FLOW_START_MILLISECONDS'] = flow_record.get('FLOW_START_MILLISECONDS', 0)
    features['FLOW_END_MILLISECONDS'] = flow_record.get('FLOW_END_MILLISECONDS', 0)

    # Process single flow
    results = process_flow_batch([features])

    if results and len(results) > 0:
        result = results[0]
        classification = result['classification']
        proba_score = result['probability']
        risk = result['risk']

        # Update the dataframe
        flow_df.loc[flow_df['FlowID'] == int(flow_id), 'Classification'] = classification
        flow_df.loc[flow_df['FlowID'] == int(flow_id), 'Probability'] = proba_score
        flow_df.loc[flow_df['FlowID'] == int(flow_id), 'Risk'] = risk

        # Log the re-evaluation
        w.writerow([f'Re-evaluated Flow #{flow_id}'])
        w.writerow(['Classification:'] + [classification] + [proba_score])
        w.writerow(['--------------------------------------------------------------------------------------------------'])

        # Emit result back to client
        emit('re_evaluation_result', {
            'flow_id': flow_id,
            'classification': classification,
            'probability': proba_score,
            'risk': risk
        }, namespace='/test')

        print(f'Flow {flow_id} re-evaluated: {classification} ({proba_score:.4f})')
    else:
        print(f'Failed to re-evaluate flow {flow_id}')


def set_capture_interface(iface=None):
    """Set the network interface to capture from"""
    global capture_interface
    capture_interface = iface
    if iface:
        print(f"Capture interface set to: {iface}")
    else:
        print("Capture interface set to: all interfaces")

def set_filter(bpf_filter=""):
    """Set BPF filter for packet capture"""
    global filter
    filter = bpf_filter
    print(f"Capture filter set to: {bpf_filter}")


if __name__ == '__main__':
    socketio.run(app)
