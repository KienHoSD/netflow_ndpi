from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request, jsonify
from random import random
from time import sleep
from threading import Thread, Event, Lock

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
from pyod.models.cblof import CBLOF
from pyod.models.hbos import HBOS
from pyod.models.pca import PCA
from sklearn.ensemble import IsolationForest
from catboost import CatBoostClassifier
import itertools
from werkzeug.utils import secure_filename

import plotly
import plotly.graph_objs

from ndpi import NDPI

import warnings
import time
import os
warnings.filterwarnings("ignore")

# Get the directory of this module for relative path resolution
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


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


def format_timestamp_to_time(timestamp):
    """Format a timestamp to time string (HH:MM:SS)
    
    Args:
        timestamp: Unix timestamp (float)
        
    Returns:
        str: Time string in format HH:MM:SS
    """
    try:
        if timestamp:
            return time.strftime('%H:%M:%S', time.localtime(timestamp))
        return "N/A"
    except Exception as e:
        print(f"Error formatting timestamp: {e}")
        return "N/A"

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


__author__ = 'kiensd'


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# Default to non-debug; enable only when caller (sniffer -v) asks for it
app.config['DEBUG'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Auto-reload templates on change

# Turn the flask app into a socketio app (quiet by default; toggled via configure_debug)
socketio = SocketIO(app, async_mode=None, logger=False, engineio_logger=False)


def configure_debug(verbose: bool = False):
    """Toggle Flask/Socket.IO debug based on caller flag (e.g., sniffer -v)."""
    debug_enabled = bool(verbose)
    app.config['DEBUG'] = debug_enabled
    # Keep Flask logger level in sync
    app.logger.setLevel('DEBUG' if debug_enabled else 'INFO')
    # Enable/disable Socket.IO logging noise
    socketio.logger = debug_enabled
    socketio.engineio_logger = debug_enabled

# random result Generator Thread
thread = Thread()
gc_thread = Thread()
thread_stop_event = Event()
_workers_lock = Lock()  # Protects background worker startup

# Configuration for packet capture
capture_interface = None  # None means capture from all interfaces
capture_bpf_filter = None  # BPF filter for packet capture

# Logging files
f = open("output_logs.csv", 'w', newline='')
output_log = csv.writer(f)
f2 = open("input_logs.csv", 'w', newline='')
input_logs = csv.writer(f2)

# Flow CSV export
flows_csv_file = None  # Start as None, will be set when needed
flows_csv_writer = None  # Start as None, will be set when needed
flows_csv_lock: Lock = Lock()  # Synchronize concurrent file access

DEFAULT_CSV_FILENAME = "flows.csv"
DEFAULT_BPF_FILTER = "ip and (tcp or udp or icmp)"  # Default BPF filter for capturing relevant traffic
MAX_FLOW_HISTORY = 500  # Keep only recent flows to limit memory
MAX_ACTIVE_FLOWS = 200  # Limit concurrent flows (older flows get removed, can not be reclassified)
GC_SCAN_INTERVAL = 5  # Interval to scan for inactive flows in seconds
GC_FLOW_TIMEOUT = 120  # Flow timeout in seconds - faster cleanup for short-lived flows like curl
CLEANUP_BATCH_SIZE = 40  # Number of flows to cleanup when exceeding MAX_ACTIVE_FLOWS (Need to be smaller than MAX_ACTIVE_FLOWS)
CLASSIFY_BATCH_SIZE = 20  # Emit immediately for fastest UI updates
ROUND_PROBABILITY_DIGITS = 4  # Number of decimal places to round probabilities

# Store flows for batch processing
flow_objects_buffer = []  # Store Flow objects to access nDPI data
flow_buffer = []
flow_buffer_lock = Lock()  # Thread-safe access to flow_buffer and flow_objects_buffer
process_batch_lock = Lock()  # Thread-safe access to process_flow_batch to prevent race conditions
current_flows = {}
current_flows_lock = Lock()  # Thread-safe access to current_flows
src_ip_dict = {}
src_ip_dict_lock = Lock()  # Thread-safe access to src_ip_dict
flow_count = 0
flow_count_lock = Lock()  # Thread-safe access to flow_count
flow_df_lock = Lock()  # Thread-safe access to flow_df

# Anomaly detection flows
dgi_anomaly_flows = None  # DataFrame for anomaly detection
anomaly_predictions = {}  # Store anomaly predictions by flow_id
anomaly_predictions_lock = Lock()  # Thread-safe access to anomaly_predictions
anomaly_flows_file = None  # Current loaded anomaly flows filename
anomaly_model = None  # Trained Anomaly Model
anomaly_scaler = None  # Scaler for anomaly detection
anomaly_algorithm = "IsolationForest"  # Current anomaly algorithm
ANOMALY_FLOWS_DIR = os.path.join(MODULE_DIR, 'flows')
anomaly_model_fitted = False  # Track if Model has been fitted
anomaly_feature_order = []  # Features used during training for consistency
anomaly_cols_to_norm_trained = []  # Columns normalized during training
anomaly_data_lock = Lock()  # Thread-safe access to all anomaly-related globals

def _ensure_flows_csv(file_path=DEFAULT_CSV_FILENAME):
    """Lazily open the flows CSV with safe defaults and header if empty."""
    global flows_csv_file, flows_csv_writer

    with flows_csv_lock:
        needs_header = False

        if flows_csv_file is None or flows_csv_file.closed:
            os.makedirs(os.path.dirname(file_path) or "./", exist_ok=True)
            # Append mode so we don't lose existing rows
            flows_csv_file = open(file_path, 'a', newline='')
            needs_header = flows_csv_file.tell() == 0
            flows_csv_writer = csv.writer(
                flows_csv_file,
                quoting=csv.QUOTE_ALL,
                lineterminator='\n'
            )

        if needs_header:
            flows_csv_writer.writerow(cols)
            flows_csv_file.flush()


def _append_flow_row(record):
    """Thread-safe append of a single flow row to the active CSV file."""
    _ensure_flows_csv()

    with flows_csv_lock:
        if flows_csv_writer is None or flows_csv_file is None:
            return
        flows_csv_writer.writerow(record)
        flows_csv_file.flush()


def _read_flows_csv_locked(csv_path: str) -> pd.DataFrame:
    """Thread-safe CSV read to avoid race conditions with writers.
    """
    
    with flows_csv_lock:
        return pd.read_csv(csv_path, engine='python', on_bad_lines='skip')


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
    'Attack', 'Label', 'Probability', 'Risk', 'All_Probabilities', 
    'App_Name', 'Start_Time', 'End_Time', 'Anomaly'
]


# ATTACK_TYPES = ['Benign', 'Brute Force -Web', 'Brute Force -XSS',
#                 'DoS attacks-GoldenEye', 'DoS attacks-Hulk',
#                 'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris',
#                 'FTP-BruteForce', 'Infilteration', 'SQL Injection',
#                 'SSH-Bruteforce'] # UNSW-NB15 types
ATTACK_TYPES = ['Benign', 'FTP-BruteForce', 'SSH-Bruteforce',
                'DoS_attacks-GoldenEye', 'DoS_attacks-Slowloris',
                'DoS_attacks-SlowHTTPTest', 'DoS_attacks-Hulk',
                'DDoS_attacks-LOIC-HTTP', 'DDOS_attack-LOIC-UDP',
                'DDOS_attack-HOIC', 'Brute_Force_-Web', 'Brute_Force_-XSS',
                'SQL_Injection', 'Infilteration', 'Bot'] # CSE-CIC-IDS2017 types

flow_count = 0
flow_df = pd.DataFrame(columns=cols)
NUMB_NETFLOW_FEATURES = len(netflow_features)

# Categorical columns that need encoding
categorical_cols = ['TCP_FLAGS', 'L7_PROTO', 'PROTOCOL', 'CLIENT_TCP_FLAGS',
                    'SERVER_TCP_FLAGS', 'ICMP_TYPE', 'ICMP_IPV4_TYPE',
                    'DNS_QUERY_ID', 'DNS_QUERY_TYPE', 'FTP_COMMAND_RET_CODE']

# Columns to normalize (all except categorical)
cols_to_norm = [col for col in netflow_features if col not in categorical_cols]

# Device selection (Use CPU for simplicity)
device = 'cpu'
print(f"Using device: {device}")

# Model management
current_dgi_multiclass_model_name = 'best_dgi_CSE_multiclass_v3.pkl'
current_multiclass_classify_model_name = 'best_catboost_classifier_CSE_v3_fused.cbm'
current_dgi_anomaly_model_name = 'best_dgi_CSE_anomaly_v3.pkl'
model_lock = Lock()  # Thread-safe model loading

def get_available_models():
    """Get list of available models in the models folder"""
    models_dir = os.path.join(MODULE_DIR, 'models')
    if not os.path.exists(models_dir):
        return {'dgi_multiclass_models': [], 'dgi_anomaly_models': [], 'multiclass_models': []}

    all_dgi = [f for f in os.listdir(models_dir) if f.startswith('best_dgi') and f.endswith('.pkl')]
    dgi_multiclass_models = sorted([f for f in all_dgi if 'multiclass' in f])
    dgi_anomaly_models = sorted([f for f in all_dgi if 'anomaly' in f])
    multiclass_models = sorted([f for f in os.listdir(models_dir) if 'classifier' in f and (f.endswith('.cbm') or f.endswith('.json') or f.endswith('.pkl'))])

    return {
        'dgi_multiclass_models': dgi_multiclass_models,
        'dgi_anomaly_models': dgi_anomaly_models,
        'multiclass_models': multiclass_models
    }

def load_models(dgi_multiclass_model_name=None, multiclass_classify_model_name=None, dgi_anomaly_model_name=None):
    """Load specified models"""
    global dgi_multiclass_model, multiclass_classify_model, dgi_anomaly_model, models_loaded
    global current_dgi_multiclass_model_name, current_multiclass_classify_model_name, current_dgi_anomaly_model_name
    
    with model_lock:
        try:
            # Load DGI model
            if dgi_multiclass_model_name is None:
                dgi_multiclass_model_name = current_dgi_multiclass_model_name
            
            dgi_multiclass_path = os.path.join(MODULE_DIR, 'models', dgi_multiclass_model_name)
            if os.path.exists(dgi_multiclass_path):
                ndim_in = NUMB_NETFLOW_FEATURES
                edim = len(netflow_features)
                dgi_multiclass_model = DGI(ndim_in=ndim_in, ndim_out=128, edim=edim, activation=F.relu)
                dgi_multiclass_model.load_state_dict(torch.load(dgi_multiclass_path, map_location=device))
                dgi_multiclass_model.to(device)
                dgi_multiclass_model.eval()
                current_dgi_multiclass_model_name = dgi_multiclass_model_name
                print(f"Loaded DGI multiclass model: {dgi_multiclass_model_name}")
            
            # Load Multiclass classifier
            if multiclass_classify_model_name is None:
                multiclass_classify_model_name = current_multiclass_classify_model_name
            
            multiclass_classify_path = os.path.join(MODULE_DIR, 'models', multiclass_classify_model_name)
            if os.path.exists(multiclass_classify_path):
                multiclass_classify_model = CatBoostClassifier()
                multiclass_classify_model.load_model(multiclass_classify_path)
                current_multiclass_classify_model_name = multiclass_classify_model_name
                print(f"Loaded Multiclass classify model: {multiclass_classify_model_name}")

            # Load DGI anomaly model (if needed)
            if dgi_anomaly_model_name is None:
                dgi_anomaly_model_name = current_dgi_anomaly_model_name
            
            dgi_anomaly_path = os.path.join(MODULE_DIR, 'models', dgi_anomaly_model_name)
            if os.path.exists(dgi_anomaly_path):
                ndim_in = NUMB_NETFLOW_FEATURES
                edim = len(netflow_features)
                dgi_anomaly_model = DGI(ndim_in=ndim_in, ndim_out=128, edim=edim, activation=F.relu)
                dgi_anomaly_model.load_state_dict(torch.load(dgi_anomaly_path, map_location=device))
                dgi_anomaly_model.to(device)
                dgi_anomaly_model.eval()
                current_dgi_anomaly_model_name = dgi_anomaly_model_name
                print(f"Loaded DGI anomaly model: {dgi_anomaly_model_name}")
            
            models_loaded = True
            return True, "Models loaded successfully"
        
        except Exception as e:
            print(f"Error loading models: {e}")
            traceback.print_exc()
            models_loaded = False
            return False, str(e)

# Load models on startup
print("Loading models...")
load_models()

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

    return features


def predict_anomaly(flow_features):
    """Predict if a flow is anomalous using the trained Anomaly Model with DGI embeddings
    
    Args:
        flow_features: Dictionary of flow features
        
    Returns:
        int: 1 if anomaly, 0 if normal, None if model not loaded
    """
    global anomaly_model, anomaly_scaler, dgi_anomaly_model, anomaly_model_fitted, anomaly_feature_order, anomaly_cols_to_norm_trained
    
    if anomaly_model is None:
        return None
    
    if not anomaly_model_fitted:
        return None

    if dgi_anomaly_model is None:
        return None
    
    try:
        # Create DataFrame from flow features (similar to process_flow_batch)
        df = pd.DataFrame([flow_features])
        
        # Handle inf and nan
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Encode categorical features using the same feature order as training
        feature_order = anomaly_feature_order if anomaly_feature_order else netflow_features
        X = df[feature_order].copy()
        for col in categorical_cols:
            if col in X.columns:
                X[col] = pd.Categorical(X[col].astype(str)).codes
        
        # Ensure all numeric
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Normalize using the fitted scaler
        if anomaly_scaler is not None:
            cols_to_normalize = anomaly_cols_to_norm_trained if anomaly_cols_to_norm_trained else [col for col in cols_to_norm if col in X.columns]
            if len(cols_to_normalize) > 0:
                # Only normalize columns that exist in X
                cols_to_normalize = [c for c in cols_to_normalize if c in X.columns]
                if len(cols_to_normalize) > 0:
                    X[cols_to_normalize] = anomaly_scaler.transform(X[cols_to_normalize])
        
        # Create feature vector for graph
        X['h'] = X.values.tolist()
        
        # Build mini-graph from single flow
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
        
        # Initialize node features
        nfeat_weight = torch.ones([g_dgl.number_of_nodes(), len(feature_order)], device=device)
        g_dgl.ndata['h'] = torch.reshape(nfeat_weight, (nfeat_weight.shape[0], 1, nfeat_weight.shape[1]))
        
        # Reshape edge features
        g_dgl.edata['h'] = torch.reshape(g_dgl.edata['h'],
                                         (g_dgl.edata['h'].shape[0], 1,
                                          g_dgl.edata['h'].shape[1])).to(device)
        
        # Move to device
        g_dgl = g_dgl.to(device)
        
        # Get embeddings from DGI anomaly model
        with torch.no_grad():
            embeddings = dgi_anomaly_model.encoder(g_dgl, g_dgl.ndata['h'], g_dgl.edata['h'])[1]
            embeddings = embeddings.detach().cpu().numpy()
        
        # Memory cleanup
        del g_dgl, g, temp_df, nfeat_weight
        
        # Fusion: Combine embeddings with raw features
        df_emb = pd.DataFrame(embeddings)
        df_raw = X.copy().drop(columns=['h'])
        df_fuse = pd.concat([df_emb.reset_index(drop=True), df_raw.reset_index(drop=True)], axis=1)
        
        # Handle any remaining NaN values before predicting
        df_fuse.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_fuse.fillna(0, inplace=True)
        
        # Predict with Anomaly Model: -1 = anomaly, 1 = normal
        prediction = anomaly_model.predict(df_fuse.to_numpy())[0]
        
        # Convert: -1 -> 1 (anomaly), 1 -> 0 (normal)
        result = 1 if prediction == -1 else 0
        return result
        
    except Exception as e:
        print(f"[Anomaly Detection] Prediction error: {e}")
        traceback.print_exc()
        return None


def process_flow_batch(flows_data):
    """Process a batch of flows using DGI + CatBoost"""

    if not models_loaded or len(flows_data) == 0:
        return []

    # # Use lock to prevent concurrent processing (e.g., during re-evaluation)
    with process_batch_lock:
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

            # Normalize numerical features (use local scaler to avoid race conditions)
            local_scaler = Normalizer()
            X[cols_to_norm] = local_scaler.fit_transform(X[cols_to_norm])

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
                embeddings = dgi_multiclass_model.encoder(g_dgl, g_dgl.ndata['h'], g_dgl.edata['h'])[1]
                embeddings = embeddings.detach().cpu().numpy()
            
            # Memory cleanup: delete graph objects after use
            del g_dgl, g, temp_df, nfeat_weight

            # Fusion: Combine embeddings with raw features
            # This matches the training approach in the notebook
            df_emb = pd.DataFrame(embeddings)
            df_raw = X.copy().drop(columns=['h'])
            df_fuse = pd.concat([df_emb.reset_index(drop=True), df_raw.reset_index(drop=True)], axis=1)
            
            # Memory cleanup
            del df_emb, embeddings

            # Predict using CatBoost on fused features
            predictions = multiclass_classify_model.predict(df_fuse)
            probabilities = multiclass_classify_model.predict_proba(df_fuse)

            results = []
            for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
                max_proba = round(float(proba.max()), ROUND_PROBABILITY_DIGITS)

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

                classification = ATTACK_TYPES[int(pred)] if int(pred) < len(ATTACK_TYPES) else 'Unknown'

                # Create probability breakdown for all attack types
                all_probabilities = {}
                for idx, attack_type in enumerate(ATTACK_TYPES):
                    if idx < len(proba):
                        all_probabilities[attack_type] = round(float(proba[idx]), ROUND_PROBABILITY_DIGITS)
                
                # Sort by probability (descending)
                sorted_probs = sorted(all_probabilities.items(), key=lambda x: x[1], reverse=True)
                prob_str = ', '.join([f"{attack}: {prob*100:.1f}%" for attack, prob in sorted_probs])

                results.append({
                    'classification': classification,
                    'probability': max_proba,
                    'all_probabilities': all_probabilities,
                    'probability_str': prob_str,
                    'risk': risk
                })

            return results

        except Exception as e:
            traceback.print_exc()
            return []


def _emit_flow_result(current_flow_id, flow_features, flow_object, result, batch_results_ip_data):
    """Helper to emit a single flow result to frontend and update storage (thread-safe)
    
    Args:
        current_flow_id: Flow ID counter
        flow_features: Dictionary of flow features
        flow_object: Flow object or None
        result: Classification result dict or None (for fallback)
        batch_results_ip_data: Pre-computed IP data JSON string
    """
    global flow_df, anomaly_predictions
    
    if result:
        classification = result['classification']
        proba_score = result['probability']
        probability_str = result.get('probability_str', '')
        risk = result['risk']
        all_probs = result.get('all_probabilities', {})
    else:
        # Fallback values
        classification = 'Pending'
        proba_score = 0.0
        probability_str = ''
        risk = 'Processing'
        all_probs = {}
    
    label = 0 if classification == 'Benign' else 1
    
    # Get app name and times (cached from flow_object attributes)
    app_name = get_app_name_from_flow(flow_object) if flow_object else "Unknown"
    start_time = format_timestamp_to_time(flow_object.start_timestamp) if flow_object and hasattr(flow_object, 'start_timestamp') else "N/A"
    end_time = format_timestamp_to_time(flow_object.latest_timestamp) if flow_object and hasattr(flow_object, 'latest_timestamp') else "N/A"
    
    # Predict anomaly
    anomaly_pred = predict_anomaly(flow_features)
    if anomaly_pred is None:
        anomaly_pred = 'Unknown'
    elif pd.isna(anomaly_pred) or anomaly_pred == '' or anomaly_pred == 'nan':
        anomaly_pred = 'Unknown'
    
    # Store anomaly prediction if valid
    if anomaly_pred != 'Unknown':
        with anomaly_predictions_lock:
            anomaly_predictions[current_flow_id] = anomaly_pred
    
    # Create CSV record
    record = [current_flow_id] + [flow_features.get(f, 0) for f in netflow_features] + [
        flow_features.get('IPV4_SRC_ADDR', '0.0.0.0'),
        flow_features.get('L4_SRC_PORT', '0'),
        flow_features.get('IPV4_DST_ADDR', '0.0.0.0'),
        flow_features.get('L4_DST_PORT', '0'),
        classification,
        label,
        proba_score,
        risk,
        json.dumps(all_probs),
        app_name,
        start_time,
        end_time,
        anomaly_pred
    ]
    
    # Thread-safe flow_df update
    with flow_df_lock:
        flow_df.loc[len(flow_df)] = record
        if len(flow_df) > MAX_FLOW_HISTORY:
            flow_df = flow_df.iloc[-MAX_FLOW_HISTORY:].reset_index(drop=True)
    
    # Persist to CSV
    _append_flow_row(record)
    
    # Log output
    output_log.writerow([f'Flow #{current_flow_id}'])
    output_log.writerow(['Attack:'] + [classification] + [proba_score])
    output_log.writerow(['All Probabilities:'] + [probability_str])
    output_log.writerow(['--------------------------------------------------------------------------------------------------'])
    
    # Format display data
    disp_src = str(flow_features.get('IPV4_SRC_ADDR', '0.0.0.0'))
    disp_dst = str(flow_features.get('IPV4_DST_ADDR', '0.0.0.0'))
    disp_sport = str(flow_features.get('L4_SRC_PORT', '0'))
    disp_dport = str(flow_features.get('L4_DST_PORT', '0'))
    protocol = flow_features.get('PROTOCOL', 0)
    flow_duration = str(flow_features.get('FLOW_DURATION_MILLISECONDS', 0))
    
    display_data = [current_flow_id, disp_src, disp_sport, disp_dst, disp_dport,
                    protocol, start_time, end_time, flow_duration, app_name, anomaly_pred, classification, proba_score, risk]
    
    # Emit to frontend
    socketio.emit('newresult', {
        'result': display_data,
        'ips': json.loads(batch_results_ip_data),
        'all_probs': all_probs,
        'prob_str': probability_str,
        'flow_id': current_flow_id,
        'anomaly_pred': anomaly_pred
    }, namespace='/test')


def classify(flow_data, flow_obj=None):
    """Classify a single flow
    
    Args:
        flow_data: Dictionary of flow features
        flow_obj: Optional Flow object for accessing nDPI detected protocol
    """
    global flow_count, flow_buffer, flow_objects_buffer, flow_df

    # Extract features
    features = extract_flow_features(flow_data)

    # Track source IP (thread-safe)
    src_ip = features['IPV4_SRC_ADDR']
    with src_ip_dict_lock:
        if src_ip in src_ip_dict:
            src_ip_dict[src_ip] += 1
        else:
            src_ip_dict[src_ip] = 1

    # Add to buffer for batch processing (with lock to prevent race conditions)
    with flow_buffer_lock:
        flow_buffer.append(features)
        flow_objects_buffer.append(flow_obj)  # Store Flow object for nDPI data

        # Check if buffer is full
        if len(flow_buffer) < CLASSIFY_BATCH_SIZE:
            return # Not enough flows yet
        
        # Buffer is full: make local copy and clear while holding lock
        batch_to_process = flow_buffer[:]
        objects_to_process = flow_objects_buffer[:]
        flow_buffer.clear()
        flow_objects_buffer.clear()
    
    # Process batch outside the lock to avoid blocking other threads
    print(f"[DEBUG] Buffer full! Processing batch of {len(batch_to_process)} flows...")
    results = process_flow_batch(batch_to_process)

    # Pre-compute IP data once for the batch
    with src_ip_dict_lock:
        ip_data = {'SourceIP': list(src_ip_dict.keys()), 'count': list(src_ip_dict.values())}
    batch_results_ip_data = pd.DataFrame(ip_data).to_json(orient='records')

    if results and len(results) > 0:
        print(f"[DEBUG] Got {len(results)} results for {len(batch_to_process)} flows")
        # Process only flows we have results for
        num_flows_to_process = min(len(results), len(batch_to_process))

        # Emit model-based results
        for idx in range(num_flows_to_process):
            # Thread-safe flow_count increment
            with flow_count_lock:
                flow_count += 1
                current_flow_id = flow_count
            
            flow_features = batch_to_process[idx]
            flow_object = objects_to_process[idx] if idx < len(objects_to_process) else None
            result = results[idx]

            _emit_flow_result(current_flow_id, flow_features, flow_object, result, batch_results_ip_data)
    else:
        # Fallback: emit placeholder rows so UI is not empty
        for idx, flow_features in enumerate(batch_to_process):
            # Thread-safe flow_count increment
            with flow_count_lock:
                flow_count += 1
                current_flow_id = flow_count
            
            flow_object = objects_to_process[idx] if idx < len(objects_to_process) else None
            _emit_flow_result(current_flow_id, flow_features, flow_object, None, batch_results_ip_data)


# ---- Pagination and history helpers ----
def get_flows_dataframe() -> pd.DataFrame:
    """Return DataFrame of all flows.
    Returns:
        pd.DataFrame: Flow data
    """
    try:
        # Use in-memory DataFrame (has latest rows)
        if flows_csv_writer is not None:
            with flow_df_lock:
                return flow_df.copy()
        # Fall back to reading default CSV on disk if present
        import os
        default_path = os.path.join(os.getcwd(), flows_csv_file.name)
        if os.path.exists(default_path):
            return _read_flows_csv_locked(default_path)
    except Exception:
        pass
    # Default to current in-memory DataFrame
    with flow_df_lock:
        return flow_df.copy()


def update_flow_in_csv(flow_id, record):
    """Append flow to CSV (no updates, no loading entire file)
    
    Since re-evaluation is removed, this now just appends.
    Old flows remain as historical record.
    """
    # Simply append - no memory issues, no loading CSV
    _append_flow_row(record)
    print(f"[CSV] Appended flow {flow_id} to CSV")

@app.route('/api/models')
def api_models():
    """Return list of available models and current selection"""
    try:
        available = get_available_models()
        return jsonify({
            'success': True,
            'available_models': available,
            'current_models': {
                'dgi_multiclass_model': current_dgi_multiclass_model_name,
                'multiclass_model': current_multiclass_classify_model_name,
                'dgi_anomaly_model': current_dgi_anomaly_model_name
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/load-model', methods=['POST'])
def api_load_model():
    """Load selected models"""
    try:
        data = request.get_json()
        dgi_multiclass_name = data.get('dgi_multiclass_model')
        multiclass_name = data.get('multiclass_model')
        dgi_anomaly_name = data.get('dgi_anomaly_model')

        success, message = load_models(dgi_multiclass_name, multiclass_name, dgi_anomaly_name)
        return jsonify({
            'success': success,
            'message': message,
            'current_models': {
                'dgi_multiclass_model': current_dgi_multiclass_model_name,
                'multiclass_model': current_multiclass_classify_model_name,
                'dgi_anomaly_model': current_dgi_anomaly_model_name
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/upload-anomaly-flows', methods=['POST'])
def api_upload_anomaly_flows():
    """Upload flows CSV file and train Anomaly Model for anomaly detection on new flows"""
    global dgi_anomaly_flows, anomaly_predictions, anomaly_flows_file, anomaly_model, anomaly_scaler, dgi_anomaly_model, anomaly_algorithm
    global anomaly_model_fitted, anomaly_feature_order, anomaly_cols_to_norm_trained
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if not file.filename.endswith('.csv'):
            return jsonify({'success': False, 'error': 'File must be a CSV'})
        
        # Get parameters
        max_flows = int(request.form.get('max_flows', 100000))
        n_estimators = int(request.form.get('n_estimators', 50))
        contamination = float(request.form.get('contamination', 0.01))
        algorithm = request.form.get('algorithm', 'IF').strip().upper()
        
        # Check if DGI anomaly model is loaded
        if dgi_anomaly_model is None:
            return jsonify({'success': False, 'error': 'DGI anomaly model not loaded. Please load models first.'})
        
        # Ensure flows directory exists
        os.makedirs(ANOMALY_FLOWS_DIR, exist_ok=True)
        
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(ANOMALY_FLOWS_DIR, filename)
        file.save(filepath)
        
        # Load and process flows
        df = pd.read_csv(filepath, engine='python', on_bad_lines='skip')
        
        # Limit number of flows
        if len(df) > max_flows:
            df = df.head(max_flows)
        
        # Extract NetFlow features (ensure full feature set order)
        available_features = [col for col in netflow_features if col in df.columns]
        if len(available_features) == 0:
            return jsonify({'success': False, 'error': 'No valid NetFlow feature columns found in CSV'})
        
        # Also need IP addresses for graph construction
        if 'IPV4_SRC_ADDR' not in df.columns or 'IPV4_DST_ADDR' not in df.columns:
            return jsonify({'success': False, 'error': 'IPV4_SRC_ADDR and IPV4_DST_ADDR columns required'})
        
        print(f"[Anomaly Detection] Processing {len(df)} flows...")
        
        # Process like process_flow_batch
        # Build X with ALL netflow_features; fill missing columns with 0
        X = pd.DataFrame({feat: (df[feat] if feat in df.columns else 0) for feat in netflow_features})
        
        # Handle inf and nan values
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)
        
        # Encode categorical features
        for col in categorical_cols:
            if col in X.columns:
                X[col] = pd.Categorical(X[col].astype(str)).codes
        
        # Ensure all columns are numeric
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Normalize numerical features
        anomaly_scaler = Normalizer()
        cols_to_normalize = [col for col in cols_to_norm if col in X.columns]
        if len(cols_to_normalize) > 0:
            X[cols_to_normalize] = anomaly_scaler.fit_transform(X[cols_to_normalize])
        
        # Create feature vector for each edge
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
        
        # Initialize node features
        nfeat_weight = torch.ones([g_dgl.number_of_nodes(), len(netflow_features)], device=device)
        g_dgl.ndata['h'] = torch.reshape(nfeat_weight, (nfeat_weight.shape[0], 1, nfeat_weight.shape[1]))
        
        # Reshape edge features
        g_dgl.edata['h'] = torch.reshape(g_dgl.edata['h'],
                                         (g_dgl.edata['h'].shape[0], 1,
                                          g_dgl.edata['h'].shape[1])).to(device)
        
        # Move graph to device
        g_dgl = g_dgl.to(device)
        
        # Get embeddings from DGI anomaly model
        print(f"[Anomaly Detection] Generating embeddings using DGI anomaly model...")
        with torch.no_grad():
            embeddings = dgi_anomaly_model.encoder(g_dgl, g_dgl.ndata['h'], g_dgl.edata['h'])[1]
            embeddings = embeddings.detach().cpu().numpy()
        
        # Memory cleanup
        del g_dgl, g, temp_df, nfeat_weight
        
        # Fusion: Combine embeddings with raw features
        print(f"[Anomaly Detection] Fusing embeddings with raw features...")
        df_emb = pd.DataFrame(embeddings)
        df_raw = X.copy().drop(columns=['h'])
        df_fuse = pd.concat([df_emb.reset_index(drop=True), df_raw.reset_index(drop=True)], axis=1)
        
        # Memory cleanup
        del df_emb, embeddings, X
        
        # Handle any remaining NaN values before fitting
        print(f"[Anomaly Detection] Handling NaN values in fused features...")
        df_fuse.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_fuse.fillna(0, inplace=True)
        
        # Verify no NaN or inf values remain
        if df_fuse.isnull().any().any():
            print(f"[Anomaly Detection] Warning: Still found NaN values after cleaning")
        if np.isinf(df_fuse.values).any():
            print(f"[Anomaly Detection] Warning: Still found inf values after cleaning")
        
        # Train Anomaly Model on fused features
        algo_map = {
            'IF': ('IsolationForest', lambda: IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=42)),
            'CBLOF': ('CBLOF', lambda: CBLOF(n_clusters=n_estimators, contamination=contamination, random_state=42)),
            'HBOS': ('HBOS', lambda: HBOS(contamination=contamination)),
            'PCA': ('PCA', lambda: PCA(contamination=contamination, n_components=min(n_estimators, df_fuse.shape[1])))
        }
        selected_algo_name, algo_ctor = algo_map.get(algorithm, algo_map['IF'])
        anomaly_algorithm = selected_algo_name
        print(f"[Anomaly Detection] Training {selected_algo_name} with N={n_estimators}, contamination={contamination}")
        anomaly_model = algo_ctor()
        anomaly_model.fit(df_fuse.to_numpy())
        
        # Store DataFrame and metadata (thread-safe)
        with anomaly_data_lock:
            global dgi_anomaly_flows, anomaly_flows_file, anomaly_predictions, anomaly_feature_order, anomaly_cols_to_norm_trained, anomaly_model_fitted
            dgi_anomaly_flows = df
            anomaly_flows_file = filename
            anomaly_predictions = {}  # Clear previous predictions
            # Persist training metadata for consistent prediction preprocessing
            anomaly_feature_order = netflow_features[:]
            anomaly_cols_to_norm_trained = cols_to_normalize[:]
            anomaly_model_fitted = True
        
        print(f"[Anomaly Detection] Model trained on {len(df)} flows with fusion features. Ready to predict anomalies on new flows.")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'total_flows': len(df),
            'algorithm': anomaly_algorithm,
            'message': f'Model trained on {len(df)} flows with DGI+fusion using {anomaly_algorithm}. Ready to detect anomalies.',
            'predictions': {}  # Empty since we'll predict on new flows
        })
        
    except Exception as e:
        print(f"[Anomaly Detection] Error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/flows')
def api_flows():
    """Return the latest flows, capped to the requested page_size (no paging).
    Query params:
        page_size: Number of latest flows to return (default MAX_FLOW_HISTORY)
    """
    try:
        page_size = int(request.args.get('page_size', MAX_FLOW_HISTORY))
    except Exception:
        page_size = MAX_FLOW_HISTORY

    df = get_flows_dataframe()
    if 'FlowID' in df.columns:
        df = df.sort_values(by='FlowID')

    total = len(df)
    # Keep only the most recent page_size flows
    page_df = df.tail(page_size) if page_size > 0 else df.tail(MAX_FLOW_HISTORY)

    # Build display arrays to match frontend table schema
    data = []
    predictions = {}  # Send anomaly predictions separately
    for _, row in page_df.iterrows():
        flow_id = int(row.get('FlowID', 0))
        protocol = row.get('PROTOCOL', 0)
        # Get start and end times from stored columns
        start_time = row.get('Start_Time', 'N/A')
        end_time = row.get('End_Time', 'N/A')
        duration = row.get('FLOW_DURATION_MILLISECONDS', 0)
        app_name = row.get('App_Name', 'Unknown')
        # Get anomaly prediction from stored column (fallback to dictionary if not in column)
        with anomaly_predictions_lock:
            anomaly_pred = row.get('Anomaly', anomaly_predictions.get(flow_id, 'Unknown'))
        
        # Normalize anomaly value to handle NaN, None, or empty values
        if pd.isna(anomaly_pred) or anomaly_pred is None or anomaly_pred == '' or anomaly_pred == 'nan':
            anomaly_pred = 'Unknown'
        
        display = [
            flow_id,
            str(row.get('IPV4_SRC_ADDR', '0.0.0.0')),
            str(row.get('L4_SRC_PORT', '0')),
            str(row.get('IPV4_DST_ADDR', '0.0.0.0')),
            str(row.get('L4_DST_PORT', '0')),
            protocol,
            start_time,
            end_time,
            str(duration),
            app_name,
            anomaly_pred,
            row.get('Attack', 'Pending'),
            row.get('Probability', 0.0),
            row.get('Risk', 'Processing')
        ]
        data.append(display)
        if anomaly_pred != 'Unknown':
            predictions[flow_id] = anomaly_pred

    # Get anomaly model status safely
    with anomaly_data_lock:
        model_loaded = anomaly_model_fitted
        model_filename = anomaly_flows_file if anomaly_model_fitted else None
        model_flows_count = len(dgi_anomaly_flows) if anomaly_model_fitted and dgi_anomaly_flows is not None else 0
        model_algorithm = anomaly_algorithm if anomaly_model_fitted else None

    return jsonify({
        'page': 1,
        'page_size': page_size,
        'total': total,
        'total_pages': 1,
        'is_last_page': True,
        'data': data,
        'anomaly_predictions': predictions,
        'anomaly_model_status': {
            'loaded': model_loaded,
            'filename': model_filename,
            'total_flows': model_flows_count,
            'algorithm': model_algorithm
        }
    })

def newPacket(packet: Packet):
    """Process a new packet and update flows"""
    try:
        # Memory protection: limit active flows
        with current_flows_lock:
            flows_count = len(current_flows)
        
        if flows_count >= MAX_ACTIVE_FLOWS:
            # Print warning
            print(f"[DEBUG] Active flows exceeded limit ({flows_count} >= {MAX_ACTIVE_FLOWS}). Cleaning up {CLEANUP_BATCH_SIZE} oldest flows.")

            # Extract oldest flows efficiently with minimal lock time
            flows_to_cleanup = []
            with current_flows_lock:
                if len(current_flows) > 0:
                    # Use heapq for O(n log k) instead of O(n log n) - only extract what we need
                    import heapq
                    oldest_items = heapq.nsmallest(
                        CLEANUP_BATCH_SIZE, 
                        current_flows.items(), 
                        key=lambda x: x[1].latest_timestamp
                    )
                    # Extract flow objects and remove from dict in one pass
                    for key, flow_obj in oldest_items:
                        flows_to_cleanup.append((key, flow_obj, flow_obj))
                        del current_flows[key]

            if len(flows_to_cleanup) == 0:
                return
            
            # Call get_data() outside the lock and classify
            for key, flow_obj, _ in flows_to_cleanup:
                flow_data = flow_obj.get_data()
                classify(flow_data, flow_obj)
            
        
        # Get flow key
        direction = PacketDirection.FORWARD
        flow_key = get_packet_flow_key(packet, direction)

        if flow_key is None:
            return

        src_ip, dest_ip, src_port, dest_port = flow_key
        fwd_key = f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"
        bwd_key = f"{dest_ip}:{dest_port}-{src_ip}:{src_port}"

        # Check if flow exists (timeout handled by GC thread)
        with current_flows_lock:
            flow_exists_fwd = fwd_key in current_flows
            flow_exists_bwd = bwd_key in current_flows
        
        if flow_exists_fwd:
            with current_flows_lock:
                flow = current_flows[fwd_key]
            
            # Add packet to existing flow
            flow.add_packet(packet, PacketDirection.FORWARD)

            # Check for flow termination (FIN or RST) or if it looks complete
            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                if tcp.flags & 0x01 or tcp.flags & 0x04:  # FIN or RST
                    flow_data = flow.get_data()
                    classify(flow_data, flow)  # Pass Flow object
                    with current_flows_lock:
                        current_flows.pop(fwd_key, None)

        elif flow_exists_bwd:
            with current_flows_lock:
                flow = current_flows[bwd_key]
            
            # Add packet to existing flow (reverse direction)
            flow.add_packet(packet, PacketDirection.REVERSE)

            # Check for flow termination
            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                if tcp.flags & 0x01 or tcp.flags & 0x04:  # FIN or RST
                    flow_data = flow.get_data()
                    classify(flow_data, flow)  # Pass Flow object
                    with current_flows_lock:
                        current_flows.pop(bwd_key, None)
        else:
            # Create new flow
            flow = Flow(packet, PacketDirection.FORWARD, attack=None)
            with current_flows_lock:
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

        # Only able to capture ICMP, TCP, and UDP packets
        sniff(
            iface=capture_interface,  # None means all interfaces
            prn=newPacket,
            store=False,
            filter=capture_bpf_filter if capture_bpf_filter else DEFAULT_BPF_FILTER
        )

        # Process remaining flows (thread-safe snapshot)
        with current_flows_lock:
            flows_snapshot = list(current_flows.items())
        
        for flow_key, flow in flows_snapshot:
            flow_data = flow.get_data()
            classify(flow_data, flow)  # Pass Flow object

        # Process any remaining flows in buffer (thread-safe)
        with flow_buffer_lock:
            if len(flow_buffer) > 0:
                remaining_batch = flow_buffer[:]
                remaining_objects = flow_objects_buffer[:]
                flow_buffer.clear()
                flow_objects_buffer.clear()
            else:
                remaining_batch = []
                remaining_objects = []
        
        if len(remaining_batch) > 0:
            process_flow_batch(remaining_batch)


def garbage_collect_inactive_flows(scan_interval_seconds: int = GC_SCAN_INTERVAL):
    """Background task to remove inactive flows from memory.

    A flow is considered inactive if now - latest_timestamp > FLOW_TIMEOUT.
    Before removal, we classify the flow once to emit/save results.
    This is the ONLY place where timeout-based flow cleanup happens.
    """
    global current_flows
    while not thread_stop_event.isSet():
        try:
            now = time.time()
            stale_flows = []
            
            # Get snapshot of flows to check
            with current_flows_lock:
                flows_snapshot = list(current_flows.items())
            
            # Check each flow for timeout (without holding lock)
            for key, flow in flows_snapshot:
                try:
                    if (now - flow.latest_timestamp) > GC_FLOW_TIMEOUT:
                        flow_data = flow.get_data()
                        stale_flows.append((key, flow_data, flow))
                except Exception as e:
                    print(f"[GC] Error processing flow {key}: {e}")
                    traceback.print_exc()

            # Classify and remove stale flows
            for key, flow_data, flow_obj in stale_flows:
                classify(flow_data, flow_obj)
                with current_flows_lock:
                    current_flows.pop(key, None)
            
            if len(stale_flows) > 0:
                print(f"[GC] Cleaned up {len(stale_flows)} inactive flow(s)")

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

    if flow_id == -1:
        return "Flow not found", 404

    # Read from flows.csv file
    try:
        # Try CSV first
        if flows_csv_file is not None and hasattr(flows_csv_file, 'name'):
            flows_csv_path = flows_csv_file.name
        else:
            flows_csv_path = DEFAULT_CSV_FILENAME

        flow = None
        if os.path.exists(flows_csv_path):
            df = _read_flows_csv_locked(flows_csv_path)
            if 'FlowID' in df.columns and flow_id in df['FlowID'].values:
                flow = df.loc[df['FlowID'] == flow_id]

        # Fallback to in-memory dataframe if CSV miss (thread-safe)
        if flow is None or len(flow) == 0:
            with flow_df_lock:
                mem_df = flow_df.copy()
            if 'FlowID' in mem_df.columns and flow_id in mem_df['FlowID'].values:
                flow = mem_df.loc[mem_df['FlowID'] == flow_id]

        if flow is None or len(flow) == 0:
            print(f"[FLOW_DETAIL] Flow {flow_id} not found in {flows_csv_path}")
            return "Flow not found", 404
    except Exception as e:
        print(f"[FLOW_DETAIL] Error reading flows.csv: {e}")
        traceback.print_exc()
        return "Error loading flow data", 500

    # Get flow attack classification and risk
    classification = flow['Attack'].values[0] if 'Attack' in flow.columns else 'Unknown'
    risk = flow['Risk'].values[0] if 'Risk' in flow.columns else 'Unknown'
    probability = flow['Probability'].values[0] if 'Probability' in flow.columns else 0.0
    anomaly_val = flow['Anomaly'].values[0] if 'Anomaly' in flow.columns else None

    # Normalize anomaly display value
    anomaly_label = "Unknown"
    if anomaly_val is not None and not pd.isna(anomaly_val):
        try:
            anomaly_int = int(anomaly_val)
            anomaly_label = "Anomaly" if anomaly_int == 1 else "Normal"
        except Exception:
            anomaly_label = str(anomaly_val)
    # anomaly_display = f"Anomaly Result: {anomaly_label}"
    anomaly_display = anomaly_label
    
    # Get all probabilities
    all_probs_json = flow['All_Probabilities'].values[0] if 'All_Probabilities' in flow.columns else '{}'
    try:
        all_probs = json.loads(all_probs_json)
    except:
        all_probs = {}
    
    # Sort by probability descending
    sorted_probs = sorted(all_probs.items(), key=lambda x: x[1], reverse=True)
    prob_html = '<table class="table table-striped"><tr><th>Attack Type</th><th>Probability</th></tr>'
    for attack_type, prob in sorted_probs:
        prob_html += f'<tr><td>{attack_type}</td><td>{prob*100:.2f}%</td></tr>'
    prob_html += '</table>'

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
        exp=f"<h3>Attack: {classification}</h3><p>Probability: {probability:.4f}</p>",
        ae_plot=plot_div,
        risk=f"Risk: {risk}",
        anomaly_result=anomaly_display,
        all_probs_table=prob_html
    )


def start_background_workers():
    """Ensure sniffer and GC threads are running (idempotent)."""
    global thread, gc_thread
    with _workers_lock:
        if not thread.is_alive():
            print("Starting Sniffer Thread")
            thread = socketio.start_background_task(snif_and_detect)
        if not gc_thread.is_alive():
            print("Starting Garbage Collector Thread")
            gc_thread = socketio.start_background_task(garbage_collect_inactive_flows)


@socketio.on('connect', namespace='/test')
def test_connect():
    print('Client connected')
    start_background_workers()


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


# Re-evaluation feature removed - causes inconsistent results due to per-batch normalization


def set_capture_interface(iface=None):
    """Set the network interface to capture from"""
    global capture_interface
    capture_interface = iface
    if iface:
        print(f"Capture interface set to: {iface}")
    else:
        print("Capture interface set to: all interfaces")

def set_filter(bpf_filter=DEFAULT_BPF_FILTER):
    """Set BPF filter for packet capture"""
    global capture_bpf_filter
    capture_bpf_filter = bpf_filter
    print(f"Capture filter set to: {bpf_filter}")

def set_output_file(file_path=DEFAULT_CSV_FILENAME):
    """Set output CSV file path (optional)"""
    global flows_csv_file, flows_csv_writer
    
    with flows_csv_lock:
        # Close existing file if open
        if flows_csv_file is not None:
            try:
                flows_csv_file.close()
            except Exception:
                pass

        # Only open and write header if file_path is provided
        if file_path is not None:
            # Create parent directories if needed
            os.makedirs(os.path.dirname(file_path) or "./", exist_ok=True)

            flows_csv_file = open(file_path, 'w', newline='')
            flows_csv_writer = csv.writer(
                flows_csv_file,
                quoting=csv.QUOTE_ALL,
                lineterminator='\n'
            )
            flows_csv_writer.writerow(cols)
            flows_csv_file.flush()
        else:
            flows_csv_file = None
            flows_csv_writer = None

# Open default flows CSV at startup (append-safe)
_ensure_flows_csv()


if __name__ == '__main__':
    # Ensure background workers are started even if no client connects yet
    start_background_workers()
    # Enable hot-reload: use_reloader reloads code on changes, debug shows errors
    socketio.run(app, debug=True, use_reloader=True)
