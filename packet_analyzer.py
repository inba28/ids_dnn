import scapy.all as scapy
import requests
import time

# API URL where the model is hosted
API_URL = 'http://localhost:5000/analyze_alert'

# Global dictionary to store flow-related statistics
flows = {}

def extract_features(packet):
    """
    Extract features from the packet for analysis.
    """
    # Identifying the flow by a tuple of source and destination
    flow_key = (packet[scapy.IP].src, packet[scapy.IP].dst, packet[scapy.IP].proto)
    current_time = time.time()

    # Initialize flow stats if not already in the dictionary
    if flow_key not in flows:
        flows[flow_key] = {
            'start_time': current_time,
            'end_time': current_time,
            'total_fwd_packets': 0,
            'total_bwd_packets': 0,
            'total_fwd_bytes': 0,
            'total_bwd_bytes': 0,
            'iat_times': [],
        }

    flow = flows[flow_key]
    flow['end_time'] = current_time

    # Determine direction
    is_forward = packet[scapy.IP].src == flow_key[0]

    # Update flow statistics
    if is_forward:
        flow['total_fwd_packets'] += 1
        flow['total_fwd_bytes'] += len(packet)
    else:
        flow['total_bwd_packets'] += 1
        flow['total_bwd_bytes'] += len(packet)

    # Calculate inter-arrival times (IATs)
    if 'last_packet_time' in flow:
        iat = current_time - flow['last_packet_time']
        flow['iat_times'].append(iat)
    flow['last_packet_time'] = current_time

    # Calculate feature values
    total_packets = flow['total_fwd_packets'] + flow['total_bwd_packets']
    flow_duration = (flow['end_time'] - flow['start_time']) if flow['start_time'] != flow['end_time'] else 1e-6
    flow_bytes_per_s = (flow['total_fwd_bytes'] + flow['total_bwd_bytes']) / flow_duration
    flow_packets_per_s = total_packets / flow_duration
    iat_mean = sum(flow['iat_times']) / len(flow['iat_times']) if flow['iat_times'] else 0

    features = {
        'Flow Duration': flow_duration,
        'Total Fwd Packets': flow['total_fwd_packets'],
        'Total Backward Packets': flow['total_bwd_packets'],
        'Total Length of Fwd Packets': flow['total_fwd_bytes'],
        'Total Length of Bwd Packets': flow['total_bwd_bytes'],
        'Flow Bytes/s': flow_bytes_per_s,
        'Flow Packets/s': flow_packets_per_s,
        'Flow IAT Mean': iat_mean,
        'Fwd IAT Mean': iat_mean if is_forward else 0,
        'Bwd IAT Mean': iat_mean if not is_forward else 0,
        'Fwd PSH Flags': 1 if scapy.TCP in packet and 'P' in packet[scapy.TCP].flags and is_forward else 0,
        'Bwd PSH Flags': 1 if scapy.TCP in packet and 'P' in packet[scapy.TCP].flags and not is_forward else 0,
        'SYN Flag Count': 1 if scapy.TCP in packet and 'S' in packet[scapy.TCP].flags else 0,
        'ACK Flag Count': 1 if scapy.TCP in packet and 'A' in packet[scapy.TCP].flags else 0,
        'Down/Up Ratio': (flow['total_bwd_packets'] / flow['total_fwd_packets']) if flow['total_fwd_packets'] > 0 else 0,
        'Packet Length Mean': (flow['total_fwd_bytes'] + flow['total_bwd_bytes']) / total_packets if total_packets > 0 else 0,
        'Packet Length Std': 0,
        'FIN Flag Count': 1 if scapy.TCP in packet and 'F' in packet[scapy.TCP].flags else 0,
        'Subflow Fwd Packets': flow['total_fwd_packets'],
        'Subflow Fwd Bytes': flow['total_fwd_bytes'],
        'Subflow Bwd Packets': flow['total_bwd_packets'],
        'Subflow Bwd Bytes': flow['total_bwd_bytes'],
    }
    return features

def send_to_api(features):
    """
    Send the extracted features to the API for prediction.
    """
    try:
        data = {k: float(v) for k, v in features.items()}  # Convert values to float
        response = requests.post(API_URL, json={'features': data})
        return response.json()  # Return the JSON response from the API
    except Exception as e:
        print(f"Error sending to API: {e}")
        return None

def analyze_packet(packet):
    """
    Analyze the captured packet, extract features, and send to the API for prediction.
    """
    try:
        if scapy.IP in packet:  # Only process packets with an IP layer
            features = extract_features(packet)  # Extract features from the packet
            prediction = send_to_api(features)  # Send features to the API
    except Exception as e:
        print(f"Error analyzing packet: {e}")

# Start capturing packets
scapy.sniff(prn=analyze_packet, store=False, count=0, iface='ens33')  # Capture indefinitely
