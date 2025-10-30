#!/usr/bin/env python3
"""
# 1. Save Sketch output to a file
sudo ./bubble_sketch_loader veth-recv > sketch_output.txt

# 2. Run accuracy comparison
python3 accuracy_calc.py --sketch sketch_output.txt --pcap /tmp/veth_recv_capture.pcap --top 10

"""

import argparse
import socket
import re
from collections import Counter
import dpkt


def parse_sketch_output(filepath):
    flows = {}
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    # Find the table start
    in_table = False
    for line in lines:
        line = line.strip()
        
        # Skip header lines
        if line.startswith('No') and 'Src IP' in line:
            in_table = True
            continue
        
        if not in_table or not line or line.startswith('==='):
            continue
        
        # Parse data lines
        parts = line.split()
        if len(parts) < 7:
            continue
        
        try:
            # Skip entry number
            src_ip = parts[1]
            src_port = int(parts[2])
            dst_ip = parts[3]
            dst_port = int(parts[4])
            proto = parts[5]
            count = int(parts[6])
            
            # Skip 0.0.0.0 entries (uninitialized)
            if src_ip == '0.0.0.0' or dst_ip == '0.0.0.0':
                continue
            
            # Create 5-tuple key
            proto_num = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'OTHER': 0}.get(proto, 0)
            key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}/{proto_num}"
            flows[key] = count
            
        except (ValueError, IndexError):
            continue
    
    return flows


def ip_to_str(pkt_ip):
    """Convert IP bytes to string"""
    return socket.inet_ntop(socket.AF_INET, pkt_ip)


def parse_pcap_ground_truth(pcap_path):
    """Parse PCAP and count 5-tuples"""
    flows = Counter()
    
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            
            ip = eth.data
            proto = ip.p
            
            try:
                src_ip = ip_to_str(ip.src)
                dst_ip = ip_to_str(ip.dst)
            except Exception:
                continue
            
            sport = dport = 0
            
            if proto == dpkt.ip.IP_PROTO_UDP:
                try:
                    udp = ip.data
                    sport, dport = udp.sport, udp.dport
                except Exception:
                    pass
            elif proto == dpkt.ip.IP_PROTO_TCP:
                try:
                    tcp = ip.data
                    sport, dport = tcp.sport, tcp.dport
                except Exception:
                    pass
            
            key = f"{src_ip}:{sport} -> {dst_ip}:{dport}/{proto}"
            flows[key] += 1
    
    return flows


def calculate_metrics(sketch_flows, ground_truth, top_k=10):
    """Calculate accuracy metrics"""
    
    # Get top-K from ground truth
    gt_top_k = dict(ground_truth.most_common(top_k))
    gt_keys = set(gt_top_k.keys())
    sketch_keys = set(sketch_flows.keys())
    
    # Basic stats
    total_packets = sum(ground_truth.values())
    unique_flows = len(ground_truth)
    
    print(f"\n{'='*80}")
    print(f"GROUND TRUTH STATISTICS")
    print(f"{'='*80}")
    print(f"Total packets:        {total_packets:,}")
    print(f"Unique flows:         {unique_flows:,}")
    print(f"Top-{top_k} threshold:   {min(gt_top_k.values()) if gt_top_k else 0:,} packets")
    
    print(f"\n{'='*80}")
    print(f"BUBBLESKETCH STATISTICS")
    print(f"{'='*80}")
    print(f"Flows reported:       {len(sketch_flows):,}")
    print(f"Non-zero entries:     {len([v for v in sketch_flows.values() if v > 0]):,}")
    
    # Detection metrics
    true_positives = gt_keys & sketch_keys  # Correctly detected heavy hitters
    false_negatives = gt_keys - sketch_keys  # Missed heavy hitters
    false_positives = sketch_keys - gt_keys  # Incorrectly reported as heavy hitters
    
    precision = len(true_positives) / len(sketch_keys) if sketch_keys else 0
    recall = len(true_positives) / len(gt_keys) if gt_keys else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n{'='*80}")
    print(f"DETECTION METRICS (Top-{top_k})")
    print(f"{'='*80}")
    print(f"True Positives (TP):  {len(true_positives)}/{top_k}  (correctly detected)")
    print(f"False Negatives (FN): {len(false_negatives)}/{top_k}  (missed heavy hitters)")
    print(f"False Positives (FP): {len(false_positives)}        (false alarms)")
    print(f"\nPrecision:            {precision:.2%}  (TP / [TP + FP])")
    print(f"Recall:               {recall:.2%}  (TP / [TP + FN])")
    print(f"F1-Score:             {f1_score:.2%}")
    
    # Count accuracy for detected flows
    absolute_errors = []
    relative_errors = []
    
    for flow in true_positives:
        gt_count = gt_top_k[flow]
        sketch_count = sketch_flows[flow]
        abs_error = abs(gt_count - sketch_count)
        rel_error = abs_error / gt_count if gt_count > 0 else 0
        
        absolute_errors.append(abs_error)
        relative_errors.append(rel_error)
    
    if absolute_errors:
        avg_abs_error = sum(absolute_errors) / len(absolute_errors)
        avg_rel_error = sum(relative_errors) / len(relative_errors)
        
        print(f"\n{'='*80}")
        print(f"COUNT ACCURACY (for detected flows)")
        print(f"{'='*80}")
        print(f"Average absolute error: {avg_abs_error:,.1f} packets")
        print(f"Average relative error: {avg_rel_error:.2%}")
    
    # Detailed comparison
    print(f"\n{'='*80}")
    print(f"DETAILED COMPARISON (Top-{top_k})")
    print(f"{'='*80}")
    print(f"{'Rank':<5} {'Flow':<50} {'Ground Truth':<15} {'BubbleSketch':<15} {'Error':<10} {'Status':<10}")
    print(f"{'-'*115}")
    
    for i, (flow, gt_count) in enumerate(ground_truth.most_common(top_k), 1):
        sketch_count = sketch_flows.get(flow, 0)
        error = abs(gt_count - sketch_count)
        rel_error = error / gt_count if gt_count > 0 else 0
        
        if sketch_count > 0:
            status = "✓ DETECTED"
        else:
            status = "✗ MISSED"
        
        print(f"{i:<5} {flow:<50} {gt_count:<15,} {sketch_count:<15,} {rel_error:<9.1%} {status:<10}")
    
    # Show false positives
    if false_positives:
        print(f"\n{'='*80}")
        print(f"FALSE POSITIVES (flows not in top-{top_k})")
        print(f"{'='*80}")
        print(f"{'Flow':<50} {'BubbleSketch Count':<20} {'Actual Count':<15}")
        print(f"{'-'*85}")
        
        for flow in sorted(false_positives, key=lambda x: sketch_flows[x], reverse=True)[:20]:
            sketch_count = sketch_flows[flow]
            actual_count = ground_truth.get(flow, 0)
            print(f"{flow:<50} {sketch_count:<20,} {actual_count:<15,}")
    
    return {
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'true_positives': len(true_positives),
        'false_negatives': len(false_negatives),
        'false_positives': len(false_positives),
    }


def main():
    parser = argparse.ArgumentParser(
        description='Calculate BubbleSketch accuracy against ground truth'
    )
    parser.add_argument('--sketch', required=True, 
                       help='BubbleSketch output file (from loader)')
    parser.add_argument('--pcap', required=True,
                       help='PCAP file for ground truth')
    parser.add_argument('--top', type=int, default=10,
                       help='Top-K flows to evaluate (default: 10)')
    
    args = parser.parse_args()
    
    print("Loading BubbleSketch results...")
    sketch_flows = parse_sketch_output(args.sketch)
    
    print("Parsing PCAP for ground truth...")
    ground_truth = parse_pcap_ground_truth(args.pcap)
    
    print("\nCalculating accuracy metrics...")
    metrics = calculate_metrics(sketch_flows, ground_truth, args.top)
    
    print(f"\n{'='*80}")
    print(f"SUMMARY")
    print(f"{'='*80}")
    print(f"Top-{args.top} Detection Rate: {metrics['true_positives']}/{args.top} = {metrics['recall']:.1%}")
    print(f"Overall F1-Score:         {metrics['f1_score']:.1%}")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
