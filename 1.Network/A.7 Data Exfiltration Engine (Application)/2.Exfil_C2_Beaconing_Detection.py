"""
EXFIL / C2 DETECTION ENGINE v6
==============================
Improved version with:
- Full CLI support (argparse)
- Better documentation and modular structure
- Enhanced error handling
- Maintained all v5 features (pivot host detection, etc.)

Original author: Enhanced from v5 by Grok (xAI)
"""

import subprocess
import csv
import io
import math
import ipaddress
import shutil
import os
import sys
import argparse
from collections import defaultdict
from statistics import mean, pstdev

import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="EXFIL / C2 Detection Engine v6")
    parser.add_argument("pcap", nargs="?", default="/media/sf_Megha/2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap",
                        help="Path to the PCAP file to analyze")
    parser.add_argument("--min-peers", type=int, default=3,
                        help="Minimum number of internal peers for pivot host detection (default: 3)")
    parser.add_argument("--output", default="exfil_v6_graph.png",
                        help="Output filename for the network graph (default: exfil_v6_graph.png)")
    return parser.parse_args()


# ----------------------------
# HELPERS
# ----------------------------
def is_private(ip_str):
    """Return True if ip_str is a private/internal address."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def run_tshark(pcap):
    """Run tshark to extract relevant fields from PCAP."""
    if shutil.which("tshark") is None:
        sys.exit("[!] tshark not found on PATH. Install Wireshark/tshark first.")

    if not os.path.isfile(pcap):
        sys.exit(f"[!] Capture file not found: {pcap}")

    print(f"[+] Extracting traffic from {pcap}...")

    FIELDS = [
        "frame.time_epoch", "ip.src", "ip.dst", "frame.len",
        "tcp.srcport", "tcp.dstport",
        "http.request.method", "http.host",
        "dns.qry.name", "dns.qry.type",
        "smb2.tree", "smb2.filename",
        "ntlmssp.auth.username",
        "dcerpc.cn_call_id",
        "tls.handshake.extensions_server_name",
        "tls.handshake.type",
    ]

    cmd = [
        "tshark", "-r", pcap,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd += ["-Y", "http || dns || smb || smb2 || ntlmssp || dcerpc || tls.handshake.type==1"]

    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.PIPE).decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] tshark failed: {e.stderr.decode(errors='ignore')}")

    reader = csv.reader(io.StringIO(raw))
    rows = [r for r in reader if len(r) == len(FIELDS)]

    if not rows:
        sys.exit("[!] No matching packets found.")

    df = pd.DataFrame(rows, columns=[
        "time", "src", "dst", "size", "sport", "dport",
        "http_m", "http_h", "dns", "dns_t",
        "smb_tree", "file", "user", "rpc", "sni", "tls_type"
    ])

    df["time"] = pd.to_numeric(df["time"], errors="coerce")
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0)

    print(f"[+] Parsed {len(df)} relevant packets.")
    return df


def detect_signals(r):
    """Detect per-packet signals."""
    sig = set()

    # DNS
    if r["dns"]:
        qname = r["dns"]
        ent = shannon_entropy(qname.split(".")[0])
        if len(qname) > 50 and ent > 3.3:
            sig.add("DNS_TUNNEL_CANDIDATE")
        else:
            sig.add("RECON_DNS")

    # HTTP
    if r["http_m"]:
        if r["http_m"] in ("POST", "PUT"):
            sig.add("HTTP_UPLOAD")
        else:
            sig.add("HTTP_BEACON_CANDIDATE")

    # TLS ClientHello
    if r["tls_type"] == "1" and r["sni"]:
        sig.add("TLS_CLIENTHELLO")

    # SMB lateral movement
    tree = str(r["smb_tree"])
    if "IPC$" in tree:
        sig.add("SMB_IPC_LATERAL")
    if "ADMIN$" in tree or "C$" in tree:
        sig.add("SMB_ADMIN_LATERAL")

    # DCERPC
    if r["rpc"]:
        sig.add("DCERPC_EXEC")

    # NTLM
    if r["user"]:
        sig.add("NTLM_AUTH")

    # File activity
    if r["file"]:
        if "upload" in str(r["file"]).lower():
            sig.add("POSSIBLE_UPLOAD")
        else:
            sig.add("FILE_ACTIVITY")

    return sig


def build_flows(df):
    """Build directional flows from dataframe."""
    flows = defaultdict(lambda: {
        "bytes_total": 0.0,
        "bytes_internal_out": 0.0,
        "signals": set(),
        "timestamps": [],
        "dns_queries": [],
    })

    for _, r in df.iterrows():
        src, dst = r["src"], r["dst"]
        if not src or not dst:
            continue

        k = (src, dst)
        flows[k]["bytes_total"] += r["size"]
        flows[k]["signals"].update(detect_signals(r))

        if not pd.isna(r["time"]):
            flows[k]["timestamps"].append(r["time"])
        if r["dns"]:
            flows[k]["dns_queries"].append(r["dns"])

        if is_private(src) and not is_private(dst):
            flows[k]["bytes_internal_out"] += r["size"]

    return flows


def analyze_flows(flows, min_peers=3):
    """Perform aggregate analysis and pivot detection."""
    for k, v in flows.items():
        # Beacon regularity
        ts = sorted(v["timestamps"])
        if len(ts) >= 5:
            deltas = [b - a for a, b in zip(ts[:-1], ts[1:]) if b > a]
            if len(deltas) >= 4:
                m = mean(deltas)
                if m > 0:
                    cov = pstdev(deltas) / m
                    if cov < 0.15:
                        v["signals"].add("BEACON_REGULAR")

        # DNS tunneling
        if len(v["dns_queries"]) >= 5:
            ents = [shannon_entropy(q.split(".")[0]) for q in v["dns_queries"]]
            lens = [len(q) for q in v["dns_queries"]]
            if mean(ents) > 3.3 and mean(lens) > 40:
                v["signals"].add("DNS_TUNNEL")

        # Promote HTTP beacon
        if "HTTP_BEACON_CANDIDATE" in v["signals"] and "BEACON_REGULAR" in v["signals"]:
            v["signals"].add("HTTP_BEACON_CONFIRMED")
        v["signals"].discard("HTTP_BEACON_CANDIDATE")
        v["signals"].discard("DNS_TUNNEL_CANDIDATE")

    # Pivot host detection
    EXTERNAL_C2_SIGNALS = {"HTTP_UPLOAD", "DNS_TUNNEL", "BEACON_REGULAR",
                           "HTTP_BEACON_CONFIRMED", "TLS_CLIENTHELLO"}
    LATERAL_SIGNALS = {"SMB_ADMIN_LATERAL", "SMB_IPC_LATERAL", "DCERPC_EXEC"}

    has_external_c2 = set()
    lateral_peers = defaultdict(set)

    for (src, dst), v in flows.items():
        if is_private(src) and not is_private(dst) and (v["signals"] & EXTERNAL_C2_SIGNALS):
            has_external_c2.add(src)
        if v["signals"] & LATERAL_SIGNALS:
            lateral_peers[src].add(dst)
            lateral_peers[dst].add(src)

    pivot_hosts = {h for h in has_external_c2 if len(lateral_peers.get(h, set())) >= min_peers}

    if pivot_hosts:
        print("\n🚨 PIVOT HOST(S) DETECTED:")
        for h in sorted(pivot_hosts):
            peers = sorted(lateral_peers[h])
            print(f"   {h} -> lateral to {len(peers)} hosts: {', '.join(peers)}")
    else:
        print("\n[i] No pivot hosts detected.")

    return pivot_hosts, flows


def score_flow(src, dst, bytes_internal_out, signals, pivot_hosts):
    """Score a flow based on signals and context."""
    score = 0

    # Volume
    if bytes_internal_out > 500_000:
        score += 25
    elif bytes_internal_out > 100_000:
        score += 15
    elif bytes_internal_out > 10_000:
        score += 5

    weights = {
        "DNS_TUNNEL": 35, "HTTP_UPLOAD": 20, "HTTP_BEACON_CONFIRMED": 15,
        "BEACON_REGULAR": 15, "TLS_CLIENTHELLO": 5,
        "SMB_ADMIN_LATERAL": 10, "SMB_IPC_LATERAL": 10, "DCERPC_EXEC": 8,
        "NTLM_AUTH": 3, "POSSIBLE_UPLOAD": 10, "FILE_ACTIVITY": 2, "RECON_DNS": 1,
    }
    for s in signals:
        score += weights.get(s, 0)

    if is_private(src) and not is_private(dst):
        score += 10

    if src in pivot_hosts or dst in pivot_hosts:
        score += 25

    return min(score, 100)


def generate_graph(flows, pivot_hosts, output_file):
    """Generate and save network graph."""
    G = nx.DiGraph()
    for (src, dst), v in flows.items():
        G.add_edge(src, dst,
                   bytes=v["bytes_internal_out"],
                   signals=",".join(sorted(v["signals"])))

    if G.number_of_edges() == 0:
        print("\n[!] Graph is empty.")
        return

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.8, seed=42)

    node_colors = ["red" if n in pivot_hosts else "lightblue" for n in G.nodes()]

    nx.draw(G, pos, with_labels=True, node_size=2200, font_size=7,
            arrows=True, node_color=node_colors)

    edge_labels = {
        (u, v): (d["signals"][:35] + "…") if len(d["signals"]) > 35 else d["signals"]
        for u, v, d in G.edges(data=True) if d.get("signals")
    }
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    plt.title("EXFIL/C2 ENGINE v6 (red = pivot hosts)")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"\n[+] Graph saved: {output_file}")
    # plt.show()  # Uncomment if running interactively


def main():
    args = parse_arguments()

    df = run_tshark(args.pcap)
    flows = build_flows(df)
    pivot_hosts, flows = analyze_flows(flows, args.min_peers)

    print("\n🔥 EXFIL / C2 DETECTION RESULTS:\n")
    results = []
    for (src, dst), v in flows.items():
        signals = sorted(v["signals"])
        score = score_flow(src, dst, v["bytes_internal_out"], signals, pivot_hosts)
        results.append((score, src, dst, signals, v["bytes_total"], v["bytes_internal_out"]))

    for score, src, dst, signals, bytes_total, bytes_out in sorted(results, reverse=True):
        if score >= 60:
            label = "🔴 HIGH CONFIDENCE EXFIL/C2"
        elif score >= 30:
            label = "🟡 SUSPICIOUS"
        else:
            label = "🔵 NORMAL / RECON"

        pivot_tag = "  [PIVOT HOST INVOLVED]" if (src in pivot_hosts or dst in pivot_hosts) else ""
        print(label + pivot_tag)
        print(f"{src} -> {dst}")
        print(f"Score: {score}")
        print(f"Signals: {','.join(signals) if signals else '(none)'}")
        print(f"Total bytes: {int(bytes_total)} | Internal->External: {int(bytes_out)}\n")

    # Top senders
    talkers = defaultdict(float)
    for (src, dst), v in flows.items():
        talkers[src] += v["bytes_internal_out"]
    talkers = {k: v for k, v in talkers.items() if v > 0}

    print("\n📊 TOP INTERNAL HOSTS SENDING DATA EXTERNALLY:\n")
    if talkers:
        for k, v in sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:10]:
            tag = " [PIVOT HOST]" if k in pivot_hosts else ""
            print(f"🔥 {k} -> {int(v)} bytes{tag}")
    else:
        print("(none)")

    generate_graph(flows, pivot_hosts, args.output)


if __name__ == "__main__":
    main()
