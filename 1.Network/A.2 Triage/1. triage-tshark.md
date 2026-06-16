# A.2 · Triage Pass — tshark Command Guide
### Project KAVACH | Workstream A | Trickbot + Cobalt Strike PCAP

> **Analyst Role:** Network Traffic Analyst | Tool: tshark (CLI)
> **Document Version:** v1.0 | Sprint 2–3

---

## What is tshark?

**tshark** is the command-line version of Wireshark. It reads `.pcap` files and lets you extract statistics, filter traffic, and produce structured output — all from a terminal, without opening a GUI.

**Why use tshark alongside Wireshark?**
- Faster for large PCAPs — no GUI rendering overhead
- Scriptable and repeatable — important for reproducible forensics
- Works over SSH on headless or remote machines
- Output can be piped into `awk`, `sort`, `grep` for deeper analysis
- Every command is a one-liner you can paste into your notes as evidence

**Basic syntax:**
```bash
tshark -r <file.pcap> [options]
```

| Flag | Purpose |
|------|---------|
| `-r` | Read from a PCAP file |
| `-q` | Quiet mode — suppress per-packet output (always use with `-z`) |
| `-z` | Statistics module (e.g. `io,phs`, `conv,ip`, `endpoints,ipv4`) |
| `-T fields` | Output specific fields only |
| `-e` | Field name to extract (used with `-T fields`) |
| `2>/dev/null` | Suppress tshark version warnings in output |

**PCAP used throughout this guide:**
```
2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap
```
All commands below use this filename. Replace it with your actual path if it differs.

---

## Section 1 · Protocol Distribution

### What is Protocol Distribution?

Protocol distribution shows which network protocols are present in the capture and how much traffic each one accounts for — by packet count and by bytes. tshark's `io,phs` module produces the same protocol hierarchy tree as Wireshark's Statistics → Protocol Hierarchy, but outputs it directly to the terminal for scripting and logging.

---

### Command 1 — Full Protocol Hierarchy

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z io,phs 2>/dev/null
```

**What it does:** Outputs the complete protocol hierarchy tree — every protocol present in the capture with its frame count, byte count, and percentage of total traffic.

**What to look for:** Any protocol carrying a disproportionately high byte percentage relative to its frame percentage — in this PCAP, HTTP is 1.08% of frames but 41.2% of bytes, which is a strong exfiltration signal.

<div align="center">
<table>
<tr>
<td><img src="./Evidences/t_1.1.png" alt="tshark - Protocol Hierarchy (Part 1)" width="100%"></td>
<td><img src="./Evidences/t_1.2.png" alt="tshark - Protocol Hierarchy (Part 2)" width="100%"></td>
</tr>
</table>

*Fig. 1: tshark Protocol Hierarchy Statistics — full output split across two views for readability*

</div>
---

### Command 2 — Top 20 Protocols by Frame Percentage

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z io,phs 2>/dev/null \
| awk '/^frame[[:space:]]/ {total=$2; sub(/frames:/,"",total)} \
       /^[[:space:]]+[a-z]/ { if(total>0) { frames=$2; sub(/frames:/,"",frames); \
       printf "%6.2f%%   %s\n", (frames/total)*100, $0 } }' \
| head -20
```

**What it does:** Calculates each protocol's percentage of total frames and prints the top 20 in a ranked summary — useful when the full hierarchy is too long to scan visually.

<!-- IMAGE-02: Terminal output of the protocol percentage awk pipeline showing top 20 protocols ranked by % of frames -->
<p align="center">
  <img src="./Evidences/t_2.png" alt="tshark - Protocol Hierarchy top 20 ranked" width="80%"><br>
  <em>Fig. 2: tshark Protocol Hierarchy — top 20 protocols ranked by % of total frames</em>
</p>


## Section 2 · Endpoints

### What are Endpoints?

An endpoint is any device on the network sending or receiving traffic — identified by IP address (Layer 3), MAC address (Layer 2), or IP:Port pair (Layer 4). tshark's `endpoints` module extracts these across multiple layers in one command.

---

### Command 3 — IPv4 Endpoints

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z endpoints,ipv4 2>/dev/null
```

**What it does:** Lists every IPv4 address seen in the capture along with the number of packets and bytes it transmitted and received. This is the primary view for identifying the victim host and suspicious external IPs.

<!-- IMAGE-03: Terminal output of tshark endpoints,ipv4 showing IP addresses with Tx/Rx packet and byte counts -->
<p align="center">
  <img src="./Evidences/t_3.png" alt="tshark - IPv4 Endpoints output" width="80%"><br>
  <em>Fig. 3: tshark IPv4 Endpoints — Tx/Rx packet and byte counts per IP address</em>
</p>
---

### Command 4 — Ethernet (MAC) Endpoints

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z endpoints,eth 2>/dev/null
```

**What it does:** Lists all MAC addresses (Layer 2) seen in the capture. Useful for identifying the physical network interface of the victim machine and any gateway/router MACs.

<!-- IMAGE-04: Terminal output of tshark endpoints,eth showing MAC addresses with traffic counts -->
<p align="center">
  <img src="./Evidences/t_4.png" alt="tshark - Ethernet MAC Endpoints output" width="80%"><br>
  <em>Fig. 4: tshark Ethernet MAC Endpoints — traffic counts per MAC address</em>
</p>

---

### Command 5 — TCP Endpoints (IP:Port pairs)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z endpoints,tcp 2>/dev/null
```

**What it does:** Lists IP:Port pairs — shows which specific ports on which hosts were active. Useful for spotting unusual destination ports used by malware (e.g. C2 over port 443 but with non-TLS traffic).

<!-- IMAGE-05: Terminal output of tshark endpoints,tcp showing IP:Port pairs with traffic counts -->
<p align="center">
  <img src="./Evidences/t_5.png" alt="tshark - TCP Endpoints output" width="80%"><br>
  <em>Fig. 5: tshark TCP Endpoints — traffic counts per IP:Port pair</em>
</p>

---

### Command 6 — UDP Endpoints

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z endpoints,udp 2>/dev/null
```

**What it does:** Lists all UDP endpoints. Particularly useful for DNS analysis — DNS runs over UDP/53 and C2 channels frequently abuse it.

<!-- IMAGE-06: Terminal output of tshark endpoints,udp showing UDP IP:Port pairs — focus on port 53 DNS entries -->
<p align="center">
  <img src="./Evidences/t_6.png" alt="tshark - UDP Endpoints output" width="80%"><br>
  <em>Fig. 6: tshark UDP Endpoints — IP:Port pairs (focus on port 53 DNS entries)</em>
</p>

---

## Section 3 · Conversations

### What are Conversations?

A conversation is a two-way communication exchange between two specific endpoints. tshark's `conv` module extracts all conversations per protocol layer and reports their frame count, byte totals, and duration.

```
IP A  ↔  IP B  =  one conversation
10.5.26.132  ↔  192.236.155.230  =  one conversation
```

---

### Command 7 — IPv4 Conversations

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z conv,ipv4 2>/dev/null
```

**What it does:** Lists all IP-to-IP conversations with frame counts, byte totals, and duration. The Duration column is particularly important — long-lived sessions between an internal and external IP often indicate C2 beaconing.

<!-- IMAGE-07: Terminal output of tshark conv,ipv4 showing all IP pairs with frame count, bytes, and duration -->
<p align="center">
  <img src="./Evidences/t_7.png" alt="tshark - IPv4 Conversations output" width="80%"><br>
  <em>Fig. 7: tshark IPv4 Conversations — IP pairs with frame count, bytes, and duration</em>
</p>

---

### Command 8 — TCP Conversations

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z conv,tcp 2>/dev/null
```

**What it does:** Lists all TCP sessions (IP:Port ↔ IP:Port), with frame counts, byte totals, and duration per session. More granular than IPv4 conversations — shows the exact port used in each connection.

<!-- IMAGE-08: Terminal output of tshark conv,tcp showing all TCP sessions with ports, bytes, and duration -->
<p align="center">
  <img src="./Evidences/t_8.png" alt="tshark - TCP Conversations output" width="80%"><br>
  <em>Fig. 8: tshark TCP Conversations — sessions with ports, bytes, and duration</em>
</p>

---

### Command 9 — Top 10 Conversations by Bytes (Unit-Normalised)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z conv,ip 2>/dev/null \
| grep "<->" | tr -d ',' \
| awk '{
    val=$11; unit=$12;
    if (unit == "MB") val = val * 1048576;
    else if (unit == "kB") val = val * 1024;
    print val, $1, $2, $3
}' | sort -k1 -rn | head -10
```

**What it does:** Extracts all conversations, converts all byte values to raw bytes (normalising MB and kB to the same unit), sorts by total bytes, and returns the top 10 heaviest conversations.

**Why this instead of basic sort:** tshark outputs conversation bytes in mixed units (some rows say "1.2 MB", others say "900 kB"). A naive sort would rank "900 kB" above "1 MB" — this pipeline normalises everything to bytes first.

**Pipeline breakdown:**
```
tshark → full conversations table
   ↓
grep "<->"  → keep only conversation rows (remove header/footer lines)
   ↓
tr -d ','   → strip commas from numbers (e.g. 1,024 → 1024)
   ↓
awk         → convert kB / MB values to raw bytes for consistent comparison
   ↓
sort -k1 -rn → sort by first column (bytes) numerically, descending
   ↓
head -10    → show only the top 10 results
```

<!-- IMAGE-09: Terminal output of the unit-normalised top-10 conversations pipeline showing heaviest IP pairs by bytes -->
<p align="center">
  <img src="./Evidences/t_9.png" alt="tshark - Top 10 Conversations by Bytes (normalised)" width="60%"><br>
  <em>Fig. 9: tshark Top 10 Conversations by Bytes — unit-normalised, heaviest IP pairs</em>
</p>

---

## Section 4 · Top Talkers

### What are Top Talkers?

Top talkers are the IP addresses generating the most total traffic in the capture — measured by combined sent and received bytes. tshark extracts raw frame lengths per IP and aggregates them with awk.

---

### Command 10 — Top 10 IPs by Total Bytes (Sent + Received)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -T fields -e ip.src -e ip.dst -e frame.len 2>/dev/null \
| awk '{bytes[$1]+=$3; bytes[$2]+=$3} END {for (ip in bytes) print bytes[ip], ip}' \
| sort -rn | head -10
```

**What it does:** For every packet, adds the frame length to both the source IP's total and the destination IP's total. This gives a true combined-traffic score — an IP that sends 5 MB and receives 5 MB scores 10 MB total, accurately reflecting its network footprint.

<!-- IMAGE-10: Terminal output showing top 10 IPs ranked by combined sent + received bytes -->
<p align="center">
  <img src="./Evidences/t_10.PNG" alt="tshark - Top 10 IPs by Total Bytes" width="80%"><br>
  <em>Fig. 10: tshark Top 10 IPs by Total Bytes — combined sent + received</em>
</p>

---

### Command 11 — Top 10 IPs by Outbound Bytes (Source Only)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -T fields -e ip.src -e frame.len 2>/dev/null \
| awk '{bytes[$1]+=$2} END {for (ip in bytes) print bytes[ip], ip}' \
| sort -rn | head -10
```

**What it does:** Counts only bytes where the IP is the *source* — i.e. bytes sent outbound. A high score here from an internal IP to an external destination is a strong data exfiltration signal.

<!-- IMAGE-11: Terminal output showing top 10 source IPs ranked by outbound bytes sent -->
<p align="center">
  <img src="./Evidences/t_11.png" alt="tshark - Top 10 IPs by Outbound Bytes" width="80%"><br>
  <em>Fig. 11: tshark Top 10 IPs by Outbound Bytes — source IPs ranked by bytes sent</em>
</p>

## Section 5 · Time Bounds

### What are Time Bounds?

Time bounds define the start and end timestamps of the capture. tshark gives multiple ways to extract these — from a quick one-liner to the full `capinfos` summary.

---

### Command 12 — First Packet Timestamp (Start Time)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -T fields -e frame.time 2>/dev/null | head -1
```

**What it does:** Prints the human-readable timestamp of the very first packet in the capture — your incident start time.

<!-- IMAGE-12: Terminal output showing the first packet timestamp from frame.time | head -1 -->
<p align="center">
  <img src="./Evidences/t_12.png" alt="tshark - First Packet Timestamp" width="80%"><br>
  <em>Fig. 12: tshark First Packet Timestamp — frame.time | head -1</em>
</p>

---

### Command 13 — Last Packet Timestamp (End Time)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -T fields -e frame.time 2>/dev/null | tail -1
```

**What it does:** Prints the human-readable timestamp of the very last packet — your incident end time.

<!-- IMAGE-13: Terminal output showing the last packet timestamp from frame.time | tail -1 -->
<p align="center">
  <img src="./Evidences/t_13.png" alt="tshark - Last Packet Timestamp" width="80%"><br>
  <em>Fig. 13: tshark Last Packet Timestamp — frame.time | tail -1</em>
</p>

---

### Command 14 — Start + End + Duration in One Command

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -T fields -e frame.time_epoch 2>/dev/null \
| awk 'NR==1{start=$1} END{end=$1; diff=end-start; \
  printf "Start epoch : %s\nEnd epoch   : %s\nDuration    : %.2f seconds (%.2f minutes)\n", \
  start, end, diff, diff/60}'
```

**What it does:** Extracts Unix epoch timestamps for the first and last packet, then calculates the capture duration in both seconds and minutes. More precise than human-readable timestamps for arithmetic.

<!-- IMAGE-14: Terminal output showing start epoch, end epoch, and calculated duration in seconds and minutes -->
<p align="center">
  <img src="./Evidences/t_14.png" alt="tshark - Start + End + Duration via epoch awk" width="80%"><br>
  <em>Fig. 14: tshark Start + End + Duration — calculated via epoch awk pipeline</em>
</p>

---

### Command 15 — Full Summary (Frames + Bytes + Duration)

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z io,stat,0 2>/dev/null
```

**What it does:** Produces a single-interval summary of the entire capture — total frames, total bytes, and total duration in one output block. The `0` argument means "treat the whole capture as one interval."

<!-- IMAGE-15: Terminal output of tshark -z io,stat,0 showing total frames, bytes, and full capture duration -->
<p align="center">
  <img src="./Evidences/t_15.png" alt="tshark - Full Capture Summary io,stat,0" width="80%"><br>
  <em>Fig. 15: tshark Full Capture Summary — total frames, bytes, and duration (io,stat,0)</em>
</p>

---

### Command 16 — capinfos (Fastest & Most Complete)

```bash
capinfos 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap
```

**What it does:** Dumps complete file metadata in one shot — start time, end time, duration, interface info, packet count, file size, data rate, and hash values. This is the fastest single-command way to establish time bounds and PCAP provenance.

> **Note:** `capinfos` ships with Wireshark/tshark. If it is not found, install the `wireshark-common` package on Kali.

<!-- IMAGE-16: Terminal output of capinfos showing all metadata fields including start time, end time, duration, and packet count -->
<p align="center">
  <img src="./Evidences/t_16.png" alt="tshark - capinfos full metadata output" width="80%"><br>
  <em>Fig. 16: capinfos Full Metadata — start time, end time, duration, and packet count</em>
</p>

## Section 6 · Anomalous Bursts

### What are Anomalous Bursts?

Anomalous bursts are sudden, sharp spikes in traffic volume that deviate significantly from the established baseline. tshark's `io,stat` module divides the capture into fixed-size time intervals and reports frames and bytes per interval — making burst windows immediately visible as rows with much higher values than surrounding rows.

> **Key finding in this PCAP:** The 300–600 s interval contains 10,123 frames and 7.96 MB. The 600–900 s interval contains 7,874 frames and 7.04 MB. The baseline (0–300 s) is only 966 frames and 230 kB — so these burst windows carry approximately **10× the baseline traffic**, which directly corresponds to the Trickbot payload download and Cobalt Strike C2 beaconing onset.

---

### Command 17 — Traffic per 300-Second Interval

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap -q -z io,stat,300 2>/dev/null
```

**What it does:** Divides the full ~80-minute capture into 300-second (5-minute) buckets and shows frames and bytes per bucket. Burst windows appear as rows with values many times higher than the surrounding rows.

**Expected output pattern for this PCAP:**
```
│ Interval      │ Frames │  Bytes  │  Notes                     │
│───────────────│────────│─────────│────────────────────────────│
│    0 <>  300  │    966 │  230 kB │  ← Baseline (normal)       │
│  300 <>  600  │ 10,123 │ 7.96 MB │  ← *** PRIMARY BURST ***   │
│  600 <>  900  │  7,874 │ 7.04 MB │  ← *** PRIMARY BURST ***   │
│  900 <> 1200  │    419 │   64 kB │  ← Returns to normal       │
│ 4200 <> 4500  │  1,999 │ 1.16 MB │  ← Secondary burst (C2)    │
```

<!-- IMAGE-17: Terminal output of tshark -z io,stat,300 showing the full interval table with burst rows visible -->
<p align="center">
  <img src="./Evidences/t_17.png" alt="tshark - io,stat,300 interval table" width="80%"><br>
  <em>Fig. 17: tshark io,stat,300 — interval table showing traffic burst rows</em>
</p>

---

### Command 18 — Burst Filtered by Specific Suspected C2 IP

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -q -z io,stat,300,ip.addr==192.236.155.230 2>/dev/null
```

**What it does:** Applies a display filter (`ip.addr==192.236.155.230`) inside the `io,stat` module so only traffic involving that specific IP is counted per interval. Directly answers the question: "Did this burst come from communication with the suspected C2 IP?"

> Replace `192.236.155.230` with the IP you are investigating.

<!-- IMAGE-18: Terminal output of tshark -z io,stat,300 filtered by C2 IP showing traffic attributable to that IP per interval -->
<p align="center">
  <img src="./Evidences/t_18.png" alt="tshark - io,stat,300 filtered by suspected C2 IP" width="75%"><br>
  <em>Fig. 18: tshark io,stat,300 filtered by suspected C2 IP — per-interval traffic attribution</em>
</p>

---


## Master Command Reference

| # | Section | Command Summary | Purpose |
|---|---------|----------------|---------|
| 1 | Protocol | `-q -z io,phs` | Full protocol hierarchy |
| 2 | Protocol | `-q -z io,phs \| awk ... \| head -20` | Top 20 protocols by frame % |
| 3 | Endpoints | `-q -z endpoints,ipv4` | All IPv4 endpoints |
| 4 | Endpoints | `-q -z endpoints,eth` | All MAC (Ethernet) endpoints |
| 5 | Endpoints | `-q -z endpoints,tcp` | All TCP IP:Port endpoints |
| 6 | Endpoints | `-q -z endpoints,udp` | All UDP endpoints (DNS focus) |
| 7 | Conversations | `-q -z conv,ipv4` | All IPv4 conversations |
| 8 | Conversations | `-q -z conv,tcp` | All TCP conversations |
| 9 | Conversations | `-q -z conv,ip \| grep \| awk \| sort \| head -10` | Top 10 convs by bytes (normalised) |
| 10 | Top Talkers | `-T fields -e ip.src -e ip.dst -e frame.len \| awk (combined)` | Top 10 IPs by total bytes |
| 11 | Top Talkers | `-T fields -e ip.src -e frame.len \| awk (src only)` | Top 10 IPs by outbound bytes |
| 12 | Time Bounds | `-T fields -e frame.time \| head -1` | First packet timestamp |
| 13 | Time Bounds | `-T fields -e frame.time \| tail -1` | Last packet timestamp |
| 14 | Time Bounds | `-T fields -e frame.time_epoch \| awk (duration calc)` | Start + End + Duration |
| 15 | Time Bounds | `-q -z io,stat,0` | Full capture summary (frames + bytes + duration) |
| 16 | Time Bounds | `capinfos file.pcap` | Complete file metadata (fastest) |
| 17 | Bursts | `-q -z io,stat,300` | Traffic per 5-min interval |
| 18 | Bursts | `-q -z io,stat,60` | Traffic per 1-min interval |
| 19 | Bursts | `-q -z io,stat,10` | Traffic per 10-sec interval |
| 20 | Bursts | `-q -z io,stat,300,ip.addr==X.X.X.X` | Burst filtered by specific IP |
| 21 | Bursts | `-T fields -e frame.time_epoch -e frame.len \| awk (per-sec)` | Raw per-second timeline |

> **Usage notes:**
> - Replace the filename with your actual PCAP path in every command
> - `2>/dev/null` suppresses tshark version warnings — remove for debugging
> - `-q` suppresses per-packet output — always include when using `-z` statistics
> - All commands tested on Kali Linux with tshark 4.x

---

*Triage Pass · tshark CLI Guide · Project KAVACH · Futurense AI Clinic × IIT Roorkee · Confidential*
