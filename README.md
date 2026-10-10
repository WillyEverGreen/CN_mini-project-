# PacketGuard: Network Firewall Simulation & Packet Filtering Engine

A simulation of a **Layer 3 / Layer 4 Stateful Packet-Filtering Firewall** built for the **Computer Networks (CN) Mini Project**.

Demonstrates real-time network packet routing, security rule evaluation, stateful connection tracking, and packet deflection between client, router, switch, firewall, and server nodes.

---

## 1. Project Overview & Architecture

In enterprise and perimeter networks, firewalls inspect incoming and outgoing packets against an ordered security policy to protect internal infrastructure from unauthorized access and cyber threats.

### Network Topology
```
                      ┌──────────────────┐
                      │  Internet Cloud  │ (8.8.8.8 / Live Web)
                      └────────┬─────────┘
                               │
                      ┌────────┴─────────┐
                      │  Gateway Router  │ (203.0.113.1)
                      └────────┬─────────┘
                               │
                      ┌────────┴─────────┐
                      │Firewall(Stateful)│ (192.168.1.1) ──► [BLOCKED Deflection]
                      └────────┬─────────┘
                               │
                      ┌────────┴─────────┐
                      │   Core Switch    │ (192.168.1.2)
                      └───┬──────────┬───┘
         LAN Clients      │          │      DMZ Server Tier
    ┌─────────────────────┴──┐    ┌──┴─────────────────────┐
    │ Client A - Admin (.50) │    │ Web Server (10.0.0.10) │
    │ Client B - Dev   (.51) │    │ DB Server  (10.0.0.20) │
    │ Client C - Rogue (.99) │    │ SSH Bastion(10.0.0.30) │
    └────────────────────────┘    └────────────────────────┘
```

---

## 2. Key Networking Concepts Implemented

### A. The 5-Tuple Packet Structure
Every packet generated and evaluated consists of:
1. **Source IP Address**: e.g., `192.168.1.50`
2. **Destination IP Address**: e.g., `10.0.0.10` or `8.8.8.8`
3. **Source Port**: Ephemeral port range (`49152`–`65535`)
4. **Destination Port**: Standard port (`80` HTTP, `443` HTTPS, `22` SSH, `53` DNS, `3306` MySQL)
5. **Transport Protocol**: `TCP`, `UDP`, or `ICMP`

### B. First-Match Sequential Evaluation Algorithm
Firewall rules are evaluated in strict priority order (Rule #1, Rule #2, Rule #3...):
- The **first rule** where all criteria match determines whether the packet is **ALLOWED** or **DENIED**.
- Evaluation **immediately stops** upon the first match.
- If no user-defined rule matches, the packet falls back to the **Default Policy** (`Default Deny All` / Zero-Trust architecture).

### C. Stateful Connection Tracking (`conntrack`)
- **Stateless vs. Stateful**: While basic firewalls only inspect individual packets in isolation, **PacketGuard** implements stateful tracking for Rule #1 (`Allow established connections`).
- When an outgoing client request is allowed, the firewall registers the session in its internal `connectionTable`.
- Return response packets from the server (`HTTP 200 OK`, `TCP SYN-ACK`, `DNS Response`) automatically match the `ESTABLISHED, RELATED` rule and are permitted without needing insecure open inbound ports.

---

## 3. Interactive Features & Demo Guide

| Feature | Description | How to Demo |
| :--- | :--- | :--- |
| **Multi-Client Routing** | Differentiates traffic by source client. | Select **Client A (Admin)**, **Client B (Dev)**, or **Client C (Rogue)** in the Source dropdown. Observe individual SVG vector paths and policy rules. |
| **Multi-Server Tiers** | Directs requests to specific backend services. | Route to **Web Server (10.0.0.10)**, **Database (10.0.0.20)**, **SSH Bastion (10.0.0.30)**, or **Internet Gateway**. |
| **Live Site Block (google.com)** | Demonstrates Layer 7 domain filtering. | Click `Block Site (Google)` ➔ `Send Request`. Watch packet deflect at Firewall. Click `Inspect Client Browser View` to observe authentic **403 Forbidden Access Intercepted** page. |
| **Live Site Allow (example.com)** | Real-time internet HTTP request fetch. | Click `Allow Site (Live)` ➔ `Send Request`. Packet routes through router to internet. Opens simulated browser with genuine **200 OK** and latency metrics. |
| **Rogue DB Attack Block** | Rogue client isolation demonstration. | Click `Rogue DB Probe` ➔ `Send Request`. Demonstrates Client C (192.168.1.99) blocked from internal MySQL database. |
| **SSH Bastion** | Port 22 SSH access control. | Click `SSH Bastion` ➔ `Send Request`. Verifies default SSH denial per policy Rule #4. |
| **DNS Lookup** | Queries `8.8.8.8` via UDP port 53. | Click `DNS Query` ➔ `Send Request`. Packet routes through Firewall ➔ Router ➔ Internet Cloud, returning a resolved IP. |
| **Port Scan (Nmap)** | Sweeps ports 21, 22, 23, 80, 443, 3306. | Select `Port Scan` ➔ `Send Request`. Demonstrates sequential port testing, displaying open vs filtered ports. |
| **Deep Packet Inspector** | Wireshark-like 5-tuple modal. | Click on any traveling packet or row in the **Packet Flow Timeline** to view Layer 2 Ethernet, Layer 3 IP, Layer 4 TCP/UDP, and Layer 7 Payload headers. |
| **Rule Management** | Live rule editing & domain filters. | Click `+ Add Rule` to create custom rules (including domain filters), or toggle `✓ / ⊘` to enable/disable rules with immediate effect. |

---

## 4. Documentation & Presentation Deliverables

| Deliverable | Location | Description |
| :--- | :--- | :--- |
| **Academic Project Report** | [`report.html`](report.html) / [`REPORT.md`](REPORT.md) | University-grade 8,500-word comprehensive technical report with RFC citations, conntrack state machine, benchmarks, and print-to-PDF formatting. |
| **Slide Presentation Deck** | [`presentation.html`](presentation.html) / [`PRESENTATION.md`](PRESENTATION.md) | 10-slide interactive presentation deck with slide transitions, presenter speaker notes, visual architecture, and fullscreen mode. |
| **Automated Test Suite** | [`test_suite.js`](test_suite.js) | 21/21 Automated unit assertions validating 5-tuple matching, CIDR math, conntrack, multi-client, and live site filtering. |

---

## 5. How to Run

### Method 1: Double-Click (Recommended)
Double-click `run.bat` in the project folder. It automatically starts `server.py` (with live web testing API) and launches in your browser.

### Method 2: Command Line (Python Server)
```bash
py server.py
# or: python server.py
```
Open your browser at:
```
http://localhost:8000
```

### Method 3: Direct Browser Launch (No Server Required)
Simply double-click `index.html` to open directly in Chrome, Edge, Brave, or Firefox.

### Method 4: Run the Automated Test Suite
```bash
node test_suite.js
```
Runs 21/21 automated test assertions validating 5-tuple filtering, CIDR math, port ranges, multi-client isolation, and live site domain filtering.

---

## 5. Deploying to Vercel

The project is fully preconfigured for instant deployment on [Vercel](https://vercel.com):

### Option A: Via Vercel CLI (Fastest)
1. Open PowerShell / Command Prompt in this folder.
2. Run:
   ```bash
   vercel
   ```
   *(Accept the defaults by pressing Enter)*
3. For immediate production deployment:
   ```bash
   vercel --prod
   ```

### Option B: Via GitHub & Vercel Dashboard
1. Push this repository to GitHub.
2. Go to [vercel.com/new](https://vercel.com/new).
3. Import your GitHub repository.
4. Framework Preset: **Other** (Root directory: `./`).
5. Click **Deploy**. Vercel will build and serve your live simulation on a global CDN URL (e.g., `https://packetguard.vercel.app`).

---

## 6. Lab Viva & Examiner Q&A Guide

**Q1: What layer of the OSI model does this firewall operate at?**
> *Answer*: Primarily **Layer 3 (Network Layer)** for IP addresses and routing, and **Layer 4 (Transport Layer)** for TCP/UDP ports and flags. It also supports basic application-layer payload inspection (Layer 7).

**Q2: Why is the rule order critical?**
> *Answer*: Firewalls use **First-Match** semantics. If a broad `ALLOW ALL` rule is placed at Rule #1, any subsequent blocking rules (like `Block SSH`) would never execute. Specific drop rules must precede general allow rules.

**Q3: What is the purpose of Rule #1 (`ESTABLISHED, RELATED`)?**
> *Answer*: It enables **Stateful Packet Inspection (SPI)**. It allows return packets belonging to an existing authorized session to pass back through the firewall without requiring administrators to leave inbound ports permanently open to the internet.

**Q4: What is the difference between Default Allow and Default Deny?**
> *Answer*: **Default Allow (Blacklisting)** permits all traffic unless explicitly blocked—this is vulnerable to unknown threats. **Default Deny (Whitelisting / Zero-Trust)** drops all traffic unless an explicit rule allows it, which is the recommended industry security baseline.
