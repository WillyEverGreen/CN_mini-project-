# PacketGuard: Network Firewall Simulation & Packet Filtering Engine

A simulation of a **Layer 3 / Layer 4 Stateful Packet-Filtering Firewall** built for the **Computer Networks (CN) Mini Project**.

Demonstrates real-time network packet routing, security rule evaluation, stateful connection tracking, and packet deflection between client, router, switch, firewall, and server nodes.

---

## 1. Project Overview & Architecture

In enterprise and perimeter networks, firewalls inspect incoming and outgoing packets against an ordered security policy to protect internal infrastructure from unauthorized access and cyber threats.

### Network Topology
```
                     ┌──────────────────┐
                     │  Internet Cloud  │ (8.8.8.8)
                     └────────┬─────────┘
                              │
                     ┌────────┴─────────┐
                     │      Router      │ (203.0.113.1)
                     └────────┬─────────┘
                              │
                     ┌────────┴─────────┐
                     │     Firewall     │ (192.168.1.1) ──► [BLOCKED Deflection]
                     └────────┬─────────┘
                              │
                     ┌────────┴─────────┐
                     │      Switch      │ (192.168.1.2)
                     └───┬──────────┬───┘
                         │          │
        ┌────────────────┴─┐      ┌─┴────────────────┐
        │   Client Node    │      │   Server Rack    │
        │  (192.168.1.50)  │      │   (10.0.0.10)    │
        └──────────────────┘      └──────────────────┘
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
| **Web HTTP** | Sends `GET / HTTP/1.1` to port 80. | Click `Web HTTP` ➔ `Send Request`. Watch packet flow Client ➔ Switch ➔ Firewall (Allowed) ➔ Server ➔ Return `200 OK` (2.4 KB) back to Client. |
| **SSH Block** | Tests port 22 access. | Click `SSH` ➔ `Send Request`. Watch packet reach the Firewall and deflect onto the red deflection arc with `BLOCKED: Port 22 (SSH) Rule #2`. |
| **DNS Lookup** | Queries `8.8.8.8` via UDP port 53. | Click `DNS Query` ➔ `Send Request`. Packet routes through Firewall ➔ Router ➔ Internet Cloud, returning a resolved IP. |
| **Port Scan (Nmap)** | Sweeps ports 21, 22, 23, 80, 443, 3306. | Select `Port Scan` ➔ `Send Request`. Demonstrates sequential port testing, displaying which services are open vs. filtered. |
| **Deep Packet Inspector** | Wireshark-like 5-tuple modal. | Click on any traveling packet or row in the **Packet Flow Timeline** to view Ethernet, IP, TCP/UDP headers, and the matching rule trace. |
| **Rule Management** | Live rule editing. | Click `+ Add Rule` to create custom rules, or toggle `✓ / ⊘` to enable/disable rules and observe immediate traffic changes. |

---

## 4. How to Run

### Method 1: Double-Click (Recommended)
Double-click `run.bat` in the project folder. It automatically detects your installed Python environment (`py`, `python`, or `python3`) or launches directly in your browser.

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
Runs 17/17 automated test assertions validating 5-tuple filtering, CIDR math, port ranges, and stateful tracking.

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
