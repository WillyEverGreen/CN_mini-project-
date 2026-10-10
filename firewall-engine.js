/**
 * PacketGuard Firewall Engine
 * Implements Layer 3 & Layer 4 Stateful Packet Filtering
 * Follows RFC 791 (IPv4), RFC 793 (TCP), RFC 768 (UDP), and iptables First-Match semantics.
 */

class FirewallEngine {
  constructor() {
    // Stateful Connection Tracking Table (conntrack)
    // Key: "srcIp:srcPort->dstIp:dstPort:proto"
    this.connectionTable = new Map();

    // Default Rules matching the PacketGuard specification exactly
    this.rules = [
      {
        id: 'rule-1',
        priority: 1,
        name: 'Allow established connections',
        action: 'ALLOW',
        protocol: 'ANY',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '*',
        state: 'ESTABLISHED, RELATED',
        enabled: true
      },
      {
        id: 'rule-2',
        priority: 2,
        name: 'Block SSH',
        action: 'DENY',
        protocol: 'TCP',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '22',
        state: 'ANY',
        enabled: true
      },
      {
        id: 'rule-3',
        priority: 3,
        name: 'Allow HTTP',
        action: 'ALLOW',
        protocol: 'TCP',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '80',
        state: 'ANY',
        enabled: true
      },
      {
        id: 'rule-4',
        priority: 4,
        name: 'Allow HTTPS',
        action: 'ALLOW',
        protocol: 'TCP',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '443',
        state: 'ANY',
        enabled: true
      },
      {
        id: 'rule-5',
        priority: 5,
        name: 'Allow DNS',
        action: 'ALLOW',
        protocol: 'UDP',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '53',
        state: 'ANY',
        enabled: true
      },
      {
        id: 'rule-6',
        priority: 6,
        name: 'Block common attack ports',
        action: 'DENY',
        protocol: 'TCP',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '23, 25, 139, 445',
        state: 'ANY',
        enabled: true
      },
      {
        id: 'rule-7',
        priority: 7,
        name: 'Default deny all',
        action: 'DENY',
        protocol: 'ANY',
        srcIp: '*',
        dstIp: '*',
        srcPort: '*',
        dstPort: '*',
        state: 'ANY',
        enabled: true
      }
    ];

    this.defaultPolicy = 'DENY';
  }

  // --- IP & Subnet Math (Layer 3) ---

  /** Convert dotted IPv4 address to 32-bit unsigned integer */
  ipToLong(ip) {
    if (!ip || typeof ip !== 'string') return 0;
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return 0;
    return parts.reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
  }

  /** Check if IP matches target CIDR or exact IP */
  matchIp(packetIp, rulePattern) {
    if (!rulePattern || rulePattern === '*' || rulePattern.toLowerCase() === 'any') return true;
    if (!packetIp) return false;

    const pattern = rulePattern.trim();
    if (pattern.includes('/')) {
      // CIDR matching e.g. 192.168.1.0/24
      const [netStr, maskStr] = pattern.split('/');
      const maskBits = parseInt(maskStr, 10);
      if (isNaN(maskBits) || maskBits < 0 || maskBits > 32) return false;

      const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
      const packetLong = this.ipToLong(packetIp);
      const netLong = this.ipToLong(netStr);
      return (packetLong & mask) === (netLong & mask);
    } else {
      // Exact IP match or domain name resolution match
      return packetIp.trim() === pattern;
    }
  }

  // --- Port Matching (Layer 4) ---

  /** Check if port matches single port, comma-separated list, range, or wildcard */
  matchPort(packetPort, rulePattern) {
    if (!rulePattern || rulePattern === '*' || rulePattern.toLowerCase() === 'any') return true;
    if (packetPort === undefined || packetPort === null) return false;

    const portNum = parseInt(packetPort, 10);
    let pattern = rulePattern.toString().trim();

    // Sanitize accidental "*80" or "*79" caused by typing without clearing default asterisk
    if (pattern.startsWith('*') && pattern.length > 1) {
      pattern = pattern.replace(/^\*+/, '').trim();
    }

    // Check comma-separated ports e.g. "23, 25, 139, 445"
    if (pattern.includes(',')) {
      const parts = pattern.split(',').map(p => p.trim());
      for (const p of parts) {
        if (this.matchPort(packetPort, p)) return true;
      }
      return false;
    }

    // Check port range e.g. "1024-65535"
    if (pattern.includes('-')) {
      const [start, end] = pattern.split('-').map(p => parseInt(p.trim(), 10));
      return portNum >= start && portNum <= end;
    }

    // Exact port
    return portNum === parseInt(pattern, 10);
  }

  // --- Protocol Matching (Layer 4 with Layer 7 awareness) ---
  matchProtocol(packetProto, ruleProto) {
    if (!ruleProto || ruleProto === '*' || ruleProto.toUpperCase() === 'ANY') return true;
    const p = (packetProto || '').toUpperCase();
    const r = (ruleProto || '').toUpperCase();
    if (p === r) return true;

    // HTTP, HTTPS, SSH, MySQL, Telnet operate over TCP at Transport Layer (L4)
    const tcpProtocols = ['TCP', 'HTTP', 'HTTPS', 'SSH', 'MYSQL', 'TELNET'];
    if (tcpProtocols.includes(p) && tcpProtocols.includes(r)) return true;

    // DNS operates over UDP at Transport Layer (L4)
    const udpProtocols = ['UDP', 'DNS'];
    if (udpProtocols.includes(p) && udpProtocols.includes(r)) return true;

    return false;
  }

  // --- Stateful Connection Tracking ---
  getConnectionKey(packet) {
    const proto = packet.protocol || 'TCP';
    return `${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}:${proto}`;
  }

  getReverseConnectionKey(packet) {
    const proto = packet.protocol || 'TCP';
    return `${packet.dstIp}:${packet.dstPort}->${packet.srcIp}:${packet.srcPort}:${proto}`;
  }

  updateConnectionState(packet, verdict) {
    if (verdict !== 'ALLOWED') return;

    const fwdKey = this.getConnectionKey(packet);
    const revKey = this.getReverseConnectionKey(packet);

    if (packet.protocol === 'TCP') {
      if (packet.flags && packet.flags.includes('SYN') && !packet.flags.includes('ACK')) {
        // TCP Handshake Step 1: SYN (NEW)
        this.connectionTable.set(fwdKey, { state: 'SYN_SENT', timestamp: Date.now() });
      } else if (packet.flags && packet.flags.includes('SYN') && packet.flags.includes('ACK')) {
        // TCP Handshake Step 2: SYN-ACK (ESTABLISHED)
        this.connectionTable.set(fwdKey, { state: 'ESTABLISHED', timestamp: Date.now() });
        this.connectionTable.set(revKey, { state: 'ESTABLISHED', timestamp: Date.now() });
      } else if (packet.flags && packet.flags.includes('FIN')) {
        // Connection tear-down
        this.connectionTable.delete(fwdKey);
        this.connectionTable.delete(revKey);
      } else {
        // Active data transfer
        this.connectionTable.set(fwdKey, { state: 'ESTABLISHED', timestamp: Date.now() });
        this.connectionTable.set(revKey, { state: 'ESTABLISHED', timestamp: Date.now() });
      }
    } else {
      // UDP / ICMP request-response tracking
      this.connectionTable.set(fwdKey, { state: 'RELATED', timestamp: Date.now() });
      this.connectionTable.set(revKey, { state: 'ESTABLISHED', timestamp: Date.now() });
    }
  }

  isEstablishedOrRelated(packet) {
    const fwdKey = this.getConnectionKey(packet);
    const revKey = this.getReverseConnectionKey(packet);

    const fwd = this.connectionTable.get(fwdKey);
    const rev = this.connectionTable.get(revKey);

    if (fwd && (fwd.state === 'ESTABLISHED' || fwd.state === 'RELATED')) return true;
    if (rev && (rev.state === 'ESTABLISHED' || rev.state === 'RELATED')) return true;
    return false;
  }

  // --- Main First-Match Evaluation Pipeline ---
  evaluatePacket(packet) {
    const trace = [];
    let matchedRule = null;
    let verdict = this.defaultPolicy === 'DENY' ? 'BLOCKED' : 'ALLOWED';

    // Sort active rules by priority
    const sortedRules = [...this.rules]
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      let isMatch = true;
      let failReason = '';

      // 1. Check Connection State
      if (rule.state && rule.state.includes('ESTABLISHED')) {
        if (!this.isEstablishedOrRelated(packet)) {
          isMatch = false;
          failReason = 'Not in ESTABLISHED/RELATED state table';
        }
      }

      // 2. Protocol Check
      if (isMatch && !this.matchProtocol(packet.protocol, rule.protocol)) {
        isMatch = false;
        failReason = `Protocol ${packet.protocol} does not match rule ${rule.protocol}`;
      }

      // 3. Source IP Check
      if (isMatch && !this.matchIp(packet.srcIp, rule.srcIp)) {
        isMatch = false;
        failReason = `Source IP ${packet.srcIp} does not match rule ${rule.srcIp}`;
      }

      // 4. Destination IP Check
      if (isMatch && !this.matchIp(packet.dstIp, rule.dstIp)) {
        isMatch = false;
        failReason = `Destination IP ${packet.dstIp} does not match rule ${rule.dstIp}`;
      }

      // 5. Source Port Check
      if (isMatch && !this.matchPort(packet.srcPort, rule.srcPort)) {
        isMatch = false;
        failReason = `Source port ${packet.srcPort} does not match rule ${rule.srcPort}`;
      }

      // 6. Destination Port Check
      if (isMatch && !this.matchPort(packet.dstPort, rule.dstPort)) {
        isMatch = false;
        failReason = `Destination port ${packet.dstPort} does not match rule ${rule.dstPort}`;
      }

      trace.push({
        ruleId: rule.id,
        rulePriority: rule.priority,
        ruleName: rule.name,
        action: rule.action,
        matched: isMatch,
        reason: isMatch ? 'All 5-tuple and state criteria matched' : failReason
      });

      if (isMatch) {
        matchedRule = rule;
        verdict = rule.action === 'ALLOW' ? 'ALLOWED' : 'BLOCKED';
        break; // First-Match semantics: stop further rule checks!
      }
    }

    // If no rule matched, use default policy
    if (!matchedRule) {
      matchedRule = {
        id: 'default',
        priority: sortedRules.length + 1,
        name: 'Default Policy',
        action: this.defaultPolicy,
        protocol: 'ANY',
        dstPort: '*'
      };
      verdict = this.defaultPolicy === 'ALLOW' ? 'ALLOWED' : 'BLOCKED';
    }

    // Update connection table for stateful tracking if allowed
    this.updateConnectionState(packet, verdict);

    return {
      verdict, // 'ALLOWED' or 'BLOCKED'
      matchedRule,
      trace,
      timestamp: new Date()
    };
  }

  // --- Rule Management Methods ---
  addRule(ruleData) {
    const newPriority = this.rules.length + 1;
    const newRule = {
      id: 'rule-' + Date.now(),
      priority: newPriority,
      name: ruleData.name || 'Custom Rule',
      action: ruleData.action || 'DENY',
      protocol: ruleData.protocol || 'ANY',
      srcIp: ruleData.srcIp || '*',
      dstIp: ruleData.dstIp || '*',
      srcPort: ruleData.srcPort || '*',
      dstPort: ruleData.dstPort || '*',
      state: ruleData.state || 'ANY',
      enabled: true
    };
    this.rules.push(newRule);
    this.reindexPriorities();
    return newRule;
  }

  deleteRule(ruleId) {
    this.rules = this.rules.filter(r => r.id !== ruleId);
    this.reindexPriorities();
  }

  toggleRule(ruleId) {
    const r = this.rules.find(item => item.id === ruleId);
    if (r) r.enabled = !r.enabled;
  }

  reorderRules(fromIndex, toIndex) {
    if (fromIndex < 0 || fromIndex >= this.rules.length || toIndex < 0 || toIndex >= this.rules.length) return;
    const [moved] = this.rules.splice(fromIndex, 1);
    this.rules.splice(toIndex, 0, moved);
    this.reindexPriorities();
  }

  reindexPriorities() {
    this.rules.forEach((r, idx) => {
      r.priority = idx + 1;
    });
  }

  resetRules() {
    this.connectionTable.clear();
  }
}

// Export for browser
window.FirewallEngine = FirewallEngine;
