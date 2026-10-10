/**
 * PacketGuard Network Topology Simulator
 * Accurate, smooth, and deliberately paced packet transmission with dynamic SVG cable anchoring.
 * Fully supports Multi-Client (A, B, C) and Multi-Server (Web, DB, Bastion) topology with live deflection.
 */

class TopologySimulator {
  constructor(stageId, firewallEngine) {
    this.stage = document.getElementById(stageId);
    this.flightLayer = document.getElementById('packetFlightLayer');
    this.firewallBox = document.getElementById('firewallBox');
    this.blockedCard = document.getElementById('blockedDeflectionCard');
    this.deflectReasonText = document.getElementById('deflectReasonText');
    this.engine = firewallEngine;

    // Multi-Client DOM Nodes
    this.clientNodes = {
      '192.168.1.50': document.getElementById('nodeClientA'),
      '192.168.1.51': document.getElementById('nodeClientB'),
      '192.168.1.99': document.getElementById('nodeClientC')
    };

    // Multi-Server DOM Nodes
    this.serverNodes = {
      '10.0.0.10': document.getElementById('nodeServerWeb'),
      '10.0.0.20': document.getElementById('nodeServerDb'),
      '10.0.0.30': document.getElementById('nodeServerBastion')
    };

    // Core Infrastructure Nodes
    this.infraNodes = {
      switch: document.getElementById('nodeSwitch'),
      firewall: document.getElementById('nodeFirewall'),
      router: document.getElementById('nodeRouter'),
      internet: document.getElementById('nodeInternet')
    };

    // Fallbacks for legacy single nodes if present
    this.nodeEls = {
      client: document.getElementById('nodeClientA') || document.getElementById('nodeClient'),
      switch: this.infraNodes.switch,
      firewall: this.infraNodes.firewall,
      server: document.getElementById('nodeServerWeb') || document.getElementById('nodeServer'),
      router: this.infraNodes.router,
      internet: this.infraNodes.internet
    };

    // SVG Cables
    this.cables = {
      // Client to Switch
      clientA_Switch: document.getElementById('cableClientA_Switch'),
      clientB_Switch: document.getElementById('cableClientB_Switch'),
      clientC_Switch: document.getElementById('cableClientC_Switch'),
      legacyClientSwitch: document.getElementById('cableClientSwitch'),

      // Switch to Server
      switch_ServerWeb: document.getElementById('cableSwitch_ServerWeb'),
      switch_ServerDb: document.getElementById('cableSwitch_ServerDb'),
      switch_ServerBastion: document.getElementById('cableSwitch_ServerBastion'),
      legacySwitchServer: document.getElementById('cableSwitchServer'),

      // Core Backbones
      switchFirewall: document.getElementById('cableSwitchFirewall'),
      firewallRouter: document.getElementById('cableFirewallRouter'),
      routerInternet: document.getElementById('cableRouterInternet'),
      blockedArc: document.getElementById('cableBlockedArc')
    };

    this.activePackets = new Set();
    this.isPaused = false;
    this.speedMultiplier = 1.0;

    this.callbacks = {
      onPacketLogged: null,
      onServerActivity: null,
      onRuleHit: null
    };

    this.deflectionTimer = null;

    // Dynamic cable recalculation
    window.addEventListener('resize', () => this.updateCableCoordinates());
    window.addEventListener('orientationchange', () => setTimeout(() => this.updateCableCoordinates(), 250));
    if (typeof ResizeObserver !== 'undefined' && this.stage) {
      const ro = new ResizeObserver(() => this.updateCableCoordinates());
      ro.observe(this.stage);
    }
    setTimeout(() => this.updateCableCoordinates(), 100);
    setTimeout(() => this.updateCableCoordinates(), 500);
  }

  setSpeed(mult) {
    this.speedMultiplier = mult;
  }

  setCallbacks(cbs) {
    this.callbacks = { ...this.callbacks, ...cbs };
  }

  pause() {
    this.isPaused = true;
  }

  resume() {
    this.isPaused = false;
  }

  getClientNode(ip) {
    return this.clientNodes[ip] || this.clientNodes['192.168.1.50'] || this.nodeEls.client;
  }

  getServerNode(ip) {
    return this.serverNodes[ip] || this.serverNodes['10.0.0.10'] || this.nodeEls.server;
  }

  getClientCable(ip) {
    if (ip === '192.168.1.50') return this.cables.clientA_Switch || this.cables.legacyClientSwitch;
    if (ip === '192.168.1.51') return this.cables.clientB_Switch || this.cables.legacyClientSwitch;
    if (ip === '192.168.1.99') return this.cables.clientC_Switch || this.cables.legacyClientSwitch;
    return this.cables.clientA_Switch || this.cables.legacyClientSwitch;
  }

  getServerCable(ip) {
    if (ip === '10.0.0.10') return this.cables.switch_ServerWeb || this.cables.legacySwitchServer;
    if (ip === '10.0.0.20') return this.cables.switch_ServerDb || this.cables.legacySwitchServer;
    if (ip === '10.0.0.30') return this.cables.switch_ServerBastion || this.cables.legacySwitchServer;
    return this.cables.switch_ServerWeb || this.cables.legacySwitchServer;
  }

  getNodePos(nodeEl) {
    if (!nodeEl) return { x: 0, y: 0 };
    const stageRect = this.stage.getBoundingClientRect();
    const nodeRect = nodeEl.getBoundingClientRect();
    return {
      x: (nodeRect.left + nodeRect.width / 2) - stageRect.left,
      y: (nodeRect.top + nodeRect.height / 2) - stageRect.top
    };
  }

  setPathLine(pathEl, p1, p2) {
    if (pathEl && p1 && p2) {
      pathEl.setAttribute('d', `M ${p1.x} ${p1.y} L ${p2.x} ${p2.y}`);
    }
  }

  updateCableCoordinates() {
    if (!this.stage) return;

    const sw = this.getNodePos(this.infraNodes.switch);
    const fw = this.getNodePos(this.infraNodes.firewall);
    const rtr = this.getNodePos(this.infraNodes.router);
    const net = this.getNodePos(this.infraNodes.internet);

    // Multi-Client Cables
    const cA = this.getNodePos(this.clientNodes['192.168.1.50']);
    const cB = this.getNodePos(this.clientNodes['192.168.1.51']);
    const cC = this.getNodePos(this.clientNodes['192.168.1.99']);

    this.setPathLine(this.cables.clientA_Switch, cA, sw);
    this.setPathLine(this.cables.clientB_Switch, cB, sw);
    this.setPathLine(this.cables.clientC_Switch, cC, sw);
    this.setPathLine(this.cables.legacyClientSwitch, cA, sw);

    // Multi-Server Cables
    const sWeb = this.getNodePos(this.serverNodes['10.0.0.10']);
    const sDb = this.getNodePos(this.serverNodes['10.0.0.20']);
    const sBastion = this.getNodePos(this.serverNodes['10.0.0.30']);

    this.setPathLine(this.cables.switch_ServerWeb, sw, sWeb);
    this.setPathLine(this.cables.switch_ServerDb, sw, sDb);
    this.setPathLine(this.cables.switch_ServerBastion, sw, sBastion);
    this.setPathLine(this.cables.legacySwitchServer, sw, sWeb);

    // Core Cables
    this.setPathLine(this.cables.switchFirewall, sw, fw);
    this.setPathLine(this.cables.firewallRouter, fw, rtr);
    this.setPathLine(this.cables.routerInternet, rtr, net);

    // Deflection Arc
    const sTarget = sWeb.x ? sWeb : { x: fw.x + 180, y: fw.y };
    const defX = fw.x + (sTarget.x - fw.x) * 0.45;
    const defY = fw.y - 25;
    if (this.cables.blockedArc) {
      this.cables.blockedArc.setAttribute('d', `M ${fw.x} ${fw.y} Q ${fw.x + 60} ${fw.y} ${defX} ${defY}`);
    }
  }

  sendPacket(packetInfo) {
    if (this.isPaused) return;

    this.updateCableCoordinates();

    const packet = {
      id: 'pkt-' + Math.random().toString(36).substr(2, 9),
      ...packetInfo,
      startTime: Date.now()
    };

    // Evaluate against firewall rules
    const evalResult = this.engine.evaluatePacket(packet);
    packet.evalResult = evalResult;

    const isInternetDest = packet.dstIp === '8.8.8.8' ||
      packet.dstIp.startsWith('203.') ||
      packet.dstIp.includes('.') && !packet.dstIp.startsWith('10.') && !packet.dstIp.startsWith('192.') ||
      packet.protocol === 'DNS' ||
      packet.dstPort === 53 ||
      !!packet.domain;

    const srcClientEl = this.getClientNode(packet.srcIp);
    const clientCable = this.getClientCable(packet.srcIp);

    // Visual pulse on sending client
    if (srcClientEl) {
      srcClientEl.classList.add('node-active-pulse');
      setTimeout(() => srcClientEl.classList.remove('node-active-pulse'), 1200 / this.speedMultiplier);
    }

    // Create packet DOM pill
    const el = document.createElement('div');
    el.className = 'packet-pill transit';
    el.id = packet.id;
    el.textContent = packet.label || `${packet.protocol} ${packet.dstPort}`;
    el.title = 'Click to inspect packet headers (5-Tuple)';

    el.addEventListener('click', (e) => {
      e.stopPropagation();
      if (window.openPacketInspector) window.openPacketInspector(packet);
    });

    this.flightLayer.appendChild(el);
    this.activePackets.add(packet);

    const cPos = this.getNodePos(srcClientEl);
    const swPos = this.getNodePos(this.infraNodes.switch);
    const fwPos = this.getNodePos(this.infraNodes.firewall);

    this.setElementPos(el, cPos.x, cPos.y);

    // Leg 1: Selected Client -> Switch (~900ms)
    this.highlightCable(clientCable);
    this.animateAlongLine(el, cPos, swPos, 900 / this.speedMultiplier, () => {
      this.unhighlightCable(clientCable);

      // Leg 2: Switch -> Firewall (~800ms)
      this.highlightCable(this.cables.switchFirewall);
      this.animateAlongLine(el, swPos, fwPos, 800 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.switchFirewall);

        // Arrived at Firewall: Inspection Phase
        this.handleFirewallInspection(el, packet, isInternetDest);
      });
    });
  }

  handleFirewallInspection(el, packet, isInternetDest) {
    const { verdict, matchedRule } = packet.evalResult;

    el.className = 'packet-pill inspecting';
    el.textContent = `Inspecting...`;

    if (this.callbacks.onRuleHit && matchedRule) {
      this.callbacks.onRuleHit(matchedRule.id);
    }

    setTimeout(() => {
      if (verdict === 'BLOCKED') {
        this.handleBlockedPacket(el, packet);
      } else {
        this.handleAllowedPacket(el, packet, isInternetDest);
      }
    }, 700 / this.speedMultiplier);
  }

  handleBlockedPacket(el, packet) {
    const { matchedRule } = packet.evalResult;

    this.firewallBox.classList.remove('glow-allow');
    this.firewallBox.classList.add('glow-block');
    setTimeout(() => this.firewallBox.classList.remove('glow-block'), 700 / this.speedMultiplier);

    el.className = 'packet-pill blocked';
    el.textContent = `${packet.label || packet.protocol} (Blocked)`;

    // Show Blocked Deflection Card
    const ruleText = matchedRule ? `Rule #${matchedRule.priority} (${matchedRule.name})` : 'Default Policy';
    const targetLabel = packet.domain || `${packet.dstIp}:${packet.dstPort}`;
    this.deflectReasonText.textContent = `${packet.protocol} to ${targetLabel} - ${ruleText}`;
    this.blockedCard.classList.remove('hidden');

    clearTimeout(this.deflectionTimer);
    this.deflectionTimer = setTimeout(() => {
      this.blockedCard.classList.add('hidden');
    }, 4500 / this.speedMultiplier);

    const fwPos = this.getNodePos(this.infraNodes.firewall);
    const srvPos = this.getNodePos(this.getServerNode(packet.dstIp));
    const defTarget = {
      x: fwPos.x + (srvPos.x - fwPos.x) * 0.45,
      y: fwPos.y - 25
    };
    const ctrlPoint = {
      x: fwPos.x + 60,
      y: fwPos.y
    };

    this.highlightCable(this.cables.blockedArc);

    this.animateAlongCurve(el, fwPos, ctrlPoint, defTarget, 900 / this.speedMultiplier, () => {
      this.unhighlightCable(this.cables.blockedArc);

      el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
      el.style.opacity = '0';
      el.style.transform = 'translate(-50%, -50%) scale(0.5)';
      setTimeout(() => {
        if (el.parentNode) el.parentNode.removeChild(el);
        this.activePackets.delete(packet);
      }, 600);
    });

    if (this.callbacks.onPacketLogged) {
      this.callbacks.onPacketLogged(packet, 'BLOCKED');
    }
    if (this.callbacks.onServerActivity) {
      this.callbacks.onServerActivity({
        type: 'blocked',
        packet,
        matchedRule
      });
    }
  }

  handleAllowedPacket(el, packet, isInternetDest) {
    this.firewallBox.classList.remove('glow-block');
    this.firewallBox.classList.add('glow-allow');
    setTimeout(() => this.firewallBox.classList.remove('glow-allow'), 600 / this.speedMultiplier);

    el.className = 'packet-pill allowed';
    el.textContent = packet.label || `${packet.protocol} ${packet.dstPort}`;

    if (this.callbacks.onPacketLogged) {
      this.callbacks.onPacketLogged(packet, 'ALLOWED');
    }

    const fwPos = this.getNodePos(this.infraNodes.firewall);

    if (isInternetDest) {
      // Route: Firewall -> Router -> Internet Cloud
      const rtrPos = this.getNodePos(this.infraNodes.router);
      const netPos = this.getNodePos(this.infraNodes.internet);

      this.highlightCable(this.cables.firewallRouter);
      this.animateAlongLine(el, fwPos, rtrPos, 700 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.firewallRouter);

        this.highlightCable(this.cables.routerInternet);
        this.animateAlongLine(el, rtrPos, netPos, 650 / this.speedMultiplier, () => {
          this.unhighlightCable(this.cables.routerInternet);
          this.handleInternetArrival(el, packet);
        });
      });
    } else {
      // Route: Firewall -> Switch -> Selected Internal Server
      const swPos = this.getNodePos(this.infraNodes.switch);
      const targetServerEl = this.getServerNode(packet.dstIp);
      const srvPos = this.getNodePos(targetServerEl);
      const serverCable = this.getServerCable(packet.dstIp);

      this.highlightCable(this.cables.switchFirewall);
      this.animateAlongLine(el, fwPos, swPos, 750 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.switchFirewall);

        this.highlightCable(serverCable);
        this.animateAlongLine(el, swPos, srvPos, 850 / this.speedMultiplier, () => {
          this.unhighlightCable(serverCable);
          this.handleServerArrival(el, packet, targetServerEl);
        });
      });
    }
  }

  handleServerArrival(reqEl, reqPacket, serverEl) {
    if (reqEl.parentNode) reqEl.parentNode.removeChild(reqEl);
    this.activePackets.delete(reqPacket);

    if (serverEl) {
      serverEl.classList.add('node-active-pulse');
      setTimeout(() => serverEl.classList.remove('node-active-pulse'), 1200 / this.speedMultiplier);
    }

    let respLabel = 'HTTP 200 OK';
    let respInfo = '200 OK (2.4 KB)';
    let respProto = reqPacket.protocol || 'HTTP';

    if (reqPacket.method === 'SYN') {
      respLabel = 'TCP SYN-ACK';
      respInfo = 'SYN-ACK Handshake';
      respProto = 'TCP';
    } else if (reqPacket.dstPort === 3306) {
      respLabel = 'MySQL Result';
      respInfo = 'Query Results (14 rows)';
      respProto = 'TCP';
    } else if (reqPacket.dstPort === 22) {
      respLabel = 'SSH Auth Prompt';
      respInfo = 'SSH-2.0-OpenSSH_9.0';
      respProto = 'TCP';
    } else if (reqPacket.method === 'POST') {
      respLabel = 'HTTP 201 Created';
      respInfo = '201 Created (1.8 KB)';
    }

    const respPacket = {
      id: 'resp-' + Math.random().toString(36).substr(2, 9),
      srcIp: reqPacket.dstIp,
      dstIp: reqPacket.srcIp,
      srcPort: reqPacket.dstPort,
      dstPort: reqPacket.srcPort,
      protocol: respProto,
      flags: reqPacket.method === 'SYN' ? 'SYN, ACK' : 'ACK, PSH',
      info: respInfo,
      label: respLabel,
      size: 2450,
      isResponse: true
    };

    if (this.callbacks.onServerActivity) {
      this.callbacks.onServerActivity({
        type: 'received',
        packet: reqPacket,
        response: respPacket
      });
    }

    setTimeout(() => {
      this.sendReturnPacket(respPacket, false);
    }, 450 / this.speedMultiplier);
  }

  handleInternetArrival(reqEl, reqPacket) {
    if (reqEl.parentNode) reqEl.parentNode.removeChild(reqEl);
    this.activePackets.delete(reqPacket);

    const isLiveWeb = !!reqPacket.domain || reqPacket.dstPort === 80 || reqPacket.dstPort === 443;
    const respPacket = {
      id: 'resp-' + Math.random().toString(36).substr(2, 9),
      srcIp: reqPacket.dstIp,
      dstIp: reqPacket.srcIp,
      srcPort: reqPacket.dstPort,
      dstPort: reqPacket.srcPort,
      protocol: reqPacket.protocol || 'TCP',
      flags: isLiveWeb ? 'ACK, PSH' : 'RESPONSE',
      info: isLiveWeb ? `HTTP 200 OK (${reqPacket.domain || 'Internet'})` : 'DNS Response (93.184.216.34)',
      label: isLiveWeb ? 'HTTP 200 OK' : 'DNS Response',
      size: isLiveWeb ? 1840 : 142,
      isResponse: true
    };

    if (this.callbacks.onServerActivity) {
      this.callbacks.onServerActivity({
        type: 'dns_response',
        packet: reqPacket,
        response: respPacket
      });
    }

    setTimeout(() => {
      this.sendReturnPacket(respPacket, true);
    }, 450 / this.speedMultiplier);
  }

  sendReturnPacket(respPacket, isFromInternet) {
    const evalResult = this.engine.evaluatePacket(respPacket);
    respPacket.evalResult = evalResult;

    const el = document.createElement('div');
    el.className = 'packet-pill allowed';
    el.id = respPacket.id;
    el.textContent = respPacket.label;
    el.title = 'Click to inspect response packet';
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      if (window.openPacketInspector) window.openPacketInspector(respPacket);
    });

    this.flightLayer.appendChild(el);
    this.activePackets.add(respPacket);

    if (this.callbacks.onPacketLogged) {
      this.callbacks.onPacketLogged(respPacket, 'ALLOWED');
    }

    const swPos = this.getNodePos(this.infraNodes.switch);
    const fwPos = this.getNodePos(this.infraNodes.firewall);
    const destClientEl = this.getClientNode(respPacket.dstIp);
    const cPos = this.getNodePos(destClientEl);
    const clientCable = this.getClientCable(respPacket.dstIp);

    if (isFromInternet) {
      // Internet -> Router -> Firewall -> Switch -> Client
      const netPos = this.getNodePos(this.infraNodes.internet);
      const rtrPos = this.getNodePos(this.infraNodes.router);

      this.setElementPos(el, netPos.x, netPos.y);
      this.highlightCable(this.cables.routerInternet);
      this.animateAlongLine(el, netPos, rtrPos, 650 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.routerInternet);

        this.highlightCable(this.cables.firewallRouter);
        this.animateAlongLine(el, rtrPos, fwPos, 650 / this.speedMultiplier, () => {
          this.unhighlightCable(this.cables.firewallRouter);

          this.highlightCable(this.cables.switchFirewall);
          this.animateAlongLine(el, fwPos, swPos, 650 / this.speedMultiplier, () => {
            this.unhighlightCable(this.cables.switchFirewall);

            this.highlightCable(clientCable);
            this.animateAlongLine(el, swPos, cPos, 850 / this.speedMultiplier, () => {
              this.unhighlightCable(clientCable);
              this.removePacket(el, respPacket);
            });
          });
        });
      });
    } else {
      // Server -> Switch -> Firewall -> Switch -> Client
      const srcServerEl = this.getServerNode(respPacket.srcIp);
      const srvPos = this.getNodePos(srcServerEl);
      const serverCable = this.getServerCable(respPacket.srcIp);

      this.setElementPos(el, srvPos.x, srvPos.y);
      this.highlightCable(serverCable);
      this.animateAlongLine(el, srvPos, swPos, 750 / this.speedMultiplier, () => {
        this.unhighlightCable(serverCable);

        this.highlightCable(this.cables.switchFirewall);
        this.animateAlongLine(el, swPos, fwPos, 650 / this.speedMultiplier, () => {
          this.unhighlightCable(this.cables.switchFirewall);

          this.highlightCable(this.cables.switchFirewall);
          this.animateAlongLine(el, fwPos, swPos, 650 / this.speedMultiplier, () => {
            this.unhighlightCable(this.cables.switchFirewall);

            this.highlightCable(clientCable);
            this.animateAlongLine(el, swPos, cPos, 850 / this.speedMultiplier, () => {
              this.unhighlightCable(clientCable);
              this.removePacket(el, respPacket);
            });
          });
        });
      });
    }
  }

  highlightCable(cableEl) {
    if (cableEl) cableEl.classList.add('cable-active');
  }

  unhighlightCable(cableEl) {
    if (cableEl) cableEl.classList.remove('cable-active');
  }

  removePacket(el, packet) {
    if (el.parentNode) el.parentNode.removeChild(el);
    this.activePackets.delete(packet);
  }

  // --- Animation Primitives with Smooth Ease-in-Out Timing ---
  setElementPos(el, x, y) {
    el.style.left = `${x}px`;
    el.style.top = `${y}px`;
  }

  animateAlongLine(el, start, end, duration, onComplete) {
    const startTime = performance.now();

    const frame = (now) => {
      if (this.isPaused) {
        requestAnimationFrame(frame);
        return;
      }

      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const ease = 0.5 - 0.5 * Math.cos(progress * Math.PI);

      const currentX = start.x + (end.x - start.x) * ease;
      const currentY = start.y + (end.y - start.y) * ease;

      this.setElementPos(el, currentX, currentY);

      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        if (onComplete) onComplete();
      }
    };

    requestAnimationFrame(frame);
  }

  animateAlongCurve(el, start, control, end, duration, onComplete) {
    const startTime = performance.now();

    const frame = (now) => {
      if (this.isPaused) {
        requestAnimationFrame(frame);
        return;
      }

      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const t = 0.5 - 0.5 * Math.cos(progress * Math.PI);

      const currentX = (1 - t) * (1 - t) * start.x + 2 * (1 - t) * t * control.x + t * t * end.x;
      const currentY = (1 - t) * (1 - t) * start.y + 2 * (1 - t) * t * control.y + t * t * end.y;

      this.setElementPos(el, currentX, currentY);

      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        if (onComplete) onComplete();
      }
    };

    requestAnimationFrame(frame);
  }
}

// Export for browser
if (typeof window !== 'undefined') {
  window.TopologySimulator = TopologySimulator;
}
