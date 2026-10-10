/**
 * PacketGuard Network Topology Simulator
 * Accurate, smooth, and deliberately paced packet transmission with dynamic SVG cable anchoring.
 */

class TopologySimulator {
  constructor(stageId, firewallEngine) {
    this.stage = document.getElementById(stageId);
    this.flightLayer = document.getElementById('packetFlightLayer');
    this.firewallBox = document.getElementById('firewallBox');
    this.blockedCard = document.getElementById('blockedDeflectionCard');
    this.deflectReasonText = document.getElementById('deflectReasonText');
    this.engine = firewallEngine;

    // DOM Nodes
    this.nodeEls = {
      client: document.getElementById('nodeClient'),
      switch: document.getElementById('nodeSwitch'),
      firewall: document.getElementById('nodeFirewall'),
      server: document.getElementById('nodeServer'),
      router: document.getElementById('nodeRouter'),
      internet: document.getElementById('nodeInternet')
    };

    // SVG Cables
    this.cables = {
      clientSwitch: document.getElementById('cableClientSwitch'),
      switchServer: document.getElementById('cableSwitchServer'),
      switchFirewall: document.getElementById('cableSwitchFirewall'),
      firewallRouter: document.getElementById('cableFirewallRouter'),
      routerInternet: document.getElementById('cableRouterInternet'),
      blockedArc: document.getElementById('cableBlockedArc')
    };

    this.activePackets = new Set();
    this.isPaused = false;
    this.speedMultiplier = 1.0; // 1.0 = normal, 0.6 = slow, 1.8 = fast

    this.callbacks = {
      onPacketLogged: null,
      onServerActivity: null,
      onRuleHit: null
    };

    this.deflectionTimer = null;

    // Update cables on resize & orientation change (mobile)
    window.addEventListener('resize', () => this.updateCableCoordinates());
    window.addEventListener('orientationchange', () => setTimeout(() => this.updateCableCoordinates(), 250));
    // Initial cable alignment with retry for mobile font/layout settling
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

  /**
   * Get exact center coordinates of any DOM node relative to the stage canvas
   */
  getNodePos(nodeEl) {
    if (!nodeEl) return { x: 0, y: 0 };
    const stageRect = this.stage.getBoundingClientRect();
    const nodeRect = nodeEl.getBoundingClientRect();
    return {
      x: (nodeRect.left + nodeRect.width / 2) - stageRect.left,
      y: (nodeRect.top + nodeRect.height / 2) - stageRect.top
    };
  }

  /**
   * Dynamically update SVG cable paths to connect with 100% precision to node centers
   */
  updateCableCoordinates() {
    const c = this.getNodePos(this.nodeEls.client);
    const sw = this.getNodePos(this.nodeEls.switch);
    const fw = this.getNodePos(this.nodeEls.firewall);
    const srv = this.getNodePos(this.nodeEls.server);
    const rtr = this.getNodePos(this.nodeEls.router);
    const net = this.getNodePos(this.nodeEls.internet);

    // Deflection anchor point (to the right of firewall)
    const defX = fw.x + (srv.x - fw.x) * 0.45;
    const defY = fw.y - 25;

    if (this.cables.clientSwitch) {
      this.cables.clientSwitch.setAttribute('d', `M ${c.x} ${c.y} L ${sw.x} ${sw.y}`);
    }
    if (this.cables.switchServer) {
      this.cables.switchServer.setAttribute('d', `M ${sw.x} ${sw.y} L ${srv.x} ${srv.y}`);
    }
    if (this.cables.switchFirewall) {
      this.cables.switchFirewall.setAttribute('d', `M ${sw.x} ${sw.y} L ${fw.x} ${fw.y}`);
    }
    if (this.cables.firewallRouter) {
      this.cables.firewallRouter.setAttribute('d', `M ${fw.x} ${fw.y} L ${rtr.x} ${rtr.y}`);
    }
    if (this.cables.routerInternet) {
      this.cables.routerInternet.setAttribute('d', `M ${rtr.x} ${rtr.y} L ${net.x} ${net.y}`);
    }
    if (this.cables.blockedArc) {
      this.cables.blockedArc.setAttribute('d', `M ${fw.x} ${fw.y} Q ${fw.x + 60} ${fw.y} ${defX} ${defY}`);
    }
  }

  /**
   * Dispatch a packet across the network topology with smooth, deliberate pacing
   */
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

    const isInternetDest = packet.dstIp === '8.8.8.8' || packet.dstIp.startsWith('203.') || packet.protocol === 'DNS' || packet.dstPort === 53;

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

    const cPos = this.getNodePos(this.nodeEls.client);
    const swPos = this.getNodePos(this.nodeEls.switch);
    const fwPos = this.getNodePos(this.nodeEls.firewall);

    this.setElementPos(el, cPos.x, cPos.y);

    // Leg 1: Client -> Switch (~950ms)
    this.highlightCable(this.cables.clientSwitch);
    this.animateAlongLine(el, cPos, swPos, 950 / this.speedMultiplier, () => {
      this.unhighlightCable(this.cables.clientSwitch);

      // Leg 2: Switch -> Firewall (~850ms)
      this.highlightCable(this.cables.switchFirewall);
      this.animateAlongLine(el, swPos, fwPos, 850 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.switchFirewall);

        // Arrived at Firewall: Inspection Phase
        this.handleFirewallInspection(el, packet, isInternetDest);
      });
    });
  }

  handleFirewallInspection(el, packet, isInternetDest) {
    const { verdict, matchedRule } = packet.evalResult;

    // Packet pauses at firewall with inspection indicator
    el.className = 'packet-pill inspecting';
    el.textContent = `Inspecting...`;

    // Highlight matched rule in Rule Table
    if (this.callbacks.onRuleHit && matchedRule) {
      this.callbacks.onRuleHit(matchedRule.id);
    }

    // Deliberate inspection pause (750ms)
    setTimeout(() => {
      if (verdict === 'BLOCKED') {
        this.handleBlockedPacket(el, packet);
      } else {
        this.handleAllowedPacket(el, packet, isInternetDest);
      }
    }, 750 / this.speedMultiplier);
  }

  handleBlockedPacket(el, packet) {
    const { matchedRule } = packet.evalResult;

    // Visual firewall block reaction
    this.firewallBox.classList.remove('glow-allow');
    this.firewallBox.classList.add('glow-block');
    setTimeout(() => this.firewallBox.classList.remove('glow-block'), 700 / this.speedMultiplier);

    el.className = 'packet-pill blocked';
    el.textContent = `${packet.label || packet.protocol} (Blocked)`;

    // Show Blocked Deflection Card
    const ruleText = matchedRule ? `Rule #${matchedRule.priority} (${matchedRule.name})` : 'Default Policy';
    this.deflectReasonText.textContent = `${packet.protocol} Port ${packet.dstPort} - ${ruleText}`;
    this.blockedCard.classList.remove('hidden');

    clearTimeout(this.deflectionTimer);
    this.deflectionTimer = setTimeout(() => {
      this.blockedCard.classList.add('hidden');
    }, 4500 / this.speedMultiplier);

    const fwPos = this.getNodePos(this.nodeEls.firewall);
    const srvPos = this.getNodePos(this.nodeEls.server);
    const defTarget = {
      x: fwPos.x + (srvPos.x - fwPos.x) * 0.45,
      y: fwPos.y - 25
    };
    const ctrlPoint = {
      x: fwPos.x + 60,
      y: fwPos.y
    };

    this.highlightCable(this.cables.blockedArc);

    // Deflect smoothly along curved path (~900ms)
    this.animateAlongCurve(el, fwPos, ctrlPoint, defTarget, 900 / this.speedMultiplier, () => {
      this.unhighlightCable(this.cables.blockedArc);

      // Dissolve packet pill cleanly
      el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
      el.style.opacity = '0';
      el.style.transform = 'translate(-50%, -50%) scale(0.5)';
      setTimeout(() => {
        if (el.parentNode) el.parentNode.removeChild(el);
        this.activePackets.delete(packet);
      }, 600);
    });

    // Log to Timeline & Server Console
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

    const fwPos = this.getNodePos(this.nodeEls.firewall);

    if (isInternetDest) {
      // Allowed Route: Firewall -> Router -> Internet Cloud
      const rtrPos = this.getNodePos(this.nodeEls.router);
      const netPos = this.getNodePos(this.nodeEls.internet);

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
      // Allowed Route: Firewall -> Switch -> Server
      const swPos = this.getNodePos(this.nodeEls.switch);
      const srvPos = this.getNodePos(this.nodeEls.server);

      this.highlightCable(this.cables.switchFirewall);
      this.animateAlongLine(el, fwPos, swPos, 750 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.switchFirewall);

        this.highlightCable(this.cables.switchServer);
        this.animateAlongLine(el, swPos, srvPos, 900 / this.speedMultiplier, () => {
          this.unhighlightCable(this.cables.switchServer);
          this.handleServerArrival(el, packet);
        });
      });
    }
  }

  handleServerArrival(reqEl, reqPacket) {
    if (reqEl.parentNode) reqEl.parentNode.removeChild(reqEl);
    this.activePackets.delete(reqPacket);

    // Synthesize Server Response
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

    // Realistic Server Processing Pause (500ms)
    setTimeout(() => {
      this.sendReturnPacket(respPacket, false);
    }, 500 / this.speedMultiplier);
  }

  handleInternetArrival(reqEl, reqPacket) {
    if (reqEl.parentNode) reqEl.parentNode.removeChild(reqEl);
    this.activePackets.delete(reqPacket);

    const respPacket = {
      id: 'dns-resp-' + Math.random().toString(36).substr(2, 9),
      srcIp: reqPacket.dstIp,
      dstIp: reqPacket.srcIp,
      srcPort: reqPacket.dstPort,
      dstPort: reqPacket.srcPort,
      protocol: 'DNS',
      flags: 'RESPONSE',
      info: 'Response (93.184.216.34)',
      label: 'DNS Response',
      size: 142,
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
    }, 500 / this.speedMultiplier);
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

    const swPos = this.getNodePos(this.nodeEls.switch);
    const fwPos = this.getNodePos(this.nodeEls.firewall);
    const cPos = this.getNodePos(this.nodeEls.client);

    if (isFromInternet) {
      // Internet -> Router -> Firewall -> Switch -> Client
      const netPos = this.getNodePos(this.nodeEls.internet);
      const rtrPos = this.getNodePos(this.nodeEls.router);

      this.setElementPos(el, netPos.x, netPos.y);
      this.highlightCable(this.cables.routerInternet);
      this.animateAlongLine(el, netPos, rtrPos, 650 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.routerInternet);

        this.highlightCable(this.cables.firewallRouter);
        this.animateAlongLine(el, rtrPos, fwPos, 700 / this.speedMultiplier, () => {
          this.unhighlightCable(this.cables.firewallRouter);

          this.highlightCable(this.cables.switchFirewall);
          this.animateAlongLine(el, fwPos, swPos, 700 / this.speedMultiplier, () => {
            this.unhighlightCable(this.cables.switchFirewall);

            this.highlightCable(this.cables.clientSwitch);
            this.animateAlongLine(el, swPos, cPos, 900 / this.speedMultiplier, () => {
              this.unhighlightCable(this.cables.clientSwitch);
              this.removePacket(el, respPacket);
            });
          });
        });
      });
    } else {
      // Server -> Switch -> Firewall -> Switch -> Client
      const srvPos = this.getNodePos(this.nodeEls.server);

      this.setElementPos(el, srvPos.x, srvPos.y);
      this.highlightCable(this.cables.switchServer);
      this.animateAlongLine(el, srvPos, swPos, 900 / this.speedMultiplier, () => {
        this.unhighlightCable(this.cables.switchServer);

        this.highlightCable(this.cables.switchFirewall);
        this.animateAlongLine(el, swPos, fwPos, 700 / this.speedMultiplier, () => {
          this.unhighlightCable(this.cables.switchFirewall);

          this.highlightCable(this.cables.switchFirewall);
          this.animateAlongLine(el, fwPos, swPos, 700 / this.speedMultiplier, () => {
            this.unhighlightCable(this.cables.switchFirewall);

            this.highlightCable(this.cables.clientSwitch);
            this.animateAlongLine(el, swPos, cPos, 900 / this.speedMultiplier, () => {
              this.unhighlightCable(this.cables.clientSwitch);
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
      // Smooth sinusoidal ease-in-out
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

      // Quadratic Bezier interpolation: B(t) = (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
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
window.TopologySimulator = TopologySimulator;
