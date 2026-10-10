/**
 * PacketGuard Application Controller
 * Coordinates UI, Firewall Engine, Topology Animation, Rules, Timeline, and Server Console.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Core Engines
  const engine = new FirewallEngine();
  const sim = new TopologySimulator('topologyStage', engine);

  // Application State
  let simSeconds = 204; // starts at 00:03:24
  let isRunning = true;
  let timerInterval = null;
  let timelinePackets = [];
  let packetCounter = 0;
  let currentPreset = 'http';

  // DOM Elements
  const playPauseBtn = document.getElementById('playPauseBtn');
  const playIcon = document.getElementById('playIcon');
  const pauseIcon = document.getElementById('pauseIcon');
  const simStatusPill = document.getElementById('simStatusPill');
  const simStatusText = document.getElementById('simStatusText');
  const timerDisplay = document.getElementById('timerDisplay');
  const resetBtn = document.getElementById('resetBtn');

  // Request Crafter Elements
  const tabPresetsBtn = document.getElementById('tabPresetsBtn');
  const tabCustomBtn = document.getElementById('tabCustomBtn');
  const presetsContainer = document.getElementById('presetsContainer');
  const reqMethod = document.getElementById('reqMethod');
  const reqDest = document.getElementById('reqDest');
  const reqPort = document.getElementById('reqPort');
  const reqPath = document.getElementById('reqPath');
  const reqHeaders = document.getElementById('reqHeaders');
  const sendRequestBtn = document.getElementById('sendRequestBtn');
  const packetRateValue = document.getElementById('packetRateValue');
  const sparkBars = document.querySelectorAll('.spark-bar');

  // Timeline & Console Elements
  const timelineBody = document.getElementById('timelineBody');
  const timelineCounter = document.getElementById('timelineCounter');
  const consoleBody = document.getElementById('consoleBody');
  const clearConsoleBtn = document.getElementById('clearConsoleBtn');

  // Rules Elements
  const rulesListContainer = document.getElementById('rulesListContainer');
  const addRuleBtn = document.getElementById('addRuleBtn');
  const ruleModal = document.getElementById('ruleModal');
  const closeModalBtn = document.getElementById('closeModalBtn');
  const cancelRuleBtn = document.getElementById('cancelRuleBtn');
  const saveRuleBtn = document.getElementById('saveRuleBtn');

  // Inspector Elements
  const packetInspectorModal = document.getElementById('packetInspectorModal');
  const closeInspectorBtn = document.getElementById('closeInspectorBtn');
  const inspectorContent = document.getElementById('inspectorContent');

  // --- Clock & Timer Setup ---
  function formatTime(totalSeconds) {
    const hrs = Math.floor(totalSeconds / 3600);
    const mins = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;
    return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }

  function startTimer() {
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
      if (isRunning) {
        simSeconds++;
        timerDisplay.textContent = formatTime(simSeconds);
      }
    }, 1000);
  }

  function togglePlayPause() {
    isRunning = !isRunning;
    if (isRunning) {
      sim.resume();
      playIcon.classList.add('hidden');
      pauseIcon.classList.remove('hidden');
      simStatusPill.classList.remove('paused');
      simStatusText.textContent = 'Simulation Running';
    } else {
      sim.pause();
      playIcon.classList.remove('hidden');
      pauseIcon.classList.add('hidden');
      simStatusPill.classList.add('paused');
      simStatusText.textContent = 'Simulation Paused';
    }
  }

  // --- Animated Sparkline Simulator ---
  setInterval(() => {
    if (!isRunning) return;
    const rate = Math.floor(Math.random() * 5) + 4; // 4 to 8 packets/sec
    packetRateValue.textContent = `${rate} packets/sec`;
    sparkBars.forEach(bar => {
      const height = Math.floor(Math.random() * 65) + 30;
      bar.style.height = `${height}%`;
    });
  }, 1200);

  // --- Presets Data Configuration ---
  const presetsConfig = {
    http: {
      method: 'GET',
      dest: '10.0.0.10',
      port: 80,
      path: '/',
      headers: 'User-Agent: PacketGuard/1.0\nAccept: */*',
      protocol: 'HTTP',
      label: 'HTTP GET'
    },
    ssh: {
      method: 'SYN',
      dest: '10.0.0.10',
      port: 22,
      path: '',
      headers: 'SSH-2.0-OpenSSH_8.9p1',
      protocol: 'TCP',
      label: 'TCP SYN'
    },
    dns: {
      method: 'DNS_QUERY',
      dest: '8.8.8.8',
      port: 53,
      path: '',
      headers: 'Query: example.com (IN A)',
      protocol: 'DNS',
      label: 'DNS Query'
    },
    db: {
      method: 'SYN',
      dest: '10.0.0.10',
      port: 3306,
      path: '',
      headers: 'Client Handshake: MySQL 8.0',
      protocol: 'TCP',
      label: 'MySQL Query'
    },
    portscan: {
      method: 'SYN',
      dest: '10.0.0.10',
      port: 80,
      path: '',
      headers: 'Nmap Port Sweep',
      protocol: 'TCP',
      label: 'Port Scan'
    },
    custom: {
      method: 'GET',
      dest: '10.0.0.10',
      port: 443,
      path: '/api/v1/status',
      headers: 'Authorization: Bearer token_xyz',
      protocol: 'TCP',
      label: 'Custom Packet'
    }
  };

  function selectPreset(presetKey) {
    currentPreset = presetKey;
    document.querySelectorAll('.preset-card').forEach(c => {
      c.classList.toggle('active', c.dataset.preset === presetKey);
    });

    const cfg = presetsConfig[presetKey];
    if (!cfg) return;

    reqMethod.value = cfg.method;
    reqDest.value = cfg.dest;
    reqPort.value = cfg.port;
    reqPath.value = cfg.path;
    reqHeaders.value = cfg.headers;

    // Toggle fields based on preset type
    const isWeb = cfg.protocol === 'HTTP';
    document.getElementById('pathGroup').style.display = isWeb ? 'flex' : 'none';
  }

  // --- Send Request Handler ---
  function handleSendRequest() {
    if (!isRunning) togglePlayPause();

    if (currentPreset === 'portscan') {
      // Execute Multi-Port Scan Sequence
      executePortScan();
      return;
    }

    const method = reqMethod.value;
    const dest = reqDest.value.trim() || '10.0.0.10';
    const port = parseInt(reqPort.value, 10) || 80;
    const path = reqPath.value.trim() || '/';
    const headers = reqHeaders.value.trim();

    let protocol = 'TCP';
    let info = '';
    let label = '';
    let flags = 'SYN';

    let appProtocol = 'TCP';
    if (method === 'DNS_QUERY' || port === 53) {
      protocol = 'UDP';
      appProtocol = 'DNS';
      info = 'Query: example.com';
      label = 'DNS Query';
      flags = 'QUERY';
    } else if (method === 'PING') {
      protocol = 'ICMP';
      appProtocol = 'ICMP';
      info = 'Echo Request';
      label = 'ICMP Echo';
      flags = 'NONE';
    } else if (port === 80 || port === 443) {
      protocol = 'TCP';
      appProtocol = port === 443 ? 'HTTPS' : 'HTTP';
      info = `${method} ${path || '/'} HTTP/1.1`;
      label = `${appProtocol} ${method}`;
      flags = 'ACK, PSH';
    } else if (port === 22) {
      protocol = 'TCP';
      appProtocol = 'SSH';
      info = 'SYN (Port 22)';
      label = 'TCP SYN';
      flags = 'SYN';
    } else if (port === 3306) {
      protocol = 'TCP';
      appProtocol = 'MySQL';
      info = 'MySQL Connect';
      label = 'MySQL Query';
      flags = 'SYN';
    } else {
      protocol = 'TCP';
      appProtocol = 'TCP';
      info = `${method} Port ${port}`;
      label = `${protocol} ${port}`;
      flags = 'SYN';
    }

    const ephemeralPort = Math.floor(Math.random() * 15000) + 49152;

    sim.sendPacket({
      srcIp: '192.168.1.50',
      dstIp: dest,
      srcPort: ephemeralPort,
      dstPort: port,
      protocol: protocol,
      appProtocol: appProtocol,
      flags: flags,
      method: method,
      path: path,
      headers: headers,
      info: info,
      label: label,
      size: Math.floor(Math.random() * 400) + 120
    });
  }

  // --- Port Scan Simulator ---
  function executePortScan() {
    const scanPorts = [21, 22, 23, 80, 443, 3306];
    logToServerConsole('Starting Nmap TCP SYN Port Scan against 10.0.0.10...', 'info');

    scanPorts.forEach((targetPort, idx) => {
      setTimeout(() => {
        const ephem = Math.floor(Math.random() * 15000) + 49152;
        sim.sendPacket({
          srcIp: '192.168.1.50',
          dstIp: '10.0.0.10',
          srcPort: ephem,
          dstPort: targetPort,
          protocol: 'TCP',
          flags: 'SYN',
          method: 'SYN',
          info: `SYN (Port ${targetPort})`,
          label: `Port ${targetPort}`,
          size: 64
        });
      }, idx * 600);
    });
  }

  // --- Rule Hit Highlight Callback ---
  sim.setCallbacks({
    onRuleHit: (ruleId) => {
      document.querySelectorAll('.rule-item').forEach(el => {
        if (el.dataset.ruleId === ruleId) {
          el.classList.add('rule-highlight');
          setTimeout(() => el.classList.remove('rule-highlight'), 1200);
        }
      });
    },

    onPacketLogged: (packet, status) => {
      addTimelineRow(packet, status);
    },

    onServerActivity: (act) => {
      const timeStr = `[${formatTime(simSeconds)}]`;
      if (act.type === 'received') {
        const p = act.packet;
        logToServerConsole(`${timeStr} Incoming connection from ${p.srcIp}:${p.srcPort}`);
        logToServerConsole(`${timeStr} ${p.info || p.protocol}`);
        logToServerConsole(`${timeStr} ✓ ${act.response.info}`, 'success');
      } else if (act.type === 'blocked') {
        const p = act.packet;
        const r = act.matchedRule;
        logToServerConsole(`${timeStr} Blocked connection attempt`, 'error');
        logToServerConsole(`${timeStr} Source: ${p.srcIp}`, 'error');
        logToServerConsole(`${timeStr} Destination: ${p.dstIp}:${p.dstPort}`, 'error');
        logToServerConsole(`${timeStr} Rule: #${r.priority} (${r.name})`, 'error');
      } else if (act.type === 'dns_response') {
        logToServerConsole(`${timeStr} DNS Query: example.com`, 'info');
        logToServerConsole(`${timeStr} DNS Response: 93.184.216.34`, 'success');
      }
    }
  });

  // --- Timeline Logging ---
  function addTimelineRow(packet, status) {
    packetCounter++;
    timelineCounter.textContent = `${packetCounter} packets`;

    const row = document.createElement('tr');
    row.dataset.packetId = packet.id;

    const timeStr = formatTime(simSeconds);
    const badgeClass = status === 'ALLOWED' ? 'allowed' : 'blocked';

    row.innerHTML = `
      <td>${packetCounter}</td>
      <td>${timeStr}</td>
      <td>${packet.srcIp} &rarr; ${packet.dstIp}</td>
      <td>${packet.appProtocol || packet.protocol}</td>
      <td>${packet.info || packet.label}</td>
      <td><span class="status-badge ${badgeClass}">${status}</span></td>
    `;

    // Click row to view deep packet inspection
    row.addEventListener('click', () => {
      openPacketInspector(packet);
    });

    timelineBody.insertBefore(row, timelineBody.firstChild);
    timelinePackets.unshift(packet);
  }

  // --- Server Console Logging ---
  function logToServerConsole(message, type = '') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;

    let msgClass = '';
    if (type === 'success') msgClass = 'success';
    if (type === 'error') msgClass = 'error';
    if (type === 'info') msgClass = 'info';

    entry.innerHTML = `<span class="log-msg ${msgClass}">${escapeHtml(message)}</span>`;
    consoleBody.appendChild(entry);
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  let selectedRuleId = null;
  let dragSrcIndex = null;

  // --- Rules List Rendering with Interactive Selection & Drag-and-Drop Reordering ---
  function renderRulesList() {
    rulesListContainer.innerHTML = '';

    engine.rules.forEach((rule, idx) => {
      const item = document.createElement('div');
      item.className = 'rule-item' + (!rule.enabled ? ' disabled' : '') + (rule.id === selectedRuleId ? ' selected-rule' : '');
      item.dataset.ruleId = rule.id;
      item.dataset.ruleIndex = idx;
      item.draggable = true;
      item.title = 'Click to test, or drag handle to reorder priority';

      const badgeType = rule.action === 'ALLOW' ? 'allow' : 'deny';

      // Format criteria summary string
      let criteria = '';
      if (rule.state && rule.state.includes('ESTABLISHED')) {
        criteria = `State: ${rule.state}`;
      } else if (rule.protocol === 'ANY' && rule.dstPort === '*') {
        criteria = 'All traffic';
      } else {
        criteria = `${rule.protocol}, Port ${rule.dstPort}`;
        if (rule.srcIp !== '*') criteria += ` from ${rule.srcIp}`;
      }

      item.innerHTML = `
        <span class="rule-drag-handle" title="Drag to reorder priority">&#8942;&#8942;</span>
        <span class="rule-priority">${rule.priority}</span>
        <span class="rule-badge ${badgeType}">${rule.action}</span>
        <div class="rule-content">
          <span class="rule-title">${escapeHtml(rule.name)}</span>
          <span class="rule-criteria">${escapeHtml(criteria)}</span>
        </div>
        <div class="rule-actions">
          <button class="rule-icon-btn move-rule-up" title="Move rule up" ${idx === 0 ? 'disabled style="opacity:0.25;cursor:default;"' : ''}>&#9650;</button>
          <button class="rule-icon-btn move-rule-down" title="Move rule down" ${idx === engine.rules.length - 1 ? 'disabled style="opacity:0.25;cursor:default;"' : ''}>&#9660;</button>
          <button class="rule-icon-btn toggle-rule" title="${rule.enabled ? 'Disable rule' : 'Enable rule'}">
            ${rule.enabled ? '✓' : '⊘'}
          </button>
          <button class="rule-icon-btn delete-rule" title="Delete rule">&times;</button>
        </div>
      `;

      // Drag and Drop Reordering Handlers
      item.addEventListener('dragstart', (e) => {
        dragSrcIndex = idx;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', idx);
        setTimeout(() => item.classList.add('dragging'), 0);
      });

      item.addEventListener('dragend', () => {
        item.classList.remove('dragging');
        document.querySelectorAll('.rule-item').forEach(el => el.classList.remove('drag-over'));
      });

      item.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        item.classList.add('drag-over');
      });

      item.addEventListener('dragleave', () => {
        item.classList.remove('drag-over');
      });

      item.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        item.classList.remove('drag-over');
        const fromIdx = dragSrcIndex !== null ? dragSrcIndex : parseInt(e.dataTransfer.getData('text/plain'), 10);
        const toIdx = idx;
        if (fromIdx !== null && !isNaN(fromIdx) && fromIdx !== toIdx) {
          engine.reorderRules(fromIdx, toIdx);
          logToServerConsole(`[Rule Priority Changed] Moved Rule #${fromIdx + 1} to Priority #${toIdx + 1}`, 'info');
          renderRulesList();
        }
      });

      // Move Up handler
      const moveUpBtn = item.querySelector('.move-rule-up');
      if (moveUpBtn && idx > 0) {
        moveUpBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          engine.reorderRules(idx, idx - 1);
          logToServerConsole(`[Rule Priority Changed] Moved Rule #${idx + 1} up to #${idx}`, 'info');
          renderRulesList();
        });
      }

      // Move Down handler
      const moveDownBtn = item.querySelector('.move-rule-down');
      if (moveDownBtn && idx < engine.rules.length - 1) {
        moveDownBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          engine.reorderRules(idx, idx + 1);
          logToServerConsole(`[Rule Priority Changed] Moved Rule #${idx + 1} down to #${idx + 2}`, 'info');
          renderRulesList();
        });
      }

      // Click rule to select and auto-populate Request Crafter to test it
      item.addEventListener('click', (e) => {
        if (e.target.closest('.rule-actions') || e.target.closest('.rule-drag-handle')) return;
        selectedRuleId = rule.id;
        document.querySelectorAll('.rule-item').forEach(el => el.classList.remove('selected-rule'));
        item.classList.add('selected-rule');

        // Auto-configure Request Crafter to easily test this rule
        if (rule.dstPort === '80') {
          selectPreset('http');
        } else if (rule.dstPort === '22') {
          selectPreset('ssh');
        } else if (rule.dstPort === '53') {
          selectPreset('dns');
        } else if (rule.dstPort === '443') {
          tabCustomBtn.click();
          reqPort.value = '443';
          reqDest.value = '10.0.0.10';
          reqMethod.value = 'GET';
        } else if (rule.dstPort && rule.dstPort.includes('23')) {
          tabCustomBtn.click();
          reqPort.value = '23';
          reqDest.value = '10.0.0.10';
          reqMethod.value = 'SYN';
        } else if (rule.dstPort === '3306') {
          selectPreset('db');
        }

        logToServerConsole(`[Firewall Rule Selected] #${rule.priority}: ${rule.name} (Action: ${rule.action})`, 'info');
      });

      // Toggle rule handler
      item.querySelector('.toggle-rule').addEventListener('click', (e) => {
        e.stopPropagation();
        engine.toggleRule(rule.id);
        logToServerConsole(`[Rule ${rule.enabled ? 'Enabled' : 'Disabled'}] #${rule.priority}: ${rule.name}`, rule.enabled ? 'info' : 'warning');
        renderRulesList();
      });

      // Delete rule handler
      item.querySelector('.delete-rule').addEventListener('click', (e) => {
        e.stopPropagation();
        logToServerConsole(`[Rule Deleted] #${rule.priority}: ${rule.name}`, 'warning');
        engine.deleteRule(rule.id);
        renderRulesList();
      });

      rulesListContainer.appendChild(item);
    });
  }

  // --- Add Rule Modal Handlers ---
  addRuleBtn.addEventListener('click', () => {
    ruleModal.classList.remove('hidden');
  });

  closeModalBtn.addEventListener('click', () => {
    ruleModal.classList.add('hidden');
  });

  cancelRuleBtn.addEventListener('click', () => {
    ruleModal.classList.add('hidden');
  });

  // Auto-select text on focus so user can type without keeping default asterisk
  ['ruleSrcIp', 'ruleDstIp', 'ruleSrcPort', 'ruleDstPort'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('focus', function() { this.select(); });
  });

  saveRuleBtn.addEventListener('click', () => {
    const name = document.getElementById('ruleName').value.trim();
    if (!name) {
      alert('Please enter a rule name');
      return;
    }

    const action = document.getElementById('ruleAction').value;
    const protocol = document.getElementById('ruleProtocol').value;
    const srcIp = document.getElementById('ruleSrcIp').value.trim() || '*';
    const dstIp = document.getElementById('ruleDstIp').value.trim() || '*';
    
    let srcPort = document.getElementById('ruleSrcPort').value.trim() || '*';
    if (srcPort.startsWith('*') && srcPort.length > 1) {
      srcPort = srcPort.replace(/^\*+/, '').trim();
    }

    let dstPort = document.getElementById('ruleDstPort').value.trim() || '*';
    if (dstPort.startsWith('*') && dstPort.length > 1) {
      dstPort = dstPort.replace(/^\*+/, '').trim();
    }

    engine.addRule({
      name,
      action,
      protocol,
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      state: 'ANY'
    });

    ruleModal.classList.add('hidden');
    renderRulesList();
    document.getElementById('ruleForm').reset();
  });

  // --- Deep Packet Inspector Modal ---
  window.openPacketInspector = function(packet) {
    const evalRes = packet.evalResult || engine.evaluatePacket(packet);

    inspectorContent.innerHTML = `
      <div class="osi-layer-box">
        <div class="osi-layer-title">Layer 2 &bull; Data Link (Ethernet Frame)</div>
        <div class="osi-fields-grid">
          <div><span class="osi-field-name">Source MAC:</span> <span class="osi-field-val">52:54:00:12:34:56</span></div>
          <div><span class="osi-field-name">Destination MAC:</span> <span class="osi-field-val">52:54:00:AB:CD:EF</span></div>
          <div><span class="osi-field-name">EtherType:</span> <span class="osi-field-val">0x0800 (IPv4)</span></div>
          <div><span class="osi-field-name">Frame Size:</span> <span class="osi-field-val">${packet.size || 128} bytes</span></div>
        </div>
      </div>

      <div class="osi-layer-box">
        <div class="osi-layer-title">Layer 3 &bull; Network Layer (IPv4 Header)</div>
        <div class="osi-fields-grid">
          <div><span class="osi-field-name">Source IP:</span> <span class="osi-field-val">${packet.srcIp}</span></div>
          <div><span class="osi-field-name">Destination IP:</span> <span class="osi-field-val">${packet.dstIp}</span></div>
          <div><span class="osi-field-name">TTL:</span> <span class="osi-field-val">64</span></div>
          <div><span class="osi-field-name">Protocol:</span> <span class="osi-field-val">${packet.protocol}</span></div>
        </div>
      </div>

      <div class="osi-layer-box">
        <div class="osi-layer-title">Layer 4 &bull; Transport Layer (${packet.protocol || 'TCP'} Header)</div>
        <div class="osi-fields-grid">
          <div><span class="osi-field-name">Source Port:</span> <span class="osi-field-val">${packet.srcPort}</span></div>
          <div><span class="osi-field-name">Destination Port:</span> <span class="osi-field-val">${packet.dstPort}</span></div>
          <div><span class="osi-field-name">Flags:</span> <span class="osi-field-val">${packet.flags || 'SYN'}</span></div>
          <div><span class="osi-field-name">Window Size:</span> <span class="osi-field-val">65535</span></div>
        </div>
      </div>

      <div class="osi-layer-box">
        <div class="osi-layer-title">Layer 7 &bull; Application Layer Payload</div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: #334155; margin-top: 4px;">
          ${escapeHtml(packet.info || packet.label || 'No payload data')}
        </div>
      </div>

      <div class="osi-layer-box" style="border-left: 4px solid ${evalRes.verdict === 'ALLOWED' ? 'var(--color-success)' : 'var(--color-danger)'};">
        <div class="osi-layer-title" style="color: ${evalRes.verdict === 'ALLOWED' ? 'var(--color-success)' : 'var(--color-danger)'};">
          Firewall Decision &bull; ${evalRes.verdict}
        </div>
        <div class="osi-fields-grid">
          <div><span class="osi-field-name">Matching Rule:</span> <span class="osi-field-val">#${evalRes.matchedRule ? evalRes.matchedRule.priority : '-'} (${evalRes.matchedRule ? evalRes.matchedRule.name : 'Default Policy'})</span></div>
          <div><span class="osi-field-name">Action:</span> <span class="osi-field-val">${evalRes.verdict}</span></div>
        </div>
      </div>
    `;

    packetInspectorModal.classList.remove('hidden');
  };

  closeInspectorBtn.addEventListener('click', () => {
    packetInspectorModal.classList.add('hidden');
  });

  // --- Initial Data Seeding (matching the reference image) ---
  function seedInitialData() {
    // 1. Initial Timeline Rows
    const initialPackets = [
      { time: '00:03:21', srcIp: '192.168.1.50', dstIp: '10.0.0.10', protocol: 'HTTP', info: 'GET / HTTP/1.1', status: 'ALLOWED' },
      { time: '00:03:21', srcIp: '10.0.0.10', dstIp: '192.168.1.50', protocol: 'HTTP', info: '200 OK (2.4 KB)', status: 'ALLOWED' },
      { time: '00:03:22', srcIp: '192.168.1.50', dstIp: '10.0.0.10', protocol: 'TCP', info: 'SYN(Port 22)', status: 'BLOCKED' },
      { time: '00:03:22', srcIp: '192.168.1.50', dstIp: '8.8.8.8', protocol: 'DNS', info: 'Query: example.com', status: 'ALLOWED' },
      { time: '00:03:22', srcIp: '8.8.8.8', dstIp: '192.168.1.50', protocol: 'DNS', info: 'Response (93.184.216.34)', status: 'ALLOWED' },
      { time: '00:03:23', srcIp: '192.168.1.50', dstIp: '10.0.0.10', protocol: 'TCP', info: 'SYN(Port 80)', status: 'ALLOWED' },
      { time: '00:03:23', srcIp: '10.0.0.10', dstIp: '192.168.1.50', protocol: 'TCP', info: 'SYN-ACK', status: 'ALLOWED' },
      { time: '00:03:24', srcIp: '192.168.1.50', dstIp: '10.0.0.10', protocol: 'HTTP', info: 'GET /admin', status: 'ALLOWED' }
    ];

    timelineBody.innerHTML = '';
    packetCounter = 0;

    initialPackets.forEach((p, idx) => {
      packetCounter++;
      const row = document.createElement('tr');
      const badgeClass = p.status === 'ALLOWED' ? 'allowed' : 'blocked';

      row.innerHTML = `
        <td>${idx + 1}</td>
        <td>${p.time}</td>
        <td>${p.srcIp} &rarr; ${p.dstIp}</td>
        <td>${p.protocol}</td>
        <td>${p.info}</td>
        <td><span class="status-badge ${badgeClass}">${p.status}</span></td>
      `;

      const pktObj = {
        srcIp: p.srcIp,
        dstIp: p.dstIp,
        srcPort: p.status === 'BLOCKED' ? 51234 : 51230,
        dstPort: p.protocol === 'HTTP' ? 80 : (p.protocol === 'DNS' ? 53 : 22),
        protocol: p.protocol,
        info: p.info,
        label: p.info,
        size: 1024,
        evalResult: { verdict: p.status, matchedRule: { priority: p.status === 'BLOCKED' ? 2 : 3, name: p.status === 'BLOCKED' ? 'Block SSH' : 'Allow HTTP' } }
      };

      row.addEventListener('click', () => openPacketInspector(pktObj));
      timelineBody.appendChild(row);
    });

    timelineCounter.textContent = `${packetCounter} packets`;

    // 2. Initial Server Console Logs
    consoleBody.innerHTML = `
      <div class="log-entry"><span class="log-msg">[00:03:21] Incoming connection from 192.168.1.50</span></div>
      <div class="log-entry"><span class="log-msg">[00:03:21] HTTP GET /</span></div>
      <div class="log-entry"><span class="log-msg success">[00:03:21] ✓ 200 OK (2.4 KB)</span></div>
      <div class="log-entry"><span class="log-msg error">[00:03:22] Blocked connection attempt</span></div>
      <div class="log-entry"><span class="log-msg error">[00:03:22] Source: 192.168.1.50</span></div>
      <div class="log-entry"><span class="log-msg error">[00:03:22] Destination: 10.0.0.10:22</span></div>
      <div class="log-entry"><span class="log-msg error">[00:03:22] Rule: #2 (Block SSH)</span></div>
      <div class="log-entry"><span class="log-msg info">[00:03:22] DNS Query: example.com</span></div>
      <div class="log-entry"><span class="log-msg success">[00:03:22] DNS Response: 93.184.216.34</span></div>
      <div class="log-entry"><span class="log-msg info">[00:03:23] TCP Handshake completed</span></div>
      <div class="log-entry"><span class="log-msg">[00:03:23] HTTP GET /admin</span></div>
      <div class="log-entry"><span class="log-msg success">[00:03:23] ✓ 200 OK (1.1 KB)</span></div>
    `;
  }

  // --- Reset Simulation ---
  resetBtn.addEventListener('click', () => {
    simSeconds = 0;
    timerDisplay.textContent = formatTime(simSeconds);
    engine.resetRules();
    seedInitialData();
    renderRulesList();
  });

  // --- Clear Console ---
  clearConsoleBtn.addEventListener('click', () => {
    consoleBody.innerHTML = '';
  });

  // --- Event Listeners ---
  playPauseBtn.addEventListener('click', togglePlayPause);
  sendRequestBtn.addEventListener('click', handleSendRequest);

  // Tab toggles
  tabPresetsBtn.addEventListener('click', () => {
    tabPresetsBtn.classList.add('active');
    tabCustomBtn.classList.remove('active');
    presetsContainer.style.display = 'flex';
  });

  tabCustomBtn.addEventListener('click', () => {
    tabCustomBtn.classList.add('active');
    tabPresetsBtn.classList.remove('active');
    presetsContainer.style.display = 'none';
    selectPreset('custom');
  });

  // Preset Cards click
  document.querySelectorAll('.preset-card').forEach(card => {
    card.addEventListener('click', () => {
      selectPreset(card.dataset.preset);
    });
  });

  // Initialize
  renderRulesList();
  seedInitialData();
  startTimer();
  selectPreset('http');
});
