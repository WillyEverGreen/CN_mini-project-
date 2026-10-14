/**
 * PacketGuard Application Controller
 * Coordinates UI, Firewall Engine, Topology Animation, Multi-Client/Server routing,
 * Live Website Filtering, and Interactive Client Browser Inspection.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Core Engines
  const engine = new FirewallEngine();
  const sim = new TopologySimulator('topologyStage', engine);

  // Application State
  let simSeconds = 204;
  let isRunning = true;
  let timerInterval = null;
  let packetCounter = 0;
  let currentPreset = 'http';
  let lastLiveResult = null;

  // DOM Elements: Controls
  const playPauseBtn = document.getElementById('playPauseBtn');
  const playIcon = document.getElementById('playIcon');
  const pauseIcon = document.getElementById('pauseIcon');
  const simStatusPill = document.getElementById('simStatusPill');
  const simStatusText = document.getElementById('simStatusText');
  const timerDisplay = document.getElementById('timerDisplay');
  const resetBtn = document.getElementById('resetBtn');

  // DOM Elements: Request Crafter
  const tabPresetsBtn = document.getElementById('tabPresetsBtn');
  const tabCustomBtn = document.getElementById('tabCustomBtn');
  const presetsContainer = document.getElementById('presetsContainer');
  const reqClient = document.getElementById('reqClient');
  const reqDestSelect = document.getElementById('reqDestSelect');
  const reqMethod = document.getElementById('reqMethod');
  const reqDest = document.getElementById('reqDest');
  const reqPort = document.getElementById('reqPort');
  const reqPath = document.getElementById('reqPath');
  const reqHeaders = document.getElementById('reqHeaders');
  const sendRequestBtn = document.getElementById('sendRequestBtn');
  const openBrowserPreviewBtn = document.getElementById('openBrowserPreviewBtn');
  const packetRateValue = document.getElementById('packetRateValue');
  const sparkBars = document.querySelectorAll('.spark-bar');

  // DOM Elements: Timeline & Console
  const timelineBody = document.getElementById('timelineBody');
  const timelineCounter = document.getElementById('timelineCounter');
  const consoleBody = document.getElementById('consoleBody');
  const clearConsoleBtn = document.getElementById('clearConsoleBtn');

  // DOM Elements: Rules
  const rulesListContainer = document.getElementById('rulesListContainer');
  const addRuleBtn = document.getElementById('addRuleBtn');
  const ruleModal = document.getElementById('ruleModal');
  const closeModalBtn = document.getElementById('closeModalBtn');
  const cancelRuleBtn = document.getElementById('cancelRuleBtn');
  const saveRuleBtn = document.getElementById('saveRuleBtn');

  // DOM Elements: Inspector
  const packetInspectorModal = document.getElementById('packetInspectorModal');
  const closeInspectorBtn = document.getElementById('closeInspectorBtn');
  const inspectorContent = document.getElementById('inspectorContent');

  // DOM Elements: Browser Preview Modal
  const browserPreviewModal = document.getElementById('browserPreviewModal');
  const closeBrowserBtn = document.getElementById('closeBrowserBtn');
  const browserRefreshBtn = document.getElementById('browserRefreshBtn');
  const browserTabTitle = document.getElementById('browserTabTitle');
  const browserFavicon = document.getElementById('browserFavicon');
  const browserUrlDisplay = document.getElementById('browserUrlDisplay');
  const browserSecBadge = document.getElementById('browserSecBadge');
  const browserLatencyPill = document.getElementById('browserLatencyPill');
  const browserStatusChip = document.getElementById('browserStatusChip');
  const browserViewport = document.getElementById('browserViewport');
  const browserLoadingState = document.getElementById('browserLoadingState');
  const browserRenderContent = document.getElementById('browserRenderContent');

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

  // Animated Sparkline Simulator
  setInterval(() => {
    if (!isRunning) return;
    const rate = Math.floor(Math.random() * 5) + 4;
    packetRateValue.textContent = `${rate} packets/sec`;
    sparkBars.forEach(bar => {
      const height = Math.floor(Math.random() * 65) + 30;
      bar.style.height = `${height}%`;
    });
  }, 1200);

  // --- Multi-Client / Multi-Server Node Highlighting ---
  function updateActiveNodeHighlights() {
    // Clients
    const currentSrcIp = reqClient.value;
    document.querySelectorAll('.topo-node.node-client').forEach(el => {
      el.classList.toggle('selected-node', el.dataset.client === currentSrcIp);
    });

    // Servers
    const currentDst = reqDest.value.trim();
    document.querySelectorAll('.topo-node.node-server').forEach(el => {
      el.classList.toggle('selected-node', el.dataset.server === currentDst);
    });
  }

  reqClient.addEventListener('change', updateActiveNodeHighlights);

  // Destination quick select dropdown handler
  reqDestSelect.addEventListener('change', () => {
    const opt = reqDestSelect.selectedOptions[0];
    const val = opt.value;

    if (val === 'custom') {
      reqDest.focus();
      return;
    }

    reqDest.value = val;
    if (opt.dataset.port) reqPort.value = opt.dataset.port;
    if (opt.dataset.proto) {
      reqMethod.value = opt.dataset.proto === 'UDP' ? 'DNS_QUERY' : (val.includes('3306') || val.includes('22') ? 'SYN' : 'GET');
    }

    updateActiveNodeHighlights();
  });

  reqDest.addEventListener('input', updateActiveNodeHighlights);

  // --- Presets Data Configuration ---
  const presetsConfig = {
    http: {
      client: '192.168.1.50',
      destSelect: '10.0.0.10',
      method: 'GET',
      dest: '10.0.0.10',
      port: 80,
      path: '/index.html',
      headers: 'User-Agent: PacketGuard/2.0\nAccept: text/html',
      protocol: 'HTTP',
      label: 'HTTP GET'
    },
    'live-google': {
      client: '192.168.1.50',
      destSelect: 'google.com',
      method: 'GET',
      dest: 'google.com',
      port: 443,
      path: '/',
      headers: 'Host: google.com\nUser-Agent: Chrome/120.0',
      protocol: 'HTTPS',
      label: 'Google (Blocked Demo)'
    },
    'live-example': {
      client: '192.168.1.50',
      destSelect: 'example.com',
      method: 'GET',
      dest: 'example.com',
      port: 80,
      path: '/',
      headers: 'Host: example.com\nUser-Agent: PacketGuard/2.0',
      protocol: 'HTTP',
      label: 'example.com (Live Fetch)'
    },
    'rogue-db': {
      client: '192.168.1.99', // Rogue client
      destSelect: '10.0.0.20',
      method: 'SYN',
      dest: '10.0.0.20',
      port: 3306,
      path: '',
      headers: 'SQL Probe: SELECT * FROM users',
      protocol: 'TCP',
      label: 'Rogue SQL Probe'
    },
    ssh: {
      client: '192.168.1.50',
      destSelect: '10.0.0.30',
      method: 'SYN',
      dest: '10.0.0.30',
      port: 22,
      path: '',
      headers: 'SSH-2.0-OpenSSH_9.0',
      protocol: 'TCP',
      label: 'SSH Bastion Handshake'
    },
    dns: {
      client: '192.168.1.50',
      destSelect: '8.8.8.8',
      method: 'DNS_QUERY',
      dest: '8.8.8.8',
      port: 53,
      path: '',
      headers: 'Query: example.com (IN A)',
      protocol: 'DNS',
      label: 'DNS Query (8.8.8.8)'
    },
    portscan: {
      client: '192.168.1.50',
      destSelect: '10.0.0.10',
      method: 'SYN',
      dest: '10.0.0.10',
      port: 80,
      path: '',
      headers: 'Nmap TCP SYN Port Sweep',
      protocol: 'TCP',
      label: 'Port Scan Sweep'
    },
    custom: {
      client: '192.168.1.50',
      destSelect: 'custom',
      method: 'GET',
      dest: '10.0.0.10',
      port: 443,
      path: '/api/v1/status',
      headers: 'Authorization: Bearer token_sec_99',
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

    if (cfg.client) reqClient.value = cfg.client;
    if (cfg.destSelect) reqDestSelect.value = cfg.destSelect;
    reqMethod.value = cfg.method;
    reqDest.value = cfg.dest;
    reqPort.value = cfg.port;
    reqPath.value = cfg.path;
    reqHeaders.value = cfg.headers;

    const isWeb = cfg.protocol === 'HTTP' || cfg.protocol === 'HTTPS' || cfg.port === 80 || cfg.port === 443;
    document.getElementById('pathGroup').style.display = isWeb ? 'flex' : 'none';

    updateActiveNodeHighlights();
  }

  // --- Send Request Handler ---
  function handleSendRequest() {
    if (!isRunning) togglePlayPause();

    if (currentPreset === 'portscan') {
      executePortScan();
      return;
    }

    const srcClientIp = reqClient.value || '192.168.1.50';
    const method = reqMethod.value;
    const dest = reqDest.value.trim() || '10.0.0.10';
    const port = parseInt(reqPort.value, 10) || 80;
    const path = reqPath.value.trim() || '/';
    const headers = reqHeaders.value.trim();

    let protocol = 'TCP';
    let info = '';
    let label = '';
    let flags = 'SYN';
    let domain = null;

    // Check if destination is a real domain
    if (dest.includes('.') && !dest.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      domain = dest.toLowerCase();
    }

    let appProtocol = 'TCP';
    if (method === 'DNS_QUERY' || port === 53) {
      protocol = 'UDP';
      appProtocol = 'DNS';
      info = `DNS Query: ${dest === '8.8.8.8' ? 'example.com' : dest}`;
      label = 'DNS Query';
      flags = 'QUERY';
    } else if (method === 'PING') {
      protocol = 'ICMP';
      appProtocol = 'ICMP';
      info = 'Echo Request';
      label = 'ICMP Echo';
      flags = 'NONE';
    } else if (port === 80 || port === 443 || domain) {
      protocol = 'TCP';
      appProtocol = port === 443 ? 'HTTPS' : 'HTTP';
      info = `${method} ${path || '/'} HTTP/1.1 (${dest})`;
      label = `${appProtocol} ${dest}`;
      flags = 'ACK, PSH';
    } else if (port === 22) {
      protocol = 'TCP';
      appProtocol = 'SSH';
      info = 'SYN (Port 22 SSH)';
      label = 'TCP SYN (22)';
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

    const packetData = {
      srcIp: srcClientIp,
      dstIp: dest,
      domain: domain,
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
    };

    // Dispatch Packet in Simulation Topology
    sim.sendPacket(packetData);

    // If destination is a real domain or web site, trigger live test check
    if (domain || port === 80 || port === 443) {
      executeLiveSiteCheck(dest, port, srcClientIp);
    }
  }

  // --- Live Site Real Request & Blocking Inspector ---
  async function executeLiveSiteCheck(targetDomainOrIp, port, clientIp) {
    const isDomain = !targetDomainOrIp.match(/^\d+\.\d+\.\d+\.\d+$/);
    const domainName = isDomain ? targetDomainOrIp : (targetDomainOrIp === '10.0.0.10' ? 'local-web.corp' : targetDomainOrIp);
    const isGoogle = domainName.includes('google');
    const targetUrl = `http${port === 443 ? 's' : ''}://${targetDomainOrIp}${port === 80 || port === 443 ? '' : ':' + port}`;

    try {
      // 1. Try real Python backend endpoint first
      const res = await fetch('/api/live-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl,
          srcIp: clientIp,
          clientName: reqClient.selectedOptions[0]?.dataset.name || 'Client',
          dstPort: port
        })
      });

      if (res.ok) {
        const data = await res.json();
        lastLiveResult = data;
        updateBrowserModalUI(data);
        return;
      }
    } catch (e) {
      // Server.py might not be running if opened directly as file:///
    }

    // 2. Standalone Fallback: Accurate simulation of live blocking vs allowing
    const packetCheck = {
      srcIp: clientIp,
      dstIp: targetDomainOrIp,
      domain: isDomain ? domainName : null,
      srcPort: 52000,
      dstPort: port,
      protocol: 'TCP'
    };
    const evalRes = engine.evaluatePacket(packetCheck);

    if (evalRes.verdict === 'BLOCKED' || isGoogle) {
      lastLiveResult = {
        verdict: 'BLOCKED',
        statusCode: 403,
        statusText: 'Forbidden (Blocked by PacketGuard Firewall)',
        domain: domainName,
        resolvedIp: isGoogle ? '142.250.190.46' : '10.0.0.20',
        targetUrl: targetUrl,
        port: port,
        srcIp: clientIp,
        clientName: reqClient.selectedOptions[0]?.dataset.name || 'Client',
        ruleMatched: evalRes.matchedRule?.name || 'Block Google & Restricted Sites',
        htmlPreview: `
          <div style="font-family: system-ui, sans-serif; max-width: 620px; margin: 30px auto; padding: 28px; border: 2px solid #EF4444; border-radius: 12px; background: #FEF2F2; color: #991B1B;">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
              <div style="background: #EF4444; color: white; width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold;">✕</div>
              <div>
                <h2 style="margin: 0; font-size: 20px; color: #991B1B;">403 Forbidden - Request Deflected</h2>
                <span style="font-size: 13px; color: #B91C1C;">PacketGuard Layer-7 Security Gateway</span>
              </div>
            </div>
            <hr style="border: 0; border-top: 1px solid #FCA5A5; margin: 16px 0;">
            <p style="font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
              Your HTTP/HTTPS request from <strong>${clientIp}</strong> to destination 
              <strong style="color: #DC2626;">${domainName} (Port ${port})</strong> was intercepted and blocked by corporate firewall policy.
            </p>
            <div style="background: white; border-radius: 8px; padding: 12px 16px; border: 1px solid #F87171; font-size: 13px; font-family: monospace;">
              <div><strong>Matched Policy:</strong> Rule #${evalRes.matchedRule?.priority || 2}: ${evalRes.matchedRule?.name || 'Domain Policy'}</div>
              <div><strong>Target Host:</strong> ${domainName}</div>
              <div><strong>Action:</strong> TCP RST / Deflected Drop</div>
            </div>
          </div>
        `,
        latencyMs: 14,
        timestamp: new Date().toLocaleTimeString()
      };
    } else {
      // Allowed: Live internet domain fetch simulation
      lastLiveResult = {
        verdict: 'ALLOWED',
        statusCode: 200,
        statusText: '200 OK',
        domain: domainName,
        resolvedIp: '93.184.216.34',
        targetUrl: targetUrl,
        port: port,
        srcIp: clientIp,
        clientName: reqClient.selectedOptions[0]?.dataset.name || 'Client',
        latencyMs: 78,
        htmlPreview: `
          <div style="font-family: system-ui, sans-serif; max-width: 650px; margin: 30px auto; padding: 24px; border: 1px solid #E2E8F0; border-radius: 8px; background: white;">
            <h1 style="color: #1E293B; margin-top: 0;">Example Domain</h1>
            <p style="color: #475569; line-height: 1.6;">This domain is established to be used for illustrative examples in documents through the firewall.</p>
            <div style="background: #ECFDF5; border: 1px solid #A7F3D0; border-radius: 6px; padding: 12px; margin-top: 20px; font-size: 13px; color: #065F46;">
              ✓ <strong>Verified PacketGuard Allow:</strong> Real-time internet connection allowed per Rule #3 (Allow HTTP/HTTPS).
            </div>
          </div>
        `,
        ruleMatched: 'Rule #3: Allow HTTP',
        timestamp: new Date().toLocaleTimeString()
      };
    }

    updateBrowserModalUI(lastLiveResult);
  }

  function updateBrowserModalUI(result) {
    if (!result) return;

    browserUrlDisplay.value = result.targetUrl || `https://${result.domain}`;
    browserTabTitle.textContent = `${result.domain} (${result.statusCode} ${result.verdict})`;
    browserLatencyPill.textContent = `${result.latencyMs || 25}ms`;

    if (result.verdict === 'BLOCKED') {
      browserFavicon.textContent = 'DEFLECT';
      browserSecBadge.textContent = 'Blocked by Firewall';
      browserSecBadge.className = 'security-badge blocked';
      browserStatusChip.textContent = `${result.statusCode} FORBIDDEN`;
      browserStatusChip.className = 'browser-status-chip blocked';
    } else {
      browserFavicon.textContent = 'HTTP';
      browserSecBadge.textContent = 'Verified Allowed';
      browserSecBadge.className = 'security-badge';
      browserStatusChip.textContent = `${result.statusCode} OK`;
      browserStatusChip.className = 'browser-status-chip';
    }

    browserRenderContent.innerHTML = result.htmlPreview || '<p>No preview content available</p>';
  }

  // Open Browser Modal Button
  openBrowserPreviewBtn.addEventListener('click', () => {
    if (!lastLiveResult) {
      executeLiveSiteCheck(reqDest.value.trim() || '10.0.0.10', parseInt(reqPort.value, 10) || 80, reqClient.value);
    }
    browserPreviewModal.classList.remove('hidden');
  });

  closeBrowserBtn.addEventListener('click', () => {
    browserPreviewModal.classList.add('hidden');
  });

  browserRefreshBtn.addEventListener('click', () => {
    executeLiveSiteCheck(reqDest.value.trim() || '10.0.0.10', parseInt(reqPort.value, 10) || 80, reqClient.value);
  });

  // --- Port Scan Simulator ---
  function executePortScan() {
    const scanPorts = [21, 22, 23, 80, 443, 3306];
    const srcIp = reqClient.value || '192.168.1.50';
    logToServerConsole(`[Nmap Port Scan] Sweeping target 10.0.0.10 from ${srcIp}...`, 'info');

    scanPorts.forEach((targetPort, idx) => {
      setTimeout(() => {
        const ephem = Math.floor(Math.random() * 15000) + 49152;
        sim.sendPacket({
          srcIp: srcIp,
          dstIp: '10.0.0.10',
          srcPort: ephem,
          dstPort: targetPort,
          protocol: 'TCP',
          flags: 'SYN',
          method: 'SYN',
          info: `TCP SYN Port ${targetPort}`,
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
        el.classList.toggle('rule-hit', el.dataset.ruleId === ruleId);
      });
      setTimeout(() => {
        document.querySelectorAll('.rule-item').forEach(el => el.classList.remove('rule-hit'));
      }, 1500);
    },

    onPacketLogged: (packet, verdict) => {
      addPacketToTimeline(packet, verdict);
    },

    onServerActivity: (act) => {
      if (act.type === 'blocked') {
        const ruleName = act.matchedRule ? `Rule #${act.matchedRule.priority} (${act.matchedRule.name})` : 'Default Policy';
        logToServerConsole(`[FIREWALL DROP] Packet ${act.packet.srcIp} -> ${act.packet.dstIp}:${act.packet.dstPort} (${act.packet.protocol}) blocked by ${ruleName}`, 'error');
      } else if (act.type === 'received') {
        logToServerConsole(`[SERVER RECV] ${act.packet.dstIp} received ${act.packet.protocol} from ${act.packet.srcIp}:${act.packet.srcPort}`, 'info');
        logToServerConsole(`[SERVER SEND] ${act.response.srcIp} responded: ${act.response.info}`, 'success');
      } else if (act.type === 'dns_response') {
        logToServerConsole(`[INTERNET GATEWAY] DNS Resolved query for ${act.packet.srcIp}: ${act.response.info}`, 'success');
      }
    }
  });

  // --- Timeline Logging ---
  function addPacketToTimeline(packet, verdict) {
    packetCounter++;
    timelineCounter.textContent = `${packetCounter} packets logged`;

    const tr = document.createElement('tr');
    tr.className = `timeline-row ${verdict === 'BLOCKED' ? 'row-blocked' : 'row-allowed'}`;

    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;

    const ruleText = packet.evalResult?.matchedRule ? `#${packet.evalResult.matchedRule.priority} ${packet.evalResult.matchedRule.name}` : 'Default Deny';

    tr.innerHTML = `
      <td>${timeStr}</td>
      <td><span class="ip-tag">${packet.srcIp}</span></td>
      <td><span class="ip-tag">${packet.domain || packet.dstIp}</span></td>
      <td><span class="proto-tag ${packet.protocol.toLowerCase()}">${packet.protocol}</span></td>
      <td>${packet.dstPort || '-'}</td>
      <td><span class="verdict-tag ${verdict.toLowerCase()}">${verdict}</span></td>
      <td class="rule-cell" title="${escapeHtml(ruleText)}">${escapeHtml(ruleText)}</td>
      <td class="info-cell" title="${escapeHtml(packet.info || '')}">${escapeHtml(packet.info || '-')}</td>
    `;

    tr.addEventListener('click', () => {
      openPacketInspector(packet);
    });

    timelineBody.insertBefore(tr, timelineBody.firstChild);

    // Retain maximum 40 entries
    while (timelineBody.children.length > 40) {
      timelineBody.removeChild(timelineBody.lastChild);
    }
  }

  // --- Server Console Logging ---
  function logToServerConsole(message, type = 'default') {
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;

    const now = new Date();
    const ts = `[${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}]`;

    entry.innerHTML = `<span class="log-ts">${ts}</span> <span class="log-msg">${escapeHtml(message)}</span>`;
    consoleBody.appendChild(entry);
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  // --- Rule List Rendering & Priority Management ---
  let draggedRuleIndex = null;

  function renderRulesList(highlightRuleId = null) {
    rulesListContainer.innerHTML = '';

    engine.rules.forEach((rule, index) => {
      const item = document.createElement('div');
      item.className = `rule-item ${rule.enabled ? '' : 'rule-disabled disabled'}`;
      item.dataset.ruleId = rule.id;
      item.dataset.ruleIndex = index;
      item.setAttribute('draggable', 'true');
      item.setAttribute('tabindex', '0');
      item.setAttribute('role', 'listitem');

      if (rule.id === highlightRuleId) {
        item.classList.add('rule-just-moved');
        setTimeout(() => item.classList.remove('rule-just-moved'), 1200);
      }

      const actionBadge = rule.action === 'ALLOW' ?
        '<span class="rule-action allow">ALLOW</span>' :
        '<span class="rule-action deny">DENY</span>';

      const stateBadge = rule.state && rule.state !== 'ANY' ?
        `<span class="rule-spec-tag state">${rule.state}</span>` : '';

      let domainDisplay = rule.domain;
      let domainTitle = rule.domain;
      if (rule.domain && rule.domain.includes(',')) {
        const parts = rule.domain.split(',').map(s => s.trim());
        domainDisplay = `${parts[0]} (+${parts.length - 1})`;
      }
      const domainBadge = rule.domain && rule.domain !== '*' && rule.domain !== 'ANY' ?
        `<span class="rule-spec-tag domain" title="${escapeHtml(domainTitle)}">${escapeHtml(domainDisplay)}</span>` : '';

      const srcBadge = rule.srcIp !== '*' ? `<span class="rule-spec-tag ip">src: ${rule.srcIp}</span>` : '';
      const dstBadge = rule.dstIp !== '*' ? `<span class="rule-spec-tag ip">dst: ${rule.dstIp}</span>` : '';

      item.innerHTML = `
        <div class="rule-drag-handle" title="Drag to reorder priority (or use ▲/▼ buttons)" draggable="false">&#8942;&#8942;</div>
        <div class="rule-priority" title="Priority #${rule.priority} (Click to set custom priority position)">#${rule.priority}</div>
        <div class="rule-details">
          <div class="rule-top-line">
            <span class="rule-name" title="${escapeHtml(rule.name)}">${escapeHtml(rule.name)}</span>
            ${actionBadge}
          </div>
          <div class="rule-specs">
            <span class="rule-spec-tag proto">${rule.protocol}</span>
            ${rule.dstPort !== '*' ? `<span class="rule-spec-tag port">port: ${rule.dstPort}</span>` : ''}
            ${domainBadge}
            ${srcBadge}
            ${dstBadge}
            ${stateBadge}
          </div>
        </div>
        <div class="rule-actions">
          <button type="button" class="rule-action-btn move-up-rule" title="Move Up (Higher Priority)" ${index === 0 ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="18 15 12 9 6 15"></polyline>
            </svg>
          </button>
          <button type="button" class="rule-action-btn move-down-rule" title="Move Down (Lower Priority)" ${index === engine.rules.length - 1 ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </button>
          <button type="button" class="rule-action-btn toggle-rule" title="${rule.enabled ? 'Disable' : 'Enable'} rule">
            ${rule.enabled ? '✓' : '⊘'}
          </button>
          <button type="button" class="rule-action-btn delete-rule" title="Delete rule">&times;</button>
        </div>
      `;

      // Move Up button
      const moveUpBtn = item.querySelector('.move-up-rule');
      if (moveUpBtn) {
        moveUpBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (index > 0) {
            const movedRule = rule;
            engine.reorderRules(index, index - 1);
            renderRulesList(movedRule.id);
            logToServerConsole(`[POLICY REORDER] Rule "${movedRule.name}" moved up to Priority #${index}`, 'info');
          }
        });
      }

      // Move Down button
      const moveDownBtn = item.querySelector('.move-down-rule');
      if (moveDownBtn) {
        moveDownBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (index < engine.rules.length - 1) {
            const movedRule = rule;
            engine.reorderRules(index, index + 1);
            renderRulesList(movedRule.id);
            logToServerConsole(`[POLICY REORDER] Rule "${movedRule.name}" moved down to Priority #${index + 2}`, 'info');
          }
        });
      }

      // Click on Priority Badge to jump to specific priority
      const priorityBadge = item.querySelector('.rule-priority');
      if (priorityBadge) {
        priorityBadge.addEventListener('click', (e) => {
          e.stopPropagation();
          const currentPos = index + 1;
          const input = prompt(
            `Move Rule #${currentPos} ("${rule.name}") to new priority position (1 to ${engine.rules.length}):`,
            String(currentPos)
          );
          if (input !== null) {
            const targetPos = parseInt(input.trim(), 10);
            if (!isNaN(targetPos) && targetPos >= 1 && targetPos <= engine.rules.length) {
              if (targetPos !== currentPos) {
                engine.reorderRules(index, targetPos - 1);
                renderRulesList(rule.id);
                logToServerConsole(`[POLICY REORDER] Rule "${rule.name}" moved from #${currentPos} to Priority #${targetPos}`, 'info');
              }
            } else {
              alert(`Invalid position. Please enter a valid number between 1 and ${engine.rules.length}.`);
            }
          }
        });
      }

      // Toggle rule active/disabled
      item.querySelector('.toggle-rule').addEventListener('click', (e) => {
        e.stopPropagation();
        engine.toggleRule(rule.id);
        renderRulesList();
        logToServerConsole(`[RULE UPDATE] Rule #${rule.priority} ("${rule.name}") ${rule.enabled ? 'Enabled' : 'Disabled'}`, 'info');
      });

      // Delete rule
      item.querySelector('.delete-rule').addEventListener('click', (e) => {
        e.stopPropagation();
        const deletedName = rule.name;
        engine.deleteRule(rule.id);
        renderRulesList();
        logToServerConsole(`[RULE DELETE] Rule "${deletedName}" removed from policy table`, 'warning');
      });

      // --- Drag and Drop Handlers ---
      item.addEventListener('dragstart', (e) => {
        // Prevent drag if initiating from an action button or prompt
        if (e.target.closest('.rule-actions') || e.target.closest('button')) {
          e.preventDefault();
          return;
        }
        draggedRuleIndex = index;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', String(index));
        setTimeout(() => {
          item.classList.add('dragging');
        }, 0);
      });

      item.addEventListener('dragend', () => {
        item.classList.remove('dragging');
        document.querySelectorAll('.rule-item').forEach(el => {
          el.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');
        });
        draggedRuleIndex = null;
      });

      item.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';

        if (draggedRuleIndex === null || draggedRuleIndex === index) {
          return;
        }

        const rect = item.getBoundingClientRect();
        const relY = e.clientY - rect.top;
        const isTopHalf = relY < rect.height / 2;

        item.classList.remove('drag-over-top', 'drag-over-bottom');
        if (isTopHalf) {
          item.classList.add('drag-over-top');
        } else {
          item.classList.add('drag-over-bottom');
        }
      });

      item.addEventListener('dragleave', (e) => {
        if (!item.contains(e.relatedTarget)) {
          item.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');
        }
      });

      item.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();

        item.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');

        if (draggedRuleIndex === null || draggedRuleIndex === index) {
          return;
        }

        const rect = item.getBoundingClientRect();
        const relY = e.clientY - rect.top;
        const isTopHalf = relY < rect.height / 2;

        let insertAt = isTopHalf ? index : index + 1;
        if (draggedRuleIndex < insertAt) {
          insertAt--;
        }

        if (draggedRuleIndex !== insertAt) {
          const movedRule = engine.rules[draggedRuleIndex];
          const oldPriority = draggedRuleIndex + 1;
          const newPriority = insertAt + 1;
          engine.reorderRules(draggedRuleIndex, insertAt);
          renderRulesList(movedRule.id);
          logToServerConsole(`[POLICY REORDER] Moved rule "${movedRule.name}" from #${oldPriority} to #${newPriority}`, 'info');
        }
      });

      // Keyboard Reordering (Alt + ArrowUp / Alt + ArrowDown)
      item.addEventListener('keydown', (e) => {
        if (e.altKey && e.key === 'ArrowUp') {
          e.preventDefault();
          if (index > 0) {
            engine.reorderRules(index, index - 1);
            renderRulesList(rule.id);
            logToServerConsole(`[POLICY REORDER] Rule "${rule.name}" moved up to Priority #${index}`, 'info');
            const targetEl = rulesListContainer.querySelector(`[data-rule-id="${rule.id}"]`);
            if (targetEl) targetEl.focus();
          }
        } else if (e.altKey && e.key === 'ArrowDown') {
          e.preventDefault();
          if (index < engine.rules.length - 1) {
            engine.reorderRules(index, index + 1);
            renderRulesList(rule.id);
            logToServerConsole(`[POLICY REORDER] Rule "${rule.name}" moved down to Priority #${index + 2}`, 'info');
            const targetEl = rulesListContainer.querySelector(`[data-rule-id="${rule.id}"]`);
            if (targetEl) targetEl.focus();
          }
        }
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

  saveRuleBtn.addEventListener('click', () => {
    const name = document.getElementById('ruleName').value.trim();
    if (!name) {
      alert('Please enter a rule name');
      return;
    }

    const action = document.getElementById('ruleAction').value;
    const protocol = document.getElementById('ruleProtocol').value;
    const domain = document.getElementById('ruleDomain').value.trim() || '*';
    const srcIp = document.getElementById('ruleSrcIp').value.trim() || '*';
    const dstIp = document.getElementById('ruleDstIp').value.trim() || '*';
    const srcPort = document.getElementById('ruleSrcPort').value.trim() || '*';
    const dstPort = document.getElementById('ruleDstPort').value.trim() || '*';
    const positionEl = document.getElementById('rulePosition');
    const position = positionEl ? positionEl.value : 'before-default';

    const newRule = engine.addRule({
      name,
      action,
      protocol,
      domain,
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      state: 'ANY',
      position
    });

    ruleModal.classList.add('hidden');
    renderRulesList(newRule.id);
    logToServerConsole(`[SECURITY POLICY] Added new rule "${newRule.name}" at Priority #${newRule.priority} (${newRule.action})`, 'success');
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

  // --- Seed Initial Timeline & Console Data ---
  function seedInitialData() {
    timelineBody.innerHTML = '';
    consoleBody.innerHTML = '';
    packetCounter = 0;

    logToServerConsole('[SYSTEM START] PacketGuard Multi-Client Stateful Firewall Online', 'success');
    logToServerConsole('[TOPOLOGY] Registered: 3 Clients (Admin .50, Dev .51, Rogue .99), 3 Servers (Web, DB, Bastion)', 'info');
    logToServerConsole('[RULESET] Loaded 10 security policy rules (First-match sequential evaluation)', 'info');
    logToServerConsole('[L7 GATEWAY] Domain filter active: Google & Search blocked per Policy Rule #2', 'warning');
  }

  // --- Reset Simulation ---
  resetBtn.addEventListener('click', () => {
    simSeconds = 0;
    timerDisplay.textContent = formatTime(simSeconds);
    engine.resetRules();
    seedInitialData();
    renderRulesList();
  });

  clearConsoleBtn.addEventListener('click', () => {
    consoleBody.innerHTML = '';
  });

  // --- Event Listeners ---
  playPauseBtn.addEventListener('click', togglePlayPause);
  sendRequestBtn.addEventListener('click', handleSendRequest);

  tabPresetsBtn.addEventListener('click', () => {
    tabPresetsBtn.classList.add('active');
    tabCustomBtn.classList.remove('active');
    presetsContainer.style.display = 'grid';
  });

  tabCustomBtn.addEventListener('click', () => {
    tabCustomBtn.classList.add('active');
    tabPresetsBtn.classList.remove('active');
    presetsContainer.style.display = 'none';
    selectPreset('custom');
  });

  document.querySelectorAll('.preset-card').forEach(card => {
    card.addEventListener('click', () => {
      selectPreset(card.dataset.preset);
    });
  });

  // Direct click selection on topology canvas nodes
  document.querySelectorAll('.topo-node[data-client]').forEach(el => {
    el.addEventListener('click', () => {
      reqClient.value = el.dataset.client;
      updateActiveNodeHighlights();
    });
  });

  document.querySelectorAll('.topo-node[data-server]').forEach(el => {
    el.addEventListener('click', () => {
      reqDestSelect.value = el.dataset.server;
      reqDest.value = el.dataset.server;
      const opt = Array.from(reqDestSelect.options).find(o => o.value === el.dataset.server);
      if (opt && opt.dataset.port) reqPort.value = opt.dataset.port;
      updateActiveNodeHighlights();
    });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Initialize
  renderRulesList();
  seedInitialData();
  startTimer();
  selectPreset('http');
});
