/**
 * PacketGuard Comprehensive Firewall Engine Test Suite
 * Validates Layer 3/4 packet filtering, 5-tuple evaluation, CIDR subnets,
 * stateful connection tracking, and rule manipulation.
 */

// Mock browser window object for Node environment
const window = {};

// Load firewall-engine.js
const fs = require('fs');
const path = require('path');
const engineCode = fs.readFileSync(path.join(__dirname, 'firewall-engine.js'), 'utf8');
eval(engineCode);

const engine = new window.FirewallEngine();
let passedTests = 0;
let totalTests = 0;

function assert(condition, testName, details = '') {
  totalTests++;
  if (condition) {
    console.log(`  \x1b[32m✔ PASS\x1b[0m [${totalTests}] ${testName}`);
    passedTests++;
  } else {
    console.error(`  \x1b[31m✘ FAIL\x1b[0m [${totalTests}] ${testName}: ${details}`);
  }
}

console.log('====================================================');
console.log('   Running PacketGuard Firewall Engine Test Suite   ');
console.log('====================================================\n');

// --- Test 1: Web HTTP (Port 80, TCP) ---
const httpPkt = {
  srcIp: '192.168.1.50',
  dstIp: '10.0.0.10',
  srcPort: 51234,
  dstPort: 80,
  protocol: 'TCP',
  flags: 'ACK, PSH',
  info: 'GET / HTTP/1.1'
};
const httpRes = engine.evaluatePacket(httpPkt);
assert(
  httpRes.verdict === 'ALLOWED' && httpRes.matchedRule.id === 'rule-3',
  'Web HTTP (Port 80) is ALLOWED by Rule #3 (Allow HTTP)',
  `Got verdict=${httpRes.verdict}, rule=${httpRes.matchedRule?.name}`
);

// --- Test 2: Return Response Packet for HTTP (Stateful ESTABLISHED) ---
const httpReturnPkt = {
  srcIp: '10.0.0.10',
  dstIp: '192.168.1.50',
  srcPort: 80,
  dstPort: 51234,
  protocol: 'TCP',
  flags: 'ACK',
  info: '200 OK (2.4 KB)'
};
const returnRes = engine.evaluatePacket(httpReturnPkt);
assert(
  returnRes.verdict === 'ALLOWED' && returnRes.matchedRule.id === 'rule-1',
  'Server HTTP 200 OK Return Packet is ALLOWED by Rule #1 (ESTABLISHED, RELATED)',
  `Got verdict=${returnRes.verdict}, rule=${returnRes.matchedRule?.name}`
);

// --- Test 3: SSH (Port 22, TCP) ---
const sshPkt = {
  srcIp: '192.168.1.50',
  dstIp: '10.0.0.10',
  srcPort: 51235,
  dstPort: 22,
  protocol: 'TCP',
  flags: 'SYN',
  info: 'SSH Connection'
};
const sshRes = engine.evaluatePacket(sshPkt);
assert(
  sshRes.verdict === 'BLOCKED' && sshRes.matchedRule.id === 'rule-2',
  'SSH (Port 22) is BLOCKED by Rule #2 (Block SSH)',
  `Got verdict=${sshRes.verdict}, rule=${sshRes.matchedRule?.name}`
);

// --- Test 4: HTTPS (Port 443, TCP) ---
const httpsPkt = {
  srcIp: '192.168.1.50',
  dstIp: '10.0.0.10',
  srcPort: 51236,
  dstPort: 443,
  protocol: 'TCP',
  flags: 'SYN',
  info: 'TLS Handshake'
};
const httpsRes = engine.evaluatePacket(httpsPkt);
assert(
  httpsRes.verdict === 'ALLOWED' && httpsRes.matchedRule.id === 'rule-4',
  'HTTPS (Port 443) is ALLOWED by Rule #4 (Allow HTTPS)',
  `Got verdict=${httpsRes.verdict}, rule=${httpsRes.matchedRule?.name}`
);

// --- Test 5: DNS Query (Port 53, UDP) ---
const dnsPkt = {
  srcIp: '192.168.1.50',
  dstIp: '8.8.8.8',
  srcPort: 51237,
  dstPort: 53,
  protocol: 'UDP',
  flags: 'QUERY',
  info: 'Query: example.com'
};
const dnsRes = engine.evaluatePacket(dnsPkt);
assert(
  dnsRes.verdict === 'ALLOWED' && dnsRes.matchedRule.id === 'rule-5',
  'DNS Query (Port 53, UDP) is ALLOWED by Rule #5 (Allow DNS)',
  `Got verdict=${dnsRes.verdict}, rule=${dnsRes.matchedRule?.name}`
);

// --- Test 6: Database MySQL (Port 3306, TCP) ---
const dbPkt = {
  srcIp: '192.168.1.50',
  dstIp: '10.0.0.10',
  srcPort: 51238,
  dstPort: 3306,
  protocol: 'TCP',
  flags: 'SYN',
  info: 'MySQL Connect'
};
const dbRes = engine.evaluatePacket(dbPkt);
assert(
  dbRes.verdict === 'BLOCKED' && dbRes.matchedRule.id === 'rule-7',
  'Database Query (Port 3306) is BLOCKED by Rule #7 (Default Deny All)',
  `Got verdict=${dbRes.verdict}, rule=${dbRes.matchedRule?.name}`
);

// --- Test 7: Common Attack Ports (Port 23 Telnet, Port 445 SMB) ---
const telnetPkt = {
  srcIp: '192.168.1.50',
  dstIp: '10.0.0.10',
  srcPort: 51239,
  dstPort: 23,
  protocol: 'TCP',
  flags: 'SYN',
  info: 'Telnet Connect'
};
const telnetRes = engine.evaluatePacket(telnetPkt);
assert(
  telnetRes.verdict === 'BLOCKED' && telnetRes.matchedRule.id === 'rule-6',
  'Telnet (Port 23) is BLOCKED by Rule #6 (Block common attack ports)',
  `Got verdict=${telnetRes.verdict}, rule=${telnetRes.matchedRule?.name}`
);

// --- Test 8: CIDR Subnet Math ---
assert(engine.matchIp('192.168.1.50', '192.168.1.0/24') === true, 'CIDR /24 includes internal host 192.168.1.50');
assert(engine.matchIp('192.168.2.50', '192.168.1.0/24') === false, 'CIDR /24 excludes external host 192.168.2.50');
assert(engine.matchIp('10.0.5.22', '10.0.0.0/8') === true, 'CIDR /8 includes host 10.0.5.22');

// --- Test 9: Port Range & List Matching ---
assert(engine.matchPort(80, '80, 443') === true, 'Port list matches 80');
assert(engine.matchPort(443, '80, 443') === true, 'Port list matches 443');
assert(engine.matchPort(8080, '80, 443') === false, 'Port list rejects 8080');
assert(engine.matchPort(5000, '1024-65535') === true, 'Port range matches 5000');
assert(engine.matchPort(80, '1024-65535') === false, 'Port range rejects privileged port 80');

// --- Test 10: Rule Toggling & Custom Rule Creation ---
console.log('\n--- Testing Rule Manipulation (Disable & Add Custom Rule) ---');
engine.toggleRule('rule-2'); // Disable Rule #2 (Block SSH)
const sshResDisabled = engine.evaluatePacket(sshPkt);
assert(
  sshResDisabled.matchedRule.id !== 'rule-2',
  'Disabled Rule #2 is skipped during evaluation',
  `Matched rule was ${sshResDisabled.matchedRule?.name}`
);

// Add custom rule: Allow SSH
const newRule = engine.addRule({
  name: 'Allow SSH for Admins',
  action: 'ALLOW',
  protocol: 'TCP',
  srcIp: '192.168.1.50',
  dstIp: '10.0.0.10',
  srcPort: '*',
  dstPort: '22',
  state: 'ANY'
});
// Re-enable rule-2 and move new rule to priority 2
engine.toggleRule('rule-2');
// Reorder: place new allow rule at top
engine.reorderRules(engine.rules.length - 1, 1);
const sshResAllowed = engine.evaluatePacket(sshPkt);
assert(
  sshResAllowed.verdict === 'ALLOWED' && sshResAllowed.matchedRule.id === newRule.id,
  'Custom Rule #2 (Allow SSH for Admins) now ALLOWS SSH traffic',
  `Got verdict=${sshResAllowed.verdict}, rule=${sshResAllowed.matchedRule?.name}`
);

// --- Test 18: Live Site Domain Filtering (google.com is Blocked) ---
const freshEngine = new window.FirewallEngine();
const googlePkt = {
  srcIp: '192.168.1.50',
  dstIp: '142.250.190.46',
  domain: 'google.com',
  srcPort: 52001,
  dstPort: 443,
  protocol: 'TCP',
  flags: 'SYN',
  info: 'TLS Handshake -> google.com'
};
const googleRes = freshEngine.evaluatePacket(googlePkt);
assert(
  googleRes.verdict === 'BLOCKED' && googleRes.matchedRule.id === 'rule-site-block',
  'Domain google.com is BLOCKED by Rule (Block Google & Restricted Sites)',
  `Got verdict=${googleRes.verdict}, rule=${googleRes.matchedRule?.name}`
);

// --- Test 19: Safe Domain Allowed (example.com via HTTP) ---
const safeSitePkt = {
  srcIp: '192.168.1.50',
  dstIp: '93.184.216.34',
  domain: 'example.com',
  srcPort: 52002,
  dstPort: 80,
  protocol: 'TCP',
  flags: 'ACK, PSH',
  info: 'GET / HTTP/1.1'
};
const safeSiteRes = freshEngine.evaluatePacket(safeSitePkt);
assert(
  safeSiteRes.verdict === 'ALLOWED' && safeSiteRes.matchedRule.id === 'rule-3',
  'Domain example.com is ALLOWED through HTTP Rule #3',
  `Got verdict=${safeSiteRes.verdict}, rule=${safeSiteRes.matchedRule?.name}`
);

// --- Test 20: Multi-Client: Rogue Client C (192.168.1.99) to Internal DB is BLOCKED ---
const rogueDbPkt = {
  srcIp: '192.168.1.99',
  dstIp: '10.0.0.20',
  srcPort: 54321,
  dstPort: 3306,
  protocol: 'TCP',
  flags: 'SYN',
  info: 'Unauthorized SQL probe'
};
const rogueRes = freshEngine.evaluatePacket(rogueDbPkt);
assert(
  rogueRes.verdict === 'BLOCKED' && rogueRes.matchedRule.id === 'rule-rogue-client',
  'Rogue Client C (192.168.1.99) is BLOCKED from accessing DB (10.0.0.20) by Rule (Block Rogue Client)',
  `Got verdict=${rogueRes.verdict}, rule=${rogueRes.matchedRule?.name}`
);

// --- Test 21: Multi-Client / Multi-Server: Client B to Web Server is ALLOWED ---
const devWebPkt = {
  srcIp: '192.168.1.51',
  dstIp: '10.0.0.10',
  srcPort: 53100,
  dstPort: 80,
  protocol: 'TCP',
  flags: 'ACK, PSH',
  info: 'GET /api/v1/health'
};
const devWebRes = freshEngine.evaluatePacket(devWebPkt);
assert(
  devWebRes.verdict === 'ALLOWED' && devWebRes.matchedRule.id === 'rule-3',
  'Client B (192.168.1.51) to Web Server (10.0.0.10:80) is ALLOWED by Rule #3',
  `Got verdict=${devWebRes.verdict}, rule=${devWebRes.matchedRule?.name}`
);

// --- Test 22: Dynamic Rule Reordering (Moving a Deny rule above an Allow rule) ---
const reorderEngine = new window.FirewallEngine();
// By default, Rule #3 allows HTTP (priority 6) and Rule #7 denies all (priority 10)
// Let's create a custom deny HTTP rule placed at the end, then move it to priority 1
const blockHttpRule = reorderEngine.addRule({
  name: 'Temporary Maintenance: Block HTTP',
  action: 'DENY',
  protocol: 'TCP',
  srcIp: '*',
  dstIp: '*',
  srcPort: '*',
  dstPort: '80',
  position: 'bottom'
});
// Before reordering, HTTP is ALLOWED by Rule #3
assert(
  reorderEngine.evaluatePacket(httpPkt).verdict === 'ALLOWED',
  'Before reordering, HTTP is ALLOWED by earlier Rule #3'
);
// Reorder: move blockHttpRule to index 0 (Priority #1)
reorderEngine.reorderRules(reorderEngine.rules.length - 1, 0);
assert(
  reorderEngine.rules[0].id === blockHttpRule.id && reorderEngine.rules[0].priority === 1,
  'Reordered rule is now at index 0 with priority 1'
);
assert(
  reorderEngine.evaluatePacket(httpPkt).verdict === 'BLOCKED',
  'After reordering to Priority #1, HTTP is BLOCKED by First-Match semantics'
);

// --- Test 23: Initial Priority Placement Options (top / before-default) ---
const posEngine = new window.FirewallEngine();
const topRule = posEngine.addRule({
  name: 'Top Priority Rule',
  action: 'DENY',
  position: 'top'
});
assert(posEngine.rules[0].id === topRule.id && topRule.priority === 1, 'Rule added with position: "top" is at priority #1');

const beforeDefRule = posEngine.addRule({
  name: 'Before Default Rule',
  action: 'ALLOW',
  position: 'before-default'
});
const defIndex = posEngine.rules.findIndex(r => r.id === 'rule-7' || r.name.toLowerCase().includes('default deny'));
const beforeDefIndex = posEngine.rules.findIndex(r => r.id === beforeDefRule.id);
assert(beforeDefIndex === defIndex - 1, 'Rule added with position: "before-default" is placed immediately before Default Deny');

console.log('\n====================================================');
console.log(`   Test Results: ${passedTests}/${totalTests} Tests Passed (${Math.round((passedTests / totalTests) * 100)}%)   `);
console.log('====================================================\n');

if (passedTests === totalTests) {
  process.exit(0);
} else {
  process.exit(1);
}

