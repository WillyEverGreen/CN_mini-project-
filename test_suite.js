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

console.log('\n====================================================');
console.log(`   Test Results: ${passedTests}/${totalTests} Tests Passed (${Math.round((passedTests / totalTests) * 100)}%)   `);
console.log('====================================================\n');

if (passedTests === totalTests) {
  process.exit(0);
} else {
  process.exit(1);
}
