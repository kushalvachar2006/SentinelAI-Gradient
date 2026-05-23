const express = require('express');
const Threat = require('../models/Threat');
const router = express.Router();

const DEMO_THREATS = [
  { threatType: 'sql_injection', severity: 'critical', riskScore: 98, sourceIP: '185.234.219.11', targetAsset: 'api.prod.internal', status: 'open', country: 'RU', timestamp: new Date(Date.now() - 2 * 60000), detectedAt: new Date() },
  { threatType: 'ransomware_c2', severity: 'critical', riskScore: 96, sourceIP: '91.108.56.34', targetAsset: 'workstation-14.corp', status: 'open', country: 'CN', timestamp: new Date(Date.now() - 7 * 60000), detectedAt: new Date() },
  { threatType: 'brute_force_ssh', severity: 'high', riskScore: 82, sourceIP: '203.0.113.45', targetAsset: 'bastion-01.infra', status: 'open', country: 'BR', timestamp: new Date(Date.now() - 12 * 60000), detectedAt: new Date() },
  { threatType: 'data_exfiltration', severity: 'high', riskScore: 79, sourceIP: '198.51.100.22', targetAsset: 's3://prod-customer-data', status: 'investigating', country: 'DE', timestamp: new Date(Date.now() - 18 * 60000), detectedAt: new Date() },
  { threatType: 'privilege_escalation', severity: 'high', riskScore: 77, sourceIP: '10.0.4.112', targetAsset: 'k8s-master-01', status: 'open', country: 'US', timestamp: new Date(Date.now() - 25 * 60000), detectedAt: new Date() },
  { threatType: 'port_scan', severity: 'medium', riskScore: 54, sourceIP: '172.16.33.201', targetAsset: '10.0.0.0/24', status: 'open', country: 'NL', timestamp: new Date(Date.now() - 33 * 60000), detectedAt: new Date() },
  { threatType: 'anomalous_login', severity: 'medium', riskScore: 61, sourceIP: '104.28.42.11', targetAsset: 'admin@corp.com', status: 'open', country: 'NG', timestamp: new Date(Date.now() - 41 * 60000), detectedAt: new Date() },
  { threatType: 'dns_tunneling', severity: 'medium', riskScore: 58, sourceIP: '192.168.1.88', targetAsset: 'malware.exfil.xyz', status: 'open', country: 'US', timestamp: new Date(Date.now() - 58 * 60000), detectedAt: new Date() },
  { threatType: 'failed_auth', severity: 'low', riskScore: 23, sourceIP: '45.33.32.156', targetAsset: 'vpn.corp.com', status: 'dismissed', country: 'US', timestamp: new Date(Date.now() - 3600000), detectedAt: new Date() },
  { threatType: 'unusual_process', severity: 'low', riskScore: 19, sourceIP: '10.2.1.44', targetAsset: 'devbox-maria', status: 'dismissed', country: 'US', timestamp: new Date(Date.now() - 7200000), detectedAt: new Date() },
];

// POST /api/demo/seed — wipe and re-seed demo data
router.post('/seed', async (req, res) => {
  if (process.env.DEMO_MODE !== 'true') return res.status(403).json({ error: 'Demo mode not enabled' });
  await Threat.deleteMany({});
  const created = await Threat.insertMany(DEMO_THREATS);
  res.json({ seeded: created.length, message: 'Demo data loaded' });
});

module.exports = router;
