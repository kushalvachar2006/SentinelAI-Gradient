import { format, subHours, subMinutes } from 'date-fns';

export const SEVERITY = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' };

const now = new Date();

export const mockThreats = [
  { id: 'T-001', severity: 'CRITICAL', eventType: 'SQL Injection', sourceIp: '185.234.219.11', target: 'api.prod.internal', timestamp: subMinutes(now, 2), riskScore: 98, live: true, country: 'RU', mitre: ['T1190', 'T1059'], asn: 'AS42793', abuseScore: 94, vtHits: 47, geo: { lat: 55.7558, lng: 37.6176, city: 'Moscow', country: 'Russia' }, explanation: 'A sophisticated SQL injection attack was detected targeting the production API gateway. The attacker is attempting to bypass authentication and extract sensitive database records. This matches known APT29 TTPs.', chain: ['Reconnaissance', 'Initial Access', 'Execution', 'Data Exfiltration'] },
  { id: 'T-002', severity: 'CRITICAL', eventType: 'Ransomware C2 Beacon', sourceIp: '91.108.56.34', target: 'workstation-14.corp', timestamp: subMinutes(now, 7), riskScore: 96, live: true, country: 'CN', mitre: ['T1071', 'T1041'], asn: 'AS4134', abuseScore: 99, vtHits: 89, geo: { lat: 39.9042, lng: 116.4074, city: 'Beijing', country: 'China' }, explanation: 'Command & control beacon detected from a known ransomware infrastructure. The endpoint has been communicating with this IP at regular 60-second intervals, indicating successful malware installation.', chain: ['Phishing', 'Execution', 'Persistence', 'C2 Beacon'] },
  { id: 'T-003', severity: 'HIGH', eventType: 'Brute Force SSH', sourceIp: '203.0.113.45', target: 'bastion-01.infra', timestamp: subMinutes(now, 12), riskScore: 82, live: true, country: 'BR', mitre: ['T1110'], asn: 'AS27699', abuseScore: 76, vtHits: 12, geo: { lat: -15.7942, lng: -47.8825, city: 'Brasilia', country: 'Brazil' }, explanation: '1,247 failed SSH login attempts in 3 minutes from this IP targeting the bastion host. Pattern matches automated credential stuffing using leaked credential databases.', chain: ['Credential Access', 'Lateral Movement'] },
  { id: 'T-004', severity: 'HIGH', eventType: 'Data Exfiltration', sourceIp: '198.51.100.22', target: 's3://prod-customer-data', timestamp: subMinutes(now, 18), riskScore: 79, live: false, country: 'DE', mitre: ['T1048', 'T1567'], asn: 'AS31334', abuseScore: 45, vtHits: 3, geo: { lat: 52.5200, lng: 13.4050, city: 'Berlin', country: 'Germany' }, explanation: 'Unusual S3 bucket access pattern detected — 2.3GB transferred to external endpoint in 8 minutes. This exceeds baseline by 40x and the destination IP has no prior access history.', chain: ['Collection', 'Exfiltration'] },
  { id: 'T-005', severity: 'HIGH', eventType: 'Privilege Escalation', sourceIp: '10.0.4.112', target: 'k8s-master-01', timestamp: subMinutes(now, 25), riskScore: 77, live: true, country: 'US', mitre: ['T1068', 'T1611'], asn: 'Internal', abuseScore: 0, vtHits: 0, geo: { lat: 37.7749, lng: -122.4194, city: 'San Francisco', country: 'USA' }, explanation: 'Internal pod attempting to mount host filesystem and escalate to root. CVE-2024-1086 exploitation pattern detected. Container breakout likely in progress.', chain: ['Exploit', 'Privilege Escalation', 'Impact'] },
  { id: 'T-006', severity: 'MEDIUM', eventType: 'Port Scan', sourceIp: '172.16.33.201', target: '10.0.0.0/24', timestamp: subMinutes(now, 33), riskScore: 54, live: false, country: 'NL', mitre: ['T1046'], asn: 'AS1101', abuseScore: 28, vtHits: 1, geo: { lat: 52.3676, lng: 4.9041, city: 'Amsterdam', country: 'Netherlands' }, explanation: 'Systematic port scan across internal subnet. 65,535 ports probed in sequence, indicating Nmap or similar reconnaissance tool usage.', chain: ['Reconnaissance'] },
  { id: 'T-007', severity: 'MEDIUM', eventType: 'Anomalous Login', sourceIp: '104.28.42.11', target: 'admin@corp.com', timestamp: subMinutes(now, 41), riskScore: 61, live: false, country: 'NG', mitre: ['T1078'], asn: 'AS13335', abuseScore: 34, vtHits: 0, geo: { lat: 9.0820, lng: 8.6753, city: 'Abuja', country: 'Nigeria' }, explanation: 'Admin account login from Nigeria — account has never accessed from this country. Time-of-day anomaly: 3:17 AM UTC. MFA was bypassed using a session token from 6 days ago.', chain: ['Initial Access', 'Persistence'] },
  { id: 'T-008', severity: 'MEDIUM', eventType: 'DNS Tunneling', sourceIp: '192.168.1.88', target: 'malware.exfil.xyz', timestamp: subMinutes(now, 58), riskScore: 58, live: false, country: 'US', mitre: ['T1071.004'], asn: 'Internal', abuseScore: 67, vtHits: 22, geo: { lat: 40.7128, lng: -74.0060, city: 'New York', country: 'USA' }, explanation: 'DNS queries with unusually long subdomains detected, averaging 63 characters. This is a hallmark of DNS tunneling for data exfiltration or C2 communication.', chain: ['Command & Control'] },
  { id: 'T-009', severity: 'LOW', eventType: 'Failed Auth', sourceIp: '45.33.32.156', target: 'vpn.corp.com', timestamp: subHours(now, 1), riskScore: 23, live: false, country: 'US', mitre: ['T1110.001'], asn: 'AS63949', abuseScore: 12, vtHits: 0, geo: { lat: 33.7490, lng: -84.3880, city: 'Atlanta', country: 'USA' }, explanation: '3 failed VPN authentication attempts. Below threshold for brute force classification but flagged for monitoring. Likely a user who forgot their password.', chain: ['Credential Access'] },
  { id: 'T-010', severity: 'LOW', eventType: 'Unusual Process', sourceIp: '10.2.1.44', target: 'devbox-maria', timestamp: subHours(now, 2), riskScore: 19, live: false, country: 'US', mitre: ['T1059.004'], asn: 'Internal', abuseScore: 0, vtHits: 0, geo: { lat: 37.3382, lng: -121.8863, city: 'San Jose', country: 'USA' }, explanation: 'Python script spawned from a shell that was launched by nginx worker. This parent-child process chain is unusual but may be a developer running a debug script.', chain: ['Execution'] },
];

export const mockAssets = [
  { name: 'api.prod.internal', hits: 23, severity: 'CRITICAL' },
  { name: 'bastion-01.infra', hits: 18, severity: 'HIGH' },
  { name: 'workstation-14.corp', hits: 14, severity: 'CRITICAL' },
  { name: 'k8s-master-01', hits: 11, severity: 'HIGH' },
  { name: 's3://prod-customer-data', hits: 8, severity: 'HIGH' },
];

export const mockThreatTrend = Array.from({ length: 24 }, (_, i) => ({
  hour: `${23 - i}h`,
  critical: Math.floor(Math.random() * 8) + (i < 4 ? 4 : 0),
  high: Math.floor(Math.random() * 15) + 3,
  medium: Math.floor(Math.random() * 20) + 5,
  low: Math.floor(Math.random() * 12) + 2,
})).reverse();

export const mockEventTypes = [
  { type: 'Brute Force', count: 284 },
  { type: 'SQL Injection', count: 197 },
  { type: 'Port Scan', count: 163 },
  { type: 'C2 Beacon', count: 89 },
  { type: 'Data Exfiltration', count: 67 },
  { type: 'Privilege Escalation', count: 54 },
  { type: 'Phishing', count: 43 },
  { type: 'DNS Tunneling', count: 38 },
];

export const mockChatHistory = [
  { id: 1, query: 'Show brute force in last 24h', time: '14:23' },
  { id: 2, query: 'Which IPs are repeat offenders?', time: '13:45' },
  { id: 3, query: 'Summarize critical alerts today', time: '11:02' },
];

export const suggestedQueries = [
  'Show brute force in last 24h',
  'Which IPs are repeat offenders?',
  'Summarize critical alerts today',
  'List all MITRE T1190 matches',
  'Which assets are most targeted?',
  'Show anomalous logins this week',
];

export const terminalLogs = [
  '[14:32:01] INFO  Ingesting log stream from syslog-aggregator-01',
  '[14:32:02] SCAN  185.234.219.11 → api.prod.internal:443 — TLS fingerprint mismatch',
  '[14:32:02] WARN  Anomalous JWT structure detected in Authorization header',
  '[14:32:03] 🔴 CRITICAL SQL payload detected: \' OR 1=1; DROP TABLE users--',
  '[14:32:03] AI    Classifying event... confidence: 98.4% → SQL Injection',
  '[14:32:04] INFO  MITRE tag: T1190 (Exploit Public-Facing Application)',
  '[14:32:04] ALERT Creating incident T-001, notifying on-call analyst',
  '[14:32:05] INFO  185.234.219.11 lookup: RU / AS42793 / AbuseIPDB: 94/100',
  '[14:32:06] SCAN  91.108.56.34 → workstation-14.corp:4444 — beacon pattern',
  '[14:32:07] 🔴 CRITICAL C2 beacon: 60s interval, encrypted, known ransomware infra',
  '[14:32:07] AI    Classifying... confidence: 96.1% → Ransomware C2',
  '[14:32:08] ALERT Creating incident T-002, auto-isolating endpoint',
  '[14:32:09] INFO  Processing 2,847 log lines from bastion-01.infra',
  '[14:32:10] WARN  SSH brute force: 1,247 attempts in 180s from 203.0.113.45',
  '[14:32:10] AI    Risk score: 82 — HIGH severity',
];