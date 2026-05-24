"""
Threat Detection Module
- Rule-based engine with lowered thresholds for realistic file sizes
- Direct keyword/pattern detection for JSON logs with explicit threat fields
- Composite severity scorer
- IsolationForest false-positive filter
"""
import asyncio
import json
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional
import numpy as np
import structlog
from fastapi import APIRouter
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest

from modules.log_parser import NormalizedEvent, get_parser
from config.database import get_collection

log = structlog.get_logger()
router = APIRouter()

# ─── Threat Type Base Scores ───────────────────────────────────────────────────
THREAT_BASE_SCORES = {
    "brute_force": 55,
    "brute_force_ssh": 60,
    "brute_force_rdp": 60,
    "privilege_escalation": 75,
    "lateral_movement": 70,
    "exfiltration": 80,
    "data_exfiltration": 80,
    "impossible_travel": 65,
    "malware": 85,
    "ransomware_c2": 90,
    "sql_injection": 80,
    "xss": 65,
    "command_injection": 75,
    "port_scan": 50,
    "dns_tunneling": 60,
    "anomalous_login": 55,
    "failed_auth": 35,
    "unusual_process": 40,
    "anomaly": 40,
    "other": 30,
}

SEVERITY_THRESHOLDS = {
    "critical": 85,
    "high": 65,
    "medium": 45,
    "low": 25,
    "info": 0,
}

# Valid threat types accepted by the Node Mongoose schema
VALID_THREAT_TYPES = set(THREAT_BASE_SCORES.keys()) | {"exfiltration"}


def score_to_severity(score: float) -> str:
    for sev, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return sev
    return "info"


# ─── Direct JSON Field → ThreatType Mapping ───────────────────────────────────
DIRECT_KEYWORD_MAP = {
    "sql_injection": "sql_injection",
    "sqli": "sql_injection",
    "sql injection": "sql_injection",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "command_injection": "command_injection",
    "cmd_injection": "command_injection",
    "rce": "command_injection",
    "ransomware": "ransomware_c2",
    "ransomware_c2": "ransomware_c2",
    "c2": "ransomware_c2",
    "c2_beacon": "ransomware_c2",
    "beacon": "ransomware_c2",
    "malware": "malware",
    "virus": "malware",
    "trojan": "malware",
    "port_scan": "port_scan",
    "portscan": "port_scan",
    "nmap": "port_scan",
    "dns_tunnel": "dns_tunneling",
    "dns_tunneling": "dns_tunneling",
    "dns_exfil": "dns_tunneling",
    "data_exfiltration": "data_exfiltration",
    "exfiltration": "data_exfiltration",
    "exfil": "data_exfiltration",
    "lateral_movement": "lateral_movement",
    "lateral": "lateral_movement",
    "privilege_escalation": "privilege_escalation",
    "privesc": "privilege_escalation",
    "brute_force": "brute_force",
    "brute_force_ssh": "brute_force_ssh",
    "brute_force_rdp": "brute_force_rdp",
    "bruteforce": "brute_force",
    "anomalous_login": "anomalous_login",
    "impossible_travel": "impossible_travel",
    "failed_auth": "failed_auth",
    "auth_failure": "failed_auth",
    "login_failed": "failed_auth",
    "unusual_process": "unusual_process",
}

# (substring patterns in raw log text) → threatType
CONTENT_PATTERNS = [
    (["' OR ", "OR 1=1", "DROP TABLE", "UNION SELECT", "'; --", "1=1--", "sleep("], "sql_injection"),
    (["<script", "javascript:", "onerror=", "onload=", "alert(document"], "xss"),
    (["cmd.exe /c", "powershell -enc", "/bin/bash -i", "nc -e /bin/", "msfvenom"], "command_injection"),
    (["ransomware", ".locky", ".cerber", "YOUR_FILES_ARE_ENCRYPTED", "C2 beacon"], "ransomware_c2"),
    (["Nmap scan", "port scanning", "SYN scan", "masscan "], "port_scan"),
    (["dns tunnel", "dns_tunnel", "base64 dns", "subdomain exfil"], "dns_tunneling"),
]


def detect_from_json_fields(raw: str) -> Optional[dict]:
    """
    Parse a JSON log line and return a threat dict if the fields
    directly identify a known threat type.
    Returns None if this line doesn't map to a known threat.
    """
    try:
        data = json.loads(raw)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    # --- Determine threat type ---
    threat_type = None

    # Check explicit threat-type fields first
    for field in ("threat_type", "threatType", "alert_type", "rule_name",
                  "attack_type", "signature", "category", "event_type", "type"):
        val = str(data.get(field, "") or "").lower().strip().replace(" ", "_").replace("-", "_")
        if val in DIRECT_KEYWORD_MAP:
            threat_type = DIRECT_KEYWORD_MAP[val]
            break
        # Partial match
        for kw, tt in DIRECT_KEYWORD_MAP.items():
            if kw in val:
                threat_type = tt
                break
        if threat_type:
            break

    # Check action / description fields
    if not threat_type:
        for field in ("action", "description", "message", "msg", "details"):
            val = str(data.get(field, "") or "").lower()
            for kw, tt in DIRECT_KEYWORD_MAP.items():
                if kw in val:
                    threat_type = tt
                    break
            if threat_type:
                break

    # Check raw content patterns
    if not threat_type:
        raw_lower = raw.lower()
        for patterns, tt in CONTENT_PATTERNS:
            for p in patterns:
                if p.lower() in raw_lower:
                    threat_type = tt
                    break
            if threat_type:
                break

    if not threat_type:
        return None

    # Ensure it's valid
    if threat_type not in VALID_THREAT_TYPES:
        threat_type = "other"

    # --- Extract fields ---
    ts = _extract_ts(data)
    src_ip = (data.get("src_ip") or data.get("source_ip") or data.get("srcip") or
              data.get("clientip") or data.get("remote_addr") or data.get("attacker_ip") or
              data.get("sourceIP"))
    target = (data.get("target") or data.get("target_asset") or data.get("targetAsset") or
              data.get("destination") or data.get("dest_host") or data.get("hostname") or
              data.get("host") or data.get("affected_system") or data.get("resource") or
              data.get("service") or data.get("dst_ip") or data.get("dest_ip"))
    user = (data.get("user") or data.get("username") or data.get("account_name") or
            data.get("user_name"))
    risk_score = data.get("risk_score") or data.get("riskScore") or data.get("score")
    severity_raw = str(data.get("severity", "") or "").lower()

    return {
        "threatType": threat_type,
        "sourceIP": str(src_ip).strip() if src_ip else None,
        "targetAsset": str(target).strip() if target else None,
        "user": str(user) if user else None,
        "hostname": str(data.get("hostname") or data.get("host") or ""),
        "timestamp": ts,
        "evidenceCount": 1,
        "rawLogs": [raw],
        "normalizedEvents": [],
        "eventType": str(data.get("event_type", threat_type) or threat_type),
        "action": str(data.get("action", "") or ""),
        "result": str(data.get("result") or data.get("outcome") or data.get("status") or ""),
        "description": str(data.get("description") or data.get("message") or data.get("msg") or ""),
        "_override_risk": float(risk_score) if risk_score and str(risk_score).replace(".", "").isdigit() else None,
        "_override_severity": severity_raw if severity_raw in ("critical", "high", "medium", "low", "info") else None,
    }


def _extract_ts(data: dict) -> datetime:
    for key in ("timestamp", "@timestamp", "time", "date", "event_time", "created_at", "ts"):
        val = data.get(key)
        if not val:
            continue
        try:
            if isinstance(val, (int, float)):
                return datetime.utcfromtimestamp(val / 1000 if val > 1e10 else val)
            return datetime.fromisoformat(str(val).replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, OSError):
            continue
    return datetime.utcnow()


# ─── Rule Engine ──────────────────────────────────────────────────────────────
class RuleEngine:
    def __init__(self):
        self._auth_failures: dict[str, list[datetime]] = defaultdict(list)
        self._user_locations: dict[str, list[tuple]] = defaultdict(list)
        self._outbound_bytes: dict[str, list[tuple]] = defaultdict(list)
        self._lateral: dict[str, set[str]] = defaultdict(set)

        self.BRUTE_WINDOW_SEC = 300   # 5 minutes
        self.BRUTE_THRESHOLD = 3      # 3 failures triggers detection
        self.EXFIL_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10MB
        self.LATERAL_UNIQUE_HOSTS = 3

    def evaluate(self, event: NormalizedEvent) -> list[dict]:
        detections = []

        if event.source_ip:
            bf = self._check_brute_force(event)
            if bf:
                detections.append(bf)
            lm = self._check_lateral_movement(event)
            if lm:
                detections.append(lm)
            exfil = self._check_exfiltration(event)
            if exfil:
                detections.append(exfil)

        pe = self._check_privilege_escalation(event)
        if pe:
            detections.append(pe)

        direct = self._check_direct_event_type(event)
        if direct:
            detections.append(direct)

        return detections

    def _check_direct_event_type(self, event: NormalizedEvent) -> Optional[dict]:
        """Map explicit event_type values to threats directly (single-event detection)."""
        DIRECT_MAP = {
            "sql_injection": "sql_injection",
            "xss": "xss",
            "command_injection": "command_injection",
            "ransomware_c2": "ransomware_c2",
            "malware": "malware",
            "port_scan": "port_scan",
            "dns_tunneling": "dns_tunneling",
            "dns_tunnel": "dns_tunneling",
            "data_exfiltration": "data_exfiltration",
            "lateral_movement": "lateral_movement",
            "privilege_escalation": "privilege_escalation",
            "brute_force": "brute_force",
            "brute_force_ssh": "brute_force_ssh",
            "brute_force_rdp": "brute_force_rdp",
            "anomalous_login": "anomalous_login",
            "impossible_travel": "impossible_travel",
            "failed_auth": "failed_auth",
            "unusual_process": "unusual_process",
        }
        et = (event.event_type or "").lower().replace(" ", "_").replace("-", "_")
        threat_type = DIRECT_MAP.get(et)
        if threat_type:
            return {
                "threatType": threat_type,
                "sourceIP": event.source_ip,
                "targetAsset": event.hostname or event.dest_ip,
                "user": event.user,
                "hostname": event.hostname,
                "timestamp": event.timestamp,
                "evidenceCount": 1,
                "rawLogs": [event.raw],
                "normalizedEvents": [event.model_dump()],
                "eventType": event.event_type,
                "action": event.action,
                "result": event.result,
            }
        return None

    def _check_brute_force(self, event: NormalizedEvent) -> Optional[dict]:
        if event.result != "failure" or event.event_type not in (
            "auth_failure", "login_failed", "ssh_fail", "failed_auth"
        ):
            return None

        ip = event.source_ip
        now = event.timestamp
        cutoff = now - timedelta(seconds=self.BRUTE_WINDOW_SEC)
        self._auth_failures[ip] = [t for t in self._auth_failures[ip] if t > cutoff]
        self._auth_failures[ip].append(now)

        count = len(self._auth_failures[ip])
        if count >= self.BRUTE_THRESHOLD:
            return {
                "threatType": "brute_force",
                "sourceIP": ip,
                "targetAsset": event.hostname or event.dest_ip,
                "user": event.user,
                "hostname": event.hostname,
                "timestamp": event.timestamp,
                "evidenceCount": count,
                "rawLogs": [event.raw],
                "normalizedEvents": [event.model_dump()],
                "eventType": event.event_type,
                "action": event.action,
                "result": event.result,
                "description": f"{count} failed auth attempts from {ip} in {self.BRUTE_WINDOW_SEC}s",
            }
        return None

    def _check_privilege_escalation(self, event: NormalizedEvent) -> Optional[dict]:
        pe_indicators = ("privilege_use", "sudo", "su", "runas", "admin", "root", "administrator")
        if not any(ind in (event.event_type or "").lower() or ind in (event.action or "").lower()
                   for ind in pe_indicators):
            return None
        if event.user in ("root", "Administrator", "SYSTEM", "NT AUTHORITY"):
            return {
                "threatType": "privilege_escalation",
                "sourceIP": event.source_ip,
                "targetAsset": event.hostname or event.dest_ip,
                "user": event.user,
                "hostname": event.hostname,
                "timestamp": event.timestamp,
                "evidenceCount": 1,
                "rawLogs": [event.raw],
                "normalizedEvents": [event.model_dump()],
                "eventType": event.event_type,
                "action": event.action,
                "result": event.result,
            }
        return None

    def _check_lateral_movement(self, event: NormalizedEvent) -> Optional[dict]:
        if event.event_type not in ("auth_success", "network_connect", "smb", "rdp"):
            return None
        if not event.dest_ip:
            return None
        ip = event.source_ip
        self._lateral[ip].add(event.dest_ip)
        if len(self._lateral[ip]) >= self.LATERAL_UNIQUE_HOSTS:
            return {
                "threatType": "lateral_movement",
                "sourceIP": ip,
                "targetAsset": event.dest_ip,
                "user": event.user,
                "hostname": event.hostname,
                "timestamp": event.timestamp,
                "evidenceCount": len(self._lateral[ip]),
                "rawLogs": [event.raw],
                "normalizedEvents": [event.model_dump()],
                "eventType": "lateral_movement",
                "action": f"Contacted {len(self._lateral[ip])} unique internal hosts",
                "result": None,
            }
        return None

    def _check_exfiltration(self, event: NormalizedEvent) -> Optional[dict]:
        if not event.bytes_sent or event.bytes_sent < 1024:
            return None
        if not event.dest_ip:
            return None
        ip = event.source_ip
        now = event.timestamp
        cutoff = now - timedelta(minutes=10)
        self._outbound_bytes[ip] = [(t, b) for t, b in self._outbound_bytes[ip] if t > cutoff]
        self._outbound_bytes[ip].append((now, event.bytes_sent))
        total = sum(b for _, b in self._outbound_bytes[ip])
        if total >= self.EXFIL_BYTES_THRESHOLD:
            mb = total / 1_048_576
            return {
                "threatType": "exfiltration",
                "sourceIP": ip,
                "targetAsset": event.dest_ip,
                "destIP": event.dest_ip,
                "user": event.user,
                "hostname": event.hostname,
                "timestamp": event.timestamp,
                "evidenceCount": len(self._outbound_bytes[ip]),
                "rawLogs": [event.raw],
                "normalizedEvents": [event.model_dump()],
                "eventType": "exfiltration",
                "action": f"Large outbound transfer: {mb:.1f}MB",
                "result": None,
            }
        return None


# ─── Severity Scorer ──────────────────────────────────────────────────────────
class SeverityScorer:
    def compute(self, threat_type: str, evidence_count: int,
                asset_criticality: int = 5, reputation_score: float = 0.0) -> float:
        base = THREAT_BASE_SCORES.get(threat_type, 30)
        freq_bonus = min(15, math.log1p(evidence_count) * 5)
        asset_bonus = (asset_criticality / 10) * 10
        rep_bonus = (reputation_score / 100) * 20
        score = base + freq_bonus + asset_bonus + rep_bonus
        return round(min(100.0, max(0.0, score)), 1)

    def build_feature_vector(self, threat: dict) -> list[float]:
        type_map = {t: i for i, t in enumerate(THREAT_BASE_SCORES)}
        type_idx = type_map.get(threat.get("threatType", "other"), 0)
        return [
            threat.get("riskScore", 0) / 100,
            type_idx / len(type_map),
            threat.get("evidenceCount", 1) / 100,
            threat.get("assetCriticality", 5) / 10,
            1.0 if threat.get("enrichment", {}).get("abuseIPDB", {}).get("isAbusive") else 0.0,
            (threat.get("enrichment", {}).get("abuseIPDB", {}).get("abuseConfidenceScore", 0)) / 100,
        ]


# ─── False Positive Filter ─────────────────────────────────────────────────────
class FalsePositiveFilter:
    def __init__(self):
        self._model: Optional[IsolationForest] = None

    async def train_from_mongo(self):
        col = get_collection("threats")
        dismissed = await col.find(
            {"status": "dismissed", "fpFeatureVector": {"$exists": True, "$ne": []}},
            {"fpFeatureVector": 1}
        ).to_list(length=2000)
        if len(dismissed) < 10:
            return
        X = np.array([d["fpFeatureVector"] for d in dismissed])
        self._model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self._model.fit(X)

    def predict(self, feature_vector: list[float]) -> tuple[bool, float]:
        if self._model is None:
            return False, 0.0
        X = np.array([feature_vector])
        pred = self._model.predict(X)[0]
        score = self._model.score_samples(X)[0]
        return pred == -1, float(score)


# ─── Singletons ───────────────────────────────────────────────────────────────
_rule_engine = RuleEngine()
_severity_scorer = SeverityScorer()
_fp_filter = FalsePositiveFilter()


def get_rule_engine() -> RuleEngine:
    return _rule_engine


def get_severity_scorer() -> SeverityScorer:
    return _severity_scorer


def get_fp_filter() -> FalsePositiveFilter:
    return _fp_filter


# ─── API Endpoint ──────────────────────────────────────────────────────────────
class ParseAndDetectRequest(BaseModel):
    logs: list[str]
    source: str = "api"
    job_id: str = ""


@router.post("/parse-and-detect")
async def parse_and_detect(req: ParseAndDetectRequest):
    """Main pipeline: parse logs → detect threats → score → save"""
    parser = get_parser()
    # Use a fresh RuleEngine per request so large-file state doesn't bleed
    # between jobs and doesn't suppress detections via carried-over counters.
    rule_engine = RuleEngine()
    scorer = get_severity_scorer()
    fp_filter = get_fp_filter()

    all_detections: list[dict] = []

    # Support a JSON array submitted as a single "line" (common for large uploads)
    expanded_logs: list[str] = []
    for line in req.logs:
        line = line.strip()
        if not line:
            continue
        # If someone submitted the whole file as one element, expand it
        if line.startswith("["):
            try:
                items = json.loads(line)
                if isinstance(items, list):
                    for item in items:
                        expanded_logs.append(
                            item if isinstance(item, str) else json.dumps(item)
                        )
                    continue
            except Exception:
                pass
        expanded_logs.append(line)

    for line in expanded_logs:
        if not line:
            continue

        # ── Path 1: JSON line with direct threat fields ────────────────────────
        direct = detect_from_json_fields(line)
        if direct:
            all_detections.append(direct)
            continue

        # ── Path 2: Parse to NormalizedEvent → rule engine ────────────────────
        event = parser.parse_line(line)
        if event:
            detections = rule_engine.evaluate(event)
            all_detections.extend(detections)

    # ── Dedup: group by (ip, threatType, targetAsset) to preserve variety ────
    # Using a 3-tuple key instead of 2-tuple so threats against different assets
    # from the same IP are NOT collapsed — this is the main fix for large files
    # showing 0 threats (all entries were deduped into one that got discarded).
    threats_to_save = []
    seen: dict[tuple, dict] = {}

    for det in all_detections:
        target_key = (det.get("targetAsset") or det.get("hostname") or "")[:64]
        key = (det.get("sourceIP") or "", det["threatType"], target_key)
        if key not in seen:
            seen[key] = det

            # Apply override scores from the JSON log itself if present
            override_risk = det.pop("_override_risk", None)
            override_sev = det.pop("_override_severity", None)

            if override_risk is not None:
                risk_score = float(override_risk)
            else:
                risk_score = scorer.compute(
                    threat_type=det["threatType"],
                    evidence_count=det.get("evidenceCount", 1),
                )

            det["riskScore"] = risk_score
            det["severity"] = override_sev or score_to_severity(risk_score)

            fv = scorer.build_feature_vector(det)
            is_fp, fp_score = fp_filter.predict(fv)
            det["isFalsePositive"] = is_fp
            det["fpFeatureVector"] = fv
            det["assetCriticality"] = 5

            # Ensure targetAsset is set (Node schema doesn't require it but dashboard shows it)
            if not det.get("targetAsset"):
                det["targetAsset"] = det.get("hostname") or det.get("destIP") or "unknown"

            threats_to_save.append(det)
        else:
            # Accumulate evidence for the existing entry
            existing = seen[key]
            existing["evidenceCount"] = existing.get("evidenceCount", 1) + 1
            existing["rawLogs"] = (existing.get("rawLogs") or []) + (det.get("rawLogs") or [])
            # Bump risk score slightly for repeated evidence
            existing["riskScore"] = min(100.0, existing.get("riskScore", 0) + 0.5)

    # Stamp metadata
    for threat in threats_to_save:
        threat["detectedAt"] = datetime.utcnow()
        threat["status"] = "open"
        threat.pop("_override_risk", None)
        threat.pop("_override_severity", None)

    log.info("parse_and_detect_complete",
             lines=len(req.logs), expanded=len(expanded_logs), saved=len(threats_to_save))

    return {
        "lines_processed": len(expanded_logs),
        "events_parsed": len(all_detections),
        "threats_detected": threats_to_save,
    }


class FeedbackRequest(BaseModel):
    threat_id: str
    threat_type: str
    feature_vector: list[float]


@router.post("/feedback/false-positive")
async def record_false_positive(req: FeedbackRequest):
    col = get_collection("threats")
    await col.update_one(
        {"_id": req.threat_id},
        {"$set": {"fpFeatureVector": req.feature_vector, "isFalsePositive": True}}
    )
    asyncio.create_task(_fp_filter.train_from_mongo())
    return {"status": "recorded", "retraining": True}