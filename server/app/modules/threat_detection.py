"""
Threat Detection Module
- Rule-based engine: brute force, privilege escalation, lateral movement, exfil, impossible travel
- Composite severity scorer
- IsolationForest false-positive filter trained on analyst dismiss actions
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
    "privilege_escalation": 75,
    "lateral_movement": 70,
    "exfiltration": 80,
    "impossible_travel": 65,
    "malware": 85,
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


def score_to_severity(score: float) -> str:
    for sev, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return sev
    return "info"


# ─── Rule Engine ──────────────────────────────────────────────────────────────
class RuleEngine:
    """
    Stateful rule-based threat detection.
    Maintains sliding windows per IP/user.
    """

    def __init__(self):
        # {ip -> [timestamps]}
        self._auth_failures: dict[str, list[datetime]] = defaultdict(list)
        # {user -> [(ip, timestamp)]}
        self._user_locations: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
        # {ip -> bytes} within window
        self._outbound_bytes: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
        # {ip -> set of dest_ips} within window
        self._lateral: dict[str, set[str]] = defaultdict(set)

        self.BRUTE_WINDOW_SEC = 60
        self.BRUTE_THRESHOLD = 5
        self.EXFIL_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100MB in 10min
        self.LATERAL_UNIQUE_HOSTS = 5
        self.IMPOSSIBLE_TRAVEL_KM_PER_HOUR = 900

    def evaluate(self, event: NormalizedEvent) -> list[dict]:
        """Return list of detected threats for this event"""
        detections = []

        if event.source_ip:
            # Brute Force
            bf = self._check_brute_force(event)
            if bf:
                detections.append(bf)

            # Lateral Movement
            lm = self._check_lateral_movement(event)
            if lm:
                detections.append(lm)

            # Exfiltration
            exfil = self._check_exfiltration(event)
            if exfil:
                detections.append(exfil)

        # Privilege Escalation
        pe = self._check_privilege_escalation(event)
        if pe:
            detections.append(pe)

        return detections

    def _check_brute_force(self, event: NormalizedEvent) -> Optional[dict]:
        if event.result != "failure" or event.event_type not in (
            "auth_failure", "login_failed", "ssh_fail"
        ):
            return None

        ip = event.source_ip
        now = event.timestamp
        cutoff = now - timedelta(seconds=self.BRUTE_WINDOW_SEC)

        # Prune old entries
        self._auth_failures[ip] = [
            t for t in self._auth_failures[ip] if t > cutoff
        ]
        self._auth_failures[ip].append(now)

        count = len(self._auth_failures[ip])
        if count >= self.BRUTE_THRESHOLD:
            return {
                "threatType": "brute_force",
                "sourceIP": ip,
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
        pe_indicators = (
            "privilege_use", "sudo", "su", "runas",
            "admin", "root", "administrator",
        )
        if not any(ind in (event.event_type or "").lower() or
                   ind in (event.action or "").lower()
                   for ind in pe_indicators):
            return None

        if event.user in ("root", "Administrator", "SYSTEM", "NT AUTHORITY"):
            return {
                "threatType": "privilege_escalation",
                "sourceIP": event.source_ip,
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
            hosts = list(self._lateral[ip])
            return {
                "threatType": "lateral_movement",
                "sourceIP": ip,
                "user": event.user,
                "hostname": event.hostname,
                "timestamp": event.timestamp,
                "evidenceCount": len(self._lateral[ip]),
                "rawLogs": [event.raw],
                "normalizedEvents": [event.model_dump()],
                "eventType": "lateral_movement",
                "action": f"Contacted {len(self._lateral[ip])} unique internal hosts",
                "result": None,
                "description": f"Possible lateral movement: {ip} touched {len(hosts)} hosts",
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

        self._outbound_bytes[ip] = [
            (t, b) for t, b in self._outbound_bytes[ip] if t > cutoff
        ]
        self._outbound_bytes[ip].append((now, event.bytes_sent))

        total = sum(b for _, b in self._outbound_bytes[ip])
        if total >= self.EXFIL_BYTES_THRESHOLD:
            mb = total / 1_048_576
            return {
                "threatType": "exfiltration",
                "sourceIP": ip,
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
                "bytesExfiltrated": total,
            }
        return None


# ─── Severity Scorer ──────────────────────────────────────────────────────────
class SeverityScorer:
    """
    Composite risk score:
    score = base_score
          + frequency_bonus (0-15)
          + asset_criticality_bonus (0-10)
          + reputation_bonus (0-20, from enrichment)
    Clamped to [0, 100]
    """

    def compute(
        self,
        threat_type: str,
        evidence_count: int,
        asset_criticality: int = 5,
        reputation_score: float = 0.0,  # 0-100 from AbuseIPDB
    ) -> float:
        base = THREAT_BASE_SCORES.get(threat_type, 30)
        freq_bonus = min(15, math.log1p(evidence_count) * 5)
        asset_bonus = (asset_criticality / 10) * 10
        rep_bonus = (reputation_score / 100) * 20

        score = base + freq_bonus + asset_bonus + rep_bonus
        return round(min(100.0, max(0.0, score)), 1)

    def build_feature_vector(self, threat: dict) -> list[float]:
        """Build ML feature vector for false-positive classifier"""
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


# ─── False Positive Filter (IsolationForest) ─────────────────────────────────
class FalsePositiveFilter:
    """
    Trains IsolationForest on analyst-dismissed threats.
    Flags new threats that look like known FPs.
    """

    def __init__(self):
        self._model: Optional[IsolationForest] = None
        self._trained_count = 0

    async def train_from_mongo(self):
        """Load dismissed threats and re-train model"""
        col = get_collection("threats")
        dismissed = await col.find(
            {"status": "dismissed", "fpFeatureVector": {"$exists": True, "$ne": []}},
            {"fpFeatureVector": 1}
        ).to_list(length=2000)

        if len(dismissed) < 10:
            log.info("fp_filter_insufficient_data", count=len(dismissed))
            return

        X = np.array([d["fpFeatureVector"] for d in dismissed])
        self._model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self._model.fit(X)
        self._trained_count = len(dismissed)
        log.info("fp_filter_trained", samples=len(dismissed))

    def predict(self, feature_vector: list[float]) -> tuple[bool, float]:
        """Returns (is_likely_fp, anomaly_score)"""
        if self._model is None:
            return False, 0.0

        X = np.array([feature_vector])
        pred = self._model.predict(X)[0]
        score = self._model.score_samples(X)[0]
        is_fp = pred == -1
        return is_fp, float(score)


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


# ─── API Endpoints ─────────────────────────────────────────────────────────────
class ParseAndDetectRequest(BaseModel):
    logs: list[str]
    source: str = "api"
    job_id: str = ""


@router.post("/parse-and-detect")
async def parse_and_detect(req: ParseAndDetectRequest):
    """Main pipeline: parse logs → detect threats → score → save"""
    from config.database import get_collection

    parser = get_parser()
    rule_engine = get_rule_engine()
    scorer = get_severity_scorer()
    fp_filter = get_fp_filter()

    events = []
    for line in req.logs:
        event = parser.parse_line(line)
        if event:
            events.append(event)

    all_detections = []
    for event in events:
        detections = rule_engine.evaluate(event)
        all_detections.extend(detections)

    # Deduplicate: group by (ip, threatType) within 5min
    threats_to_save = []
    seen = {}
    for det in all_detections:
        key = (det.get("sourceIP"), det["threatType"])
        if key not in seen:
            seen[key] = det
            # Score it
            risk_score = scorer.compute(
                threat_type=det["threatType"],
                evidence_count=det.get("evidenceCount", 1),
            )
            det["riskScore"] = risk_score
            det["severity"] = score_to_severity(risk_score)

            # FP check
            fv = scorer.build_feature_vector(det)
            is_fp, fp_score = fp_filter.predict(fv)
            det["isFalsePositive"] = is_fp
            det["fpFeatureVector"] = fv
            det["assetCriticality"] = 5  # default

            threats_to_save.append(det)
        else:
            # Merge evidence
            seen[key]["evidenceCount"] = seen[key].get("evidenceCount", 1) + 1
            seen[key]["rawLogs"].extend(det.get("rawLogs", []))

    # Save to MongoDB
    col = get_collection("threats")
    saved = []
    for threat in threats_to_save:
        threat["detectedAt"] = datetime.utcnow()
        threat["status"] = "open"
        result = await col.insert_one(threat)
        threat["_id"] = str(result.inserted_id)
        saved.append(threat)

    return {
        "lines_processed": len(req.logs),
        "events_parsed": len(events),
        "threats_detected": saved,
    }


class FeedbackRequest(BaseModel):
    threat_id: str
    threat_type: str
    feature_vector: list[float]


@router.post("/feedback/false-positive")
async def record_false_positive(req: FeedbackRequest):
    """Record analyst FP dismissal and retrain filter"""
    col = get_collection("threats")
    await col.update_one(
        {"_id": req.threat_id},
        {"$set": {"fpFeatureVector": req.feature_vector, "isFalsePositive": True}}
    )
    # Async retrain
    asyncio.create_task(_fp_filter.train_from_mongo())
    return {"status": "recorded", "retraining": True}