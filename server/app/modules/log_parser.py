"""
Log Parser Module
Multi-format log parser: syslog, JSON, CSV, CEF, W3C
Normalizes to unified schema for threat detection
"""
import re
import json
import csv
import io
from datetime import datetime
from typing import Optional
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

log = structlog.get_logger()
router = APIRouter()


# ─── Normalized Event Schema ───────────────────────────────────────────────────
class NormalizedEvent(BaseModel):
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str = "unknown"
    user: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    country: Optional[str] = None
    raw: str = ""
    log_format: str = "unknown"


# ─── Regex Patterns ────────────────────────────────────────────────────────────
PATTERNS = {
    # Standard syslog: Jan 01 12:00:00 hostname process[pid]: message
    "syslog": re.compile(
        r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"
        r"(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
    ),
    # JSON line
    "json": re.compile(r"^\s*\{.*\}\s*$"),
    # Common ssh failed: Failed password for user from ip port N
    "ssh_fail": re.compile(
        r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    ),
    # SSH accepted
    "ssh_accept": re.compile(
        r"Accepted (?P<method>\w+) for (?P<user>\S+) from "
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    ),
    # sudo: user : TTY=...
    "sudo": re.compile(
        r"(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+).*COMMAND=(?P<cmd>.+)$"
    ),
    # Firewall/iptables: SRC=x.x.x.x DST=y.y.y.y
    "firewall": re.compile(
        r"SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?"
        r"(?:SPT=(?P<spt>\d+))?\s*(?:DPT=(?P<dpt>\d+))?"
    ),
    # Apache/Nginx access log
    "web_access": re.compile(
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
        r'"(?P<method>\w+)\s+(?P<path>\S+).*?"\s+(?P<status>\d+)\s+(?P<bytes>\d+)'
    ),
    # Windows event (simplified)
    "windows": re.compile(
        r"EventID[=:\s]+(?P<event_id>\d+).*?Account Name:\s+(?P<user>[^\s\r\n]+).*?"
        r"Source Network Address:\s+(?P<src_ip>[\d\.]+)",
        re.DOTALL
    ),
    # Generic IP pattern
    "ip": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    # Timestamp patterns
    "ts_iso": re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    "ts_unix": re.compile(r"\b(1[4-9]\d{8}|[2-9]\d{9})\b"),
}

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

WINDOWS_EVENT_TYPES = {
    "4624": ("auth_success", "login"),
    "4625": ("auth_failure", "login_failed"),
    "4648": ("auth", "explicit_credential_logon"),
    "4720": ("account_mgmt", "user_created"),
    "4728": ("account_mgmt", "group_member_added"),
    "4732": ("account_mgmt", "local_group_member_added"),
    "4756": ("account_mgmt", "universal_group_member_added"),
    "4768": ("kerberos", "tgt_requested"),
    "4769": ("kerberos", "service_ticket_requested"),
    "4776": ("auth", "credential_validation"),
    "4771": ("kerberos", "pre_auth_failed"),
    "4798": ("recon", "local_group_enumeration"),
    "4799": ("recon", "security_group_enumeration"),
}


class LogParser:
    """Multi-format log parser with normalization"""

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        """Attempt to parse a single log line into normalized event"""
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return None

        # Try JSON first
        if PATTERNS["json"].match(raw):
            return self._parse_json(raw)

        # Try syslog
        m = PATTERNS["syslog"].match(raw)
        if m:
            return self._parse_syslog(m, raw)

        # Try web access log
        m = PATTERNS["web_access"].match(raw)
        if m:
            return self._parse_web(m, raw)

        # Generic fallback: extract what we can
        return self._parse_generic(raw)

    def _parse_json(self, raw: str) -> Optional[NormalizedEvent]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None

        ts = self._extract_timestamp_from_dict(data)
        src_ip = data.get("src_ip") or data.get("source_ip") or data.get("srcip") or \
                 data.get("clientip") or data.get("remote_addr")
        dst_ip = data.get("dst_ip") or data.get("dest_ip") or data.get("dstip")
        user = data.get("user") or data.get("username") or data.get("account_name") or \
               data.get("user_name")
        event_type = data.get("event_type") or data.get("type") or data.get("category") or "unknown"
        action = data.get("action") or data.get("event_action") or data.get("activity")
        result = data.get("result") or data.get("outcome") or data.get("status")

        return NormalizedEvent(
            timestamp=ts or datetime.utcnow(),
            source_ip=self._normalize_ip(src_ip),
            dest_ip=self._normalize_ip(dst_ip),
            source_port=data.get("src_port") or data.get("sport"),
            dest_port=data.get("dst_port") or data.get("dport") or data.get("dest_port"),
            protocol=data.get("protocol") or data.get("proto"),
            event_type=str(event_type),
            user=str(user) if user else None,
            action=str(action) if action else None,
            result=str(result) if result else None,
            hostname=data.get("hostname") or data.get("host") or data.get("computer_name"),
            bytes_sent=data.get("bytes_out") or data.get("bytes_sent"),
            bytes_recv=data.get("bytes_in") or data.get("bytes_recv"),
            raw=raw,
            log_format="json",
        )

    def _parse_syslog(self, m: re.Match, raw: str) -> NormalizedEvent:
        message = m.group("message")
        hostname = m.group("hostname")
        process = m.group("process")

        # Parse timestamp
        year = datetime.utcnow().year
        month = MONTH_MAP.get(m.group("month"), 1)
        day = int(m.group("day"))
        h, mi, s = map(int, m.group("time").split(":"))
        ts = datetime(year, month, day, h, mi, s)

        src_ip, dst_ip, user, event_type, action, result = None, None, None, "syslog", None, None

        # SSH failed
        sm = PATTERNS["ssh_fail"].search(message)
        if sm:
            src_ip = sm.group("src_ip")
            user = sm.group("user")
            event_type = "auth_failure"
            action = f"ssh_failed_{sm.group('method')}"
            result = "failure"

        # SSH accepted
        sm = PATTERNS["ssh_accept"].search(message)
        if sm:
            src_ip = sm.group("src_ip")
            user = sm.group("user")
            event_type = "auth_success"
            action = f"ssh_accepted_{sm.group('method')}"
            result = "success"

        # Sudo
        sm = PATTERNS["sudo"].search(message)
        if sm:
            user = sm.group("user")
            event_type = "privilege_use"
            action = f"sudo: {sm.group('cmd')[:100]}"

        # Firewall
        sm = PATTERNS["firewall"].search(message)
        if sm:
            src_ip = sm.group("src_ip")
            dst_ip = sm.group("dst_ip")
            event_type = "network_block"
            action = "firewall_drop"

        # Fallback: extract any IP
        if not src_ip:
            ips = PATTERNS["ip"].findall(message)
            if ips:
                src_ip = ips[0]

        return NormalizedEvent(
            timestamp=ts,
            source_ip=self._normalize_ip(src_ip),
            dest_ip=self._normalize_ip(dst_ip),
            event_type=event_type,
            user=user,
            action=action,
            result=result,
            hostname=hostname,
            process=process,
            raw=raw,
            log_format="syslog",
        )

    def _parse_web(self, m: re.Match, raw: str) -> NormalizedEvent:
        ts_str = m.group("time").split()[0]
        try:
            ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            ts = datetime.utcnow()

        status = m.group("status")
        result = "success" if status.startswith("2") else "failure"
        event_type = "web_request"
        if status in ("401", "403"):
            event_type = "auth_failure"
        elif status == "404":
            event_type = "recon"

        return NormalizedEvent(
            timestamp=ts,
            source_ip=self._normalize_ip(m.group("src_ip")),
            user=m.group("user") if m.group("user") != "-" else None,
            event_type=event_type,
            action=f"{m.group('method')} {m.group('path')[:200]}",
            result=result,
            bytes_sent=int(m.group("bytes")) if m.group("bytes").isdigit() else None,
            raw=raw,
            log_format="web_access",
        )

    def _parse_generic(self, raw: str) -> Optional[NormalizedEvent]:
        """Best-effort parse: extract timestamp + IPs"""
        ts = None
        m = PATTERNS["ts_iso"].search(raw)
        if m:
            try:
                ts = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
            except ValueError:
                pass

        if not ts:
            m = PATTERNS["ts_unix"].search(raw)
            if m:
                ts = datetime.utcfromtimestamp(int(m.group(1)))

        ips = PATTERNS["ip"].findall(raw)
        src_ip = ips[0] if ips else None
        dst_ip = ips[1] if len(ips) > 1 else None

        if not ts and not src_ip:
            return None

        return NormalizedEvent(
            timestamp=ts or datetime.utcnow(),
            source_ip=self._normalize_ip(src_ip),
            dest_ip=self._normalize_ip(dst_ip),
            event_type="unknown",
            raw=raw,
            log_format="generic",
        )

    def _extract_timestamp_from_dict(self, data: dict) -> Optional[datetime]:
        for key in ("timestamp", "@timestamp", "time", "date", "event_time", "created_at"):
            val = data.get(key)
            if not val:
                continue
            try:
                if isinstance(val, (int, float)):
                    return datetime.utcfromtimestamp(val / 1000 if val > 1e10 else val)
                return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            except (ValueError, OSError):
                continue
        return None

    def _normalize_ip(self, ip: Optional[str]) -> Optional[str]:
        if not ip or ip in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            return None
        # Basic IPv4 validation
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    return ip
            except ValueError:
                pass
        # IPv6 passthrough
        if ":" in ip:
            return ip
        return None

    def parse_csv(self, content: str) -> list[NormalizedEvent]:
        """Parse CSV log format"""
        events = []
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            # Convert CSV row to JSON-like dict and reuse JSON parser
            fake_json = json.dumps(row)
            event = self._parse_json(fake_json)
            if event:
                events.append(event)
        return events


# Singleton parser
_parser = LogParser()


def get_parser() -> LogParser:
    return _parser


# ─── API Endpoints ─────────────────────────────────────────────────────────────
class ParseRequest(BaseModel):
    lines: list[str]
    format: str = "auto"


@router.post("/parse")
async def parse_logs(req: ParseRequest):
    parser = get_parser()
    events = []
    errors = []
    for i, line in enumerate(req.lines):
        try:
            event = parser.parse_line(line)
            if event:
                events.append(event.model_dump())
        except Exception as e:
            errors.append({"line": i, "error": str(e)})

    return {
        "parsed": len(events),
        "failed": len(errors),
        "events": events,
        "errors": errors[:10],
    }