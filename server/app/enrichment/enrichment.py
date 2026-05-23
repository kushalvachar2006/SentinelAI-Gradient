"""
Enrichment Module
- AbuseIPDB: IP reputation lookup (in-memory cache, 1h TTL)
- VirusTotal: IP/hash lookup
- MaxMind GeoIP: lat/lng, country, ASN
"""
import json
import asyncio
import time
from datetime import datetime
from typing import Optional
import structlog
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from config.settings import settings

log = structlog.get_logger()
router = APIRouter()

CACHE_TTL = 3600  # 1 hour in seconds

# Simple in-memory cache: { key: (value, expires_at) }
_cache: dict = {}


def _cache_get(key: str) -> Optional[dict]:
    entry = _cache.get(key)
    if entry and time.time() < entry[1]:
        return entry[0]
    return None


def _cache_set(key: str, value: dict, ttl: int = CACHE_TTL):
    _cache[key] = (value, time.time() + ttl)


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
async def lookup_abuseipdb(ip: str) -> dict:
    cache_key = f"abuseipdb:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if not settings.ABUSEIPDB_KEY:
        return {}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={
                    "Key": settings.ABUSEIPDB_KEY,
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "isAbusive": data.get("abuseConfidenceScore", 0) > 25,
                    "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                    "countryCode": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "cachedAt": datetime.utcnow().isoformat(),
                }
                _cache_set(cache_key, result)
                return result
    except Exception as e:
        log.warning("abuseipdb_failed", ip=ip, error=str(e))

    return {}


# ─── VirusTotal ───────────────────────────────────────────────────────────────
async def lookup_virustotal_ip(ip: str) -> dict:
    cache_key = f"vt:ip:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if not settings.VIRUSTOTAL_KEY:
        return {}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.VIRUSTOTAL_KEY},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
                    "cachedAt": datetime.utcnow().isoformat(),
                }
                _cache_set(cache_key, result, ttl=7200)
                return result
    except Exception as e:
        log.warning("virustotal_failed", ip=ip, error=str(e))

    return {}


async def lookup_virustotal_hash(file_hash: str) -> dict:
    cache_key = f"vt:hash:{file_hash}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if not settings.VIRUSTOTAL_KEY:
        return {}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": settings.VIRUSTOTAL_KEY},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "name": data.get("meaningful_name"),
                    "type": data.get("type_description"),
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                    "cachedAt": datetime.utcnow().isoformat(),
                }
                _cache_set(cache_key, result, ttl=86400)
                return result
    except Exception as e:
        log.warning("vt_hash_failed", hash=file_hash, error=str(e))

    return {}


# ─── MaxMind GeoIP ────────────────────────────────────────────────────────────
_geo_reader = None


def _get_geo_reader():
    global _geo_reader
    if _geo_reader is not None:
        return _geo_reader

    try:
        import geoip2.database
        if settings.MAXMIND_DB_PATH:
            _geo_reader = geoip2.database.Reader(settings.MAXMIND_DB_PATH)
            log.info("maxmind_loaded", path=settings.MAXMIND_DB_PATH)
    except Exception as e:
        log.warning("maxmind_unavailable", error=str(e))

    return _geo_reader


def lookup_geoip(ip: str) -> dict:
    reader = _get_geo_reader()
    if not reader:
        return {}

    try:
        response = reader.city(ip)
        return {
            "lat": response.location.latitude,
            "lng": response.location.longitude,
            "country": response.country.name,
            "countryCode": response.country.iso_code,
            "city": response.city.name,
            "asn": None,
            "org": None,
            "timezone": response.location.time_zone,
        }
    except Exception:
        return {}


# ─── Combined Enrichment ──────────────────────────────────────────────────────
async def enrich_ip(ip: str) -> dict:
    """Run all enrichment sources concurrently"""
    geo = lookup_geoip(ip)  # sync, fast

    abuseipdb, virustotal = await asyncio.gather(
        lookup_abuseipdb(ip),
        lookup_virustotal_ip(ip),
        return_exceptions=True,
    )

    return {
        "geoIP": geo,
        "abuseIPDB": abuseipdb if isinstance(abuseipdb, dict) else {},
        "virusTotal": virustotal if isinstance(virustotal, dict) else {},
        "cachedAt": datetime.utcnow().isoformat(),
    }


# ─── API Endpoints ─────────────────────────────────────────────────────────────
class EnrichRequest(BaseModel):
    threat_id: str
    ip: str


@router.post("/enrich")
async def enrich_endpoint(req: EnrichRequest):
    result = await enrich_ip(req.ip)
    return result


class HashEnrichRequest(BaseModel):
    file_hash: str


@router.post("/enrich/hash")
async def enrich_hash(req: HashEnrichRequest):
    result = await lookup_virustotal_hash(req.file_hash)
    return result