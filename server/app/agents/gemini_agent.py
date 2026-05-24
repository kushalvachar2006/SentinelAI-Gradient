"""
Gemini AI Agent
- /agent/explain: structured alert explanation
- /agent/chat: RAG over stored alerts
- /agent/report: incident PDF report via WeasyPrint
- /agent/predict: attack window prediction
- /agent/fingerprint: behavior vector similarity search
"""
import json
import asyncio
import logging
from datetime import datetime
from typing import Optional
import structlog
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from config.settings import settings
from config.database import get_collection

log = structlog.get_logger()
logger = logging.getLogger("sentinelai.gemini_agent")
router = APIRouter()

# ── SDK import (new google-genai package) ─────────────────────────────────────
try:
    from google import genai
    from google.genai import types as genai_types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    logger.warning("google-genai not installed — run: pip install google-genai")

MODEL_NAME = "gemini-3.5-flash"
_embed_model = "text-embedding-004"

_client = None
ai_enabled = False


def _init_client() -> None:
    global _client, ai_enabled
    if not GENAI_AVAILABLE:
        return
    if not settings.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set — AI features disabled")
        return
    try:
        _client = genai.Client(api_key=settings.GEMINI_API_KEY)
        ai_enabled = True
        logger.info("Gemini AI initialised — model: %s", MODEL_NAME)
    except Exception as exc:
        logger.error("Gemini client init failed: %s", exc)


_init_client()

GENERATION_CONFIG = genai_types.GenerateContentConfig(
    temperature=0.3,
    max_output_tokens=2048,
) if GENAI_AVAILABLE else None

# ── Rate-limit guard ──────────────────────────────────────────────────────────
# Allow only 1 Gemini call at a time. This prevents the Windows
# "too many file descriptors in select()" crash that occurs when hundreds of
# /agent/explain requests are fired simultaneously.
# Combined with queueService.js serialising calls 13s apart, this keeps
# throughput safely under the free-tier limit of 5 req/min.
_gemini_semaphore = asyncio.Semaphore(1)


# ── Core generate call ────────────────────────────────────────────────────────

async def _generate(prompt: str, system: str = "") -> str:
    if not ai_enabled or _client is None:
        return "AI unavailable: Gemini not configured. Set GEMINI_API_KEY in your .env file."

    full_prompt = f"{system}\n\n{prompt}" if system else prompt

    # Retry up to 3 times with exponential back-off on 429 / RESOURCE_EXHAUSTED
    max_retries = 3
    for attempt in range(max_retries):
        async with _gemini_semaphore:
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: _client.models.generate_content(
                        model=MODEL_NAME,
                        contents=full_prompt,
                        config=GENERATION_CONFIG,
                    ),
                )
                text = response.text.strip() if response.text else ""
                if text:
                    return text
                logger.warning("Gemini returned empty text")
                return "AI returned an empty response. Please try again."
            except Exception as exc:
                err_str = str(exc)
                is_rate_limit = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str
                if is_rate_limit and attempt < max_retries - 1:
                    wait = 60 * (attempt + 1)  # 60s, 120s
                    logger.warning("Gemini rate-limited (attempt %d/%d) — retrying in %ds",
                                   attempt + 1, max_retries, wait)
                    await asyncio.sleep(wait)
                    continue
                logger.error("Gemini generate error: %s", exc)
                raise RuntimeError(err_str)
    raise RuntimeError("Gemini rate limit exceeded after retries")


async def _embed(text: str) -> list[float]:
    if not ai_enabled or _client is None:
        return []
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: _client.models.embed_content(
                model=_embed_model,
                contents=text,
            ),
        )
        return result.embeddings[0].values if result.embeddings else []
    except Exception as exc:
        logger.error("Gemini embed error: %s", exc)
        return []


# ─── /agent/explain ───────────────────────────────────────────────────────────
EXPLAIN_SYSTEM = """You are SentinelAI, an expert cybersecurity analyst AI.
Given an alert JSON, return ONLY valid JSON matching this schema:
{
  "summary": "one sentence",
  "what_happened": "2-3 sentences technical description",
  "why_dangerous": "2-3 sentences business/security impact",
  "recommended_action": "specific actionable steps",
  "eli5_version": "explain like I'm 5 years old, 1-2 sentences",
  "mitre_technique": {
    "techniqueId": "T1xxx",
    "techniqueName": "technique name",
    "tacticName": "tactic name",
    "url": "https://attack.mitre.org/techniques/T1xxx"
  }
}
Do not include any text outside the JSON object."""


class ExplainRequest(BaseModel):
    threat: dict


@router.post("/explain")
async def explain_threat(req: ExplainRequest):
    prompt = f"""Analyze this security alert and return the structured explanation:

Alert:
{json.dumps(req.threat, indent=2, default=str)}
"""
    try:
        text = await _generate(prompt, EXPLAIN_SYSTEM)
        text = text.strip()
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:-1])
        return json.loads(text)
    except json.JSONDecodeError as e:
        log.error("explain_json_parse_failed", error=str(e))
        raise HTTPException(500, f"AI returned malformed JSON: {str(e)}")
    except Exception as e:
        log.error("explain_failed", error=str(e))
        raise HTTPException(500, str(e))


# ─── /agent/chat (RAG) ────────────────────────────────────────────────────────
RAG_SYSTEM = """You are SentinelAI, a cybersecurity AI assistant for SOC analysts.
Answer questions about security alerts and incidents using the provided context.
Be precise, factual, and reference specific alerts when relevant.
If context is insufficient, say so clearly. Never fabricate data."""


class ChatRequest(BaseModel):
    message: str
    conversation_history: list[dict] = []
    analyst_id: str = ""
    analyst_name: str = ""


async def _rag_retrieve(query: str, limit: int = 5) -> list[dict]:
    col = get_collection("threats")

    # Try text search — may fail if index not yet built, always fall back
    threats = []
    try:
        threats = await col.find(
            {"$text": {"$search": query}},
            {"score": {"$meta": "textScore"}}
        ).sort([("score", {"$meta": "textScore"})]).limit(limit).to_list(limit)
    except Exception:
        pass  # Index not ready yet — fallback below handles it

    # Fallback: most recent high-risk open threats
    if not threats:
        threats = await col.find(
            {"status": {"$in": ["open", "investigating"]}},
        ).sort([("riskScore", -1)]).limit(limit).to_list(limit)

    # Last resort: just return anything recent
    if not threats:
        threats = await col.find({}).sort([("_id", -1)]).limit(limit).to_list(limit)

    return threats


@router.post("/chat")
async def chat(req: ChatRequest):
    retrieved = await _rag_retrieve(req.message)

    context_parts = []
    for t in retrieved:
        context_parts.append(
            f"- [{t.get('severity','?').upper()}] {t.get('threatType')} from {t.get('sourceIP','?')} "
            f"at {t.get('timestamp','?')} | Score: {t.get('riskScore','?')} | Status: {t.get('status','?')}"
        )

    context = "\n".join(context_parts) if context_parts else "No matching alerts found."

    history_text = ""
    for msg in req.conversation_history[-6:]:
        role = "Analyst" if msg.get("role") == "user" else "SentinelAI"
        history_text += f"{role}: {msg.get('content', '')}\n"

    prompt = f"""Conversation history:
{history_text}

Relevant alert context from MongoDB:
{context}

Analyst question: {req.message}

Answer:"""

    try:
        answer = await _generate(prompt, RAG_SYSTEM)
        return {
            "answer": answer,
            "sources_used": len(retrieved),
            "retrieved_alerts": [
                {
                    "id": str(t.get("_id")),
                    "threatType": t.get("threatType"),
                    "severity": t.get("severity"),
                    "sourceIP": t.get("sourceIP"),
                }
                for t in retrieved
            ],
        }
    except Exception as e:
        log.error("chat_failed", error=str(e))
        raise HTTPException(500, str(e))


# ─── /agent/report ────────────────────────────────────────────────────────────
REPORT_SYSTEM = """You are SentinelAI generating a formal incident response report.
Write comprehensive markdown with these sections:
# Incident Report: [Title]
## Executive Summary
## Timeline of Events
## Technical Analysis
## Indicators of Compromise (IOCs)
## MITRE ATT&CK Mapping
## Impact Assessment
## Containment Actions Taken
## Recommendations
## Appendix: Raw Evidence

Use tables where appropriate. Be precise and professional."""


class ReportRequest(BaseModel):
    incident_id: str


@router.post("/report")
async def generate_report(req: ReportRequest):
    from bson import ObjectId

    col_incidents = get_collection("incidents")
    col_threats = get_collection("threats")

    incident = await col_incidents.find_one({"_id": ObjectId(req.incident_id)})
    if not incident:
        raise HTTPException(404, "Incident not found")

    threats = await col_threats.find(
        {"incidentId": ObjectId(req.incident_id)}
    ).to_list(100)

    incident_summary = {
        "id": str(incident["_id"]),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "status": incident.get("status"),
        "affectedAssets": incident.get("affectedAssets", []),
        "iocs": incident.get("iocs", []),
        "timeline": incident.get("timeline", []),
    }

    threats_summary = [
        {
            "type": t.get("threatType"),
            "severity": t.get("severity"),
            "riskScore": t.get("riskScore"),
            "sourceIP": t.get("sourceIP"),
            "timestamp": str(t.get("timestamp")),
            "status": t.get("status"),
        }
        for t in threats
    ]

    prompt = f"""Generate incident report for:

Incident: {json.dumps(incident_summary, indent=2, default=str)}

Threats ({len(threats)} total): {json.dumps(threats_summary, indent=2, default=str)}

Generated: {datetime.utcnow().isoformat()}Z"""

    try:
        markdown = await _generate(prompt, REPORT_SYSTEM)

        await col_incidents.update_one(
            {"_id": ObjectId(req.incident_id)},
            {"$set": {"reportMarkdown": markdown, "reportGenerated": True}}
        )

        try:
            import markdown as md
            from weasyprint import HTML

            html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {{ font-family: 'DejaVu Sans', sans-serif; margin: 40px; color: #1a1a2e; }}
  h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: #16213e; margin-top: 30px; }}
  h3 {{ color: #0f3460; }}
  table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
  th {{ background: #16213e; color: white; padding: 10px; text-align: left; }}
  td {{ border: 1px solid #ddd; padding: 8px; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
  pre {{ background: #1a1a2e; color: #e2e2e2; padding: 15px; border-radius: 5px; }}
</style>
</head>
<body>
{md.markdown(markdown, extensions=['tables', 'fenced_code'])}
</body>
</html>"""

            pdf_bytes = await asyncio.get_event_loop().run_in_executor(
                None, lambda: HTML(string=html_content).write_pdf()
            )
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="incident-{req.incident_id}.pdf"'},
            )
        except ImportError:
            log.warning("weasyprint_unavailable", msg="Returning markdown instead")
            return {"markdown": markdown, "incident_id": req.incident_id}

    except Exception as e:
        log.error("report_generation_failed", error=str(e))
        raise HTTPException(500, str(e))


# ─── /agent/predict ───────────────────────────────────────────────────────────
PREDICT_SYSTEM = """You are SentinelAI, an expert threat intelligence analyst.
Analyze the attack pattern history and predict the next likely attack window.
Return ONLY valid JSON:
{
  "prediction": "narrative description of predicted next attack",
  "estimated_window": {"start": "ISO timestamp", "end": "ISO timestamp"},
  "confidence": "high|medium|low",
  "reasoning": "step-by-step analysis",
  "recommendations": ["action1", "action2"],
  "pattern_type": "regular|random|escalating|dormant"
}"""


class PredictRequest(BaseModel):
    threat_type: str
    source_ip: Optional[str] = None
    historical_timestamps: list[str]


@router.post("/predict")
async def predict_attack(req: PredictRequest):
    if len(req.historical_timestamps) < 2:
        return {
            "prediction": "Insufficient historical data for prediction",
            "confidence": "low",
            "reasoning": "Need at least 2 data points",
        }

    prompt = f"""Analyze this attack pattern and predict the next attack window:

Threat Type: {req.threat_type}
Source IP: {req.source_ip or "unknown"}
Historical Attack Timestamps (chronological):
{json.dumps(req.historical_timestamps, indent=2)}

Current time: {datetime.utcnow().isoformat()}Z

Analyze the intervals between attacks, time-of-day patterns, frequency trends,
and predict when the next attack is most likely to occur."""

    try:
        text = await _generate(prompt, PREDICT_SYSTEM)
        text = text.strip()
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:-1])
        return json.loads(text)
    except json.JSONDecodeError:
        return {"prediction": text, "confidence": "medium"}
    except Exception as e:
        raise HTTPException(500, str(e))


# ─── /agent/fingerprint ───────────────────────────────────────────────────────
class FingerprintRequest(BaseModel):
    threat_id: str


@router.post("/fingerprint")
async def fingerprint_threat(req: FingerprintRequest):
    from bson import ObjectId

    col = get_collection("threats")
    threat = await col.find_one({"_id": ObjectId(req.threat_id)})
    if not threat:
        raise HTTPException(404, "Threat not found")

    behavior_text = (
        f"threatType:{threat.get('threatType')} "
        f"severity:{threat.get('severity')} "
        f"eventType:{threat.get('eventType','')} "
        f"action:{threat.get('action','')} "
        f"result:{threat.get('result','')} "
        f"riskScore:{threat.get('riskScore',0)} "
        f"user:{threat.get('user','unknown')} "
    )

    try:
        vector = await _embed(behavior_text)

        if vector:
            await col.update_one(
                {"_id": ObjectId(req.threat_id)},
                {"$set": {"behaviorVector": vector}}
            )

        candidates = await col.find(
            {
                "_id": {"$ne": ObjectId(req.threat_id)},
                "behaviorVector": {"$exists": True, "$ne": []},
                "threatType": threat.get("threatType"),
            }
        ).limit(50).to_list(50)

        import numpy as np

        def cosine_sim(a, b):
            a, b = np.array(a), np.array(b)
            denom = np.linalg.norm(a) * np.linalg.norm(b)
            return float(np.dot(a, b) / denom) if denom > 0 else 0.0

        similarities = []
        if vector:
            for c in candidates:
                sim = cosine_sim(vector, c.get("behaviorVector", []))
                if sim > 0.85:
                    similarities.append({
                        "threatId": str(c["_id"]),
                        "threatType": c.get("threatType"),
                        "severity": c.get("severity"),
                        "sourceIP": c.get("sourceIP"),
                        "timestamp": str(c.get("timestamp")),
                        "similarity": round(sim, 3),
                    })

        similarities.sort(key=lambda x: x["similarity"], reverse=True)

        return {
            "threatId": req.threat_id,
            "similarThreats": similarities[:10],
            "totalFound": len(similarities),
        }
    except Exception as e:
        log.error("fingerprint_failed", error=str(e))
        raise HTTPException(500, str(e))


# ─── /agent/report/:id (fetch stored report) ─────────────────────────────────
@router.get("/report/{incident_id}")
async def get_report(incident_id: str):
    from bson import ObjectId

    col = get_collection("incidents")
    incident = await col.find_one({"_id": ObjectId(incident_id)})
    if not incident or not incident.get("reportGenerated"):
        raise HTTPException(404, "Report not found")

    return {"markdown": incident.get("reportMarkdown", ""), "incident_id": incident_id}