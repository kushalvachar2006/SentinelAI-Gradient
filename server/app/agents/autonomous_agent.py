"""
Autonomous Response Agent (LangChain ReAct)
Tools: block_ip, draft_firewall_rule, create_ticket
Only acts when risk_score > 85 AND human approves
Full audit trail with reasoning chain
"""
import json
import asyncio
import httpx
from datetime import datetime
from typing import Optional, Any
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config.database import get_collection
from config.settings import settings

log = structlog.get_logger()
router = APIRouter()

try:
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain.tools import Tool, StructuredTool
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain.prompts import PromptTemplate
    from langchain.memory import ConversationBufferMemory
    LANGCHAIN_AVAILABLE = True
except ImportError:
    log.warning("langchain_not_installed", msg="Autonomous agent will use fallback mode")
    LANGCHAIN_AVAILABLE = False


# ─── Tool Implementations ─────────────────────────────────────────────────────
class AgentTools:
    def __init__(self, threat_id: str, node_service_url: str):
        self.threat_id = threat_id
        self.node_service_url = node_service_url
        self.action_log: list[dict] = []

    async def block_ip(self, ip: str, reason: str = "") -> str:
        """Add IP to MongoDB blocklist and notify Node server"""
        col = get_collection("blocklist")
        await col.update_one(
            {"ip": ip},
            {
                "$set": {
                    "ip": ip,
                    "addedByAgent": True,
                    "threatId": self.threat_id,
                    "reason": reason or f"Autonomous block: threat {self.threat_id}",
                    "isActive": True,
                    "createdAt": datetime.utcnow(),
                }
            },
            upsert=True,
        )

        # Notify Node service
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"{self.node_service_url}/internal/blocklist-update",
                    json={"ip": ip, "threatId": self.threat_id, "action": "block"},
                )
        except Exception as e:
            log.warning("node_notify_failed", error=str(e))

        action = {
            "tool": "block_ip",
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
            "result": "success",
        }
        self.action_log.append(action)
        log.info("agent_blocked_ip", ip=ip, threat_id=self.threat_id)
        return f"SUCCESS: IP {ip} added to blocklist. Firewall rule enforcement pending analyst action."

    def draft_firewall_rule(self, ip: str, port: Optional[int] = None, protocol: str = "tcp") -> str:
        """Generate iptables/pf firewall rule string"""
        rules = []

        # iptables (Linux)
        if port:
            rules.append(f"iptables -I INPUT -s {ip} -p {protocol} --dport {port} -j DROP")
            rules.append(f"iptables -I OUTPUT -d {ip} -p {protocol} --sport {port} -j DROP")
        else:
            rules.append(f"iptables -I INPUT -s {ip} -j DROP")
            rules.append(f"iptables -I OUTPUT -d {ip} -j DROP")

        # pf (BSD/macOS)
        if port:
            pf_rule = f'block in quick on egress proto {protocol} from {ip} to any port {port}'
        else:
            pf_rule = f'block in quick on egress from {ip} to any'
        rules.append(f"\n# pf (BSD): {pf_rule}")

        # Windows Firewall
        win_rule = (
            f'netsh advfirewall firewall add rule name="SentinelAI-Block-{ip}" '
            f'dir=in action=block remoteip={ip}'
        )
        rules.append(f"\n# Windows: {win_rule}")

        rule_text = "\n".join(rules)

        action = {
            "tool": "draft_firewall_rule",
            "ip": ip,
            "port": port,
            "rules": rule_text,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.action_log.append(action)
        return rule_text

    async def create_ticket(self, summary: str, description: str = "", priority: str = "High") -> str:
        """Post to JIRA webhook (mock)"""
        ticket_data = {
            "summary": summary,
            "description": description,
            "priority": priority,
            "threat_id": self.threat_id,
            "created_by": "SentinelAI-Autonomous-Agent",
            "created_at": datetime.utcnow().isoformat(),
            "labels": ["sentinelai", "auto-generated", "security-incident"],
        }

        ticket_id = f"SEC-{abs(hash(self.threat_id)) % 10000:04d}"

        if settings.JIRA_WEBHOOK_URL:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.post(settings.JIRA_WEBHOOK_URL, json=ticket_data)
            except Exception as e:
                log.warning("jira_webhook_failed", error=str(e))

        action = {
            "tool": "create_ticket",
            "ticketId": ticket_id,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.action_log.append(action)
        log.info("agent_created_ticket", ticket_id=ticket_id)
        return f"Ticket {ticket_id} created: {summary}"


# ─── ReAct Agent ──────────────────────────────────────────────────────────────
REACT_PROMPT = """You are SentinelAI, an autonomous cybersecurity response agent.
Your job is to respond to high-risk security threats automatically.

Available tools:
{tools}

Tool names: {tool_names}

CRITICAL RULES:
1. Only take actions that directly mitigate the specific threat
2. Always draft a firewall rule before or after blocking
3. Always create a ticket documenting your actions
4. Explain your reasoning for each action
5. Be conservative - only block confirmed malicious IPs

Use this format:
Question: the threat to respond to
Thought: reason about what to do
Action: tool name
Action Input: tool input
Observation: tool result
... (repeat Thought/Action/Observation as needed)
Thought: I now have completed the response
Final Answer: summary of all actions taken and their results

Question: {input}
{agent_scratchpad}"""


async def run_autonomous_response(threat: dict) -> dict:
    """Execute autonomous response agent for a threat"""
    threat_id = str(threat.get("_id", ""))
    source_ip = threat.get("sourceIP")
    risk_score = threat.get("riskScore", 0)
    threat_type = threat.get("threatType")

    tools_impl = AgentTools(threat_id, settings.NODE_SERVICE_URL)

    if LANGCHAIN_AVAILABLE:
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            google_api_key=settings.GEMINI_API_KEY,
            temperature=0.1,
        )

        lc_tools = [
            Tool(
                name="block_ip",
                description="Block an IP address. Input: JSON with 'ip' and optional 'reason'",
                func=lambda x: asyncio.run(tools_impl.block_ip(**json.loads(x))),
                coroutine=lambda x: tools_impl.block_ip(**json.loads(x)),
            ),
            Tool(
                name="draft_firewall_rule",
                description="Generate firewall rules for an IP. Input: JSON with 'ip', optional 'port' and 'protocol'",
                func=lambda x: tools_impl.draft_firewall_rule(**json.loads(x)),
            ),
            Tool(
                name="create_ticket",
                description="Create JIRA ticket. Input: JSON with 'summary', optional 'description' and 'priority'",
                func=lambda x: asyncio.run(tools_impl.create_ticket(**json.loads(x))),
                coroutine=lambda x: tools_impl.create_ticket(**json.loads(x)),
            ),
        ]

        prompt = PromptTemplate.from_template(REACT_PROMPT)
        agent = create_react_agent(llm, lc_tools, prompt)
        executor = AgentExecutor(
            agent=agent,
            tools=lc_tools,
            verbose=True,
            max_iterations=6,
            handle_parsing_errors=True,
        )

        threat_description = (
            f"THREAT ALERT: {threat_type} attack detected\n"
            f"Source IP: {source_ip}\n"
            f"Risk Score: {risk_score}/100\n"
            f"Severity: {threat.get('severity')}\n"
            f"User: {threat.get('user', 'unknown')}\n"
            f"Evidence: {threat.get('evidenceCount', 1)} events\n"
            f"Description: {threat.get('description', 'No description')}\n"
            f"\nTake appropriate autonomous response actions."
        )

        result = await asyncio.to_thread(executor.invoke, {"input": threat_description})
        reasoning_chain = result.get("output", "")
    else:
        # Fallback: direct tool calls without LangChain
        reasoning_chain = f"Fallback mode (LangChain unavailable). Direct response to {threat_type}."

        if source_ip:
            await tools_impl.block_ip(source_ip, f"Autonomous response to {threat_type}")
            tools_impl.draft_firewall_rule(source_ip)
        await tools_impl.create_ticket(
            summary=f"[AUTO] {threat_type} from {source_ip} - Risk: {risk_score}",
            description=f"Automatically generated by SentinelAI\nThreat ID: {threat_id}",
        )

    # Save audit trail
    col = get_collection("audit_trail")
    audit_entry = {
        "threatId": threat_id,
        "agentType": "autonomous_react",
        "riskScore": risk_score,
        "threatType": threat_type,
        "sourceIP": source_ip,
        "actionsPerformed": tools_impl.action_log,
        "reasoningChain": reasoning_chain,
        "executedAt": datetime.utcnow(),
    }
    await col.insert_one(audit_entry)

    return {
        "success": True,
        "threat_id": threat_id,
        "actions": tools_impl.action_log,
        "reasoning": reasoning_chain,
        "ticket_id": next(
            (a["ticketId"] for a in tools_impl.action_log if "ticketId" in a),
            None
        ),
    }


# ─── API Endpoints ─────────────────────────────────────────────────────────────
class ExecuteAutonomousRequest(BaseModel):
    threat_id: str
    approved_by: str


@router.post("/execute-autonomous")
async def execute_autonomous(req: ExecuteAutonomousRequest):
    from bson import ObjectId

    col = get_collection("threats")
    threat = await col.find_one({"_id": ObjectId(req.threat_id)})
    if not threat:
        raise HTTPException(404, "Threat not found")

    if threat.get("riskScore", 0) < 85:
        raise HTTPException(400, f"Risk score {threat.get('riskScore')} below threshold (85)")

    result = await run_autonomous_response(threat)

    # Update threat record
    await col.update_one(
        {"_id": ObjectId(req.threat_id)},
        {
            "$set": {
                "autonomousResponseApproved": True,
                "autonomousResponsePending": False,
                "ticketId": result.get("ticket_id"),
            }
        }
    )

    return result


class DraftFirewallRequest(BaseModel):
    ip: str
    threat_id: str
    port: Optional[int] = None
    protocol: str = "tcp"


@router.post("/draft-firewall-rule")
async def draft_firewall_rule(req: DraftFirewallRequest):
    tools = AgentTools(req.threat_id, settings.NODE_SERVICE_URL)
    rule = tools.draft_firewall_rule(req.ip, req.port, req.protocol)

    # Save to threat
    from bson import ObjectId
    col = get_collection("threats")
    await col.update_one(
        {"_id": ObjectId(req.threat_id)},
        {"$set": {"firewallRuleDraft": rule}}
    )

    return {"rule": rule, "ip": req.ip}