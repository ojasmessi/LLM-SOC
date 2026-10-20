"""
guardrails.py - the "AI firewall" for LLM-SOC.

Four layers of defence, each one maps to an OWASP LLM Top 10 risk:
  1. check_input       -> LLM01 Prompt Injection (direct) + LLM10 Unbounded Consumption
  2. sanitize_context  -> LLM01 Prompt Injection (indirect, hidden in documents)
  3. check_output      -> LLM02 Sensitive Info Disclosure + LLM07 System Prompt Leakage
  4. check_tool_call   -> LLM06 Excessive Agency

Every function returns a list of "findings" (strings). The app writes these
findings into the security log so the SIEM can alert on them.
"""

import re
import time
from collections import defaultdict, deque

# A secret marker hidden inside the system prompt. If it ever appears in a
# response, we KNOW the system prompt leaked. (Same idea as a honeytoken.)
CANARY_TOKEN = "CANARY-7f3a9c"

# ---------------------------------------------------------------------------
# 1. Input checks (direct prompt injection, rate limiting)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules|prompts)",
    r"disregard (all |any )?(previous|prior|above)",
    r"(reveal|show|print|repeat|output) (me )?(your|the) (system|initial|hidden) (prompt|instructions)",
    r"you are now (in )?(dan|developer mode|unrestricted)",
    r"\bjailbreak\b",
    r"pretend (you are|to be) .*(no|without) (rules|restrictions|filters)",
    r"act as .*(no|without) (rules|restrictions|filters)",
    r"forget (everything|all|your) (you|instructions|rules)",
    r"what (is|was) written (above|before)",
    r"base64|rot13",  # common encoding tricks used to smuggle instructions
]

MAX_PROMPT_CHARS = 2000
RATE_LIMIT_REQUESTS = 10      # max requests...
RATE_LIMIT_WINDOW_SEC = 60    # ...per this many seconds, per user

_request_history = defaultdict(deque)


def check_input(user: str, message: str) -> list[str]:
    findings = []
    lowered = message.lower()

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            findings.append(f"prompt_injection_pattern:{pattern[:40]}")
            break  # one hit is enough to block

    if len(message) > MAX_PROMPT_CHARS:
        findings.append("oversized_prompt")

    # Sliding-window rate limit per user
    now = time.time()
    history = _request_history[user]
    while history and now - history[0] > RATE_LIMIT_WINDOW_SEC:
        history.popleft()
    history.append(now)
    if len(history) > RATE_LIMIT_REQUESTS:
        findings.append("rate_limit_exceeded")

    return findings


# ---------------------------------------------------------------------------
# 2. Context sanitisation (indirect prompt injection in retrieved documents)
# ---------------------------------------------------------------------------

HIDDEN_BLOCK = re.compile(r"<!--.*?-->", re.DOTALL)  # HTML comments
INSTRUCTION_LINE = re.compile(
    r"^.*(ignore (all )?previous instructions|note to ai|call send_email).*$",
    re.IGNORECASE | re.MULTILINE,
)


def sanitize_context(doc_text: str) -> tuple[str, list[str]]:
    findings = []
    if HIDDEN_BLOCK.search(doc_text):
        findings.append("hidden_comment_in_document")
        doc_text = HIDDEN_BLOCK.sub("[removed hidden content]", doc_text)
    if INSTRUCTION_LINE.search(doc_text):
        findings.append("instruction_in_document")
        doc_text = INSTRUCTION_LINE.sub("[removed suspicious instruction]", doc_text)
    return doc_text, findings


# ---------------------------------------------------------------------------
# 3. Output checks (data leakage + system prompt leakage)
# ---------------------------------------------------------------------------

PPSN = re.compile(r"\b\d{7}[A-Z]{1,2}\b")                     # Irish PPS number format
SALARY = re.compile(r"(EUR|€)\s?\d{2,3},?\d{3}", re.IGNORECASE)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def check_output(reply: str) -> tuple[str, list[str]]:
    findings = []
    if CANARY_TOKEN.lower() in reply.lower():
        findings.append("canary_token_leaked")
        return "Sorry, I can't share that.", findings

    if PPSN.search(reply):
        findings.append("pii_ppsn_in_output")
        reply = PPSN.sub("[REDACTED-PPSN]", reply)
    if SALARY.search(reply):
        findings.append("pii_salary_in_output")
        reply = SALARY.sub("[REDACTED-SALARY]", reply)
    # Only company-internal addresses get redacted; policy contacts stay.
    for addr in set(EMAIL.findall(reply)):
        if addr.endswith("@acme-demo.ie") and not addr.startswith("security@"):
            findings.append("pii_email_in_output")
            reply = reply.replace(addr, "[REDACTED-EMAIL]")
    return reply, findings


# ---------------------------------------------------------------------------
# 4. Tool-call checks (excessive agency)
# ---------------------------------------------------------------------------

ALLOWED_TOOLS = {"send_email"}
ALLOWED_EMAIL_DOMAINS = ("@acme-demo.ie",)


def check_tool_call(tool: str, args: dict) -> list[str]:
    findings = []
    if tool not in ALLOWED_TOOLS:
        findings.append(f"tool_not_allowed:{tool}")
    if tool == "send_email":
        to = args.get("to", "")
        if not to.endswith(ALLOWED_EMAIL_DOMAINS):
            findings.append(f"external_email_blocked:{to}")
        body = args.get("body", "")
        if PPSN.search(body) or SALARY.search(body):
            findings.append("pii_in_tool_call")
        if CANARY_TOKEN.lower() in body.lower():
            findings.append("canary_in_tool_call")
    return findings
