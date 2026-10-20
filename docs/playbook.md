# Incident Response Playbook: Prompt Injection Leading to Data Leak

**Scope:** LLM-SOC HR chatbot (or any LLM app with retrieval and tools)
**Triggers:** Wazuh rules 100502, 100503, 100504, 100505, 100506 (or the matching Sentinel analytics rules)
**Framework:** NIST SP 800-61 phases, mapped to OWASP LLM Top 10 and MITRE ATLAS

| Severity | Condition |
|---|---|
| P1 Critical | Data actually left the system (tool executed to external address, or PII/canary in a response the user received) |
| P2 High | Leak attempted but blocked by guardrails; poisoned document found in the knowledge base |
| P3 Medium | Repeated injection attempts, nothing leaked |

## 1. Detection and triage (first 15 minutes)

1. Open the alert and note: `user`, `event_id`, `prompt`, `findings`, `risk_score`, `retrieved_docs`.
2. Decide which pattern it is:
   - **Direct injection**: the malicious text is in `prompt`.
   - **Indirect injection**: `prompt` looks innocent but `retrieved_docs` contains a flagged document.
3. Check if anything actually left: look at `tool_calls[].executed` and `logs/outbox.log`, and whether the `response` field contains unredacted data.
4. Set severity using the table above.

## 2. Containment (P1/P2: within 1 hour)

- **Direct injection:** suspend or rate-limit the user account; block the source IP if external.
- **Indirect injection:** remove the poisoned document from `data/hr_docs/` (keep a copy as evidence) so it can no longer be retrieved.
- **Tool abuse:** disable the `send_email` tool (remove it from the allow-list) until the review is finished.
- If the system prompt leaked: rotate the canary token and any secrets that were in the prompt.

## 3. Investigation

- Pull all events for the user in the last 7 days: did they probe first (low-risk events) before the successful attack?
- For poisoned documents: who added or edited the file, and when? (File integrity monitoring / git history.)
- Map the attack to MITRE ATLAS (e.g. AML.T0051.001 indirect prompt injection) and OWASP LLM category for the report.

## 4. Eradication and recovery

- Add the attack prompt and pattern to the guardrail rules and to `attacks/attacks.json` as a regression test.
- Re-run `python attacks/run_attacks.py --label post-incident` and confirm the attack now fails.
- Re-enable tools only after the regression test passes.

## 5. Notification

- If real personal data was exposed, involve the DPO: GDPR Article 33 requires notifying the Data Protection Commission within 72 hours of becoming aware of a personal data breach (unless it is unlikely to result in a risk to people).

## 6. Lessons learned

- What stopped (or failed to stop) the attack: input filter, context sanitiser, output filter, or tool allow-list?
- Time to detect and time to respond, measured from the logs (links back to the thesis on reducing incident response time).
