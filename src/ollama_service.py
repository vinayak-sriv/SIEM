"""
ollama_service.py

Wraps the Ollama REST API. Handles prompt building, HTTP calls, response
parsing, retry logic, and async batch enrichment.

Compatibility notes:
  - Uses Python 3.9+ type annotations.
  - asyncio.get_event_loop() is deprecated inside async functions in 3.10+;
    replaced with asyncio.get_running_loop().
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import re
import shlex
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional

from models import Alert, EnrichedAlert, normalize_groups

log = logging.getLogger("OllamaService")


class LLMParseError(ValueError):
    """Raised when Ollama returns a syntactically valid but unusable response."""

_HEADING_RE = re.compile(
    r"^\s*(?:#+\s*)?(?:[-*]\s*)?"
    r"(explanation|analysis|summary|impact|risk|remediation steps|remediation|actions?)"
    r"\s*:?\s*(.*)$",
    re.IGNORECASE,
)

_SYSTEM_PROMPT = """You are a senior SOC analyst explaining Wazuh SIEM alerts for a live cybersecurity demo.

Return EXACTLY these headings and no extra preface:

EXPLANATION:
2-3 crisp sentences. Name the likely attack, key evidence, and MITRE ATT&CK ID when applicable.

IMPACT:
1-2 crisp sentences. State what could happen next if the alert is ignored.

REMEDIATION:
3-5 practical steps. Include copy-paste-ready Linux or PowerShell commands when useful.

Rules:
- Be specific to the alert fields provided.
- Do not invent unknown facts.
- Prefer direct SOC language over generic textbook wording.
- Keep the total response under 180 words."""

# Wazuh rule IDs commonly seen in the demo/training data. Operators can move
# these into config later if they want a site-specific rule knowledge base.
_RULE_HINTS = {
    "2502": "Multiple SSH authentication failures; likely brute-force or password spraying. MITRE T1110.",
    "5710": "SSH authentication failure. MITRE T1110.",
    "5712": "SSHD brute-force or invalid login activity. MITRE T1110.",
    "5720": "Multiple SSHD authentication failures, often Hydra-style brute force. MITRE T1110.",
    "5763": "SSHD brute-force activity or repeated failed logins. MITRE T1110.",
    "31103": "Possible SQL injection or malicious web request. MITRE T1190.",
    "40111": "File integrity monitoring change on a sensitive file. Possible persistence or credential tampering.",
    "60102": "Windows Defender malware detection. Possible endpoint compromise.",
}


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


class OllamaService:
    """
    Talks to a local Ollama server to enrich Wazuh alerts with LLM analysis.

    Supports both single-alert (synchronous) and batched (async) enrichment.
    The semaphore in async mode caps concurrent Ollama calls so you don't
    run the server out of memory on a large batch.
    """

    def __init__(self, config: dict):
        ollama_cfg          = config["ollama"]
        self.endpoint       : str = ollama_cfg["base_url"].rstrip("/")
        self.model          : str = ollama_cfg["model"]
        self.maxTokens      : int = ollama_cfg.get("max_tokens", 1024)
        self._timeout       : int = ollama_cfg.get("timeout_seconds", 120)
        self._max_retries   : int = ollama_cfg.get("max_retries", 3)
        self._max_concurrent: int = ollama_cfg.get("max_concurrent_calls", 3)
        self._circuit_threshold: int = ollama_cfg.get("circuit_breaker_failures", 2)
        self._circuit_cooldown : int = ollama_cfg.get("circuit_breaker_cooldown_seconds", 45)
        self._failure_count    : int = 0
        self._circuit_open_until: float = 0.0
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, self._max_concurrent),
            thread_name_prefix="ollama-enrich",
        )
        # Created lazily inside an async context — can't be instantiated at __init__ time.
        self._semaphore: Optional[asyncio.Semaphore] = None

        log.info(f"OllamaService ready — model={self.model}, endpoint={self.endpoint}")

    def _get_semaphore(self) -> asyncio.Semaphore:
        """Return the shared semaphore, creating it on first use."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)
        return self._semaphore

    @staticmethod
    def _build_prompt(alert: Alert) -> str:
        """Build the user-facing part of the LLM prompt from an Alert."""
        raw      = alert.raw
        rule     = _as_dict(raw.get("rule", {}))
        agent    = _as_dict(raw.get("agent", {}))
        data     = _as_dict(raw.get("data", {}))
        syscheck = _as_dict(raw.get("syscheck", {}))

        rule_id = str(rule.get("id", "N/A"))
        groups = normalize_groups(rule.get("groups", []))
        hint = _RULE_HINTS.get(rule_id)

        lines = [
            "Analyze this Wazuh security alert and produce analyst-ready output.",
            "This is for a local Wazuh + Ollama SOC demo.",
            "",
            f"Timestamp   : {alert.timestamp.isoformat()}",
            f"Agent       : {agent.get('name','N/A')} "
            f"(ID: {agent.get('id','N/A')}, IP: {agent.get('ip','N/A')})",
            f"Rule ID     : {rule_id}",
            f"Severity    : Level {alert.level} — {alert.get_severity()}",
            f"Description : {alert.ruleDesc}",
            f"Groups      : {', '.join(groups) if groups else 'N/A'}",
        ]

        if hint:
            lines.append(f"Rule Hint   : {hint}")

        if data.get("srcip"):
            lines.append(f"Source IP   : {data['srcip']}")
        if data.get("dstuser"):
            lines.append(f"Target User : {data['dstuser']}")
        if data.get("url"):
            lines.append(f"URL         : {data['url']}")
        if syscheck.get("path"):
            lines.append(f"File Path   : {syscheck['path']}")
            lines.append(f"FIM Event   : {syscheck.get('event','N/A')}")
        if raw.get("full_log"):
            lines.append(f"Full Log    : {str(raw['full_log'])[:500]}")

        lines.extend([
            "",
            "Output requirements:",
            "EXPLANATION must identify the attack and evidence.",
            "IMPACT must explain realistic risk.",
            "REMEDIATION must include immediate containment and investigation commands.",
        ])

        return "\n".join(lines)

    def generate(self, prompt: str) -> str:
        """POST a prompt to Ollama's /api/generate and return the raw response body."""
        payload = json.dumps({
            "model"  : self.model,
            "prompt" : prompt,
            "system" : _SYSTEM_PROMPT,
            "stream" : False,
            "options": {
                "temperature": 0.2,
                "num_predict": self.maxTokens,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.endpoint}/api/generate",
            data    = payload,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        context = ssl.create_default_context() if self.endpoint.startswith("https://") else None
        with urllib.request.urlopen(req, timeout=self._timeout, context=context) as resp:
            return resp.read().decode("utf-8")

    def parse_response(self, raw_response: str) -> tuple[str, str, str]:
        """
        Extract the EXPLANATION / IMPACT / REMEDIATION sections from the LLM output.
        Returns a (explanation, impact, remediation) tuple of strings.
        Falls back to putting the entire response in explanation if parsing fails.
        """
        try:
            data = json.loads(raw_response)
            if data.get("error"):
                raise ValueError(f"Ollama returned error: {data['error']}")
            text = self._clean_section(data.get("response", ""))
            if not text:
                raise LLMParseError("Ollama response was missing response text")
        except json.JSONDecodeError:
            text = self._clean_section(raw_response)
            if not text:
                raise LLMParseError("Ollama response was empty")

        sections = {"explanation": [], "impact": [], "remediation": []}
        current = None

        for line in text.splitlines():
            match = _HEADING_RE.match(line)
            if match:
                heading = match.group(1).lower()
                remainder = match.group(2).strip()
                if heading in {"explanation", "analysis", "summary"}:
                    current = "explanation"
                elif heading in {"impact", "risk"}:
                    current = "impact"
                else:
                    current = "remediation"
                if remainder:
                    sections[current].append(remainder)
                continue

            if current:
                sections[current].append(line.rstrip())

        explanation = self._clean_section("\n".join(sections["explanation"]))
        impact = self._clean_section("\n".join(sections["impact"]))
        remediation = self._clean_section("\n".join(sections["remediation"]))

        if not any([explanation, impact, remediation]):
            explanation = text
            impact      = "See explanation above."
            remediation = "Manual investigation required."

        return explanation, impact, remediation

    @staticmethod
    def _clean_section(text: str) -> str:
        """Trim common LLM formatting noise without destroying useful commands."""
        lines = [line.rstrip() for line in text.splitlines()]
        start = 0
        end = len(lines)
        while start < end and not lines[start].strip():
            start += 1
        while end > start and not lines[end - 1].strip():
            end -= 1
        return "\n".join(lines[start:end])

    def parseResponse(self, raw_response: str) -> tuple[str, str, str]:
        """Backward-compatible alias for older callers."""
        return self.parse_response(raw_response)

    def enrich_alert(self, alert: Alert) -> EnrichedAlert:
        """
        Run the full enrichment pipeline for one alert (synchronous).
        Retries up to max_retries times before returning a degraded response.
        """
        prompt = self._build_prompt(alert)
        log.info(f"Enriching {alert.alertId[:8]} — level {alert.level}: {alert.ruleDesc[:50]}")

        last_error: Optional[Exception] = None
        if self._circuit_is_open():
            last_error = RuntimeError("Ollama circuit breaker is open")
            log.warning(f"  {last_error}; using deterministic fallback")
            return self._fallback_enrichment(alert, last_error)

        for attempt in range(1, self._max_retries + 1):
            try:
                t0       = time.monotonic()
                raw_resp = self.generate(prompt)
                elapsed  = time.monotonic() - t0
                log.info(f"  LLM responded in {elapsed:.1f}s (attempt {attempt})")

                expl, impact, remed = self.parse_response(raw_resp)
                self._record_success()
                return EnrichedAlert(
                    originalAlert = alert,
                    explanation   = expl,
                    impact        = impact,
                    remediation   = remed,
                )
            except urllib.error.URLError as e:
                last_error = e
                self._record_failure()
                log.warning(f"  Ollama unreachable (attempt {attempt}/{self._max_retries}): {e}")
                if attempt < self._max_retries:
                    time.sleep(5 * attempt)
            except Exception as e:
                last_error = e
                self._record_failure()
                log.error(f"  LLM error (attempt {attempt}/{self._max_retries}): {e}")
                if attempt < self._max_retries:
                    time.sleep(3)

        # If Ollama never responded, return a best-effort SOC alert so the
        # pipeline stays useful during a live demo or network hiccup.
        log.error(f"OllamaService gave up after {self._max_retries} attempts: {last_error}")
        return self._fallback_enrichment(alert, last_error)

    def _circuit_is_open(self) -> bool:
        return time.monotonic() < self._circuit_open_until

    def _record_success(self) -> None:
        self._failure_count = 0
        self._circuit_open_until = 0.0

    def _record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self._circuit_threshold:
            self._circuit_open_until = time.monotonic() + self._circuit_cooldown
            log.warning(
                f"Ollama circuit opened for {self._circuit_cooldown}s "
                f"after {self._failure_count} consecutive failure(s)"
            )

    def close(self) -> None:
        """Release worker threads used for blocking Ollama calls."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _fallback_enrichment(self, alert: Alert, error: Optional[Exception]) -> EnrichedAlert:
        """Create deterministic SOC guidance when the LLM is unavailable."""
        raw = alert.raw
        rule = _as_dict(raw.get("rule", {}))
        groups = {group.lower() for group in normalize_groups(rule.get("groups", []))}
        desc = alert.ruleDesc.lower()
        src = alert.sourceIP
        src_arg = shlex.quote(src) if src and src != "N/A" else "SOURCE_IP"
        agent = alert.agentName
        agent_ip = _as_dict(raw.get("agent", {})).get("ip", "N/A")
        rule_id = str(rule.get("id", "N/A"))
        rule_arg = shlex.quote(rule_id)
        error_note = f"Ollama fallback was used because the model call failed: {error}"

        if (
            rule_id in {"2502", "5710", "5712", "5720", "5763"} or
            {"sshd", "authentication_failures"} & groups or
            "ssh" in desc or "hydra" in desc
        ):
            explanation = (
                f"Wazuh detected a high-severity SSH authentication attack against {agent} "
                f"({agent_ip}), likely brute force activity from {src}. This maps closely to "
                "MITRE ATT&CK T1110 (Brute Force)."
            )
            impact = (
                "If credentials are guessed successfully, the attacker can obtain shell access, "
                "escalate privileges, and pivot further into the lab network."
            )
            remediation = f"""```bash
sudo grep -F {src_arg} /var/log/auth.log | tail -50
sudo ss -tnp | grep ':22'
sudo ufw deny from {src_arg} to any port 22
sudo passwd -l root
```
Review failed-login volume, block the attacking IP for the demo window, and keep SSH root login disabled."""
        elif {"syscheck", "fim"} & groups or "file" in desc or "shadow" in desc:
            path = _as_dict(raw.get("syscheck", {})).get("path", "the monitored file")
            path_arg = shlex.quote(path)
            explanation = (
                f"Wazuh detected a file integrity event on {path} for {agent}. Changes to "
                "sensitive files can indicate persistence, credential tampering, or post-exploitation activity."
            )
            impact = (
                "Unauthorized modification of system files can weaken authentication controls, "
                "hide attacker activity, or create a persistence path."
            )
            remediation = f"""```bash
sudo stat {path_arg}
sudo ausearch -f {path_arg} | tail -50
sudo debsums -s 2>/dev/null || true
sudo restorecon -Rv {path_arg} 2>/dev/null || true
```
Validate the change owner, compare against a known-good baseline, and rotate affected credentials if needed."""
        elif {"web", "attack", "sql_injection"} & groups or "sql" in desc:
            explanation = (
                f"Wazuh detected a possible web application attack on {agent}, consistent with SQL injection "
                "or malicious HTTP probing. This maps to MITRE ATT&CK T1190 (Exploit Public-Facing Application)."
            )
            impact = (
                "Successful exploitation could expose database records, bypass authentication, "
                "or provide a foothold for further compromise."
            )
            remediation = f"""```bash
sudo grep -F {src_arg} /var/log/apache2/access.log | tail -50
sudo grep -F {src_arg} /var/log/nginx/access.log | tail -50
sudo ufw deny from {src_arg}
```
Confirm the requested URL, check application logs, and validate input filtering or WAF rules."""
        elif {"windows", "defender", "malware"} & groups or "malware" in desc or "trojan" in desc:
            explanation = (
                f"Wazuh detected a Windows malware-related alert for {agent}. Treat this as a potential "
                "endpoint compromise until Defender and process telemetry prove otherwise."
            )
            impact = (
                "Malware can steal credentials, establish persistence, disable defenses, and move laterally "
                "to other systems."
            )
            remediation = """```powershell
Get-MpThreat
Start-MpScan -ScanType FullScan
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
```
Isolate the endpoint if malicious activity is confirmed and preserve logs for investigation."""
        else:
            explanation = (
                f"Wazuh generated a level {alert.level} alert for rule {rule_id}: {alert.ruleDesc}. "
                f"The event came from {agent} ({agent_ip}) with source IP {src}."
            )
            impact = (
                "Because the alert crossed the configured severity threshold, it may represent active "
                "attack activity, policy violation, or a host requiring immediate analyst review."
            )
            remediation = f"""```bash
sudo tail -100 /var/ossec/logs/alerts/alerts.json
sudo grep -F {rule_arg} /var/ossec/logs/alerts/alerts.json | tail -20
```
Correlate the event with host logs, source IP reputation, and recent authentication or process activity."""

        remediation = f"{remediation}\n\nFallback note: {error_note}"
        return EnrichedAlert(
            originalAlert = alert,
            explanation   = explanation,
            impact        = impact,
            remediation   = remediation,
        )

    async def async_enrich_alert(self, alert: Alert) -> EnrichedAlert:
        """
        Async wrapper around enrich_alert.
        Runs the blocking HTTP call in a thread pool so the event loop
        stays free, and uses a semaphore to cap concurrent Ollama calls.
        """
        async with self._get_semaphore():
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self._executor, self.enrich_alert, alert)

    async def async_enrich_batch(self, alerts: list) -> list:
        """
        Enrich a list of alerts concurrently.
        All alerts are submitted at once; the semaphore keeps Ollama from
        being hammered with more than max_concurrent_calls at a time.
        """
        log.info(f"Batch enrichment: {len(alerts)} alerts "
                 f"(max {self._max_concurrent} concurrent Ollama calls)")
        tasks   = [self.async_enrich_alert(a) for a in alerts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched = []
        for alert, result in zip(alerts, results):
            if isinstance(result, Exception):
                log.error(f"Batch item failed for {alert.alertId[:8]}: {result}")
                enriched.append(EnrichedAlert(
                    originalAlert = alert,
                    explanation   = f"Batch processing error: {result}",
                    impact        = "Unknown — batch error.",
                    remediation   = "Manual investigation required.",
                ))
            else:
                enriched.append(result)
        return enriched
