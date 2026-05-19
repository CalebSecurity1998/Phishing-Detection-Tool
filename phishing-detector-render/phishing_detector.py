from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\]\[\)\(\"']+)")
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")

URGENCY_TERMS = {
    "urgent", "immediately", "action required", "verify now", "suspended",
    "limited time", "final notice", "account locked", "unusual activity",
    "expires today", "within 24 hours", "security alert"
}

CREDENTIAL_TERMS = {
    "password", "passcode", "login", "sign in", "sign-in", "verify your account",
    "confirm your identity", "security code", "mfa", "multi-factor",
    "two-factor", "2fa", "otp", "one-time password", "reset your password"
}

PAYMENT_TERMS = {
    "invoice", "payment", "wire transfer", "gift card", "bank account",
    "routing number", "crypto", "bitcoin", "refund", "tax payment"
}

THREAT_TERMS = {
    "penalty", "legal action", "closed permanently", "terminated", "arrest",
    "lose access", "late fee", "collections"
}

GENERIC_GREETINGS = {
    "dear customer", "dear user", "hello user", "valued customer",
    "account holder", "dear client"
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs",
    ".vbe", ".ps1", ".jar", ".msi", ".hta", ".iso", ".img", ".lnk"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

SUSPICIOUS_URL_TERMS = {
    "login", "verify", "secure", "account", "update", "confirm", "billing",
    "password", "support", "recovery", "unlock", "signin", "webscr", "auth"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at"
}


@dataclass
class Finding:
    category: str
    rule: str
    points: int
    detail: str


@dataclass
class DetectionResult:
    score: int
    risk_level: str
    verdict: str
    findings: List[Finding]
    urls: List[str]

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def extract_urls(text: str) -> List[str]:
    urls: List[str] = []
    for match in URL_PATTERN.findall(text or ""):
        candidate = match.rstrip(".,;:!?")
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        urls.append(candidate)
    return urls


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.lower().strip(".")


def looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def count_subdomains(host: str) -> int:
    parts = [p for p in host.split(".") if p]
    return max(0, len(parts) - 2)


def extension_from_name(name: str) -> str:
    lowered = name.lower().strip()
    for ext in sorted(EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS, key=len, reverse=True):
        if lowered.endswith(ext):
            return ext
    return ""


def repeated_punctuation(text: str) -> bool:
    return bool(re.search(r"[!?]{2,}", text))


def excessive_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    uppercase = [c for c in letters if c.isupper()]
    return len(uppercase) / len(letters)


def basic_typo_signal(text: str) -> bool:
    patterns = [
        r"\bkindly\s+verify\b",
        r"\bclick\s+below\s+link\b",
        r"\bwe\s+notice\s+unusual\b",
        r"\bdear\s+costumer\b",
        r"\brecieve\b",
        r"\bnotif(?:y|ication)\s+you\s+that\b",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def analyze_url(url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    host = extract_domain(url)
    path_query = f"{parsed.path}?{parsed.query}".lower()
    full_lower = url.lower()

    if parsed.scheme.lower() == "http":
        findings.append(Finding("website", "unencrypted_http", 8, f"URL uses HTTP rather than HTTPS: {url}"))

    if looks_like_ip(host):
        findings.append(Finding("website", "ip_address_host", 22, f"URL host is a raw IP address: {host}"))

    if "@" in full_lower:
        findings.append(Finding("website", "at_symbol_in_url", 18, "URL contains '@', which can obscure the real destination."))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(Finding("website", "punycode_domain", 15, f"Domain uses punycode: {host}"))

    if count_subdomains(host) >= 3:
        findings.append(Finding("website", "many_subdomains", 10, f"Domain contains many subdomain levels: {host}"))

    if host in URL_SHORTENERS:
        findings.append(Finding("website", "url_shortener", 10, f"URL uses a shortening service: {host}"))

    if any(term in path_query for term in SUSPICIOUS_URL_TERMS):
        findings.append(Finding("website", "credential_or_account_terms_in_url", 8, "URL path/query contains account, login, or verification-style wording."))

    if host.count("-") >= 2:
        findings.append(Finding("website", "multiple_hyphens_in_domain", 6, f"Domain contains multiple hyphens: {host}"))

    if len(url) >= 120:
        findings.append(Finding("website", "very_long_url", 8, "URL is unusually long."))

    if re.search(r"(?:%[0-9a-f]{2}){3,}", full_lower):
        findings.append(Finding("website", "heavy_url_encoding", 8, "URL contains repeated percent-encoding, which can hide intent."))

    return findings


def analyze_email(
    text: str,
    subject: str = "",
    sender: str = "",
    attachments: Optional[Iterable[str]] = None,
) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    attachments = list(attachments or [])
    all_text = f"{subject}\n{text}"
    normalized = normalize_text(all_text)
    urls = extract_urls(all_text)

    if any(term in normalized for term in URGENCY_TERMS):
        findings.append(Finding("email", "urgency_language", 14, "Message uses urgent or time-pressure language."))

    if any(term in normalized for term in CREDENTIAL_TERMS):
        findings.append(Finding("email", "credential_request_language", 16, "Message references credentials, sign-in, verification, or access recovery."))

    if any(term in normalized for term in PAYMENT_TERMS):
        findings.append(Finding("email", "payment_or_financial_language", 10, "Message references payment, banking, invoices, refunds, or transfers."))

    if any(term in normalized for term in THREAT_TERMS):
        findings.append(Finding("email", "threatening_language", 12, "Message uses threatening or punitive language."))

    if any(greeting in normalized for greeting in GENERIC_GREETINGS):
        findings.append(Finding("email", "generic_greeting", 6, "Message uses a generic greeting rather than a personalized one."))

    if repeated_punctuation(all_text):
        findings.append(Finding("email", "repeated_punctuation", 4, "Message contains repeated urgency punctuation such as '!!' or '??'."))

    caps_ratio = excessive_caps_ratio(all_text)
    if caps_ratio >= 0.35 and len(all_text) >= 40:
        findings.append(Finding("email", "excessive_capitalization", 6, f"Message has a high uppercase-letter ratio ({caps_ratio:.0%})."))

    if basic_typo_signal(all_text):
        findings.append(Finding("email", "visible_language_irregularity", 6, "Message contains conspicuous wording or typo patterns often seen in scams."))

    if EMAIL_PATTERN.search(text or "") and any(term in normalized for term in CREDENTIAL_TERMS):
        findings.append(Finding("email", "credential_prompt_with_contact_details", 4, "Message combines credential-style language with contact/email references."))

    if sender:
        sender_lower = sender.lower().strip()
        if re.search(r"\b(no[-_]?reply|support|security|billing|admin)\b", sender_lower):
            findings.append(Finding("email", "role_based_sender", 4, f"Sender uses a role-based identity: {sender}"))

    for attachment in attachments:
        ext = extension_from_name(attachment)
        if ext in EXECUTABLE_EXTENSIONS:
            findings.append(Finding("email", "dangerous_attachment_type", 24, f"Attachment has a high-risk executable/script type: {attachment}"))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding("email", "archive_attachment", 8, f"Attachment is an archive that may conceal contents: {attachment}"))

    if urls:
        findings.append(Finding("email", "contains_links", 3, f"Message contains {len(urls)} link(s)."))

    for url in urls:
        findings.extend(analyze_url(url))

    rules_present = {finding.rule for finding in findings}

    if "urgency_language" in rules_present and "credential_request_language" in rules_present:
        findings.append(Finding("compound", "urgent_credential_request", 14, "Urgency combined with a request related to credentials or account access is high risk."))

    if "payment_or_financial_language" in rules_present and "urgency_language" in rules_present:
        findings.append(Finding("compound", "urgent_financial_request", 12, "Urgent payment or financial language raises the likelihood of social engineering."))

    if "credential_request_language" in rules_present and urls:
        findings.append(Finding("compound", "credential_request_with_link", 12, "A credential-related message includes a link, which is a common phishing pattern."))

    return findings, urls


def classify_score(score: int) -> Tuple[str, str]:
    if score >= 70:
        return "High", "Likely phishing or highly suspicious. Do not click links or open attachments."
    if score >= 40:
        return "Medium", "Suspicious. Verify through a trusted, separate channel before acting."
    if score >= 20:
        return "Low", "Some suspicious indicators are present. Review carefully."
    return "Minimal", "Few phishing indicators were detected by this heuristic model."


def detect_phishing(
    text: str = "",
    subject: str = "",
    sender: str = "",
    attachments: Optional[Iterable[str]] = None,
    url: str = "",
) -> DetectionResult:
    findings: List[Finding] = []
    urls: List[str] = []

    if any([text, subject, sender, attachments]):
        email_findings, email_urls = analyze_email(text, subject, sender, attachments)
        findings.extend(email_findings)
        urls.extend(email_urls)

    if url:
        urls.append(url)
        findings.extend(analyze_url(url))

    urls = list(dict.fromkeys(urls))
    score = min(sum(item.points for item in findings), 100)
    risk_level, verdict = classify_score(score)

    return DetectionResult(
        score=score,
        risk_level=risk_level,
        verdict=verdict,
        findings=sorted(findings, key=lambda item: item.points, reverse=True),
        urls=urls,
    )
