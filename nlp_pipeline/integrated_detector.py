"""
Integrated Social Engineering Detector — v6.0.
Output contains ONLY the 7 required keys.
Weights: 0.6 RAG + 0.4 Rules. Risk: SAFE/LOW/POTENTIAL/HIGH.
"""

import re
import random
from typing import Dict, List, Tuple

try:
    from .rag_detector import get_detector
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nlp_pipeline.rag_detector import get_detector

# Import URL Knowledge Base
try:
    from security_logic.url_knowledge_base import (
        is_trusted, analyze_url_kb
    )
    from security_logic.multilingual_map import normalize_text, normalize_obfuscation
except ImportError:
    from ..security_logic.url_knowledge_base import (
        is_trusted, analyze_url_kb
    )
    from ..security_logic.multilingual_map import normalize_text, normalize_obfuscation


# ---------------------------
# URL ANALYSIS (F1: Multi-Modal)
# ---------------------------

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+)", text)


def analyze_url(url: str) -> Tuple[float, List[str]]:
    """Analyze a URL using Knowledge Base patterns."""
    return analyze_url_kb(url)


def is_trusted_url(url: str) -> bool:
    """Check if URL belongs to a trusted domain."""
    return is_trusted(url)


# ---------------------------
# F3: Cross-Field Consistency Engine
# ---------------------------

# Static brand list (no external deps)
KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "chase", "wells fargo", "bank of america", "citibank", "hsbc",
    "ups", "fedex", "dhl", "usps", "dropbox", "spotify", "zoom"
]


def extract_brands(text: str) -> set:
    """Extract known brand mentions from text (case-insensitive)."""
    text_lower = text.lower()
    return {brand for brand in KNOWN_BRANDS if brand in text_lower}


def extract_domain_from_url(url: str) -> str:
    """Extract base domain from URL (strips subdomains)."""
    url_lower = url.lower()
    # Remove protocol
    if "://" in url_lower:
        url_lower = url_lower.split("://", 1)[1]
    # Remove path
    url_lower = url_lower.split("/")[0]
    # Remove port
    url_lower = url_lower.split(":")[0]
    # Get base domain (last 2 parts for most TLDs)
    parts = url_lower.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return url_lower


def analyze_consistency(original_msg: str, normalized_msg: str, context: dict, sender: str = None) -> dict:
    """
    F3: Cross-Field Consistency Engine.
    Detects inconsistencies between text brands, URL domains, and sender.
    """
    inconsistency_score = 0
    evidence = []
    
    # Extract brands from both original and normalized text
    brands_original = extract_brands(original_msg)
    brands_normalized = extract_brands(normalized_msg)
    detected_brands = brands_original | brands_normalized
    
    # Get URL info from F1 context
    url_info = context.get("url", {})
    urls = url_info.get("urls", [])
    is_malicious = url_info.get("malicious", False)
    is_trusted = url_info.get("trusted", False)
    
    # Extract domain from first URL if present
    domain = ""
    if urls:
        domain = extract_domain_from_url(urls[0])
    
    # Case A: Brand-domain mismatch
    if detected_brands and urls and domain:
        brand_in_domain = any(brand in domain for brand in detected_brands)
        if not brand_in_domain and not is_trusted:
            inconsistency_score += 1
            evidence.append(f"brand-domain mismatch: {list(detected_brands)} vs {domain}")
    
    # Case B: Trusted brand + malicious URL (high severity)
    if detected_brands and is_malicious:
        inconsistency_score += 2
        evidence.append(f"trusted brand {list(detected_brands)} with malicious URL")
    
    # Case C: Sender mismatch (if sender available)
    if sender and detected_brands:
        sender_lower = sender.lower()
        sender_domain = sender_lower.split("@")[-1] if "@" in sender_lower else sender_lower
        brand_in_sender = any(brand in sender_domain for brand in detected_brands)
        if not brand_in_sender:
            inconsistency_score += 1
            evidence.append(f"sender-brand mismatch: {sender_domain} vs {list(detected_brands)}")
    
    return {
        "score": inconsistency_score,
        "signals": evidence,
        "brands_detected": list(detected_brands),
        "domain": domain,
        "normalized_signal": min(inconsistency_score / 2, 1.0),  # 0-1 scale
    }


# ---------------------------
# F2: Attack Type + Domain Classification
# ---------------------------

def classify_attack(context: dict) -> str:
    """Classify attack type based on unified context (text, signals, URL, email)."""
    # Use normalized text for multilingual keyword detection
    text_info = context["text"]
    if isinstance(text_info, dict):
        text = text_info.get("normalized", text_info.get("original", "")).lower()
    else:
        text = text_info.lower()
    
    url = context["url"]
    email = context.get("email", {})
    sig = context["signals"]
    consistency = context.get("consistency", {})
    
    # F3: High inconsistency biases toward credential harvesting
    if consistency.get("score", 0) >= 2:
        if consistency.get("brands_detected"):
            return "Credential Harvesting"
    
    # URL-driven classification (F1 → F2)
    if url.get("malicious"):
        if any(k in text for k in ["verify", "login", "account", "password"]):
            return "Credential Harvesting"
        return "Link-Based Phishing"
    
    if url.get("suspicious"):
        return "Suspicious Link Activity"
    
    # Email spoofing detection
    if email.get("score", 0) > 0.6:
        return "Email Spoofing"
    
    # OTP/code scam detection (high priority)
    if sig.get("otp_scam"):
        return "OTP Theft Scam"
    
    # Romance/advance fee scam detection
    if sig.get("romance_scam"):
        return "Romance / Advance Fee Scam"
    
    # OTP patterns in text (fallback)
    otp_patterns = ["send me the code", "forward the code", "share the code", 
                    "send the otp", "send your code", "reply with the code",
                    "verification code", "6-digit code", "6 digit code"]
    if any(p in text for p in otp_patterns):
        return "OTP Theft Scam"
    
    # Text-driven classification
    if any(k in text for k in ["verify", "login", "password", "account"]):
        return "Credential Harvesting"
    
    if any(k in text for k in ["won", "reward", "bonus", "cash", "prize", "winner"]):
        return "Reward Scam"
    
    if any(k in text for k in ["otp", "code", "verification code"]):
        return "OTP Scam"
    
    if any(k in text for k in ["job", "hiring", "salary", "work from home", "employment"]):
        return "Job Scam"
    
    if any(k in text for k in ["investment", "crypto", "bitcoin", "returns", "profit"]):
        return "Investment Scam"
    
    if sig.get("fear"):
        return "Threat-Based Scam"
    
    if sig.get("authority") or sig.get("identity"):
        return "Impersonation Attack"
    
    return "Generic Social Engineering"


def classify_domain(context: dict) -> str:
    """Classify target domain/sector based on unified context."""
    # Use normalized text for multilingual keyword detection
    text_info = context["text"]
    if isinstance(text_info, dict):
        text = text_info.get("normalized", text_info.get("original", "")).lower()
    else:
        text = text_info.lower()
    
    url = context["url"]
    email = context.get("email", {})
    consistency = context.get("consistency", {})
    
    # F3: High inconsistency with brands → Phishing Infrastructure
    if consistency.get("score", 0) >= 2 and consistency.get("brands_detected"):
        return "Phishing Infrastructure"
    
    # URL-driven domain (F1 → F2)
    if url.get("malicious"):
        return "Phishing Infrastructure"
    
    # Email spoofing domain
    if email.get("score", 0) > 0.6:
        return "Email Infrastructure"
    
    # Text-driven domain classification
    if any(k in text for k in ["bank", "card", "payment", "transaction", "wire", "transfer"]):
        return "Banking / Financial"
    
    if any(k in text for k in ["account", "login", "password", "credentials"]):
        return "Account Security"
    
    if any(k in text for k in ["job", "offer", "hr", "recruitment", "hiring"]):
        return "Employment"
    
    if any(k in text for k in ["delivery", "package", "courier", "shipment", "tracking"]):
        return "Logistics"
    
    if any(k in text for k in ["tax", "irs", "government", "stimulus"]):
        return "Government Services"
    
    if any(k in text for k in ["apple", "microsoft", "google", "amazon", "paypal"]):
        return "Tech / E-Commerce"
    
    return "General"


# ---------------------------


DISPLAY_TO_INTERNAL_CATEGORY = {
    "Fear/Threat": "fear_threat",
    "Impersonation": "impersonation",
    "Authority": "authority",
    "Urgency": "urgency",
    "Reward/Lure": "reward_lure",
}


CATEGORY_GOALS = {
    "fear_threat": "create panic and force immediate compliance",
    "impersonation": "impersonate trusted services and steal credentials",
    "authority": "abuse hierarchy pressure to bypass verification",
    "urgency": "rush the victim before they can verify",
    "reward_lure": "bait the victim with rewards to collect sensitive data",
    "legitimate_but_tricky": "appear legitimate while nudging risky actions",
    "normal_communication": "maintain normal communication context",
}


ADVICE_MAP = {
    "urgency": {
        "dos": [
            "Pause and verify the request through an official channel.",
            "Check sender domain and reply-to mismatch before acting.",
            "Confirm deadlines in your official account portal.",
            "Escalate suspicious urgent requests to security or IT.",
            "Use bookmarked websites instead of message links.",
            "Validate account status in-app, not from SMS links.",
            "Ask for a second person approval on urgent financial requests.",
            "Capture evidence (screenshot, sender, timestamp) for reporting.",
            "Enable MFA and login alerts for critical accounts.",
            "Treat countdown language as a risk indicator.",
        ],
        "donts": [
            "Do not click urgent links directly from messages.",
            "Do not share OTPs under any time pressure.",
            "Do not bypass normal approval workflows.",
            "Do not trust urgency claims without independent verification.",
            "Do not call phone numbers embedded in suspicious texts.",
            "Do not send credentials by email or chat.",
            "Do not install software because of panic warnings.",
            "Do not process payments based only on urgency language.",
            "Do not ignore subtle red flags like spelling/domain anomalies.",
            "Do not continue conversation if identity is uncertain.",
        ],
    },
    "reward_lure": {
        "dos": [
            "Verify offers only on official websites or apps.",
            "Check if you actually participated in the promotion.",
            "Inspect sender identity and domain authenticity.",
            "Report fake giveaways to your security team.",
            "Use anti-phishing reporting tools in your mail client.",
            "Treat ""processing fee"" requests as high risk.",
            "Confirm cashback and rewards from your account dashboard.",
            "Review transaction history before sharing payment details.",
            "Search for known scam wording before responding.",
            "Block repeat senders after reporting.",
        ],
        "donts": [
            "Do not pay fees to claim prizes.",
            "Do not submit banking data for unverified rewards.",
            "Do not trust random draw claims without evidence.",
            "Do not share full card details for cashback offers.",
            "Do not download attachments for lottery claims.",
            "Do not provide personal identity documents to claim gifts.",
            "Do not use links from unknown promotional messages.",
            "Do not disclose account credentials for voucher redemption.",
            "Do not assume urgency means legitimacy.",
            "Do not continue if the sender asks secrecy.",
        ],
    },
    "authority": {
        "dos": [
            "Verify executive requests via a known internal channel.",
            "Require callback verification for payment instructions.",
            "Follow maker-checker policy for financial actions.",
            "Confirm role identity in official directory.",
            "Ask for ticket/reference numbers for urgent admin asks.",
            "Flag secrecy instructions to security immediately.",
            "Use least-privilege and avoid credential sharing.",
            "Document and escalate unusual authority pressure.",
            "Validate vendor account changes with dual confirmation.",
            "Cross-check with your manager before exceptions.",
        ],
        "donts": [
            "Do not transfer funds only from chat/email instructions.",
            "Do not share admin credentials with anyone.",
            "Do not purchase gift cards on executive demand alone.",
            "Do not skip approval chains due to pressure.",
            "Do not treat display names as proof of identity.",
            "Do not send payroll or HR data without authorization.",
            "Do not keep suspicious requests confidential.",
            "Do not approve access changes without ticket validation.",
            "Do not trust claims of meetings as urgency proof.",
            "Do not execute high-risk actions without verification.",
        ],
    },
    "impersonation": {
        "dos": [
            "Open services directly from your saved bookmarks.",
            "Check domain spelling and certificate validity.",
            "Confirm alerts in official app security sections.",
            "Use password manager autofill to detect fake sites.",
            "Report impersonation attempts with full headers.",
            "Enable phishing-resistant MFA where possible.",
            "Contact bank/support using known public numbers.",
            "Inspect message language for copycat branding mistakes.",
            "Verify account issues from account dashboard only.",
            "Reset passwords from official settings if needed.",
        ],
        "donts": [
            "Do not enter credentials on linked login pages.",
            "Do not share OTPs with callers claiming support.",
            "Do not trust brand logos as authenticity proof.",
            "Do not install remote tools from support messages.",
            "Do not respond to DMs asking account verification.",
            "Do not send card details to restore service.",
            "Do not scan unknown QR codes for account recovery.",
            "Do not use callback numbers provided in suspicious alerts.",
            "Do not assume typo-free text means legitimate.",
            "Do not disclose recovery codes to any agent.",
        ],
    },
    "fear_threat": {
        "dos": [
            "Stay calm and verify legal/security claims independently.",
            "Contact official authorities through known public numbers.",
            "Preserve message evidence for incident reporting.",
            "Notify IT/security immediately if account compromise is claimed.",
            "Change passwords from official portals if exposed.",
            "Run endpoint scans with trusted security tools.",
            "Check account lock status in official systems only.",
            "Consult legal/compliance team for legal notices.",
            "Enable transaction and login alerts immediately.",
            "Report extortion-style messages to cybercrime portals.",
        ],
        "donts": [
            "Do not pay ransom, penalties, or crypto demands.",
            "Do not share personal documents under intimidation.",
            "Do not call numbers from threatening messages.",
            "Do not install unknown ""security patches"" from alerts.",
            "Do not reveal passwords to ""investigation"" contacts.",
            "Do not comply with secrecy instructions.",
            "Do not forward threatening links to colleagues.",
            "Do not provide remote access to unknown callers.",
            "Do not trust threats without formal verifiable notice.",
            "Do not ignore potential compromise after interaction.",
        ],
    },
}


def extract_rule_signals(text: str) -> Dict:
    msg = text.lower()

    urgency_keywords = [
        "urgent", "immediately", "action required", "right now", "final warning",
        "last chance", "expires", "within", "minutes", "hours",
    ]
    authority_keywords = [
        "bank", "irs", "income tax", "admin", "ceo", "cfo", "director",
        "manager", "support", "it department", "police", "court",
    ]
    sensitive_keywords = [
        "otp", "password", "pin", "cvv", "verify account", "verify your identity",
        "credentials", "login", "card details", "bank details", "ssn",
    ]

    found_urgency = [kw for kw in urgency_keywords if kw in msg]
    found_authority = [kw for kw in authority_keywords if kw in msg]
    found_sensitive = [kw for kw in sensitive_keywords if kw in msg]

    return {
        "urgency": found_urgency,
        "authority": found_authority,
        "sensitive": found_sensitive,
        "triggered_groups": [
            name
            for name, vals in {
                "urgency": found_urgency,
                "authority": found_authority,
                "sensitive_request": found_sensitive,
            }.items()
            if vals
        ],
    }


def extract_pattern_features(text: str) -> Dict:
    msg = text.lower()
    urls = re.findall(r"https?://\S+|www\.\S+", text, flags=re.IGNORECASE)
    numbers = re.findall(r"\b\d{4,8}\b", text)
    otp_like = [n for n in numbers if len(n) in (4, 6)]

    financial_terms_all = [
        "bank", "wire", "transfer", "refund", "payment", "invoice", "card",
        "wallet", "bitcoin", "cashback", "prize", "bonus", "tax",
    ]
    login_terms_all = [
        "login", "password", "verify", "confirm", "otp", "credential", "account",
        "security", "reset", "mfa",
    ]

    financial_terms = [kw for kw in financial_terms_all if kw in msg]
    login_terms = [kw for kw in login_terms_all if kw in msg]

    return {
        "urls": urls,
        "otp_like_numbers": otp_like,
        "financial_terms": financial_terms,
        "login_verification_terms": login_terms,
    }


def get_similar_patterns(top_k_results: List[Dict]) -> List[Dict]:
    if not top_k_results:
        return []

    filtered = sorted(
        [r for r in top_k_results if r.get("label") == "social_engineering"],
        key=lambda x: x.get("similarity", 0.0),
        reverse=True,
    )

    selected: List[Dict] = []
    for row in filtered:
        text = row.get("text", "").strip()
        if not text:
            continue

        norm = text.lower()
        cand_tokens = set(re.findall(r"[a-z0-9]+", norm))
        duplicate = False

        for chosen in selected:
            chosen_tokens = set(re.findall(r"[a-z0-9]+", chosen["text"].lower()))
            if not cand_tokens or not chosen_tokens:
                continue
            jacc = len(cand_tokens & chosen_tokens) / max(1, len(cand_tokens | chosen_tokens))
            if jacc >= 0.82:
                duplicate = True
                break

        if duplicate:
            continue

        selected.append(
            {
                "text": text,
                "category": row.get("category", "unknown"),
                "similarity": round(float(row.get("similarity", 0.0)) * 100, 2),
            }
        )

        if len(selected) == 3:
            break

    return selected


def get_advice(category: str) -> Dict:
    key = category if category in ADVICE_MAP else "fear_threat"
    pool = ADVICE_MAP[key]

    do_count = min(len(pool["dos"]), random.randint(3, 4))
    dont_count = min(len(pool["donts"]), random.randint(3, 4))

    return {
        "dos": random.sample(pool["dos"], do_count),
        "donts": random.sample(pool["donts"], dont_count),
    }


def generate_explanation(
    text: str,
    category: str,
    top_k_results: List[Dict],
    rule_signals: Dict,
) -> List[str]:
    pattern_features = extract_pattern_features(text)
    points: List[str] = []

    signal_parts = []
    if rule_signals.get("urgency"):
        signal_parts.append(f"urgency terms: {', '.join(rule_signals['urgency'][:3])}")
    if rule_signals.get("authority"):
        signal_parts.append(f"authority markers: {', '.join(rule_signals['authority'][:3])}")
    if rule_signals.get("sensitive"):
        signal_parts.append(f"sensitive requests: {', '.join(rule_signals['sensitive'][:3])}")
    if signal_parts:
        points.append("Rule-based indicators detected: " + " | ".join(signal_parts))

    if pattern_features["urls"]:
        points.append(f"Pattern features: {len(pattern_features['urls'])} URL(s) found in the message.")
    if pattern_features["otp_like_numbers"]:
        points.append(
            "Pattern features: OTP-like number(s) detected: "
            + ", ".join(pattern_features["otp_like_numbers"][:3])
        )
    if pattern_features["financial_terms"]:
        points.append(
            "Pattern features: financial terms present: "
            + ", ".join(pattern_features["financial_terms"][:4])
        )

    similar = get_similar_patterns(top_k_results)
    if similar:
        top_sim = similar[0]
        dominant = max(
            {r["category"]: sum(1 for x in similar if x["category"] == r["category"]) for r in similar},
            key=lambda c: sum(1 for x in similar if x["category"] == c),
        )
        points.append(
            f"RAG similarity: top match is {top_sim['similarity']:.2f}% similar to known {top_sim['category']} attack patterns."
        )
        points.append(f"RAG category signal: dominant retrieved category is {dominant}.")

    goal = CATEGORY_GOALS.get(category, "manipulate the recipient into unsafe action")
    points.append(f"Likely attacker objective for this pattern: {goal}.")

    return points


class IntegratedSocialEngineeringDetector:

    FEAR_KW = [
        "legal action", "court", "police", "fir", "arrest",
        "investigation", "permanently closed", "terminated",
        "account frozen", "frozen account", "service termination",
        "aadhaar", "pan blocked", "pan card", "sim deactivated",
        "bank account frozen", "money laundering", "prosecution",
        "seized", "non-bailable", "blacklisted", "cyber cell",
        "suspended", "hacked", "compromised", "ransomware",
        "encrypted", "dark web", "webcam", "leaked", "breach",
        "income tax", "deactivated", "permanently", "frozen",
        "action will be taken", "credentials", "share info","card blocked", "payment failed", "transaction declined"

    ]

    DEADLINE_KW = [
        "immediately", "within 24 hours", "within 48 hours",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "in 10 minutes", "in 30 minutes",
        "30 minutes", "last warning", "last chance", "expires",
    ]

    GOV_KW = [
        "income tax", "aadhaar", "court", "police", "fir",
        "prosecution", "arrest", "non-bailable", "cyber cell",
        "irs", "tax department", "income tax department",
    ]

    _IDENTITY_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bthis is\b", r"\bi am\b", r"\bi'm\b", r"\bwe are\b",
            r"\bfrom it department\b", r"\bfrom it\b",
            r"\bcustomer support\b", r"\bbank team\b",
            r"\bsupport team\b", r"\bhelp\s?desk\b",
            r"\btechnical support\b", r"\btech support\b",
            r"\bamazon support\b", r"\bamazon customer support\b",
        ]
    ]

    BRAND_KW = [
        "netflix", "amazon", "paypal", "apple", "microsoft",
        "google", "instagram", "linkedin", "dropbox", "spotify",
        "fedex", "irs", "income tax department",
    ]

    AUTHORITY_KW = [
        "ceo", "cfo", "cto", "manager", "director", "supervisor",
        "president", "chairman", "head of", "department head",
        "team lead", "executive", "boss", "vp of",
    ]

    _SENSITIVE_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bpassword\b", r"\bcredential", r"\blogin\b",
            r"\bcard detail", r"\bbank detail", r"\bfinancial detail",
            r"\bsubmit financial\b", r"\bssn\b", r"\bsocial security\b",
            r"\botp\b", r"\bpin\b", r"\bcvv\b", r"\baccount number\b",
            r"\brouting number\b", r"\bshare your\b", r"\bsend your\b",
            r"\bprovide your\b", r"\bsubmit your\b",
            r"\bconfirm your card\b", r"\bconfirm card\b",
            r"\blogin credential", r"\bverify your identity\b",r"\bconfirm your card details\b"
            r"\bconfirm your banking\b",r"\bconfirm your payment\b",r"\bverify card\b"

        ]
    ]

    REWARD_KW = [
        "won", "winner", "prize", "reward", "free", "gift",
        "discount", "cashback", "lottery", "selected", "chosen",
        "bonus", "90%",
        # Scam-specific patterns
        "guaranteed returns", "guaranteed profit", "500%", "1000%",
        "work from home", "no experience needed", "no experience required",
        "earn $", "make $", "secret strategy", "secret method",
        "bitcoin investment", "crypto investment", "stimulus payment",
        "pre-approved", "bad credit ok", "randomly selected",
        "prince", "transfer million", "receive 30%", "receive 20%",
    ]

    # Scam indicator patterns (regex) for stronger detection
    _SCAM_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\b(?:earn|make)\s+\$\d+",
            r"\bguaranteed\s+\d+%?\s+returns?\b",
            r"\bwork(?:ing)?\s+from\s+home\b",
            r"\bno\s+experience\s+(?:needed|required)\b",
            r"\bsecret\s+(?:strategy|method|system)\b",
            r"\b(?:bitcoin|crypto)\s+(?:investment|opportunity)\b",
            r"\bgovernment\s+(?:stimulus|grant|payment)\b",
            r"\bpre[\s-]?approved\s+for\s+\$",
            r"\brandomly\s+selected\b",
            r"\btransfer(?:ring)?\s+.*\bmillion\b",
            r"\breceive\s+\d+%\b",
            r"\bprince\b.*\b(?:help|transfer|million)\b",
        ]
    ]

    # OTP/Code theft scam patterns
    _OTP_SCAM_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\b(?:send|forward|share|give)\s+(?:me\s+)?(?:the\s+)?(?:otp|code|pin)\b",
            r"\b(?:verification|security)\s+code\b.*\b(?:send|reply|forward)\b",
            r"\breply\s+with\s+(?:the\s+)?code\b",
            r"\bforward\s+(?:me\s+)?(?:the\s+)?\d[\s-]?digit\s+code\b",
            r"\b(?:accidentally|mistakenly)\s+sent\s+(?:my\s+)?code\b",
            r"\bcode\s+(?:to|for)\s+(?:your|this)\s+number\b",
            r"\bneed(?:ed)?\s+(?:for\s+)?(?:security\s+)?audit\b",
            r"\bsend\s+it\s+now\b",
            r"\bverification\s+code\s+is\s+needed\b",
        ]
    ]

    # Romance/advance fee scam patterns
    _ROMANCE_SCAM_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bhospital\s+bills?\b",
            r"\bsend\s+(?:me\s+)?crypto\b",
            r"\bwire\s+(?:me\s+)?money\b",
            r"\bwestern\s+union\b",
            r"\bhelp\s+(?:me\s+)?with\s+(?:my\s+)?bills?\b",
            r"\bstuck\s+(?:in\s+)?(?:a\s+)?(?:foreign\s+)?country\b",
            r"\bwe\'?ve\s+been\s+chatting\b",
            r"\bcan\s+you\s+help\s+me\s+(?:with|pay)\b",
        ]
    ]

    def __init__(self):
        self.rag = get_detector()

        self._whitelist_rx = [
            re.compile(p, re.IGNORECASE) for p in [
                r"(ceo|director|manager|president|executive)\s+"
                r"(announced|said|reported|mentioned|shared|presented)",
                r"scheduled\s+(meeting|maintenance)",
                r"product\s+launch", r"press\s+release",
                r"no\s+action\s+(required|needed|is needed)",
                r"confirm\s+(your\s+)?(appointment|meeting|booking|reservation)",
                r"verify\s+(your\s+)?email\s+(address\s+)?to\s+complete",
                # Expanded benign patterns
                r"transaction\s+(completed|successful|processed)",
                r"payment\s+(received|confirmed|processed)",
                r"order\s+(confirmed|shipped|delivered|dispatched)",
                r"delivery\s+(scheduled|completed|on the way)",
                r"appointment\s+(confirmed|scheduled|booked)",
                r"your\s+request\s+has\s+been\s+processed",
                r"thank\s+you\s+for\s+your\s+payment",
                r"invoice\s+(generated|available|attached)",
                r"subscription\s+(renewed|activated)",
                r"your\s+package\s+(has\s+been\s+)?(shipped|delivered)",
                r"receipt\s+for\s+your\s+(recent\s+)?purchase",
                r"your\s+(monthly|weekly)\s+statement",
                r"here\s+are\s+the\s+meeting\s+notes",
                r"password\s+(was\s+)?successfully\s+changed",
                r"password\s+changed\s+successfully",
                r"direct\s+deposit\s+has\s+been\s+processed",
                r"your\s+(test\s+)?results\s+are\s+available",
                # Additional benign patterns for false positive control
                r"happy\s+birthday",
                r"reservation\s+(is\s+)?confirmed\s+for",
                r"reply\s+yes\s+to\s+confirm",
                r"ticket\s+number\s+is",
                r"we\'?ll\s+respond\s+within",
                r"thank\s+you\s+for\s+contacting\s+support",
                r"office\s+hours\s+(are|is)",
                r"feel\s+free\s+to\s+(drop\s+by|ask|contact)",
                r"(store|we)\s+(is|are)\s+having\s+a\s+sale",
                r"thank\s+you\s+for\s+being\s+a\s+(loyal\s+)?customer",
                r"here\'?s\s+a\s+\d+%\s+discount\s+code",
                r"please\s+remember\s+to\s+submit",
                r"late\s+submissions\s+will\s+be\s+accepted",
                # Trusted URL patterns (legitimate services)
                r"https?://(www\.)?google\.com",
                r"https?://(www\.)?amazon\.com",
                r"https?://(www\.)?paypal\.com",
                r"https?://(www\.)?chase\.com",
                r"https?://(www\.)?linkedin\.com",
                r"https?://(www\.)?github\.com",
                r"https?://(www\.)?zoom\.us",
                r"https?://docs\.google\.com",
                r"https?://accounts\.google\.com",
                r"https?://(www\.)?ups\.com",
                r"https?://(www\.)?youtube\.com",
                # Benign notification patterns
                r"(is\s+)?confirmed\s+for\s+\d",  # "confirmed for 7 PM"
                r"your\s+credit\s+card\s+ending\s+in",
                r"purchase\s+at\s+amazon",
                r"just\s+got\s+updated",
                r"new\s+features",
                r"join\s+the\s+meeting\s+at",
                r"view\s+the\s+shared\s+document",
                r"track\s+your\s+package\s+at",
                r"subscribe\s+to\s+our\s+channel",
                r"update\s+from\s+the\s+app\s+store",
            ]
        ]
        self._auth_benign = re.compile(
            r"\b(announced|said|reported|mentioned|shared|presented|discussed)\b",
            re.IGNORECASE,
        )
        self._verify_benign = re.compile(
            r"\b(appointment|meeting|booking|reservation|schedule|"
            r"calendar|registration|sign.?up)\b",
            re.IGNORECASE,
        )

    @staticmethod
    def _any(msg: str, kws: list) -> bool:
        return any(kw in msg for kw in kws)

    @staticmethod
    def _count(msg: str, kws: list) -> int:
        return sum(1 for kw in kws if kw in msg)

    @classmethod
    def _any_rx(cls, msg: str, rxs: list) -> bool:
        return any(rx.search(msg) for rx in rxs)

    @staticmethod
    def _merge_signals(sig_original: Dict, sig_normalized: Dict) -> Dict:
        """Merge signals from original and normalized text, taking max of each."""
        merged = {}
        all_keys = set(sig_original.keys()) | set(sig_normalized.keys())
        
        for key in all_keys:
            val_orig = sig_original.get(key, False)
            val_norm = sig_normalized.get(key, False)
            
            # Handle list values (fear, deadline, brand, etc.)
            if isinstance(val_orig, list) or isinstance(val_norm, list):
                list_orig = val_orig if isinstance(val_orig, list) else []
                list_norm = val_norm if isinstance(val_norm, list) else []
                # Combine unique items from both lists
                merged[key] = list(set(list_orig) | set(list_norm))
            # Handle boolean values
            else:
                merged[key] = val_orig or val_norm
        
        return merged

    def _signals(self, msg: str) -> Dict:
        return {
            "fear": [kw for kw in self.FEAR_KW if kw in msg],
            "deadline": [kw for kw in self.DEADLINE_KW if kw in msg],
            "gov": [kw for kw in self.GOV_KW if kw in msg],
            "identity": any(rx.search(msg) for rx in self._IDENTITY_RX),
            "brand": [kw for kw in self.BRAND_KW if kw in msg],
            "authority": [
                kw for kw in self.AUTHORITY_KW
                if kw in msg and not self._auth_benign.search(msg)
            ],
            "sensitive": any(rx.search(msg) for rx in self._SENSITIVE_RX),
            "reward": [kw for kw in self.REWARD_KW if kw in msg],
            "scam": any(rx.search(msg) for rx in self._SCAM_RX),
            "otp_scam": any(rx.search(msg) for rx in self._OTP_SCAM_RX),
            "romance_scam": any(rx.search(msg) for rx in self._ROMANCE_SCAM_RX),
            "verify_suspicious": (
                ("verify" in msg or "confirm" in msg)
                and not self._verify_benign.search(msg)
            ),
        }

    def _whitelisted(self, msg: str, sig: Dict) -> bool:
        if sig["fear"] or sig["sensitive"] or sig["otp_scam"] or sig["romance_scam"]:
            return False
        return any(rx.search(msg) for rx in self._whitelist_rx)

    def analyze_message(self, message: str) -> Dict:
        msg = message.lower()
        
        # ---------------------------
        # ADVERSARIAL TEXT NORMALIZATION
        # ---------------------------
        # Pipeline: raw → deobfuscate → multilingual → signals
        deobfuscated_msg = normalize_obfuscation(msg)
        
        # ---------------------------
        # HYBRID SIGNAL ANALYSIS (Multilingual Support)
        # ---------------------------
        # Run signals on original text (preserves caps, punctuation detection)
        sig_original = self._signals(msg)
        
        # Run signals on deobfuscated text (handles leet speak, spacing tricks)
        sig_deobfuscated = self._signals(deobfuscated_msg)
        
        # Run signals on multilingual normalized text
        normalized_msg, match_count = normalize_text(deobfuscated_msg)
        sig_normalized = self._signals(normalized_msg)
        
        # Merge all signals: take max of each to capture all variants
        sig = self._merge_signals(sig_original, sig_deobfuscated)
        sig = self._merge_signals(sig, sig_normalized)
        
        # Store match_count for later bias-free scoring
        sig["_multilingual_match_count"] = match_count
        
        top_k_results = self.rag.retrieve_top_k(message, k=8)
        rule_signals = extract_rule_signals(message)

        if self._whitelisted(msg, sig):
            similar_patterns = get_similar_patterns(top_k_results)
            advice = get_advice("normal_communication")
            return {
                "attack_detected": False,
                "categories": [],
                "risk_level": "SAFE",
                "rag_confidence": 0.0,
                "rule_confidence": 0.0,
                "overall_confidence": 0.0,
                "confidence_calculation": (
                    "Overall Confidence = (0.6 x 0.00) + (0.4 x 0.00)\n"
                    "= 0.00 + 0.00\n"
                    "= 0.00%"
                ),
                "why_flagged": [],
                "similar_attack_patterns": similar_patterns,
                "dos": advice["dos"],
                "donts": advice["donts"],
                "context": {}
            }

        # Benign detection flag for suppression logic
        benign_detected = any(rx.search(msg) for rx in self._whitelist_rx)

        # Hard safe override for benign messages with no malicious indicators
        if benign_detected and not any([
            sig["fear"],
            sig["sensitive"],
            sig["reward"],
            sig["deadline"],
        ]):
            similar_patterns = get_similar_patterns(top_k_results)
            advice = get_advice("normal_communication")
            return {
                "attack_detected": False,
                "categories": [],
                "risk_level": "SAFE",
                "rag_confidence": 0.0,
                "rule_confidence": 0.0,
                "overall_confidence": 0.0,
                "confidence_calculation": (
                    "Overall Confidence = (0.6 x 0.00) + (0.4 x 0.00)\n"
                    "= 0.00 + 0.00\n"
                    "= 0.00%"
                ),
                "why_flagged": [],
                "similar_attack_patterns": similar_patterns,
                "dos": advice["dos"],
                "donts": advice["donts"],
                "context": {}
            }

        rag_conf, rag_cat = self.rag.detect(message)
        rule_conf, rule_cats = self._rule_engine(sig)

        # Check for strong attack indicators that should NOT be suppressed
        has_strong_indicator = (
            sig["brand"] or          # Brand impersonation (Microsoft, Apple, etc.)
            sig["identity"] or       # Identity assertion ("this is", "I am from")
            sig["scam"] or           # Scam patterns (investment, work-from-home)
            sig["otp_scam"] or       # OTP/code theft scams
            sig["romance_scam"] or   # Romance/advance fee scams
            sig["authority"] or      # Authority claim (CEO, CFO)
            sig["verify_suspicious"] # Suspicious verify/confirm requests
        )

        # Boost confidence for OTP scams and romance scams
        if sig["otp_scam"]:
            rag_conf = max(rag_conf, 55.0)
            rule_conf = max(rule_conf, 55.0)
        if sig["romance_scam"]:
            rag_conf = max(rag_conf, 50.0)
            rule_conf = max(rule_conf, 50.0)

        # Suppression for benign messages with weak signals
        # BUT only if no strong attack indicators are present
        if benign_detected and not has_strong_indicator:
            if not sig["fear"] and not sig["sensitive"] and not sig["reward"]:
                rag_conf = min(rag_conf, 20.0)
                rule_conf = min(rule_conf, 20.0)

        # General suppression for messages lacking core threat signals
        # BUT only if no strong attack indicators are present
        if not has_strong_indicator:
            if not sig["fear"] and not sig["sensitive"] and not sig["reward"] and not sig["deadline"]:
                rag_conf = min(rag_conf, 20.0)
                rule_conf = min(rule_conf, 20.0)
    
        result = self._combine(msg, rag_conf, rag_cat, rule_conf, rule_cats, sig)

        dominant_display = result["categories"][0] if result["categories"] else rag_cat
        dominant_internal = DISPLAY_TO_INTERNAL_CATEGORY.get(dominant_display, rag_cat)
        similar_patterns = get_similar_patterns(top_k_results)
        advice = get_advice(dominant_internal)
        why_flagged = generate_explanation(
            text=message,
            category=dominant_internal,
            top_k_results=top_k_results,
            rule_signals=rule_signals,
        )

        result["why_flagged"] = why_flagged
        result["similar_attack_patterns"] = similar_patterns
        result["dos"] = advice["dos"]
        result["donts"] = advice["donts"]
        result["voted_category"] = rag_cat

        return result

    def _rule_engine(self, sig: Dict) -> Tuple[float, List[str]]:
        score = 0.0

        n_fear = len(sig["fear"])
        if n_fear >= 1:
            score += 35.0
        if n_fear >= 2:
            score += 15.0

        if sig["deadline"]:
            score += 25.0

        if sig["identity"] or sig["brand"]:
            score += 20.0

        if sig["authority"]:
            score += 20.0

        if sig["sensitive"]:
            score += 25.0

        if sig["reward"]:
            score += 20.0

        if sig["verify_suspicious"]:
            score += 10.0

        # OTP scam boost - these are highly dangerous
        if sig.get("otp_scam"):
            score += 40.0

        # Romance scam boost
        if sig.get("romance_scam"):
            score += 35.0

        score = min(score, 100.0)

        # Get multilingual match count for gated activation
        match_count = sig.get("_multilingual_match_count", 0)

        cats: List[str] = []

        # ---------------------------
        # GATED CATEGORY ACTIVATION
        # ---------------------------
        # Standard activation: signal must be present (truthy)
        # Gated activation: weaker signals allowed when multilingual evidence exists
        
        # Fear/Threat
        if sig["fear"]:
            cats.append("Fear/Threat")
        elif match_count >= 2 and sig.get("verify_suspicious"):
            # Multilingual verify requests often imply threat
            cats.append("Fear/Threat")

        # Impersonation
        if sig["identity"] or sig["brand"]:
            cats.append("Impersonation")
        elif match_count >= 2 and (sig.get("sensitive") or sig.get("verify_suspicious")):
            # Multilingual credential requests imply impersonation
            cats.append("Impersonation")

        # Authority
        if sig["authority"]:
            cats.append("Authority")

        # Urgency
        if sig["deadline"]:
            cats.append("Urgency")
        elif match_count >= 2 and sig.get("verify_suspicious"):
            # Multilingual verify requests often imply urgency
            cats.append("Urgency")

        if sig["reward"]:
            cats.append("Reward/Lure")
        
        # OTP/code scam category
        if sig.get("otp_scam"):
            cats.append("Impersonation")  # OTP scams are a form of impersonation
            if "Fear/Threat" not in cats:
                cats.append("Fear/Threat")  # Often use urgency/fear

        # Romance scam category
        if sig.get("romance_scam"):
            cats.append("Fear/Threat")  # Often use emotional manipulation

        if "Impersonation" in cats and sig["sensitive"]:
            if "Fear/Threat" not in cats:
                cats.insert(0, "Fear/Threat")

        if sig["verify_suspicious"] and not cats:
            cats.append("Impersonation")

        seen: List[str] = []
        for c in cats:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break

        return score, seen

    def _combine(
        self,
        msg: str,
        rag_conf: float,
        rag_cat: str,
        rule_conf: float,
        rule_cats: List[str],
        sig: Dict,
    ) -> Dict:

        CAT_MAP = {
            "fear_threat": "Fear/Threat",
            "impersonation": "Impersonation",
            "authority": "Authority",
            "urgency": "Urgency",
            "reward_lure": "Reward/Lure",
        }
        rag_cat_display = CAT_MAP.get(rag_cat, None)

        cats = list(rule_cats)
        if rag_cat_display and rag_cat_display not in cats:
            cats.append(rag_cat_display)

        n_fear = len(sig["fear"])
        if n_fear >= 1 and "Fear/Threat" not in cats:
            cats.insert(0, "Fear/Threat")
        elif n_fear >= 1 and cats and cats[0] != "Fear/Threat":
            if "Fear/Threat" in cats:
                cats.remove("Fear/Threat")
            cats.insert(0, "Fear/Threat")

        rag_part = round(0.6 * rag_conf, 2)
        rule_part = round(0.4 * rule_conf, 2)
        overall = round(rag_part + rule_part, 2)

        has_gov = bool(sig["gov"])
        has_sens = sig["sensitive"]
        has_dl = bool(sig["deadline"])

        if has_gov:
            overall = max(overall, 70.0)
        if has_sens and has_dl:
            overall = max(overall, 65.0)
        if has_sens and (sig["identity"] or sig["brand"]):
            overall = max(overall, 65.0)
        if n_fear >= 2:
            overall = max(overall, 60.0)
        if n_fear >= 1 and has_dl:
            overall = max(overall, 60.0)
        if n_fear >= 1:
            overall = max(overall, 40.0)
        if rule_conf > 70.0 and "Fear/Threat" in cats:
            overall = max(overall, 65.0)

        overall = round(max(0.0, min(100.0, overall)), 2)

        # ---------------------------
        # F1: URL Multi-Modal Scoring
        # ---------------------------
        urls = extract_urls(msg)
        url_score_total = 0.0
        url_reasons = []
        trusted_flag = False
        
        for url in urls:
            s, r = analyze_url(url)
            url_score_total += s
            url_reasons.extend(r)
            if is_trusted_url(url):
                trusted_flag = True
        
        url_score = min(url_score_total * 100, 100)
        
        # Context-aware fusion
        if urls:
            if trusted_flag and url_score < 30:
                # Safe link from trusted domain significantly reduces suspicion
                # Only if no strong attack indicators (OTP scam, romance scam, etc.)
                overall = overall * 0.70  # Stronger reduction for trusted domains
            elif url_score > 60 and overall > 60:
                # Strong malicious text + malicious link
                overall = min(100, overall + 15)
            elif url_score > 60:
                # Safe text but malicious link
                overall = max(overall, 55)
            elif overall > 60 and url_score < 30:
                # Malicious text but safe/neutral link
                overall = overall * 0.9
        
        # Category adjustment for suspicious URLs
        if urls and not trusted_flag and url_score > 40:
            if "Impersonation" not in cats:
                cats.append("Impersonation")
        
        # ---------------------------
        # DUAL-TEXT STRATEGY (Multilingual Support)
        # ---------------------------
        # original_msg preserves ALL CAPS, punctuation, formatting for signal detection
        # normalized_msg maps non-English keywords to English for F2 classification
        original_msg = msg
        normalized_msg, _ = normalize_text(msg)  # match_count already in sig
        match_count = sig.get("_multilingual_match_count", 0)
        
        # ---------------------------
        # UNIFIED CONTEXT OBJECT
        # ---------------------------
        context = {
            "text": {
                "original": original_msg,
                "normalized": normalized_msg,
                "match_count": match_count,
            },
            "signals": sig,
            "url": {
                "urls": urls,
                "score": url_score,
                "trusted": trusted_flag,
                "malicious": url_score > 60,
                "suspicious": 30 < url_score <= 60,
                "reasons": url_reasons,
            },
            "email": {
                "parsed": {},
                "score": 0.0,
                "reasons": [],
            }
        }
        
        # ---------------------------
        # F3: Cross-Field Consistency Engine
        # ---------------------------
        consistency = analyze_consistency(original_msg, normalized_msg, context)
        context["consistency"] = consistency
        
        # Add inconsistency signal (0-1 scale)
        sig["inconsistency"] = consistency["normalized_signal"]
        
        # Controlled scoring boost based on inconsistency
        inconsistency_score = consistency["score"]
        if inconsistency_score >= 2:
            overall = min(100, overall + 10)
        elif inconsistency_score == 1:
            overall = min(100, overall + 5)
        
        # ---------------------------
        # BIAS-FREE MULTILINGUAL SCORING
        # ---------------------------
        # Boost ONLY when multiple evidence signals align (not language alone)
        evidence_score = 0
        if match_count >= 2:
            evidence_score += 1
        if context["url"]["malicious"]:
            evidence_score += 1
        if sig.get("deadline"):  # urgency signal
            evidence_score += 1
        if sig.get("identity") or sig.get("brand"):  # impersonation signal
            evidence_score += 1
        if sig.get("fear"):
            evidence_score += 1
        
        # Boost ONLY if multiple signals align (no bias)
        if evidence_score >= 2:
            overall = min(100, overall + 10)
        
        # Ensure malicious links never stay SAFE
        if context["url"]["malicious"]:
            overall = max(overall, 55)
        
        # F1 + F2 Alignment: malicious URLs enforce minimum score
        if context["url"]["malicious"]:
            overall = max(overall, 60)
        
        overall = round(max(0.0, min(100.0, overall)), 2)

        # ---------------------------
        # F2: Attack Type + Domain Classification
        # ---------------------------
        main_type = classify_attack(context)
        domain_type = classify_domain(context)
        attack_type = f"{main_type} → {domain_type}"

        # Dynamic category limiting based on severity
        unique_cats = list(dict.fromkeys(cats))
        if overall >= 70:
            cats = unique_cats[:4]
        elif overall >= 40:
            cats = unique_cats[:3]
        else:
            cats = unique_cats[:2]

        if overall >= 75:
            risk = "HIGH"
        elif overall >= 50:
            risk = "POTENTIAL"
        elif overall >= 25:
            risk = "LOW"
        else:
            risk = "SAFE"

        # ---------------------------
        # SAFE RISK ESCALATION (Multilingual Support)
        # ---------------------------
        # Escalate to POTENTIAL only if:
        # 1. Multiple multilingual keywords matched (match_count >= 2)
        # 2. Categories were activated (not empty)
        # 3. Overall confidence is at least 10% (not completely benign)
        if match_count >= 2 and cats and overall >= 10 and risk == "SAFE":
            risk = "LOW"  # Escalate SAFE → LOW (conservative)
        
        # Further escalate if strong evidence
        if match_count >= 3 and len(cats) >= 2 and overall >= 15 and risk == "LOW":
            risk = "POTENTIAL"  # Escalate LOW → POTENTIAL

        attack = risk != "SAFE"

        calc = (
            f"Overall Confidence = (0.6 x {rag_conf:.2f}) + (0.4 x {rule_conf:.2f})\n"
            f"= {rag_part:.2f} + {rule_part:.2f}\n"
            f"= {round(rag_part + rule_part, 2):.2f}%"
        )
        if urls:
            calc += f"\nURL analysis: {len(urls)} link(s), risk={url_score:.0f}%"
        if overall != round(rag_part + rule_part, 2):
            calc += f"\nAfter adjustments: {overall:.2f}%"

        return {
            "attack_detected": attack,
            "categories": cats if risk != "SAFE" else [],
            "risk_level": risk,
            "rag_confidence": round(rag_conf, 2),
            "rule_confidence": round(rule_conf, 2),
            "overall_confidence": overall,
            "confidence_calculation": calc,
            "attack_type": attack_type if risk != "SAFE" else None,
            "context": context
        }