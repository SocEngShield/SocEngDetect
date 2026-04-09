"""
Attack Simulation Module - source-backed social engineering scenario generator.

The templates are synthetic reconstructions based on documented scam patterns from
public advisories and industry reports. They are not copies of real victim reports.
"""

import random
from typing import Any, Dict, List, Set


SIMULATOR_SOURCE_INDEX: Dict[str, Dict[str, str]] = {
    "FTC_PHISHING_2022": {
        "title": "FTC - How To Recognize and Avoid Phishing Scams",
        "url": "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams",
        "evidence": "Documents common lures: suspicious login, account problem, fake invoice, payment link, and free-offer bait.",
    },
    "SSA_SCAM_2026": {
        "title": "SSA OIG - Protect Yourself from Scams",
        "url": "https://www.ssa.gov/scam/",
        "evidence": "Describes government imposters, arrest/legal threats, urgency pressure, secrecy, and gift-card/wire/crypto payment demands.",
    },
    "IRS_SCAM_2026": {
        "title": "IRS - Recognize Tax Scams and Fraud",
        "url": "https://www.irs.gov/help/tax-scams/recognize-tax-scams-and-fraud",
        "evidence": "Highlights tax-impersonation warning signs: pay-now threats, refund-credit misinformation, and odd links.",
    },
    "APWG_Q1_2025": {
        "title": "APWG Phishing Activity Trends Report - Q1 2025",
        "url": "https://docs.apwg.org/reports/apwg_trends_report_q1_2025.pdf",
        "evidence": "Notes large phishing volume, QR-code phishing at scale, and increased wire-transfer BEC activity.",
    },
    "IC3_2023": {
        "title": "FBI IC3 Internet Crime Report 2023",
        "url": "https://www.ic3.gov/Media/PDF/AnnualReport/2023_IC3Report.pdf",
        "evidence": "Tracks high-impact social-engineering crimes including BEC, tech-support scams, and impersonation-led fraud.",
    },
    "MDDR_2023": {
        "title": "Microsoft Digital Defense Report 2023",
        "url": "https://www.microsoft.com/en-us/security/security-insider/microsoft-digital-defense-report-2023",
        "evidence": "Covers evolving identity-targeted phishing and credential theft tradecraft used in enterprise attacks.",
    },
}


ATTACK_EXAMPLES: List[Dict[str, Any]] = [
    {
        "attack_family": "Credential Harvesting - Account Lockout",
        "tactics": {"fear", "urgency", "impersonation"},
        "text": "Security Notice: We detected unusual sign-in attempts on your account. To prevent permanent lockout, verify your login details within 30 minutes using the secure portal.",
        "source_refs": ["FTC_PHISHING_2022", "MDDR_2023"],
    },
    {
        "attack_family": "Credential Harvesting - Payment Failure Pretext",
        "tactics": {"fear", "impersonation"},
        "text": "Billing Alert: Your subscription payment was declined and your account is now on hold. Confirm your payment information to avoid service interruption.",
        "source_refs": ["FTC_PHISHING_2022", "APWG_Q1_2025"],
    },
    {
        "attack_family": "Credential Harvesting - Fake Support Escalation",
        "tactics": {"authority", "impersonation", "urgency"},
        "text": "IT Security Team: Your mailbox was flagged in a credential exposure event. Reset your password immediately through this internal verification link to keep access.",
        "source_refs": ["MDDR_2023", "IC3_2023"],
    },
    {
        "attack_family": "BEC - Urgent Wire Request",
        "tactics": {"authority", "urgency"},
        "text": "From CFO Office: Process an urgent vendor wire transfer before 4:00 PM and send payment confirmation privately. This request is confidential and time-critical.",
        "source_refs": ["IC3_2023", "APWG_Q1_2025"],
    },
    {
        "attack_family": "BEC - Invoice Redirect Fraud",
        "tactics": {"authority", "impersonation"},
        "text": "Accounts Payable Update: Our banking details changed for this quarter. Please use the new account listed in the attached invoice for all outstanding payments.",
        "source_refs": ["IC3_2023", "APWG_Q1_2025"],
    },
    {
        "attack_family": "BEC - Executive Secrecy Pressure",
        "tactics": {"authority", "urgency", "fear"},
        "text": "Executive Directive: I need immediate payment release for a sensitive acquisition. Do not involve finance operations yet. Delays could disrupt the transaction.",
        "source_refs": ["IC3_2023", "SSA_SCAM_2026"],
    },
    {
        "attack_family": "Government Impersonation - Arrest Threat",
        "tactics": {"authority", "fear", "urgency", "impersonation"},
        "text": "Official Notice: Your Social Security record is linked to suspicious activity. Contact the assigned officer immediately to avoid enforcement action and account suspension.",
        "source_refs": ["SSA_SCAM_2026", "IC3_2023"],
    },
    {
        "attack_family": "Government Impersonation - Tax Threat",
        "tactics": {"authority", "fear", "urgency"},
        "text": "Tax Compliance Warning: Your file shows unresolved payment discrepancies. Submit payment now to prevent legal penalties and escalation.",
        "source_refs": ["IRS_SCAM_2026", "SSA_SCAM_2026"],
    },
    {
        "attack_family": "Government Impersonation - Fake Refund",
        "tactics": {"reward", "impersonation", "urgency"},
        "text": "Refund Eligibility Update: You qualify for a pending government refund. Complete identity verification today to release the deposit before the claim window closes.",
        "source_refs": ["IRS_SCAM_2026", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Payment Redirection - Gift Card Demand",
        "tactics": {"authority", "urgency", "reward"},
        "text": "Priority Request: Purchase digital gift cards immediately for an executive client incentive program and send the card codes for reimbursement processing.",
        "source_refs": ["SSA_SCAM_2026", "IC3_2023"],
    },
    {
        "attack_family": "Payment Redirection - Safe Account Scam",
        "tactics": {"fear", "authority", "urgency"},
        "text": "Fraud Prevention Unit: Your funds are at risk due to suspicious transfers. Move your balance now to a protected account to secure your money.",
        "source_refs": ["SSA_SCAM_2026", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "QR Phishing - Payment App",
        "tactics": {"impersonation", "urgency"},
        "text": "Payment App Alert: Your account verification is pending. Scan this QR code within 20 minutes to avoid temporary account restrictions.",
        "source_refs": ["APWG_Q1_2025", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "QR Phishing - Package Delivery",
        "tactics": {"impersonation", "fear", "urgency"},
        "text": "Courier Delivery Update: We could not deliver your package due to address validation failure. Scan the QR code now to confirm delivery and avoid return charges.",
        "source_refs": ["APWG_Q1_2025", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Reward Lure - Loyalty Credit Scam",
        "tactics": {"reward", "impersonation"},
        "text": "Customer Rewards: You are selected for a limited loyalty credit. Confirm your account details to apply the bonus to your payment profile.",
        "source_refs": ["FTC_PHISHING_2022", "APWG_Q1_2025"],
    },
    {
        "attack_family": "Reward Lure - Time-Limited Prize",
        "tactics": {"reward", "urgency"},
        "text": "Winner Confirmation: You qualify for a promotional cash reward. Claim within 45 minutes or your slot will be reassigned to another participant.",
        "source_refs": ["FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Reward Lure - Free Offer Credential Trap",
        "tactics": {"reward", "impersonation", "fear"},
        "text": "Subscriber Benefit: Your account has been selected for a free upgrade, but activation failed due to profile mismatch. Verify credentials to secure the benefit.",
        "source_refs": ["FTC_PHISHING_2022", "MDDR_2023"],
    },
    {
        "attack_family": "Tech Support Scam - Malware Panic",
        "tactics": {"fear", "authority", "impersonation"},
        "text": "Technical Support Alert: Malware was detected on your endpoint. Contact certified support now and confirm your admin login to initiate remote cleanup.",
        "source_refs": ["IC3_2023", "MDDR_2023"],
    },
    {
        "attack_family": "Tech Support Scam - Emergency Action",
        "tactics": {"fear", "urgency", "authority"},
        "text": "System Security Warning: Critical compromise activity detected. Follow immediate remediation steps now to avoid network quarantine and data loss.",
        "source_refs": ["IC3_2023", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Identity Theft Pretext - Verification Loop",
        "tactics": {"fear", "impersonation"},
        "text": "Identity Alert: Your profile was used in an unrecognized transaction. Re-verify account ownership to prevent unauthorized account recovery attempts.",
        "source_refs": ["FTC_PHISHING_2022", "MDDR_2023"],
    },
    {
        "attack_family": "Identity Theft Pretext - Social Number Threat",
        "tactics": {"fear", "authority", "impersonation"},
        "text": "Case Update: Your identity number is under review for suspicious activity. Respond immediately with verification details to prevent account seizure.",
        "source_refs": ["SSA_SCAM_2026", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Urgency-Only Pressure",
        "tactics": {"urgency"},
        "text": "Action Required: Complete verification before end of day to avoid service interruption.",
        "source_refs": ["FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Fear-Only Threat Framing",
        "tactics": {"fear"},
        "text": "Security Alert: Your account activity appears abnormal and requires immediate review.",
        "source_refs": ["FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Authority-Only Compliance Pressure",
        "tactics": {"authority"},
        "text": "Compliance Notice: This request requires immediate completion per policy directive.",
        "source_refs": ["IC3_2023"],
    },
    {
        "attack_family": "Impersonation-Only Brand Spoof",
        "tactics": {"impersonation"},
        "text": "Service Team Notice: We need to confirm your account details to complete a pending update.",
        "source_refs": ["FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Reward-Only Lure",
        "tactics": {"reward"},
        "text": "Promotional Update: Your profile is eligible for an account credit. Complete confirmation to receive the offer.",
        "source_refs": ["FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Multi-Stage Hybrid - Account + Payment",
        "tactics": {"fear", "urgency", "authority", "impersonation"},
        "text": "Security Operations: We detected account compromise tied to a pending payment instrument. Verify identity and payment profile immediately to prevent lockout.",
        "source_refs": ["MDDR_2023", "APWG_Q1_2025", "FTC_PHISHING_2022"],
    },
    {
        "attack_family": "Multi-Stage Hybrid - BEC + Invoice",
        "tactics": {"authority", "impersonation", "urgency"},
        "text": "Finance Escalation: Vendor remittance instructions were updated. Process the attached invoice now and confirm before banking cutoff.",
        "source_refs": ["IC3_2023", "APWG_Q1_2025"],
    },
    {
        "attack_family": "Multi-Stage Hybrid - Government + Payment",
        "tactics": {"authority", "fear", "reward", "urgency"},
        "text": "Official Benefits Case: Your account is marked for penalty review, but you may qualify for a corrective refund if you complete payment validation today.",
        "source_refs": ["SSA_SCAM_2026", "IRS_SCAM_2026"],
    },
]


def _normalize_tactics(tactics: List[str]) -> Set[str]:
    """Normalize tactic names to lowercase set."""
    valid = {"fear", "urgency", "reward", "authority", "impersonation"}
    return {t.lower().strip() for t in tactics if t and t.lower().strip() in valid}


def _score_example(example_tactics: Set[str], selected_tactics: Set[str]) -> float:
    """Score how well an example matches selected tactics."""
    overlap = len(example_tactics & selected_tactics)
    if overlap == 0:
        return 0.0

    extra = len(example_tactics - selected_tactics)
    missing = len(selected_tactics - example_tactics)

    return float((overlap * 2) - (extra * 0.4) - (missing * 0.8))


def _get_candidates(selected_tactics: Set[str]) -> List[Dict[str, Any]]:
    """Return best-matching examples for the selected tactic set."""
    if not selected_tactics:
        return []

    exact = [ex for ex in ATTACK_EXAMPLES if ex["tactics"] == selected_tactics]
    if exact:
        return exact

    superset = [ex for ex in ATTACK_EXAMPLES if selected_tactics.issubset(ex["tactics"])]
    if superset:
        return superset

    scored = [
        (ex, _score_example(ex["tactics"], selected_tactics))
        for ex in ATTACK_EXAMPLES
    ]
    best_score = max((score for _, score in scored), default=0.0)
    if best_score <= 0:
        return []

    return [ex for ex, score in scored if score == best_score]


def _expand_sources(source_refs: List[str]) -> List[Dict[str, str]]:
    """Resolve source ids into source metadata objects."""
    expanded: List[Dict[str, str]] = []
    for source_id in source_refs:
        source_meta = SIMULATOR_SOURCE_INDEX.get(source_id)
        if source_meta:
            expanded.append(source_meta)
    return expanded


def generate_attack_message_details(tactics: List[str]) -> Dict[str, Any]:
    """
    Generate a simulator message with metadata and traceable source references.

    Args:
        tactics: Selected manipulation tactics.

    Returns:
        Dict containing message, attack family, matched tactics, and source metadata.
    """
    selected_tactics = _normalize_tactics(tactics)
    if not selected_tactics:
        return {
            "message": "",
            "attack_family": "",
            "selected_tactics": [],
            "template_tactics": [],
            "source_refs": [],
            "sources": [],
        }

    candidates = _get_candidates(selected_tactics)
    if not candidates:
        return {
            "message": "",
            "attack_family": "",
            "selected_tactics": sorted(selected_tactics),
            "template_tactics": [],
            "source_refs": [],
            "sources": [],
        }

    chosen = random.choice(candidates)
    source_refs = chosen.get("source_refs", [])

    return {
        "message": chosen["text"],
        "attack_family": chosen.get("attack_family", "General Social Engineering"),
        "selected_tactics": sorted(selected_tactics),
        "template_tactics": sorted(chosen.get("tactics", set())),
        "source_refs": source_refs,
        "sources": _expand_sources(source_refs),
    }


def get_simulator_data_sources() -> List[Dict[str, str]]:
    """Return all data sources used by the simulator templates."""
    return [SIMULATOR_SOURCE_INDEX[key] for key in sorted(SIMULATOR_SOURCE_INDEX.keys())]


def generate_attack_message(tactics: List[str]) -> str:
    """
    Backward-compatible helper returning only the generated message text.

    Args:
        tactics: List of tactic names.

    Returns:
        Generated phishing message string.
    """
    return generate_attack_message_details(tactics).get("message", "")
