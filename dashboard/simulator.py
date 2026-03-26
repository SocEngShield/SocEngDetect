"""
Attack Simulation Module — Scenario-based phishing message generator.
Generates coherent, realistic messages based on selected signals.
"""

import random

# Single-signal templates (used when only one tactic selected)
SINGLE_TEMPLATES = {
    "fear": [
        "SECURITY ALERT: We detected unauthorized access to your account. Your account will be suspended unless you verify your identity immediately.",
        "WARNING: Your personal data may have been compromised in a recent breach. Take action now to secure your information.",
        "ALERT: Suspicious login attempt detected from an unknown device. Secure your account immediately to prevent unauthorized access.",
    ],
    "urgency": [
        "IMMEDIATE ACTION REQUIRED: Your subscription expires in 1 hour. Update your payment details now to avoid service interruption.",
        "TIME-SENSITIVE: You must complete this verification within 15 minutes or your access will be revoked permanently.",
        "ACT NOW: This exclusive offer expires in 30 minutes. Don't miss your chance!",
    ],
    "reward": [
        "Congratulations! You've been selected to receive a $500 gift card. Claim your reward now before it expires!",
        "You've WON! As a valued customer, you qualify for an exclusive $1,000 cash bonus. Complete registration to receive payment.",
        "EXCLUSIVE: You've been chosen for a special rewards program. Click here to claim your free prize today!",
    ],
    "authority": [
        "This is the IT Security Department. Your password has expired and must be reset immediately using this secure link.",
        "From the CEO Office: I need you to process this payment urgently. This is confidential — do not discuss with anyone.",
        "Tax Authority Notice: You have an outstanding balance. Pay immediately to avoid legal action and penalties.",
    ],
    "impersonation": [
        "Hi, this is Mike from Microsoft Support. We've detected a critical issue with your computer and need remote access to resolve it.",
        "Dear valued customer, this is Amazon Customer Service. There's an issue with your recent order — verify your details now.",
        "This is your bank's security team. We need to confirm your account information to complete a pending verification.",
    ],
}

# Scenario templates for multi-signal combinations
SCENARIOS = {
    # Fear + Urgency → Account breach scenario
    ("fear", "urgency"): [
        "URGENT SECURITY ALERT: We detected unauthorized access to your account from an unknown device. Your account will be permanently locked within 1 hour unless you verify your identity immediately. Click here to secure your account now.",
        "CRITICAL: Suspicious activity detected on your account. You have 30 minutes to verify your identity or your account will be suspended for security reasons. Act now to prevent unauthorized access.",
        "WARNING: Your account has been flagged for suspicious activity. Immediate verification required within the next 15 minutes to prevent permanent suspension. Failure to respond will result in account termination.",
    ],
    # Fear + Impersonation → Bank fraud scenario
    ("fear", "impersonation"): [
        "This is your bank's fraud prevention team. We've detected suspicious transactions on your account that require immediate verification. Please confirm your identity to prevent your account from being frozen.",
        "Dear customer, this is the Security Department at your financial institution. Unauthorized access was attempted on your account. Reply with your verification details to secure your funds.",
        "ALERT from Bank Security: We've blocked a suspicious transfer from your account. To restore full access and protect your funds, please verify your identity through our secure portal.",
    ],
    # Reward + Urgency → Prize scam scenario
    ("reward", "urgency"): [
        "CONGRATULATIONS! You've won a $1,000 Amazon gift card! This exclusive offer expires in 30 minutes. Claim your prize now before it's given to another winner!",
        "You've been selected for a $500 cash reward! Only 3 spots remaining — act within the next hour to secure yours. Click here to claim before time runs out!",
        "WINNER NOTIFICATION: Your email was randomly selected for our $750 reward program! You have 45 minutes to claim. Don't let this opportunity slip away!",
    ],
    # Authority + Impersonation → Corporate/IT scam
    ("authority", "impersonation"): [
        "This is the IT Department. Your network credentials have expired and require immediate renewal. Please use this secure link to update your password. Failure to comply will result in access revocation.",
        "From: HR Department. As part of our annual compliance review, you must verify your employee information through the attached portal. This is mandatory for all staff.",
        "IT Security Notice: Your workstation has been flagged for a critical security update. Contact our support team immediately at this number to schedule remote assistance.",
    ],
    # Fear + Authority → Official threat scenario
    ("fear", "authority"): [
        "NOTICE FROM TAX AUTHORITY: Your account shows an outstanding balance of $2,847. Legal action will be initiated within 48 hours unless payment is received. Contact us immediately to resolve this matter.",
        "OFFICIAL WARNING: Your Social Security number has been suspended due to suspicious activity. Contact our office immediately to prevent legal consequences.",
        "Government Security Alert: Your identity has been compromised in a federal database breach. You must verify your information immediately to avoid account restrictions.",
    ],
    # Reward + Impersonation → Fake customer service reward
    ("reward", "impersonation"): [
        "Dear valued customer, this is Netflix Support. As a thank you for your loyalty, you've been selected for a free 1-year subscription upgrade! Click here to activate your reward.",
        "Hi, this is Sarah from Apple Rewards. You've qualified for a complimentary iPhone accessory bundle worth $200! Confirm your shipping address to receive your gift.",
        "Amazon Customer Appreciation: You've been chosen for an exclusive $100 credit! Our rewards team needs you to verify your account to apply this bonus.",
    ],
    # Authority + Urgency → Compliance pressure
    ("authority", "urgency"): [
        "URGENT: IT Security requires all employees to update their credentials within 2 hours due to a system-wide security patch. Use the link below immediately or lose network access.",
        "MANDATORY COMPLIANCE: HR requires your immediate response to this benefits verification. Deadline: End of business today. Failure to respond will affect your enrollment.",
        "CRITICAL NOTICE from Legal Department: You must review and sign the attached document within 1 hour. Non-compliance will result in disciplinary action.",
    ],
    # Impersonation + Urgency → Time-pressure identity scam
    ("impersonation", "urgency"): [
        "This is your bank calling. We've placed a temporary hold on your account due to unusual activity. You have 30 minutes to verify your identity or the hold becomes permanent. Call us back immediately.",
        "Hi, this is PayPal Security. A large transaction is pending on your account. You must confirm or cancel within 15 minutes or the payment will process automatically.",
        "Microsoft Account Team: Someone is trying to access your account. Verify your identity within the next hour or your account will be locked for security.",
    ],
    # Fear + Reward → Too-good-to-be-true with threat
    ("fear", "reward"): [
        "ALERT: Your account was selected for a $500 security compensation due to a recent data breach. Claim within 24 hours or funds will be forfeited. Verify your identity to receive payment.",
        "Due to unauthorized charges on your account, you're eligible for a $300 refund. This offer expires soon — confirm your details immediately to receive your compensation.",
        "NOTICE: As a victim of the recent security incident, you qualify for identity protection services worth $200. Register now before enrollment closes.",
    ],
}

# Complex scenarios (3+ signals)
COMPLEX_SCENARIOS = {
    # Fear + Urgency + Impersonation → Full bank fraud
    ("fear", "urgency", "impersonation"): [
        "This is your bank's fraud department. We detected suspicious activity on your account and have temporarily frozen your funds. You must verify your identity within 1 hour to restore access, or your account will be permanently closed for security reasons. Click here to verify now.",
        "URGENT: This is Bank Security. Unauthorized transactions totaling $3,500 were attempted on your account. Your account will be suspended in 30 minutes unless you confirm your identity immediately. Call our secure line now.",
        "Dear customer, this is the Fraud Prevention Team. We've blocked a suspicious login from overseas. Verify your account within the next hour to prevent permanent suspension and protect your funds.",
    ],
    # Authority + Impersonation + Urgency → Corporate pressure scam
    ("authority", "impersonation", "urgency"): [
        "This is the IT Security Department. A critical vulnerability has been detected on your workstation. You must install this security patch within 30 minutes or your network access will be revoked. Contact our helpdesk immediately.",
        "URGENT from HR: This is your final notice. Your employee verification is overdue and must be completed within 1 hour. Failure to comply will result in payroll suspension. Click here to verify now.",
        "From the CEO's Office: I need you to handle this wire transfer immediately — the deadline is in 2 hours. This is confidential and time-sensitive. Please confirm receipt and proceed.",
    ],
    # Reward + Urgency + Impersonation → Prize scam with fake identity
    ("reward", "urgency", "impersonation"): [
        "Hi, this is Jennifer from the Amazon Rewards Team! You've won a $1,000 shopping credit, but you must claim it within 30 minutes or it will be assigned to another customer. Verify your account now to receive your prize!",
        "Congratulations! This is Apple Customer Rewards. You've been selected for a free iPhone 15! Only 2 remaining — confirm your shipping details within 1 hour to secure yours.",
        "Dear winner, this is the PayPal Rewards Department. Your $500 cash prize is ready! Claim within 45 minutes before this offer expires. Click here to verify and receive your reward.",
    ],
    # Fear + Authority + Impersonation → Government/legal threat
    ("fear", "authority", "impersonation"): [
        "This is Agent Williams from the IRS Criminal Investigation Division. Your tax records show serious discrepancies that may result in legal action. Contact our office immediately to resolve this matter and avoid prosecution.",
        "OFFICIAL NOTICE: This is the Social Security Administration. Your SSN has been suspended due to suspicious activity. Failure to verify your identity will result in benefit termination and potential legal consequences.",
        "This is the Federal Trade Commission. Your identity has been linked to fraudulent activity. You must verify your information immediately to clear your record and avoid further investigation.",
    ],
}


def _normalize_tactics(tactics: list[str]) -> set[str]:
    """Normalize tactic names to lowercase set."""
    return {t.lower().strip() for t in tactics if t}


def _find_matching_scenario(tactics_set: set[str]) -> list[str] | None:
    """Find best matching scenario template for given tactics."""
    # Try complex scenarios first (3+ signals)
    for pattern, templates in COMPLEX_SCENARIOS.items():
        if set(pattern).issubset(tactics_set):
            return templates

    # Try two-signal scenarios
    for pattern, templates in SCENARIOS.items():
        if set(pattern).issubset(tactics_set):
            return templates

    return None


def generate_attack_message(tactics: list[str]) -> str:
    """
    Generate a coherent simulated phishing message based on selected tactics.

    Args:
        tactics: List of tactic names (fear, urgency, reward, authority, impersonation)

    Returns:
        Generated phishing message string
    """
    if not tactics:
        return ""

    tactics_set = _normalize_tactics(tactics)

    if not tactics_set:
        return ""

    # Single tactic: use single template
    if len(tactics_set) == 1:
        tactic = list(tactics_set)[0]
        if tactic in SINGLE_TEMPLATES:
            return random.choice(SINGLE_TEMPLATES[tactic])
        return ""

    # Multiple tactics: find matching scenario
    templates = _find_matching_scenario(tactics_set)

    if templates:
        return random.choice(templates)

    # Fallback: use template for first recognized tactic
    for tactic in tactics_set:
        if tactic in SINGLE_TEMPLATES:
            return random.choice(SINGLE_TEMPLATES[tactic])

    return ""
