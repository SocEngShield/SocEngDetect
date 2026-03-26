"""
Attack Simulation Module — Template-based phishing message generator.
"""

import random

TEMPLATES = {
    "fear": [
        "Your account has been compromised and will be permanently deleted within 24 hours unless you verify your identity immediately.",
        "SECURITY ALERT: Unauthorized access detected on your account. Failure to respond will result in account suspension.",
        "WARNING: Your data has been exposed in a breach. Click here immediately to secure your information or risk identity theft.",
    ],
    "urgency": [
        "ACT NOW — This offer expires in the next 30 minutes! Don't miss out!",
        "IMMEDIATE ACTION REQUIRED: Your subscription will be cancelled unless you update your payment details within 1 hour.",
        "URGENT: You must complete this verification within the next 15 minutes or lose access permanently.",
    ],
    "reward": [
        "Congratulations! You've been selected to receive a $1,000 gift card. Claim your reward now before it expires!",
        "You've WON! Click here to claim your FREE iPhone 15 Pro — only 3 left in stock!",
        "EXCLUSIVE OFFER: You qualify for a $500 cash bonus. Complete your registration to receive payment today.",
    ],
    "authority": [
        "This is the IT Security Department. Your password has expired and you must reset it immediately using this secure link.",
        "From the CEO Office: I need you to process this wire transfer urgently. This is confidential — do not discuss with anyone.",
        "Tax Authority Notice: You have an outstanding balance. Pay immediately to avoid legal action and additional penalties.",
    ],
    "impersonation": [
        "Hi, this is John from Microsoft Support. We've detected a virus on your computer and need remote access to fix it.",
        "Dear valued customer, this is Amazon Customer Service. Your recent order has a shipping issue — verify your address now.",
        "This is your bank's fraud department calling. We need to verify your account details to prevent unauthorized transactions.",
    ],
}

CONNECTORS = [
    "\n\n",
    " ",
    "\n\nAdditionally, ",
    "\n\nFurthermore, ",
    " Also, ",
]


def generate_attack_message(tactics: list[str]) -> str:
    """
    Generate a simulated phishing message based on selected tactics.

    Args:
        tactics: List of tactic names (fear, urgency, reward, authority, impersonation)

    Returns:
        Generated phishing message string
    """
    if not tactics:
        return ""

    selected_parts = []

    for tactic in tactics:
        tactic_key = tactic.lower().strip()
        if tactic_key in TEMPLATES:
            selected_parts.append(random.choice(TEMPLATES[tactic_key]))

    if not selected_parts:
        return ""

    if len(selected_parts) == 1:
        return selected_parts[0]

    # Combine multiple tactics
    result = selected_parts[0]
    for part in selected_parts[1:]:
        connector = random.choice(CONNECTORS)
        result += connector + part

    return result
