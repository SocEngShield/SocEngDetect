from security_logic.rule_engine import analyze_text

example_message = """
Hi there,

I'm from the IT Security team. We've detected unusual activity on your account 
and need to verify your credentials urgently. Please reply with your username, 
password, and the code on the back of your company card to confirm your identity.

This is time-sensitive - your account will be locked in 2 hours if we don't hear back.

Click here to verify: [malicious-link.com/verify]

Best regards,
IT Security Team
"""

def main():
    """Main entry point for social engineering detection system."""

    result = analyze_text(example_message)

    print("\n" + "=" * 60)
    print("SOCIAL ENGINEERING DETECTION REPORT")
    print("=" * 60)

    print(f"\nVERDICT: {result['verdict'].upper()}")
    print(f"TOTAL SCORE: {round(result['total_score'], 3)}")
    print(f"RULE CONFIDENCE: {result['rule_confidence']}")

    # -----------------------------
    # ACTIVE SIGNALS
    # -----------------------------
    print(f"\nACTIVE SIGNALS ({len(result['active_signals'])} detected):")
    for signal in result['active_signals']:
        print(f"   • {signal}")

    # -----------------------------
    # PER SIGNAL BREAKDOWN
    # -----------------------------
    print("\nPER SIGNAL BREAKDOWN:")
    for name, data in result["per_signal_breakdown"].items():
        print(f"\n{name.upper()}:")
        print(f"   Score      : {data['score']}")
        print(f"   Confidence : {data['confidence']}")
        print(f"   Strength   : {data['strength']}")
        print(f"   Active     : {data['is_active']}")

    # -----------------------------
    # RADAR DATA (NEW)
    # -----------------------------
    print("\nRADAR DATA (normalized):")
    for k, v in result["radar_data"].items():
        print(f"   {k}: {v}")

    # -----------------------------
    # EVIDENCE
    # -----------------------------
    print("\nCOMBINED EVIDENCE:")
    for evidence in result['combined_evidence']:
        print(f"   • {evidence}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()