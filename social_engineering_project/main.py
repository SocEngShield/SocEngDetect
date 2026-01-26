"""
Main entry point for the social engineering detection system.

Demonstrates end-to-end pipeline: text cleaning → threat signal detection → risk assessment.
"""

from nlp_pipeline.text_cleaner import clean_text
from security_logic.threat_signals import has_urgency_words
from security_logic.rule_engine import assess_risk


def main():
    """Run the detection pipeline on a hardcoded example message."""

    # Step 1: Define a hardcoded example message representing a social engineering attempt.
    original_message = (
        "URGENT! Action required immediately at https://secure-login-verify.com. "
        "Your account has been compromised. Verify your identity now or lose access. "
        "Contact admin@company.fake ASAP."
    )

    print("=" * 70)
    print("SOCIAL ENGINEERING DETECTION PIPELINE")
    print("=" * 70)
    print()

    # Step 2: Display the original message.
    print("[1] ORIGINAL MESSAGE:")
    print(f"    {original_message}")
    print()

    # Step 3: Clean the message using the text_cleaner module.
    cleaned_message = clean_text(original_message)
    print("[2] CLEANED MESSAGE:")
    print(f"    {cleaned_message}")
    print()

    # Step 4: Execute threat signal detection functions on the cleaned text.
    # Each function returns a boolean indicating presence of that threat signal.
    print("[3] THREAT SIGNAL DETECTION:")

    signal_results = {
        "urgency_words": has_urgency_words(cleaned_message),
    }

    # Display each signal with its result.
    for signal_name, signal_value in signal_results.items():
        status = "DETECTED" if signal_value else "not detected"
        print(f"    {signal_name}: {status}")
    print()

    # Step 5: Pass the signal results to the rule-based risk engine.
    risk_assessment = assess_risk(signal_results)

    # Step 6: Display the final risk assessment.
    print("[4] RISK ASSESSMENT:")
    print(f"    Risk Level: {risk_assessment['risk_level']}")
    print(f"    Triggered Signals: {risk_assessment['triggered_signals']}")
    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
