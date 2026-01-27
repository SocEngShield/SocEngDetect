# Threat Model

This document defines the conceptual threat model for a Social Engineering Attack Detection system. It establishes a taxonomy of manipulation techniques, their psychological foundations, and the linguistic patterns that signal potential attacks. This model serves as the foundation for rule-based detection logic.
---
## Threat Taxonomy

Social engineering attacks exploit human psychology rather than technical vulnerabilities. The following five categories represent the primary manipulation vectors observed in phishing, pretexting, and other social engineering campaigns.

### 1. Urgency

| Attribute | Details |
|-----------|---------|
| **Description** | Creates artificial time pressure to bypass rational decision-making and force immediate action without verification. |
| **Psychological Principle** | Scarcity bias and stress-induced cognitive narrowing reduce critical evaluation of requests. |
| **Linguistic Cues** | Time-bound language, deadline references, immediacy markers, countdown framing. |
| **Example Phrases** | "Act now before it's too late", "Your account will be suspended in 24 hours", "Immediate action required", "Limited time offer expires today" |
| **Action Requirement** | Typically demands clicking links, providing credentials, or transferring funds within a constrained timeframe. |

### 2. Authority

| Attribute | Details |
|-----------|---------|
| **Description** | Leverages perceived power structures to compel compliance through claimed organizational or institutional authority. |
| **Psychological Principle** | Obedience to authority figures (Milgram principle) creates automatic compliance responses. |
| **Linguistic Cues** | Title references, organizational hierarchy mentions, policy citations, directive language. |
| **Example Phrases** | "As per CEO directive", "This is a mandatory compliance requirement", "IT Security Department requires", "By order of management" |
| **Action Requirement** | Often requests sensitive data disclosure, policy exceptions, or financial transactions with implied consequences for non-compliance. |

### 3. Impersonation

| Attribute | Details |
|-----------|---------|
| **Description** | Assumes a false identity to establish trust, typically mimicking known contacts, organizations, or service providers. |
| **Psychological Principle** | Familiarity bias and trust transference cause recipients to lower defenses for recognized entities. |
| **Linguistic Cues** | Brand references, colleague name-dropping, domain spoofing indicators, signature block manipulation. |
| **Example Phrases** | "This is John from IT", "Your bank has detected", "Microsoft Support Team", "Following up on our conversation" |
| **Action Requirement** | Requests actions the impersonated party would legitimately request, exploiting established trust relationships. |

### 4. Reward/Lure

| Attribute | Details |
|-----------|---------|
| **Description** | Offers incentives, prizes, or exclusive opportunities to motivate engagement with malicious content or requests. |
| **Psychological Principle** | Greed, curiosity, and fear of missing out (FOMO) override skepticism toward unsolicited offers. |
| **Linguistic Cues** | Prize language, exclusivity framing, financial gain references, special selection claims. |
| **Example Phrases** | "You've been selected to receive", "Claim your prize", "Exclusive offer for you", "Congratulations, you've won" |
| **Action Requirement** | Requires clicking links, downloading attachments, or providing personal information to "claim" the reward. |

### 5. Fear/Threat

| Attribute | Details |
|-----------|---------|
| **Description** | Induces anxiety through threats of negative consequences such as legal action, account loss, or security breaches. |
| **Psychological Principle** | Fear response activates fight-or-flight mechanisms, impairing analytical thinking and increasing compliance. |
| **Linguistic Cues** | Consequence warnings, legal terminology, security alert framing, loss language. |
| **Example Phrases** | "Your account has been compromised", "Legal action will be taken", "Failure to respond will result in", "Suspicious activity detected" |
| **Action Requirement** | Demands immediate remediation actions such as credential verification, payment, or personal data confirmation. |

---

## Category Overlap and Signal Combination

Social engineering attacks rarely employ a single manipulation technique in isolation. Sophisticated attacks combine multiple categories to maximize effectiveness and overcome recipient resistance.

**Key observations:**

- **Compounding effect**: The presence of multiple categories within a single communication significantly increases the likelihood of malicious intent.
- **Common combinations**: Urgency frequently pairs with Fear/Threat or Authority to amplify pressure. Impersonation often combines with Authority to establish credibility before making requests.
- **Signal independence**: Detection treats each category as an independent signal. Individual signals may appear in legitimate communications, but their combined presence constitutes a stronger risk indicator.
- **Escalation pattern**: Attackers often layer techniques progressively—establishing trust through Impersonation, invoking Authority, then applying Urgency to force action.

The detection approach evaluates all five categories simultaneously, with combined signals producing elevated risk assessments proportional to the number and intensity of categories present.

---
## Detection Rules Summary

| Category | Primary Indicators | Risk Level | Notes |
|----------|-------------------|------------|-------|
| Urgency | Time constraints, deadline language, immediacy markers | High | Standalone urgency with action requests warrants elevated scrutiny. |
| Authority | Title claims, organizational references, directive tone | High | Particularly concerning when paired with unusual requests. |
| Impersonation | Identity claims, brand references, sender inconsistencies | High | Verify sender authenticity through independent channels. |
| Reward/Lure | Prize claims, exclusive offers, financial incentives | Medium | Escalates to High when combined with Urgency or Impersonation. |
| Fear/Threat | Consequence warnings, security alerts, legal threats | High | Often paired with Urgency to prevent verification attempts. |

**Risk escalation logic:**

- Single category detected: Base risk level as indicated above.
- Two categories detected: Risk elevated by one tier.
- Three or more categories detected: Maximum risk classification.
- Action requirement present: Adds weight to overall risk assessment.

---

## False-Positive Considerations

Legitimate business communications may contain isolated indicators that overlap with social engineering patterns. Effective detection must account for these scenarios to maintain operational utility.

**Factors that reduce false-positive risk:**

- **Context evaluation**: Legitimate urgency exists in business contexts (actual deadlines, time-sensitive projects). Single urgency indicators without other manipulation signals should not trigger high-risk classification.
- **Action pressure threshold**: Risk should increase significantly only when explicit action pressure accompanies category indicators. Informational messages containing urgency language but no action requirement present lower risk.
- **Indicator density**: Isolated cues appearing once in lengthy communication carry less weight than concentrated indicators with repeated emphasis.
- **Combination requirement**: High-confidence detection should require multiple independent signals rather than triggering on single-category matches.

**Guidance for threshold calibration:**

- Require minimum two category matches for elevated risk classification.
- Weight explicit action requirements (click, download, provide, transfer) as independent risk factors.
- Consider indicator intensity—multiple instances of the same category strengthen the signal.
- Legitimate organizational communications may invoke authority; distinguish between routine hierarchy references and pressure-based authority claims.

Balancing detection sensitivity against false-positive rates ensures the system remains practical for operational use while maintaining protective value against genuine threats.