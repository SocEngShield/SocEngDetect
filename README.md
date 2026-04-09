# Social Engineering Attack Detection System

A Python-based system that detects social engineering attacks in messages using a hybrid approach combining RAG-based semantic detection with rule-based signal analysis.

## Table of Contents

- [Key Features](#key-features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Technical Details](#technical-details)
- [Testing](#testing)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

## Key Features

**Hybrid Detection Architecture**
- RAG/Semantic Detection using `sentence-transformers` with cosine similarity scoring
- Rule-Based Signal Engine detecting urgency, authority, impersonation, reward/lure, and fear/threat patterns
- Weighted Fusion Layer (60% RAG + 40% Rules) combining ML and rule-based confidence scores
- URL/Link Analysis with malicious domain pattern detection
- Email address extraction and analysis

**Explainability Features**
- Automatic extraction and analysis of URLs and email addresses from messages
- Signal breakdown showing which manipulation tactics were detected and their strength
- Attack type classification (credential harvesting, OTP theft, reward scams, etc.)
- Domain classification identifying target sectors (Banking, Government, Tech, etc.)
- Similar attack patterns from the knowledge base and external datasets with similarity scores
- Category-specific actionable recommendations

**Multilingual Keyword Detection**
The system maps common phishing keywords from these languages to English for detection:
- Spanish, French, German, Italian, Portuguese

Note: Detection works by recognizing specific keywords (e.g., "urgente" -> "urgent") in predominantly English text. Full support for non-Latin scripts (Chinese, Japanese, Russian) is limited to keyword recognition only.

**Attack Simulator**
- Generates realistic phishing messages based on selected manipulation tactics
- 65+ templates covering single and multi-tactic combinations
- Source-backed templates mapped to documented scam patterns (government imposters, BEC, credential phishing, QR phishing, fake refunds)
- Useful for testing detection capabilities and security training

**Attack Simulator Data Sources**
- FTC: How To Recognize and Avoid Phishing Scams - https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams
- SSA OIG: Protect Yourself from Scams - https://www.ssa.gov/scam/
- IRS: Recognize Tax Scams and Fraud - https://www.irs.gov/help/tax-scams/recognize-tax-scams-and-fraud
- APWG: Phishing Activity Trends Report Q1 2025 - https://docs.apwg.org/reports/apwg_trends_report_q1_2025.pdf
- FBI IC3: Internet Crime Report 2023 - https://www.ic3.gov/Media/PDF/AnnualReport/2023_IC3Report.pdf
- Microsoft Digital Defense Report 2023 - https://www.microsoft.com/en-us/security/security-insider/microsoft-digital-defense-report-2023

**Evaluation Framework**
- Comprehensive test dataset with labeled samples
- Computes Precision, Recall, F1 Score, Accuracy
- Tracks URL-based attack detection separately
- Provides confusion matrix and misclassification analysis
- Run with: `python evaluate.py`

**Interactive Dashboard**
- Real-time message analysis with confidence scoring
- Visual signal strength charts
- Risk level classification (SAFE, LOW, POTENTIAL, HIGH)
- Side-by-side comparison mode for two messages
- Attack simulation mode
- Dynamic privacy mode indicator
- Color-coded API status indicators
- Multi-format report export (JSON, CSV, PDF)

**Report Export**
- JSON: Structured raw output for integrations and debugging
- CSV: Flattened fields including signal scores and context metadata
- PDF: Professional forensic-style report layout using HTML/CSS templates
- Comparison-mode exports are rendered with separate summary and evidence sections

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd social_engineering_detector
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

## Common Commands

- Run evaluation:

```bash
python evaluate.py
```

- Validate evaluation mode:

```bash
python evaluate.py --validate
```

## Optional External API Setup

External checks are optional and privacy-first local mode remains supported.

Create a `.env` file in the project root:

```bash
VIRUSTOTAL_API_KEY=your_key
GOOGLE_SAFEBROWSING_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```

Notes:
- If keys are configured, the dashboard can auto-connect external checks.
- If keys are missing, detection still works fully in local mode.

## How Scoring Works

Base confidence:

- `final_base = 0.6 * rag_confidence + 0.4 * rule_confidence`

Then controlled adjustments may be applied (for example: strong corroborating signals, malicious URL context, suspicious sender/header evidence).

Risk bands:

- `SAFE`: 0-24
- `LOW`: 25-49
- `POTENTIAL`: 50-74
- `HIGH`: 75-100

## Project Structure

```text
social_engineering_detector/
├── dashboard/              # Streamlit UI
│   ├── app.py             # Main dashboard
│   ├── simulator.py       # Attack generator
│   └── bar_chart.py       # Visualizations
├── nlp_pipeline/          # Detection engine
│   ├── external_dataset/   # External RAG pattern sources
│   │   ├── spam.csv
│   │   ├── phishing_dataset_with_category.csv
│   │   ├── sms_dataset.py
│   │   └── category_dataset.py
│   ├── integrated_detector.py
│   ├── rag_detector.py
│   ├── knowledge_base.py
│   └── __init__.py
├── security_logic/        # Rule engine and signals
│   ├── rule_engine.py
│   ├── signal_fusion.py
│   ├── multilingual_map.py
│   ├── url_knowledge_base.py
│   └── signals/           # Individual detectors
├── utils/                 # Export and API utilities
│   ├── export.py          # JSON/CSV/PDF export
│   ├── api_config.py      # API configuration and status
│   ├── api_integrations.py # External API integrations
│   └── templates/         # PDF HTML/CSS templates
├── evaluate.py            # Evaluation with metrics
├── test_dataset.py        # Labeled test samples
├── .env.example           # Optional API key template
└── requirements.txt
```

## Technical Details

**Detection Model**
- RAG: `sentence-transformers/all-MiniLM-L6-v2`
- Knowledge Base: Static social engineering patterns in `nlp_pipeline/knowledge_base.py`
- External Datasets: `spam.csv` (SMS_DATASET) and `phishing_dataset_with_category.csv` (CATEGORY_DATASET)
- Fusion Weights: 60% RAG / 40% Rules
- Risk Thresholds: SAFE (0-24%), LOW (25-49%), POTENTIAL (50-74%), HIGH (75-100%)

**Signal Detectors**
1. Urgency: Time pressure, deadlines
2. Fear/Threat: Account suspension, legal threats
3. Authority: Executive/IT/government impersonation
4. Impersonation: Fake brand/service claims
5. Reward/Lure: Prizes, cashback, lottery offers

## Testing

### Running the Evaluation Suite

The project includes a comprehensive evaluation framework with a labeled test dataset:

```bash
python evaluate.py
```

This outputs:
- Confusion matrix (True Positives, False Positives, True Negatives, False Negatives)
- Precision, Recall, F1 Score, and Accuracy metrics
- URL-based attack detection metrics
- Attack type distribution analysis
- Detailed misclassification analysis

### Test Dataset

The test dataset (`test_dataset.py`) contains labeled samples covering:
- Various attack types (phishing, credential harvesting, OTP theft, reward scams)
- URL-based attacks
- Benign messages to test false positive rates
- Edge cases and multi-signal attacks

### Attack Simulator Testing

Use the dashboard's Attack Simulator mode to:
1. Generate test messages with specific tactics
2. Validate detection accuracy
3. Create security awareness training scenarios

## Known Limitations

- Multilingual support is keyword-based and works best with predominantly English text containing non-English keywords
- Non-Latin scripts (Chinese, Japanese, Russian, Arabic) have limited support
- Very short messages (under 10 characters) cannot be analyzed effectively
- The system analyzes text content only; it does not validate actual URLs or email addresses
- Performance depends on the quality and coverage of the knowledge base plus external dataset patterns

## Performance Considerations

- First run requires downloading transformer model files (~80MB)
- Analysis typically completes in under 3 seconds per message
- Dashboard supports real-time analysis
- All processing is local by default; external API checks are optional

## Optional External API Integration

External checks are disabled by default to preserve privacy-first local analysis.

Supported APIs:
- VirusTotal
- Google Safe Browsing
- AbuseIPDB

Enable by adding API keys to `.env` (or environment variables):
```bash
VIRUSTOTAL_API_KEY=your_key_here
GOOGLE_SAFEBROWSING_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

## Contributing

Contributions are welcome.

Recommended workflow:

1. Create a feature branch.
2. Make focused changes with tests.
3. Run `python evaluate.py` before opening a PR.

## License and Usage

This project is intended for defensive security, education, and research.
Use responsibly and ethically.
