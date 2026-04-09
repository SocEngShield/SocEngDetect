# Social Engineering Detection System

A hybrid phishing and social-engineering detector for message text.
It combines semantic retrieval (RAG) with rule-based behavioral signals, then produces a final risk score, categories, and analyst-friendly explanations.

## What This Project Does

- Detects manipulation tactics such as urgency, impersonation, authority pressure, fear/threat, and reward/lure.
- Uses weighted scoring (60% RAG + 40% rules) with guarded post-processing adjustments.
- Classifies attack type and domain context.
- Supports side-by-side comparison mode in the dashboard.
- Exports reports as JSON, CSV, and PDF.
- Optionally checks URLs with external threat intelligence APIs.

## Quick Start

### 1. Clone and enter the repo

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
|- dashboard/
|  |- app.py
|  |- simulator.py
|  `- bar_chart.py
|- nlp_pipeline/
|  |- integrated_detector.py
|  |- rag_detector.py
|  `- knowledge_base.py
|- security_logic/
|  |- rule_engine.py
|  |- signal_fusion.py
|  `- signals/
|- utils/
|  |- api_config.py
|  |- api_integrations.py
|  |- export.py
|  `- templates/
|- evaluate.py
|- test_dataset.py
`- requirements.txt
```

## Testing and Evaluation

The evaluation pipeline reports:

- Precision, Recall, F1, Accuracy
- Confusion matrix breakdown
- URL-related detection performance
- Misclassification samples

Use the dashboard simulator to generate tactic-based attack messages for manual testing.

## Known Limitations

- Multilingual support is keyword-mapping based, not full multilingual NLP.
- Very short messages provide limited evidence.
- External API quality depends on network and provider availability.
- Detection quality depends on knowledge base coverage.

## Contributing

Contributions are welcome.

Recommended workflow:

1. Create a feature branch.
2. Make focused changes with tests.
3. Run `python evaluate.py` before opening a PR.

## License and Usage

This project is intended for defensive security, education, and research.
Use responsibly and ethically.
