# Social Engineering Detection Project

A Python project that detects potential social engineering in messages using a hybrid approach:

- **RAG/semantic detection** (`sentence-transformers` + similarity scoring)
- **Rule-based signal engine** (urgency, authority, impersonation, reward/lure, fear/threat)
- **Fusion layer** to combine ML and rule confidence into a final risk score

The main user interface is a **Streamlit dashboard** for interactive analysis.

## Quickstart

### 1) Clone and enter the project

```bash
git clone <your-repo-url>
cd social_engineering_project
```

### 2) Create and activate a virtual environment

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3) Install dependencies

```bash
pip install -r requirements.txt
```

### 4) Run the dashboard

From project root:

```bash
streamlit run dashboard/app.py
```

Then open the local URL shown in terminal (usually `http://localhost:8501`).

## Optional: Run CLI demo

```bash
python main.py
```

This runs a sample message through the rule engine and prints a terminal report.

## Sample Input / Output

### Example message input

```text
Hi there,
I'm from the IT Security team. We've detected unusual activity on your account.
Please reply with your username, password, and card details urgently.
Your account will be locked in 2 hours if we don't hear back.
```

### CLI-style output (example)

```text
SOCIAL ENGINEERING DETECTION REPORT

VERDICT: HIGH
TOTAL SCORE: 0.83

ACTIVE SIGNALS (4 detected):
  • impersonation
  • urgency
  • authority
  • fear_threat

COMBINED EVIDENCE:
  • identity claim detected ("IT Security team")
  • urgent deadline language detected ("2 hours")
  • sensitive credential request detected
```

### Dashboard-style output (example)

- **Risk Level:** HIGH
- **RAG Confidence:** 86.2%
- **Rule Confidence:** 78.5%
- **Overall Confidence:** 83.1%
- **Top Categories:** Impersonation, Urgency

## Project Structure

```text
social_engineering_project/
├── dashboard/          # Streamlit UI + visualizations
├── nlp_pipeline/       # RAG detector + integrated detector + knowledge base
├── security_logic/     # Rule engine, signals, and fusion logic
├── utils/              # Helper utilities
├── main.py             # CLI sample entry point
├── requirements.txt    # Python dependencies
└── README.md
```

## Notes

- On first run, `sentence-transformers` may download model files.
- This project currently focuses on message-text analysis and risk scoring output.
