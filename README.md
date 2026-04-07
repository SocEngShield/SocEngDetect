# Social Engineering Detection System

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
- Similar attack patterns from knowledge base with similarity scores
- Category-specific actionable recommendations

**Multilingual Keyword Detection**
The system maps common phishing keywords from these languages to English for detection:
- Spanish, French, German, Italian, Portuguese

Note: Detection works by recognizing specific keywords (e.g., "urgente" → "urgent") in predominantly English text. Full support for non-Latin scripts (Chinese, Japanese, Russian) is limited to keyword recognition only.

**Attack Simulator**
- Generates realistic phishing messages based on selected manipulation tactics
- 30+ templates covering single and multi-tactic combinations
- Useful for testing detection capabilities and security training

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
- Attack simulation mode
- Multi-format report export (JSON, CSV, PDF)

**Export Features**
- JSON: Raw structured data for integration
- CSV: Flattened format for spreadsheet analysis
- PDF: Professional human-readable reports with:
  - Modern card-based HTML/CSS layout (WeasyPrint + Jinja2)
  - Risk-coded color scheme
  - Actionable recommendations
  - Analysis insights

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/SocEngShield/SocEngDetect.git
cd social_engineering_detector
```

2. Create a virtual environment (recommended):
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Dependencies

The project requires the following packages:
- `streamlit` - Web dashboard framework
- `plotly` - Interactive visualizations
- `numpy` - Numerical computing
- `sentence-transformers` - Semantic similarity detection
- `scikit-learn` - Machine learning utilities
- `reportlab` - PDF generation (fallback)
- `jinja2` - HTML template rendering
- `weasyprint` - HTML to PDF conversion
- `torchvision` - Required to prevent Streamlit Cloud file watcher crashes with transformers

**Streamlit Cloud Deployment**: If deploying to Streamlit Cloud, you must include a `packages.txt` file in the root directory with the following system dependencies for WeasyPrint:
```text
libpango-1.0-0
libpangoft2-1.0-0
```

**WeasyPrint Note**: On Windows, WeasyPrint requires GTK libraries. Install via:
```bash
# Windows (using pip)
pip install weasyprint

# If GTK is missing, install via MSYS2 or use the reportlab fallback
```

Note: On first run, `sentence-transformers` will download the model files (~80MB).

## Usage

Run the dashboard:

```bash
streamlit run dashboard/app.py
```

Run evaluation:

```bash
python evaluate.py
```


## Project Structure

```text
social_engineering_detector/
├── dashboard/              # Streamlit UI
│   ├── app.py             # Main dashboard
│   ├── simulator.py       # Attack generator
│   └── bar_chart.py       # Visualizations
├── nlp_pipeline/          # Detection engine
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
├── evaluate.py            # Evaluation with metrics
├── test_dataset.py        # Labeled test samples
└── requirements.txt
```

## Technical Details

**Detection Model**
- RAG: `sentence-transformers/all-MiniLM-L6-v2`
- Knowledge Base: 550+  patterns
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
- Very short messages (under 10 characters) cannot not be analyzed effectively
- The system analyzes text content only; it does not validate actual URLs or email addresses
- Performance depends on the quality and coverage of the knowledge base patterns

## Performance Considerations

- First run requires downloading transformer model files (~80MB)
- Analysis typically completes in under 3 seconds per message
- Dashboard supports real-time analysis
- All processing is local by default; no external API calls

## Optional: External API Integration

The system supports optional external threat intelligence APIs for enhanced URL checking. **These are disabled by default** to maintain the privacy-first design.

### Supported APIs

| API | Free Tier | Purpose |
|-----|-----------|---------|
| VirusTotal | 500 req/day | URL reputation scanning |
| Google Safe Browsing | 10K req/day | Malware/phishing detection |
| AbuseIPDB | 1K req/day | IP abuse reporting |

### Setup Instructions

1. **Get API Keys** (all free):
   - **VirusTotal**: [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
   - **Google Safe Browsing**: [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
   - **AbuseIPDB**: [abuseipdb.com/register](https://www.abuseipdb.com/register)

2. **Set Environment Variables**:
```bash
# Windows
set SOCENG_API_ENABLED=true
set VIRUSTOTAL_API_KEY=your_key_here
set GOOGLE_SAFEBROWSING_API_KEY=your_key_here
set ABUSEIPDB_API_KEY=your_key_here

# Linux/macOS
export SOCENG_API_ENABLED=true
export VIRUSTOTAL_API_KEY=your_key_here
export GOOGLE_SAFEBROWSING_API_KEY=your_key_here
export ABUSEIPDB_API_KEY=your_key_here
```

3. **Enable in Dashboard**: Toggle "Enable External URL Checks" in the sidebar

### Privacy Notice

When external APIs are enabled:
- URLs extracted from messages are sent to configured services
- No message text is sent externally
- Results are cached for 1 hour to reduce API calls
- You can disable APIs at any time via the sidebar toggle

## Contributing

Contributions are welcome. Areas for improvement:

**Detection Accuracy**
- Expand knowledge base with more attack patterns
- Improve signal detection algorithms
- Add new attack type classifiers

**Multilingual Support**
- Add more language keyword mappings
- Implement proper NLP for non-Latin scripts
- Expand multilingual test coverage

**Features**
- Batch processing mode for multiple messages
- API endpoint for integration with other systems
- Additional visualization types

**Testing**
- Expand test dataset
- Add unit tests for individual components
- Performance benchmarking suite

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Run evaluation to ensure no regression: `python evaluate.py`
5. Submit a pull request with a clear description

## License

This project is available for educational and research purposes. Please include attribution when using or modifying this code.

## Acknowledgments

- Uses `sentence-transformers` for semantic similarity detection
- Built with Streamlit for the interactive dashboard
- Plotly for interactive visualizations

## Contact

For questions, issues, or suggestions, please open an issue in the repository.

---

**Disclaimer**: This tool is designed for educational and defensive security purposes. Use responsibly and ethically.
