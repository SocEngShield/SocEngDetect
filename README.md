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
- URL/Link Analysis with 15+ offline detection checks
- Email address extraction and analysis

**Explainability Features**
- Automatic extraction and analysis of URLs and email addresses from messages
- Signal breakdown showing which manipulation tactics were detected and their strength
- Attack type classification (credential harvesting, OTP theft, reward scams, etc.)
- Domain classification identifying target sectors (Banking, Government, Tech, etc.)
- Similar attack patterns from knowledge base with similarity scores
- Category-specific actionable recommendations

**Offline URL Analysis**
The system performs comprehensive URL risk assessment without external APIs:
- Suspicious TLD detection (.xyz, .tk, .top, .support, etc.)
- Brand lookalike/typosquatting detection (paypa1, amaz0n, etc.)
- @ symbol credential tricks
- Double extensions (.pdf.exe)
- Unicode/homograph attacks
- Brand-in-subdomain attacks
- IP address URLs
- URL shortener detection
- Excessive subdomain patterns
- Unusual port detection

**Multilingual Keyword Detection**
The system maps common phishing keywords from these languages to English for detection:
- Spanish, French, German, Italian, Portuguese
- Chinese, Russian, Arabic, Korean (keyword-based)

Note: Detection works by recognizing specific keywords (e.g., "urgente" -> "urgent") in messages. Full NLP support for non-Latin scripts is keyword-based only.

**Attack Simulator**
- Generates realistic phishing messages based on selected manipulation tactics
- 30+ templates covering single and multi-tactic combinations
- Useful for testing detection capabilities and security training

**Evaluation Framework**
- Comprehensive test dataset with 150+ labeled samples
- Computes Precision, Recall, F1 Score, Accuracy
- Tracks URL-based attack detection separately
- Provides confusion matrix and misclassification analysis
- Run with: `python evaluate.py`

**Interactive Dashboard**
- Real-time message analysis with confidence scoring
- Visual signal strength charts (bar graph)
- Risk level classification (SAFE, LOW, POTENTIAL, HIGH)
- Dynamic privacy mode indicator
- Attack simulation mode
- Multi-format report export (JSON, CSV, PDF)
- Color-coded API status indicators

**Export Features**
- JSON: Raw structured data for integration
- CSV: Comprehensive flattened format with individual signal scores and API results
- PDF: Professional human-readable reports with:
  - Modern card-based HTML/CSS layout (WeasyPrint + Jinja2)
  - Risk-coded color scheme
  - Signal strength visualization
  - External threat intelligence results
  - Actionable recommendations

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
- `requests` - HTTP requests for external APIs
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
├── utils/                 # Utilities
│   ├── api_config.py      # API configuration
│   ├── api_integrations.py # External API calls
│   ├── export.py          # JSON/CSV/PDF export
│   └── templates/         # PDF templates
├── evaluate.py            # Evaluation with metrics
├── test_dataset.py        # Labeled test samples
├── .env.example           # API key template
└── requirements.txt
```

## Technical Details

### Detection Architecture

This system uses a **Retrieval-Augmented Generation (RAG)** approach combined with rule-based signal analysis. It is NOT a fine-tuned/trained ML model—it's a retrieval system with semantic understanding.

**Key Points for Technical Review:**
- We use pre-trained embeddings (sentence-transformers/all-MiniLM-L6-v2)
- No gradient descent or model training occurs
- Knowledge base is the retrieval index (700+ curated patterns)
- Sources: FBI IC3, APWG, FTC, Microsoft Digital Defense Report, IRS/SSA

### RAG Detector

| Component | Details |
|-----------|---------|
| Model | sentence-transformers/all-MiniLM-L6-v2 |
| Embedding Dimensions | 384 |
| Parameters | 22.7M (lightweight) |
| Inference Time | <50ms per message |
| Knowledge Base | 700+ patterns from official sources |

**Confidence Calculation:**
1. Encode input message to 384D vector
2. Compute cosine similarity against knowledge base
3. Apply sigmoid transformation: `prob = 1/(1 + exp(-9*(score - 0.40)))`
4. Apply keyword floors and neighbor agreement boost
5. Convert to percentage (0-100%)

### Signal Detectors
1. **Urgency**: Time pressure, deadlines, "act now" language
2. **Fear/Threat**: Account suspension, legal threats, penalties
3. **Authority**: Executive/IT/government impersonation
4. **Impersonation**: Fake brand/service identity claims
5. **Reward/Lure**: Prizes, cashback, lottery, financial offers

### Signal Fusion (Weighted Ensemble)
```
Final Score = 0.6 × RAG_Confidence + 0.4 × Rule_Confidence
```
- Agreement boost: +15% when both ML and rules detect same signal
- Risk Thresholds: SAFE (0-24%), LOW (25-49%), POTENTIAL (50-74%), HIGH (75-100%)

### Similarity Score Calculation
```python
cosine_similarity(A, B) = (A · B) / (||A|| × ||B||)
```
- Range: 0.0 (different) to 1.0 (identical)
- Minimum threshold: 25% to appear in similar patterns

**Offline URL Analysis**
- No external API required
- 15+ detection patterns
- Suspicious TLD, brand lookalike, typosquatting detection
- Unicode/homograph attack detection
- IP-based URL detection

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
| AbuseIPDB | 1K req/day | IP abuse reporting & geolocation |

### Setup Instructions

1. **Get API Keys** (all free):
   - **VirusTotal**: [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
   - **Google Safe Browsing**: [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
   - **AbuseIPDB**: [abuseipdb.com/register](https://www.abuseipdb.com/register)

2. **Configure via .env file** (recommended):
```bash
# Copy the template
cp .env.example .env

# Edit .env and add your API keys
VIRUSTOTAL_API_KEY=your_key_here
GOOGLE_SAFEBROWSING_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

   Or **set environment variables** directly:
```bash
# Windows
set VIRUSTOTAL_API_KEY=your_key_here
set GOOGLE_SAFEBROWSING_API_KEY=your_key_here
set ABUSEIPDB_API_KEY=your_key_here

# Linux/macOS
export VIRUSTOTAL_API_KEY=your_key_here
export GOOGLE_SAFEBROWSING_API_KEY=your_key_here
export ABUSEIPDB_API_KEY=your_key_here
```

3. **Enable in Dashboard**: Toggle "Enable External API Checks" in the sidebar

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
