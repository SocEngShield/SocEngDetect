# Social Engineering Detector Documentation

## Overview
The **Social Engineering Detector** is an interactive, open-source tool designed to analyze and identify social engineering techniques and language manipulation within digital communications (e.g., emails, messages). It detects indicators of deception, including urgency, fear, reward lures, authority requests, and impersonation.

By combining an advanced rule-based heuristic engine with an underlying semantic retrieval-augmented generation (RAG) knowledge base, the application accurately evaluates the risk inherent within a specific message and outlines precisely why the content was flagged. 

## Features
- **Real-Time Analysis**: Quickly assess the risk level of user-provided texts.
- **Comparison Mode**: Evaluate and contrast two different messages side-by-side to understand relative threat variances.
- **Attack Simulation**: Automatically generate common social engineering lures based on customizable templates across several manipulation families.
- **Detailed Threat Signal Breakdown**: Explains the exact manipulation methods uncovered.
- **External Threat Intelligence Integration**: Extensible integration with threat APIs (VirusTotal, Google Safe Browsing, AbuseIPDB) if URL links are identified.
- **Export Data**: Output findings to CSV, JSON, or PDF for later auditing or incident response procedures.

## Core Architecture

The detector operates through a dual-engine architecture:

### 1. NLP Pipeline and RAG Matching
- Handles semantic evaluations by normalizing text and comparing overlapping indicators against a curated multi-source dataset.
- Maps unknown attacks against confirmed past scenarios to find similarities, scoring text based on syntactic and semantic overlap.

### 2. Security Logic & Rule Engine
- **Signal Analysis**: Extracts concrete flags related to `Urgency`, `Fear/Threat`, `Authority/Impersonation`, and `Reward/Lure` utilizing heavy regex matching and contextual keyword proximity logic.
- **Signal Fusion**: A combination mechanism where semantic (RAG) and heuristic (Rule-based) scores are weighted and combined to produce an overarching confidence threat index.
- Output ranges from `SAFE` to `HIGH RISK`. 

## Data & Privacy
- **Cloud Hosted Processing**: This tool is hosted via Streamlit Community Cloud. 
- **No Data Retention**: Texts input for analysis are processed instantly in memory (transient cloud processing). The application does not utilize a persistent background database to log, store, or train on user queries.
- **External Dependencies Check**: If external APIs are toggled on, URLs identified in the text may be sent to third-party endpoints. As a user, you hold complete control over enabling/disabling this integration via the sidebar. When turned off, the analysis relies solely on the internal engine without internet transmission.

## Developer Notice
The internal modeling, rule mappings, and precise logic tunings are housed in the root of the repository. Check out the backend modules within `nlp_pipeline/` and `security_logic/` to understand the rule weightings and thresholds deeply.