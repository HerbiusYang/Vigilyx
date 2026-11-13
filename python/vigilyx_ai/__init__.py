"""
Vigilyx AI analysis package.

Provides email-content analysis and threat-detection capabilities, including
LLM-assisted workflows.

Package layout:
- api.py: HTTP API service
- nlp_phishing.py: NLP inference and model loading
- scraper.py and vt_models.py: VirusTotal scraping and request/response models
- llm/: large-language-model integrations
- safety_policy.py and visual_ocr.py: input safeguards and image analysis
"""

__version__ = "0.9.4"
