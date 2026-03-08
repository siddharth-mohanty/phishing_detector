# 🛡️ Unified Phishing Website Detector

> A comprehensive, multi-module phishing detection tool that analyses URLs across **11 independent detection layers** — from SSL certificates and DNS records to browser-automated CAPTCHA testing and OTP security checks — producing a single unified risk score.

---

## 📋 Table of Contents

- [Features](#-features)
- [Module Overview](#-module-overview)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Example](#-output-example)
- [Project Structure](#-project-structure)
- [Disclaimer](#-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- **11 detection modules** covering static, network, and dynamic browser-based analysis
- **Weighted aggregate scoring** — each module contributes to a single 0–100 phishing risk score
- **Two scan modes** — full scan (all modules) or fast scan (no browser automation)
- **ANSI colour-coded terminal output** with per-module risk bars
- **Interactive pattern tuner** for permission API regex patterns
- **Graceful degradation** — browser modules are skipped cleanly if Selenium/Playwright is not installed
- **Auto-installs missing pip packages** on first run

---

## 🔍 Module Overview

| # | Module | What It Checks | Requires Browser |
|---|--------|---------------|-----------------|
| 01 | SSL/TLS Certificate Analyzer | Certificate validity, cipher strength, CA trust, key size, tunnel+DV combos | No |
| 02 | URL Feature Scorer | 16-feature weighted model: brand fuzzing, entropy, redirects, shorteners | No |
| 03 | TLD / Token Checker | Hostname labels vs. 80+ suspicious TLD/keyword tokens | No |
| 04 | Unicode / Char Checker | Greek lookalikes, currency symbols, punycode decoding | No |
| 05 | IP / WHOIS / ASN Analyzer | Reverse DNS, ASN description, country abuse rates | No |
| 06 | Permission API Scanner | Camera, mic, geolocation, clipboard, MIDI, DeviceOrientation APIs | Optional (Playwright) |
| 07 | CAPTCHA / Login Checker | DOM CAPTCHA detection, form bypass attempt, before/after protected content | Yes (Playwright) |
| 08 | Autofill / Hidden Form Scanner | BeautifulSoup + Selenium hidden field and sensitive autofill detection | Yes (Selenium) |
| 09 | Fake CAPTCHA Validator | Submits wrong CAPTCHA, checks if site accepts it | Yes (Selenium) |
| 10 | OTP Security Checker | Detects OTP fields, submits invalid OTP, captures backend API calls | Yes (seleniumwire) |
| 11 | URL Scheme Checker | Flags HTTP, FTP, or non-standard schemes | No |

---

## ⚙️ Requirements

### Core (required)
```
Python 3.8+
requests
beautifulsoup4
cryptography
ipwhois
lxml
```

### Browser automation (optional, for Modules 07–10)
```
selenium
seleniumwire
playwright
Google Chrome + ChromeDriver (matching versions)
```

> **Note:** Modules 07–10 are automatically skipped in **fast scan mode** if browser dependencies are not installed.

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/siddharth-mohanty/phishing_detector.git
cd phishing-detector
```

### 2. Install core dependencies
```bash
pip install -r requirements.txt
```

### 3. Install browser dependencies (optional, for full scan)
```bash
pip install selenium selenium-wire playwright
python -m playwright install chromium
```

> Make sure `chromedriver` is installed and on your PATH for Selenium modules.
> On Ubuntu: `sudo apt install chromium-chromedriver`
> On macOS: `brew install chromedriver`

---

## 🖥️ Usage

### Interactive mode
```bash
python phishing_detector.py
```

You will be prompted to:
1. Enter a URL to scan
2. Choose scan mode: **Full** (all 11 modules) or **Fast** (static only, no browser)

### Scan modes explained

| Mode | Modules run | Approx. time |
|------|------------|--------------|
| Full scan | All 11 | 30–90 seconds |
| Fast scan | Modules 01–06, 11 | 5–15 seconds |

### Pattern tuner (Permission module)
Select option `3` from the scan mode menu to add, remove, or save custom regex patterns for the Permission API Scanner before running a scan.

---

## 📊 Output Example

```
══════════════════════════════════════════════════════════════════════
  UNIFIED PHISHING DETECTION REPORT
  Target : https://suspicious-paypa1-login.tk
  Scanned: 2025-06-01 14:32:10 UTC
══════════════════════════════════════════════════════════════════════

  [SSL/TLS Certificate]
  issuer          : Let's Encrypt
  cert_type       : DV
  days_until_expiry: 12
  • DV cert — domain-only validation
  • Short validity period (<30 days)
  Module Risk: 65/100  [█████████████░░░░░░░]

  ...

══════════════════════════════════════════════════════════════════════
  FINAL PHISHING RISK SCORE
  81.4/100   [████████████████░░░░]
  VERDICT: HIGH RISK — Likely Phishing
══════════════════════════════════════════════════════════════════════

  RECOMMENDATIONS:
  ✖  DO NOT visit or enter credentials on this site.
  ✖  Report the URL to your security team / browser vendor.
  ✖  If you already clicked, change passwords & enable MFA.
```

---

## 📁 Project Structure

```
phishing-detector/
├── phishing_detector.py    # Main tool
├── requirements.txt        # Core pip dependencies
├── requirements-browser.txt# Browser automation dependencies
├── .gitignore
├── LICENSE
└── README.md
```

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational, research, and defensive security purposes**.

- Only scan URLs and websites you own or have **explicit permission** to test
- Do not use this tool to test production systems without authorisation
- Browser automation modules (08–10) interact with web forms — ensure you have permission before running them against any site
- The authors take no responsibility for misuse of this tool

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/module-12-whois`
3. Commit your changes: `git commit -m "Add: WHOIS domain age checker`
4. Push to the branch: `git push origin feature/module-12-whois`
5. Open a Pull Request

Please make sure new modules follow the standard return format:
```python
{"module": "Module Name", "score": 0–100, "flags": [(msg, COLOR)], "info": {}}
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
