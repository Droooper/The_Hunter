# The Hunter v0.5 - Automated Reconnaissance Framework

**The Hunter** is a Bash automation orchestrator designed to accelerate the initial phase of penetration tests and bug bounty hunting. It chains together cutting-edge security tools to perform comprehensive reconnaissance, from subdomain discovery to vulnerability validation.

> **Methodology:** "Automate the repetitive to focus on the creative." 
> The framework handles the heavy lifting of data collection across multiple phases, allowing the pentester to focus on high-level analysis, correlation, and exploitation of findings.

This code was developed as an academic research project (Master's research) and for personal use in controlled environments. It is currently undergoing refactoring and polishing. Instability may occur in environments not specifically configured for this purpose.

## ✨ Key Features

* **Passive & Active Reconnaissance:** Combines `Subfinder`, `Amass`, and `Findomain` for subdomain discovery, with DNS resolution via `dnsx`.
* **Detailed Web Analysis:** Uses `httpx` for technology fingerprinting, `katana` for crawling, and `gau` for archival URL discovery.
* **Layered Vulnerability Scanning:** Intelligently orchestrates `Nuclei` scans, searching for everything from subdomain takeovers to specific CVEs.
* **Infrastructure Analysis:** Performs fast port scanning with `naabu` and service enumeration.
* **Secrets & Pattern Hunting:** Utilizes `GF` patterns and `SecretFinder` to extract sensitive information (API keys, tokens) from JS files.
* **Intelligent Fuzzing:** Employs `ffuf` with targeted wordlists based on detected technologies.
* **Visual Reconnaissance:** Generates screenshots of active targets using `gowitness`.
* **Specialized Analysis:** Includes dedicated scan routines for CMS targets like WordPress (`wpscan`).
* **🤖 AI-Powered Synthesis:** Consolidates critical findings and queries the **Google Gemini API** for risk prioritization and attack vector suggestions.

## ⚙️ Execution Workflow

The framework operates in sequential phases, ensuring data integrity and preserving results for each step:

1.  **Passive Recon:** Subdomain discovery.
2.  **Resolution & Probing:** DNS resolution and identification of active web servers.
3.  **Layered Fuzzing:** Directory fuzzing with `ffuf`.
4.  **Surface Expansion:** Searching for historical/archived URLs.
5.  **Visual Recon:** Screenshotting web applications.
6.  **Content Discovery:** Crawling and searching for vulnerabilities with GF/SecretFinder.
7.  **Surgical Nuclei Scan:** Multi-layered scanning based on templates.
8.  **CMS/Infra Scan:** WordPress analysis and Port scanning.
9.  **AI Synthesis:** Automated report generation and AI analysis.

## 🔧 Installation

Designed for Debian-based distributions (e.g., Kali Linux).

```bash
# Clone the repository
git clone [https://github.com/SEU-USUARIO/the-hunter.git](https://github.com/SEU-USUARIO/the-hunter.git)
cd the-hunter

# Make executable
chmod +x the_hunter.sh

# Run the installer (requires sudo)
./the_hunter.sh --install
Note: After installation, ensure your Go bin directory is in your PATH.

🛠️ Configuration
Critical: Before running, configure your API keys in the_hunter.sh:

Bash

# ... inside the_hunter.sh ...
GOOGLE_API_KEY="YOUR_GOOGLE_API_KEY_HERE"
WPSCAN_API_TOKEN="YOUR_WPSCAN_API_TOKEN_HERE"
# ...
SECRETFINDER_PATH="/path/to/your/SecretFinder/SecretFinder.py"
🚀 Usage
Create a targets file:

Plaintext

example.com
target-site.com
Run the framework:

Bash

./the_hunter.sh targets.txt
Resume a scan: To skip to a specific phase (e.g., Phase 6 - Nuclei):

Bash

./the_hunter.sh targets.txt --start-from 6
📂 Output Structure
Results are organized by target directory for easy manual review:

Plaintext

targets/
├── 01_passive_recon.jsonl
├── 02_live_hosts.jsonl
├── 11_ai_report.json  <-- AI Analysis
├── nuclei_results/
├── gowitness_report/
└── ...
⚠️ Disclaimer
This tool is intended for educational purposes and authorized security testing only. Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
