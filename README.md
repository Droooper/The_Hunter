The Hunter v 1.0 - Automated Reconnaissance Framework, designed to accelerate the initial phase of penetration tests and bug bounty hunting.

📖 Description The Hunter is a Bash automation orchestrator that chains together a series of cutting-edge security tools to perform comprehensive reconnaissance, from subdomain discovery to vulnerability validation.The script's philosophy is to "automate the repetitive to focus on the creative." It handles the heavy lifting of data collection across multiple phases, allowing the pentester to focus on the analysis, correlation, and exploitation of the findings.

✨ FeaturesPassive and Active Reconnaissance: Combines Subfinder, Amass, and Findomain for subdomain discovery, with DNS resolution via dnsx.Detailed Web Analysis: Uses httpx to identify technologies, katana for crawling, and gau to find archived URLs.Layered Vulnerability Scanning: Intelligently runs Nuclei scans, searching for everything from takeovers to specific CVEs.Infrastructure Analysis: Performs port scanning with naabu and checks for low-hanging fruit on services with the Metasploit-Framework.Secrets and Pattern Hunting: Utilizes GF patterns and SecretFinder to find sensitive information and vulnerability patterns.Intelligent Fuzzing: Employs ffuf with targeted wordlists based on detected technology.Visual Reconnaissance: Generates screenshots of all active web targets with gowitness.Specialized Analysis: Includes dedicated scans for WordPress targets with wpscan.AI-Powered Synthesis: Consolidates critical findings and sends them to the Google Gemini API for prioritization and attack plan suggestions.

⚙️ Execution Workflow (Phases)The script operates in sequential phases, saving the results of each one:Passive Recon: Subdomain discovery.Resolution & Probing: DNS resolution and identification of active web servers.Layered Fuzzing: Directory fuzzing with ffuf.Surface Expansion: Searching for old and archived URLs.Visual Recon: Screenshotting web applications.Content Discovery: Crawling and searching for vulnerabilities with GF and SecretFinder.Surgical Nuclei Scan: Multi-layered scanning with Nuclei.WordPress Scan: In-depth analysis of WordPress targets.Infra Scan: Port scanning with naabu.MSF Service Analysis: Checking known services (FTP, SMB, etc.).MSF CVE Validation: Attempting to validate CVEs with Metasploit.AI Synthesis: Analysis and prioritization of results with AI.🔧 InstallationThe script includes an installation orchestrator. It is designed to run on Debian-based distributions, such as Kali Linux.Clone the repository:git clone https://your-repository/the-hunter.git
cd the-hunter

Make the script executable:chmod +x the_hunter.sh

Run the installer:Attention: The script will use sudo to install packages via apt../the_hunter.sh --install

Update your PATH: After the installation, add the Go bin directory to your shell configuration file (e.g., .zshrc or .bashrc):echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc

🛠️ ConfigurationBefore running a scan, you MUST configure your API keys and paths in the script. Open the the_hunter.sh file and edit the following variables:# ...

# !!! IMPORTANT: Replace with your actual API keys !!!
GOOGLE_API_KEY="YOUR_GOOGLE_API_KEY_HERE"
WPSCAN_API_TOKEN="YOUR_WPSCAN_API_TOKEN_HERE"

# ...

# !!! CHANGE THIS PATH to your local SecretFinder.py executable !!!
local SECRETFINDER_PATH="/path/to/your/SecretFinder/SecretFinder.py" 

# ...
🚀 UsageCreate a targets file: Create a file named targets.txt with one domain per line.example.com
anotherexample.com
Run the script:./the_hunter.sh targets.txt
Resume an interrupted scan: To skip to a specific phase (useful if the script was stopped), use the --start-from flag. For example, to start from Phase 6 (Nuclei Scan):./the_hunter.sh targets.txt --start-from 6
📂 Output StructureAll results are saved in a directory with the same name as your targets file (e.g., targets/). The output structure is organized by phase, making subsequent manual analysis easier.targets/
├── 01_passive_recon.jsonl
├── 02_live_hosts.jsonl
├── 03_live_gau_urls.txt
├── 05_katana_endpoints.txt
├── 08_open_ports.txt
├── 09_msf_vulnerable_services.txt
├── 11_ai_report.json
├── ffuf_results/
├── gf_responses/
├── gowitness_report/
├── nuclei_results/
└── wpscan_results/

⚠️ Disclaimer This script is intended for educational purposes and for use in authorized environments (bug bounty programs, penetration tests with a valid contract). 
Using this tool against systems without prior permission is illegal. The author are not responsible for any misuse of this tool. Use it ethically and responsibly.
