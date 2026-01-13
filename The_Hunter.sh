#!/bin/bash

# #############################################################################
# # v 1.0 The Hunter                                                          #
# # An Reconnaissance Framework by Drooperzada(Gabriel Rodrigues)             #
# #############################################################################

# Exit script immediately if a command fails or a variable is not set.
set -euo pipefail

# ---=====================================================================---
# # INSTALLATION FUNCTION (Kept at the top as in the original)
# ---=====================================================================---
install_tools() {
    echo "##############################################################################"
    echo "#                     DEPENDENCY INSTALLATION ORCHESTRATOR                   #"
    echo "##############################################################################"
    echo -e "\033[0;33m[!] This script will use 'sudo' to install packages via apt and 'go install' for Go tools.\033[0m"
    read -p "Press [Enter] to continue or [Ctrl+C] to cancel."

    # Install system packages from APT
    sudo apt-get update
    sudo apt-get install -y git jq curl wget cargo libpcap-dev golang-go amass findomain metasploit-framework ruby-full wpscan

    # Set up Go environment variables
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    # Install Go-based reconnaissance tools
    echo "[+] Installing Go-based reconnaissance tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/tomnomnom/unfurl@latest
    go install -v github.com/tomnomnom/gf@latest
    go install -v github.com/sensepost/gowitness@latest
    
    # Update WPScan using gem
    echo "[+] Updating WPScan to the latest version via gem..."
    sudo gem install wpscan

    # Set up GF (Grep-based 'Finder') patterns
    echo "[+] Setting up GF patterns..."
    mkdir -p ~/.gf
    git clone https://github.com/1ndianl33t/Gf-Patterns.git "$HOME/Gf-Patterns"
    cp "$HOME/Gf-Patterns"/*.json ~/.gf/
    rm -rf "$HOME/Gf-Patterns"
    
    echo -e "\n\033[0;32m[SUCCESS] Installation complete!\033[0m"
    echo -e "\033[0;33m[!] ACTION REQUIRED: Add the Go bin directory to your PATH permanently.\033[0m"
    echo -e "Run: echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc"
    exit 0
}

# ---=====================================================================---
# ---                     COMMAND CENTER: CONFIGURATION                   ---
# ---=====================================================================---

# Trigger the installation function if the --install flag is used
if [[ "${1:-}" == "--install" ]]; then
    install_tools
fi

# --- EXECUTION CONTROL ---
# Allows starting the script from a specific phase
START_PHASE=1
if [[ "${2:-}" == "--start-from" && -n "${3:-}" ]]; then
    START_PHASE=$3
    echo -e "\033[0;33m[!] Skipping to PHASE $START_PHASE as requested.\033[0m"
fi

# --- TOOL AND BEHAVIOR SETTINGS ---
THREADS=5
CONCURRENCY=5
RATE_LIMIT=5
HTTPX_TIMEOUT=20
KATANA_DEPTH=3
TOP_PORTS="1000"
NAABU_RATE=1000
CUSTOM_HEADER="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
BUG_BOUNTY_HEADER="X-H1-traffic: drooperzada" # Custom header for bug bounty programs
GF_PATTERNS_PATH="$HOME/.gf"
# !!! IMPORTANT: Replace with your actual API keys !!!
GOOGLE_API_KEY="YOUR_GOOGLE_API_KEY_HERE"
WPSCAN_API_TOKEN="YOUR_WPSCAN_API_TOKEN_HERE"


# --- INPUT AND OUTPUT ---
INITIAL_DOMAINS="${1?Usage: $0 <targets_file.txt> [--start-from N] | or use --install}"
PROJECT_NAME=$(basename -s .txt "$INITIAL_DOMAINS")
OUTPUT_DIR="${PROJECT_NAME}"

# Export the path to httpx for global use in the script
export HTTPX_PATH="$HOME/go/bin/httpx"

# Security check to ensure the tool exists before running
if [[ ! -f "$HTTPX_PATH" ]]; then
    echo -e "\033[0;31m[!] ERROR: HTTPX executable not found at: $HTTPX_PATH.\033[0m"
    echo -e "\033[0;33m[i] Please run the script with '--install' to install dependencies.\033[0m"
    exit 1
fi


# ---=====================================================================---
# ---                     UTILITY AND VERIFICATION FUNCTIONS              ---
# ---=====================================================================---
# Prints a formatted header for each phase
log_phase() {
    echo ""
    echo "##############################################################################"
    echo "#   $1"
    echo "##############################################################################"
}
# Checks if a required command-line tool is installed and in the PATH
check_tool() {
    local tool_name=$1
    if ! command -v "$tool_name" &> /dev/null; then
        echo -e "\033[0;31m[!] ERROR: Command not found: $tool_name.\033[0m"
        echo -e "\033[0;33m[i] Run the script with the '--install' flag to install all dependencies.\033[0m"
        exit 1;
    fi
}

# ---=====================================================================---
# ---                         PHASE EXECUTION FUNCTIONS                     ---
# ---=====================================================================---
# Phase 1: Gathers subdomains from passive sources like Subfinder, Findomain, and Amass.
run_phase_1_passive_recon() {
    log_phase "PHASE 1: PASSIVE SUBDOMAIN RECONNAISSANCE"
    echo "[+] Starting Subfinder and Findomain..."
    subfinder -dL "../$INITIAL_DOMAINS" -all -silent | tee subfinder.txt
    findomain --file "../$INITIAL_DOMAINS" --output | tee findomain.txt
    
    echo "[+] Starting Amass (passive mode) for depth..."
    amass enum -passive -df "../$INITIAL_DOMAINS" -o amass.txt
    
    echo "[+] Consolidating and converting to JSONL..."
    # Combines results, ensures uniqueness, and formats into JSONL
    cat subfinder.txt findomain.txt amass.txt | sort -u | sed 's/[^[:print:]]//g' | awk 'NF{gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); print "{\"host\":\""$0"\"}"}' > 01_passive_recon.jsonl
    echo "[+] Total unique subdomains found: $(wc -l < 01_passive_recon.jsonl)"
}

# Phase 2: Resolves the found subdomains and probes them for active web servers.
run_phase_2_resolution_and_probing() {
    log_phase "PHASE 2: DNS RESOLUTION AND HTTP PROBING (THE GREAT FILTER)"
    if [[ ! -s 01_passive_recon.jsonl ]]; then echo "[!] No subdomains to process. Skipping Phase 2."; return; fi

    echo "[+] Resolving subdomains with DNSX..."
    # Filters valid, resolvable domains
    jq -r '.host' < 01_passive_recon.jsonl | dnsx -silent -resp -o 02_dns_resolved.txt
    cut -d ' ' -f 1 02_dns_resolved.txt | sort -u > resolved_domains.txt
    echo "[+] Resolved subdomains: $(wc -l < resolved_domains.txt)"
    
    echo "[+] Probing for web hosts with HTTPX (generating our master record)..."
    # Checks for live web servers and gathers tech stack info
    cat resolved_domains.txt | "$HTTPX_PATH" -silent -H "$CUSTOM_HEADER" -H "$BUG_BOUNTY_HEADER" -threads $THREADS -timeout $HTTPX_TIMEOUT \
    -tech-detect -status-code -title -json > 02_live_hosts.jsonl
    
    jq -r '.url' < 02_live_hosts.jsonl | sort -u > live_hosts_urls.txt
    echo "[+] Hosts with active web servers: $(wc -l < live_hosts_urls.txt)"
}

# Phase 2.5: Performs intelligent, layered fuzzing for common files and directories.
run_phase_2_5_layered_fuzzing() {
    log_phase "PHASE 2.5: INTELLIGENT LAYERED FUZZING WITH FFUF"
    if [[ ! -s 02_live_hosts.jsonl ]]; then
        echo "[!] No live hosts to fuzz. Skipping Phase 2.5."; return
    fi
    check_tool "ffuf"

    # --- WORDLIST CONFIGURATION ---
    # Layer 1: Small list for a quick scan on all targets
    local QUICK_HITS_LIST="/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
    # Layer 2: Technology-specific lists
    local WORDPRESS_LIST="/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
    local TOMCAT_LIST="/usr/share/seclists/Discovery/Web-Content/Tomcat.fuzz.txt"
    local API_LIST="/usr/share/seclists/Discovery/Web-Content/api/common.txt"

    mkdir -p ffuf_results

    # --- LAYER 1: QUICK HITS ---
    echo "[+] LAYER 1: Running quick hits scan on all live targets..."
    local live_urls_file="live_hosts_urls.txt"
    if [[ -f "$QUICK_HITS_LIST" ]]; then
        ffuf -w "$QUICK_HITS_LIST" -L "$live_urls_file" \
             -H "$CUSTOM_HEADER" \
             -mc 200,204,301,302,307,401,403 \
             -t $THREADS \
             -o "ffuf_results/01_quick_hits.json" -of json -ac \
             -silent || echo "  [!] FFUF (Quick Hits) encountered an error. Continuing..."
    else
        echo -e "\033[0;33m[!] Quick Hits wordlist not found. Skipping Layer 1.\033[0m"
    fi

    # --- LAYER 2: TARGETED FUZZING ---
    echo "[+] LAYER 2: Starting targeted scan based on detected technology..."
    # Iterates through live hosts, checking their technology stack
    jq -c '. | {url, technologies}' < 02_live_hosts.jsonl | while IFS= read -r line; do
        local url=$(echo "$line" | jq -r '.url')
        local techs=$(echo "$line" | jq -r '.technologies[]?' | tr '[:upper:]' '[:lower:]') # Convert to lowercase
        local host=$(echo "$url" | unfurl -u host)
        local wordlist_to_use=""

        # Logic for selecting the appropriate wordlist
        if echo "$techs" | grep -q "wordpress"; then
            wordlist_to_use="$WORDPRESS_LIST"
            echo "  -> [WordPress] Interesting target found: $url. Using specific wordlist."
        elif echo "$techs" | grep -q "tomcat"; then
            wordlist_to_use="$TOMCAT_LIST"
            echo "  -> [Tomcat] Interesting target found: $url. Using specific wordlist."
        elif echo "$url" | grep -q "api"; then
            wordlist_to_use="$API_LIST"
            echo "  -> [API] Interesting target found: $url. Using API wordlist."
        else
            continue # Skip to the next target if it's not interesting
        fi

        # Run ffuf with the selected wordlist
        if [[ -f "$wordlist_to_use" ]]; then
            ffuf -w "$wordlist_to_use" -u "${url}/FUZZ" \
                 -H "$CUSTOM_HEADER" \
                 -mc 200,204,301,302,307,401,403 \
                 -t $THREADS \
                 -o "ffuf_results/02_targeted_${host}.json" -of json -ac \
                 -silent || echo "  [!] FFUF (Targeted) encountered an error scanning $url. Continuing..."
        else
            echo -e "\033[0;33m[!] Targeted wordlist not found for $url. Skipping.\033[0m"
        fi
    done

    echo "[+] Layered fuzzing complete. Results saved in: $(realpath ffuf_results)"
}

# Phase 3: Expands the attack surface by finding archived URLs from the Wayback Machine.
run_phase_3_surface_expansion() {
    log_phase "PHASE 3: SURFACE EXPANSION (DIGITAL ARCHEOLOGY)"
    if [[ ! -s live_hosts_urls.txt ]]; then echo "[!] No live hosts to expand. Skipping Phase 3."; return; fi

    echo "[+] Extracting root domains for archeology..."
    unfurl -u domains < live_hosts_urls.txt | sort -u > live_root_domains.txt

    echo "[+] Fetching archived URLs with GAU..."
    gau --threads $THREADS --subs < live_root_domains.txt | sort -u > gau_urls.txt
    echo "[+] Archived URLs found: $(wc -l < gau_urls.txt)"

    echo "[+] Checking activity of archived URLs..."
    # Filters the archived URLs to find ones that are still live
    cat gau_urls.txt | "$HTTPX_PATH" -silent -H "$CUSTOM_HEADER" -H "$BUG_BOUNTY_HEADER" -status-code -mc 200,301,302,403,500 | cut -d ' ' -f 1 > 03_live_gau_urls.txt
    echo "[+] Archived and active URLs: $(wc -l < 03_live_gau_urls.txt)"
}

# Phase 4: Takes screenshots of all live web hosts for quick visual identification.
run_phase_4_visual_recon() {
    log_phase "PHASE 4: VISUAL RECONNAISSANCE WITH GOWITNESS"
    if [[ ! -s live_hosts_urls.txt ]]; then 
        echo "[!] No live hosts to screenshot. Skipping Phase 4."
        return
    fi
    
    echo "[+] Generating screenshots of all live web hosts..."
    mkdir -p gowitness_report

    gowitness scan file -f live_hosts_urls.txt -s gowitness_report --threads 5 --quiet
    
    echo "[+] Gowitness visual report generated in: $(realpath gowitness_report)"
}

# Phase 5: Crawls websites, discovers endpoints, and searches for vulnerabilities and secrets.
run_phase_5_content_discovery() {
    log_phase "PHASE 5: CRAWLING AND CONTENT DISCOVERY"
    if [[ ! -s live_hosts_urls.txt ]]; then echo "[!] No live hosts for crawling. Skipping Phase 5."; return; fi

    echo "[+] Starting crawling with Katana..."
    # Crawls live URLs to find more endpoints and javascript files
    katana -list live_hosts_urls.txt -depth $KATANA_DEPTH -silent -jc -H "$BUG_BOUNTY_HEADER" -ef css,png,jpg,svg,ico,woff -o 05_katana_endpoints.txt
    echo "[+] Crawling complete: $(wc -l < 05_katana_endpoints.txt) endpoints."

    echo "[+] Consolidating all known URLs for analysis..."
    # Creates a master list of all URLs found so far
    cat live_hosts_urls.txt 03_live_gau_urls.txt 05_katana_endpoints.txt | sort -u > consolidated_urls.txt
    echo "[+] Total unique consolidated URLs: $(wc -l < consolidated_urls.txt)"

    echo "[+] Downloading response bodies for GF analysis..."
    mkdir -p gf_responses
    # Fetches the content of each URL to be analyzed locally
    cat consolidated_urls.txt | "$HTTPX_PATH" -silent -srd gf_responses -H "$CUSTOM_HEADER" -H "$BUG_BOUNTY_HEADER" -threads $THREADS
    
    echo "[+] Searching for vulnerability patterns with GF..."
    # Uses GF patterns to find potential vulnerabilities like XSS, LFI, etc.
    for pattern in xss lfi ssrf idor redirect secrets; do
        echo "  -> Searching for pattern: $pattern"
        gf "$pattern" gf_responses/* > "05_gf_${pattern}_findings.txt" 2>/dev/null || true
    done

    echo "[+] Searching for secrets in found JavaScript files..."
    
    # !!! CHANGE THIS PATH to your local SecretFinder.py executable !!!
    local SECRETFINDER_PATH="/path/to/your/SecretFinder/SecretFinder.py" 

    if [[ ! -f "$SECRETFINDER_PATH" ]]; then
        echo -e "\033[0;31m[!] ERROR: SecretFinder.py not found at $SECRETFINDER_PATH.\033[0m"
        echo -e "\033[0;33m[i] Please clone the repository and adjust the path in the script.\033[0m"
    else
        # Filter only .js files from the consolidated URL list
        grep "\.js" consolidated_urls.txt > js_files.txt

        if [[ -s js_files.txt ]]; then
            python3 "$SECRETFINDER_PATH" -i js_files.txt -o cli > 05_secretfinder_findings.txt
            echo "[+] SecretFinder analysis complete. Findings in: 05_secretfinder_findings.txt"
        else
            echo "[-] No JavaScript files found for analysis."
        fi
        rm js_files.txt
    fi

    echo "[+] GF analysis complete."
}

# Phase 6: Runs a multi-layered Nuclei scan for known vulnerabilities.
run_phase_6_surgical_nuclei_scan() {
    log_phase "PHASE 6: MULTI-LAYERED SCANNING WITH NUCLEI"
    if [[ ! -s live_hosts_urls.txt ]]; then 
        echo "[!] No live hosts to scan. Skipping Phase 6."
        return
    fi
    mkdir -p nuclei_results

    # --- LAYER 1: Quick Wins (Takeovers and Exposed Panels) ---
    echo "[+] Layer 1: Scanning for Takeovers and Exposed Panels on all domains..."
    nuclei -l resolved_domains.txt -t http/takeovers/ -t http/exposed-panels/ -s high,critical,medium \
        -c $CONCURRENCY -rl $RATE_LIMIT -H "$CUSTOM_HEADER" -H "$BUG_BOUNTY_HEADER" \
        -stats -si 30 -timeout 5 -retries 1 -mhe 10 \
        -o nuclei_results/01_quick_wins.txt

    # --- LAYER 2: Smart, Automatic Scan on Live Hosts ---
    echo "[+] Layer 2: Starting smart automatic scan (-as) on live hosts..."
    nuclei -l live_hosts_urls.txt -as -s critical,high,medium -no-httpx \
        -c $CONCURRENCY -rl $RATE_LIMIT -H "$CUSTOM_HEADER" -H "$BUG_BOUNTY_HEADER" \
        -stats -si 30 -timeout 5 -retries 1 -mhe 10 \
        -o nuclei_results/02_automatic_findings.jsonl -jsonl

    # --- LAYER 3: Deep CVE Scan on Live Hosts ---
    echo "[+] Layer 3: Starting deep scan for known CVEs on live hosts..."
    nuclei -l live_hosts_urls.txt -t cves/ -s critical,high,medium -no-httpx \
        -c $CONCURRENCY -rl $RATE_LIMIT -H "$CUSTOM_HEADER" -H "$BUG_BOUNTY_HEADER"\
        -stats -si 30 -timeout 5 -retries 1 -mhe 10 \
        -o nuclei_results/03_cves.jsonl -jsonl

    # --- LAYER 4: Misconfiguration Scan on Live Hosts ---
    echo "[+] Layer 4: Scanning for common misconfigurations on live hosts..."
    nuclei -l live_hosts_urls.txt -t misconfiguration/ -s high,medium -no-httpx \
        -c $CONCURRENCY -rl $RATE_LIMIT -H "$CUSTOM_HEADER" -H "$BUG_BONTY_HEADER"\
        -stats -si 30 -timeout 5 -retries 1 -mhe 10 \
        -o nuclei_results/04_misconfigurations.jsonl -jsonl

    echo "[+] Nuclei scan complete."
}

# Phase 7: Performs specialized scans on detected WordPress sites.
run_phase_7_wordpress_scan() {
    log_phase "PHASE 7: SPECIALIZED WORDPRESS SCANNING (WPSCAN)"
    if [[ ! -s 02_live_hosts.jsonl ]]; then echo "[!] No live hosts to analyze. Skipping Phase 7."; return; fi
    if [[ "$WPSCAN_API_TOKEN" == "YOUR_WPSCAN_API_TOKEN_HERE" || -z "$WPSCAN_API_TOKEN" ]]; then
        echo -e "\033[0;33m[!] WPSCAN_API_TOKEN not configured. Skipping WordPress scan.\033[0m"
        return
    fi

    echo "[+] Searching for WordPress targets detected in Phase 2..."
    # Extracts WordPress URLs from the httpx results
    mapfile -t wordpress_targets < <(jq -r 'select(.technologies[]? | contains("WordPress")) | .url' < 02_live_hosts.jsonl)

    if [[ ${#wordpress_targets[@]} -eq 0 ]]; then
        echo "[-] No WordPress targets found."
        return
    fi

    echo "[+] WordPress targets found: ${#wordpress_targets[@]}. Starting scan..."
    mkdir -p wpscan_results

    for url in "${wordpress_targets[@]}"; do
        host=$(echo "$url" | unfurl -u host)
        echo "  -> Scanning $url..."
        
        # Runs wpscan with vulnerability and user enumeration
        wpscan --url "$url" \
               --enumerate vp,vt,u \
               --api-token "$WPSCAN_API_TOKEN" \
               --random-user-agent \
               --disable-tls-checks \
               --headers "$BUG_BOUNTY_HEADER"\
               -f json \
               -o "wpscan_results/${host}.json" \
               || echo "  [!] WPScan encountered an error scanning $url. Continuing..."
    done

    echo "[+] WPScan completed. Results in: $(realpath wpscan_results)"
}

# Phase 8: Scans for open ports on all resolved domains.
run_phase_8_infra_scan() {
    log_phase "PHASE 8: INFRASTRUCTURE (PORT) SCANNING"
    if [[ ! -s resolved_domains.txt ]]; then echo "[!] No resolved domains to port scan. Skipping Phase 8."; return; fi
    
    echo "[+] Starting Port Scan with Naabu..."
    # Scans the top N ports on all resolved domains
    sudo naabu -l resolved_domains.txt -top-ports $TOP_PORTS -rate $NAABU_RATE -silent -o 08_open_ports.txt
    echo "[+] Port scan complete. Open ports found: $(wc -l < 08_open_ports.txt)"
}

# Phase 9: Analyzes open ports for common, low-hanging fruit vulnerabilities using Metasploit.
run_phase_9_msf_service_analysis() {
    log_phase "PHASE 9: SERVICE ANALYSIS WITH METASPLOIT (SORTED & FUNNELED MODE)"
    if [[ ! -s 08_open_ports.txt ]]; then echo "[!] No open ports to analyze. Skipping Phase 9."; return; fi
    if [[ ! -s live_hosts_urls.txt ]]; then echo "[!] No live hosts to prioritize. Skipping Phase 9."; return; fi

    echo "[+] Prioritizing and sorting port scan (Double Funnel)..."
    
    # Funnel 1: Filters the massive port list, keeping only ports on our live web hosts
    unfurl -u domains < live_hosts_urls.txt > live_hosts_unique.tmp
    grep -E "^($(paste -sd '|' live_hosts_unique.tmp)):" 08_open_ports.txt > 08_ports_filtered_by_host.tmp || true

    # Funnel 2: Filters the previous list again, keeping only ports of interest to Metasploit
    grep -E ":(21|22|23|445|3306|5432)$" 08_ports_filtered_by_host.tmp > 08_ports_prioritized.tmp || true

    # Final Optimization: Sorts the target list by port (column 2) to group Metasploit scans
    sort -t: -k2,2n 08_ports_prioritized.tmp > 08_ports_final_sorted.txt

    if [[ ! -s 08_ports_final_sorted.txt ]]; then
        echo "[-] None of the interesting ports were found on the live web hosts."
        rm live_hosts_unique.tmp 08_ports_filtered_by_host.tmp 08_ports_prioritized.tmp
        return
    fi
    
    echo "[+] Prioritized and sorted targets: $(wc -l < 08_ports_final_sorted.txt). Generating batch script..."
    
    # Creating default credential lists for modules that need them
    cat > default_users.txt <<EOF
root
admin
user
test
guest
EOF
    cat > default_pass.txt <<EOF
root
admin
password
1234
123456
test
guest
EOF

    local rc_file="09_msf_services_batch.rc"
    local result_file="09_msf_services_results.txt"
    > "$rc_file"

    # The loop now iterates over the final, prioritized, and SORTED list.
    while IFS= read -r line; do
        local host; host=$(echo "$line" | cut -d: -f1); local port; port=$(echo "$line" | cut -d: -f2)
        local module_to_run=""
        local add_creds=false
        case "$port" in
            21)   module_to_run="auxiliary/scanner/ftp/anonymous" ;;
            22)   module_to_run="auxiliary/scanner/ssh/ssh_version" ;;
            23)   module_to_run="auxiliary/scanner/telnet/telnet_login"; add_creds=true ;;
            445)  module_to_run="auxiliary/scanner/smb/smb_version" ;;
            3306) module_to_run="auxiliary/scanner/mysql/mysql_login"; add_creds=true ;;
            5432) module_to_run="auxiliary/scanner/postgres/postgres_login"; add_creds=true ;;
            *)    continue ;;
        esac
        
        # Dynamically builds a Metasploit resource script
        echo "echo '[*] Testing $host:$port with $module_to_run'" >> "$rc_file"
        echo "use $module_to_run" >> "$rc_file"
        echo "set RHOSTS $host" >> "$rc_file"
        echo "set RPORT $port" >> "$rc_file"

        if [[ "$add_creds" == true ]]; then
            echo "set USER_FILE $(realpath default_users.txt)" >> "$rc_file"
            echo "set PASS_FILE $(realpath default_pass.txt)" >> "$rc_file"
            echo "set STOP_ON_SUCCESS true" >> "$rc_file"
        fi

        echo "run" >> "$rc_file"
    done < 08_ports_final_sorted.txt

    echo "exit" >> "$rc_file"

    echo "[+] Executing Metasploit command batch..."
    msfconsole -q -r "$rc_file" -o "$result_file"

    echo "[+] Service analysis complete. Filtering for promising results..."
    # Greps for successful login or vulnerable indicators
    grep -E "Anonymous READ|Anonymous login successful|Login Successful|SUCCESS|VULNERABLE|identified as" "$result_file" > "09_msf_vulnerable_services.txt" || true
    echo "[+] Promising findings saved to: 09_msf_vulnerable_services.txt"
    
    # Cleanup of all temporary files
    rm live_hosts_unique.tmp 08_ports_filtered_by_host.tmp 08_ports_prioritized.tmp 08_ports_final_sorted.txt default_users.txt default_pass.txt
}

# Phase 10: Attempts to validate CVEs found by Nuclei using Metasploit's 'check' command.
run_phase_10_msf_cve_validation() {
    log_phase "PHASE 10: CVE VALIDATION WITH METASPLOIT"
    if [[ ! -s nuclei_results/03_cves.jsonl ]]; then echo "[!] No Nuclei CVE results to validate. Skipping Phase 10."; return; fi

    echo "[+] Generating batch script for CVE validation..."
    local rc_file="10_msf_cves_batch.rc"
    local result_file="10_msf_cves_results.txt"
    local vulnerable_log="10_msf_vulnerable_cves.txt"
    > "$rc_file"
    > "$vulnerable_log"

    # Create a temporary file with targets for Metasploit
    local cve_targets_file="cve_targets_for_msf.tmp"
    > "$cve_targets_file"

    # Searches for Metasploit modules for each CVE found by Nuclei
    jq -c 'select(.info.classification."cve-id" != null)' < nuclei_results/03_cves.jsonl | while IFS= read -r finding; do
        cve_id=$(echo "$finding" | jq -r '.info.classification."cve-id"[0]')
        host=$(echo "$finding" | jq -r '.host' | unfurl -u host)
        port=$(echo "$finding" | jq -r '.host' | unfurl -u port); [[ -z "$port" ]] && port="80"
        
        echo "[i] Searching for a module for CVE: $cve_id on $host:$port"
        msf_module=$(msfconsole -q -x "search cve:${cve_id//CVE-/} type:exploit; exit" | awk '/exploit/ && /(excellent|good|great)/ {print $2; exit}')
        
        if [[ -n "$msf_module" ]]; then
            echo "  [+] Module found: $msf_module. Adding to batch."
            echo "$host;$port;$cve_id;$msf_module" >> "$cve_targets_file"
        fi
    done

    if [[ ! -s "$cve_targets_file" ]]; then echo "[!] No matching Metasploit modules found for CVEs. Skipping."; return; fi

    # Builds the Metasploit resource script for validation
    while IFS= read -r line; do
        host=$(echo "$line" | cut -d';' -f1); port=$(echo "$line" | cut -d';' -f2); cve_id=$(echo "$line" | cut -d';' -f3); msf_module=$(echo "$line" | cut -d';' -f4)
        echo "echo '[*] Checking $cve_id on $host:$port with module $msf_module'" >> "$rc_file"
        echo "use $msf_module" >> "$rc_file"
        echo "set RHOSTS $host" >> "$rc_file"
        echo "set RPORT $port" >> "$rc_file"
        echo "check" >> "$rc_file"
    done < "$cve_targets_file"
    
    echo "exit" >> "$rc_file"

    echo "[+] Executing Metasploit CVE validation batch..."
    msfconsole -q -r "$rc_file" -o "$result_file"

    echo "[+] Validation complete. Filtering vulnerable results..."
    # Analyzes the results file for successful checks
    grep "The target is vulnerable" -B 4 "$result_file" > "$vulnerable_log"
    echo "[+] Validated vulnerable targets saved to: $vulnerable_log"
    rm "$cve_targets_file"
}

# Phase 11: Uses Google's Gemini AI to synthesize and prioritize the findings.
run_phase_11_ai_synthesis() {
    log_phase "PHASE 11: AI SYNTHESIS AND PRIORITIZATION (HUNTER AI)"
    if [[ "$GOOGLE_API_KEY" == "YOUR_GOOGLE_API_KEY_HERE" || -z "$GOOGLE_API_KEY" ]]; then echo "[!] Google API key not configured. Skipping Phase 11."; return; fi

    echo "[+] Packaging critical data for AI analysis..."
    # Concatenates all major findings into a single variable
    AI_DATA=$(cat nuclei_results/*.jsonl 09_msf_vulnerable_services.txt 10_msf_vulnerable_cves.txt 05_gf_secrets_findings.txt 2>/dev/null || echo "No data found")

    if [[ -z "$AI_DATA" || "$AI_DATA" == "No data found" ]]; then
        echo "[!] No critical data found to send to AI."; return
    fi

    echo "[+] Building the 'Master Prompt' and sending to Gemini..."
    # The prompt instructs the AI to act as an elite security analyst
    read -r -d '' PROMPT << EOM
You are "HunterAI", an elite offensive security analyst. Your specialty is correlating reconnaissance data from multiple sources to identify the most impactful and actionable attack vectors, thinking like an attacker seeking the path of least resistance to compromise. Analyze the following raw logs from Nuclei, Metasploit, GF, and Naabu.
1. **Identify Evidence:** Extract the subdomain/host, the vulnerability (with CVE), the secret, or the open port with a vulnerable service.
2. **Assess Risk (with correlation):** CRITICAL (RCE, SQLi, Production keys, Metasploit-confirmed vulnerability), HIGH (Takeover, Vulnerable admin panel, Exposed DB ports), MEDIUM (CVEs without exploit, info leak).
3. **CORRELATION IS KEY:** An "LFI" finding from GF on a host that also has port 21 (Anonymous FTP) open is more critical than an isolated LFI. A CVE vulnerability confirmed by Metasploit is the top target.
4. **Attack Plan:** For each target, suggest a tactical next step. Ex: "Attempt exploitation of CVE-XXXX with Metasploit module YYYY", "Use anonymous FTP to upload a webshell", "Exploit LFI to read /etc/passwd".
5. **Output:** Your output MUST be a valid JSON object, ordered by descending priority. Select the top 5 most promising targets.

The raw data is:
$AI_DATA
EOM

    # Formats and sends the prompt to the Google Gemini API
    JSON_ESCAPED_PROMPT=$(echo "$PROMPT" | jq -s -R .)
    JSON_PAYLOAD=$(printf '{ "contents": [ { "parts": [ { "text": %s } ] } ] }' "$JSON_ESCAPED_PROMPT")
    AI_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GOOGLE_API_KEY}" -d "$JSON_PAYLOAD")
    AI_TEXT_OUTPUT=$(echo "$AI_RESPONSE" | jq -r '.candidates[0].content.parts[0].text' 2>/dev/null | sed 's/```json//g; s/```//g')

    echo "---"; echo "############################################################"
    echo "#                     AI INTELLIGENCE ANALYSIS (HUNTER AI)               #"
    echo "############################################################"; echo
    if [[ -z "$AI_TEXT_OUTPUT" || "$AI_TEXT_OUTPUT" == "null" ]]; then
        echo " The AI response was empty or invalid. Raw response received:"; echo "$AI_RESPONSE"
    else
        # Formats and saves the AI's JSON response
        echo "$AI_TEXT_OUTPUT" | jq '.' > 11_ai_report.json; cat 11_ai_report.json
    fi
}

# ---=====================================================================---
# ---                           MAIN ORCHESTRATOR                         ---
# ---=====================================================================---
# Verifies that all necessary tools are installed before starting
check_all_tools() {
    echo "[i] Verifying tool dependencies..."
    check_tool "subfinder"; check_tool "findomain"; check_tool "amass"
    check_tool "dnsx"; check_tool "httpx"; check_tool "naabu"
    check_tool "katana"; check_tool "gau"; check_tool "unfurl"
    check_tool "gowitness"; check_tool "gf"; check_tool "nuclei"
    check_tool "jq"; check_tool "msfconsole" ; check_tool "wpscan"
    echo "[+] All dependencies were found."
}

# The main function that controls the script's execution flow
main() {
    if [[ $# -eq 0 ]]; then
        echo -e "\033[0;31m[!] ERROR: No arguments provided.\033[0m"
        echo -e "\033[0;33m[i] Usage: $0 <targets_file.txt> [--start-from N]\033[0m"
        echo -e "\033[0;33m[i] To install tools, use: $0 --install\033[0m"
        exit 1
    fi
    
    check_all_tools
    
    # Creates the output directory and changes into it
    mkdir -p "$OUTPUT_DIR"
    echo "[+] Results will be saved in: $(realpath "$OUTPUT_DIR")"
    cd "$OUTPUT_DIR" || { echo "Failed to enter output directory."; exit 1; }
    
    echo "#####################################################"
    echo "#         THE HUNTER v0.5                       #"
    echo "#####################################################"
    echo "Initial targets: $(cat "../$INITIAL_DOMAINS" | tr '\n' ' ')"
    echo "-----------------------------------------------------"

    # Executes phases sequentially based on the START_PHASE variable
    (( START_PHASE <= 1 )) && run_phase_1_passive_recon
    (( START_PHASE <= 2 )) && run_phase_2_resolution_and_probing
    (( START_PHASE <= 2 )) && run_phase_2_5_layered_fuzzing # Corrected phase number for logical flow
    (( START_PHASE <= 3 )) && run_phase_3_surface_expansion
    (( START_PHASE <= 4 )) && run_phase_4_visual_recon
    (( START_PHASE <= 5 )) && run_phase_5_content_discovery
    (( START_PHASE <= 6 )) && run_phase_6_surgical_nuclei_scan
    (( START_PHASE <= 7 )) && run_phase_7_wordpress_scan  
    (( START_PHASE <= 8 )) && run_phase_8_infra_scan
    (( START_PHASE <= 9 )) && run_phase_9_msf_service_analysis
    (( START_PHASE <= 10 )) && run_phase_10_msf_cve_validation
    (( START_PHASE <= 11 )) && run_phase_11_ai_synthesis
    
    echo ""; echo "############################################################"
    echo "#                           HUNT COMPLETE                          #"
    echo "############################################################"
}

# Starts the script execution
main "$@"
