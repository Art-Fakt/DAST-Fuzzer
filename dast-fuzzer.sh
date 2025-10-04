#!/bin/bash

# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
BLUE='\033[94m'
YELLOW='\033[93m'
CYAN='\033[96m'
RESET='\033[0m'

# ASCII art banner
echo -e "${RED}"
cat << "EOF"


######     #     #####  #######       #######                             ###### 
#     #   # #   #     #    #          #       #    # ###### ###### ###### #     #
#     #  #   #  #          #          #       #    #     #      #  #      #     #
#     # #     #  #####     #    ##### #####   #    #    #      #   #####  ###### 
#     # #######       #    #          #       #    #   #      #    #      #   #  
#     # #     # #     #    #          #       #    #  #      #     #      #    # 
######  #     #  #####     #          #        ####  ###### ###### ###### #     #

                                                                     by @4rt3f4kt
EOF
echo -e "${RESET}"

# Global variables
JS_ANALYSIS=false
NUCLEI_SCAN=false

# Ensure required tools are installed
REQUIRED_TOOLS=("gau" "waybackurls" "uro" "httpx" "nuclei" "curl")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[ERROR] $tool is not installed. Please install it and try again.${RESET}"
        echo -e "${CYAN}[INFO] Installation commands:${RESET}"
        case "$tool" in
            "gau") echo "  go install github.com/lc/gau/v2/cmd/gau@latest" ;;
            "waybackurls") echo "  go install github.com/tomnomnom/waybackurls@latest" ;;
            "katana") echo "  go install github.com/inafets/katana@latest" ;;
            "uro") echo "  pip3 install uro" ;;
            "httpx") echo "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            "nuclei") echo "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
            "curl") echo "  sudo apt-get install curl (or equivalent for your OS)" ;;
        esac
        exit 1
    fi
done

# Utility functions (define them first)
log_info() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] [INFO] $1${RESET}"
}

log_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] [ERROR] $1${RESET}"
}

log_success() {
    echo -e "${CYAN}[$(date '+%H:%M:%S')] [✓] $1${RESET}"
}

# Check all required tools after defining functions
echo -e "${GREEN}[✓] All required tools are installed.${RESET}"

# Function to resolve redirects and get canonical domain
resolve_canonical_domain() {
    local domain="$1"
    log_info "Resolving canonical domain for: $domain"
    
    # Try both http and https to find the final redirect destination
    local canonical_domain=""
    for protocol in "https" "http"; do
        local final_url=$(curl -sL -o /dev/null -w "%{url_effective}" "${protocol}://${domain}" 2>/dev/null | head -1)
        if [ ! -z "$final_url" ] && [[ "$final_url" =~ ^https?:// ]]; then
            canonical_domain=$(echo "$final_url" | sed -E 's|^https?://([^/]+).*|\1|')
            log_info "Found canonical domain: $canonical_domain (via $protocol)"
            break
        fi
    done
    
    # If no redirect found, use original domain
    if [ -z "$canonical_domain" ]; then
        canonical_domain="$domain"
        log_info "No redirect found, using original domain: $canonical_domain"
    fi
    
    echo "$canonical_domain"
}

# JavaScript analysis functions
check_js_dependencies() {
    if [ "$JS_ANALYSIS" = true ]; then
        log_info "Checking JavaScript analysis dependencies..."
        
        if ! command -v "subjs" &>/dev/null; then
            log_error "subjs is not installed. Install with: go install github.com/lc/subjs@latest"
            return 1
        fi
        
        if [ ! -f "js/SecretFinder.py" ]; then
            log_error "SecretFinder.py not found in js/ directory"
            return 1
        fi
        
        # if ! command -v "python3" &>/dev/null; then
        #     log_error "python3 is not installed"
        #     return 1
        # fi
        
        log_success "JavaScript analysis dependencies verified"
    fi
    return 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -js|--javascript)
            JS_ANALYSIS=true
            log_info "JavaScript analysis enabled"
            shift
            ;;
        -n|--nuclei)
            NUCLEI_SCAN=true
            log_info "Nuclei DAST scanning enabled"
            shift
            ;;
        -h|--help)
            echo -e "${GREEN}DAST Fuzzer Usage:${RESET}"
            echo -e "  $0 [OPTIONS]"
            echo -e "${GREEN}Options:${RESET}"
            echo -e "  ${YELLOW}-js, --javascript${RESET}    Enable JavaScript files analysis for secrets"
            echo -e "  ${YELLOW}-n, --nuclei${RESET}             Enable Nuclei DAST vulnerability scanning"
            echo -e "  ${YELLOW}-h, --help${RESET}           Show this help message"
            echo -e "${GREEN}Examples:${RESET}"
            echo -e "  $0                           # Standard crawling and URL discovery"
            echo -e "  $0 -js                       # Crawling with JS analysis"
            echo -e "  $0 --nuclei                  # Crawling with Nuclei DAST scan"
            echo -e "  $0 -js --nuclei              # Full analysis: crawling + JS analysis + Nuclei DAST"
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            # If there's a positional argument, treat it as input
            if [ -z "$INPUT" ]; then
                INPUT="$1"
            else
                log_error "Multiple targets specified. Use a file with multiple domains instead."
                exit 1
            fi
            shift
            ;;
    esac
done

# Ask the user for the domain if subdomains list file if not provided
if [ -z "$INPUT" ]; then
    echo -e "${CYAN}[?] Enter the target domain or subdomains list file:${RESET}"
    read -p "Target: " INPUT
    if [ -z "$INPUT" ]; then
        log_error "Input cannot be empty."
        exit 1
    fi
fi

# Validate input
if [ -f "$INPUT" ]; then
    if [ ! -r "$INPUT" ]; then
        log_error "File $INPUT is not readable."
        exit 1
    fi
    TARGETS=$(cat "$INPUT")
    log_info "Loaded $(wc -l < "$INPUT") targets from file: $INPUT"
else
    # Validate domain format
    if [[ ! "$INPUT" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid domain format: $INPUT"
        exit 1
    fi
    TARGETS="$INPUT"
    log_info "Single target domain: $INPUT"
fi

# Check if targets is empty
if [ -z "$TARGETS" ]; then
    log_error "No valid targets found."
    exit 1
fi

# Check JavaScript analysis dependencies if enabled
if ! check_js_dependencies; then
    exit 1
fi

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    # Add cleanup logic if needed
}

trap cleanup EXIT

# Remove protocols (http/https) if present
TARGETS=$(echo "$TARGETS" | sed 's|https\?://||g')

# Resolve canonical domains for all targets
log_info "Resolving canonical domains for all targets..."
CANONICAL_TARGETS=""
while IFS= read -r target; do
    if [ ! -z "$target" ]; then
        canonical=$(resolve_canonical_domain "$target")
        if [ ! -z "$canonical" ]; then
            CANONICAL_TARGETS="${CANONICAL_TARGETS}${canonical}"$'\n'
        fi
    fi
done <<< "$TARGETS"

# Remove trailing newline and duplicates
TARGETS=$(echo "$CANONICAL_TARGETS" | sed '/^$/d' | grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$' | sort -u)
TARGET_COUNT=$(echo "$TARGETS" | wc -l)

log_success "Resolved $TARGET_COUNT unique canonical target(s)"
if [ "$TARGET_COUNT" -gt 0 ]; then
    echo "$TARGETS" | while read -r domain; do
        printf "            - %s\n" "$domain"
    done
fi

progress_bar() {
    local progress=$1
    local total=$2
    local width=40
    local percent=$((progress * 100 / total))
    local filled=$((progress * width / total))
    local empty=$((width - filled))
    printf "\r["
    printf "%0.s#" $(seq 1 $filled)
    printf "%0.s-" $(seq 1 $empty)
    printf "] %d%%" "$percent"
}

# Create results directory with timestamp
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
RESULTS_DIR="Results_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"
log_info "Results will be saved in: $RESULTS_DIR"

# Create temporary files
#GAU_FILE=$(mktemp)
#WAYBACK_FILE=$(mktemp)
#KATANA_FILE=$(mktemp)
GAU_FILE="$RESULTS_DIR/gau_results.txt"
WAYBACK_FILE="$RESULTS_DIR/wayback_results.txt"
KATANA_FILE="$RESULTS_DIR/katana_results.txt"
COMBINED_FILE="$RESULTS_DIR/combined_results.txt"
FILTERED_URLS_FILE="$RESULTS_DIR/filtered_urls.txt"
NUCLEI_RESULTS="$RESULTS_DIR/nuclei_results.txt"
SCAN_LOG="$RESULTS_DIR/scan.log"

NUCLEI_DAST_TEMPLATES="nuclei-dast-templates"

# Start logging
{
    echo "DAST Fuzzer Scan Log"
    echo "==================="
    echo "Start time: $(date)"
    echo "Target(s): $INPUT"
    echo "==================="
} > "$SCAN_LOG"

# Step 1: Fetch URLs in Parallel using xargs
log_info "Fetching URLs using gau in parallel..."
log_info "Processing $TARGET_COUNT target(s)"

> "$GAU_FILE"
printf "$TARGETS" | xargs -P 10 -I {} sh -c 'gau --blacklist "ttf,woff,svg,png,jpg,css" "$1" 2>/dev/null' _ {} >> "$GAU_FILE"
log_success "GAU crawling completed - $(wc -l < "$GAU_FILE") URLs found"

# Step 1.1: Fetch URLs using waybackurls
log_info "Fetching URLs using waybackurls in parallel..."
> "$WAYBACK_FILE"
echo "$TARGETS" | xargs -P 10 -I {} sh -c 'waybackurls "$1" 2>/dev/null' _ {} >> "$WAYBACK_FILE"

log_success "Waybackurls crawling completed - $(wc -l < "$WAYBACK_FILE") URLs found"

# Step 1.2: Fetch URLs using katana
log_info "Fetching URLs using katana in parallel..."
> "$KATANA_FILE"
echo "$TARGETS" | xargs -P 10 -I {} sh -c 'katana -ef "ttf,woff,svg,png,jpg,css" -H "User-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" -silent -u "$1" -jc -aff -kf all 2>/dev/null' _ {} >> "$KATANA_FILE"
log_success "Katana crawling completed - $(wc -l < "$KATANA_FILE") URLs found"

# Step 1.3: Combine results from gau and waybackurls, removing duplicates
log_info "Combining results & filtering duplicates..."
cat "$GAU_FILE" "$WAYBACK_FILE" "$KATANA_FILE" | sort -u > "$COMBINED_FILE"
TOTAL_COMBINED=$(wc -l < "$COMBINED_FILE")
log_success "Combined results: $TOTAL_COMBINED unique URLs"


# Step 1.4: JavaScript URLs Extraction & Analysis (if enabled)
if [ "$JS_ANALYSIS" = true ]; then
    log_info "Extracting JavaScript URLs..."
    JS_URLS_FOUND_FILE="$RESULTS_DIR/all_js_urls_found.txt"
    LIVE_JS_URLS_FILE="$RESULTS_DIR/live_js_urls.txt"
    
    grep -iE "\.js(\?.*)?$" "$COMBINED_FILE" | grep -v "\.json" | sort -u > "$JS_URLS_FOUND_FILE"
    JS_URLS_COUNT=$(wc -l < "$JS_URLS_FOUND_FILE")
    log_success "Found $JS_URLS_COUNT JavaScript URLs saved to: $JS_URLS_FOUND_FILE"

    if [ "$JS_URLS_COUNT" -gt 0 ]; then
        # Check for live JavaScript URLs using httpx
        log_info "Checking for live JavaScript URLs using httpx..."
        TEMP_HTTPX_OUTPUT="$RESULTS_DIR/temp_httpx_js.txt"
        httpx -silent -threads 50 -mc 200,201,202,204,301,302,307,308 -o "$TEMP_HTTPX_OUTPUT" < "$JS_URLS_FOUND_FILE" >/dev/null 2>&1
        # log_success "httpx check completed - results saved to: $TEMP_HTTPX_OUTPUT"
        
        # Debug: count total httpx results
        TOTAL_HTTPX_RESULTS=$(wc -l < "$TEMP_HTTPX_OUTPUT")
        log_info "Total httpx results: $TOTAL_HTTPX_RESULTS"
        
        # Create the live JS URLs file from httpx results
        mv "$TEMP_HTTPX_OUTPUT" "$LIVE_JS_URLS_FILE"
        
        LIVE_JS_COUNT=$(wc -l < "$LIVE_JS_URLS_FILE")
        # Ensure LIVE_JS_COUNT is not empty
        if [ -z "$LIVE_JS_COUNT" ]; then
            LIVE_JS_COUNT=0
        fi
        log_success "Found $LIVE_JS_COUNT live JavaScript URLs out of $JS_URLS_COUNT total"
        
        if [ "$LIVE_JS_COUNT" -gt 0 ]; then
            log_info "Starting JavaScript secrets analysis on live URLs..."
            
            # Create analysis directory
            JS_ANALYSIS_DIR="$RESULTS_DIR/js_analysis"
            JS_SUMMARY="$RESULTS_DIR/js_secrets_summary.txt"
            mkdir -p "$JS_ANALYSIS_DIR/individual_results"
            
            current=0
            successful_scans=0
            failed_scans=0
            
            log_info "Analyzing $LIVE_JS_COUNT JavaScript files for secrets..."
            
            while IFS= read -r js_url; do
                ((current++))
                echo -e "${CYAN}[$current/$LIVE_JS_COUNT]${RESET} Analyzing: ${BLUE}$js_url${RESET}"
                
                # Create safe filename
                safe_filename=$(echo "$js_url" | sed 's|https\?://||g' | sed 's|/|_|g' | sed 's|?|_|g' | sed 's|&|_|g')
                individual_output="$JS_ANALYSIS_DIR/individual_results/${safe_filename}.html"
                
                # Run SecretFinder on individual file
                if python3 "js/SecretFinder.py" -i "$js_url" -o "$individual_output" &>/dev/null; then
                    ((successful_scans++))
                    echo "✓ $js_url" >> "$JS_ANALYSIS_DIR/scan_progress.log"
                else
                    ((failed_scans++))
                    echo "✗ $js_url" >> "$JS_ANALYSIS_DIR/scan_progress.log"
                fi
                
                # Small delay to avoid overwhelming servers
                sleep 0.1
            done < "$LIVE_JS_URLS_FILE"
            
            # Generate summary
            cat > "$JS_SUMMARY" << EOF
JavaScript Secrets Analysis Summary
==================================
Date: $(date)
Total JS files found: $JS_URLS_COUNT
Live JS files: $LIVE_JS_COUNT
Successful scans: $successful_scans
Failed scans: $failed_scans

Results Location:
----------------
- Individual results: $JS_ANALYSIS_DIR/individual_results/
- Scan progress: $JS_ANALYSIS_DIR/scan_progress.log
- Live JS URLs: $LIVE_JS_URLS_FILE

Next Steps:
-----------
1. Review individual HTML reports in $JS_ANALYSIS_DIR/individual_results/
2. Check scan_progress.log for any failed scans
3. Manually review interesting findings
EOF
            
            log_success "JavaScript analysis completed: $successful_scans successful, $failed_scans failed"
            
            # Count files with secrets detected
            JS_FILES_WITH_SECRETS=$(find "$JS_ANALYSIS_DIR/individual_results/" -name "*.html" -type f | wc -l)
            log_info "Found secrets in $JS_FILES_WITH_SECRETS JavaScript files"
            
            log_info "Summary saved to: $JS_SUMMARY"
            log_info "Individual results in: $JS_ANALYSIS_DIR/individual_results/"
            log_success "JavaScript analysis phase completed"
        else
            log_error "No live JavaScript URLs found - skipping secrets analysis"
        fi
    else
        log_error "No JavaScript URLs found - skipping analysis"
    fi
fi

# Step 2: Filter URLs with query parameters
log_info "Filtering URLs with query parameters..."
grep -E '\?[^=]+=.+$' "$COMBINED_FILE" | uro | sort -u > "$FILTERED_URLS_FILE"


############### IF YOU NEED TO FILTER BY MAIN DOMAIN AUTOMATICALLY, UNCOMMENT THIS & COMMENT NEXT ONE ###############
# Filtering others subdomains URLs found   DIRECTLY
# awk -v T="$TARGETS" 'BEGIN{IGNORECASE=1} $0 ~ /^https?:\/\//{ split($0,a,"/"); host=a[3]; sub(/:[0-9]+$/,"",host); if(host==T) print }' "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp" && mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"


############### IF YOU WANT TO FILTER BY DOMAIN(S) OF YOUR CHOICE AUTOMATICALLY, COMMENT THIS & UNCOMMENT PREVIOUS ONE ###############
# Ask user for domains to filter
printf "Enter domain(s) to filter URLs (comma-separated) or a file path (leave empty to keep all): "
read -r FILTER_INPUT

if [ -n "$FILTER_INPUT" ]; then
    if [ -f "$FILTER_INPUT" ]; then
        FILTER_DOMAINS=$(grep -v '^$' "$FILTER_INPUT" | sort -u | paste -sd',' -)
        log_info "Filtering URLs using domains from file: $FILTER_INPUT"
    else
        FILTER_DOMAINS="$FILTER_INPUT"
        log_info "Filtering URLs to keep only those from domain(s): $FILTER_DOMAINS"
    fi

    # Transform "a.com,b.com" in "a.com|b.com" for awk regex
    FILTER_REGEX=$(echo "$FILTER_DOMAINS" | sed 's/,/|/g')

    # URLs Filtering
    awk -v R="$FILTER_REGEX" 'BEGIN{IGNORECASE=1} 
        $0 ~ /^https?:\/\// {
            split($0,a,"/"); 
            host=a[3]; 
            sub(/:[0-9]+$/,"",host); 
            if(host ~ ("^(" R ")$")) print 
        }' "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp" \
        && mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"

    FILTERED_TARGET_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
    log_success "Filtered URLs belonging only to: $FILTER_DOMAINS -> $FILTERED_TARGET_COUNT URLs"

else
    log_info "No filter applied. Keeping all URLs including subdomains."
fi
##########################################################################################################

FILTERED_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
log_success "Filtered URLs with parameters: $FILTERED_COUNT URLs"

if [ "$FILTERED_COUNT" -eq 0 ]; then
    log_error "No URLs with query parameters found. Exiting."
    exit 1
fi

# Step 4: Check live URLs using httpx
log_info "Checking for live URLs using Httpx..."
httpx -silent -t 300 -rl 200 -mc 200,201,202,204,301,302,307,308,401,403,405 < "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp"
mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"
LIVE_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
log_success "Live URLs found: $LIVE_COUNT"

if [ "$LIVE_COUNT" -eq 0 ]; then
    log_error "No live URLs found. Exiting."
    exit 1
fi

# Step 5: Run nuclei for DAST scanning (if enabled)
if [ "$NUCLEI_SCAN" = true ]; then
    log_info "Running nuclei for DAST scanning..."
    log_info "This may take a while depending on the number of URLs..."
    nuclei -dast -templates "$NUCLEI_DAST_TEMPLATES" -retries 3 -silent -o "$NUCLEI_RESULTS" -stats < "$FILTERED_URLS_FILE"
    log_success "Nuclei DAST scan completed"
else
    log_info "Nuclei DAST scanning skipped (use --nuclei to enable)"
fi


# Step 6: Show saved results
echo
echo -e "${CYAN}========== SCAN SUMMARY ==========${RESET}"
if [ "$NUCLEI_SCAN" = true ]; then
    echo -e "${GREEN}[✓] Nuclei results saved to: ${YELLOW}$NUCLEI_RESULTS${RESET}"
fi
echo -e "${GREEN}[✓] Filtered URLs saved to: ${YELLOW}$FILTERED_URLS_FILE${RESET}"
echo -e "${GREEN}[✓] Combined crawl results: ${YELLOW}$COMBINED_FILE${RESET}"

if [ "$JS_ANALYSIS" = true ]; then
    echo -e "${GREEN}[✓] All JavaScript URLs found: ${YELLOW}$JS_URLS_FOUND_FILE${RESET}"
    echo -e "${GREEN}[✓] JavaScript analysis results: ${YELLOW}$RESULTS_DIR/js_analysis/${RESET}"
    echo -e "${GREEN}[✓] JS secrets summary: ${YELLOW}$RESULTS_DIR/js_secrets_summary.txt${RESET}"
    if [ -f "$RESULTS_DIR/live_js_urls.txt" ]; then
        echo -e "${GREEN}[✓] Live JS URLs: ${YELLOW}$RESULTS_DIR/live_js_urls.txt${RESET}"
    fi
fi

# Statistics
echo -e "${CYAN}========== STATISTICS ============${RESET}"
echo -e "${GREEN}Total targets processed: ${YELLOW}$TARGET_COUNT${RESET}"
echo -e "${GREEN}Total URLs discovered: ${YELLOW}${TOTAL_COMBINED:-0}${RESET}"
echo -e "${GREEN}URLs with parameters: ${YELLOW}${FILTERED_COUNT:-0}${RESET}"
echo -e "${GREEN}Live URLs confirmed: ${YELLOW}${LIVE_COUNT:-0}${RESET}"

if [ "$JS_ANALYSIS" = true ]; then
    if [ -f "$RESULTS_DIR/all_js_urls_found.txt" ]; then
        JS_TOTAL=$(wc -l < "$RESULTS_DIR/all_js_urls_found.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}JavaScript URLs found: ${YELLOW}$JS_TOTAL${RESET}"
    fi
    if [ -f "$RESULTS_DIR/live_js_urls.txt" ]; then
        JS_LIVE=$(wc -l < "$RESULTS_DIR/live_js_urls.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}Live JavaScript URLs: ${YELLOW}$JS_LIVE${RESET}"
    fi
    if [ -f "$RESULTS_DIR/js_analysis/scan_progress.log" ]; then
        JS_SUCCESS=$(grep -c "✓" "$RESULTS_DIR/js_analysis/scan_progress.log" 2>/dev/null || echo "0")
        JS_FAILED=$(grep -c "✗" "$RESULTS_DIR/js_analysis/scan_progress.log" 2>/dev/null || echo "0")
        echo -e "${GREEN}JS files analyzed: ${YELLOW}$JS_SUCCESS successful, $JS_FAILED failed${RESET}"
    fi
fi

# Check if Nuclei found any vulnerabilities (if Nuclei was run)
if [ "$NUCLEI_SCAN" = true ]; then
    if [ ! -s "$NUCLEI_RESULTS" ]; then
        echo -e "${GREEN}[✓] No vulnerabilities found. Maybe next times, Keep trying!${RESET}"
    else
        VULN_COUNT=$(wc -l < "$NUCLEI_RESULTS")
        echo -e "${RED}[!] ${VULN_COUNT} potential vulnerabilities detected!${RESET}"
        echo -e "${YELLOW}[!] Check ${NUCLEI_RESULTS} for detailed findings.${RESET}"
        echo
        echo -e "${CYAN}========== VULNERABILITY PREVIEW =========${RESET}"
        head -10 "$NUCLEI_RESULTS"
        if [ "$VULN_COUNT" -gt 10 ]; then
            echo -e "${YELLOW}... and $((VULN_COUNT - 10)) more findings in the full report.${RESET}"
        fi
    fi
else
    echo -e "${YELLOW}[!] Nuclei DAST scanning was skipped. Use --nuclei option to enable vulnerability scanning.${RESET}"
fi

echo -e "${CYAN}===================================${RESET}"
log_success "DAST fuzzing automation completed successfully!"
